# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Deterministic HTTP workflow and error-handling tests for clamsubmit."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest


CSRF_TOKEN = "test-page-level-csrf-token"
FORM_AUTHENTICITY_TOKEN = "test-form-authenticity-token"
SESSION_COOKIE = "_clamav-net_session=test-session"


def valid_presigned_response(include_acl=True):
    response = {
        "key": "uploads/12345-sample.txt",
        "policy": "test-policy",
        "x-amz-meta-original-filename": "sample.txt",
        "x-amz-credential": "test-credential",
        "x-amz-algorithm": "AWS4-HMAC-SHA256",
        "x-amz-date": "20260928T120000Z",
        "x-amz-signature": "test-signature",
    }
    if include_acl:
        response["acl"] = "private"
    return json.dumps(response).encode("utf-8")


class Scenario:
    def __init__(
        self,
        report_status=200,
        report_body=None,
        presigned_status=200,
        presigned_body=None,
        upload_status=204,
        submit_status=302,
        submit_location="/reports/success",
    ):
        self.report_status = report_status
        self.report_body = (
            '<html><head><meta name="csrf-token" content="{}"></head>'
            '<body><form><input value="{}" name="authenticity_token" '
            'type="hidden"></form></body></html>'.format(
                CSRF_TOKEN, FORM_AUTHENTICITY_TOKEN
            ).encode("utf-8")
            if report_body is None
            else report_body
        )
        self.presigned_status = presigned_status
        self.presigned_body = (
            valid_presigned_response() if presigned_body is None else presigned_body
        )
        self.upload_status = upload_status
        self.submit_status = submit_status
        self.submit_location = submit_location
        self.requests = []


def make_handler(scenario):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def record_request(self, body=b""):
            scenario.requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": body,
                }
            )

        def send_body(self, status, body=b"", headers=None):
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

        def do_GET(self):
            self.record_request()
            if self.path not in ("/reports/malware", "/reports/fp"):
                self.send_body(404)
                return
            self.send_body(
                scenario.report_status,
                scenario.report_body,
                {"Set-Cookie": SESSION_COOKIE + "; Path=/; HttpOnly"},
            )

        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length)
            self.record_request(body)
            if self.path == "/presigned":
                if (
                    self.headers.get("X-CSRF-Token") != CSRF_TOKEN
                    or SESSION_COOKIE not in self.headers.get("Cookie", "")
                ):
                    self.send_body(422)
                    return
                self.send_body(
                    scenario.presigned_status,
                    scenario.presigned_body,
                    {"Content-Type": "application/json"},
                )
            elif self.path == "/upload":
                self.send_body(scenario.upload_status)
            elif self.path == "/reports/submit":
                headers = {}
                if scenario.submit_location is not None:
                    headers["Location"] = scenario.submit_location
                self.send_body(scenario.submit_status, headers=headers)
            else:
                self.send_body(404)

    return Handler


def multipart_fields(request):
    content_type = request["headers"].get("content-type", "")
    match = re.search(r"boundary=([^;]+)", content_type)
    if match is None:
        raise AssertionError("request is not multipart/form-data")
    boundary = match.group(1).strip('"').encode("ascii")
    fields = {}
    for part in request["body"].split(b"--" + boundary):
        if b"\r\n\r\n" not in part:
            continue
        headers, value = part.split(b"\r\n\r\n", 1)
        name_match = re.search(br'name="([^"]+)"', headers)
        if name_match is None:
            continue
        fields[name_match.group(1).decode("ascii")] = value.rstrip(b"\r\n-")
    return fields


class ClamSubmitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clamsubmit = os.environ.get("CLAMSUBMIT_TEST")
        if not cls.clamsubmit:
            raise unittest.SkipTest("CLAMSUBMIT_TEST is not configured")

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.sample = Path(self.temporary_directory.name, "sample.txt")
        self.sample.write_bytes(b"sample data")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def run_client(self, scenario, arguments, input_data=None):
        server = HTTPServer(("127.0.0.1", 0), make_handler(scenario))
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.daemon = True
        thread.start()
        environment = os.environ.copy()
        environment["CLAMSUBMIT_TEST_BASE_URL"] = "http://127.0.0.1:{}".format(
            server.server_port
        )
        try:
            result = subprocess.run(
                [self.clamsubmit] + arguments,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        return result

    def standard_arguments(self, false_positive=False, filename=None):
        arguments = [
            "-e",
            "submitter@example.com",
            "-N",
            "Test Submitter",
        ]
        if false_positive:
            arguments += ["-p", str(filename or self.sample), "-V", "Test.Signature"]
        else:
            arguments += ["-n", str(filename or self.sample)]
        return arguments

    def request_for_path(self, scenario, path):
        return next(request for request in scenario.requests if request["path"] == path)

    def assert_presigned_request(self, scenario, sample_type):
        request = self.request_for_path(scenario, "/presigned")
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["body"], ("type=" + sample_type).encode("ascii"))
        self.assertEqual(
            request["headers"].get("content-type"),
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(request["headers"].get("x-csrf-token"), CSRF_TOKEN)
        self.assertIn(SESSION_COOKIE, request["headers"].get("cookie", ""))
        self.assertTrue(
            request["headers"].get("referer", "").endswith(
                "/reports/" + ("malware" if sample_type == "malware" else "fp")
            )
        )

    def test_false_negative_workflow_with_acl(self):
        scenario = Scenario()
        result = self.run_client(scenario, self.standard_arguments())
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"Submission success!", result.stdout)
        self.assert_presigned_request(scenario, "malware")

        upload_fields = multipart_fields(self.request_for_path(scenario, "/upload"))
        self.assertEqual(upload_fields["acl"], b"private")
        self.assertEqual(upload_fields["policy"], b"test-policy")
        self.assertEqual(upload_fields["file"], b"sample data")

        submit_fields = multipart_fields(
            self.request_for_path(scenario, "/reports/submit")
        )
        submit_request = self.request_for_path(scenario, "/reports/submit")
        self.assertIn(SESSION_COOKIE, submit_request["headers"].get("cookie", ""))
        self.assertEqual(
            submit_fields["authenticity_token"],
            FORM_AUTHENTICITY_TOKEN.encode("utf-8"),
        )
        self.assertEqual(submit_fields["submissionID"], b"12345")
        self.assertEqual(submit_fields["type"], b"malware")
        self.assertEqual(submit_fields["utf8"], "✓".encode("utf-8"))
        self.assertEqual(submit_fields["sendername"], b"Test Submitter")
        self.assertEqual(submit_fields["email"], b"submitter@example.com")
        self.assertEqual(submit_fields["description"], b"clamsubmit")
        self.assertEqual(submit_fields["notify"], b"on")
        self.assertEqual(submit_fields["privacy"], b"on")
        self.assertIn("shareSample", submit_fields)

    def test_false_positive_workflow_without_acl(self):
        scenario = Scenario(presigned_body=valid_presigned_response(False))
        result = self.run_client(
            scenario, self.standard_arguments(false_positive=True)
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assert_presigned_request(scenario, "fp")
        self.assertNotIn(
            "acl", multipart_fields(self.request_for_path(scenario, "/upload"))
        )
        submit_fields = multipart_fields(
            self.request_for_path(scenario, "/reports/submit")
        )
        self.assertEqual(submit_fields["virusname"], b"Test.Signature")
        self.assertNotIn("shareSample", submit_fields)

    def test_stdin_sample(self):
        scenario = Scenario()
        result = self.run_client(
            scenario,
            self.standard_arguments(filename="-"),
            input_data=b"sample from stdin",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fields = multipart_fields(self.request_for_path(scenario, "/upload"))
        self.assertEqual(fields["file"], b"sample from stdin")

    def test_http_failures_stop_at_failing_stage(self):
        cases = [
            (Scenario(report_status=500), "report form", 1),
            (Scenario(presigned_status=404, presigned_body=b""), "presigned POST", 2),
            (Scenario(upload_status=403), "S3 upload", 3),
            (Scenario(submit_status=500), "report submission", 4),
        ]
        for scenario, expected_error, expected_requests in cases:
            with self.subTest(expected_error=expected_error):
                result = self.run_client(scenario, self.standard_arguments())
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected_error.encode(), result.stderr)
                self.assertEqual(len(scenario.requests), expected_requests)

    def test_invalid_presigned_responses(self):
        missing_required_fields = []
        for field in (
            "key",
            "policy",
            "x-amz-meta-original-filename",
            "x-amz-credential",
            "x-amz-algorithm",
            "x-amz-date",
            "x-amz-signature",
        ):
            response = json.loads(valid_presigned_response())
            del response[field]
            missing_required_fields.append(
                (
                    json.dumps(response).encode(),
                    ("missing required string field '{}'".format(field)).encode(),
                )
            )

        invalid_responses = [
            (b"", b"response body is empty"),
            (b"{not json", b"not valid JSON"),
            (
                b'{"x-amz-signature":"must-not-be-logged"} trailing',
                b"not valid JSON",
            ),
            (b"[]", b"JSON is not an object"),
            (
                json.dumps(
                    dict(
                        json.loads(valid_presigned_response()),
                        policy=123,
                    )
                ).encode(),
                b"field 'policy' is not a string",
            ),
            (
                json.dumps(
                    dict(
                        json.loads(valid_presigned_response()),
                        policy="",
                    )
                ).encode(),
                b"field 'policy' is empty",
            ),
            (
                json.dumps(
                    dict(
                        json.loads(valid_presigned_response(False)),
                        acl=123,
                    )
                ).encode(),
                b"field 'acl' is not a string",
            ),
        ] + missing_required_fields
        for response, expected_error in invalid_responses:
            with self.subTest(expected_error=expected_error):
                scenario = Scenario(presigned_body=response)
                result = self.run_client(scenario, self.standard_arguments())
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected_error, result.stderr)
                self.assertNotIn(b"must-not-be-logged", result.stderr)
                self.assertEqual(len(scenario.requests), 2)

    def test_oversized_presigned_response(self):
        scenario = Scenario(presigned_body=b"x" * (1024 * 1024 + 1))
        result = self.run_client(scenario, self.standard_arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"exceeded the 1048576-byte limit", result.stderr)

    def test_bad_submission_redirects(self):
        cases = [
            (None, b"no redirect destination"),
            ("/unexpected", b"Unknown report submission redirect"),
            (
                "http://attacker.invalid/reports/success",
                b"Unknown report submission redirect",
            ),
            ("/reports/failure", b"rejected the submission"),
        ]
        for location, expected_error in cases:
            with self.subTest(location=location):
                scenario = Scenario(submit_location=location)
                result = self.run_client(scenario, self.standard_arguments())
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected_error, result.stderr)

    def test_missing_token_fails_cleanly(self):
        scenario = Scenario(report_body=b"<html>no token</html>")
        result = self.run_client(scenario, self.standard_arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"does not contain an authenticity token", result.stderr)
        self.assertEqual(len(scenario.requests), 1)

    def test_missing_page_csrf_token_fails_cleanly(self):
        scenario = Scenario(
            report_body=(
                '<html><form><input value="{}" name="authenticity_token" '
                'type="hidden"></form></html>'.format(FORM_AUTHENTICITY_TOKEN)
            ).encode("utf-8")
        )
        result = self.run_client(scenario, self.standard_arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"does not contain a page-level CSRF token", result.stderr)
        self.assertEqual(len(scenario.requests), 1)

    def test_empty_report_form_fails_cleanly(self):
        scenario = Scenario(report_body=b"")
        result = self.run_client(scenario, self.standard_arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Report form response body is empty", result.stderr)
        self.assertEqual(len(scenario.requests), 1)

    def test_debug_output_redacts_sensitive_values(self):
        scenario = Scenario()
        result = self.run_client(scenario, self.standard_arguments() + ["-d"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for secret in (
            CSRF_TOKEN,
            FORM_AUTHENTICITY_TOKEN,
            "test-session",
            "test-policy",
            "test-credential",
            "test-signature",
            "submitter@example.com",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret.encode(), result.stderr)

    def test_cli_validation(self):
        result = subprocess.run(
            [self.clamsubmit]
            + self.standard_arguments()
            + ["-p", str(self.sample), "-V", "Test.Signature"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"mutually exclusive", result.stderr)

        result = subprocess.run(
            [self.clamsubmit]
            + self.standard_arguments(
                filename=Path(self.temporary_directory.name, "missing")
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Unable to open sample file", result.stderr)


if __name__ == "__main__":
    unittest.main()
