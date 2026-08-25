# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Run clamscan mail parser tests."""

import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    @staticmethod
    def _content_type_with_whitespace(prefix, suffix, whitespace_size):
        lines = [prefix]

        while whitespace_size:
            line_size = min(900, whitespace_size)
            lines.append(b' (comment)' + (b' ' * line_size))
            whitespace_size -= line_size

        lines[-1] += suffix
        return b'\n'.join(lines)

    def test_content_disposition_unquoted_escaped_semicolon(self):
        self.step_name('Test escaped semicolon in an unquoted attachment filename')

        testfile = (
            TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' /
            'clam.mail-content-disposition-escaped-semicolon.eml'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --gen-json --debug'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found, no failures
        self.verify_output(
            output.out,
            expected=[
                'clam.mail-content-disposition-escaped-semicolon.eml: '
                'ClamAV-Test-File.UNOFFICIAL FOUND',
            ],
        )
        self.verify_output(
            output.err,
            expected=[r'"Filename":"foo\\\\;bar\.exe"'],
        )

    def test_content_type_long_whitespace_runs(self):
        self.step_name('Test long whitespace runs in MIME boundary look-ahead')

        source = (
            TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' /
            'clam.mail-boundary-ordinary-parameter.eml'
        ).read_bytes()
        original_header = b'Content-Type: multipart/mixed; boundary=X\\; name=a'
        testfiles = []

        cases = (
            (
                'clam.mail-boundary-long-seek-whitespace.eml',
                b'Content-Type: multipart/mixed',
                b'; boundary=Z',
            ),
            (
                'clam.mail-boundary-long-argument-whitespace.eml',
                b'Content-Type: multipart/mixed; boundary=X',
                b' boundary=Y; boundary=Z',
            ),
        )

        for filename, prefix, suffix in cases:
            header = self._content_type_with_whitespace(
                prefix,
                suffix,
                32 * 1024,
            )
            message = source.replace(original_header, header, 1)
            message = message.replace(b'--X\\;', b'--Z')
            testfile = TC.path_tmp / filename
            testfile.write_bytes(message)
            testfiles.append(testfile)

        command = '{valgrind} {valgrind_args} {clamscan} --no-summary -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfiles=' '.join(str(testfile) for testfile in testfiles),
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found, no failures
        self.verify_output(
            output.out,
            expected=[
                'clam.mail-boundary-long-seek-whitespace.eml: '
                'ClamAV-Test-File.UNOFFICIAL FOUND',
                'clam.mail-boundary-long-argument-whitespace.eml: '
                'ClamAV-Test-File.UNOFFICIAL FOUND',
            ],
        )
