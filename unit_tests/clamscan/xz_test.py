# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Run clamscan tests for the Rust XZ scanner."""

import hashlib
import lzma
import re
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        cls.payload = b'CLAMAV_RUST_XZ_SECOND_STREAM_TEST\n'
        cls.large_payload = b'CLAMAV_RUST_XZ_LARGE_OUTPUT\n' + b'B' * (3 * 64 * 1024)
        cls.database = TC.path_tmp / 'rust-xz.hdb'
        cls.database.write_text(
            '{}:{}:RUST_XZ_SECOND_STREAM_TEST\n{}:{}:RUST_XZ_LARGE_OUTPUT_TEST\n'.format(
                hashlib.md5(cls.payload).hexdigest(),
                len(cls.payload),
                hashlib.md5(cls.large_payload).hexdigest(),
                len(cls.large_payload),
            )
        )

        cls.single_stream = TC.path_tmp / 'rust-xz-single.xz'
        cls.single_stream.write_bytes(lzma.compress(cls.payload, format=lzma.FORMAT_XZ))

        empty_stream = lzma.compress(b'', format=lzma.FORMAT_XZ)
        malicious_stream = lzma.compress(cls.payload, format=lzma.FORMAT_XZ)
        cls.concatenated = TC.path_tmp / 'rust-xz-concatenated.xz'
        cls.concatenated.write_bytes(empty_stream + malicious_stream)

        cls.malformed_tail = TC.path_tmp / 'rust-xz-malformed-tail.xz'
        cls.malformed_tail.write_bytes(malicious_stream + empty_stream[:-1])

        # XZ permits stream padding in multiples of four bytes. Put the next
        # stream exactly at the old C scanner's 256 KiB refill boundary.
        padding_size = (-len(empty_stream)) % (256 * 1024)
        if padding_size == 0:
            padding_size = 256 * 1024
        assert padding_size % 4 == 0
        cls.boundary_concatenated = TC.path_tmp / 'rust-xz-boundary-concatenated.xz'
        cls.boundary_concatenated.write_bytes(
            empty_stream + bytes(padding_size) + malicious_stream
        )

        cls.limit_stream = TC.path_tmp / 'rust-xz-limit.xz'
        cls.limit_stream.write_bytes(lzma.compress(b'A' * (1024 * 1024)))

        cls.large_stream = TC.path_tmp / 'rust-xz-large.xz'
        cls.large_stream.write_bytes(
            lzma.compress(cls.large_payload, format=lzma.FORMAT_XZ)
        )

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def scan(self, testfile, options=''):
        command = (
            '{valgrind} {valgrind_args} {clamscan} {options} '
            '-d {database} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            options=options,
            database=TC.database,
            testfile=testfile,
        )
        return self.execute_command(command)

    def assert_test_signature_found(self, testfile):
        output = self.scan(testfile)
        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['RUST_XZ_SECOND_STREAM_TEST.UNOFFICIAL FOUND'],
        )

    def test_single_stream_is_finished_and_scanned(self):
        self.step_name('Test scanning a small XZ stream through physical EOF')
        self.assert_test_signature_found(TC.single_stream)

    def test_second_concatenated_stream_is_scanned(self):
        self.step_name('Test scanning the second of two concatenated XZ streams')
        self.assert_test_signature_found(TC.concatenated)

    def test_second_stream_at_old_refill_boundary_is_scanned(self):
        self.step_name('Test concatenated XZ at the old 256 KiB refill boundary')
        self.assert_test_signature_found(TC.boundary_concatenated)

    def test_large_output_is_flushed_and_scanned(self):
        self.step_name('Test XZ output spanning multiple bounded chunks')
        output = self.scan(TC.large_stream)
        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['RUST_XZ_LARGE_OUTPUT_TEST.UNOFFICIAL FOUND'],
        )

    def test_output_before_malformed_later_stream_is_scanned(self):
        self.step_name('Test scanning output produced before a malformed XZ tail')
        self.assert_test_signature_found(TC.malformed_tail)

    def test_limits_use_decompressed_bytes(self):
        self.step_name('Test XZ limits are checked against bounded output chunks')
        output = self.scan(
            TC.limit_stream,
            '--alert-exceeds-max=yes --max-filesize=1K --max-scansize=2M',
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxFileSize FOUND'],
            unexpected=['RUST_XZ_SECOND_STREAM_TEST.UNOFFICIAL FOUND'],
        )
        self.verify_output(output.out, expected=[re.escape('Infected files: 1')])
