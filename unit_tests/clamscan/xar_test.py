# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan XAR tests.
"""

import struct
import sys
import zlib
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
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

    def make_xar(self, name, toc_length_decompressed):
        compressed_toc = zlib.compress(b'<xar></xar>')
        compressed_toc += bytes(44 - len(compressed_toc))
        testfile = TC.path_tmp / name
        testfile.write_bytes(
            struct.pack(
                '>IHHQQI',
                0x78617221,
                28,
                0,
                len(compressed_toc),
                toc_length_decompressed,
                0,
            ) + compressed_toc
        )
        assert testfile.stat().st_size == 72
        return testfile

    def scan_xar(self, testfile, limits):
        command = (
            '{valgrind} {valgrind_args} {clamscan} {limits} '
            '-d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            limits=limits,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile=testfile,
        )
        return self.execute_command(command)

    def test_toc_allocation_obeys_scan_limits(self):
        self.step_name('Test XAR TOC allocation obeys scan limits')

        testfile = self.make_xar(
            'oversized-toc.xar',
            1024 * 1024 * 1024,
        )
        output = self.scan_xar(
            testfile,
            '--alert-exceeds-max=yes --max-filesize=1M --max-scansize=1M',
        )

        assert output.ec == 1  # limits heuristic

        expected_results = [
            'Heuristics.Limits.Exceeded.MaxScanSize FOUND',
        ]
        unexpected_results = [
            "Can't allocate memory ERROR",
        ]
        self.verify_output(
            output.out,
            expected=expected_results,
            unexpected=unexpected_results,
        )

    def test_toc_allocation_has_internal_limit(self):
        self.step_name('Test XAR TOC allocation has an internal limit')

        for name, toc_length_decompressed in (
            ('allocation-limit-toc.xar', 1024 * 1024 * 1024),
            ('overflow-toc.xar', (1 << 64) - 1),
        ):
            with self.subTest(toc_length_decompressed=toc_length_decompressed):
                testfile = self.make_xar(name, toc_length_decompressed)
                output = self.scan_xar(
                    testfile,
                    '--max-filesize=0 --max-scansize=0',
                )

                # A malformed archive is skipped without turning the scan into
                # an allocation error, even when policy limits are disabled.
                assert output.ec == 0
                self.verify_output(
                    output.out,
                    unexpected=["Can't allocate memory ERROR"],
                )
