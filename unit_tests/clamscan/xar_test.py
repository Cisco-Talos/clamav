# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan XAR tests.
"""

import hashlib
import re
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

    def make_xar(
        self,
        name,
        toc_length_decompressed,
        toc=b'<xar></xar>',
        truncate_stream=False,
        pad_compressed_to=None,
    ):
        compressed_toc = zlib.compress(toc)
        if truncate_stream:
            compressed_toc = compressed_toc[:-4]
        if pad_compressed_to is not None:
            assert len(compressed_toc) <= pad_compressed_to
            compressed_toc += bytes(pad_compressed_to - len(compressed_toc))

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
        return testfile

    def scan_xar(self, testfile, limits, path_db=None):
        if path_db is None:
            path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        command = (
            '{valgrind} {valgrind_args} {clamscan} {limits} '
            '-d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            limits=limits,
            path_db=path_db,
            testfile=testfile,
        )
        return self.execute_command(command)

    def test_declared_large_actual_small_toc_is_scanned(self):
        self.step_name('Test XAR limits use the actual TOC size')

        for name, declared_length in (
            ('allocation-limit-toc.xar', 1024 * 1024 * 1024),
            ('overflow-toc.xar', (1 << 64) - 1),
        ):
            with self.subTest(declared_length=declared_length):
                testfile = self.make_xar(
                    name,
                    declared_length,
                    pad_compressed_to=44,
                )
                assert testfile.stat().st_size == 72
                output = self.scan_xar(
                    testfile,
                    '--alert-exceeds-max=yes --max-filesize=1M --max-scansize=1M',
                )

                assert output.ec == 0
                self.verify_output(
                    output.out,
                    expected=[re.escape('{}: OK'.format(testfile))],
                    unexpected=[
                        'Heuristics.Limits.Exceeded',
                        "Can't allocate memory ERROR",
                    ],
                )

    def test_declared_small_actual_large_toc_obeys_scan_limits(self):
        self.step_name('Test XAR limits stop actual TOC output')

        actual_toc = b'<xar>' + (b' ' * (2 * 1024 * 1024)) + b'</xar>'
        testfile = self.make_xar(
            'actual-oversized-toc.xar',
            1,
            toc=actual_toc,
        )
        output = self.scan_xar(
            testfile,
            '--alert-exceeds-max=yes --max-filesize=1M --max-scansize=1M',
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxScanSize FOUND'],
            unexpected=["Can't allocate memory ERROR"],
        )

    def test_incomplete_toc_stream_is_not_scanned(self):
        self.step_name('Test XAR requires a complete TOC stream')

        toc = b'<xar></xar>'
        path_db = TC.path_tmp / 'xar-toc.hdb'
        path_db.write_text(
            '{}:{}:XAR_TOC_TEST\n'.format(
                hashlib.md5(toc).hexdigest(),
                len(toc),
            )
        )
        testfile = self.make_xar(
            'incomplete-toc.xar',
            len(toc),
            toc=toc,
            truncate_stream=True,
        )
        output = self.scan_xar(testfile, '', path_db=path_db)

        assert output.ec == 0
        self.verify_output(
            output.out,
            unexpected=['XAR_TOC_TEST.UNOFFICIAL FOUND'],
        )
