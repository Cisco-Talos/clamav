# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan 7z tests.
"""

import hashlib
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import testcase

TINY_FILE = b'solid 7z folder small test file\n'


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

    def scan_solid_folder(self, limits):
        path_db = TC.path_tmp / 'sevenzip-tiny.hdb'
        path_db.write_text(
            '{}:{}:SEVENZIP_TINY_FILE\n'.format(
                hashlib.md5(TINY_FILE).hexdigest(),
                len(TINY_FILE),
            )
        )
        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'solid-folder.7z'

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

    def test_solid_folder_within_scan_size_is_scanned(self):
        self.step_name('Test a solid 7z folder within the scan size is unpacked')

        output = self.scan_solid_folder('--alert-exceeds-max=yes --max-scansize=200M')

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZIP_TINY_FILE.UNOFFICIAL FOUND'],
            unexpected=['Heuristics.Limits.Exceeded'],
        )

    def test_solid_folder_beyond_scan_size_is_not_unpacked(self):
        self.step_name('Test a solid 7z folder beyond the scan size is not unpacked')

        output = self.scan_solid_folder('--alert-exceeds-max=yes --max-scansize=1M')

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxScanSize FOUND'],
            unexpected=['SEVENZIP_TINY_FILE'],
        )
