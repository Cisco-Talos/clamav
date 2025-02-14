# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import shutil
import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

        (TC.path_tmp / 'Clam-VI.ldb').write_text(
            "Clam-VI-Test:Target;Engine:52-255,Target:1;(0&1);VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00\n"
        )
        (TC.path_tmp / 'yara-at-offset.yara').write_text(
            "rule yara_at_offset {strings: $tar_magic = { 75 73 74 61 72 } condition: $tar_magic at 257}\n"
        )
        (TC.path_tmp / 'yara-in-range.yara').write_text(
            "rule yara_in_range {strings: $tar_magic = { 75 73 74 61 72 } condition: $tar_magic in (200..300)}\n"
        )

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_LDB_VI(self):
        self.step_name('Test LDB VI feature')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_tmp / 'Clam-VI.ldb', testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam_ISmsi_ext.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'clam_ISmsi_int.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'Infected files: 2',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_yara_at_offset(self):
        self.step_name('Test yara signature - detect TAR file magic at an offset')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_tmp / 'yara-at-offset.yara', testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'Infected files: 3',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_yara_in_range(self):
        self.step_name('Test yara signature - detect TAR file magic in a range')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_tmp / 'yara-in-range.yara', testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'Infected files: 3',
        ]
        self.verify_output(output.out, expected=expected_results)
