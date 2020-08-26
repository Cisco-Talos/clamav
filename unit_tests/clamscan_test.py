# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('test/clam*')) # A list of Path()'s of each of our generated test files

        # Prepare a directory to store our test databases
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)

        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'clamav.hdb'),
            str(TC.path_db),
        )

        (TC.path_db / 'clamav.ign2').write_text('ClamAV-Test-File\n')

        (TC.path_db / 'phish.pdb').write_text('H:example.com\n')

        (TC.path_db / 'icon.idb').write_text(
            "EA0X-32x32x8:ea0x-grp1:ea0x-grp2:2046f030a42a07153f4120a0031600007000005e1617ef0000d21100cb090674150f880313970b0e7716116d01136216022500002f0a173700081a004a0e\n"
            "IScab-16x16x8:iscab-grp1:iscab-grp2:107b3000168306015c20a0105b07060be0a0b11c050bea0706cb0a0bbb060b6f00017c06018301068109086b03046705081b000a270a002a000039002b17\n"
        )
        (TC.path_db / 'icon.ldb').write_text(
            "ClamAV-Test-Icon-EA0X;Engine:52-1000,Target:1,IconGroup1:ea0x-grp1,IconGroup2:*;(0);0:4d5a\n"
            "ClamAV-Test-Icon-IScab;Engine:52-1000,Target:1,IconGroup2:iscab-grp2;(0);0:4d5a\n"
        )
        (TC.path_db / 'Clam-VI.ldb').write_text(
            "Clam-VI-Test:Target;Engine:52-255,Target:1;(0&1);VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00\n"
        )
        (TC.path_db / 'yara-at-offset.yara').write_text(
            "rule yara_at_offset {strings: $tar_magic = { 75 73 74 61 72 } condition: $tar_magic at 257}\n"
        )
        (TC.path_db / 'yara-in-range.yara').write_text(
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

    def test_clamscan_00_version(self):
        self.step_name('clamscan version test')

        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -V'
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            f'ClamAV {TC.version}',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_01_all_testfiles(self):
        self.step_name('Test that clamscan alerts on all test files')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "clamav.hdb"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [f'{testpath.name}: ClamAV-Test-File.UNOFFICIAL FOUND' for testpath in TC.testpaths]
        expected_results.append(f'Scanned files: {len(TC.testpaths)}')
        expected_results.append(f'Infected files: {len(TC.testpaths)}')
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_02_all_testfiles_ign2(self):
        self.step_name('Test that clamscan ignores ClamAV-Test-File alerts')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "clamav.hdb"} -d {TC.path_db / "clamav.ign2"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [f'{testpath.name}: ClamAV-Test-File.UNOFFICIAL FOUND' for testpath in TC.testpaths]
        expected_results.append(f'Scanned files: {len(TC.testpaths)}')
        expected_results.append(f'Infected files: {len(TC.testpaths)}')
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_03_phish_test_not_enabled(self):
        self.step_name('Test that clamscan will load the phishing sigs w/out issue')

        testpaths = list(TC.path_source.glob('unit_tests/input/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "phish.pdb"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'Scanned files: 3',
            'Infected files: 0',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_04_phish_test_alert_phishing_ssl_alert_phishing_cloak(self):
        self.step_name('Test clamscan --alert-phishing-ssl --alert-phishing-cloak')

        testpaths = list(TC.path_source.glob('unit_tests/input/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "phish.pdb"} --alert-phishing-ssl --alert-phishing-cloak {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'phish-test-ssl: Heuristics.Phishing.Email.SSL-Spoof FOUND',
            'phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND',
            'Scanned files: 3',
            'Infected files: 2', # there's a clean one
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_05_icon(self):
        self.step_name('Test icon (.ldb + .idb) signatures')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "icon.ldb"} -d {TC.path_db / "icon.idb"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        # Use check_fpu_endian to determine expected results
        command = f'{TC.check_fpu_endian}'
        fpu_endian_output = self.execute_command(command)

        expected_results = [
            'clam_IScab_ext.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND',
            'clam_IScab_int.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND',
        ]
        if fpu_endian_output.ec == 3:
            expected_num_infected = 3
        else:
            expected_results.append('clam.ea06.exe: ClamAV-Test-Icon-EA0X.UNOFFICIAL FOUND')
            expected_num_infected = 4
        expected_results.append(f'Infected files: {expected_num_infected}')
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_06_LDB_VI(self):
        self.step_name('Test LDB VI feature')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "Clam-VI.ldb"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam_ISmsi_ext.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'clam_ISmsi_int.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'Infected files: 2',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_07_yara_at_offset(self):
        self.step_name('Test yara signature - detect TAR file magic at an offset')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "yara-at-offset.yara"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'Infected files: 2',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_08_yara_in_range(self):
        self.step_name('Test yara signature - detect TAR file magic in a range')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamscan} -d {TC.path_db / "yara-in-range.yara"} {testfiles}'
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'Infected files: 2',
        ]
        self.verify_output(output.out, expected=expected_results)
