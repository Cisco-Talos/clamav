# Copyright (C) 2020-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import unittest
import sys
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_00_version(self):
        self.step_name('clamscan version test')

        command = '{valgrind} {valgrind_args} {clamscan} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_weak_indicator_icon(self):
        self.step_name('Test icon (.ldb + .idb) weak indicator matching signatures')

        (TC.path_tmp / 'icon.idb').write_text(
            "EA0X-32x32x8:ea0x-grp1:ea0x-grp2:2046f030a42a07153f4120a0031600007000005e1617ef0000d21100cb090674150f880313970b0e7716116d01136216022500002f0a173700081a004a0e\n"
            "IScab-16x16x8:iscab-grp1:iscab-grp2:107b3000168306015c20a0105b07060be0a0b11c050bea0706cb0a0bbb060b6f00017c06018301068109086b03046705081b000a270a002a000039002b17\n"
        )
        (TC.path_tmp / 'icon.ldb').write_text(
            "ClamAV-Test-Icon-EA0X;Engine:52-1000,Target:1,IconGroup1:ea0x-grp1,IconGroup2:*;(0);0:4d5a\n"
            "ClamAV-Test-Icon-IScab;Engine:52-1000,Target:1,IconGroup2:iscab-grp2;(0);0:4d5a\n"
        )

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_ldb} -d {path_idb} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_ldb=TC.path_tmp / 'icon.ldb',
            path_idb=TC.path_tmp / 'icon.idb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        # Use check_fpu_endian to determine expected results
        command = '{}'.format(TC.check_fpu_endian)
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
        expected_results.append('Infected files: {}'.format(expected_num_infected))
        self.verify_output(output.out, expected=expected_results)

    def test_pe_cert_trust(self):
        self.step_name('Test that clam can trust an EXE based on an authenticode certificate check.')

        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'
        test_exe = test_path / 'test.exe'

        command = '{valgrind} {valgrind_args} {clamscan} \
             -d {alerting_dbs} \
             -d {weak_dbs} \
             -d {broken_dbs} \
             -d {trust_dbs} \
             --allmatch --bytecode-unsigned {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            alerting_dbs=test_path / 'alert-sigs',
            weak_dbs=test_path / 'weak-sigs',
            broken_dbs=test_path / 'broken-sigs',
            trust_dbs=test_path / 'trust-sigs',
            testfiles=test_exe,
        )
        output = self.execute_command(command)

        assert output.ec == 0

        expected_results = ['OK']

        # The alert sig files are all given the signature name, so we can verify that the correct sigs were found.
        # We need only to trim off the extension and say "FOUND" for the alerting sigs.
        # Note: Some of these have ".UNOFFICIAL" in the name because not all of them have that ".UNOFFICIAL" suffix when reported.
        #       I think this is a minor bug. So if we change that, we'll need to update this test.
        unexpected_results = ['{sig} FOUND'.format(sig=f.stem) for f in (test_path / 'alert-sigs').iterdir()]

        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_pe_cert_block(self):
        self.step_name('Test that clam will disregard a certificate trust signature if a block certificate rule is used.')

        # The sig set and test.exe for test set was written by one of our threat researchers to test the allmatch option.
        # Overall, it's much more thorough than previous tests, but some of the tests are duplicates of the previous tests.

        # TODO: The section signatures are not working as written, hence the "broken_dbs" directory.
        #       There is a known issue with relative offset signatures when using the Boyer-Moore matcher. The sigs work if using the Aho-Corasick matcher.
        #       When we fix section signatures, we can move them to the alerting sigs directory and update this test.

        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'
        test_exe = test_path / 'test.exe'

        command = '{valgrind} {valgrind_args} {clamscan} \
             -d {alerting_dbs} \
             -d {weak_dbs} \
             -d {broken_dbs} \
             -d {block_cert_dbs} \
             --allmatch --bytecode-unsigned {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            alerting_dbs=test_path / 'alert-sigs',
            block_cert_dbs=test_path / 'block-cert-sigs',
            weak_dbs=test_path / 'weak-sigs',
            broken_dbs=test_path / 'broken-sigs',
            trust_dbs=test_path / 'trust-sigs',
            testfiles=test_exe,
        )
        output = self.execute_command(command)

        assert output.ec == 1

        # The alert sig files are all given the signature name, so we can verify that the correct sigs were found.
        # We need only to trim off the extension and say "FOUND" for the alerting sigs.
        # Note: Some of these have ".UNOFFICIAL" in the name because not all of them have that ".UNOFFICIAL" suffix when reported.
        #       I think this is a minor bug. So if we change that, we'll need to update this test.
        expected_results = ['{sig} FOUND'.format(sig=f.stem) for f in (test_path / 'alert-sigs').iterdir()]
        expected_results += ['{sig} FOUND'.format(sig=f.stem) for f in (test_path / 'block-cert-sigs').iterdir()]

        # The broken sig files are all given the signature name, so we can verify that the correct sigs were found.
        # TODO: When we fix section signatures, we can move them to the alerting sigs directory and get rid of this line.
        unexpected_results = ['{sig} FOUND'.format(sig=f.stem) for f in (test_path / 'broken-sigs').iterdir()]

        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_pe_cert_trust_archive(self):
        self.step_name('Test that clam\'s trust of an EXE based on a cert check doesn\'t trust a whole archive.')

        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'

        # This file we'll trust.
        test_exe = test_path / 'test.exe'

        # This file we'll match on for an alert
        clam_exe = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        # Build a ZIP that first has file that we trust, followed by a file we would alert on.
        trusted_plus_mal_zip = TC.path_tmp / 'trust_plus_mal.zip'
        with ZipFile(str(trusted_plus_mal_zip), 'w', ZIP_DEFLATED) as zf:
            zf.writestr('test.exe', test_exe.read_bytes())
            zf.writestr('clam.exe', clam_exe.read_bytes())

        # Build another ZIP, but with files added in reverse order, for good measure.
        trusted_plus_mal_zip_2 = TC.path_tmp / 'trust_plus_mal2.zip'
        with ZipFile(str(trusted_plus_mal_zip_2), 'w', ZIP_DEFLATED) as zf:
            zf.writestr('clam.exe', clam_exe.read_bytes())
            zf.writestr('test.exe', test_exe.read_bytes())

        command = '{valgrind} {valgrind_args} {clamscan} \
             -d {alerting_dbs} \
             -d {weak_dbs} \
             -d {broken_dbs} \
             -d {trust_dbs} \
             -d {clamav_hdb} \
             --allmatch --bytecode-unsigned {testfile1} {testfile2}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            alerting_dbs=test_path / 'alert-sigs',
            weak_dbs=test_path / 'weak-sigs',
            broken_dbs=test_path / 'broken-sigs',
            trust_dbs=test_path / 'trust-sigs',
            clamav_hdb=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile1=trusted_plus_mal_zip,
            testfile2=trusted_plus_mal_zip_2,
        )
        output = self.execute_command(command)

        assert output.ec == 1

        expected_results = [
            'trust_plus_mal.zip: ClamAV-Test-File.UNOFFICIAL FOUND',
            'trust_plus_mal2.zip: ClamAV-Test-File.UNOFFICIAL FOUND',
        ]
        unexpected_results = ['OK']

        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_iso_missing_joliet(self):
        self.step_name('Test that we correctly extract files from an ISO even if the joliet file path is empty.')

        test_path = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles'
        sig_path = TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'logo.hsb'

        command = '{valgrind} {valgrind_args} {clamscan} \
             -d {sig_path} \
             --allmatch {testfile1} {testfile2}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            sig_path=sig_path,
            testfile1=test_path / 'iso_normal.logo.iso',
            testfile2=test_path / 'iso_no_joliet.logo.iso',
        )
        output = self.execute_command(command)

        assert output.ec == 1

        expected_results = [
            'iso_normal.logo.iso: logo.png.UNOFFICIAL FOUND',
            'iso_no_joliet.logo.iso: logo.png.UNOFFICIAL FOUND',
        ]
        unexpected_results = ['OK']

        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)
