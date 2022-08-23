# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import unittest
import sys

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

    @unittest.expectedFailure
    def test_pe_cert_trust(self):
        self.step_name('Test that clam can trust an EXE based on an authenticode certificate check.')

        # TODO: This feature was added in 0.105, but was also broken during that release cycle when we upgraded TomsFastMath.
        #       So instead of trusting the certificate, prints this out and the certificate is not trusted so the matches may still happen:
        #           LibClamAV Warning: crtmgr_rsa_verify: verification failed: fp_exptmod failed with 1
        #       We need to fix this, and then update this test.

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
