# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run sigtool tests.
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

        # Prepare a directory to host our test databases
        TC.path_www = TC.path_tmp / 'www'
        TC.path_www.mkdir()
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.path_db = TC.path_tmp / 'database'
        TC.sigtool_pid = TC.path_tmp / 'sigtool-test.pid'
        TC.sigtool_config = TC.path_tmp / 'sigtool-test.conf'
        TC.sigtool_config.write_text('''
            DatabaseMirror localhost
            PidFile {sigtool_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseCustomURL file://{path_www}/clamav.hdb
            ExcludeDatabase daily
            ExcludeDatabase main
            ExcludeDatabase bytecode
        '''.format(
            sigtool_pid=TC.sigtool_pid,
            path_db=TC.path_db,
            path_www=TC.path_www
        ))

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        TC.original_cwd = os.getcwd()
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()
        os.chdir(TC.original_cwd)

    def test_sigtool_00_version(self):
        self.step_name('sigtool version test')

        self.log.warning('VG: {}'.format(os.getenv("VG")))
        command = '{valgrind} {valgrind_args} {sigtool} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_sigtool_01_run_cdiff(self):
        self.step_name('sigtool run cdiff test')
        # In addition to testing that running a cdiff works, this also tests a regression.
        # Applying test-3.cdiff was failing because UNLINK wasn't properly implemented (since 0.105.0).
        # We didn't notice it because logging wasn't enabled, and leniency in our freshclam cdiff process
        # allowed the test to pass without noticing the bug.

        self.log.warning('VG: {}'.format(os.getenv("VG")))

        (TC.path_tmp / 'run_cdiff').mkdir()
        os.chdir(str(TC.path_tmp / 'run_cdiff'))

        command = '{valgrind} {valgrind_args} {sigtool} --unpack {cvd}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            cvd=TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        # Apply 1st cdiff.

        command = '{valgrind} {valgrind_args} {sigtool} --run-cdiff={cdiff}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            cdiff=TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff'
        )
        output = self.execute_command(command)

        # Apply 2nd cdiff. This one failed because the CLOSE operation should create a file
        # if it didn't exist, and it was only appending but not creating.

        command = '{valgrind} {valgrind_args} {sigtool} --run-cdiff={cdiff}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            cdiff=TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

    def test_sigtool_02_rust_logs_messages_work(self):
        self.step_name('sigtool test rust log macros work')
        # In addition to testing that running a cdiff works, this also tests a regression.
        # Applying test-3.cdiff was failing because UNLINK wasn't properly implemented (since 0.105.0).
        # We didn't notice it because logging wasn't enabled, and leniency in our freshclam cdiff process
        # allowed the test to pass without noticing the bug.

        self.log.warning('VG: {}'.format(os.getenv("VG")))

        (TC.path_tmp / 'run_cdiff_log').mkdir()
        os.chdir(str(TC.path_tmp / 'run_cdiff_log'))

        command = '{valgrind} {valgrind_args} {sigtool} --unpack {cvd}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            cvd=TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        # Apply cdiffs in wrong order. Should fail and print a message.

        command = '{valgrind} {valgrind_args} {sigtool} --run-cdiff={cdiff}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            cdiff=TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff'
        )
        output = self.execute_command(command)

        assert output.ec == 1  # failure

        # Verify that the `error!()` message was printed to stderr.
        # This didn't happen before when we didn't initialize the rust logging lib at the top of sigtool.
        expected_results = [
            'LibClamAV Error',
        ]
        self.verify_output(output.err, expected=expected_results)

    def test_sigtool_03_sign_and_verify(self):
        self.step_name('sigtool test for --sign and --verify')
        # Verify that you can sign and verify any file.

        # Create a file to sign.
        (TC.path_tmp / 'file_to_sign').write_text('This is a file to sign.')

        self.log.warning('VG: {}'.format(os.getenv("VG")))

        command = '{valgrind} {valgrind_args} {sigtool} --sign {input} --key {signing_key} --cert {signing_cert} --cert {intermediate_cert}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            input=TC.path_tmp / 'file_to_sign',
            signing_key=TC.path_build / 'unit_tests' / 'input' / 'signing' / 'sign' / 'signing-test.key',
            signing_cert=TC.path_source / 'unit_tests' / 'input' / 'signing' / 'sign' / 'signing-test.crt',
            intermediate_cert=TC.path_source / 'unit_tests' / 'input' / 'signing' / 'sign' / 'intermediate-test.crt'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        # Verify the signed file (should pass)

        command = '{valgrind} {valgrind_args} {sigtool} --verify {input} --cvdcertsdir {cvdcertsdir}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            input=TC.path_tmp / 'file_to_sign',
            cvdcertsdir=TC.path_source / 'unit_tests' / 'input' / 'signing' / 'verify'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Successfully verified file',
            "signed by 'ClamAV TEST CVD Signing Cert'",
        ]
        self.verify_output(output.out, expected=expected_results)

        # Modify the signed file

        (TC.path_tmp / 'file_to_sign').write_text(' Modified.')

        # verify the signed file (should fail now)

        command = '{valgrind} {valgrind_args} {sigtool} --verify {input} --cvdcertsdir {cvdcertsdir}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            input=TC.path_tmp / 'file_to_sign',
            cvdcertsdir=TC.path_source / 'unit_tests' / 'input' / 'signing' / 'verify'
        )
        output = self.execute_command(command)

        assert output.ec != 0  # not success

        expected_results = [
            'Failed to verify file',
        ]
        unexpected_results = [
            'Successfully verified file',
            "signed by 'ClamAV TEST CVD Signing Cert'",
        ]
        self.verify_output(output.err, expected=expected_results, )
        self.verify_output(output.out, unexpected=unexpected_results)

    def test_sigtool_04_diff(self):
        self.step_name('sigtool test for --diff')
        # Verify that you can diff two versions of a CVD.

        # Get two CVD's. The '.script' diff file will be placed in the same
        # directory as the CVD's, so we'll put them inour temp directory.
        (TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles'/ 'test-5.cvd')
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cvd'),
                    str(TC.path_tmp))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cvd.sign'),
                    str(TC.path_tmp))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'),
                    str(TC.path_tmp / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd.sign'),
                    str(TC.path_tmp / 'test-6.cvd.sign'))

        # Run the diff command.
        self.log.warning('VG: {}'.format(os.getenv("VG")))

        command = '{valgrind} {valgrind_args} {sigtool} --diff {old_cvd} {new_cvd}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            old_cvd=TC.path_tmp / 'test-5.cvd',
            new_cvd=TC.path_tmp / 'test.cvd'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Generated diff file',
            'correctly applies to',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_sigtool_05_build(self):
        self.step_name('sigtool test for --build')
        # Verify that you can build a CUD (not signed with legacy-method).

        # This test starts with an existing CVD, adding a new signature to it.
        # The CVD will be unpacked, a new signature will be added, and then a new CUD will be built.

        # Get a CVD.
        (TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles'/ 'test-5.cvd')
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'),
                    str(TC.path_tmp / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd.sign'),
                    str(TC.path_tmp / 'test-6.cvd.sign'))

        # Unpack it to the tmp directory.
        self.log.warning('VG: {}'.format(os.getenv("VG")))

        command = '{valgrind} {valgrind_args} {sigtool} --unpack {old_cvd} --debug'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            old_cvd=TC.path_tmp / 'test.cvd'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'CVD unpacked successfully',
        ]
        self.verify_output(output.err, expected=expected_results)

        # Add a line to one of the signature files.
        with (TC.path_tmp / 'test.ldb').open('ab') as f:
            f.write(
                b'What.a.Silly.Sig.Name-123-0;Engine:51-255,Target:0;0;deadbeefcafe\n'
            )

        # Set 'SIGNDUSER' environment variable to 'pytest' to avoid permission issues.
        os.environ['SIGNDUSER'] = 'pytest'

        # Build a new CVD.
        command = '{valgrind} {valgrind_args} {sigtool} --build=test.cud --unsigned --debug --datadir={path_tmp}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool,
            path_tmp=TC.path_tmp
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Total sigs: 42',
            'New sigs: 28',
            'Created test.cud',
            'Generated diff file test-7.script',
            'Verification',
            'test-7.script correctly applies to the previous version',
        ]
        self.verify_output(output.out, expected=expected_results)

        # Check that the new CUD file was created, and that the '.cud.script' file was created.
        assert (TC.path_tmp / 'test.cud').exists()
        assert (TC.path_tmp / 'test-7.script').exists()
