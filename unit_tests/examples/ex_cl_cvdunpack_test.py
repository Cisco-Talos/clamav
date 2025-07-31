# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run sigtool tests.
"""

import os
import platform
import shutil
import sys

sys.path.append('../unit_tests')
import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()

program_name = 'ex_cl_cvdunpack'

class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        # Find the example program
        if operating_system == 'windows':
            # Windows needs the example program to be in the same directory as libclamav and the rest.
            shutil.copy(
                str(TC.path_build / 'examples' / program_name + '.exe'),
                str(TC.path_build / 'unit_tests' / program_name + '.exe'),
            )

            TC.example_program = TC.path_build / 'unit_tests' / program_name + '.exe'
            if not TC.example_program.exists():
                # Try the static version.
                TC.example_program = TC.path_build / 'unit_tests' / program_name + '_static.exe'
                if not TC.example_program.exists():
                    raise Exception('Could not find the example program.')
        else:
            # Linux and macOS can use the LD_LIBRARY_PATH environment variable to find libclamav
            TC.example_program = TC.path_build / 'examples' / program_name
            if not TC.example_program.exists():
                # Try the static version.
                TC.example_program = TC.path_build / 'examples' / program_name + '_static'
                if not TC.example_program.exists():
                    raise Exception('Could not find the example program.')

        # Copy the test cvd to the temp directory
        shutil.copyfile(
            str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cvd'),
            str(TC.path_tmp / 'verify_good.cvd')
        )
        shutil.copyfile(
            str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cvd.sign'),
            str(TC.path_tmp / 'verify_good-2.cvd.sign')
        )

        # Also get a corrupted version of the cvd
        shutil.copyfile(
            str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cvd'),
            str(TC.path_tmp / 'verify_bad.cvd')
        )
        shutil.copyfile(
            str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cvd.sign'),
            str(TC.path_tmp / 'verify_bad-2.cvd.sign')
        )
        with open(str(TC.path_tmp / 'verify_bad.cvd'), 'r+b') as f:
            f.seek(0, os.SEEK_END)
            f.write(b'egad bad cvd')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_cl_cvdunpack_verify_success(self):
        self.step_name('test with good cvd, verify extraction')

        # Make temp directory to store extracted stuffs
        (TC.path_tmp / 'verify_good').mkdir(parents=True)

        command = '{valgrind} {valgrind_args} {example} {database} {tmp}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=TC.path_tmp / 'verify_good.cvd',
            tmp=TC.path_tmp / 'verify_good'
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success
        for each in (TC.path_tmp / 'verify_good').iterdir():
            if each.name == 'test.info':
                return
        # could not find test.info
        assert False

    def test_cl_cvdunpack_verify_failure(self):
        self.step_name('test with bad cvd, verify failure')

        # Make temp directory to store extracted stuffs
        (TC.path_tmp / 'verify_bad').mkdir(parents=True)

        command = '{valgrind} {valgrind_args} {example} {database} {tmp}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=TC.path_tmp / 'verify_bad.cvd',
            tmp=TC.path_tmp / 'verify_bad'
        )
        output = self.execute_command(command)

        assert output.ec != 0  # success
        for each in (TC.path_tmp / 'verify_bad').iterdir():
            if each.name == 'test.info':
                # found test.info
                assert False

        expected_results = [
            'ERROR: Can\'t verify database integrity',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_cl_cvdunpack_noverify(self):
        self.step_name('test with bad cvd, use --no-verify')

        # Make temp directory to store extracted stuffs
        (TC.path_tmp / 'no_verify_bad').mkdir(parents=True)

        command = '{valgrind} {valgrind_args} {example} --no-verify {database} {tmp}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=TC.path_tmp / 'verify_bad.cvd',
            tmp=TC.path_tmp / 'no_verify_bad'
        )
        output = self.execute_command(command)

        # In this case, because we just tacked on bytes at the end, it will
        # probably still extract at least some stuff.
        assert output.ec == 0  # success
        for each in (TC.path_tmp / 'no_verify_bad').iterdir():
            if each.name == 'test.info':
                return
        # could not find test.info
        assert False
