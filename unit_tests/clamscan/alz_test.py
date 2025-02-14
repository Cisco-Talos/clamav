# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import sys

sys.path.append('../unit_tests')
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

    def test_deflate(self):
        self.step_name('Test alz files compressed with deflate (gzip)')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'deflate.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_bzip2(self):
        self.step_name('Test alz files compressed with bzip2')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'bzip2.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_bzip2_with_binary(self):
        self.step_name('Test alz files compressed with bzip2')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'bzip2.bin.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE_EXECUTABLE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_uncompressed(self):
        self.step_name('Test alz files with no compression')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'uncompressed.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_uncompressed_with_binary(self):
        self.step_name('Test alz files with no compression with binary data')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'uncompressed.bin.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE_EXECUTABLE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)
