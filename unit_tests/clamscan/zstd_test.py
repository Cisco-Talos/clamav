# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for Zstandard (zstd) compressed files.
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

    def test_zstd(self):
        self.step_name('Test scanning a zstd compressed file')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'zstd' / 'testfile.txt.zst'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'zstd.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ZSTD_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)
