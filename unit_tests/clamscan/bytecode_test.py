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

    def test_pdf_hook(self):
        self.step_name('Test that pdf bytecode hooks trigger')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --bytecode-unsigned'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'bytecode_sigs' / 'pdf-hook.cbc',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.Case.BC.PDF.hook FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)
