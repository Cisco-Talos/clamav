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

        (TC.path_tmp / 'monitor-example-com.pdb').write_text('H:example.com\n')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_not_enabled(self):
        self.step_name('Test that clamscan will load the phishing sigs w/out issue')

        testpaths = list(TC.path_source.glob('unit_tests/input/other_scanfiles/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'monitor-example-com.pdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'Scanned files: 3',
            'Infected files: 0',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ssl_and_cloak(self):
        self.step_name('Test clamscan --alert-phishing-ssl --alert-phishing-cloak')

        testpaths = list(TC.path_source.glob('unit_tests/input/other_scanfiles/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --alert-phishing-ssl --alert-phishing-cloak {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'monitor-example-com.pdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'phish-test-ssl: Heuristics.Phishing.Email.SSL-Spoof FOUND',
            'phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND',
            'Scanned files: 3',
            'Infected files: 2', # there's a clean one
        ]
        self.verify_output(output.out, expected=expected_results)
