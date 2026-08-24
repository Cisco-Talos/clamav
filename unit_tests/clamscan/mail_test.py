# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Run clamscan mail parser tests."""

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

    def test_content_disposition_unquoted_escaped_semicolon(self):
        self.step_name('Test escaped semicolon in an unquoted attachment filename')

        testfile = (
            TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' /
            'clam.mail-content-disposition-escaped-semicolon.eml'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --gen-json --debug'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found, no failures
        self.verify_output(
            output.out,
            expected=[
                'clam.mail-content-disposition-escaped-semicolon.eml: '
                'ClamAV-Test-File.UNOFFICIAL FOUND',
            ],
        )
        self.verify_output(
            output.err,
            expected=[r'"Filename":"foo\\\\;bar\.exe"'],
        )
