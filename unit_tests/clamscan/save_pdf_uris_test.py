# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import sys
import os
import re
import shutil

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

        # Remove scan temps directory between tests
        if (self.path_tmp / "TD").exists():
            shutil.rmtree(self.path_tmp / "TD")

        self.verify_valgrind_log()

    def test_save_links(self):
        self.step_name('Extract Links')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'uri-and-ref.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [
            'URIs',
            '"https://docs.clamav.net/manual/Development.html"',
            '"https://docs.clamav.net/"'
        ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_out_of_order_links(self):
        self.step_name('Out-of-Order Links')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'out-of-order.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [
            'URIs',
            '"https://docs.clamav.net/manual/Development.html"',
            '"https://docs.clamav.net/"'
        ]
        self.verify_metadata_json(tempdir, expected_strings)
