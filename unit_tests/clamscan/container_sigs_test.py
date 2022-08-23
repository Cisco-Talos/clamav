# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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

    def test_container(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        (TC.path_tmp / '7z_zip_container.ldb').write_text(
            "7z_zip_container_good;Engine:81-255,Container:CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_container_bad;Engine:81-255,Container:CL_TYPE_ZIP,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / '7z_zip_container.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_container_good.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_container_bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_intermediates(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        (TC.path_tmp / '7z_zip_intermediates.ldb').write_text(
            "7z_zip_intermediates_good;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_intermediates;Engine:81-255,Intermediates:CL_TYPE_7Z>CL_TYPE_TEXT_ASCII,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / '7z_zip_intermediates.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_intermediates_good.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_intermediates_bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)
