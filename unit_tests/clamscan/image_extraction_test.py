# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import os
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

    def test_xls_jpeg_png(self):
        self.step_name('Test that clamav can successfully extract jpeg and png images from XLS documents')
        # Note: we aren't testing BMP, TIFF, or GIF because excel converts them to PNG when you try to insert them.

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'has_png_and_jpeg.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # no virus, no failures

        expected_results = [
            'Recognized PNG file',
            'Recognized JPEG file',
            '"FileMD5":"41e64a9ddb49690f0b6fbbd71362b1b3"',
            '"FileMD5":"5341e0efde53a50c416b2352263e7693"',
        ]
        self.verify_output(output.err, expected=expected_results)

    def test_xls_with_detection(self):
        self.step_name('Test that clamav can successfully alert on PNG image extracted from XLS documents')
        # This tests a regression wherein extracted images weren't properly scanned, or the scan result recorded.
        # Note: we aren't testing the JPEG detection because the JPEG attached to the sample XLS is not properly fuzzy-hashed by clamav, yet.
        # TODO: Once it is working, add the JPEG detection test.

        os.mkdir(str(TC.path_tmp / 'xls-jpeg-detection-sigs'))

        (TC.path_tmp / 'logo.png.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#ea0f85d0de719887#0\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'has_png_and_jpeg.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'logo.png.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stderr = [
            'Recognized PNG file',
            'Recognized JPEG file',
            '"FileMD5":"41e64a9ddb49690f0b6fbbd71362b1b3"',
            '"FileMD5":"5341e0efde53a50c416b2352263e7693"',
        ]
        self.verify_output(output.err, expected=expected_stderr)

        expected_stdout = [
            'has_png_and_jpeg.xls: logo.png.good.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout)
