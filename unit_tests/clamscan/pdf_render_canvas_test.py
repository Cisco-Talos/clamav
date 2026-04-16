# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import sys
import os
import shutil
import unittest

sys.path.append('../unit_tests')
import testcase


@unittest.skipUnless(os.getenv("HAVE_PDFIUM") == "1", "requires PDFium support")
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

        if (self.path_tmp / "TD").exists():
            shutil.rmtree(self.path_tmp / "TD")

        self.verify_valgrind_log()

    def test_pdf_render_canvas_valid(self):
        self.step_name('Test valid PDF render canvas option')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'pdf-stats-test.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --scan-pdf-image-fuzzy-hash=no --pdf-render-canvas=1920x1080'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

    def test_pdf_render_canvas_invalid(self):
        self.step_name('Test invalid PDF render canvas option')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'pdf-stats-test.pdf'

        invalid_values = [
            '1920',
            '1920x0',
            'x1080',
        ]

        for invalid_value in invalid_values:
            command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --pdf-render-canvas={invalid_value}'.format(
                valgrind=TC.valgrind,
                valgrind_args=TC.valgrind_args,
                clamscan=TC.clamscan,
                path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
                testfile=testfile,
                invalid_value=invalid_value,
            )
            output = self.execute_command(command)

            assert output.ec == 2  # error
            self.verify_output(
                output.err,
                expected=['--pdf-render-canvas must be in WIDTHxHEIGHT format, for example 1920x1080.'],
            )

    def test_pdf_render_format_valid(self):
        self.step_name('Test valid PDF render format option')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'pdf-stats-test.pdf'

        for image_format in ['png', 'jpeg']:
            command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --scan-pdf-image-fuzzy-hash=no --pdf-render-format={image_format}'.format(
                valgrind=TC.valgrind,
                valgrind_args=TC.valgrind_args,
                clamscan=TC.clamscan,
                path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
                testfile=testfile,
                image_format=image_format,
            )
            output = self.execute_command(command)

            assert output.ec == 0  # clean

    def test_pdf_render_format_invalid(self):
        self.step_name('Test invalid PDF render format option')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'pdf-stats-test.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --pdf-render-format=gif'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error
        self.verify_output(
            output.err,
            expected=['--pdf-render-format must be either png or jpeg.'],
        )

    def test_pdf_render_jpeg_honors_pdf_fuzzy_hash_option(self):
        self.step_name('Test JPEG PDF render honors PDF fuzzy hash option')

        tempdir = self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / 'pdf-stats-test.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile} --scan-pdf-image-fuzzy-hash=yes --scan-image-fuzzy-hash=no --pdf-render-format=jpeg'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [
            '"FileName":"pdf-render-pdf-stats-test.pdf.jpeg"',
            '"Normalized":true',
            '"FileType":"CL_TYPE_JPEG"',
            '"ImageFuzzyHash":{',
        ]
        self.verify_metadata_json(tempdir, expected_strings)
