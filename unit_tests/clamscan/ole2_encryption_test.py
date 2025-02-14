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

    def test_FAT_doc(self):
        self.step_name('Test FAT doc')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.doc'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_doc_metadata(self):
        self.step_name('Test FAT doc')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.doc'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_doc(self):
        self.step_name('Test ministream doc')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.doc'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_doc_metadata(self):
        self.step_name('Test ministream doc')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.doc'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)


    def test_FAT_docx(self):
        self.step_name('Test FAT docx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.docx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_docx_metadata(self):
        self.step_name('Test FAT docx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.docx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_docx(self):
        self.step_name('Test ministream docx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.docx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_docx_metadata(self):
        self.step_name('Test ministream docx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.docx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_FAT_dot(self):
        self.step_name('Test FAT dot')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.dot'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_dot_metadata(self):
        self.step_name('Test FAT dot')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.dot'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_dot(self):
        self.step_name('Test ministream dot')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.dot'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_dot_metadata(self):
        self.step_name('Test ministream dot')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.dot'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_FAT_ppsx(self):
        self.step_name('Test FAT ppsx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.ppsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_ppsx_metadata(self):
        self.step_name('Test FAT ppsx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.ppsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_ppsx(self):
        self.step_name('Test ministream ppsx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.ppsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_ppsx_metadata(self):
        self.step_name('Test ministream ppsx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.ppsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_FAT_pptx(self):
        self.step_name('Test FAT pptx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.pptx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_pptx_metadata(self):
        self.step_name('Test FAT pptx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.pptx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_pptx(self):
        self.step_name('Test ministream pptx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.pptx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_pptx_metadata(self):
        self.step_name('Test ministream pptx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.pptx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_FAT_xls(self):
        self.step_name('Test FAT xls')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_xls_metadata(self):
        self.step_name('Test FAT xls')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"RC4"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_xls(self):
        self.step_name('Test ministream xls')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_xls_metadata(self):
        self.step_name('Test ministream xls')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"RC4"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_FAT_xlsx(self):
        self.step_name('Test FAT xlsx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.xlsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_FAT_xlsx_metadata(self):
        self.step_name('Test FAT xlsx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.fat.xlsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)

    def test_ministream_xlsx(self):
        self.step_name('Test ministream xlsx')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.xlsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Encrypted.OLE2 FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ministream_xlsx_metadata(self):
        self.step_name('Test ministream xlsx')

        tempdir=self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir);

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'ole2_encryption' / 'password.ministream.xlsx'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --gen-json --leave-temps --tempdir={tempdir} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            tempdir=tempdir,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # clean

        expected_strings = [ '"Encrypted":"ENCRYPTION_TYPE_UNKNOWN"' ]
        self.verify_metadata_json(tempdir, expected_strings)
