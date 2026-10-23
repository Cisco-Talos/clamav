# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import sys
from zipfile import ZIP_DEFLATED, ZipFile

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

    def test_png_trailing_data(self):
        self.step_name('Test that data appended after the PNG IEND chunk is scanned by default')

        # The signature is anchored at offset 0, so it only matches if the trailing data is scanned as its own layer.
        (TC.path_tmp / 'png-trailing-data.ndb').write_text(
            "Test.PNG.TrailingData:0:0:{}\n".format(b'CLAMAV-PNG-TRAILING-DATA-TEST'.hex())
        )
        testfile = TC.path_tmp / 'logo.png.trailing-data'
        testfile.write_bytes((TC.path_source / 'logo.png').read_bytes() + b'CLAMAV-PNG-TRAILING-DATA-TEST')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'png-trailing-data.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_stdout = [
            'logo.png.trailing-data: Test.PNG.TrailingData.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            testcase.CLEAN_SCAN_RESULT,
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_embedded_zips(self):
        self.step_name('Test that clamav can successfully extract and alert on multiple embedded ZIP files')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'signatures'
        testfiles = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'test.png.emb-zips'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'test.png.emb-zips: test-file-1-1.UNOFFICIAL FOUND',
            'test.png.emb-zips: test-file-1-2.UNOFFICIAL FOUND',
            'test.png.emb-zips: test-file-2-1.UNOFFICIAL FOUND',
            'test.png.emb-zips: test-file-2-2.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            testcase.CLEAN_SCAN_RESULT,
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_embedded_arjs(self):
        self.step_name('Test that clamav can successfully extract and alert on multiple embedded ARJ files')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'signatures'
        testfiles = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'test.png.emb-arjs'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'test.png.emb-arjs: test-file-1-1.UNOFFICIAL FOUND',
            'test.png.emb-arjs: test-file-1-2.UNOFFICIAL FOUND',
            'test.png.emb-arjs: test-file-2-1.UNOFFICIAL FOUND',
            'test.png.emb-arjs: test-file-2-2.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            testcase.CLEAN_SCAN_RESULT,
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_embedded_cabs(self):
        self.step_name('Test that clamav can successfully extract and alert on multiple embedded CAB files')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'signatures'
        testfiles = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'test.png.emb-cabs'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'test.png.emb-cabs: test-file-1-1.UNOFFICIAL FOUND',
            'test.png.emb-cabs: test-file-1-2.UNOFFICIAL FOUND',
            'test.png.emb-cabs: test-file-2-1.UNOFFICIAL FOUND',
            'test.png.emb-cabs: test-file-2-2.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            testcase.CLEAN_SCAN_RESULT,
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_embedded_exes(self):
        self.step_name('Test that clamav can successfully extract and alert on multiple embedded EXE files')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'signatures'
        testfiles = TC.path_source / 'unit_tests' / 'input' / 'embedded_testfiles' / 'clam.exe.emb-exes'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'clam.exe.emb-exes: Win.Test.LilEXE.UNOFFICIAL FOUND',
            'clam.exe.emb-exes: Win.Test.SmolEXE.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            testcase.CLEAN_SCAN_RESULT,
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)
