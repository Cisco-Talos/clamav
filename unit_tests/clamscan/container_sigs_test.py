# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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

    def test_clamscan_container_cache(self):
        self.step_name('Test that near-matches for container sigs are not cached')
        # Files should not be cached as "clean" if the container sig is a near-match
        # and only fails because the container requirement is not met.
        # This is a regression test for a bug where a file was cached as "clean" and
        # then later when scanned within a container it was not detected.

        not_eicar_file = TC.path_tmp / 'not_eicar'
        if not not_eicar_file.exists():
            with not_eicar_file.open('wb') as f:
                f.write(b"CLAMAV-TEST-STRING-NOT-EICAR")

        not_eicar_zip = TC.path_tmp / 'not_eicar.zip'
        if not not_eicar_zip.exists():
            with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
                zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        (TC.path_tmp / 'zip_container.ldb').write_text(
            "LDB.Clamav-Unit-Test-Signature-Container;Engine:81-255,Container:CL_TYPE_ZIP,Target:0;0;0:434c414d41562d544553542d535452494e472d4e4f542d4549434152\n"
        )

        testfiles = '{} {}'.format(not_eicar_file, not_eicar_zip)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'zip_container.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'not_eicar: OK',
            'not_eicar.zip: LDB.Clamav-Unit-Test-Signature-Container.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'not_eicar: LDB.Clamav-Unit-Test-Signature-Container.UNOFFICIAL FOUND',
            'not_eicar.zip: OK',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_intermediates_cache(self):
        self.step_name('Test that near-matches for intermediates sigs are not cached')
        # Files should not be cached as "clean" if the intermediates sig is a near-match
        # and only fails because the intermediates requirement is not met.
        # This is a regression test for a bug where a file was cached as "clean" and
        # then later when scanned within a container it was not detected.

        not_eicar_file = TC.path_tmp / 'not_eicar'
        if not not_eicar_file.exists():
            with not_eicar_file.open('wb') as f:
                f.write(b"CLAMAV-TEST-STRING-NOT-EICAR")

        not_eicar_zip = TC.path_tmp / 'not_eicar.zip'
        if not not_eicar_zip.exists():
            with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
                zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        (TC.path_tmp / 'zip_intermediates.ldb').write_text(
            "LDB.Clamav-Unit-Test-Signature-Intermediates;Engine:81-255,Intermediates:CL_TYPE_ZIP,Target:0;0;0:434c414d41562d544553542d535452494e472d4e4f542d4549434152\n"
        )

        testfiles = '{} {}'.format(not_eicar_file, not_eicar_zip)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'zip_intermediates.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'not_eicar: OK',
            'not_eicar.zip: LDB.Clamav-Unit-Test-Signature-Intermediates.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'not_eicar: LDB.Clamav-Unit-Test-Signature-Intermediates.UNOFFICIAL FOUND',
            'not_eicar.zip: OK',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)
