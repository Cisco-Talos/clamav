# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import os
from zipfile import ZIP_DEFLATED, ZipFile
import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        # Prepare a directory to store our test databases
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)

        (TC.path_db / 'clam.ndb').write_text(
            "Test.NDB:0:*:4b45524e454c33322e444c4c00004578\n"
        )
        (TC.path_db / 'clam.ldb').write_text(
            "Test.LDB;Engine:52-255,Target:1;0;4B45524E454C33322E444C4C00004578697450726F63657373005553455233322E444C4C00434C414D657373616765426F7841\n"
        )
        (TC.path_db / 'clam.hdb').write_text(
            "aa15bcf478d165efd2065190eb473bcb:544:Test.MD5.Hash:73\n"
            "aa15bcf478d165efd2065190eb473bcb:*:Test.MD5.Hash.NoSize:73\n"
        )
        (TC.path_db / 'clam.hsb').write_text(
            "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:544:Test.Sha256.Hash:73\n"
            "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:Test.Sha256.Hash.NoSize:73\n"
            "62dd70f5e7530e0239901ac186f1f9ae39292561:544:Test.Sha1.Hash:73\n"
            "62dd70f5e7530e0239901ac186f1f9ae39292561:*:Test.Sha1.NoSize:73\n"
        )
        (TC.path_db / 'clam.imp').write_text(
            "98c88d882f01a3f6ac1e5f7dfd761624:39:Test.Import.Hash\n"
            "98c88d882f01a3f6ac1e5f7dfd761624:*:Test.Import.Hash.NoSize\n"
        )
        (TC.path_db / 'clam.mdb').write_text(
            "512:23db1dd3f77fae25610b6a32701313ae:Test.PESection.Hash:73\n"
            "*:23db1dd3f77fae25610b6a32701313ae:Test.PESection.Hash.NoSize:73\n"
        )

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_many_sigs(self):
        self.step_name('Test that each type of sig alerts in all-match mode')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.LDB.UNOFFICIAL FOUND',
            'Test.NDB.UNOFFICIAL FOUND',
            'Test.MD5.Hash.UNOFFICIAL FOUND',
            'Test.MD5.Hash.NoSize.UNOFFICIAL FOUND',
            'Test.Sha1.Hash.UNOFFICIAL FOUND',
            'Test.Sha1.NoSize.UNOFFICIAL FOUND',
            'Test.Sha256.Hash.UNOFFICIAL FOUND',
            'Test.Sha256.Hash.NoSize.UNOFFICIAL FOUND',
            'Test.PESection.Hash.UNOFFICIAL FOUND',
            'Test.PESection.Hash.NoSize.UNOFFICIAL FOUND',
            'Test.Import.Hash.UNOFFICIAL FOUND',
            'Test.Import.Hash.NoSize.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_many_sigs_no_allmatch(self):
        self.step_name('Test that only one sig alerts when not using all-match mode')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        assert output.out.count('FOUND') == 1 # only finds one of these (order not guaranteeds afaik, so don't care which)

    def test_regression_imphash_nosize(self):
        self.step_name('Test an import hash with wildcard size when all-match mode is disabled.')

        db_dir = TC.path_db / 'allmatch-regression-test-sigs'

        os.mkdir(str(db_dir))

        (db_dir / 'clam.imp').write_text(
            "98c88d882f01a3f6ac1e5f7dfd761624:*:Test.Import.Hash.NoSize\n"
        )

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=db_dir / 'clam.imp',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.Import.Hash.NoSize.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_regression_cbc_and_ndb(self):
        self.step_name('Test that bytecode rules will run after content match alerts in all-match mode.')

        # Source for ClamAV-Unit-Test_Signature.cbc
        # ```c
        # VIRUSNAME_PREFIX("BC.Clamav-Unit-Test-Signature")
        # VIRUSNAMES("")
        # TARGET(0)

        # FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_096_4)

        # SIGNATURES_DECL_BEGIN
        # DECLARE_SIGNATURE(test_string)
        # SIGNATURES_DECL_END

        # SIGNATURES_DEF_BEGIN
        # /* matches "CLAMAV-TEST-STRING-NOT-EICAR" */
        # DEFINE_SIGNATURE(test_string, "0:434c414d41562d544553542d535452494e472d4e4f542d4549434152")
        # SIGNATURES_DEF_END

        # bool logical_trigger()
        # {
        #     return matches(Signatures.test_string);
        # }

        # int entrypoint(void)
        # {
        #     foundVirus("");
        #     return 0;
        # }
        # ```

        testfile = TC.path_tmp / 'CLAMAV-TEST-STRING-NOT-EICAR'

        (testfile).write_text(
            "CLAMAV-TEST-STRING-NOT-EICAR"
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {cbc_db} -d {ndb_db} --bytecode-unsigned --allmatch {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            cbc_db=TC.path_source / 'unit_tests' / 'input' / 'bytecode_sigs' / 'Clamav-Unit-Test-Signature.cbc',
            ndb_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'BC.Clamav-Unit-Test-Signature FOUND', # <-- ".UNOFFICIAL" is not added for bytecode signatures
            'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_txt_plus_clam_zipsfx(self):
        self.step_name('Test that clam will detect a string in text file, plus identify, extract, and alert on concatenated clam.zip containing clam.exe with a hash sig.')

        testfile = TC.path_tmp / 'test-string-cat-clam.exe.txt'

        clamzip = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip'

        testfile.write_bytes(b"CLAMAV-TEST-STRING-NOT-EICAR" + clamzip.read_bytes())

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} -d {not_eicar_db} --allmatch {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
            not_eicar_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ClamAV-Test-File.UNOFFICIAL FOUND',
            'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_exe_imphash_plus_zipsfx(self):
        self.step_name('Test that clam will detect a string in text file, plus identify, extract, and alert on concatenated clam.zip containing clam.exe with an imp-hash sig.')

        # We can't use the hash sig for this clam.exe program because the hash goes out the window when we concatenate on the zip.
        (TC.path_tmp / 'clam.imp').write_text(
            "98c88d882f01a3f6ac1e5f7dfd761624:39:Test.Import.Hash\n"
        )

        # Build a file that is the clam.exe program with a zip concatinated on that contains the not_eicar test string file.
        clam_exe = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        not_eicar_zip = TC.path_tmp / 'not-eicar.zip'
        with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
            zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        testfile = TC.path_tmp / 'clam.exe.not_eicar.zipsfx'
        testfile.write_bytes(clam_exe.read_bytes() + not_eicar_zip.read_bytes())

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} -d {not_eicar_db} --allmatch {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'clam.imp',
            not_eicar_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.Import.Hash.UNOFFICIAL FOUND',
            'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_exe_pattern_plus_zipsfx(self):
        self.step_name('Test that clam will detect a string in text file, plus identify, extract, and alert on concatenated clam.zip containing clam.exe with a pattern-match sig.')
        # This tests a regression where clam will fail to extract the embedded zip file if the pattern-match sig matches before the embedded file type sig.

        # Build a file that is the clam.exe program with a zip concatinated on that contains the not_eicar test string file.
        clam_exe = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        not_eicar_zip = TC.path_tmp / 'not-eicar.zip'
        with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
            zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        testfile = TC.path_tmp / 'clam.exe.not_eicar.zipsfx'
        testfile.write_bytes(clam_exe.read_bytes() + not_eicar_zip.read_bytes())

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} -d {not_eicar_db} --allmatch {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            # We can't use the hash sig for this clam.exe program because the hash goes out the window when we concatenate on the zip.
            clam_exe_db=TC.path_db / 'clam.ndb',
            not_eicar_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.NDB.UNOFFICIAL FOUND',
            'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_pe_allmatch(self):
        self.step_name('Test that clam will detect a string in test.exe with a wide variety of signatures written or generated for the file.')

        # The sig set and test.exe for test set was written by one of our threat researchers to test the allmatch option.
        # Overall, it's much more thorough than previous tests, but some of the tests are duplicates of the previous tests.

        # TODO: The section signatures are not working as written, hence the "broken_dbs" directory.
        #       There is a known issue with relative offset signatures when using the Boyer-Moore matcher. The sigs work if using the Aho-Corasick matcher.
        #       When we fix section signatures, we can move them to the alerting sigs directory and update this test.

        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'
        test_exe = test_path / 'test.exe'

        command = '{valgrind} {valgrind_args} {clamscan} \
             -d {alerting_dbs} \
             -d {weak_dbs} \
             --allmatch --bytecode-unsigned {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            alerting_dbs=test_path / 'alert-sigs',
            weak_dbs=test_path / 'weak-sigs',
            testfiles=test_exe,
        )
        output = self.execute_command(command)

        assert output.ec == 1

        # The alert sig files are all given the signature name, so we can verify that the correct sigs were found.
        # We need only to trim off the extension and say "FOUND" for the alerting sigs.
        # Note: Some of these have ".UNOFFICIAL" in the name because not all of them have that ".UNOFFICIAL" suffix when reported.
        #       I think this is a minor bug. So if we change that, we'll need to update this test.
        expected_results = ['{sig} FOUND'.format(sig=f.stem) for f in (test_path / 'alert-sigs').iterdir()]

        self.verify_output(output.out, expected=expected_results)
