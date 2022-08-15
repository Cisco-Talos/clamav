# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest
from zipfile import ZIP_DEFLATED, ZipFile

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

        # Prepare a directory to store our test databases
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)

        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )

        (TC.path_db / 'clamav.ign2').write_text('ClamAV-Test-File\n')

        (TC.path_db / 'phish.pdb').write_text('H:example.com\n')

        (TC.path_db / 'icon.idb').write_text(
            "EA0X-32x32x8:ea0x-grp1:ea0x-grp2:2046f030a42a07153f4120a0031600007000005e1617ef0000d21100cb090674150f880313970b0e7716116d01136216022500002f0a173700081a004a0e\n"
            "IScab-16x16x8:iscab-grp1:iscab-grp2:107b3000168306015c20a0105b07060be0a0b11c050bea0706cb0a0bbb060b6f00017c06018301068109086b03046705081b000a270a002a000039002b17\n"
        )
        (TC.path_db / 'icon.ldb').write_text(
            "ClamAV-Test-Icon-EA0X;Engine:52-1000,Target:1,IconGroup1:ea0x-grp1,IconGroup2:*;(0);0:4d5a\n"
            "ClamAV-Test-Icon-IScab;Engine:52-1000,Target:1,IconGroup2:iscab-grp2;(0);0:4d5a\n"
        )
        (TC.path_db / 'Clam-VI.ldb').write_text(
            "Clam-VI-Test:Target;Engine:52-255,Target:1;(0&1);VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00\n"
        )
        (TC.path_db / 'yara-at-offset.yara').write_text(
            "rule yara_at_offset {strings: $tar_magic = { 75 73 74 61 72 } condition: $tar_magic at 257}\n"
        )
        (TC.path_db / 'yara-in-range.yara').write_text(
            "rule yara_in_range {strings: $tar_magic = { 75 73 74 61 72 } condition: $tar_magic in (200..300)}\n"
        )

        # Signatures for detecting clam.exe
        TC.path_clam_exe_sigs = TC.path_db / 'clam-exe-test-sigs'

        os.mkdir(str(TC.path_clam_exe_sigs))

        (TC.path_clam_exe_sigs / 'clam.ndb').write_text(
            "Test.NDB:0:*:4b45524e454c33322e444c4c00004578\n"
        )
        (TC.path_clam_exe_sigs / 'clam.ldb').write_text(
            "Test.LDB;Engine:52-255,Target:1;0;4B45524E454C33322E444C4C00004578697450726F63657373005553455233322E444C4C00434C414D657373616765426F7841\n"
        )
        (TC.path_clam_exe_sigs / 'clam.hdb').write_text(
            "aa15bcf478d165efd2065190eb473bcb:544:Test.MD5.Hash:73\n"
            "aa15bcf478d165efd2065190eb473bcb:*:Test.MD5.Hash.NoSize:73\n"
        )
        (TC.path_clam_exe_sigs / 'clam.hsb').write_text(
            "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:544:Test.Sha256.Hash:73\n"
            "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:Test.Sha256.Hash.NoSize:73\n"
            "62dd70f5e7530e0239901ac186f1f9ae39292561:544:Test.Sha1.Hash:73\n"
            "62dd70f5e7530e0239901ac186f1f9ae39292561:*:Test.Sha1.NoSize:73\n"
        )
        (TC.path_clam_exe_sigs / 'clam.imp').write_text(
            "98c88d882f01a3f6ac1e5f7dfd761624:39:Test.Import.Hash\n"
            "98c88d882f01a3f6ac1e5f7dfd761624:*:Test.Import.Hash.NoSize\n"
        )
        (TC.path_clam_exe_sigs / 'clam.mdb').write_text(
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

    def test_clamscan_00_version(self):
        self.step_name('clamscan version test')

        command = '{valgrind} {valgrind_args} {clamscan} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_01_all_testfiles(self):
        self.step_name('Test that clamscan alerts on all test files')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "clamav.hdb", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        expected_results.append('Scanned files: {}'.format(len(TC.testpaths)))
        expected_results.append('Infected files: {}'.format(len(TC.testpaths)))
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_02_all_testfiles_ign2(self):
        self.step_name('Test that clamscan ignores ClamAV-Test-File alerts')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} -d {path_ign_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "clamav.hdb", path_ign_db=TC.path_db / "clamav.ign2", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        expected_results.append('Scanned files: {}'.format(len(TC.testpaths)))
        expected_results.append('Infected files: {}'.format(len(TC.testpaths)))
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_03_phish_test_not_enabled(self):
        self.step_name('Test that clamscan will load the phishing sigs w/out issue')

        testpaths = list(TC.path_source.glob('unit_tests/input/other_scanfiles/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "phish.pdb", path_ign_db=TC.path_db / "clamav.ign2", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'Scanned files: 3',
            'Infected files: 0',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_04_phish_test_alert_phishing_ssl_alert_phishing_cloak(self):
        self.step_name('Test clamscan --alert-phishing-ssl --alert-phishing-cloak')

        testpaths = list(TC.path_source.glob('unit_tests/input/other_scanfiles/phish-test-*'))

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --alert-phishing-ssl --alert-phishing-cloak {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "phish.pdb", testfiles=testfiles,
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

    def test_clamscan_05_icon(self):
        self.step_name('Test icon (.ldb + .idb) signatures')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_ldb} -d {path_idb} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_ldb=TC.path_db / "icon.ldb", path_idb=TC.path_db / "icon.idb", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        # Use check_fpu_endian to determine expected results
        command = '{}'.format(TC.check_fpu_endian)
        fpu_endian_output = self.execute_command(command)

        expected_results = [
            'clam_IScab_ext.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND',
            'clam_IScab_int.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND',
        ]
        if fpu_endian_output.ec == 3:
            expected_num_infected = 3
        else:
            expected_results.append('clam.ea06.exe: ClamAV-Test-Icon-EA0X.UNOFFICIAL FOUND')
            expected_num_infected = 4
        expected_results.append('Infected files: {}'.format(expected_num_infected))
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_06_LDB_VI(self):
        self.step_name('Test LDB VI feature')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "Clam-VI.ldb", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam_ISmsi_ext.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'clam_ISmsi_int.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
            'Infected files: 2',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_07_yara_at_offset(self):
        self.step_name('Test yara signature - detect TAR file magic at an offset')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "yara-at-offset.yara", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_at_offset.UNOFFICIAL FOUND',
            'Infected files: 3',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_08_yara_in_range(self):
        self.step_name('Test yara signature - detect TAR file magic in a range')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=TC.path_db / "yara-in-range.yara", testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'clam.tar.gz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'clam_cache_emax.tgz: YARA.yara_in_range.UNOFFICIAL FOUND',
            'Infected files: 3',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_09_xls_jpeg_png_extraction(self):
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

    def test_clamscan_10_bytecode_pdf_hook(self):
        self.step_name('Test that pdf bytecode hooks trigger')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.pdf'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --bytecode-unsigned'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'bytecode_sigs' / 'pdf-hook.cbc',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.Case.BC.PDF.hook FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_11_allmatch_many_sigs(self):
        self.step_name('Test that each type of sig alerts in all-match mode')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_clam_exe_sigs,
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

    def test_clamscan_11_no_allmatch_many_sigs(self):
        self.step_name('Test that only one sig alerts when not using all-match mode')

        testfiles = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_clam_exe_sigs,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        assert output.out.count('FOUND') == 1 # only finds one of these (order not guaranteeds afaik, so don't care which)

    def test_clamscan_11_allmatch_regression_imphash_nosize(self):
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

    def test_clamscan_11_allmatch_regression_cbc_and_ndb(self):
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

    def test_clamscan_11_allmatch_txt_plus_clam_zipsfx(self):
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

    def test_clamscan_11_allmatch_clam_exe_imphash_plus_not_eicar_zipsfx(self):
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

    def test_clamscan_11_allmatch_clam_exe_pattern_plus_not_eicar_zipsfx(self):
        self.step_name('Test that clam will detect a string in text file, plus identify, extract, and alert on concatenated clam.zip containing clam.exe with a pattern-match sig.')
        # This tests a regression where clam will fail to extract the embedded zip file if the pattern-match sig matches before the embedded file type sig.

        # We can't use the hash sig for this clam.exe program because the hash goes out the window when we concatenate on the zip.
        (TC.path_tmp / 'clam.ndb').write_text(
            "Test.Pattern.Match:0:*:4b45524e454c33322e444c4c00004578\n"
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
            clam_exe_db=TC.path_tmp / 'clam.ndb',
            not_eicar_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.Pattern.Match.UNOFFICIAL FOUND',
            'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_12_image_fuzzy_hash_sigs(self):
        self.step_name('Test that each type of hash sig is detected in all-match mode')

        os.mkdir(str(TC.path_db / 'image-fuzzy-hash-test-sigs'))

        (TC.path_db / 'image-fuzzy-hash-test-sigs' / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
            "logo.png.bad.with.second.subsig;Engine:150-255,Target:0;0&1;deadbeef;fuzzy_img#af2ad01ed42993c7#0\n"
            "logo.png.good.with.second.subsig;Engine:150-255,Target:0;0&1;49484452;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        testfiles = TC.path_source / 'logo.png'

        #
        # First check with the good database in all-match mode.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / 'image-fuzzy-hash-test-sigs' / 'good.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_stdout = [
            'logo.png.good.UNOFFICIAL FOUND',
            'logo.png.good.with.second.subsig.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'logo.png.bad.with.second.subsig.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout)

        #
        # Next check with the bad signatures
        #

        # Invalid hash
        (TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-hash.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_img#abcdef#0\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-hash.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stderr = [
            'LibClamAV Error: Failed to load',
            'Invalid hash: Image fuzzy hash must be 16 characters in length: abcdef',
        ]
        unexpected_stdout = [
            'logo.png.bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.err, expected=expected_stderr)
        self.verify_output(output.out, unexpected=unexpected_stdout)

        # Unsupported hamming distance
        (TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-ham.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#1\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-ham.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stderr = [
            'LibClamAV Error: Failed to load',
            'Invalid hamming distance: 1',
        ]
        unexpected_stdout = [
            'logo.png.bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.err, expected=expected_stderr)
        self.verify_output(output.out, unexpected=unexpected_stdout)

        # invalid algorithm
        (TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-alg.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_imgy#af2ad01ed42993c7#0\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / 'image-fuzzy-hash-test-sigs' / 'invalid-alg.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stderr = [
            'cli_loadldb: failed to parse subsignature 0 in logo.png',
        ]
        unexpected_stdout = [
            'logo.png.bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.err, expected=expected_stderr)
        self.verify_output(output.out, unexpected=unexpected_stdout)

    def test_clamscan_13_yara_regex(self):
        self.step_name('Test yara signature - detect TAR file magic in a range')

        db = TC.path_tmp / 'regex.yara'
        db.write_text(
            r'''
rule regex
{
    meta:
        author      = "Micah"
        date        = "2022/03/12"
        description = "Just a test"
    strings:
        $a = "/+eat/"                 /* <-- not a regex */
        $b = /\$protein+=\([a-z]+\)/  /* <-- is a regex */
    condition:
        all of them
}
            '''
        )
        testfile = TC.path_tmp / 'regex.sample'
        testfile.write_text('var $protein=(slugs); /+eat/ $protein')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'regex.sample: YARA.regex.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamscan_14_xls_jpeg_detection(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        os.mkdir(str(TC.path_db / 'xls-jpeg-detection-sigs'))

        (TC.path_db / 'image-fuzzy-hash-test-sigs' / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#ea0f85d0de719887#0\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'has_png_and_jpeg.xls'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / 'image-fuzzy-hash-test-sigs' / 'good.ldb',
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

    def test_clamscan_15_container(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        os.mkdir(str(TC.path_db / '7z_zip_container'))

        (TC.path_db / '7z_zip_container' / 'test.ldb').write_text(
            "7z_zip_container_good;Engine:81-255,Container:CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_container_bad;Engine:81-255,Container:CL_TYPE_ZIP,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / '7z_zip_container' / 'test.ldb',
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

    def test_clamscan_16_intermediates(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        os.mkdir(str(TC.path_db / '7z_zip_intermediates'))

        (TC.path_db / '7z_zip_intermediates' / 'test.ldb').write_text(
            "7z_zip_intermediates_good;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_intermediates;Engine:81-255,Intermediates:CL_TYPE_7Z>CL_TYPE_TEXT_ASCII,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_db / '7z_zip_intermediates' / 'test.ldb',
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
