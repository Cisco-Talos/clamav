# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_yara(self):
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

    def test_slash_colon(self):
        self.step_name('Test LDB and Yara regex rules with / and : in the string work')
        # This is a regression test for a bug where :'s in a PCRE regex would act
        # as delimiters if there was also a / in the regex before the :

        testfile = TC.path_tmp / 'regex-slash-colon.sample'
        testfile.write_text('hello blee/blah: bleh')

        # First test with LDB PCRE rule
        #
        yara_db = TC.path_tmp / 'regex-slash-colon.ldb'
        yara_db.write_text(
            r'regex;Engine:81-255,Target:0;1;68656c6c6f20;0/hello blee\/blah: bleh/'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'regex-slash-colon.sample: regex.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]
        self.verify_output(output.out, expected=expected_results)

        # Second test with YARA regex rule
        #
        yara_db = TC.path_tmp / 'regex-slash-colon.yara'
        yara_db.write_text(
            r'''
rule regex
{
    meta:
        author      = "Micah"
        date        = "2022/07/25"
        description = "Just a test"
    strings:
        $b = /hello blee\/blah: bleh/
    condition:
        all of them
}
            '''
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'regex-slash-colon.sample: YARA.regex.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_ldb_offset_pcre(self):
        self.step_name('Test LDB regex rules with an offset')
        # The offset feature starts the match some # of bytes after start of the pattern match
        # The offset is EXACT, meaning it's no longer wildcard.
        # The match must occur exactly that number of bytes from the start of the file.

        # using 'MZ' prefix so it is detected as MSEXE and not TEXT. This is to avoid normalization.
        testfile = TC.path_tmp / 'ldb_offset_pcre'
        testfile.write_text('MZ hello blee')

        # First without the offset, make sure it matches
        yara_db = TC.path_tmp / 'ldb_pcre_no_offset.ldb'
        yara_db.write_text(
            r'ldb_pcre_no_offset;Engine:81-255,Target:0;0&1;68656c6c6f20;0/hello blee/'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'ldb_offset_pcre: ldb_pcre_no_offset.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]

        # Next, with the offset, but it won't match, because the regex pattern is "hello blee"
        # and with the offset of 5 (from start of file) means it should start the pcre matching at "llo blee"
        yara_db = TC.path_tmp / 'ldb_pcre_offset_no_match.ldb'
        yara_db.write_text(
            r'ldb_pcre_offset_no_match;Engine:81-255,Target:0;0&1;68656c6c6f20;5:0/hello blee/'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'ldb_offset_pcre: OK',
        ]

        # Next, with the offset, and it SHOULD match, because the regex pattern is "llo blee"
        # and with the offset of 5 (from start of file) means it should start the pcre matching at "llo blee"
        yara_db = TC.path_tmp / 'ldb_pcre_offset_match.ldb'
        yara_db.write_text(
            r'ldb_pcre_offset_match;Engine:81-255,Target:0;0&1;68656c6c6f20;5:0/llo blee/'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'ldb_offset_pcre: ldb_pcre_offset_match.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]

    def test_pcre_flag(self):
        self.step_name('Test LDB regex rules with case insensitive flag')
        # This test validates that the flags field is, and more specifically the case-insensitive flag is working.

        # using 'MZ' prefix so it is detected as MSEXE and not TEXT. This is to avoid normalization.
        testfile = TC.path_tmp / 'ldb_pcre_flag'
        testfile.write_text('MZ hello blee / BlAh')

        # First test withOUT the case-insensitive flag. It should NOT match.
        yara_db = TC.path_tmp / 'ldb_pcre_case.ldb'
        yara_db.write_text(
            r'ldb_pcre_case;Engine:81-255,Target:0;0&1;68656c6c6f20;0/blah/'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'ldb_pcre_flag: OK',
        ]

        # First test WITH the case-insensitive flag. It SHOULD match.
        yara_db = TC.path_tmp / 'ldb_pcre_nocase.ldb'
        yara_db.write_text(
            r'ldb_pcre_nocase;Engine:81-255,Target:0;0&1;68656c6c6f20;0/blah/i'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'ldb_pcre_flag: ldb_pcre_nocase.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]

    def test_ldb_multi_pcre(self):
        self.step_name('Test LDB and Yara regex rules with / and : in the string work')
        # This is a regression test for a bug where :'s in a PCRE regex would act
        # as delimiters if there was also a / in the regex before the :

        # using 'MZ' prefix so it is detected as MSEXE and not TEXT. This is to avoid normalization.
        testfile = TC.path_tmp / 'ldb_multi_pcre'
        testfile.write_text('MZ hello blee / BlAh')

        # Verify first with two subsigs that should match, that the alert has found.
        yara_db = TC.path_tmp / 'ldb_multi_pcre.ldb'
        yara_db.write_text(
            r'ldb_multi_pcre;Engine:81-255,Target:0;0&1&2;68656c6c6f20;0/hello blee/;0/blah/i'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'ldb_multi_pcre: ldb_multi_pcre.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]

        # Verify next that if one of the two subsigs do not match, the whole thing does not match.
        yara_db = TC.path_tmp / 'ldb_multi_pcre.ldb'
        yara_db.write_text(
            r'ldb_multi_pcre;Engine:81-255,Target:0;0&1&2;68656c6c6f20;0/hello blee/;0/bloh/i'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'ldb_multi_pcre: OK',
            'Infected files: 0',
        ]

        # Verify next that if the other of the two subsigs do not match, the whole thing does not match.
        yara_db = TC.path_tmp / 'ldb_multi_pcre.ldb'
        yara_db.write_text(
            r'ldb_multi_pcre;Engine:81-255,Target:0;0&1&2;68656c6c6f20;0/hella blee/;0/blah/i'
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan, path_db=yara_db, testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus NOT found

        expected_results = [
            'ldb_multi_pcre: OK',
            'Infected files: 0',
        ]
