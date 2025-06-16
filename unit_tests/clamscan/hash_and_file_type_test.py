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

        # Testing with our logo png file.
        TC.testfiles = TC.path_source / 'logo.png'

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    #
    # First check with the good database in all-match mode.
    #

    def test_log_hash(self):
        self.step_name('Test that the --log-hash option adds the FileHash output.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # First try with --log-hash enabled to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Then try without --log-hash enabled to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = []
        unexpected_stdout = [
            'FileHash:',
            r'\(sha2-256\)',
            r'\(sha1\)',
            r'\(md5\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Now add the --hash-alg option to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-alg sha1'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: da5b226552d19b5c1c3277d28a776162e568222c \(sha1\)',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)


    def test_hash_hint(self):
        self.step_name('Test that the --hash-hint option can be used to supply the file hash.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # Use --hash-hint to feed clamscan a different hash for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 0000000000000000000000000000000000000000000000000000000000000123'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: 0000000000000000000000000000000000000000000000000000000000000123 \(sha2-256\)',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Combine this with --hash-alg to change a different hash algorithm.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-alg sha1 --hash-hint 0000000000000000000000000000000000000123'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: 0000000000000000000000000000000000000123 \(sha1\)',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
            r'logo.png FileHash: da5b226552d19b5c1c3277d28a776162e568222c \(sha1\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it a smaller hash than expected fails gracefully.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 012345'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stdout = [
            'Invalid argument passed to function ERROR',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: 012345 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it a bigger hash than expected fails gracefully.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stdout = [
            'Invalid argument passed to function ERROR',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)


    def test_file_type_hint(self):
        self.step_name('Test that the --file-type-hint option can be used to supply the file type.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # Don't provide a hint. Just use --log-file-type and verify that clamav gives the correct file type.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Don't use the new options. Verify that it does not output the file type.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = []
        unexpected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Use --file-type-hint to feed clamscan a different file type for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint JPEG'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_JPEG',
        ]
        unexpected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Use --file-type-hint to feed clamscan the real file type for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint png'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it an unknown file type properly ignores the hint and determines the file type itself.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint faketype'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = [
            'logo.png FileType: faketype',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)
