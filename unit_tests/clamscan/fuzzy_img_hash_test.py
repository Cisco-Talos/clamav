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

    def test_sigs_good_allmatch(self):
        self.step_name('Test with a good database in all-match mode.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
            "logo.png.bad.with.second.subsig;Engine:150-255,Target:0;0&1;deadbeef;fuzzy_img#af2ad01ed42993c7#0\n"
            "logo.png.good.with.second.subsig;Engine:150-255,Target:0;0&1;49484452;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
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

        # Try again with image fuzzy hashing disabled to verify the flag will disable this feature (at least for PNG files)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch --scan-image-fuzzy-hash=no'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus

        # Try again with image scanning disabled to verify that the flag disables this feature (at least for PNG files)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch --scan-image=no'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus

    #
    # Next check with the bad signatures
    #

    def test_sigs_bad_hash(self):
        self.step_name('Test Invalid hash')

        # Invalid hash
        (TC.path_tmp / 'invalid-hash.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_img#abcdef#0\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'invalid-hash.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stderr = [
            'LibClamAV Error: Failed to load',
            'Invalid hash: ImageFuzzyHash hash must be 16 characters in length: abcdef',
        ]
        unexpected_stdout = [
            'logo.png.bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.err, expected=expected_stderr)
        self.verify_output(output.out, unexpected=unexpected_stdout)

    def test_sigs_bad_hamming(self):
        self.step_name('Test Unsupported hamming distance')

        # Unsupported hamming distance
        (TC.path_tmp / 'invalid-ham.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#1\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'invalid-ham.ldb',
            testfiles=TC.testfiles,
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

    def test_sigs_bad_algorithm(self):
        self.step_name('Test invalid fuzzy image hash algorithm')

        # invalid algorithm
        (TC.path_tmp / 'invalid-alg.ldb').write_text(
            "logo.png.bad;Engine:150-255,Target:0;0;fuzzy_imgy#af2ad01ed42993c7#0\n"
        )
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'invalid-alg.ldb',
            testfiles=TC.testfiles,
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
