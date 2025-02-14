# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

from zipfile import ZIP_DEFLATED, ZipFile
import sys

sys.path.append('../unit_tests')
import testcase
from testcase import STRICT_ORDER


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        (TC.path_tmp / 'clam.ndb').write_text(
            "Test.NDB:0:*:4b45524e454c33322e444c4c00004578\n"
        )

        # Create a ZIP that has two things:
        # 1. malformed file that will alert with  --alert-broken-media
        # 2. the clam.exe file that will alert normally.
        # The idea is that since the malformed file is first, the heuristic alert will be encountered first.
        # The heuristic alert must behave as intended, depending on whether we use --allmatch, --heuristic-scan-precedence, etc.
        TC.heuristics_testfile = TC.path_tmp / 'heuristics-test.zip'
        with ZipFile(str(TC.heuristics_testfile), 'w', ZIP_DEFLATED) as zf:
            # Add truncated PNG file that will alert with  --alert-broken-media
            with (TC.path_source / 'logo.png').open('br') as logo_png:
                zf.writestr('logo.png.truncated', logo_png.read(6378))

            # Add clam.exe which will alert normally
            clam_exe = TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'
            zf.writestr('clam.exe', clam_exe.read_bytes())

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_hidden_by_strong_indicator(self):
        '''
        This test uses a ZIP that has two things:
        1. malformed file that will alert with  --alert-broken-media
        2. the clam.exe file that will alert normally.
        The idea is that since the malformed file is first, the heuristic alert will be encountered first.

        In this test the heuristic alert must not alert because neither allmatch is specified, nor --heuristic-scan-precedence
        '''
        self.step_name('Test that a clam heuristic not alert because regular sig alerts first.')

        testfile = TC.heuristics_testfile

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} {testfiles} --alert-broken-media'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'clam.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = ['Test.NDB.UNOFFICIAL FOUND']
        unexpected_results = ['Heuristics.Broken.Media.PNG.EOFReadingChunk FOUND']
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_only_heur(self):
        '''
        This test uses a ZIP that has two things:
        1. malformed file that will alert with  --alert-broken-media
        2. the clam.exe file that will alert normally.
        The idea is that since the malformed file is first, the heuristic alert will be encountered first.

        In this test the heuristic alert must alert because we don't use the sig for the other file.
        '''
        self.step_name('Test that a clam heuristic will alert, because it is the only detection.')

        testfile = TC.heuristics_testfile

        # Add an empty NDB file, because we need to pass in some sort of database.
        (TC.path_tmp / 'empty.ndb').write_text(
            "# Just a comment\n"
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} {testfiles} --alert-broken-media'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'empty.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = ['Heuristics.Broken.Media.PNG.EOFReadingChunk FOUND']
        unexpected_results = ['Test.NDB.UNOFFICIAL FOUND']
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_precedence(self):
        '''
        This test uses a ZIP that has two things:
        1. malformed file that will alert with  --alert-broken-media
        2. the clam.exe file that will alert normally.
        The idea is that since the malformed file is first, the heuristic alert will be encountered first.

        In this test the heuristic alert must alert first because --heuristic-scan-precedence is enabled.
        We won't see the other alert because it's not allmatch mode.
        '''
        self.step_name('Test that a heuristic-precedence will cause the heuristic alert to happen first, with no other alerts because not allmatch.')

        testfile = TC.heuristics_testfile

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} {testfiles} --alert-broken-media \
             --heuristic-scan-precedence'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'clam.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = ['Heuristics.Broken.Media.PNG.EOFReadingChunk FOUND']
        unexpected_results = ['Test.NDB.UNOFFICIAL FOUND']
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_allmatch(self):
        '''
        This test uses a ZIP that has two things:
        1. malformed file that will alert with  --alert-broken-media
        2. the clam.exe file that will alert normally.
        The idea is that since the malformed file is first, the heuristic alert will be encountered first.

        In this test we use --allmatch but we don't use --heuristic-scan-precedence.
        That means the NDB sig should alert first, even though the heuristic is encountered first.
        Note the verify_output() uses STRICT_ORDER.
        '''
        self.step_name('Test that a clam heuristic alert will alert LAST in allmatch mode without heuristic-precedence.')

        testfile = TC.heuristics_testfile

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} {testfiles} --alert-broken-media \
             --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'clam.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Test.NDB.UNOFFICIAL FOUND',
            'Heuristics.Broken.Media.PNG.EOFReadingChunk FOUND',
        ]
        self.verify_output(output.out, expected=expected_results, order=STRICT_ORDER)

    def test_allmatch_precedence(self):
        '''
        This test uses a ZIP that has two things:
        1. malformed file that will alert with  --alert-broken-media
        2. the clam.exe file that will alert normally.
        The idea is that since the malformed file is first, the heuristic alert will be encountered first.

        In this test we use --allmatch AND we use --heuristic-scan-precedence.
        That means the heuristic is encountered first and should be treated equally, so it should alert first.
        Note the verify_output() uses STRICT_ORDER.
        '''
        self.step_name('Test that a clam heuristic alert will alert FIRST in allmatch mode with heuristic-precedence.')

        testfile = TC.heuristics_testfile

        command = '{valgrind} {valgrind_args} {clamscan} -d {clam_exe_db} {testfiles} --alert-broken-media \
             --allmatch \
             --heuristic-scan-precedence'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            clam_exe_db=TC.path_tmp / 'clam.ndb',
            testfiles=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Broken.Media.PNG.EOFReadingChunk FOUND',
            'Test.NDB.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results, order=STRICT_ORDER)
