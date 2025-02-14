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
        TC.testfiles = list(TC.path_source.glob('unit_tests/input/other_scanfiles/lha_lzh/*.lzh'))

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_good_archives(self):
        self.step_name('Verify that these LHA archives containing logo.png and cisco-logo.png correctly extract each.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
            "cisco-logo.png;Engine:150-255,Target:0;0;fuzzy_img#9463944473afd82f#0\n"
        )

        testfiles = ' '.join([str(testfile) for testfile in TC.testfiles])

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus
        assert output.out.count(' logo.png.UNOFFICIAL FOUND') == len(TC.testfiles)
        assert output.out.count(' cisco-logo.png.UNOFFICIAL FOUND') == len(TC.testfiles)

        expected_stdout = [
            'logo.png.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'OK',
        ]
        self.verify_output(output.out, expected=expected_stdout)
