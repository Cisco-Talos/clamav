# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan YARA parser tests.
"""

import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.sample = TC.path_tmp / 'yara-parser.sample'
        TC.sample.write_text('AABBCC')

        (TC.path_tmp / 'yara-hex-comments-private-octal.yara').write_text(
            r'''rule yara_hex_comments_private_octal
{
    strings:
        $a = { 41 /* A */ 41 // end-of-line comment
               42 42 43 43 } private
    condition:
        $a and filesize == 0o6
}
'''
        )

        (TC.path_tmp / 'yara-unsupported-xor.yara').write_text(
            r'''rule yara_unsupported_xor
{
    strings:
        $a = "ABC" xor
    condition:
        $a
}
'''
        )

        (TC.path_tmp / 'yara-divide-by-zero.yara').write_text(
            r'''rule yara_divide_by_zero
{
    strings:
        $a = "AA"
    condition:
        $a and 1 \ 0 == 0
}
'''
        )

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_yara_hex_comments_private_octal(self):
        self.step_name('Test YARA hex comments, private modifier, and octal literal')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'yara-hex-comments-private-octal.yara',
            testfile=TC.sample,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = [
            'yara-parser.sample: YARA.yara_hex_comments_private_octal.UNOFFICIAL FOUND',
            'Infected files: 1',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_yara_unsupported_xor_modifier(self):
        self.step_name('Test YARA unsupported xor modifier reports a parser error')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'yara-unsupported-xor.yara',
            testfile=TC.sample,
        )
        output = self.execute_command(command)

        assert output.ec == 0

        self.verify_output(
            output.err,
            expected=[
                'unsupported string modifier "xor"',
                'failed to parse or load 1 yara rules',
            ],
        )
        self.verify_output(output.out, expected=['yara-parser.sample: OK'])

    def test_yara_divide_by_zero_is_undefined(self):
        self.step_name('Test YARA divide by zero evaluates as undefined')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'yara-divide-by-zero.yara',
            testfile=TC.sample,
        )
        output = self.execute_command(command)

        assert output.ec == 0

        self.verify_output(output.out, expected=['yara-parser.sample: OK'], unexpected=['FOUND'])
