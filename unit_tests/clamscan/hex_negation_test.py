# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run native and YARA hexadecimal negation tests.
"""

import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        samples = {
            'not-byte-match.bin': b'A\x01BCXX',
            'not-byte-no-match.bin': b'A\x00BCXX',
            'not-low-match.bin': b'A\x01BCXX',
            'not-low-no-match.bin': b'A\x10BCXX',
            'not-high-match.bin': b'A\x10BCXX',
            'not-high-no-match.bin': b'A\x0fBCXX',
            'prefix-match.bin': b'\x01ABCXX',
            'prefix-no-match.bin': b'\x00ABCXX',
            'suffix-match.bin': b'XXABC\x01',
            'suffix-no-match.bin': b'XXABC\x00',
            'gap-match.bin': b'AAxyz\x01BC',
            'mixed-match.bin': b'AXYABXX',
            'logical-match.bin': b'AAxyz\x01BC',
            'legacy-special-match.bin': b'AA\x01BBXX',
            'legacy-special-no-match.bin': b'AA\x00BBXX',
            'boundary-marker-match.bin': b'xx AB xx',
            'line-marker-match.bin': b'xx\nAB\nxx',
            'word-marker-match.bin': b'xx!AB!xx',
        }
        for name, data in samples.items():
            (TC.path_tmp / name).write_bytes(data)

        native_signatures = {
            'not-byte.ndb': 'Native.NotByte:0:*:41~004243\n',
            'not-low.ndb': 'Native.NotLowNibble:0:*:41~?04243\n',
            'not-high.ndb': 'Native.NotHighNibble:0:*:41~0?4243\n',
            'prefix.ndb': 'Native.Prefix:0:0:~00414243\n',
            'suffix.ndb': 'Native.Suffix:0:2:414243~00\n',
            'gap.ndb': 'Native.Gap:0:*:4141*~004243\n',
            'mixed.ndb': 'Native.Mixed:0:*:41??~?04?42\n',
            'legacy-special.ndb': 'Native.LegacySpecial:0:*:4141!(00)4242\n',
            'boundary-marker.ndb': 'Native.BoundaryMarker:0:*:(B)4142(B)\n',
            'line-marker.ndb': 'Native.LineMarker:0:*:(L)4142(L)\n',
            'word-marker.ndb': 'Native.WordMarker:0:*:(W)4142(W)\n',
        }
        for name, signature in native_signatures.items():
            (TC.path_tmp / name).write_text(signature)

        (TC.path_tmp / 'logical.ldb').write_text(
            'Native.Logical;Engine:90-255,Target:0;0&1;4141;~004243\n'
        )

        yara_patterns = {
            'not-byte': '~00 42',
            'not-low': '~?0 42',
            'not-high': '~0? 42',
        }
        for name, pattern in yara_patterns.items():
            (TC.path_tmp / f'yara-{name}.yara').write_text(
                f'''rule yara_{name.replace("-", "_")}
{{
    strings:
        $a = {{ 41 {pattern} }}
    condition:
        $a
}}
'''
            )

        invalid_yara_patterns = {
            'bare': '41 42 ~',
            'all-wildcard': '41 ~?? 42',
            'alternate': '41 ~( 42 | 43 ) 44',
            'double': '41 ~~00 42',
            'jump': '41 ~[1-2] 42',
        }
        for name, pattern in invalid_yara_patterns.items():
            (TC.path_tmp / f'yara-invalid-{name}.yara').write_text(
                f'''rule yara_invalid_{name.replace("-", "_")}
{{
    strings:
        $a = {{ {pattern} }}
    condition:
        $a
}}
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

    def scan(self, database, sample, extra_args=''):
        command = '{valgrind} {valgrind_args} {clamscan} {extra_args} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            extra_args=extra_args,
            path_db=TC.path_tmp / database,
            testfile=TC.path_tmp / sample,
        )
        return self.execute_command(command)

    def verify_match(self, database, sample, signature_name):
        output = self.scan(database, sample)
        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                f'{sample}: {signature_name}.UNOFFICIAL FOUND',
                'Infected files: 1',
            ],
        )

    def verify_no_match(self, database, sample):
        output = self.scan(database, sample)
        assert output.ec == 0
        self.verify_output(output.out, expected=[f'{sample}: OK'], unexpected=['FOUND'])

    def test_native_negated_byte(self):
        self.step_name('Test native exact-byte negation')
        self.verify_match('not-byte.ndb', 'not-byte-match.bin', 'Native.NotByte')
        self.verify_no_match('not-byte.ndb', 'not-byte-no-match.bin')

    def test_native_negated_nibbles(self):
        self.step_name('Test native high- and low-nibble negation')
        self.verify_match('not-low.ndb', 'not-low-match.bin', 'Native.NotLowNibble')
        self.verify_no_match('not-low.ndb', 'not-low-no-match.bin')
        self.verify_match('not-high.ndb', 'not-high-match.bin', 'Native.NotHighNibble')
        self.verify_no_match('not-high.ndb', 'not-high-no-match.bin')

    def test_native_negation_at_file_boundaries(self):
        self.step_name('Test native negation at the start and end of a file')
        self.verify_match('prefix.ndb', 'prefix-match.bin', 'Native.Prefix')
        self.verify_no_match('prefix.ndb', 'prefix-no-match.bin')
        self.verify_match('suffix.ndb', 'suffix-match.bin', 'Native.Suffix')
        self.verify_no_match('suffix.ndb', 'suffix-no-match.bin')

    def test_native_negation_with_gap_and_wildcards(self):
        self.step_name('Test native negation with gaps and ordinary wildcards')
        self.verify_match('gap.ndb', 'gap-match.bin', 'Native.Gap')
        self.verify_match('mixed.ndb', 'mixed-match.bin', 'Native.Mixed')

    def test_native_negation_in_logical_signature(self):
        self.step_name('Test native negation in a multi-part logical signature')
        self.verify_match('logical.ldb', 'logical-match.bin', 'Native.Logical')

    def test_yara_negation_semantics(self):
        self.step_name('Test YARA byte and nibble negation semantics')
        cases = [
            ('yara-not-byte.yara', 'not-byte-match.bin', 'YARA.yara_not_byte'),
            ('yara-not-low.yara', 'not-low-match.bin', 'YARA.yara_not_low'),
            ('yara-not-high.yara', 'not-high-match.bin', 'YARA.yara_not_high'),
        ]
        for database, sample, signature_name in cases:
            self.verify_match(database, sample, signature_name)

        self.verify_no_match('yara-not-byte.yara', 'not-byte-no-match.bin')
        self.verify_no_match('yara-not-low.yara', 'not-low-no-match.bin')
        self.verify_no_match('yara-not-high.yara', 'not-high-no-match.bin')

    def test_invalid_yara_negation_is_rejected(self):
        self.step_name('Test invalid YARA negation forms')
        for name in ('bare', 'all-wildcard', 'alternate', 'double', 'jump'):
            output = self.scan(f'yara-invalid-{name}.yara', 'not-byte-match.bin')
            assert output.ec == 2
            self.verify_output(
                output.err,
                expected=['Invalid YARA hex negation'],
            )

    def test_invalid_native_negation_is_rejected(self):
        self.step_name('Test invalid native negation forms')
        invalid_signatures = {
            'bare': '4142~',
            'all-wildcard': '4142~??43',
            'alternate': '41~(42|43)44',
            'double': '4142~~0043',
            'jump': '4142~[1-2]4344',
        }
        for name, pattern in invalid_signatures.items():
            database = TC.path_tmp / f'native-invalid-{name}.ndb'
            database.write_text(f'Native.Invalid.{name}:0:*:{pattern}\n')
            output = self.scan(database.name, 'not-byte-match.bin')
            assert output.ec == 2
            self.verify_output(output.err, expected=['Invalid hex negation'])

    def test_existing_special_syntax_is_unchanged(self):
        self.step_name('Test existing negated alternates and marker classes')
        self.verify_match(
            'legacy-special.ndb',
            'legacy-special-match.bin',
            'Native.LegacySpecial',
        )
        self.verify_no_match('legacy-special.ndb', 'legacy-special-no-match.bin')
        self.verify_match(
            'boundary-marker.ndb',
            'boundary-marker-match.bin',
            'Native.BoundaryMarker',
        )
        self.verify_match(
            'line-marker.ndb',
            'line-marker-match.bin',
            'Native.LineMarker',
        )
        self.verify_match(
            'word-marker.ndb',
            'word-marker-match.bin',
            'Native.WordMarker',
        )
