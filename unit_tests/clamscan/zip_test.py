# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan ZIP tests.
"""

import re
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.append(str(Path(__file__).resolve().parents[1]))
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        cls.testfile = cls.path_tmp / 'max-filesize.zip'
        with ZipFile(cls.testfile, 'w', ZIP_DEFLATED) as archive:
            archive.writestr('oversized.txt', b'A' * 4096)

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def scan_archive(self, alert_exceeds_max):
        command = (
            '{valgrind} {valgrind_args} {clamscan} --max-filesize=1K '
            '--max-scansize=1M --alert-exceeds-max={alert_exceeds_max} '
            '-d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            alert_exceeds_max=alert_exceeds_max,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile=TC.testfile,
        )
        return self.execute_command(command)

    def test_decompressed_member_exceeds_max_file_size(self):
        self.step_name('Test ZIP member truncation honors AlertExceedsMax')

        output = self.scan_archive('yes')

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxFileSize FOUND'],
        )

    def test_decompressed_member_limit_alert_is_optional(self):
        self.step_name('Test ZIP member truncation alert remains opt-in')

        output = self.scan_archive('no')

        assert output.ec == 0
        self.verify_output(
            output.out,
            expected=[re.escape('{}: OK'.format(TC.testfile))],
            unexpected=['Heuristics.Limits.Exceeded.MaxFileSize'],
        )

    def test_other_compression_methods_exceed_max_file_size(self):
        self.step_name('Test ZIP member limits with other compression methods')

        for filename in ('clam.bz2.zip', 'clam.d64.zip', 'clam.impl.zip'):
            with self.subTest(filename=filename):
                testfile = (
                    TC.path_build
                    / 'unit_tests'
                    / 'input'
                    / 'clamav_hdb_scanfiles'
                    / filename
                )
                command = (
                    '{valgrind} {valgrind_args} {clamscan} --max-filesize=500 '
                    '--max-scansize=1M --alert-exceeds-max=yes '
                    '-d {path_db} {testfile}'
                ).format(
                    valgrind=TC.valgrind,
                    valgrind_args=TC.valgrind_args,
                    clamscan=TC.clamscan,
                    path_db=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
                    testfile=testfile,
                )
                output = self.execute_command(command)

                assert output.ec == 1
                self.verify_output(
                    output.out,
                    expected=['Heuristics.Limits.Exceeded.MaxFileSize FOUND'],
                )
