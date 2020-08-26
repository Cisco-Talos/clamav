# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run freshclam tests
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        # Prepare a directory to host our test databases
        TC.path_www = Path(TC.path_tmp, 'www')
        TC.path_www.mkdir()
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.path_db = Path(TC.path_tmp, 'database')
        TC.freshclam_pid = Path(TC.path_tmp, 'freshclam-test.pid')
        TC.freshclam_config = Path(TC.path_tmp, 'freshclam-test.conf')
        TC.freshclam_config.write_text(f'''
            DatabaseMirror 127.0.0.1
            PidFile {TC.freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {TC.path_db}
            DatabaseCustomURL file://{TC.path_www / "clamav.hdb"}
            ExcludeDatabase daily
            ExcludeDatabase main
            ExcludeDatabase bytecode
        ''')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_freshclam_00_version(self):
        self.step_name('freshclam version test')

        command = f'{TC.valgrind} {TC.valgrind_args} {TC.freshclam} --config-file={TC.freshclam_config} -V'
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            f'ClamAV {TC.version}',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_freshclam_01_file_copy(self):
        self.step_name('Basic freshclam test using file:// to "download" clamav.hdb')

        command = f'{TC.valgrind} {TC.valgrind_args} {TC.freshclam} --config-file={TC.freshclam_config}'
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            f'Downloading clamav.hdb',
            f'Database test passed.',
            f'clamav.hdb updated',
        ]
        self.verify_output(output.out, expected=expected_results)
