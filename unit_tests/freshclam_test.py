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
        TC.freshclam_config.write_text('''
            DatabaseMirror 127.0.0.1
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseCustomURL file://{file_db}
            ExcludeDatabase daily
            ExcludeDatabase main
            ExcludeDatabase bytecode
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            file_db=TC.path_www / "clamav.hdb",
        ))

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

        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_freshclam_01_file_copy(self):
        self.step_name('Basic freshclam test using file:// to "download" clamav.hdb')

        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Downloading clamav.hdb',
            'Database test passed.',
            'clamav.hdb updated',
        ]
        self.verify_output(output.out, expected=expected_results)
