# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run sigtool tests.
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
        TC.path_www = TC.path_tmp / 'www'
        TC.path_www.mkdir()
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.path_db = TC.path_tmp / 'database'
        TC.sigtool_pid = TC.path_tmp / 'sigtool-test.pid'
        TC.sigtool_config = TC.path_tmp / 'sigtool-test.conf'
        TC.sigtool_config.write_text(f'''
            DatabaseMirror 127.0.0.1
            PidFile {TC.sigtool_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {TC.path_db}
            DatabaseCustomURL file://{TC.path_www}/clamav.hdb
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

    def test_sigtool_00_version(self):
        self.step_name('sigtool version test')

        self.log.warning(f'VG: {os.getenv("VG")}')
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.sigtool} -V'
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            f'ClamAV {TC.version}',
        ]
        self.verify_output(output.out, expected=expected_results)

