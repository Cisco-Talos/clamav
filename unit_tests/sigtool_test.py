# Copyright (C) 2020-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.path_db = TC.path_tmp / 'database'
        TC.sigtool_pid = TC.path_tmp / 'sigtool-test.pid'
        TC.sigtool_config = TC.path_tmp / 'sigtool-test.conf'
        TC.sigtool_config.write_text('''
            DatabaseMirror localhost
            PidFile {sigtool_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseCustomURL file://{path_www}/clamav.hdb
            ExcludeDatabase daily
            ExcludeDatabase main
            ExcludeDatabase bytecode
        '''.format(
            sigtool_pid=TC.sigtool_pid,
            path_db=TC.path_db,
            path_www=TC.path_www
        ))

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

        self.log.warning('VG: {}'.format(os.getenv("VG")))
        command = '{valgrind} {valgrind_args} {sigtool} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, sigtool=TC.sigtool
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)
