# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run libclamav unit tests
"""

import os
from pathlib import Path
import platform
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

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_libclamav_00_unit_test(self):
        self.step_name('libclamav unit tests')

        # If no valgrind, valgrind nad valgrind args are empty strings
        command = '{valgrind} {valgrind_args} {check_clamav}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, check_clamav=TC.check_clamav
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            '100%', 'Failures: 0', 'Errors: 0'
        ]
        self.verify_output(output.out, expected=expected_results)
