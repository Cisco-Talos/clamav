# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run ex_scan_callbacks tests.

For reference:

    Usage: ./install/bin/ex_scan_callbacks -d <database> -f <file>
    Example: ./install/bin/ex_scan_callbacks -d /path/to/clamav.db -f /path/to/file.txt

    Options:
    --help (-h)                : Help message.
    --database (-d) FILE       : Path to the ClamAV database.
    --file (-f)     FILE       : Path to the file to scan.
    --hash-hint     HASH       : (optional) Hash of file to scan.
    --hash-alg      ALGORITHM  : (optional) Hash algorithm of hash-hint.
                                 Will also change the hash algorithm reported at end of scan.
    --file-type-hint CL_TYPE_* : (optional) File type hint for the file to scan.
    --script        FILE       : (optional) Path for non-interactive test script.
                                 Script must be a new-line delimited list of integers from 1-to-5
                                 Corresponding to the interactive scan options.
    --one-match (-1)           : Disable allmatch (stops scans after one match).
    --gen-json                 : Generate scan metadata JSON.

    Scripted scan options are:
    1  - Return CL_BREAK to abort scanning. Will still encounter POST_SCAN-callbacks on the way out.
    2  - Return CL_SUCCESS to keep scanning. Will ignore an alert in the ALERT-callback.
    3  - Return CL_VIRUS to create a new alert and keep scanning. Will agree with alert in the ALERT-callback.
    4  - Return CL_VERIFIED to trust this layer (discarding all alerts) and skip the rest of this layer.
    5  - Request md5 hash when it calculates any hash. Does not return from the callback!
    6  - Request sha1 hash when it calculates any hash. Does not return from the callback!
    7  - Request sha2-256 hash when it calculates any hash. Does not return from the callback!
    8  - Get md5 hash. Does not return from the callback!
    9  - Get sha1 hash. Does not return from the callback!
    10 - Get sha2-256 hash. Does not return from the callback!
    11 - Print all hashes that have already been calculated. Does not return from the callback!

"""

import os
import platform
import shutil
import sys
from pathlib import Path

sys.path.append('../unit_tests')
import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()

program_name = 'ex_scan_callbacks'


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        # Find the example program
        TC.example_program = Path(os.getenv("EX_SCAN_CALLBACKS"))
        if not TC.example_program.exists():
            raise Exception(f'Could not find the example program {TC.example_program}')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_cl_scan_callbacks_clam_zip_basic(self):
        self.step_name('Basic test with clam.zip that just keeps scanning. Nothing special.')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'zip_basic.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('3\n') # Return CL_VIRUS to keep scanning and accept the alert

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP'
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'Data scanned: 948 B',
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Verdict:      CL_VERDICT_STRONG_INDICATOR',
                'Return Code:  CL_SUCCESS (0)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_SUCCESS return code
        assert output.ec == 0

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]

    def test_cl_scan_callbacks_clam_zip_basic_one_match(self):
        self.step_name('Same as basic test with clam.zip that just keeps scanning--but disables allmatch mode.')

        # Notably, the return code at the end should be CL_VIRUS (1) instead of CL_SUCCESS (0).
        # This is because the reason the scan ended "early" is because of the alert in the clam.exe file.

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'zip_basic.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('3\n') # Return CL_VIRUS to keep scanning and accept the alert

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP'
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'Data scanned: 544 B',  # Note this is less, because allmatch disabled so stopped after clam.exe matched.
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Verdict:      CL_VERDICT_STRONG_INDICATOR',
                'Return Code:  CL_VIRUS (1)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script} --one-match'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_VIRUS return code
        assert output.ec == 1

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]

    def test_cl_scan_callbacks_clam_zip_ignore_alert(self):
        self.step_name('Ignore alert in clam.exe (within clam.zip) and keep scanning.')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'ignore_alert.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to ignore the alert and keep scanning

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'Data scanned: 948 B',
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Return Code:  CL_SUCCESS (0)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_SUCCESS return code
        assert output.ec == 0

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]

    def test_cl_scan_callbacks_clam_zip_abort(self):
        self.step_name('Test with clam.zip that immediately aborts using CL_BREAK.')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'zip_abort.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('1\n') # Return CL_EBREAK to keep scanning

            expected_results += [
                'Data scanned: 0 B',
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Return Code:  CL_SUCCESS (0)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_SUCCESS return code
        assert output.ec == 0

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]

        unexpected_results = [
            'CL_TYPE_MSEXE',
        ]
        self.verify_output(output.out, unexpected=unexpected_results)

    def test_cl_scan_callbacks_clam_zip_add_alert(self):
        self.step_name('Test adding an alert using CL_VIRUS from the FILE_TYPE callback.')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'add_alert.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('3\n') # Return CL_VIRUS to create a new alert and keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
                'Last Alert:         Detected.By.Callback.FileType',
            ]
            f.write('3\n') # Return CL_VIRUS to keep scanning and accept the alert

            expected_results += [
                'Data scanned: 0 B',
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Verdict:      CL_VERDICT_STRONG_INDICATOR',
                'Return Code:  CL_SUCCESS (0)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_SUCCESS return code
        assert output.ec == 0

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]

        unexpected_results = [
            'CL_TYPE_MSEXE',
        ]
        self.verify_output(output.out, unexpected=unexpected_results)

    def test_cl_scan_callbacks_clam_verify(self):
        self.step_name('Test that returning CL_VERIFIED from the POST_SCAN for the top level discards all previous alerts.')

        path_db = TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'

        # Build up expected results as we define the test script.
        expected_results = []

        test_script = TC.path_tmp / 'verify.txt'
        with open(test_script, 'w') as f:
            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In FILE_TYPE callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_HASH callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In PRE_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
            ]
            f.write('2\n') # Return CL_SUCCESS to keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('3\n') # Return CL_VIRUS to keep scanning and accept the alert

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         ClamAV-Test-File.UNOFFICIAL',
            ]
            f.write('3\n') # Return CL_VIRUS to add another alert and keep scanning

            expected_results += [
                'In ALERT callback',
                'Recursion Level:    1',
                'File Name:          clam.exe',
                'File Type:          CL_TYPE_MSEXE',
                'Last Alert:         Detected.By.Callback.PostScan',
            ]
            f.write('3\n') # Return CL_VIRUS to keep scanning and accept the alert

            expected_results += [
                'In POST_SCAN callback',
                'Recursion Level:    0',
                'File Name:          clam.zip',
                'File Type:          CL_TYPE_ZIP'
            ]
            f.write('4\n') # Return CL_VERIFIED to trust this layer (discarding all alerts) and skip the rest of this layer

            expected_results += [
                'Data scanned: 948 B',
                'Hash:         21495c3a579d537dc63b0df710f63e60a0bfbc74d1c2739a313dbd42dd31e1fa',
                'File Type:    CL_TYPE_ZIP',
                'Return Code:  CL_SUCCESS (0)',
            ]

        command = '{valgrind} {valgrind_args} {example} -d {database} -f {target} --script {script}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, example=TC.example_program,
            database=path_db,
            target=TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.zip',
            script=test_script
        )
        output = self.execute_command(command)

        # Check for CL_SUCCESS return code
        assert output.ec == 0

        # Custom logic to verify the output making sure that all expected results are found in the output in order.
        #
        # This is necessary because the STRICT_ORDER option gets confused when expected results have multiple of the
        # same string, but in different contexts.
        remaining_output = output.out

        for expected in expected_results:
            # find the first occurrence of the expected string in remaining_output, splitting into two parts
            parts = remaining_output.split(expected, 1)
            assert len(parts) == 2, f"Expected '{expected}' in output, but it was not found:\n{remaining_output}"

            remaining_output = parts[1]
