# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamd tests.
"""

import os
from pathlib import Path
import platform
import socket
import subprocess
import shutil
import sys
import time
import unittest

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()

def check_port_available(port_num: int) -> bool:
    '''
    Check if port # is available
    '''
    port_is_available = True # It's probably available...

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = ("127.0.0.1", port_num)

    result_of_check = sock.connect_ex(location)
    if result_of_check == 0:
        port_is_available = False # Oh nevermind! Someone was listening!
    sock.close()

    return port_is_available

class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('test/clam*')) # A list of Path()'s of each of our generated test files

        TC.clamd_pid = TC.path_tmp / 'clamd-test.pid'
        TC.clamd_socket =   TC.path_build / 'unit_tests' / 'clamd-test.socket' # <-- this is hard-coded into the `check_clamd` program
        TC.clamd_port_num = 3319                                               # <-- this is hard-coded into the `check_clamd` program
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'clamav.hdb'),
            str(TC.path_db),
        )
        shutil.copy(
            str(TC.path_source / 'unit_tests' / 'input' / 'daily.pdb'),
            str(TC.path_db),
        )

        # Identify a TCP port we can use.
        # Presently disabled because check_clamd's port # is hardcoded.
        #found_open_port = False
        #for port_num in range(3310, 3410):
        #    if check_port_available(port_num) == True:
        #        found_open_port = True
        #        break
        #assert found_open_port == True

        # Prep a clamd.conf to use for most (if not all) of the tests.
        config = f'''
            Foreground yes
            PidFile {TC.clamd_pid}
            DatabaseDirectory {TC.path_db}
            LogFileMaxSize 0
            LogTime yes
            #Debug yes
            LogClean yes
            LogVerbose yes
            ExitOnOOM yes
            DetectPUA yes
            ScanPDF yes
            CommandReadTimeout 1
            MaxQueue 800
            MaxConnectionQueueLength 1024
            '''
        if operating_system == 'windows':
            # Only have TCP socket option for Windows.
            config += f'''
                TCPSocket {TC.clamd_port_num}
                TCPAddr 127.0.0.1
                '''
        else:
            # Use LocalSocket for Posix, because that's what check_clamd expects.
            config += f'''
                LocalSocket {TC.clamd_socket}
                TCPSocket {TC.clamd_port_num}
                TCPAddr 127.0.0.1
                '''

        TC.clamd_config = TC.path_tmp / 'clamd-test.conf'
        TC.clamd_config.write_text(config)

        # Check if fdpassing is supported.
        TC.has_fdpass_support = False
        with (TC.path_build / 'clamav-config.h').open('r') as clamav_config:
            if "#define HAVE_FD_PASSING 1" in clamav_config.read():
                TC.has_fdpass_support = True

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()
        self.proc = None

    def tearDown(self):
        super(TC, self).tearDown()

        # Kill clamd (if running)
        if self.proc != None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=120)
                self.proc.stdin.close()
            except OSError as exc:
                self.log.warning(f'Unexpected exception {exc}')
                pass  # ignore
            self.proc = None
        TC.clamd_pid.unlink(missing_ok=True)
        TC.clamd_socket.unlink(missing_ok=True)

        self.verify_valgrind_log()

    def start_clamd(self):
        '''
        Start clamd
        '''
        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamd} --config-file={TC.clamd_config}'
        self.log.info(f'Starting clamd: {command}')
        self.proc = subprocess.Popen(
            command.strip().split(' '),
            stdin=subprocess.PIPE,
            stdout=sys.stdout.buffer,
            stderr=sys.stdout.buffer,
        )

    def run_clamdscan(self,
                      scan_args,
                      expected_ec=0,
                      expected_out=[],
                      expected_err=[],
                      unexpected_out=[],
                      unexpected_err=[]):
        '''
        Run clamdscan in each mode
        The first scan uses ping & wait to give clamd time to start.
        '''
        # default (filepath) mode
        output = self.execute_command(f'{TC.clamdscan} --ping 5 --wait -c {TC.clamd_config} {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        # multi mode
        output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} -m {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        if TC.has_fdpass_support:
            # fdpass
            output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} --fdpass {scan_args}')
            assert output.ec == expected_ec
            if expected_out != [] or unexpected_out != []:
                self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
            if expected_err != [] or unexpected_err != []:
                self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

            # fdpass multi mode
            output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} --fdpass -m {scan_args}')
            assert output.ec == expected_ec
            if expected_out != [] or unexpected_out != []:
                self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
            if expected_err != [] or unexpected_err != []:
                self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        # stream
        output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} --stream {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        # stream multi mode
        output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} --stream -m {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

    def run_clamdscan_file_only(self,
                                scan_args,
                                expected_ec=0,
                                expected_out=[],
                                expected_err=[],
                                unexpected_out=[],
                                unexpected_err=[]):
        '''
        Run clamdscan in filepath mode (and filepath multi mode)
        The first scan uses ping & wait to give clamd time to start.
        '''
        # default mode
        output = self.execute_command(f'{TC.clamdscan} --ping 5 --wait -c {TC.clamd_config} {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        # multi mode
        output = self.execute_command(f'{TC.clamdscan} -c {TC.clamd_config} -m {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

    def run_clamdscan_fdpass_only(self,
                                  scan_args,
                                  expected_ec=0,
                                  expected_out=[],
                                  expected_err=[],
                                  unexpected_out=[],
                                  unexpected_err=[]):
        '''
        Run clamdscan fdpass mode only
        Use ping & wait to give clamd time to start.
        '''
        # fdpass
        output = self.execute_command(f'{TC.clamdscan} --ping 5 --wait -c {TC.clamd_config} --fdpass {scan_args}')
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

    def test_clamd_00_version(self):
        '''
        verify that clamd -v returns the version
        '''
        self.step_name('clamd version test')

        command = f'{TC.valgrind} {TC.valgrind_args} {TC.clamd} --config-file={TC.clamd_config} -V'
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            f'ClamAV {TC.version}',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_clamd_01_ping_pong(self):
        '''
        Verify that clamd responds to a PING command
        '''
        self.step_name('Testing clamd + clamdscan PING PONG feature')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        output = self.execute_command(f'{TC.clamdscan} -p 5 -c {TC.clamd_config}')

        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

    def test_clamd_02_clamdscan_version(self):
        '''
        Verify that clamdscan --version returns the expected version #
        Explanation: clamdscan --version will query clamd for it's version
          and print out clamd's version.  If it can't connect to clamd, it'll
          throw and error saying as much and then report it's own version.

        In this test, we want to check clamd's version through clamdscan.
        '''
        self.step_name('Testing clamd + clamdscan version feature')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # First we'll ping-pong to make sure clamd is up
        # If clamd isn't up before the version test, clamdscan will return it's
        # own version, which isn't really the point of the test.
        output = self.execute_command(f'{TC.clamdscan} --ping 5 -c {TC.clamd_config}')
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

        # Ok now it's up, let's check clamd's version via clamdscan.
        output = self.execute_command(f'{TC.clamdscan} --version -c {TC.clamd_config}')
        assert output.ec == 0  # success
        self.verify_output(output.out,
            expected=[f'ClamAV {TC.version}'], unexpected=['Could not connect to clamd'])

    def test_clamd_03_reload(self):
        '''
        In this test, it is not supposed to detect until we actually put the
        signature there and reload!
        '''
        self.step_name('Test scan before & after reload')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        (TC.path_tmp / 'reload-testfile').write_bytes(b'ClamAV-RELOAD-Test')

        self.run_clamdscan(f'{TC.path_tmp / "reload-testfile"}',
            expected_ec=0, expected_out=['reload-testfile: OK', 'Infected files: 0'])

        (TC.path_db / 'reload-test.ndb').write_text('ClamAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374')

        output = self.execute_command(f'{TC.clamdscan} --reload -c {TC.clamd_config}')
        assert output.ec == 0  # success

        time.sleep(2) # give clamd a moment to reload before trying again
                      # with multi-threaded reloading will clamd would happily
                      # re-scan with the old engine while it reloads.

        self.run_clamdscan(f'{TC.path_tmp / "reload-testfile"}',
            expected_ec=1, expected_out=['ClamAV-RELOAD-TestFile.UNOFFICIAL FOUND', 'Infected files: 1'])

    def test_clamd_04_all_testfiles(self):
        '''
        Verify that clamd + clamdscan detect each of our <build>/test/clam* test files.
        '''
        self.step_name('Testing clamd + clamdscan scan of all `test` files')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        expected_results = [f'{testpath.name}: ClamAV-Test-File.UNOFFICIAL FOUND' for testpath in TC.testpaths]
        expected_results.append(f'Infected files: {len(TC.testpaths)}')

        self.run_clamdscan(f'{testfiles}',
            expected_ec=1, expected_out=expected_results)

    def test_clamd_05_check_clamd(self):
        '''
        Uses the check_clamd program to test clamd's socket API in various ways
        that aren't possible with clamdscan.
        '''
        self.step_name('Testing clamd + check_clamd')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # Let's first use the ping-pong test to make sure clamd is listening.
        output = self.execute_command(f'{TC.clamdscan} -p 5 -c {TC.clamd_config}')
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

        # Ok now run check_clamd to have fun with clamd's API
        output = self.execute_command(f'{TC.check_clamd}')
        assert output.ec == 0  # success

        expected_results = [
            '100%', 'Failures: 0', 'Errors: 0'
        ]
        self.verify_output(output.out, expected=expected_results)

        # Let's do another ping-pong test to see if `check_clamd` killed clamd (Mu-ha-ha).
        output = self.execute_command(f'{TC.clamdscan} -p 5 -c {TC.clamd_config}')
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

    def test_clamd_06_HeuristicScanPrecedence_off(self):
        '''
        Verify that HeuristicScanPrecedence off works as expected (default)
        In a later test, we'll add `HeuristicScanPrecedence yes` to the config
        and retest with it on.

        With it off, we expect the scan to complete and the "real" virus to alert
        rather than the heuristic.
        '''
        self.step_name('Testing clamd + clamdscan w/ HeuristicScanPrecedence no (default)')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        self.run_clamdscan(f'{TC.path_build / "unit_tests" / "clam-phish-exe"}',
            expected_ec=1, expected_out=['ClamAV-Test-File'])

    def test_clamd_07_HeuristicScanPrecedence_on(self):
        '''
        Verify that HeuristicScanPrecedence on works as expected.

        With it on, we expect the scan to stop and raise an alert as soon as
        the phishing heuristic is detected.
        '''
        self.step_name('Testing clamd + clamdscan w/ HeuristicScanPrecedence yes')

        with TC.clamd_config.open('a') as config:
            config.write('''
                HeuristicScanPrecedence yes
                ''')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        self.run_clamdscan(f'{TC.path_build / "unit_tests" / "clam-phish-exe"}',
            expected_ec=1, expected_out=['Heuristics.Phishing.Email.SpoofedDomain'])

    @unittest.skipIf(operating_system == 'windows', 'This test uses a shell script to test virus-action. TODO: add Windows support to this test.')
    def test_clamd_08_VirusEvent(self):
        '''
        Test that VirusEvent works
        '''
        self.step_name('Testing clamd + clamdscan w/ VirusEvent')

        with TC.clamd_config.open('a') as config:
            config.write(f'VirusEvent {TC.path_source / "unit_tests" / "virusaction-test.sh"} {TC.path_tmp} "Virus found: %v"\n')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        self.run_clamdscan_file_only(f'{TC.path_build / "test" / "clam.exe"}',
            expected_ec=1)#, expected_out=['Virus found: ClamAV-Test-File.UNOFFICIAL'])

        self.log.info(f'verifying log output from virusaction-test.sh: {str(TC.path_tmp / "test-clamd.log")}')
        self.verify_log(str(TC.path_tmp / 'test-clamd.log'),
            expected=['Virus found: ClamAV-Test-File.UNOFFICIAL'],
            unexpected=['VirusEvent incorrect', 'VirusName incorrect'])
