# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamd (and clamdscan) tests.
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
from zipfile import ZIP_DEFLATED, ZipFile

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()

def check_port_available(port_num: int) -> bool:
    '''
    Check if port # is available
    '''
    port_is_available = True # It's probably available...

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = ('localhost', port_num)

    result_of_check = sock.connect_ex(location)
    if result_of_check == 0:
        port_is_available = False # Oh nevermind! Someone was listening!
    sock.close()

    return port_is_available

class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

        TC.clamd_pid = TC.path_tmp / 'clamd-test.pid'
        TC.clamd_socket =   'clamd-test.socket'             # <-- A relative path here and in check_clamd to avoid-
                                                            # test failures caused by (invalid) long socket filepaths.
                                                            # The max length for a socket file path is _really_ short.
        TC.clamd_port_num = 3319                            # <-- This is hard-coded into the `check_clamd` program on Windows.
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )
        shutil.copy(
            str(TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'daily.pdb'),
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
        config = '''
            Foreground yes
            PidFile {pid}
            DatabaseDirectory {dbdir}
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
            '''.format(pid=TC.clamd_pid, dbdir=TC.path_db)
        if operating_system == 'windows':
            # Only have TCP socket option for Windows.
            config += '''
                TCPSocket {socket}
                TCPAddr localhost
                '''.format(socket=TC.clamd_port_num)
        else:
            # Use LocalSocket for Posix, because that's what check_clamd expects.
            config += '''
                LocalSocket {localsocket}
                '''.format(localsocket=TC.clamd_socket)

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
                self.log.warning('Unexpected exception {}'.format(exc))
                pass  # ignore
            self.proc = None
        try:
            TC.clamd_pid.unlink()
        except Exception:
            pass # missing_ok=True is too for common use.
        try:
            TC.clamd_socket.unlink()
        except Exception:
            pass # missing_ok=True is too for common use.

        self.verify_valgrind_log()

    def start_clamd(self, use_valgrind=True, clamd_config=None):
        '''
        Start clamd
        '''
        if clamd_config == None:
            clamd_config = TC.clamd_config

        if use_valgrind:
            command = '{valgrind} {valgrind_args} {clamd} --config-file={clamd_config}'.format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamd=TC.clamd, clamd_config=clamd_config
            )
        else:
            command = '{clamd} --config-file={clamd_config}'.format(
                clamd=TC.clamd, clamd_config=TC.clamd_config
            )
        self.log.info('Starting clamd: {}'.format(command))
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
                      unexpected_err=[],
                      use_valgrind=False):
        '''
        Run clamdscan in each mode
        The first scan uses ping & wait to give clamd time to start.
        '''
        arg_variations = [
            '--ping 5 --wait',          # default (filepath) mode
            '--multiscan',              # multi mode
            '--stream',                 # stream mode
            '--stream --multiscan',     # fdstreampass multi mode
        ]
        if TC.has_fdpass_support:
            arg_variations += [
                '--fdpass',             # fdpass mode
                '--fdpass --multiscan', # fdpass multi mode
            ]

        for arg_variation in arg_variations:
            if use_valgrind:
                output = self.execute_command('{valgrind} {valgrind_args} {clamdscan} {arg_variation} {scan_args} -c {clamd_config}'.format(
                    valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, arg_variation=arg_variation, scan_args=scan_args))
            else:
                output = self.execute_command('{clamdscan} {arg_variation} {scan_args} -c {clamd_config}'.format(
                    clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, arg_variation=arg_variation, scan_args=scan_args))

            if expected_out != [] or unexpected_out != []:
                self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
            if expected_err != [] or unexpected_err != []:
                self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

            if use_valgrind:
                self.verify_valgrind_log()


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
        output = self.execute_command('{clamdscan} --ping 5 --wait -c {clamd_config} {scan_args}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, scan_args=scan_args))
        assert output.ec == expected_ec
        if expected_out != [] or unexpected_out != []:
            self.verify_output(output.out, expected=expected_out, unexpected=unexpected_out)
        if expected_err != [] or unexpected_err != []:
            self.verify_output(output.err, expected=expected_err, unexpected=unexpected_err)

        # multi mode
        output = self.execute_command('{clamdscan} -c {clamd_config} -m {scan_args}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, scan_args=scan_args))
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
        output = self.execute_command('{clamdscan} --ping 5 --wait -c {clamd_config} --fdpass {scan_args}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, scan_args=scan_args))
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

        command = '{valgrind} {valgrind_args} {clamd} --config-file={clamd_config} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamd=TC.clamd, clamd_config=TC.clamd_config)
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
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

        output = self.execute_command('{clamdscan} -p 5 -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))

        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

    def test_clamd_02_clamdscan_version(self):
        '''
        Verify that clamdscan --version returns the expected version #
        Explanation: clamdscan --version will query clamd for its version
          and print out clamd's version.  If it can't connect to clamd, it'll
          throw and error saying as much and then report its own version.

        In this test, we want to check clamd's version through clamdscan.
        '''
        self.step_name('Testing clamd + clamdscan version feature')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # First we'll ping-pong to make sure clamd is up
        # If clamd isn't up before the version test, clamdscan will return its
        # own version, which isn't really the point of the test.
        output = self.execute_command('{clamdscan} --ping 5 -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

        # Ok now it's up, let's check clamd's version via clamdscan.
        output = self.execute_command('{clamdscan} --version -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))
        assert output.ec == 0  # success
        self.verify_output(output.out,
            expected=['ClamAV {}'.format(TC.version)], unexpected=['Could not connect to clamd'])

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

        self.run_clamdscan('{}'.format(TC.path_tmp / 'reload-testfile'),
            expected_ec=0, expected_out=['reload-testfile: OK', 'Infected files: 0'])

        (TC.path_db / 'reload-test.ndb').write_text('ClamAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374')

        output = self.execute_command('{clamdscan} --reload -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))
        assert output.ec == 0  # success

        time.sleep(2) # give clamd a moment to reload before trying again
                      # with multi-threaded reloading will clamd would happily
                      # re-scan with the old engine while it reloads.

        self.run_clamdscan('{}'.format(TC.path_tmp / 'reload-testfile'),
            expected_ec=1, expected_out=['ClamAV-RELOAD-TestFile.UNOFFICIAL FOUND', 'Infected files: 1'])

    def test_clamd_04_all_testfiles(self):
        '''
        Verify that clamd + clamdscan detect each of our <build>/unit_tests/input/clamav_hdb_scanfiles/clam* test files.
        '''
        self.step_name('Testing clamd + clamdscan scan of all `test` files')

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        expected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        expected_results.append('Infected files: {}'.format(len(TC.testpaths)))

        self.run_clamdscan(testfiles,
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
        output = self.execute_command('{clamdscan} -p 5 -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

        # Ok now run check_clamd to have fun with clamd's API
        output = self.execute_command('{}'.format(TC.check_clamd))
        self.log.info('check_clamd stdout: \n{}'.format(output.out))
        self.log.info('check_clamd stderr: \n{}'.format(output.err))
        assert output.ec == 0  # success

        expected_results = [
            '100%', 'Failures: 0', 'Errors: 0'
        ]
        self.verify_output(output.out, expected=expected_results)

        # Let's do another ping-pong test to see if `check_clamd` killed clamd (Mu-ha-ha).
        output = self.execute_command('{clamdscan} -p 5 -c {clamd_config}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config))
        assert output.ec == 0  # success
        self.verify_output(output.out, expected=['PONG'])

        time.sleep(5)

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

        self.run_clamdscan('{}'.format(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe_and_mail.tar.gz'),
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

        self.run_clamdscan('{}'.format(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe_and_mail.tar.gz'),
            expected_ec=1, expected_out=['Heuristics.Phishing.Email.SpoofedDomain'])

    @unittest.skipIf(operating_system == 'windows', 'This test uses a shell script to test virus-action. TODO: add Windows support to this test.')
    def test_clamd_08_VirusEvent(self):
        '''
        Test that VirusEvent works
        '''
        self.step_name('Testing clamd + clamdscan w/ VirusEvent')

        with TC.clamd_config.open('a') as config:
            config.write('VirusEvent {} {} "Virus found: %v"\n'.format(
                TC.path_source / 'unit_tests' / 'input' / 'virusaction-test.sh',
                TC.path_tmp))

        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        self.run_clamdscan_file_only('{}'.format(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'),
            expected_ec=1)#, expected_out=['Virus found: ClamAV-Test-File.UNOFFICIAL'])

        self.log.info('verifying log output from virusaction-test.sh: {}'.format(str(TC.path_tmp / 'test-clamd.log')))
        self.verify_log(str(TC.path_tmp / 'test-clamd.log'),
            expected=['Virus found: ClamAV-Test-File.UNOFFICIAL'],
            unexpected=['VirusEvent incorrect', 'VirusName incorrect'])

    def test_clamd_09_clamdscan_ExcludePath(self):
        '''
        Verify that ExcudePath works and does not cause other  on works as expected.
        We'll use valgrind on clamdscan instead of clamd for this one, if enabled
        as a regression for clamdscan memory leak fixes.

        With it on, we expect the scan to stop and raise an alert as soon as
        the phishing heuristic is detected.
        '''
        self.step_name('Testing clamd + clamdscan w/ ExcludePath')

        (TC.path_tmp / 'alpha').mkdir()
        (TC.path_tmp / 'beta').mkdir()
        (TC.path_tmp / 'charlie').mkdir()

        shutil.copy(str(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'), str(TC.path_tmp / 'alpha' / 'a_found'))     # This should be found (first)
        shutil.copy(str(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'), str(TC.path_tmp / 'beta' / 'b_excluded'))  # This one should be excluded
        shutil.copy(str(TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam.exe'), str(TC.path_tmp / 'charlie' / 'c_found'))     # This one should still be found after excluding the previous

        with TC.clamd_config.open('a') as config:
            exclude_path = 'beta'

            config.write('''
                ExcludePath {}
                '''.format(exclude_path))

        self.start_clamd(use_valgrind=False)

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        expected_out = [
            'a_found: ClamAV-Test-File.UNOFFICIAL FOUND',
          # 'b_excluded: Excluded',  <-- Bug: this doesn't appear in recursive regular scans :-(, only fdpass and stream
            'c_found: ClamAV-Test-File.UNOFFICIAL FOUND',
        ]

        unexpected_out = [
            'a_found: Excluded',
            'b_excluded: ClamAV-Test-File.UNOFFICIAL FOUND',
            'c_found: Excluded',
        ]

        self.run_clamdscan('{}'.format(TC.path_tmp),
            expected_ec=1, expected_out=expected_out, unexpected_out=unexpected_out,
            use_valgrind=True)

    def test_clamd_10_allmatch_not_sticky(self):
        '''
        Verify that a scanning without allmatch does not use allmatch mode, after scanning with allmatch.
        This is a regression test for an issue where the allmatch scan option is sticky and any scans after an allmatch scan become an allmatch scan.
        '''
        self.step_name('Testing clamdscan --allmatch is not sticky')

        # Get a list of Path()'s of each of signature file
        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'
        database_files = list(test_path.glob('alert-sigs/*'))

        test_exe = test_path / 'test.exe'

        # Copy them to the database directory before starting ClamD
        for db in database_files:
            shutil.copy(str(db), str(TC.path_db))

        #
        # Start ClamD
        #
        self.start_clamd()

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # Try first without --allmatch
        output = self.execute_command('{clamdscan} -c {clamd_config} --wait --ping 10 {test_exe}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, test_exe=test_exe))
        assert output.ec == 1
        assert output.out.count('FOUND') == 1


        # Next, try WITH --allmatch
        output = self.execute_command('{clamdscan} -c {clamd_config} --allmatch {test_exe}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, test_exe=test_exe))
        assert output.ec == 1
        assert output.out.count('FOUND') > 1


        # Try again without --allmatch
        output = self.execute_command('{clamdscan} -c {clamd_config} {test_exe}'.format(
            clamdscan=TC.clamdscan, clamd_config=TC.clamd_config, test_exe=test_exe))
        assert output.ec == 1
        assert output.out.count('FOUND') == 1

    def test_clamd_11_alertexceedsmax_maxfilesize(self):
        '''
        Verify that exceeding maxfilesize with AlertExceedsMax reports an alert and not an error.
        We'll use some fine-tuned values to make sure we check both MaxFileSize (for a flat file) and MaxScanSize (for an archive).
        '''
        self.step_name('Testing clamd\'s AlertExceedsMax with MaxFileSize and MaxScanSize')

        # Make a "big" file to test to test max filesize.
        # We'll go with 501 bytes.
        big_file = TC.path_tmp / 'big_file'
        with big_file.open('wb') as test_file:
            test_file.write(b'\x00' * 501)

        # Make an even bigger archive to test max scansize,
        # This ends up being 492 bytes.
        big_zip = TC.path_tmp / 'big_zip'
        with ZipFile(str(big_zip), 'w', ZIP_DEFLATED) as zf:
            # Add a bunch of smaller files that won't exceed max filesize
            for i in range(0, 5):
                zf.writestr(f'file-{i}', b'\x00' * 50)

        # We'll use a config that sets:
        #   MaxFileSize 500
        #   MaxScanSize 500
        #   AlertExceedsMax yes
        config = '''
            Foreground yes
            PidFile {pid}
            DatabaseDirectory {dbdir}
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
            MaxFileSize 500
            MaxScanSize 500
            AlertExceedsMax yes
            '''.format(pid=TC.clamd_pid, dbdir=TC.path_db)
        if operating_system == 'windows':
            # Only have TCP socket option for Windows.
            config += '''
                TCPSocket {socket}
                TCPAddr localhost
                '''.format(socket=TC.clamd_port_num)
        else:
            # Use LocalSocket for Posix, because that's what check_clamd expects.
            config += '''
                LocalSocket {localsocket}
                '''.format(localsocket=TC.clamd_socket)

        clamd_config = TC.path_tmp / 'clamd-test.conf'
        clamd_config.write_text(config)

        # Copy database to database path
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )

        #
        # Start ClamD with our custom config
        #
        self.start_clamd(clamd_config=clamd_config)

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # Check the big_file scan exceeds max filesize
        output = self.execute_command('{clamdscan} -c {clamd_config} --wait --ping 10 {test_exe}'.format(
            clamdscan=TC.clamdscan, clamd_config=clamd_config, test_exe=big_file))
        expected_results = ['MaxFileSize FOUND']
        unexpected_results = ['OK', 'MaxScanSize FOUND', 'Can\'t allocate memory ERROR']
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)
        assert output.ec == 1

        # Check the big_zip scan exceeds max scansize
        output = self.execute_command('{clamdscan} -c {clamd_config} {test_exe}'.format(
            clamdscan=TC.clamdscan, clamd_config=clamd_config, test_exe=big_zip))
        expected_results = ['MaxScanSize FOUND']
        unexpected_results = ['OK', 'MaxFileSize FOUND', 'Can\'t allocate memory ERROR']
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)
        assert output.ec == 1

    def test_clamd_12_onenote_disabled(self):
        self.step_name('Test that clamd.conf `ScanOneNote no` disables onenote support.')

        testpaths = [
            TC.path_build / "unit_tests" / "input" / "clamav_hdb_scanfiles" / "clam.exe.2007.one",
            TC.path_build / "unit_tests" / "input" / "clamav_hdb_scanfiles" / "clam.exe.2010.one",
            TC.path_build / "unit_tests" / "input" / "clamav_hdb_scanfiles" / "clam.exe.webapp-export.one",
        ]

        testfiles = ' '.join([str(testpath) for testpath in testpaths])

        # We'll use a config that sets `ScanOneNote yes`
        config = '''
            Foreground yes
            PidFile {pid}
            DatabaseDirectory {dbdir}
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
            ScanOneNote yes
            '''.format(pid=TC.clamd_pid, dbdir=TC.path_db)
        if operating_system == 'windows':
            # Only have TCP socket option for Windows.
            config += '''
                TCPSocket {socket}
                TCPAddr localhost
                '''.format(socket=TC.clamd_port_num)
        else:
            # Use LocalSocket for Posix, because that's what check_clamd expects.
            config += '''
                LocalSocket {localsocket}
                '''.format(localsocket=TC.clamd_socket)

        clamd_config = TC.path_tmp / 'clamd-test.conf'
        clamd_config.write_text(config)

        # Copy database to database path
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )

        #
        # Start ClamD with our custom config
        #
        self.start_clamd(clamd_config=clamd_config)

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # Check the big_file scan exceeds max filesize
        output = self.execute_command('{clamdscan} -c {clamd_config} --wait --ping 10 {testfiles}'.format(
            clamdscan=TC.clamdscan, clamd_config=clamd_config, testfiles=testfiles))

        assert output.ec == 1  # virus found

        expected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in testpaths]
        expected_results.append('Infected files: {}'.format(len(testpaths)))
        self.verify_output(output.out, expected=expected_results)


        #
        # Now retry with ScanOneNote disabled
        #

        # First kill clamd
        if self.proc != None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=120)
                self.proc.stdin.close()
            except OSError as exc:
                self.log.warning('Unexpected exception {}'.format(exc))
                pass  # ignore
            self.proc = None
        try:
            TC.clamd_pid.unlink()
        except Exception:
            pass # missing_ok=True is too for common use.
        try:
            TC.clamd_socket.unlink()
        except Exception:
            pass # missing_ok=True is too for common use.

        # Then update the config.
        # This time, we'll use a config that sets `ScanOneNote no`
        config = '''
            Foreground yes
            PidFile {pid}
            DatabaseDirectory {dbdir}
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
            ScanOneNote no
            '''.format(pid=TC.clamd_pid, dbdir=TC.path_db)
        if operating_system == 'windows':
            # Only have TCP socket option for Windows.
            config += '''
                TCPSocket {socket}
                TCPAddr localhost
                '''.format(socket=TC.clamd_port_num)
        else:
            # Use LocalSocket for Posix, because that's what check_clamd expects.
            config += '''
                LocalSocket {localsocket}
                '''.format(localsocket=TC.clamd_socket)

        clamd_config = TC.path_tmp / 'clamd-test.conf'
        clamd_config.write_text(config)

        #
        # Start ClamD with our custom config
        #
        self.start_clamd(clamd_config=clamd_config)

        poll = self.proc.poll()
        assert poll == None  # subprocess is alive if poll() returns None

        # Check the big_file scan exceeds max filesize
        output = self.execute_command('{clamdscan} -c {clamd_config} --wait --ping 10 {testfiles}'.format(
            clamdscan=TC.clamdscan, clamd_config=clamd_config, testfiles=testfiles))

        assert output.ec == 0  # virus found

        expected_results = ['{}: OK'.format(testpath.name) for testpath in testpaths]
        expected_results.append('Infected files: 0')
        self.verify_output(output.out, expected=expected_results)
