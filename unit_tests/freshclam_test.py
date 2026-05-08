# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run freshclam tests
"""

import getpass
from multiprocessing import Process, Pipe
import os
from pathlib import Path
import platform
import shutil
import socket
import unittest
from functools import partial

from http.server import HTTPServer, BaseHTTPRequestHandler

import testcase

os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()
MOCK_MIRROR_IPV4_HOST = '127.0.0.1'
MOCK_MIRROR_IPV6_HOST = '::1'
MOCK_MIRROR_START_TIMEOUT = 10


class IPv6HTTPServer(HTTPServer):
    address_family = socket.AF_INET6


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        # Prepare a directory to host our test databases
        TC.path_www = Path(TC.path_tmp, 'www')
        TC.path_www.mkdir()

        TC.path_db = Path(TC.path_tmp, 'database')
        TC.path_db.mkdir()

        TC.freshclam_pid = Path(TC.path_tmp, 'freshclam-test.pid')
        TC.freshclam_config = Path(TC.path_tmp, 'freshclam-test.conf')

        TC.mock_mirror_host = MOCK_MIRROR_IPV4_HOST
        TC.mock_mirror_port = 8001 # Unused unless a test does not start the mock mirror.
        TC.mock_mirror = None

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        if TC.mock_mirror != None:
            TC.mock_mirror.terminate()
            TC.mock_mirror.join(5)
            if TC.mock_mirror.is_alive():
                TC.mock_mirror.kill()
                TC.mock_mirror.join()
            TC.mock_mirror = None
            TC.mock_mirror_host = MOCK_MIRROR_IPV4_HOST
            TC.mock_mirror_port = 8001

        # Clear the database directory
        try:
            shutil.rmtree(str(self.path_db))
        except Exception:
            pass
        self.path_db.mkdir()

        # Clear the www directory
        try:
            shutil.rmtree(str(self.path_www))
        except Exception:
            pass
        self.path_www.mkdir()

        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def start_mock_mirror(self, handler):
        TC.mock_mirror, TC.mock_mirror_host, TC.mock_mirror_port = (
            start_mock_database_mirror(handler)
        )

    def test_freshclam_00_version(self):
        self.step_name('freshclam version test')

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
        ))

        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'ClamAV {}'.format(TC.version),
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout)

    def test_freshclam_01_file_copy(self):
        self.step_name('Basic freshclam test using file:// to "download" clamav.hdb')

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        # Select database files for test
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseCustomURL file://{file_db}
            ExcludeDatabase daily
            ExcludeDatabase main
            ExcludeDatabase bytecode
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            file_db=TC.path_www / "clamav.hdb",
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))

        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'Downloading clamav.hdb',
            'Database test passed.',
            'clamav.hdb updated',
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout)

    def test_freshclam_02_http_403(self):
        self.step_name('Verify correct behavior when receiving 403 (forbidden)')

        self.start_mock_mirror(WebServerHandler_02)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=daily'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 17  # forbidden

        expected_stderr = [
            'FreshClam received error code 403',
            'Forbidden',
        ]

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr)

        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=daily'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # "fine" (on cooldown, refusing to try again for now)

        expected_stderr = [
            'FreshClam previously received error code 429 or 403',
            'You are still on cool-down until after',
        ]

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr)

    def test_freshclam_03_http_403_daemonized(self):
        self.step_name('Verify correct behavior when receiving 403 (forbidden) and daemonized')

        self.start_mock_mirror(WebServerHandler_02)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=daily --daemon -F'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 17  # forbidden

        expected_stderr = [
            'FreshClam received error code 403',
            'Forbidden',
        ]

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr)

    def test_freshclam_04_http_429(self):
        self.step_name('Verify correct behavior when receiving 429 (too-many-requests)')

        self.start_mock_mirror(WebServerHandler_04)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=daily'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stderr = [
            'FreshClam received error code 429',
            'You are on cool-down',
        ]

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr)

    def test_freshclam_05_cdiff_update(self):
        self.step_name('Verify that freshclam can update from an older CVD to a newer with CDIFF patches')

        # start with this CVD
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd.sign'), str(TC.path_db))

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff.sign'), str(TC.path_www))

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

    @unittest.skipIf(operating_system != 'windows', 'This test is specific to Windows.')
    def test_freshclam_05_cdiff_update_UNC(self):
        # This is a regression test for https://github.com/Cisco-Talos/clamav/pull/226
        self.step_name('Verify that freshclam can update from an older CVD to a newer with CDIFF patches with UNC paths')

        # start with this CVD
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd.sign'), str(TC.path_db))

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff.sign'), str(TC.path_www))

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        path_db_unc = str(TC.path_db).replace('C:\\', '\\\\localhost\\c$\\').replace('D:\\', '\\\\localhost\\d$\\').replace('E:\\', '\\\\localhost\\e$\\')

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=path_db_unc,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

    def test_freshclam_06_cdiff_partial_minus_1(self):
        self.step_name('Verify that freshclam will accept a partial update with 1 missing cdiff')

        # start with this CVD
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cvd.sign'), str(TC.path_db))

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff.sign'), str(TC.path_www))
        #shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))  # <-- don't give them the last CDIFF

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'Downloaded 2 patches for test, which is fewer than the 3 expected patches',
            'We\'ll settle for this partial-update, at least for now',
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

        #
        # Try again, we should be 1 behind which is tolerable and should not trigger a full CVD download
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'The database server doesn\'t have the latest patch',
            'The server will likely have updated if you check again in a few hours',
        ]
        unexpected_results = [
            'test.cld updated',
            'test.cvd updated',
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

    def test_freshclam_07_cdiff_partial_minus_2(self):
        self.step_name('Verify that freshclam behavior with 2 missing cdiffs')

        # start with this CVD
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cvd.sign'), str(TC.path_db))

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # serve this CVD when requested instead of the advertised one
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.served'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd.sign'), str(TC.path_www))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff'), str(TC.path_www))
        # shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))  <--- don't give them the second to last, either!
        # shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))  <--- don't give them the last CDIFF

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'Downloaded 1 patches for test, which is fewer than the 3 expected patches',
            'We\'ll settle for this partial-update, at least for now',
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

        #
        # Try again, we should be 2 behind which is NOT tolerable and SHOULD trigger a full CVD download
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = ['test.cvd updated']
        expected_stderr = ['Incremental update failed, trying to download test.cvd']
        unexpected_results = ['test.cld updated']

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr, unexpected=unexpected_results)

    def test_freshclam_07_no_cdiff_out_of_date_cvd(self):
        self.step_name('Verify that freshclam will properly handle an out-of-date CVD update after a zero-byte CDIFF')

        # start with CVD 1
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd.sign'), str(TC.path_db))

        # advertise CVD 6 (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # Serve the patches 2.
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff.sign'), str(TC.path_www))

        # Serve a zero-byte file instead of test-3.cdiff. This should trigger a whole CVD download.
        with (TC.path_www / 'test-3.cdiff').open('w') as fp:
            pass

        # Serve CVD 5 when test.cvd is requested instead of 6 (the advertised one). This should trigger an incremental update, starting a test-4.cvd + patches 5-6.
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cvd'), str(TC.path_www / 'test.cvd.served'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cvd.sign'), str(TC.path_www))

        # Serve the patches 5 - 6. Patch 4 should never be requested.
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff.sign'), str(TC.path_www))

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))

        #
        # 1st attempt
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = ['test.cvd updated \\(version: 5']
        expected_stderr = ['Received an older test CVD than was advertised. Incremental updates either failed or ']
        unexpected_results = ['already up-to-date']

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, expected=expected_stderr, unexpected=unexpected_results)

        #
        # 2nd attempt
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'test.cld updated \\(version: 6',
        ]
        unexpected_results = [
            'already up-to-date',
            'Received an older test CVD than was advertised',
            'cdiff_apply: lseek\\(desc, -350, SEEK_END\\) failed',
            'Incremental update failed, trying to download test.cvd',
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

        #
        # 3rd attempt
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'database is up-to-date',
        ]
        unexpected_results = [
            'test.cld updated \\(version: 6',
            'Received an older test CVD than was advertised',
            'cdiff_apply: lseek\\(desc, -350, SEEK_END\\) failed',
            'Incremental update failed, trying to download test.cvd',
        ]
        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

    def test_freshclam_08_cdiff_update_twice(self):
        self.step_name('Verify that freshclam can update from an older CVD to a newer with CDIFF patches, and then update from an older CLD to the latest with more CDIFF patches')

        # start with this CVD
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd'), str(TC.path_db / 'test.cvd'))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-1.cvd.sign'), str(TC.path_db))

        # advertise this CVD FIRST (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-2.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-3.cdiff.sign'), str(TC.path_www))

        handler = partial(WebServerHandler_WWW, TC.path_www)
        self.start_mock_mirror(handler)

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://{host}:{port}
            DNSDatabaseInfo no
            PidFile {freshclam_pid}
            LogVerbose yes
            LogFileMaxSize 0
            LogTime yes
            DatabaseDirectory {path_db}
            DatabaseOwner {user}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            host=TC.mock_mirror_host,
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))

        #
        # Now run the update for the first set up updates.
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --debug --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]

        # verify stdout
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_results)

        # verify stderr
        self.verify_output(output.err, unexpected=unexpected_results)

        # advertise this newer CVD SECOND (by sending the header response to Range requests)
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cvd'), str(TC.path_www / 'test.cvd.advertised'))

        # using these CDIFFs
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-4.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-5.cdiff.sign'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff'), str(TC.path_www))
        shutil.copy(str(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' / 'test-6.cdiff.sign'), str(TC.path_www))

        #
        # Now re-run the update for more updates.
        #
        command = '{valgrind} {valgrind_args} {freshclam} --no-dns --debug --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_stdout = [
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]


def start_mock_database_mirror(handler):
    '''
    Start the mock mirror and wait until it is ready to accept connections.
    '''
    parent_conn, child_conn = Pipe(duplex=False)
    server_process = Process(target=mock_database_mirror, args=(handler, child_conn))
    server_process.start()
    child_conn.close()

    try:
        if not parent_conn.poll(MOCK_MIRROR_START_TIMEOUT):
            raise RuntimeError("Timed out waiting for mock database mirror to start.")

        try:
            message = parent_conn.recv()
        except EOFError as e:
            raise RuntimeError("Mock database mirror exited before reporting readiness.") from e

        if message[0] != 'ready':
            raise RuntimeError("Mock database mirror failed to start: {}".format(message[1]))

        return server_process, format_url_host(message[1]), message[2]
    except Exception:
        server_process.terminate()
        server_process.join(5)
        if server_process.is_alive():
            server_process.kill()
            server_process.join()
        raise
    finally:
        parent_conn.close()


def format_url_host(host):
    '''
    Format an address literal for use in a URL.
    '''
    if ':' in host and not host.startswith('['):
        return '[{}]'.format(host)
    return host


def create_mock_database_mirror_server(handler, port):
    '''
    Bind to IPv4 loopback first, then IPv6 loopback if IPv4 is unavailable.
    '''
    last_error = None

    for server_class, host in (
        (HTTPServer, MOCK_MIRROR_IPV4_HOST),
        (IPv6HTTPServer, MOCK_MIRROR_IPV6_HOST),
    ):
        try:
            return server_class((host, port), handler)
        except OSError as e:
            last_error = e

    raise last_error


def mock_database_mirror(handler, ready_conn=None, port=0):
    '''
    Process entry point for our HTTP Server to mock a database mirror.
    '''
    server = None
    try:
        server = create_mock_database_mirror_server(handler, port)
        bound_host = server.server_address[0]
        bound_port = server.server_address[1]
        if ready_conn is not None:
            ready_conn.send(('ready', bound_host, bound_port))
            ready_conn.close()
            ready_conn = None

        print("Web server is running on {}:{}".format(bound_host, bound_port))
        server.serve_forever()

    except KeyboardInterrupt:
        print("^C entered, stopping web server...")
    except Exception as e:
        if ready_conn is not None:
            ready_conn.send(('error', str(e)))
            ready_conn.close()
        raise
    finally:
        if server is not None:
            server.server_close()

class WebServerHandler_02(BaseHTTPRequestHandler):
    '''
    Web server handler to send 403 (Forbidden) if a whole file is requested.
    Will send a CVD header if a Range-request is received.
    '''
    def do_GET(self):
        if 'Range' in self.headers:
            # HACK: This will send a CVD header so FreshClam thinks there is an update.
            #       This is needed so we can operate with `DNSDatabaseInfo no` in case
            #       someone wants to run these tests without internet access.
            self.send_response(206) # Partial file
            self.send_header('Content-type', 'application/octet-stream')
            page =b'ClamAV-VDB:21 Sep 2020 09-52 -0400:25934:4320797:63:2ee5a3e4285b496656117ae3809b6040:gMj7NXhxfew0+bToOF8GX7xPHPGXhOSD+CSuf3E7SHhLmVZCJUVhPS01h42I0W1py7L+BmM2yhPIW8t/oGPFw8+hdD4DU/ceET15wnPWU4lsJJeRkl46Z4D8INe9Oq36ixT1xEIkERogPE3qr6wszmjT2Xe2VcmydTXN2GfPQX:raynman:1600696324                                                                                                                                                                                                                                               '
        else:
            # Send the 403 FORBIDDEN header.
            self.send_response(403) # Forbidden (blocked)
            self.send_header('Content-type', 'text/html')
            page= b'''<html><body>
                    No CVD for you!
                    </body></html>'''
        self.end_headers()
        self.wfile.write(page)

class WebServerHandler_04(BaseHTTPRequestHandler):
    '''
    Web server handler to send 429 (Too-Many-Requests) if a whole file is requested.
    Will send a CVD header if a Range-request is received.
    '''
    def do_GET(self):
        if 'Range' in self.headers:
            # HACK: This will send a CVD header so FreshClam thinks there is an update.
            #       This is needed so we can operate with `DNSDatabaseInfo no` in case
            #       someone wants to run these tests without internet access.
            self.send_response(206) # Partial file
            self.send_header('Content-type', 'application/octet-stream')
            page =b'ClamAV-VDB:21 Sep 2020 09-52 -0400:25934:4320797:63:2ee5a3e4285b496656117ae3809b6040:gMj7NXhxfew0+bToOF8GX7xPHPGXhOSD+CSuf3E7SHhLmVZCJUVhPS01h42I0W1py7L+BmM2yhPIW8t/oGPFw8+hdD4DU/ceET15wnPWU4lsJJeRkl46Z4D8INe9Oq36ixT1xEIkERogPE3qr6wszmjT2Xe2VcmydTXN2GfPQX:raynman:1600696324                                                                                                                                                                                                                                               '
        else:
            # Send the 429 Too-Many-Requests header.
            self.send_response(429) # Too-Many-Requests (rate limiting)
            self.send_header('Content-type', 'text/html')
            self.send_header('Retry-After', '60') # Try again in a minute ;-)!
            page= b'''<html><body>
                    Retry later please!
                    </body></html>'''
        self.end_headers()
        self.wfile.write(page)

class WebServerHandler_WWW(BaseHTTPRequestHandler):
    '''
    Make an HTTP server handler that has a configurable directory for hosting files.

    Server handler to send a CVD header of `test.cvd.advertised` indicating an update is available,
    and then to serve up CDIFFs that should allow the test to do an incremental update.

    If `test.cvd` is requested, it will serve up `test.cvd.served` (not `test.cvd.advertised`)
    '''

    def __init__(self, path_www, *args, **kwargs):
        self.path_www = path_www
        super().__init__(*args, **kwargs)

    def do_GET(self):
        requested_file = self.path_www / self.path.lstrip('/')
        print("Mock Server:  Test requested: {}".format(requested_file))

        if 'Range' in self.headers:
            # This will send a CVD header so FreshClam thinks there is an update.
            (range_start, range_end) = self.headers['Range'].split('=')[-1].split('-')
            print("Mock Server:  But they only want bytes {} through {} ...".format(range_start, range_end))

            if requested_file.name.endswith('.cvd'):
                response_file = requested_file.parent / '{}.advertised'.format(requested_file)
            else:
                response_file = requested_file

            if not response_file.exists():
                self.send_error(404, "{} Not Found".format(self.path.lstrip('/')))
            else:
                with response_file.open('rb') as the_file:
                    self.send_response(206) # Partial file
                    self.send_header('Content-type', 'application/octet-stream')
                    self.end_headers()

                    the_file.seek(int(range_start))
                    page = the_file.read(int(range_end) - int(range_start) + 1)

                    bytes_written = self.wfile.write(page)
                    print("Mock Server:  Sending {} bytes back to client.".format(bytes_written))

        else:
            # Send back some whole files
            if requested_file.name.endswith('.cvd'):
                response_file = requested_file.parent / '{}.served'.format(requested_file)
            else:
                response_file = requested_file

            if not response_file.exists():
                self.send_error(404, "{} Not Found".format(self.path.lstrip('/')))
            else:
                with response_file.open('rb') as the_file:
                    self.send_response(200) # Partial file
                    self.send_header('Content-type', 'application/octet-stream')
                    self.end_headers()

                    page = the_file.read()

                    bytes_written = self.wfile.write(page)
                    print("Mock Server:  Sending {} bytes back to client.".format(bytes_written))
