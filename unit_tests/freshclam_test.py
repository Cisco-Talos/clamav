# Copyright (C) 2020-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run freshclam tests
"""

import getpass
from multiprocessing import Process, Pipe
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest
from functools import partial

from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi

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

        TC.path_db = Path(TC.path_tmp, 'database')
        TC.freshclam_pid = Path(TC.path_tmp, 'freshclam-test.pid')
        TC.freshclam_config = Path(TC.path_tmp, 'freshclam-test.conf')

        TC.mock_mirror_port = 8001 # Chosen instead of 8000 because CVD-Update tool serves on 8000 by default.
                                   # TODO: Ideally we'd find an open port to use for these tests instead of crossing our fingers.
        TC.mock_mirror = None

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        if TC.mock_mirror != None:
            TC.mock_mirror.terminate()
            TC.mock_mirror = None

        # Clear the database directory
        try:
            shutil.rmtree(self.path_db)
        except Exception:
            pass
        self.path_db.mkdir()

        # Clear the www directory
        try:
            shutil.rmtree(self.path_www)
        except Exception:
            pass
        self.path_www.mkdir()

        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_freshclam_00_version(self):
        self.step_name('freshclam version test')

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
        '''.format(
            freshclam_pid=TC.freshclam_pid,
            path_db=TC.path_db,
            port=TC.mock_mirror_port,
        ))

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

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        # Select database files for test
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            file_db=TC.path_www / "clamav.hdb",
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))

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

    def test_freshclam_02_http_403(self):
        self.step_name('Verify correct behavior when receiving 403 (forbidden)')

        # Start our mock database mirror.
        TC.mock_mirror = Process(target=mock_database_mirror, args=(WebServerHandler_02,))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=daily'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 17  # forbidden

        expected_results = [
            'FreshClam received error code 403',
            'Forbidden',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_freshclam_03_http_403_daemonized(self):
        self.step_name('Verify correct behavior when receiving 403 (forbidden) and daemonized')

        # Start our mock database mirror.
        TC.mock_mirror = Process(target=mock_database_mirror, args=(WebServerHandler_02,))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=daily --daemon -F'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 17  # forbidden

        expected_results = [
            'FreshClam received error code 403',
            'Forbidden',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_freshclam_04_http_429(self):
        self.step_name('Verify correct behavior when receiving 429 (too-many-requests)')

        # Start our mock database mirror.
        TC.mock_mirror = Process(target=mock_database_mirror, args=(WebServerHandler_04,TC.mock_mirror_port))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=daily'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'FreshClam received error code 429',
            'You are on cool-down',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_freshclam_05_cdiff_update(self):
        self.step_name('Verify that freshclam can update from an older CVD to a newer with CDIFF patches')

        # start with this CVD
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-1.cvd', TC.path_db / 'test.cvd')

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cvd', TC.path_www / 'test.cvd.advertised')

        # using these CDIFFs
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-2.cdiff', TC.path_www)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-3.cdiff', TC.path_www)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-4.cdiff', TC.path_www)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-5.cdiff', TC.path_www)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cdiff', TC.path_www)

        handler = partial(WebServerHandler_WWW, TC.path_www)
        TC.mock_mirror = Process(target=mock_database_mirror, args=(handler, TC.mock_mirror_port))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_freshclam_06_cdiff_partial_minus_1(self):
        self.step_name('Verify that freshclam will accept a partial update with 1 missing cdiff')

        # start with this CVD
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-3.cvd', TC.path_db / 'test.cvd')

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cvd', TC.path_www / 'test.cvd.advertised')

        # using these CDIFFs
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-4.cdiff', TC.path_www)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-5.cdiff', TC.path_www)
        #shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cdiff', TC.path_www)  # <-- don't give them the last CDIFF

        handler = partial(WebServerHandler_WWW, TC.path_www)
        TC.mock_mirror = Process(target=mock_database_mirror, args=(handler, TC.mock_mirror_port))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Downloaded 2 patches for test, which is fewer than the 3 expected patches',
            'We\'ll settle for this partial-update, at least for now',
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

        #
        # Try again, we should be 1 behind which is tolerable and should not trigger a full CVD download
        #
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'The database server doesn\'t have the latest patch',
            'The server will likely have updated if you check again in a few hours',
        ]
        unexpected_results = [
            'test.cld updated',
            'test.cvd updated',
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_freshclam_07_cdiff_partial_minus_2(self):
        self.step_name('Verify that freshclam behavior with 2 missing cdiffs')

        # start with this CVD
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-3.cvd', TC.path_db / 'test.cvd')

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cvd', TC.path_www / 'test.cvd.advertised')

        # serve this CVD when requested instead of the advertised one
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cvd', TC.path_www / 'test.cvd.served')

        # using these CDIFFs
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-4.cdiff', TC.path_www)
        # shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-5.cdiff', TC.path_www)  <--- dont' give them the second to last, either!
        # shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cdiff', TC.path_www)  <--- don't give them the last CDIFF

        handler = partial(WebServerHandler_WWW, TC.path_www)
        TC.mock_mirror = Process(target=mock_database_mirror, args=(handler, TC.mock_mirror_port))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Downloaded 1 patches for test, which is fewer than the 3 expected patches',
            'We\'ll settle for this partial-update, at least for now',
            'test.cld updated',
        ]
        unexpected_results = [
            'already up-to-date'
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

        #
        # Try again, we should be 2 behind which is NOT tolerable and SHOULD trigger a full CVD download
        #
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Incremental update failed, trying to download test.cvd',
            'test.cvd updated',
        ]
        unexpected_results = [
            'test.cld updated',
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_freshclam_07_no_cdiff_out_of_date_cvd(self):
        self.step_name('Verify that freshclam will properly handle an out-of-date CVD update after a zero-byte CDIFF')

        # start with this CVD
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-3.cvd', TC.path_db / 'test.cvd')

        # advertise this CVD (by sending the header response to Range requests)
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-6.cvd', TC.path_www / 'test.cvd.advertised')

        # serve this CVD when requested instead of the advertised one
        shutil.copy(TC.path_source / 'unit_tests' / 'input' / 'freshclam_testfiles' /'test-5.cvd', TC.path_www / 'test.cvd.served')

        # Serve a zero-byte test-4.cdiff instead of the real test-4.cdiff. This should trigger a whole CVD download.
        with (TC.path_www / 'test-4.cdiff').open('w') as fp:
            pass

        handler = partial(WebServerHandler_WWW, TC.path_www)
        TC.mock_mirror = Process(target=mock_database_mirror, args=(handler, TC.mock_mirror_port))
        TC.mock_mirror.start()

        if TC.freshclam_config.exists():
            os.remove(str(TC.freshclam_config))

        TC.freshclam_config.write_text('''
            DatabaseMirror http://localhost:{port}
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
            port=TC.mock_mirror_port,
            user=getpass.getuser(),
        ))
        command = '{valgrind} {valgrind_args} {freshclam} --config-file={freshclam_config} --update-db=test'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, freshclam=TC.freshclam, freshclam_config=TC.freshclam_config
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'Incremental updates either failed or are disabled, so we\'ll have to settle for a slightly out-of-date database.',
        ]
        unexpected_results = [
            'already up-to-date'
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

def mock_database_mirror(handler, port=8001):
    '''
    Process entry point for our HTTP Server to mock a database mirror.
    '''
    try:
        server = HTTPServer(('', port), handler)
        print("Web server is running on port {}".format(port))
        server.serve_forever()

    except KeyboardInterrupt:
        print("^C entered, stopping web server...")
        server.socket.close()

class WebServerHandler_02(BaseHTTPRequestHandler):
    '''
    Web server handler to send 403 (Forbidden) if a whole file is requested.
    Will send a CVD header if a Range-requeset is received.
    '''
    def do_GET(self):
        if 'Range' in self.headers:
            # HACK: This will send a CVD header so FreshClam thinks there is an update.
            #       This is needed so we can operate with `DNSDatabaseInfo no` in case
            #       someone wants to run these tests without internet access.
            self.send_response(206) # Partial file
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            page =b'ClamAV-VDB:21 Sep 2020 09-52 -0400:25934:4320797:63:2ee5a3e4285b496656117ae3809b6040:gMj7NXhxfew0+bToOF8GX7xPHPGXhOSD+CSuf3E7SHhLmVZCJUVhPS01h42I0W1py7L+BmM2yhPIW8t/oGPFw8+hdD4DU/ceET15wnPWU4lsJJeRkl46Z4D8INe9Oq36ixT1xEIkERogPE3qr6wszmjT2Xe2VcmydTXN2GfPQX:raynman:1600696324                                                                                                                                                                                                                                               '
            self.wfile.write(page)

        else:
            # Send the 403 FORBIDDEN header.
            self.send_response(403) # Forbidden (blocked)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            page= b'''<html><body>
                    No CVD for you!
                    </body></html>'''
            self.wfile.write(page)

class WebServerHandler_04(BaseHTTPRequestHandler):
    '''
    Web server handler to send 429 (Too-Many-Requests) if a whole file is requested.
    Will send a CVD header if a Range-requeset is received.
    '''
    def do_GET(self):
        if 'Range' in self.headers:
            # HACK: This will send a CVD header so FreshClam thinks there is an update.
            #       This is needed so we can operate with `DNSDatabaseInfo no` in case
            #       someone wants to run these tests without internet access.
            self.send_response(206) # Partial file
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            page =b'ClamAV-VDB:21 Sep 2020 09-52 -0400:25934:4320797:63:2ee5a3e4285b496656117ae3809b6040:gMj7NXhxfew0+bToOF8GX7xPHPGXhOSD+CSuf3E7SHhLmVZCJUVhPS01h42I0W1py7L+BmM2yhPIW8t/oGPFw8+hdD4DU/ceET15wnPWU4lsJJeRkl46Z4D8INe9Oq36ixT1xEIkERogPE3qr6wszmjT2Xe2VcmydTXN2GfPQX:raynman:1600696324                                                                                                                                                                                                                                               '
            self.wfile.write(page)

        else:
            # Send the 429 Too-Many-Requests header.
            self.send_response(429) # Too-Many-Requests (rate limiting)
            self.send_header('Content-type', 'text/html')
            self.send_header('Retry-After', '60') # Try again in a minute ;-)!
            self.end_headers()

            page= b'''<html><body>
                    Retry later please!
                    </body></html>'''
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
                response_file = requested_file.parent / f'{requested_file}.advertised'
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
                response_file = requested_file.parent / f'{requested_file}.served'
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
