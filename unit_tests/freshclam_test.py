# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'clamav.hdb'),
            str(TC.path_www),
        )

        TC.path_db = Path(TC.path_tmp, 'database')
        TC.freshclam_pid = Path(TC.path_tmp, 'freshclam-test.pid')
        TC.freshclam_config = Path(TC.path_tmp, 'freshclam-test.conf')

        TC.mock_mirror_port = 8000
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

        if (TC.path_db / 'mirrors.dat').exists():
            os.remove(str(TC.path_db / 'mirrors.dat'))

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

def mock_database_mirror(handler, port=8000):
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
