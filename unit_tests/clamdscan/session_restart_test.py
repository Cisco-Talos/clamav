# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Regression tests for ClamDScan IDSESSION recovery after clamd hangs up.

These tests do not use a real clamd.  Making clamd drop a session in the middle
of a scan depends on timing (a CommandReadTimeout expiry) and would be flaky.
Instead they run clamdscan against a stand-in server that speaks just enough of
the IDSESSION protocol and closes the connection at an exact point in the
exchange, which makes every restart deterministic.
"""

import hashlib
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.append('../unit_tests')
import testcase


operating_system = platform.platform().split('-')[0].lower()

# Must match MAX_SESSION_RESTARTS in clamdscan/proto.c.  It bounds restarts
# that happen in a row without clamd answering in between, not the number of
# disconnects a scan may recover from in total.
MAX_SESSION_RESTARTS = 3

# The stand-in server calls everything infected.  A verdict that never reaches
# clamdscan is then visible in the infected count, which is what makes "this
# file silently went unscanned" an assertable failure.
SIGNATURE = 'ClamAV-Session-Restart-Test.UNOFFICIAL'

# "Serve this connection normally", as opposed to a (requests, replies) drop.
SERVE_NORMALLY = None


class MessageReader(object):
    """Reads the client half of the clamd protocol off a connected socket.

    Every read goes through recvmsg() so that the descriptor a FILDES command
    passes as SCM_RIGHTS ancillary data is never dropped on the floor.
    """

    def __init__(self, conn):
        self._conn = conn
        self._buffer = bytearray()
        self._descriptors = []
        self._at_eof = False

    def _fill(self):
        if self._at_eof:
            return False

        try:
            data, ancillary, _flags, _addr = self._conn.recvmsg(
                4096, socket.CMSG_SPACE(struct.calcsize('i')))
        except OSError:
            self._at_eof = True
            return False

        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(payload) // struct.calcsize('i')
                self._descriptors.extend(
                    struct.unpack('{}i'.format(count),
                                  payload[:count * struct.calcsize('i')]))

        if not data:
            self._at_eof = True
            return False

        self._buffer.extend(data)
        return True

    def read_exact(self, count):
        while len(self._buffer) < count:
            if not self._fill():
                return None

        data = bytes(self._buffer[:count])
        del self._buffer[:count]
        return data

    def read_command(self):
        """Returns the next NUL-terminated command, or None at end of stream."""
        while True:
            end = self._buffer.find(b'\0')
            if end >= 0:
                break
            if not self._fill():
                return None

        command = bytes(self._buffer[:end])
        del self._buffer[:end + 1]

        # Every command clamdscan sends in a session is "z"-prefixed.
        if command.startswith(b'z'):
            command = command[1:]
        return command

    def read_stream(self):
        """Reads the length-prefixed chunks that follow an INSTREAM command."""
        payload = bytearray()

        while True:
            header = self.read_exact(4)
            if header is None:
                return None

            size = struct.unpack('!I', header)[0]
            if size == 0:
                return bytes(payload)

            chunk = self.read_exact(size)
            if chunk is None:
                return None
            payload.extend(chunk)

    def read_fildes(self):
        """Reads the descriptor that follows a FILDES command, and its file."""
        # The command is followed by a one byte message carrying the descriptor.
        if self.read_exact(1) is None:
            return None
        if not self._descriptors:
            return None

        descriptor = self._descriptors.pop(0)
        payload = bytearray()
        try:
            while True:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    break
                payload.extend(chunk)
        finally:
            os.close(descriptor)

        return bytes(payload)


class FakeClamd(threading.Thread):
    """A clamd stand-in that can hang up in the middle of an IDSESSION.

    `behaviors` is applied to connections in order.  Each entry is either
    SERVE_NORMALLY, or a (requests, replies) pair meaning "answer the first this
    many requests, then stop answering, and close the connection once this many
    requests have arrived".  Whatever went unanswered is exactly what clamdscan
    has to re-send.  Connections past the end of `behaviors` are served normally.
    """

    def __init__(self, socket_path, behaviors=(), accept_limit=None):
        threading.Thread.__init__(self)
        self.daemon = True

        self.socket_path = str(socket_path)
        self.behaviors = list(behaviors)
        # Stop listening after this many connections, so that clamdscan's next
        # reconnect is refused outright rather than the session merely dying.
        self.accept_limit = accept_limit

        self.connections = 0    # how many times clamdscan (re)connected
        self.scanned = []       # digest of every file received, in order
        self.error = None       # first protocol violation seen, if any

        self._stopping = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(self.socket_path)
        self._listener.listen(8)
        # Closing a listening socket does not wake up a blocked accept(), so
        # poll instead of relying on the close in stop() to break the loop.
        self._listener.settimeout(0.1)

    def stop(self):
        self._stopping.set()
        self.join(timeout=60)
        try:
            self._listener.close()
        except OSError:
            pass

    def run(self):
        while not self._stopping.is_set():
            try:
                conn, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return  # the listening socket went away

            index = self.connections
            self.connections += 1

            behavior = SERVE_NORMALLY
            if index < len(self.behaviors):
                behavior = self.behaviors[index]

            try:
                conn.settimeout(None)
                self._serve(conn, behavior)
            except Exception as exc:  # noqa: BLE001 - reported back to the test
                if self.error is None:
                    self.error = exc
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

            if self.accept_limit is not None and self.connections >= self.accept_limit:
                try:
                    self._listener.close()
                except OSError:
                    pass
                return

    def _serve(self, conn, behavior):
        reader = MessageReader(conn)
        last_id = 0
        received = 0
        answered = 0

        while True:
            command = reader.read_command()
            if command is None:
                return  # clamdscan closed the connection
            if command == b'IDSESSION':
                continue
            if command == b'END':
                return

            if command == b'INSTREAM':
                payload = reader.read_stream()
                description = 'stream'
            elif command == b'FILDES':
                payload = reader.read_fildes()
                description = 'fd[0]'
            else:
                raise AssertionError(
                    'unexpected command from clamdscan: {}'.format(command))

            if payload is None:
                return  # truncated request; clamdscan went away mid-send

            self.scanned.append(hashlib.sha256(payload).hexdigest())
            last_id += 1
            received += 1

            if behavior is SERVE_NORMALLY or answered < behavior[1]:
                self._reply(conn, last_id, description)
                answered += 1

            if behavior is not SERVE_NORMALLY and received >= behavior[0]:
                # Hang up, leaving whatever went unanswered outstanding for
                # clamdscan to re-send on a new session.
                conn.close()
                return

    @staticmethod
    def _reply(conn, scan_id, description):
        conn.sendall('{}: {}: {} FOUND\0'.format(
            scan_id, description, SIGNATURE).encode('utf-8'))


@unittest.skipIf(operating_system == 'windows',
                 'the stand-in clamd listens on an AF_UNIX socket.')
class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

        self.server = None

        # AF_UNIX paths are limited to ~108 bytes, and the test temp directory
        # can be nested deeply enough to blow past that, so keep the socket in a
        # directory of its own with a short path.
        self.socket_dir = Path(tempfile.mkdtemp(prefix='clamdscan-sock-', dir='/tmp'))
        self.socket_path = self.socket_dir / 'clamd.sock'

        self.scan_dir = self.path_tmp / '{}-files'.format(self._testMethodName)
        self.scan_dir.mkdir()

    def tearDown(self):
        if self.server is not None:
            self.server.stop()
            self.server = None

        shutil.rmtree(str(self.socket_dir), ignore_errors=True)

        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def create_scan_files(self, count, size=0):
        """Writes `count` files with unique contents, and returns their digests.

        `size` pads each file out to at least that many bytes, for the tests
        that need a request too large to fit in the socket buffer.
        """
        digests = []

        for index in range(count):
            payload = 'clamdscan-session-restart-{:04d}\n'.format(index).encode('utf-8')
            if size > len(payload):
                payload += b'.' * (size - len(payload))
            (self.scan_dir / 'file-{:04d}'.format(index)).write_bytes(payload)
            digests.append(hashlib.sha256(payload).hexdigest())

        return digests

    def start_fake_clamd(self, behaviors=(), accept_limit=None):
        self.server = FakeClamd(self.socket_path, behaviors=behaviors,
                                accept_limit=accept_limit)
        self.server.start()
        return self.server

    def run_clamdscan(self, mode):
        config = self.path_tmp / '{}-clamd.conf'.format(self._testMethodName)
        config.write_text('LocalSocket {}\n'.format(self.socket_path))

        return self.execute_command(
            '{valgrind} {valgrind_args} {clamdscan} {mode} --multiscan -c {config} {target}'.format(
                valgrind=TC.valgrind,
                valgrind_args=TC.valgrind_args,
                clamdscan=TC.clamdscan,
                mode=mode,
                config=config,
                target=self.scan_dir))

    def assert_server_healthy(self):
        if self.server.error is not None:
            raise self.server.error

    def test_session_restart_01_stream_resends_outstanding(self):
        """A mid-session hangup re-sends every unanswered stream request."""
        self.step_name('Testing IDSESSION recovery in --stream mode')

        expected = self.create_scan_files(20)

        # Take 5 requests, answer 2 of them, then hang up: 3 requests are left
        # outstanding and must reappear on the second session.
        self.start_fake_clamd(behaviors=[(5, 2)])

        output = self.run_clamdscan('--stream')
        self.assert_server_healthy()

        assert output.ec == 1  # everything is "infected", nothing errored

        self.verify_output(output.err, expected=[
            r'Connection to clamd lost \(restart 1/{}\)'.format(MAX_SESSION_RESTARTS),
            r'outstanding request\(s\)',
        ])
        # Every file must come back with a verdict, including the re-sent ones.
        self.verify_output(output.out, expected=['Infected files: 20'])
        self.verify_output(output.out, unexpected=['Total errors:'])

        assert self.server.connections == 2
        assert set(self.server.scanned) == set(expected)

    @unittest.skipIf(operating_system == 'windows', 'no FD passing on Windows')
    def test_session_restart_02_fdpass_resends_outstanding(self):
        """The same recovery, over the separate FD passing code path."""
        self.step_name('Testing IDSESSION recovery in --fdpass mode')

        expected = self.create_scan_files(20)

        self.start_fake_clamd(behaviors=[(5, 2)])

        output = self.run_clamdscan('--fdpass')
        self.assert_server_healthy()

        assert output.ec == 1

        self.verify_output(output.err, expected=[
            r'Connection to clamd lost \(restart 1/{}\)'.format(MAX_SESSION_RESTARTS),
            r'outstanding request\(s\)',
        ])
        self.verify_output(output.out, expected=['Infected files: 20'])

        assert self.server.connections == 2
        assert set(self.server.scanned) == set(expected)

    def test_session_restart_03_recovers_when_the_new_session_dies_too(self):
        """A hangup that lands while re-sending is recovered from as well."""
        self.step_name('Testing IDSESSION recovery when the new session also dies')

        # The requests are sized so that the whole backlog does not fit in the
        # socket buffer.  clamdscan is then still in send() when the second
        # session is dropped, so the re-send itself fails rather than the
        # failure only turning up on the following read.  That is the path that
        # has to put the request back on the outstanding list.
        expected = self.create_scan_files(20, size=64 * 1024)

        # The first session dies with several requests outstanding; the
        # replacement session then dies while those are being re-sent.
        self.start_fake_clamd(behaviors=[(6, 0), (1, 0)])

        output = self.run_clamdscan('--stream')
        self.assert_server_healthy()

        assert output.ec == 1

        self.verify_output(output.err, expected=[
            r'Connection to clamd lost \(restart 2/{}\)'.format(MAX_SESSION_RESTARTS),
        ])
        # A request dropped by the second failure would silently never be
        # scanned again, leaving the count short.
        self.verify_output(output.out, expected=['Infected files: 20'])
        self.verify_output(output.out, unexpected=['Total errors:'])

        assert self.server.connections == 3
        assert set(self.server.scanned) == set(expected)

    def test_session_restart_04_gives_up_after_max_restarts(self):
        """clamdscan stops reconnecting once the restart budget is spent."""
        self.step_name('Testing the IDSESSION restart budget')

        self.create_scan_files(20)

        # Every session dies after a single request and answers nothing, so no
        # amount of reconnecting will make progress.
        self.start_fake_clamd(behaviors=[(1, 0)] * (MAX_SESSION_RESTARTS + 5))

        output = self.run_clamdscan('--stream')
        self.assert_server_healthy()

        assert output.ec == 2  # gave up with an error

        self.verify_output(output.err, expected=[
            'Connection to clamd lost {} consecutive times, giving up'.format(MAX_SESSION_RESTARTS),
        ])

        # The original connection plus one per restart, and not one more.
        assert self.server.connections == MAX_SESSION_RESTARTS + 1

    def test_session_restart_05_budget_only_counts_consecutive_failures(self):
        """Disconnects that the scan recovers from do not use up the budget."""
        self.step_name('Testing that the IDSESSION restart budget resets on progress')

        file_count = 40

        # Sized so that clamdscan cannot run far ahead of the server: the
        # backlog left behind by a hangup stays small enough for the next
        # session to absorb it, which is what a healthy clamd would do.
        expected = self.create_scan_files(file_count, size=64 * 1024)

        # Every session answers a few requests and then hangs up.  That is far
        # more disconnects than the budget allows, but the scan makes progress
        # across each one, so it has to run to completion rather than give up.
        self.start_fake_clamd(behaviors=[(5, 5)] * file_count)

        output = self.run_clamdscan('--stream')
        self.assert_server_healthy()

        assert output.ec == 1

        self.verify_output(output.out, expected=['Infected files: {}'.format(file_count)])
        self.verify_output(output.err, unexpected=['giving up'])

        assert self.server.connections > MAX_SESSION_RESTARTS + 1
        assert set(self.server.scanned) == set(expected)

    def test_session_restart_06_releases_outstanding_when_reconnect_fails(self):
        """Giving up on a reconnect must not leak the outstanding requests."""
        self.step_name('Testing cleanup when the session cannot be restored')

        self.create_scan_files(20)

        # The session dies with requests outstanding and nothing is listening
        # afterwards, so clamdscan gives up straight away.  Under Valgrind this
        # is where the requests it was still holding would show up as leaked.
        self.start_fake_clamd(behaviors=[(5, 0)], accept_limit=1)

        output = self.run_clamdscan('--stream')
        self.assert_server_healthy()

        assert output.ec == 2  # gave up with an error, nothing was reported

        self.verify_output(output.err, expected=['Could not connect to clamd'])
        # Reconnecting is not retried, so the restart budget is untouched.
        self.verify_output(output.err, unexpected=['giving up'])


if __name__ == '__main__':
    unittest.main()
