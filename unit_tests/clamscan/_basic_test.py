# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import shutil
import os
import socket
import stat
import sys
import unittest

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = list(TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')) # A list of Path()'s of each of our generated test files

        # Prepare a directory to store our test databases
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)

        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_00_version(self):
        self.step_name('clamscan version test')

        command = '{valgrind} {valgrind_args} {clamscan} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_01_all_testfiles(self):
        self.step_name('Test that clamscan alerts on all test files')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_db / 'clamav.hdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        expected_results.append('Scanned files: {}'.format(len(TC.testpaths)))
        expected_results.append('Infected files: {}'.format(len(TC.testpaths)))
        self.verify_output(output.out, expected=expected_results)

    def test_02_all_testfiles_ign2(self):
        self.step_name('Test that clamscan ignores ClamAV-Test-File alerts')

        # Drop an ignore db into the test database directory
        # in our scan, we'll just use the whole directory, which should load the ignore db *first*.
        (TC.path_db / 'clamav.ign2').write_text('ClamAV-Test-File\n')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # virus found

        expected_results = ['Scanned files: {}'.format(len(TC.testpaths))]
        expected_results.append('Infected files: 0')
        unexpected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    @unittest.skipIf(os.name == 'nt' or not hasattr(os, 'mkfifo') or not hasattr(socket, 'AF_UNIX'),
                     'requires FIFO and Unix domain socket support')
    def test_03_ignore_special_file_errors(self):
        self.step_name('Test clamscan --ignore-{socket,pipe,device}-errors')

        fifo  = TC.path_tmp / 'clamscan-fifo'
        sockp = TC.path_tmp / 'clamscan.sock'
        flist = TC.path_tmp / 'clamscan-file-list.txt'
        dev   = '/dev/null' if os.path.exists('/dev/null') and stat.S_ISCHR(os.lstat('/dev/null').st_mode) else None

        os.mkfifo(str(fifo))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        def scan(*args):
            return self.execute_command(
                '{v} {va} {c} -d {db} --no-summary {a}'.format(
                    v=TC.valgrind, va=TC.valgrind_args, c=TC.clamscan,
                    db=TC.path_db / 'clamav.hdb',
                    a=' '.join(str(x) for x in args)))

        try:
            sock.bind(str(sockp))

            out = scan(fifo)
            assert out.ec == 2
            self.verify_output(out.err, expected=['{}: Not supported file type'.format(fifo)])

            cases = [('--ignore-pipe-errors',   fifo,  'pipe'),
                     ('--ignore-socket-errors', sockp, 'socket')]
            if dev:
                cases.append(('--ignore-device-errors', dev, 'device'))
            for flag, path, label in cases:
                out = scan(flag, path)
                assert out.ec == 0, label
                self.verify_output(out.out, expected=['{}: Skipping unsupported {}'.format(path, label)])

            # A flag must not suppress ec=2 for an unrelated file type.
            out = scan('--ignore-socket-errors', fifo)
            assert out.ec == 2
            self.verify_output(out.err, expected=['{}: Not supported file type'.format(fifo)])

            # The -f file-list code path is separate from direct-target handling.
            flist.write_text('{}\n'.format(fifo))
            out = scan('--ignore-pipe-errors', '-f', flist)
            assert out.ec == 0
            self.verify_output(out.out, expected=['{}: Skipping unsupported pipe'.format(fifo)])

            # An infection in another target must still surface as ec=1.
            out = scan('--ignore-pipe-errors', fifo, TC.testpaths[0])
            assert out.ec == 1
        finally:
            sock.close()
            for p in [fifo, sockp, flist]:
                try: p.unlink()
                except Exception: pass
