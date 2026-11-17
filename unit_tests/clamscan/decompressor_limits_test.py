# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests of the scan size limit on single stream decompressors.
"""

import bz2
import gzip
import lzma
import sys
import zipfile
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import testcase

MEBIBYTE = 1024 * 1024
MAX_SCAN_SIZE = 4 * MEBIBYTE
ENTRY_COUNT = 8
ENTRY_SIZE = 12 * MEBIBYTE


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

    def make_zip(self, name, extension, compress):
        testfile = TC.path_tmp / name
        with zipfile.ZipFile(testfile, 'w', zipfile.ZIP_STORED) as archive:
            for index in range(ENTRY_COUNT):
                content = bytes([index + 1]) * ENTRY_SIZE
                archive.writestr('entry{}.{}'.format(index, extension), compress(content))
        return testfile

    def scan_and_measure_temporary_files(self, testfile):
        path_db = TC.path_tmp / 'decompressor-limits.hdb'
        path_db.write_text('ffffffffffffffffffffffffffffffff:99999999:DECOMPRESSOR_LIMITS_NEVER\n')
        path_tempdir = TC.path_tmp / 'tempdir-{}'.format(testfile.stem)
        path_tempdir.mkdir()

        command = (
            '{valgrind} {valgrind_args} {clamscan} --alert-exceeds-max=yes '
            '--max-scansize={max_scansize} --max-filesize=100M '
            '--leave-temps=yes --tempdir={tempdir} -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            max_scansize=MAX_SCAN_SIZE,
            tempdir=path_tempdir,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)
        written = sum(path.stat().st_size for path in path_tempdir.rglob('*') if path.is_file())
        return output, written

    def check_stops_at_scan_size(self, name, extension, compress):
        testfile = self.make_zip(name, extension, compress)
        output, written = self.scan_and_measure_temporary_files(testfile)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxScanSize FOUND'],
        )
        assert written <= MAX_SCAN_SIZE, \
            '{} bytes written to the temporary directory, scan size limit is {}'.format(written, MAX_SCAN_SIZE)

    def test_gzip_entries_stop_at_scan_size(self):
        self.step_name('Test gzip files in a ZIP do not write past the scan size')
        self.check_stops_at_scan_size('gzip-entries.zip', 'gz', lambda content: gzip.compress(content))

    def test_bzip2_entries_stop_at_scan_size(self):
        self.step_name('Test bzip2 files in a ZIP do not write past the scan size')
        self.check_stops_at_scan_size('bzip2-entries.zip', 'bz2', lambda content: bz2.compress(content))

    def test_xz_entries_stop_at_scan_size(self):
        self.step_name('Test xz files in a ZIP do not write past the scan size')
        self.check_stops_at_scan_size('xz-entries.zip', 'xz', lambda content: lzma.compress(content))
