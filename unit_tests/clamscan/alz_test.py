# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import hashlib
import sys
import zlib

sys.path.append('../unit_tests')
import testcase


ALZ_FILE_HEADER = 0x015A4C41
ALZ_LOCAL_FILE_HEADER = 0x015A4C42
ALZ_END_OF_CENTRAL_DIRECTORY_HEADER = 0x025A4C43
ALZ_ATTR_DIRECTORY = 0x10
ALZ_ATTR_FILE = 0x20
ALZ_COMP_NOCOMP = 0
ALZ_COMP_BZIP2 = 1
ALZ_COMP_DEFLATE = 2
ALZ_ENCR_HEADER_LEN = 12


def append_alz_file(
    alz,
    name,
    compression_method,
    uncompressed_size,
    data,
    file_attribute=ALZ_ATTR_FILE,
    file_descriptor=0x10,
):
    name = name.encode('utf-8')

    alz.extend(ALZ_LOCAL_FILE_HEADER.to_bytes(4, 'little'))
    alz.extend(len(name).to_bytes(2, 'little'))
    alz.append(file_attribute)
    alz.extend((0).to_bytes(4, 'little'))  # file time/date
    alz.append(file_descriptor)
    alz.append(0)  # unknown
    alz.append(compression_method)
    alz.append(0)  # unknown
    alz.extend((0).to_bytes(4, 'little'))  # crc
    alz.append(len(data))
    alz.append(uncompressed_size)
    alz.extend(name)
    if file_descriptor & 0x01:
        alz.extend(b'\x00' * ALZ_ENCR_HEADER_LEN)
    alz.extend(data)


def raw_deflate(data):
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


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

    def test_deflate(self):
        self.step_name('Test alz files compressed with deflate (gzip)')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'deflate.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_bzip2(self):
        self.step_name('Test alz files compressed with bzip2')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'bzip2.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_bzip2_with_binary(self):
        self.step_name('Test alz files compressed with bzip2')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'bzip2.bin.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE_EXECUTABLE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_uncompressed(self):
        self.step_name('Test alz files with no compression')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'uncompressed.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_uncompressed_with_binary(self):
        self.step_name('Test alz files with no compression with binary data')

        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'alz' / 'uncompressed.bin.alz'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'alz.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_TEST_FILE_EXECUTABLE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_extraction_error_does_not_abort_archive_scan(self):
        self.step_name('Test alz scan continues after a malformed member')

        payload = b'alz-later-member'
        testfile = TC.path_tmp / 'bad-then-good.alz'
        path_db = TC.path_tmp / 'bad-then-good.hdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(alz, 'bad.bz2', ALZ_COMP_BZIP2, 1, b'\x00')
        append_alz_file(alz, 'good.txt', ALZ_COMP_NOCOMP, len(payload), payload)
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))

        testfile.write_bytes(alz)
        path_db.write_text(
            '{}:{}:ALZ_LATER_FILE\n'.format(hashlib.sha1(payload).hexdigest(), len(payload))
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_LATER_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_later_parse_error_does_not_skip_earlier_member_scan(self):
        self.step_name('Test alz scan checks earlier members before later parse errors')

        payload = b'alz-earlier-member'
        testfile = TC.path_tmp / 'good-then-bad-header.alz'
        path_db = TC.path_tmp / 'good-then-bad-header.hdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(alz, 'good.txt', ALZ_COMP_NOCOMP, len(payload), payload)
        alz.extend(ALZ_LOCAL_FILE_HEADER.to_bytes(4, 'little'))

        testfile.write_bytes(alz)
        path_db.write_text(
            '{}:{}:ALZ_EARLIER_FILE\n'.format(hashlib.sha1(payload).hexdigest(), len(payload))
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_EARLIER_FILE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_deflate_limit_uses_decompressed_size(self):
        self.step_name('Test alz deflate scan limits use decompressed output size')

        truncated_payload = b'A' * 64
        payload = b'A' * 4096
        compressed = raw_deflate(payload)
        assert len(compressed) <= 255

        testfile = TC.path_tmp / 'deflate-limit.alz'
        path_db = TC.path_tmp / 'deflate-limit.hdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(alz, 'x', ALZ_COMP_DEFLATE, 1, compressed)
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))
        assert len(alz) <= 64

        testfile.write_bytes(alz)
        path_db.write_text(
            '{}:{}:ALZ_DEFLATE_LIMIT\n'.format(
                hashlib.sha1(truncated_payload).hexdigest(),
                len(truncated_payload),
            )
        )

        command = (
            '{valgrind} {valgrind_args} {clamscan} --max-filesize=64 '
            '--max-scansize=4096 -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_DEFLATE_LIMIT.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_inflated_header_size_does_not_skip_extraction(self):
        self.step_name('Test alz scan ignores inflated header size for extraction gating')

        payload = b'alz-small-hit'
        testfile = TC.path_tmp / 'inflated-header-size.alz'
        path_db = TC.path_tmp / 'inflated-header-size.hdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(alz, 'x', ALZ_COMP_NOCOMP, 80, payload)
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))

        testfile.write_bytes(alz)
        path_db.write_text(
            '{}:{}:ALZ_INFLATED_HEADER_SIZE\n'.format(
                hashlib.sha1(payload).hexdigest(),
                len(payload),
            )
        )

        command = (
            '{valgrind} {valgrind_args} {clamscan} --max-filesize=64 '
            '--max-scansize=1024 -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_INFLATED_HEADER_SIZE.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_total_limit_does_not_report_max_file_size(self):
        self.step_name('Test alz archive total limit is not reported as max file size')

        payload = b'A' * 60
        testfile = TC.path_tmp / 'total-limit.alz'
        path_db = TC.path_tmp / 'total-limit.hdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(alz, 'a', ALZ_COMP_NOCOMP, len(payload), payload)
        append_alz_file(alz, 'b', ALZ_COMP_NOCOMP, len(payload), payload)
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))
        assert len(alz) <= 200

        testfile.write_bytes(alz)
        path_db.write_text(
            '{}:{}:ALZ_UNUSED\n'.format(
                hashlib.sha1(b'not-present').hexdigest(),
                len(b'not-present'),
            )
        )

        command = (
            '{valgrind} {valgrind_args} {clamscan} --alert-exceeds-max=yes '
            '--max-filesize=200 --max-scansize=100 -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'Heuristics.Limits.Exceeded.MaxScanSize FOUND',
        ]
        unexpected_results = [
            'Heuristics.Limits.Exceeded.MaxFileSize FOUND',
        ]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)

    def test_metadata_filepos_counts_skipped_entries_from_one(self):
        self.step_name('Test alz metadata file position counts skipped entries from one')

        payload = b'alz-filepos-member'
        testfile = TC.path_tmp / 'filepos-skipped.alz'
        path_db = TC.path_tmp / 'filepos-skipped.cdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(
            alz,
            'dir/',
            ALZ_COMP_NOCOMP,
            0,
            b'',
            file_attribute=ALZ_ATTR_DIRECTORY,
        )
        append_alz_file(
            alz,
            'encrypted.bin',
            ALZ_COMP_NOCOMP,
            0,
            b'',
            file_descriptor=0x11,
        )
        append_alz_file(alz, 'good.txt', ALZ_COMP_NOCOMP, len(payload), payload)
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))

        testfile.write_bytes(alz)
        path_db.write_text('ALZ_FILEPOS_TEST:CL_TYPE_ALZ:*:good.txt:*:*:0:3:*:*\n')

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_FILEPOS_TEST.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_encrypted_metadata_matches_before_extraction_skip(self):
        self.step_name('Test alz encrypted entries are matched before extraction skip')

        testfile = TC.path_tmp / 'encrypted-metadata.alz'
        path_db = TC.path_tmp / 'encrypted-metadata.cdb'

        alz = bytearray()
        alz.extend(ALZ_FILE_HEADER.to_bytes(4, 'little'))
        alz.extend((0).to_bytes(4, 'little'))
        append_alz_file(
            alz,
            'encrypted.bin',
            ALZ_COMP_NOCOMP,
            0,
            b'',
            file_descriptor=0x11,
        )
        alz.extend(ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_bytes(4, 'little'))

        testfile.write_bytes(alz)
        path_db.write_text(
            'ALZ_ENCRYPTED_METADATA_TEST:CL_TYPE_ALZ:*:encrypted.bin:*:*:1:1:*:*\n'
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_results = [
            'ALZ_ENCRYPTED_METADATA_TEST.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_results)
