# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Run clamscan tests for Rust-backed 7z extraction."""

import hashlib
import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()
        cls.archive = (
            TC.path_source
            / 'libclamav_rust'
            / 'vendor'
            / 'sevenz-rust2'
            / 'tests'
            / 'resources'
            / 'bzip2_file.7z'
        )
        cls.limit_archive = cls.archive.with_name('bzip2_limit.7z')
        cls.later_entry_archive = cls.archive.with_name('non_solid.7z')
        cls.encrypted_content_archive = cls.archive.with_name('encrypted.7z')
        cls.database = TC.path_tmp / 'sevenz-bzip2.hdb'
        payload = b'world\n'
        cls.large_payload = b'A' * (1024 * 1024)
        cls.database.write_text(
            '{}:{}:SEVENZ_BZIP2_TEST\n'
            '{}:{}:SEVENZ_ACTUAL_SIZE_TEST\n'
            '{}:{}:SEVENZ_LATER_ENTRY_TEST\n'.format(
                hashlib.md5(payload).hexdigest(),
                len(payload),
                hashlib.md5(cls.large_payload).hexdigest(),
                len(cls.large_payload),
                '05195b31a821a97eaa6e825627b2be8a',
                2654,
            )
        )
        cls.clean_database = TC.path_tmp / 'sevenz-clean.hdb'
        cls.clean_database.write_text(
            '00000000000000000000000000000000:1:SEVENZ_NEVER_MATCH\n'
        )
        cls.declared_small_archive = TC.path_tmp / 'sevenz-declared-small.7z'
        cls.declared_large_archive = TC.path_tmp / 'sevenz-declared-large.7z'
        cls._rewrite_declared_size(cls.limit_archive, cls.declared_small_archive, b'\xc0\x00\x04')
        cls._rewrite_declared_size(cls.limit_archive, cls.declared_large_archive, b'\xd0\x01\x00')
        cls.mixed_encryption_archive = TC.path_tmp / 'sevenz-mixed-encryption.7z'
        cls.mixed_encryption_archive.write_bytes(bytes.fromhex(
            '377abcaf271c000411c3976a9200000000000000290000000000000097c5b1c5'
            '706c61696e20636f6e74656e746c8111f52a377c2efa15db8752f9a68481d5ee'
            '9f28734051320301f4a9d83d210000813307ae31991ebb85f91121a28e92f096a'
            'b0705465594e257d28286b120c060de0b51fa71279e001ec1b2b747b159f6f62'
            'c9e362bfd6a708944af83970f796848357322c3295f9b9fa3ec2edd319bd49d30'
            '07142bc9c678a4bacbc8ab51b6b462000017062d0109650a01146941ac00070b01'
            '000123030101055d000080000c809000080a010f6ac8f20000'
        ))
        cls.encrypted_header_archive = TC.path_tmp / 'sevenz-encrypted-header.7z'
        cls.encrypted_header_archive.write_bytes(bytes.fromhex(
            '377abcaf271c000441c1749d600000000000000053000000000000001cbfdc49'
            '099ba68ed8c4f340d3eedec842fb26a0a43f46b9a30d5bc4e8896c5d57042f0b'
            '91b66a4d8edb8bfab2f88c02d3562c478f94744e370b650812774a04dc24a3a5'
            '8181f01e9e6f8a7b6f4dd33075b802a6e2565c5b6e55395aad7c649295ef2448'
            '1706100109500a01ffe7d92300070b0100022406f1070122c8ff111111111111'
            '111111111111111111112222222222222222222222222222222223030101055d'
            '0000800001000c486900080a0156e2cc840000'
        ))
        cls.bad_start_crc_archive = TC.path_tmp / 'sevenz-bad-start-crc.7z'
        bad_start_crc = bytearray(cls.archive.read_bytes())
        bad_start_crc[8] ^= 0x01
        cls.bad_start_crc_archive.write_bytes(bad_start_crc)
        cls.malformed_database = TC.path_tmp / 'sevenz-malformed.hdb'
        cls.malformed_database.write_text(
            '{}:{}:SEVENZ_MALFORMED_RAW_TEST\n'.format(
                hashlib.md5(bad_start_crc).hexdigest(),
                len(bad_start_crc),
            )
        )

        cls.bad_next_header_crc_archive = TC.path_tmp / 'sevenz-bad-next-header-crc.7z'
        bad_next_header_crc = bytearray(cls.archive.read_bytes())
        bad_next_header_crc[28] ^= 0x01
        struct.pack_into('<I', bad_next_header_crc, 8, zlib.crc32(bad_next_header_crc[12:32]))
        cls.bad_next_header_crc_archive.write_bytes(bad_next_header_crc)

        cls.truncated_archive = TC.path_tmp / 'sevenz-truncated.7z'
        cls.truncated_archive.write_bytes(cls.archive.read_bytes()[:-1])

        copy_archive = cls.archive.with_name('copy.7z')
        cls.bad_file_crc_archive = TC.path_tmp / 'sevenz-bad-file-crc.7z'
        bad_file_crc = bytearray(copy_archive.read_bytes())
        bad_file_crc[33] ^= 0x01
        cls.bad_file_crc_archive.write_bytes(bad_file_crc)

        lzma_archive = cls.archive.with_name('single_file_with_content_lzma.7z')
        cls.memory_limited_archive = TC.path_tmp / 'sevenz-memory-limited.7z'
        cls._rewrite_next_header_bytes(
            lzma_archive,
            cls.memory_limited_archive,
            b'\x5d\x00\x00\x80\x00',
            b'\x5d\x00\x00\x00\x20',
        )
        cls.unsupported_codec_archive = TC.path_tmp / 'sevenz-unsupported-codec.7z'
        cls._rewrite_next_header_bytes(
            lzma_archive,
            cls.unsupported_codec_archive,
            b'\x03\x01\x01',
            b'\x03\x01\xff',
        )
        # ArchiveWriter was deliberately given Some(empty_reader), producing a
        # file with has_stream=true whose valid LZMA stream decodes to no bytes.
        cls.zero_output_stream_archive = TC.path_tmp / 'sevenz-zero-output-stream.7z'
        cls.zero_output_stream_archive.write_bytes(bytes.fromhex(
            '377abcaf271c0004dda096c701000000000000004a000000000000005bae719d'
            '00010406000109010a018def02d200070b010001212101160c0000080a01000000'
            '00000005011121007a00650072006f002d00730074007200650061006d002e00'
            '74007800740000000000'
        ))

    @staticmethod
    def _rewrite_declared_size(source, destination, encoded_size):
        archive = bytearray(source.read_bytes())
        next_header_offset = struct.unpack_from('<Q', archive, 12)[0]
        next_header_size = struct.unpack_from('<Q', archive, 20)[0]
        header_start = 32 + next_header_offset
        header_end = header_start + next_header_size
        header = archive[header_start:header_end]

        original_size = b'\xd0\x00\x00'  # Canonical 7z uint64 encoding of 1 MiB.
        position = header.find(original_size)
        assert position >= 0
        assert header.find(original_size, position + 1) < 0
        header[position:position + len(original_size)] = encoded_size
        archive[header_start:header_end] = header

        struct.pack_into('<I', archive, 28, zlib.crc32(header))
        struct.pack_into('<I', archive, 8, zlib.crc32(archive[12:32]))
        destination.write_bytes(archive)

    @staticmethod
    def _rewrite_next_header_bytes(source, destination, original, replacement):
        assert len(original) == len(replacement)
        archive = bytearray(source.read_bytes())
        next_header_offset = struct.unpack_from('<Q', archive, 12)[0]
        next_header_size = struct.unpack_from('<Q', archive, 20)[0]
        header_start = 32 + next_header_offset
        header_end = header_start + next_header_size
        header = archive[header_start:header_end]

        position = header.find(original)
        assert position >= 0
        assert header.find(original, position + 1) < 0
        header[position:position + len(original)] = replacement
        archive[header_start:header_end] = header

        struct.pack_into('<I', archive, 28, zlib.crc32(header))
        struct.pack_into('<I', archive, 8, zlib.crc32(archive[12:32]))
        destination.write_bytes(archive)

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def scan(self, options='', archive=None, database=None):
        if archive is None:
            archive = TC.archive
        if database is None:
            database = TC.database
        command = (
            '{valgrind} {valgrind_args} {clamscan} {options} '
            '-d {database} {archive}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            options=options,
            database=database,
            archive=archive,
        )
        return self.execute_command(command)

    def test_bzip2_member_is_scanned(self):
        self.step_name('Test scanning bzip2-compressed 7z members')
        output = self.scan()

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_BZIP2_TEST.UNOFFICIAL FOUND'],
        )

    def test_successful_scan_removes_temporary_file(self):
        self.step_name('Test successful 7z scans remove extracted temporary files')
        tempdir = TC.path_tmp / 'sevenz-cleanup-success'
        tempdir.mkdir()

        output = self.scan(
            options='--tempdir={}'.format(tempdir),
            database=TC.clean_database,
        )

        assert output.ec == 0
        assert not [path for path in tempdir.rglob('*') if path.is_file()]

    def test_leave_temps_preserves_closed_temporary_file(self):
        self.step_name('Test leave-temps preserves readable 7z extracted files')
        tempdir = TC.path_tmp / 'sevenz-keep-temp'
        tempdir.mkdir()

        output = self.scan(
            options='--leave-temps --tempdir={}'.format(tempdir),
            database=TC.clean_database,
        )

        assert output.ec == 0
        extracted = [path for path in tempdir.rglob('*') if path.is_file()]
        assert any(path.read_bytes() == b'world\n' for path in extracted)

    def test_empty_entry_does_not_create_temporary_file(self):
        self.step_name('Test zero-length 7z entries do not create temporary files')
        tempdir = TC.path_tmp / 'sevenz-empty-no-temp'
        tempdir.mkdir()

        output = self.scan(
            options='--leave-temps --tempdir={}'.format(tempdir),
            archive=TC.zero_output_stream_archive,
            database=TC.clean_database,
        )

        assert output.ec == 0
        assert not [path for path in tempdir.rglob('*') if path.is_file()]

    def test_invalid_archives_return_format_error(self):
        self.step_name('Test malformed, CRC, truncation, and memory errors are not clean')
        cases = (
            TC.bad_start_crc_archive,
            TC.bad_next_header_crc_archive,
            TC.truncated_archive,
            TC.bad_file_crc_archive,
            TC.memory_limited_archive,
        )
        for archive in cases:
            output = self.scan(archive=archive, database=TC.clean_database)
            assert output.ec == 2, '{} returned {}:\n{}'.format(
                archive.name,
                output.ec,
                output.out,
            )

    def test_unsupported_codec_remains_clean(self):
        self.step_name('Test unsupported 7z codecs preserve legacy clean handling')
        output = self.scan(
            archive=TC.unsupported_codec_archive,
            database=TC.clean_database,
        )

        assert output.ec == 0

    def test_detection_takes_precedence_over_format_error(self):
        self.step_name('Test raw detection takes precedence over a 7z format error')
        output = self.scan(
            archive=TC.bad_start_crc_archive,
            database=TC.malformed_database,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_MALFORMED_RAW_TEST.UNOFFICIAL FOUND'],
        )

    def test_bzip2_member_limit_uses_extracted_bytes(self):
        self.step_name('Test 7z limits are enforced while output is produced')
        output = self.scan(
            '--alert-exceeds-max=yes --max-filesize=1K --max-scansize=2M',
            archive=TC.limit_archive,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxFileSize FOUND'],
            unexpected=['SEVENZ_BZIP2_TEST.UNOFFICIAL FOUND'],
        )
        self.verify_output(
            output.out,
            expected=[re.escape('Infected files: 1')],
        )

    def test_declared_small_size_does_not_hide_decoder_output(self):
        self.step_name('Test a declared-small 7z member cannot hide output')
        output = self.scan(archive=TC.declared_small_archive)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_ACTUAL_SIZE_TEST.UNOFFICIAL FOUND'],
        )

    def test_declared_large_size_scans_actual_output_before_rejection(self):
        self.step_name('Test a declared-large 7z member scans actual output')
        output = self.scan(archive=TC.declared_large_archive)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_ACTUAL_SIZE_TEST.UNOFFICIAL FOUND'],
        )

    def test_oversized_entry_does_not_hide_later_independent_entry(self):
        self.step_name('Test a 7z file-size limit skips only the affected block')
        output = self.scan(
            '--max-filesize=3K --max-scansize=10M',
            archive=TC.later_entry_archive,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_LATER_ENTRY_TEST.UNOFFICIAL FOUND'],
            unexpected=['Heuristics.Limits.Exceeded'],
        )

    def test_scan_size_rejection_does_not_hide_later_independent_entry(self):
        self.step_name('Test a 7z scan-size limit skips only the affected block')
        output = self.scan(
            '--max-filesize=10M --max-scansize=6K',
            archive=TC.later_entry_archive,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_LATER_ENTRY_TEST.UNOFFICIAL FOUND'],
            unexpected=['Heuristics.Limits.Exceeded'],
        )

    def test_metadata_uses_original_zero_based_file_table_index(self):
        self.step_name('Test 7z metadata uses original file-table ordering')
        metadata_db = TC.path_tmp / 'sevenz-filepos.cdb'
        metadata_db.write_text(
            'SEVENZ_METADATA_FILEPOS_TEST:CL_TYPE_7Z:*:'
            '^test/test2[.]txt$:0:2654:0:2:*:*\n'
        )

        for archive in (
            TC.later_entry_archive,
            TC.later_entry_archive.with_name('solid.7z'),
        ):
            output = self.scan(archive=archive, database=metadata_db)

            assert output.ec == 1
            self.verify_output(
                output.out,
                expected=['SEVENZ_METADATA_FILEPOS_TEST.UNOFFICIAL FOUND'],
            )

    def test_empty_file_metadata_is_preserved(self):
        self.step_name('Test streamless 7z files remain eligible for metadata signatures')
        metadata_db = TC.path_tmp / 'sevenz-empty-metadata.cdb'
        metadata_db.write_text(
            'SEVENZ_EMPTY_METADATA_TEST:CL_TYPE_7Z:*:'
            '^empty[.]txt$:0:0:0:0:*:*\n'
        )

        output = self.scan(
            archive=TC.archive.with_name('single_empty_file.7z'),
            database=metadata_db,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_EMPTY_METADATA_TEST.UNOFFICIAL FOUND'],
        )

    def test_encrypted_content_metadata_sets_encrypted_flag(self):
        self.step_name('Test 7z AES content is marked encrypted in metadata')
        metadata_db = TC.path_tmp / 'sevenz-encrypted-content.cdb'
        metadata_db.write_text(
            'SEVENZ_ENCRYPTED_CONTENT_METADATA_TEST:CL_TYPE_7Z:*:'
            '^encripted/7zFormat[.]txt$:0:2247:1:1:*:*\n'
        )

        output = self.scan(
            archive=TC.encrypted_content_archive,
            database=metadata_db,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['SEVENZ_ENCRYPTED_CONTENT_METADATA_TEST.UNOFFICIAL FOUND'],
        )

    def test_mixed_plain_and_encrypted_metadata(self):
        self.step_name('Test mixed 7z blocks receive independent encryption metadata')
        cases = (
            ('plain.txt', 13, 0, 0, 'SEVENZ_PLAIN_METADATA_TEST'),
            ('encrypted.txt', 17, 1, 1, 'SEVENZ_MIXED_ENCRYPTED_METADATA_TEST'),
        )
        for name, size, encrypted, filepos, signature in cases:
            metadata_db = TC.path_tmp / '{}.cdb'.format(signature)
            metadata_db.write_text(
                '{}:CL_TYPE_7Z:*:^{}$:0:{}:{}:{}:*:*\n'.format(
                    signature,
                    re.escape(name),
                    size,
                    encrypted,
                    filepos,
                )
            )
            output = self.scan(
                archive=TC.mixed_encryption_archive,
                database=metadata_db,
            )

            assert output.ec == 1
            self.verify_output(
                output.out,
                expected=['{}.UNOFFICIAL FOUND'.format(signature)],
            )

    def test_encrypted_content_heuristic_is_preserved(self):
        self.step_name('Test encrypted 7z content raises the encrypted heuristic')
        output = self.scan(
            options='--alert-encrypted-archive=yes',
            archive=TC.mixed_encryption_archive,
        )

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Encrypted.7Zip FOUND'],
        )

    def test_encrypted_header_heuristic_without_metadata(self):
        self.step_name('Test encrypted 7z headers alert without exposing file metadata')
        hidden_metadata_db = TC.path_tmp / 'sevenz-hidden-header.cdb'
        hidden_metadata_db.write_text(
            'SEVENZ_HIDDEN_HEADER_METADATA_TEST:CL_TYPE_7Z:*:'
            '^hidden[.]txt$:0:14:1:0:*:*\n'
        )

        metadata_output = self.scan(
            archive=TC.encrypted_header_archive,
            database=hidden_metadata_db,
        )
        assert metadata_output.ec == 0
        self.verify_output(
            metadata_output.out,
            unexpected=['SEVENZ_HIDDEN_HEADER_METADATA_TEST.UNOFFICIAL FOUND'],
        )

        heuristic_output = self.scan(
            options='--alert-encrypted-archive=yes',
            archive=TC.encrypted_header_archive,
        )
        assert heuristic_output.ec == 1
        self.verify_output(
            heuristic_output.out,
            expected=['Heuristics.Encrypted.7Zip FOUND'],
        )
