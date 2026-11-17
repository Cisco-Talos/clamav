# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Exercise ClamAV's bounded, reader-only Rust RAR scanner."""

import base64
import hashlib
import shutil
import sys
import zlib

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()
        cls.fixtures = cls.path_source / 'unit_tests' / 'input' / 'rar'

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def _scan(self, fixture, database=None, options=''):
        database = database or (
            TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} -d {database} '
            '{options} {fixture}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            database=database,
            options=options,
            fixture=self.fixtures / fixture,
        )
        return self.execute_command(command)

    def _sha1_database(self, entries):
        path = TC.path_tmp / 'rar.hdb'
        path.write_text(''.join(
            '{}:{}:{}\n'.format(hashlib.sha1(data).hexdigest(), len(data), name)
            for name, data in entries
        ))
        return path

    def test_reader_versions_solid_and_filters(self):
        # Known payloads from the checked-in corpus make extraction, rather
        # than merely header parsing, observable to ClamAV.
        database = TC.path_tmp / 'rar-formats.hdb'
        database.write_text(
            'cf43130700d3751ef53167327f01aaae0d8b02b1:4198:RAR15\n'
            'a8a5ddb23f91ed6dc283adeb438ce3fa69fa343d:240:RAR20\n'
            '43f57fc589210e51ebe4c2d4a62b630476c306fc:48:RAR3_SOLID_ONE\n'
            '875f38d2e59a139af92c1fad40514feaf4b5119a:47:RAR3_SOLID_TWO\n'
            '8fd85c608277c5aa1f826d312b8f10cdbcdebbfb:196608:RAR3_FILTER\n'
            '864cd6ba00ac37f94359b61ca408f43f7d61cc50:30:RAR5\n'
            '84cea654b0d59b711712557538db7e79144dd881:262144:RAR5_FILTER\n'
            '0b1125dcdf496ce2a503ab954c5f7aae677a8aa7:37:RAR7\n'
        )
        cases = {
            'rar15-normal.rar': 'RAR15.UNOFFICIAL FOUND',
            'rar20-zero-fill.rar': 'RAR20.UNOFFICIAL FOUND',
            'rar3-solid.rar': 'RAR3_SOLID_ONE.UNOFFICIAL FOUND',
            'rar3-filter-e8.rar': 'RAR3_FILTER.UNOFFICIAL FOUND',
            'rar5-store.rar': 'RAR5.UNOFFICIAL FOUND',
            'rar3-sfx.exe': 'RAR3_SOLID_ONE.UNOFFICIAL FOUND',
            'rar5-filter-delta.rar': 'RAR5_FILTER.UNOFFICIAL FOUND',
            'rar7-store.rar': 'RAR7.UNOFFICIAL FOUND',
        }
        for fixture, expected in cases.items():
            output = self._scan(fixture, database)
            assert output.ec == 1, fixture
            self.verify_output(output.out, expected=[expected])

    def test_allmatch_scans_solid_members_in_archive_order(self):
        database = self._sha1_database([
            ('RAR3_SOLID_ONE',
             b'shared prefix shared prefix shared prefix alpha\n'),
            ('RAR3_SOLID_TWO',
             b'shared prefix shared prefix shared prefix beta\n'),
        ])
        output = self._scan('rar3-solid.rar', database, options='--allmatch')
        assert output.ec == 1
        first = output.out.index('RAR3_SOLID_ONE.UNOFFICIAL FOUND')
        second = output.out.index('RAR3_SOLID_TWO.UNOFFICIAL FOUND')
        assert first < second

    def test_archive_comments_are_scanned(self):
        database = self._sha1_database([
            ('RAR3_COMMENT', b'This is the archive comment.\n'),
            ('RAR5_COMMENT', b'This is the archive comment.\n\0'),
        ])
        for fixture, expected in (
            ('rar3-comment.rar', 'RAR3_COMMENT.UNOFFICIAL FOUND'),
            ('rar5-comment.rar', 'RAR5_COMMENT.UNOFFICIAL FOUND'),
        ):
            output = self._scan(fixture, database)
            assert output.ec == 1, fixture
            self.verify_output(output.out, expected=[expected])

    def test_metadata_name_size_encryption_and_position(self):
        database = TC.path_tmp / 'rar.cdb'
        database.write_text(
            'RAR_METADATA:CL_TYPE_RAR:*:hello.txt:30:30:0:1:*:*\n'
            'RAR_ENCRYPTED_METADATA:CL_TYPE_RAR:*:hello.txt:*:*:1:1:*:*\n'
        )
        output = self._scan('rar5-store.rar', database)
        assert output.ec == 1
        self.verify_output(output.out, expected=['RAR_METADATA.UNOFFICIAL FOUND'])

        output = self._scan('rar5-member-encrypted.rar', database)
        assert output.ec == 1
        self.verify_output(
            output.out, expected=['RAR_ENCRYPTED_METADATA.UNOFFICIAL FOUND']
        )

    def test_encrypted_header_and_member_heuristic(self):
        for fixture in (
            'rar3-header-encrypted.rar',
            'rar3-member-encrypted.rar',
            'rar5-header-encrypted.rar',
            'rar5-member-encrypted.rar',
        ):
            output = self._scan(
                fixture,
                options='--heuristic-alerts --alert-encrypted-archive',
            )
            assert output.ec == 1, fixture
            self.verify_output(
                output.out, expected=['Heuristics.Encrypted.RAR FOUND']
            )

    def test_special_records_are_not_restored(self):
        tempdir = TC.path_tmp / 'special-records'
        tempdir.mkdir()
        for fixture in ('rar5-redirections.rar', 'rar5-services.rar'):
            output = self._scan(
                fixture,
                options='--debug --leave-temps --tempdir={}'.format(tempdir),
            )
            assert output.ec == 0, fixture
            assert 'writing nested map content to temp file' not in (
                output.out + output.err
            )
        # Generic recursive scanners may retain their own processing files,
        # but the RAR scanner must not restore links or service records.
        restored_names = {
            'hard.txt', 'copy.txt', 'abs.txt', 'sym.txt', 'near.txt',
            'CMT', 'QO', 'RR',
        }
        assert not [
            path for path in tempdir.rglob('*')
            if path.is_symlink() or path.name in restored_names
        ]

    def test_force_to_disk_uses_generic_recursive_tempfile(self):
        tempdir = TC.path_tmp / 'force-to-disk'
        tempdir.mkdir()
        output = self._scan(
            'rar5-store.rar',
            options=(
                '--force-to-disk --leave-temps --tempdir={}'
                .format(tempdir)
            ),
        )
        assert output.ec == 0
        retained = [path for path in tempdir.rglob('*') if path.is_file()]
        assert retained
        assert any(path.read_bytes() == b'Hello, RAR 5.0 fixture world.\n'
                   for path in retained)

    def test_split_stops_without_sibling_discovery(self):
        isolated = TC.path_tmp / 'isolated-volume'
        isolated.mkdir()
        fixture = isolated / 'sample.part1.rar'
        shutil.copyfile(self.fixtures / 'rar5-split-part1.rar', fixture)
        command = '{clamscan} -d {database} {fixture}'.format(
            clamscan=TC.clamscan,
            database=TC.path_source / 'unit_tests' / 'input' / 'clamav.hdb',
            fixture=fixture,
        )
        output = self.execute_command(command)
        assert output.ec == 0
        self.verify_output(output.out, expected=['sample.part1.rar: OK'])

    def test_malformed_custom_vm_and_zero_length_are_bounded(self):
        for fixture in (
            'rar13-store.rar',
            'rar3-custom-vm.rar',
            'rar5-empty.rar',
            'rar5-malformed-member.rar',
            'rar5-malformed-service.rar',
        ):
            output = self._scan(fixture)
            assert output.ec in (0, 2), fixture
            assert output.ec != 111, fixture

    def test_member_with_bad_checksum_is_still_scanned(self):
        # Corrupt the stored member's data CRC and repair the RAR5 file-header
        # CRC so parsing succeeds and extraction reaches the integrity check.
        archive = bytearray((self.fixtures / 'rar5-store.rar').read_bytes())
        assert archive[0x25:0x29] == bytes.fromhex('2772b283')
        archive[0x25] ^= 1
        header_end = 0x1c + archive[0x1b]
        archive[0x17:0x1b] = zlib.crc32(
            archive[0x1b:header_end]
        ).to_bytes(4, 'little')
        fixture = TC.path_tmp / 'rar5-bad-member-crc.rar'
        fixture.write_bytes(archive)

        database = self._sha1_database([
            ('RAR_BAD_CRC', b'Hello, RAR 5.0 fixture world.\n'),
        ])
        command = '{clamscan} -d {database} {fixture}'.format(
            clamscan=TC.clamscan,
            database=database,
            fixture=fixture,
        )
        output = self.execute_command(command)
        assert output.ec == 1
        self.verify_output(
            output.out, expected=['RAR_BAD_CRC.UNOFFICIAL FOUND']
        )

    def test_valid_member_before_malformed_header_is_still_scanned(self):
        archive = bytearray((self.fixtures / 'rar5-store.rar').read_bytes())
        assert archive[-8:] == bytes.fromhex('1d77565103050400')
        archive[-8] ^= 1
        fixture = TC.path_tmp / 'rar5-malformed-trailing-header.rar'
        fixture.write_bytes(archive)

        database = self._sha1_database([
            ('RAR_BEFORE_BAD_HEADER', b'Hello, RAR 5.0 fixture world.\n'),
        ])
        command = '{clamscan} -d {database} {fixture}'.format(
            clamscan=TC.clamscan,
            database=database,
            fixture=fixture,
        )
        output = self.execute_command(command)
        assert output.ec == 1
        self.verify_output(
            output.out, expected=['RAR_BEFORE_BAD_HEADER.UNOFFICIAL FOUND']
        )

    def test_oversized_independent_member_does_not_hide_later_member(self):
        encoded = self.fixtures / 'rar5-oversized-then-small.rar.b64'
        fixture = TC.path_tmp / 'rar5-oversized-then-small.rar'
        fixture.write_bytes(base64.b64decode(encoded.read_bytes()))
        database = self._sha1_database([
            ('RAR_AFTER_OVERSIZE', b'RAR later member payload\n'),
        ])
        command = (
            '{clamscan} -d {database} --max-filesize=1K {fixture}'
        ).format(
            clamscan=TC.clamscan,
            database=database,
            fixture=fixture,
        )
        output = self.execute_command(command)
        assert output.ec == 1
        self.verify_output(
            output.out, expected=['RAR_AFTER_OVERSIZE.UNOFFICIAL FOUND']
        )

    def test_scan_limits(self):
        # The first RAR7 member is larger than the file limit. The scanner
        # must stop through ClamAV's normal limit path without allocating it.
        output = self._scan(
            'rar7-store.rar',
            options=(
                '--alert-exceeds-max=yes --max-filesize=1K '
                '--max-scansize=1M'
            ),
        )
        assert output.ec == 2
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxFileSize FOUND'],
        )

        output = self._scan(
            'rar5-solid.rar',
            options='--alert-exceeds-max=yes --max-files=1',
        )
        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['Heuristics.Limits.Exceeded.MaxFiles FOUND'],
        )
