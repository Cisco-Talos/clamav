# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for ZIP64 archives.

ZIP64 archives store values that do not fit in the original 32-bit header fields elsewhere,
leaving an "all ones" placeholder behind:

  - 32-bit size/offset fields are set to 0xFFFFFFFF
  - 16-bit count/disk fields are set to 0xFFFF

The real values then live in the Zip64 Extended Information Extra Field (extra field header
ID 0x0001) of the local file header and the central directory file header, or - for the
central directory offset - in the Zip64 end of central directory record.

Rather than committing opaque binary samples, every archive here is assembled byte by byte so
the exact header shape under test is visible in the test. See unit_tests/clamscan/alz_test.py
for the same approach applied to ALZ archives.

Regression test for https://github.com/Cisco-Talos/clamav/issues/1527
"""

import struct
import sys
import zlib

sys.path.append('../unit_tests')
import testcase


# ClamAV's test corpus deliberately avoids the real EICAR string. This string is matched by
# unit_tests/input/other_sigs/Clamav-Unit-Test-Signature.ndb at offset 0.
PAYLOAD = b'CLAMAV-TEST-STRING-NOT-EICAR'
PAYLOAD_SIG_NAME = 'NDB.Clamav-Unit-Test-Signature.UNOFFICIAL'

ZIP64_PLACEHOLDER_32 = 0xFFFFFFFF
ZIP64_PLACEHOLDER_16 = 0xFFFF

ZIP_EXTRA_FIELD_ID_ZIP64 = 0x0001

FLAG_USE_DATA_DESCRIPTOR = 1 << 3

METHOD_STORED = 0

# "Version needed to extract" 4.5 - i.e. this archive uses ZIP64 extensions.
VERSION_ZIP64 = 45


def zip64_extra_field(values):
    """Build a Zip64 Extended Information Extra Field.

    `values` is an ordered list of (width_in_bytes, value) pairs. The caller decides which
    fields to include, because for a central directory file header only the fields whose
    32-bit counterpart holds the placeholder are actually stored.
    """
    data = b''
    for width, value in values:
        if width == 8:
            data += struct.pack('<Q', value)
        elif width == 4:
            data += struct.pack('<I', value)
        else:
            raise ValueError('unsupported ZIP64 field width: {}'.format(width))

    return struct.pack('<HH', ZIP_EXTRA_FIELD_ID_ZIP64, len(data)) + data


def extra_field_record(header_id, data, declared_size=None):
    """Build an arbitrary extra field record, optionally lying about its data size."""
    if declared_size is None:
        declared_size = len(data)
    return struct.pack('<HH', header_id, declared_size) + data


def local_file_header(name, crc=0, csize=0, usize=0, flags=0,
                      method=METHOD_STORED, extra=b'', version=VERSION_ZIP64):
    return (
        b'PK\x03\x04'
        + struct.pack('<HHHHH', version, flags, method, 0, 0)  # version, flags, method, time, date
        + struct.pack('<III', crc, csize, usize)
        + struct.pack('<HH', len(name), len(extra))
        + name
        + extra
    )


def central_file_header(name, crc=0, csize=0, usize=0, flags=0, method=METHOD_STORED,
                        extra=b'', comment=b'', disk=0, local_header_offset=0,
                        version=VERSION_ZIP64):
    return (
        b'PK\x01\x02'
        + struct.pack('<HHHHHH', version, version, flags, method, 0, 0)
        + struct.pack('<III', crc, csize, usize)
        + struct.pack('<HHHHH', len(name), len(extra), len(comment), disk, 0)
        + struct.pack('<II', 0, local_header_offset)  # external attributes, local header offset
        + name
        + extra
        + comment
    )


def end_of_central_directory(cd_size, cd_offset, disk_entries=1, total_entries=1, comment=b''):
    return (
        b'PK\x05\x06'
        + struct.pack('<HHHH', 0, 0, disk_entries, total_entries)
        + struct.pack('<II', cd_size, cd_offset)
        + struct.pack('<H', len(comment))
        + comment
    )


def zip64_end_of_central_directory(cd_size, cd_offset, total_entries=1):
    body = (
        struct.pack('<HH', VERSION_ZIP64, VERSION_ZIP64)
        + struct.pack('<II', 0, 0)  # this disk, disk with the start of the central directory
        + struct.pack('<QQQQ', total_entries, total_entries, cd_size, cd_offset)
    )
    # The size field counts everything after itself, i.e. the record size minus 12.
    return b'PK\x06\x06' + struct.pack('<Q', len(body)) + body


def zip64_end_of_central_directory_locator(zip64_eocd_offset, total_disks=1):
    return (
        b'PK\x06\x07'
        + struct.pack('<I', 0)  # disk with the ZIP64 end of central directory record
        + struct.pack('<Q', zip64_eocd_offset)
        + struct.pack('<I', total_disks)
    )


def data_descriptor(crc, csize, usize, zip64=True, signature=True):
    """Build a data descriptor. ZIP64 entries use 8-byte sizes instead of 4-byte."""
    out = b'PK\x07\x08' if signature else b''
    out += struct.pack('<I', crc)
    if zip64:
        out += struct.pack('<QQ', csize, usize)
    else:
        out += struct.pack('<II', csize, usize)
    return out


def stored_member(name, payload=PAYLOAD):
    """The common case: one stored (uncompressed) member holding the test payload."""
    return {
        'name': name,
        'payload': payload,
        'crc': zlib.crc32(payload) & 0xFFFFFFFF,
        'size': len(payload),
    }


def zip64_archive_local_header_placeholders(name=b'payload.txt'):
    """The archive shape from issue #1527.

    The local file header carries the 0xFFFFFFFF placeholders plus a ZIP64 extra field with
    the real sizes. The central directory is small enough to use plain 32-bit values.
    This is exactly what Python's `ZipFile.open(..., force_zip64=True)` produces.
    """
    member = stored_member(name)

    lfh = local_file_header(
        name,
        crc=member['crc'],
        csize=ZIP64_PLACEHOLDER_32,
        usize=ZIP64_PLACEHOLDER_32,
        extra=zip64_extra_field([(8, member['size']), (8, member['size'])]),
    )

    cd_offset = len(lfh) + len(member['payload'])
    cdh = central_file_header(
        name,
        crc=member['crc'],
        csize=member['size'],
        usize=member['size'],
        local_header_offset=0,
    )

    return (
        lfh
        + member['payload']
        + cdh
        + end_of_central_directory(cd_size=len(cdh), cd_offset=cd_offset)
    )


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.payload_db = TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb'

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def scan(self, filename, archive, extra_args=''):
        """Write `archive` to the temp dir and scan it with the payload signature loaded."""
        testfile = TC.path_tmp / filename
        testfile.write_bytes(archive)

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {extra_args} {testfile}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.payload_db,
            extra_args=extra_args,
            testfile=testfile,
        )
        return self.execute_command(command)

    def assert_detected(self, filename, archive, extra_args='--debug'):
        output = self.scan(filename, archive, extra_args=extra_args)

        assert output.ec == 1, (
            'expected a detection in {}, got exit code {}.\nstdout:\n{}\nstderr tail:\n{}'.format(
                filename, output.ec, output.out, output.err[-4000:])
        )
        self.verify_output(output.out, expected=['{}: {} FOUND'.format(filename, PAYLOAD_SIG_NAME)])
        return output

    def assert_clean(self, filename, archive, extra_args='--debug'):
        output = self.scan(filename, archive, extra_args=extra_args)

        assert output.ec == 0, (
            'expected a clean scan of {}, got exit code {}.\nstdout:\n{}\nstderr tail:\n{}'.format(
                filename, output.ec, output.out, output.err[-4000:])
        )
        self.verify_output(output.out, expected=['{}: OK'.format(filename)])
        return output

    #
    # The reported bug.
    #

    def test_zip64_local_file_header_extra_field(self):
        self.step_name('Test a ZIP64 archive whose local file header uses the 0xFFFFFFFF size placeholders')

        # Before ZIP64 support this failed in parse_local_file_header() with
        # "local header - stream out of file", because the 0xFFFFFFFF placeholder was taken
        # as the literal compressed size, and nothing was extracted.
        output = self.assert_detected(
            'zip64-local-header.zip',
            zip64_archive_local_header_placeholders(),
            extra_args='--allmatch --gen-json --debug',
        )

        self.verify_output(output.err, expected=['"FileName":"payload.txt"'])

    def test_zip64_nested(self):
        self.step_name('Test a ZIP64 archive nested inside two more ZIP64 archives')

        # The scenario from the issue report: nested ZIP64 archives with the payload innermost.
        archive = zip64_archive_local_header_placeholders(b'payload.txt')

        for depth, name in enumerate([b'inner.zip', b'outer.zip']):
            crc = zlib.crc32(archive) & 0xFFFFFFFF
            size = len(archive)

            lfh = local_file_header(
                name,
                crc=crc,
                csize=ZIP64_PLACEHOLDER_32,
                usize=ZIP64_PLACEHOLDER_32,
                extra=zip64_extra_field([(8, size), (8, size)]),
            )
            cd_offset = len(lfh) + size
            cdh = central_file_header(name, crc=crc, csize=size, usize=size, local_header_offset=0)

            archive = (
                lfh
                + archive
                + cdh
                + end_of_central_directory(cd_size=len(cdh), cd_offset=cd_offset)
            )

        self.assert_detected('zip64-nested.zip', archive)

    #
    # The other three places ZIP64 values hide.
    #

    def test_zip64_central_directory_extra_field(self):
        self.step_name('Test a ZIP64 archive whose central directory file header uses placeholders')

        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']

        # All three of usize, csize and the local header offset are placeholders, so the
        # ZIP64 record carries all three, in that order.
        cdh = central_file_header(
            member['name'],
            crc=member['crc'],
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            local_header_offset=ZIP64_PLACEHOLDER_32,
            extra=zip64_extra_field([(8, member['size']), (8, member['size']), (8, 0)]),
        )

        self.assert_detected(
            'zip64-central-header.zip',
            lfh + member['payload'] + cdh + end_of_central_directory(
                cd_size=len(cdh), cd_offset=cd_offset),
        )

    def test_zip64_central_directory_partial_extra_field(self):
        self.step_name('Test a central directory ZIP64 record that only carries the local header offset')

        # The subtle case: in a central directory file header only the fields whose 32-bit
        # counterpart holds the placeholder are stored. Here only the local header offset
        # does, so the record's first 8 bytes are the offset and NOT the uncompressed size.
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']

        cdh = central_file_header(
            member['name'],
            crc=member['crc'],
            csize=member['size'],
            usize=member['size'],
            local_header_offset=ZIP64_PLACEHOLDER_32,
            extra=zip64_extra_field([(8, 0)]),
        )

        self.assert_detected(
            'zip64-central-header-partial.zip',
            lfh + member['payload'] + cdh + end_of_central_directory(
                cd_size=len(cdh), cd_offset=cd_offset),
        )

    def test_zip64_end_of_central_directory(self):
        self.step_name('Test a ZIP64 archive whose central directory offset comes from the ZIP64 EOCD record')

        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        zip64_eocd_offset = cd_offset + len(cdh)
        zip64_eocd = zip64_end_of_central_directory(cd_size=len(cdh), cd_offset=cd_offset)
        locator = zip64_end_of_central_directory_locator(zip64_eocd_offset)

        # The 32-bit end of central directory record holds nothing but placeholders.
        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32,
            cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16,
            total_entries=ZIP64_PLACEHOLDER_16,
        )

        output = self.assert_detected(
            'zip64-eocd.zip',
            lfh + member['payload'] + cdh + zip64_eocd + locator + eocd,
        )

        self.verify_output(output.err, expected=[
            'Found ZIP64 End Of Central Directory locator at offset',
            '(via ZIP64)',
        ])

    def test_zip64_eocd_record_found_by_backwards_scan(self):
        self.step_name('Test a ZIP64 archive whose ZIP64 EOCD record is found without a locator')

        # Some self-extracting archives shift the ZIP64 records by the size of the stub, so
        # the locator's offset does not pan out. The parser then has to find the record by
        # scanning backwards from the end of central directory record.
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        zip64_eocd = zip64_end_of_central_directory(cd_size=len(cdh), cd_offset=cd_offset)
        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32, cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16, total_entries=ZIP64_PLACEHOLDER_16)

        output = self.assert_detected(
            'zip64-eocd-no-locator.zip',
            lfh + member['payload'] + cdh + zip64_eocd + eocd)

        self.verify_output(output.err, expected=['(via ZIP64)'])

    def test_zip64_fake_eocd_record_in_comment(self):
        self.step_name('Test that a fake ZIP64 EOCD record in the EOCD comment cannot override a valid 32-bit offset')

        # The 32-bit central directory offset is valid, but the entry count is the 0xFFFF
        # placeholder (which a plain archive may legitimately hold for exactly 65535 files).
        # The EOCD comment carries a planted ZIP64 EOCD record claiming a bogus central
        # directory offset. The valid 32-bit offset must win.
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        fake_record = (
            b'PK\x06\x06'
            + struct.pack('<Q', 44)                      # record size
            + struct.pack('<QQQQ', 1, 1, 1, len(cdh))    # entries, cd size
            + struct.pack('<Q', 0)                       # bogus cd offset: the local file header, not a CD
        )

        eocd = end_of_central_directory(
            cd_size=len(cdh), cd_offset=cd_offset,
            disk_entries=ZIP64_PLACEHOLDER_16, total_entries=ZIP64_PLACEHOLDER_16,
            comment=fake_record)

        output = self.assert_detected(
            'zip64-fake-eocd-comment.zip',
            lfh + member['payload'] + cdh + eocd)

        assert '(via ZIP64)' not in output.err, (
            'the fake ZIP64 EOCD record was used instead of the valid 32-bit offset.\n'
            'stderr tail:\n{}'.format(output.err[-4000:])
        )

    def test_zip64_fake_eocd_record_scan_bogus_cd(self):
        self.step_name('Test that a scanned ZIP64 EOCD record with a bogus central directory is rejected')

        # The 32-bit offset is a placeholder, so the ZIP64 records must be consulted. The
        # only ZIP64 EOCD record in the file (found by the backwards scan) claims a central
        # directory offset that holds no central directory file header, so it must be
        # rejected and the file recovered by scanning for local file headers instead.
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])

        fake_record = (
            b'PK\x06\x06'
            + struct.pack('<Q', 44)
            + struct.pack('<QQQQ', 1, 1, 1, 8)
            + struct.pack('<Q', 4)  # points into the local file header name field, not a CD
        )

        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32, cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16, total_entries=ZIP64_PLACEHOLDER_16,
            comment=fake_record)

        self.assert_detected(
            'zip64-fake-eocd-scan.zip',
            lfh + member['payload'] + fake_record + eocd)

    def test_zip64_data_descriptor(self):
        self.step_name('Test a ZIP64 archive that uses an 8-byte data descriptor')

        # A streaming writer does not know the sizes when it writes the local file header, so
        # it sets the data descriptor flag and writes the real sizes afterwards. For a ZIP64
        # entry the descriptor's two sizes are 8 bytes wide rather than 4, so a parser that
        # assumes 12 bytes walks off the end of the record.
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'],
            flags=FLAG_USE_DATA_DESCRIPTOR,
            crc=0,
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            extra=zip64_extra_field([(8, 0), (8, 0)]),
        )
        descriptor = data_descriptor(member['crc'], member['size'], member['size'], zip64=True)

        cd_offset = len(lfh) + member['size'] + len(descriptor)
        cdh = central_file_header(
            member['name'],
            flags=FLAG_USE_DATA_DESCRIPTOR,
            crc=member['crc'],
            csize=member['size'],
            usize=member['size'],
            local_header_offset=0,
        )

        self.assert_detected(
            'zip64-data-descriptor.zip',
            lfh + member['payload'] + descriptor + cdh + end_of_central_directory(
                cd_size=len(cdh), cd_offset=cd_offset),
        )

    #
    # Interaction with the existing non-ZIP64 code paths.
    #

    def test_zip64_mixed_with_plain_entry(self):
        self.step_name('Test an archive with one ZIP64 entry and one ordinary entry')

        # Guards against ZIP64 handling leaking into the plain path, or vice versa.
        first = stored_member(b'zip64.txt')
        second = stored_member(b'plain.txt')

        lfh1 = local_file_header(
            first['name'],
            crc=first['crc'],
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            extra=zip64_extra_field([(8, first['size']), (8, first['size'])]),
        )
        lfh2_offset = len(lfh1) + first['size']
        lfh2 = local_file_header(
            second['name'], crc=second['crc'], csize=second['size'], usize=second['size'],
            version=20)

        cd_offset = lfh2_offset + len(lfh2) + second['size']
        cdh1 = central_file_header(
            first['name'], crc=first['crc'], csize=first['size'], usize=first['size'],
            local_header_offset=0)
        cdh2 = central_file_header(
            second['name'], crc=second['crc'], csize=second['size'], usize=second['size'],
            local_header_offset=lfh2_offset, version=20)

        archive = (
            lfh1 + first['payload']
            + lfh2 + second['payload']
            + cdh1 + cdh2
            + end_of_central_directory(
                cd_size=len(cdh1) + len(cdh2), cd_offset=cd_offset,
                disk_entries=2, total_entries=2)
        )

        output = self.assert_detected(
            'zip64-mixed.zip', archive, extra_args='--allmatch --gen-json --debug')

        self.verify_output(output.err, expected=['"FileName":"zip64.txt"', '"FileName":"plain.txt"'])

    def test_zip64_no_central_directory(self):
        self.step_name('Test a ZIP64 archive with its central directory truncated away')

        # Forces the local-file-header-only code path.
        archive = zip64_archive_local_header_placeholders()
        archive = archive[:archive.index(b'PK\x01\x02')]

        self.assert_detected('zip64-no-central-dir.zip', archive)

    def test_zip64_unknown_extra_field_records(self):
        self.step_name('Test a ZIP64 record surrounded by other extra field records')

        # The ZIP64 record has to be found by walking the extra field, not by assuming it
        # comes first.
        member = stored_member(b'payload.txt')

        extra = (
            extra_field_record(0x5455, b'\x01\x02\x03\x04\x05')       # extended timestamp
            + zip64_extra_field([(8, member['size']), (8, member['size'])])
            + extra_field_record(0x7875, b'\x01' + b'\x00' * 10)      # unix uid/gid
        )

        lfh = local_file_header(
            member['name'],
            crc=member['crc'],
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            extra=extra,
        )
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        self.assert_detected(
            'zip64-extra-field-records.zip',
            lfh + member['payload'] + cdh + end_of_central_directory(
                cd_size=len(cdh), cd_offset=cd_offset),
        )

    #
    # Graceful degradation: the ZIP64 records are unusable, so the central directory is
    # abandoned and the entry is recovered by scanning for local file headers instead.
    #

    def test_zip64_eocd_placeholder_without_zip64_records(self):
        self.step_name('Test an archive claiming ZIP64 in its EOCD but with no ZIP64 records')

        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32,
            cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16,
            total_entries=ZIP64_PLACEHOLDER_16,
        )

        self.assert_detected(
            'zip64-eocd-no-records.zip', lfh + member['payload'] + cdh + eocd)

    def test_zip64_eocd_locator_points_past_eof(self):
        self.step_name('Test a ZIP64 EOCD locator pointing past the end of the file')

        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        locator = zip64_end_of_central_directory_locator(0xFFFFFFFFFFFF)
        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32, cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16, total_entries=ZIP64_PLACEHOLDER_16)

        self.assert_detected(
            'zip64-locator-past-eof.zip', lfh + member['payload'] + cdh + locator + eocd)

    def test_zip64_eocd_record_offset_past_eof(self):
        self.step_name('Test a ZIP64 EOCD record whose central directory offset is past the end of the file')

        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'])
        cd_offset = len(lfh) + member['size']
        cdh = central_file_header(
            member['name'], crc=member['crc'], csize=member['size'], usize=member['size'],
            local_header_offset=0)

        zip64_eocd_offset = cd_offset + len(cdh)
        zip64_eocd = zip64_end_of_central_directory(
            cd_size=len(cdh), cd_offset=0xFFFFFFFFFFFF)
        locator = zip64_end_of_central_directory_locator(zip64_eocd_offset)
        eocd = end_of_central_directory(
            cd_size=ZIP64_PLACEHOLDER_32, cd_offset=ZIP64_PLACEHOLDER_32,
            disk_entries=ZIP64_PLACEHOLDER_16, total_entries=ZIP64_PLACEHOLDER_16)

        self.assert_detected(
            'zip64-eocd-offset-past-eof.zip',
            lfh + member['payload'] + cdh + zip64_eocd + locator + eocd)

    #
    # Malformed ZIP64 metadata: nothing is extractable, but the scan must stay clean and
    # must not read out of bounds (the clamscan_valgrind variant of this test checks that).
    #

    def malformed_archive(self, extra):
        """A ZIP64 archive whose local file header sizes are only resolvable via `extra`."""
        member = stored_member(b'payload.txt')

        lfh = local_file_header(
            member['name'],
            crc=member['crc'],
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            extra=extra,
        )
        cd_offset = len(lfh) + member['size']
        # Only the two sizes are placeholders here, so a well-formed ZIP64 record would
        # carry exactly the two 8-byte fields that `extra` is built from.
        cdh = central_file_header(
            member['name'],
            crc=member['crc'],
            csize=ZIP64_PLACEHOLDER_32,
            usize=ZIP64_PLACEHOLDER_32,
            local_header_offset=0,
            extra=extra,
        )

        return (
            lfh + member['payload'] + cdh
            + end_of_central_directory(cd_size=len(cdh), cd_offset=cd_offset)
        )

    def test_zip64_extra_field_truncated(self):
        self.step_name('Test a ZIP64 extra field record that declares more data than it has')

        # Declares 16 bytes of data but only 8 follow.
        extra = extra_field_record(
            ZIP_EXTRA_FIELD_ID_ZIP64, b'\x00' * 8, declared_size=16)

        self.assert_clean('zip64-extra-truncated.zip', self.malformed_archive(extra))

    def test_zip64_extra_field_size_overflow(self):
        self.step_name('Test a ZIP64 extra field record claiming a 0xFFFF data size')

        extra = extra_field_record(ZIP_EXTRA_FIELD_ID_ZIP64, b'', declared_size=0xFFFF)

        self.assert_clean('zip64-extra-overflow.zip', self.malformed_archive(extra))

    def test_zip64_extra_field_zero_length_records(self):
        self.step_name('Test a long chain of zero-length extra field records')

        # Each record is only its 4-byte header, so a parser that advances by the data size
        # alone would never make progress. This must terminate.
        extra = extra_field_record(0x5455, b'') * 1000

        self.assert_clean('zip64-extra-zero-length.zip', self.malformed_archive(extra))

    def test_zip64_size_larger_than_file(self):
        self.step_name('Test a ZIP64 compressed size larger than the whole archive')

        extra = zip64_extra_field([(8, 0x100000), (8, 0x100000)])

        self.assert_clean('zip64-size-too-big.zip', self.malformed_archive(extra))

    def test_zip64_size_above_32_bits(self):
        self.step_name('Test a ZIP64 compressed size that does not fit in 32 bits')

        # Must be rejected as out of range rather than truncated to its low 32 bits, which
        # for 0x100000000 would be zero.
        extra = zip64_extra_field([(8, 0x100000000), (8, 0x100000000)])

        self.assert_clean('zip64-size-above-32-bits.zip', self.malformed_archive(extra))
