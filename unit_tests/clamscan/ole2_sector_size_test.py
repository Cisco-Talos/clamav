# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Run clamscan tests for OLE2 files with 4,096-byte sectors."""

import struct
import sys

sys.path.append('../unit_tests')
import testcase


SECTOR_SIZE = 4096
PAYLOAD_SECTOR = 128
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def _directory_entry(name, entry_type, child=FREESECT, start=ENDOFCHAIN, size=0):
    encoded_name = (name.encode('utf-16-le') + b'\x00\x00')[:64].ljust(64, b'\x00')
    name_length = min(len(name) * 2 + 2, 64)

    entry = encoded_name
    entry += struct.pack('<HBB', name_length, entry_type, 1)
    entry += struct.pack('<III', FREESECT, FREESECT, child)
    entry += b'\x00' * 16
    entry += struct.pack('<I', 0)
    entry += b'\x00' * 16
    entry += struct.pack('<IQ', start, size)

    assert len(entry) == 128
    return entry


def _write_v4_ole2(path, marker):
    """Write a valid major-version-4 OLE2 file with a marker stream."""
    entries_per_sector = SECTOR_SIZE // 4
    fat = [FREESECT] * entries_per_sector
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN
    fat[PAYLOAD_SECTOR] = ENDOFCHAIN

    empty = _directory_entry('', 0)
    directory_entries = [
        _directory_entry('Root Entry', 5, child=4),
        empty,
        empty,
        empty,
        _directory_entry('Payload', 2, start=PAYLOAD_SECTOR, size=SECTOR_SIZE),
    ]
    directory_entries.extend([empty] * (SECTOR_SIZE // 128 - len(directory_entries)))

    header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    header += b'\x00' * 16
    header += struct.pack('<HHHH', 0x003E, 0x0004, 0xFFFE, 0x000C)
    header += struct.pack('<H', 0x0006)
    header += b'\x00' * 6
    header += struct.pack(
        '<IIIIIIIII',
        1,
        1,
        1,
        0,
        0x1000,
        ENDOFCHAIN,
        0,
        ENDOFCHAIN,
        0,
    )
    header += b''.join(struct.pack('<I', sector) for sector in [0] + [FREESECT] * 108)
    header = header.ljust(SECTOR_SIZE, b'\x00')

    payload = marker.ljust(SECTOR_SIZE, b'\x00')
    path.write_bytes(
        header
        + b''.join(struct.pack('<I', value) for value in fat)
        + b''.join(directory_entries)
        + b'\x00' * (SECTOR_SIZE * (PAYLOAD_SECTOR - 2))
        + payload
    )


class TC(testcase.TestCase):
    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_v4_directory_and_fat_entry_offsets(self):
        self.step_name('Test OLE2 directory and FAT entries in 4,096-byte sectors')

        marker = b'CLAM_OLE2_V4_SECTOR_MARKER'
        testfile = TC.path_tmp / 'ole2-v4-sector.cfb'
        signature = TC.path_tmp / 'ole2-v4-sector.ndb'
        _write_v4_ole2(testfile, marker)
        signature.write_text(
            'OLE2.V4.Sector:0:0:{}\n'.format(marker.hex())
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {signature} {testfile}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            signature=signature,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=['ole2-v4-sector.cfb: OLE2.V4.Sector.UNOFFICIAL FOUND'],
        )
