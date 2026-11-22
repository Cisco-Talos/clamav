# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import base64
import struct
import sys
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.append('../unit_tests')
import testcase


SECTOR_SIZE = 512
STREAM_SIZE = 4096  # Streams this size or larger are stored in regular sectors, not the mini stream.
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def _directory_entry(name, entry_type, right=FREESECT, child=FREESECT, start=ENDOFCHAIN, size=0):
    encoded_name = (name.encode('utf-16-le') + b'\x00\x00')[:64].ljust(64, b'\x00')
    name_length = min(len(name) * 2 + 2, 64) if name else 0

    entry = encoded_name
    entry += struct.pack('<HBB', name_length, entry_type, 1)
    entry += struct.pack('<III', FREESECT, right, child)
    entry += b'\x00' * 16
    entry += struct.pack('<I', 0)
    entry += b'\x00' * 16
    entry += struct.pack('<IQ', start, size)

    assert len(entry) == 128
    return entry


def _write_ole2(path, streams):
    """Write a minimal OLE2 file whose root storage holds the given (name, data) streams."""
    assert 0 < len(streams) <= 3

    fat = [FREESECT] * (SECTOR_SIZE // 4)
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN

    entries = [_directory_entry('Root Entry', 5, child=1)]
    sectors = []
    next_sector = 2
    for index, (name, data) in enumerate(streams):
        assert len(data) >= STREAM_SIZE
        sector_count = (len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE
        for offset in range(sector_count):
            sector = next_sector + offset
            fat[sector] = sector + 1 if offset + 1 < sector_count else ENDOFCHAIN
        right = index + 2 if index + 1 < len(streams) else FREESECT
        entries.append(_directory_entry(name, 2, right=right, start=next_sector, size=len(data)))
        padded = data.ljust(sector_count * SECTOR_SIZE, b'\x00')
        sectors.extend(padded[offset:offset + SECTOR_SIZE] for offset in range(0, len(padded), SECTOR_SIZE))
        next_sector += sector_count
    assert next_sector <= SECTOR_SIZE // 4
    entries.extend([_directory_entry('', 0)] * (4 - len(entries)))

    header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    header += b'\x00' * 16
    header += struct.pack('<HHHH', 0x003E, 0x0003, 0xFFFE, 0x0009)
    header += struct.pack('<H', 0x0006)
    header += b'\x00' * 6
    header += struct.pack('<IIIIIIIII', 0, 1, 1, 0, 0x1000, ENDOFCHAIN, 0, ENDOFCHAIN, 0)
    header += b''.join(struct.pack('<I', sector) for sector in [0] + [FREESECT] * 108)
    assert len(header) == SECTOR_SIZE

    fat_sector = b''.join(struct.pack('<I', value) for value in fat)
    path.write_bytes(header + fat_sector + b''.join(entries) + b''.join(sectors))


def _write_vba_document(path, module_source):
    """
    Write an OLE2 document with a _VBA_PROJECT stream that names one module, and
    that module's source, in the layout cli_vba_readdir() and cli_vba_inflate() read.
    The source is stored as literal-only compressed chunks, so it never appears
    contiguously in the module stream itself.
    """
    module_name = 'Module1'
    assert len(module_source) < 4096

    # Header: magic, version and ignored bytes.
    vba_project = b'\xCC\x61' + b'\x00' * 32
    # One project string, then a zero length that ends the strings.
    vba_project += struct.pack('<H', 6) + '*\\g'.encode('utf-16-le')
    vba_project += struct.pack('<H', 0) + b'\x00' * 10
    # Skipped words up to 0xFFFF, two empty (0xFFFF) lengths, and 100 skipped bytes.
    vba_project += b'\x00\x00\xFF\xFF'
    vba_project += b'\xFF\xFF\xFF\xFF' + b'\x00' * 100
    # One module record: its name, skipped fields, and the offset of its source.
    vba_project += struct.pack('<H', 1)
    vba_project += struct.pack('<H', len(module_name) * 2) + module_name.encode('utf-16-le')
    vba_project += struct.pack('<HH', 0, 0) + b'\x00' * 10
    vba_project += struct.pack('<H', 0) + b'\x00' * 5
    source_offset = STREAM_SIZE
    vba_project += struct.pack('<I', source_offset) + b'\x00' * 2

    compressed = b'\x01' + struct.pack('<H', 0xB000)
    for offset in range(0, len(module_source), 8):
        compressed += b'\x00' + module_source[offset:offset + 8]
    module = b'\x00' * source_offset + compressed

    _write_ole2(path, [
        ('_VBA_PROJECT', vba_project.ljust(STREAM_SIZE, b'\x00')),
        (module_name, module),
    ])


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

    def test_container(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        (TC.path_tmp / '7z_zip_container.ldb').write_text(
            "7z_zip_container_good;Engine:81-255,Container:CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_container_bad;Engine:81-255,Container:CL_TYPE_ZIP,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / '7z_zip_container.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_container_good.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_container_bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_intermediates(self):
        self.step_name('Test that clamav can successfully alert on jpeg image extracted from XLS documents')
        # Note: we aren't testing PNG because the attached PNG is not properly fuzzy-hashed by clamav, yet.

        (TC.path_tmp / '7z_zip_intermediates.ldb').write_text(
            "7z_zip_intermediates_good;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_7Z,Target:0;0;0:7631727573\n"
            "7z_zip_intermediates;Engine:81-255,Intermediates:CL_TYPE_7Z>CL_TYPE_TEXT_ASCII,Target:0;0;0:7631727573\n"
        )

        testfiles = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'v1rusv1rus.7z.zip'
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --gen-json --debug --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / '7z_zip_intermediates.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_intermediates_good.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'v1rusv1rus.7z.zip: 7z_zip_intermediates_bad.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_clamscan_container_cache(self):
        self.step_name('Test that near-matches for container sigs are not cached')
        # Files should not be cached as "clean" if the container sig is a near-match
        # and only fails because the container requirement is not met.
        # This is a regression test for a bug where a file was cached as "clean" and
        # then later when scanned within a container it was not detected.

        not_eicar_file = TC.path_tmp / 'not_eicar'
        if not not_eicar_file.exists():
            with not_eicar_file.open('wb') as f:
                f.write(b"CLAMAV-TEST-STRING-NOT-EICAR")

        not_eicar_zip = TC.path_tmp / 'not_eicar.zip'
        if not not_eicar_zip.exists():
            with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
                zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        (TC.path_tmp / 'zip_container.ldb').write_text(
            "LDB.Clamav-Unit-Test-Signature-Container;Engine:81-255,Container:CL_TYPE_ZIP,Target:0;0;0:434c414d41562d544553542d535452494e472d4e4f542d4549434152\n"
        )

        testfiles = '{} {}'.format(not_eicar_file, not_eicar_zip)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'zip_container.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'not_eicar: OK',
            'not_eicar.zip: LDB.Clamav-Unit-Test-Signature-Container.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'not_eicar: LDB.Clamav-Unit-Test-Signature-Container.UNOFFICIAL FOUND',
            'not_eicar.zip: OK',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_intermediates_cache(self):
        self.step_name('Test that near-matches for intermediates sigs are not cached')
        # Files should not be cached as "clean" if the intermediates sig is a near-match
        # and only fails because the intermediates requirement is not met.
        # This is a regression test for a bug where a file was cached as "clean" and
        # then later when scanned within a container it was not detected.

        not_eicar_file = TC.path_tmp / 'not_eicar'
        if not not_eicar_file.exists():
            with not_eicar_file.open('wb') as f:
                f.write(b"CLAMAV-TEST-STRING-NOT-EICAR")

        not_eicar_zip = TC.path_tmp / 'not_eicar.zip'
        if not not_eicar_zip.exists():
            with ZipFile(str(not_eicar_zip), 'w', ZIP_DEFLATED) as zf:
                zf.writestr('not-eicar.txt', b"CLAMAV-TEST-STRING-NOT-EICAR")

        (TC.path_tmp / 'zip_intermediates.ldb').write_text(
            "LDB.Clamav-Unit-Test-Signature-Intermediates;Engine:81-255,Intermediates:CL_TYPE_ZIP,Target:0;0;0:434c414d41562d544553542d535452494e472d4e4f542d4549434152\n"
        )

        testfiles = '{} {}'.format(not_eicar_file, not_eicar_zip)
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'zip_intermediates.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # no virus, no failures

        expected_stdout = [
            'not_eicar: OK',
            'not_eicar.zip: LDB.Clamav-Unit-Test-Signature-Intermediates.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'not_eicar: LDB.Clamav-Unit-Test-Signature-Intermediates.UNOFFICIAL FOUND',
            'not_eicar.zip: OK',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_handler_type_does_not_alert_on_retyped_layer(self):
        self.step_name('Test that a HandlerType signature does not alert after retyping the layer')

        marker = b'CLAMAV-TEST-HANDLERTYPE'
        testfile = TC.path_tmp / 'handler_type_retype'
        testfile.write_bytes(marker)

        (TC.path_tmp / 'handler_type_retype.ldb').write_text(
            'handler_type_retype;Engine:51-255,HandlerType:CL_TYPE_ZIP,Target:0;0;{}\n'.format(marker.hex())
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'handler_type_retype.ldb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 0

        expected_stdout = [
            'handler_type_retype: OK',
        ]
        unexpected_stdout = [
            'handler_type_retype.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def test_handler_type_retyped_layer_is_not_cached(self):
        self.step_name('Test that one HandlerType scan does not cache a later HandlerType scan as clean')

        marker = b'CLAMAV-TEST-HANDLERTYPE-CACHE'
        testfile = TC.path_tmp / 'handler_type_cache'
        testfile.write_bytes(marker)

        (TC.path_tmp / 'handler_type_cache.ldb').write_text(
            'handler_type_zip;Engine:51-255,HandlerType:CL_TYPE_ZIP,Target:0;0;{}\n'
            'handler_type_pe;Engine:51-255,HandlerType:CL_TYPE_MSEXE,Target:0;0;{}\n'
            'handler_type_pe_detection;Engine:51-255,Target:1;0;{}\n'.format(
                marker.hex(), marker.hex(), marker.hex()
            )
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --allmatch'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'handler_type_cache.ldb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1

        expected_stdout = [
            'handler_type_cache: handler_type_pe_detection.UNOFFICIAL FOUND',
        ]
        unexpected_stdout = [
            'handler_type_cache: OK',
            'handler_type_cache: handler_type_zip.UNOFFICIAL FOUND',
            'handler_type_cache: handler_type_pe.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

    def write_mail_container_pcre_samples(self):
        db = TC.path_tmp / 'container_pcre.ldb'
        db.write_text(
            r'container_pcre_mail;Engine:81-255,Container:CL_TYPE_MAIL,Target:0;1;0:504b;0/hidden_member_[0-9]{4}\.txt/'
            '\n'
        )

        archive = TC.path_tmp / 'container_pcre.zip'
        with ZipFile(archive, 'w', ZIP_DEFLATED) as zf:
            zf.writestr('hidden_member_1234.txt', 'plain text\n')

        attachment = base64.encodebytes(archive.read_bytes()).decode()
        mail = TC.path_tmp / 'container_pcre.eml'
        mail.write_text(
            'From: sender@example.com\n'
            'To: recipient@example.com\n'
            'Subject: archive\n'
            'MIME-Version: 1.0\n'
            'Content-Type: multipart/mixed; boundary="boundary"\n'
            '\n'
            '--boundary\n'
            'Content-Type: application/zip\n'
            'Content-Transfer-Encoding: base64\n'
            'Content-Disposition: attachment; filename="container_pcre.zip"\n'
            '\n'
            + attachment +
            '--boundary--\n'
        )
        return db, archive, mail

    def test_container_pcre_skipped_outside_its_container(self):
        self.step_name('Test that a PCRE subsignature is not evaluated where its Container constraint cannot match')

        db, archive, _ = self.write_mail_container_pcre_samples()

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --debug'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=db, testfile=archive,
        )
        output = self.execute_command(command)

        assert output.ec == 0  # no virus, no failures

        self.verify_output(output.out, expected=['container_pcre.zip: OK'])
        self.verify_output(output.err, expected=['its logical signature requires another container'])

    def test_container_pcre_matches_inside_its_container(self):
        self.step_name('Test that a PCRE subsignature still matches inside its container, '
                       'after the same content was scanned outside it')

        db, archive, mail = self.write_mail_container_pcre_samples()

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {first} {second}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=db, first=archive, second=mail,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_stdout = [
            'container_pcre.zip: OK',
            'container_pcre.eml: container_pcre_mail.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout)

    def write_ole2_container_pcre_samples(self):
        db = TC.path_tmp / 'ole2_container_pcre.ldb'
        db.write_text(
            r'ole2_container_pcre_vba;Engine:81-255,Container:CL_TYPE_MSOLE2,Target:0;0&1;{};0/CLAMAV-TEST-VBA-[0-9]{{4}}-PCRE/'
            '\n'.format(b'Sub AutoOpen'.hex())
        )

        document = TC.path_tmp / 'ole2_container_pcre.doc'
        _write_vba_document(
            document,
            b'Attribute VB_Name = "Module1"\r\n'
            b'Sub AutoOpen()\r\n'
            b'    MsgBox "CLAMAV-TEST-VBA-1234-PCRE"\r\n'
            b'End Sub\r\n'
        )

        archive = TC.path_tmp / 'ole2_container_pcre.zip'
        with ZipFile(archive, 'w', ZIP_DEFLATED) as zf:
            zf.writestr('ole2_container_pcre.doc', document.read_bytes())

        return db, document, archive

    def test_container_pcre_matches_vba_macro(self):
        self.step_name('Test that a PCRE subsignature constrained to the OLE2 container still matches a VBA macro, '
                       'which is matched before its own layer is entered')

        db, document, archive = self.write_ole2_container_pcre_samples()

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {document} {archive}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=db, document=document, archive=archive,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_stdout = [
            'ole2_container_pcre.doc: ole2_container_pcre_vba.UNOFFICIAL FOUND',
            'ole2_container_pcre.zip: ole2_container_pcre_vba.UNOFFICIAL FOUND',
        ]
        self.verify_output(output.out, expected=expected_stdout)
