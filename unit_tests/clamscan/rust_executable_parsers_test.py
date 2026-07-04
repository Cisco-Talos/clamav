# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for the Rust executable parser migration.
"""

import os
import shutil
import sys

sys.path.append('../unit_tests')
import testcase


def minimal_elf64_with_ep_marker():
    marker = b'CLAMELF'
    entry_file_offset = 0x80
    base_virtual_address = 0x0040_0000
    data = bytearray(0x180)
    data[0:4] = b'\x7fELF'
    data[4] = 2  # ELFCLASS64
    data[5] = 1  # ELFDATA2LSB
    data[6] = 1  # EV_CURRENT
    data[16:18] = (2).to_bytes(2, 'little')  # ET_EXEC
    data[18:20] = (0x3e).to_bytes(2, 'little')  # EM_X86_64
    data[20:24] = (1).to_bytes(4, 'little')
    data[24:32] = (base_virtual_address + entry_file_offset).to_bytes(8, 'little')
    data[32:40] = (64).to_bytes(8, 'little')
    data[40:48] = (0x100).to_bytes(8, 'little')
    data[52:54] = (64).to_bytes(2, 'little')
    data[54:56] = (56).to_bytes(2, 'little')
    data[56:58] = (1).to_bytes(2, 'little')
    data[58:60] = (64).to_bytes(2, 'little')
    data[60:62] = (2).to_bytes(2, 'little')
    data[62:64] = (1).to_bytes(2, 'little')

    data[64:68] = (1).to_bytes(4, 'little')  # PT_LOAD
    data[68:72] = (5).to_bytes(4, 'little')  # PF_R | PF_X
    data[72:80] = (0).to_bytes(8, 'little')
    data[80:88] = base_virtual_address.to_bytes(8, 'little')
    data[96:104] = (0x180).to_bytes(8, 'little')
    data[104:112] = (0x180).to_bytes(8, 'little')
    data[112:120] = (0x1000).to_bytes(8, 'little')

    data[entry_file_offset:entry_file_offset + len(marker)] = marker
    shstr = b'\0.shstrtab\0'
    data[0xf0:0xf0 + len(shstr)] = shstr
    sh1 = 0x140
    data[sh1:sh1 + 4] = (1).to_bytes(4, 'little')
    data[sh1 + 4:sh1 + 8] = (3).to_bytes(4, 'little')  # SHT_STRTAB
    data[sh1 + 24:sh1 + 32] = (0xf0).to_bytes(8, 'little')
    data[sh1 + 32:sh1 + 40] = (len(shstr)).to_bytes(8, 'little')
    data[sh1 + 48:sh1 + 56] = (1).to_bytes(8, 'little')
    return bytes(data)


def minimal_macho64_with_ep_marker():
    marker = b'CLAMMACHO'
    entry_file_offset = 0x38
    data = bytearray(entry_file_offset + len(marker))
    data[0:4] = bytes.fromhex('cffaedfe')  # MH_CIGAM_64; little-endian fields follow.
    data[4:8] = (0x0100_0007).to_bytes(4, 'little')  # CPU_TYPE_X86_64
    data[8:12] = (3).to_bytes(4, 'little')
    data[12:16] = (2).to_bytes(4, 'little')  # MH_EXECUTE
    data[16:20] = (1).to_bytes(4, 'little')
    data[20:24] = (24).to_bytes(4, 'little')
    data[24:28] = (0).to_bytes(4, 'little')
    data[28:32] = (0).to_bytes(4, 'little')

    command_offset = 32
    data[command_offset:command_offset + 4] = (0x8000_0028).to_bytes(4, 'little')  # LC_MAIN
    data[command_offset + 4:command_offset + 8] = (24).to_bytes(4, 'little')
    data[command_offset + 8:command_offset + 16] = entry_file_offset.to_bytes(8, 'little')
    data[command_offset + 16:command_offset + 24] = (0).to_bytes(8, 'little')
    data[entry_file_offset:entry_file_offset + len(marker)] = marker
    return bytes(data)


def minimal_universal_macho64_with_ep_marker():
    thin = minimal_macho64_with_ep_marker()
    fat_header_size = 8
    fat_arch_size = 20
    slice_offset = fat_header_size + fat_arch_size
    data = bytearray(slice_offset + len(thin))
    data[0:4] = (0xcafe_babe).to_bytes(4, 'big')
    data[4:8] = (1).to_bytes(4, 'big')
    data[8:12] = (0x0100_0007).to_bytes(4, 'big')  # CPU_TYPE_X86_64
    data[12:16] = (3).to_bytes(4, 'big')
    data[16:20] = slice_offset.to_bytes(4, 'big')
    data[20:24] = len(thin).to_bytes(4, 'big')
    data[24:28] = (2).to_bytes(4, 'big')
    data[slice_offset:] = thin
    return bytes(data)


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

        if (self.path_tmp / "TD").exists():
            shutil.rmtree(self.path_tmp / "TD")

        self.verify_valgrind_log()

    def test_rust_pe_parser_alert_parity_for_hdb_packer_fixtures(self):
        self.step_name('Rust PE parser preserves HDB alert parity for PE packer fixtures')

        fixture_names = [
            'clam-aspack.exe',
            'clam-fsg.exe',
            'clam-mew.exe',
            'clam-pespin.exe',
            'clam-petite.exe',
            'clam-upack.exe',
            'clam-upx.exe',
            'clam-wwpack.exe',
            'clam-yc.exe',
            'clam.ea05.exe',
            'clam.ea06.exe',
        ]
        fixture_dir = (
            TC.path_build
            / 'unit_tests'
            / 'input'
            / 'clamav_hdb_scanfiles'
        )
        testfiles = ' '.join([str(fixture_dir / name) for name in fixture_names])
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug --cvdcertsdir={certs} -d {path_db} {testfiles}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            certs=TC.path_source / 'certs',
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                f'{name}: ClamAV-Test-File.UNOFFICIAL FOUND'
                for name in fixture_names
            ] + ['Infected files: 11'],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanpe: using Rust executable parser',
            ],
        )

    def test_rust_pe_parser_detects_packed_fixture_and_emits_metadata(self):
        self.step_name('Rust PE parser scans UPX child and emits ClamAV PE metadata')

        tempdir = self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = (
            TC.path_build
            / 'unit_tests'
            / 'input'
            / 'clamav_hdb_scanfiles'
            / 'clam-upx.exe'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug --gen-json --leave-temps --tempdir={tempdir} '
            '--cvdcertsdir={certs} -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            tempdir=tempdir,
            certs=TC.path_source / 'certs',
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'clam-upx.exe: ClamAV-Test-File.UNOFFICIAL FOUND',
                'Infected files: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanpe: using Rust executable parser',
                'Rust PE parser found 3 sections',
                'FP SIGNATURE: 71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:544:ClamAV-Test-File.UNOFFICIAL',
            ],
        )
        self.verify_metadata_json(
            tempdir,
            expected=[
                '"PE":\\{',
                '"Type":"EXE"',
                '"ArchType":"80386"',
                '"NumberOfSections":3',
                '"MajorSubsystemVersion":[0-9]+',
                '"MinorSubsystemVersion":[0-9]+',
                '"ImportTable":\\[',
                '"Packer":"UPX"',
                '"Sections":\\[',
                '"FileName":"upx-unpacked-1.exe"',
                '"FileSize":20480',
            ],
        )

    def test_rust_pe_parser_preserves_pe_allmatch_fixture_parity(self):
        self.step_name('Rust PE parser preserves PE allmatch fixture parity')

        test_path = TC.path_source / 'unit_tests' / 'input' / 'pe_allmatch'
        test_exe = test_path / 'test.exe'
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug '
            '-d {alerting_dbs} '
            '-d {weak_dbs} '
            '-d {broken_dbs} '
            '-d {block_cert_dbs} '
            '--allmatch --bytecode-unsigned {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            alerting_dbs=test_path / 'alert-sigs',
            block_cert_dbs=test_path / 'block-cert-sigs',
            weak_dbs=test_path / 'weak-sigs',
            broken_dbs=test_path / 'broken-sigs',
            testfile=test_exe,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        expected_results = [
            '{sig} FOUND'.format(sig=f.stem)
            for f in (test_path / 'alert-sigs').iterdir()
        ]
        expected_results += [
            '{sig} FOUND'.format(sig=f.stem)
            for f in (test_path / 'block-cert-sigs').iterdir()
        ]
        unexpected_results = [
            '{sig} FOUND'.format(sig=f.stem)
            for f in (test_path / 'broken-sigs').iterdir()
        ]
        self.verify_output(
            output.out,
            expected=expected_results,
            unexpected=unexpected_results,
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanpe: using Rust executable parser',
            ],
        )

    def test_rust_pe_parser_preserves_installshield_overlay_fixture_parity(self):
        self.step_name('Rust PE parser preserves InstallShield overlay fixture parity')

        fixture_dir = (
            TC.path_build
            / 'unit_tests'
            / 'input'
            / 'clamav_hdb_scanfiles'
        )
        testfiles = ' '.join([
            str(fixture_dir / 'clam_IScab_ext.exe'),
            str(fixture_dir / 'clam_IScab_int.exe'),
            str(fixture_dir / 'clam_ISmsi_ext.exe'),
            str(fixture_dir / 'clam_ISmsi_int.exe'),
        ])
        (TC.path_tmp / 'Clam-VI.ldb').write_text(
            'Clam-VI-Test:Target;Engine:52-255,Target:1;(0&1);'
            'VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;'
            'VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00\n'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug -d {path_db} {testfiles}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'Clam-VI.ldb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'clam_ISmsi_ext.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
                'clam_ISmsi_int.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND',
                'Infected files: 2',
            ],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanpe: using Rust executable parser',
            ],
        )

    def test_rust_elf_parser_emits_metadata_and_supports_ep_signatures(self):
        self.step_name('Rust ELF parser emits metadata and supports EP-relative signatures')

        tempdir = self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = self.path_tmp / 'minimal-rust.elf'
        testfile.write_bytes(minimal_elf64_with_ep_marker())
        sigfile = self.path_tmp / 'rust-elf-ep.ldb'
        sigfile.write_text(
            'Rust.ELF.EP;Engine:52-255,Target:6;0;EP+0:434c414d454c46\n'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug --gen-json --leave-temps --tempdir={tempdir} '
            '--cvdcertsdir={certs} -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            tempdir=tempdir,
            certs=TC.path_source / 'certs',
            path_db=sigfile,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'minimal-rust.elf: Rust.ELF.EP.UNOFFICIAL FOUND',
                'Infected files: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanelf: using Rust executable parser',
                'Rust ELF parser found 2 sections',
            ],
            unexpected=[
                'Failed to successfully parse the executable header',
            ],
        )
        self.verify_metadata_json(
            tempdir,
            expected=[
                '"FileType":"CL_TYPE_ELF"',
                '"ELF":\\{',
                '"Class":"ELF64"',
                '"Machine":"AMD x86-64"',
                '"EntryPoint":"0x400080"',
                '"NumberOfProgramHeaders":1',
                '"NumberOfSections":2',
                '"Name":".shstrtab"',
            ],
        )

    def test_rust_macho_parser_emits_metadata_and_supports_ep_signatures(self):
        self.step_name('Rust Mach-O parser emits metadata and supports EP-relative signatures')

        tempdir = self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = self.path_tmp / 'minimal-rust.macho'
        testfile.write_bytes(minimal_macho64_with_ep_marker())
        sigfile = self.path_tmp / 'rust-macho-ep.ldb'
        sigfile.write_text(
            'Rust.MachO.EP;Engine:52-255,Target:9;0;EP+0:434c414d4d4143484f\n'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug --gen-json --leave-temps --tempdir={tempdir} '
            '--cvdcertsdir={certs} -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            tempdir=tempdir,
            certs=TC.path_source / 'certs',
            path_db=sigfile,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'minimal-rust.macho: Rust.MachO.EP.UNOFFICIAL FOUND',
                'Infected files: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanmacho: using Rust executable parser',
                'Rust Mach-O parser found 1 files',
            ],
            unexpected=[
                'Failed to successfully parse the executable header',
            ],
        )
        self.verify_metadata_json(
            tempdir,
            expected=[
                '"FileType":"CL_TYPE_MACHO"',
                '"MachO":\\{',
                '"Universal":false',
                '"FileCount":1',
                '"Class":"MachO64"',
                '"Endian":"little"',
                '"CpuType":"x86_64"',
                '"FileType":"Executable"',
                '"EntryPoint":"0x38"',
            ],
        )

    def test_rust_macho_universal_parser_extracts_slice_for_ep_signatures(self):
        self.step_name('Rust universal Mach-O parser extracts slices for EP signatures')

        tempdir = self.path_tmp / "TD"
        if not os.path.isdir(tempdir):
            os.makedirs(tempdir)

        testfile = self.path_tmp / 'minimal-rust-universal.macho'
        testfile.write_bytes(minimal_universal_macho64_with_ep_marker())
        sigfile = self.path_tmp / 'rust-macho-universal-ep.ldb'
        sigfile.write_text(
            'Rust.MachO.Universal.EP;Engine:52-255,Target:9;0;EP+0:434c414d4d4143484f\n'
        )
        command = (
            '{valgrind} {valgrind_args} {clamscan} '
            '--debug --gen-json --leave-temps --tempdir={tempdir} '
            '--cvdcertsdir={certs} -d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            tempdir=tempdir,
            certs=TC.path_source / 'certs',
            path_db=sigfile,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'minimal-rust-universal.macho: Rust.MachO.Universal.EP.UNOFFICIAL FOUND',
                'Infected files: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=[
                'cli_scanmacho_unibin: using Rust executable parser',
                'cli_scanmacho: using Rust executable parser',
                'Rust Mach-O parser found 1 files and 1 universal slice children',
            ],
            unexpected=[
                'Failed to successfully parse the executable header',
            ],
        )
        self.verify_metadata_json(
            tempdir,
            expected=[
                '"FileType":"CL_TYPE_MACHO_UNIBIN"',
                '"FileName":"macho-slice-1.macho"',
                '"FileType":"CL_TYPE_MACHO"',
                '"MachO":\\{',
                '"Universal":true',
                '"FileCount":1',
                '"SliceCount":1',
                '"EntryPoint":"0x38"',
            ],
        )
