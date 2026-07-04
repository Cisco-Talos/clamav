// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Bounded COFF member probes shared by MIME recognition and archive policy.
//!
//! ## Scope
//!
//! COFF is the object-file container used by Windows toolchains inside static
//! libraries and import libraries. The migration keeps a cheap,
//! allocation-free classifier here so archive/file-type policy can distinguish
//! package-like archives from linker libraries. Full PE images start with an
//! `MZ` DOS header and are handled by the PE parser; this module intentionally
//! does not parse PE image sections, imports, relocations, or certificates.
//!
//! ## References
//!
//! - Microsoft PE/COFF specification:
//!   <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//! - `ClamAV` file-type compatibility context: `libclamav/filetypes.c` and
//!   PE/COFF handling in `libclamav/pe.c`.
//!
//! ## Layout
//!
//! Classic COFF object member, from the Microsoft PE/COFF specification:
//!
//! ```text
//! +----------------------+ 20 bytes
//! | COFF file header     | machine, section count, symbol-table location
//! +----------------------+ section_count * 40 bytes
//! | Section table        | names and raw-data/relocation pointers
//! +----------------------+
//! | Section data/...     | not interpreted by this probe
//! +----------------------+
//! | Symbol table         | optional, 18-byte records
//! +----------------------+
//! | String table         | optional
//! +----------------------+
//! ```
//!
//! Microsoft import libraries may instead contain short-import objects:
//!
//! ```text
//! +----------------------+ 20 bytes
//! | Short import header  | sig1=0, sig2=0xffff, machine, import-data size
//! +----------------------+
//! | Import name strings  | symbol name and DLL name
//! +----------------------+
//! ```
//!
//! ## Parser Outputs
//!
//! `probe_coff_member` returns `CoffMemberKind::Object` or
//! `CoffMemberKind::ShortImport` only when header arithmetic and declared
//! ranges fit within the caller-provided `object_len`. Callers use that
//! scanner-agnostic member kind for MIME recognition and AR static-library
//! policy decisions.
//!
//! ## Bounds And Recovery
//!
//! The probe reads only the supplied head slice, performs checked size math,
//! and rejects truncated or ambiguous members as `None` so fallback recognition
//! can continue. It does not allocate, decode, or walk symbol names.
//!
//! ## Encoding Notes
//!
//! COFF object headers use little-endian integer fields. This probe does not
//! decode section or symbol names; it only checks that a first-section name is
//! printable when a symbol table is absent.
//!
//! ## Intentional Gaps
//!
//! This module does not parse PE images, COFF relocations, symbol names,
//! section payloads, archive link members, or import-library member payloads.
//! It is a bounded classifier, not a full object-file parser.

#![forbid(unsafe_code)]

const COFF_HEADER_LEN: usize = 20;
const COFF_SECTION_HEADER_LEN: usize = 40;
const COFF_SYMBOL_LEN: usize = 18;
const SHORT_IMPORT_HEADER_LEN: usize = 20;
const MAX_REASONABLE_COFF_SECTIONS: u16 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoffMemberKind {
    Object,
    ShortImport,
}

pub(crate) fn probe_coff_member(head: &[u8], object_len: usize) -> Option<CoffMemberKind> {
    if looks_like_coff_object(head, object_len) {
        Some(CoffMemberKind::Object)
    } else if looks_like_short_import_object(head, object_len) {
        Some(CoffMemberKind::ShortImport)
    } else {
        None
    }
}

fn looks_like_coff_object(head: &[u8], object_len: usize) -> bool {
    if object_len < COFF_HEADER_LEN || head.len() < COFF_HEADER_LEN {
        return false;
    }
    let machine = read_u16_le(head, 0);
    if !is_known_coff_machine(machine) {
        return false;
    }
    let section_count = read_u16_le(head, 2);
    if section_count == 0 || section_count > MAX_REASONABLE_COFF_SECTIONS {
        return false;
    }
    let optional_header_size = read_u16_le(head, 16);
    if optional_header_size != 0 {
        return false;
    }
    let Some(section_table_end) = COFF_HEADER_LEN
        .checked_add(usize::from(section_count).saturating_mul(COFF_SECTION_HEADER_LEN))
    else {
        return false;
    };
    if section_table_end > object_len {
        return false;
    }

    let symbol_table_offset = read_u32_le(head, 8) as usize;
    let symbol_count = read_u32_le(head, 12) as usize;
    if symbol_table_offset == 0 || symbol_count == 0 {
        return first_section_name_plausible(head);
    }
    if symbol_table_offset < section_table_end || symbol_table_offset > object_len {
        return false;
    }
    let Some(symbol_table_end) = symbol_count
        .checked_mul(COFF_SYMBOL_LEN)
        .and_then(|symbol_bytes| symbol_table_offset.checked_add(symbol_bytes))
    else {
        return false;
    };
    symbol_table_end <= object_len
}

fn looks_like_short_import_object(head: &[u8], object_len: usize) -> bool {
    if object_len < SHORT_IMPORT_HEADER_LEN || head.len() < SHORT_IMPORT_HEADER_LEN {
        return false;
    }
    if read_u16_le(head, 0) != 0 || read_u16_le(head, 2) != 0xffff {
        return false;
    }
    let version = read_u16_le(head, 4);
    if version > 2 {
        return false;
    }
    let machine = read_u16_le(head, 6);
    if !is_known_coff_machine(machine) {
        return false;
    }
    let import_data_size = read_u32_le(head, 12) as usize;
    if import_data_size == 0 {
        return false;
    }
    SHORT_IMPORT_HEADER_LEN
        .checked_add(import_data_size)
        .is_some_and(|end| end <= object_len)
}

fn first_section_name_plausible(head: &[u8]) -> bool {
    let Some(raw_name) = head.get(COFF_HEADER_LEN..COFF_HEADER_LEN + 8) else {
        return false;
    };
    let name = raw_name.split(|byte| *byte == 0).next().unwrap_or_default();
    !name.is_empty()
        && name
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
}

fn is_known_coff_machine(machine: u16) -> bool {
    matches!(
        machine,
        0x014c // IMAGE_FILE_MACHINE_I386
            | 0x0162 // IMAGE_FILE_MACHINE_R3000
            | 0x0166 // IMAGE_FILE_MACHINE_R4000
            | 0x0168 // IMAGE_FILE_MACHINE_R10000
            | 0x0169 // IMAGE_FILE_MACHINE_WCEMIPSV2
            | 0x0184 // IMAGE_FILE_MACHINE_ALPHA
            | 0x01a2 // IMAGE_FILE_MACHINE_SH3
            | 0x01a3 // IMAGE_FILE_MACHINE_SH3DSP
            | 0x01a4 // IMAGE_FILE_MACHINE_SH3E
            | 0x01a6 // IMAGE_FILE_MACHINE_SH4
            | 0x01a8 // IMAGE_FILE_MACHINE_SH5
            | 0x01c0 // IMAGE_FILE_MACHINE_ARM
            | 0x01c2 // IMAGE_FILE_MACHINE_THUMB
            | 0x01c4 // IMAGE_FILE_MACHINE_ARMNT
            | 0x01d3 // IMAGE_FILE_MACHINE_AM33
            | 0x01f0 // IMAGE_FILE_MACHINE_POWERPC
            | 0x01f1 // IMAGE_FILE_MACHINE_POWERPCFP
            | 0x0200 // IMAGE_FILE_MACHINE_IA64
            | 0x0266 // IMAGE_FILE_MACHINE_MIPS16
            | 0x0284 // IMAGE_FILE_MACHINE_ALPHA64
            | 0x0366 // IMAGE_FILE_MACHINE_MIPSFPU
            | 0x0466 // IMAGE_FILE_MACHINE_MIPSFPU16
            | 0x0520 // IMAGE_FILE_MACHINE_TRICORE
            | 0x0cef // IMAGE_FILE_MACHINE_CEF
            | 0x0ebc // IMAGE_FILE_MACHINE_EBC
            | 0x5032 // IMAGE_FILE_MACHINE_RISCV32
            | 0x5064 // IMAGE_FILE_MACHINE_RISCV64
            | 0x5128 // IMAGE_FILE_MACHINE_RISCV128
            | 0x6232 // IMAGE_FILE_MACHINE_LOONGARCH32
            | 0x6264 // IMAGE_FILE_MACHINE_LOONGARCH64
            | 0x8664 // IMAGE_FILE_MACHINE_AMD64
            | 0x9041 // IMAGE_FILE_MACHINE_M32R
            | 0xaa64 // IMAGE_FILE_MACHINE_ARM64
    )
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_i386_coff_object() {
        let bytes = synthetic_coff_object(0x014c, 2, 1);

        assert_eq!(
            probe_coff_member(&bytes, bytes.len()),
            Some(CoffMemberKind::Object)
        );
    }

    #[test]
    fn recognizes_coff_object_without_symbol_table_when_section_name_is_plausible() {
        let bytes = synthetic_coff_object(0x8664, 1, 0);

        assert_eq!(
            probe_coff_member(&bytes, bytes.len()),
            Some(CoffMemberKind::Object)
        );
    }

    #[test]
    fn rejects_truncated_section_table() {
        let bytes = synthetic_coff_object(0x014c, 3, 1);

        assert_eq!(
            probe_coff_member(&bytes, COFF_HEADER_LEN + COFF_SECTION_HEADER_LEN),
            None
        );
    }

    #[test]
    fn rejects_pe_or_random_prefixes() {
        let mut pe = vec![0; 64];
        pe[0..2].copy_from_slice(b"MZ");
        assert_eq!(probe_coff_member(&pe, pe.len()), None);

        let mut bytes = synthetic_coff_object(0x014c, 1, 1);
        bytes[16..18].copy_from_slice(&224u16.to_le_bytes());
        assert_eq!(probe_coff_member(&bytes, bytes.len()), None);
    }

    #[test]
    fn recognizes_short_import_object() {
        let mut bytes = vec![0; SHORT_IMPORT_HEADER_LEN + 24];
        bytes[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&24u32.to_le_bytes());

        assert_eq!(
            probe_coff_member(&bytes, bytes.len()),
            Some(CoffMemberKind::ShortImport)
        );
    }

    #[test]
    fn rejects_truncated_short_import_object() {
        let mut bytes = vec![0; SHORT_IMPORT_HEADER_LEN + 24];
        bytes[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&25u32.to_le_bytes());

        assert_eq!(probe_coff_member(&bytes, bytes.len()), None);
    }

    fn synthetic_coff_object(machine: u16, sections: u16, symbols: u32) -> Vec<u8> {
        let section_table_len = usize::from(sections) * COFF_SECTION_HEADER_LEN;
        let symbol_table_offset = if symbols == 0 {
            0
        } else {
            COFF_HEADER_LEN + section_table_len + 16
        };
        let symbol_table_len = usize::try_from(symbols)
            .expect("synthetic COFF symbol count fits in usize")
            * COFF_SYMBOL_LEN;
        let mut bytes = vec![
            0;
            symbol_table_offset.max(COFF_HEADER_LEN + section_table_len)
                + symbol_table_len
        ];
        bytes[0..2].copy_from_slice(&machine.to_le_bytes());
        bytes[2..4].copy_from_slice(&sections.to_le_bytes());
        bytes[8..12].copy_from_slice(
            &u32::try_from(symbol_table_offset)
                .expect("synthetic COFF symbol table offset fits in u32")
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(&symbols.to_le_bytes());
        bytes[16..18].copy_from_slice(&0u16.to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        if sections > 1 {
            bytes[60..65].copy_from_slice(b".data");
        }
        bytes
    }
}
