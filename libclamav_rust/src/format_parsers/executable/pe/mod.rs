// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! PE/COFF parser and executable-child inventory.
//!
//! ## Scope
//!
//! This parser reads bounded PE/COFF structure needed by scanner metadata and
//! future YARA/YARA-X-style predicates, identifies ClamAV-known PE packer
//! families as metadata, and identifies extractable resource byte ranges when
//! the parser can prove the range and a useful MIME hint.
//!
//! ## References
//!
//! Compatibility behavior is checked against `ClamAV` `pe.c`, `pe.h`,
//! `pe_structs.h`, `rebuildpe.c`, and packer helpers such as `upx.c`,
//! `aspack.c`, `fsg.c`, `petite.c`, `mew.c`, `upack.c`, and `wwunpack.c`.
//! The structural reference is the Microsoft PE/COFF specification:
//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>.
//!
//! ## Layout
//!
//! ```text
//! file offset 0
//! +-------------------------------+
//! | DOS header ("MZ")             |
//! |   e_lfanew -------------------+----+
//! +-------------------------------+    |
//! | DOS stub / padding            |    |
//! +-------------------------------+    |
//! | PE signature ("PE\0\0")       | <--+
//! | COFF header                   | -> machine, DLL flag, section count,
//! |                               |    optional-header size
//! +-------------------------------+
//! | optional header               | -> PE32/PE32+, entrypoint RVA, image base,
//! |                               |    alignments, checksum, subsystem
//! | data directories              | -> [0] export, [1] import, [2] resource,
//! |                               |    [4] security/certificate, [14] CLR, ...
//! +-------------------------------+
//! | section table                 | -> name, virtual address/size,
//! |                               |    raw pointer/size, flags
//! +-------------------------------+
//! | section raw data              | -> RVA-to-file-offset mapping for imports,
//! |                               |    exports, resources, and entrypoint
//! +-------------------------------+
//! | overlay / certificate tail    | -> exact embedded-child probe when bounded
//! +-------------------------------+
//!
//! resource directory tree:
//!   root -> type id/name -> resource id/name -> language -> data entry
//!        -> RVA/size mapped through sections -> embedded-child probe
//!
//! import directory:
//!   IMAGE_IMPORT_DESCRIPTOR[] -> DLL name RVA -> ILT/IAT thunk table
//!        -> ordinal imports or hint/name records
//! ```
//!
//! ## Parser Outputs
//!
//! Output includes header facts, section records, optional hashes, import and
//! export records, resource child byte ranges, overlay child candidates, packer
//! facts, and bounded parse diagnostics.
//!
//! ## Bounds And Recovery
//!
//! The parser caps section counts, data directories, imports, exports,
//! resources, packer marker scans, strings, child candidates, and parse errors.
//! PE candidates require an `MZ` header and valid `PE\0\0` signature path.
//!
//! ## Intentional Gaps
//!
//! The parser does not materialize scanner children directly. It returns byte
//! ranges and derived facts; the PE file-type handler owns nested fmap scans,
//! generated child scans, and ClamAV limit/accounting behavior.
//!

use std::borrow::Cow;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::sync::Arc;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::format_parsers::embedded::{
    EmbeddedChildCandidate, EmbeddedChildProbe, probe_embedded_child,
};

use super::{
    common::{ascii_lowercase_cow, hex_lower},
    unpacker,
};

pub(crate) mod rebuild;

const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

const MAX_SECTIONS: usize = 96;
const MAX_DATA_DIRECTORIES: usize = 16;
const MAX_IMPORT_DLLS: usize = 128;
const MAX_IMPORTS_PER_DLL: usize = 1024;
const MAX_EXPORTS: usize = 512;
const MAX_RESOURCE_ENTRIES: usize = 512;
const MAX_RESOURCE_CHILDREN: usize = 64;
const MAX_PARSE_ERRORS: usize = 32;
const MAX_PACKER_MARKER_SCAN: usize = 4096;
const MAX_PE_C_STRING_BYTES: usize = 4096;
const MAX_RESOURCE_STRING_CHARS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeAnalysisOptions {
    pub(crate) probe_overlay_children: bool,
    pub(crate) calculate_checksum: bool,
    pub(crate) section_hashes: PeHashAlgorithmSet,
    pub(crate) import_table_hashes: PeHashAlgorithmSet,
    pub(crate) calculate_imphash: bool,
}

impl Default for PeAnalysisOptions {
    fn default() -> Self {
        Self {
            probe_overlay_children: true,
            calculate_checksum: false,
            section_hashes: PeHashAlgorithmSet::default(),
            import_table_hashes: PeHashAlgorithmSet::default(),
            calculate_imphash: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeHashAlgorithmSet {
    pub(crate) md5: bool,
    pub(crate) sha1: bool,
    pub(crate) sha256: bool,
}

impl PeHashAlgorithmSet {
    fn is_empty(self) -> bool {
        !self.md5 && !self.sha1 && !self.sha256
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "parser output mirrors independent PE metadata booleans"
)]
pub(crate) struct PeAnalysis {
    pub(crate) is_pe: bool,
    pub(crate) is_32bit: bool,
    pub(crate) is_64bit: bool,
    pub(crate) is_dll: bool,
    pub(crate) pe_header_offset: Option<u32>,
    pub(crate) machine: Option<u16>,
    pub(crate) characteristics: Option<u16>,
    pub(crate) timestamp: Option<u32>,
    pub(crate) pointer_to_symbol_table: Option<u32>,
    pub(crate) number_of_symbols: Option<u32>,
    pub(crate) optional_header_size: Option<u16>,
    pub(crate) optional_header_magic: Option<u16>,
    pub(crate) major_linker_version: Option<u8>,
    pub(crate) minor_linker_version: Option<u8>,
    pub(crate) size_of_code: Option<u32>,
    pub(crate) size_of_initialized_data: Option<u32>,
    pub(crate) size_of_uninitialized_data: Option<u32>,
    pub(crate) subsystem: Option<u16>,
    pub(crate) dll_characteristics: Option<u16>,
    pub(crate) image_base: Option<u64>,
    pub(crate) entrypoint_rva: Option<u32>,
    pub(crate) entrypoint_offset: Option<u64>,
    pub(crate) base_of_code: Option<u32>,
    pub(crate) base_of_data: Option<u32>,
    pub(crate) checksum: Option<u32>,
    pub(crate) calculated_checksum: Option<u32>,
    pub(crate) section_alignment: Option<u32>,
    pub(crate) file_alignment: Option<u32>,
    pub(crate) major_operating_system_version: Option<u16>,
    pub(crate) minor_operating_system_version: Option<u16>,
    pub(crate) major_image_version: Option<u16>,
    pub(crate) minor_image_version: Option<u16>,
    pub(crate) major_subsystem_version: Option<u16>,
    pub(crate) minor_subsystem_version: Option<u16>,
    pub(crate) win32_version_value: Option<u32>,
    pub(crate) size_of_image: Option<u32>,
    pub(crate) size_of_headers: Option<u32>,
    pub(crate) size_of_stack_reserve: Option<u64>,
    pub(crate) size_of_stack_commit: Option<u64>,
    pub(crate) size_of_heap_reserve: Option<u64>,
    pub(crate) size_of_heap_commit: Option<u64>,
    pub(crate) loader_flags: Option<u32>,
    pub(crate) number_of_rva_and_sizes: Option<u32>,
    pub(crate) sections: Vec<PeSection>,
    pub(crate) data_directories: Vec<PeDataDirectory>,
    pub(crate) imports: Vec<PeImportLibrary>,
    pub(crate) import_hashes: Option<PeImportHashAnalysis>,
    pub(crate) exports: Vec<PeExport>,
    pub(crate) resources: Vec<PeResource>,
    pub(crate) resource_children: Vec<PeResourceChild>,
    pub(crate) overlay: Option<PeOverlay>,
    pub(crate) overlay_children: Vec<PeOverlayChild>,
    pub(crate) packers: Vec<PePacker>,
    pub(crate) upx_layout_candidate: bool,
    pub(crate) unpacked_children: Vec<PeUnpackedChild>,
    pub(crate) version_info_offset: Option<u64>,
    pub(crate) clr_runtime_header: Option<PeDataDirectory>,
    pub(crate) parse_errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeImportHashAnalysis {
    pub(crate) size: u64,
    pub(crate) md5: Option<String>,
    pub(crate) sha1: Option<String>,
    pub(crate) sha256: Option<String>,
    pub(crate) imphash: Option<String>,
    pub(crate) status: &'static str,
    pub(crate) skip_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeSection {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) virtual_size: u32,
    pub(crate) virtual_address: u32,
    pub(crate) raw_size: u32,
    pub(crate) raw_offset: u32,
    pub(crate) characteristics: u32,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) hash_size: Option<u64>,
    pub(crate) md5: Option<String>,
    pub(crate) sha1: Option<String>,
    pub(crate) sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeDataDirectory {
    pub(crate) index: usize,
    pub(crate) name: &'static str,
    pub(crate) rva: u32,
    pub(crate) size: u32,
    pub(crate) file_offset: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeImportLibrary {
    pub(crate) dll: String,
    pub(crate) descriptor_rva: u32,
    pub(crate) descriptor_offset: Option<u64>,
    pub(crate) imports: Vec<PeImport>,
    pub(crate) imports_omitted: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PeImport {
    Name { name: String, hint: u16 },
    Ordinal(u64),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeExport {
    pub(crate) index: usize,
    pub(crate) name: Option<String>,
    pub(crate) ordinal: u32,
    pub(crate) rva: u32,
    pub(crate) file_offset: Option<u64>,
    pub(crate) forwarder: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeResource {
    pub(crate) index: usize,
    pub(crate) type_id: Option<u32>,
    pub(crate) type_name: Option<String>,
    pub(crate) name_id: Option<u32>,
    pub(crate) name: Option<String>,
    pub(crate) language_id: Option<u32>,
    pub(crate) rva: u32,
    pub(crate) file_offset: Option<u64>,
    pub(crate) size: u32,
    pub(crate) codepage: u32,
    pub(crate) mime: Option<&'static str>,
    pub(crate) extracted: bool,
    pub(crate) skip_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeResourceChild {
    pub(crate) resource_index: usize,
    pub(crate) file_offset: u64,
    pub(crate) size: u64,
    pub(crate) mime: &'static str,
    pub(crate) filename: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeOverlay {
    pub(crate) offset: u64,
    pub(crate) size: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeOverlayChild {
    pub(crate) index: usize,
    pub(crate) source_offset: u64,
    pub(crate) source_size: u64,
    pub(crate) mime: &'static str,
    pub(crate) range_status: &'static str,
    pub(crate) range_basis: &'static str,
    pub(crate) status: &'static str,
    pub(crate) skip_reason: Option<&'static str>,
    pub(crate) filename: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PePacker {
    pub(crate) name: &'static str,
    pub(crate) confidence: &'static str,
    pub(crate) status: &'static str,
    pub(crate) detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeUnpackedChild {
    pub(crate) index: usize,
    pub(crate) packer: &'static str,
    pub(crate) status: &'static str,
    pub(crate) source_offset: Option<u64>,
    pub(crate) source_size: Option<u64>,
    pub(crate) unpacked_size: Option<u64>,
    pub(crate) mime: &'static str,
    pub(crate) skip_reason: Option<&'static str>,
    pub(crate) bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct PeHeaders {
    section_table_offset: usize,
    section_count: usize,
    is_64bit: bool,
    entrypoint_rva: u32,
    resource_directory: Option<PeDataDirectory>,
    export_directory: Option<PeDataDirectory>,
    import_directory: Option<PeDataDirectory>,
}

#[derive(Debug)]
struct ResourceFrame {
    offset: usize,
    depth: usize,
    type_id: Option<u32>,
    type_name: Option<Arc<str>>,
    name_id: Option<u32>,
    name: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug)]
struct ResourceLeafPath<'a> {
    type_id: Option<u32>,
    type_name: Option<&'a str>,
    name_id: Option<u32>,
    name: Option<&'a str>,
    language_id: Option<u32>,
}

#[derive(Clone, Debug)]
struct ResourceChildDecision {
    mime: Option<&'static str>,
    child: Option<PeResourceChild>,
    extracted: bool,
    skip_reason: Option<&'static str>,
}

/// Parse PE metadata from one object.
#[cfg(test)]
pub(crate) fn analyze(bytes: &[u8]) -> PeAnalysis {
    analyze_with_options(bytes, PeAnalysisOptions::default())
}

/// Parse PE metadata from one object with caller-controlled probe policy.
pub(crate) fn analyze_with_options(bytes: &[u8], options: PeAnalysisOptions) -> PeAnalysis {
    let mut analysis = PeAnalysis::default();
    if options.calculate_checksum {
        analysis.calculated_checksum = Some(calculate_pe_checksum(bytes));
    }
    let Some(headers) = parse_headers(bytes, &mut analysis) else {
        return analysis;
    };
    parse_sections(bytes, &headers, &mut analysis);
    calculate_pe_section_hashes(bytes, &mut analysis.sections, options.section_hashes);
    analysis.entrypoint_offset =
        rva_to_file_offset(headers.entrypoint_rva, &analysis.sections, bytes.len());
    parse_data_directory_payloads(bytes, &headers, &mut analysis);
    analysis.import_hashes = calculate_pe_import_hashes(
        &analysis,
        options.import_table_hashes,
        options.calculate_imphash,
    );
    analysis.overlay = compute_overlay(bytes, analysis.size_of_headers, &analysis.sections);
    if options.probe_overlay_children {
        analysis.overlay_children = probe_overlay_children(bytes, analysis.overlay.as_ref());
    }
    let section_hints = PackerSectionHints::from_sections(&analysis.sections);
    analysis.upx_layout_candidate = section_hints.upx_layout;
    analysis.packers = detect_packers(bytes, section_hints, analysis.entrypoint_offset);
    analysis.unpacked_children = unpacker::unpack_pe(bytes, &analysis);
    promote_successful_structural_upx(&mut analysis);
    analysis
}

fn parse_headers(bytes: &[u8], analysis: &mut PeAnalysis) -> Option<PeHeaders> {
    if bytes.len() < 0x40 {
        push_error(&mut analysis.parse_errors, "pe_header_too_short");
        return None;
    }
    if !has_dos_magic(bytes) {
        push_error(&mut analysis.parse_errors, "missing_mz_magic");
        return None;
    }
    let Some(pe_offset) = read_u32_le(bytes, 0x3c).and_then(|offset| usize::try_from(offset).ok())
    else {
        push_error(&mut analysis.parse_errors, "invalid_e_lfanew");
        return None;
    };
    if pe_offset
        .checked_add(24)
        .is_none_or(|end| end > bytes.len())
    {
        push_error(&mut analysis.parse_errors, "invalid_e_lfanew");
        return None;
    }
    if pe_offset
        .checked_add(4)
        .and_then(|end| bytes.get(pe_offset..end))
        != Some(PE_SIGNATURE)
    {
        push_error(&mut analysis.parse_errors, "missing_pe_signature");
        return None;
    }
    let coff_offset = pe_offset.checked_add(4)?;
    let machine = read_u16_le(bytes, coff_offset)?;
    let section_count = read_u16_le(bytes, coff_offset + 2)? as usize;
    let timestamp = read_u32_le(bytes, coff_offset + 4)?;
    let pointer_to_symbol_table = read_u32_le(bytes, coff_offset + 8)?;
    let number_of_symbols = read_u32_le(bytes, coff_offset + 12)?;
    let optional_header_size_u16 = read_u16_le(bytes, coff_offset + 16)?;
    let optional_header_size = optional_header_size_u16 as usize;
    let characteristics = read_u16_le(bytes, coff_offset + 18)?;
    let optional_header_offset = coff_offset.checked_add(20)?;
    let Some(section_table_offset) = optional_header_offset.checked_add(optional_header_size)
    else {
        push_error(
            &mut analysis.parse_errors,
            "optional_header_offset_overflow",
        );
        return None;
    };
    if optional_header_offset
        .checked_add(optional_header_size)
        .is_none_or(|end| end > bytes.len())
    {
        push_error(&mut analysis.parse_errors, "optional_header_truncated");
        return None;
    }
    if section_table_offset
        .checked_add(section_count.saturating_mul(40))
        .is_none_or(|end| end > bytes.len())
    {
        push_error(&mut analysis.parse_errors, "section_table_truncated");
    }
    if section_count > MAX_SECTIONS {
        push_error(&mut analysis.parse_errors, "section_count_exceeded");
    }
    let optional_header_magic = read_u16_le(bytes, optional_header_offset)?;
    let is_32bit = optional_header_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    let is_64bit = optional_header_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if !is_32bit && !is_64bit {
        push_error(&mut analysis.parse_errors, "unknown_optional_header_magic");
        return None;
    }
    let minimum_optional_header_size = if is_64bit { 112 } else { 96 };
    if optional_header_size < minimum_optional_header_size {
        push_error(&mut analysis.parse_errors, "optional_header_too_small");
        return None;
    }

    let major_linker_version = *bytes.get(optional_header_offset + 2)?;
    let minor_linker_version = *bytes.get(optional_header_offset + 3)?;
    let size_of_code = read_u32_le(bytes, optional_header_offset + 4)?;
    let size_of_initialized_data = read_u32_le(bytes, optional_header_offset + 8)?;
    let size_of_uninitialized_data = read_u32_le(bytes, optional_header_offset + 12)?;
    let entrypoint_rva = read_u32_le(bytes, optional_header_offset + 16)?;
    let base_of_code = read_u32_le(bytes, optional_header_offset + 20)?;
    let image_base = if is_64bit {
        read_u64_le(bytes, optional_header_offset + 24)?
    } else {
        u64::from(read_u32_le(bytes, optional_header_offset + 28)?)
    };
    let base_of_data = if is_64bit {
        None
    } else {
        Some(read_u32_le(bytes, optional_header_offset + 24)?)
    };
    let section_alignment = read_u32_le(bytes, optional_header_offset + 32)?;
    let file_alignment = read_u32_le(bytes, optional_header_offset + 36)?;
    let major_operating_system_version = read_u16_le(bytes, optional_header_offset + 40)?;
    let minor_operating_system_version = read_u16_le(bytes, optional_header_offset + 42)?;
    let major_image_version = read_u16_le(bytes, optional_header_offset + 44)?;
    let minor_image_version = read_u16_le(bytes, optional_header_offset + 46)?;
    let major_subsystem_version = read_u16_le(bytes, optional_header_offset + 48)?;
    let minor_subsystem_version = read_u16_le(bytes, optional_header_offset + 50)?;
    let win32_version_value = read_u32_le(bytes, optional_header_offset + 52)?;
    let size_of_image = read_u32_le(bytes, optional_header_offset + 56)?;
    let size_of_headers = read_u32_le(bytes, optional_header_offset + 60)?;
    let checksum = read_u32_le(bytes, optional_header_offset + 64)?;
    let subsystem = read_u16_le(bytes, optional_header_offset + 68)?;
    let dll_characteristics = read_u16_le(bytes, optional_header_offset + 70)?;
    let (
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
    ) = if is_64bit {
        (
            read_u64_le(bytes, optional_header_offset + 72)?,
            read_u64_le(bytes, optional_header_offset + 80)?,
            read_u64_le(bytes, optional_header_offset + 88)?,
            read_u64_le(bytes, optional_header_offset + 96)?,
            read_u32_le(bytes, optional_header_offset + 104)?,
        )
    } else {
        (
            u64::from(read_u32_le(bytes, optional_header_offset + 72)?),
            u64::from(read_u32_le(bytes, optional_header_offset + 76)?),
            u64::from(read_u32_le(bytes, optional_header_offset + 80)?),
            u64::from(read_u32_le(bytes, optional_header_offset + 84)?),
            read_u32_le(bytes, optional_header_offset + 88)?,
        )
    };
    let number_of_rva_and_sizes = if is_64bit {
        read_u32_le(bytes, optional_header_offset + 108)?
    } else {
        read_u32_le(bytes, optional_header_offset + 92)?
    };

    analysis.is_pe = true;
    analysis.is_32bit = is_32bit;
    analysis.is_64bit = is_64bit;
    analysis.is_dll = characteristics & IMAGE_FILE_DLL != 0;
    analysis.pe_header_offset = Some(pe_offset as u32);
    analysis.machine = Some(machine);
    analysis.characteristics = Some(characteristics);
    analysis.timestamp = Some(timestamp);
    analysis.pointer_to_symbol_table = Some(pointer_to_symbol_table);
    analysis.number_of_symbols = Some(number_of_symbols);
    analysis.optional_header_size = Some(optional_header_size_u16);
    analysis.optional_header_magic = Some(optional_header_magic);
    analysis.major_linker_version = Some(major_linker_version);
    analysis.minor_linker_version = Some(minor_linker_version);
    analysis.size_of_code = Some(size_of_code);
    analysis.size_of_initialized_data = Some(size_of_initialized_data);
    analysis.size_of_uninitialized_data = Some(size_of_uninitialized_data);
    analysis.subsystem = Some(subsystem);
    analysis.dll_characteristics = Some(dll_characteristics);
    analysis.image_base = Some(image_base);
    analysis.entrypoint_rva = Some(entrypoint_rva);
    analysis.base_of_code = Some(base_of_code);
    analysis.base_of_data = base_of_data;
    analysis.checksum = Some(checksum);
    analysis.section_alignment = Some(section_alignment);
    analysis.file_alignment = Some(file_alignment);
    analysis.major_operating_system_version = Some(major_operating_system_version);
    analysis.minor_operating_system_version = Some(minor_operating_system_version);
    analysis.major_image_version = Some(major_image_version);
    analysis.minor_image_version = Some(minor_image_version);
    analysis.major_subsystem_version = Some(major_subsystem_version);
    analysis.minor_subsystem_version = Some(minor_subsystem_version);
    analysis.win32_version_value = Some(win32_version_value);
    analysis.size_of_image = Some(size_of_image);
    analysis.size_of_headers = Some(size_of_headers);
    analysis.size_of_stack_reserve = Some(size_of_stack_reserve);
    analysis.size_of_stack_commit = Some(size_of_stack_commit);
    analysis.size_of_heap_reserve = Some(size_of_heap_reserve);
    analysis.size_of_heap_commit = Some(size_of_heap_commit);
    analysis.loader_flags = Some(loader_flags);
    analysis.number_of_rva_and_sizes = Some(number_of_rva_and_sizes);

    let directory_offset = optional_header_offset + if is_64bit { 112 } else { 96 };
    let declared_directory_count = cmp::min(number_of_rva_and_sizes as usize, MAX_DATA_DIRECTORIES);
    let available_directory_count = section_table_offset.saturating_sub(directory_offset) / 8;
    let directory_count = cmp::min(declared_directory_count, available_directory_count);
    if directory_count < declared_directory_count {
        push_error(
            &mut analysis.parse_errors,
            "data_directory_count_exceeds_optional_header",
        );
    }
    parse_data_directories(bytes, directory_offset, directory_count, analysis);
    let mut import_directory = None;
    let mut export_directory = None;
    let mut resource_directory = None;
    let mut clr_runtime_header = None;
    for directory in &analysis.data_directories {
        if directory.rva == 0 || directory.size == 0 {
            continue;
        }
        match directory.index {
            IMAGE_DIRECTORY_ENTRY_IMPORT => import_directory = Some(*directory),
            IMAGE_DIRECTORY_ENTRY_EXPORT => export_directory = Some(*directory),
            IMAGE_DIRECTORY_ENTRY_RESOURCE => resource_directory = Some(*directory),
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR => clr_runtime_header = Some(*directory),
            _ => {}
        }
    }
    analysis.clr_runtime_header = clr_runtime_header;

    Some(PeHeaders {
        section_table_offset,
        section_count,
        is_64bit,
        entrypoint_rva,
        resource_directory,
        export_directory,
        import_directory,
    })
}

pub(crate) fn has_dos_magic(bytes: &[u8]) -> bool {
    bytes.get(..2) == Some(b"MZ")
}

fn parse_sections(bytes: &[u8], headers: &PeHeaders, analysis: &mut PeAnalysis) {
    let count = cmp::min(headers.section_count, MAX_SECTIONS);
    for section_index in 0..count {
        let Some(offset) = section_index
            .checked_mul(40)
            .and_then(|delta| headers.section_table_offset.checked_add(delta))
        else {
            push_error(&mut analysis.parse_errors, "section_offset_overflow");
            break;
        };
        if offset.checked_add(40).is_none_or(|end| end > bytes.len()) {
            push_error(&mut analysis.parse_errors, "section_record_truncated");
            break;
        }
        let Some(name_end) = offset.checked_add(8) else {
            push_error(&mut analysis.parse_errors, "section_offset_overflow");
            break;
        };
        let name = section_name(&bytes[offset..name_end]);
        let declared_virtual_size = read_u32_le(bytes, offset + 8).unwrap_or_default();
        let declared_virtual_address = read_u32_le(bytes, offset + 12).unwrap_or_default();
        let declared_raw_size = read_u32_le(bytes, offset + 16).unwrap_or_default();
        let declared_raw_offset = read_u32_le(bytes, offset + 20).unwrap_or_default();
        let characteristics = read_u32_le(bytes, offset + 36).unwrap_or_default();
        let virtual_address = align_down(
            declared_virtual_address,
            analysis.section_alignment.unwrap_or_default(),
        );
        let mut virtual_size = align_up(
            declared_virtual_size,
            analysis.section_alignment.unwrap_or_default(),
        );
        let raw_offset = align_down(
            declared_raw_offset,
            analysis.file_alignment.unwrap_or_default(),
        );
        let mut raw_size = align_up(
            declared_raw_size,
            analysis.file_alignment.unwrap_or_default(),
        );
        raw_size = clamp_section_raw_size(
            raw_size,
            raw_offset,
            declared_raw_offset,
            bytes.len() as u64,
        );
        if virtual_size == 0 && raw_size != 0 {
            virtual_size = align_up(
                declared_raw_size,
                analysis.section_alignment.unwrap_or_default(),
            );
        }
        let start = u64::from(raw_offset);
        let end = if let Some(end) = start.checked_add(u64::from(raw_size)) {
            end
        } else {
            push_error(&mut analysis.parse_errors, "section_raw_data_overflow");
            u64::MAX
        };
        if declared_raw_size != 0
            && u64::from(declared_raw_offset)
                .checked_add(u64::from(declared_raw_size))
                .is_none_or(|end| end > bytes.len() as u64)
        {
            push_error(&mut analysis.parse_errors, "section_raw_data_truncated");
        }
        analysis.sections.push(PeSection {
            index: section_index + 1,
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics,
            start,
            end,
            hash_size: None,
            md5: None,
            sha1: None,
            sha256: None,
        });
    }
}

fn clamp_section_raw_size(
    raw_size: u32,
    raw_offset: u32,
    declared_raw_offset: u32,
    file_len: u64,
) -> u32 {
    if raw_size == 0 {
        return 0;
    }
    let raw_offset = u64::from(raw_offset);
    if raw_offset >= file_len || u64::from(declared_raw_offset) >= file_len {
        return 0;
    }
    let available = file_len.saturating_sub(raw_offset);
    match u32::try_from(available) {
        Ok(available) => raw_size.min(available),
        Err(_) => raw_size,
    }
}

fn calculate_pe_section_hashes(
    bytes: &[u8],
    sections: &mut [PeSection],
    algorithms: PeHashAlgorithmSet,
) {
    if algorithms.is_empty() {
        return;
    }
    for section in sections {
        let Some(section_bytes) = section_hash_bytes(section, bytes) else {
            continue;
        };
        let hashes = hash_bytes(section_bytes, algorithms);
        section.hash_size = Some(hashes.size);
        section.md5 = hashes.md5;
        section.sha1 = hashes.sha1;
        section.sha256 = hashes.sha256;
    }
}

fn section_hash_bytes<'a>(section: &PeSection, bytes: &'a [u8]) -> Option<&'a [u8]> {
    if section.raw_size == 0 {
        return None;
    }
    let start = usize::try_from(section.start).ok()?;
    if start >= bytes.len() {
        return None;
    }
    let declared_size = usize::try_from(section.raw_size).ok()?;
    let end = start
        .checked_add(declared_size)
        .unwrap_or(bytes.len())
        .min(bytes.len());
    if end <= start {
        return None;
    }
    Some(&bytes[start..end])
}

fn parse_data_directories(
    bytes: &[u8],
    directory_offset: usize,
    count: usize,
    analysis: &mut PeAnalysis,
) {
    for index in 0..count {
        let Some(offset) = index
            .checked_mul(8)
            .and_then(|delta| directory_offset.checked_add(delta))
        else {
            push_error(&mut analysis.parse_errors, "data_directory_offset_overflow");
            break;
        };
        if offset.checked_add(8).is_none_or(|end| end > bytes.len()) {
            push_error(&mut analysis.parse_errors, "data_directory_truncated");
            break;
        }
        let rva = read_u32_le(bytes, offset).unwrap_or_default();
        let size = read_u32_le(bytes, offset + 4).unwrap_or_default();
        analysis.data_directories.push(PeDataDirectory {
            index,
            name: data_directory_name(index),
            rva,
            size,
            file_offset: None,
        });
    }
}

fn parse_data_directory_payloads(bytes: &[u8], headers: &PeHeaders, analysis: &mut PeAnalysis) {
    for directory in &mut analysis.data_directories {
        directory.file_offset = rva_to_file_offset(directory.rva, &analysis.sections, bytes.len());
    }
    if let Some(directory) = &headers.import_directory {
        parse_imports(bytes, directory, headers.is_64bit, analysis);
    }
    if let Some(directory) = &headers.export_directory {
        parse_exports(bytes, directory, analysis);
    }
    if let Some(directory) = &headers.resource_directory {
        parse_resources(bytes, directory, analysis);
    }
}

fn parse_imports(
    bytes: &[u8],
    directory: &PeDataDirectory,
    is_64bit: bool,
    analysis: &mut PeAnalysis,
) {
    let mut rva_cache = None;
    let Some(mut descriptor_offset) = rva_to_file_offset_usize_cached(
        directory.rva,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "import_directory_unmapped");
        return;
    };
    let mut descriptor_count = 0usize;
    loop {
        if descriptor_offset
            .checked_add(20)
            .is_none_or(|end| end > bytes.len())
        {
            push_error(&mut analysis.parse_errors, "import_descriptor_truncated");
            break;
        }
        let original_first_thunk = read_u32_le(bytes, descriptor_offset).unwrap_or_default();
        let name_rva = read_u32_le(bytes, descriptor_offset + 12).unwrap_or_default();
        let first_thunk = read_u32_le(bytes, descriptor_offset + 16).unwrap_or_default();
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        descriptor_count += 1;
        if descriptor_count > MAX_IMPORT_DLLS {
            push_error(&mut analysis.parse_errors, "import_dll_limit_exceeded");
            break;
        }
        let dll = read_rva_c_string_cached(bytes, name_rva, &analysis.sections, &mut rva_cache)
            .unwrap_or_else(|| format!("unmapped_{name_rva:08X}"));
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let (imports, imports_omitted) = parse_import_thunks(
            bytes,
            thunk_rva,
            is_64bit,
            &analysis.sections,
            &mut rva_cache,
            &mut analysis.parse_errors,
        );
        let descriptor_rva = if let Some(rva) = descriptor_count
            .saturating_sub(1)
            .checked_mul(20)
            .and_then(|delta| u32::try_from(delta).ok())
            .and_then(|delta| directory.rva.checked_add(delta))
        {
            rva
        } else {
            push_error(&mut analysis.parse_errors, "import_descriptor_rva_overflow");
            directory.rva
        };
        analysis.imports.push(PeImportLibrary {
            dll,
            descriptor_rva,
            descriptor_offset: Some(descriptor_offset as u64),
            imports,
            imports_omitted,
        });
        let Some(next_descriptor_offset) = descriptor_offset.checked_add(20) else {
            push_error(
                &mut analysis.parse_errors,
                "import_descriptor_offset_overflow",
            );
            break;
        };
        descriptor_offset = next_descriptor_offset;
    }
}

fn parse_import_thunks(
    bytes: &[u8],
    thunk_rva: u32,
    is_64bit: bool,
    sections: &[PeSection],
    rva_cache: &mut Option<usize>,
    parse_errors: &mut Vec<String>,
) -> (Vec<PeImport>, usize) {
    let Some(mut thunk_offset) =
        rva_to_file_offset_usize_cached(thunk_rva, sections, bytes.len(), rva_cache)
    else {
        push_error(parse_errors, "import_thunk_unmapped");
        return (Vec::new(), 0);
    };
    let thunk_size = if is_64bit { 8 } else { 4 };
    let ordinal_mask = if is_64bit {
        0x8000_0000_0000_0000u64
    } else {
        0x8000_0000u64
    };
    let rva_mask = if is_64bit {
        0x7fff_ffff_ffff_ffffu64
    } else {
        0x7fff_ffffu64
    };
    let mut imports = Vec::new();
    let mut omitted = 0usize;
    loop {
        if thunk_offset
            .checked_add(thunk_size)
            .is_none_or(|end| end > bytes.len())
        {
            push_error(parse_errors, "import_thunk_truncated");
            break;
        }
        let thunk = if is_64bit {
            read_u64_le(bytes, thunk_offset).unwrap_or_default()
        } else {
            u64::from(read_u32_le(bytes, thunk_offset).unwrap_or_default())
        };
        if thunk == 0 {
            break;
        }
        if imports.len() >= MAX_IMPORTS_PER_DLL {
            omitted = 1;
            push_error(parse_errors, "import_thunks_omitted");
            break;
        }
        if thunk & ordinal_mask != 0 {
            imports.push(PeImport::Ordinal(thunk & 0xffff));
        } else {
            let name_rva_raw = thunk & rva_mask;
            let Ok(name_rva) = u32::try_from(name_rva_raw) else {
                push_error(parse_errors, "import_name_rva_overflow");
                imports.push(PeImport::Name {
                    name: format!("unmapped_{name_rva_raw:016X}"),
                    hint: 0,
                });
                continue;
            };
            if let Some(name_offset) =
                rva_to_file_offset_usize_cached(name_rva, sections, bytes.len(), rva_cache)
            {
                let hint = read_u16_le(bytes, name_offset).unwrap_or_default();
                let name = name_offset
                    .checked_add(2)
                    .and_then(|offset| read_c_string(bytes, offset))
                    .unwrap_or_else(|| format!("unreadable_{name_rva:08X}"));
                imports.push(PeImport::Name { name, hint });
            } else {
                imports.push(PeImport::Name {
                    name: format!("unmapped_{name_rva:08X}"),
                    hint: 0,
                });
            }
        }
        let Some(next_thunk_offset) = thunk_offset.checked_add(thunk_size) else {
            push_error(parse_errors, "import_thunk_offset_overflow");
            break;
        };
        thunk_offset = next_thunk_offset;
    }
    (imports, omitted)
}

fn parse_exports(bytes: &[u8], directory: &PeDataDirectory, analysis: &mut PeAnalysis) {
    let mut rva_cache = None;
    let Some(export_offset) = rva_to_file_offset_usize_cached(
        directory.rva,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "export_directory_unmapped");
        return;
    };
    if export_offset
        .checked_add(40)
        .is_none_or(|end| end > bytes.len())
    {
        push_error(&mut analysis.parse_errors, "export_directory_truncated");
        return;
    }
    let ordinal_base = read_u32_le(bytes, export_offset + 16).unwrap_or_default();
    let function_count = read_u32_le(bytes, export_offset + 20).unwrap_or_default();
    let name_count = read_u32_le(bytes, export_offset + 24).unwrap_or_default();
    let address_of_functions = read_u32_le(bytes, export_offset + 28).unwrap_or_default();
    let address_of_names = read_u32_le(bytes, export_offset + 32).unwrap_or_default();
    let address_of_name_ordinals = read_u32_le(bytes, export_offset + 36).unwrap_or_default();
    let Some(functions_offset) = rva_to_file_offset_usize_cached(
        address_of_functions,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "export_functions_unmapped");
        return;
    };
    let Some(names_offset) = rva_to_file_offset_usize_cached(
        address_of_names,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "export_names_unmapped");
        return;
    };
    let Some(ordinals_offset) = rva_to_file_offset_usize_cached(
        address_of_name_ordinals,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "export_ordinals_unmapped");
        return;
    };
    let mut names_by_ordinal = HashMap::new();
    for i in 0..cmp::min(name_count as usize, MAX_EXPORTS) {
        let Some(name_rva_offset) = table_record_offset(names_offset, 4, i) else {
            push_error(&mut analysis.parse_errors, "export_name_record_overflow");
            break;
        };
        let Some(ordinal_offset) = table_record_offset(ordinals_offset, 2, i) else {
            push_error(&mut analysis.parse_errors, "export_name_record_overflow");
            break;
        };
        if name_rva_offset
            .checked_add(4)
            .is_none_or(|end| end > bytes.len())
            || ordinal_offset
                .checked_add(2)
                .is_none_or(|end| end > bytes.len())
        {
            push_error(&mut analysis.parse_errors, "export_name_record_truncated");
            break;
        }
        let name_rva = read_u32_le(bytes, name_rva_offset).unwrap_or_default();
        let ordinal_index = u32::from(read_u16_le(bytes, ordinal_offset).unwrap_or_default());
        if let Some(name) =
            read_rva_c_string_cached(bytes, name_rva, &analysis.sections, &mut rva_cache)
        {
            names_by_ordinal.insert(ordinal_index, name);
        }
    }
    for i in 0..cmp::min(function_count as usize, MAX_EXPORTS) {
        let Some(function_rva_offset) = table_record_offset(functions_offset, 4, i) else {
            push_error(
                &mut analysis.parse_errors,
                "export_function_record_overflow",
            );
            break;
        };
        if function_rva_offset
            .checked_add(4)
            .is_none_or(|end| end > bytes.len())
        {
            push_error(
                &mut analysis.parse_errors,
                "export_function_record_truncated",
            );
            break;
        }
        let rva = read_u32_le(bytes, function_rva_offset).unwrap_or_default();
        if rva == 0 {
            continue;
        }
        let file_offset =
            rva_to_file_offset_usize_cached(rva, &analysis.sections, bytes.len(), &mut rva_cache)
                .map(|offset| offset as u64);
        let forwarder = if directory
            .rva
            .checked_add(directory.size)
            .is_some_and(|end| rva >= directory.rva && rva < end)
        {
            read_rva_c_string_cached(bytes, rva, &analysis.sections, &mut rva_cache)
        } else {
            None
        };
        let Ok(export_index) = u32::try_from(i) else {
            push_error(&mut analysis.parse_errors, "export_index_overflow");
            break;
        };
        let ordinal = ordinal_base.checked_add(export_index).unwrap_or_else(|| {
            push_error(&mut analysis.parse_errors, "export_ordinal_overflow");
            ordinal_base
        });
        analysis.exports.push(PeExport {
            index: i + 1,
            name: names_by_ordinal.remove(&export_index),
            ordinal,
            rva,
            file_offset,
            forwarder,
        });
    }
}

fn parse_resources(bytes: &[u8], directory: &PeDataDirectory, analysis: &mut PeAnalysis) {
    let mut rva_cache = None;
    let Some(resource_base) = rva_to_file_offset_usize_cached(
        directory.rva,
        &analysis.sections,
        bytes.len(),
        &mut rva_cache,
    ) else {
        push_error(&mut analysis.parse_errors, "resource_directory_unmapped");
        return;
    };
    let Some(resource_range) = resource_directory_range(resource_base, directory.size, bytes.len())
    else {
        push_error(
            &mut analysis.parse_errors,
            "resource_directory_range_invalid",
        );
        return;
    };
    let mut queue = VecDeque::with_capacity(1);
    let mut visited = HashSet::new();
    let mut processed_entries = 0usize;
    queue.push_back(ResourceFrame {
        offset: resource_base,
        depth: 0,
        type_id: None,
        type_name: None,
        name_id: None,
        name: None,
    });
    while let Some(frame) = queue.pop_front() {
        if processed_entries >= MAX_RESOURCE_ENTRIES {
            push_error(&mut analysis.parse_errors, "resource_entry_limit_exceeded");
            break;
        }
        if !visited.insert(frame.offset) {
            push_error(&mut analysis.parse_errors, "resource_directory_cycle");
            continue;
        }
        if !range_contains(&resource_range, frame.offset, 16) {
            push_error(&mut analysis.parse_errors, "resource_directory_truncated");
            continue;
        }
        let named_count = read_u16_le(bytes, frame.offset + 12).unwrap_or_default() as usize;
        let id_count = read_u16_le(bytes, frame.offset + 14).unwrap_or_default() as usize;
        let entry_count = named_count.saturating_add(id_count);
        for i in 0..entry_count {
            if processed_entries >= MAX_RESOURCE_ENTRIES {
                push_error(&mut analysis.parse_errors, "resource_entry_limit_exceeded");
                return;
            }
            processed_entries = processed_entries.saturating_add(1);
            let Some(entries_base) = frame.offset.checked_add(16) else {
                push_error(&mut analysis.parse_errors, "resource_entry_offset_overflow");
                break;
            };
            let Some(entry_offset) = table_record_offset(entries_base, 8, i) else {
                push_error(&mut analysis.parse_errors, "resource_entry_offset_overflow");
                break;
            };
            if !range_contains(&resource_range, entry_offset, 8) {
                push_error(&mut analysis.parse_errors, "resource_entry_truncated");
                break;
            }
            let name_raw = read_u32_le(bytes, entry_offset).unwrap_or_default();
            let data_raw = read_u32_le(bytes, entry_offset + 4).unwrap_or_default();
            let named = name_raw & 0x8000_0000 != 0;
            let id = name_raw & 0x7fff_ffff;
            let string_name = named.then(|| {
                Arc::<str>::from(
                    read_resource_string(bytes, resource_base, id as usize, &resource_range)
                        .unwrap_or_else(|| format!("unreadable_{id:08X}")),
                )
            });
            if data_raw & 0x8000_0000 != 0 {
                let subdir_offset = (data_raw & 0x7fff_ffff) as usize;
                if let Some(next_offset) = resource_base.checked_add(subdir_offset) {
                    if !range_contains(&resource_range, next_offset, 16) {
                        push_error(
                            &mut analysis.parse_errors,
                            "resource_subdirectory_out_of_bounds",
                        );
                        continue;
                    }
                    let child_frame =
                        resource_child_frame(&frame, named, id, string_name, next_offset);
                    if child_frame.depth <= 8 {
                        queue.push_back(child_frame);
                    } else {
                        push_error(
                            &mut analysis.parse_errors,
                            "resource_directory_depth_exceeded",
                        );
                    }
                } else {
                    push_error(
                        &mut analysis.parse_errors,
                        "resource_subdirectory_offset_overflow",
                    );
                }
                continue;
            }
            let resource_path = resource_leaf_path(&frame, named, id, string_name.as_ref());
            let Some(data_entry_offset) = resource_base.checked_add(data_raw as usize) else {
                push_error(
                    &mut analysis.parse_errors,
                    "resource_data_entry_offset_overflow",
                );
                continue;
            };
            if !range_contains(&resource_range, data_entry_offset, 16) {
                push_error(
                    &mut analysis.parse_errors,
                    "resource_data_entry_out_of_bounds",
                );
                continue;
            }
            let rva = read_u32_le(bytes, data_entry_offset).unwrap_or_default();
            let size = read_u32_le(bytes, data_entry_offset + 4).unwrap_or_default();
            let codepage = read_u32_le(bytes, data_entry_offset + 8).unwrap_or_default();
            let file_offset = rva_to_file_offset_usize_cached(
                rva,
                &analysis.sections,
                bytes.len(),
                &mut rva_cache,
            )
            .map(|offset| offset as u64);
            let child_probe = file_offset
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| {
                    let size = usize::try_from(size).ok()?;
                    let end = offset.checked_add(size)?;
                    let sample = bytes.get(offset..end)?;
                    probe_embedded_child(sample)
                });
            let resource_index = analysis.resources.len() + 1;
            let child_decision = resource_child_decision(
                child_probe,
                resource_index,
                file_offset,
                analysis.resource_children.len(),
                bytes.len(),
            );
            let extracted = child_decision.extracted;
            if let Some(child) = child_decision.child {
                analysis.resource_children.push(child);
            }
            if resource_path.type_id == Some(16) && analysis.version_info_offset.is_none() {
                analysis.version_info_offset = file_offset;
            }
            analysis.resources.push(PeResource {
                index: resource_index,
                type_id: resource_path.type_id,
                type_name: resource_path.type_name.map(str::to_owned),
                name_id: resource_path.name_id,
                name: resource_path.name.map(str::to_owned),
                language_id: resource_path.language_id,
                rva,
                file_offset,
                size,
                codepage,
                mime: child_decision.mime,
                extracted,
                skip_reason: child_decision.skip_reason,
            });
        }
    }
}

fn resource_child_decision(
    probe: Option<EmbeddedChildProbe>,
    resource_index: usize,
    file_offset: Option<u64>,
    child_count: usize,
    bytes_len: usize,
) -> ResourceChildDecision {
    match probe {
        Some(EmbeddedChildProbe::Valid(candidate)) => {
            let child = resource_child(
                candidate,
                resource_index,
                file_offset,
                child_count,
                bytes_len,
            );
            let extracted = child.is_some();
            ResourceChildDecision {
                mime: Some(candidate.mime),
                child,
                extracted,
                skip_reason: (!extracted).then_some("resource_child_limit_or_range"),
            }
        }
        Some(EmbeddedChildProbe::Rejected(rejection)) => ResourceChildDecision {
            mime: Some(rejection.mime),
            child: None,
            extracted: false,
            skip_reason: Some(rejection.skip_reason),
        },
        None => ResourceChildDecision {
            mime: None,
            child: None,
            extracted: false,
            skip_reason: Some("unknown_resource_mime"),
        },
    }
}

fn resource_child(
    candidate: EmbeddedChildCandidate,
    resource_index: usize,
    file_offset: Option<u64>,
    child_count: usize,
    bytes_len: usize,
) -> Option<PeResourceChild> {
    if child_count >= MAX_RESOURCE_CHILDREN {
        return None;
    }
    let file_offset = file_offset?;
    let end = file_offset.checked_add(candidate.size)?;
    if !usize::try_from(end).is_ok_and(|end| end <= bytes_len) {
        return None;
    }
    Some(PeResourceChild {
        resource_index,
        file_offset,
        size: candidate.size,
        mime: candidate.mime,
        filename: format!("resource-{resource_index}.{ext}", ext = candidate.extension),
    })
}

fn resource_child_frame(
    frame: &ResourceFrame,
    named: bool,
    id: u32,
    string_name: Option<Arc<str>>,
    offset: usize,
) -> ResourceFrame {
    let depth = frame.depth.saturating_add(1);
    match frame.depth {
        0 => ResourceFrame {
            offset,
            depth,
            type_id: (!named).then_some(id),
            type_name: string_name,
            name_id: None,
            name: None,
        },
        1 => ResourceFrame {
            offset,
            depth,
            type_id: frame.type_id,
            type_name: frame.type_name.as_ref().map(Arc::clone),
            name_id: (!named).then_some(id),
            name: string_name,
        },
        _ => ResourceFrame {
            offset,
            depth,
            type_id: frame.type_id,
            type_name: frame.type_name.as_ref().map(Arc::clone),
            name_id: frame.name_id,
            name: frame.name.as_ref().map(Arc::clone),
        },
    }
}

fn resource_leaf_path<'a>(
    frame: &'a ResourceFrame,
    named: bool,
    id: u32,
    string_name: Option<&'a Arc<str>>,
) -> ResourceLeafPath<'a> {
    match frame.depth {
        0 => ResourceLeafPath {
            type_id: (!named).then_some(id),
            type_name: string_name.map(std::convert::AsRef::as_ref),
            name_id: None,
            name: None,
            language_id: None,
        },
        1 => ResourceLeafPath {
            type_id: frame.type_id,
            type_name: frame.type_name.as_deref(),
            name_id: (!named).then_some(id),
            name: string_name.map(std::convert::AsRef::as_ref),
            language_id: None,
        },
        _ => ResourceLeafPath {
            type_id: frame.type_id,
            type_name: frame.type_name.as_deref(),
            name_id: frame.name_id,
            name: frame.name.as_deref(),
            language_id: (!named).then_some(id),
        },
    }
}

fn compute_overlay(
    bytes: &[u8],
    size_of_headers: Option<u32>,
    sections: &[PeSection],
) -> Option<PeOverlay> {
    let mut end = u64::from(size_of_headers.unwrap_or_default());
    for section in sections {
        if section.raw_size != 0 {
            end = end.max(section.end);
        }
    }
    let len = bytes.len() as u64;
    if end < len {
        Some(PeOverlay {
            offset: end,
            size: len - end,
        })
    } else {
        None
    }
}

fn probe_overlay_children(bytes: &[u8], overlay: Option<&PeOverlay>) -> Vec<PeOverlayChild> {
    let Some(overlay) = overlay else {
        return Vec::new();
    };
    let Ok(offset) = usize::try_from(overlay.offset) else {
        return vec![rejected_overlay_child(
            1,
            overlay.offset,
            overlay.size,
            "application/octet-stream",
            "unknown",
            "overlay_offset",
            "overlay_offset_unrepresentable",
        )];
    };
    let Ok(overlay_size) = usize::try_from(overlay.size) else {
        return vec![rejected_overlay_child(
            1,
            overlay.offset,
            overlay.size,
            "application/octet-stream",
            "unknown",
            "overlay_size",
            "overlay_size_unrepresentable",
        )];
    };
    let Some(end) = offset.checked_add(overlay_size) else {
        return vec![rejected_overlay_child(
            1,
            overlay.offset,
            overlay.size,
            "application/octet-stream",
            "unknown",
            "overlay_range",
            "overlay_range_overflow",
        )];
    };
    let Some(sample) = bytes.get(offset..end) else {
        return vec![rejected_overlay_child(
            1,
            overlay.offset,
            overlay.size,
            "application/octet-stream",
            "unknown",
            "overlay_range",
            "overlay_range_invalid",
        )];
    };
    match probe_embedded_child(sample) {
        Some(EmbeddedChildProbe::Valid(candidate)) if candidate.size <= overlay.size => {
            vec![PeOverlayChild {
                index: 1,
                source_offset: overlay.offset,
                source_size: candidate.size,
                mime: candidate.mime,
                range_status: candidate.range_status,
                range_basis: candidate.range_basis,
                status: "extracted",
                skip_reason: None,
                filename: format!("overlay-1.{ext}", ext = candidate.extension),
            }]
        }
        Some(EmbeddedChildProbe::Valid(candidate)) => vec![rejected_overlay_child(
            1,
            overlay.offset,
            candidate.size,
            candidate.mime,
            "unknown",
            candidate.range_basis,
            "overlay_child_range_invalid",
        )],
        Some(EmbeddedChildProbe::Rejected(rejection)) => vec![PeOverlayChild {
            index: 1,
            source_offset: overlay.offset,
            source_size: rejection.source_size,
            mime: rejection.mime,
            range_status: rejection.range_status,
            range_basis: rejection.range_basis,
            status: "not_extracted",
            skip_reason: Some(rejection.skip_reason),
            filename: String::new(),
        }],
        None => Vec::new(),
    }
}

fn rejected_overlay_child(
    index: usize,
    source_offset: u64,
    source_size: u64,
    mime: &'static str,
    range_status: &'static str,
    range_basis: &'static str,
    skip_reason: &'static str,
) -> PeOverlayChild {
    PeOverlayChild {
        index,
        source_offset,
        source_size,
        mime,
        range_status,
        range_basis,
        status: "not_extracted",
        skip_reason: Some(skip_reason),
        filename: String::new(),
    }
}

fn detect_packers(
    bytes: &[u8],
    section_hints: PackerSectionHints,
    entrypoint_offset: Option<u64>,
) -> Vec<PePacker> {
    let entrypoint_marker_bytes = entrypoint_offset
        .and_then(|offset| usize::try_from(offset).ok())
        .and_then(|offset| bytes.get(offset..))
        .map(|tail| &tail[..tail.len().min(MAX_PACKER_MARKER_SCAN)])
        .unwrap_or_default();
    let entrypoint_markers = PackerEntrypointMarkers::from_bytes(entrypoint_marker_bytes);
    let mut packers = Vec::new();
    let mut add = |name: &'static str, detail: Option<String>| {
        packers.push(PePacker {
            name,
            confidence: "heuristic",
            status: "detected",
            detail,
        });
    };
    if section_hints.upx || entrypoint_markers.upx {
        let detail = if section_hints.upx {
            "UPX section"
        } else {
            "UPX marker"
        };
        add("upx", Some(detail.to_owned()));
    }
    if section_hints.aspack || entrypoint_markers.aspack {
        add("aspack", Some("ASPack section or marker".to_owned()));
    }
    if section_hints.fsg
        || entrypoint_markers.fsg
        || (section_hints.clamav && entrypoint_markers.papadding)
    {
        add("fsg", Some("FSG section or marker".to_owned()));
    }
    if entrypoint_markers.petite || section_hints.petite {
        add("petite", Some("Petite marker".to_owned()));
    }
    if entrypoint_markers.pespin || section_hints.pespin {
        add("pespin", Some("PESpin marker".to_owned()));
    }
    if entrypoint_markers.wwpack || section_hints.wwpack {
        add("wwpack", Some("WWPack marker".to_owned()));
    }
    if entrypoint_markers.nspack || section_hints.nspack {
        add("nspack", Some("NsPack marker".to_owned()));
    }
    if entrypoint_markers.upack
        || section_hints.upack
        || (entrypoint_markers.load_library_a
            && entrypoint_markers.get_proc_address
            && section_hints.upack_unnamed_or_non_ascii)
    {
        add("upack", Some("Upack marker".to_owned()));
    }
    if entrypoint_markers.mew || section_hints.mew {
        add("mew", Some("MEW marker".to_owned()));
    }
    if section_hints.yc || (entrypoint_markers.yc && entrypoint_markers.unpack) {
        add("yc", Some("yC marker".to_owned()));
    }
    packers
}

fn promote_successful_structural_upx(analysis: &mut PeAnalysis) {
    if !analysis.upx_layout_candidate || analysis.packers.iter().any(|packer| packer.name == "upx")
    {
        return;
    }
    let unpacked = analysis
        .unpacked_children
        .iter()
        .any(|child| child.packer == "upx" && child.status == "unpacked");
    if unpacked {
        analysis.packers.push(PePacker {
            name: "upx",
            confidence: "heuristic",
            status: "detected",
            detail: Some("UPX structural section pair".to_owned()),
        });
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "named packer marker flags are less error-prone than manual bit masks"
)]
struct PackerEntrypointMarkers {
    upx: bool,
    aspack: bool,
    fsg: bool,
    papadding: bool,
    petite: bool,
    pespin: bool,
    wwpack: bool,
    nspack: bool,
    upack: bool,
    load_library_a: bool,
    get_proc_address: bool,
    mew: bool,
    yc: bool,
    unpack: bool,
}

impl PackerEntrypointMarkers {
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut markers = Self::default();
        for offset in 0..bytes.len() {
            if markers.all_found() {
                break;
            }
            let tail = &bytes[offset..];
            match bytes[offset].to_ascii_lowercase() {
                b'a' => markers.aspack |= starts_ascii_case_insensitive(tail, b"ASPack"),
                b'f' => markers.fsg |= starts_ascii_case_insensitive(tail, b"FSG!"),
                b'g' => {
                    markers.get_proc_address |=
                        starts_ascii_case_insensitive(tail, b"GetProcAddress");
                }
                b'l' => {
                    markers.load_library_a |= starts_ascii_case_insensitive(tail, b"LoadLibraryA");
                }
                b'm' => markers.mew |= starts_ascii_case_insensitive(tail, b"MEW"),
                b'n' => markers.nspack |= starts_ascii_case_insensitive(tail, b"NsPack"),
                b'p' => {
                    markers.papadding |= starts_ascii_case_insensitive(tail, b"PAPADDING");
                    markers.petite |= starts_ascii_case_insensitive(tail, b"Petite");
                    markers.pespin |= starts_ascii_case_insensitive(tail, b"PESpin");
                }
                b'u' => {
                    markers.upack |= starts_ascii_case_insensitive(tail, b"UPack");
                    markers.unpack |= starts_ascii_case_insensitive(tail, b"unpack");
                    markers.upx |= starts_ascii_case_insensitive(tail, b"UPX!");
                }
                b'w' => markers.wwpack |= starts_ascii_case_insensitive(tail, b"WWPACK"),
                b'y' => markers.yc |= starts_ascii_case_insensitive(tail, b"yC"),
                _ => {}
            }
        }
        markers
    }

    fn all_found(self) -> bool {
        self.upx
            && self.aspack
            && self.fsg
            && self.papadding
            && self.petite
            && self.pespin
            && self.wwpack
            && self.nspack
            && self.upack
            && self.load_library_a
            && self.get_proc_address
            && self.mew
            && self.yc
            && self.unpack
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "named packer section hints document each independent heuristic"
)]
struct PackerSectionHints {
    upx: bool,
    upx_layout: bool,
    aspack: bool,
    fsg: bool,
    clamav: bool,
    petite: bool,
    pespin: bool,
    wwpack: bool,
    nspack: bool,
    upack: bool,
    upack_unnamed_or_non_ascii: bool,
    mew: bool,
    yc: bool,
}

impl PackerSectionHints {
    fn from_sections(sections: &[PeSection]) -> Self {
        let mut hints = Self {
            upx_layout: sections.windows(2).any(|pair| {
                pair[0].raw_size == 0
                    && pair[0].virtual_size != 0
                    && pair[1].raw_size != 0
                    && pair[1].virtual_size != 0
            }),
            ..Self::default()
        };
        for section in sections {
            let name = section.name.as_str();
            let name_bytes = name.as_bytes();
            hints.upx |= matches_ignore_ascii_case(name, "upx0")
                || matches_ignore_ascii_case(name, "upx1")
                || matches_ignore_ascii_case(name, "upx2");
            hints.aspack |= contains_ascii_case_insensitive(name_bytes, b"aspack")
                || matches_ignore_ascii_case(name, ".adata");
            hints.fsg |= contains_ascii_case_insensitive(name_bytes, b"fsg");
            hints.clamav |= matches_ignore_ascii_case(name, ".clamav");
            hints.petite |= contains_ascii_case_insensitive(name_bytes, b"petite");
            hints.pespin |= contains_ascii_case_insensitive(name_bytes, b"pespin")
                || matches_ignore_ascii_case(name, "kungbim");
            hints.wwpack |= contains_ascii_case_insensitive(name_bytes, b"wwpack");
            hints.nspack |= contains_ascii_case_insensitive(name_bytes, b"nsp");
            hints.upack |= contains_ascii_case_insensitive(name_bytes, b"upack");
            hints.upack_unnamed_or_non_ascii |= name.is_empty() || !name.is_ascii();
            hints.mew |= contains_ascii_case_insensitive(name_bytes, b"mew");
            hints.yc |= matches_ignore_ascii_case(name, "yc");
            if hints.all_found() {
                break;
            }
        }
        hints
    }

    fn all_found(self) -> bool {
        self.upx
            && self.aspack
            && self.fsg
            && self.clamav
            && self.petite
            && self.pespin
            && self.wwpack
            && self.nspack
            && self.upack
            && self.upack_unnamed_or_non_ascii
            && self.mew
            && self.yc
    }
}

fn matches_ignore_ascii_case(value: &str, expected: &str) -> bool {
    value.len() == expected.len() && value.eq_ignore_ascii_case(expected)
}

fn rva_to_file_offset(rva: u32, sections: &[PeSection], file_len: usize) -> Option<u64> {
    rva_to_file_offset_usize(rva, sections, file_len).map(|offset| offset as u64)
}

fn rva_to_file_offset_usize(rva: u32, sections: &[PeSection], file_len: usize) -> Option<usize> {
    let mut cache = None;
    rva_to_file_offset_usize_cached(rva, sections, file_len, &mut cache)
}

fn rva_to_file_offset_usize_cached(
    rva: u32,
    sections: &[PeSection],
    file_len: usize,
    cache: &mut Option<usize>,
) -> Option<usize> {
    if let Some(index) = *cache
        && let Some(section) = sections.get(index)
    {
        match section_rva_to_file_offset(rva, section, file_len) {
            SectionRvaFileOffset::Offset(offset) => return Some(offset),
            SectionRvaFileOffset::Unmapped => return None,
            SectionRvaFileOffset::Outside => {}
        }
    }
    for (index, section) in sections.iter().enumerate() {
        match section_rva_to_file_offset(rva, section, file_len) {
            SectionRvaFileOffset::Offset(offset) => {
                *cache = Some(index);
                return Some(offset);
            }
            SectionRvaFileOffset::Unmapped => return None,
            SectionRvaFileOffset::Outside => {}
        }
    }
    let offset = usize::try_from(rva).ok()?;
    (offset < file_len).then_some(offset)
}

enum SectionRvaFileOffset {
    Outside,
    Unmapped,
    Offset(usize),
}

fn section_rva_to_file_offset(
    rva: u32,
    section: &PeSection,
    file_len: usize,
) -> SectionRvaFileOffset {
    let section_span = section.virtual_size.max(section.raw_size);
    let start = section.virtual_address;
    let Some(end) = start.checked_add(section_span) else {
        return SectionRvaFileOffset::Outside;
    };
    if section_span == 0 || rva < start || rva >= end {
        return SectionRvaFileOffset::Outside;
    }
    let delta = rva - start;
    if delta >= section.raw_size {
        return SectionRvaFileOffset::Unmapped;
    }
    let Some(offset) = section.raw_offset.checked_add(delta) else {
        return SectionRvaFileOffset::Unmapped;
    };
    let Ok(offset) = usize::try_from(offset) else {
        return SectionRvaFileOffset::Unmapped;
    };
    if offset < file_len {
        SectionRvaFileOffset::Offset(offset)
    } else {
        SectionRvaFileOffset::Unmapped
    }
}

fn read_rva_c_string_cached(
    bytes: &[u8],
    rva: u32,
    sections: &[PeSection],
    cache: &mut Option<usize>,
) -> Option<String> {
    let offset = rva_to_file_offset_usize_cached(rva, sections, bytes.len(), cache)?;
    read_c_string(bytes, offset)
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let tail = &tail[..tail.len().min(MAX_PE_C_STRING_BYTES)];
    let len = tail.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..len]).into_owned())
}

fn resource_directory_range(
    resource_base: usize,
    directory_size: u32,
    bytes_len: usize,
) -> Option<Range<usize>> {
    let directory_size = usize::try_from(directory_size).ok()?;
    let declared_end = resource_base.checked_add(directory_size)?;
    let end = declared_end.min(bytes_len);
    (resource_base < end).then_some(resource_base..end)
}

fn range_contains(range: &Range<usize>, offset: usize, len: usize) -> bool {
    offset >= range.start && offset.checked_add(len).is_some_and(|end| end <= range.end)
}

fn table_record_offset(base: usize, record_size: usize, index: usize) -> Option<usize> {
    index
        .checked_mul(record_size)
        .and_then(|relative| base.checked_add(relative))
}

fn read_resource_string(
    bytes: &[u8],
    resource_base: usize,
    offset: usize,
    resource_range: &Range<usize>,
) -> Option<String> {
    let absolute = resource_base.checked_add(offset)?;
    if !range_contains(resource_range, absolute, 2) {
        return None;
    }
    let char_count = read_u16_le(bytes, absolute)? as usize;
    if char_count > MAX_RESOURCE_STRING_CHARS {
        return None;
    }
    let bytes_start = absolute.checked_add(2)?;
    let bytes_len = char_count.checked_mul(2)?;
    if !range_contains(resource_range, bytes_start, bytes_len) {
        return None;
    }
    let raw = bytes.get(bytes_start..bytes_start.checked_add(bytes_len)?)?;
    Some(decode_utf16le_lossy(raw, char_count))
}

fn decode_utf16le_lossy(raw: &[u8], char_count: usize) -> String {
    let units = raw
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let mut out = String::with_capacity(char_count);
    for decoded in char::decode_utf16(units) {
        out.push(decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    out
}

fn section_name(raw: &[u8]) -> String {
    let len = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..len]).trim().to_owned()
}

#[derive(Clone, Debug)]
struct PeComputedHashes {
    size: u64,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
}

fn hash_bytes(bytes: &[u8], algorithms: PeHashAlgorithmSet) -> PeComputedHashes {
    PeComputedHashes {
        size: bytes.len() as u64,
        md5: algorithms.md5.then(|| hex_lower(&Md5::digest(bytes))),
        sha1: algorithms.sha1.then(|| hex_lower(&Sha1::digest(bytes))),
        sha256: algorithms.sha256.then(|| hex_lower(&Sha256::digest(bytes))),
    }
}

fn calculate_pe_import_hashes(
    analysis: &PeAnalysis,
    algorithms: PeHashAlgorithmSet,
    calculate_imphash: bool,
) -> Option<PeImportHashAnalysis> {
    if algorithms.is_empty() && !calculate_imphash {
        return None;
    }
    if analysis.imports.is_empty() {
        return None;
    }
    if analysis
        .imports
        .iter()
        .any(|library| library.imports_omitted != 0)
    {
        return Some(PeImportHashAnalysis {
            status: "not_computed",
            skip_reason: Some("imports_omitted"),
            ..PeImportHashAnalysis::default()
        });
    }
    let mut md5 = (algorithms.md5 || calculate_imphash).then(Md5::new);
    let mut sha1 = algorithms.sha1.then(Sha1::new);
    let mut sha256 = algorithms.sha256.then(Sha256::new);
    let mut size = 0u64;
    let mut write_hash_bytes = |chunk: &[u8]| {
        size = size.saturating_add(chunk.len() as u64);
        if let Some(hasher) = md5.as_mut() {
            hasher.update(chunk);
        }
        if let Some(hasher) = sha1.as_mut() {
            hasher.update(chunk);
        }
        if let Some(hasher) = sha256.as_mut() {
            hasher.update(chunk);
        }
    };

    let mut emitted = false;
    for_each_normalized_import(analysis, |dll, function| {
        if emitted {
            write_hash_bytes(b",");
        }
        write_hash_bytes(dll.as_bytes());
        write_hash_bytes(b".");
        write_hash_bytes(function.as_bytes());
        emitted = true;
    });

    if !emitted {
        return None;
    }
    let md5 = md5.map(|hasher| hex_lower(&hasher.finalize()));
    let sha1 = sha1.map(|hasher| hex_lower(&hasher.finalize()));
    let sha256 = sha256.map(|hasher| hex_lower(&hasher.finalize()));
    let (md5, imphash) = split_import_md5(md5, algorithms.md5, calculate_imphash);
    Some(PeImportHashAnalysis {
        size,
        md5,
        sha1,
        sha256,
        imphash,
        status: "computed",
        skip_reason: None,
    })
}

fn split_import_md5(
    value: Option<String>,
    needs_md5: bool,
    needs_imphash: bool,
) -> (Option<String>, Option<String>) {
    match (needs_md5, needs_imphash, value) {
        (true, true, Some(value)) => (Some(value.clone()), Some(value)),
        (true, false, value) => (value, None),
        (false, true, value) => (None, value),
        _ => (None, None),
    }
}

pub(crate) fn for_each_normalized_import(analysis: &PeAnalysis, mut visit: impl FnMut(&str, &str)) {
    for library in &analysis.imports {
        let Some(dll) = normalized_import_library_name(&library.dll) else {
            continue;
        };
        for import in &library.imports {
            let Some(function) = normalized_import_function_name(dll.as_ref(), import) else {
                continue;
            };
            visit(dll.as_ref(), function.as_ref());
        }
    }
}

fn normalized_import_library_name(dll: &str) -> Option<Cow<'_, str>> {
    let mut name = ascii_lowercase_cow(dll.trim());
    if name.is_empty() || name.starts_with("unmapped_") {
        return None;
    }
    for suffix in [".dll", ".sys", ".ocx"] {
        if name.ends_with(suffix) {
            let new_len = name.len().saturating_sub(suffix.len());
            match &mut name {
                Cow::Borrowed(value) => *value = &value[..new_len],
                Cow::Owned(value) => value.truncate(new_len),
            }
            break;
        }
    }
    (!name.is_empty()).then_some(name)
}

fn normalized_import_function_name<'a>(dll: &str, import: &'a PeImport) -> Option<Cow<'a, str>> {
    match import {
        PeImport::Name { name, .. } => {
            let name = ascii_lowercase_cow(name.trim());
            (!name.is_empty() && !name.starts_with("unmapped_") && !name.starts_with("unreadable_"))
                .then_some(name)
        }
        PeImport::Ordinal(ordinal) => Some(Cow::Owned(ordinal_import_name(dll, *ordinal))),
    }
}

fn ordinal_import_name(_dll: &str, ordinal: u64) -> String {
    format!("ord{ordinal}")
}

fn align_down(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        value
    } else {
        value / alignment * alignment
    }
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 || value == 0 {
        value
    } else {
        let addend = alignment - 1;
        let Some(adjusted) = value.checked_add(addend) else {
            return u32::MAX / alignment * alignment;
        };
        adjusted / alignment * alignment
    }
}

fn data_directory_name(index: usize) -> &'static str {
    match index {
        0 => "export",
        1 => "import",
        2 => "resource",
        3 => "exception",
        4 => "certificate",
        5 => "base_relocation",
        6 => "debug",
        7 => "architecture",
        8 => "global_pointer",
        9 => "tls",
        10 => "load_config",
        11 => "bound_import",
        12 => "iat",
        13 => "delay_import",
        14 => "clr_runtime_header",
        15 => "reserved",
        _ => "unknown",
    }
}

fn calculate_pe_checksum(bytes: &[u8]) -> u32 {
    let checksum_offset = read_u32_le(bytes, 0x3c)
        .and_then(|pe_offset| usize::try_from(pe_offset).ok())
        .and_then(|pe_offset| pe_offset.checked_add(4 + 20 + 64));
    let mut sum = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        if checksum_offset.is_some_and(|offset| i == offset || i == offset + 2) {
            i += 2;
            continue;
        }
        let word = if i + 1 < bytes.len() {
            u64::from(u16::from_le_bytes([bytes[i], bytes[i + 1]]))
        } else {
            u64::from(bytes[i])
        };
        sum = (sum & 0xffff) + word + (sum >> 16);
        i += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    let folded_sum = u32::try_from(sum).expect("folded PE checksum fits in u32");
    let length_low =
        u32::try_from(bytes.len() & 0xffff_ffffusize).expect("masked PE length fits in u32");
    folded_sum.wrapping_add(length_low)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let first = needle[0].to_ascii_lowercase();
    let last_start = haystack.len() - needle.len();
    for start in 0..=last_start {
        if haystack[start].to_ascii_lowercase() == first
            && haystack[start..start + needle.len()].eq_ignore_ascii_case(needle)
        {
            return true;
        }
    }
    false
}

fn starts_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn push_error(errors: &mut Vec<String>, error: &'static str) {
    if errors.len() < MAX_PARSE_ERRORS {
        errors.push(error.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_usize_to_u16(value: usize) -> u16 {
        u16::try_from(value).expect("fixture value fits in u16")
    }

    fn fixture_usize_to_u32(value: usize) -> u32 {
        u32::try_from(value).expect("fixture value fits in u32")
    }

    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(PE_SIGNATURE);
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&(0x14cu16).to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&(1u16).to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(0xe0u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&(0x0102u16).to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2]
            .copy_from_slice(&(IMAGE_NT_OPTIONAL_HDR32_MAGIC).to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[optional + 28..optional + 32].copy_from_slice(&(0x0040_0000_u32).to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&(3u16).to_le_bytes());
        bytes[optional + 92..optional + 96].copy_from_slice(&(16u32).to_le_bytes());
        let section = optional + 0xe0;
        bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
        bytes[section + 8..section + 12].copy_from_slice(&(0x100u32).to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&(0x6000_0020_u32).to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(b"\x55\x8b\xec\xc3");
        bytes
    }

    fn minimal_pe_with_png_resource() -> Vec<u8> {
        minimal_pe_with_resource(&minimal_png())
    }

    fn minimal_pe_with_resource(payload: &[u8]) -> Vec<u8> {
        let mut bytes = minimal_pe();
        let required_len = 0x380usize + payload.len();
        if required_len > bytes.len() {
            bytes.resize(required_len, 0);
            let section = 0x84 + 20 + 0xe0;
            let raw_size = fixture_usize_to_u32(required_len - 0x200);
            bytes[section + 8..section + 12].copy_from_slice(&raw_size.to_le_bytes());
            bytes[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
        }
        let optional = 0x84 + 20;
        let resource_directory = optional + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        bytes[resource_directory..resource_directory + 4]
            .copy_from_slice(&(0x1100u32).to_le_bytes());
        bytes[resource_directory + 4..resource_directory + 8]
            .copy_from_slice(&(0x90u32).to_le_bytes());

        let base = 0x300usize;
        bytes[base + 14..base + 16].copy_from_slice(&(1u16).to_le_bytes());
        bytes[base + 16..base + 20].copy_from_slice(&(10u32).to_le_bytes());
        bytes[base + 20..base + 24].copy_from_slice(&(0x8000_0020u32).to_le_bytes());

        let name_dir = base + 0x20;
        bytes[name_dir + 14..name_dir + 16].copy_from_slice(&(1u16).to_le_bytes());
        bytes[name_dir + 16..name_dir + 20].copy_from_slice(&(1u32).to_le_bytes());
        bytes[name_dir + 20..name_dir + 24].copy_from_slice(&(0x8000_0040u32).to_le_bytes());

        let lang_dir = base + 0x40;
        bytes[lang_dir + 14..lang_dir + 16].copy_from_slice(&(1u16).to_le_bytes());
        bytes[lang_dir + 16..lang_dir + 20].copy_from_slice(&(1033u32).to_le_bytes());
        bytes[lang_dir + 20..lang_dir + 24].copy_from_slice(&(0x60u32).to_le_bytes());

        let data_entry = base + 0x60;
        bytes[data_entry..data_entry + 4].copy_from_slice(&(0x1180u32).to_le_bytes());
        bytes[data_entry + 4..data_entry + 8]
            .copy_from_slice(&fixture_usize_to_u32(payload.len()).to_le_bytes());
        bytes[0x380..0x380 + payload.len()].copy_from_slice(payload);
        bytes
    }

    fn pe_with_many_root_resource_entries(entry_count: usize) -> Vec<u8> {
        let mut bytes = minimal_pe();
        let base = 0x300usize;
        let table_size = 16usize + entry_count.saturating_mul(8);
        let required_len = base.saturating_add(table_size);
        if required_len > bytes.len() {
            bytes.resize(required_len, 0);
            let section = 0x84 + 20 + 0xe0;
            let raw_size = fixture_usize_to_u32(required_len - 0x200);
            bytes[section + 8..section + 12].copy_from_slice(&raw_size.to_le_bytes());
            bytes[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
        }
        let optional = 0x84 + 20;
        let resource_directory = optional + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        bytes[resource_directory..resource_directory + 4]
            .copy_from_slice(&(0x1100u32).to_le_bytes());
        bytes[resource_directory + 4..resource_directory + 8]
            .copy_from_slice(&fixture_usize_to_u32(table_size).to_le_bytes());
        bytes[base + 14..base + 16]
            .copy_from_slice(&fixture_usize_to_u16(entry_count).to_le_bytes());
        bytes
    }

    fn minimal_png() -> Vec<u8> {
        b"\x89PNG\r\n\x1a\n\0\0\0\0IEND\xae\x42\x60\x82".to_vec()
    }

    fn minimal_empty_zip() -> Vec<u8> {
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec()
    }

    fn minimal_pdf() -> Vec<u8> {
        b"%PDF-1.7\n%%EOF\n".to_vec()
    }

    fn minimal_embedded_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(PE_SIGNATURE);
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&(0x14cu16).to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(0xe0u16).to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2]
            .copy_from_slice(&(IMAGE_NT_OPTIONAL_HDR32_MAGIC).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes
    }

    #[test]
    fn parses_minimal_pe32_headers_and_sections() {
        let analysis = analyze(&minimal_pe());

        assert!(analysis.is_pe);
        assert!(analysis.is_32bit);
        assert!(!analysis.is_64bit);
        assert_eq!(analysis.machine, Some(0x14c));
        assert_eq!(analysis.entrypoint_rva, Some(0x1000));
        assert_eq!(analysis.entrypoint_offset, Some(0x200));
        assert_eq!(analysis.sections.len(), 1);
        assert_eq!(analysis.sections[0].name, ".text");
        assert_eq!(analysis.sections[0].start, 0x200);
        assert_eq!(analysis.sections[0].end, 0x400);
    }

    #[test]
    fn computes_requested_section_hashes_only() {
        let mut bytes = minimal_pe();
        bytes[0x200..0x203].copy_from_slice(b"abc");
        let expected_sha1 = hex_lower(&Sha1::digest(&bytes[0x200..0x400]));
        let analysis = analyze_with_options(
            &bytes,
            PeAnalysisOptions {
                section_hashes: PeHashAlgorithmSet {
                    sha1: true,
                    ..PeHashAlgorithmSet::default()
                },
                ..PeAnalysisOptions::default()
            },
        );

        assert_eq!(
            analysis.sections[0].sha1.as_deref(),
            Some(expected_sha1.as_str())
        );
        assert_eq!(analysis.sections[0].hash_size, Some(0x200));
        assert_eq!(analysis.sections[0].md5, None);
        assert_eq!(analysis.sections[0].sha256, None);
    }

    #[test]
    fn omits_section_hashes_without_hash_options() {
        let analysis = analyze(&minimal_pe());

        assert_eq!(analysis.sections[0].md5, None);
        assert_eq!(analysis.sections[0].sha1, None);
        assert_eq!(analysis.sections[0].sha256, None);
        assert_eq!(analysis.sections[0].hash_size, None);
    }

    #[test]
    fn import_hashes_use_normalized_import_stream() {
        let mut analysis = PeAnalysis::default();
        analysis.imports.push(PeImportLibrary {
            dll: "KERNEL32.dll".to_owned(),
            imports: vec![PeImport::Name {
                name: "CreateFileA".to_owned(),
                hint: 0,
            }],
            ..PeImportLibrary::default()
        });
        let normalized = b"kernel32.createfilea";
        let expected_md5 = hex_lower(&Md5::digest(normalized));
        let expected_sha256 = hex_lower(&Sha256::digest(normalized));
        let hashes = calculate_pe_import_hashes(
            &analysis,
            PeHashAlgorithmSet {
                md5: true,
                sha256: true,
                ..PeHashAlgorithmSet::default()
            },
            true,
        )
        .expect("import hashes");

        assert_eq!(hashes.size, normalized.len() as u64);
        assert_eq!(hashes.md5.as_deref(), Some(expected_md5.as_str()));
        assert_eq!(hashes.sha1, None);
        assert_eq!(hashes.sha256.as_deref(), Some(expected_sha256.as_str()));
        assert_eq!(hashes.status, "computed");
        assert_eq!(hashes.imphash.as_deref(), Some(expected_md5.as_str()));

        let imphash_only =
            calculate_pe_import_hashes(&analysis, PeHashAlgorithmSet::default(), true)
                .expect("imphash-only import hash");
        assert_eq!(imphash_only.md5, None);
        assert_eq!(imphash_only.imphash.as_deref(), Some(expected_md5.as_str()));
    }

    #[test]
    fn import_hashes_skip_truncated_import_inventory() {
        let mut analysis = PeAnalysis::default();
        analysis.imports.push(PeImportLibrary {
            dll: "KERNEL32.dll".to_owned(),
            imports_omitted: 1,
            ..PeImportLibrary::default()
        });
        let hashes = calculate_pe_import_hashes(&analysis, PeHashAlgorithmSet::default(), true)
            .expect("not-computed import hash status");

        assert_eq!(hashes.status, "not_computed");
        assert_eq!(hashes.skip_reason, Some("imports_omitted"));
        assert_eq!(hashes.md5, None);
        assert_eq!(hashes.imphash, None);
    }

    #[test]
    fn import_thunks_stop_after_per_dll_limit() {
        let thunk_count = MAX_IMPORTS_PER_DLL + 64;
        let mut bytes = vec![0u8; thunk_count * 4];
        for index in 0..thunk_count {
            let offset = index * 4;
            bytes[offset..offset + 4].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        }
        let mut parse_errors = Vec::new();
        let mut rva_cache = None;

        let (imports, omitted) =
            parse_import_thunks(&bytes, 0, false, &[], &mut rva_cache, &mut parse_errors);

        assert_eq!(imports.len(), MAX_IMPORTS_PER_DLL);
        assert_eq!(omitted, 1);
        assert!(
            parse_errors
                .iter()
                .any(|error| error == "import_thunks_omitted"),
            "{parse_errors:?}"
        );
    }

    #[test]
    fn rejects_non_pe_without_panicking() {
        let analysis = analyze(b"not a pe");

        assert!(!analysis.is_pe);
        assert!(
            analysis
                .parse_errors
                .contains(&"pe_header_too_short".to_owned())
        );
    }

    #[test]
    fn detects_upx_section_names() {
        let mut bytes = minimal_pe();
        let section = 0x84 + 20 + 0xe0;
        bytes[section..section + 8].copy_from_slice(b"UPX0\0\0\0\0");

        let analysis = analyze(&bytes);

        assert_eq!(analysis.packers.len(), 1);
        assert_eq!(analysis.packers[0].name, "upx");
        assert_eq!(analysis.unpacked_children[0].status, "not_unpacked");
    }

    #[test]
    fn structural_upx_section_pair_without_valid_payload_remains_probe_only() {
        let mut bytes = minimal_pe();
        let coff = 0x84;
        bytes[coff + 2..coff + 4].copy_from_slice(&(2u16).to_le_bytes());
        let optional = coff + 20;
        bytes[optional + 16..optional + 20].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&(0x3000u32).to_le_bytes());
        let section = optional + 0xe0;

        bytes[section..section + 8].copy_from_slice(b"CODE\0\0\0\0");
        bytes[section + 8..section + 12].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&(0u32).to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&(0xe000_0020_u32).to_le_bytes());

        let section = section + 40;
        bytes[section..section + 8].copy_from_slice(b"DATA\0\0\0\0");
        bytes[section + 8..section + 12].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&(0xe000_0040_u32).to_le_bytes());

        let analysis = analyze(&bytes);

        assert!(analysis.upx_layout_candidate);
        assert!(analysis.packers.is_empty());
        assert!(analysis.unpacked_children.is_empty());
    }

    #[test]
    fn successful_structural_upx_probe_promotes_packer_metadata() {
        let mut analysis = PeAnalysis {
            upx_layout_candidate: true,
            unpacked_children: vec![PeUnpackedChild {
                index: 1,
                packer: "upx",
                status: "unpacked",
                source_offset: Some(0x200),
                source_size: Some(0x100),
                unpacked_size: Some(0x300),
                mime: "application/x-dosexec",
                skip_reason: None,
                bytes: None,
            }],
            ..PeAnalysis::default()
        };

        promote_successful_structural_upx(&mut analysis);

        assert_eq!(analysis.packers.len(), 1);
        assert_eq!(analysis.packers[0].name, "upx");
        assert_eq!(
            analysis.packers[0].detail.as_deref(),
            Some("UPX structural section pair")
        );
    }

    #[test]
    fn ignores_packer_marker_strings_outside_entrypoint_stub() {
        let mut bytes = minimal_pe();
        bytes.resize(0x200 + MAX_PACKER_MARKER_SCAN + 0x100, 0);
        bytes.extend_from_slice(
            b"ASPack Petite PESpin WWPACK NsPack UPack MEW yC unpack \
              LoadLibraryA GetProcAddress FSG! PAPADDING",
        );

        let analysis = analyze(&bytes);

        assert!(
            analysis.packers.is_empty(),
            "ordinary PE payload strings should not produce packer metadata: {:?}",
            analysis.packers
        );
        assert!(analysis.unpacked_children.is_empty());
    }

    #[test]
    fn resource_strings_are_length_bounded() {
        let mut bytes = vec![0u8; 2 + (MAX_RESOURCE_STRING_CHARS + 1) * 2];
        bytes[0..2]
            .copy_from_slice(&(fixture_usize_to_u16(MAX_RESOURCE_STRING_CHARS) + 1).to_le_bytes());

        assert_eq!(read_resource_string(&bytes, 0, 0, &(0..bytes.len())), None);
    }

    #[test]
    fn resource_directory_entries_are_globally_capped() {
        let analysis = analyze(&pe_with_many_root_resource_entries(
            MAX_RESOURCE_ENTRIES + 64,
        ));

        assert_eq!(analysis.resources.len(), MAX_RESOURCE_ENTRIES);
        assert!(
            analysis
                .parse_errors
                .iter()
                .any(|error| error == "resource_entry_limit_exceeded"),
            "{:?}",
            analysis.parse_errors
        );
    }

    #[test]
    fn rva_mapping_rejects_virtual_section_tail_without_raw_bytes() {
        let mut bytes = minimal_pe();
        let optional = 0x84 + 20;
        bytes[optional + 16..optional + 20].copy_from_slice(&(0x1300u32).to_le_bytes());
        let analysis = analyze(&bytes);

        assert_eq!(analysis.entrypoint_rva, Some(0x1300));
        assert_eq!(analysis.entrypoint_offset, None);
        assert_eq!(
            rva_to_file_offset(0x1300, &analysis.sections, bytes.len()),
            None
        );
        assert_eq!(
            rva_to_file_offset(0x11ff, &analysis.sections, bytes.len()),
            Some(0x3ff)
        );
    }

    #[test]
    fn data_directories_are_clamped_to_optional_header_size() {
        let mut bytes = minimal_pe();
        let coff = 0x84;
        let optional = coff + 20;
        let old_section = optional + 0xe0;
        let new_section = optional + 0x60;
        let section_record = bytes[old_section..old_section + 40].to_vec();
        bytes[new_section..new_section + 40].copy_from_slice(&section_record);
        bytes[old_section..old_section + 40].fill(0);
        bytes[coff + 16..coff + 18].copy_from_slice(&(0x60u16).to_le_bytes());
        bytes[optional + 92..optional + 96].copy_from_slice(&(16u32).to_le_bytes());

        let analysis = analyze(&bytes);

        assert!(analysis.is_pe);
        assert_eq!(analysis.number_of_rva_and_sizes, Some(16));
        assert!(analysis.data_directories.is_empty());
        assert!(
            analysis
                .parse_errors
                .contains(&"data_directory_count_exceeds_optional_header".to_owned())
        );
        assert_eq!(analysis.sections[0].name, ".text");
    }

    #[test]
    fn goblin_differential_minimal_pe_sections() {
        let bytes = minimal_pe();
        let analysis = analyze(&bytes);
        let goblin = goblin::pe::PE::parse(&bytes).expect("goblin parses minimal fixture");

        assert_eq!(goblin.sections.len(), analysis.sections.len());
        assert_eq!(goblin.entry, analysis.entrypoint_rva.unwrap());
        assert_eq!(
            u64::from(goblin.sections[0].pointer_to_raw_data),
            analysis.sections[0].start
        );
        assert_eq!(
            u64::from(goblin.sections[0].size_of_raw_data),
            u64::from(analysis.sections[0].raw_size)
        );
    }

    #[test]
    fn parses_png_resource_as_extractable_child() {
        let analysis = analyze(&minimal_pe_with_png_resource());

        assert_eq!(analysis.resources.len(), 1);
        assert_eq!(analysis.resources[0].type_id, Some(10));
        assert_eq!(analysis.resources[0].language_id, Some(1033));
        assert_eq!(analysis.resources[0].mime, Some("image/png"));
        assert!(analysis.resources[0].extracted);
        assert_eq!(analysis.resource_children.len(), 1);
        assert_eq!(analysis.resource_children[0].file_offset, 0x380);
        assert_eq!(
            analysis.resource_children[0].size,
            minimal_png().len() as u64
        );
    }

    #[test]
    fn resource_data_entry_offsets_must_stay_inside_resource_directory() {
        let mut bytes = minimal_pe_with_png_resource();
        let optional = 0x84 + 20;
        let resource_directory = optional + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        bytes[resource_directory + 4..resource_directory + 8]
            .copy_from_slice(&(0x70u32).to_le_bytes());
        let base = 0x300usize;
        let lang_dir = base + 0x40;
        bytes[lang_dir + 20..lang_dir + 24].copy_from_slice(&(0x80u32).to_le_bytes());

        let analysis = analyze(&bytes);

        assert!(analysis.resources.is_empty());
        assert!(analysis.resource_children.is_empty());
        assert!(
            analysis
                .parse_errors
                .contains(&"resource_data_entry_out_of_bounds".to_owned())
        );
    }

    #[test]
    fn padded_resource_extracts_only_validated_child_size() {
        let png = minimal_png();
        let mut payload = png.clone();
        payload.extend_from_slice(b"resource padding");
        let analysis = analyze(&minimal_pe_with_resource(&payload));

        assert_eq!(analysis.resources.len(), 1);
        assert_eq!(
            analysis.resources[0].size,
            fixture_usize_to_u32(payload.len())
        );
        assert_eq!(analysis.resources[0].mime, Some("image/png"));
        assert!(analysis.resources[0].extracted);
        assert_eq!(analysis.resource_children.len(), 1);
        assert_eq!(analysis.resource_children[0].file_offset, 0x380);
        assert_eq!(analysis.resource_children[0].size, png.len() as u64);
    }

    #[test]
    fn parses_zip_pdf_and_pe_resources_as_extractable_children() {
        let fixtures = [
            (minimal_empty_zip(), "application/zip"),
            (minimal_pdf(), "application/pdf"),
            (minimal_embedded_pe(), "application/x-dosexec"),
        ];

        for (payload, expected_mime) in fixtures {
            let analysis = analyze(&minimal_pe_with_resource(&payload));

            assert_eq!(analysis.resources.len(), 1);
            assert_eq!(analysis.resources[0].mime, Some(expected_mime));
            assert!(analysis.resources[0].extracted);
            assert_eq!(analysis.resource_children.len(), 1);
            assert_eq!(analysis.resource_children[0].file_offset, 0x380);
            assert_eq!(analysis.resource_children[0].size, payload.len() as u64);
            assert_eq!(analysis.resource_children[0].mime, expected_mime);
        }
    }

    #[test]
    fn probes_zip_overlay_as_exact_overlay_child() {
        let mut bytes = minimal_pe();
        let overlay_offset = bytes.len() as u64;
        let zip = minimal_empty_zip();
        bytes.extend_from_slice(&zip);

        let analysis = analyze(&bytes);

        assert_eq!(
            analysis.overlay.as_ref().map(|overlay| overlay.offset),
            Some(overlay_offset)
        );
        assert_eq!(analysis.overlay_children.len(), 1);
        let child = &analysis.overlay_children[0];
        assert_eq!(child.source_offset, overlay_offset);
        assert_eq!(child.source_size, zip.len() as u64);
        assert_eq!(child.mime, "application/zip");
        assert_eq!(child.range_status, "exact");
        assert_eq!(child.range_basis, "zip_eocd");
        assert_eq!(child.status, "extracted");
    }

    #[test]
    fn ignores_junk_overlay_without_false_child() {
        let mut bytes = minimal_pe();
        bytes.extend_from_slice(b"junk overlay");

        let analysis = analyze(&bytes);

        assert!(analysis.overlay.is_some());
        assert!(analysis.overlay_children.is_empty());
    }

    #[test]
    fn records_tail_bounded_pdf_overlay_without_extracting() {
        let mut bytes = minimal_pe();
        bytes.extend_from_slice(b"%PDF-1.7\n");

        let analysis = analyze(&bytes);

        assert_eq!(analysis.overlay_children.len(), 1);
        let child = &analysis.overlay_children[0];
        assert_eq!(child.mime, "application/pdf");
        assert_eq!(child.status, "not_extracted");
        assert_eq!(child.range_status, "tail_bounded");
        assert_eq!(child.skip_reason, Some("tail_bounded_range_not_extracted"));
    }

    #[test]
    fn overlay_child_probing_can_be_disabled() {
        let mut bytes = minimal_pe();
        bytes.extend_from_slice(&minimal_empty_zip());

        let analysis = analyze_with_options(
            &bytes,
            PeAnalysisOptions {
                probe_overlay_children: false,
                ..PeAnalysisOptions::default()
            },
        );

        assert!(analysis.overlay.is_some());
        assert!(analysis.overlay_children.is_empty());
    }
}
