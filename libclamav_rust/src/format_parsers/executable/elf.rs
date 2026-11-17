// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! ELF parser and executable-child inventory.
//!
//! ## Scope
//!
//! This parser reads ELF32/ELF64, little-endian and big-endian headers; walks
//! bounded program-header and section-header tables; extracts interpreter,
//! note, dynamic-linking, symbol, import/export, and library metadata needed by
//! future YARA/YARA-X `elf` parity; identifies exact parser-owned embedded
//! children from section ranges; and feeds ELF packer facts into executable
//! unpacker dispatch.
//!
//! ## References
//!
//! Compatibility references are `ClamAV` `elf.c`, `elf.h`, and `upx_elf.c`, plus
//! the generic ELF specification and YARA/YARA-X ELF module behavior:
//!
//! - System V ABI ELF specification:
//!   <https://refspecs.linuxfoundation.org/elf/elf.pdf>
//!
//! ## Layout
//!
//! ```text
//! file offset 0
//! +--------------------------------+
//! | e_ident                        | -> ELF magic, ELF32/ELF64, endian
//! | ELF file header                | -> entrypoint, phoff/shoff,
//! |                                |    phentsize/phnum, shentsize/shnum,
//! |                                |    shstrndx
//! +--------------------------------+
//! | program header table, optional | -> PT_LOAD ranges, PT_INTERP,
//! |                                |    PT_NOTE, PT_DYNAMIC
//! +--------------------------------+
//! | section header table, optional | -> section name offsets, SHT_SYMTAB,
//! |                                |    SHT_DYNSYM, SHT_STRTAB, SHT_DYNAMIC
//! +--------------------------------+
//! | file bytes for sections        | -> names, symbols, notes, embedded-child
//! | and load segments              |    probes, UPX layout evidence
//! +--------------------------------+
//!
//! dynamic-linking view:
//!   PT_DYNAMIC or SHT_DYNAMIC -> DT_NEEDED / DT_STRTAB / DT_SYMTAB
//!                              -> DT_HASH or DT_GNU_HASH for symbol count
//!                              -> DT_REL/DT_RELA/JMPREL relocation metadata
//!
//! linking view:
//!   section header string table -> section names
//!   symbol table + linked string table -> import/export names
//!
//! execution view:
//!   program headers map virtual addresses to file ranges. The parser can
//!   recover dynamic metadata from program headers even when section headers
//!   are stripped.
//! ```
//!
//! ## Parser Outputs
//!
//! Output includes header facts, program and section records, interpreter,
//! notes, libraries, symbols/imports/exports, optional hashes, embedded child
//! byte ranges, UPX facts, and bounded parse diagnostics.
//!
//! ## Bounds And Recovery
//!
//! Header-table counts, string tables, dynamic records, symbols, notes, child
//! candidates, packer marker scans, and parse diagnostics are capped. The parser
//! rejects non-ELF candidates but records recoverable malformed table state for
//! matched ELF inputs.
//!
//! ## Intentional Gaps
//!
//! The parser does not materialize scanner children directly; it returns stable
//! indexes, byte ranges, and derived facts for the ELF file-type handler.

#![forbid(unsafe_code)]

use md5::Md5;
use sha2::Digest;
use tlsh::{BucketKind, ChecksumKind, TlshBuilder, Version};

use crate::format_parsers::embedded::{EmbeddedChildProbe, probe_embedded_child};

use super::common::{
    Endian, ascii_lowercase_cow, bounded_range, checked_range, fixed_name, hex_lower,
    read_c_string, read_string_table_entry,
};
use super::unpacker;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

const SHN_UNDEF: u16 = 0;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
const DT_PLTRELSZ: i64 = 2;
const DT_JMPREL: i64 = 23;
const DT_RUNPATH: i64 = 29;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

const MAX_PROGRAM_HEADERS: usize = 256;
const MAX_SECTION_HEADERS: usize = 4096;
const MAX_DYNAMIC_ENTRIES: usize = 2048;
const MAX_NOTES: usize = 1024;
const MAX_SYMBOLS: usize = 8192;
const MAX_EXTRACTED_CHILDREN: usize = 64;
const MAX_PARSE_ERRORS: usize = 64;
const MAX_ELF_STRING_BYTES: usize = 4096;
const MAX_UPX_ELF_END_L_INFO_SCAN: usize = 1024 * 1024;

fn bounded_u64_count_to_usize(count: u64, limit: usize) -> usize {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    usize::try_from(count.min(limit_u64)).unwrap_or(limit)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElfAnalysisOptions {
    pub(crate) probe_children: bool,
    pub(crate) calculate_import_md5: bool,
    pub(crate) calculate_telfhash: bool,
}

impl Default for ElfAnalysisOptions {
    fn default() -> Self {
        Self {
            probe_children: true,
            calculate_import_md5: false,
            calculate_telfhash: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfAnalysis {
    pub(crate) is_elf: bool,
    pub(crate) is_32bit: bool,
    pub(crate) is_64bit: bool,
    pub(crate) endian: Option<&'static str>,
    pub(crate) elf_type: Option<u16>,
    pub(crate) machine: Option<u16>,
    pub(crate) version: Option<u32>,
    pub(crate) os_abi: Option<u8>,
    pub(crate) abi_version: Option<u8>,
    pub(crate) entrypoint: Option<u64>,
    pub(crate) program_header_offset: Option<u64>,
    pub(crate) section_header_offset: Option<u64>,
    pub(crate) flags: Option<u32>,
    pub(crate) header_size: Option<u16>,
    pub(crate) program_header_entry_size: Option<u16>,
    pub(crate) program_header_count: Option<u16>,
    pub(crate) section_header_entry_size: Option<u16>,
    pub(crate) section_header_count: Option<u16>,
    pub(crate) section_name_string_table_index: Option<u16>,
    pub(crate) segments: Vec<ElfSegment>,
    pub(crate) sections: Vec<ElfSection>,
    pub(crate) interpreter: Option<String>,
    pub(crate) notes: Vec<ElfNote>,
    pub(crate) dynamic: Vec<ElfDynamicEntry>,
    pub(crate) needed_libraries: Vec<String>,
    pub(crate) soname: Option<String>,
    pub(crate) rpath: Option<String>,
    pub(crate) runpath: Option<String>,
    pub(crate) symtab: Vec<ElfSymbol>,
    pub(crate) dynsym: Vec<ElfSymbol>,
    pub(crate) imports: Vec<String>,
    pub(crate) exports: Vec<String>,
    pub(crate) import_md5: Option<String>,
    pub(crate) telfhash: Option<String>,
    pub(crate) relocations: Vec<ElfRelocationTable>,
    pub(crate) extracted_children: Vec<ElfExtractedChild>,
    pub(crate) packers: Vec<ElfPacker>,
    pub(crate) unpacked_children: Vec<ElfUnpackedChild>,
    pub(crate) parse_errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfSegment {
    pub(crate) index: usize,
    pub(crate) segment_type: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) virtual_address: u64,
    pub(crate) physical_address: u64,
    pub(crate) file_size: u64,
    pub(crate) memory_size: u64,
    pub(crate) alignment: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfSection {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) name_offset: u32,
    pub(crate) section_type: u32,
    pub(crate) flags: u64,
    pub(crate) address: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) address_alignment: u64,
    pub(crate) entry_size: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfDynamicEntry {
    pub(crate) index: usize,
    pub(crate) tag: i64,
    pub(crate) value: u64,
    pub(crate) string_value: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfSymbol {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) value: u64,
    pub(crate) size: u64,
    pub(crate) bind: u8,
    pub(crate) symbol_type: u8,
    pub(crate) visibility: u8,
    pub(crate) section_index: u16,
    pub(crate) is_import: bool,
    pub(crate) is_export: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfNote {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) note_type: u32,
    pub(crate) desc_size: u32,
    pub(crate) offset: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfRelocationTable {
    pub(crate) index: usize,
    pub(crate) table_type: &'static str,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) entry_size: u64,
    pub(crate) count: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ElfExtractedChild {
    pub(crate) index: usize,
    pub(crate) source: &'static str,
    pub(crate) source_index: usize,
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
pub(crate) struct ElfPacker {
    pub(crate) name: &'static str,
    pub(crate) confidence: &'static str,
    pub(crate) status: &'static str,
    pub(crate) detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ElfUnpackedChild {
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

#[derive(Clone, Copy, Debug)]
struct ElfHeader {
    class: u8,
    endian: Endian,
    program_header_offset: u64,
    section_header_offset: u64,
    program_header_entry_size: u16,
    program_header_count: u16,
    section_header_entry_size: u16,
    section_header_count: u16,
    section_name_string_table_index: u16,
}

pub(crate) fn analyze_with_options(bytes: &[u8], options: ElfAnalysisOptions) -> ElfAnalysis {
    let mut analysis = ElfAnalysis::default();
    let Some(header) = parse_header(bytes, &mut analysis) else {
        return analysis;
    };
    parse_segments(bytes, header, &mut analysis);
    parse_sections(bytes, header, &mut analysis);
    parse_interpreter(bytes, &mut analysis);
    parse_notes(bytes, &mut analysis);
    parse_dynamic(bytes, header, &mut analysis);
    parse_symbols(bytes, header, &mut analysis);
    derive_imports_exports(&mut analysis);
    if options.calculate_import_md5 || options.calculate_telfhash {
        calculate_elf_hashes(&mut analysis, options);
    }
    if options.probe_children {
        analysis.extracted_children = probe_section_children(bytes, &analysis.sections);
    }
    analysis.packers = detect_packers(bytes, &analysis);
    analysis.unpacked_children = unpacker::unpack_elf(bytes, &analysis);
    analysis
}

#[cfg(test)]
pub(crate) fn analyze(bytes: &[u8]) -> ElfAnalysis {
    analyze_with_options(bytes, ElfAnalysisOptions::default())
}

fn parse_header(bytes: &[u8], analysis: &mut ElfAnalysis) -> Option<ElfHeader> {
    if bytes.len() < 16 || !has_elf_magic(bytes) {
        return None;
    }
    analysis.is_elf = true;
    let ident = &bytes[..16];
    analysis.os_abi = Some(ident[7]);
    analysis.abi_version = Some(ident[8]);
    let class = ident[4];
    let endian = match ident[5] {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        other => {
            push_parse_error(analysis, format!("unsupported_elf_endian_0x{other:02X}"));
            return None;
        }
    };
    analysis.endian = Some(match endian {
        Endian::Little => "little",
        Endian::Big => "big",
    });
    analysis.is_32bit = class == ELFCLASS32;
    analysis.is_64bit = class == ELFCLASS64;
    let header_size = match class {
        ELFCLASS32 => 52usize,
        ELFCLASS64 => 64usize,
        other => {
            push_parse_error(analysis, format!("unsupported_elf_class_0x{other:02X}"));
            return None;
        }
    };
    if bytes.len() < header_size {
        push_parse_error(analysis, "truncated_elf_header".to_owned());
        return None;
    }
    analysis.elf_type = endian.read_u16(bytes, 16);
    analysis.machine = endian.read_u16(bytes, 18);
    analysis.version = endian.read_u32(bytes, 20);
    analysis.entrypoint = if class == ELFCLASS32 {
        endian.read_u32(bytes, 24).map(u64::from)
    } else {
        endian.read_u64(bytes, 24)
    };
    let program_header_offset = if class == ELFCLASS32 {
        endian.read_u32(bytes, 28).map(u64::from)?
    } else {
        endian.read_u64(bytes, 32)?
    };
    let section_header_offset = if class == ELFCLASS32 {
        endian.read_u32(bytes, 32).map(u64::from)?
    } else {
        endian.read_u64(bytes, 40)?
    };
    analysis.program_header_offset = Some(program_header_offset);
    analysis.section_header_offset = Some(section_header_offset);
    analysis.flags = if class == ELFCLASS32 {
        endian.read_u32(bytes, 36)
    } else {
        endian.read_u32(bytes, 48)
    };
    let header_size_offset = if class == ELFCLASS32 { 40 } else { 52 };
    analysis.header_size = endian.read_u16(bytes, header_size_offset);
    analysis.program_header_entry_size = endian.read_u16(bytes, header_size_offset + 2);
    analysis.program_header_count = endian.read_u16(bytes, header_size_offset + 4);
    analysis.section_header_entry_size = endian.read_u16(bytes, header_size_offset + 6);
    analysis.section_header_count = endian.read_u16(bytes, header_size_offset + 8);
    analysis.section_name_string_table_index = endian.read_u16(bytes, header_size_offset + 10);
    Some(ElfHeader {
        class,
        endian,
        program_header_offset,
        section_header_offset,
        program_header_entry_size: analysis.program_header_entry_size?,
        program_header_count: analysis.program_header_count?,
        section_header_entry_size: analysis.section_header_entry_size?,
        section_header_count: analysis.section_header_count?,
        section_name_string_table_index: analysis.section_name_string_table_index?,
    })
}

pub(crate) fn has_elf_magic(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(ELF_MAGIC)
}

fn parse_segments(bytes: &[u8], header: ElfHeader, analysis: &mut ElfAnalysis) {
    if header.program_header_offset == 0 || header.program_header_count == 0 {
        return;
    }
    let min_entry_size = if header.class == ELFCLASS32 { 32 } else { 56 };
    if usize::from(header.program_header_entry_size) < min_entry_size {
        push_parse_error(analysis, "elf_program_header_entry_too_small".to_owned());
        return;
    }
    let count = usize::from(header.program_header_count).min(MAX_PROGRAM_HEADERS);
    if usize::from(header.program_header_count) > MAX_PROGRAM_HEADERS {
        push_parse_error(analysis, "elf_program_headers_omitted".to_owned());
    }
    for index in 0..count {
        let Some(offset) = table_offset(
            header.program_header_offset,
            header.program_header_entry_size,
            index,
        ) else {
            push_parse_error(analysis, "elf_program_header_offset_overflow".to_owned());
            break;
        };
        let Some(entry) = parse_segment(bytes, header, offset, index + 1) else {
            push_parse_error(
                analysis,
                format!("elf_program_header_{}_truncated", index + 1),
            );
            break;
        };
        analysis.segments.push(entry);
    }
}

fn parse_segment(
    bytes: &[u8],
    header: ElfHeader,
    offset: usize,
    index: usize,
) -> Option<ElfSegment> {
    let endian = header.endian;
    if header.class == ELFCLASS32 {
        Some(ElfSegment {
            index,
            segment_type: endian.read_u32(bytes, offset)?,
            offset: endian
                .read_u32(bytes, offset.checked_add(4)?)
                .map(u64::from)?,
            virtual_address: endian
                .read_u32(bytes, offset.checked_add(8)?)
                .map(u64::from)?,
            physical_address: endian
                .read_u32(bytes, offset.checked_add(12)?)
                .map(u64::from)?,
            file_size: endian
                .read_u32(bytes, offset.checked_add(16)?)
                .map(u64::from)?,
            memory_size: endian
                .read_u32(bytes, offset.checked_add(20)?)
                .map(u64::from)?,
            flags: endian.read_u32(bytes, offset.checked_add(24)?)?,
            alignment: endian
                .read_u32(bytes, offset.checked_add(28)?)
                .map(u64::from)?,
        })
    } else {
        Some(ElfSegment {
            index,
            segment_type: endian.read_u32(bytes, offset)?,
            flags: endian.read_u32(bytes, offset.checked_add(4)?)?,
            offset: endian.read_u64(bytes, offset.checked_add(8)?)?,
            virtual_address: endian.read_u64(bytes, offset.checked_add(16)?)?,
            physical_address: endian.read_u64(bytes, offset.checked_add(24)?)?,
            file_size: endian.read_u64(bytes, offset.checked_add(32)?)?,
            memory_size: endian.read_u64(bytes, offset.checked_add(40)?)?,
            alignment: endian.read_u64(bytes, offset.checked_add(48)?)?,
        })
    }
}

fn parse_sections(bytes: &[u8], header: ElfHeader, analysis: &mut ElfAnalysis) {
    if header.section_header_offset == 0 || header.section_header_count == 0 {
        return;
    }
    let min_entry_size = if header.class == ELFCLASS32 { 40 } else { 64 };
    if usize::from(header.section_header_entry_size) < min_entry_size {
        push_parse_error(analysis, "elf_section_header_entry_too_small".to_owned());
        return;
    }
    let count = usize::from(header.section_header_count).min(MAX_SECTION_HEADERS);
    if usize::from(header.section_header_count) > MAX_SECTION_HEADERS {
        push_parse_error(analysis, "elf_section_headers_omitted".to_owned());
    }
    for index in 0..count {
        let Some(offset) = table_offset(
            header.section_header_offset,
            header.section_header_entry_size,
            index,
        ) else {
            push_parse_error(analysis, "elf_section_header_offset_overflow".to_owned());
            break;
        };
        let Some(section) = parse_section(bytes, header, offset, index + 1) else {
            push_parse_error(
                analysis,
                format!("elf_section_header_{}_truncated", index + 1),
            );
            break;
        };
        analysis.sections.push(section);
    }
    populate_section_names(bytes, header, analysis);
}

fn parse_section(
    bytes: &[u8],
    header: ElfHeader,
    offset: usize,
    index: usize,
) -> Option<ElfSection> {
    let endian = header.endian;
    if header.class == ELFCLASS32 {
        Some(ElfSection {
            index,
            name_offset: endian.read_u32(bytes, offset)?,
            section_type: endian.read_u32(bytes, offset.checked_add(4)?)?,
            flags: endian
                .read_u32(bytes, offset.checked_add(8)?)
                .map(u64::from)?,
            address: endian
                .read_u32(bytes, offset.checked_add(12)?)
                .map(u64::from)?,
            offset: endian
                .read_u32(bytes, offset.checked_add(16)?)
                .map(u64::from)?,
            size: endian
                .read_u32(bytes, offset.checked_add(20)?)
                .map(u64::from)?,
            link: endian.read_u32(bytes, offset.checked_add(24)?)?,
            info: endian.read_u32(bytes, offset.checked_add(28)?)?,
            address_alignment: endian
                .read_u32(bytes, offset.checked_add(32)?)
                .map(u64::from)?,
            entry_size: endian
                .read_u32(bytes, offset.checked_add(36)?)
                .map(u64::from)?,
            name: String::new(),
        })
    } else {
        Some(ElfSection {
            index,
            name_offset: endian.read_u32(bytes, offset)?,
            section_type: endian.read_u32(bytes, offset.checked_add(4)?)?,
            flags: endian.read_u64(bytes, offset.checked_add(8)?)?,
            address: endian.read_u64(bytes, offset.checked_add(16)?)?,
            offset: endian.read_u64(bytes, offset.checked_add(24)?)?,
            size: endian.read_u64(bytes, offset.checked_add(32)?)?,
            link: endian.read_u32(bytes, offset.checked_add(40)?)?,
            info: endian.read_u32(bytes, offset.checked_add(44)?)?,
            address_alignment: endian.read_u64(bytes, offset.checked_add(48)?)?,
            entry_size: endian.read_u64(bytes, offset.checked_add(56)?)?,
            name: String::new(),
        })
    }
}

fn populate_section_names(bytes: &[u8], header: ElfHeader, analysis: &mut ElfAnalysis) {
    let shstr_index = usize::from(header.section_name_string_table_index);
    if shstr_index == 0 || shstr_index >= analysis.sections.len() {
        return;
    }
    let shstr = &analysis.sections[shstr_index];
    let Some(range) = checked_range(shstr.offset, shstr.size, bytes.len()) else {
        push_parse_error(analysis, "elf_shstrtab_out_of_bounds".to_owned());
        return;
    };
    let table = &bytes[range];
    for section in &mut analysis.sections {
        section.name = read_string_table_entry(table, section.name_offset, MAX_ELF_STRING_BYTES)
            .unwrap_or_default();
    }
}

fn parse_interpreter(bytes: &[u8], analysis: &mut ElfAnalysis) {
    let Some(segment) = analysis
        .segments
        .iter()
        .find(|segment| segment.segment_type == PT_INTERP)
    else {
        return;
    };
    let Some(range) = checked_range(segment.offset, segment.file_size, bytes.len()) else {
        push_parse_error(analysis, "elf_interpreter_out_of_bounds".to_owned());
        return;
    };
    analysis.interpreter = read_c_string(bytes, range.start, range.len().min(MAX_ELF_STRING_BYTES));
}

fn parse_notes(bytes: &[u8], analysis: &mut ElfAnalysis) {
    let endian = if analysis.endian == Some("big") {
        Endian::Big
    } else {
        Endian::Little
    };
    let mut index = 1usize;
    for segment_index in 0..analysis.segments.len() {
        let Some(range) = ({
            let segment = &analysis.segments[segment_index];
            (segment.segment_type == PT_NOTE)
                .then(|| checked_range(segment.offset, segment.file_size, bytes.len()))
                .flatten()
        }) else {
            continue;
        };
        let mut offset = range.start;
        while offset.checked_add(12).is_some_and(|end| end <= range.end) {
            if analysis.notes.len() >= MAX_NOTES {
                push_parse_error(analysis, "elf_notes_omitted".to_owned());
                return;
            }
            let Some(name_size) = endian.read_u32(bytes, offset) else {
                break;
            };
            let Some(desc_size) = offset
                .checked_add(4)
                .and_then(|offset| endian.read_u32(bytes, offset))
            else {
                break;
            };
            let Some(note_type) = offset
                .checked_add(8)
                .and_then(|offset| endian.read_u32(bytes, offset))
            else {
                break;
            };
            let Some(name_start) = offset.checked_add(12) else {
                break;
            };
            let Some(name_end) = align_checked(name_start, u64::from(name_size), 4) else {
                break;
            };
            let Some(desc_end) = align_checked(name_end, u64::from(desc_size), 4) else {
                break;
            };
            if desc_end > range.end {
                break;
            }
            let Some(name_end_unaligned) = name_start.checked_add(name_size as usize) else {
                break;
            };
            let name = bytes
                .get(name_start..name_end_unaligned)
                .map(fixed_name)
                .unwrap_or_default();
            analysis.notes.push(ElfNote {
                index,
                name,
                note_type,
                desc_size,
                offset: offset as u64,
            });
            index += 1;
            offset = desc_end;
        }
    }
}

fn parse_dynamic(bytes: &[u8], header: ElfHeader, analysis: &mut ElfAnalysis) {
    for segment_index in 0..analysis.segments.len() {
        let Some((index, offset, file_size)) = ({
            let segment = &analysis.segments[segment_index];
            (segment.segment_type == PT_DYNAMIC).then_some((
                segment.index,
                segment.offset,
                segment.file_size,
            ))
        }) else {
            continue;
        };
        parse_dynamic_range(
            bytes,
            header,
            analysis,
            offset,
            file_size,
            None,
            &format!("elf_dynamic_segment_{index}"),
        );
    }

    for section_index in 0..analysis.sections.len() {
        let Some((index, offset, size, link)) = ({
            let section = &analysis.sections[section_index];
            (section.section_type == SHT_DYNAMIC).then_some((
                section.index,
                section.offset,
                section.size,
                section.link,
            ))
        }) else {
            continue;
        };
        let dynstr_range = link
            .try_into()
            .ok()
            .and_then(|index: usize| section_range(&analysis.sections, index, bytes.len()));
        parse_dynamic_range(
            bytes,
            header,
            analysis,
            offset,
            size,
            dynstr_range,
            &format!("elf_dynamic_section_{index}"),
        );
    }
}

fn parse_dynamic_range(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    offset: u64,
    size: u64,
    linked_dynstr_range: Option<std::ops::Range<usize>>,
    source_name: &str,
) {
    let entry_size = if header.class == ELFCLASS32 {
        8u64
    } else {
        16u64
    };
    let Some(range) = checked_range(offset, size, bytes.len()) else {
        push_parse_error(analysis, format!("{source_name}_out_of_bounds"));
        return;
    };
    let declared_count = range.len() as u64 / entry_size;
    let count = bounded_u64_count_to_usize(declared_count, MAX_DYNAMIC_ENTRIES);
    if declared_count > MAX_DYNAMIC_ENTRIES as u64 {
        push_parse_error(analysis, format!("{source_name}_entries_omitted"));
    }

    let mut raw_entries = Vec::with_capacity(count);
    for index in 0..count {
        let Some(entry_offset) = table_record_offset(range.start, entry_size, index) else {
            push_parse_error(analysis, format!("{source_name}_entry_offset_overflow"));
            break;
        };
        let (tag, value) = if header.class == ELFCLASS32 {
            let Some(tag) = header.endian.read_i32(bytes, entry_offset).map(i64::from) else {
                break;
            };
            let Some(value) = header
                .endian
                .read_u32(bytes, entry_offset + 4)
                .map(u64::from)
            else {
                break;
            };
            (tag, value)
        } else {
            let Some(tag) = header.endian.read_i64(bytes, entry_offset) else {
                break;
            };
            let Some(value) = header.endian.read_u64(bytes, entry_offset + 8) else {
                break;
            };
            (tag, value)
        };
        if tag == DT_NULL {
            break;
        }
        raw_entries.push((tag, value));
    }

    let dynstr_range =
        linked_dynstr_range.or_else(|| dynamic_string_range(bytes, analysis, &raw_entries));
    let dynstr_table = dynstr_range
        .as_ref()
        .map(|range| &bytes[range.start..range.end]);
    let mut dynamic_entries = Vec::with_capacity(raw_entries.len());
    let mut needed_libraries = Vec::new();
    for (tag, value) in &raw_entries {
        let string_value = if matches!(*tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH) {
            dynstr_table
                .and_then(|table| {
                    u32::try_from(*value).ok().and_then(|offset| {
                        read_string_table_entry(table, offset, MAX_ELF_STRING_BYTES)
                    })
                })
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        match (*tag, string_value.as_ref()) {
            (DT_NEEDED, Some(value)) => needed_libraries.push(value.clone()),
            (DT_SONAME, Some(value)) => analysis.soname = Some(value.clone()),
            (DT_RPATH, Some(value)) => analysis.rpath = Some(value.clone()),
            (DT_RUNPATH, Some(value)) => analysis.runpath = Some(value.clone()),
            _ => {}
        }
        dynamic_entries.push(ElfDynamicEntry {
            index: 0,
            tag: *tag,
            value: *value,
            string_value,
        });
    }
    append_unique_strings(&mut analysis.needed_libraries, needed_libraries);
    append_unique_dynamic(&mut analysis.dynamic, dynamic_entries);

    parse_dynamic_symbols(bytes, header, analysis, &raw_entries, dynstr_table);
    record_dynamic_relocations(bytes, header, analysis, &raw_entries);
}

fn parse_symbols(bytes: &[u8], header: ElfHeader, analysis: &mut ElfAnalysis) {
    for section_index in 0..analysis.sections.len() {
        let Some((index, section_type, offset, size, section_entry_size, link)) = ({
            let section = &analysis.sections[section_index];
            matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM).then_some((
                section.index,
                section.section_type,
                section.offset,
                section.size,
                section.entry_size,
                section.link,
            ))
        }) else {
            continue;
        };
        let min_entry_size = if header.class == ELFCLASS32 { 16 } else { 24 };
        let entry_size = section_entry_size.max(min_entry_size);
        if entry_size == 0 {
            continue;
        }
        let Some(range) = checked_range(offset, size, bytes.len()) else {
            push_parse_error(
                analysis,
                format!("elf_symbol_section_{index}_out_of_bounds"),
            );
            continue;
        };
        let string_table = link
            .try_into()
            .ok()
            .and_then(|index: usize| section_range(&analysis.sections, index, bytes.len()))
            .map(|range| &bytes[range]);
        let declared_count = range.len() as u64 / entry_size;
        let symbols = parse_symbol_table(
            bytes,
            header,
            analysis,
            range.start as u64,
            declared_count,
            entry_size,
            string_table,
            &format!("elf_symbol_section_{index}"),
        );
        if section_type == SHT_DYNSYM {
            append_unique_symbols(&mut analysis.dynsym, symbols);
        } else {
            append_unique_symbols(&mut analysis.symtab, symbols);
        }
    }
}

fn parse_dynamic_symbols(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
    dynstr_table: Option<&[u8]>,
) {
    let Some(symtab_vaddr) = dynamic_value(entries, DT_SYMTAB) else {
        return;
    };
    let Some(symtab_offset) = vaddr_to_file_offset(analysis, symtab_vaddr) else {
        push_parse_error(analysis, "elf_dynamic_symtab_unmapped".to_owned());
        return;
    };
    let min_entry_size = if header.class == ELFCLASS32 { 16 } else { 24 };
    let entry_size = dynamic_value(entries, DT_SYMENT)
        .filter(|value| *value >= min_entry_size)
        .unwrap_or(min_entry_size);
    let Some(symbol_count) = dynamic_symbol_count(bytes, header, analysis, entries) else {
        push_parse_error(analysis, "elf_dynamic_symbol_count_unavailable".to_owned());
        return;
    };
    let Some(dynstr_table) = dynstr_table else {
        push_parse_error(analysis, "elf_dynamic_string_table_unavailable".to_owned());
        return;
    };
    let symbols = parse_symbol_table(
        bytes,
        header,
        analysis,
        symtab_offset,
        symbol_count,
        entry_size,
        Some(dynstr_table),
        "elf_dynamic_symtab",
    );
    append_unique_symbols(&mut analysis.dynsym, symbols);
}

#[allow(clippy::too_many_arguments)]
fn parse_symbol_table(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    offset: u64,
    declared_count: u64,
    entry_size: u64,
    string_table: Option<&[u8]>,
    source_name: &str,
) -> Vec<ElfSymbol> {
    let Some(total_size) = entry_size.checked_mul(declared_count) else {
        push_parse_error(analysis, format!("{source_name}_size_overflow"));
        return Vec::new();
    };
    let Some(range) = bounded_range(offset, total_size, bytes.len()) else {
        push_parse_error(analysis, format!("{source_name}_out_of_bounds"));
        return Vec::new();
    };
    let available_count = range.len() as u64 / entry_size;
    let count = bounded_u64_count_to_usize(available_count, MAX_SYMBOLS);
    if available_count < declared_count {
        push_parse_error(analysis, format!("{source_name}_truncated"));
    }
    if declared_count > MAX_SYMBOLS as u64 {
        push_parse_error(analysis, format!("{source_name}_symbols_omitted"));
    }
    let mut symbols = Vec::with_capacity(count);
    for index in 0..count {
        let Some(symbol_offset) = table_record_offset(range.start, entry_size, index) else {
            push_parse_error(analysis, format!("{source_name}_symbol_offset_overflow"));
            break;
        };
        let symbol = if header.class == ELFCLASS32 {
            parse_symbol32(bytes, header.endian, symbol_offset, index, string_table)
        } else {
            parse_symbol64(bytes, header.endian, symbol_offset, index, string_table)
        };
        if let Some(symbol) = symbol {
            symbols.push(symbol);
        } else {
            push_parse_error(
                analysis,
                format!("{source_name}_symbol_{}_truncated", index + 1),
            );
            break;
        }
    }
    symbols
}

fn dynamic_string_range(
    bytes: &[u8],
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
) -> Option<std::ops::Range<usize>> {
    let strtab_vaddr = dynamic_value(entries, DT_STRTAB)?;
    let strtab_size = dynamic_value(entries, DT_STRSZ)?;
    let Some(strtab_offset) = vaddr_to_file_offset(analysis, strtab_vaddr) else {
        push_parse_error(analysis, "elf_dynamic_strtab_unmapped".to_owned());
        return None;
    };
    let range = checked_range(strtab_offset, strtab_size, bytes.len());
    if range.is_none() {
        push_parse_error(analysis, "elf_dynamic_strtab_out_of_bounds".to_owned());
    }
    range
}

fn dynamic_symbol_count(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
) -> Option<u64> {
    dynamic_sysv_symbol_count(bytes, header, analysis, entries)
        .or_else(|| dynamic_gnu_symbol_count(bytes, header, analysis, entries))
}

fn dynamic_sysv_symbol_count(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
) -> Option<u64> {
    let hash_vaddr = dynamic_value(entries, DT_HASH)?;
    let Some(hash_offset) = vaddr_to_file_offset(analysis, hash_vaddr) else {
        push_parse_error(analysis, "elf_dynamic_hash_unmapped".to_owned());
        return None;
    };
    let offset = usize::try_from(hash_offset).ok()?;
    let _bucket_count = header.endian.read_u32(bytes, offset)?;
    header
        .endian
        .read_u32(bytes, offset.checked_add(4)?)
        .map(u64::from)
}

fn dynamic_gnu_symbol_count(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
) -> Option<u64> {
    let hash_vaddr = dynamic_value(entries, DT_GNU_HASH)?;
    let Some(hash_offset) = vaddr_to_file_offset(analysis, hash_vaddr) else {
        push_parse_error(analysis, "elf_dynamic_gnu_hash_unmapped".to_owned());
        return None;
    };
    let offset = usize::try_from(hash_offset).ok()?;
    let Some(bucket_count) = header.endian.read_u32(bytes, offset).map(usize::try_from) else {
        push_parse_error(analysis, "elf_dynamic_gnu_hash_header_truncated".to_owned());
        return None;
    };
    let Ok(bucket_count) = bucket_count else {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bucket_count_invalid".to_owned(),
        );
        return None;
    };
    if bucket_count > MAX_SYMBOLS {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bucket_count_exceeded".to_owned(),
        );
        return None;
    }
    let Some(symbol_offset) = offset
        .checked_add(4)
        .and_then(|offset| header.endian.read_u32(bytes, offset))
        .map(u64::from)
    else {
        push_parse_error(analysis, "elf_dynamic_gnu_hash_header_truncated".to_owned());
        return None;
    };
    let Some(bloom_size) = header
        .endian
        .read_u32(bytes, offset.checked_add(8)?)
        .and_then(|value| usize::try_from(value).ok())
    else {
        push_parse_error(analysis, "elf_dynamic_gnu_hash_header_truncated".to_owned());
        return None;
    };
    if bloom_size > MAX_SYMBOLS {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bloom_size_exceeded".to_owned(),
        );
        return None;
    }
    let bloom_word_size = if header.class == ELFCLASS32 {
        4usize
    } else {
        8usize
    };
    let Some(bloom_bytes) = bloom_size.checked_mul(bloom_word_size) else {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bloom_size_overflow".to_owned(),
        );
        return None;
    };
    let Some(bucket_offset) = offset
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_bytes))
    else {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bucket_offset_overflow".to_owned(),
        );
        return None;
    };
    let Some(bucket_bytes) = bucket_count.checked_mul(4) else {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_bucket_size_overflow".to_owned(),
        );
        return None;
    };
    let Some(chain_offset) = bucket_offset.checked_add(bucket_bytes) else {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_chain_offset_overflow".to_owned(),
        );
        return None;
    };
    if bucket_offset
        .checked_add(bucket_bytes)
        .is_none_or(|end| end > bytes.len())
    {
        push_parse_error(
            analysis,
            "elf_dynamic_gnu_hash_buckets_truncated".to_owned(),
        );
        return None;
    }

    let mut max_symbol = symbol_offset;
    let mut saw_bucket = false;
    let mut visited_chains = std::collections::HashSet::new();
    let mut visited_chain_count = 0usize;
    for bucket_index in 0..bucket_count {
        let Some(bucket_entry_offset) = bucket_offset.checked_add(bucket_index.saturating_mul(4))
        else {
            push_parse_error(
                analysis,
                "elf_dynamic_gnu_hash_bucket_offset_overflow".to_owned(),
            );
            return None;
        };
        let Some(bucket_symbol) = header
            .endian
            .read_u32(bytes, bucket_entry_offset)
            .map(u64::from)
        else {
            push_parse_error(analysis, "elf_dynamic_gnu_hash_bucket_truncated".to_owned());
            return None;
        };
        if bucket_symbol == 0 {
            continue;
        }
        if bucket_symbol < symbol_offset {
            push_parse_error(
                analysis,
                "elf_dynamic_gnu_hash_bucket_before_symoffset".to_owned(),
            );
            continue;
        }
        saw_bucket = true;
        let mut chain_index = bucket_symbol - symbol_offset;
        let mut chain_terminated = false;
        for _ in 0..MAX_SYMBOLS {
            if !visited_chains.insert(chain_index) {
                chain_terminated = true;
                break;
            }
            visited_chain_count = visited_chain_count.saturating_add(1);
            if visited_chain_count > MAX_SYMBOLS {
                push_parse_error(analysis, "elf_dynamic_gnu_hash_chains_omitted".to_owned());
                return None;
            }
            let Some(chain_byte_offset) = chain_index
                .checked_mul(4)
                .and_then(|value| usize::try_from(value).ok())
            else {
                push_parse_error(
                    analysis,
                    "elf_dynamic_gnu_hash_chain_offset_overflow".to_owned(),
                );
                return None;
            };
            let Some(chain_entry_offset) = chain_offset.checked_add(chain_byte_offset) else {
                push_parse_error(
                    analysis,
                    "elf_dynamic_gnu_hash_chain_offset_overflow".to_owned(),
                );
                return None;
            };
            let Some(chain) = header.endian.read_u32(bytes, chain_entry_offset) else {
                push_parse_error(analysis, "elf_dynamic_gnu_hash_chains_truncated".to_owned());
                return None;
            };
            let Some(symbol_index) = symbol_offset.checked_add(chain_index) else {
                push_parse_error(
                    analysis,
                    "elf_dynamic_gnu_hash_symbol_index_overflow".to_owned(),
                );
                return None;
            };
            max_symbol = max_symbol.max(symbol_index);
            if chain & 1 != 0 {
                chain_terminated = true;
                break;
            }
            let Some(next_index) = chain_index.checked_add(1) else {
                push_parse_error(
                    analysis,
                    "elf_dynamic_gnu_hash_chain_index_overflow".to_owned(),
                );
                return None;
            };
            chain_index = next_index;
        }
        if !chain_terminated {
            push_parse_error(analysis, "elf_dynamic_gnu_hash_chains_omitted".to_owned());
            return None;
        }
    }
    Some(if saw_bucket {
        let Some(symbol_count) = max_symbol.checked_add(1) else {
            push_parse_error(
                analysis,
                "elf_dynamic_gnu_hash_symbol_index_overflow".to_owned(),
            );
            return None;
        };
        symbol_count
    } else {
        symbol_offset
    })
}

fn record_dynamic_relocations(
    bytes: &[u8],
    header: ElfHeader,
    analysis: &mut ElfAnalysis,
    entries: &[(i64, u64)],
) {
    let rel_entry_size = dynamic_value(entries, DT_RELENT)
        .unwrap_or(if header.class == ELFCLASS32 { 8 } else { 16 });
    let rel_addend_entry_size = dynamic_value(entries, DT_RELAENT)
        .unwrap_or(if header.class == ELFCLASS32 { 12 } else { 24 });
    if let (Some(vaddr), Some(size)) = (
        dynamic_value(entries, DT_REL),
        dynamic_value(entries, DT_RELSZ),
    ) {
        record_relocation_table(bytes, analysis, "rel", vaddr, size, rel_entry_size);
    }
    if let (Some(vaddr), Some(size)) = (
        dynamic_value(entries, DT_RELA),
        dynamic_value(entries, DT_RELASZ),
    ) {
        record_relocation_table(bytes, analysis, "rela", vaddr, size, rel_addend_entry_size);
    }
    if let (Some(vaddr), Some(size)) = (
        dynamic_value(entries, DT_JMPREL),
        dynamic_value(entries, DT_PLTRELSZ),
    ) {
        let is_rela = dynamic_value(entries, DT_PLTREL) == Some(DT_RELA as u64);
        record_relocation_table(
            bytes,
            analysis,
            if is_rela { "plt_rela" } else { "plt_rel" },
            vaddr,
            size,
            if is_rela {
                rel_addend_entry_size
            } else {
                rel_entry_size
            },
        );
    }
}

fn record_relocation_table(
    bytes: &[u8],
    analysis: &mut ElfAnalysis,
    table_type: &'static str,
    vaddr: u64,
    size: u64,
    entry_size: u64,
) {
    if size == 0 || entry_size == 0 {
        return;
    }
    let Some(offset) = vaddr_to_file_offset(analysis, vaddr) else {
        push_parse_error(analysis, format!("elf_{table_type}_relocations_unmapped"));
        return;
    };
    let Some(range) = bounded_range(offset, size, bytes.len()) else {
        push_parse_error(
            analysis,
            format!("elf_{table_type}_relocations_out_of_bounds"),
        );
        return;
    };
    let count = range.len() as u64 / entry_size;
    if range.len() as u64 != size {
        push_parse_error(analysis, format!("elf_{table_type}_relocations_truncated"));
    }
    if analysis
        .relocations
        .iter()
        .any(|table| table.table_type == table_type && table.offset == offset && table.size == size)
    {
        return;
    }
    analysis.relocations.push(ElfRelocationTable {
        index: analysis.relocations.len() + 1,
        table_type,
        offset,
        size,
        entry_size,
        count: usize::try_from(count).expect("relocation count is bounded by byte slice length"),
    });
}

fn dynamic_value(entries: &[(i64, u64)], tag: i64) -> Option<u64> {
    entries
        .iter()
        .find_map(|(entry_tag, value)| (*entry_tag == tag).then_some(*value))
}

fn vaddr_to_file_offset(analysis: &ElfAnalysis, vaddr: u64) -> Option<u64> {
    for segment in &analysis.segments {
        if segment.segment_type != PT_LOAD || segment.file_size == 0 {
            continue;
        }
        let Some(end) = segment.virtual_address.checked_add(segment.file_size) else {
            continue;
        };
        if vaddr >= segment.virtual_address && vaddr < end {
            return segment
                .offset
                .checked_add(vaddr.checked_sub(segment.virtual_address)?);
        }
    }
    None
}

fn append_unique_dynamic(target: &mut Vec<ElfDynamicEntry>, entries: Vec<ElfDynamicEntry>) {
    if entries.is_empty() {
        return;
    }
    if target.is_empty() && entries.len() == 1 {
        for mut entry in entries {
            entry.index = 1;
            target.push(entry);
        }
        return;
    }

    let accepted = {
        let mut seen =
            std::collections::HashSet::with_capacity(target.len().saturating_add(entries.len()));
        seen.extend(target.iter().map(ElfDynamicKey::from));
        entries
            .iter()
            .map(|entry| seen.insert(ElfDynamicKey::from(entry)))
            .collect::<Vec<_>>()
    };
    for (mut entry, keep) in entries.into_iter().zip(accepted) {
        if !keep {
            continue;
        }
        entry.index = target.len() + 1;
        target.push(entry);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ElfDynamicKey<'a> {
    tag: i64,
    value: u64,
    string_value: Option<&'a str>,
}

impl<'a> From<&'a ElfDynamicEntry> for ElfDynamicKey<'a> {
    fn from(entry: &'a ElfDynamicEntry) -> Self {
        Self {
            tag: entry.tag,
            value: entry.value,
            string_value: entry.string_value.as_deref(),
        }
    }
}

fn append_unique_symbols(target: &mut Vec<ElfSymbol>, symbols: Vec<ElfSymbol>) {
    if symbols.is_empty() {
        return;
    }
    if target.is_empty() && symbols.len() == 1 {
        for mut symbol in symbols {
            symbol.index = 1;
            target.push(symbol);
        }
        return;
    }

    let accepted = {
        let mut seen =
            std::collections::HashSet::with_capacity(target.len().saturating_add(symbols.len()));
        seen.extend(target.iter().map(ElfSymbolKey::from));
        symbols
            .iter()
            .map(|symbol| seen.insert(ElfSymbolKey::from(symbol)))
            .collect::<Vec<_>>()
    };
    for (mut symbol, keep) in symbols.into_iter().zip(accepted) {
        if !keep {
            continue;
        }
        symbol.index = target.len() + 1;
        target.push(symbol);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ElfSymbolKey<'a> {
    value: u64,
    size: u64,
    bind: u8,
    symbol_type: u8,
    section_index: u16,
    name: &'a str,
}

impl<'a> From<&'a ElfSymbol> for ElfSymbolKey<'a> {
    fn from(symbol: &'a ElfSymbol) -> Self {
        Self {
            value: symbol.value,
            size: symbol.size,
            bind: symbol.bind,
            symbol_type: symbol.symbol_type,
            section_index: symbol.section_index,
            name: symbol.name.as_str(),
        }
    }
}

fn append_unique_strings(target: &mut Vec<String>, values: Vec<String>) {
    if values.is_empty() {
        return;
    }
    if values.len() == 1 {
        for value in values {
            if !target.iter().any(|existing| existing == &value) {
                target.push(value);
            }
        }
        return;
    }

    let accepted = {
        let mut seen =
            std::collections::HashSet::with_capacity(target.len().saturating_add(values.len()));
        seen.extend(target.iter().map(String::as_str));
        values
            .iter()
            .map(|value| seen.insert(value.as_str()))
            .collect::<Vec<_>>()
    };
    for (value, keep) in values.into_iter().zip(accepted) {
        if keep {
            target.push(value);
        }
    }
}

fn parse_symbol32(
    bytes: &[u8],
    endian: Endian,
    offset: usize,
    index: usize,
    string_table: Option<&[u8]>,
) -> Option<ElfSymbol> {
    let name_offset = endian.read_u32(bytes, offset)?;
    let value = endian
        .read_u32(bytes, offset.checked_add(4)?)
        .map(u64::from)?;
    let size = endian
        .read_u32(bytes, offset.checked_add(8)?)
        .map(u64::from)?;
    let info = *bytes.get(offset.checked_add(12)?)?;
    let other = *bytes.get(offset.checked_add(13)?)?;
    let section_index = endian.read_u16(bytes, offset.checked_add(14)?)?;
    Some(symbol_from_parts(
        index + 1,
        name_offset,
        value,
        size,
        info,
        other,
        section_index,
        string_table,
    ))
}

fn parse_symbol64(
    bytes: &[u8],
    endian: Endian,
    offset: usize,
    index: usize,
    string_table: Option<&[u8]>,
) -> Option<ElfSymbol> {
    let name_offset = endian.read_u32(bytes, offset)?;
    let info = *bytes.get(offset.checked_add(4)?)?;
    let other = *bytes.get(offset.checked_add(5)?)?;
    let section_index = endian.read_u16(bytes, offset.checked_add(6)?)?;
    let value = endian.read_u64(bytes, offset.checked_add(8)?)?;
    let size = endian.read_u64(bytes, offset.checked_add(16)?)?;
    Some(symbol_from_parts(
        index + 1,
        name_offset,
        value,
        size,
        info,
        other,
        section_index,
        string_table,
    ))
}

fn table_record_offset(start: usize, entry_size: u64, index: usize) -> Option<usize> {
    usize::try_from(entry_size)
        .ok()
        .and_then(|entry_size| index.checked_mul(entry_size))
        .and_then(|relative| start.checked_add(relative))
}

#[allow(clippy::too_many_arguments)]
fn symbol_from_parts(
    index: usize,
    name_offset: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    section_index: u16,
    string_table: Option<&[u8]>,
) -> ElfSymbol {
    let name = string_table
        .and_then(|table| read_string_table_entry(table, name_offset, MAX_ELF_STRING_BYTES))
        .unwrap_or_default();
    let bind = info >> 4;
    let symbol_type = info & 0x0f;
    let visibility = other & 0x03;
    ElfSymbol {
        index,
        name,
        value,
        size,
        bind,
        symbol_type,
        visibility,
        section_index,
        is_import: section_index == SHN_UNDEF && bind != 0,
        is_export: section_index != SHN_UNDEF && bind != 0 && visibility != 2,
    }
}

fn derive_imports_exports(analysis: &mut ElfAnalysis) {
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for symbol in analysis.dynsym.iter().chain(analysis.symtab.iter()) {
        if symbol.name.is_empty() {
            continue;
        }
        if symbol.is_import {
            imports.push(symbol.name.as_str());
        } else if symbol.is_export {
            exports.push(symbol.name.as_str());
        }
    }
    imports.sort_unstable();
    imports.dedup();
    exports.sort_unstable();
    exports.dedup();
    let imports = imports.into_iter().map(str::to_owned).collect();
    let exports = exports.into_iter().map(str::to_owned).collect();
    analysis.imports = imports;
    analysis.exports = exports;
}

fn calculate_elf_hashes(analysis: &mut ElfAnalysis, options: ElfAnalysisOptions) {
    if options.calculate_import_md5 {
        analysis.import_md5 = elf_import_md5(analysis);
    }
    if options.calculate_telfhash {
        analysis.telfhash = elf_telfhash(analysis);
    }
}

fn elf_import_md5(analysis: &ElfAnalysis) -> Option<String> {
    let symbols = if analysis.dynsym.is_empty() {
        &analysis.symtab
    } else {
        &analysis.dynsym
    };
    let mut imports = Vec::new();
    for symbol in symbols {
        if symbol.is_import && !symbol.name.is_empty() {
            imports.push(ascii_lowercase_cow(&symbol.name));
        }
    }
    imports.sort_unstable();
    imports.dedup();
    hash_md5_joined(&imports)
}

fn elf_telfhash(analysis: &ElfAnalysis) -> Option<String> {
    let symbols = if analysis.dynsym.is_empty() {
        &analysis.symtab
    } else {
        &analysis.dynsym
    };
    let mut names = Vec::new();
    for symbol in symbols {
        if symbol.bind == 1
            && symbol.symbol_type == 2
            && symbol.visibility == 0
            && !symbol.name.is_empty()
            && let Some(name) = normalize_telfhash_symbol(&symbol.name)
        {
            names.push(name);
        }
    }
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return None;
    }
    if joined_len(&names) < 50 {
        return None;
    }
    let mut builder = TlshBuilder::new(
        BucketKind::Bucket128,
        ChecksumKind::OneByte,
        Version::Version4,
    );
    update_tlsh_joined(&mut builder, &names);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.build()))
        .ok()
        .and_then(Result::ok)
        .map(|hash| hash.hash())
}

fn hash_md5_joined<T: AsRef<str>>(values: &[T]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    let mut hasher = Md5::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            hasher.update(b",");
        }
        hasher.update(value.as_ref().as_bytes());
    }
    let digest = hasher.finalize();
    Some(hex_lower(&digest))
}

fn joined_len<T: AsRef<str>>(values: &[T]) -> usize {
    values
        .iter()
        .map(|value| value.as_ref().len())
        .sum::<usize>()
        .saturating_add(values.len().saturating_sub(1))
}

fn update_tlsh_joined<T: AsRef<str>>(builder: &mut TlshBuilder, values: &[T]) {
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            builder.update(b",");
        }
        builder.update(value.as_ref().as_bytes());
    }
}

fn normalize_telfhash_symbol(name: &str) -> Option<std::borrow::Cow<'_, str>> {
    match ascii_lowercase_cow(name.trim_start_matches('_')) {
        std::borrow::Cow::Borrowed(value) => {
            let value = normalize_telfhash_borrowed(value);
            (!telfhash_symbol_excluded(value)).then_some(std::borrow::Cow::Borrowed(value))
        }
        std::borrow::Cow::Owned(mut value) => {
            if value.ends_with("@plt") {
                value.truncate(value.len() - 4);
            }
            (!telfhash_symbol_excluded(&value)).then_some(std::borrow::Cow::Owned(value))
        }
    }
}

fn normalize_telfhash_borrowed(value: &str) -> &str {
    value.strip_suffix("@plt").unwrap_or(value)
}

fn telfhash_symbol_excluded(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    for prefix in ["__libc_", "__"] {
        if value.starts_with(prefix) {
            return true;
        }
    }
    for prefix in ["str", "mem"] {
        if value.starts_with(prefix) {
            return true;
        }
    }
    value.ends_with("64")
}

fn probe_section_children(bytes: &[u8], sections: &[ElfSection]) -> Vec<ElfExtractedChild> {
    let mut children = Vec::with_capacity(sections.len().min(MAX_EXTRACTED_CHILDREN));
    for section in sections {
        if children.len() >= MAX_EXTRACTED_CHILDREN {
            break;
        }
        if section.size == 0 || section.section_type == SHT_STRTAB {
            continue;
        }
        let Some(range) = checked_range(section.offset, section.size, bytes.len()) else {
            continue;
        };
        let section_bytes = &bytes[range.start..range.end];
        let Some(probe) = probe_embedded_child(section_bytes) else {
            continue;
        };
        let index = children.len() + 1;
        match probe {
            EmbeddedChildProbe::Valid(candidate) => {
                children.push(ElfExtractedChild {
                    index,
                    source: "section",
                    source_index: section.index,
                    source_offset: section.offset,
                    source_size: candidate.size,
                    mime: candidate.mime,
                    range_status: candidate.range_status,
                    range_basis: candidate.range_basis,
                    status: "extracted",
                    skip_reason: None,
                    filename: format!(
                        "elf-section-{}-{}.{}",
                        section.index, index, candidate.extension
                    ),
                });
            }
            EmbeddedChildProbe::Rejected(rejection) => {
                children.push(ElfExtractedChild {
                    index,
                    source: "section",
                    source_index: section.index,
                    source_offset: section.offset,
                    source_size: rejection.source_size,
                    mime: rejection.mime,
                    range_status: rejection.range_status,
                    range_basis: rejection.range_basis,
                    status: "not_extracted",
                    skip_reason: Some(rejection.skip_reason),
                    filename: format!("elf-section-{}-{index}.bin", section.index),
                });
            }
        }
    }
    children
}

fn detect_packers(bytes: &[u8], analysis: &ElfAnalysis) -> Vec<ElfPacker> {
    let mut packers = Vec::with_capacity(1);
    let has_upx_layout = has_upx_layout_marker(bytes, analysis);
    let has_upx_section = analysis.sections.iter().any(|section| {
        let name = section.name.as_bytes();
        name.len() >= 3 && name[..3].eq_ignore_ascii_case(b"UPX")
    });
    if has_upx_layout || has_upx_section {
        packers.push(ElfPacker {
            name: "upx",
            confidence: "heuristic",
            status: "detected",
            detail: Some(if has_upx_layout {
                "UPX ELF pack header".to_owned()
            } else {
                "UPX section name".to_owned()
            }),
        });
    }
    packers
}

fn has_upx_layout_marker(bytes: &[u8], analysis: &ElfAnalysis) -> bool {
    if analysis.endian != Some("little") {
        return false;
    }
    let Some(phdr_end) = analysis
        .program_header_offset
        .zip(analysis.program_header_entry_size)
        .zip(analysis.program_header_count)
        .and_then(|((offset, entry_size), count)| {
            offset.checked_add(u64::from(entry_size).checked_mul(u64::from(count))?)
        })
        .and_then(|offset| usize::try_from(offset).ok())
    else {
        return false;
    };
    let magic_at_4 = phdr_end
        .checked_add(4)
        .and_then(|offset| read_u32_le(bytes, offset));
    if matches!(magic_at_4, Some(0x2158_5055 | 0x5850_557f)) {
        return true;
    }
    if analysis.is_64bit {
        let magic_at_8 = phdr_end
            .checked_add(8)
            .and_then(|offset| read_u32_le(bytes, offset));
        if magic_at_8 == Some(0x2158_5055) {
            return true;
        }
        if phdr_end
            .checked_add(12)
            .and_then(|end| bytes.get(phdr_end..end))
            .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0))
            && p_info_original_size_plausible(bytes, phdr_end)
            && plausible_end_l_info(bytes, phdr_end).is_some()
        {
            return true;
        }
    }
    let Some(scan_end) = phdr_end.checked_add(1024).map(|end| end.min(bytes.len())) else {
        return false;
    };
    (phdr_end..scan_end).any(|offset| {
        matches!(
            offset
                .checked_add(4)
                .and_then(|offset| read_u32_le(bytes, offset)),
            Some(0x2158_5055 | 0x5850_557f)
        )
    })
}

fn plausible_end_l_info(bytes: &[u8], start_l_info_offset: usize) -> Option<usize> {
    let search_end = start_l_info_offset
        .checked_add(12)?
        .checked_add(12)?
        .checked_add(12)?
        .checked_add(1)?;
    if bytes.len() < 12 {
        return None;
    }
    let min_offset = bytes
        .len()
        .saturating_sub(MAX_UPX_ELF_END_L_INFO_SCAN)
        .max(search_end);
    let mut offset = bytes.len().saturating_sub(12);
    loop {
        if offset < min_offset {
            break;
        }
        if read_u32_le(bytes, offset.checked_add(4)?) == Some(0x2158_5055) {
            let loader_size = read_u16_le(bytes, offset.checked_add(8)?)?;
            let version = *bytes.get(offset.checked_add(10)?)?;
            if (0x80..=0x4000).contains(&loader_size)
                && usize::from(loader_size) <= offset
                && (11..=14).contains(&version)
            {
                return Some(offset);
            }
        }
        if offset == 0 {
            break;
        }
        offset -= 1;
    }
    None
}

fn p_info_original_size_plausible(bytes: &[u8], l_info_offset: usize) -> bool {
    let Some(size_offset) = l_info_offset
        .checked_add(12)
        .and_then(|offset| offset.checked_add(4))
    else {
        return false;
    };
    read_u32_le(bytes, size_offset).is_some_and(|size| {
        size != 0 && usize::try_from(size).is_ok_and(|size| size <= 128 * 1024 * 1024)
    })
}

fn table_offset(base: u64, entry_size: u16, index: usize) -> Option<usize> {
    let offset = u64::from(entry_size).checked_mul(index as u64)?;
    usize::try_from(base.checked_add(offset)?).ok()
}

fn section_range(
    sections: &[ElfSection],
    elf_section_index: usize,
    len: usize,
) -> Option<std::ops::Range<usize>> {
    if elf_section_index == 0 || elf_section_index >= sections.len() {
        return None;
    }
    let section = &sections[elf_section_index];
    checked_range(section.offset, section.size, len)
}

fn align_checked(start: usize, size: u64, alignment: usize) -> Option<usize> {
    let size = usize::try_from(size).ok()?;
    let end = start.checked_add(size)?;
    let mask = alignment.checked_sub(1)?;
    Some(end.checked_add(mask)? & !mask)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn push_parse_error(analysis: &mut ElfAnalysis, message: String) {
    if analysis.parse_errors.len() < MAX_PARSE_ERRORS {
        analysis.parse_errors.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf64() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x180];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0040_1000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&2u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1u16.to_le_bytes());

        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

        let shstr = b"\0.shstrtab\0";
        bytes[0xf0..0xf0 + shstr.len()].copy_from_slice(shstr);
        let sh0 = 0x100;
        let sh1 = 0x140;
        bytes[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[sh1 + 4..sh1 + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        bytes[sh1 + 24..sh1 + 32].copy_from_slice(&0xf0u64.to_le_bytes());
        bytes[sh1 + 32..sh1 + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
        bytes[sh1 + 48..sh1 + 56].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(sh0, 0x100);
        bytes
    }

    fn note_heavy_elf64(note_count: usize) -> Vec<u8> {
        let note_offset = 0x100usize;
        let note_size = note_count * 12;
        let mut bytes = vec![0u8; note_offset + note_size];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        bytes[64..68].copy_from_slice(&PT_NOTE.to_le_bytes());
        bytes[72..80].copy_from_slice(&(note_offset as u64).to_le_bytes());
        bytes[96..104].copy_from_slice(&(note_size as u64).to_le_bytes());
        bytes[104..112].copy_from_slice(&(note_size as u64).to_le_bytes());
        bytes[112..120].copy_from_slice(&4u64.to_le_bytes());

        for index in 0..note_count {
            let offset = note_offset + index * 12;
            let name_size = u32::try_from(index).expect("fixture note index fits u32");
            bytes[offset + 8..offset + 12].copy_from_slice(&name_size.to_le_bytes());
        }
        bytes
    }

    fn write_upx_end_l_info_marker(bytes: &mut [u8], offset: usize) {
        bytes[offset + 4..offset + 8].copy_from_slice(&0x2158_5055u32.to_le_bytes());
        bytes[offset + 8..offset + 10].copy_from_slice(&0x80u16.to_le_bytes());
        bytes[offset + 10] = 12;
    }

    fn write_dynamic64(bytes: &mut [u8], offset: usize, tag: i64, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn write_sym64(bytes: &mut [u8], offset: usize, name: u32, info: u8, shndx: u16, value: u64) {
        bytes[offset..offset + 4].copy_from_slice(&name.to_le_bytes());
        bytes[offset + 4] = info;
        bytes[offset + 6..offset + 8].copy_from_slice(&shndx.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        bytes[offset + 16..offset + 24].copy_from_slice(&8u64.to_le_bytes());
    }

    fn stripped_dynamic_elf64() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x500];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0040_1000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        let load = 64;
        bytes[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[load + 4..load + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[load + 16..load + 24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        bytes[load + 32..load + 40].copy_from_slice(&0x500u64.to_le_bytes());
        bytes[load + 40..load + 48].copy_from_slice(&0x500u64.to_le_bytes());
        bytes[load + 48..load + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        let dynamic = 120;
        bytes[dynamic..dynamic + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        bytes[dynamic + 4..dynamic + 8].copy_from_slice(&6u32.to_le_bytes());
        bytes[dynamic + 8..dynamic + 16].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[dynamic + 16..dynamic + 24].copy_from_slice(&0x0040_0200_u64.to_le_bytes());
        bytes[dynamic + 32..dynamic + 40].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[dynamic + 40..dynamic + 48].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[dynamic + 48..dynamic + 56].copy_from_slice(&8u64.to_le_bytes());

        let strtab = b"\0libc.so.6\0fixture.so\0/rpath\0/runpath\0imported_function\0export_function_alpha\0export_function_beta\0export_function_gamma\0";
        bytes[0x300..0x300 + strtab.len()].copy_from_slice(strtab);
        let imported = 38u32;
        let export_alpha = 56u32;
        let export_beta = 78u32;
        let export_gamma = 99u32;

        write_sym64(&mut bytes, 0x380 + 24, imported, 0x12, SHN_UNDEF, 0);
        write_sym64(&mut bytes, 0x380 + 48, export_alpha, 0x12, 1, 0x0040_1100);
        write_sym64(&mut bytes, 0x380 + 72, export_beta, 0x12, 1, 0x0040_1120);
        write_sym64(&mut bytes, 0x380 + 96, export_gamma, 0x12, 1, 0x0040_1140);

        bytes[0x420..0x424].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x424..0x428].copy_from_slice(&5u32.to_le_bytes());

        let dyn_entries = [
            (DT_STRTAB, 0x0040_0300),
            (DT_STRSZ, strtab.len() as u64),
            (DT_SYMTAB, 0x0040_0380),
            (DT_SYMENT, 24),
            (DT_HASH, 0x0040_0420),
            (DT_NEEDED, 1),
            (DT_SONAME, 11),
            (DT_RPATH, 22),
            (DT_RUNPATH, 29),
            (DT_RELA, 0x0040_0450),
            (DT_RELASZ, 24),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ];
        for (index, (tag, value)) in dyn_entries.into_iter().enumerate() {
            write_dynamic64(&mut bytes, 0x200 + index * 16, tag, value);
        }
        bytes
    }

    fn write_gnu_hash_for_stripped_fixture(bytes: &mut [u8]) {
        write_dynamic64(bytes, 0x200 + 4 * 16, DT_GNU_HASH, 0x0040_0420);
        bytes[0x420..0x424].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x424..0x428].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x428..0x42c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x42c..0x430].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x430..0x438].copy_from_slice(&0u64.to_le_bytes());
        bytes[0x438..0x43c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x43c..0x440].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x440..0x444].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x444..0x448].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x448..0x44c].copy_from_slice(&1u32.to_le_bytes());
    }

    #[test]
    fn parses_minimal_elf64_header_and_sections() {
        let analysis = analyze(&minimal_elf64());
        assert!(analysis.is_elf);
        assert!(analysis.is_64bit);
        assert_eq!(analysis.machine, Some(0x3e));
        assert_eq!(analysis.entrypoint, Some(0x0040_1000));
        assert_eq!(analysis.segments.len(), 1);
        assert_eq!(analysis.sections.len(), 2);
        assert_eq!(analysis.sections[1].name, ".shstrtab");
    }

    #[test]
    fn rejects_non_elf() {
        let analysis = analyze(b"MZ");
        assert!(!analysis.is_elf);
    }

    #[test]
    fn upx_detection_rejects_overflowing_marker_offsets_without_panic() {
        let mut bytes = minimal_elf64();
        bytes[32..40].copy_from_slice(&((usize::MAX - 4) as u64).to_le_bytes());
        bytes[56..58].copy_from_slice(&0u16.to_le_bytes());

        let analysis = analyze_with_options(
            &bytes,
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: false,
                calculate_telfhash: false,
            },
        );

        assert!(analysis.is_elf);
        assert!(analysis.packers.is_empty());
    }

    #[test]
    fn note_metadata_is_capped() {
        let analysis = analyze(&note_heavy_elf64(MAX_NOTES + 8));

        assert_eq!(analysis.notes.len(), MAX_NOTES);
        assert!(
            analysis
                .parse_errors
                .iter()
                .any(|error| error == "elf_notes_omitted"),
            "{:?}",
            analysis.parse_errors
        );
    }

    #[test]
    fn zeroed_l_info_detection_does_not_scan_whole_file() {
        let mut bytes = minimal_elf64();
        let phdr_end = 64 + 56;
        let far_marker = phdr_end + 0x8000;
        bytes.resize(far_marker + MAX_UPX_ELF_END_L_INFO_SCAN + 0x100, 0);
        bytes[phdr_end + 16..phdr_end + 20].copy_from_slice(&4096u32.to_le_bytes());
        write_upx_end_l_info_marker(&mut bytes, far_marker);

        let analysis = analyze_with_options(
            &bytes,
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: false,
                calculate_telfhash: false,
            },
        );

        assert!(
            analysis.packers.is_empty(),
            "far fabricated marker should not be treated as UPX: {:?}",
            analysis.packers
        );
    }

    #[test]
    fn stripped_dynamic_elf_recovers_metadata_from_program_headers() {
        let analysis = analyze_with_options(
            &stripped_dynamic_elf64(),
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: true,
                calculate_telfhash: true,
            },
        );
        assert!(analysis.is_elf);
        assert!(analysis.sections.is_empty());
        assert_eq!(analysis.needed_libraries, vec!["libc.so.6"]);
        assert_eq!(analysis.soname.as_deref(), Some("fixture.so"));
        assert_eq!(analysis.rpath.as_deref(), Some("/rpath"));
        assert_eq!(analysis.runpath.as_deref(), Some("/runpath"));
        assert!(
            analysis
                .imports
                .iter()
                .any(|value| value == "imported_function")
        );
        assert!(
            analysis
                .exports
                .iter()
                .any(|value| value == "export_function_alpha")
        );
        assert_eq!(analysis.relocations.len(), 1);
        assert_eq!(analysis.relocations[0].table_type, "rela");
        assert_eq!(
            analysis.import_md5,
            Some(hex_lower(&Md5::digest(b"imported_function")))
        );
        assert!(
            analysis
                .telfhash
                .as_deref()
                .is_some_and(|value| value.starts_with("T1"))
        );
    }

    #[test]
    fn telfhash_treats_low_diversity_input_as_no_hash() {
        let low_diversity_name = "a".repeat(80);
        let analysis = ElfAnalysis {
            symtab: vec![ElfSymbol {
                name: low_diversity_name.clone(),
                bind: 1,
                symbol_type: 2,
                visibility: 0,
                section_index: 1,
                ..Default::default()
            }],
            ..Default::default()
        };

        assert!(joined_len(&[low_diversity_name.as_str()]) >= 50);
        assert_eq!(elf_telfhash(&analysis), None);
    }

    #[test]
    fn stripped_dynamic_elf_recovers_symbols_from_gnu_hash() {
        let mut bytes = stripped_dynamic_elf64();
        write_gnu_hash_for_stripped_fixture(&mut bytes);

        let analysis = analyze_with_options(
            &bytes,
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: true,
                calculate_telfhash: false,
            },
        );

        assert!(
            !analysis
                .parse_errors
                .iter()
                .any(|error| error == "elf_dynamic_symbol_count_unavailable"),
            "{:?}",
            analysis.parse_errors
        );
        assert!(
            analysis
                .dynamic
                .iter()
                .any(|entry| entry.tag == DT_GNU_HASH && entry.value == 0x0040_0420)
        );
        assert!(
            analysis
                .imports
                .iter()
                .any(|value| value == "imported_function")
        );
        assert!(
            analysis
                .exports
                .iter()
                .any(|value| value == "export_function_gamma")
        );
        assert_eq!(
            analysis.import_md5,
            Some(hex_lower(&Md5::digest(b"imported_function")))
        );
    }

    #[test]
    fn dynamic_gnu_hash_rejects_excessive_bucket_count() {
        let mut bytes = stripped_dynamic_elf64();
        write_gnu_hash_for_stripped_fixture(&mut bytes);
        let excessive_bucket_count =
            u32::try_from(MAX_SYMBOLS).expect("fixture max symbol count fits u32") + 1;
        bytes[0x420..0x424].copy_from_slice(&excessive_bucket_count.to_le_bytes());

        let analysis = analyze_with_options(
            &bytes,
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: false,
                calculate_telfhash: false,
            },
        );

        assert!(
            analysis
                .parse_errors
                .iter()
                .any(|error| error == "elf_dynamic_gnu_hash_bucket_count_exceeded"),
            "{:?}",
            analysis.parse_errors
        );
        assert!(
            analysis
                .parse_errors
                .iter()
                .any(|error| error == "elf_dynamic_symbol_count_unavailable"),
            "{:?}",
            analysis.parse_errors
        );
    }

    #[test]
    fn dynamic_gnu_hash_duplicate_buckets_do_not_hide_symbols() {
        let mut bytes = stripped_dynamic_elf64();
        write_gnu_hash_for_stripped_fixture(&mut bytes);
        bytes[0x420..0x424].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x438..0x43c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x43c..0x440].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x440..0x444].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x444..0x448].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x448..0x44c].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x44c..0x450].copy_from_slice(&1u32.to_le_bytes());

        let analysis = analyze_with_options(
            &bytes,
            ElfAnalysisOptions {
                probe_children: false,
                calculate_import_md5: false,
                calculate_telfhash: false,
            },
        );

        assert!(
            !analysis
                .parse_errors
                .iter()
                .any(|error| error == "elf_dynamic_symbol_count_unavailable"),
            "{:?}",
            analysis.parse_errors
        );
        assert!(
            analysis
                .exports
                .iter()
                .any(|value| value == "export_function_gamma")
        );
    }

    #[test]
    fn append_unique_strings_batches_duplicate_detection() {
        let mut values = vec!["liba.so".to_owned()];
        append_unique_strings(
            &mut values,
            vec![
                "liba.so".to_owned(),
                "libb.so".to_owned(),
                "libb.so".to_owned(),
                "libc.so".to_owned(),
            ],
        );

        assert_eq!(values, ["liba.so", "libb.so", "libc.so"]);
    }

    #[test]
    fn normalize_telfhash_symbol_borrows_lowercase_slices() {
        assert!(matches!(
            normalize_telfhash_symbol("_exported@plt"),
            Some(std::borrow::Cow::Borrowed("exported"))
        ));
        assert_eq!(
            normalize_telfhash_symbol("_EXPORTED@PLT").as_deref(),
            Some("exported")
        );
        assert!(normalize_telfhash_symbol("_strlen").is_none());
    }

    #[test]
    fn append_unique_symbols_deduplicates_by_full_symbol_key() {
        fn symbol(name: &str) -> ElfSymbol {
            ElfSymbol {
                name: name.to_owned(),
                value: 0x0040_1000,
                size: 8,
                bind: 1,
                symbol_type: 2,
                section_index: 1,
                ..Default::default()
            }
        }

        let mut symbols = Vec::new();
        append_unique_symbols(
            &mut symbols,
            vec![symbol("alpha"), symbol("beta"), symbol("alpha")],
        );
        append_unique_symbols(&mut symbols, vec![symbol("beta"), symbol("gamma")]);

        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "beta", "gamma"]
        );
        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn append_unique_dynamic_deduplicates_by_full_entry_key() {
        fn entry(tag: i64, value: u64, string_value: Option<&str>) -> ElfDynamicEntry {
            ElfDynamicEntry {
                tag,
                value,
                string_value: string_value.map(ToOwned::to_owned),
                ..Default::default()
            }
        }

        let mut entries = Vec::new();
        append_unique_dynamic(
            &mut entries,
            vec![
                entry(DT_NEEDED, 1, Some("liba.so")),
                entry(DT_NEEDED, 1, Some("libb.so")),
                entry(DT_NEEDED, 1, Some("liba.so")),
            ],
        );
        append_unique_dynamic(
            &mut entries,
            vec![
                entry(DT_NEEDED, 1, Some("libb.so")),
                entry(DT_RPATH, 2, Some("/tmp")),
            ],
        );

        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.string_value.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("liba.so"), Some("libb.so"), Some("/tmp")]
        );
        assert_eq!(
            entries.iter().map(|entry| entry.index).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn section_names_use_correct_shstrndx_section() {
        // Regression test for off-by-one bug: e_shstrndx is a 0-based ELF section index.
        // A fixture with 3 sections (null at index 0, placeholder at index 1, shstrtab at
        // index 2) and e_shstrndx=2 must resolve the section at ELF index 2, not index 1.
        let mut bytes = vec![0u8; 0x280];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&0x100u64.to_le_bytes()); // e_shoff
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum = 3
        bytes[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx = 2 (shstrtab at ELF index 2)

        // Place string table data at 0x200: "\0.placeholder\0.shstrtab\0"
        let strtab = b"\0.placeholder\0.shstrtab\0";
        bytes[0x200..0x200 + strtab.len()].copy_from_slice(strtab);

        // Section header 0 (ELF index 0): null section (all zeros, already zero)
        let sh0 = 0x100usize;
        // Section header 1 (ELF index 1): placeholder section, name_offset=1
        let sh1 = 0x140usize;
        bytes[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name = 1 -> ".placeholder"
        bytes[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes()); // sh_type = SHT_PROGBITS
        // Section header 2 (ELF index 2): shstrtab, name_offset=14 -> ".shstrtab"
        let sh2 = 0x180usize;
        bytes[sh2..sh2 + 4].copy_from_slice(&14u32.to_le_bytes()); // sh_name = 14 -> ".shstrtab"
        bytes[sh2 + 4..sh2 + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        bytes[sh2 + 24..sh2 + 32].copy_from_slice(&0x200u64.to_le_bytes()); // sh_offset
        bytes[sh2 + 32..sh2 + 40].copy_from_slice(&(strtab.len() as u64).to_le_bytes()); // sh_size
        assert_eq!(sh0, 0x100);

        let analysis = analyze(&bytes);
        assert_eq!(analysis.sections.len(), 3);
        // Index 1 (ELF section 1) must use the correct name from the shstrtab
        assert_eq!(
            analysis.sections[1].name, ".placeholder",
            "sh_link off-by-one: wrong string table used"
        );
        // Index 2 (ELF section 2) is the shstrtab itself
        assert_eq!(analysis.sections[2].name, ".shstrtab");
    }
}
