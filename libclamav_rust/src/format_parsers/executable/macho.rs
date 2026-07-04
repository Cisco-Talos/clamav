// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Mach-O and universal-binary parser.
//!
//! ## Scope
//!
//! The parser supports thin Mach-O 32/64-bit files plus fat/universal
//! containers. It inventories load commands, segments/sections, imported and
//! exported symbols, dylibs, code-signature byte ranges, universal slices, and
//! parser-owned embedded child ranges.
//!
//! ## References
//!
//! `ClamAV` `macho.c` and `macho.h` are the compatibility baseline, together
//! with Apple Mach-O and universal binary format references:
//!
//! - Mach-O overview:
//!   <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>
//! - Mach-O loader structures:
//!   <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>
//!
//! ## Layout
//!
//! ```text
//! universal/fat container, optional
//! +-------------------------------+
//! | fat_header / fat_header_64    | -> endian, arch count
//! +-------------------------------+
//! | fat_arch / fat_arch_64[]      | -> CPU type/subtype,
//! |                               |    thin slice offset/size/alignment
//! +-------------------------------+
//! | thin Mach-O slice bytes       | -> emitted as structured slice children
//! +-------------------------------+
//!
//! thin Mach-O
//! +-------------------------------+
//! | mach_header / mach_header_64  | -> magic, endian, CPU, filetype,
//! |                               |    ncmds, sizeofcmds, flags
//! +-------------------------------+
//! | load commands                 |
//! |   LC_SEGMENT(_64)             | -> segments and section records
//! |   LC_SYMTAB / LC_DYSYMTAB     | -> symbol and dynamic-symbol tables
//! |   LC_LOAD_*_DYLIB / LC_RPATH  | -> dylib and path strings
//! |   LC_MAIN or LC_(UNIX)THREAD  | -> entrypoint
//! |   LC_DYLD_INFO(_ONLY)         | -> bind, weak-bind, lazy-bind,
//! |                               |    and export-trie byte ranges
//! |   LC_DYLD_EXPORTS_TRIE        | -> modern export trie byte range
//! |   LC_CODE_SIGNATURE           | -> code-signature byte range
//! +-------------------------------+
//! | segment and __LINKEDIT bytes  | -> section byte ranges, string tables,
//! |                               |    symbol tables, dyld bind/export data
//! +-------------------------------+
//!
//! import/export derivation:
//!   nlist symbols + dysymtab ranges + dyld bind opcodes + export trie
//!        -> merged import/export name inventories and optional export hash
//! ```
//!
//! ## Parser Outputs
//!
//! Output includes header facts, universal slice children, segment and section
//! records, dylib/import/export metadata, optional hashes, code-signature
//! inventory, embedded child candidates, and parse diagnostics.
//!
//! ## Bounds And Recovery
//!
//! Fat architecture counts, load commands, segment sections, symbol tables,
//! string tables, child candidates, and parse errors are capped. Non-Mach-O
//! magic rejects the candidate; malformed matching records are reported without
//! making the parser depend on scanner metadata types.
//!
//! ## Intentional Gaps
//!
//! Universal slices are structured children, while Mach-O UPX unpacking is not
//! implemented because `ClamAV` does not provide a native or bytecode Mach-O UPX
//! unpacker to match.

#![forbid(unsafe_code)]

use md5::Md5;
use sha2::Digest;

use super::common::{
    Endian, ascii_lowercase_cow, checked_range, fixed_name, hex_lower, read_c_string,
};

const MH_MAGIC: u32 = 0xfeed_face;
const MH_CIGAM: u32 = 0xcefa_edfe;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_THREAD: u32 = 0x4;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_RPATH: u32 = 0x8000_001c;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_SOURCE_VERSION: u32 = 0x2a;
const LC_MAIN: u32 = 0x8000_0028;
const LC_LINKER_OPTION: u32 = 0x2d;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

const BIND_OPCODE_MASK: u8 = 0xf0;
#[cfg(test)]
const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;

const MAX_FAT_ARCHES: usize = 64;
const MAX_LOAD_COMMANDS: usize = 2048;
const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 8192;
const MAX_PARSE_ERRORS: usize = 64;
const MAX_MACHO_STRING_BYTES: usize = 4096;
const MAX_DYLD_BIND_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_TRIE_DEPTH: usize = 64;
const MAX_EXPORT_TRIE_NODES: usize = MAX_SYMBOLS * 2;

fn bounded_u64_count_to_usize(count: u64, limit: usize) -> usize {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    usize::try_from(count.min(limit_u64)).unwrap_or(limit)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent expensive metadata toggles are clearer as named flags"
)]
pub(crate) struct MachoAnalysisOptions {
    pub(crate) calculate_dylib_hash: bool,
    pub(crate) calculate_import_hash: bool,
    pub(crate) calculate_export_hash: bool,
    pub(crate) calculate_symhash: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoAnalysis {
    pub(crate) is_macho: bool,
    pub(crate) is_universal: bool,
    pub(crate) fat_arches: Vec<MachoFatArch>,
    pub(crate) slice_children: Vec<MachoSliceChild>,
    pub(crate) files: Vec<MachoFile>,
    pub(crate) dylib_hash: Option<String>,
    pub(crate) import_hash: Option<String>,
    pub(crate) export_hash: Option<String>,
    pub(crate) symhash: Option<String>,
    pub(crate) parse_errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoFatArch {
    pub(crate) index: usize,
    pub(crate) cpu_type: i32,
    pub(crate) cpu_subtype: i32,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) align: u32,
    pub(crate) valid: bool,
    pub(crate) skip_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoSliceChild {
    pub(crate) index: usize,
    pub(crate) arch_index: usize,
    pub(crate) source_offset: u64,
    pub(crate) source_size: u64,
    pub(crate) mime: &'static str,
    pub(crate) status: &'static str,
    pub(crate) skip_reason: Option<&'static str>,
    pub(crate) filename: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoFile {
    pub(crate) index: usize,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) is_32bit: bool,
    pub(crate) is_64bit: bool,
    pub(crate) endian: &'static str,
    pub(crate) magic: u32,
    pub(crate) cpu_type: i32,
    pub(crate) cpu_subtype: i32,
    pub(crate) filetype: u32,
    pub(crate) command_count: u32,
    pub(crate) sizeof_commands: u32,
    pub(crate) flags: u32,
    pub(crate) reserved: Option<u32>,
    pub(crate) entrypoint: Option<u64>,
    pub(crate) stack_size: Option<u64>,
    pub(crate) uuid: Option<String>,
    pub(crate) dylinker: Option<String>,
    pub(crate) rpaths: Vec<String>,
    pub(crate) dylibs: Vec<String>,
    pub(crate) segments: Vec<MachoSegment>,
    pub(crate) sections: Vec<MachoSection>,
    pub(crate) dysymtab: Option<MachoDysymtab>,
    pub(crate) linker_options: Vec<String>,
    pub(crate) symbols: Vec<MachoSymbol>,
    pub(crate) imports: Vec<String>,
    pub(crate) exports: Vec<String>,
    pub(crate) code_signature: Option<MachoDataRange>,
    pub(crate) dyld_info: Option<MachoDyldInfo>,
    pub(crate) dyld_exports_trie: Option<MachoDataRange>,
    pub(crate) dyld_chained_fixups: Option<MachoDataRange>,
    pub(crate) source_version: Option<u64>,
    pub(crate) min_version: Option<MachoVersion>,
    pub(crate) build_version: Option<MachoBuildVersion>,
    pub(crate) parse_errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoSegment {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) virtual_address: u64,
    pub(crate) virtual_size: u64,
    pub(crate) file_offset: u64,
    pub(crate) file_size: u64,
    pub(crate) max_protection: u32,
    pub(crate) initial_protection: u32,
    pub(crate) flags: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoSection {
    pub(crate) index: usize,
    pub(crate) segment: String,
    pub(crate) name: String,
    pub(crate) address: u64,
    pub(crate) size: u64,
    pub(crate) offset: u32,
    pub(crate) align: u32,
    pub(crate) relocation_offset: u32,
    pub(crate) relocation_count: u32,
    pub(crate) flags: u32,
    pub(crate) reserved1: u32,
    pub(crate) reserved2: u32,
    pub(crate) reserved3: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoDysymtab {
    pub(crate) local_symbol_index: u32,
    pub(crate) local_symbol_count: u32,
    pub(crate) external_defined_symbol_index: u32,
    pub(crate) external_defined_symbol_count: u32,
    pub(crate) undefined_symbol_index: u32,
    pub(crate) undefined_symbol_count: u32,
    pub(crate) table_of_contents_offset: u32,
    pub(crate) table_of_contents_count: u32,
    pub(crate) module_table_offset: u32,
    pub(crate) module_table_count: u32,
    pub(crate) external_reference_symbol_offset: u32,
    pub(crate) external_reference_symbol_count: u32,
    pub(crate) indirect_symbol_offset: u32,
    pub(crate) indirect_symbol_count: u32,
    pub(crate) external_relocation_offset: u32,
    pub(crate) external_relocation_count: u32,
    pub(crate) local_relocation_offset: u32,
    pub(crate) local_relocation_count: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoSymbol {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) symbol_type: u8,
    pub(crate) section_index: u8,
    pub(crate) description: u16,
    pub(crate) value: u64,
    pub(crate) is_import: bool,
    pub(crate) is_export: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoDataRange {
    pub(crate) offset: u64,
    pub(crate) size: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoDyldInfo {
    pub(crate) rebase: MachoDataRange,
    pub(crate) bind: MachoDataRange,
    pub(crate) weak_bind: MachoDataRange,
    pub(crate) lazy_bind: MachoDataRange,
    pub(crate) export: MachoDataRange,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoVersion {
    pub(crate) version: u32,
    pub(crate) sdk: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MachoBuildVersion {
    pub(crate) platform: u32,
    pub(crate) minos: u32,
    pub(crate) sdk: u32,
    pub(crate) tool_count: u32,
}

#[derive(Clone, Copy, Debug)]
struct ThinHeader {
    magic: u32,
    endian: Endian,
    is_64bit: bool,
    header_size: usize,
}

pub(crate) fn analyze_with_options(bytes: &[u8], options: MachoAnalysisOptions) -> MachoAnalysis {
    let mut analysis = MachoAnalysis::default();
    let Some(raw) = macho_magic_word(bytes) else {
        return analysis;
    };
    match raw {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
            parse_fat(bytes, raw, &mut analysis);
        }
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => {
            if let Some(file) = parse_thin(bytes, 0, bytes.len() as u64, 1) {
                analysis.is_macho = true;
                analysis.files.push(file);
            }
        }
        _ => {}
    }
    if options.calculate_dylib_hash
        || options.calculate_import_hash
        || options.calculate_export_hash
        || options.calculate_symhash
    {
        calculate_hashes(&mut analysis, options);
    }
    analysis
}

pub(crate) fn has_macho_or_fat_magic(bytes: &[u8]) -> bool {
    matches!(
        macho_magic_word(bytes),
        Some(
            MH_MAGIC
                | MH_CIGAM
                | MH_MAGIC_64
                | MH_CIGAM_64
                | FAT_MAGIC
                | FAT_CIGAM
                | FAT_MAGIC_64
                | FAT_CIGAM_64
        )
    )
}

#[cfg(test)]
pub(crate) fn analyze(bytes: &[u8]) -> MachoAnalysis {
    analyze_with_options(bytes, MachoAnalysisOptions::default())
}

fn parse_fat(bytes: &[u8], raw_magic: u32, analysis: &mut MachoAnalysis) {
    let (endian, is_64bit) = match raw_magic {
        FAT_MAGIC => (Endian::Big, false),
        FAT_CIGAM => (Endian::Little, false),
        FAT_MAGIC_64 => (Endian::Big, true),
        FAT_CIGAM_64 => (Endian::Little, true),
        _ => return,
    };
    let Some(nfat_arch) = endian.read_u32(bytes, 4) else {
        return;
    };
    analysis.is_macho = true;
    analysis.is_universal = true;
    let arch_size = if is_64bit { 32usize } else { 20usize };
    let arch_count = (nfat_arch as usize).min(MAX_FAT_ARCHES);
    if nfat_arch as usize > MAX_FAT_ARCHES {
        push_parse_error(analysis, "macho_fat_arches_omitted".to_owned());
    }
    for arch_index in 0..arch_count {
        let Some(offset) = 8usize.checked_add(arch_index.saturating_mul(arch_size)) else {
            push_parse_error(analysis, "macho_fat_arch_offset_overflow".to_owned());
            break;
        };
        let Some(arch) = parse_fat_arch(bytes, endian, is_64bit, offset, arch_index + 1) else {
            push_parse_error(
                analysis,
                format!("macho_fat_arch_{}_truncated", arch_index + 1),
            );
            break;
        };
        let valid = checked_range(arch.offset, arch.size, bytes.len())
            .and_then(|range| bytes.get(range.start..))
            .and_then(|slice| slice.get(..4))
            .is_some_and(is_macho_magic);
        let mut arch = arch;
        arch.valid = valid;
        arch.skip_reason = (!valid).then_some("invalid_slice_range_or_magic");
        let child_index = analysis.slice_children.len() + 1;
        if arch.valid {
            analysis.slice_children.push(MachoSliceChild {
                index: child_index,
                arch_index: arch.index,
                source_offset: arch.offset,
                source_size: arch.size,
                mime: "application/x-mach-binary",
                status: "extracted",
                skip_reason: None,
                filename: format!("macho-slice-{}.macho", arch.index),
            });
            if let Some(file) = parse_thin(bytes, arch.offset, arch.size, arch.index) {
                analysis.files.push(file);
            }
        }
        analysis.fat_arches.push(arch);
    }
}

fn parse_fat_arch(
    bytes: &[u8],
    endian: Endian,
    is_64bit: bool,
    offset: usize,
    index: usize,
) -> Option<MachoFatArch> {
    let cpu_type = endian.read_i32(bytes, offset)?;
    let cpu_subtype = endian.read_i32(bytes, offset.checked_add(4)?)?;
    let (slice_offset, slice_size, align) = if is_64bit {
        (
            endian.read_u64(bytes, offset.checked_add(8)?)?,
            endian.read_u64(bytes, offset.checked_add(16)?)?,
            endian.read_u32(bytes, offset.checked_add(24)?)?,
        )
    } else {
        (
            endian
                .read_u32(bytes, offset.checked_add(8)?)
                .map(u64::from)?,
            endian
                .read_u32(bytes, offset.checked_add(12)?)
                .map(u64::from)?,
            endian.read_u32(bytes, offset.checked_add(16)?)?,
        )
    };
    Some(MachoFatArch {
        index,
        cpu_type,
        cpu_subtype,
        offset: slice_offset,
        size: slice_size,
        align,
        valid: false,
        skip_reason: None,
    })
}

fn parse_thin(bytes: &[u8], base_offset: u64, size: u64, index: usize) -> Option<MachoFile> {
    let range = checked_range(base_offset, size, bytes.len())?;
    let slice = &bytes[range.start..range.end];
    let header = thin_header(slice)?;
    let endian = header.endian;
    let cpu_type = endian.read_i32(slice, 4)?;
    let cpu_subtype = endian.read_i32(slice, 8)?;
    let filetype = endian.read_u32(slice, 12)?;
    let command_count = endian.read_u32(slice, 16)?;
    let sizeof_commands = endian.read_u32(slice, 20)?;
    let flags = endian.read_u32(slice, 24)?;
    let reserved = header
        .is_64bit
        .then(|| endian.read_u32(slice, 28))
        .flatten();
    let mut file = MachoFile {
        index,
        offset: base_offset,
        size,
        is_32bit: !header.is_64bit,
        is_64bit: header.is_64bit,
        endian: match endian {
            Endian::Little => "little",
            Endian::Big => "big",
        },
        magic: header.magic,
        cpu_type,
        cpu_subtype,
        filetype,
        command_count,
        sizeof_commands,
        flags,
        reserved,
        ..MachoFile::default()
    };
    parse_load_commands(slice, header, &mut file);
    derive_imports_exports(slice, &mut file);
    Some(file)
}

fn thin_header(bytes: &[u8]) -> Option<ThinHeader> {
    let raw = u32::from_be_bytes([*bytes.first()?, bytes[1], bytes[2], bytes[3]]);
    match raw {
        MH_MAGIC => Some(ThinHeader {
            magic: raw,
            endian: Endian::Big,
            is_64bit: false,
            header_size: 28,
        }),
        MH_CIGAM => Some(ThinHeader {
            magic: raw,
            endian: Endian::Little,
            is_64bit: false,
            header_size: 28,
        }),
        MH_MAGIC_64 => Some(ThinHeader {
            magic: raw,
            endian: Endian::Big,
            is_64bit: true,
            header_size: 32,
        }),
        MH_CIGAM_64 => Some(ThinHeader {
            magic: raw,
            endian: Endian::Little,
            is_64bit: true,
            header_size: 32,
        }),
        _ => None,
    }
}

fn parse_load_commands(bytes: &[u8], header: ThinHeader, file: &mut MachoFile) {
    let command_bytes_end = usize::try_from(file.sizeof_commands)
        .ok()
        .and_then(|size| header.header_size.checked_add(size))
        .map_or(bytes.len(), |end| end.min(bytes.len()));
    let count = (file.command_count as usize).min(MAX_LOAD_COMMANDS);
    if file.command_count as usize > MAX_LOAD_COMMANDS {
        push_file_error(file, "macho_load_commands_omitted".to_owned());
    }
    let mut offset = header.header_size;
    for command_index in 0..count {
        if offset
            .checked_add(8)
            .is_none_or(|end| end > command_bytes_end)
        {
            push_file_error(
                file,
                format!("macho_load_command_{}_truncated", command_index + 1),
            );
            break;
        }
        let Some(cmd) = header.endian.read_u32(bytes, offset) else {
            break;
        };
        let Some(cmdsize) = header.endian.read_u32(bytes, offset + 4) else {
            break;
        };
        let cmdsize_usize = cmdsize as usize;
        let Some(command_end) = offset.checked_add(cmdsize_usize) else {
            push_file_error(
                file,
                format!("macho_load_command_{}_bad_size", command_index + 1),
            );
            break;
        };
        if cmdsize_usize < 8 || command_end > command_bytes_end {
            push_file_error(
                file,
                format!("macho_load_command_{}_bad_size", command_index + 1),
            );
            break;
        }
        parse_load_command(bytes, header, file, offset, command_end, cmd);
        offset = command_end;
    }
}

fn parse_load_command(
    bytes: &[u8],
    header: ThinHeader,
    file: &mut MachoFile,
    offset: usize,
    end: usize,
    cmd: u32,
) {
    let command = &bytes[offset..end];
    match cmd {
        LC_SEGMENT => parse_segment32(command, header, file),
        LC_SEGMENT_64 => parse_segment64(command, header, file),
        LC_SYMTAB => parse_symtab(bytes, command, header, file),
        LC_DYSYMTAB => parse_dysymtab(command, header, file),
        LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
        | LC_LOAD_UPWARD_DYLIB => {
            if let Some(value) = macho_load_command_string(command, header, 8) {
                file.dylibs.push(value);
            }
        }
        LC_RPATH => {
            if let Some(value) = macho_load_command_string(command, header, 8) {
                file.rpaths.push(value);
            }
        }
        LC_LOAD_DYLINKER => {
            file.dylinker = macho_load_command_string(command, header, 8);
        }
        LC_UUID => {
            if command.len() >= 24 {
                file.uuid = Some(format_uuid(&command[8..24]));
            }
        }
        LC_MAIN => {
            file.entrypoint = header.endian.read_u64(command, 8);
            file.stack_size = header.endian.read_u64(command, 16);
        }
        LC_THREAD | LC_UNIXTHREAD => {
            if file.entrypoint.is_none() {
                file.entrypoint = parse_thread_entrypoint(command, header);
            }
        }
        LC_CODE_SIGNATURE => {
            file.code_signature = parse_data_range_command(command, header);
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            file.dyld_info = parse_dyld_info(command, header);
        }
        LC_DYLD_EXPORTS_TRIE => {
            file.dyld_exports_trie = parse_data_range_command(command, header);
        }
        LC_DYLD_CHAINED_FIXUPS => {
            file.dyld_chained_fixups = parse_data_range_command(command, header);
        }
        LC_VERSION_MIN_MACOSX => {
            if let (Some(version), Some(sdk)) = (
                header.endian.read_u32(command, 8),
                header.endian.read_u32(command, 12),
            ) {
                file.min_version = Some(MachoVersion { version, sdk });
            }
        }
        LC_SOURCE_VERSION => {
            file.source_version = header.endian.read_u64(command, 8);
        }
        LC_BUILD_VERSION => {
            if let (Some(platform), Some(minos), Some(sdk), Some(tool_count)) = (
                header.endian.read_u32(command, 8),
                header.endian.read_u32(command, 12),
                header.endian.read_u32(command, 16),
                header.endian.read_u32(command, 20),
            ) {
                file.build_version = Some(MachoBuildVersion {
                    platform,
                    minos,
                    sdk,
                    tool_count,
                });
            }
        }
        LC_LINKER_OPTION => {
            parse_linker_options(command, header, file);
        }
        _ => {}
    }
}

fn parse_data_range_command(command: &[u8], header: ThinHeader) -> Option<MachoDataRange> {
    let offset = header.endian.read_u32(command, 8).map(u64::from)?;
    let size = header.endian.read_u32(command, 12).map(u64::from)?;
    Some(MachoDataRange { offset, size })
}

fn parse_segment32(command: &[u8], header: ThinHeader, file: &mut MachoFile) {
    if command.len() < 56 {
        return;
    }
    let endian = header.endian;
    let segment_index = file.segments.len() + 1;
    let name = fixed_name(&command[8..24]);
    let nsects = endian.read_u32(command, 48).unwrap_or(0) as usize;
    let segment = MachoSegment {
        index: segment_index,
        name,
        virtual_address: endian.read_u32(command, 24).map_or(0, u64::from),
        virtual_size: endian.read_u32(command, 28).map_or(0, u64::from),
        file_offset: endian.read_u32(command, 32).map_or(0, u64::from),
        file_size: endian.read_u32(command, 36).map_or(0, u64::from),
        max_protection: endian.read_u32(command, 40).unwrap_or(0),
        initial_protection: endian.read_u32(command, 44).unwrap_or(0),
        flags: endian.read_u32(command, 52).unwrap_or(0),
    };
    file.segments.push(segment);
    let count = capped_section_count(file, nsects);
    parse_sections32(command, header, file, 56, count);
}

fn parse_segment64(command: &[u8], header: ThinHeader, file: &mut MachoFile) {
    if command.len() < 72 {
        return;
    }
    let endian = header.endian;
    let segment_index = file.segments.len() + 1;
    let name = fixed_name(&command[8..24]);
    let nsects = endian.read_u32(command, 64).unwrap_or(0) as usize;
    let segment = MachoSegment {
        index: segment_index,
        name,
        virtual_address: endian.read_u64(command, 24).unwrap_or(0),
        virtual_size: endian.read_u64(command, 32).unwrap_or(0),
        file_offset: endian.read_u64(command, 40).unwrap_or(0),
        file_size: endian.read_u64(command, 48).unwrap_or(0),
        max_protection: endian.read_u32(command, 56).unwrap_or(0),
        initial_protection: endian.read_u32(command, 60).unwrap_or(0),
        flags: endian.read_u32(command, 68).unwrap_or(0),
    };
    file.segments.push(segment);
    let count = capped_section_count(file, nsects);
    parse_sections64(command, header, file, 72, count);
}

fn capped_section_count(file: &mut MachoFile, declared_count: usize) -> usize {
    let remaining = MAX_SECTIONS.saturating_sub(file.sections.len());
    if declared_count > remaining {
        push_file_error(file, "macho_sections_omitted".to_owned());
    }
    declared_count.min(remaining)
}

fn parse_sections32(
    command: &[u8],
    header: ThinHeader,
    file: &mut MachoFile,
    start: usize,
    count: usize,
) {
    let section_size = 68usize;
    for index in 0..count {
        let Some(offset) = section_record_offset(command, start, section_size, index, file) else {
            break;
        };
        file.sections.push(MachoSection {
            index: file.sections.len() + 1,
            name: fixed_name(&command[offset..offset + 16]),
            segment: fixed_name(&command[offset + 16..offset + 32]),
            address: header
                .endian
                .read_u32(command, offset + 32)
                .map_or(0, u64::from),
            size: header
                .endian
                .read_u32(command, offset + 36)
                .map_or(0, u64::from),
            offset: header.endian.read_u32(command, offset + 40).unwrap_or(0),
            align: header.endian.read_u32(command, offset + 44).unwrap_or(0),
            relocation_offset: header.endian.read_u32(command, offset + 48).unwrap_or(0),
            relocation_count: header.endian.read_u32(command, offset + 52).unwrap_or(0),
            flags: header.endian.read_u32(command, offset + 56).unwrap_or(0),
            reserved1: header.endian.read_u32(command, offset + 60).unwrap_or(0),
            reserved2: header.endian.read_u32(command, offset + 64).unwrap_or(0),
            reserved3: None,
        });
    }
}

fn parse_sections64(
    command: &[u8],
    header: ThinHeader,
    file: &mut MachoFile,
    start: usize,
    count: usize,
) {
    let section_size = 80usize;
    for index in 0..count {
        let Some(offset) = section_record_offset(command, start, section_size, index, file) else {
            break;
        };
        file.sections.push(MachoSection {
            index: file.sections.len() + 1,
            name: fixed_name(&command[offset..offset + 16]),
            segment: fixed_name(&command[offset + 16..offset + 32]),
            address: header.endian.read_u64(command, offset + 32).unwrap_or(0),
            size: header.endian.read_u64(command, offset + 40).unwrap_or(0),
            offset: header.endian.read_u32(command, offset + 48).unwrap_or(0),
            align: header.endian.read_u32(command, offset + 52).unwrap_or(0),
            relocation_offset: header.endian.read_u32(command, offset + 56).unwrap_or(0),
            relocation_count: header.endian.read_u32(command, offset + 60).unwrap_or(0),
            flags: header.endian.read_u32(command, offset + 64).unwrap_or(0),
            reserved1: header.endian.read_u32(command, offset + 68).unwrap_or(0),
            reserved2: header.endian.read_u32(command, offset + 72).unwrap_or(0),
            reserved3: header.endian.read_u32(command, offset + 76),
        });
    }
}

fn section_record_offset(
    command: &[u8],
    start: usize,
    section_size: usize,
    index: usize,
    file: &mut MachoFile,
) -> Option<usize> {
    let Some(offset) = index
        .checked_mul(section_size)
        .and_then(|relative| start.checked_add(relative))
    else {
        push_file_error(file, "macho_section_offset_overflow".to_owned());
        return None;
    };
    if offset
        .checked_add(section_size)
        .is_none_or(|end| end > command.len())
    {
        push_file_error(file, "macho_section_records_truncated".to_owned());
        return None;
    }
    Some(offset)
}

fn parse_symtab(bytes: &[u8], command: &[u8], header: ThinHeader, file: &mut MachoFile) {
    let Some(symoff) = header.endian.read_u32(command, 8).map(u64::from) else {
        return;
    };
    let Some(nsyms) = header.endian.read_u32(command, 12) else {
        return;
    };
    let Some(stroff) = header.endian.read_u32(command, 16).map(u64::from) else {
        return;
    };
    let Some(strsize) = header.endian.read_u32(command, 20).map(u64::from) else {
        return;
    };
    let Some(strtab_range) = checked_range(stroff, strsize, bytes.len()) else {
        push_file_error(file, "macho_strtab_out_of_bounds".to_owned());
        return;
    };
    let strtab = &bytes[strtab_range];
    let entry_size = if header.is_64bit { 16u64 } else { 12u64 };
    let declared_count = u64::from(nsyms);
    let count = bounded_u64_count_to_usize(declared_count, MAX_SYMBOLS);
    if declared_count > u64::try_from(MAX_SYMBOLS).unwrap_or(u64::MAX) {
        push_file_error(file, "macho_symbols_omitted".to_owned());
    }
    for index in 0..count {
        let Some(symbol_offset) = (index as u64)
            .checked_mul(entry_size)
            .and_then(|delta| symoff.checked_add(delta))
        else {
            push_file_error(file, format!("macho_symbol_{}_out_of_bounds", index + 1));
            break;
        };
        let Some(range) = checked_range(symbol_offset, entry_size, bytes.len()) else {
            push_file_error(file, format!("macho_symbol_{}_out_of_bounds", index + 1));
            break;
        };
        let symbol = if header.is_64bit {
            parse_symbol64(&bytes[range], header, strtab, index + 1)
        } else {
            parse_symbol32(&bytes[range], header, strtab, index + 1)
        };
        if let Some(symbol) = symbol {
            file.symbols.push(symbol);
        }
    }
}

fn parse_dysymtab(command: &[u8], header: ThinHeader, file: &mut MachoFile) {
    if command.len() < 80 {
        push_file_error(file, "macho_dysymtab_truncated".to_owned());
        return;
    }
    let endian = header.endian;
    file.dysymtab = Some(MachoDysymtab {
        local_symbol_index: endian.read_u32(command, 8).unwrap_or(0),
        local_symbol_count: endian.read_u32(command, 12).unwrap_or(0),
        external_defined_symbol_index: endian.read_u32(command, 16).unwrap_or(0),
        external_defined_symbol_count: endian.read_u32(command, 20).unwrap_or(0),
        undefined_symbol_index: endian.read_u32(command, 24).unwrap_or(0),
        undefined_symbol_count: endian.read_u32(command, 28).unwrap_or(0),
        table_of_contents_offset: endian.read_u32(command, 32).unwrap_or(0),
        table_of_contents_count: endian.read_u32(command, 36).unwrap_or(0),
        module_table_offset: endian.read_u32(command, 40).unwrap_or(0),
        module_table_count: endian.read_u32(command, 44).unwrap_or(0),
        external_reference_symbol_offset: endian.read_u32(command, 48).unwrap_or(0),
        external_reference_symbol_count: endian.read_u32(command, 52).unwrap_or(0),
        indirect_symbol_offset: endian.read_u32(command, 56).unwrap_or(0),
        indirect_symbol_count: endian.read_u32(command, 60).unwrap_or(0),
        external_relocation_offset: endian.read_u32(command, 64).unwrap_or(0),
        external_relocation_count: endian.read_u32(command, 68).unwrap_or(0),
        local_relocation_offset: endian.read_u32(command, 72).unwrap_or(0),
        local_relocation_count: endian.read_u32(command, 76).unwrap_or(0),
    });
}

fn parse_linker_options(command: &[u8], header: ThinHeader, file: &mut MachoFile) {
    let Some(count) = header.endian.read_u32(command, 8) else {
        return;
    };
    let mut offset = 12usize;
    for _ in 0..count.min(64) {
        if offset >= command.len() {
            push_file_error(file, "macho_linker_options_truncated".to_owned());
            break;
        }
        let Some(value) = read_c_string(command, offset, command.len() - offset) else {
            break;
        };
        let next = offset
            .checked_add(value.len())
            .and_then(|offset| offset.checked_add(1));
        if !value.is_empty() {
            file.linker_options.push(value);
        }
        let Some(next) = next else {
            push_file_error(file, "macho_linker_option_offset_overflow".to_owned());
            break;
        };
        offset = next;
    }
    if count > 64 {
        push_file_error(file, "macho_linker_options_omitted".to_owned());
    }
}

fn parse_symbol32(
    bytes: &[u8],
    header: ThinHeader,
    strtab: &[u8],
    index: usize,
) -> Option<MachoSymbol> {
    let strx = header.endian.read_u32(bytes, 0)?;
    let symbol_type = *bytes.get(4)?;
    let section_index = *bytes.get(5)?;
    let description = header.endian.read_u16(bytes, 6)?;
    let value = header.endian.read_u32(bytes, 8).map(u64::from)?;
    Some(macho_symbol(
        index,
        strx,
        symbol_type,
        section_index,
        description,
        value,
        strtab,
    ))
}

fn parse_symbol64(
    bytes: &[u8],
    header: ThinHeader,
    strtab: &[u8],
    index: usize,
) -> Option<MachoSymbol> {
    let strx = header.endian.read_u32(bytes, 0)?;
    let symbol_type = *bytes.get(4)?;
    let section_index = *bytes.get(5)?;
    let description = header.endian.read_u16(bytes, 6)?;
    let value = header.endian.read_u64(bytes, 8)?;
    Some(macho_symbol(
        index,
        strx,
        symbol_type,
        section_index,
        description,
        value,
        strtab,
    ))
}

fn macho_symbol(
    index: usize,
    strx: u32,
    symbol_type: u8,
    section_index: u8,
    description: u16,
    value: u64,
    strtab: &[u8],
) -> MachoSymbol {
    let name = read_c_string(strtab, strx as usize, MAX_MACHO_STRING_BYTES).unwrap_or_default();
    let n_type = symbol_type & 0x0e;
    let external = symbol_type & 0x01 != 0;
    MachoSymbol {
        index,
        name,
        symbol_type,
        section_index,
        description,
        value,
        is_import: external && n_type == 0,
        is_export: external && n_type != 0,
    }
}

fn derive_imports_exports(bytes: &[u8], file: &mut MachoFile) {
    let mut dyld_imports = Vec::new();
    let mut dyld_exports = Vec::new();
    extend_dyld_imports_exports(bytes, file, &mut dyld_imports, &mut dyld_exports);

    let (imports, exports) = {
        let mut symbol_imports = Vec::new();
        let mut symbol_exports = Vec::new();
        if let Some(dysymtab) = &file.dysymtab {
            extend_symbol_range(
                &mut symbol_imports,
                &file.symbols,
                dysymtab.undefined_symbol_index,
                dysymtab.undefined_symbol_count,
            );
            extend_symbol_range(
                &mut symbol_exports,
                &file.symbols,
                dysymtab.external_defined_symbol_index,
                dysymtab.external_defined_symbol_count,
            );
        } else {
            for symbol in &file.symbols {
                if symbol.name.is_empty() {
                    continue;
                }
                if symbol.is_import {
                    symbol_imports.push(symbol.name.as_str());
                } else if symbol.is_export {
                    symbol_exports.push(symbol.name.as_str());
                }
            }
        }

        (
            merge_macho_names(symbol_imports, dyld_imports),
            merge_macho_names(symbol_exports, dyld_exports),
        )
    };
    file.imports = imports;
    file.exports = exports;
}

fn calculate_hashes(analysis: &mut MachoAnalysis, options: MachoAnalysisOptions) {
    let mut dylibs = options.calculate_dylib_hash.then(Vec::new);
    let mut imports = options.calculate_import_hash.then(Vec::new);
    let mut exports = options.calculate_export_hash.then(Vec::new);
    let mut symbols = options.calculate_symhash.then(Vec::new);
    for file in &analysis.files {
        if let Some(dylibs) = dylibs.as_mut() {
            extend_lowercase_hash_values(dylibs, &file.dylibs);
        }
        if let Some(imports) = imports.as_mut() {
            extend_lowercase_hash_values(imports, &file.imports);
        }
        if let Some(exports) = exports.as_mut() {
            extend_lowercase_hash_values(exports, &file.exports);
        }
        if let Some(symbols) = symbols.as_mut() {
            for symbol in &file.symbols {
                if symbol.is_import && !symbol.name.is_empty() {
                    symbols.push(symbol.name.as_str());
                }
            }
        }
    }
    analysis.dylib_hash = dylibs.as_mut().and_then(hash_joined_nonempty);
    analysis.import_hash = imports.as_mut().and_then(hash_joined_nonempty);
    analysis.export_hash = exports.as_mut().and_then(hash_joined_nonempty);
    analysis.symhash = symbols.as_mut().and_then(hash_joined_nonempty);
}

fn extend_symbol_range<'a>(
    out: &mut Vec<&'a str>,
    symbols: &'a [MachoSymbol],
    start: u32,
    count: u32,
) {
    let start = start as usize;
    let count = count as usize;
    let Some(end) = start.checked_add(count) else {
        return;
    };
    let end = end.min(symbols.len());
    let Some(range) = symbols.get(start..end) else {
        return;
    };
    for symbol in range {
        if !symbol.name.is_empty() {
            out.push(symbol.name.as_str());
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum MachoName<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl MachoName<'_> {
    fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value.as_str(),
        }
    }

    fn into_owned(self) -> String {
        match self {
            Self::Borrowed(value) => value.to_owned(),
            Self::Owned(value) => value,
        }
    }
}

fn merge_macho_names(borrowed: Vec<&str>, owned: Vec<String>) -> Vec<String> {
    if borrowed.is_empty() {
        return sorted_unique_strings(owned);
    }
    if owned.is_empty() {
        let mut names = borrowed;
        names.sort_unstable();
        names.dedup();
        return names.into_iter().map(str::to_owned).collect();
    }

    let mut names = Vec::with_capacity(borrowed.len().saturating_add(owned.len()));
    names.extend(borrowed.into_iter().map(MachoName::Borrowed));
    names.extend(owned.into_iter().map(MachoName::Owned));
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    names.dedup_by(|left, right| left.as_str() == right.as_str());
    names.into_iter().map(MachoName::into_owned).collect()
}

fn sorted_unique_strings(mut names: Vec<String>) -> Vec<String> {
    names.sort_unstable();
    names.dedup();
    names
}

fn extend_dyld_imports_exports(
    bytes: &[u8],
    file: &mut MachoFile,
    imports: &mut Vec<String>,
    exports: &mut Vec<String>,
) {
    if let Some(info) = file.dyld_info {
        for range in [&info.bind, &info.weak_bind, &info.lazy_bind] {
            append_dyld_bind_symbols(bytes, file, range, imports);
        }
        append_export_trie(bytes, file, &info.export, exports);
    }
    if let Some(range) = file.dyld_exports_trie {
        append_export_trie(bytes, file, &range, exports);
    }
    if file.dyld_chained_fixups.is_some() {
        push_file_error(
            file,
            "macho_dyld_chained_fixups_present_unparsed".to_owned(),
        );
    }
}

fn append_dyld_bind_symbols(
    bytes: &[u8],
    file: &mut MachoFile,
    range: &MachoDataRange,
    out: &mut Vec<String>,
) {
    if range.size == 0 {
        return;
    }
    let Some(range) = checked_range(range.offset, range.size, bytes.len()) else {
        push_file_error(file, "macho_dyld_bind_range_out_of_bounds".to_owned());
        return;
    };
    let mut bytes = &bytes[range];
    if bytes.len() > MAX_DYLD_BIND_BYTES {
        push_file_error(file, "macho_dyld_bind_range_omitted".to_owned());
        bytes = &bytes[..MAX_DYLD_BIND_BYTES];
    }
    let mut offset = 0usize;
    let base_len = out.len();
    while offset < bytes.len() && out.len().saturating_sub(base_len) < MAX_SYMBOLS {
        let opcode = bytes[offset] & BIND_OPCODE_MASK;
        let immediate = bytes[offset] & !BIND_OPCODE_MASK;
        offset += 1;
        match opcode {
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
            | BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
            | BIND_OPCODE_SET_TYPE_IMM
            | BIND_OPCODE_DO_BIND
            | BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                let _ = immediate;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
            | BIND_OPCODE_SET_ADDEND_SLEB
            | BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            | BIND_OPCODE_ADD_ADDR_ULEB
            | BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                if read_uleb(bytes, &mut offset).is_none() {
                    break;
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let start = offset;
                let Some(limit) = start
                    .checked_add(MAX_MACHO_STRING_BYTES)
                    .and_then(|limit| limit.checked_add(1))
                    .map(|limit| limit.min(bytes.len()))
                else {
                    push_file_error(file, "macho_dyld_bind_symbol_too_long".to_owned());
                    break;
                };
                let Some(relative_end) = bytes[start..limit].iter().position(|byte| *byte == 0)
                else {
                    push_file_error(file, "macho_dyld_bind_symbol_too_long".to_owned());
                    break;
                };
                let Some(symbol_end) = start.checked_add(relative_end) else {
                    push_file_error(file, "macho_dyld_bind_symbol_too_long".to_owned());
                    break;
                };
                offset = symbol_end;
                if offset > start {
                    out.push(String::from_utf8_lossy(&bytes[start..offset]).into_owned());
                }
                let Some(next_offset) = offset.checked_add(1) else {
                    push_file_error(file, "macho_dyld_bind_symbol_too_long".to_owned());
                    break;
                };
                offset = next_offset;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                if read_uleb(bytes, &mut offset).is_none()
                    || read_uleb(bytes, &mut offset).is_none()
                {
                    break;
                }
            }
            _ => break,
        }
    }
    if out.len().saturating_sub(base_len) >= MAX_SYMBOLS {
        push_file_error(file, "macho_dyld_bind_symbols_omitted".to_owned());
    }
}

fn append_export_trie(
    bytes: &[u8],
    file: &mut MachoFile,
    range: &MachoDataRange,
    out: &mut Vec<String>,
) {
    if range.size == 0 {
        return;
    }
    let Some(range) = checked_range(range.offset, range.size, bytes.len()) else {
        push_file_error(file, "macho_export_trie_out_of_bounds".to_owned());
        return;
    };
    let bytes = &bytes[range];
    let base_len = out.len();
    let mut visited = std::collections::HashSet::new();
    let mut cycle_reported = false;
    let mut stack = Vec::with_capacity(1);
    stack.push((0usize, Vec::<u8>::new(), 0usize));
    let mut visited_count = 0usize;
    while let Some((node_offset, prefix, depth)) = stack.pop() {
        if out.len().saturating_sub(base_len) >= MAX_SYMBOLS {
            break;
        }
        if depth > MAX_EXPORT_TRIE_DEPTH {
            push_file_error(file, "macho_export_trie_depth_omitted".to_owned());
            continue;
        }
        if node_offset >= bytes.len() {
            push_file_error(file, "macho_export_trie_node_out_of_bounds".to_owned());
            continue;
        }
        if !visited.insert(node_offset) {
            if !cycle_reported {
                push_file_error(file, "macho_export_trie_cycle_omitted".to_owned());
                cycle_reported = true;
            }
            continue;
        }
        visited_count += 1;
        if visited_count > MAX_EXPORT_TRIE_NODES {
            push_file_error(file, "macho_export_trie_nodes_omitted".to_owned());
            break;
        }

        let mut offset = node_offset;
        let Some(terminal_size) =
            read_uleb(bytes, &mut offset).and_then(|value| usize::try_from(value).ok())
        else {
            push_file_error(file, "macho_export_trie_terminal_truncated".to_owned());
            continue;
        };
        let Some(children_offset) = offset.checked_add(terminal_size) else {
            push_file_error(
                file,
                "macho_export_trie_children_offset_overflow".to_owned(),
            );
            continue;
        };
        if children_offset > bytes.len() {
            push_file_error(file, "macho_export_trie_children_out_of_bounds".to_owned());
            continue;
        }
        if terminal_size > 0 && !prefix.is_empty() {
            out.push(String::from_utf8_lossy(&prefix).into_owned());
            if out.len().saturating_sub(base_len) >= MAX_SYMBOLS {
                break;
            }
        }
        if children_offset == bytes.len() {
            continue;
        }

        offset = children_offset;
        let child_count = bytes[offset];
        offset += 1;
        let mut children = Vec::with_capacity(child_count as usize);
        let mut malformed = false;
        for _ in 0..child_count {
            let start = offset;
            let Some(edge_limit) = start
                .checked_add(MAX_MACHO_STRING_BYTES)
                .and_then(|limit| limit.checked_add(1))
                .map(|limit| limit.min(bytes.len()))
            else {
                push_file_error(file, "macho_export_trie_symbol_too_long".to_owned());
                malformed = true;
                break;
            };
            let Some(relative_end) = bytes[start..edge_limit].iter().position(|byte| *byte == 0)
            else {
                if edge_limit.saturating_sub(start) > MAX_MACHO_STRING_BYTES {
                    push_file_error(file, "macho_export_trie_symbol_too_long".to_owned());
                } else {
                    push_file_error(file, "macho_export_trie_edge_truncated".to_owned());
                }
                malformed = true;
                break;
            };
            let Some(edge_end) = start.checked_add(relative_end) else {
                push_file_error(file, "macho_export_trie_symbol_too_long".to_owned());
                malformed = true;
                break;
            };
            offset = edge_end;
            let edge = &bytes[start..offset];
            let Some(next_offset) = offset.checked_add(1) else {
                push_file_error(file, "macho_export_trie_edge_truncated".to_owned());
                malformed = true;
                break;
            };
            offset = next_offset;
            let Some(child_node_offset) =
                read_uleb(bytes, &mut offset).and_then(|value| usize::try_from(value).ok())
            else {
                push_file_error(file, "macho_export_trie_child_offset_truncated".to_owned());
                malformed = true;
                break;
            };
            let Some(child_prefix_len) = prefix.len().checked_add(edge.len()) else {
                push_file_error(file, "macho_export_trie_symbol_too_long".to_owned());
                malformed = true;
                break;
            };
            if child_prefix_len > MAX_MACHO_STRING_BYTES {
                push_file_error(file, "macho_export_trie_symbol_too_long".to_owned());
                malformed = true;
                break;
            }
            let mut child_prefix = Vec::with_capacity(child_prefix_len);
            child_prefix.extend_from_slice(&prefix);
            child_prefix.extend_from_slice(edge);
            children.push((child_node_offset, child_prefix, depth + 1));
        }
        if malformed {
            continue;
        }
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    if out.len().saturating_sub(base_len) >= MAX_SYMBOLS {
        push_file_error(file, "macho_export_symbols_omitted".to_owned());
    }
}

fn hash_joined_nonempty<T>(values: &mut Vec<T>) -> Option<String>
where
    T: AsRef<str> + Ord,
{
    values.sort_unstable();
    values.dedup();
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

fn extend_lowercase_hash_values<'a>(
    out: &mut Vec<std::borrow::Cow<'a, str>>,
    values: &'a [String],
) {
    for value in values {
        if !value.is_empty() {
            out.push(ascii_lowercase_cow(value));
        }
    }
}

fn parse_dyld_info(command: &[u8], header: ThinHeader) -> Option<MachoDyldInfo> {
    Some(MachoDyldInfo {
        rebase: MachoDataRange {
            offset: header.endian.read_u32(command, 8).map(u64::from)?,
            size: header.endian.read_u32(command, 12).map(u64::from)?,
        },
        bind: MachoDataRange {
            offset: header.endian.read_u32(command, 16).map(u64::from)?,
            size: header.endian.read_u32(command, 20).map(u64::from)?,
        },
        weak_bind: MachoDataRange {
            offset: header.endian.read_u32(command, 24).map(u64::from)?,
            size: header.endian.read_u32(command, 28).map(u64::from)?,
        },
        lazy_bind: MachoDataRange {
            offset: header.endian.read_u32(command, 32).map(u64::from)?,
            size: header.endian.read_u32(command, 36).map(u64::from)?,
        },
        export: MachoDataRange {
            offset: header.endian.read_u32(command, 40).map(u64::from)?,
            size: header.endian.read_u32(command, 44).map(u64::from)?,
        },
    })
}

fn parse_thread_entrypoint(command: &[u8], header: ThinHeader) -> Option<u64> {
    if header.is_64bit && command.len() >= 184 {
        return header.endian.read_u64(command, 16 + 16 * 8);
    }
    if !header.is_64bit && command.len() >= 80 {
        return header.endian.read_u32(command, 16 + 10 * 4).map(u64::from);
    }
    None
}

fn macho_load_command_string(
    command: &[u8],
    header: ThinHeader,
    field_offset: usize,
) -> Option<String> {
    let string_offset = header.endian.read_u32(command, field_offset)? as usize;
    if string_offset >= command.len() {
        return None;
    }
    read_c_string(command, string_offset, MAX_MACHO_STRING_BYTES).filter(|value| !value.is_empty())
}

fn read_uleb(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while *offset < bytes.len() && shift < 64 {
        let byte = bytes[*offset];
        *offset += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn format_uuid(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(4));
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        macho_magic_word(bytes),
        Some(MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
    )
}

fn macho_magic_word(bytes: &[u8]) -> Option<u32> {
    let magic = bytes.get(..4)?;
    Some(u32::from_be_bytes([magic[0], magic[1], magic[2], magic[3]]))
}

fn push_parse_error(analysis: &mut MachoAnalysis, message: String) {
    if analysis.parse_errors.len() < MAX_PARSE_ERRORS {
        analysis.parse_errors.push(message);
    }
}

fn push_file_error(file: &mut MachoFile, message: String) {
    if file.parse_errors.len() < MAX_PARSE_ERRORS {
        file.parse_errors.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_usize_to_u32(value: usize) -> u32 {
        u32::try_from(value).expect("fixture value fits u32")
    }

    fn minimal_macho64() -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[0..4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        bytes[4..8].copy_from_slice(&0x0100_0007_i32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3i32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn macho64_with_truncated_excessive_section_count() -> Vec<u8> {
        let mut bytes = minimal_macho64();
        bytes.resize(32 + 72, 0);
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&72u32.to_le_bytes());
        write_command_header(&mut bytes, 32, LC_SEGMENT_64, 72);
        let excessive_section_count = fixture_usize_to_u32(MAX_SECTIONS) + 1;
        bytes[32 + 64..32 + 68].copy_from_slice(&excessive_section_count.to_le_bytes());
        bytes
    }

    fn write_command_header(bytes: &mut [u8], offset: usize, cmd: u32, cmdsize: u32) {
        bytes[offset..offset + 4].copy_from_slice(&cmd.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&cmdsize.to_le_bytes());
    }

    fn write_nlist64(
        bytes: &mut [u8],
        offset: usize,
        strx: u32,
        symbol_type: u8,
        section_index: u8,
        value: u64,
    ) {
        bytes[offset..offset + 4].copy_from_slice(&strx.to_le_bytes());
        bytes[offset + 4] = symbol_type;
        bytes[offset + 5] = section_index;
        bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn macho64_with_dynamic_metadata() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x220];
        let sizeof_commands = 24u32 + 80 + 32 + 24 + 48;
        bytes[0..4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        bytes[4..8].copy_from_slice(&0x0100_0007_i32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3i32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&5u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&sizeof_commands.to_le_bytes());
        bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());

        let symoff = 0x100u32;
        let stroff = 0x130u32;
        let strtab = b"\0_local\0_exported\0_imported\0";
        let bindoff = 0x170u32;
        let exportoff = 0x190u32;
        let export_trie = {
            let mut trie = Vec::new();
            trie.push(0);
            trie.push(1);
            trie.extend_from_slice(b"dyld_export\0");
            trie.push(15);
            trie.push(2);
            trie.push(0);
            trie.push(1);
            trie.push(0);
            trie
        };

        let mut cmd = 32usize;
        write_command_header(&mut bytes, cmd, LC_SYMTAB, 24);
        bytes[cmd + 8..cmd + 12].copy_from_slice(&symoff.to_le_bytes());
        bytes[cmd + 12..cmd + 16].copy_from_slice(&3u32.to_le_bytes());
        bytes[cmd + 16..cmd + 20].copy_from_slice(&stroff.to_le_bytes());
        bytes[cmd + 20..cmd + 24]
            .copy_from_slice(&fixture_usize_to_u32(strtab.len()).to_le_bytes());
        cmd += 24;

        write_command_header(&mut bytes, cmd, LC_DYSYMTAB, 80);
        bytes[cmd + 8..cmd + 12].copy_from_slice(&0u32.to_le_bytes());
        bytes[cmd + 12..cmd + 16].copy_from_slice(&1u32.to_le_bytes());
        bytes[cmd + 16..cmd + 20].copy_from_slice(&1u32.to_le_bytes());
        bytes[cmd + 20..cmd + 24].copy_from_slice(&1u32.to_le_bytes());
        bytes[cmd + 24..cmd + 28].copy_from_slice(&2u32.to_le_bytes());
        bytes[cmd + 28..cmd + 32].copy_from_slice(&1u32.to_le_bytes());
        cmd += 80;

        write_command_header(&mut bytes, cmd, LC_LINKER_OPTION, 32);
        bytes[cmd + 8..cmd + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[cmd + 12..cmd + 21].copy_from_slice(b"-lSystem\0");
        bytes[cmd + 21..cmd + 27].copy_from_slice(b"-ObjC\0");
        cmd += 32;

        write_command_header(&mut bytes, cmd, LC_MAIN, 24);
        bytes[cmd + 8..cmd + 16].copy_from_slice(&0x1234u64.to_le_bytes());
        bytes[cmd + 16..cmd + 24].copy_from_slice(&0x4000u64.to_le_bytes());
        cmd += 24;

        write_command_header(&mut bytes, cmd, LC_DYLD_INFO, 48);
        bytes[cmd + 16..cmd + 20].copy_from_slice(&bindoff.to_le_bytes());
        bytes[cmd + 20..cmd + 24].copy_from_slice(&14u32.to_le_bytes());
        bytes[cmd + 40..cmd + 44].copy_from_slice(&exportoff.to_le_bytes());
        bytes[cmd + 44..cmd + 48]
            .copy_from_slice(&fixture_usize_to_u32(export_trie.len()).to_le_bytes());

        write_nlist64(&mut bytes, symoff as usize, 1, 0x0f, 1, 0x1000);
        write_nlist64(&mut bytes, symoff as usize + 16, 8, 0x0f, 1, 0x1100);
        write_nlist64(&mut bytes, symoff as usize + 32, 18, 0x01, 0, 0);
        bytes[stroff as usize..stroff as usize + strtab.len()].copy_from_slice(strtab);
        bytes[bindoff as usize] = BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM;
        bytes[bindoff as usize + 1..bindoff as usize + 13].copy_from_slice(b"dyld_import\0");
        bytes[bindoff as usize + 13] = BIND_OPCODE_DONE;
        bytes[exportoff as usize..exportoff as usize + export_trie.len()]
            .copy_from_slice(&export_trie);
        bytes
    }

    #[test]
    fn parses_minimal_macho64() {
        let analysis = analyze(&minimal_macho64());
        assert!(analysis.is_macho);
        assert!(!analysis.is_universal);
        assert_eq!(analysis.files.len(), 1);
        assert!(analysis.files[0].is_64bit);
        assert_eq!(analysis.files[0].cpu_type, 0x0100_0007);
    }

    #[test]
    fn segment_section_metadata_is_globally_capped() {
        let analysis = analyze(&macho64_with_truncated_excessive_section_count());
        let file = &analysis.files[0];

        assert_eq!(file.sections.len(), 0);
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_sections_omitted"),
            "{:?}",
            file.parse_errors
        );
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_section_records_truncated"),
            "{:?}",
            file.parse_errors
        );
    }

    #[test]
    fn parses_universal_slice_child() {
        let thin = minimal_macho64();
        let mut bytes = vec![0u8; 8 + 20 + thin.len()];
        bytes[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x0100_0007_i32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3i32.to_be_bytes());
        bytes[16..20].copy_from_slice(&28u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&fixture_usize_to_u32(thin.len()).to_be_bytes());
        bytes[24..28].copy_from_slice(&2u32.to_be_bytes());
        bytes[28..].copy_from_slice(&thin);

        let analysis = analyze(&bytes);
        assert!(analysis.is_universal);
        assert_eq!(analysis.fat_arches.len(), 1);
        assert_eq!(analysis.slice_children.len(), 1);
        assert_eq!(analysis.files.len(), 1);
    }

    #[test]
    fn parses_dysymtab_linker_options_and_dyld_imports() {
        let analysis = analyze_with_options(
            &macho64_with_dynamic_metadata(),
            MachoAnalysisOptions {
                calculate_dylib_hash: false,
                calculate_import_hash: true,
                calculate_export_hash: true,
                calculate_symhash: true,
            },
        );
        let file = analysis.files.first().expect("Mach-O file");
        assert_eq!(file.entrypoint, Some(0x1234));
        assert_eq!(file.stack_size, Some(0x4000));
        assert!(file.dysymtab.is_some());
        assert_eq!(file.linker_options, vec!["-lSystem", "-ObjC"]);
        assert!(file.imports.iter().any(|value| value == "_imported"));
        assert!(file.imports.iter().any(|value| value == "dyld_import"));
        assert!(file.exports.iter().any(|value| value == "_exported"));
        assert!(file.exports.iter().any(|value| value == "dyld_export"));
        assert!(analysis.import_hash.is_some());
        assert!(analysis.export_hash.is_some());
        assert!(analysis.symhash.is_some());
    }

    #[test]
    fn export_trie_cycle_is_bounded() {
        let bytes = [0, 1, b'a', 0, 0];
        let mut file = MachoFile::default();
        let mut exports = Vec::new();
        append_export_trie(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut exports,
        );

        assert!(exports.is_empty());
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_export_trie_cycle_omitted"),
            "{:?}",
            file.parse_errors
        );
    }

    #[test]
    fn export_trie_symbol_prefix_is_bounded() {
        let mut bytes = Vec::new();
        bytes.push(0);
        bytes.push(1);
        bytes.extend(std::iter::repeat_n(b'a', MAX_MACHO_STRING_BYTES + 1));
        bytes.push(0);
        bytes.push(0);
        let mut file = MachoFile::default();
        let mut exports = Vec::new();
        append_export_trie(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut exports,
        );

        assert!(exports.is_empty());
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_export_trie_symbol_too_long"),
            "{:?}",
            file.parse_errors
        );
    }

    #[test]
    fn export_trie_unterminated_edge_probe_is_bounded() {
        let mut bytes = Vec::new();
        bytes.push(0);
        bytes.push(1);
        bytes.extend(std::iter::repeat_n(b'a', MAX_MACHO_STRING_BYTES + 1));
        let mut file = MachoFile::default();
        let mut exports = Vec::new();
        append_export_trie(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut exports,
        );

        assert!(exports.is_empty());
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_export_trie_symbol_too_long"),
            "{:?}",
            file.parse_errors
        );
    }

    #[test]
    fn dyld_bind_symbol_probe_is_bounded() {
        let mut bytes = Vec::new();
        bytes.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        bytes.extend(std::iter::repeat_n(b'a', MAX_MACHO_STRING_BYTES + 1));
        let mut file = MachoFile::default();
        let mut imports = Vec::new();
        append_dyld_bind_symbols(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut imports,
        );

        assert!(imports.is_empty());
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_dyld_bind_symbol_too_long"),
            "{:?}",
            file.parse_errors
        );
    }

    #[test]
    fn dyld_bind_done_stops_before_padding() {
        let mut bytes = Vec::new();
        bytes.push(BIND_OPCODE_DONE);
        bytes.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        bytes.extend_from_slice(b"after_done\0");
        let mut file = MachoFile::default();
        let mut imports = Vec::new();
        append_dyld_bind_symbols(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut imports,
        );

        assert!(imports.is_empty());
        assert!(file.parse_errors.is_empty(), "{:?}", file.parse_errors);
    }

    #[test]
    fn dyld_bind_range_scan_is_bounded() {
        let bytes = vec![BIND_OPCODE_SET_TYPE_IMM; MAX_DYLD_BIND_BYTES + 32];
        let mut file = MachoFile::default();
        let mut imports = Vec::new();
        append_dyld_bind_symbols(
            &bytes,
            &mut file,
            &MachoDataRange {
                offset: 0,
                size: bytes.len() as u64,
            },
            &mut imports,
        );

        assert!(imports.is_empty());
        assert!(
            file.parse_errors
                .iter()
                .any(|error| error == "macho_dyld_bind_range_omitted"),
            "{:?}",
            file.parse_errors
        );
    }
}
