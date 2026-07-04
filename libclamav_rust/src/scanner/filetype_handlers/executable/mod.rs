/*
 *  Experimental executable file-type handlers backed by Inkie-derived parsers.
 *
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_void},
    ptr,
};

use log::{debug, error, warn};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{
    ctx,
    fmap::FMap,
    format_parsers::executable::{
        elf::{self, ElfAnalysisOptions},
        macho::{self, MachoAnalysisOptions},
        pe::{self, PeAnalysisOptions},
    },
    scanner::json::JsonObject,
    sys::{
        cl_error_t, cl_error_t_CL_BREAK, cl_error_t_CL_CLEAN, cl_error_t_CL_EARG,
        cl_error_t_CL_EFORMAT, cl_error_t_CL_EMEM, cl_error_t_CL_ERROR, cl_error_t_CL_EVERIFY,
        cl_error_t_CL_SUCCESS, cl_error_t_CL_VERIFIED, cl_error_t_CL_VIRUS, cl_fmap_t, cli_ctx,
        cli_file_CL_TYPE_ANY, cli_file_CL_TYPE_MACHO, cli_file_t, cli_matcher,
    },
};

#[allow(unused_doc_comments)]
/// cbindgen:ignore
unsafe extern "C" {
    fn cli_max_calloc(nmemb: usize, size: usize) -> *mut c_void;

    fn cli_scanpe_clamav_services_from_rust(
        ctx: *mut cli_ctx,
        pedata: *const CliPeHookData,
        sections: *const CliExeSection,
        nsections: u16,
        is_pe32plus: u32,
        import_md5_hex: *const c_char,
        import_sha1_hex: *const c_char,
        import_sha256_hex: *const c_char,
        import_hash_size: u32,
    ) -> cl_error_t;
    fn cli_pe_targetinfo_from_rust(
        peinfo: *mut c_void,
        sections: *const CliExeSection,
        nsections: u16,
        ep: u32,
        res_addr: u32,
        hdr_size: u32,
        vep: u32,
        ndatadirs: u32,
        is_dll: u32,
        is_pe32plus: u32,
        e_lfanew: u32,
        min: u32,
        max: u32,
        overlay_start: u32,
        overlay_size: u32,
        dirs: *const CliPeImageDataDir,
        dir_count: usize,
        version_offsets: *const u32,
        version_offset_count: usize,
    ) -> cl_error_t;

    fn cli_magic_scan_nested_fmap_type(
        map: *mut cl_fmap_t,
        offset: usize,
        length: usize,
        ctx: *mut cli_ctx,
        type_: cli_file_t,
        name: *const c_char,
        attributes: u32,
    ) -> cl_error_t;

    fn cli_magic_scan_buff(
        buffer: *const c_void,
        length: usize,
        ctx: *mut cli_ctx,
        name: *const c_char,
        attributes: u32,
    ) -> cl_error_t;

    fn cli_hm_have_size(root: *const cli_matcher, type_: u32, size: u32) -> bool;
    fn cli_hm_have_wild(root: *const cli_matcher, type_: u32) -> bool;
    fn cli_hm_have_any(root: *const cli_matcher, type_: u32) -> bool;
    fn cli_hm_scan(
        digest: *const u8,
        size: u32,
        virname: *mut *const c_char,
        root: *const cli_matcher,
        type_: u32,
    ) -> cl_error_t;
    fn cli_hm_scan_wild(
        digest: *const u8,
        virname: *mut *const c_char,
        root: *const cli_matcher,
        type_: u32,
    ) -> cl_error_t;

    fn asn1_check_mscat(
        engine: *mut crate::sys::cl_engine,
        map: *mut cl_fmap_t,
        offset: usize,
        size: u32,
        regions: *mut CliMappedRegion,
        nregions: u32,
        ctx: *mut cli_ctx,
    ) -> cl_error_t;

    fn cli_trust_this_layer(ctx: *mut cli_ctx, source: *const c_char) -> cl_error_t;
}

/// Scan a PE file through the Rust executable parser experiment.
///
/// The handler keeps ClamAV-owned scanning behavior at the boundary: generated
/// unpacker output is passed back to `cli_magic_scan_buff`, and parent-backed
/// resource/overlay ranges go through `cli_magic_scan_nested_fmap_type` so
/// force-to-disk and leave-temp policy stay in ClamAV.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context.
pub unsafe fn scan_pe(ctx: *mut cli_ctx) -> cl_error_t {
    let Some(fmap) = (unsafe { current_fmap(ctx, "scan_pe") }) else {
        return cl_error_t_CL_ERROR;
    };
    let fmap_ptr = fmap.as_ptr();
    let Some(bytes) = full_fmap_bytes(&fmap, "scan_pe") else {
        return cl_error_t_CL_ERROR;
    };
    if !pe::has_dos_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let hash_algorithms = pe::PeHashAlgorithmSet {
        md5: true,
        sha1: true,
        sha256: true,
    };
    let mut analysis = pe::analyze_with_options(
        bytes,
        PeAnalysisOptions {
            probe_overlay_children: true,
            calculate_checksum: true,
            section_hashes: hash_algorithms,
            import_table_hashes: hash_algorithms,
            calculate_imphash: true,
        },
    );
    debug!(
        "Rust PE parser found {} sections, {} resource children, {} overlay children, {} unpacked children",
        analysis.sections.len(),
        analysis.resource_children.len(),
        analysis.overlay_children.len(),
        analysis.unpacked_children.len()
    );
    add_pe_metadata(ctx, &analysis);

    if let Some((pedata, sections)) = pe_clamav_services_input(&analysis) {
        let import_md5 = cstring_opt(
            analysis
                .import_hashes
                .as_ref()
                .and_then(|hashes| hashes.md5.as_deref()),
        );
        let import_sha1 = cstring_opt(
            analysis
                .import_hashes
                .as_ref()
                .and_then(|hashes| hashes.sha1.as_deref()),
        );
        let import_sha256 = cstring_opt(
            analysis
                .import_hashes
                .as_ref()
                .and_then(|hashes| hashes.sha256.as_deref()),
        );
        let import_hash_size = analysis
            .import_hashes
            .as_ref()
            .and_then(|hashes| u32::try_from(hashes.size).ok())
            .unwrap_or_default();
        let ret = unsafe {
            cli_scanpe_clamav_services_from_rust(
                ctx,
                &pedata,
                sections.as_ptr(),
                u16::try_from(sections.len()).unwrap_or(u16::MAX),
                u32::from(analysis.is_64bit),
                import_md5
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                import_sha1
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                import_sha256
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                import_hash_size,
            )
        };
        if ret != cl_error_t_CL_SUCCESS && ret != cl_error_t_CL_CLEAN {
            return ret;
        }
    }

    for child in &analysis.resource_children {
        let ret = scan_parent_range(
            ctx,
            fmap_ptr,
            child.file_offset,
            child.size,
            cli_file_CL_TYPE_ANY,
            Some(&child.filename),
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    for child in &analysis.overlay_children {
        let ret = scan_parent_range(
            ctx,
            fmap_ptr,
            child.source_offset,
            child.source_size,
            cli_file_CL_TYPE_ANY,
            Some(&child.filename),
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    for child in &mut analysis.unpacked_children {
        if let Some(bytes) = child.bytes.take() {
            let ret = scan_generated_bytes(
                ctx,
                &bytes,
                Some(&format!("{}-unpacked-{}.exe", child.packer, child.index)),
            );
            if ret != cl_error_t_CL_SUCCESS {
                return ret;
            }
        }
    }

    cl_error_t_CL_SUCCESS
}

/// Validate that a parent fmap range beginning at `offset` contains a PE
/// header that the Rust parser can understand.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context.
pub unsafe fn check_pe_header_at(ctx: *mut cli_ctx, offset: usize) -> cl_error_t {
    let Some(fmap) = (unsafe { current_fmap(ctx, "check_pe_header_at") }) else {
        return cl_error_t_CL_ERROR;
    };
    if offset >= fmap.len() {
        return cl_error_t_CL_EFORMAT;
    }
    let Some(length) = fmap.len().checked_sub(offset) else {
        return cl_error_t_CL_EFORMAT;
    };
    let bytes = match fmap.need_off(offset, length) {
        Ok(bytes) => bytes,
        Err(error) => {
            error!(
                "check_pe_header_at: failed to borrow fmap bytes at offset {offset} for {length} bytes: {error}"
            );
            return cl_error_t_CL_ERROR;
        }
    };
    if !pe::has_dos_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }
    let analysis = pe::analyze_with_options(bytes, PeAnalysisOptions::default());
    if analysis.is_pe {
        cl_error_t_CL_SUCCESS
    } else {
        cl_error_t_CL_EFORMAT
    }
}

/// Populate ClamAV matcher target information for a PE file.
///
/// The Rust parser owns PE structure parsing. C still owns allocation and the
/// `cli_hashset` internals used by VI-offset signatures.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by `cli_exe_info_init()`.
pub unsafe fn populate_pe_target_info(ctx: *mut cli_ctx, exe_info: *mut c_void) -> cl_error_t {
    if exe_info.is_null() {
        return cl_error_t_CL_ERROR;
    }
    let Some(fmap) = (unsafe { current_fmap(ctx, "populate_pe_target_info") }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(bytes) = full_fmap_bytes(&fmap, "populate_pe_target_info") else {
        return cl_error_t_CL_ERROR;
    };
    if !pe::has_dos_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }
    let analysis = pe::analyze_with_options(
        bytes,
        PeAnalysisOptions {
            probe_overlay_children: false,
            calculate_checksum: false,
            section_hashes: pe::PeHashAlgorithmSet::default(),
            import_table_hashes: pe::PeHashAlgorithmSet::default(),
            calculate_imphash: false,
        },
    );
    if !analysis.is_pe {
        return cl_error_t_CL_EFORMAT;
    }
    let Some(target) = pe_target_info_input(bytes, &analysis) else {
        return cl_error_t_CL_EFORMAT;
    };
    unsafe {
        cli_pe_targetinfo_from_rust(
            exe_info,
            target.sections.as_ptr(),
            u16::try_from(target.sections.len()).unwrap_or_default(),
            target.ep,
            target.res_addr,
            target.hdr_size,
            target.vep,
            target.ndatadirs,
            u32::from(target.is_dll),
            u32::from(target.is_pe32plus),
            target.e_lfanew,
            target.min,
            target.max,
            target.overlay_start,
            target.overlay_size,
            target.dirs.as_ptr(),
            target.dirs.len(),
            target.version_offsets.as_ptr(),
            target.version_offsets.len(),
        )
    }
}

/// Scan an ELF file through the Rust executable parser experiment.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context.
pub unsafe fn scan_elf(ctx: *mut cli_ctx) -> cl_error_t {
    let Some(fmap) = (unsafe { current_fmap(ctx, "scan_elf") }) else {
        return cl_error_t_CL_ERROR;
    };
    let fmap_ptr = fmap.as_ptr();
    let Some(bytes) = full_fmap_bytes(&fmap, "scan_elf") else {
        return cl_error_t_CL_ERROR;
    };
    if !elf::has_elf_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let mut analysis = elf::analyze_with_options(
        bytes,
        ElfAnalysisOptions {
            probe_children: true,
            calculate_import_md5: true,
            calculate_telfhash: true,
        },
    );
    debug!(
        "Rust ELF parser found {} sections, {} extracted children, {} unpacked children",
        analysis.sections.len(),
        analysis.extracted_children.len(),
        analysis.unpacked_children.len()
    );
    add_elf_metadata(ctx, &analysis);

    for child in &analysis.extracted_children {
        let ret = scan_parent_range(
            ctx,
            fmap_ptr,
            child.source_offset,
            child.source_size,
            cli_file_CL_TYPE_ANY,
            Some(&child.filename),
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    for child in &mut analysis.unpacked_children {
        if let Some(bytes) = child.bytes.take() {
            let ret = scan_generated_bytes(
                ctx,
                &bytes,
                Some(&format!("{}-unpacked-{}", child.packer, child.index)),
            );
            if ret != cl_error_t_CL_SUCCESS {
                return ret;
            }
        }
    }

    cl_error_t_CL_SUCCESS
}

/// Scan a Mach-O or universal Mach-O file through the Rust executable parser
/// experiment.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context.
pub unsafe fn scan_macho(ctx: *mut cli_ctx, _expected_type: cli_file_t) -> cl_error_t {
    let Some(fmap) = (unsafe { current_fmap(ctx, "scan_macho") }) else {
        return cl_error_t_CL_ERROR;
    };
    let fmap_ptr = fmap.as_ptr();
    let Some(bytes) = full_fmap_bytes(&fmap, "scan_macho") else {
        return cl_error_t_CL_ERROR;
    };
    if !macho::has_macho_or_fat_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let analysis = macho::analyze_with_options(
        bytes,
        MachoAnalysisOptions {
            calculate_dylib_hash: true,
            calculate_import_hash: true,
            calculate_export_hash: true,
            calculate_symhash: true,
        },
    );
    debug!(
        "Rust Mach-O parser found {} files and {} universal slice children",
        analysis.files.len(),
        analysis.slice_children.len()
    );
    add_macho_metadata(ctx, &analysis);

    for child in &analysis.slice_children {
        let ret = scan_parent_range(
            ctx,
            fmap_ptr,
            child.source_offset,
            child.source_size,
            cli_file_CL_TYPE_MACHO,
            Some(&child.filename),
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    cl_error_t_CL_SUCCESS
}

/// Populate ClamAV matcher target information for an ELF file.
///
/// This is intentionally narrower than full scan metadata: the legacy matcher
/// and bytecode paths need an entry-point file offset plus section raw ranges.
/// The section table is allocated with ClamAV's allocator so
/// `cli_exe_info_destroy()` can keep owning cleanup on the C side.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by `cli_exe_info_init()`.
pub unsafe fn populate_elf_target_info(ctx: *mut cli_ctx, exe_info: *mut c_void) -> cl_error_t {
    let Some(info) = (unsafe { CliExeInfoPrefix::from_raw(exe_info) }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(fmap) = (unsafe { current_fmap(ctx, "populate_elf_target_info") }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(bytes) = full_fmap_bytes(&fmap, "populate_elf_target_info") else {
        return cl_error_t_CL_ERROR;
    };
    if !elf::has_elf_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let analysis = elf::analyze_with_options(bytes, ElfAnalysisOptions::default());
    if !analysis.is_elf {
        return cl_error_t_CL_EFORMAT;
    }
    if analysis.sections.len() > 256 {
        return cl_error_t_CL_BREAK;
    }

    let Some(sections) = elf_target_sections(&analysis) else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(section_count) = u16::try_from(sections.len()).ok() else {
        return cl_error_t_CL_BREAK;
    };
    let Some(ep) = elf_entry_file_offset(&analysis) else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(section_ptr) = allocate_target_sections(&sections) else {
        return cl_error_t_CL_EMEM;
    };

    info.sections = section_ptr;
    info.ep = ep;
    info.nsections = section_count;

    cl_error_t_CL_SUCCESS
}

/// Populate ClamAV matcher target information for a thin Mach-O file.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by `cli_exe_info_init()`.
pub unsafe fn populate_macho_target_info(ctx: *mut cli_ctx, exe_info: *mut c_void) -> cl_error_t {
    let Some(info) = (unsafe { CliExeInfoPrefix::from_raw(exe_info) }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(fmap) = (unsafe { current_fmap(ctx, "populate_macho_target_info") }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(bytes) = full_fmap_bytes(&fmap, "populate_macho_target_info") else {
        return cl_error_t_CL_ERROR;
    };
    if !macho::has_macho_or_fat_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let analysis = macho::analyze_with_options(bytes, MachoAnalysisOptions::default());
    if !analysis.is_macho || analysis.is_universal {
        return cl_error_t_CL_EFORMAT;
    }
    let Some(file) = analysis.files.first() else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(sections) = macho_target_sections(file) else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(section_count) = u16::try_from(sections.len()).ok() else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(section_ptr) = allocate_target_sections(&sections) else {
        return cl_error_t_CL_EMEM;
    };

    info.sections = section_ptr;
    info.ep = macho_entry_file_offset(file).unwrap_or(0);
    info.nsections = section_count;

    cl_error_t_CL_SUCCESS
}

fn add_pe_metadata(ctx: *mut cli_ctx, analysis: &pe::PeAnalysis) {
    let Some(root) = (unsafe { current_metadata_json(ctx) }) else {
        return;
    };
    if let Some(imphash) = analysis
        .import_hashes
        .as_ref()
        .and_then(|hashes| hashes.imphash.as_deref())
    {
        root.string("Imphash", imphash);
    }
    add_pe_import_table_metadata(root, analysis);

    let Some(pe_json) = root.object("PE") else {
        return;
    };

    if analysis.is_dll {
        pe_json.string("Type", "DLL");
    } else if analysis
        .characteristics
        .is_some_and(|flags| flags & 0x0002 != 0)
    {
        pe_json.string("Type", "EXE");
    }

    if let Some(machine) = analysis.machine {
        pe_json.string("ArchType", pe_machine_type_name(machine));
    }
    pe_json.u64_opt("NumberOfSections", Some(analysis.sections.len() as u64));
    pe_json.timestamp_opt("TimeDateStamp", analysis.timestamp);
    pe_json.u64_opt(
        "SizeOfOptionalHeader",
        analysis.optional_header_size.map(u64::from),
    );
    pe_json.u64_opt(
        "MajorLinkerVersion",
        analysis.major_linker_version.map(u64::from),
    );
    pe_json.u64_opt(
        "MinorLinkerVersion",
        analysis.minor_linker_version.map(u64::from),
    );
    pe_json.u64_opt("SizeOfCode", analysis.size_of_code.map(u64::from));
    pe_json.u64_opt(
        "SizeOfInitializedData",
        analysis.size_of_initialized_data.map(u64::from),
    );
    pe_json.u64_opt(
        "SizeOfUninitializedData",
        analysis.size_of_uninitialized_data.map(u64::from),
    );
    pe_json.u64_opt(
        "NumberOfRvaAndSizes",
        analysis.number_of_rva_and_sizes.map(u64::from),
    );
    pe_json.u64_opt(
        "MajorSubsystemVersion",
        analysis.major_subsystem_version.map(u64::from),
    );
    pe_json.u64_opt(
        "MinorSubsystemVersion",
        analysis.minor_subsystem_version.map(u64::from),
    );
    pe_json.hex_u32_opt("EntryPoint", analysis.entrypoint_rva);
    pe_json.hex_u32_opt("BaseOfCode", analysis.base_of_code);
    pe_json.hex_u32_opt("SectionAlignment", analysis.section_alignment);
    pe_json.hex_u32_opt("FileAlignment", analysis.file_alignment);
    pe_json.hex_u32_opt("SizeOfImage", analysis.size_of_image);
    pe_json.hex_u32_opt("SizeOfHeaders", analysis.size_of_headers);

    if let Some(subsystem) = analysis.subsystem {
        pe_json.string("Subsystem", pe_subsystem_name(subsystem));
    }
    pe_json.u64_opt("EntryPointOffset", analysis.entrypoint_offset);

    if let Some(packer) = successful_pe_packer_name(analysis) {
        pe_json.string("Packer", packer);
    }

    add_pe_sections_metadata(pe_json, &analysis.sections);
    add_parse_errors_metadata(pe_json, &analysis.parse_errors);
}

fn add_pe_import_table_metadata(root: JsonObject, analysis: &pe::PeAnalysis) {
    let mut imports = Vec::new();
    pe::for_each_normalized_import(analysis, |dll, function| {
        imports.push(format!("{dll}.{function}"));
    });
    if imports.is_empty() {
        return;
    }

    let Some(imports_json) = root.array("ImportTable") else {
        return;
    };
    for import in imports {
        imports_json.string_item(&import);
    }
}

fn add_pe_sections_metadata(pe_json: JsonObject, sections: &[pe::PeSection]) {
    if sections.is_empty() {
        return;
    }
    let Some(sections_json) = pe_json.array("Sections") else {
        return;
    };
    for section in sections {
        let Some(section_json) = sections_json.object_item() else {
            return;
        };
        section_json.u64_opt("RawSize", Some(u64::from(section.raw_size)));
        section_json.u64_opt("RawOffset", Some(u64::from(section.raw_offset)));
        section_json.string(
            "VirtualAddress",
            &format!("0x{:x}", section.virtual_address),
        );
        section_json.bool("Executable", section.characteristics & 0x2000_0000 != 0);
        section_json.bool("Writable", section.characteristics & 0x8000_0000 != 0);
        section_json.bool("Signed", pe_section_has_signed_layout(section));
    }
}

fn add_parse_errors_metadata(pe_json: JsonObject, parse_errors: &[String]) {
    if parse_errors.is_empty() {
        return;
    }
    let Some(errors_json) = pe_json.array("ParseErrors") else {
        return;
    };
    for error in parse_errors {
        errors_json.string_item(error);
    }
}

fn add_elf_metadata(ctx: *mut cli_ctx, analysis: &elf::ElfAnalysis) {
    let Some(root) = (unsafe { current_metadata_json(ctx) }) else {
        return;
    };
    let Some(elf_json) = root.object("ELF") else {
        return;
    };

    elf_json.string(
        "Class",
        if analysis.is_64bit {
            "ELF64"
        } else if analysis.is_32bit {
            "ELF32"
        } else {
            "Unknown"
        },
    );
    if let Some(endian) = analysis.endian {
        elf_json.string("Endian", endian);
    }
    if let Some(elf_type) = analysis.elf_type {
        elf_json.string("Type", elf_type_name(elf_type));
    }
    if let Some(machine) = analysis.machine {
        elf_json.string("Machine", elf_machine_name(machine));
    }
    elf_json.hex_u64_opt("EntryPoint", analysis.entrypoint);
    elf_json.u64_opt(
        "NumberOfProgramHeaders",
        analysis.program_header_count.map(u64::from),
    );
    elf_json.u64_opt(
        "NumberOfSections",
        analysis.section_header_count.map(u64::from),
    );
    elf_json.string("Interpreter", analysis.interpreter.as_deref().unwrap_or(""));
    if let Some(import_md5) = &analysis.import_md5 {
        elf_json.string("ImportMD5", import_md5);
    }
    if let Some(telfhash) = &analysis.telfhash {
        elf_json.string("Telfhash", telfhash);
    }

    if !analysis.needed_libraries.is_empty()
        && let Some(libs_json) = elf_json.array("NeededLibraries")
    {
        for library in &analysis.needed_libraries {
            libs_json.string_item(library);
        }
    }
    add_elf_sections_metadata(elf_json, &analysis.sections);
    add_parse_errors_metadata(elf_json, &analysis.parse_errors);
}

fn add_elf_sections_metadata(elf_json: JsonObject, sections: &[elf::ElfSection]) {
    if sections.is_empty() {
        return;
    }
    let Some(sections_json) = elf_json.array("Sections") else {
        return;
    };
    for section in sections {
        let Some(section_json) = sections_json.object_item() else {
            return;
        };
        if !section.name.is_empty() {
            section_json.string("Name", &section.name);
        }
        section_json.u64_opt("Offset", Some(section.offset));
        section_json.u64_opt("Size", Some(section.size));
        section_json.string("Type", elf_section_type_name(section.section_type));
        section_json.bool("Writable", section.flags & 0x1 != 0);
        section_json.bool("Allocated", section.flags & 0x2 != 0);
        section_json.bool("Executable", section.flags & 0x4 != 0);
    }
}

fn add_macho_metadata(ctx: *mut cli_ctx, analysis: &macho::MachoAnalysis) {
    let Some(root) = (unsafe { current_metadata_json(ctx) }) else {
        return;
    };
    let Some(macho_json) = root.object("MachO") else {
        return;
    };

    macho_json.bool("Universal", analysis.is_universal);
    macho_json.u64_opt("FileCount", Some(analysis.files.len() as u64));
    macho_json.u64_opt("SliceCount", Some(analysis.fat_arches.len() as u64));
    if let Some(hash) = &analysis.dylib_hash {
        macho_json.string("DylibHash", hash);
    }
    if let Some(hash) = &analysis.import_hash {
        macho_json.string("ImportHash", hash);
    }
    if let Some(hash) = &analysis.export_hash {
        macho_json.string("ExportHash", hash);
    }
    if let Some(hash) = &analysis.symhash {
        macho_json.string("Symhash", hash);
    }
    add_macho_files_metadata(macho_json, &analysis.files);
    add_parse_errors_metadata(macho_json, &analysis.parse_errors);
}

fn add_macho_files_metadata(macho_json: JsonObject, files: &[macho::MachoFile]) {
    if files.is_empty() {
        return;
    }
    let Some(files_json) = macho_json.array("Files") else {
        return;
    };
    for file in files {
        let Some(file_json) = files_json.object_item() else {
            return;
        };
        file_json.u64_opt("Offset", Some(file.offset));
        file_json.u64_opt("Size", Some(file.size));
        file_json.string(
            "Class",
            if file.is_64bit {
                "MachO64"
            } else if file.is_32bit {
                "MachO32"
            } else {
                "Unknown"
            },
        );
        file_json.string("Endian", file.endian);
        file_json.string("CpuType", macho_cpu_type_name(file.cpu_type));
        file_json.string("FileType", macho_file_type_name(file.filetype));
        file_json.u64_opt("NumberOfCommands", Some(u64::from(file.command_count)));
        file_json.hex_u64_opt("EntryPoint", file.entrypoint);
        if let Some(uuid) = &file.uuid {
            file_json.string("Uuid", uuid);
        }
        if let Some(dylinker) = &file.dylinker {
            file_json.string("Dylinker", dylinker);
        }
        add_macho_string_array(file_json, "Dylibs", &file.dylibs);
        add_macho_string_array(file_json, "Rpaths", &file.rpaths);
        add_macho_segments_metadata(file_json, &file.segments);
        add_parse_errors_metadata(file_json, &file.parse_errors);
    }
}

fn add_macho_string_array(parent: JsonObject, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let Some(array) = parent.array(key) else {
        return;
    };
    for value in values {
        array.string_item(value);
    }
}

fn add_macho_segments_metadata(file_json: JsonObject, segments: &[macho::MachoSegment]) {
    if segments.is_empty() {
        return;
    }
    let Some(segments_json) = file_json.array("Segments") else {
        return;
    };
    for segment in segments {
        let Some(segment_json) = segments_json.object_item() else {
            return;
        };
        if !segment.name.is_empty() {
            segment_json.string("Name", &segment.name);
        }
        segment_json.hex_u64_opt("VirtualAddress", Some(segment.virtual_address));
        segment_json.u64_opt("VirtualSize", Some(segment.virtual_size));
        segment_json.u64_opt("FileOffset", Some(segment.file_offset));
        segment_json.u64_opt("FileSize", Some(segment.file_size));
    }
}

fn elf_type_name(elf_type: u16) -> &'static str {
    match elf_type {
        0x0 => "None",
        0x1 => "Relocatable",
        0x2 => "Executable",
        0x3 => "SharedObject",
        0x4 => "Core",
        _ => "Unknown",
    }
}

fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        0 => "None",
        2 => "SPARC",
        3 => "Intel 80386",
        4 => "Motorola 68000",
        8 => "MIPS RS3000",
        9 => "IBM System/370",
        15 => "HPPA",
        20 => "PowerPC",
        21 => "PowerPC 64-bit",
        22 => "IBM S390",
        40 => "ARM",
        41 => "Digital Alpha",
        43 => "SPARC v9 64-bit",
        50 => "IA64",
        62 => "AMD x86-64",
        183 => "AArch64",
        _ => "Unknown",
    }
}

fn elf_section_type_name(section_type: u32) -> &'static str {
    match section_type {
        0 => "Null",
        1 => "Program information",
        2 => "Symbol table",
        3 => "String table",
        4 => "Relocation entries with explicit addends",
        6 => "Dynamic linking information",
        7 => "Note section",
        8 => "Empty section",
        9 => "Relocation entries without explicit addends",
        11 => "Symbols for dynamic linking",
        14 => "Array of pointers to initialization functions",
        15 => "Array of pointers to termination functions",
        16 => "Array of pointers to preinit functions",
        0x6fff_fff6 => "Symbol Version Table",
        0x6fff_fffd => "Provided symbol versions",
        0x6fff_fffe => "Required symbol versions",
        0x6fff_ffff => "Symbol hash table",
        _ => "Unknown",
    }
}

fn macho_cpu_type_name(cpu_type: i32) -> &'static str {
    match cpu_type {
        7 => "i386",
        12 => "ARM",
        18 => "PowerPC",
        0x0100_0007 => "x86_64",
        0x0100_000c => "ARM64",
        0x0100_0012 => "PowerPC64",
        _ => "Unknown",
    }
}

fn macho_file_type_name(filetype: u32) -> &'static str {
    match filetype {
        0x1 => "Object",
        0x2 => "Executable",
        0x3 => "FixedVmLibrary",
        0x4 => "Core",
        0x5 => "Preload",
        0x6 => "Dylib",
        0x7 => "Dylinker",
        0x8 => "Bundle",
        0x9 => "DylibStub",
        0xa => "Dsym",
        0xb => "KextBundle",
        _ => "Unknown",
    }
}

fn successful_pe_packer_name(analysis: &pe::PeAnalysis) -> Option<&'static str> {
    analysis
        .unpacked_children
        .iter()
        .find(|child| child.status == "unpacked")
        .map(|child| clamav_packer_name(child.packer))
        .or_else(|| {
            analysis
                .packers
                .first()
                .map(|packer| clamav_packer_name(packer.name))
        })
}

fn clamav_packer_name(name: &str) -> &'static str {
    match name {
        "aspack" => "Aspack",
        "fsg" => "FSG",
        "mew" => "MEW",
        "nspack" => "NsPack",
        "pespin" => "PEspin",
        "petite" => "Petite",
        "upack" => "Upack",
        "upx" => "UPX",
        "wwpack" => "WWPack",
        "yc" => "yC",
        _ => "Unknown",
    }
}

fn pe_section_has_signed_layout(section: &pe::PeSection) -> bool {
    section.virtual_address & 0x8000_0000 != 0
        || section.virtual_size & 0x8000_0000 != 0
        || (section.raw_size != 0 && section.raw_offset & 0x8000_0000 != 0)
        || section.raw_size & 0x8000_0000 != 0
}

fn pe_machine_type_name(machine: u16) -> &'static str {
    match machine {
        0x0000 => "Unknown",
        0x0001 => "Target Host",
        0x014c => "80386",
        0x014d => "80486",
        0x014e => "80586",
        0x0160 => "R3000 MIPS BE",
        0x0162 => "R3000 MIPS LE",
        0x0166 => "R4000 MIPS LE",
        0x0168 => "R10000 MIPS LE",
        0x0169 => "WCE MIPS LE",
        0x0184 => "DEC Alpha AXP",
        0x01a2 => "Hitachi SH3 LE",
        0x01a3 => "Hitachi SH3-DSP",
        0x01a4 => "Hitachi SH3-E LE",
        0x01a6 => "Hitachi SH4 LE",
        0x01a8 => "Hitachi SH5",
        0x01c0 => "ARM LE",
        0x01c2 => "ARM Thumb/Thumb-2 LE",
        0x01c4 => "ARM Thumb-2 LE",
        0x01d3 => "AM33",
        0x01f0 => "PowerPC LE",
        0x01f1 => "PowerPC FP",
        0x0200 => "IA64",
        0x0266 => "MIPS16",
        0x0268 => "M68k",
        0x0284 => "DEC Alpha AXP 64bit",
        0x0366 => "MIPS+FPU",
        0x0466 => "MIPS16+FPU",
        0x0520 => "Infineon TriCore",
        0x0cef => "CEF",
        0x0ebc => "EFI Byte Code",
        0x8664 => "AMD64",
        0x9041 => "M32R",
        0xaa64 => "ARM64 LE",
        0xc0ee => "CEE",
        _ => "Unknown",
    }
}

fn pe_subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native (svc)",
        2 => "Win32 GUI",
        3 => "Win32 console",
        5 => "OS/2 console",
        7 => "POSIX console",
        8 => "Native Win9x driver",
        9 => "WinCE GUI",
        10 => "EFI application",
        11 => "EFI driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM image",
        14 => "Xbox",
        16 => "Boot application",
        _ => "Unknown",
    }
}

#[repr(C)]
struct CliExeInfoPrefix {
    sections: *mut CliExeSection,
    offset: u32,
    ep: u32,
    nsections: u16,
}

impl CliExeInfoPrefix {
    unsafe fn from_raw(ptr: *mut c_void) -> Option<&'static mut Self> {
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { &mut *(ptr.cast::<Self>()) })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliExeSection {
    pub rva: u32,
    pub vsz: u32,
    pub raw: u32,
    pub rsz: u32,
    pub chr: u32,
    pub urva: u32,
    pub uvsz: u32,
    pub uraw: u32,
    pub ursz: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CliMappedRegion {
    offset: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliPeImageFileHdr {
    pub magic: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliPeImageDataDir {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliPeImageOptionalHdr32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliPeImageOptionalHdr64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CliPeHookData {
    pub offset: u32,
    pub ep: u32,
    pub nsections: u16,
    pub dummy: u16,
    pub file_hdr: CliPeImageFileHdr,
    pub opt32: CliPeImageOptionalHdr32,
    pub opt32_dirs: [CliPeImageDataDir; 16],
    pub dummy2: u32,
    pub opt64: CliPeImageOptionalHdr64,
    pub opt64_dirs: [CliPeImageDataDir; 16],
    pub dirs: [CliPeImageDataDir; 16],
    pub e_lfanew: u32,
    pub overlays: u32,
    pub overlays_sz: i32,
    pub hdr_size: u32,
}

fn allocate_target_sections(sections: &[CliExeSection]) -> Option<*mut CliExeSection> {
    if sections.is_empty() {
        return Some(ptr::null_mut());
    }
    let ptr = unsafe {
        cli_max_calloc(sections.len(), std::mem::size_of::<CliExeSection>()).cast::<CliExeSection>()
    };
    if ptr.is_null() {
        return None;
    }
    for (index, section) in sections.iter().copied().enumerate() {
        unsafe { ptr.add(index).write(section) };
    }
    Some(ptr)
}

fn pe_clamav_services_input(
    analysis: &pe::PeAnalysis,
) -> Option<(CliPeHookData, Vec<CliExeSection>)> {
    let sections = pe_target_sections(analysis);
    let mut data_directories = [CliPeImageDataDir::default(); 16];
    for directory in &analysis.data_directories {
        if directory.index < data_directories.len() {
            data_directories[directory.index] = CliPeImageDataDir {
                virtual_address: directory.rva,
                size: directory.size,
            };
        }
    }
    let optional_header_magic = analysis.optional_header_magic?;
    let file_hdr = CliPeImageFileHdr {
        magic: 0x0000_4550,
        machine: analysis.machine?,
        number_of_sections: u16::try_from(sections.len()).ok()?,
        time_date_stamp: analysis.timestamp.unwrap_or_default(),
        pointer_to_symbol_table: analysis.pointer_to_symbol_table.unwrap_or_default(),
        number_of_symbols: analysis.number_of_symbols.unwrap_or_default(),
        size_of_optional_header: analysis.optional_header_size.unwrap_or_default(),
        characteristics: analysis.characteristics.unwrap_or_default(),
    };
    let mut pedata = CliPeHookData {
        ep: u32::try_from(analysis.entrypoint_offset.unwrap_or_default()).ok()?,
        nsections: u16::try_from(sections.len()).ok()?,
        file_hdr,
        dirs: data_directories,
        e_lfanew: analysis.pe_header_offset.unwrap_or_default(),
        overlays: analysis
            .overlay
            .as_ref()
            .and_then(|overlay| u32::try_from(overlay.offset).ok())
            .unwrap_or_default(),
        overlays_sz: analysis
            .overlay
            .as_ref()
            .and_then(|overlay| i32::try_from(overlay.size).ok())
            .unwrap_or_default(),
        hdr_size: analysis.size_of_headers.unwrap_or_default(),
        ..CliPeHookData::default()
    };
    if analysis.is_64bit {
        pedata.opt64 = CliPeImageOptionalHdr64 {
            magic: optional_header_magic,
            major_linker_version: analysis.major_linker_version.unwrap_or_default(),
            minor_linker_version: analysis.minor_linker_version.unwrap_or_default(),
            size_of_code: analysis.size_of_code.unwrap_or_default(),
            size_of_initialized_data: analysis.size_of_initialized_data.unwrap_or_default(),
            size_of_uninitialized_data: analysis.size_of_uninitialized_data.unwrap_or_default(),
            address_of_entry_point: analysis.entrypoint_rva.unwrap_or_default(),
            base_of_code: analysis.base_of_code.unwrap_or_default(),
            image_base: analysis.image_base.unwrap_or_default(),
            section_alignment: analysis.section_alignment.unwrap_or_default(),
            file_alignment: analysis.file_alignment.unwrap_or_default(),
            major_operating_system_version: analysis
                .major_operating_system_version
                .unwrap_or_default(),
            minor_operating_system_version: analysis
                .minor_operating_system_version
                .unwrap_or_default(),
            major_image_version: analysis.major_image_version.unwrap_or_default(),
            minor_image_version: analysis.minor_image_version.unwrap_or_default(),
            major_subsystem_version: analysis.major_subsystem_version.unwrap_or_default(),
            minor_subsystem_version: analysis.minor_subsystem_version.unwrap_or_default(),
            win32_version_value: analysis.win32_version_value.unwrap_or_default(),
            size_of_image: analysis.size_of_image.unwrap_or_default(),
            size_of_headers: analysis.size_of_headers.unwrap_or_default(),
            checksum: analysis.checksum.unwrap_or_default(),
            subsystem: analysis.subsystem.unwrap_or_default(),
            dll_characteristics: analysis.dll_characteristics.unwrap_or_default(),
            size_of_stack_reserve: analysis.size_of_stack_reserve.unwrap_or_default(),
            size_of_stack_commit: analysis.size_of_stack_commit.unwrap_or_default(),
            size_of_heap_reserve: analysis.size_of_heap_reserve.unwrap_or_default(),
            size_of_heap_commit: analysis.size_of_heap_commit.unwrap_or_default(),
            loader_flags: analysis.loader_flags.unwrap_or_default(),
            number_of_rva_and_sizes: analysis.number_of_rva_and_sizes.unwrap_or_default(),
        };
        pedata.opt64_dirs = data_directories;
    } else {
        pedata.opt32 = CliPeImageOptionalHdr32 {
            magic: optional_header_magic,
            major_linker_version: analysis.major_linker_version.unwrap_or_default(),
            minor_linker_version: analysis.minor_linker_version.unwrap_or_default(),
            size_of_code: analysis.size_of_code.unwrap_or_default(),
            size_of_initialized_data: analysis.size_of_initialized_data.unwrap_or_default(),
            size_of_uninitialized_data: analysis.size_of_uninitialized_data.unwrap_or_default(),
            address_of_entry_point: analysis.entrypoint_rva.unwrap_or_default(),
            base_of_code: analysis.base_of_code.unwrap_or_default(),
            base_of_data: analysis.base_of_data.unwrap_or_default(),
            image_base: u32::try_from(analysis.image_base.unwrap_or_default()).unwrap_or_default(),
            section_alignment: analysis.section_alignment.unwrap_or_default(),
            file_alignment: analysis.file_alignment.unwrap_or_default(),
            major_operating_system_version: analysis
                .major_operating_system_version
                .unwrap_or_default(),
            minor_operating_system_version: analysis
                .minor_operating_system_version
                .unwrap_or_default(),
            major_image_version: analysis.major_image_version.unwrap_or_default(),
            minor_image_version: analysis.minor_image_version.unwrap_or_default(),
            major_subsystem_version: analysis.major_subsystem_version.unwrap_or_default(),
            minor_subsystem_version: analysis.minor_subsystem_version.unwrap_or_default(),
            win32_version_value: analysis.win32_version_value.unwrap_or_default(),
            size_of_image: analysis.size_of_image.unwrap_or_default(),
            size_of_headers: analysis.size_of_headers.unwrap_or_default(),
            checksum: analysis.checksum.unwrap_or_default(),
            subsystem: analysis.subsystem.unwrap_or_default(),
            dll_characteristics: analysis.dll_characteristics.unwrap_or_default(),
            size_of_stack_reserve: u32::try_from(
                analysis.size_of_stack_reserve.unwrap_or_default(),
            )
            .unwrap_or_default(),
            size_of_stack_commit: u32::try_from(analysis.size_of_stack_commit.unwrap_or_default())
                .unwrap_or_default(),
            size_of_heap_reserve: u32::try_from(analysis.size_of_heap_reserve.unwrap_or_default())
                .unwrap_or_default(),
            size_of_heap_commit: u32::try_from(analysis.size_of_heap_commit.unwrap_or_default())
                .unwrap_or_default(),
            loader_flags: analysis.loader_flags.unwrap_or_default(),
            number_of_rva_and_sizes: analysis.number_of_rva_and_sizes.unwrap_or_default(),
        };
        pedata.opt32_dirs = data_directories;
    }
    Some((pedata, sections))
}

fn pe_target_sections(analysis: &pe::PeAnalysis) -> Vec<CliExeSection> {
    analysis
        .sections
        .iter()
        .map(|section| CliExeSection {
            rva: section.virtual_address,
            vsz: section.virtual_size,
            raw: section.raw_offset,
            rsz: section.raw_size,
            chr: section.characteristics,
            urva: section.virtual_address,
            uvsz: section.virtual_size,
            uraw: section.raw_offset,
            ursz: section.raw_size,
        })
        .collect()
}

fn cstring_opt(value: Option<&str>) -> Option<CString> {
    value.and_then(|value| CString::new(value).ok())
}

struct PeTargetInfoInput {
    sections: Vec<CliExeSection>,
    ep: u32,
    res_addr: u32,
    hdr_size: u32,
    vep: u32,
    ndatadirs: u32,
    is_dll: bool,
    is_pe32plus: bool,
    e_lfanew: u32,
    min: u32,
    max: u32,
    overlay_start: u32,
    overlay_size: u32,
    dirs: [CliPeImageDataDir; 16],
    version_offsets: Vec<u32>,
}

fn pe_target_info_input(bytes: &[u8], analysis: &pe::PeAnalysis) -> Option<PeTargetInfoInput> {
    let sections = pe_target_sections(analysis);
    let mut dirs = [CliPeImageDataDir::default(); 16];
    for directory in &analysis.data_directories {
        if directory.index < dirs.len() {
            dirs[directory.index] = CliPeImageDataDir {
                virtual_address: directory.rva,
                size: directory.size,
            };
        }
    }
    let min = sections
        .iter()
        .filter(|section| section.rva != 0)
        .map(|section| section.rva)
        .min()
        .unwrap_or_default();
    let max = sections
        .iter()
        .filter_map(|section| section.rva.checked_add(section.vsz))
        .max()
        .unwrap_or_default();
    let resource_dir = dirs.get(2).copied().unwrap_or_default();
    let res_addr = if analysis.is_dll || resource_dir.size == 0 {
        0
    } else {
        resource_dir.virtual_address
    };
    Some(PeTargetInfoInput {
        sections,
        ep: u32::try_from(analysis.entrypoint_offset.unwrap_or_default()).ok()?,
        res_addr,
        hdr_size: analysis.size_of_headers.unwrap_or_default(),
        vep: analysis.entrypoint_rva.unwrap_or_default(),
        ndatadirs: analysis.number_of_rva_and_sizes.unwrap_or_default(),
        is_dll: analysis.is_dll,
        is_pe32plus: analysis.is_64bit,
        e_lfanew: analysis.pe_header_offset.unwrap_or_default(),
        min,
        max,
        overlay_start: analysis
            .overlay
            .as_ref()
            .and_then(|overlay| u32::try_from(overlay.offset).ok())
            .unwrap_or_default(),
        overlay_size: analysis
            .overlay
            .as_ref()
            .and_then(|overlay| u32::try_from(overlay.size).ok())
            .unwrap_or_default(),
        dirs,
        version_offsets: pe_version_info_string_offsets(bytes, analysis),
    })
}

const MAX_PE_VERSION_INFO_OFFSETS: usize = 512;
const CL_GENHASH_PE_CLASS_SECTION: u32 = 0;
const CL_GENHASH_PE_CLASS_IMPTBL: u32 = 1;
const CLI_HASH_MD5: u32 = 0;
const CLI_HASH_SHA1: u32 = 1;
const CLI_HASH_SHA2_256: u32 = 2;
const CLI_HASH_AVAIL_TYPES: u32 = CLI_HASH_SHA2_256 + 1;
const CLI_MAX_ALLOCATION: u32 = 1024 * 1024 * 1024;
const PE_CONF_CERTS: u32 = 0x20000;
const ENGINE_OPTIONS_DISABLE_PE_CERTS: u64 = 0x8;
const PE_AUTH_CERTIFICATE_DIRECTORY_INDEX: usize = 4;
const PE_AUTH_FILE_HEADER_SIZE: u32 = 24;
const PE_AUTH_OPTIONAL_CHECKSUM_OFFSET: u32 = 64;
const PE_AUTH_OPTIONAL_HEADER32_BASE_SIZE: u32 = 96;
const PE_AUTH_OPTIONAL_HEADER64_BASE_SIZE: u32 = 112;
const PE_AUTH_DATA_DIRECTORY_SIZE: u32 = 8;
const PE_AUTH_CHECKSUM_SIZE: u32 = 4;
const PE_AUTH_CERTIFICATE_HEADER_SIZE: u32 = 8;
const WIN_CERT_REV_2: u16 = 0x0200;
const WIN_CERT_TYPE_PKCS7: u16 = 0x0002;

/// Check PE Authenticode signatures and catalog hashes using Rust PE header facts.
///
/// The ASN.1 certificate trust/block-list parser remains a C service for now,
/// but PE-specific certificate-table validation and catalog hash construction
/// live here so the legacy PE parser is no longer needed for trust decisions.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context for the current PE layer.
/// `peinfo` is accepted for C ABI compatibility but is not dereferenced; Rust
/// reparses the current fmap to avoid depending on legacy C PE structs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_check_auth_header(
    ctx: *mut cli_ctx,
    _peinfo: *mut c_void,
) -> cl_error_t {
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    let Some(dconf) = (unsafe { ctx_ref.dconf.as_ref() }) else {
        return cl_error_t_CL_EVERIFY;
    };
    if dconf.pe & PE_CONF_CERTS == 0 {
        return cl_error_t_CL_EVERIFY;
    }
    let Some(engine) = (unsafe { ctx_ref.engine.as_ref() }) else {
        return cl_error_t_CL_EVERIFY;
    };
    if engine.engine_options & ENGINE_OPTIONS_DISABLE_PE_CERTS != 0 {
        return cl_error_t_CL_EVERIFY;
    }

    let Ok(fmap) = FMap::try_from(ctx_ref.fmap) else {
        return cl_error_t_CL_EFORMAT;
    };
    let Ok(bytes) = fmap.need_off(0, fmap.len()) else {
        return cl_error_t_CL_EFORMAT;
    };
    let analysis = pe::analyze_with_options(
        bytes,
        PeAnalysisOptions {
            probe_overlay_children: false,
            section_hashes: pe::PeHashAlgorithmSet::default(),
            import_table_hashes: pe::PeHashAlgorithmSet::default(),
            calculate_imphash: false,
            calculate_checksum: false,
        },
    );
    if !analysis.is_pe {
        return cl_error_t_CL_EFORMAT;
    }

    let Some(layout) = pe_authenticode_layout(bytes.len(), &analysis) else {
        return cl_error_t_CL_EFORMAT;
    };
    let Some(sec_dir) = pe_authenticode_certificate_directory(&analysis) else {
        if !catalog_hashes_configured(engine.hm_fp) {
            return cl_error_t_CL_BREAK;
        }
        return pe_check_catalog_hashes(ctx, engine.hm_fp, &fmap, &layout.regions);
    };

    if sec_dir.size < PE_AUTH_CERTIFICATE_HEADER_SIZE && !catalog_hashes_configured(engine.hm_fp) {
        return cl_error_t_CL_BREAK;
    }

    let mut regions = layout.regions;
    if sec_dir.rva != 0 {
        let Some(ret) = pe_check_embedded_authenticode(
            ctx,
            ctx_ref.fmap,
            engine,
            &fmap,
            sec_dir,
            &mut regions,
            layout.after_security_directory,
        ) else {
            return cl_error_t_CL_EFORMAT;
        };
        if ret == cl_error_t_CL_VERIFIED || ret == cl_error_t_CL_VIRUS {
            return ret;
        }
    }

    pe_check_catalog_hashes(ctx, engine.hm_fp, &fmap, &regions)
}

struct PeAuthenticodeLayout {
    regions: Vec<CliMappedRegion>,
    after_security_directory: u32,
}

fn pe_authenticode_layout(
    file_size: usize,
    analysis: &pe::PeAnalysis,
) -> Option<PeAuthenticodeLayout> {
    let pe_header_offset = analysis.pe_header_offset?;
    let optional_base_size = if analysis.is_64bit {
        PE_AUTH_OPTIONAL_HEADER64_BASE_SIZE
    } else {
        PE_AUTH_OPTIONAL_HEADER32_BASE_SIZE
    };

    let checksum_start = pe_header_offset
        .checked_add(PE_AUTH_FILE_HEADER_SIZE)?
        .checked_add(PE_AUTH_OPTIONAL_CHECKSUM_OFFSET)?;
    let after_checksum = checksum_start.checked_add(PE_AUTH_CHECKSUM_SIZE)?;
    let data_directory_start = after_checksum.checked_add(
        optional_base_size
            .checked_sub(PE_AUTH_OPTIONAL_CHECKSUM_OFFSET)?
            .checked_sub(PE_AUTH_CHECKSUM_SIZE)?,
    )?;
    let security_directory_start = data_directory_start.checked_add(
        (PE_AUTH_CERTIFICATE_DIRECTORY_INDEX as u32).checked_mul(PE_AUTH_DATA_DIRECTORY_SIZE)?,
    )?;
    let after_security_directory =
        security_directory_start.checked_add(PE_AUTH_DATA_DIRECTORY_SIZE)?;

    if after_security_directory > analysis.size_of_headers? {
        return None;
    }

    let mut regions = Vec::with_capacity(4);
    push_auth_region(&mut regions, 0, checksum_start)?;
    push_auth_region(
        &mut regions,
        after_checksum,
        security_directory_start.checked_sub(after_checksum)?,
    )?;

    if let Some(sec_dir) = pe_authenticode_certificate_directory(analysis) {
        if sec_dir.rva == 0 {
            let file_size = u32::try_from(file_size).ok()?;
            if after_security_directory < file_size {
                push_auth_region(
                    &mut regions,
                    after_security_directory,
                    file_size.checked_sub(after_security_directory)?,
                )?;
            }
        }
    } else {
        let file_size = u32::try_from(file_size).ok()?;
        if after_security_directory < file_size {
            push_auth_region(
                &mut regions,
                after_security_directory,
                file_size.checked_sub(after_security_directory)?,
            )?;
        }
    }

    Some(PeAuthenticodeLayout {
        regions,
        after_security_directory,
    })
}

fn pe_authenticode_certificate_directory(
    analysis: &pe::PeAnalysis,
) -> Option<&pe::PeDataDirectory> {
    analysis
        .data_directories
        .iter()
        .find(|directory| directory.index == PE_AUTH_CERTIFICATE_DIRECTORY_INDEX)
}

fn push_auth_region(regions: &mut Vec<CliMappedRegion>, offset: u32, size: u32) -> Option<()> {
    if size == 0 {
        return Some(());
    }
    regions.push(CliMappedRegion { offset, size });
    Some(())
}

fn catalog_hashes_configured(matcher: *const cli_matcher) -> bool {
    !matcher.is_null()
        && (unsafe { cli_hm_have_size(matcher, CLI_HASH_SHA1, 2) }
            || unsafe { cli_hm_have_size(matcher, CLI_HASH_SHA2_256, 2) })
}

fn pe_check_embedded_authenticode(
    ctx: *mut cli_ctx,
    map: *mut cl_fmap_t,
    engine: &crate::sys::cl_engine,
    fmap: &FMap,
    sec_dir: &pe::PeDataDirectory,
    regions: &mut Vec<CliMappedRegion>,
    after_security_directory: u32,
) -> Option<cl_error_t> {
    let sec_dir_offset = usize::try_from(sec_dir.rva).ok()?;
    let sec_dir_size = usize::try_from(sec_dir.size).ok()?;
    if fmap.len() != sec_dir_offset.checked_add(sec_dir_size)? {
        debug!("cli_check_auth_header: expected authenticode data at the end of the file");
        return None;
    }
    if after_security_directory < sec_dir.rva {
        push_auth_region(
            regions,
            after_security_directory,
            sec_dir.rva.checked_sub(after_security_directory)?,
        )?;
    } else if after_security_directory > sec_dir.rva {
        debug!(
            "cli_check_auth_header: security directory offset appears to overlap with the PE header"
        );
        return None;
    }

    let header = fmap
        .need_off(
            sec_dir_offset,
            usize::try_from(PE_AUTH_CERTIFICATE_HEADER_SIZE).ok()?,
        )
        .ok()?;
    let declared_len = read_u32_from_slice(header, 0)?;
    let revision = read_u16_from_slice(header, 4)?;
    let certificate_type = read_u16_from_slice(header, 6)?;
    if revision != WIN_CERT_REV_2 {
        debug!("cli_check_auth_header: unsupported authenticode data revision");
        return None;
    }
    if certificate_type != WIN_CERT_TYPE_PKCS7 {
        debug!("cli_check_auth_header: unsupported authenticode data type");
        return None;
    }
    if declared_len != sec_dir.size {
        debug!(
            "cli_check_auth_header: MS13-098 violation detected, but continuing on to verify certificate"
        );
    }

    let content_offset =
        sec_dir_offset.checked_add(usize::try_from(PE_AUTH_CERTIFICATE_HEADER_SIZE).ok()?)?;
    let content_size = sec_dir.size.checked_sub(PE_AUTH_CERTIFICATE_HEADER_SIZE)?;
    let mut c_regions = regions.clone();
    Some(unsafe {
        asn1_check_mscat(
            (engine as *const crate::sys::cl_engine).cast_mut(),
            map,
            content_offset,
            content_size,
            c_regions.as_mut_ptr(),
            u32::try_from(c_regions.len()).ok()?,
            ctx,
        )
    })
}

fn pe_check_catalog_hashes(
    ctx: *mut cli_ctx,
    matcher: *const cli_matcher,
    fmap: &FMap,
    regions: &[CliMappedRegion],
) -> cl_error_t {
    if matcher.is_null() {
        return cl_error_t_CL_EVERIFY;
    }

    for (hash_type, hash_name) in [(CLI_HASH_SHA1, "sha1"), (CLI_HASH_SHA2_256, "sha2-256")] {
        if !unsafe { cli_hm_have_size(matcher, hash_type, 2) } {
            continue;
        }
        let Some(digest) = pe_authenticode_digest(hash_type, fmap, regions) else {
            return cl_error_t_CL_EVERIFY;
        };
        if unsafe { cli_hm_scan(digest.as_ptr(), 2, ptr::null_mut(), matcher, hash_type) }
            == cl_error_t_CL_VIRUS
        {
            debug!("cli_check_auth_header: PE file trusted by catalog file ({hash_name})");
            let Ok(source) = CString::new(format!("authenticode catalog file: {hash_name}")) else {
                return cl_error_t_CL_EMEM;
            };
            unsafe {
                let _ = cli_trust_this_layer(ctx, source.as_ptr());
            }
            return cl_error_t_CL_VERIFIED;
        }
    }

    cl_error_t_CL_EVERIFY
}

fn pe_authenticode_digest(
    hash_type: u32,
    fmap: &FMap,
    regions: &[CliMappedRegion],
) -> Option<Vec<u8>> {
    match hash_type {
        CLI_HASH_SHA1 => {
            let mut hasher = Sha1::new();
            for region in regions {
                if region.size == 0 {
                    continue;
                }
                hasher.update(
                    fmap.need_off(
                        usize::try_from(region.offset).ok()?,
                        usize::try_from(region.size).ok()?,
                    )
                    .ok()?,
                );
            }
            Some(hasher.finalize().to_vec())
        }
        CLI_HASH_SHA2_256 => {
            let mut hasher = Sha256::new();
            for region in regions {
                if region.size == 0 {
                    continue;
                }
                hasher.update(
                    fmap.need_off(
                        usize::try_from(region.offset).ok()?,
                        usize::try_from(region.size).ok()?,
                    )
                    .ok()?,
                );
            }
            Some(hasher.finalize().to_vec())
        }
        _ => None,
    }
}

fn read_u16_from_slice(bytes: &[u8], offset: usize) -> Option<u16> {
    let array: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

fn read_u32_from_slice(bytes: &[u8], offset: usize) -> Option<u32> {
    let array: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

/// Scan one PE section against ClamAV MDB section-hash signatures.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context, `map` must be the active
/// layer fmap, and `section` must point to a valid `struct cli_exe_section`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_pe_section_hash_rust(
    ctx: *mut cli_ctx,
    map: *mut cl_fmap_t,
    section: *const c_void,
) -> cl_error_t {
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    let Some(engine) = (unsafe { ctx_ref.engine.as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    let matcher = engine.hm_mdb;
    if matcher.is_null() {
        return cl_error_t_CL_SUCCESS;
    }
    let Some(section) = (unsafe { section.cast::<CliExeSection>().as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    if section.rsz == 0 {
        return cl_error_t_CL_SUCCESS;
    }
    if section.rsz > CLI_MAX_ALLOCATION {
        debug!("scan_pe_section_hash_rust: skipping hash calculation for too big section");
        return cl_error_t_CL_SUCCESS;
    }

    let Ok(fmap) = FMap::try_from(map) else {
        return cl_error_t_CL_ERROR;
    };
    let section_bytes = match fmap.need_off(
        usize::try_from(section.raw).unwrap_or(usize::MAX),
        usize::try_from(section.rsz).unwrap_or(usize::MAX),
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            debug!("scan_pe_section_hash_rust: unable to read section data: {error}");
            return cl_error_t_CL_SUCCESS;
        }
    };

    for hash_type in CLI_HASH_MD5..CLI_HASH_AVAIL_TYPES {
        let found_size = unsafe { cli_hm_have_size(matcher, hash_type, section.rsz) };
        let found_wild = unsafe { cli_hm_have_wild(matcher, hash_type) };
        if !found_size && !found_wild {
            continue;
        }
        let digest = digest_for_hash_type(hash_type, section_bytes);
        let ret = unsafe {
            scan_hash_digest(
                ctx,
                matcher,
                &digest,
                section.rsz,
                hash_type,
                found_size,
                found_wild,
            )
        };
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    cl_error_t_CL_SUCCESS
}

/// Scan Rust-computed PE import table hashes against ClamAV IMP signatures.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context. Hash pointers, when non-null,
/// must point to NUL-terminated lowercase or uppercase hexadecimal digests.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_pe_import_hashes_rust(
    ctx: *mut cli_ctx,
    md5_hex: *const c_char,
    sha1_hex: *const c_char,
    sha256_hex: *const c_char,
    import_hash_size: u32,
) -> cl_error_t {
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    let Some(engine) = (unsafe { ctx_ref.engine.as_ref() }) else {
        return cl_error_t_CL_EARG;
    };
    let matcher = engine.hm_imp;
    if matcher.is_null() {
        return cl_error_t_CL_SUCCESS;
    }

    for hash_type in CLI_HASH_MD5..CLI_HASH_AVAIL_TYPES {
        if !unsafe { cli_hm_have_any(matcher, hash_type) } {
            continue;
        }
        let Some(digest) = decode_hex_digest(
            hash_hex_pointer(hash_type, md5_hex, sha1_hex, sha256_hex),
            hash_type,
        ) else {
            continue;
        };
        let ret = unsafe {
            scan_hash_digest(
                ctx,
                matcher,
                &digest,
                import_hash_size,
                hash_type,
                true,
                true,
            )
        };
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    cl_error_t_CL_SUCCESS
}

fn digest_for_hash_type(hash_type: u32, bytes: &[u8]) -> Vec<u8> {
    match hash_type {
        CLI_HASH_MD5 => Md5::digest(bytes).to_vec(),
        CLI_HASH_SHA1 => Sha1::digest(bytes).to_vec(),
        CLI_HASH_SHA2_256 => Sha256::digest(bytes).to_vec(),
        _ => Vec::new(),
    }
}

fn hash_digest_len(hash_type: u32) -> Option<usize> {
    Some(match hash_type {
        CLI_HASH_MD5 => 16,
        CLI_HASH_SHA1 => 20,
        CLI_HASH_SHA2_256 => 32,
        _ => return None,
    })
}

fn hash_hex_pointer(
    hash_type: u32,
    md5_hex: *const c_char,
    sha1_hex: *const c_char,
    sha256_hex: *const c_char,
) -> *const c_char {
    match hash_type {
        CLI_HASH_MD5 => md5_hex,
        CLI_HASH_SHA1 => sha1_hex,
        CLI_HASH_SHA2_256 => sha256_hex,
        _ => ptr::null(),
    }
}

fn decode_hex_digest(hex: *const c_char, hash_type: u32) -> Option<Vec<u8>> {
    let digest_len = hash_digest_len(hash_type)?;
    if hex.is_null() {
        return None;
    }
    let hex = unsafe { CStr::from_ptr(hex) }.to_bytes();
    if hex.len() != digest_len.checked_mul(2)? {
        return None;
    }

    let mut digest = Vec::with_capacity(digest_len);
    for chunk in hex.chunks_exact(2) {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        digest.push((high << 4) | low);
    }
    Some(digest)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

unsafe fn scan_hash_digest(
    ctx: *mut cli_ctx,
    matcher: *const cli_matcher,
    digest: &[u8],
    size: u32,
    hash_type: u32,
    scan_sized: bool,
    scan_wild: bool,
) -> cl_error_t {
    let mut virname: *const c_char = ptr::null();
    if scan_sized
        && unsafe { cli_hm_scan(digest.as_ptr(), size, &mut virname, matcher, hash_type) }
            == cl_error_t_CL_VIRUS
    {
        let ret = unsafe { crate::sys::cli_append_virus(ctx, virname) };
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    if scan_wild
        && unsafe { cli_hm_scan_wild(digest.as_ptr(), &mut virname, matcher, hash_type) }
            == cl_error_t_CL_VIRUS
    {
        let ret = unsafe { crate::sys::cli_append_virus(ctx, virname) };
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    cl_error_t_CL_SUCCESS
}

/// Generate PE section or import-table hashes through the Rust parser.
///
/// This preserves the public C `cli_genhash_pe()` surface while avoiding a
/// legacy C PE header parse just to populate section and import facts.
///
/// # Safety
///
/// `ctx` must be a valid ClamAV scanner context.
pub unsafe fn genhash_pe(ctx: *mut cli_ctx, class: u32, hash_type: u32) -> cl_error_t {
    let Some(algorithm) = pe_hash_algorithm_set(hash_type) else {
        debug!("cli_genhash_pe: Invalid hash type {hash_type}");
        return cl_error_t_CL_EARG;
    };
    let Some(fmap) = (unsafe { current_fmap(ctx, "genhash_pe") }) else {
        return cl_error_t_CL_ERROR;
    };
    let Some(bytes) = full_fmap_bytes(&fmap, "genhash_pe") else {
        return cl_error_t_CL_ERROR;
    };
    if !pe::has_dos_magic(bytes) {
        return cl_error_t_CL_EFORMAT;
    }

    let analysis = pe::analyze_with_options(
        bytes,
        PeAnalysisOptions {
            probe_overlay_children: false,
            calculate_checksum: false,
            section_hashes: if class == CL_GENHASH_PE_CLASS_SECTION {
                algorithm
            } else {
                pe::PeHashAlgorithmSet::default()
            },
            import_table_hashes: if class == CL_GENHASH_PE_CLASS_IMPTBL {
                algorithm
            } else {
                pe::PeHashAlgorithmSet::default()
            },
            calculate_imphash: false,
        },
    );
    if !analysis.is_pe {
        return cl_error_t_CL_EFORMAT;
    }

    match class {
        CL_GENHASH_PE_CLASS_SECTION => {
            let mut sections: Vec<_> = analysis.sections.iter().collect();
            sections.sort_by_key(|section| section.raw_offset);
            for (index, section) in sections.into_iter().enumerate() {
                if let Some(hash) = pe_hash_for_type(
                    section.md5.as_deref(),
                    section.sha1.as_deref(),
                    section.sha256.as_deref(),
                    hash_type,
                ) {
                    debug!("Section{{{index}}}: {}:{hash}", section.raw_size);
                } else if section.raw_size != 0 {
                    debug!("Section{{{index}}}: failed to generate hash for section");
                } else {
                    debug!("Section{{{index}}}: section contains no data");
                }
            }
        }
        CL_GENHASH_PE_CLASS_IMPTBL => {
            if let Some(hashes) = analysis.import_hashes.as_ref()
                && let Some(hash) = pe_hash_for_type(
                    hashes.md5.as_deref(),
                    hashes.sha1.as_deref(),
                    hashes.sha256.as_deref(),
                    hash_type,
                )
            {
                debug!("Imphash: {hash}:{}", hashes.size);
            } else {
                debug!(
                    "Imphash: failed to generate hash for import table ({cl_error_t_CL_EFORMAT})"
                );
            }
        }
        _ => {
            debug!("cli_genhash_pe: unknown pe genhash class: {class}");
        }
    }

    cl_error_t_CL_SUCCESS
}

fn pe_hash_algorithm_set(hash_type: u32) -> Option<pe::PeHashAlgorithmSet> {
    Some(match hash_type {
        CLI_HASH_MD5 => pe::PeHashAlgorithmSet {
            md5: true,
            ..pe::PeHashAlgorithmSet::default()
        },
        CLI_HASH_SHA1 => pe::PeHashAlgorithmSet {
            sha1: true,
            ..pe::PeHashAlgorithmSet::default()
        },
        CLI_HASH_SHA2_256 => pe::PeHashAlgorithmSet {
            sha256: true,
            ..pe::PeHashAlgorithmSet::default()
        },
        _ => return None,
    })
}

fn pe_hash_for_type<'a>(
    md5: Option<&'a str>,
    sha1: Option<&'a str>,
    sha256: Option<&'a str>,
    hash_type: u32,
) -> Option<&'a str> {
    match hash_type {
        CLI_HASH_MD5 => md5,
        CLI_HASH_SHA1 => sha1,
        CLI_HASH_SHA2_256 => sha256,
        _ => None,
    }
}

fn pe_version_info_string_offsets(bytes: &[u8], analysis: &pe::PeAnalysis) -> Vec<u32> {
    let mut offsets = Vec::new();
    for resource in &analysis.resources {
        if resource.type_id != Some(16) {
            continue;
        }
        let Some(start) = resource
            .file_offset
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        let Ok(size) = usize::try_from(resource.size) else {
            continue;
        };
        if start.checked_add(size).is_none_or(|end| end > bytes.len()) {
            continue;
        }
        parse_version_info_resource(bytes, start, size, &mut offsets);
        if offsets.len() >= MAX_PE_VERSION_INFO_OFFSETS {
            break;
        }
    }
    offsets
}

fn parse_version_info_resource(bytes: &[u8], start: usize, size: usize, offsets: &mut Vec<u32>) {
    let end = start.saturating_add(size).min(bytes.len());
    let cursor = start;
    if end.saturating_sub(cursor) <= 4 {
        return;
    }
    let Some(vinfo_size) = read_u16_at(bytes, cursor).map(usize::from) else {
        return;
    };
    let Some(vinfo_value_size) = read_u16_at(bytes, cursor + 2).map(usize::from) else {
        return;
    };
    if vinfo_size > end.saturating_sub(cursor)
        || vinfo_size <= 0x5c
        || vinfo_value_size != 0x34
        || bytes.get(cursor + 6..cursor + 0x26) != Some(VS_VERSION_INFO_KEY)
        || read_u32_at(bytes, cursor + 0x28) != Some(0xfeef_04bd)
    {
        return;
    }

    let child_start = cursor + 0x5c;
    let child_end = cursor + vinfo_size;
    parse_version_info_children(bytes, child_start, child_end, offsets);
}

fn parse_version_info_children(
    bytes: &[u8],
    mut cursor: usize,
    end: usize,
    offsets: &mut Vec<u32>,
) {
    let mut remaining = end.saturating_sub(cursor);
    let mut got_var_file_info = false;
    while remaining > 6 {
        let Some(sfi_size) = read_u16_at(bytes, cursor).map(usize::from) else {
            break;
        };
        if sfi_size > remaining {
            break;
        }
        if !got_var_file_info
            && sfi_size > 0x1e
            && bytes.get(cursor + 6..cursor + 0x1e) == Some(VAR_FILE_INFO_KEY)
        {
            cursor = cursor.saturating_add(sfi_size);
            remaining = remaining.saturating_sub(sfi_size);
            got_var_file_info = true;
            continue;
        }
        if sfi_size <= 0x24 || bytes.get(cursor + 6..cursor + 0x24) != Some(STRING_FILE_INFO_KEY) {
            break;
        }
        parse_string_file_info(bytes, cursor + 0x24, sfi_size - 0x24, offsets);
        break;
    }
}

fn parse_string_file_info(
    bytes: &[u8],
    mut cursor: usize,
    mut remaining: usize,
    offsets: &mut Vec<u32>,
) {
    while remaining > 6 && offsets.len() < MAX_PE_VERSION_INFO_OFFSETS {
        let Some(table_size) = read_u16_at(bytes, cursor).map(usize::from) else {
            break;
        };
        let next_cursor = cursor.saturating_add(table_size);
        let next_remaining = remaining.saturating_sub(table_size);
        if table_size > remaining || table_size <= 24 {
            break;
        }
        parse_string_table(bytes, cursor + 24, table_size - 24, offsets);
        cursor = next_cursor;
        remaining = next_remaining;
    }
}

fn parse_string_table(
    bytes: &[u8],
    mut cursor: usize,
    mut remaining: usize,
    offsets: &mut Vec<u32>,
) {
    while remaining > 6 && offsets.len() < MAX_PE_VERSION_INFO_OFFSETS {
        let Some(raw_string_size) = read_u16_at(bytes, cursor).map(usize::from) else {
            break;
        };
        let string_size = align_up_usize(raw_string_size, 4);
        if string_size > remaining || string_size <= 16 {
            break;
        }
        let mut key_size = 6usize;
        while key_size + 1 < string_size {
            if bytes.get(cursor + key_size) == Some(&0)
                && bytes.get(cursor + key_size + 1) == Some(&0)
            {
                key_size += 2;
                break;
            }
            key_size += 2;
        }
        key_size = align_up_usize(key_size, 4);
        if key_size < string_size
            && string_size.saturating_sub(key_size) > 2
            && let Some(offset) = cursor
                .checked_add(6)
                .and_then(|offset| u32::try_from(offset).ok())
        {
            offsets.push(offset);
        }
        cursor = cursor.saturating_add(string_size);
        remaining = remaining.saturating_sub(string_size);
    }
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn align_up_usize(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    value.saturating_add(alignment - 1) / alignment * alignment
}

const VS_VERSION_INFO_KEY: &[u8] = b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0";
const VAR_FILE_INFO_KEY: &[u8] = b"V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0";
const STRING_FILE_INFO_KEY: &[u8] = b"S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0";

fn elf_target_sections(analysis: &elf::ElfAnalysis) -> Option<Vec<CliExeSection>> {
    analysis
        .sections
        .iter()
        .map(|section| {
            Some(CliExeSection {
                rva: u32::try_from(section.address).ok()?,
                raw: u32::try_from(section.offset).ok()?,
                rsz: u32::try_from(section.size).ok()?,
                ..CliExeSection::default()
            })
        })
        .collect()
}

fn elf_entry_file_offset(analysis: &elf::ElfAnalysis) -> Option<u32> {
    let entrypoint = analysis.entrypoint?;
    if entrypoint == 0 {
        return Some(0);
    }
    for segment in &analysis.segments {
        let end = segment.virtual_address.checked_add(segment.memory_size)?;
        if segment.virtual_address <= entrypoint && entrypoint < end {
            let relative = entrypoint.checked_sub(segment.virtual_address)?;
            let file_offset = segment.offset.checked_add(relative)?;
            return u32::try_from(file_offset).ok();
        }
    }
    None
}

fn macho_target_sections(file: &macho::MachoFile) -> Option<Vec<CliExeSection>> {
    file.sections
        .iter()
        .map(|section| {
            let alignment = macho_section_alignment(section.align)?;
            let size = section.size;
            let aligned_size = if alignment == 0 {
                size
            } else {
                size.checked_add((alignment - (size % alignment)) % alignment)?
            };
            Some(CliExeSection {
                rva: u32::try_from(section.address).ok()?,
                vsz: u32::try_from(section.size).ok()?,
                raw: section.offset,
                rsz: u32::try_from(aligned_size).ok()?,
                ..CliExeSection::default()
            })
        })
        .collect()
}

fn macho_section_alignment(align_exponent: u32) -> Option<u64> {
    if align_exponent >= 32 {
        return None;
    }
    Some(1u64 << align_exponent)
}

fn macho_entry_file_offset(file: &macho::MachoFile) -> Option<u32> {
    let entrypoint = file.entrypoint?;
    for section in &file.sections {
        let end = section.address.checked_add(section.size)?;
        if section.address <= entrypoint && entrypoint < end {
            let relative = entrypoint.checked_sub(section.address)?;
            let file_offset = u64::from(section.offset).checked_add(relative)?;
            return u32::try_from(file_offset).ok();
        }
    }

    // LC_MAIN stores an entry offset rather than a virtual address. The legacy
    // C parser did not understand LC_MAIN, but preserving it here makes modern
    // Mach-O target-info useful without disturbing LC_THREAD conversion above.
    u32::try_from(entrypoint).ok()
}

unsafe fn current_metadata_json(ctx: *mut cli_ctx) -> Option<JsonObject> {
    if ctx.is_null() {
        return None;
    }
    let root = unsafe { (*ctx).this_layer_metadata_json };
    unsafe { JsonObject::from_raw(root) }
}

unsafe fn current_fmap(ctx: *mut cli_ctx, scanner_name: &'static str) -> Option<FMap> {
    Some(match unsafe { ctx::current_fmap(ctx) } {
        Ok(fmap) => fmap,
        Err(error) => {
            warn!("{scanner_name}: failed to get current fmap: {error}");
            return None;
        }
    })
}

fn full_fmap_bytes<'a>(fmap: &'a FMap, scanner_name: &'static str) -> Option<&'a [u8]> {
    let bytes = match fmap.need_off(0, fmap.len()) {
        Ok(bytes) => bytes,
        Err(error) => {
            error!(
                "{scanner_name}: failed to borrow full fmap bytes for {} bytes: {error}",
                fmap.len()
            );
            return None;
        }
    };
    Some(bytes)
}

unsafe fn scan_parent_range(
    ctx: *mut cli_ctx,
    fmap: *mut cl_fmap_t,
    offset: u64,
    size: u64,
    type_: cli_file_t,
    name: Option<&str>,
) -> cl_error_t {
    let Ok(offset) = usize::try_from(offset) else {
        return cl_error_t_CL_SUCCESS;
    };
    let Ok(size) = usize::try_from(size) else {
        return cl_error_t_CL_SUCCESS;
    };
    if size == 0 {
        return cl_error_t_CL_SUCCESS;
    }
    let name = cstring_or_null(name);
    let name_ptr = name.as_ref().map_or(ptr::null(), |name| name.as_ptr());
    unsafe { cli_magic_scan_nested_fmap_type(fmap, offset, size, ctx, type_, name_ptr, 0) }
}

unsafe fn scan_generated_bytes(ctx: *mut cli_ctx, bytes: &[u8], name: Option<&str>) -> cl_error_t {
    if bytes.is_empty() {
        return cl_error_t_CL_SUCCESS;
    }
    let name = cstring_or_null(name);
    let name_ptr = name.as_ref().map_or(ptr::null(), |name| name.as_ptr());
    unsafe {
        cli_magic_scan_buff(
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            ctx,
            name_ptr,
            0,
        )
    }
}

fn cstring_or_null(name: Option<&str>) -> Option<CString> {
    name.and_then(|name| CString::new(name).ok())
}
