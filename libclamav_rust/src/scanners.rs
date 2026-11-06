/*
 *  Rust equivalent of libclamav's scanners.c module
 *
 *  Copyright (C) 2023-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

use std::{
    ffi::{CString, c_char},
    io::{Cursor, Read},
    os::raw::{c_int, c_uint},
    panic,
    path::Path,
    ptr::null_mut,
};

use delharc::LhaDecodeReader;
use libc::c_void;
use log::{debug, error, warn};
use ruzstd::decoding::{
    StreamingDecoder,
    errors::{FrameDecoderError, ReadFrameHeaderError},
};

use crate::{
    alz::{Alz, AlzExtractionDecision, AlzExtractionLimits, Error as AlzError},
    ctx,
    fmap::FMap,
    onenote::OneNote,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_ERROR, cl_error_t_CL_SUCCESS, cl_error_t_CL_VIRUS,
        cli_ctx, cli_magic_scan_buff,
    },
    util::{
        HEURISTICS_LIMITS_EXCEEDED_MAX_FILES, HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE,
        append_potentially_unwanted_if_heur_exceedsmax, check_scan_limits, check_scan_time_limit,
        scan_archive_metadata,
    },
};

/// Rust wrapper of libclamav's cli_magic_scan_buff() function.
/// Use magic sigs to identify the file type and then scan it.
///
/// # Safety
///
/// The ctx pointer must be valid.
pub unsafe fn magic_scan(ctx: *mut cli_ctx, buf: &[u8], name: Option<String>) -> cl_error_t {
    let ptr = buf.as_ptr();
    let len = buf.len();

    if 0 == len {
        return cl_error_t_CL_SUCCESS;
    }

    match &name {
        Some(name) => debug!("Scanning {}-byte file named {:?}.", len, name),
        None => debug!("Scanning {}-byte unnamed file.", len),
    }

    // Convert name to a C string.
    let name = name.unwrap_or_default();

    let name_ptr: *mut c_char = match CString::new(name) {
        Ok(name_cstr) => {
            // into_raw() so name_cstr doesn't get dropped and
            // we don't do an unsafe deref of the pointer.
            name_cstr.into_raw()
        }
        Err(_) => null_mut(),
    };

    let ret = unsafe { cli_magic_scan_buff(ptr as *const c_void, len, ctx, name_ptr, 0) };
    if ret != cl_error_t_CL_SUCCESS {
        debug!("cli_magic_scan_buff returned error: {}", ret);
    }

    // Okay now safe to drop the name CString.
    if !name_ptr.is_null() {
        let _ = unsafe { CString::from_raw(name_ptr) };
    }

    ret
}

/// Scan a PE/MSEXE file with the Rust executable parser.
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_pe_rust(ctx: *mut cli_ctx) -> cl_error_t {
    unsafe { crate::scanner::filetype_handlers::executable::scan_pe(ctx) }
}

/// Validate a PE header at a parent fmap offset with the Rust executable parser.
///
/// # Safety
///
/// `ctx` must be a valid scanner context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn check_pe_header_at_rust(ctx: *mut cli_ctx, offset: usize) -> cl_error_t {
    unsafe { crate::scanner::filetype_handlers::executable::check_pe_header_at(ctx, offset) }
}

/// Populate ClamAV matcher target-info for a PE file with the Rust parser.
///
/// # Safety
///
/// `ctx` must be a valid scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn populate_pe_target_info_rust(
    ctx: *mut cli_ctx,
    exe_info: *mut c_void,
) -> cl_error_t {
    unsafe { crate::scanner::filetype_handlers::executable::populate_pe_target_info(ctx, exe_info) }
}

/// Generate PE section or import-table hashes with the Rust executable parser.
///
/// # Safety
///
/// `ctx` must be a valid scanner context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn genhash_pe_rust(
    ctx: *mut cli_ctx,
    class: u32,
    hash_type: u32,
) -> cl_error_t {
    unsafe { crate::scanner::filetype_handlers::executable::genhash_pe(ctx, class, hash_type) }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CliRawAddrSection {
    rva: u32,
    vsz: u32,
    raw: u32,
    rsz: u32,
    chr: u32,
    urva: u32,
    uvsz: u32,
    uraw: u32,
    ursz: u32,
}

/// Map a PE RVA to a raw file offset for legacy ClamAV consumers.
///
/// The symbol name intentionally matches the historical C helper so existing
/// bytecode and icon code can continue calling `cli_rawaddr()` while the
/// executable parsing arithmetic lives in Rust.
///
/// # Safety
///
/// `sections` must point to `nos` valid `struct cli_exe_section` records when
/// `nos` is nonzero. `err`, when non-null, must point to writable storage.
#[unsafe(export_name = "cli_rawaddr")]
pub unsafe extern "C" fn cli_rawaddr_rust(
    rva: u32,
    sections: *const c_void,
    nos: u16,
    err: *mut c_uint,
    fsize: usize,
    hdr_size: u32,
) -> u32 {
    fn set_error(err: *mut c_uint, value: bool) {
        if !err.is_null() {
            unsafe {
                *err = c_uint::from(value);
            }
        }
    }

    if rva < hdr_size {
        if usize::try_from(rva).is_ok_and(|offset| offset < fsize) {
            set_error(err, false);
            return rva;
        }
        set_error(err, true);
        return 0;
    }

    let section_count = usize::from(nos);
    if section_count == 0 || sections.is_null() {
        set_error(err, true);
        return 0;
    }

    let sections = sections.cast::<CliRawAddrSection>();
    for index in (0..section_count).rev() {
        let section = unsafe { *sections.add(index) };
        if section.rsz == 0 || section.rva > rva {
            continue;
        }
        let delta = rva - section.rva;
        if section.rsz <= delta {
            continue;
        }
        let Some(offset) = delta.checked_add(section.raw) else {
            set_error(err, true);
            return 0;
        };
        set_error(err, false);
        return offset;
    }

    set_error(err, true);
    0
}

type PeResourceCallback = unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32) -> c_int;

const PE_RESOURCE_ENTRY_SIZE: usize = 8;
const PE_RESOURCE_DIRECTORY_SIZE: usize = 16;
const PE_RESOURCE_SUBDIRECTORY: u32 = 0x8000_0000;
const PE_RESOURCE_OFFSET_MASK: u32 = 0x7fff_ffff;
const PE_RESOURCE_ANY_NAME: u32 = 0xffff_ffff;

/// Walk a PE resource directory for legacy icon fuzzy-hash consumers.
///
/// C keeps the stable `findres()` shim because it already owns
/// `struct cli_exe_info`. The actual resource directory parsing is here so PE
/// resource offset arithmetic follows the Rust executable parser migration.
///
/// # Safety
///
/// `map` must point to a valid ClamAV `fmap_t`. `sections` must point to
/// `nsections` valid `struct cli_exe_section` records when `nsections` is
/// nonzero. `cb`, when present, must be a valid callback for `opaque`.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn findres_rust(
    by_type: u32,
    by_name: u32,
    map: *mut crate::sys::cl_fmap_t,
    sections: *const c_void,
    nsections: u16,
    pe_offset: u32,
    hdr_size: u32,
    ndatadirs: u32,
    res_rva: u32,
    cb: PeResourceCallback,
    opaque: *mut c_void,
) {
    if ndatadirs < 3 {
        return;
    }
    if pe_offset != 0 {
        debug!("findres: resource lookup requested for embedded PE at offset {pe_offset}");
    }

    let Ok(fmap) = FMap::try_from(map) else {
        return;
    };
    let Some(root_raw) = resource_rva_to_raw(&fmap, sections, nsections, hdr_size, res_rva) else {
        return;
    };
    let Some((named_types, id_types)) = resource_directory_counts(&fmap, root_raw) else {
        return;
    };

    let (type_entry_base, type_count) = if by_type & PE_RESOURCE_SUBDIRECTORY == 0 {
        let Some(offset) = resource_entry_table_offset(root_raw, named_types) else {
            return;
        };
        (offset, id_types)
    } else {
        let Some(offset) = root_raw.checked_add(PE_RESOURCE_DIRECTORY_SIZE) else {
            return;
        };
        (offset, named_types)
    };

    for index in 0..usize::from(type_count) {
        let Some(type_entry_offset) = resource_indexed_entry_offset(type_entry_base, index) else {
            return;
        };
        let Some((type_id, type_offset)) = resource_directory_entry(&fmap, type_entry_offset)
        else {
            return;
        };
        if type_id != by_type || type_offset & PE_RESOURCE_SUBDIRECTORY == 0 {
            continue;
        }

        let type_offset = type_offset & PE_RESOURCE_OFFSET_MASK;
        let Some(type_rva) = res_rva.checked_add(type_offset) else {
            return;
        };
        let Some(type_raw) = resource_rva_to_raw(&fmap, sections, nsections, hdr_size, type_rva)
        else {
            return;
        };
        walk_resource_names(
            &fmap, sections, nsections, hdr_size, res_rva, type_raw, by_name, type_id, cb, opaque,
        );
        return;
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_resource_names(
    fmap: &FMap,
    sections: *const c_void,
    nsections: u16,
    hdr_size: u32,
    res_rva: u32,
    type_raw: usize,
    by_name: u32,
    type_id: u32,
    callback: PeResourceCallback,
    opaque: *mut c_void,
) {
    let Some((named_entries, id_entries)) = resource_directory_counts(fmap, type_raw) else {
        return;
    };
    let (name_entry_base, name_count) = if by_name == PE_RESOURCE_ANY_NAME {
        let Some(offset) = type_raw.checked_add(PE_RESOURCE_DIRECTORY_SIZE) else {
            return;
        };
        let Some(count) = named_entries.checked_add(id_entries) else {
            return;
        };
        (offset, count)
    } else if by_name & PE_RESOURCE_SUBDIRECTORY == 0 {
        let Some(offset) = resource_entry_table_offset(type_raw, named_entries) else {
            return;
        };
        (offset, id_entries)
    } else {
        let Some(offset) = type_raw.checked_add(PE_RESOURCE_DIRECTORY_SIZE) else {
            return;
        };
        (offset, named_entries)
    };

    for index in 0..usize::from(name_count) {
        let Some(name_entry_offset) = resource_indexed_entry_offset(name_entry_base, index) else {
            return;
        };
        let Some((name_id, name_offset)) = resource_directory_entry(fmap, name_entry_offset) else {
            return;
        };
        if by_name != PE_RESOURCE_ANY_NAME && name_id != by_name {
            continue;
        }
        if name_offset & PE_RESOURCE_SUBDIRECTORY == 0 {
            continue;
        }

        let name_offset = name_offset & PE_RESOURCE_OFFSET_MASK;
        let Some(name_rva) = res_rva.checked_add(name_offset) else {
            return;
        };
        let Some(name_raw) = resource_rva_to_raw(fmap, sections, nsections, hdr_size, name_rva)
        else {
            return;
        };
        walk_resource_languages(fmap, name_raw, res_rva, type_id, name_id, callback, opaque);
    }
}

fn walk_resource_languages(
    fmap: &FMap,
    name_raw: usize,
    res_rva: u32,
    type_id: u32,
    name_id: u32,
    callback: PeResourceCallback,
    opaque: *mut c_void,
) {
    let Some((named_entries, id_entries)) = resource_directory_counts(fmap, name_raw) else {
        return;
    };
    let Some(lang_count) = named_entries.checked_add(id_entries) else {
        return;
    };
    let Some(lang_entry_base) = name_raw.checked_add(PE_RESOURCE_DIRECTORY_SIZE) else {
        return;
    };

    for index in 0..usize::from(lang_count) {
        let Some(lang_entry_offset) = resource_indexed_entry_offset(lang_entry_base, index) else {
            return;
        };
        let Some((lang_id, lang_offset)) = resource_directory_entry(fmap, lang_entry_offset) else {
            return;
        };
        if lang_offset & PE_RESOURCE_SUBDIRECTORY != 0 {
            continue;
        }
        let Some(data_entry_rva) = res_rva.checked_add(lang_offset) else {
            return;
        };
        let should_stop = unsafe { callback(opaque, type_id, name_id, lang_id, data_entry_rva) };
        if should_stop != 0 {
            return;
        }
    }
}

fn resource_rva_to_raw(
    fmap: &FMap,
    sections: *const c_void,
    nsections: u16,
    hdr_size: u32,
    rva: u32,
) -> Option<usize> {
    let mut err = 0;
    let raw = unsafe { cli_rawaddr_rust(rva, sections, nsections, &mut err, fmap.len(), hdr_size) };
    if err != 0 {
        return None;
    }
    usize::try_from(raw).ok()
}

fn resource_entry_table_offset(directory_raw: usize, named_entries: u16) -> Option<usize> {
    directory_raw
        .checked_add(PE_RESOURCE_DIRECTORY_SIZE)?
        .checked_add(usize::from(named_entries).checked_mul(PE_RESOURCE_ENTRY_SIZE)?)
}

fn resource_indexed_entry_offset(base: usize, index: usize) -> Option<usize> {
    base.checked_add(index.checked_mul(PE_RESOURCE_ENTRY_SIZE)?)
}

fn resource_directory_counts(fmap: &FMap, raw_offset: usize) -> Option<(u16, u16)> {
    let directory = fmap.need_off(raw_offset, PE_RESOURCE_DIRECTORY_SIZE).ok()?;
    Some((read_u16_le(directory, 12)?, read_u16_le(directory, 14)?))
}

fn resource_directory_entry(fmap: &FMap, raw_offset: usize) -> Option<(u32, u32)> {
    let entry = fmap.need_off(raw_offset, PE_RESOURCE_ENTRY_SIZE).ok()?;
    Some((read_u32_le(entry, 0)?, read_u32_le(entry, 4)?))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(raw.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

/// Scan an ELF file with the Rust executable parser.
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_elf_rust(ctx: *mut cli_ctx) -> cl_error_t {
    unsafe { crate::scanner::filetype_handlers::executable::scan_elf(ctx) }
}

/// Scan a thin Mach-O file with the Rust executable parser.
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_macho_rust(ctx: *mut cli_ctx) -> cl_error_t {
    unsafe {
        crate::scanner::filetype_handlers::executable::scan_macho(
            ctx,
            crate::sys::cli_file_CL_TYPE_MACHO,
        )
    }
}

/// Scan a universal/fat Mach-O file with the Rust executable parser.
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_macho_unibin_rust(ctx: *mut cli_ctx) -> cl_error_t {
    unsafe {
        crate::scanner::filetype_handlers::executable::scan_macho(
            ctx,
            crate::sys::cli_file_CL_TYPE_MACHO_UNIBIN,
        )
    }
}

/// Populate ClamAV matcher target-info for an ELF file with the Rust parser.
///
/// # Safety
///
/// `ctx` must be a valid scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn populate_elf_target_info_rust(
    ctx: *mut cli_ctx,
    exe_info: *mut c_void,
) -> cl_error_t {
    unsafe {
        crate::scanner::filetype_handlers::executable::populate_elf_target_info(ctx, exe_info)
    }
}

/// Populate ClamAV matcher target-info for a Mach-O file with the Rust parser.
///
/// # Safety
///
/// `ctx` must be a valid scanner context and `exe_info` must point to a
/// `struct cli_exe_info` initialized by C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn populate_macho_target_info_rust(
    ctx: *mut cli_ctx,
    exe_info: *mut c_void,
) -> cl_error_t {
    unsafe {
        crate::scanner::filetype_handlers::executable::populate_macho_target_info(ctx, exe_info)
    }
}

/// Scan a OneNote file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_onenote(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            warn!("Error getting FMap from ctx: {e}");
            return cl_error_t_CL_ERROR;
        }
    };

    let file_bytes = match fmap.need_off(0, fmap.len()) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(
                "Failed to get file bytes for fmap of size {}: {err}",
                fmap.len()
            );
            return cl_error_t_CL_ERROR;
        }
    };

    let one = match OneNote::from_bytes(file_bytes, Path::new(fmap.name())) {
        Ok(x) => x,
        Err(err) => {
            error!("Failed to parse OneNote file: {err}");
            return cl_error_t_CL_ERROR;
        }
    };

    let mut scan_result = cl_error_t_CL_SUCCESS;

    one.into_iter().all(|attachment| {
        debug!(
            "Extracted {}-byte attachment with name: {:?}",
            attachment.data.len(),
            attachment.name
        );

        let ret = magic_scan(ctx, &attachment.data, attachment.name);
        if ret != cl_error_t_CL_SUCCESS {
            scan_result = ret;
            return false;
        }

        true
    });

    scan_result
}

/// Scan the contents of a LHA or LZH archive
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_lha_lzh(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            warn!("Error getting FMap from ctx: {e}");
            return cl_error_t_CL_ERROR;
        }
    };

    let file_bytes = match fmap.need_off(0, fmap.len()) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(
                "Failed to get file bytes for fmap of size {}: {err}",
                fmap.len()
            );
            return cl_error_t_CL_ERROR;
        }
    };

    // Try to parse the LHA/LZH file data using the delharc crate.
    debug!("Attempting to parse the LHA/LZH file data using the delharc crate.");

    // Attempt to catch panics in case the parser encounter unexpected issues.
    let result_result = panic::catch_unwind(
        || -> Result<LhaDecodeReader<&[u8]>, delharc::decode::LhaDecodeError<&[u8]>> {
            LhaDecodeReader::new(file_bytes)
        },
    );

    // Check if it panicked. If no panic, grab the parse result.
    let result = match result_result {
        Ok(result) => result,
        Err(_) => {
            debug!("Panic occurred when trying to open LHA archive with delharc crate");
            return cl_error_t_CL_EFORMAT;
        }
    };

    // Check if any issue opening the archive.
    let mut decoder = match result {
        Ok(result) => result,
        Err(err) => {
            debug!("Unable to parse LHA archive with delharc crate: {err}");
            return cl_error_t_CL_EFORMAT;
        }
    };

    debug!("Opened the LHA/LZH archive");

    let mut index: usize = 0;
    loop {
        // Check if we've already exceeded the limits and should bail out.
        let ret = check_scan_limits("LHA", ctx, 0, 0, 0);
        if ret != cl_error_t_CL_SUCCESS {
            debug!("Exceeded scan limits. Bailing out.");
            break;
        }

        // Get the file header.
        let header = decoder.header();

        let filepath = header.parse_pathname();
        let filename = filepath.to_string_lossy();
        if header.is_directory() {
            debug!("Skipping directory {filename}");
        } else {
            debug!("Found file in LHA archive: {filename}");

            // Scan the archive metadata first.
            if scan_archive_metadata(
                ctx,
                &filename,
                header.compressed_size as usize,
                header.original_size as usize,
                false,
                index,
                header.file_crc as i32,
            ) != cl_error_t_CL_SUCCESS
            {
                debug!("Extracted file '{filename}' would exceed size limits. Skipping.");
            } else {
                // Check if scanning the next file would exceed the limits and should be skipped.
                if check_scan_limits("LHA", ctx, header.original_size, 0, 0)
                    != cl_error_t_CL_SUCCESS
                {
                    debug!("Extracted file '{filename}' would exceed size limits. Skipping.");
                } else if !decoder.is_decoder_supported() {
                    debug!("err: unsupported compression method");
                } else {
                    // Read the file into a buffer.
                    let mut file_data: Vec<u8> = Vec::<u8>::new();

                    match decoder.read_to_end(&mut file_data) {
                        Ok(bytes_read) => {
                            if bytes_read > 0 {
                                debug!(
                                    "Read {bytes_read} bytes from file {filename} in the LHA archive."
                                );

                                // Verify the CRC check *after* reading the file.
                                match decoder.crc_check() {
                                    Ok(crc) => {
                                        // CRC is valid.  Very likely this is an LHA or LZH archive.
                                        debug!(
                                            "CRC check passed.  Very likely this is an LHA or LZH archive.  CRC: {crc}"
                                        );
                                    }
                                    Err(err) => {
                                        // Error checking CRC.
                                        debug!(
                                            "An error occurred when checking the CRC of this LHA or LZH archive: {err}"
                                        );

                                        // Allow the scan to continue even with a CRC error, for now.
                                        // break;
                                    }
                                }

                                // Scan the file.
                                let ret = magic_scan(ctx, &file_data, Some(filename.to_string()));
                                if ret != cl_error_t_CL_SUCCESS {
                                    debug!("cl_scandesc_magic returned error: {}", ret);
                                    return ret;
                                }
                            } else {
                                debug!("Read zero-byte file.");
                            }
                        }
                        err => {
                            debug!("Error reading file {err:?}");
                        }
                    }
                }
            }

            index += 1;
        }

        // Get the next file.
        match decoder.next_file() {
            Ok(true) => {
                debug!("Found another file in the archive!");
            }
            Ok(false) => {
                debug!("No more files in the archive.");
                break;
            }
            Err(err) => {
                // Error getting the next file.
                // Use debug-level because may not actually be an LHA/LZH archive.
                // LHA/LZH does not have particularly identifiable magic bytes.
                debug!(
                    "An error occurred when checking for the next file in this LHA or LZH archive: {err}"
                );
                break;
            }
        }
    }

    cl_error_t_CL_SUCCESS
}

unsafe fn alz_extraction_limits(ctx: *mut cli_ctx) -> AlzExtractionLimits {
    if ctx.is_null() || (*ctx).engine.is_null() {
        return AlzExtractionLimits {
            max_file_size: u64::MAX,
            max_total_size: u64::MAX,
            max_files_remaining: usize::MAX,
        };
    }

    let engine = &*(*ctx).engine;
    let max_files_remaining = if engine.maxfiles == 0 {
        usize::MAX
    } else {
        usize::try_from(engine.maxfiles.saturating_sub((*ctx).scannedfiles)).unwrap_or(usize::MAX)
    };

    AlzExtractionLimits {
        max_file_size: if engine.maxfilesize == 0 {
            u64::MAX
        } else {
            engine.maxfilesize
        },
        max_total_size: if engine.maxscansize == 0 {
            u64::MAX
        } else {
            engine.maxscansize.saturating_sub((*ctx).scansize)
        },
        max_files_remaining,
    }
}

fn handle_alz_metadata_scan_result(
    file_name: &str,
    metadata_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match metadata_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        ret if ret == cl_error_t_CL_EFORMAT => {
            debug!(
                "ALZ file {:?} metadata scan failed with {}. Continuing extraction.",
                file_name, metadata_ret
            );
            true
        }
        ret if ret == cl_error_t_CL_VIRUS => {
            *alz_metadata_ret = metadata_ret;
            debug!(
                "ALZ file {:?} metadata did not pass scan checks. Skipping extraction.",
                file_name
            );
            false
        }
        _ => {
            *alz_metadata_ret = metadata_ret;
            debug!(
                "ALZ file {:?} metadata scan failed with {}. Aborting extraction.",
                file_name, metadata_ret
            );
            false
        }
    }
}

fn handle_alz_metadata_limit_result(
    limit_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match limit_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        ret if ret == cl_error_t_CL_EMAXFILES => false,
        _ => {
            *alz_metadata_ret = limit_ret;
            false
        }
    }
}

fn alz_metadata_size(size: u64) -> Option<usize> {
    usize::try_from(size).ok()
}

fn handle_alz_metadata_directory_limit_result(
    limit_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match limit_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        _ => {
            *alz_metadata_ret = limit_ret;
            false
        }
    }
}

/// Scan an Alz file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_scanalz(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            warn!("Error getting FMap from ctx: {e}");
            return cl_error_t_CL_ERROR;
        }
    };

    let file_bytes = match fmap.need_off(0, fmap.len()) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(
                "Failed to get file bytes for fmap of size {}: {err}",
                fmap.len()
            );
            return cl_error_t_CL_ERROR;
        }
    };

    let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;
    let alz_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        Alz::from_bytes_with_filter(file_bytes, |metadata| {
            if alz_metadata_ret != cl_error_t_CL_SUCCESS {
                return AlzExtractionDecision::Stop;
            }

            if metadata.is_directory {
                let limit_ret = check_scan_time_limit(ctx);
                if !handle_alz_metadata_directory_limit_result(limit_ret, &mut alz_metadata_ret) {
                    debug!("Exceeded scan limits. Bailing out.");
                    return AlzExtractionDecision::Stop;
                }

                return AlzExtractionDecision::Skip;
            }

            let limit_ret = check_scan_limits("ALZ", ctx, 0, 0, 0);
            if !handle_alz_metadata_limit_result(limit_ret, &mut alz_metadata_ret) {
                debug!("Exceeded scan limits. Bailing out.");
                return AlzExtractionDecision::Stop;
            }

            match (
                alz_metadata_size(metadata.compressed_size),
                alz_metadata_size(metadata.uncompressed_size),
            ) {
                (Some(compressed_size), Some(uncompressed_size)) => {
                    let metadata_ret = scan_archive_metadata(
                        ctx,
                        metadata.file_name,
                        compressed_size,
                        uncompressed_size,
                        metadata.is_encrypted,
                        metadata.filepos,
                        metadata.file_crc as i32,
                    );
                    if !handle_alz_metadata_scan_result(
                        metadata.file_name,
                        metadata_ret,
                        &mut alz_metadata_ret,
                    ) {
                        return AlzExtractionDecision::Stop;
                    }
                }
                _ => {
                    debug!(
                        "ALZ file {:?} metadata size does not fit platform size_t. Skipping metadata scan.",
                        metadata.file_name
                    );
                }
            }

            AlzExtractionDecision::Extract(alz_extraction_limits(ctx))
        })
    }));

    let alz = match alz_result {
        Ok(Ok(x)) => x,
        Ok(Err(AlzError::Alloc)) => {
            debug!("Failed to allocate memory when parsing ALZ archive");
            return cl_error_t_CL_EMEM;
        }
        Ok(Err(err)) => {
            debug!("Failed to parse Alz file: {err}");
            return cl_error_t_CL_EFORMAT;
        }
        Err(_) => {
            debug!("Panic occurred when trying to parse ALZ archive");
            return cl_error_t_CL_EFORMAT;
        }
    };

    if alz_metadata_ret != cl_error_t_CL_SUCCESS {
        return alz_metadata_ret;
    }

    if let Some(needed) = alz.file_limit_exceeded_size {
        let ret = check_scan_limits("ALZ", ctx, needed, 0, 0);
        if ret != cl_error_t_CL_SUCCESS && ret != cl_error_t_CL_EMAXSIZE {
            return ret;
        }
    }

    if alz.total_limit_exceeded_size.is_some() {
        append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE,
        );
    }

    if alz.file_count_limit_exceeded {
        append_potentially_unwanted_if_heur_exceedsmax(ctx, HEURISTICS_LIMITS_EXCEEDED_MAX_FILES);
    }

    for i in 0..alz.embedded_files.len() {
        let ret = magic_scan(
            ctx,
            &alz.embedded_files[i].data,
            alz.embedded_files[i].name.clone(),
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    if alz.has_parse_error() {
        return cl_error_t_CL_EFORMAT;
    }

    cl_error_t_CL_SUCCESS
}

/// Decompress and scan a Zstandard (zstd) compressed file.
///
/// Uses the pure-Rust `ruzstd` decoder, so no libzstd C dependency is required.
/// Handles streams made up of multiple concatenated frames as well as
/// skippable frames, mirroring the behavior of the gzip/bzip2/xz scanners.
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_scanzstd(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            warn!("Error getting FMap from ctx: {e}");
            return cl_error_t_CL_ERROR;
        }
    };

    let file_bytes = match fmap.need_off(0, fmap.len()) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(
                "Failed to get file bytes for fmap of size {}: {err}",
                fmap.len()
            );
            return cl_error_t_CL_ERROR;
        }
    };

    debug!("in cli_scanzstd()");

    // Decompress every zstd frame into a single buffer.
    //
    // `output` is owned outside the closure so that even if the decoder panics
    // on malformed input we still scan whatever was decompressed so far, rather
    // than discarding it (an evasion gap). The decode loop is wrapped in
    // catch_unwind so that a panic cannot unwind across the C FFI boundary.
    let mut output: Vec<u8> = Vec::new();

    let decompress = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let mut cursor = Cursor::new(file_bytes);
        let total_len = file_bytes.len() as u64;
        let mut chunk = [0u8; 65536];

        'frames: while cursor.position() < total_len {
            // Stop before starting a new frame if we've already hit scan limits.
            if unsafe { check_scan_limits("zstd", ctx, output.len() as u64, 0, 0) }
                != cl_error_t_CL_SUCCESS
            {
                debug!("cli_scanzstd: exceeded scan limits. Bailing out.");
                break;
            }

            // ruzstd's StreamingDecoder decodes a single frame, so we recreate it
            // for each concatenated frame in the stream.
            let mut decoder = match StreamingDecoder::new(&mut cursor) {
                Ok(decoder) => decoder,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                    length,
                    ..
                })) => {
                    // Skippable frame: its 8-byte header was already consumed; skip the body.
                    let next = cursor
                        .position()
                        .saturating_add(length as u64)
                        .min(total_len);
                    cursor.set_position(next);
                    continue;
                }
                Err(err) => {
                    // No more valid frames (e.g. trailing data). Scan what we have.
                    debug!("cli_scanzstd: stopping frame parsing: {err}");
                    break;
                }
            };

            loop {
                match decoder.read(&mut chunk) {
                    Ok(0) => break, // current frame fully decoded
                    Ok(n) => {
                        output.extend_from_slice(&chunk[..n]);

                        if unsafe { check_scan_limits("zstd", ctx, output.len() as u64, 0, 0) }
                            != cl_error_t_CL_SUCCESS
                        {
                            debug!(
                                "cli_scanzstd: decompressed size exceeds limits - \
                                 only scanning {} bytes",
                                output.len()
                            );
                            break 'frames;
                        }
                    }
                    Err(err) => {
                        // Scan whatever we decompressed so far.
                        debug!("cli_scanzstd: decompress error: {err}");
                        break 'frames;
                    }
                }
            }
        }
    }));

    if decompress.is_err() {
        // The decoder panicked; scan whatever was decompressed before the panic.
        debug!("cli_scanzstd: panic while decompressing zstd data");
    }

    magic_scan(ctx, &output, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::cl_error_t_CL_ETIMEOUT;
    use std::ffi::c_void;
    use std::os::raw::c_uint;

    #[test]
    fn alz_metadata_scan_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_scan_format_error_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_EFORMAT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_scan_virus_stops() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_VIRUS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_VIRUS);
    }

    #[test]
    fn alz_metadata_scan_hard_error_stops() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_EMEM,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_EMEM);
    }

    #[test]
    fn alz_metadata_limit_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_limit_result(
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_limit_failure_stops_without_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_limit_result(
            cl_error_t_CL_EMAXFILES,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_limit_hard_failure_stops_with_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_limit_result(
            cl_error_t_CL_ETIMEOUT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_ETIMEOUT);
    }

    #[test]
    fn alz_metadata_directory_limit_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_directory_limit_result(
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_directory_limit_hard_failure_stops_with_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_directory_limit_result(
            cl_error_t_CL_ETIMEOUT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_ETIMEOUT);
    }

    #[test]
    fn alz_metadata_size_rejects_platform_overflow() {
        assert_eq!(alz_metadata_size(42), Some(42usize));
        assert_eq!(alz_metadata_size(usize::MAX as u64), Some(usize::MAX));

        #[cfg(target_pointer_width = "32")]
        assert_eq!(alz_metadata_size(u64::from(u32::MAX) + 1), None);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(alz_metadata_size(u64::MAX), Some(usize::MAX));
    }

    fn map_raw_addr(
        rva: u32,
        sections: &[CliRawAddrSection],
        fsize: usize,
        hdr_size: u32,
    ) -> (u32, c_uint) {
        let mut err = 99;
        let offset = unsafe {
            cli_rawaddr_rust(
                rva,
                sections.as_ptr().cast::<c_void>(),
                u16::try_from(sections.len()).unwrap(),
                &mut err,
                fsize,
                hdr_size,
            )
        };
        (offset, err)
    }

    #[test]
    fn rawaddr_maps_header_rvas_before_section_table() {
        let (offset, err) = map_raw_addr(0x30, &[], 0x200, 0x100);

        assert_eq!(offset, 0x30);
        assert_eq!(err, 0);
    }

    #[test]
    fn rawaddr_rejects_header_rvas_beyond_file_size() {
        let (offset, err) = map_raw_addr(0x80, &[], 0x80, 0x100);

        assert_eq!(offset, 0);
        assert_eq!(err, 1);
    }

    #[test]
    fn rawaddr_maps_matching_section_in_reverse_order() {
        let sections = [
            CliRawAddrSection {
                rva: 0x1000,
                raw: 0x200,
                rsz: 0x300,
                ..empty_section()
            },
            CliRawAddrSection {
                rva: 0x1000,
                raw: 0x800,
                rsz: 0x300,
                ..empty_section()
            },
        ];
        let (offset, err) = map_raw_addr(0x1010, &sections, 0x1000, 0x100);

        assert_eq!(offset, 0x810);
        assert_eq!(err, 0);
    }

    #[test]
    fn rawaddr_rejects_virtual_section_tail_without_raw_data() {
        let sections = [CliRawAddrSection {
            rva: 0x1000,
            raw: 0x200,
            rsz: 0x100,
            ..empty_section()
        }];
        let (offset, err) = map_raw_addr(0x1200, &sections, 0x1000, 0x100);

        assert_eq!(offset, 0);
        assert_eq!(err, 1);
    }

    #[test]
    fn rawaddr_rejects_file_offset_overflow() {
        let sections = [CliRawAddrSection {
            rva: 0x1000,
            raw: u32::MAX,
            rsz: 0x10,
            ..empty_section()
        }];
        let (offset, err) = map_raw_addr(0x1001, &sections, 0x1000, 0x100);

        assert_eq!(offset, 0);
        assert_eq!(err, 1);
    }

    fn empty_section() -> CliRawAddrSection {
        CliRawAddrSection {
            rva: 0,
            vsz: 0,
            raw: 0,
            rsz: 0,
            chr: 0,
            urva: 0,
            uvsz: 0,
            uraw: 0,
            ursz: 0,
        }
    }
}
