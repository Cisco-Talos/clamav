/*
 *  Rust equivalent of libclamav's scanners.c module
 *
 *  Copyright (C) 2023-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
    convert::TryFrom,
    ffi::{c_char, CString},
    io::Read,
    panic,
    path::Path,
    ptr::null_mut,
};

use delharc::LhaDecodeReader;
use libc::c_void;
use log::{debug, error, warn};

use crate::{
    alz::{Alz, AlzExtractionLimits, Error as AlzError},
    ctx,
    onenote::OneNote,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXSIZE, cl_error_t_CL_EMEM,
        cl_error_t_CL_ERROR, cl_error_t_CL_SUCCESS, cl_error_t_CL_VIRUS, cli_ctx,
        cli_magic_scan_buff,
    },
    util::{
        append_potentially_unwanted_if_heur_exceedsmax, check_scan_limits, scan_archive_metadata,
    },
};

/// Rust wrapper of libclamav's cli_magic_scan_buff() function.
/// Use magic sigs to identify the file type and then scan it.
pub fn magic_scan(ctx: *mut cli_ctx, buf: &[u8], name: Option<String>) -> cl_error_t {
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
    let name = match name {
        Some(name) => name,
        None => String::from(""),
    };

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

/// Scan a OneNote file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
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
            error!("Failed to parse OneNote file: {}", err.to_string());
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
#[no_mangle]
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
                } else {
                    if !decoder.is_decoder_supported() {
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
                                            debug!("CRC check passed.  Very likely this is an LHA or LZH archive.  CRC: {crc}");
                                        }
                                        Err(err) => {
                                            // Error checking CRC.
                                            debug!("An error occurred when checking the CRC of this LHA or LZH archive: {err}");

                                            // Allow the scan to continue even with a CRC error, for now.
                                            // break;
                                        }
                                    }

                                    // Scan the file.
                                    let ret =
                                        magic_scan(ctx, &file_data, Some(filename.to_string()));
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
                debug!("An error occurred when checking for the next file in this LHA or LZH archive: {err}");
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
        };
    }

    let engine = &*(*ctx).engine;

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
    }
}

/// Scan an Alz file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
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
            if check_scan_limits("ALZ", ctx, 0, 0, 0) != cl_error_t_CL_SUCCESS {
                debug!("Exceeded scan limits. Bailing out.");
                return None;
            }

            match (
                usize::try_from(metadata.compressed_size),
                usize::try_from(metadata.uncompressed_size),
            ) {
                (Ok(compressed_size), Ok(uncompressed_size)) => {
                    let metadata_ret = scan_archive_metadata(
                        ctx,
                        metadata.file_name,
                        compressed_size,
                        uncompressed_size,
                        metadata.is_encrypted,
                        metadata.filepos,
                        metadata.file_crc as i32,
                    );
                    if metadata_ret == cl_error_t_CL_VIRUS {
                        alz_metadata_ret = metadata_ret;
                        debug!(
                            "ALZ file {:?} metadata did not pass scan checks. Skipping extraction.",
                            metadata.file_name
                        );
                        return None;
                    } else if metadata_ret != cl_error_t_CL_SUCCESS {
                        debug!(
                            "ALZ file {:?} metadata scan failed with {}. Continuing extraction.",
                            metadata.file_name, metadata_ret
                        );
                    }
                }
                _ => debug!(
                    "ALZ file {:?} metadata sizes are too large for this platform. Continuing extraction.",
                    metadata.file_name
                ),
            }

            Some(alz_extraction_limits(ctx))
        })
    }));

    let alz = match alz_result {
        Ok(Ok(x)) => x,
        Ok(Err(AlzError::Alloc)) => {
            debug!("Failed to allocate memory when parsing ALZ archive");
            return cl_error_t_CL_EMEM;
        }
        Ok(Err(err)) => {
            debug!("Failed to parse Alz file: {}", err.to_string());
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
        let ret = append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        );
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
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
