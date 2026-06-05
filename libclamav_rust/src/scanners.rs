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
    ffi::{c_char, CString},
    io::{Cursor, Read},
    panic,
    path::Path,
    ptr::null_mut,
};

use delharc::LhaDecodeReader;
use libc::c_void;
use log::{debug, error, warn};
use ruzstd::decoding::{
    errors::{FrameDecoderError, ReadFrameHeaderError},
    StreamingDecoder,
};

use crate::{
    alz::Alz,
    ctx,
    onenote::OneNote,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_ERROR, cl_error_t_CL_SUCCESS, cli_ctx,
        cli_magic_scan_buff,
    },
    util::{check_scan_limits, scan_archive_metadata},
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
                debug!("An error occurred when checking for the next file in this LHA or LZH archive: {err}");
                break;
            }
        }
    }

    cl_error_t_CL_SUCCESS
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

    let alz = match Alz::from_bytes(file_bytes) {
        Ok(x) => x,
        Err(err) => {
            error!("Failed to parse Alz file: {}", err.to_string());
            return cl_error_t_CL_ERROR;
        }
    };

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
#[no_mangle]
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
