/*
 *  Assorted utility functions and macros.
 *
 *  Copyright (C) 2021-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Scott Hutton
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

use std::{ffi::CStr, fs::File};

use log::{debug, error};

use crate::sys;

extern "C" {
    fn cli_checktimelimit(ctx: *mut sys::cli_ctx) -> sys::cl_error_t;
}

/// Obtain a std::fs::File from an i32 in a platform-independent manner.
///
/// On Unix-like platforms, this is done with File::from_raw_fd().
/// On Windows, this is done through the `libc` crate's `get_osfhandle()` function.
/// All other platforms will panic!()
pub fn file_from_fd_or_handle(fd: i32) -> File {
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        unsafe { File::from_raw_fd(fd) }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        unsafe {
            let handle = libc::get_osfhandle(fd);
            File::from_raw_handle(handle as RawHandle)
        }
    }

    #[cfg(not(any(windows, unix)))]
    compile_error!("implemented only for unix and windows targets")
}

/// Get a string from a pointer.
///
/// # Safety
///
/// The caller is responsible for making sure the lifetime of the pointer
/// exceeds the lifetime of the output string.
///
/// ptr must be a valid pointer to a C string.
pub unsafe fn str_from_ptr(
    ptr: *const ::std::os::raw::c_char,
) -> Result<Option<&'static str>, std::str::Utf8Error> {
    if ptr.is_null() {
        return Ok(None);
    }

    Some(unsafe { CStr::from_ptr(ptr) }.to_str()).transpose()
}

/// Check scan limits in case we need to abort the scan.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn check_scan_limits(
    module_name: &str,
    ctx: *mut sys::cli_ctx,
    need1: u64,
    need2: u64,
    need3: u64,
) -> sys::cl_error_t {
    let module_name = match std::ffi::CString::new(module_name) {
        Ok(name) => name,
        Err(_) => {
            error!("Invalid module_name: {:?}", module_name);
            return sys::cl_error_t_CL_EFORMAT;
        }
    };

    unsafe { sys::cli_checklimits(module_name.as_ptr(), ctx, need1, need2, need3) }
}

/// Check only the scan time limit in case we need to abort the scan.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn check_scan_time_limit(ctx: *mut sys::cli_ctx) -> sys::cl_error_t {
    unsafe { cli_checktimelimit(ctx) }
}

pub const HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE: &[u8] =
    b"Heuristics.Limits.Exceeded.MaxScanSize\0";
pub const HEURISTICS_LIMITS_EXCEEDED_MAX_FILES: &[u8] = b"Heuristics.Limits.Exceeded.MaxFiles\0";

/// Append an exceeds-max heuristic alert or metadata entry.
///
/// The C evidence store retains the original `virname` pointer, so the alert
/// name must have static lifetime rather than temporary Rust string storage.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure.
/// virname must point to a static NUL-terminated C string.
///
pub unsafe fn append_potentially_unwanted_if_heur_exceedsmax(
    ctx: *mut sys::cli_ctx,
    virname: &'static [u8],
) {
    debug_assert_eq!(virname.last(), Some(&0));

    unsafe {
        sys::cli_append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            virname.as_ptr().cast_mut().cast(),
        );
    }
}

/// Scan archive metadata.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn scan_archive_metadata(
    ctx: *mut sys::cli_ctx,
    filename: &str,
    filesize_compressed: usize,
    filesize_original: usize,
    is_encrypted: bool,
    filepos: usize,
    res1: i32,
) -> sys::cl_error_t {
    let module_name = match std::ffi::CString::new(filename) {
        Ok(name) => name,
        Err(_) => {
            debug!("Invalid archive metadata filename: {:?}", filename);
            return sys::cl_error_t_CL_EFORMAT;
        }
    };

    unsafe {
        sys::cli_matchmeta(
            ctx,
            module_name.as_ptr(),
            filesize_compressed,
            filesize_original,
            i32::from(is_encrypted),
            filepos as u32,
            res1,
        )
    }
}
