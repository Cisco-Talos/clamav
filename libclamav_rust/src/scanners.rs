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
    ffi::{c_char, CString},
    path::Path,
    ptr::null_mut,
};

use libc::c_void;
use log::{debug, error, warn};

use crate::{
    ctx,
    onenote::OneNote,
    sys::{cl_error_t, cl_error_t_CL_ERROR, cl_error_t_CL_SUCCESS, cli_ctx, cli_magic_scan_buff},
};

/// Rust wrapper of libclamav's cli_magic_scan_buff() function.
/// Use magic sigs to identify the file type and then scan it.
fn magic_scan(ctx: *mut cli_ctx, buf: &[u8], name: Option<String>) -> cl_error_t {
    let ptr = buf.as_ptr();
    let len = buf.len();

    match &name {
        Some(name) => debug!("Scanning {}-byte file named {}.", len, name),
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
    let _ = unsafe { CString::from_raw(name_ptr) };

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
