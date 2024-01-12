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

/// Get a string from a pointer
///
/// # Safety
///
/// The caller is responsible for making sure the lifetime of the pointer
/// exceeds the lifetime of the output string.
///
/// ptr must be a valid pointer to a C string.
pub unsafe fn str_from_ptr(ptr: *const ::std::os::raw::c_char) -> Result<Option<&'static str>, std::str::Utf8Error> {
    if ptr.is_null() {
        return Ok(None);
    }

    Some(unsafe { CStr::from_ptr(ptr) }.to_str()).transpose()
}
