/*
 *  FRSError: Painlessly transfer errors to and from C
 *
 *  Copyright (C) 2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use std::{
    ffi::{CStr, CString},
    mem::ManuallyDrop,
    os::raw::c_char,
};

/// Wraps a function call, allowing it to specify an error receiver and (optionally) result receiver
///
/// If the `out` parameter is omitted, the function's return value will be
/// expected to be a pointer on success, or NULL if the function call returns an error.
///
/// If the `out` parameter is included, the function will return a `bool`
/// indicating success, and *either* populate the `out` input variable with the
/// result, or the `err` input variable with a pointer to an FRSError struct.
///
/// Example (on the Rust side)
/// ```
/// use frs_error::{frs_result, FRSError};
/// use num_traits::CheckedDiv;
///
/// pub fn checked_div<T>(numerator: T, denominator: T) -> Result<T, MyError>
/// where
/// T: CheckedDiv,
/// {
///     numerator
///         .checked_div(&denominator)
///         .ok_or(MyError::DivByZero)
/// }
///
/// #[no_mangle]
/// pub unsafe extern "C" fn checked_div_i64(
///    numerator: i64,
///    denominator: i64,
///    result: *mut i64,
///    err: *mut *mut FRSError,
/// ) -> bool {
///    frs_result!(checked_div(out = result, err = err, numerator, denominator))
/// }
/// ```
///
/// And from the C side:
/// ``` c
/// int64_t result;
/// FRSError *err = NULL;
///
/// if (checked_div_i64(10, 0, &result, &err)) {
///     return 0;
/// } else {
///     fprintf(stderr, "Error: %s\n", frserror_fmt(err));
///     frserror_free(err);
///     return 1;
/// }
/// ```
#[macro_export]
macro_rules! frs_result {
    ($fn:ident( out=$result_out:ident, err=$err:ident $(, $args:expr)* )) => {
        if $err.is_null() {
            panic!("{} is NULL", stringify!($err));
        } else {
            match $fn( $($args),* ) {
                Ok(result) => {
                    *$result_out = result;
                    true
                }
                Err(e) => {
                    *$err = Box::into_raw(Box::new(e.into()));
                    false
                }
            }
        }
    };

    ($fn:ident( err=$err:ident $(, $args:expr)* )) => {
        if $err.is_null() {
            panic!("{} is NULL", stringify!($err));
        } else {
            match $fn( $($args),* ) {
                Ok(result) => {
                    Box::into_raw(Box::new(result))
                    // result as *const ::core::ffi::c_void
                }
                Err(e) => {
                    *$err = Box::into_raw(Box::new(e.into()));
                    std::ptr::null()
                }
            }
        }
    };
}

#[repr(C)]
/// A generic container for any error that implements `Into<std::error::Error>`
pub struct FRSError {
    /// The contained error
    error: Box<dyn std::error::Error>,
    /// Cached formatted version of the error
    c_string: Option<CString>,
}

impl FRSError {
    pub(crate) fn get_cstring(&mut self) -> Result<&CStr, std::ffi::NulError> {
        if self.c_string.is_none() {
            self.c_string = Some(CString::new(format!("{}", self.error))?);
        }
        Ok(self.c_string.as_ref().unwrap().as_c_str())
    }
}

impl<T: 'static + std::error::Error> From<T> for FRSError {
    fn from(err: T) -> Self {
        FRSError {
            error: Box::new(err),
            c_string: None,
        }
    }
}

/// Compute (and cache) a formatted error string from the provided [`FRSError`] pointer.
///
/// # Safety
///
/// `err` must not be NULL
#[no_mangle]
pub unsafe extern "C" fn frserror_fmt(err: *mut FRSError) -> *const c_char {
    assert!(!err.is_null());
    let mut err: ManuallyDrop<Box<FRSError>> = ManuallyDrop::new(Box::from_raw(err));
    match err.get_cstring() {
        Ok(s) => s.as_ptr(),
        Err(_) => CStr::from_bytes_with_nul_unchecked(b"<error string contains NUL>\0").as_ptr(),
    }
}

/// Free a [`FRSError`] structure
///
/// # Safety
///
/// `err` must not be NULL
#[no_mangle]
pub unsafe extern "C" fn frserror_free(err: *mut FRSError) {
    assert!(!err.is_null());
    let _: Box<FRSError> = Box::from_raw(err);
}

#[cfg(test)]
mod tests {
    use super::FRSError;

    #[test]
    fn basic() {
        // Capture a typical error
        if let Err(e) = std::str::from_utf8(b"\x80") {
            let _: FRSError = e.into();
        }
    }

    #[test]
    fn size() {
        eprintln!("FRSError size = {}", std::mem::size_of::<FRSError>())
    }
}
