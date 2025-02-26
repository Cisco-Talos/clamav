/*
 *  Various functions to ease working through FFI
 *
 *  Copyright (C) 2022-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use log::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Null Parameter: {0}")]
    NullParameter(String),
}

/// Wraps a call to a "result-returning function", allowing it to specify an
/// error receiver and (optionally) result receiver.
///
/// If the `out` parameter is omitted, the function's return value will be
/// expected to be a pointer on success, or NULL if the function call returns an error.
///
/// If the `out` parameter is included, the function will return a `bool`
/// indicating success, and *either* populate the `out` input variable with the
/// result, or the `err` input variable with a pointer to an FFIError struct.
///
/// Example (on the Rust side)
/// ```
/// use ffi_util::{ffi_result, FFIError};
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
///    err: *mut *mut FFIError,
/// ) -> bool {
///    rrf_call!(out = result, err = err, checked_div(numerator, denominator))
/// }
/// ```
///
/// And from the C side:
/// ``` c
/// int64_t result;
/// FFIError *err = NULL;
///
/// if (checked_div_i64(10, 0, &result, &err)) {
///     return 0;
/// } else {
///     fprintf(stderr, "Error: %s\n", ffierror_fmt(err));
///     ffierror_free(err);
///     return 1;
/// }
/// ```
#[macro_export]
macro_rules! rrf_call {
    (err = $err_out:ident, $($fn:ident).+( $($args:expr),* )) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err_out));
        } else {
            match $($fn).*( $($args),* ) {
                Ok(()) => {
                    true
                }
                Err(e) => {
                    *$err_out = Box::into_raw(Box::new(e.into()));
                    false
                }
            }
        }
    };

    (out = $result_out:ident, err=$err_out:ident, $($fn:ident).+( $($args:expr),* )) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err_out));
        } else {
            match $($fn).*( $($args),* ) {
                Ok(result) => {
                    *$result_out = result;
                    true
                }
                Err(e) => {
                    *$err_out = Box::into_raw(Box::new(e.into()));
                    false
                }
            }
        }
    };

    ($fn:ident( err=$err_out:ident $(, $args:expr)* )) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err_out));
        } else {
            match $fn( $($args),* ) {
                Ok(result) => {
                    Box::into_raw(Box::new(result))
                    // result as *const ::core::ffi::c_void
                }
                Err(e) => {
                    *$err_out = Box::into_raw(Box::new(e.into()));
                    std::ptr::null()
                }
            }
        }
    };
}

/// Consume the specified `Result<T,E>`, update output variables, and return true
/// (if Result::is_ok) or false (if Result::is_err).
//
/// The `Result`'s `E` must implement `std::error::Error`.
///
/// The `out` parameter is optional, and the Result's "ok" value will be ignored
/// if `out` is omitted.
///
/// Or for returning errors more explicitly without a function call:
/// ```
/// #[no_mangle]
/// pub unsafe extern "C" fn checked_div_i64(
///    numerator: i64,
///    denominator: i64,
///    out: *mut i64,
///    err: *mut *mut FFIError,
/// ) -> bool {
///    let div_result = checked_div(numerator, denominator);
///
///    // Do other things that examine `div_result`, but don't consume it
///    // ...
///
///    // Finally return
///    ffi_result!(result_in = div_result, out = out, err = err)
/// }
/// ```
///
#[macro_export]
macro_rules! ffi_result {
    (result_in=$result_in:ident, err=$err_out:ident) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err_out));
        } else {
            match $result_in {
                Ok(_) => true,
                Err(e) => {
                    *$err_out = Box::into_raw(Box::new(e.into()));
                    false
                }
            }
        }
    };

    (result_in=$result_in:ident, out=$result_out:ident, err=$err:ident) => {
        if $err.is_null() {
            panic!("{} is NULL", stringify!($err));
        } else {
            match $result_in {
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
}

/// Consume the specified error and update an output variable, returning false.
///
/// The given error must implement `std::error::Error`.
///
/// This macro is best used when specifically returning an error encountered
/// outside of wrapping a Result-returning function (such as input validation).
#[macro_export]
macro_rules! ffi_error {
    (err=$err_out:ident, $err:expr) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err));
        } else {
            *$err_out = Box::into_raw(Box::new($err.into()));
            false
        }
    };
}

/// Consume the specified error and update an output variable, returning null.
///
/// The given error must implement `std::error::Error`.
///
/// This macro is best used when specifically returning an error encountered
/// outside of wrapping a Result-returning function (such as input validation).
#[macro_export]
macro_rules! ffi_error_null {
    (err=$err_out:ident, $err:expr) => {
        if $err_out.is_null() {
            panic!("{} is NULL", stringify!($err));
        } else {
            *$err_out = Box::into_raw(Box::new($err.into()));
            std::ptr::null_mut()
        }
    };
}

/// A generic container for any error that implements `Into<std::error::Error>`
pub struct FFIError {
    /// The contained error
    error: Box<dyn std::error::Error>,
    /// Cached formatted version of the error
    c_string: Option<CString>,
}

impl FFIError {
    pub(crate) fn get_cstring(&mut self) -> Result<&CStr, std::ffi::NulError> {
        if self.c_string.is_none() {
            self.c_string = Some(CString::new(format!("{}", self.error))?);
        }
        Ok(self.c_string.as_ref().unwrap().as_c_str())
    }
}

impl<T: 'static + std::error::Error> From<T> for FFIError {
    fn from(err: T) -> Self {
        FFIError {
            error: Box::new(err),
            c_string: None,
        }
    }
}

/// Compute (and cache) a formatted error string from the provided [`FFIError`] pointer.
///
/// # Safety
///
/// `err` must not be NULL
#[no_mangle]
pub unsafe extern "C" fn ffierror_fmt(err: *mut FFIError) -> *const c_char {
    assert!(!err.is_null());
    let mut err: ManuallyDrop<Box<FFIError>> = ManuallyDrop::new(Box::from_raw(err));
    match err.get_cstring() {
        Ok(s) => s.as_ptr(),
        Err(_) => CStr::from_bytes_with_nul_unchecked(b"<error string contains NUL>\0").as_ptr(),
    }
}

/// Free a [`FFIError`] structure
///
/// # Safety
///
/// `err` must not be NULL
#[no_mangle]
pub unsafe extern "C" fn ffierror_free(err: *mut FFIError) {
    assert!(!err.is_null());
    let _: Box<FFIError> = Box::from_raw(err);
}

#[cfg(test)]
mod tests {
    use super::FFIError;

    #[test]
    fn basic() {
        // Capture a typical error
        if let Err(e) = std::str::from_utf8(b"\x80") {
            let _: FFIError = e.into();
        }
    }

    #[test]
    fn size() {
        eprintln!("FFIError size = {}", std::mem::size_of::<FFIError>())
    }
}

/// Verify that the given parameter is not NULL, and valid UTF-8,
/// returns a &str if successful else returns sys::cl_error_t_CL_EARG
///
/// # Examples
///
/// ```edition2018
/// use util::validate_str_param;
///
/// # pub extern "C" fn _my_c_interface(blah: *const c_char) -> sys::cl_error_t {
///    let blah = validate_str_param!(blah);
/// # }
/// ```
/// ```edition2018
/// use util::validate_str_param;
///
/// # pub extern "C" fn _my_c_interface(blah: *const c_char) -> sys::cl_error_t {
///    let blah = validate_str_param!(blah, err = err);
/// # }
/// ```
#[macro_export]
macro_rules! validate_str_param {
    ($ptr:ident) => {
        if $ptr.is_null() {
            warn!("{} is NULL", stringify!($ptr));
            return false;
        } else {
            #[allow(unused_unsafe)]
            match unsafe { CStr::from_ptr($ptr) }.to_str() {
                Err(e) => {
                    warn!("{} is not valid unicode: {}", stringify!($ptr), e);
                    return false;
                }
                Ok(s) => s,
            }
        }
    };

    ($ptr:ident, err=$err:ident) => {
        if $ptr.is_null() {
            warn!("{} is NULL", stringify!($ptr));

            *$err = Box::into_raw(Box::new(
                crate::ffi_util::Error::NullParameter(stringify!($ptr).to_string()).into(),
            ));
            return false;
        } else {
            #[allow(unused_unsafe)]
            match unsafe { CStr::from_ptr($ptr) }.to_str() {
                Err(e) => {
                    warn!("{} is not valid unicode: {}", stringify!($ptr), e);

                    *$err = Box::into_raw(Box::new(e.into()));
                    return false;
                }
                Ok(s) => s,
            }
        }
    };
}

/// Verify that the given parameter is not NULL, and valid UTF-8,
/// returns a &str if successful else returns sys::cl_error_t_CL_EARG
///
/// # Examples
///
/// ```edition2018
/// use util::validate_optional_str_param;
///
/// # pub extern "C" fn _my_c_interface(blah: *const c_char) -> sys::cl_error_t {
///    let blah = validate_optional_str_param!(blah);
/// # }
/// ```
#[macro_export]
macro_rules! validate_optional_str_param {
    ($ptr:ident) => {
        if $ptr.is_null() {
            None
        } else {
            #[allow(unused_unsafe)]
            match unsafe { CStr::from_ptr($ptr) }.to_str() {
                Err(e) => {
                    warn!("{} is not valid unicode: {}", stringify!($ptr), e);
                    return false;
                }
                Ok(s) => Some(s),
            }
        }
    };
}

/// Verify that the given parameter is not NULL, and valid UTF-8,
/// returns a &str if successful else returns sys::cl_error_t_CL_EARG
///
/// This variant is for use in functions that return *mut c_void success value.
///
/// # Examples
///
/// ```edition2018
/// use util::validate_str_param;
///
/// # pub extern "C" fn _my_c_interface(blah: *const c_char) -> sys::cl_error_t {
///    let blah = validate_str_param!(blah);
/// # }
/// ```
#[macro_export]
macro_rules! validate_str_param_null {
    ($ptr:ident) => {
        if $ptr.is_null() {
            warn!("{} is NULL", stringify!($ptr));
            return std::ptr::null_mut();
        } else {
            #[allow(unused_unsafe)]
            match unsafe { CStr::from_ptr($ptr) }.to_str() {
                Err(e) => {
                    warn!("{} is not valid unicode: {}", stringify!($ptr), e);
                    return std::ptr::null_mut();
                }
                Ok(s) => s,
            }
        }
    };
}

/// C interface to free a CString.
/// Handles all the unsafe ffi stuff.
/// Frees the CString.
///
/// # Safety
///
/// The CString pointer must be valid
/// The CString pointer must not be used after calling this function
#[export_name = "ffi_cstring_free"]
pub unsafe extern "C" fn ffi_cstring_free(cstring: *mut c_char) {
    if cstring.is_null() {
        warn!("Attempted to free a NULL CString pointer. Please report this at:: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { CString::from_raw(cstring) };
    }
}
