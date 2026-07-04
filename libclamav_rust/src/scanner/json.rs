/*
 *  Safe Rust adapter for ClamAV JSON metadata helpers.
 *
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr,
};

use crate::sys::{cl_error_t, json_object};

unsafe extern "C" {
    fn cli_jsonobj(obj: *mut json_object, key: *const c_char) -> *mut json_object;
    fn cli_jsonarray(obj: *mut json_object, key: *const c_char) -> *mut json_object;
    fn cli_jsonstr(obj: *mut json_object, key: *const c_char, value: *const c_char) -> cl_error_t;
    fn cli_jsonint(obj: *mut json_object, key: *const c_char, value: i32) -> cl_error_t;
    fn cli_jsonuint64(obj: *mut json_object, key: *const c_char, value: u64) -> cl_error_t;
    fn cli_jsonbool(obj: *mut json_object, key: *const c_char, value: i32) -> cl_error_t;
    fn cli_ctime(timep: *const libc::time_t, buf: *mut c_char, bufsize: usize) -> *const c_char;
}

#[derive(Clone, Copy)]
pub(crate) struct JsonObject {
    raw: *mut json_object,
}

#[derive(Clone, Copy)]
pub(crate) struct JsonArray {
    raw: *mut json_object,
}

impl JsonObject {
    /// Wrap a ClamAV-owned JSON object pointer.
    ///
    /// # Safety
    ///
    /// `raw` must point to a live ClamAV `json_object` for the current scan
    /// layer. The wrapper never takes ownership.
    pub(crate) unsafe fn from_raw(raw: *mut json_object) -> Option<Self> {
        (!raw.is_null()).then_some(Self { raw })
    }

    pub(crate) fn object(self, key: &str) -> Option<Self> {
        let key = CString::new(key).ok()?;
        let object = unsafe { cli_jsonobj(self.raw, key.as_ptr()) };
        (!object.is_null()).then_some(Self { raw: object })
    }

    pub(crate) fn array(self, key: &str) -> Option<JsonArray> {
        let key = CString::new(key).ok()?;
        let array = unsafe { cli_jsonarray(self.raw, key.as_ptr()) };
        (!array.is_null()).then_some(JsonArray { raw: array })
    }

    pub(crate) fn string(self, key: &str, value: &str) {
        let Ok(key) = CString::new(key) else {
            return;
        };
        let Ok(value) = CString::new(value) else {
            return;
        };
        unsafe {
            let _ = cli_jsonstr(self.raw, key.as_ptr(), value.as_ptr());
        }
    }

    pub(crate) fn bool(self, key: &str, value: bool) {
        let Ok(key) = CString::new(key) else {
            return;
        };
        unsafe {
            let _ = cli_jsonbool(self.raw, key.as_ptr(), i32::from(value));
        }
    }

    pub(crate) fn u64_opt(self, key: &str, value: Option<u64>) {
        let Some(value) = value else {
            return;
        };
        let Ok(key) = CString::new(key) else {
            return;
        };
        unsafe {
            let _ = if let Ok(value) = i32::try_from(value) {
                cli_jsonint(self.raw, key.as_ptr(), value)
            } else {
                cli_jsonuint64(self.raw, key.as_ptr(), value)
            };
        }
    }

    pub(crate) fn hex_u32_opt(self, key: &str, value: Option<u32>) {
        if let Some(value) = value {
            self.string(key, &format!("0x{value:x}"));
        }
    }

    pub(crate) fn hex_u64_opt(self, key: &str, value: Option<u64>) {
        if let Some(value) = value {
            self.string(key, &format!("0x{value:x}"));
        }
    }

    pub(crate) fn timestamp_opt(self, key: &str, timestamp: Option<u32>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        let timestamp: libc::time_t = timestamp.into();
        let mut buffer = [0 as c_char; 128];
        let timestamp = unsafe { cli_ctime(&timestamp, buffer.as_mut_ptr(), buffer.len()) };
        if timestamp.is_null() {
            return;
        }
        let Ok(timestamp) = (unsafe { CStr::from_ptr(timestamp) }).to_str() else {
            return;
        };
        self.string(key, timestamp);
    }
}

impl JsonArray {
    pub(crate) fn object_item(self) -> Option<JsonObject> {
        let object = unsafe { cli_jsonobj(self.raw, ptr::null()) };
        (!object.is_null()).then_some(JsonObject { raw: object })
    }

    pub(crate) fn string_item(self, value: &str) {
        let Ok(value) = CString::new(value) else {
            return;
        };
        unsafe {
            let _ = cli_jsonstr(self.raw, ptr::null(), value.as_ptr());
        }
    }
}
