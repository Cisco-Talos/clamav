// Copyright (C) 2020-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
//
// Authors: Jonas Zaddach, Scott Hutton
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.

#![warn(clippy::all, clippy::pedantic)]
#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    clippy::unreadable_literal
)]

use std::ffi::CStr;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl Default for cl_scan_options {
    fn default() -> Self {
        cl_scan_options {
            general: 0,
            parse: CL_SCAN_PARSE_ARCHIVE
                | CL_SCAN_PARSE_MAIL
                | CL_SCAN_PARSE_OLE2
                | CL_SCAN_PARSE_PDF
                | CL_SCAN_PARSE_HTML
                | CL_SCAN_PARSE_SWF
                | CL_SCAN_PARSE_PE
                | CL_SCAN_PARSE_ELF
                | CL_SCAN_PARSE_SWF
                | CL_SCAN_PARSE_XMLDOCS,
            heuristic: 0,
            mail: 0,
            dev: 0,
        }
    }
}

impl PartialEq for cl_scan_options {
    fn eq(&self, other: &Self) -> bool {
        self.general == other.general
            && self.parse == other.parse
            && self.heuristic == other.heuristic
            && self.mail == other.mail
            && self.dev == other.dev
    }
}

/// We need this for Windows, MSVC will use an `i32` as underlying enum type instead of `u32` like
/// gcc and clang.
impl From<i32> for cl_error_t {
    fn from(val: i32) -> cl_error_t {
        unsafe { cl_error_t(std::mem::transmute(val)) }
    }
}

impl From<u32> for cl_error_t {
    fn from(val: u32) -> cl_error_t {
        cl_error_t(val)
    }
}

impl From<cl_error_t> for i32 {
    fn from(val: cl_error_t) -> i32 {
        unsafe { std::mem::transmute(val.0) }
    }
}

impl From<cl_error_t> for u32 {
    fn from(val: cl_error_t) -> u32 {
        val.0
    }
}

impl std::fmt::Display for cl_error_t {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let msg = CStr::from_ptr(cl_strerror(*self));
            f.write_str(msg.to_str().unwrap_or("<unknown ClamAV error>"))
        }
    }
}

/// We need this for Windows, MSVC will use an `i32` as underlying enum type instead of `u32` like
/// gcc and clang.
impl From<i32> for cl_engine_field {
    fn from(val: i32) -> cl_engine_field {
        unsafe { cl_engine_field(std::mem::transmute(val)) }
    }
}

impl From<u32> for cl_engine_field {
    fn from(val: u32) -> cl_engine_field {
        cl_engine_field(val)
    }
}

impl From<cl_engine_field> for i32 {
    fn from(val: cl_engine_field) -> i32 {
        unsafe { std::mem::transmute(val.0) }
    }
}

impl From<cl_engine_field> for u32 {
    fn from(val: cl_engine_field) -> u32 {
        val.0
    }
}

impl std::fmt::Display for cl_engine_field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// We need this for Windows, MSVC will use an `i32` as underlying enum type instead of `u32` like
/// gcc and clang.
impl From<i32> for cl_msg {
    fn from(val: i32) -> cl_msg {
        unsafe { cl_msg(std::mem::transmute(val)) }
    }
}

impl From<u32> for cl_msg {
    fn from(val: u32) -> cl_msg {
        cl_msg(val)
    }
}

impl From<cl_msg> for i32 {
    fn from(val: cl_msg) -> i32 {
        unsafe { std::mem::transmute(val.0) }
    }
}

impl From<cl_msg> for u32 {
    fn from(val: cl_msg) -> u32 {
        val.0
    }
}

impl std::fmt::Display for cl_msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::cl_msg;

    #[test]
    fn msg_levels_exist() {
        // Just a compilation check that the message levels are there. We don't
        // check their values since those are defined in the C header file.
        assert!(cl_msg::CL_MSG_WARN != cl_msg(0));
        assert!(cl_msg::CL_MSG_ERROR != cl_msg(0));
        assert!(cl_msg::CL_MSG_INFO_VERBOSE != cl_msg(0));
    }

    #[test]
    fn test_cl_error_t_to_string() {
        let err = super::cl_error_t::CL_EMEM;
        assert_eq!(err.to_string(), "Can't allocate memory".to_string());
    }
}
