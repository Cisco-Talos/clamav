//
// Copyright (C) 2020 Jonas Zaddach.
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

#![allow(non_camel_case_types, non_upper_case_globals)]

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

#[cfg(test)]
mod tests {
    use super::cl_msg;

    #[test]
    fn msg_levels_exist() {
        // Just a compilation check that the message levels are there. We don't
        // check their values since those are defined in the C header file.
        assert!(cl_msg::CL_MSG_WARN as isize != 0);
        assert!(cl_msg::CL_MSG_ERROR as isize != 0);
        assert!(cl_msg::CL_MSG_INFO_VERBOSE as isize != 0);
    }
}
