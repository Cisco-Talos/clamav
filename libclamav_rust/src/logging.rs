/*
 *  Rust logging module
 *
 *  Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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

use std::ffi::c_void;
use std::ffi::CString;
use std::os::raw::c_char;

extern crate log;

use self::log::LevelFilter;
use self::log::{Level, Metadata, Record};

extern "C" {
    fn cli_warnmsg(str: *const c_char, ...) -> c_void;
    fn cli_dbgmsg(str: *const c_char, ...) -> c_void;
    fn cli_infomsg_simple(str: *const c_char, ...) -> c_void;
    fn cli_errmsg(str: *const c_char, ...) -> c_void;
}

pub struct ClamLogger;

impl log::Log for ClamLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = CString::new(format!("{}\n", record.args())).unwrap();
            let ptr = msg.as_ptr();

            match record.level() {
                Level::Debug => unsafe {
                    cli_dbgmsg(ptr);
                },
                Level::Error => unsafe {
                    cli_errmsg(ptr);
                },
                Level::Info => unsafe {
                    cli_infomsg_simple(ptr);
                },
                Level::Warn => unsafe {
                    cli_warnmsg(ptr);
                },
                _ => {}
            }
        }
    }

    fn flush(&self) {}
}

#[no_mangle]
pub extern "C" fn clrs_log_init() -> bool {
    log::set_boxed_logger(Box::new(ClamLogger))
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .is_ok()
}
