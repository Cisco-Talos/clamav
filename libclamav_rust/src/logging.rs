/*
 *  Rust logging module
 *
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use log::{set_max_level, Level, LevelFilter, Metadata, Record};

use crate::sys;

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
                    sys::cli_dbgmsg_no_inline(ptr);
                },
                Level::Error => unsafe {
                    sys::cli_errmsg(ptr);
                },
                Level::Info => unsafe {
                    sys::cli_infomsg_simple(ptr);
                },
                Level::Warn => unsafe {
                    sys::cli_warnmsg(ptr);
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
        .map(|()| set_max_level(LevelFilter::Debug))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::clrs_log_init;
    use log::{debug, error, info, warn};

    #[test]
    fn parse_move_works() {
        let init_status = clrs_log_init();
        assert!(init_status);
        debug!("Hello");
        info!("darkness");
        warn!("my old");
        error!("friend.");
    }
}

/// API exported for C code to log to standard error using Rust.
/// This would be an alternative to fputs, and reliably prints
/// non-ASCII UTF8 characters on Windows, where fputs does not.
///
/// # Safety
///
/// This function dereferences the c_buff raw pointer. Pointer must be valid.
#[no_mangle]
pub unsafe extern "C" fn clrs_eprint(c_buf: *const c_char) {
    if c_buf.is_null() {
        return;
    }

    let msg = unsafe { CStr::from_ptr(c_buf) }.to_string_lossy();
    eprint!("{}", msg);
}
