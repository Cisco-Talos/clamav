/* rust logging module */

use std::ffi::c_void;
use std::ffi::CString;
use std::os::raw::c_char;

extern crate log;
//use log::debug;

use self::log::{Level, Metadata, Record};
use self::log::{LevelFilter};

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
                _ => {},
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
