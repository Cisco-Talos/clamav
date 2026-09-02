/*
 * Streaming XZ scanner for libclamav.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates.
 * SPDX-License-Identifier: GPL-2.0-only
 */

use std::{
    ffi::{c_char, c_int, c_void},
    io, mem,
    panic::{self, AssertUnwindSafe},
    ptr,
};

use log::{debug, error, warn};
use lzma_rust2::{Action, Status, XzStream};

use crate::{
    fmap::FMap,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_ERROR, cl_error_t_CL_EUNLINK, cl_error_t_CL_EWRITE,
        cl_error_t_CL_SUCCESS, cli_ctx,
    },
    util::check_scan_limits,
};

const INPUT_CHUNK_SIZE: usize = 64 * 1024;
const OUTPUT_CHUNK_SIZE: usize = 64 * 1024;
const DECODER_MEMORY_LIMIT_KB: u32 = 128 * 1024;
const LAYER_ATTRIBUTES_NONE: u32 = 0;

unsafe extern "C" {
    fn cli_gentempfd(dir: *const c_char, name: *mut *mut c_char, fd: *mut c_int) -> cl_error_t;
    fn cli_magic_scan_desc(
        desc: c_int,
        filepath: *const c_char,
        ctx: *mut cli_ctx,
        name: *const c_char,
        attributes: u32,
    ) -> cl_error_t;
    fn cli_unlink(pathname: *const c_char) -> cl_error_t;
    fn cli_writen(fd: c_int, buffer: *const c_void, count: usize) -> usize;
    fn free(ptr: *mut c_void);
}

unsafe fn close_fd(fd: c_int) {
    unsafe { libc::close(fd) };
}

// `cli_gentempfd()` returns a C runtime descriptor on Windows. Keep that
// descriptor as the sole owner: constructing a Rust `File` from its underlying
// OS handle would close the handle without releasing the CRT descriptor slot.
struct TempFile {
    fd: c_int,
    path: *mut c_char,
    keep: bool,
}

impl TempFile {
    unsafe fn create(ctx: *mut cli_ctx) -> Result<Self, cl_error_t> {
        let mut path = ptr::null_mut();
        let mut fd = -1;
        let result = unsafe { cli_gentempfd((*ctx).this_layer_tmpdir, &mut path, &mut fd) };
        if result != cl_error_t_CL_SUCCESS {
            return Err(result);
        }
        Ok(Self {
            fd,
            path,
            keep: unsafe { !(*ctx).engine.is_null() && (*(*ctx).engine).keeptmp != 0 },
        })
    }

    fn write_all(&self, bytes: &[u8]) -> Result<(), cl_error_t> {
        if bytes.is_empty() {
            return Ok(());
        }
        let written = unsafe { cli_writen(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        if written == bytes.len() {
            Ok(())
        } else {
            Err(cl_error_t_CL_EWRITE)
        }
    }

    unsafe fn scan(&self, ctx: *mut cli_ctx) -> cl_error_t {
        unsafe { cli_magic_scan_desc(self.fd, self.path, ctx, ptr::null(), LAYER_ATTRIBUTES_NONE) }
    }

    fn cleanup(&mut self) -> cl_error_t {
        if self.fd >= 0 {
            unsafe { close_fd(self.fd) };
            self.fd = -1;
        }
        if self.path.is_null() {
            return cl_error_t_CL_SUCCESS;
        }
        let result = if self.keep || unsafe { cli_unlink(self.path) } == cl_error_t_CL_SUCCESS {
            cl_error_t_CL_SUCCESS
        } else {
            cl_error_t_CL_EUNLINK
        };
        unsafe { free(self.path.cast()) };
        self.path = ptr::null_mut();
        result
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn decoder_error(error: &io::Error) -> cl_error_t {
    if error.kind() == io::ErrorKind::OutOfMemory {
        cl_error_t_CL_EMEM
    } else {
        cl_error_t_CL_EFORMAT
    }
}

unsafe fn scan_xz_impl(ctx: *mut cli_ctx) -> cl_error_t {
    if ctx.is_null() {
        return cl_error_t_CL_ERROR;
    }
    let fmap = match FMap::try_from(unsafe { (*ctx).fmap }) {
        Ok(fmap) => fmap,
        Err(error) => {
            error!("cli_scanxz: invalid fmap: {error}");
            return cl_error_t_CL_ERROR;
        }
    };
    let mut tempfile = match unsafe { TempFile::create(ctx) } {
        Ok(tempfile) => tempfile,
        Err(result) => {
            error!("cli_scanxz: cannot create temporary file");
            return result;
        }
    };

    debug!("cli_scanxz: decompressing XZ stream");
    let mut decoder = XzStream::new_mem_limit(true, DECODER_MEMORY_LIMIT_KB);
    let mut input_offset = 0usize;
    let mut output_size = 0u64;

    // This inner guard converts a decoder panic into a scan result without
    // skipping the partial-output scan and deterministic temporary-file cleanup
    // below. The outer guard on `cli_scanxz` protects the complete C ABI call.
    let decode_result = panic::catch_unwind(AssertUnwindSafe(|| loop {
        let input_len = INPUT_CHUNK_SIZE.min(fmap.len().saturating_sub(input_offset));
        let input = if input_len == 0 {
            &[][..]
        } else {
            match fmap.need_off(input_offset, input_len) {
                Ok(input) => input,
                Err(error) => {
                    debug!("cli_scanxz: cannot read compressed input: {error}");
                    break cl_error_t_CL_ERROR;
                }
            }
        };
        // Concatenated-stream mode cannot report final completion until it sees
        // physical EOF. Submit empty Finish calls after all mapped input has
        // been consumed until buffered output and the final stream are validated.
        let action = if input_offset == fmap.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let mut output = [0u8; OUTPUT_CHUNK_SIZE];
        let result = match decoder.process(input, &mut output, action) {
            Ok(result) => result,
            Err(error) => {
                debug!("cli_scanxz: decompression error: {error}");
                break decoder_error(&error);
            }
        };

        input_offset = match input_offset.checked_add(result.bytes_consumed) {
            Some(offset) if offset <= fmap.len() => offset,
            _ => break cl_error_t_CL_EFORMAT,
        };
        if result.bytes_produced != 0 {
            if let Err(result) = tempfile.write_all(&output[..result.bytes_produced]) {
                error!("cli_scanxz: cannot write decompressed output");
                break result;
            }
            output_size = match output_size.checked_add(result.bytes_produced as u64) {
                Some(size) => size,
                None => break cl_error_t_CL_EMEM,
            };
            let limit_result = unsafe { check_scan_limits("cli_scanxz", ctx, output_size, 0, 0) };
            if limit_result != cl_error_t_CL_SUCCESS {
                warn!("cli_scanxz: scan limit reached; only scanning {output_size} bytes");
                // Preserve archive-limit behavior: scan the bounded partial
                // output and let any exceeds-max evidence determine the final
                // verdict. Unlike ordinary size/file limits, a timeout must be
                // propagated because it aborts the whole scan.
                break if limit_result == cl_error_t_CL_EMAXSIZE
                    || limit_result == cl_error_t_CL_EMAXFILES
                {
                    cl_error_t_CL_SUCCESS
                } else {
                    limit_result
                };
            }
        }

        if result.status == Status::StreamEnd {
            break cl_error_t_CL_SUCCESS;
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
            debug!("cli_scanxz: decoder made no progress");
            break cl_error_t_CL_EFORMAT;
        }
    }));

    let decode_result = match decode_result {
        Ok(result) => result,
        Err(_) => {
            error!("cli_scanxz: panic while decompressing XZ data");
            cl_error_t_CL_ERROR
        }
    };

    // Scan useful output even when a later stream is malformed. This prevents a
    // corrupt tail from hiding content successfully decoded before the error.
    let scan_result = unsafe { tempfile.scan(ctx) };
    let cleanup_result = tempfile.cleanup();
    if scan_result != cl_error_t_CL_SUCCESS {
        scan_result
    } else if decode_result != cl_error_t_CL_SUCCESS {
        decode_result
    } else {
        cleanup_result
    }
}

/// Decompress and scan all streams in an XZ file.
///
/// # Safety
///
/// `ctx` must either be null or point to a valid libclamav scan context.
#[no_mangle]
pub unsafe extern "C" fn cli_scanxz(ctx: *mut cli_ctx) -> cl_error_t {
    // Nothing may unwind through this C ABI boundary, including temporary-file
    // cleanup or logging after the narrower decoder guard has run.
    match panic::catch_unwind(AssertUnwindSafe(|| unsafe { scan_xz_impl(ctx) })) {
        Ok(result) => result,
        Err(payload) => {
            let dropping = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)));
            if let Err(payload) = dropping {
                mem::forget(payload);
            }
            let logging = panic::catch_unwind(AssertUnwindSafe(|| {
                error!("cli_scanxz: panic at the Rust FFI boundary")
            }));
            if let Err(payload) = logging {
                mem::forget(payload);
            }
            cl_error_t_CL_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XZ_HELLO: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x1c,
        0x18, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xed,
        0x1f, 0x76, 0x01, 0x00, 0x17, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x58, 0x5a, 0x20,
        0x63, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00,
        0x7b, 0xef, 0x17, 0x96, 0x00, 0x01, 0x34, 0x18, 0x8a, 0xde, 0xc0, 0x88, 0x90, 0x42, 0x99,
        0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
    ];

    fn decode(
        input: &[u8],
        input_chunk_size: usize,
        output_chunk_size: usize,
    ) -> io::Result<Vec<u8>> {
        let mut decoder = XzStream::new_mem_limit(true, DECODER_MEMORY_LIMIT_KB);
        let mut offset = 0;
        let mut output = Vec::new();
        loop {
            let end = (offset + input_chunk_size).min(input.len());
            let action = if offset == input.len() {
                Action::Finish
            } else {
                Action::Run
            };
            let mut chunk = vec![0; output_chunk_size];
            let result = decoder.process(&input[offset..end], &mut chunk, action)?;
            offset += result.bytes_consumed;
            output.extend_from_slice(&chunk[..result.bytes_produced]);
            if result.status == Status::StreamEnd {
                return Ok(output);
            }
            if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "no progress"));
            }
        }
    }

    #[test]
    fn xz_is_finished_and_decoded_in_tiny_chunks() {
        assert_eq!(decode(XZ_HELLO, 1, 3).unwrap(), b"Hello, XZ chunked world!");
    }

    #[test]
    fn concatenated_xz_streams_are_all_decoded() {
        let input = [XZ_HELLO, XZ_HELLO].concat();
        assert_eq!(
            decode(&input, XZ_HELLO.len(), 7).unwrap(),
            b"Hello, XZ chunked world!Hello, XZ chunked world!"
        );
    }

    #[test]
    fn xz_dictionary_is_checked_before_decoder_allocation() {
        let mut stream = XzStream::new_mem_limit(true, 1);
        let mut output = [0u8; 16];
        assert!(stream.process(XZ_HELLO, &mut output, Action::Run).is_err());
    }
}
