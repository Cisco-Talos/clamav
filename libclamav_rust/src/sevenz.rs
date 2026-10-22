/*
 * Streaming 7z scanner for libclamav.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates.
 * SPDX-License-Identifier: GPL-2.0-only
 */

use std::{
    ffi::{c_char, c_int, c_void, CString},
    io::{self, Read, Seek, SeekFrom},
    mem,
    panic::{self, AssertUnwindSafe},
    ptr,
};

use log::{debug, warn};
use sevenz_rust2::{ArchiveReader, EntryDecision, Error as SevenZError, Password};

use crate::{
    fmap::FMap,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_ERROR, cl_error_t_CL_EUNLINK, cl_error_t_CL_EWRITE, cl_error_t_CL_SUCCESS,
        cl_error_t_CL_VIRUS, cli_ctx,
    },
    util::{check_scan_limits, scan_archive_metadata},
};

const EXTRACTION_CHUNK_SIZE: usize = 64 * 1024;
const DECODER_MEMORY_LIMIT_KB: usize = 128 * 1024;
const HEURISTIC_ENCRYPTED_ARCHIVE: u32 = 0x40;
const HEURISTIC_EXCEEDS_MAX: u32 = 0x4;
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
    fn cli_append_potentially_unwanted(ctx: *mut cli_ctx, virname: *const c_char) -> cl_error_t;
    fn free(ptr: *mut c_void);
}

unsafe fn close_fd(fd: c_int) {
    unsafe { libc::close(fd) };
}

struct FMapReader {
    fmap: FMap,
    base: usize,
    position: usize,
}

impl FMapReader {
    fn new(fmap: FMap, base: usize) -> io::Result<Self> {
        if base > fmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "7z offset past EOF",
            ));
        }
        Ok(Self {
            fmap,
            base,
            position: 0,
        })
    }

    fn len(&self) -> usize {
        self.fmap.len() - self.base
    }
}

impl Read for FMapReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = buf.len().min(self.len().saturating_sub(self.position));
        if count == 0 {
            return Ok(0);
        }
        let at = self.base.checked_add(self.position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "7z read offset overflow")
        })?;
        let source = self
            .fmap
            .need_off(at, count)
            .map_err(|error| io::Error::new(io::ErrorKind::UnexpectedEof, error))?;
        buf[..count].copy_from_slice(source);
        self.position += count;
        Ok(count)
    }
}

impl Seek for FMapReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let len = i128::try_from(self.len()).map_err(|_| io::Error::other("7z size overflow"))?;
        let current =
            i128::try_from(self.position).map_err(|_| io::Error::other("7z position overflow"))?;
        let next = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(delta) => len + i128::from(delta),
            SeekFrom::Current(delta) => current + i128::from(delta),
        };
        if !(0..=len).contains(&next) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid 7z seek",
            ));
        }
        self.position = usize::try_from(next).map_err(|_| io::Error::other("7z seek overflow"))?;
        Ok(self.position as u64)
    }
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

    unsafe fn scan(mut self, ctx: *mut cli_ctx, name: &CString) -> cl_error_t {
        let result = unsafe {
            cli_magic_scan_desc(
                self.fd,
                self.path,
                ctx,
                name.as_ptr(),
                LAYER_ATTRIBUTES_NONE,
            )
        };
        let cleanup = self.cleanup();
        if result == cl_error_t_CL_SUCCESS {
            cleanup
        } else {
            result
        }
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

unsafe fn encrypted_heuristic_enabled(ctx: *mut cli_ctx) -> bool {
    unsafe {
        !ctx.is_null()
            && !(*ctx).options.is_null()
            && ((*(*ctx).options).heuristic & HEURISTIC_ENCRYPTED_ARCHIVE) != 0
    }
}

unsafe fn exceeds_max_heuristic_enabled(ctx: *mut cli_ctx) -> bool {
    unsafe {
        !ctx.is_null()
            && !(*ctx).options.is_null()
            && ((*(*ctx).options).heuristic & HEURISTIC_EXCEEDS_MAX) != 0
    }
}

unsafe fn record_limit_result(ctx: *mut cli_ctx, limit: cl_error_t) -> cl_error_t {
    if limit == cl_error_t_CL_EMAXSIZE || limit == cl_error_t_CL_EMAXFILES {
        if unsafe { exceeds_max_heuristic_enabled(ctx) } {
            cl_error_t_CL_VIRUS
        } else {
            cl_error_t_CL_SUCCESS
        }
    } else {
        limit
    }
}

fn merge_scan_result(current: cl_error_t, next: cl_error_t) -> cl_error_t {
    // A detection is final, and a later clean result must never erase an
    // earlier result. Otherwise retain the newest non-clean error so callers
    // receive the failure closest to where archive processing stopped.
    if current == cl_error_t_CL_VIRUS || next == cl_error_t_CL_SUCCESS {
        current
    } else {
        next
    }
}

unsafe fn report_encrypted(ctx: *mut cli_ctx) -> cl_error_t {
    if unsafe { encrypted_heuristic_enabled(ctx) } {
        const NAME: &[u8] = b"Heuristics.Encrypted.7Zip\0";
        unsafe { cli_append_potentially_unwanted(ctx, NAME.as_ptr().cast()) }
    } else {
        cl_error_t_CL_SUCCESS
    }
}

fn is_encrypted_error(error: &SevenZError) -> bool {
    matches!(
        error,
        SevenZError::PasswordRequired | SevenZError::MaybeBadPassword(_)
    )
}

fn is_unsupported_error(error: &SevenZError) -> bool {
    // Unsupported-but-well-formed content preserves the former scanner's clean
    // result. Structural, CRC, truncation, and resource errors intentionally do
    // not enter this set and are surfaced as CL_EFORMAT.
    matches!(
        error,
        SevenZError::ExternalUnsupported
            | SevenZError::UnsupportedCompressionMethod(_)
            | SevenZError::Unsupported(_)
    )
}

unsafe fn scan_impl(ctx: *mut cli_ctx, offset: usize) -> cl_error_t {
    if ctx.is_null() || unsafe { (*ctx).fmap.is_null() } {
        return cl_error_t_CL_ERROR;
    }
    let fmap = match FMap::try_from(unsafe { (*ctx).fmap }) {
        Ok(fmap) => fmap,
        Err(error) => {
            warn!("Unable to access 7z fmap: {error}");
            return cl_error_t_CL_ERROR;
        }
    };
    let source = match FMapReader::new(fmap, offset) {
        Ok(source) => source,
        Err(error) => {
            debug!("Invalid 7z source: {error}");
            return cl_error_t_CL_EFORMAT;
        }
    };
    let mut archive = match ArchiveReader::new_with_memory_limit(
        source,
        Password::empty(),
        DECODER_MEMORY_LIMIT_KB,
    ) {
        Ok(archive) => archive,
        Err(error) if is_encrypted_error(&error) => return unsafe { report_encrypted(ctx) },
        Err(error) if is_unsupported_error(&error) => {
            debug!("Unsupported 7z archive: {error}");
            return cl_error_t_CL_SUCCESS;
        }
        Err(error) => {
            debug!("Unable to parse 7z archive: {error}");
            return cl_error_t_CL_EFORMAT;
        }
    };
    // Keep decoder resource use predictable inside a process that may scan many
    // files concurrently. Dictionary/model memory is bounded separately above.
    archive.set_thread_count(1);

    let mut scan_result = cl_error_t_CL_SUCCESS;

    // Compression blocks are not required to follow file-table order, and
    // streamless entries are visited after all blocks by the extraction API.
    // Match metadata separately in the original table order so `filepos`
    // retains the zero-based value exposed by the former C SDK scanner.
    for (filepos, entry) in archive.archive().files.iter().enumerate() {
        // The old scanner did not submit directory metadata. Empty files and
        // anti-items are non-directory table entries and remain eligible.
        if entry.is_directory {
            continue;
        }

        let limit = unsafe { check_scan_limits("7unz", ctx, 0, 0, 0) };
        if limit != cl_error_t_CL_SUCCESS {
            return merge_scan_result(scan_result, unsafe { record_limit_result(ctx, limit) });
        }

        let is_encrypted = archive.archive().is_file_encrypted(filepos);
        if is_encrypted && unsafe { encrypted_heuristic_enabled(ctx) } {
            return merge_scan_result(scan_result, unsafe { report_encrypted(ctx) });
        }

        let metadata = unsafe {
            scan_archive_metadata(
                ctx,
                &entry.name,
                // Preserve the old 7z C scanner's signature-visible value.
                // A folder's packed size cannot be attributed reliably to
                // one member, especially for solid archives.
                0,
                usize::try_from(entry.size).unwrap_or(usize::MAX),
                is_encrypted,
                filepos,
                if entry.has_crc { entry.crc as i32 } else { 0 },
            )
        };
        if metadata != cl_error_t_CL_SUCCESS {
            return merge_scan_result(scan_result, metadata);
        }
    }

    let extraction = archive.for_each_entries_with_decision(|entry, reader| {
        if !entry.has_stream || entry.is_directory || entry.is_anti_item {
            return Ok(EntryDecision::Continue);
        }

        let limit = unsafe { check_scan_limits("7unz", ctx, 0, 0, 0) };
        if limit != cl_error_t_CL_SUCCESS {
            scan_result =
                merge_scan_result(scan_result, unsafe { record_limit_result(ctx, limit) });
            return Ok(EntryDecision::Stop);
        }

        let name = CString::new(entry.name.as_bytes()).unwrap_or_else(|_| CString::default());
        // Some malformed or unusual archives associate a stream with an entry
        // that ultimately produces no bytes. Delay allocating the temporary
        // file until the decoder returns the first bounded output chunk.
        let mut temp: Option<TempFile> = None;
        let mut actual_size = 0u64;
        let mut buffer = [0u8; EXTRACTION_CHUNK_SIZE];
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => {
                    // A falsified size, CRC failure, or truncated stream must not
                    // discard bytes the decoder already produced. Scan the
                    // bounded partial output before reporting the format error.
                    if let Some(temp) = temp.take() {
                        let entry_result = unsafe { temp.scan(ctx, &name) };
                        scan_result = merge_scan_result(scan_result, entry_result);
                        if entry_result != cl_error_t_CL_SUCCESS {
                            return Ok(EntryDecision::Stop);
                        }
                    }
                    return Err(error.into());
                }
            };
            if count == 0 {
                break;
            }
            actual_size = actual_size.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "7z extracted size overflow")
            })?;
            // Enforce limits using bytes actually produced, never entry.size.
            let limit = unsafe { check_scan_limits("7unz", ctx, actual_size, 0, 0) };
            if limit != cl_error_t_CL_SUCCESS {
                scan_result =
                    merge_scan_result(scan_result, unsafe { record_limit_result(ctx, limit) });
                return Ok(if limit == cl_error_t_CL_EMAXSIZE {
                    EntryDecision::SkipBlock
                } else {
                    EntryDecision::Stop
                });
            }
            if temp.is_none() {
                temp = match unsafe { TempFile::create(ctx) } {
                    Ok(temp) => Some(temp),
                    Err(error) => {
                        scan_result = merge_scan_result(scan_result, error);
                        return Ok(EntryDecision::Stop);
                    }
                };
            }
            let Some(temp) = temp.as_ref() else {
                return Err(io::Error::other("7z temporary file was not created").into());
            };
            if temp.write_all(&buffer[..count]).is_err() {
                scan_result = merge_scan_result(scan_result, cl_error_t_CL_EWRITE);
                return Ok(EntryDecision::Stop);
            }
        }
        if let Some(temp) = temp {
            let entry_result = unsafe { temp.scan(ctx, &name) };
            scan_result = merge_scan_result(scan_result, entry_result);
            if entry_result != cl_error_t_CL_SUCCESS {
                return Ok(EntryDecision::Stop);
            }
        }
        Ok(EntryDecision::Continue)
    });

    match extraction {
        Ok(()) => scan_result,
        Err(error) if is_encrypted_error(&error) => {
            merge_scan_result(scan_result, unsafe { report_encrypted(ctx) })
        }
        Err(error) if is_unsupported_error(&error) => {
            debug!("Unsupported 7z compression method: {error}");
            scan_result
        }
        Err(error) => {
            debug!("7z extraction failed: {error}");
            if scan_result == cl_error_t_CL_SUCCESS {
                cl_error_t_CL_EFORMAT
            } else {
                scan_result
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn scan_7z(ctx: *mut cli_ctx, offset: usize) -> cl_error_t {
    match panic::catch_unwind(AssertUnwindSafe(|| unsafe { scan_impl(ctx, offset) })) {
        Ok(result) => result,
        Err(payload) => {
            let dropping = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)));
            if let Err(payload) = dropping {
                mem::forget(payload);
            }
            let logging =
                panic::catch_unwind(AssertUnwindSafe(|| warn!("Panic while parsing 7z archive")));
            if let Err(payload) = logging {
                mem::forget(payload);
            }
            cl_error_t_CL_EFORMAT
        }
    }
}
