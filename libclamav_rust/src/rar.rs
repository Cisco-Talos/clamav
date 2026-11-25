/*
 *  Bounded RAR archive scanning through the rars crate.
 *
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

use std::{
    ffi::CStr,
    io::{self, Read, Seek, SeekFrom, Write},
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use log::{debug, warn};
use rars::{
    ArchiveMember, ArchiveMemberDetail, ArchiveReadOptions, ArchiveReader, Error as RarsError,
    ErrorKind as RarsErrorKind, ExtractionDecision, ExtractionErrorAction, Rar50Scratch,
    ReadCancellation,
};

use crate::{
    scanners::magic_scan,
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_EREAD, cl_error_t_CL_ERROR, cl_error_t_CL_ETIMEOUT,
        cl_error_t_CL_SUCCESS, cli_ctx, fmap_t,
    },
    util::{check_scan_limits, check_scan_time_limit, scan_archive_metadata},
};

const HEADER_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const HEADER_COUNT_LIMIT: u64 = 1_000_000;
const RAR5_BUFFERED_LIMIT: u64 = 16 * 1024 * 1024;
const RAR5_FILTER_WORKSPACE: u64 = 8 * 1024 * 1024;
const RAR5_SCRATCH_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

fn scan_timeout_error() -> io::Error {
    // Read::read_exact and Write::write_all retry Interrupted errors. A scan
    // deadline is terminal, so report a non-retryable error kind instead.
    io::Error::new(io::ErrorKind::TimedOut, "ClamAV scan time limit reached")
}

#[cfg(target_pointer_width = "64")]
const RAR5_DICTIONARY_LIMIT: u64 = 1024 * 1024 * 1024;
#[cfg(target_pointer_width = "32")]
const RAR5_DICTIONARY_LIMIT: u64 = 384 * 1024 * 1024;

#[cfg(target_pointer_width = "64")]
const READER_WORKSPACE_LIMIT: u64 = 1152 * 1024 * 1024;
#[cfg(target_pointer_width = "32")]
const READER_WORKSPACE_LIMIT: u64 = 512 * 1024 * 1024;

/// A seekable view of the current fmap.
///
/// rars requires ownership of a `'static` reader because the parsed archive
/// retains it. This adapter is valid only while `cli_scanrar_rust()` is running:
/// that function owns the parsed archive and drops it before returning to C.
/// Every read copies bytes while the fmap pages are locked and immediately
/// releases the lock, so rars never retains a borrowed fmap pointer.
struct FMapReader {
    fmap: NonNull<fmap_t>,
    ctx: NonNull<cli_ctx>,
    position: u64,
    length: u64,
    cancellation: ReadCancellation,
    status: Arc<AtomicU32>,
}

// SAFETY: The adapter is scoped synchronously to a single ClamAV scan and the
// rars dependency is built without its parallel feature. Although rars requires
// `Send` for an owned reader, this adapter is never accessed concurrently. All
// fmap access is completed, copied, and unlocked within each `read()` call.
unsafe impl Send for FMapReader {}

struct FMapLock {
    fmap: NonNull<fmap_t>,
    offset: usize,
    length: usize,
    unneed: unsafe extern "C" fn(*mut fmap_t, usize, usize),
}

impl Drop for FMapLock {
    fn drop(&mut self) {
        unsafe { (self.unneed)(self.fmap.as_ptr(), self.offset, self.length) };
    }
}

impl FMapReader {
    unsafe fn new(
        ctx: *mut cli_ctx,
        cancellation: ReadCancellation,
        status: Arc<AtomicU32>,
        length_limit: Option<u64>,
    ) -> Result<Self, cl_error_t> {
        let ctx = NonNull::new(ctx).ok_or(cl_error_t_CL_ERROR)?;
        let fmap = NonNull::new(unsafe { ctx.as_ref().fmap }).ok_or(cl_error_t_CL_ERROR)?;
        let source_length =
            u64::try_from(unsafe { fmap.as_ref().len }).map_err(|_| cl_error_t_CL_EREAD)?;
        let length = length_limit.unwrap_or(source_length).min(source_length);
        Ok(Self {
            fmap,
            ctx,
            position: 0,
            length,
            cancellation,
            status,
        })
    }

    fn fail(&self, status: cl_error_t, kind: io::ErrorKind, message: &'static str) -> io::Error {
        self.status.store(status, Ordering::Relaxed);
        self.cancellation.cancel();
        io::Error::new(kind, message)
    }

    fn check_time(&self) -> io::Result<()> {
        let status = unsafe { check_scan_time_limit(self.ctx.as_ptr()) };
        if status == cl_error_t_CL_SUCCESS {
            Ok(())
        } else {
            self.status.store(status, Ordering::Relaxed);
            self.cancellation.cancel();
            Err(scan_timeout_error())
        }
    }
}

impl Read for FMapReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check_time()?;
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }

        let remaining = self.length - self.position;
        let length = usize::try_from(remaining.min(output.len() as u64)).map_err(|_| {
            self.fail(
                cl_error_t_CL_EREAD,
                io::ErrorKind::InvalidData,
                "RAR read is too large",
            )
        })?;
        let offset = usize::try_from(self.position).map_err(|_| {
            self.fail(
                cl_error_t_CL_EREAD,
                io::ErrorKind::InvalidInput,
                "RAR read offset is too large",
            )
        })?;

        let fmap = unsafe { self.fmap.as_ref() };
        let need = fmap.need.ok_or_else(|| {
            self.fail(
                cl_error_t_CL_EREAD,
                io::ErrorKind::Unsupported,
                "fmap need callback is unavailable",
            )
        })?;
        let unneed = fmap.unneed_off.ok_or_else(|| {
            self.fail(
                cl_error_t_CL_EREAD,
                io::ErrorKind::Unsupported,
                "fmap unneed callback is unavailable",
            )
        })?;
        let source = unsafe { need(self.fmap.as_ptr(), offset, length, 1) }.cast::<u8>();
        if source.is_null() {
            return Err(self.fail(
                cl_error_t_CL_EREAD,
                io::ErrorKind::UnexpectedEof,
                "fmap read failed",
            ));
        }

        let lock = FMapLock {
            fmap: self.fmap,
            offset,
            length,
            unneed,
        };

        // SAFETY: `need` returned a locked range of exactly `length` bytes.
        // Copying cannot outlive `lock`; its Drop implementation releases the
        // fmap range on both the normal path and Rust unwinding.
        unsafe {
            output[..length].copy_from_slice(std::slice::from_raw_parts(source, length));
        }
        drop(lock);
        self.position += length as u64;
        Ok(length)
    }
}

impl Seek for FMapReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check_time()?;
        let position = match from {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
        };
        if !(0..=i128::from(self.length)).contains(&position) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAR seek is outside the fmap",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[derive(Clone, Copy)]
struct ScanLimits {
    max_file_size: u64,
    max_total_size: u64,
    max_headers: u64,
}

fn header_count_limit(max_files: u32) -> u64 {
    if max_files == 0 {
        HEADER_COUNT_LIMIT
    } else {
        u64::from(max_files)
            .saturating_mul(4)
            .saturating_add(1024)
            .clamp(1024, HEADER_COUNT_LIMIT)
    }
}

unsafe fn scan_limits(ctx: *mut cli_ctx) -> Result<ScanLimits, cl_error_t> {
    if ctx.is_null() || unsafe { (*ctx).engine.is_null() } {
        return Err(cl_error_t_CL_ERROR);
    }
    let engine = unsafe { &*(*ctx).engine };
    Ok(ScanLimits {
        max_file_size: if engine.maxfilesize == 0 {
            u64::MAX
        } else {
            engine.maxfilesize
        },
        max_total_size: if engine.maxscansize == 0 {
            u64::MAX
        } else {
            engine
                .maxscansize
                .saturating_sub(unsafe { (*ctx).scansize })
        },
        max_headers: header_count_limit(engine.maxfiles),
    })
}

fn scratch_limit(max_file_size: u64) -> u64 {
    if max_file_size == u64::MAX {
        RAR5_SCRATCH_LIMIT
    } else {
        max_file_size.saturating_mul(2).min(RAR5_SCRATCH_LIMIT)
    }
}

unsafe fn scratch_directory_from_path(path: *const std::os::raw::c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }

    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }

    #[cfg(windows)]
    {
        std::str::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

fn read_options<'a>(
    limits: ScanLimits,
    cancellation: &'a ReadCancellation,
    scratch: Option<&'a Rar50Scratch>,
) -> ArchiveReadOptions<'a> {
    let mut options = ArchiveReadOptions::new()
        .with_cancellation(cancellation)
        .with_max_header_count(limits.max_headers)
        .with_max_header_bytes(HEADER_BYTES_LIMIT)
        .with_rar50_buffered_decode_limit(RAR5_BUFFERED_LIMIT)
        .with_rar50_dictionary_size_limit(RAR5_DICTIONARY_LIMIT)
        .with_max_reader_workspace_bytes(READER_WORKSPACE_LIMIT)
        .with_max_member_output_bytes(limits.max_file_size)
        .with_max_total_output_bytes(limits.max_total_size)
        .with_rar50_decode_workers(0)
        .with_threads(1)
        .with_rar3_vm_programs(false);
    if let Some(scratch) = scratch {
        options = options.with_rar50_scratch(scratch);
    }
    options
}

fn sanitized_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', "�")
}

fn sanitized_basename(bytes: &[u8]) -> Option<String> {
    let base = bytes
        .rsplit(|byte| *byte == b'/' || *byte == b'\\')
        .next()?;
    if base.is_empty() {
        None
    } else {
        Some(sanitized_name(base))
    }
}

fn member_crc(member: &ArchiveMember) -> i32 {
    match &member.detail {
        ArchiveMemberDetail::Rar13 { file_checksum, .. } => i32::from(*file_checksum),
        ArchiveMemberDetail::Rar15To40 { crc32, .. } => *crc32 as i32,
        ArchiveMemberDetail::Rar50Plus { crc32, .. } => crc32.unwrap_or(0) as i32,
        _ => 0,
    }
}

struct MemberBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
    limit: usize,
    ctx: NonNull<cli_ctx>,
    cancellation: ReadCancellation,
    status: Arc<AtomicU32>,
}

impl Write for MemberBuffer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let status = unsafe { check_scan_time_limit(self.ctx.as_ptr()) };
        if status != cl_error_t_CL_SUCCESS {
            self.status.store(status, Ordering::Relaxed);
            self.cancellation.cancel();
            return Err(scan_timeout_error());
        }
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_| io::Error::other("RAR member buffer lock is poisoned"))?;
        let new_len = bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| io::Error::other("RAR member output length overflow"))?;
        if new_len > self.limit {
            return Err(io::Error::other(
                "RAR member exceeded its declared output size",
            ));
        }
        bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PendingMember {
    name: Vec<u8>,
    bytes: Arc<Mutex<Vec<u8>>>,
}

unsafe fn scan_pending(
    ctx: *mut cli_ctx,
    pending: &mut Option<PendingMember>,
    scan_empty: bool,
) -> cl_error_t {
    let Some(pending) = pending.take() else {
        return cl_error_t_CL_SUCCESS;
    };
    let bytes = match pending.bytes.lock() {
        Ok(bytes) => bytes,
        Err(_) => return cl_error_t_CL_ERROR,
    };
    if bytes.is_empty() && !scan_empty {
        return cl_error_t_CL_SUCCESS;
    }
    unsafe { magic_scan(ctx, &bytes, sanitized_basename(&pending.name)) }
}

fn is_encryption_error(error: &RarsError) -> bool {
    matches!(
        error.kind(),
        RarsErrorKind::PasswordRequired | RarsErrorKind::BadPassword
    ) || matches!(error, RarsError::FeatureDisabled { feature } if *feature == "encryption")
}

fn map_rars_error(error: &RarsError, callback_status: cl_error_t) -> cl_error_t {
    if callback_status != cl_error_t_CL_SUCCESS {
        return callback_status;
    }
    match error.kind() {
        RarsErrorKind::Cancelled => cl_error_t_CL_ETIMEOUT,
        RarsErrorKind::ResourceLimit => cl_error_t_CL_EMAXSIZE,
        RarsErrorKind::Io => cl_error_t_CL_EREAD,
        RarsErrorKind::InvalidArchive
        | RarsErrorKind::InvalidArgument
        | RarsErrorKind::UnsupportedFormat
        | RarsErrorKind::UnsupportedFeature
        | RarsErrorKind::ChecksumMismatch
        | RarsErrorKind::SourceChanged
        | RarsErrorKind::WriterFailure => cl_error_t_CL_EFORMAT,
        _ => cl_error_t_CL_EFORMAT,
    }
}

fn archive_error_offset(error: &RarsError) -> Option<u64> {
    match error {
        RarsError::AtArchiveOffset { offset, .. } => u64::try_from(*offset).ok(),
        RarsError::AtEntry { source, .. } | RarsError::InVolume { source, .. } => {
            archive_error_offset(source)
        }
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CommentErrorDisposition {
    Abort(cl_error_t),
    Defer(cl_error_t),
    Ignore,
}

fn comment_error_disposition(
    error: &RarsError,
    callback_status: cl_error_t,
) -> CommentErrorDisposition {
    if callback_status != cl_error_t_CL_SUCCESS {
        return CommentErrorDisposition::Abort(callback_status);
    }
    match error.kind() {
        RarsErrorKind::Cancelled => {
            CommentErrorDisposition::Abort(map_rars_error(error, callback_status))
        }
        RarsErrorKind::ResourceLimit => {
            CommentErrorDisposition::Defer(map_rars_error(error, callback_status))
        }
        _ => CommentErrorDisposition::Ignore,
    }
}

fn comment_output_limit_required(error: &RarsError) -> Option<u64> {
    match error.root_cause() {
        RarsError::MemberOutputLimitExceeded { required, .. }
        | RarsError::TotalOutputLimitExceeded { required, .. } => Some(*required),
        _ => None,
    }
}

unsafe fn record_comment_output_limit(ctx: *mut cli_ctx, error: &RarsError) {
    let Some(required) = comment_output_limit_required(error) else {
        return;
    };
    // rars checks the same declared output against its bounded comment
    // decoder before cli_magic_scan_buff() gets a chance to invoke ClamAV's
    // limit checker. Replay that check so AlertExceedsMax and metadata receive
    // the ordinary MaxFileSize or MaxScanSize evidence.
    let _ = unsafe { check_scan_limits("RAR comment", ctx, required, 0, 0) };
}

fn record_encrypted_member(count: &mut u32) {
    *count = count.saturating_add(1);
}

unsafe fn scan_rar(
    ctx: *mut cli_ctx,
    scratch_directory_path: *const std::os::raw::c_char,
    encrypted_members_out: *mut u32,
) -> cl_error_t {
    if ctx.is_null() || encrypted_members_out.is_null() {
        return cl_error_t_CL_ERROR;
    }
    unsafe { *encrypted_members_out = 0 };

    let initial_limits = match unsafe { scan_limits(ctx) } {
        Ok(limits) => limits,
        Err(status) => return status,
    };
    let cancellation = ReadCancellation::new();
    let callback_status = Arc::new(AtomicU32::new(cl_error_t_CL_SUCCESS));
    let reader = match unsafe {
        FMapReader::new(ctx, cancellation.clone(), callback_status.clone(), None)
    } {
        Ok(reader) => reader,
        Err(status) => return status,
    };
    let source_length = reader.length;

    let parse_options = read_options(initial_limits, &cancellation, None);
    let mut deferred_status = cl_error_t_CL_SUCCESS;
    let archive = match ArchiveReader::read_reader_with_options(reader, parse_options) {
        Ok(archive) => archive,
        Err(error) if is_encryption_error(&error) => {
            debug!("RAR: encrypted archive headers cannot be decoded: {error}");
            unsafe { *encrypted_members_out = 1 };
            return cl_error_t_CL_SUCCESS;
        }
        Err(error) => {
            debug!("RAR: failed to parse archive: {error}");
            let status = map_rars_error(&error, callback_status.load(Ordering::Relaxed));
            let recovery_end = archive_error_offset(&error).unwrap_or(source_length);
            if !matches!(
                error.kind(),
                RarsErrorKind::ChecksumMismatch
                    | RarsErrorKind::InvalidArchive
                    | RarsErrorKind::ResourceLimit
            ) || callback_status.load(Ordering::Relaxed) != cl_error_t_CL_SUCCESS
                || recovery_end == 0
                || recovery_end >= source_length
            {
                return status;
            }

            // rars parses the complete header table before exposing members.
            // If a later header is malformed or exceeds a parser budget, retry
            // once with a view ending at the start of that header. Each rars
            // seekable parser accepts such a clean prefix, allowing verified
            // members before the failure to remain visible to the scanner.
            let recovery_reader = match unsafe {
                FMapReader::new(
                    ctx,
                    cancellation.clone(),
                    callback_status.clone(),
                    Some(recovery_end),
                )
            } {
                Ok(reader) => reader,
                Err(_) => return status,
            };
            match ArchiveReader::read_reader_with_options(
                recovery_reader,
                read_options(initial_limits, &cancellation, None),
            ) {
                Ok(archive) => {
                    debug!(
                        "RAR: scanning members before invalid header at source offset {recovery_end}"
                    );
                    deferred_status = status;
                    archive
                }
                Err(recovery_error) => {
                    debug!("RAR: prefix recovery failed: {recovery_error}");
                    return status;
                }
            }
        }
    };

    let mut encrypted_members = 0u32;
    let comment_limits = match unsafe { scan_limits(ctx) } {
        Ok(limits) => limits,
        Err(status) => return status,
    };
    let comment_options = read_options(comment_limits, &cancellation, None);
    match archive.comment_with_options(comment_options) {
        Ok(Some(comment)) if !comment.is_empty() => {
            let status = unsafe { magic_scan(ctx, &comment, None) };
            if status != cl_error_t_CL_SUCCESS {
                return status;
            }
        }
        Ok(_) => {}
        Err(error) if is_encryption_error(&error) => {
            record_encrypted_member(&mut encrypted_members)
        }
        Err(error) => {
            match comment_error_disposition(&error, callback_status.load(Ordering::Relaxed)) {
                CommentErrorDisposition::Abort(status) => return status,
                CommentErrorDisposition::Defer(status) => {
                    // A comment is independent of file-member decoding.
                    // Preserve the limit result, but do not let an oversized
                    // comment hide ordinary members which still fit.
                    debug!("RAR: archive comment exceeded a scan limit: {error}");
                    unsafe { record_comment_output_limit(ctx, &error) };
                    if deferred_status == cl_error_t_CL_SUCCESS {
                        deferred_status = status;
                    }
                }
                CommentErrorDisposition::Ignore => {
                    debug!("RAR: archive comment could not be decoded: {error}")
                }
            }
        }
    }

    let limits = match unsafe { scan_limits(ctx) } {
        Ok(limits) => limits,
        Err(status) => return status,
    };
    let scratch = unsafe { scratch_directory_from_path(scratch_directory_path) }.map(|directory| {
        Rar50Scratch::new(directory, scratch_limit(limits.max_file_size))
            .with_filter_memory_limit(RAR5_FILTER_WORKSPACE)
    });
    let archive_is_solid = archive.is_solid();
    let extraction_deferred_status = AtomicU32::new(deferred_status);
    // The options-level rars handler requires a Sync callback even though it
    // invokes the handler on this calling thread in archive order. A mutex
    // lets it share the staged member safely with the selector.
    let pending = Mutex::new(None::<PendingMember>);
    let context_address = ctx as usize;
    let member_error_handler = |member: &ArchiveMember, error: &RarsError| {
        let mut pending = match pending.lock() {
            Ok(pending) => pending,
            Err(_) => {
                callback_status.store(cl_error_t_CL_ERROR, Ordering::Relaxed);
                return Ok(ExtractionErrorAction::Abort);
            }
        };
        let status = callback_status.load(Ordering::Relaxed);
        if status != cl_error_t_CL_SUCCESS {
            pending.take();
            return Ok(ExtractionErrorAction::Abort);
        }
        if archive_is_solid {
            pending.take();
            return Ok(ExtractionErrorAction::Abort);
        }
        let recoverable = matches!(
            error.kind(),
            RarsErrorKind::ChecksumMismatch
                | RarsErrorKind::InvalidArchive
                | RarsErrorKind::UnsupportedFormat
                | RarsErrorKind::UnsupportedFeature
                | RarsErrorKind::ResourceLimit
        );
        if recoverable {
            // rars retains bytes written before an independent member failure.
            // Scan them before advancing so a forged checksum or a late
            // decoder error cannot hide the payload. Resource limits reach
            // this handler only when rars classifies them as member-local and
            // the member is independent, non-solid and not split.
            let scan_status =
                unsafe { scan_pending(context_address as *mut cli_ctx, &mut pending, false) };
            if scan_status != cl_error_t_CL_SUCCESS {
                callback_status.store(scan_status, Ordering::Relaxed);
                return Ok(ExtractionErrorAction::Abort);
            }
            debug!(
                "RAR: skipping independently damaged, unsupported, or resource-limited member {:?}: {error}",
                sanitized_name(&member.meta.name)
            );
            if error.kind() == RarsErrorKind::ResourceLimit
                && extraction_deferred_status.load(Ordering::Relaxed) == cl_error_t_CL_SUCCESS
            {
                extraction_deferred_status.store(cl_error_t_CL_EMAXSIZE, Ordering::Relaxed);
            }
            Ok(ExtractionErrorAction::Continue)
        } else {
            pending.take();
            Ok(ExtractionErrorAction::Abort)
        }
    };
    let extraction_options = read_options(limits, &cancellation, scratch.as_ref())
        .with_member_error_handler(&member_error_handler);
    let mut file_count = 0usize;
    let mut skipped_solid_candidate = false;

    let extraction = archive.extract_with_control(extraction_options, |member| {
        skipped_solid_candidate = false;
        let status = match pending.lock() {
            Ok(mut pending) => unsafe { scan_pending(ctx, &mut pending, true) },
            Err(_) => cl_error_t_CL_ERROR,
        };
        if status != cl_error_t_CL_SUCCESS {
            callback_status.store(status, Ordering::Relaxed);
            return Ok(ExtractionDecision::Stop);
        }

        // Some members require no source read or output write (directories,
        // redirections, encrypted entries, and split entries). Check the scan
        // deadline explicitly so a long metadata-only archive cannot evade
        // MaxScanTime enforcement.
        let status = unsafe { check_scan_time_limit(ctx) };
        if status != cl_error_t_CL_SUCCESS {
            callback_status.store(status, Ordering::Relaxed);
            cancellation.cancel();
            return Ok(ExtractionDecision::Stop);
        }

        file_count = file_count.saturating_add(1);
        let name = sanitized_name(&member.meta.name);
        let packed = usize::try_from(member.meta.packed_size).unwrap_or(usize::MAX);
        let unpacked = usize::try_from(member.meta.unpacked_size).unwrap_or(usize::MAX);
        let metadata_status = unsafe {
            scan_archive_metadata(
                ctx,
                &name,
                packed,
                unpacked,
                member.meta.is_encrypted,
                file_count,
                member_crc(member),
            )
        };
        if metadata_status != cl_error_t_CL_SUCCESS {
            callback_status.store(metadata_status, Ordering::Relaxed);
            return Ok(ExtractionDecision::Stop);
        }

        // Record encryption as soon as it is known from the member header.
        // Split members and filesystem metadata are not extracted, but they
        // still count for the encrypted-archive heuristic just as they did in
        // the former UnRAR metadata path.
        if member.meta.is_encrypted {
            record_encrypted_member(&mut encrypted_members);
        }

        if member.meta.is_directory || member.meta.is_redirection {
            return Ok(ExtractionDecision::Skip);
        }
        if member.meta.is_split_before || member.meta.is_split_after {
            debug!("RAR: stopping at split member {:?}", name);
            return Ok(ExtractionDecision::Stop);
        }
        if member.meta.is_encrypted {
            return if archive_is_solid {
                Ok(ExtractionDecision::Stop)
            } else {
                skipped_solid_candidate = true;
                Ok(ExtractionDecision::Skip)
            };
        }

        let limit_status =
            unsafe { check_scan_limits("RAR", ctx, member.meta.unpacked_size, 0, 0) };
        if limit_status != cl_error_t_CL_SUCCESS {
            // A size limit applies to this member, not necessarily to
            // smaller independent members which follow it. Preserve the
            // limit alert and continue at the next independent member.
            if limit_status == cl_error_t_CL_EMAXSIZE && !archive_is_solid {
                skipped_solid_candidate = true;
                return Ok(ExtractionDecision::Skip);
            }

            // MaxFiles cannot recover later in this archive. A solid
            // member cannot be skipped without invalidating its chain.
            // In both cases stop cleanly while retaining any limit alert.
            if limit_status == cl_error_t_CL_EMAXFILES
                || (limit_status == cl_error_t_CL_EMAXSIZE && archive_is_solid)
            {
                return Ok(ExtractionDecision::Stop);
            }

            callback_status.store(limit_status, Ordering::Relaxed);
            return Ok(ExtractionDecision::Stop);
        }

        let capacity = match usize::try_from(member.meta.unpacked_size) {
            Ok(capacity) => capacity,
            Err(_) => {
                if archive_is_solid {
                    return Ok(ExtractionDecision::Stop);
                }
                skipped_solid_candidate = true;
                return Ok(ExtractionDecision::Skip);
            }
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(capacity).is_err() {
            callback_status.store(cl_error_t_CL_EMEM, Ordering::Relaxed);
            return Err(RarsError::WriterFailure("cannot reserve RAR member output"));
        }
        let bytes = Arc::new(Mutex::new(bytes));
        match pending.lock() {
            Ok(mut pending) => {
                *pending = Some(PendingMember {
                    name: member.meta.name.clone(),
                    bytes: bytes.clone(),
                });
            }
            Err(_) => {
                callback_status.store(cl_error_t_CL_ERROR, Ordering::Relaxed);
                return Ok(ExtractionDecision::Stop);
            }
        }
        Ok(ExtractionDecision::Extract(Box::new(MemberBuffer {
            bytes,
            limit: capacity,
            ctx: NonNull::new(ctx).expect("validated scan context"),
            cancellation: cancellation.clone(),
            status: callback_status.clone(),
        })))
    });

    let mut pending = match pending.into_inner() {
        Ok(pending) => pending,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut status = callback_status.load(Ordering::Relaxed);
    match extraction {
        Ok(_) if status == cl_error_t_CL_SUCCESS => {
            status = unsafe { scan_pending(ctx, &mut pending, true) };
        }
        Ok(_) => {}
        Err(error)
            if skipped_solid_candidate
                && matches!(error.root_cause(), RarsError::CannotSkipSolidMember) =>
        {
            // A member which appeared independent can still belong to an
            // archive-wide solid chain. rars refuses the skip because doing so
            // would invalidate all following history. Treat that refusal as
            // the intended end of this archive scan.
            debug!("RAR: stopping at a skipped member in a solid archive");
        }
        Err(error) => {
            status = map_rars_error(&error, status);
            debug!("RAR: extraction stopped: {error}");
        }
    }

    let deferred_status = extraction_deferred_status.load(Ordering::Relaxed);
    if status == cl_error_t_CL_SUCCESS && deferred_status != cl_error_t_CL_SUCCESS {
        status = deferred_status;
    }

    // Publish the count only after reaching the ordinary end of archive
    // processing. Early hard errors and panics must not be converted into a
    // heuristic alert by the C wrapper.
    unsafe { *encrypted_members_out = encrypted_members };
    status
}

/// Scan the current fmap as a RAR archive using bounded reader-only rars.
///
/// # Safety
///
/// `ctx` must point to a valid ClamAV scan context for the duration of this call.
/// `scratch_directory` must be null or point to a valid, NUL-terminated path.
/// On Windows the path must be UTF-8; the C wrapper performs ClamAV's active
/// code-page fallback before calling this function.
/// `encrypted_members` must point to writable storage for a `u32`.
#[no_mangle]
pub unsafe extern "C" fn cli_scanrar_rust(
    ctx: *mut cli_ctx,
    scratch_directory: *const std::os::raw::c_char,
    encrypted_members: *mut u32,
) -> cl_error_t {
    if !encrypted_members.is_null() {
        unsafe { *encrypted_members = 0 };
    }
    match panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        scan_rar(ctx, scratch_directory, encrypted_members)
    })) {
        Ok(status) => status,
        Err(_) => {
            if !encrypted_members.is_null() {
                unsafe { *encrypted_members = 0 };
            }
            warn!("RAR: Rust scanner panicked; aborting this archive scan");
            cl_error_t_CL_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_limit_uses_configured_max_files() {
        assert_eq!(header_count_limit(0), HEADER_COUNT_LIMIT);
        assert_eq!(header_count_limit(1), 1028);
        assert_eq!(header_count_limit(10_000), 41_024);
        assert_eq!(header_count_limit(u32::MAX), HEADER_COUNT_LIMIT);
    }

    #[test]
    fn scratch_limit_is_bounded_and_saturating() {
        assert_eq!(scratch_limit(0), 0);
        assert_eq!(scratch_limit(1), 2);
        assert_eq!(scratch_limit(1024), 2048);
        assert_eq!(scratch_limit(u64::MAX), RAR5_SCRATCH_LIMIT);
        assert_eq!(scratch_limit(RAR5_SCRATCH_LIMIT), RAR5_SCRATCH_LIMIT);
    }

    #[test]
    fn scan_timeout_errors_are_not_retryable_interrupts() {
        assert_eq!(scan_timeout_error().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn archive_offsets_are_taken_from_rars_error_context() {
        let error = RarsError::InvalidHeader("bad block").at_archive_offset(42);
        assert_eq!(archive_error_offset(&error), Some(42));
        assert_eq!(archive_error_offset(&RarsError::TooShort), None);
    }

    #[test]
    fn comment_limits_are_deferred_but_cancellation_is_terminal() {
        let limit = RarsError::MemberOutputLimitExceeded {
            limit: 8,
            required: 9,
        };
        assert_eq!(
            comment_error_disposition(&limit, cl_error_t_CL_SUCCESS),
            CommentErrorDisposition::Defer(cl_error_t_CL_EMAXSIZE)
        );

        assert_eq!(
            comment_error_disposition(&RarsError::Cancelled, cl_error_t_CL_SUCCESS),
            CommentErrorDisposition::Abort(cl_error_t_CL_ETIMEOUT)
        );
        assert_eq!(
            comment_error_disposition(&limit, cl_error_t_CL_ETIMEOUT),
            CommentErrorDisposition::Abort(cl_error_t_CL_ETIMEOUT)
        );
        assert_eq!(
            comment_error_disposition(
                &RarsError::InvalidHeader("bad comment"),
                cl_error_t_CL_SUCCESS,
            ),
            CommentErrorDisposition::Ignore
        );

        assert_eq!(comment_output_limit_required(&limit), Some(9));
        assert_eq!(
            comment_output_limit_required(&RarsError::TotalOutputLimitExceeded {
                limit: 8,
                required: 10,
                used: 7,
            }),
            Some(10)
        );
        assert_eq!(
            comment_output_limit_required(&RarsError::Rar50DictionaryLimitExceeded {
                limit: 8,
                required: 16,
            }),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn scratch_path_preserves_unix_bytes() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let configured = CString::new(b"/tmp/configured-\xff".as_slice()).unwrap();
        let selected = unsafe { scratch_directory_from_path(configured.as_ptr()).unwrap() };
        assert_eq!(selected.as_os_str().as_bytes(), b"/tmp/configured-\xff");
        assert!(unsafe { scratch_directory_from_path(std::ptr::null()) }.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn scratch_path_accepts_normalized_windows_utf8() {
        use std::ffi::CString;

        let normalized = CString::new("C:\\José").unwrap();
        let selected = unsafe { scratch_directory_from_path(normalized.as_ptr()).unwrap() };
        assert_eq!(selected, PathBuf::from("C:\\José"));

        let unnormalized = CString::new(b"C:\\Jos\xe9".as_slice()).unwrap();
        assert!(unsafe { scratch_directory_from_path(unnormalized.as_ptr()) }.is_none());
    }

    #[test]
    fn member_names_are_safe_for_c_and_recursive_scanning() {
        assert_eq!(
            sanitized_basename(b"dir\\nested/name.txt"),
            Some("name.txt".into())
        );
        assert_eq!(sanitized_basename(b"dir/"), None);
        assert_eq!(sanitized_basename(b"bad\0name"), Some("bad�name".into()));
        assert_eq!(
            sanitized_basename(b"invalid-\xff"),
            Some("invalid-�".into())
        );
    }
}
