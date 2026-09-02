//! LZMA / LZMA2 / LZIP / XZ compression ported from [tukaani xz for java](https://tukaani.org/xz/java.html).
//!
//! This is a fork of the original, unmaintained lzma-rust crate to continue the development and
//! maintenance.
//!
//! ## Safety
//!
//! Only the `optimization` feature uses unsafe Rust features to implement optimizations, that are
//! not possible in safe Rust. Those optimizations are properly guarded and are of course sound.
//! This includes creation of aligned memory, handwritten assembly code for hot functions and some
//! pointer logic. Those optimization are well localized and generally consider safe to use, even
//! with untrusted input.
//!
//! Deactivating the `optimization` feature will result in 100% standard Rust code.
//!
//! ## Performance
//!
//! When compared against the `liblzma` crate, which uses the C library of the same name, this crate
//! has improved decoding speed.
//!
//! Encoding is also well optimized and is surpassing `liblzma` for level 0 to 3 and matches it for
//! level 4 to 9.
//!
//! ## no_std Support
//!
//! This crate supports `no_std` environments by disabling the default `std` feature.
//!
//! When used in `no_std` mode, the crate provides custom `Read`, `Write`, and `Error` types
//! (defined in `no_std.rs`) that are compatible with `no_std` environments. These types offer
//! similar functionality to their `std::io` counterparts but are implemented using only `core`
//! and `alloc`.
//!
//! The custom types include:
//!
//! - [`Error`]: A custom error enum with variants for different error conditions.
//! - [`Read`]: A trait similar to `std::io::Read` with `read()` and `read_exact()` methods.
//! - [`Write`]: A trait similar to `std::io::Write` with `write()`, `write_all()`, and `flush()`
//!   methods.
//!
//! Default implementations for `&[u8]` (Read) and `&mut [u8]` (Write) are provided.
//!
//! Note that multithreaded features are not available in `no_std` mode as they require
//! standard library threading primitives.
//!
//! ## License
//!
//! Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

// TODO: There is a lot of code left that only the "encode" feature uses.
#![allow(dead_code)]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "optimization"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod decoder;
mod lz;
#[cfg(feature = "lzip")]
mod lzip;
mod lzma2_reader;
mod lzma_reader;
mod range_dec;
mod state;
mod stream;
#[cfg(feature = "std")]
mod work_queue;
#[cfg(feature = "xz")]
mod xz;

#[cfg(feature = "encoder")]
mod enc;

pub mod filter;

#[cfg(any(feature = "lzip", feature = "xz"))]
mod crc;
#[cfg(feature = "std")]
mod lzma2_reader_mt;
#[cfg(not(feature = "std"))]
mod no_std;
#[cfg(feature = "std")]
mod work_pool;

#[cfg(feature = "std")]
pub(crate) use std::io::Error;
#[cfg(feature = "std")]
pub(crate) use std::io::Read;
#[cfg(feature = "std")]
pub(crate) use std::io::Write;

#[cfg(feature = "encoder")]
pub use enc::*;
pub use lz::MfType;
#[cfg(all(feature = "lzip", feature = "std"))]
pub use lzip::LzipReaderMt;
#[cfg(all(feature = "lzip", feature = "encoder", feature = "std"))]
pub use lzip::LzipWriterMt;
#[cfg(all(feature = "lzip", feature = "encoder"))]
pub use lzip::{LzipOptions, LzipWriter};
#[cfg(feature = "lzip")]
pub use lzip::{LzipReader, LzipStream};
pub use lzma_reader::{
    LzmaReader, LzmaStream, get_memory_usage as lzma_get_memory_usage,
    get_memory_usage_by_props as lzma_get_memory_usage_by_props,
};
pub use lzma2_reader::{Lzma2Reader, Lzma2Stream, get_memory_usage as lzma2_get_memory_usage};
#[cfg(feature = "std")]
pub use lzma2_reader_mt::Lzma2ReaderMt;
#[cfg(not(feature = "std"))]
pub use no_std::Error;
#[cfg(not(feature = "std"))]
pub use no_std::Read;
#[cfg(not(feature = "std"))]
pub use no_std::Write;
use state::*;
pub use stream::{Action, Status, StreamResult};
#[cfg(all(feature = "xz", feature = "std"))]
pub use xz::XzReaderMt;
#[cfg(all(feature = "xz", feature = "encoder", feature = "std"))]
pub use xz::XzWriterMt;
#[cfg(feature = "xz")]
pub use xz::{CheckType, FilterConfig, FilterType, XzReader, XzStream};
#[cfg(all(feature = "xz", feature = "encoder"))]
pub use xz::{XzOptions, XzWriter};

/// Result type of the crate.
#[cfg(feature = "std")]
pub type Result<T> = core::result::Result<T, Error>;

/// Result type of the crate.
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

/// The minimal size of a dictionary.
pub const DICT_SIZE_MIN: u32 = 4096;

/// The maximal size of a dictionary.
pub const DICT_SIZE_MAX: u32 = !15_u32;

const LOW_SYMBOLS: usize = 1 << 3;
const MID_SYMBOLS: usize = 1 << 3;
const HIGH_SYMBOLS: usize = 1 << 8;

const POS_STATES_MAX: usize = 1 << 4;
const MATCH_LEN_MIN: usize = 2;
const MATCH_LEN_MAX: usize = MATCH_LEN_MIN + LOW_SYMBOLS + MID_SYMBOLS + HIGH_SYMBOLS - 1;

const DIST_STATES: usize = 4;
const DIST_SLOTS: usize = 1 << 6;
const DIST_MODEL_START: usize = 4;
const DIST_MODEL_END: usize = 14;
const FULL_DISTANCES: usize = 1 << (DIST_MODEL_END / 2);

const ALIGN_BITS: usize = 4;
const ALIGN_SIZE: usize = 1 << ALIGN_BITS;
const ALIGN_MASK: usize = ALIGN_SIZE - 1;

const REPS: usize = 4;

const SHIFT_BITS: u32 = 8;
const TOP_MASK: u32 = 0xFF000000;
const BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << BIT_MODEL_TOTAL_BITS;
const PROB_INIT: u16 = (BIT_MODEL_TOTAL / 2) as u16;
const MOVE_BITS: u32 = 5;
const DIST_SPECIAL_INDEX: [usize; 10] = [0, 2, 4, 8, 12, 20, 28, 44, 60, 92];
const DIST_SPECIAL_END: [usize; 10] = [2, 4, 8, 12, 20, 28, 44, 60, 92, 124];
const TOP_VALUE: u32 = 0x0100_0000;
const RC_BIT_MODEL_OFFSET: u32 = (1u32 << MOVE_BITS)
    .wrapping_sub(1)
    .wrapping_sub(BIT_MODEL_TOTAL);

/// Helper to set the shared error state and trigger shutdown.
#[cfg(feature = "std")]
fn set_error(
    error: Error,
    error_store: &std::sync::Arc<std::sync::Mutex<Option<Error>>>,
    shutdown_flag: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut guard = error_store.lock().unwrap();
    if guard.is_none() {
        *guard = Some(error);
    }
    shutdown_flag.store(true, std::sync::atomic::Ordering::Release);
}

pub(crate) struct LzmaCoder {
    pub(crate) pos_mask: u32,
    pub(crate) reps: [i32; REPS],
    pub(crate) state: State,
    pub(crate) is_match: [[u16; POS_STATES_MAX]; STATES],
    pub(crate) is_rep: [u16; STATES],
    pub(crate) is_rep0: [u16; STATES],
    pub(crate) is_rep1: [u16; STATES],
    pub(crate) is_rep2: [u16; STATES],
    pub(crate) is_rep0_long: [[u16; POS_STATES_MAX]; STATES],
    pub(crate) dist_slots: [[u16; DIST_SLOTS]; DIST_STATES],
    dist_special: [u16; 124],
    dist_align: [u16; ALIGN_SIZE],
}

pub(crate) fn coder_get_dict_size(len: usize) -> usize {
    if len < DIST_STATES + MATCH_LEN_MIN {
        len - MATCH_LEN_MIN
    } else {
        DIST_STATES - 1
    }
}

pub(crate) fn get_dist_state(len: u32) -> u32 {
    (if (len as usize) < DIST_STATES + MATCH_LEN_MIN {
        len as usize - MATCH_LEN_MIN
    } else {
        DIST_STATES - 1
    }) as u32
}

impl LzmaCoder {
    pub(crate) fn new(pb: usize) -> Self {
        let mut c = Self {
            pos_mask: (1 << pb) - 1,
            reps: Default::default(),
            state: Default::default(),
            is_match: Default::default(),
            is_rep: Default::default(),
            is_rep0: Default::default(),
            is_rep1: Default::default(),
            is_rep2: Default::default(),
            is_rep0_long: Default::default(),
            dist_slots: [[Default::default(); DIST_SLOTS]; DIST_STATES],
            dist_special: [Default::default(); 124],
            dist_align: Default::default(),
        };
        c.reset();
        c
    }

    pub(crate) fn reset(&mut self) {
        self.reps = [0; REPS];
        self.state.reset();
        for ele in self.is_match.iter_mut() {
            init_probs(ele);
        }
        init_probs(&mut self.is_rep);
        init_probs(&mut self.is_rep0);
        init_probs(&mut self.is_rep1);
        init_probs(&mut self.is_rep2);

        for ele in self.is_rep0_long.iter_mut() {
            init_probs(ele);
        }
        for ele in self.dist_slots.iter_mut() {
            init_probs(ele);
        }
        init_probs(&mut self.dist_special);
        init_probs(&mut self.dist_align);
    }

    #[inline(always)]
    pub(crate) fn get_dist_special(&mut self, i: usize) -> &mut [u16] {
        &mut self.dist_special[DIST_SPECIAL_INDEX[i]..DIST_SPECIAL_END[i]]
    }
}

#[inline(always)]
pub(crate) fn init_probs(probs: &mut [u16]) {
    probs.fill(PROB_INIT);
}

pub(crate) struct LiteralCoder {
    lc: u32,
    literal_pos_mask: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LiteralSubCoder {
    probs: [u16; 0x300],
}

impl LiteralSubCoder {
    pub fn new() -> Self {
        let probs = [PROB_INIT; 0x300];
        Self { probs }
    }

    pub fn reset(&mut self) {
        self.probs = [PROB_INIT; 0x300];
    }
}

impl LiteralCoder {
    pub fn new(lc: u32, lp: u32) -> Self {
        Self {
            lc,
            literal_pos_mask: (1 << lp) - 1,
        }
    }

    pub(crate) fn get_sub_coder_index(&self, prev_byte: u32, pos: u32) -> u32 {
        let low = prev_byte >> (8 - self.lc);
        let high = (pos & self.literal_pos_mask) << self.lc;
        low + high
    }
}

pub(crate) struct LengthCoder {
    choice: [u16; 2],
    low: [[u16; LOW_SYMBOLS]; POS_STATES_MAX],
    mid: [[u16; MID_SYMBOLS]; POS_STATES_MAX],
    high: [u16; HIGH_SYMBOLS],
}

impl LengthCoder {
    pub fn new() -> Self {
        Self {
            choice: Default::default(),
            low: Default::default(),
            mid: Default::default(),
            high: [0; HIGH_SYMBOLS],
        }
    }

    pub fn reset(&mut self) {
        init_probs(&mut self.choice);
        for ele in self.low.iter_mut() {
            init_probs(ele);
        }
        for ele in self.mid.iter_mut() {
            init_probs(ele);
        }
        init_probs(&mut self.high);
    }
}

trait ByteReader {
    fn read_u8(&mut self) -> Result<u8>;

    fn read_u16(&mut self) -> Result<u16>;

    fn read_u16_be(&mut self) -> Result<u16>;

    fn read_u32(&mut self) -> Result<u32>;

    fn read_u32_be(&mut self) -> Result<u32>;

    fn read_u64(&mut self) -> Result<u64>;
}

trait ByteWriter {
    fn write_u8(&mut self, value: u8) -> Result<()>;

    fn write_u16(&mut self, value: u16) -> Result<()>;

    fn write_u32(&mut self, value: u32) -> Result<()>;

    fn write_u64(&mut self, value: u64) -> Result<()>;
}

impl<T: Read> ByteReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(buf.as_mut())?;
        Ok(u16::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u16_be(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(buf.as_mut())?;
        Ok(u16::from_be_bytes(buf))
    }

    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u32_be(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_be_bytes(buf))
    }

    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<T: Write> ByteWriter for T {
    #[inline(always)]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])
    }

    #[inline(always)]
    fn write_u16(&mut self, value: u16) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    #[inline(always)]
    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    #[inline(always)]
    fn write_u64(&mut self, value: u64) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_eof() -> Error {
    Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::other(msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidInput, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_out_of_memory(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::OutOfMemory, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::Unsupported, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    Error::new(error.kind(), error.to_string())
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_eof() -> Error {
    Error::Eof
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::Other(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::InvalidInput(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_out_of_memory(msg: &'static str) -> Error {
    Error::OutOfMemory(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::Unsupported(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    *error
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    fn with_count(inner: R, bytes_read: u64) -> Self {
        Self { inner, bytes_read }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn into_inner(self) -> R {
        self.inner
    }

    fn inner(&self) -> &R {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read_size = self.inner.read(buf)?;
        self.bytes_read += read_size as u64;
        Ok(read_size)
    }
}

#[cfg(feature = "encoder")]
struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

#[cfg(feature = "encoder")]
impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn into_inner(self) -> W {
        self.inner
    }

    fn inner(&self) -> &W {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

#[cfg(feature = "encoder")]
impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let bytes_written = self.inner.write(buf)?;
        self.bytes_written += bytes_written as u64;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// A trait for writers that finishes the stream on drop.
trait AutoFinish {
    /// Finish writing the stream without error handling.
    fn finish_ignore_error(self);
}

/// A wrapper around a writer that finishes the stream on drop.
#[allow(private_bounds)]
pub struct AutoFinisher<T: AutoFinish>(Option<T>);

impl<T: AutoFinish> Drop for AutoFinisher<T> {
    fn drop(&mut self) {
        if let Some(writer) = self.0.take() {
            writer.finish_ignore_error();
        }
    }
}

impl<T: AutoFinish> core::ops::Deref for AutoFinisher<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<T: AutoFinish> core::ops::DerefMut for AutoFinisher<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

impl<T: AutoFinish + Write> Write for AutoFinisher<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        use core::ops::DerefMut;

        self.deref_mut().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        use core::ops::DerefMut;

        self.deref_mut().flush()
    }
}
