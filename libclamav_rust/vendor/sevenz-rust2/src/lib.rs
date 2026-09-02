//! This project is a 7z compressor/decompressor written in pure Rust.
//!
//! This is a fork of the original, unmaintained sevenz-rust crate to continue the development
//! and maintenance.
//!
//! ## Supported Codecs & filters
//!
//! | Codec          | Decompression | Compression |
//! |----------------|---------------|-------------|
//! | COPY           | ✓             | ✓           |
//! | LZMA           | ✓             | ✓           |
//! | LZMA2          | ✓             | ✓           |
//! | BROTLI (*)     | ✓             | ✓           |
//! | BZIP2          | ✓             | ✓           |
//! | DEFLATE (*)    | ✓             | ✓           |
//! | PPMD           | ✓             | ✓           |
//! | LZ4 (*)        | ✓             | ✓           |
//! | ZSTD (*)       | ✓             | ✓           |
//!
//! (*) Require optional cargo feature.
//!
//! | Filter        | Decompression | Compression |
//! |---------------|---------------|-------------|
//! | BCJ X86       | ✓             | ✓           |
//! | BCJ ARM       | ✓             | ✓           |
//! | BCJ ARM64     | ✓             | ✓           |
//! | BCJ ARM_THUMB | ✓             | ✓           |
//! | BCJ RISC_V    | ✓             | ✓           |
//! | BCJ PPC       | ✓             | ✓           |
//! | BCJ SPARC     | ✓             | ✓           |
//! | BCJ IA64      | ✓             | ✓           |
//! | BCJ2          | ✓             |             |
//! | DELTA         | ✓             | ✓           |
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(target_arch = "wasm32")]
extern crate wasm_bindgen;

#[cfg(feature = "compress")]
mod encoder;
/// Encoding options when compressing.
#[cfg(feature = "compress")]
pub mod encoder_options;
mod encryption;
mod error;
mod reader;

#[cfg(feature = "compress")]
mod writer;

pub(crate) mod archive;
pub(crate) mod bitset;
pub(crate) mod block;
mod codec;
pub(crate) mod decoder;

mod time;
#[cfg(feature = "util")]
mod util;

use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub use archive::*;
pub use block::*;
pub use encryption::Password;
pub use error::Error;
pub use reader::{ArchiveReader, BlockDecoder, EntryDecision};
pub use time::NtTime;
#[cfg(all(feature = "compress", feature = "util", not(target_arch = "wasm32")))]
pub use util::compress::*;
#[cfg(all(feature = "util", not(target_arch = "wasm32")))]
pub use util::decompress::*;
#[cfg(all(feature = "util", target_arch = "wasm32"))]
pub use util::wasm::*;
#[cfg(feature = "compress")]
pub use writer::*;

trait ByteReader {
    fn read_u8(&mut self) -> std::io::Result<u8>;

    #[cfg(feature = "brotli")]
    fn read_u16(&mut self) -> std::io::Result<u16>;

    fn read_u32(&mut self) -> std::io::Result<u32>;

    fn read_u64(&mut self) -> std::io::Result<u64>;
}

trait ByteWriter {
    #[cfg(feature = "compress")]
    fn write_u8(&mut self, value: u8) -> std::io::Result<()>;

    fn write_u16(&mut self, value: u16) -> std::io::Result<()>;

    #[cfg(feature = "compress")]
    fn write_u32(&mut self, value: u32) -> std::io::Result<()>;

    #[cfg(feature = "compress")]
    fn write_u64(&mut self, value: u64) -> std::io::Result<()>;
}

impl<T: Read> ByteReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[cfg(feature = "brotli")]
    #[inline(always)]
    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(buf.as_mut())?;
        Ok(u16::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<T: Write> ByteWriter for T {
    #[cfg(feature = "compress")]
    #[inline(always)]
    fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&[value])
    }

    #[inline(always)]
    fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    #[cfg(feature = "compress")]
    #[inline(always)]
    fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    #[cfg(feature = "compress")]
    #[inline(always)]
    fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        self.write_all(&value.to_le_bytes())
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

impl<T: AutoFinish> Deref for AutoFinisher<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<T: AutoFinish> DerefMut for AutoFinisher<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}
