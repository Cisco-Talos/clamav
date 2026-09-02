//! Branch/Call/Jump Filters for executables of different architectures.

mod arm;
mod ia64;
mod ppc;
mod riscv;
mod sparc;
mod x86;

use alloc::{vec, vec::Vec};

use crate::Read;
#[cfg(feature = "encoder")]
use crate::Write;

pub(crate) struct BcjFilter {
    is_encoder: bool,
    pos: usize,
    prev_mask: u32,
    filter: FilterFn,
}

type FilterFn = fn(filter: &mut BcjFilter, buf: &mut [u8]) -> usize;

impl BcjFilter {
    #[inline]
    pub(crate) fn code(&mut self, buf: &mut [u8]) -> usize {
        let filter = self.filter;
        filter(self, buf)
    }
}

const FILTER_BUF_SIZE: usize = 4096;

/// Reader that applies BCJ (Branch/Call/Jump) filtering to compressed data.
pub struct BcjReader<R> {
    inner: R,
    filter: BcjFilter,
    state: State,
}

#[derive(Debug, Default)]
struct State {
    filter_buf: Vec<u8>,
    pos: usize,
    filtered: usize,
    unfiltered: usize,
    end_reached: bool,
}

impl<R> BcjReader<R> {
    fn new(inner: R, filter: BcjFilter) -> Self {
        Self {
            inner,
            filter,
            state: State {
                filter_buf: vec![0; FILTER_BUF_SIZE],
                ..Default::default()
            },
        }
    }

    /// Unwraps the reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns a reference to the inner reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the inner reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Creates a new BCJ reader for x86 instruction filtering.
    #[inline]
    pub fn new_x86(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_x86(start_pos, false))
    }

    /// Creates a new BCJ reader for ARM instruction filtering.
    #[inline]
    pub fn new_arm(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm(start_pos, false))
    }

    /// Creates a new BCJ reader for ARM64 instruction filtering.
    #[inline]
    pub fn new_arm64(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm64(start_pos, false))
    }

    /// Creates a new BCJ reader for ARM Thumb instruction filtering.
    #[inline]
    pub fn new_arm_thumb(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm_thumb(start_pos, false))
    }

    /// Creates a new BCJ reader for PowerPC instruction filtering.
    #[inline]
    pub fn new_ppc(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_power_pc(start_pos, false))
    }

    /// Creates a new BCJ reader for SPARC instruction filtering.
    #[inline]
    pub fn new_sparc(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_sparc(start_pos, false))
    }

    /// Creates a new BCJ reader for IA-64 instruction filtering.
    #[inline]
    pub fn new_ia64(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_ia64(start_pos, false))
    }

    /// Creates a new BCJ reader for RISC-V instruction filtering.
    #[inline]
    pub fn new_riscv(inner: R, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_riscv(start_pos, false))
    }
}

impl<R: Read> Read for BcjReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut len = buf.len();
        let mut state = core::mem::take(&mut self.state);
        let mut off = 0;
        let mut size = 0;

        loop {
            // Copy filtered data into the caller-provided buffer.
            if state.filtered > 0 {
                let copy_size = state.filtered.min(len);
                let pos = state.pos;
                buf[off..(off + copy_size)]
                    .copy_from_slice(&state.filter_buf[pos..(pos + copy_size)]);
                state.pos += copy_size;
                state.filtered -= copy_size;
                off += copy_size;
                len -= copy_size;
                size += copy_size;
            }

            // If end of filterBuf was reached, move the pending data to
            // the beginning of the buffer so that more data can be
            // copied into filterBuf on the next loop iteration.
            if state.pos + state.filtered + state.unfiltered == FILTER_BUF_SIZE {
                // state.filter_buf.copy_from_slice(src);
                state.filter_buf.rotate_left(state.pos);
                state.pos = 0;
            }

            if len == 0 || state.end_reached {
                self.state = state;
                return Ok(if size > 0 { size } else { 0 });
            }

            assert_eq!(state.filtered, 0);
            // Get more data into the temporary buffer.
            let mut in_size = FILTER_BUF_SIZE - (state.pos + state.filtered + state.unfiltered);
            let start = state.pos + state.filtered + state.unfiltered;
            let temp = &mut state.filter_buf[start..(start + in_size)];
            in_size = match self.inner.read(temp) {
                Ok(s) => s,
                Err(error) => {
                    self.state = state;
                    return Err(error);
                }
            };

            if in_size == 0 {
                // Mark the remaining unfiltered bytes to be ready
                // to be copied out.
                state.end_reached = true;
                state.filtered = state.unfiltered;
                state.unfiltered = 0;
            } else {
                // Filter the data in filterBuf.
                state.unfiltered += in_size;
                state.filtered = self
                    .filter
                    .code(&mut state.filter_buf[state.pos..(state.pos + state.unfiltered)]);
                assert!(state.filtered <= state.unfiltered);
                state.unfiltered -= state.filtered;
            }
        }
    }
}

/// Writer that applies BCJ (Branch/Call/Jump) filtering to data before compression.
#[cfg(feature = "encoder")]
pub struct BcjWriter<W> {
    inner: W,
    filter: BcjFilter,
    buffer: Vec<u8>,
}

#[cfg(feature = "encoder")]
impl<W> BcjWriter<W> {
    fn new(inner: W, filter: BcjFilter) -> Self {
        Self {
            inner,
            filter,
            buffer: Vec::with_capacity(FILTER_BUF_SIZE),
        }
    }

    /// Unwraps the writer, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Creates a new BCJ writer for x86 instruction filtering.
    #[inline]
    pub fn new_x86(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_x86(start_pos, true))
    }

    /// Creates a new BCJ writer for ARM instruction filtering.
    #[inline]
    pub fn new_arm(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm(start_pos, true))
    }

    /// Creates a new BCJ writer for ARM64 instruction filtering.
    #[inline]
    pub fn new_arm64(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm64(start_pos, true))
    }

    /// Creates a new BCJ writer for ARM Thumb instruction filtering.
    #[inline]
    pub fn new_arm_thumb(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_arm_thumb(start_pos, true))
    }

    /// Creates a new BCJ writer for PowerPC instruction filtering.
    #[inline]
    pub fn new_ppc(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_power_pc(start_pos, true))
    }

    /// Creates a new BCJ writer for SPARC instruction filtering.
    #[inline]
    pub fn new_sparc(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_sparc(start_pos, true))
    }

    /// Creates a new BCJ writer for IA-64 instruction filtering.
    #[inline]
    pub fn new_ia64(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_ia64(start_pos, true))
    }

    /// Creates a new BCJ writer for RISC-V instruction filtering.
    #[inline]
    pub fn new_riscv(inner: W, start_pos: usize) -> Self {
        Self::new(inner, BcjFilter::new_riscv(start_pos, true))
    }

    /// Finishes writing by flushing any remaining unprocessed data.
    /// This should be called when no more data will be written.
    pub fn finish(mut self) -> crate::Result<W>
    where
        W: Write,
    {
        if !self.buffer.is_empty() {
            // Write any remaining unprocessed data.
            self.inner.write_all(&self.buffer)?;
            self.buffer.clear();
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

#[cfg(feature = "encoder")]
impl<W: Write> Write for BcjWriter<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let original_len = buf.len();

        self.buffer.extend_from_slice(buf);

        let filtered_size = self.filter.code(&mut self.buffer);

        if filtered_size > 0 {
            self.inner.write_all(&self.buffer[..filtered_size])?;
        }

        if filtered_size < self.buffer.len() {
            self.buffer.copy_within(filtered_size.., 0);
            self.buffer.truncate(self.buffer.len() - filtered_size);
        } else {
            self.buffer.clear();
        }

        Ok(original_len)
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.inner.flush()
    }
}

#[cfg(all(feature = "encoder", feature = "std"))]
#[cfg(test)]
mod tests {
    use std::io::{Cursor, copy};

    use super::*;

    #[test]
    fn large_start_pos_does_not_panic() {
        let data = [0u8; 64];
        for make in [
            BcjReader::new_x86,
            BcjReader::new_arm,
            BcjReader::new_arm_thumb,
        ] {
            let mut reader = make(Cursor::new(data), usize::MAX);
            let mut out = Vec::new();
            copy(&mut reader, &mut out).unwrap();
        }
    }

    #[test]
    fn test_bcj_x86_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-x86").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_x86(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_x86(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_arm_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-arm").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_arm(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_arm(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_arm64_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-arm64").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_arm64(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_arm64(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_arm_thumb_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-arm-thumb").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_arm_thumb(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_arm_thumb(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_ppc_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-ppc").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_ppc(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_ppc(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_sparc_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-sparc").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_sparc(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_sparc(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_ia64_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-ia64").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_ia64(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_ia64(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }

    #[test]
    fn test_bcj_riscv_roundtrip() {
        let test_data = std::fs::read("tests/data/wget-riscv").unwrap();

        let mut encoded_buffer = Vec::new();
        let mut writer = BcjWriter::new_riscv(Cursor::new(&mut encoded_buffer), 0);
        copy(&mut test_data.as_slice(), &mut writer).expect("Failed to encode data");
        writer.finish().expect("Failed to finish encoding");

        assert!(test_data != encoded_buffer);

        let mut decoded_data = Vec::new();
        let mut reader = BcjReader::new_riscv(Cursor::new(&encoded_buffer), 0);
        copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

        assert!(test_data == decoded_data);
    }
}
