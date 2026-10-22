use alloc::vec::Vec;

use super::{
    Read,
    decoder::LzmaDecoder,
    error_invalid_data, error_invalid_input,
    lz::LzDecoder,
    range_dec::{RangeDecoder, RangeDecoderBuffer},
};
use crate::{
    ByteReader, DICT_SIZE_MIN,
    stream::{Action, Status, StreamResult},
};

pub const COMPRESSED_SIZE_MAX: u32 = 1 << 16;

/// A single-threaded LZMA2 decompressor.
///
/// # Examples
/// ```
/// use std::io::Read;
///
/// use lzma_rust2::{Lzma2Reader, LzmaOptions};
///
/// let compressed: Vec<u8> = vec![
///     1, 0, 12, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 0,
/// ];
/// let mut reader = Lzma2Reader::new(compressed.as_slice(), LzmaOptions::DICT_SIZE_DEFAULT, None);
/// let mut decompressed = Vec::new();
/// reader.read_to_end(&mut decompressed).unwrap();
/// assert_eq!(&decompressed[..], b"Hello, world!");
/// ```
pub struct Lzma2Reader<R> {
    inner: R,
    lz: LzDecoder,
    rc: RangeDecoder<RangeDecoderBuffer>,
    lzma: Option<LzmaDecoder>,
    uncompressed_size: usize,
    is_lzma_chunk: bool,
    need_dict_reset: bool,
    need_props: bool,
    end_reached: bool,
}

/// Calculates the memory usage in KiB required for LZMA2 decompression.
#[inline]
pub fn get_memory_usage(dict_size: u32) -> u32 {
    40 + COMPRESSED_SIZE_MAX / 1024 + get_dict_size(dict_size) / 1024
}

#[inline]
fn get_dict_size(dict_size: u32) -> u32 {
    if dict_size >= (u32::MAX - 15) {
        return u32::MAX;
    }

    (dict_size + 15) & !15
}

fn decode_lzma2_props(props: u8) -> crate::Result<LzmaDecoder> {
    if props > (4 * 5 + 4) * 9 + 8 {
        return Err(error_invalid_input("corrupted input data (LZMA2:3)"));
    }
    let pb = props / (9 * 5);
    let remainder = props - pb * 9 * 5;
    let lp = remainder / 9;
    let lc = remainder - lp * 9;
    if lc + lp > 4 {
        return Err(error_invalid_input("corrupted input data (LZMA2:4)"));
    }
    Ok(LzmaDecoder::new(lc as _, lp as _, pb as _))
}

impl<R> Lzma2Reader<R> {
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
}

impl<R: Read> Lzma2Reader<R> {
    /// Create a new LZMA2 reader.
    /// `inner` is the reader to read compressed data from.
    /// `dict_size` is the dictionary size in bytes.
    pub fn new(inner: R, dict_size: u32, preset_dict: Option<&[u8]>) -> Self {
        let has_preset = preset_dict.as_ref().map(|a| !a.is_empty()).unwrap_or(false);
        let lz = LzDecoder::new(get_dict_size(dict_size) as _, preset_dict);
        let rc = RangeDecoder::new_buffer(COMPRESSED_SIZE_MAX as _);
        Self {
            inner,
            lz,
            rc,
            lzma: None,
            uncompressed_size: 0,
            is_lzma_chunk: false,
            need_dict_reset: !has_preset,
            need_props: true,
            end_reached: false,
        }
    }

    // ### LZMA2 Control Byte Meaning
    //
    //  Control Byte    | Chunk Type      | Formal Action
    //  --------------- | --------------- | ----------------------------
    //  0x00            | End of Stream   | Terminates the LZMA2 stream.
    //  0x01            | Uncompressed    | Resets Dictionary.
    //  0x02            | Uncompressed    | Preserves Dictionary.
    //  0x03 – 0x7F     | Reserved        | Invalid stream.
    //  0x80 – 0xFF     | LZMA Compressed | Varies based on bits 6 and 5
    //
    // ### Detailed Breakdown of LZMA Compressed Chunks (0x80 - 0xFF)
    //
    //  Bits | Control Byte | Reset Action            | Suitable for Parallel Start? |
    //  ---- | ------------ | ----------------------- | ---------------------------- |
    //  00   | 0x80 – 0x9F  | None                    | No
    //  01   | 0xA0 – 0xBF  | Reset State             | No
    //  10   | 0xC0 – 0xDF  | Reset State & Props     | No
    //  11   | 0xE0 – 0xFF  | Reset Everything        | Yes
    fn decode_chunk_header(&mut self) -> crate::Result<()> {
        let control = self.inner.read_u8()?;

        if control == 0x00 {
            self.end_reached = true;
            return Ok(());
        }

        if control >= 0xE0 || control == 0x01 {
            self.need_props = true;
            self.need_dict_reset = false;
            // Reset dictionary
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }
        if control >= 0x80 {
            self.is_lzma_chunk = true;
            self.uncompressed_size = ((control & 0x1F) as usize) << 16;
            self.uncompressed_size += self.inner.read_u16_be()? as usize + 1;
            let compressed_size = self.inner.read_u16_be()? as usize + 1;

            if control >= 0xC0 {
                // Reset props and state (by re-creating it)
                self.need_props = false;
                self.decode_props()?;
            } else if self.need_props {
                return Err(error_invalid_input("corrupted input data (LZMA2:1)"));
            } else if control >= 0xA0 {
                // Reset state
                if let Some(l) = self.lzma.as_mut() {
                    l.reset()
                }
            }

            self.rc.prepare(&mut self.inner, compressed_size)?;
        } else if control > 0x02 {
            return Err(error_invalid_input("corrupted input data (LZMA2:2)"));
        } else {
            self.is_lzma_chunk = false;
            self.uncompressed_size = (self.inner.read_u16_be()? as usize) + 1;
        }
        Ok(())
    }

    fn decode_props(&mut self) -> crate::Result<()> {
        let props = self.inner.read_u8()?;
        self.lzma = Some(decode_lzma2_props(props)?);
        Ok(())
    }
}

impl<R: Read> Read for Lzma2Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.end_reached {
            return Ok(0);
        }

        self.lz.ensure_capacity()?;

        let mut size = 0;
        let mut len = buf.len();
        let mut off = 0;
        while len > 0 {
            if self.uncompressed_size == 0 {
                self.decode_chunk_header()?;
                if self.end_reached {
                    return Ok(size);
                }
            }

            let copy_size_max = self.uncompressed_size.min(len);
            if !self.is_lzma_chunk {
                self.lz.copy_uncompressed(&mut self.inner, copy_size_max)?;
            } else {
                self.lz.set_limit(copy_size_max);
                if let Some(lzma) = self.lzma.as_mut() {
                    lzma.decode(&mut self.lz, &mut self.rc)?;
                }
            }

            {
                let copied_size = self.lz.flush(buf, off)?;
                off = off.saturating_add(copied_size);
                len = len.saturating_sub(copied_size);
                size = size.saturating_add(copied_size);
                self.uncompressed_size = self.uncompressed_size.saturating_sub(copied_size);
                if self.uncompressed_size == 0 && (!self.rc.is_finished() || self.lz.has_pending())
                {
                    return Err(error_invalid_input("rc not finished or lz has pending"));
                }
            }
        }

        Ok(size)
    }
}

#[derive(Clone, Copy)]
enum Lzma2State {
    ChunkHeader,
    CompressedData { remaining: usize },
    UncompressedData { remaining: usize },
    DrainUncompressed { remaining: usize },
    Decode,
    DrainOutput,
    Finished,
}

/// Sans-I/O LZMA2 stream decoder.
///
/// Decodes a raw LZMA2 byte stream (no XZ container). Call `process()` repeatedly
/// with input/output buffers until `Status::StreamEnd` is returned.
pub struct Lzma2Stream {
    state: Lzma2State,
    accum: Vec<u8>,
    accum_needed: usize,
    lz: LzDecoder,
    rc: RangeDecoder<RangeDecoderBuffer>,
    lzma: Option<LzmaDecoder>,
    compressed_buf: Vec<u8>,
    uncompressed_size: usize,
    need_dict_reset: bool,
    need_props: bool,
    total_in: u64,
    total_out: u64,
}

impl Lzma2Stream {
    /// Create a new LZMA2 stream decoder with the given dictionary size.
    pub fn new(dict_size: u32) -> Self {
        let dict_size = get_dict_size(dict_size.max(DICT_SIZE_MIN)) as usize;
        Self {
            state: Lzma2State::ChunkHeader,
            accum: Vec::with_capacity(8),
            accum_needed: 1,
            lz: LzDecoder::new(dict_size, None),
            rc: RangeDecoder::new_buffer(65536),
            lzma: None,
            compressed_buf: Vec::new(),
            uncompressed_size: 0,
            need_dict_reset: true,
            need_props: true,
            total_in: 0,
            total_out: 0,
        }
    }

    /// Total bytes consumed from input across all `process()` calls.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Total bytes produced to output across all `process()` calls.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Returns true if the LZMA2 stream has been fully decoded.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, Lzma2State::Finished)
    }

    /// Returns true if there is decoded output waiting to be flushed.
    pub fn has_output(&self) -> bool {
        self.lz.has_output()
    }

    /// Process available LZMA2 data from `input` into `output`.
    pub fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> crate::Result<StreamResult> {
        self.lz.ensure_capacity()?;

        let mut in_pos = 0;
        let mut out_pos = 0;

        loop {
            match self.state {
                Lzma2State::Finished => {
                    return Ok(StreamResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Status::StreamEnd,
                    });
                }

                Lzma2State::DrainOutput | Lzma2State::DrainUncompressed { .. } => {
                    if out_pos >= output.len() {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }
                    if !self.flush_output(output, &mut out_pos) {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }
                }

                Lzma2State::Decode => {
                    self.decode_lzma()?;
                }

                Lzma2State::CompressedData { remaining } => {
                    if let Some(result) = self.process_compressed_data(
                        input,
                        action,
                        &mut in_pos,
                        out_pos,
                        remaining,
                    )? {
                        return Ok(result);
                    }
                }

                Lzma2State::UncompressedData { remaining } => {
                    if let Some(result) = self.process_uncompressed_data(
                        input,
                        action,
                        &mut in_pos,
                        out_pos,
                        remaining,
                    )? {
                        return Ok(result);
                    }
                }

                Lzma2State::ChunkHeader => {
                    if let Some(result) =
                        self.accumulate_chunk_header(input, action, &mut in_pos, out_pos)?
                    {
                        return Ok(result);
                    }
                }
            }
        }
    }

    fn flush_output(&mut self, output: &mut [u8], out_pos: &mut usize) -> bool {
        let n = self.lz.flush_partial(&mut output[*out_pos..]);
        if n > 0 {
            *out_pos += n;
            self.total_out += n as u64;
        }
        if self.lz.has_output() {
            return false;
        }
        self.finish_drain();
        true
    }

    fn decode_lzma(&mut self) -> crate::Result<()> {
        let pos_before = self.lz.get_pos();
        self.lz.set_limit(self.uncompressed_size);
        self.lzma
            .as_mut()
            .ok_or_else(|| error_invalid_input("corrupted input data (LZMA2:1)"))?
            .decode(&mut self.lz, &mut self.rc)?;
        let decoded = self.lz.get_pos() - pos_before;
        self.uncompressed_size -= decoded;

        if self.uncompressed_size == 0 && (!self.rc.is_finished() || self.lz.has_pending()) {
            return Err(error_invalid_input("rc not finished or lz has pending"));
        }

        self.state = Lzma2State::DrainOutput;
        Ok(())
    }

    fn process_compressed_data(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
        remaining: usize,
    ) -> crate::Result<Option<StreamResult>> {
        if *in_pos >= input.len() {
            if action == Action::Finish {
                return Err(error_invalid_data("unexpected end of LZMA2 stream"));
            }
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: out_pos,
                status: Status::Ok,
            }));
        }
        let available = &input[*in_pos..];
        let to_copy = remaining.min(available.len());
        self.compressed_buf.extend_from_slice(&available[..to_copy]);
        *in_pos += to_copy;
        self.total_in += to_copy as u64;
        let new_remaining = remaining - to_copy;
        if new_remaining == 0 {
            self.rc.prepare_from_slice(&self.compressed_buf)?;
            self.compressed_buf.clear();
            self.state = Lzma2State::Decode;
        } else {
            self.state = Lzma2State::CompressedData {
                remaining: new_remaining,
            };
        }
        Ok(None)
    }

    fn process_uncompressed_data(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
        remaining: usize,
    ) -> crate::Result<Option<StreamResult>> {
        let lz_space = self.lz.available_space();
        if lz_space == 0 {
            self.state = Lzma2State::DrainUncompressed { remaining };
            return Ok(None);
        }
        if *in_pos >= input.len() {
            if action == Action::Finish {
                return Err(error_invalid_data("unexpected end of LZMA2 stream"));
            }
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: out_pos,
                status: Status::Ok,
            }));
        }
        let available = &input[*in_pos..];
        let to_copy = remaining.min(available.len()).min(lz_space);
        self.lz
            .copy_uncompressed_from_slice(&available[..to_copy])?;
        *in_pos += to_copy;
        self.total_in += to_copy as u64;
        self.uncompressed_size -= to_copy;
        let new_remaining = remaining - to_copy;
        if new_remaining == 0 {
            self.state = Lzma2State::DrainOutput;
        } else if self.lz.available_space() == 0 {
            self.state = Lzma2State::DrainUncompressed {
                remaining: new_remaining,
            };
        } else {
            self.state = Lzma2State::UncompressedData {
                remaining: new_remaining,
            };
        }
        Ok(None)
    }

    fn accumulate_chunk_header(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
    ) -> crate::Result<Option<StreamResult>> {
        if self.accum.len() < self.accum_needed {
            if *in_pos >= input.len() {
                if action == Action::Finish {
                    return Err(error_invalid_data("unexpected end of LZMA2 stream"));
                }
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: out_pos,
                    status: Status::Ok,
                }));
            }
            let available = &input[*in_pos..];
            let need = self.accum_needed - self.accum.len();
            let to_copy = need.min(available.len());
            self.accum.extend_from_slice(&available[..to_copy]);
            *in_pos += to_copy;
            self.total_in += to_copy as u64;
            if self.accum.len() < self.accum_needed {
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: out_pos,
                    status: Status::Ok,
                }));
            }
        }
        self.process_chunk_header()?;
        Ok(None)
    }

    pub(crate) fn is_draining(&self) -> bool {
        matches!(
            self.state,
            Lzma2State::DrainOutput | Lzma2State::DrainUncompressed { .. }
        )
    }

    pub(crate) fn drain_with_filter(&mut self, output: &mut [u8], out_pos: &mut usize) -> usize {
        if *out_pos >= output.len() {
            return 0;
        }
        let n = self.lz.flush_partial(&mut output[*out_pos..]);
        if n > 0 {
            *out_pos += n;
            self.total_out += n as u64;
        }
        if !self.lz.has_output() {
            self.finish_drain();
        }
        n
    }

    pub(crate) fn drain_to_buf(&mut self, buf: &mut Vec<u8>, limit: usize) -> usize {
        let mut tmp = [0u8; 4096];
        let cap = limit.min(tmp.len());
        let n = self.lz.flush_partial(&mut tmp[..cap]);
        if n > 0 {
            buf.extend_from_slice(&tmp[..n]);
            self.total_out += n as u64;
        }
        if !self.lz.has_output() {
            self.finish_drain();
        }
        n
    }

    fn finish_drain(&mut self) {
        match self.state {
            Lzma2State::DrainUncompressed { remaining } => {
                self.state = Lzma2State::UncompressedData { remaining };
            }
            _ if self.uncompressed_size > 0 => {
                self.state = Lzma2State::Decode;
            }
            _ => {
                self.state = Lzma2State::ChunkHeader;
                self.accum.clear();
                self.accum_needed = 1;
            }
        }
    }

    fn process_chunk_header(&mut self) -> crate::Result<()> {
        let control = self.accum[0];
        if control == 0x00 {
            self.state = Lzma2State::Finished;
            Ok(())
        } else if control >= 0x80 {
            self.process_compressed_chunk_header(control)
        } else if control <= 0x02 {
            self.process_uncompressed_chunk_header(control)
        } else {
            Err(error_invalid_input("corrupted input data (LZMA2:2)"))
        }
    }

    fn process_compressed_chunk_header(&mut self, control: u8) -> crate::Result<()> {
        let needed = if control >= 0xC0 { 6 } else { 5 };
        if self.accum.len() < needed {
            self.accum_needed = needed;
            return Ok(());
        }

        if control >= 0xE0 {
            self.need_props = true;
            self.need_dict_reset = false;
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }

        self.uncompressed_size = ((control & 0x1F) as usize) << 16;
        let uncompressed_hi = u16::from_be_bytes([self.accum[1], self.accum[2]]);
        self.uncompressed_size += uncompressed_hi as usize + 1;
        let compressed_size = u16::from_be_bytes([self.accum[3], self.accum[4]]) as usize + 1;

        if control >= 0xC0 {
            self.need_props = false;
            self.lzma = Some(decode_lzma2_props(self.accum[5])?);
        } else if self.need_props {
            return Err(error_invalid_input("corrupted input data (LZMA2:1)"));
        } else if control >= 0xA0 {
            if let Some(l) = self.lzma.as_mut() {
                l.reset();
            }
        }

        self.compressed_buf.clear();
        self.compressed_buf.reserve(compressed_size);
        self.state = Lzma2State::CompressedData {
            remaining: compressed_size,
        };
        self.accum.clear();
        Ok(())
    }

    fn process_uncompressed_chunk_header(&mut self, control: u8) -> crate::Result<()> {
        if self.accum.len() < 3 {
            self.accum_needed = 3;
            return Ok(());
        }

        if control == 0x01 {
            self.need_props = true;
            self.need_dict_reset = false;
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }

        self.uncompressed_size = u16::from_be_bytes([self.accum[1], self.accum[2]]) as usize + 1;

        self.state = Lzma2State::UncompressedData {
            remaining: self.uncompressed_size,
        };
        self.accum.clear();
        Ok(())
    }
}
