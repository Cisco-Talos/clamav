use alloc::vec::Vec;

use crate::{
    ByteReader, DICT_SIZE_MAX, Read,
    decoder::LzmaDecoder,
    error_invalid_data, error_invalid_input, error_out_of_memory,
    lz::LzDecoder,
    range_dec::{RangeCoderState, RangeDecoder, SliceRangeReader},
    stream::{Action, Status, StreamResult},
};

/// Calculates the memory usage in KiB required for LZMA decompression from properties byte.
pub fn get_memory_usage_by_props(dict_size: u32, props_byte: u8) -> crate::Result<u32> {
    if dict_size > DICT_SIZE_MAX {
        return Err(error_invalid_input("dict size too large"));
    }
    if props_byte > (4 * 5 + 4) * 9 + 8 {
        return Err(error_invalid_input("invalid props byte"));
    }
    let props = props_byte % (9 * 5);
    let lp = props / 9;
    let lc = props - lp * 9;
    get_memory_usage(dict_size, lc as u32, lp as u32)
}

/// Calculates the memory usage in KiB required for LZMA decompression.
pub fn get_memory_usage(dict_size: u32, lc: u32, lp: u32) -> crate::Result<u32> {
    if lc > 8 || lp > 4 {
        return Err(error_invalid_input("invalid lc or lp"));
    }
    Ok(10 + get_dict_size(dict_size)? / 1024 + ((2 * 0x300) << (lc + lp)) / 1024)
}

fn get_dict_size(dict_size: u32) -> crate::Result<u32> {
    if dict_size > DICT_SIZE_MAX {
        return Err(error_invalid_input("dict size too large"));
    }
    let dict_size = dict_size.max(4096);
    Ok((dict_size + 15) & !15)
}

/// A single-threaded LZMA decompressor.
///
/// # Examples
/// ```
/// use std::io::Read;
///
/// use lzma_rust2::LzmaReader;
///
/// let compressed: Vec<u8> = vec![
///     93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 36, 25, 73, 152, 111, 22, 2,
///     140, 232, 230, 91, 177, 71, 198, 206, 183, 99, 255, 255, 60, 172, 0, 0,
/// ];
/// let mut reader = LzmaReader::new_mem_limit(compressed.as_slice(), u32::MAX, None).unwrap();
/// let mut buf = [0; 1024];
/// let mut out = Vec::new();
/// loop {
///     let n = reader.read(&mut buf).unwrap();
///     if n == 0 {
///         break;
///     }
///     out.extend_from_slice(&buf[..n]);
/// }
/// assert_eq!(out, b"Hello, world!");
/// ```
pub struct LzmaReader<R> {
    lz: LzDecoder,
    rc: RangeDecoder<R>,
    lzma: LzmaDecoder,
    end_reached: bool,
    relaxed_end_cond: bool,
    remaining_size: u64,
    deferred_error: Option<crate::Error>,
}

impl<R> LzmaReader<R> {
    /// Controls whether a known-size raw LZMA stream may stop without the
    /// range coder reaching its canonical terminal state.
    pub fn set_relaxed_end_condition(&mut self, relaxed: bool) {
        self.relaxed_end_cond = relaxed;
    }

    /// Unwraps the reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.rc.into_inner()
    }

    /// Returns a reference to the inner reader.
    pub fn inner(&self) -> &R {
        self.rc.inner()
    }

    /// Returns a mutable reference to the inner reader.
    pub fn inner_mut(&mut self) -> &mut R {
        self.rc.inner_mut()
    }
}

impl<R: Read> LzmaReader<R> {
    fn construct1(
        reader: R,
        uncomp_size: u64,
        mut props: u8,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        if props > (4 * 5 + 4) * 9 + 8 {
            return Err(error_invalid_input("invalid props byte"));
        }
        let pb = props / (9 * 5);
        props -= pb * 9 * 5;
        let lp = props / 9;
        let lc = props - lp * 9;
        if dict_size > DICT_SIZE_MAX {
            return Err(error_invalid_input("dict size too large"));
        }
        Self::construct2(
            reader,
            uncomp_size,
            lc as _,
            lp as _,
            pb as _,
            dict_size,
            preset_dict,
        )
    }

    fn construct2(
        reader: R,
        uncomp_size: u64,
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_input("invalid lc or lp or pb"));
        }
        let mut dict_size = get_dict_size(dict_size)?;

        let preset_size = preset_dict
            .map(|dict| dict.len().min(dict_size as usize) as u64)
            .unwrap_or(0);
        let min_history_size = uncomp_size.saturating_add(preset_size);

        if uncomp_size <= u64::MAX / 2 && dict_size as u64 > min_history_size {
            dict_size = get_dict_size(min_history_size as u32)?;
        }

        let rc = RangeDecoder::new_stream(reader);
        let rc = match rc {
            Ok(r) => r,
            Err(e) => {
                return Err(e);
            }
        };
        let lz = LzDecoder::new(get_dict_size(dict_size)? as _, preset_dict);
        let lzma = LzmaDecoder::new(lc, lp, pb);
        Ok(Self {
            // reader,
            lz,
            rc,
            lzma,
            end_reached: false,
            relaxed_end_cond: true,
            remaining_size: uncomp_size,
            deferred_error: None,
        })
    }

    /// Creates a new .lzma file format decompressor with an optional memory usage limit.
    /// - `mem_limit_kb` - memory usage limit in kibibytes (KiB). `u32::MAX` means no limit.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new_mem_limit(
        mut reader: R,
        mem_limit_kb: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        let props = reader.read_u8()?;
        let dict_size = reader.read_u32()?;

        let uncomp_size = reader.read_u64()?;
        let need_mem = get_memory_usage_by_props(dict_size, props)?;
        if mem_limit_kb < need_mem {
            return Err(error_out_of_memory(
                "needed memory too big for mem_limit_kb",
            ));
        }
        Self::construct1(reader, uncomp_size, props, dict_size, preset_dict)
    }

    /// Creates a new input stream that decompresses raw LZMA data (no .lzma header) from `reader` optionally with a preset dictionary.
    /// - `reader` - the reader to read compressed data from.
    /// - `uncomp_size` - the uncompressed size of the data to be decompressed.
    /// - `props` - the LZMA properties byte.
    /// - `dict_size` - the LZMA dictionary size.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new_with_props(
        reader: R,
        uncomp_size: u64,
        props: u8,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        Self::construct1(reader, uncomp_size, props, dict_size, preset_dict)
    }

    /// Creates a new input stream that decompresses raw LZMA data (no .lzma header) from `reader` optionally with a preset dictionary.
    /// - `reader` - the input stream to read compressed data from.
    /// - `uncomp_size` - the uncompressed size of the data to be decompressed.
    /// - `lc` - the number of literal context bits.
    /// - `lp` - the number of literal position bits.
    /// - `pb` - the number of position bits.
    /// - `dict_size` - the LZMA dictionary size.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new(
        reader: R,
        uncomp_size: u64,
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        Self::construct2(reader, uncomp_size, lc, lp, pb, dict_size, preset_dict)
    }

    fn read_decode(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.end_reached {
            return Ok(0);
        }
        if let Some(error) = self.deferred_error.take() {
            return Err(error);
        }

        self.lz.ensure_capacity()?;

        let mut size: u64 = 0;
        let mut len = buf.len() as u64;
        let mut off: u64 = 0;
        while len > 0 {
            let mut copy_size_max = len;
            if self.remaining_size <= u64::MAX / 2 && self.remaining_size < len {
                copy_size_max = self.remaining_size;
            }
            self.lz.set_limit(copy_size_max as usize);

            let mut decode_error = None;
            match self.lzma.decode(&mut self.lz, &mut self.rc) {
                Ok(_) => {}
                Err(error) => {
                    if self.remaining_size != u64::MAX || !self.lzma.end_marker_detected() {
                        decode_error = Some(error);
                    } else {
                        self.end_reached = true;
                        self.rc.normalize();
                    }
                }
            }

            let copied_size = self.lz.flush(buf, off as _)? as u64;
            off = off.saturating_add(copied_size);
            len = len.saturating_sub(copied_size);
            size = size.saturating_add(copied_size);
            if let Some(error) = decode_error {
                if size != 0 {
                    self.deferred_error = Some(error);
                    return Ok(size as usize);
                }
                return Err(error);
            }
            if self.remaining_size <= u64::MAX / 2 {
                self.remaining_size = self.remaining_size.saturating_sub(copied_size);
                if self.remaining_size == 0 {
                    self.end_reached = true;
                }
            }

            if self.end_reached {
                if self.lz.has_pending()
                    || (!self.relaxed_end_cond && !self.rc.is_stream_finished())
                {
                    let error = error_invalid_data("end reached but not decoder finished");
                    if size != 0 {
                        self.deferred_error = Some(error);
                        return Ok(size as usize);
                    }
                    return Err(error);
                }
                return Ok(size as _);
            }
        }
        Ok(size as _)
    }
}

impl<R: Read> Read for LzmaReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        self.read_decode(buf)
    }
}

/// Minimum number of input bytes needed to safely decode one LZMA symbol.
///
/// The worst case is a match with the maximum length at the maximum distance:
/// 22 probability-coded bits plus 26 direct bits, which together can consume at
/// most 20 input bytes.
const IN_REQUIRED: usize = 20;

/// Capacity of the carry buffer: up to 19 bytes left over from the last call,
/// plus 20 fresh ones.
///
/// Those 20 are what lets a pass use up the leftovers and carry on decoding
/// straight out of the caller's buffer.
const CARRY_CAP: usize = 2 * IN_REQUIRED;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LzmaState {
    Header,
    RcInit,
    Decode,
    DrainOutput,
    Finished,
}

/// Output space the decoder may fill before it has to stop.
fn room_for(lz: Option<&LzDecoder>, remaining_size: u64) -> usize {
    let Some(lz) = lz else {
        return 0;
    };
    let mut room = lz.available_space();
    if remaining_size <= u64::MAX / 2 {
        room = room.min(remaining_size.min(usize::MAX as u64) as usize);
    }
    room
}

/// A sans-I/O LZMA1 stream decoder.
///
/// Unlike [`LzmaReader`] this pulls no bytes on its own: call [`process()`] with
/// an input slice and an output slice until it returns [`Status::StreamEnd`].
///
/// Every call consumes the whole `input` slice unless the output buffer filled
/// first or the stream ended, so the caller never has to re-present bytes.
///
/// [`process()`]: LzmaStream::process
///
/// # Examples
/// ```
/// use lzma_rust2::{Action, LzmaStream, Status};
///
/// let compressed: Vec<u8> = vec![
///     93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 36, 25, 73, 152, 111, 22, 2,
///     140, 232, 230, 91, 177, 71, 198, 206, 183, 99, 255, 255, 60, 172, 0, 0,
/// ];
///
/// let mut stream = LzmaStream::new_mem_limit(u32::MAX, None);
/// let mut buf = [0; 1024];
/// let mut out = Vec::new();
/// let mut consumed = 0;
/// loop {
///     let result = stream
///         .process(&compressed[consumed..], &mut buf, Action::Finish)
///         .unwrap();
///     consumed += result.bytes_consumed;
///     out.extend_from_slice(&buf[..result.bytes_produced]);
///     if result.status == Status::StreamEnd {
///         break;
///     }
/// }
/// assert_eq!(out, b"Hello, world!");
/// ```
pub struct LzmaStream {
    state: LzmaState,
    /// `None` until the dictionary size is known (header mode).
    lz: Option<LzDecoder>,
    /// `None` until the properties byte is known (header mode).
    lzma: Option<LzmaDecoder>,
    rc: RangeCoderState,
    /// Bytes taken from the caller that were too few to start a symbol from.
    carry: [u8; CARRY_CAP],
    carry_len: usize,
    /// Header and range-coder-init bytes.
    accum: Vec<u8>,
    accum_needed: usize,
    /// `u64::MAX` means unknown; such a stream is terminated by an end of
    /// payload marker.
    remaining_size: u64,
    mem_limit_kb: u32,
    preset_dict: Option<Vec<u8>>,
    end_reached: bool,
    /// Set once `process()` has returned an error. A failed stream stays failed.
    failed: bool,
    total_in: u64,
    total_out: u64,
}

impl LzmaStream {
    fn with_parts(
        state: LzmaState,
        lz: Option<LzDecoder>,
        lzma: Option<LzmaDecoder>,
        accum_needed: usize,
        remaining_size: u64,
        mem_limit_kb: u32,
        preset_dict: Option<&[u8]>,
    ) -> Self {
        Self {
            state,
            lz,
            lzma,
            rc: RangeCoderState::default(),
            carry: [0; CARRY_CAP],
            carry_len: 0,
            accum: Vec::new(),
            accum_needed,
            remaining_size,
            mem_limit_kb,
            preset_dict: preset_dict.map(|dict| dict.to_vec()),
            end_reached: false,
            failed: false,
            total_in: 0,
            total_out: 0,
        }
    }

    /// Creates a decompressor for the .lzma file format, including its 13 byte
    /// header, with an optional memory usage limit.
    /// - `mem_limit_kb` - memory usage limit in kibibytes (KiB). `u32::MAX` means no limit.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    ///
    /// The header is parsed on the first [`process()`] call, so malformed
    /// headers and memory limit violations surface from there rather than here.
    ///
    /// [`process()`]: LzmaStream::process
    pub fn new_mem_limit(mem_limit_kb: u32, preset_dict: Option<&[u8]>) -> Self {
        Self::with_parts(
            LzmaState::Header,
            None,
            None,
            13,
            u64::MAX,
            mem_limit_kb,
            preset_dict,
        )
    }

    /// Creates a decompressor for raw LZMA data (no .lzma header) optionally
    /// with a preset dictionary.
    /// - `uncomp_size` - the uncompressed size of the data to be decompressed.
    /// - `props` - the LZMA properties byte.
    /// - `dict_size` - the LZMA dictionary size.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new_with_props(
        uncomp_size: u64,
        mut props: u8,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        if props > (4 * 5 + 4) * 9 + 8 {
            return Err(error_invalid_input("invalid props byte"));
        }
        let pb = props / (9 * 5);
        props -= pb * 9 * 5;
        let lp = props / 9;
        let lc = props - lp * 9;
        if dict_size > DICT_SIZE_MAX {
            return Err(error_invalid_input("dict size too large"));
        }
        Self::new(
            uncomp_size,
            lc as _,
            lp as _,
            pb as _,
            dict_size,
            preset_dict,
        )
    }

    /// Creates a decompressor for raw LZMA data (no .lzma header) optionally
    /// with a preset dictionary.
    /// - `uncomp_size` - the uncompressed size of the data to be decompressed.
    /// - `lc` - the number of literal context bits.
    /// - `lp` - the number of literal position bits.
    /// - `pb` - the number of position bits.
    /// - `dict_size` - the LZMA dictionary size.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new(
        uncomp_size: u64,
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        let (lz, lzma) = build_decoders(uncomp_size, lc, lp, pb, dict_size, preset_dict)?;
        Ok(Self::with_parts(
            LzmaState::RcInit,
            Some(lz),
            Some(lzma),
            5,
            uncomp_size,
            u32::MAX,
            preset_dict,
        ))
    }

    /// Total bytes consumed from input across all `process()` calls.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Total bytes produced to output across all `process()` calls.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Returns true if the LZMA stream has been fully decoded.
    pub fn is_finished(&self) -> bool {
        self.state == LzmaState::Finished
    }

    /// Returns true if there is decoded output waiting to be flushed.
    pub fn has_output(&self) -> bool {
        self.lz.as_ref().is_some_and(|lz| lz.has_output())
    }

    /// Bytes that were absorbed from the caller but turned out not to belong to
    /// the LZMA stream.
    ///
    /// Only meaningful once [`Status::StreamEnd`] has been returned; before
    /// that it is always empty. Never more than 40 bytes.
    ///
    /// Since `process()` always takes the whole input, a container format with
    /// more data behind the LZMA stream gets it back as `unused_input()` plus
    /// anything past `bytes_consumed` in the last slice it passed.
    ///
    /// Note that for a stream with a known uncompressed size the decoder may
    /// consume one extra byte for the final range coder normalisation, exactly
    /// as [`LzmaReader`] does.
    pub fn unused_input(&self) -> &[u8] {
        if self.state == LzmaState::Finished {
            &self.carry[..self.carry_len]
        } else {
            &[]
        }
    }

    /// Process available LZMA data from `input` into `output`.
    pub fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> crate::Result<StreamResult> {
        if self.failed {
            return Err(error_invalid_data("LZMA stream already failed"));
        }

        let result = self.process_inner(input, output, action);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn process_inner(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> crate::Result<StreamResult> {
        let mut in_pos = 0;
        let mut out_pos = 0;
        // Set when a decode pass could make no progress at all. Without this
        // the loop spins forever on an empty input or a full output buffer.
        let mut stalled = false;

        loop {
            match self.state {
                LzmaState::Finished => {
                    return Ok(StreamResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Status::StreamEnd,
                    });
                }

                LzmaState::Header => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }
                    self.parse_header()?;
                }

                LzmaState::RcInit => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }
                    self.init_range_coder()?;
                }

                LzmaState::Decode => {
                    if stalled {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }

                    // A stream whose declared size is zero is already over; no
                    // decode pass will ever set this for us.
                    if self.remaining_size == 0 {
                        self.end_reached = true;
                    }

                    let space = {
                        let lz = self.lz_mut()?;
                        lz.ensure_capacity()?;
                        lz.available_space()
                    };

                    if self.end_reached || space == 0 {
                        self.state = LzmaState::DrainOutput;
                        continue;
                    }

                    let (consumed, produced) = self.decode_pass(input, &mut in_pos, action)?;
                    if consumed == 0 && produced == 0 && !self.end_reached {
                        stalled = true;
                    }
                    self.state = LzmaState::DrainOutput;
                }

                LzmaState::DrainOutput => {
                    if out_pos >= output.len() {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }

                    let (flushed, has_output) = {
                        let lz = self.lz_mut()?;
                        let flushed = lz.flush_partial(&mut output[out_pos..]);
                        (flushed, lz.has_output())
                    };
                    out_pos += flushed;
                    self.total_out += flushed as u64;

                    if has_output {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }

                    self.state = if self.end_reached {
                        LzmaState::Finished
                    } else {
                        LzmaState::Decode
                    };
                }
            }
        }
    }

    fn lz_mut(&mut self) -> crate::Result<&mut LzDecoder> {
        self.lz
            .as_mut()
            .ok_or_else(|| error_invalid_data("LZMA decoder not initialized"))
    }

    /// Fills `accum` up to `accum_needed` bytes, returning a result to hand back
    /// to the caller when the input ran dry first.
    fn accumulate(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
    ) -> crate::Result<Option<StreamResult>> {
        while self.accum.len() < self.accum_needed {
            if *in_pos >= input.len() {
                if action == Action::Finish {
                    return Err(error_invalid_data("unexpected end of LZMA stream"));
                }
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: out_pos,
                    status: Status::Ok,
                }));
            }
            let need = self.accum_needed - self.accum.len();
            let to_copy = need.min(input.len() - *in_pos);
            self.accum
                .extend_from_slice(&input[*in_pos..*in_pos + to_copy]);
            *in_pos += to_copy;
            self.total_in += to_copy as u64;
        }
        Ok(None)
    }

    /// Parses the 13 byte .lzma header: `props: u8`, `dict_size: u32` little
    /// endian, `uncomp_size: u64` little endian. Note that LZMA2 chunk headers
    /// are big endian; these are not.
    fn parse_header(&mut self) -> crate::Result<()> {
        let props = self.accum[0];
        let dict_size =
            u32::from_le_bytes([self.accum[1], self.accum[2], self.accum[3], self.accum[4]]);
        let uncomp_size = u64::from_le_bytes([
            self.accum[5],
            self.accum[6],
            self.accum[7],
            self.accum[8],
            self.accum[9],
            self.accum[10],
            self.accum[11],
            self.accum[12],
        ]);

        // Check the memory limit before allocating anything.
        let need_mem = get_memory_usage_by_props(dict_size, props)?;
        if self.mem_limit_kb < need_mem {
            return Err(error_out_of_memory(
                "needed memory too big for mem_limit_kb",
            ));
        }

        let mut props = props;
        let pb = props / (9 * 5);
        props -= pb * 9 * 5;
        let lp = props / 9;
        let lc = props - lp * 9;
        if dict_size > DICT_SIZE_MAX {
            return Err(error_invalid_input("dict size too large"));
        }

        let (lz, lzma) = build_decoders(
            uncomp_size,
            lc as _,
            lp as _,
            pb as _,
            dict_size,
            self.preset_dict.as_deref(),
        )?;
        self.lz = Some(lz);
        self.lzma = Some(lzma);
        self.remaining_size = uncomp_size;

        self.accum.clear();
        self.accum_needed = 5;
        self.state = LzmaState::RcInit;
        Ok(())
    }

    /// Incremental equivalent of [`RangeDecoder::new_stream`]: the first byte
    /// must be zero, the next four are `code` in big endian order.
    fn init_range_coder(&mut self) -> crate::Result<()> {
        if self.accum[0] != 0x00 {
            return Err(error_invalid_input("range decoder first byte is not zero"));
        }
        self.rc = RangeCoderState {
            range: 0xFFFF_FFFF,
            code: u32::from_be_bytes([self.accum[1], self.accum[2], self.accum[3], self.accum[4]]),
        };
        self.accum.clear();
        self.accum_needed = 0;
        self.state = LzmaState::Decode;
        Ok(())
    }

    /// Runs one decode pass, returning `(bytes consumed from input, bytes
    /// decoded into the dictionary)`.
    fn decode_pass(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        action: Action,
    ) -> crate::Result<(usize, usize)> {
        let mut consumed = 0;
        let mut produced = 0;

        // No more input will ever arrive, so go straight to the finish tail
        // rather than pointlessly re-running the carry.
        let finish_now = action == Action::Finish && *in_pos >= input.len();

        // Set when the carry could not be drained. The caller's remaining input
        // cannot be decoded in place until it has been.
        let mut carry_blocked = false;

        // Decode across the boundary between the bytes carried over from an
        // earlier call and the fresh input.
        if self.carry_len > 0 && !finish_now {
            let carry_len = self.carry_len;
            let m = (input.len() - *in_pos).min(CARRY_CAP - carry_len);
            let filled = carry_len + m;

            let mut scratch = self.carry;
            scratch[carry_len..filled].copy_from_slice(&input[*in_pos..*in_pos + m]);

            let symbol_limit = filled.saturating_sub(IN_REQUIRED - 1);
            let (pos, decoded) = self.run(&scratch[..filled], filled, symbol_limit)?;
            produced += decoded;

            if pos >= carry_len {
                // The carry is drained. Un-consume the scratch residue so the
                // direct path below can pick it up in place.
                let extra = pos - carry_len;
                *in_pos += extra;
                self.total_in += extra as u64;
                consumed += extra;
                self.carry_len = 0;
            } else {
                // Only reachable when `m < IN_REQUIRED`, i.e. the caller did
                // not hand us enough to complete even one symbol. The residue
                // can be as large as `CARRY_CAP - 1`.
                let residue = filled - pos;
                self.carry[..residue].copy_from_slice(&scratch[pos..filled]);
                self.carry_len = residue;
                *in_pos += m;
                self.total_in += m as u64;
                consumed += m;
                carry_blocked = true;
            }
        }

        // Decode in place over the caller's buffer, zero copy.
        if !carry_blocked && !self.end_reached {
            let avail = input.len() - *in_pos;
            if avail >= IN_REQUIRED {
                // A symbol may start only while `pos + IN_REQUIRED <= avail`,
                // that is while `pos < avail - (IN_REQUIRED - 1)`.
                let symbol_limit = avail - (IN_REQUIRED - 1);
                let (pos, decoded) = self.run(&input[*in_pos..], avail, symbol_limit)?;
                produced += decoded;
                *in_pos += pos;
                self.total_in += pos as u64;
                consumed += pos;
            }
        }

        // What is left is too short to start a symbol from, so take it into the
        // carry.
        if !carry_blocked && !self.end_reached {
            let rest = input.len() - *in_pos;
            if rest > 0 && rest < IN_REQUIRED {
                debug_assert_eq!(self.carry_len, 0);
                self.carry[..rest].copy_from_slice(&input[*in_pos..]);
                self.carry_len = rest;
                *in_pos = input.len();
                self.total_in += rest as u64;
                consumed += rest;
            }
        }

        // Decode the carry against zero padding and require the stream to end
        // inside the real bytes.
        if action == Action::Finish && !self.end_reached && *in_pos >= input.len() {
            produced += self.decode_finish_tail()?;
        }

        Ok((consumed, produced))
    }

    /// Decodes what is left of the carry with padding zeros behind it, so the
    /// decoder still sees the 20 bytes it needs to start one more symbol.
    ///
    /// The carry bytes were counted as consumed when they were taken in, so this
    /// adds nothing to `bytes_consumed`.
    fn decode_finish_tail(&mut self) -> crate::Result<usize> {
        if room_for(self.lz.as_ref(), self.remaining_size) == 0 {
            // No output space, so we cannot yet tell whether the stream really
            // ends here. The caller has to drain first.
            return Ok(0);
        }

        let carry_len = self.carry_len;

        // One symbol may start at `pos == carry_len` and read up to
        // `IN_REQUIRED` bytes from there, so at least that many zeros follow.
        let mut scratch = [0u8; CARRY_CAP + IN_REQUIRED + 1];
        scratch[..carry_len].copy_from_slice(&self.carry[..carry_len]);
        let padded_len = carry_len + IN_REQUIRED + 1;
        let (pos, produced) = self.run(&scratch[..padded_len], carry_len, carry_len + 1)?;

        if pos > carry_len {
            // The decoder had to read padding to get here, so the input is
            // really truncated.
            return Err(error_invalid_data("truncated LZMA stream"));
        }

        // Padding bytes must never be written back into the carry.
        self.carry.copy_within(pos..carry_len, 0);
        self.carry_len = carry_len - pos;

        Ok(produced)
    }

    /// Decodes as much as fits from `buf`, returning `(read position, bytes
    /// decoded into the dictionary)`.
    fn run(
        &mut self,
        buf: &[u8],
        real_len: usize,
        symbol_limit: usize,
    ) -> crate::Result<(usize, usize)> {
        // `lz` and `lzma` stay borrowed while `rc` lives, so the fields are
        // destructured up front and the range coder state is written back in
        // exactly one place below, error paths included.
        let Self {
            lz,
            lzma,
            rc: rc_state,
            remaining_size,
            end_reached,
            ..
        } = self;

        let room = room_for(lz.as_ref(), *remaining_size);
        if room == 0 {
            return Ok((0, 0));
        }

        let (lz, lzma) = match (lz.as_mut(), lzma.as_mut()) {
            (Some(lz), Some(lzma)) => (lz, lzma),
            _ => return Err(error_invalid_data("LZMA decoder not initialized")),
        };

        let pos_before = lz.get_pos();
        lz.set_limit(room);

        let mut rc = RangeDecoder::from_parts(
            SliceRangeReader::new(buf, real_len, symbol_limit),
            *rc_state,
        );
        let decode_result = lzma.decode(lz, &mut rc);

        // Must be read before anything can flush: `flush_partial` wraps `pos`
        // back to zero once the dictionary is full and fully drained.
        let produced = lz.get_pos() - pos_before;

        let mut error = None;
        if let Err(decode_error) = decode_result {
            // An end of payload marker surfaces as an error, because the decoder
            // calls `lz.repeat(0xFFFF_FFFF, len)`, which fails with "dist
            // overflow". Anything else is genuine corruption. Check the order:
            // `end_marker_detected()` is only meaningful right after a failed
            // `repeat`.
            if *remaining_size != u64::MAX || !lzma.end_marker_detected() {
                error = Some(decode_error);
            } else {
                if rc.can_normalize() {
                    rc.normalize();
                }
                // Only once the stream is known to end cleanly, or a caller that
                // calls again after the error is told it did.
                if rc.is_stream_finished() {
                    *end_reached = true;
                } else {
                    error = Some(error_invalid_data("LZMA stream not properly terminated"));
                }
            }
        }

        // The reported position is only ever compared against buffer bounds:
        // the assembly `decode_direct_bits` advances `pos` past what a symbol
        // logically needed and clamps its reads instead of signalling.
        let pos = rc.inner().pos().min(buf.len());
        *rc_state = rc.state();

        if let Some(error) = error {
            return Err(error);
        }

        if *remaining_size <= u64::MAX / 2 {
            *remaining_size -= produced as u64;
            if *remaining_size == 0 {
                *end_reached = true;
            }
        }

        if *end_reached && lz.has_pending() {
            return Err(error_invalid_data("end reached but not decoder finished"));
        }

        Ok((pos, produced))
    }
}

/// Shared by both the raw constructors and the header parser. Mirrors
/// `LzmaReader::construct2`, including the dictionary shrink for known sizes.
fn build_decoders(
    uncomp_size: u64,
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: u32,
    preset_dict: Option<&[u8]>,
) -> crate::Result<(LzDecoder, LzmaDecoder)> {
    if lc > 8 || lp > 4 || pb > 4 {
        return Err(error_invalid_input("invalid lc or lp or pb"));
    }
    let mut dict_size = get_dict_size(dict_size)?;

    let preset_size = preset_dict
        .map(|dict| dict.len().min(dict_size as usize) as u64)
        .unwrap_or(0);
    let min_history_size = uncomp_size.saturating_add(preset_size);

    if uncomp_size <= u64::MAX / 2 && dict_size as u64 > min_history_size {
        dict_size = get_dict_size(min_history_size as u32)?;
    }

    let lz = LzDecoder::new(get_dict_size(dict_size)? as _, preset_dict);
    let lzma = LzmaDecoder::new(lc, lp, pb);
    Ok((lz, lzma))
}
