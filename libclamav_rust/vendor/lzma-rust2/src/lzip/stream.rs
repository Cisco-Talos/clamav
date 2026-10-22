use alloc::vec::Vec;

use super::{HEADER_SIZE, LZIP_MAGIC, LZIP_VERSION, TRAILER_SIZE, decode_dict_size};
use crate::{
    Action, LzmaStream, Result, Status, StreamResult, crc::Crc32, error_invalid_data,
    error_out_of_memory, lzma_reader::get_memory_usage,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum LzipState {
    /// Collecting the six byte member header.
    Header,
    /// Decoding the member payload.
    LzmaData,
    /// Collecting the twenty byte member trailer.
    Trailer,
    Finished,
}

/// The bytes to read next: the pushback queue while it still has any, then the
/// caller's input. The flag says which one it is, because only bytes taken from
/// the caller may be counted.
fn source<'a>(pending: &'a [u8], input: &'a [u8]) -> (&'a [u8], bool) {
    if pending.is_empty() {
        (input, true)
    } else {
        (pending, false)
    }
}

/// Validates a member header and returns its dictionary size.
fn parse_header(header: &[u8]) -> Result<u32> {
    if header[..4] != LZIP_MAGIC {
        return Err(error_invalid_data("invalid LZIP magic bytes"));
    }
    if header[4] != LZIP_VERSION {
        return Err(error_invalid_data("unsupported LZIP version"));
    }
    decode_dict_size(header[5])
}

/// A sans-I/O LZIP stream decoder.
///
/// Unlike [`LzipReader`] this pulls no bytes on its own: call [`process()`] with
/// an input slice and an output slice until it returns [`Status::StreamEnd`].
///
/// Every call consumes the whole `input` slice unless the output buffer filled
/// first or the stream ended, so the caller never has to re-present bytes.
///
/// Members are decoded one after another, so a concatenation of LZIP files
/// decodes as if it were one file.
///
/// [`LzipReader`]: crate::LzipReader
/// [`process()`]: LzipStream::process
///
/// # Examples
/// ```
/// use lzma_rust2::{Action, LzipStream, Status};
///
/// let compressed: Vec<u8> = vec![
///     76, 90, 73, 80, 1, 23, 0, 36, 25, 73, 152, 111, 22, 2, 140, 232, 230, 91, 177, 71, 198,
///     206, 183, 99, 255, 255, 60, 172, 0, 0, 230, 198, 230, 235, 13, 0, 0, 0, 0, 0, 0, 0, 50, 0,
///     0, 0, 0, 0, 0, 0,
/// ];
///
/// let mut stream = LzipStream::new();
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
pub struct LzipStream {
    state: LzipState,
    /// The current member's payload decoder.
    lzma: Option<LzmaStream>,
    /// Header or trailer bytes, whichever the state is collecting.
    accum: Vec<u8>,
    accum_needed: usize,
    /// Bytes a finished member handed back because they belong to what follows
    /// it. They are read before the caller's input.
    pending: Vec<u8>,
    pending_pos: usize,
    crc: Crc32,
    /// Bytes the current member has decoded.
    data_size: u64,
    /// Payload bytes the current member has used.
    member_compressed: u64,
    members: usize,
    mem_limit_kb: u32,
    /// Bytes that belong to no member. Filled in once the stream ends.
    leftover: Vec<u8>,
    total_in: u64,
    total_out: u64,
}

impl Default for LzipStream {
    fn default() -> Self {
        Self::new()
    }
}

impl LzipStream {
    /// Creates a decompressor for the LZIP file format with no memory limit.
    pub fn new() -> Self {
        Self::new_mem_limit(u32::MAX)
    }

    /// Creates a decompressor for the LZIP file format with a memory usage
    /// limit.
    /// - `mem_limit_kb` - memory usage limit in kibibytes (KiB). `u32::MAX` means no limit.
    ///
    /// Each member header is checked against the limit as it is parsed, so
    /// violations surface from [`process()`] rather than from here.
    ///
    /// [`process()`]: LzipStream::process
    pub fn new_mem_limit(mem_limit_kb: u32) -> Self {
        Self {
            state: LzipState::Header,
            lzma: None,
            accum: Vec::with_capacity(TRAILER_SIZE),
            accum_needed: HEADER_SIZE,
            pending: Vec::new(),
            pending_pos: 0,
            crc: Crc32::new(),
            data_size: 0,
            member_compressed: 0,
            members: 0,
            mem_limit_kb,
            leftover: Vec::new(),
            total_in: 0,
            total_out: 0,
        }
    }

    /// Total bytes consumed from input across all `process()` calls.
    ///
    /// This includes the [`unused_input()`] bytes.
    ///
    /// [`unused_input()`]: LzipStream::unused_input
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Total bytes produced to output across all `process()` calls.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Returns true if the LZIP stream has been fully decoded.
    pub fn is_finished(&self) -> bool {
        self.state == LzipState::Finished
    }

    /// Returns true if there is decoded output waiting to be flushed.
    pub fn has_output(&self) -> bool {
        self.lzma.as_ref().is_some_and(|lzma| lzma.has_output())
    }

    /// Number of members that have been decoded and verified so far.
    pub fn member_count(&self) -> usize {
        self.members
    }

    /// Bytes that were absorbed from the caller but turned out not to belong to
    /// any member.
    ///
    /// Only meaningful once [`Status::StreamEnd`] has been returned; before that
    /// it is always empty.
    ///
    /// Since `process()` always takes the whole input, everything behind the
    /// last member comes back as `unused_input()` plus whatever is left past
    /// `bytes_consumed` in the last slice that was passed in.
    pub fn unused_input(&self) -> &[u8] {
        if self.state == LzipState::Finished {
            &self.leftover
        } else {
            &[]
        }
    }

    /// Process available LZIP data from `input` into `output`.
    pub fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> Result<StreamResult> {
        let mut in_pos = 0;
        let mut out_pos = 0;

        loop {
            match self.state {
                LzipState::Finished => {
                    return Ok(StreamResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Status::StreamEnd,
                    });
                }

                LzipState::Header => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }

                    let dict_size = match parse_header(&self.accum) {
                        Ok(dict_size) => dict_size,
                        Err(error) => {
                            // Only the first member has to be there. Behind a
                            // decoded one this is trailing data, which the
                            // caller gets back instead of an error.
                            if self.members == 0 {
                                return Err(error);
                            }
                            self.finish();
                            return Ok(StreamResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Status::StreamEnd,
                            });
                        }
                    };

                    self.start_member(dict_size)?;
                }

                LzipState::LzmaData => {
                    if let Some(result) =
                        self.decode_payload(input, output, action, &mut in_pos, &mut out_pos)?
                    {
                        return Ok(result);
                    }
                }

                LzipState::Trailer => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }
                    self.verify_trailer()?;
                }
            }
        }
    }

    /// Fills `accum` up to `accum_needed` bytes, returning a result to hand back
    /// to the caller when the input ran dry first.
    fn accumulate(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
    ) -> Result<Option<StreamResult>> {
        while self.accum.len() < self.accum_needed {
            let (buf, from_caller) = source(&self.pending[self.pending_pos..], &input[*in_pos..]);

            if buf.is_empty() {
                if action != Action::Finish {
                    return Ok(Some(StreamResult {
                        bytes_consumed: *in_pos,
                        bytes_produced: out_pos,
                        status: Status::Ok,
                    }));
                }

                // A header that never arrives is just the end of the file, as
                // long as a member has already been decoded. Anything else is a
                // truncated stream.
                if self.state != LzipState::Header || self.members == 0 {
                    return Err(error_invalid_data("unexpected end of LZIP stream"));
                }

                self.finish();
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: out_pos,
                    status: Status::StreamEnd,
                }));
            }

            let to_copy = (self.accum_needed - self.accum.len()).min(buf.len());
            self.accum.extend_from_slice(&buf[..to_copy]);

            if from_caller {
                *in_pos += to_copy;
                self.total_in += to_copy as u64;
            } else {
                self.pending_pos += to_copy;
            }
        }

        Ok(None)
    }

    /// Sets up the payload decoder for a member.
    fn start_member(&mut self, dict_size: u32) -> Result<()> {
        // Check the memory limit before allocating anything.
        let need_mem = get_memory_usage(dict_size, 3, 0)?;
        if self.mem_limit_kb < need_mem {
            return Err(error_out_of_memory(
                "needed memory too big for mem_limit_kb",
            ));
        }

        // LZIP fixes lc=3, lp=0 and pb=2, and the payload carries no size, so
        // only its end marker says where it stops.
        self.lzma = Some(LzmaStream::new(u64::MAX, 3, 0, 2, dict_size, None)?);

        self.crc = Crc32::new();
        self.data_size = 0;
        self.member_compressed = 0;
        self.accum.clear();
        self.accum_needed = 0;
        self.state = LzipState::LzmaData;
        Ok(())
    }

    /// Runs the payload decoder once, returning a result to hand back to the
    /// caller when it needs more input or more output space.
    fn decode_payload(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: &mut usize,
    ) -> Result<Option<StreamResult>> {
        let (buf, from_caller) = source(&self.pending[self.pending_pos..], &input[*in_pos..]);

        // The caller's input is still queued behind the pushback, so saying that
        // the stream ends here would make the payload decoder report a
        // truncation that is not there.
        let action = if from_caller { action } else { Action::Run };

        let lzma = self
            .lzma
            .as_mut()
            .ok_or_else(|| error_invalid_data("payload decoder not set"))?;
        let result = lzma.process(buf, &mut output[*out_pos..], action)?;

        if from_caller {
            *in_pos += result.bytes_consumed;
            self.total_in += result.bytes_consumed as u64;
        } else {
            self.pending_pos += result.bytes_consumed;
        }

        if result.bytes_produced > 0 {
            self.crc
                .update(&output[*out_pos..*out_pos + result.bytes_produced]);
            self.data_size += result.bytes_produced as u64;
            *out_pos += result.bytes_produced;
            self.total_out += result.bytes_produced as u64;
        }

        if result.status == Status::StreamEnd {
            self.finish_payload();
            return Ok(None);
        }

        // The last condition is what keeps a payload decoder that can make no
        // progress at all from being called forever.
        if (from_caller && *in_pos >= input.len())
            || *out_pos >= output.len()
            || (result.bytes_consumed == 0 && result.bytes_produced == 0)
        {
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: *out_pos,
                status: Status::Ok,
            }));
        }

        Ok(None)
    }

    /// Ends the payload and queues the bytes the decoder read past it.
    fn finish_payload(&mut self) {
        let lzma = self.lzma.take().expect("payload decoder not set");
        let unused = lzma.unused_input();

        // A byte counts as consumed the moment it is taken in, decoded or not,
        // so the ones handed back have to come off the member's size again.
        self.member_compressed = lzma.total_in() - unused.len() as u64;

        // They go in front of what is still queued: the payload decoder saw
        // them first.
        self.pending.drain(..self.pending_pos);
        self.pending_pos = 0;
        self.pending.splice(..0, unused.iter().copied());

        self.accum.clear();
        self.accum_needed = TRAILER_SIZE;
        self.state = LzipState::Trailer;
    }

    /// Checks the member against its trailer and moves on to the next one.
    fn verify_trailer(&mut self) -> Result<()> {
        let crc32 =
            u32::from_le_bytes([self.accum[0], self.accum[1], self.accum[2], self.accum[3]]);
        let data_size = u64::from_le_bytes([
            self.accum[4],
            self.accum[5],
            self.accum[6],
            self.accum[7],
            self.accum[8],
            self.accum[9],
            self.accum[10],
            self.accum[11],
        ]);
        let member_size = u64::from_le_bytes([
            self.accum[12],
            self.accum[13],
            self.accum[14],
            self.accum[15],
            self.accum[16],
            self.accum[17],
            self.accum[18],
            self.accum[19],
        ]);

        if self.crc.finalize() != crc32 {
            return Err(error_invalid_data("LZIP CRC32 mismatch"));
        }

        if self.data_size != data_size {
            return Err(error_invalid_data("LZIP data size mismatch"));
        }

        let actual_member_size = HEADER_SIZE as u64 + self.member_compressed + TRAILER_SIZE as u64;
        if actual_member_size != member_size {
            return Err(error_invalid_data("LZIP member size mismatch"));
        }

        self.members += 1;
        self.accum.clear();
        self.accum_needed = HEADER_SIZE;
        self.state = LzipState::Header;
        Ok(())
    }

    /// Ends the stream, keeping what is left for [`unused_input()`].
    ///
    /// [`unused_input()`]: LzipStream::unused_input
    fn finish(&mut self) {
        self.leftover.clear();
        self.leftover.extend_from_slice(&self.accum);
        self.leftover
            .extend_from_slice(&self.pending[self.pending_pos..]);

        self.accum.clear();
        self.pending.clear();
        self.pending_pos = 0;
        self.state = LzipState::Finished;
    }
}
