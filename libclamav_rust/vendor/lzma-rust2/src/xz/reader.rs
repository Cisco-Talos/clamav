use alloc::{boxed::Box, vec::Vec};

use super::{
    BlockHeader, CheckType, ChecksumCalculator, FilterType, Index, IndexRecord, StreamFooter,
    StreamHeader, XZ_FOOTER_MAGIC, XZ_MAGIC, count_multibyte_integer_size, parse_multibyte_integer,
};
use crate::{
    CountingReader, Lzma2Reader, Read, Result, lzma2_get_memory_usage,
    crc::Crc32,
    error_invalid_data, error_out_of_memory,
    filter::{
        bcj::{BcjFilter, BcjReader},
        delta::{Delta, DeltaReader},
    },
    lzma2_reader::Lzma2Stream,
    stream::{Action, Status, StreamResult},
};

#[allow(clippy::large_enum_variant)]
enum FilterReader<R: Read> {
    Counting(CountingReader<R>),
    Lzma2(Lzma2Reader<Box<FilterReader<R>>>),
    Delta(DeltaReader<Box<FilterReader<R>>>),
    Bcj(BcjReader<Box<FilterReader<R>>>),
    Dummy,
}

impl<R: Read> Read for FilterReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            FilterReader::Counting(reader) => reader.read(buf),
            FilterReader::Lzma2(reader) => reader.read(buf),
            FilterReader::Delta(reader) => reader.read(buf),
            FilterReader::Bcj(reader) => reader.read(buf),
            FilterReader::Dummy => unimplemented!(),
        }
    }
}

impl<R: Read> FilterReader<R> {
    fn create_filter_chain(inner: R, filters: &[Option<FilterType>], properties: &[u32]) -> Self {
        let mut chain_reader = FilterReader::Counting(CountingReader::new(inner));

        for (filter, property) in filters
            .iter()
            .copied()
            .zip(properties)
            .filter_map(|(filter, property)| filter.map(|filter| (filter, *property)))
            .rev()
        {
            chain_reader = match filter {
                FilterType::Delta => {
                    let distance = property as usize;
                    FilterReader::Delta(DeltaReader::new(Box::new(chain_reader), distance))
                }
                FilterType::BcjX86 => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_x86(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjPpc => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_ppc(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjIa64 => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_ia64(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjArm => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_arm(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjArmThumb => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_arm_thumb(
                        Box::new(chain_reader),
                        start_offset,
                    ))
                }
                FilterType::BcjSparc => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_sparc(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjArm64 => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_arm64(Box::new(chain_reader), start_offset))
                }
                FilterType::BcjRiscv => {
                    let start_offset = property as usize;
                    FilterReader::Bcj(BcjReader::new_riscv(Box::new(chain_reader), start_offset))
                }
                FilterType::Lzma2 => {
                    let dict_size = property;
                    FilterReader::Lzma2(Lzma2Reader::new(Box::new(chain_reader), dict_size, None))
                }
            };
        }

        chain_reader
    }

    fn bytes_read(&self) -> u64 {
        match self {
            FilterReader::Counting(reader) => reader.bytes_read(),
            FilterReader::Lzma2(reader) => reader.inner().bytes_read(),
            FilterReader::Delta(reader) => reader.inner().bytes_read(),
            FilterReader::Bcj(reader) => reader.inner().bytes_read(),
            FilterReader::Dummy => unimplemented!(),
        }
    }

    fn into_inner(self) -> R {
        match self {
            FilterReader::Counting(reader) => reader.inner,
            FilterReader::Lzma2(reader) => {
                let filter_reader = reader.into_inner();
                filter_reader.into_inner()
            }
            FilterReader::Delta(reader) => {
                let filter_reader = reader.into_inner();
                filter_reader.into_inner()
            }
            FilterReader::Bcj(reader) => {
                let filter_reader = reader.into_inner();
                filter_reader.into_inner()
            }
            FilterReader::Dummy => unimplemented!(),
        }
    }

    fn inner(&self) -> &R {
        match self {
            FilterReader::Counting(reader) => &reader.inner,
            FilterReader::Lzma2(reader) => {
                let filter_reader = reader.inner();

                filter_reader.inner()
            }
            FilterReader::Delta(reader) => {
                let filter_reader = reader.inner();
                filter_reader.inner()
            }
            FilterReader::Bcj(reader) => {
                let filter_reader = reader.inner();
                filter_reader.inner()
            }
            FilterReader::Dummy => unimplemented!(),
        }
    }

    fn inner_mut(&mut self) -> &mut R {
        match self {
            FilterReader::Counting(reader) => &mut reader.inner,
            FilterReader::Lzma2(reader) => {
                let filter_reader = reader.inner_mut();
                filter_reader.inner_mut()
            }
            FilterReader::Delta(reader) => {
                let filter_reader = reader.inner_mut();
                filter_reader.inner_mut()
            }
            FilterReader::Bcj(reader) => {
                let filter_reader = reader.inner_mut();
                filter_reader.inner_mut()
            }
            FilterReader::Dummy => unimplemented!(),
        }
    }
}

/// A single-threaded XZ decompressor.
pub struct XzReader<R: Read> {
    reader: FilterReader<R>,
    stream_header: Option<StreamHeader>,
    checksum_calculator: Option<ChecksumCalculator>,
    finished: bool,
    allow_multiple_streams: bool,
    blocks_processed: u64,
}

impl<R: Read> XzReader<R> {
    /// Create a new [`XzReader`].
    pub fn new(inner: R, allow_multiple_streams: bool) -> Self {
        let reader = FilterReader::Counting(CountingReader::new(inner));

        Self {
            reader,
            stream_header: None,
            checksum_calculator: None,
            finished: false,
            allow_multiple_streams,
            blocks_processed: 0,
        }
    }

    /// Consume the XzReader and return the inner reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns a reference to the inner reader.
    pub fn inner(&self) -> &R {
        self.reader.inner()
    }

    /// Returns a mutable reference to the inner reader.
    pub fn inner_mut(&mut self) -> &mut R {
        self.reader.inner_mut()
    }
}

impl<R: Read> XzReader<R> {
    fn ensure_stream_header(&mut self) -> Result<()> {
        if self.stream_header.is_none() {
            let header = StreamHeader::parse(&mut self.reader)?;
            self.stream_header = Some(header);
        }
        Ok(())
    }

    fn prepare_next_block(&mut self) -> Result<bool> {
        match BlockHeader::parse(&mut self.reader)? {
            Some(block_header) => {
                let base_reader: FilterReader<R> =
                    core::mem::replace(&mut self.reader, FilterReader::Dummy);

                self.reader = FilterReader::create_filter_chain(
                    base_reader.into_inner(),
                    &block_header.filters,
                    &block_header.properties,
                );

                match self.stream_header.as_ref() {
                    Some(header) => {
                        self.checksum_calculator = Some(ChecksumCalculator::new(header.check_type));
                    }
                    None => {
                        panic!("stream_header not set");
                    }
                }

                self.blocks_processed += 1;

                Ok(true)
            }
            None => {
                // End of blocks reached, index follows.
                self.parse_index_and_footer()?;

                if self.allow_multiple_streams && self.try_start_next_stream()? {
                    return self.prepare_next_block();
                }

                self.finished = true;
                Ok(false)
            }
        }
    }

    fn consume_padding(&mut self, compressed_bytes: u64) -> Result<()> {
        let padding_needed = match (4 - (compressed_bytes % 4)) % 4 {
            0 => return Ok(()),
            n => n as usize,
        };

        let mut padding_buf = [0u8; 3];

        let bytes_read = self.reader.read(&mut padding_buf[..padding_needed])?;

        if bytes_read != padding_needed {
            return Err(error_invalid_data("incomplete XZ block padding"));
        }

        if !padding_buf[..bytes_read].iter().all(|&byte| byte == 0) {
            return Err(error_invalid_data("invalid XZ block padding"));
        }

        Ok(())
    }

    fn verify_block_checksum(&mut self) -> Result<()> {
        let checksum_calculator = self
            .checksum_calculator
            .take()
            .expect("checksum_calculator not set");

        match checksum_calculator {
            ChecksumCalculator::None => { /* Nothing to check */ }
            ChecksumCalculator::Crc32(_) => {
                let mut checksum = [0u8; 4];
                self.reader.read_exact(&mut checksum)?;

                if !checksum_calculator.verify(&checksum) {
                    return Err(error_invalid_data("invalid block checksum"));
                }
            }
            ChecksumCalculator::Crc64(_) => {
                let mut checksum = [0u8; 8];
                self.reader.read_exact(&mut checksum)?;

                if !checksum_calculator.verify(&checksum) {
                    return Err(error_invalid_data("invalid block checksum"));
                }
            }
            ChecksumCalculator::Sha256(_) => {
                let mut checksum = [0u8; 32];
                self.reader.read_exact(&mut checksum)?;

                if !checksum_calculator.verify(&checksum) {
                    return Err(error_invalid_data("invalid block checksum"));
                }
            }
        }

        Ok(())
    }

    /// Look for the start of the next stream by reading bytes one at a time
    /// and checking for the XZ magic sequence, allowing for stream padding.
    fn try_start_next_stream(&mut self) -> Result<bool> {
        let mut padding_bytes = 0;
        let mut buffer = [0u8; 6];

        loop {
            let mut byte_buffer = [0u8; 1];
            let read = self.reader.read(&mut byte_buffer)?;
            if read == 0 {
                // EOF reached, no more streams.
                return Ok(false);
            }

            let byte = byte_buffer[0];

            if byte == 0 {
                // Potential stream padding.
                padding_bytes += 1;
                continue;
            }

            // Non-zero byte found - check if it starts XZ magic.
            if byte != XZ_MAGIC[0] {
                return Err(error_invalid_data("invalid data after stream"));
            }

            buffer[0] = byte;
            let mut buffer_pos = 1;

            // Read the rest of the magic bytes.
            while buffer_pos < 6 {
                match self.reader.read(&mut byte_buffer)? {
                    0 => {
                        return Err(error_invalid_data("incomplete XZ magic bytes"));
                    }
                    1 => {
                        buffer[buffer_pos] = byte_buffer[0];
                        buffer_pos += 1;
                    }
                    _ => unreachable!(),
                }
            }

            if buffer != XZ_MAGIC {
                return Err(error_invalid_data("invalid data after stream padding"));
            }

            if padding_bytes % 4 != 0 {
                return Err(error_invalid_data("stream padding size not multiple of 4"));
            }

            let stream_header = StreamHeader::parse_stream_header_flags_and_crc(&mut self.reader)?;

            // Reset state for new stream.
            self.stream_header = Some(stream_header);
            self.blocks_processed = 0;

            return Ok(true);
        }
    }

    fn parse_index_and_footer(&mut self) -> Result<()> {
        let index = Index::parse(&mut self.reader)?;

        if index.number_of_records != self.blocks_processed {
            return Err(error_invalid_data(
                "number of blocks processed doesn't match index records",
            ));
        }

        let stream_footer = StreamFooter::parse(&mut self.reader)?;

        let header = self.stream_header.as_ref().expect("stream_header not set");

        let header_flags = [0, header.check_type as u8];
        if stream_footer.stream_flags != header_flags {
            return Err(error_invalid_data(
                "stream header and footer flags mismatch",
            ));
        }

        Ok(())
    }
}

impl<R: Read> Read for XzReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.finished {
            return Ok(0);
        }

        self.ensure_stream_header()?;

        loop {
            if self.checksum_calculator.is_some() {
                let bytes_read = self.reader.read(buf)?;

                if bytes_read > 0 {
                    if let Some(ref mut calc) = self.checksum_calculator {
                        calc.update(&buf[..bytes_read]);
                    }

                    return Ok(bytes_read);
                } else {
                    let reader = core::mem::replace(&mut self.reader, FilterReader::Dummy);
                    let compressed_bytes = reader.bytes_read();
                    self.reader = FilterReader::Counting(CountingReader::with_count(
                        reader.into_inner(),
                        compressed_bytes,
                    ));

                    self.consume_padding(compressed_bytes)?;
                    self.verify_block_checksum()?;
                }
            } else {
                // No current block, prepare the next one.
                if !self.prepare_next_block()? {
                    // No more blocks, we're done.
                    return Ok(0);
                }
            }
        }
    }
}

enum StreamFilter {
    Delta(Box<Delta>),
    Bcj(BcjFilter),
}

impl StreamFilter {
    fn from_filter_type(ft: FilterType, property: u32) -> Option<Self> {
        match ft {
            FilterType::Delta => Some(StreamFilter::Delta(Box::new(Delta::new(property as usize)))),
            FilterType::BcjX86 => Some(StreamFilter::Bcj(BcjFilter::new_x86(
                property as usize,
                false,
            ))),
            FilterType::BcjArm => Some(StreamFilter::Bcj(BcjFilter::new_arm(
                property as usize,
                false,
            ))),
            FilterType::BcjArm64 => Some(StreamFilter::Bcj(BcjFilter::new_arm64(
                property as usize,
                false,
            ))),
            FilterType::BcjArmThumb => Some(StreamFilter::Bcj(BcjFilter::new_arm_thumb(
                property as usize,
                false,
            ))),
            FilterType::BcjPpc => Some(StreamFilter::Bcj(BcjFilter::new_power_pc(
                property as usize,
                false,
            ))),
            FilterType::BcjSparc => Some(StreamFilter::Bcj(BcjFilter::new_sparc(
                property as usize,
                false,
            ))),
            FilterType::BcjIa64 => Some(StreamFilter::Bcj(BcjFilter::new_ia64(
                property as usize,
                false,
            ))),
            FilterType::BcjRiscv => Some(StreamFilter::Bcj(BcjFilter::new_riscv(
                property as usize,
                false,
            ))),
            FilterType::Lzma2 => None,
        }
    }

    fn apply_decode(&mut self, buf: &mut [u8]) -> usize {
        match self {
            StreamFilter::Delta(d) => {
                d.decode(buf);
                buf.len()
            }
            StreamFilter::Bcj(b) => b.code(buf),
        }
    }
}

#[derive(Clone, Copy)]
enum XzStreamState {
    StreamHeader,
    BlockHeaderSize,
    BlockHeaderBody { header_size: usize },
    Lzma2Data,
    BlockPadding,
    BlockChecksum { remaining: usize },
    IndexCount,
    IndexRecordUnpadded { remaining: u64 },
    IndexRecordUncompressed { remaining: u64 },
    IndexPaddingCrc,
    StreamFooter,
    InterStreamPadding,
    Finished,
}

/// Sans-I/O XZ stream decoder.
///
/// Implements a buffer-pair API: call `process()` repeatedly with input/output
/// buffers until `Status::StreamEnd` is returned.
///
/// # Limitations
///
/// A block may contain at most one non-LZMA2 filter (a single BCJ or Delta
/// filter) preceding the terminating LZMA2 filter. Streams that chain multiple
/// non-LZMA2 filters in a block are rejected with an error. Use the blocking
/// [`XzReader`] to decode those.
pub struct XzStream {
    state: XzStreamState,
    accum: Vec<u8>,
    accum_needed: usize,
    lzma2: Option<Lzma2Stream>,
    checksum: Option<ChecksumCalculator>,
    check_type: Option<CheckType>,
    block_count: usize,
    block_header_size: u64,
    block_compressed_size: u64,
    block_uncompressed_size: u64,
    index_records: Vec<IndexRecord>,
    index_crc: Crc32,
    index_size: usize,
    allow_multiple_streams: bool,
    total_in: u64,
    total_out: u64,
    filter: Option<StreamFilter>,
    filter_buf: Vec<u8>,
    filter_pos: usize,
    filter_unfiltered: usize,
    mem_limit_kb: u32,
}

impl XzStream {
    /// Create a new XZ stream decoder.
    ///
    /// If `allow_multiple_streams` is true, concatenated XZ streams are decoded
    /// sequentially until EOF.
    pub fn new(allow_multiple_streams: bool) -> Self {
        Self::new_mem_limit(allow_multiple_streams, u32::MAX)
    }

    /// Create a new XZ stream decoder with an LZMA2 dictionary memory limit.
    ///
    /// `mem_limit_kb` is measured in kibibytes. The limit is checked from each
    /// block header before its decoder dictionary is allocated.
    pub fn new_mem_limit(allow_multiple_streams: bool, mem_limit_kb: u32) -> Self {
        Self {
            state: XzStreamState::StreamHeader,
            accum: Vec::with_capacity(1024),
            accum_needed: 12,
            lzma2: None,
            checksum: None,
            check_type: None,
            block_count: 0,
            block_header_size: 0,
            block_compressed_size: 0,
            block_uncompressed_size: 0,
            index_records: Vec::new(),
            index_crc: Crc32::new(),
            index_size: 0,
            allow_multiple_streams,
            total_in: 0,
            total_out: 0,
            filter: None,
            filter_buf: Vec::new(),
            filter_pos: 0,
            filter_unfiltered: 0,
            mem_limit_kb,
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

    /// The integrity check type used by the current stream.
    ///
    /// This is read from the stream header during decoding.
    /// Before the header has been parsed, returns [`CheckType::None`].
    pub fn check_type(&self) -> Option<CheckType> {
        self.check_type
    }

    /// Process available data from `input` into `output`.
    ///
    /// Returns how many bytes were consumed/produced and the stream status.
    /// Call repeatedly until `Status::StreamEnd` is returned.
    pub fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> Result<StreamResult> {
        let mut in_pos = 0;
        let mut out_pos = 0;

        loop {
            match &self.state {
                XzStreamState::Finished => {
                    return Ok(StreamResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Status::StreamEnd,
                    });
                }

                XzStreamState::Lzma2Data => {
                    if self.filter.is_some() {
                        if self.process_lzma2_filtered(
                            input,
                            output,
                            action,
                            &mut in_pos,
                            &mut out_pos,
                        )? == 0
                        {
                            return Ok(StreamResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Status::Ok,
                            });
                        }
                    } else if let Some(result) = self.process_lzma2_unfiltered(
                        input,
                        output,
                        action,
                        &mut in_pos,
                        &mut out_pos,
                    )? {
                        return Ok(result);
                    }
                }

                _ => {
                    if self.accum.len() < self.accum_needed {
                        if in_pos >= input.len() {
                            if action == Action::Finish {
                                if matches!(self.state, XzStreamState::InterStreamPadding) {
                                    if !self.accum.is_empty() {
                                        return Err(error_invalid_data(
                                            "inter-stream padding not a multiple of 4 bytes",
                                        ));
                                    }
                                    self.state = XzStreamState::Finished;
                                    continue;
                                }
                                return Err(error_invalid_data("unexpected end of XZ stream"));
                            }
                            return Ok(StreamResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Status::Ok,
                            });
                        }
                        let available = &input[in_pos..];
                        let need = self.accum_needed - self.accum.len();
                        let to_copy = need.min(available.len());
                        self.accum.extend_from_slice(&available[..to_copy]);
                        in_pos += to_copy;
                        self.total_in += to_copy as u64;
                        if self.accum.len() < self.accum_needed {
                            return Ok(StreamResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Status::Ok,
                            });
                        }
                    }

                    self.process_accumulated()?;
                }
            }
        }
    }

    fn process_lzma2_unfiltered(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: &mut usize,
    ) -> Result<Option<StreamResult>> {
        let lzma2 = self
            .lzma2
            .as_mut()
            .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?;

        if lzma2.is_draining() {
            if *out_pos >= output.len() {
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: *out_pos,
                    status: Status::Ok,
                }));
            }
            let prev_out = *out_pos;
            lzma2.drain_with_filter(output, out_pos);
            let drained = *out_pos - prev_out;
            if drained > 0 {
                self.total_out += drained as u64;
                if let Some(cs) = self.checksum.as_mut() {
                    cs.update(&output[prev_out..*out_pos]);
                }
            }
            if lzma2.has_output() {
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: *out_pos,
                    status: Status::Ok,
                }));
            }
            if lzma2.is_finished() {
                self.finish_lzma2_block()?;
            }
            return Ok(None);
        }

        let result = lzma2.process(&input[*in_pos..], &mut output[*out_pos..], action)?;
        *in_pos += result.bytes_consumed;
        self.total_in += result.bytes_consumed as u64;

        if result.bytes_produced > 0 {
            if let Some(cs) = self.checksum.as_mut() {
                cs.update(&output[*out_pos..*out_pos + result.bytes_produced]);
            }
            *out_pos += result.bytes_produced;
            self.total_out += result.bytes_produced as u64;
        }

        if result.status == Status::StreamEnd {
            self.finish_lzma2_block()?;
        } else if *in_pos >= input.len() || *out_pos >= output.len() {
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: *out_pos,
                status: Status::Ok,
            }));
        }
        Ok(None)
    }

    fn process_lzma2_filtered(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: &mut usize,
    ) -> Result<usize> {
        if *out_pos >= output.len() {
            return Ok(0);
        }

        let ready_end = self
            .filter_buf
            .len()
            .checked_sub(self.filter_unfiltered)
            .ok_or_else(|| error_invalid_data("invalid XZ filter buffer state"))?;
        if self.filter_pos < ready_end {
            return self.emit_filtered_output(output, out_pos);
        }

        if self
            .lzma2
            .as_ref()
            .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?
            .is_draining()
        {
            self.drain_and_filter_lzma2()?;
            let lzma2 = self
                .lzma2
                .as_ref()
                .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?;
            if !lzma2.has_output() && lzma2.is_finished() {
                self.flush_filter_pending();
            }
            return Ok(1);
        }

        let result = self
            .lzma2
            .as_mut()
            .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?
            .process(&input[*in_pos..], &mut [], action)?;
        *in_pos += result.bytes_consumed;
        self.total_in += result.bytes_consumed as u64;

        if result.status == Status::StreamEnd {
            return self.try_complete_filtered_block();
        }

        if *in_pos >= input.len()
            && !self
                .lzma2
                .as_ref()
                .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?
                .is_draining()
        {
            return Ok(0);
        }
        Ok(1)
    }

    fn emit_filtered_output(&mut self, output: &mut [u8], out_pos: &mut usize) -> Result<usize> {
        let ready_end = self
            .filter_buf
            .len()
            .checked_sub(self.filter_unfiltered)
            .ok_or_else(|| error_invalid_data("invalid XZ filter buffer state"))?;
        let available = ready_end
            .checked_sub(self.filter_pos)
            .ok_or_else(|| error_invalid_data("invalid XZ filter position"))?;
        let space = output
            .len()
            .checked_sub(*out_pos)
            .ok_or_else(|| error_invalid_data("invalid XZ output position"))?;
        let n = available.min(space);
        output[*out_pos..*out_pos + n]
            .copy_from_slice(&self.filter_buf[self.filter_pos..self.filter_pos + n]);
        if let Some(cs) = self.checksum.as_mut() {
            cs.update(&output[*out_pos..*out_pos + n]);
        }
        *out_pos += n;
        self.total_out += n as u64;
        self.filter_pos += n;

        if self.filter_pos < ready_end {
            return Ok(0);
        }

        self.compact_filter_buf()?;

        let is_finished = {
            let lzma2 = self
                .lzma2
                .as_ref()
                .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?;
            !lzma2.has_output() && lzma2.is_finished()
        };
        if is_finished {
            return self.try_complete_filtered_block();
        }
        Ok(1)
    }

    fn drain_and_filter_lzma2(&mut self) -> Result<usize> {
        let lzma2 = self
            .lzma2
            .as_mut()
            .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?;
        let prev_len = self.filter_buf.len();
        lzma2.drain_to_buf(&mut self.filter_buf, 4096);
        let new_bytes = self
            .filter_buf
            .len()
            .checked_sub(prev_len)
            .ok_or_else(|| error_invalid_data("invalid XZ filter buffer length"))?;
        if new_bytes > 0 {
            let filter_start = prev_len
                .checked_sub(self.filter_unfiltered)
                .ok_or_else(|| error_invalid_data("invalid XZ filter buffer state"))?;
            let filter_slice = &mut self.filter_buf[filter_start..];
            let filtered = self
                .filter
                .as_mut()
                .ok_or_else(|| error_invalid_data("XZ filter not initialized"))?
                .apply_decode(filter_slice);
            self.filter_unfiltered = filter_slice
                .len()
                .checked_sub(filtered)
                .ok_or_else(|| error_invalid_data("invalid XZ filtered byte count"))?;
        }
        Ok(new_bytes)
    }

    fn compact_filter_buf(&mut self) -> Result<()> {
        if self.filter_unfiltered > 0 {
            let tail_start = self
                .filter_buf
                .len()
                .checked_sub(self.filter_unfiltered)
                .ok_or_else(|| error_invalid_data("invalid XZ filter buffer state"))?;
            let pending: Vec<u8> = self.filter_buf[tail_start..].to_vec();
            self.filter_buf.clear();
            self.filter_buf.extend_from_slice(&pending);
        } else {
            self.filter_buf.clear();
        }
        self.filter_pos = 0;
        self.filter_unfiltered = self.filter_buf.len();
        Ok(())
    }

    fn try_complete_filtered_block(&mut self) -> Result<usize> {
        self.flush_filter_pending();
        let ready_end = self
            .filter_buf
            .len()
            .checked_sub(self.filter_unfiltered)
            .ok_or_else(|| error_invalid_data("invalid XZ filter buffer state"))?;
        if self.filter_pos < ready_end {
            return Ok(1);
        }
        self.filter.take();
        self.finish_lzma2_block()?;
        Ok(1)
    }

    fn flush_filter_pending(&mut self) {
        self.filter_unfiltered = 0;
    }

    fn finish_lzma2_block(&mut self) -> Result<()> {
        let lzma2 = self
            .lzma2
            .as_ref()
            .ok_or_else(|| error_invalid_data("LZMA2 decoder not initialized"))?;
        self.block_compressed_size = lzma2.total_in();
        self.block_uncompressed_size = lzma2.total_out();

        let pad_needed = ((4 - (self.block_compressed_size % 4)) % 4) as usize;
        if pad_needed > 0 {
            self.state = XzStreamState::BlockPadding;
            self.accum.clear();
            self.accum_needed = pad_needed;
        } else {
            let check_size = self.check_type.map(|c| c.checksum_size()).unwrap_or(0) as usize;
            if check_size > 0 {
                self.state = XzStreamState::BlockChecksum {
                    remaining: check_size,
                };
                self.accum.clear();
                self.accum_needed = check_size;
            } else {
                self.push_index_record();
                self.state = XzStreamState::BlockHeaderSize;
                self.accum.clear();
                self.accum_needed = 1;
            }
        }
        Ok(())
    }

    fn push_index_record(&mut self) {
        let check_size = self.check_type.map(|c| c.checksum_size()).unwrap_or(0);
        self.checksum.take();
        self.index_records.push(IndexRecord {
            unpadded_size: self.block_header_size + self.block_compressed_size + check_size,
            uncompressed_size: self.block_uncompressed_size,
        });
    }

    fn process_accumulated(&mut self) -> Result<()> {
        match self.state {
            XzStreamState::StreamHeader => self.process_stream_header(),
            XzStreamState::BlockHeaderSize => self.process_block_header_size(),
            XzStreamState::BlockHeaderBody { header_size } => {
                self.process_block_header_body(header_size)
            }
            XzStreamState::BlockPadding => self.process_block_padding(),
            XzStreamState::BlockChecksum { remaining } => self.process_block_checksum(remaining),
            XzStreamState::IndexCount => self.process_index_count(),
            XzStreamState::IndexRecordUnpadded { remaining } => {
                self.process_index_record_unpadded(remaining)
            }
            XzStreamState::IndexRecordUncompressed { remaining } => {
                self.process_index_record_uncompressed(remaining)
            }
            XzStreamState::IndexPaddingCrc => self.process_index_padding_crc(),
            XzStreamState::StreamFooter => self.process_stream_footer(),
            XzStreamState::InterStreamPadding => self.process_inter_stream_padding(),
            _ => Ok(()),
        }
    }

    fn process_stream_header(&mut self) -> Result<()> {
        let data = &self.accum;
        if data[..6] != XZ_MAGIC {
            return Err(error_invalid_data("invalid XZ magic bytes"));
        }
        if data[6] != 0 {
            return Err(error_invalid_data("invalid XZ stream flags"));
        }
        let check_type = CheckType::from_byte(data[7])?;
        let expected_crc = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if expected_crc != Crc32::checksum(&data[6..8]) {
            return Err(error_invalid_data("XZ stream header CRC32 mismatch"));
        }
        self.check_type = Some(check_type);
        self.index_records.clear();
        self.block_count = 0;
        self.state = XzStreamState::BlockHeaderSize;
        self.accum.clear();
        self.accum_needed = 1;
        Ok(())
    }

    fn process_block_header_size(&mut self) -> Result<()> {
        let byte = self.accum[0];
        if byte == 0x00 {
            self.state = XzStreamState::IndexCount;
            self.index_crc = Crc32::new();
            self.index_crc.update(&[0x00]);
            self.index_size = 0;
            self.accum.clear();
            self.accum_needed = 1;
        } else {
            let header_size = (byte as usize + 1) * 4;
            self.state = XzStreamState::BlockHeaderBody { header_size };
            self.accum_needed = header_size;
        }
        Ok(())
    }

    fn process_block_header_body(&mut self, header_size: usize) -> Result<()> {
        let data = &self.accum[..header_size];

        let crc_offset = header_size - 4;
        let expected_crc = u32::from_le_bytes([
            data[crc_offset],
            data[crc_offset + 1],
            data[crc_offset + 2],
            data[crc_offset + 3],
        ]);
        let actual_crc = Crc32::checksum(&data[..crc_offset]);
        if expected_crc != actual_crc {
            return Err(error_invalid_data("block header CRC32 mismatch"));
        }

        let (filters, properties, _) = BlockHeader::parse_from_slice(data)?;

        let mut lzma2_dict_size = 0u32;
        let mut found_lzma2 = false;
        let mut pre_filter: Option<StreamFilter> = None;
        for i in 0..4 {
            if let Some(ft) = filters[i] {
                if ft == FilterType::Lzma2 {
                    lzma2_dict_size = properties[i];
                    found_lzma2 = true;
                } else if let Some(f) = StreamFilter::from_filter_type(ft, properties[i]) {
                    // TODO: Support multiple filters for sans-I/O API.
                    if pre_filter.is_some() {
                        return Err(error_invalid_data(
                            "multiple non-LZMA2 filters not supported yet for stream API",
                        ));
                    }
                    pre_filter = Some(f);
                }
            }
        }
        if !found_lzma2 {
            return Err(error_invalid_data("no LZMA2 filter in block"));
        }

        let memory_kb = lzma2_get_memory_usage(lzma2_dict_size);
        if memory_kb > self.mem_limit_kb {
            return Err(error_out_of_memory(
                "XZ LZMA2 dictionary exceeds memory limit",
            ));
        }

        self.lzma2 = Some(Lzma2Stream::new(lzma2_dict_size));
        if let Some(ct) = self.check_type {
            self.checksum = Some(ChecksumCalculator::new(ct));
        }
        self.filter = pre_filter;
        self.filter_buf.clear();
        self.filter_pos = 0;
        self.filter_unfiltered = 0;
        self.block_count += 1;
        self.block_header_size = header_size as u64;
        self.block_compressed_size = 0;
        self.block_uncompressed_size = 0;

        self.state = XzStreamState::Lzma2Data;
        self.accum.clear();
        Ok(())
    }

    fn process_block_padding(&mut self) -> Result<()> {
        for &b in self.accum.iter() {
            if b != 0 {
                return Err(error_invalid_data("non-zero block padding"));
            }
        }

        let check_size = self.check_type.map(|c| c.checksum_size()).unwrap_or(0) as usize;
        if check_size > 0 {
            self.state = XzStreamState::BlockChecksum {
                remaining: check_size,
            };
            self.accum.clear();
            self.accum_needed = check_size;
        } else {
            self.push_index_record();
            self.state = XzStreamState::BlockHeaderSize;
            self.accum.clear();
            self.accum_needed = 1;
        }
        Ok(())
    }

    fn process_block_checksum(&mut self, remaining: usize) -> Result<()> {
        if self.accum.len() < remaining {
            self.accum_needed = remaining;
            return Ok(());
        }
        if let Some(checksum) = self.checksum.take() {
            if !checksum.verify(&self.accum[..remaining]) {
                return Err(error_invalid_data("block checksum mismatch"));
            }
        }
        self.push_index_record();
        self.state = XzStreamState::BlockHeaderSize;
        self.accum.clear();
        self.accum_needed = 1;
        Ok(())
    }

    fn process_index_count(&mut self) -> Result<()> {
        if !has_complete_vli(&self.accum)? {
            self.accum_needed = self.accum.len() + 1;
            return Ok(());
        }
        let num_records = parse_multibyte_integer(&self.accum)?;
        let vli_size = count_multibyte_integer_size(&self.accum);
        self.index_crc.update(&self.accum[..vli_size]);
        self.index_size += vli_size;

        if num_records != self.block_count as u64 {
            return Err(error_invalid_data(
                "index record count does not match number of blocks",
            ));
        }

        self.accum.clear();
        if num_records > 0 {
            self.state = XzStreamState::IndexRecordUnpadded {
                remaining: num_records,
            };
            self.accum_needed = 1;
        } else {
            self.state = XzStreamState::IndexPaddingCrc;
            let pad_needed = (4 - ((1 + self.index_size) % 4)) % 4;
            self.accum_needed = pad_needed + 4;
        }
        Ok(())
    }

    fn process_index_record_unpadded(&mut self, remaining: u64) -> Result<()> {
        if !has_complete_vli(&self.accum)? {
            self.accum_needed = self.accum.len() + 1;
            return Ok(());
        }
        let unpadded = parse_multibyte_integer(&self.accum)?;
        let vli_size = count_multibyte_integer_size(&self.accum);
        self.index_crc.update(&self.accum[..vli_size]);
        self.index_size += vli_size;

        let idx = self.block_count - remaining as usize;
        if self.index_records[idx].unpadded_size != unpadded {
            return Err(error_invalid_data("index unpadded size mismatch"));
        }

        self.accum.clear();
        self.state = XzStreamState::IndexRecordUncompressed { remaining };
        self.accum_needed = 1;
        Ok(())
    }

    fn process_index_record_uncompressed(&mut self, remaining: u64) -> Result<()> {
        if !has_complete_vli(&self.accum)? {
            self.accum_needed = self.accum.len() + 1;
            return Ok(());
        }
        let uncompressed = parse_multibyte_integer(&self.accum)?;
        let vli_size = count_multibyte_integer_size(&self.accum);
        self.index_crc.update(&self.accum[..vli_size]);
        self.index_size += vli_size;

        let idx = self.block_count - remaining as usize;
        if self.index_records[idx].uncompressed_size != uncompressed {
            return Err(error_invalid_data("index uncompressed size mismatch"));
        }

        self.accum.clear();
        let remaining = remaining - 1;
        if remaining > 0 {
            self.state = XzStreamState::IndexRecordUnpadded { remaining };
            self.accum_needed = 1;
        } else {
            self.state = XzStreamState::IndexPaddingCrc;
            let pad_needed = (4 - ((1 + self.index_size) % 4)) % 4;
            self.accum_needed = pad_needed + 4;
        }
        Ok(())
    }

    fn process_index_padding_crc(&mut self) -> Result<()> {
        let pad_needed = (4 - ((1 + self.index_size) % 4)) % 4;
        let total_needed = pad_needed + 4;
        if self.accum.len() < total_needed {
            self.accum_needed = total_needed;
            return Ok(());
        }

        for &b in &self.accum[..pad_needed] {
            if b != 0 {
                return Err(error_invalid_data("non-zero index padding"));
            }
        }
        self.index_crc.update(&self.accum[..pad_needed]);

        let expected_crc = u32::from_le_bytes([
            self.accum[pad_needed],
            self.accum[pad_needed + 1],
            self.accum[pad_needed + 2],
            self.accum[pad_needed + 3],
        ]);

        let actual_crc = core::mem::replace(&mut self.index_crc, Crc32::new()).finalize();
        if actual_crc != expected_crc {
            return Err(error_invalid_data("index CRC32 mismatch"));
        }

        self.accum.clear();
        self.accum_needed = 12;
        self.state = XzStreamState::StreamFooter;
        Ok(())
    }

    fn process_stream_footer(&mut self) -> Result<()> {
        let data = &self.accum;
        if data.len() < 12 {
            self.accum_needed = 12;
            return Ok(());
        }

        let expected_crc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let actual_crc = Crc32::checksum(&data[4..10]);
        if expected_crc != actual_crc {
            return Err(error_invalid_data("stream footer CRC32 mismatch"));
        }
        if data[10..12] != XZ_FOOTER_MAGIC {
            return Err(error_invalid_data("invalid XZ footer magic"));
        }
        if data[8] != 0 {
            return Err(error_invalid_data(
                "reserved stream footer flags byte is non-zero",
            ));
        }
        let footer_check_type = CheckType::from_byte(data[9])?;
        if Some(footer_check_type) != self.check_type {
            return Err(error_invalid_data("stream footer flags don't match header"));
        }

        if self.allow_multiple_streams {
            self.state = XzStreamState::InterStreamPadding;
            self.accum.clear();
            self.accum_needed = 4;
        } else {
            self.state = XzStreamState::Finished;
        }
        Ok(())
    }

    fn process_inter_stream_padding(&mut self) -> Result<()> {
        if self.accum.len() < 4 {
            self.accum_needed = 4;
            return Ok(());
        }
        if self.accum[..4] == [0, 0, 0, 0] {
            self.accum.clear();
            self.accum_needed = 4;
        } else if self.accum[..6.min(self.accum.len())] == XZ_MAGIC[..self.accum.len().min(6)] {
            if self.accum.len() >= 6 && self.accum[..6] == XZ_MAGIC {
                self.state = XzStreamState::StreamHeader;
                self.accum_needed = 12;
            } else {
                self.accum_needed = 12;
            }
        } else {
            return Err(error_invalid_data("invalid inter-stream padding"));
        }
        Ok(())
    }
}

fn has_complete_vli(data: &[u8]) -> Result<bool> {
    if data.len() > 9 {
        return Err(error_invalid_data("XZ multibyte integer too long"));
    }
    for &byte in data {
        if (byte & 0x80) == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}
