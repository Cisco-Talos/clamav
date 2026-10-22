use alloc::{boxed::Box, vec::Vec};
use core::num::NonZeroU64;

use super::{
    CheckType, ChecksumCalculator, FilterConfig, FilterType, IndexRecord, add_padding,
    write_xz_block_header, write_xz_index, write_xz_stream_footer, write_xz_stream_header,
};
use crate::{
    AutoFinish, AutoFinisher, CountingWriter, Lzma2Options, Result, Write,
    enc::{Lzma2Writer, LzmaOptions},
    error_invalid_data, error_invalid_input,
    filter::{bcj::BcjWriter, delta::DeltaWriter},
};

#[allow(clippy::large_enum_variant)]
enum FilterWriter<W: Write> {
    Counting(CountingWriter<W>),
    Lzma2(Lzma2Writer<Box<FilterWriter<W>>>),
    Delta(DeltaWriter<Box<FilterWriter<W>>>),
    Bcj(BcjWriter<Box<FilterWriter<W>>>),
    Dummy,
}

impl<W: Write> Write for FilterWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            FilterWriter::Counting(writer) => writer.write(buf),
            FilterWriter::Lzma2(writer) => writer.write(buf),
            FilterWriter::Delta(writer) => writer.write(buf),
            FilterWriter::Bcj(writer) => writer.write(buf),
            FilterWriter::Dummy => unimplemented!(),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            FilterWriter::Counting(writer) => writer.flush(),
            FilterWriter::Lzma2(writer) => writer.flush(),
            FilterWriter::Delta(writer) => writer.flush(),
            FilterWriter::Bcj(writer) => writer.flush(),
            FilterWriter::Dummy => unimplemented!(),
        }
    }
}

impl<W: Write> FilterWriter<W> {
    fn create_filter_chain(
        inner: CountingWriter<W>,
        filters: &[FilterConfig],
        lzma_options: &LzmaOptions,
    ) -> Result<Self> {
        let mut chain_writer = FilterWriter::Counting(inner);

        for filter_config in filters.iter().rev() {
            chain_writer = match filter_config.filter_type {
                FilterType::Delta => {
                    let distance = filter_config.property as usize;
                    FilterWriter::Delta(DeltaWriter::new(Box::new(chain_writer), distance))
                }
                FilterType::BcjX86 => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_x86(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjPpc => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_ppc(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjIa64 => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_ia64(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjArm => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_arm(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjArmThumb => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_arm_thumb(
                        Box::new(chain_writer),
                        start_offset,
                    ))
                }
                FilterType::BcjSparc => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_sparc(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjArm64 => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_arm64(Box::new(chain_writer), start_offset))
                }
                FilterType::BcjRiscv => {
                    let start_offset = filter_config.property as usize;
                    FilterWriter::Bcj(BcjWriter::new_riscv(Box::new(chain_writer), start_offset))
                }
                FilterType::Lzma2 => {
                    let options = Lzma2Options {
                        lzma_options: lzma_options.clone(),
                        ..Default::default()
                    };
                    FilterWriter::Lzma2(Lzma2Writer::new(Box::new(chain_writer), options))
                }
            };
        }

        Ok(chain_writer)
    }

    fn into_inner(self) -> W {
        match self {
            FilterWriter::Counting(writer) => writer.inner,
            FilterWriter::Lzma2(writer) => {
                let filter_writer = writer.into_inner();
                filter_writer.into_inner()
            }
            FilterWriter::Delta(writer) => {
                let filter_writer = writer.into_inner();
                filter_writer.into_inner()
            }
            FilterWriter::Bcj(writer) => {
                let filter_writer = writer.into_inner();
                filter_writer.into_inner()
            }
            FilterWriter::Dummy => unimplemented!(),
        }
    }

    fn inner(&self) -> &W {
        match self {
            FilterWriter::Counting(writer) => &writer.inner,
            FilterWriter::Lzma2(writer) => {
                let filter_writer = writer.inner();
                filter_writer.inner()
            }
            FilterWriter::Delta(writer) => {
                let filter_writer = writer.inner();
                filter_writer.inner()
            }
            FilterWriter::Bcj(writer) => {
                let filter_writer = writer.inner();
                filter_writer.inner()
            }
            FilterWriter::Dummy => unimplemented!(),
        }
    }

    fn inner_mut(&mut self) -> &mut W {
        match self {
            FilterWriter::Counting(writer) => &mut writer.inner,
            FilterWriter::Lzma2(writer) => {
                let filter_writer = writer.inner_mut();
                filter_writer.inner_mut()
            }
            FilterWriter::Delta(writer) => {
                let filter_writer = writer.inner_mut();
                filter_writer.inner_mut()
            }
            FilterWriter::Bcj(writer) => {
                let filter_writer = writer.inner_mut();
                filter_writer.inner_mut()
            }
            FilterWriter::Dummy => unimplemented!(),
        }
    }

    fn finish(self) -> Result<CountingWriter<W>> {
        match self {
            FilterWriter::Counting(writer) => Ok(writer),
            FilterWriter::Lzma2(writer) => {
                let inner_writer = writer.finish()?;
                inner_writer.finish()
            }
            FilterWriter::Delta(writer) => {
                let inner_writer = writer.into_inner();
                inner_writer.finish()
            }
            FilterWriter::Bcj(writer) => {
                let inner_writer = writer.finish()?;
                inner_writer.finish()
            }
            FilterWriter::Dummy => unimplemented!(),
        }
    }
}

/// Configuration options for XZ compression.
#[derive(Default, Debug, Clone)]
pub struct XzOptions {
    /// LZMA compression options.
    pub lzma_options: LzmaOptions,
    /// Checksum type to use.
    pub check_type: CheckType,
    /// Maximum uncompressed size for each block (None = single block).
    /// Will get clamped to be at least the dict size to not waste memory.
    pub block_size: Option<NonZeroU64>,
    /// Pre-filter to use (at most 3).
    pub filters: Vec<FilterConfig>,
}

impl XzOptions {
    /// Create options with specific preset and checksum type.
    pub fn with_preset(preset: u32) -> Self {
        Self {
            lzma_options: LzmaOptions::with_preset(preset),
            check_type: CheckType::Crc64,
            block_size: None,
            filters: Vec::new(),
        }
    }

    /// Set the checksum type to use (Default is CRC64).
    pub fn set_check_sum_type(&mut self, check_type: CheckType) {
        self.check_type = check_type;
    }

    /// Set the maximum block size (None means a single block, which is the default).
    pub fn set_block_size(&mut self, block_size: Option<NonZeroU64>) {
        self.block_size = block_size;
    }

    /// Prepend a filter to the chain. You can prepend at most 3 additional filter.
    pub fn prepend_pre_filter(&mut self, filter_type: FilterType, property: u32) {
        self.filters.insert(
            0,
            FilterConfig {
                filter_type,
                property,
            },
        );
    }
}

/// A single-threaded XZ compressor.
pub struct XzWriter<W: Write> {
    writer: FilterWriter<W>,
    options: XzOptions,
    index_records: Vec<IndexRecord>,
    block_uncompressed_size: u64,
    checksum_calculator: ChecksumCalculator,
    header_written: bool,
    finished: bool,
    total_uncompressed_pos: u64,
    current_block_start_pos: u64,
    current_block_header_size: u64,
    current_block_open: bool,
}

impl<W: Write> XzWriter<W> {
    /// Create a new XZ writer with the given options.
    pub fn new(inner: W, options: XzOptions) -> Result<Self> {
        let mut options = options;

        if options.filters.len() > 3 {
            return Err(error_invalid_input(
                "XZ allows only at most 3 pre-filters plus LZMA2",
            ));
        }

        if let Some(block_size) = options.block_size.as_mut() {
            *block_size =
                NonZeroU64::new(block_size.get().max(options.lzma_options.dict_size as u64))
                    .expect("block size is zero");
        }

        // Last filter is always LZMA2.
        options.filters.push(FilterConfig {
            filter_type: FilterType::Lzma2,
            property: 0,
        });

        let checksum_calculator = ChecksumCalculator::new(options.check_type);
        let writer = FilterWriter::Counting(CountingWriter::new(inner));

        Ok(Self {
            writer,
            options,
            index_records: Vec::new(),
            block_uncompressed_size: 0,
            checksum_calculator,
            header_written: false,
            finished: false,
            total_uncompressed_pos: 0,
            current_block_start_pos: 0,
            current_block_header_size: 0,
            current_block_open: false,
        })
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Consume the XzWriter and return the inner writer.
    pub fn into_inner(self) -> W {
        self.writer.into_inner()
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        self.writer.inner()
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        self.writer.inner_mut()
    }

    fn write_stream_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        write_xz_stream_header(&mut self.writer, self.options.check_type)?;

        self.header_written = true;

        Ok(())
    }

    fn prepare_next_block(&mut self) -> Result<()> {
        let writer = core::mem::replace(&mut self.writer, FilterWriter::Dummy);
        let counting_writer = writer.finish()?;
        self.writer = FilterWriter::Counting(counting_writer);

        self.current_block_header_size = write_xz_block_header(
            &mut self.writer,
            &self.options.filters,
            self.options.lzma_options.dict_size,
        )?;

        let writer = core::mem::replace(&mut self.writer, FilterWriter::Dummy);
        let counting_writer = writer.finish()?;
        let bytes_written = counting_writer.bytes_written();
        self.current_block_start_pos = bytes_written;

        self.writer = FilterWriter::create_filter_chain(
            counting_writer,
            &self.options.filters,
            &self.options.lzma_options,
        )?;

        self.block_uncompressed_size = 0;
        self.current_block_open = true;

        Ok(())
    }

    fn should_finish_block(&self) -> bool {
        if let Some(block_size) = self.options.block_size {
            self.block_uncompressed_size >= block_size.get()
        } else {
            false
        }
    }

    fn finish_current_block(&mut self) -> Result<()> {
        if !self.current_block_open {
            return Ok(());
        }

        // Finish the filter chain and get back to the counting writer.
        let writer = core::mem::replace(&mut self.writer, FilterWriter::Dummy);
        let counting_writer = writer.finish()?;
        let bytes_written = counting_writer.bytes_written();
        self.writer = FilterWriter::Counting(counting_writer);

        let block_compressed_size = bytes_written - self.current_block_start_pos;

        let data_size = block_compressed_size;
        let padding_needed = (4 - (data_size % 4)) % 4;

        add_padding(&mut self.writer, padding_needed as usize)?;

        self.write_block_checksum()?;

        let unpadded_size = self.current_block_header_size
            + block_compressed_size
            + self.options.check_type.checksum_size();

        self.index_records.push(IndexRecord {
            unpadded_size,
            uncompressed_size: self.block_uncompressed_size,
        });

        self.block_uncompressed_size = 0;
        self.current_block_start_pos = 0;
        self.current_block_header_size = 0;
        self.current_block_open = false;

        Ok(())
    }

    fn get_block_header_size(&self, _compressed_size: u64, _uncompressed_size: u64) -> u64 {
        // Block header: size_byte(1) + flags(1) + filter_id(1) + props_size(1)
        // + dict_prop(1) + padding + crc32(4)
        let base_size: u64 = 9;
        base_size.div_ceil(4) * 4
    }

    fn write_block_checksum(&mut self) -> Result<()> {
        let checksum = self.take_checksum();
        self.writer.write_all(&checksum)?;

        // Reset checksum calculator for next block.
        self.checksum_calculator = ChecksumCalculator::new(self.options.check_type);

        Ok(())
    }

    fn take_checksum(&mut self) -> Vec<u8> {
        let calculator = core::mem::replace(
            &mut self.checksum_calculator,
            ChecksumCalculator::new(self.options.check_type),
        );
        calculator.finalize_to_bytes()
    }

    /// Finish writing the XZ stream and return the inner writer.
    pub fn finish(mut self) -> Result<W> {
        if self.finished {
            return Ok(self.into_inner());
        }

        self.write_stream_header()?;
        self.finish_current_block()?;

        write_xz_index(&mut self.writer, &self.index_records)?;

        write_xz_stream_footer(
            &mut self.writer,
            &self.index_records,
            self.options.check_type,
        )?;

        Ok(self.into_inner())
    }
}

impl<W: Write> Write for XzWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.finished {
            return Err(error_invalid_data("XzWriter already finished"));
        }

        self.write_stream_header()?;

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Check if we need to start a new block.
            if self.should_finish_block() {
                self.finish_current_block()?;
            }

            // Check if we need to prepare the next block (either first block or after finishing one).
            if self.block_uncompressed_size == 0 {
                self.prepare_next_block()?;
            }

            let max_write_size = match self.options.block_size {
                Some(block_size) => {
                    let remaining_capacity = block_size
                        .get()
                        .saturating_sub(self.block_uncompressed_size);
                    remaining.len().min(remaining_capacity as usize)
                }
                None => remaining.len(),
            };

            if max_write_size == 0 {
                // Block is full, finish it and continue.
                continue;
            }

            let chunk_to_write = &remaining[..max_write_size];
            let written = self.writer.write(chunk_to_write)?;

            self.checksum_calculator.update(&remaining[..written]);

            remaining = &remaining[written..];
            total_written += written;
            self.block_uncompressed_size += written as u64;
            self.total_uncompressed_pos += written as u64;
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> AutoFinish for XzWriter<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}
