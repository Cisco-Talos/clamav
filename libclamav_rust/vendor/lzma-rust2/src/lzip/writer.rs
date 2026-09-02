use core::num::NonZeroU64;

use super::{
    HEADER_SIZE, LZIP_MAGIC, LZIP_VERSION, MAX_DICT_SIZE, MIN_DICT_SIZE, TRAILER_SIZE,
    encode_dict_size,
};
use crate::{
    AutoFinish, AutoFinisher, ByteWriter, CountingWriter, Result, Write,
    crc::Crc32,
    enc::{LzmaOptions, LzmaWriter},
    error_invalid_data,
};

/// Options for LZIP compression.
#[derive(Default, Debug, Clone)]
pub struct LzipOptions {
    /// LZMA compression options (will be overridden partially to use LZMA-302eos defaults).
    pub lzma_options: LzmaOptions,
    /// The maximal size of a member. If not set, the whole data will be written in one member.
    /// Will get clamped to be at least the dict size to not waste memory.
    pub member_size: Option<NonZeroU64>,
}

impl LzipOptions {
    /// Create options with specific preset.
    pub fn with_preset(preset: u32) -> Self {
        Self {
            lzma_options: LzmaOptions::with_preset(preset),
            member_size: None,
        }
    }

    /// Set the maximum member size (None means a single member, which is the default).
    pub fn set_member_size(&mut self, member_size: Option<NonZeroU64>) {
        self.member_size = member_size;
    }
}

/// A single-threaded LZIP compressor.
pub struct LzipWriter<W: Write> {
    inner: Option<W>,
    lzma_writer: Option<LzmaWriter<CountingWriter<W>>>,
    options: LzipOptions,
    header_written: bool,
    finished: bool,
    crc_digest: Crc32,
    uncompressed_size: u64,
    member_start_pos: u64,
    current_member_uncompressed_size: u64,
}

impl<W: Write> LzipWriter<W> {
    /// Create a new LZIP writer with the given options.
    pub fn new(inner: W, options: LzipOptions) -> Self {
        let mut options = options;

        // Overwrite with LZMA-302eos defaults.
        options.lzma_options.lc = 3;
        options.lzma_options.lp = 0;
        options.lzma_options.pb = 2;
        options.lzma_options.dict_size = options
            .lzma_options
            .dict_size
            .clamp(MIN_DICT_SIZE, MAX_DICT_SIZE);

        if let Some(member_size) = options.member_size.as_mut() {
            *member_size =
                NonZeroU64::new(member_size.get().max(options.lzma_options.dict_size as u64))
                    .expect("member size is zero");
        }

        Self {
            inner: Some(inner),
            lzma_writer: None,
            options,
            header_written: false,
            finished: false,
            crc_digest: Crc32::new(),
            uncompressed_size: 0,
            member_start_pos: 0,
            current_member_uncompressed_size: 0,
        }
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(mut self) -> W {
        if let Some(lzma_writer) = self.lzma_writer.take() {
            return lzma_writer.into_inner().into_inner();
        }

        self.inner.take().expect("inner writer not set")
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        self.lzma_writer
            .as_ref()
            .map(|reader| reader.inner().inner())
            .unwrap_or_else(|| self.inner.as_ref().expect("inner writer not set"))
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        self.lzma_writer
            .as_mut()
            .map(|reader| reader.inner_mut().inner_mut())
            .unwrap_or_else(|| self.inner.as_mut().expect("inner writer not set"))
    }

    /// Check if we should finish the current member and start a new one.
    fn should_finish_member(&self) -> bool {
        if let Some(member_size) = self.options.member_size {
            self.current_member_uncompressed_size >= member_size.get()
        } else {
            false
        }
    }

    /// Start a new LZIP member.
    fn start_new_member(&mut self) -> Result<()> {
        let mut writer = self.inner.take().expect("inner writer not set");

        self.member_start_pos = 0;

        writer.write_all(&LZIP_MAGIC)?;
        writer.write_all(&[LZIP_VERSION])?;

        let dict_size_byte = encode_dict_size(self.options.lzma_options.dict_size)?;
        writer.write_u8(dict_size_byte)?;

        let counting_writer = CountingWriter::new(writer);

        let lzma_writer =
            LzmaWriter::new_no_header(counting_writer, &self.options.lzma_options, true)?;

        self.lzma_writer = Some(lzma_writer);
        self.header_written = true;
        self.current_member_uncompressed_size = 0;
        self.crc_digest = Crc32::new();
        self.uncompressed_size = 0;

        Ok(())
    }

    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        self.start_new_member()
    }

    /// Finish the current member by writing its trailer.
    fn finish_current_member(&mut self) -> Result<()> {
        let lzma_writer = self.lzma_writer.take().expect("lzma writer not set");

        let counting_writer = lzma_writer.finish()?;
        let compressed_size = counting_writer.bytes_written();
        let mut writer = counting_writer.into_inner();

        // Calculate member size: header + compressed data + trailer.
        let member_size = HEADER_SIZE as u64 + compressed_size + TRAILER_SIZE as u64;

        let crc_digest = core::mem::replace(&mut self.crc_digest, Crc32::new());
        let computed_crc = crc_digest.finalize();
        writer.write_u32(computed_crc)?;
        writer.write_u64(self.uncompressed_size)?;
        writer.write_u64(member_size)?;

        self.inner = Some(writer);
        self.header_written = false;

        Ok(())
    }

    /// Finish writing the LZIP stream and return the inner writer.
    pub fn finish(mut self) -> Result<W> {
        if self.finished {
            return Ok(self.into_inner());
        }

        if !self.header_written {
            self.write_header()?;
        }

        self.finish_current_member()?;
        self.finished = true;

        Ok(self.into_inner())
    }
}

impl<W: Write> Write for LzipWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.finished {
            return Err(error_invalid_data("LZIP writer already finished"));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            if self.should_finish_member() && self.header_written {
                self.finish_current_member()?;
            }

            if !self.header_written {
                self.start_new_member()?;
            }

            let lzma_writer = self.lzma_writer.as_mut().expect("lzma writer not set");

            let bytes_to_write = if let Some(member_size) = self.options.member_size {
                let remaining_in_member = member_size
                    .get()
                    .saturating_sub(self.current_member_uncompressed_size);
                (remaining.len() as u64).min(remaining_in_member) as usize
            } else {
                remaining.len()
            };

            if bytes_to_write == 0 {
                self.finish_current_member()?;
                continue;
            }

            let bytes_written = lzma_writer.write(&remaining[..bytes_to_write])?;

            if bytes_written > 0 {
                self.crc_digest.update(&remaining[..bytes_written]);
                self.uncompressed_size += bytes_written as u64;
                self.current_member_uncompressed_size += bytes_written as u64;
                total_written += bytes_written;
                remaining = &remaining[bytes_written..];
            } else {
                break;
            }
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut lzma_writer) = self.lzma_writer {
            lzma_writer.flush()?;
        }
        Ok(())
    }
}

impl<W: Write> AutoFinish for LzipWriter<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}
