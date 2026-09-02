use alloc::vec::Vec;
use core::num::NonZeroU64;

use super::{
    encoder::{EncodeMode, LzmaEncoder, LzmaEncoderModes},
    lz::MfType,
    range_enc::{RangeEncoder, RangeEncoderBuffer},
};
use crate::{AutoFinish, AutoFinisher, ByteWriter, Write};

/// Encoder settings when compressing with LZMA and LZMA2.
#[derive(Debug, Clone)]
pub struct LzmaOptions {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// Number of literal context bits (0-8).
    pub lc: u32,
    /// Number of literal position bits (0-4).
    pub lp: u32,
    /// Number of position bits (0-4).
    pub pb: u32,
    /// Compression mode.
    pub mode: EncodeMode,
    /// Match finder nice length.
    pub nice_len: u32,
    /// Match finder type.
    pub mf: MfType,
    /// Match finder depth limit.
    pub depth_limit: i32,
    /// Preset dictionary data.
    pub preset_dict: Option<Vec<u8>>,
}

impl Default for LzmaOptions {
    fn default() -> Self {
        Self::with_preset(6)
    }
}

impl LzmaOptions {
    /// Default number of literal context bits.
    pub const LC_DEFAULT: u32 = 3;

    /// Default number of literal position bits.
    pub const LP_DEFAULT: u32 = 0;

    /// Default number of position bits.
    pub const PB_DEFAULT: u32 = 2;

    /// Maximum match finder nice length.
    pub const NICE_LEN_MAX: u32 = 273;

    /// Minimum match finder nice length.
    pub const NICE_LEN_MIN: u32 = 8;

    /// Default dictionary size (8MB).
    pub const DICT_SIZE_DEFAULT: u32 = 8 << 20;

    const PRESET_TO_DICT_SIZE: &'static [u32] = &[
        1 << 18,
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 22,
        1 << 23,
        1 << 23,
        1 << 24,
        1 << 25,
        1 << 26,
    ];

    const PRESET_TO_DEPTH_LIMIT: &'static [i32] = &[4, 8, 24, 48];

    /// Creates new LZMA encoding options with specified parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dict_size: u32,
        lc: u32,
        lp: u32,
        pb: u32,
        mode: EncodeMode,
        nice_len: u32,
        mf: MfType,
        depth_limit: i32,
    ) -> Self {
        Self {
            dict_size,
            lc,
            lp,
            pb,
            mode,
            nice_len,
            mf,
            depth_limit,
            preset_dict: None,
        }
    }

    /// preset: [0..9]
    #[inline]
    pub fn with_preset(preset: u32) -> Self {
        let mut opt = Self {
            dict_size: Default::default(),
            lc: Default::default(),
            lp: Default::default(),
            pb: Default::default(),
            mode: EncodeMode::Normal,
            nice_len: Default::default(),
            mf: Default::default(),
            depth_limit: Default::default(),
            preset_dict: Default::default(),
        };
        opt.set_preset(preset);
        opt
    }

    /// preset: [0..9]
    pub fn set_preset(&mut self, preset: u32) {
        let preset = preset.min(9);

        self.lc = Self::LC_DEFAULT;
        self.lp = Self::LP_DEFAULT;
        self.pb = Self::PB_DEFAULT;
        self.dict_size = Self::PRESET_TO_DICT_SIZE[preset as usize];
        if preset <= 3 {
            self.mode = EncodeMode::Fast;
            self.mf = MfType::Hc4;
            self.nice_len = if preset <= 1 { 128 } else { Self::NICE_LEN_MAX };
            self.depth_limit = Self::PRESET_TO_DEPTH_LIMIT[preset as usize];
        } else {
            self.mode = EncodeMode::Normal;
            self.mf = MfType::Bt4;
            self.nice_len = if preset == 4 {
                16
            } else if preset == 5 {
                32
            } else {
                64
            };
            self.depth_limit = 0;
        }
    }

    /// Returns the estimated memory usage in kilobytes for these options.
    pub fn get_memory_usage(&self) -> u32 {
        let dict_size = self.dict_size;
        let extra_size_before = get_extra_size_before(dict_size);
        70 + LzmaEncoder::get_mem_usage(self.mode, dict_size, extra_size_before, self.mf)
    }

    /// Returns the LZMA properties byte for these options.
    #[inline(always)]
    pub fn get_props(&self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }
}

/// Options for LZMA2 compression.
#[derive(Default, Debug, Clone)]
pub struct Lzma2Options {
    /// LZMA compression options.
    pub lzma_options: LzmaOptions,
    /// The size of each independent chunk in bytes.
    /// If not set, the whole data will be written as one chunk.
    /// Will get clamped to be at least the dict size to not waste memory.
    pub chunk_size: Option<NonZeroU64>,
}

impl Lzma2Options {
    /// Create options with specific preset.
    pub fn with_preset(preset: u32) -> Self {
        Self {
            lzma_options: LzmaOptions::with_preset(preset),
            chunk_size: None,
        }
    }

    /// Set the chunk size (None means a single chunk, which is the default).
    /// Chunk size will be clamped to be at least the dictionary size.
    pub fn set_chunk_size(&mut self, chunk_size: Option<NonZeroU64>) {
        self.chunk_size = chunk_size;
    }
}

const COMPRESSED_SIZE_MAX: u32 = 64 << 10;

/// Calculates the extra space needed before the dictionary for LZMA2 encoding.
pub fn get_extra_size_before(dict_size: u32) -> u32 {
    COMPRESSED_SIZE_MAX.saturating_sub(dict_size)
}

/// A single-threaded LZMA2 compressor.
pub struct Lzma2Writer<W: Write> {
    inner: W,
    rc: RangeEncoder<RangeEncoderBuffer>,
    lzma: LzmaEncoder,
    mode: LzmaEncoderModes,
    dict_reset_needed: bool,
    state_reset_needed: bool,
    props_needed: bool,
    pending_size: u32,
    chunk_size: Option<u64>,
    uncompressed_size: u64,
    force_independent_chunk: bool,
    options: Lzma2Options,
}

impl<W: Write> Lzma2Writer<W> {
    /// Creates a new LZMA2 writer that will write compressed data to the given writer.
    pub fn new(inner: W, options: Lzma2Options) -> Self {
        let lzma_options = &options.lzma_options;
        let dict_size = lzma_options.dict_size;

        let rc = RangeEncoder::new_buffer(COMPRESSED_SIZE_MAX as usize);
        let (mut lzma, mode) = LzmaEncoder::new(
            lzma_options.mode,
            lzma_options.lc,
            lzma_options.lp,
            lzma_options.pb,
            lzma_options.mf,
            lzma_options.depth_limit,
            lzma_options.dict_size,
            lzma_options.nice_len as usize,
        );

        let mut dict_reset_needed = true;
        if let Some(preset_dict) = &lzma_options.preset_dict {
            lzma.lz.set_preset_dict(dict_size, preset_dict);
            dict_reset_needed = false;
        }

        let chunk_size = options.chunk_size.map(|s| s.get().max(dict_size as u64));

        Self {
            inner,
            rc,
            lzma,
            mode,

            dict_reset_needed,
            state_reset_needed: true,
            props_needed: true,
            pending_size: 0,
            chunk_size,
            uncompressed_size: 0,
            force_independent_chunk: false,
            options,
        }
    }

    fn should_start_independent_chunk(&self) -> bool {
        if let Some(chunk_size) = self.chunk_size {
            self.uncompressed_size >= chunk_size
        } else {
            false
        }
    }

    fn start_independent_chunk(&mut self) -> crate::Result<()> {
        self.lzma.lz.set_flushing();

        while self.pending_size > 0 {
            self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)?;
            self.write_chunk()?;
        }

        self.force_independent_chunk = true;
        self.dict_reset_needed = true;
        self.state_reset_needed = true;
        self.props_needed = true;
        self.uncompressed_size = 0;

        let lzma_options = &self.options.lzma_options;

        let (new_lzma, new_mode) = LzmaEncoder::new(
            lzma_options.mode,
            lzma_options.lc,
            lzma_options.lp,
            lzma_options.pb,
            lzma_options.mf,
            lzma_options.depth_limit,
            lzma_options.dict_size,
            lzma_options.nice_len as usize,
        );

        self.lzma = new_lzma;
        self.mode = new_mode;
        self.rc = RangeEncoder::new_buffer(COMPRESSED_SIZE_MAX as usize);

        Ok(())
    }

    fn write_lzma(&mut self, uncompressed_size: u32, compressed_size: u32) -> crate::Result<()> {
        let mut control = if self.props_needed || self.force_independent_chunk {
            if self.dict_reset_needed || self.force_independent_chunk {
                0x80 + (3 << 5)
            } else {
                0x80 + (2 << 5)
            }
        } else if self.state_reset_needed {
            0x80 + (1 << 5)
        } else {
            0x80
        };
        control |= (uncompressed_size - 1) >> 16;

        let mut chunk_header = [0u8; 6];
        chunk_header[0] = control as u8;
        chunk_header[1] = ((uncompressed_size - 1) >> 8) as u8;
        chunk_header[2] = (uncompressed_size - 1) as u8;
        chunk_header[3] = ((compressed_size - 1) >> 8) as u8;
        chunk_header[4] = (compressed_size - 1) as u8;
        if self.props_needed {
            chunk_header[5] = self.options.lzma_options.get_props();
            self.inner.write_all(&chunk_header)?;
        } else {
            self.inner.write_all(&chunk_header[..5])?;
        }

        self.rc.write_to(&mut self.inner)?;
        self.props_needed = false;
        self.state_reset_needed = false;
        self.dict_reset_needed = false;
        self.force_independent_chunk = false;
        Ok(())
    }

    fn write_uncompressed(&mut self, mut uncompressed_size: u32) -> crate::Result<()> {
        while uncompressed_size > 0 {
            let chunk_size = uncompressed_size.min(COMPRESSED_SIZE_MAX);
            let mut chunk_header = [0u8; 3];
            chunk_header[0] = if self.dict_reset_needed { 0x01 } else { 0x02 };
            chunk_header[1] = ((chunk_size - 1) >> 8) as u8;
            chunk_header[2] = (chunk_size - 1) as u8;
            self.inner.write_all(&chunk_header)?;
            self.lzma.lz.copy_uncompressed(
                &mut self.inner,
                uncompressed_size as i32,
                chunk_size as usize,
            )?;
            uncompressed_size -= chunk_size;
            self.dict_reset_needed = false;
        }
        self.state_reset_needed = true;
        Ok(())
    }

    fn write_chunk(&mut self) -> crate::Result<()> {
        let compressed_size = self.rc.finish_buffer()?.unwrap_or_default() as u32;
        let mut uncompressed_size = self.lzma.data.uncompressed_size;
        debug_assert!(compressed_size > 0);
        debug_assert!(
            uncompressed_size > 0,
            "uncompressed_size is 0, read_pos={}",
            self.lzma.lz.read_pos,
        );
        if compressed_size + 2 < uncompressed_size {
            self.write_lzma(uncompressed_size, compressed_size)?;
        } else {
            self.lzma.reset(&mut self.mode);
            uncompressed_size = self.lzma.data.uncompressed_size;
            debug_assert!(uncompressed_size > 0);
            self.write_uncompressed(uncompressed_size)?;
        }
        self.pending_size -= uncompressed_size;
        self.uncompressed_size += uncompressed_size as u64;

        self.lzma.reset_uncompressed_size();
        self.rc.reset_buffer();
        Ok(())
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
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

    /// Finishes the compression and returns the underlying writer.
    pub fn finish(mut self) -> crate::Result<W> {
        self.lzma.lz.set_finishing();

        while self.pending_size > 0 {
            self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)?;
            self.write_chunk()?;
        }

        self.inner.write_u8(0x00)?;

        Ok(self.inner)
    }
}

impl<W: Write> Write for Lzma2Writer<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let mut len = buf.len();

        let mut off = 0;
        while len > 0 {
            if self.should_start_independent_chunk() {
                self.start_independent_chunk()?;
            }

            let used = self.lzma.lz.fill_window(&buf[off..(off + len)]);
            off += used;
            len -= used;
            self.pending_size += used as u32;
            if self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)? {
                self.write_chunk()?;
            }
        }
        Ok(off)
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.lzma.lz.set_flushing();

        while self.pending_size > 0 {
            self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)?;
            self.write_chunk()?;
        }

        self.inner.flush()
    }
}

impl<W: Write> AutoFinish for Lzma2Writer<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}
