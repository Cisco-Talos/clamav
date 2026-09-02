#[cfg(feature = "compress")]
use crate::encoder_options::EncoderOptions;
use crate::{NtTime, bitset::BitSet, block::*};

/// Size of the 7z signature header in bytes (32 bytes).
/// This is needed for calculating absolute byte offsets within the archive.
pub const SIGNATURE_HEADER_SIZE: u64 = 32;
pub(crate) const SEVEN_Z_SIGNATURE: &[u8] = &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

pub(crate) const K_END: u8 = 0x00;
pub(crate) const K_HEADER: u8 = 0x01;
pub(crate) const K_ARCHIVE_PROPERTIES: u8 = 0x02;
pub(crate) const K_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
pub(crate) const K_MAIN_STREAMS_INFO: u8 = 0x04;
pub(crate) const K_FILES_INFO: u8 = 0x05;
pub(crate) const K_PACK_INFO: u8 = 0x06;
pub(crate) const K_UNPACK_INFO: u8 = 0x07;
pub(crate) const K_SUB_STREAMS_INFO: u8 = 0x08;
pub(crate) const K_SIZE: u8 = 0x09;
pub(crate) const K_CRC: u8 = 0x0A;
pub(crate) const K_FOLDER: u8 = 0x0B;
pub(crate) const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
pub(crate) const K_NUM_UNPACK_STREAM: u8 = 0x0D;
pub(crate) const K_EMPTY_STREAM: u8 = 0x0E;
pub(crate) const K_EMPTY_FILE: u8 = 0x0F;
pub(crate) const K_ANTI: u8 = 0x10;
pub(crate) const K_NAME: u8 = 0x11;
pub(crate) const K_C_TIME: u8 = 0x12;
pub(crate) const K_A_TIME: u8 = 0x13;
pub(crate) const K_M_TIME: u8 = 0x14;
pub(crate) const K_WIN_ATTRIBUTES: u8 = 0x15;

/// TODO: Implement reading & writing comments
#[allow(unused)]
pub(crate) const K_COMMENT: u8 = 0x16;
pub(crate) const K_ENCODED_HEADER: u8 = 0x17;
pub(crate) const K_START_POS: u8 = 0x18;
pub(crate) const K_DUMMY: u8 = 0x19;

/// Represents a parsed 7z archive structure.
///
/// Contains metadata about the archive including files, compression blocks,
/// and internal structure information necessary for decompression.
#[derive(Debug, Default, Clone)]
pub struct Archive {
    /// Offset from beginning of file + SIGNATURE_HEADER_SIZE to packed streams.
    pub(crate) pack_pos: u64,
    pub(crate) pack_sizes: Vec<u64>,
    pub(crate) pack_crcs_defined: BitSet,
    pub(crate) pack_crcs: Vec<u64>,
    pub(crate) sub_streams_info: Option<SubStreamsInfo>,
    /// Compression blocks in the archive.
    pub blocks: Vec<Block>,
    /// File and directory entries in the archive.
    pub files: Vec<ArchiveEntry>,
    /// Mapping between files, blocks, and pack streams.
    pub stream_map: StreamMap,
    /// Whether this is a solid archive (better compression, slower random access).
    pub is_solid: bool,
}

impl Archive {
    /// Returns the offset from beginning of file + SIGNATURE_HEADER_SIZE to packed streams.
    /// Used for calculating byte offsets when streaming uncompressed (COPY) content.
    pub fn pack_pos(&self) -> u64 {
        self.pack_pos
    }

    /// Returns the sizes of each packed stream in bytes.
    /// Used for calculating byte ranges when streaming.
    pub fn pack_sizes(&self) -> &[u64] {
        &self.pack_sizes
    }

    /// Returns whether a file's owning compression block contains the 7z
    /// AES256-SHA256 coder.
    pub fn is_file_encrypted(&self, file_index: usize) -> bool {
        self.stream_map
            .file_block_index
            .get(file_index)
            .and_then(|block_index| *block_index)
            .and_then(|block_index| self.blocks.get(block_index))
            .is_some_and(|block| {
                block
                    .coders
                    .iter()
                    .any(|coder| coder.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
            })
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SubStreamsInfo {
    pub(crate) unpack_sizes: Vec<u64>,
    pub(crate) has_crc: BitSet,
    pub(crate) crcs: Vec<u64>,
}

/// Represents a single file or directory entry within a 7z archive.
///
/// Contains metadata about the entry including name, timestamps, attributes,
/// and size information.
#[derive(Debug, Default, Clone)]
pub struct ArchiveEntry {
    /// Name/path of the entry within the archive.
    pub name: String,
    /// Whether this entry has associated data stream.
    pub has_stream: bool,
    /// Whether this entry is a directory.
    pub is_directory: bool,
    /// Whether this is an anti-item (used for deletion in updates).
    pub is_anti_item: bool,
    /// Whether creation date is present.
    pub has_creation_date: bool,
    /// Whether last modified date is present.
    pub has_last_modified_date: bool,
    /// Whether access date is present.
    pub has_access_date: bool,
    /// Creation date and time.
    pub creation_date: NtTime,
    /// Last modified date and time.
    pub last_modified_date: NtTime,
    /// Last access date and time.
    pub access_date: NtTime,
    /// Whether Windows file attributes are present.
    pub has_windows_attributes: bool,
    /// Windows file attributes.
    pub windows_attributes: u32,
    /// Whether CRC is present.
    pub has_crc: bool,
    /// CRC32 checksum of uncompressed data.
    pub crc: u64,
    /// CRC32 checksum of compressed data.
    pub compressed_crc: u64,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
}

impl ArchiveEntry {
    /// Creates a new default archive entry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new archive entry representing a file.
    ///
    /// # Arguments
    /// * `entry_name` - The name/path of the file within the archive
    pub fn new_file(entry_name: &str) -> Self {
        Self {
            name: entry_name.to_string(),
            has_stream: true,
            is_directory: false,
            ..Default::default()
        }
    }

    /// Creates a new archive entry representing a directory.
    ///
    /// # Arguments
    /// * `entry_name` - The name/path of the directory within the archive
    pub fn new_directory(entry_name: &str) -> Self {
        Self {
            name: entry_name.to_string(),
            has_stream: false,
            is_directory: true,
            ..Default::default()
        }
    }

    /// Creates a new archive entry from a filesystem path.
    ///
    /// Automatically extracts metadata like timestamps and attributes from the filesystem.
    /// On Windows, backslashes in the entry name are converted to forward slashes.
    ///
    /// # Arguments
    /// * `path` - The filesystem path to extract metadata from
    /// * `entry_name` - The name/path to use for this entry within the archive
    pub fn from_path(path: impl AsRef<std::path::Path>, entry_name: String) -> Self {
        let path = path.as_ref();
        #[cfg(target_os = "windows")]
        let entry_name = {
            let mut name_bytes = entry_name.into_bytes();
            for b in &mut name_bytes {
                if *b == b'\\' {
                    *b = b'/';
                }
            }
            String::from_utf8(name_bytes).unwrap()
        };
        let mut entry = ArchiveEntry {
            name: entry_name,
            has_stream: path.is_file(),
            is_directory: path.is_dir(),
            ..Default::default()
        };

        if let Ok(meta) = path.metadata() {
            if let Ok(modified) = meta.modified()
                && let Ok(date) = NtTime::try_from(modified)
            {
                entry.last_modified_date = date;
                entry.has_last_modified_date = entry.last_modified_date.0 > 0;
            }
            if let Ok(date) = meta.created()
                && let Ok(date) = NtTime::try_from(date)
            {
                entry.creation_date = date;
                entry.has_creation_date = entry.creation_date.0 > 0;
            }
            if let Ok(date) = meta.accessed()
                && let Ok(date) = NtTime::try_from(date)
            {
                entry.access_date = date;
                entry.has_access_date = entry.access_date.0 > 0;
            }
        }
        entry
    }

    /// Returns the name/path of this entry within the archive.
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Returns whether this entry has an associated data stream.
    pub fn has_stream(&self) -> bool {
        self.has_stream
    }

    /// Returns the creation date of this entry.
    pub fn creation_date(&self) -> NtTime {
        self.creation_date
    }

    /// Returns the last modified date of this entry.
    pub fn last_modified_date(&self) -> NtTime {
        self.last_modified_date
    }

    /// Returns the uncompressed size of this entry in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the Windows file attributes of this entry.
    pub fn windows_attributes(&self) -> u32 {
        self.windows_attributes
    }

    /// Returns the last access date of this entry.
    pub fn access_date(&self) -> NtTime {
        self.access_date
    }

    /// Returns whether this entry is an anti-item (used for deletion in updates).
    pub fn is_anti_item(&self) -> bool {
        self.is_anti_item
    }
}

/// Configuration for encoding methods when compressing data.
///
/// Combines an encoder method with optional encoder-specific options.
#[cfg(feature = "compress")]
#[derive(Debug, Default)]
pub struct EncoderConfiguration {
    /// The encoder method to use.
    pub method: EncoderMethod,
    /// Optional encoder-specific options.
    pub options: Option<EncoderOptions>,
}

#[cfg(feature = "compress")]
impl From<EncoderMethod> for EncoderConfiguration {
    fn from(value: EncoderMethod) -> Self {
        Self::new(value)
    }
}

#[cfg(feature = "compress")]
impl Clone for EncoderConfiguration {
    fn clone(&self) -> Self {
        Self {
            method: self.method,
            options: self.options.clone(),
        }
    }
}

#[cfg(feature = "compress")]
impl EncoderConfiguration {
    /// Creates a new encoder configuration with the specified method.
    ///
    /// # Arguments
    /// * `method` - The encoder method to use
    pub fn new(method: EncoderMethod) -> Self {
        Self {
            method,
            options: None,
        }
    }

    /// Adds encoder-specific options to this configuration.
    ///
    /// # Arguments
    /// * `options` - The encoder options to apply
    pub fn with_options(mut self, options: EncoderOptions) -> Self {
        self.options = Some(options);
        self
    }
}

/// Encoder method that can be chained (filter, compression and encryption).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Hash)]
pub struct EncoderMethod(&'static str, &'static [u8]);

impl EncoderMethod {
    /// Method ID for COPY (no compression).
    pub const ID_COPY: &'static [u8] = &[0x00];
    /// Method ID for Delta filter.
    pub const ID_DELTA: &'static [u8] = &[0x03];

    /// Method ID for LZMA compression.
    pub const ID_LZMA: &'static [u8] = &[0x03, 0x01, 0x01];
    /// Method ID for BCJ x86 filter.
    pub const ID_BCJ_X86: &'static [u8] = &[0x03, 0x03, 0x01, 0x03];
    /// Method ID for BCJ2 filter.
    pub const ID_BCJ2: &'static [u8] = &[0x03, 0x03, 0x01, 0x1B];
    /// Method ID for BCJ PowerPC filter.
    pub const ID_BCJ_PPC: &'static [u8] = &[0x03, 0x03, 0x02, 0x05];
    /// Method ID for BCJ IA64 filter.
    pub const ID_BCJ_IA64: &'static [u8] = &[0x03, 0x03, 0x04, 0x01];
    /// Method ID for BCJ ARM filter.
    pub const ID_BCJ_ARM: &'static [u8] = &[0x03, 0x03, 0x05, 0x01];
    /// Method ID for BCJ ARM64 filter.
    pub const ID_BCJ_ARM64: &'static [u8] = &[0xA];
    /// Method ID for BCJ ARM Thumb filter.
    pub const ID_BCJ_ARM_THUMB: &'static [u8] = &[0x03, 0x03, 0x07, 0x01];
    /// Method ID for BCJ SPARC filter.
    pub const ID_BCJ_SPARC: &'static [u8] = &[0x03, 0x03, 0x08, 0x05];
    /// Method ID for BCJ RISCV filter.
    pub const ID_BCJ_RISCV: &'static [u8] = &[0xB];
    /// Method ID for PPMD compression.
    pub const ID_PPMD: &'static [u8] = &[0x03, 0x04, 0x01];

    /// Method ID for LZMA2 compression.
    pub const ID_LZMA2: &'static [u8] = &[0x21];
    /// Method ID for BZIP2 compression.
    pub const ID_BZIP2: &'static [u8] = &[0x04, 0x02, 0x02];
    /// Method ID for Zstandard compression.
    pub const ID_ZSTD: &'static [u8] = &[0x04, 0xF7, 0x11, 0x01];
    /// Method ID for Brotli compression.
    pub const ID_BROTLI: &'static [u8] = &[0x04, 0xF7, 0x11, 0x02];
    /// Method ID for LZ4 compression.
    pub const ID_LZ4: &'static [u8] = &[0x04, 0xF7, 0x11, 0x04];
    /// Method ID for LZS compression.
    pub const ID_LZS: &'static [u8] = &[0x04, 0xF7, 0x11, 0x05];
    /// Method ID for Lizard compression.
    pub const ID_LIZARD: &'static [u8] = &[0x04, 0xF7, 0x11, 0x06];
    /// Method ID for Deflate compression.
    pub const ID_DEFLATE: &'static [u8] = &[0x04, 0x01, 0x08];
    /// Method ID for Deflate64 compression.
    pub const ID_DEFLATE64: &'static [u8] = &[0x04, 0x01, 0x09];
    /// Method ID for AES256-SHA256 encryption.
    pub const ID_AES256_SHA256: &'static [u8] = &[0x06, 0xF1, 0x07, 0x01];

    /// COPY method (no compression).
    pub const COPY: Self = Self("COPY", Self::ID_COPY);
    /// LZMA compression method.
    pub const LZMA: Self = Self("LZMA", Self::ID_LZMA);
    /// LZMA2 compression method.
    pub const LZMA2: Self = Self("LZMA2", Self::ID_LZMA2);
    /// PPMD compression method.
    pub const PPMD: Self = Self("PPMD", Self::ID_PPMD);
    /// BZIP2 compression method.
    pub const BZIP2: Self = Self("BZIP2", Self::ID_BZIP2);
    /// Zstandard compression method.
    pub const ZSTD: Self = Self("ZSTD", Self::ID_ZSTD);
    /// Brotli compression method.
    pub const BROTLI: Self = Self("BROTLI", Self::ID_BROTLI);
    /// LZ4 compression method.
    pub const LZ4: Self = Self("LZ4", Self::ID_LZ4);
    /// LZS compression method.
    pub const LZS: Self = Self("LZS", Self::ID_LZS);
    /// Lizard compression method.
    pub const LIZARD: Self = Self("LIZARD", Self::ID_LIZARD);
    /// Deflate compression method.
    pub const DEFLATE: Self = Self("DEFLATE", Self::ID_DEFLATE);
    /// Deflate64 compression method.
    pub const DEFLATE64: Self = Self("DEFLATE64", Self::ID_DEFLATE64);
    /// AES256-SHA256 encryption method.
    pub const AES256_SHA256: Self = Self("AES256_SHA256", Self::ID_AES256_SHA256);

    /// BCJ x86 filter method.
    pub const BCJ_X86_FILTER: Self = Self("BCJ_X86", Self::ID_BCJ_X86);
    /// BCJ PowerPC filter method.
    pub const BCJ_PPC_FILTER: Self = Self("BCJ_PPC", Self::ID_BCJ_PPC);
    /// BCJ IA64 filter method.
    pub const BCJ_IA64_FILTER: Self = Self("BCJ_IA64", Self::ID_BCJ_IA64);
    /// BCJ ARM filter method.
    pub const BCJ_ARM_FILTER: Self = Self("BCJ_ARM", Self::ID_BCJ_ARM);
    /// BCJ ARM64 filter method.
    pub const BCJ_ARM64_FILTER: Self = Self("BCJ_ARM64", Self::ID_BCJ_ARM64);
    /// BCJ ARM Thumb filter method.
    pub const BCJ_ARM_THUMB_FILTER: Self = Self("BCJ_ARM_THUMB", Self::ID_BCJ_ARM_THUMB);
    /// BCJ SPARC filter method.
    pub const BCJ_SPARC_FILTER: Self = Self("BCJ_SPARC", Self::ID_BCJ_SPARC);
    /// BCJ RISC-V filter method.
    pub const BCJ_RISCV_FILTER: Self = Self("BCJ_RISCV", Self::ID_BCJ_RISCV);
    /// Delta filter method.
    pub const DELTA_FILTER: Self = Self("DELTA", Self::ID_DELTA);
    /// BCJ2 filter method.
    pub const BCJ2_FILTER: Self = Self("BCJ2", Self::ID_BCJ2);

    const ENCODING_METHODS: &'static [&'static EncoderMethod] = &[
        &Self::COPY,
        &Self::LZMA,
        &Self::LZMA2,
        &Self::PPMD,
        &Self::BZIP2,
        &Self::ZSTD,
        &Self::BROTLI,
        &Self::LZ4,
        &Self::LZS,
        &Self::LIZARD,
        &Self::DEFLATE,
        &Self::DEFLATE64,
        &Self::AES256_SHA256,
        &Self::BCJ_X86_FILTER,
        &Self::BCJ_PPC_FILTER,
        &Self::BCJ_IA64_FILTER,
        &Self::BCJ_ARM_FILTER,
        &Self::BCJ_ARM64_FILTER,
        &Self::BCJ_ARM_THUMB_FILTER,
        &Self::BCJ_SPARC_FILTER,
        &Self::BCJ_RISCV_FILTER,
        &Self::DELTA_FILTER,
        &Self::BCJ2_FILTER,
    ];

    #[inline]
    /// Returns the human-readable name of this encoder method.
    pub const fn name(&self) -> &'static str {
        self.0
    }

    #[inline]
    /// Returns the binary ID of this encoder method.
    pub const fn id(&self) -> &'static [u8] {
        self.1
    }

    #[inline]
    /// Finds an encoder method by its binary ID.
    ///
    /// # Arguments
    /// * `id` - The binary method ID to search for
    pub fn by_id(id: &[u8]) -> Option<Self> {
        Self::ENCODING_METHODS
            .iter()
            .find(|item| item.id() == id)
            .cloned()
            .cloned()
    }
}

/// Mapping structure that correlates files, blocks, and pack streams within an archive.
///
/// This structure maintains the relationships between archive entries and their
/// corresponding compression blocks and packed data streams.
#[derive(Debug, Default, Clone)]
pub struct StreamMap {
    pub(crate) block_first_pack_stream_index: Vec<usize>,
    pub(crate) pack_stream_offsets: Vec<u64>,
    /// Index of first file for each block.
    pub block_first_file_index: Vec<usize>,
    /// Block index for each file (None if file has no data).
    pub file_block_index: Vec<Option<usize>>,
}

impl StreamMap {
    /// Returns the index of the first pack stream for each block.
    /// Used for mapping blocks to their packed data streams.
    pub fn block_first_pack_stream_index(&self) -> &[usize] {
        &self.block_first_pack_stream_index
    }

    /// Returns byte offsets of each pack stream within the packed data region.
    /// Combined with pack_pos and SIGNATURE_HEADER_SIZE to get absolute offsets.
    pub fn pack_stream_offsets(&self) -> &[u64] {
        &self.pack_stream_offsets
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartHeader {
    pub(crate) next_header_offset: u64,
    pub(crate) next_header_size: u64,
    pub(crate) next_header_crc: u64,
}
