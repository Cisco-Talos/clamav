/*
 *  ALZ archive extraction.
 *
 *  Copyright (C) 2024-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Andy Ragusa
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/*
#![warn(
    clippy::all,
    clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
)]
*/

use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use bzip2_rs::DecoderReader;
use flate2::read::DeflateDecoder;
use log::debug;

/// File header
const ALZ_FILE_HEADER: u32 = 0x015a_4c41;
/// Local file header
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a_4c42;
/// Central directory header
const ALZ_CENTRAL_DIRECTORY_HEADER: u32 = 0x015a_4c43;
/// End of Central directory header
const ALZ_END_OF_CENTRAL_DIRECTORY_HEADER: u32 = 0x025a_4c43;

const ALZ_COMP_NOCOMP: u8 = 0;
const ALZ_COMP_BZIP2: u8 = 1;
const ALZ_COMP_DEFLATE: u8 = 2;
const MIN_SCANNED_FILE_SIZE: usize = 5;

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error parsing ALZ archive: {0}")]
    Parse(&'static str),

    #[error("Unrecognized sig: '{0}'")]
    UnrecognizedSig(String),

    #[error("Unsupported ALZ feature: {0}")]
    UnsupportedFeature(&'static str),

    #[error("Failed to extract file")]
    Extract,

    #[error("Failed to allocate extracted file")]
    Alloc,

    #[error("Extracted file exceeds scan limits")]
    ScanLimitExceeded(u64),

    #[error("Stopped ALZ archive traversal")]
    Stop,

    #[error("Failed to read field: {0}")]
    Read(&'static str),
}

struct AlzLocalFileHeaderHead {
    file_name_length: u16,

    file_attribute: u8,

    file_time_date: u32,

    file_descriptor: u8,

    unknown: u8,
}

const ALZ_ENCR_HEADER_LEN: u32 = 12;

struct AlzLocalFileHeader {
    head: AlzLocalFileHeaderHead,

    compression_method: u8,
    unknown: u8,
    file_crc: u32,

    /* Can be smaller sizes, depending on file_descriptor/0x10 .*/
    compressed_size: u64,
    uncompressed_size: u64,

    file_name: String,

    enc_chk: [u8; ALZ_ENCR_HEADER_LEN as usize],

    start_of_compressed_data: u64,
    compressed_data_is_within_bounds: bool,
}

#[allow(dead_code)]
enum AlzFileAttribute {
    Readonly = 0x1,
    Hidden = 0x2,
    Directory = 0x10,
    File = 0x20,
}

impl AlzLocalFileHeader {
    const fn is_encrypted(&self) -> bool {
        0 != (self.head.file_descriptor & 0x1)
    }

    const fn is_data_descriptor(&self) -> bool {
        0 != (self.head.file_descriptor & 0x8)
    }

    const fn is_directory(&self) -> bool {
        0 != ((AlzFileAttribute::Directory as u8) & self.head.file_attribute)
    }

    const fn _is_file(&self) -> bool {
        0 != ((AlzFileAttribute::File as u8) & self.head.file_attribute)
    }

    const fn _is_readonly(&self) -> bool {
        0 != ((AlzFileAttribute::Readonly as u8) & self.head.file_attribute)
    }

    const fn _is_hidden(&self) -> bool {
        0 != ((AlzFileAttribute::Hidden as u8) & self.head.file_attribute)
    }

    const fn scan_limit_size_hint(&self) -> u64 {
        if self.compressed_size == 0 {
            return 0;
        }

        let size_hint = if self.compression_method == ALZ_COMP_NOCOMP {
            self.compressed_size
        } else if self.uncompressed_size <= MIN_SCANNED_FILE_SIZE as u64 {
            MIN_SCANNED_FILE_SIZE as u64 + 1
        } else {
            self.uncompressed_size
        };

        if size_hint == 0 && self.compressed_size > 0 {
            1
        } else {
            size_hint
        }
    }

    const fn is_known_scan_limit_exempt(&self) -> bool {
        self.compressed_size == 0
            || (self.compression_method == ALZ_COMP_NOCOMP
                && self.compressed_size <= MIN_SCANNED_FILE_SIZE as u64)
    }

    const fn has_valid_compressed_data_bounds(&self) -> bool {
        self.compressed_data_is_within_bounds
    }

    fn _dump(&self) {
        println!(
            "self.start_of_compressed_data = {}",
            self.start_of_compressed_data
        );

        println!(
            "self.head.file_name_length = {:x}",
            self.head.file_name_length
        );
        println!(
            "self.head.file_attribute = {:02x}",
            self.head.file_attribute
        );
        println!("self.head.file_time_date = {:x}", self.head.file_time_date);
        println!(
            "self.head.file_descriptor = {:x}",
            self.head.file_descriptor
        );
        println!("self.head.unknown = {:x}", self.head.unknown);

        println!("self.compression_method = {:x}", self.compression_method);
        println!("self.unknown = {:x}", self.unknown);
        println!("self.file_crc = {:x}", self.file_crc);
        println!("self.compressed_size = {:x}", self.compressed_size);
        println!("self.uncompressed_size = {:x}", self.uncompressed_size);

        println!("self.file_name = {}", self.file_name);

        print!("self.enc_chk = ");
        for i in 0..ALZ_ENCR_HEADER_LEN {
            if 0 != i {
                print!(" ");
            }
            print!("{}", self.enc_chk[i as usize]);
        }
        println!();

        println!("is_encrypted = {}", self.is_encrypted());
        println!("is_data_descriptor = {}", self.is_data_descriptor());

        println!();
    }

    pub const fn new() -> Self {
        Self {
            head: AlzLocalFileHeaderHead {
                file_name_length: 0,
                file_attribute: 0,
                file_time_date: 0,
                file_descriptor: 0,
                unknown: 0,
            },

            compression_method: 0,
            unknown: 0,
            file_crc: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            file_name: String::new(),
            enc_chk: [0; ALZ_ENCR_HEADER_LEN as usize],
            start_of_compressed_data: 0,
            compressed_data_is_within_bounds: true,
        }
    }

    pub fn parse(&mut self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> Result<(), Error> {
        self.head.file_name_length = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| Error::Read("file_name_length"))?;
        self.head.file_attribute = cursor
            .read_u8()
            .map_err(|_| Error::Read("file_attribute"))?;
        self.head.file_time_date = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Error::Read("file_time_date"))?;
        self.head.file_descriptor = cursor
            .read_u8()
            .map_err(|_| Error::Read("file_descriptor"))?;
        self.head.unknown = cursor.read_u8().map_err(|_| Error::Read("unknown u8"))?;

        if 0 == self.head.file_name_length {
            return Err(Error::Parse("File Name Length is zero"));
        }

        let byte_len = self.head.file_descriptor / 0x10;
        if byte_len > 0 {
            self.compression_method = cursor
                .read_u8()
                .map_err(|_| Error::Read("compression_method"))?;
            self.unknown = cursor.read_u8().map_err(|_| Error::Read("unknown u8"))?;
            self.file_crc = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| Error::Read("file_crc"))?;

            match byte_len {
                1 => {
                    self.compressed_size = u64::from(
                        cursor
                            .read_u8()
                            .map_err(|_| Error::Read("compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        cursor
                            .read_u8()
                            .map_err(|_| Error::Read("uncompressed_size"))?,
                    );
                }
                2 => {
                    self.compressed_size = u64::from(
                        cursor
                            .read_u16::<LittleEndian>()
                            .map_err(|_| Error::Read("compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        cursor
                            .read_u16::<LittleEndian>()
                            .map_err(|_| Error::Read("uncompressed_size"))?,
                    );
                }
                4 => {
                    self.compressed_size = u64::from(
                        cursor
                            .read_u32::<LittleEndian>()
                            .map_err(|_| Error::Read("compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        cursor
                            .read_u32::<LittleEndian>()
                            .map_err(|_| Error::Read("uncompressed_size"))?,
                    );
                }
                8 => {
                    self.compressed_size = cursor
                        .read_u64::<LittleEndian>()
                        .map_err(|_| Error::Read("compressed_size"))?;
                    self.uncompressed_size = cursor
                        .read_u64::<LittleEndian>()
                        .map_err(|_| Error::Read("uncompressed_size"))?;
                }
                _ => return Err(Error::Parse("Unsupported File Descriptor")),
            }
        }

        let idx0: usize = usize::try_from(cursor.position())
            .map_err(|_| Error::Parse("Invalid file name offset"))?;
        let idx1: usize = idx0
            .checked_add(usize::from(self.head.file_name_length))
            .ok_or(Error::Parse("Invalid file name length"))?;

        if idx1 > cursor.get_ref().len() {
            return Err(Error::Parse("Invalid file name length"));
        }

        let filename = &cursor.get_ref().as_slice()[idx0..idx1];
        cursor.set_position(
            u64::try_from(idx1).map_err(|_| Error::Parse("Invalid file name length"))?,
        );

        self.file_name = String::from_utf8_lossy(filename).into_owned();

        if self.is_encrypted() {
            cursor
                .read_exact(&mut self.enc_chk)
                .map_err(|_| Error::Read("encrypted buffer"))?;
        }

        self.start_of_compressed_data = cursor.position();
        let end_of_compressed_data = self
            .start_of_compressed_data
            .checked_add(self.compressed_size)
            .ok_or(Error::Parse("Invalid compressed data length"))?;

        self.compressed_data_is_within_bounds = end_of_compressed_data
            <= u64::try_from(cursor.get_ref().len())
                .map_err(|_| Error::Parse("Invalid compressed data length"))?;

        cursor.set_position(end_of_compressed_data);

        Ok(())
    }

    pub fn is_supported(&self) -> Result<(), Error> {
        if self.is_encrypted() {
            return Err(Error::UnsupportedFeature("Encryption Unsupported"));
        }

        if self.is_data_descriptor() {
            return Err(Error::UnsupportedFeature(
                "Data Descriptors are Unsupported",
            ));
        }

        self.check_compression_supported()
    }

    fn check_compression_supported(&self) -> Result<(), Error> {
        match self.compression_method {
            ALZ_COMP_NOCOMP | ALZ_COMP_BZIP2 | ALZ_COMP_DEFLATE => {}
            _ => return Err(Error::UnsupportedFeature("Compression Method Unsupported")),
        }

        Ok(())
    }

    /*
     * This has no header/checksum validation.
     */
    fn extract_file_deflate_reader<R: Read>(
        &mut self,
        decompressor: &mut R,
        files: &mut Vec<ExtractedFile>,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        let mut out: Vec<u8> = Vec::<u8>::new();
        let mut buffer = [0u8; 8192];

        loop {
            let len = match decompressor.read(&mut buffer) {
                Ok(len) => len,
                Err(_) => {
                    debug!("Unable to decompress deflate data");
                    if out.is_empty() {
                        return Err(Error::Extract);
                    }

                    self.push_file(out, files)?;
                    return Err(Error::Extract);
                }
            };
            if len == 0 {
                break;
            }

            if let Some(needed) =
                self.append_output(&mut out, &buffer[..len], max_extracted_size)?
            {
                self.push_file(out, files)?;
                return Err(Error::ScanLimitExceeded(needed));
            }
        }

        self.push_file(out, files)
    }

    /*
     * This has no header/checksum validation.
     */
    fn extract_file_deflate(
        &mut self,
        cursor: &std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        let start: usize =
            usize::try_from(self.start_of_compressed_data).map_err(|_| Error::Extract)?;
        let len: usize = usize::try_from(self.compressed_size).map_err(|_| Error::Extract)?;
        let end: usize = start.checked_add(len).ok_or(Error::Extract)?;
        let data: &[u8] = cursor
            .get_ref()
            .as_slice()
            .get(start..end)
            .ok_or(Error::Extract)?;

        let mut decompressor = DeflateDecoder::new(data);
        self.extract_file_deflate_reader(&mut decompressor, files, max_extracted_size)
    }

    fn append_output(
        &self,
        out: &mut Vec<u8>,
        buffer: &[u8],
        max_extracted_size: u64,
    ) -> Result<Option<u64>, Error> {
        let needed = out.len().checked_add(buffer.len()).ok_or(Error::Extract)?;
        let needed_u64 = u64::try_from(needed).map_err(|_| Error::Extract)?;

        if needed_u64 > max_extracted_size {
            let current = u64::try_from(out.len()).map_err(|_| Error::Extract)?;
            let remaining = max_extracted_size.saturating_sub(current);
            let copy_len = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buffer.len());

            out.try_reserve(copy_len).map_err(|_| Error::Alloc)?;
            out.extend_from_slice(&buffer[..copy_len]);

            return Ok(Some(needed_u64));
        }

        out.try_reserve(buffer.len()).map_err(|_| Error::Alloc)?;
        out.extend_from_slice(buffer);

        Ok(None)
    }

    fn push_file(&mut self, data: Vec<u8>, files: &mut Vec<ExtractedFile>) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }

        let mut name = String::new();
        name.try_reserve(self.file_name.len())
            .map_err(|_| Error::Alloc)?;
        name.push_str(&self.file_name);

        let extracted_file: ExtractedFile = ExtractedFile {
            name: Some(name),
            data,
        };

        files.try_reserve(1).map_err(|_| Error::Alloc)?;
        files.push(extracted_file);

        Ok(())
    }

    fn write_file(&mut self, buffer: &[u8], files: &mut Vec<ExtractedFile>) -> Result<(), Error> {
        let mut data: Vec<u8> = Vec::new();
        data.try_reserve_exact(buffer.len())
            .map_err(|_| Error::Alloc)?;
        data.extend_from_slice(buffer);

        self.push_file(data, files)
    }

    fn extract_file_nocomp(
        &mut self,
        cursor: &std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        let idx0: usize =
            usize::try_from(self.start_of_compressed_data).map_err(|_| Error::Extract)?;

        if self.compressed_size != self.uncompressed_size {
            debug!("Uncompressed file has different lengths for compressed vs uncompressed, using the stored size");
        }

        let len: usize = usize::try_from(self.compressed_size).map_err(|_| Error::Extract)?;
        let idx1: usize = idx0.checked_add(len).ok_or(Error::Extract)?;

        let contents = cursor
            .get_ref()
            .as_slice()
            .get(idx0..idx1)
            .ok_or(Error::Extract)?;

        let contents_len = u64::try_from(contents.len()).map_err(|_| Error::Extract)?;
        if contents_len > max_extracted_size {
            let copy_len = usize::try_from(max_extracted_size)
                .unwrap_or(usize::MAX)
                .min(contents.len());
            self.write_file(&contents[..copy_len], files)?;
            return Err(Error::ScanLimitExceeded(contents_len));
        }

        self.write_file(contents, files)
    }

    fn extract_file_bzip2(
        &mut self,
        cursor: &std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        let idx0: usize =
            usize::try_from(self.start_of_compressed_data).map_err(|_| Error::Extract)?;
        let len: usize = usize::try_from(self.compressed_size).map_err(|_| Error::Extract)?;
        let idx1: usize = idx0.checked_add(len).ok_or(Error::Extract)?;

        let contents = cursor
            .get_ref()
            .as_slice()
            .get(idx0..idx1)
            .ok_or(Error::Extract)?;

        let mut out: Vec<u8> = Vec::new();
        let mut decompressor = DecoderReader::new(contents);
        let mut buffer = [0u8; 8192];
        loop {
            let len = match decompressor.read(&mut buffer) {
                Ok(len) => len,
                Err(_) => {
                    debug!("Unable to decompress bz2 data");
                    if out.is_empty() {
                        return Err(Error::Extract);
                    }

                    self.push_file(out, files)?;
                    return Err(Error::Extract);
                }
            };
            if len == 0 {
                break;
            }

            if let Some(needed) =
                self.append_output(&mut out, &buffer[..len], max_extracted_size)?
            {
                self.push_file(out, files)?;
                return Err(Error::ScanLimitExceeded(needed));
            }
        }

        if let Ok(uncompressed_size) = usize::try_from(self.uncompressed_size) {
            if out.len() != uncompressed_size {
                debug!(
                    "Bzip2 file has different lengths for declared vs decompressed data, using the decompressed size"
                );
            }
        }

        self.push_file(out, files)
    }

    fn extract_file(
        &mut self,
        cursor: &mut std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        match self.compression_method {
            ALZ_COMP_NOCOMP => self.extract_file_nocomp(cursor, files, max_extracted_size),
            ALZ_COMP_BZIP2 => self.extract_file_bzip2(cursor, files, max_extracted_size),
            ALZ_COMP_DEFLATE => self.extract_file_deflate(cursor, files, max_extracted_size),
            _ => Err(Error::Extract),
        }
    }
}

/*TODO: Merge this with the onenote extracted_file struct, and use the same one everywhere.*/
pub struct ExtractedFile {
    pub name: Option<String>,
    pub data: Vec<u8>,
}

impl ExtractedFile {
    const fn counts_toward_scan_limits(&self) -> bool {
        self.data.len() > MIN_SCANNED_FILE_SIZE
    }
}

pub struct AlzFileMetadata<'a> {
    pub file_name: &'a str,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub file_crc: u32,
    pub filepos: usize,
}

pub struct AlzExtractionLimits {
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_files_remaining: usize,
}

pub enum AlzExtractionDecision {
    Extract(AlzExtractionLimits),
    Skip,
    Stop,
}

#[derive(Default)]
pub struct Alz {
    pub embedded_files: Vec<ExtractedFile>,
    pub file_limit_exceeded_size: Option<u64>,
    pub total_limit_exceeded_size: Option<u64>,
    pub file_count_limit_exceeded: bool,
    extracted_size: u64,
    scan_counted_files: usize,
    parse_error: bool,
}

impl<'aa> Alz {
    /* Check for the ALZ file header. */
    #[allow(clippy::unused_self)]
    fn is_alz(&self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
        cursor
            .read_u32::<LittleEndian>()
            .map_or(false, |n| ALZ_FILE_HEADER == n)
    }

    fn parse_local_fileheader<F>(
        &mut self,
        cursor: &mut std::io::Cursor<&Vec<u8>>,
        filepos: &mut usize,
        should_extract: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
    {
        let mut local_fileheader = AlzLocalFileHeader::new();

        local_fileheader.parse(cursor)?;

        let metadata_filepos = *filepos;
        *filepos = metadata_filepos.saturating_add(1);

        /* The is_file flag doesn't appear to always be set, so we'll just assume it's a file if
         * it's not marked as a directory.*/
        let metadata = AlzFileMetadata {
            file_name: &local_fileheader.file_name,
            compressed_size: local_fileheader.compressed_size,
            uncompressed_size: local_fileheader.uncompressed_size,
            is_directory: local_fileheader.is_directory(),
            is_encrypted: local_fileheader.is_encrypted(),
            file_crc: local_fileheader.file_crc,
            filepos: metadata_filepos,
        };

        let extraction_decision = should_extract(&metadata);
        if matches!(extraction_decision, AlzExtractionDecision::Stop) {
            return Err(Error::Stop);
        }

        if !local_fileheader.is_directory() {
            let AlzExtractionDecision::Extract(limits) = extraction_decision else {
                if !local_fileheader.has_valid_compressed_data_bounds() {
                    return Err(Error::Parse("Invalid compressed data length"));
                }

                return Ok(());
            };

            let support_error = local_fileheader.is_supported().err();
            if let Some(err) = support_error {
                if !local_fileheader.has_valid_compressed_data_bounds() {
                    return Err(Error::Parse("Invalid compressed data length"));
                }

                debug!("{err}");
                return Ok(());
            }

            let base_extracted_size = self.extracted_size;
            let max_total_remaining = limits.max_total_size.saturating_sub(base_extracted_size);
            let max_extracted_size = limits.max_file_size.min(max_total_remaining);
            let files_start = self.embedded_files.len();

            if self.scan_counted_files >= limits.max_files_remaining
                && !local_fileheader.is_known_scan_limit_exempt()
            {
                debug!(
                    "ALZ file {:?} skipped because the file count limit was reached.",
                    local_fileheader.file_name
                );
                self.file_count_limit_exceeded = true;
                return Err(Error::Stop);
            }

            if !local_fileheader.has_valid_compressed_data_bounds() {
                return Err(Error::Parse("Invalid compressed data length"));
            }

            let max_extracted_size = if local_fileheader.is_known_scan_limit_exempt() {
                local_fileheader.compressed_size
            } else if max_extracted_size <= MIN_SCANNED_FILE_SIZE as u64 {
                0
            } else {
                max_extracted_size
            };

            if max_extracted_size == 0 {
                debug!(
                    "ALZ file {:?} skipped because the extraction size budget is exhausted.",
                    local_fileheader.file_name
                );

                let needed = local_fileheader.scan_limit_size_hint();
                if needed > limits.max_file_size
                    && self
                        .file_limit_exceeded_size
                        .map_or(true, |current| current < needed)
                {
                    self.file_limit_exceeded_size = Some(needed);
                }

                let total_needed = base_extracted_size.saturating_add(needed);
                if total_needed > limits.max_total_size
                    && self
                        .total_limit_exceeded_size
                        .map_or(true, |current| current < total_needed)
                {
                    self.total_limit_exceeded_size = Some(total_needed);
                }

                return Ok(());
            }

            match local_fileheader.extract_file(
                cursor,
                &mut self.embedded_files,
                max_extracted_size,
            ) {
                Ok(()) => {}
                Err(Error::ScanLimitExceeded(needed)) => {
                    debug!(
                        "ALZ file {:?} exceeded extraction size limits. Scanning truncated content.",
                        local_fileheader.file_name
                    );
                    if needed > limits.max_file_size
                        && self
                            .file_limit_exceeded_size
                            .map_or(true, |current| current < needed)
                    {
                        self.file_limit_exceeded_size = Some(needed);
                    }

                    let total_needed = base_extracted_size.saturating_add(needed);
                    if total_needed > limits.max_total_size
                        && self
                            .total_limit_exceeded_size
                            .map_or(true, |current| current < total_needed)
                    {
                        self.total_limit_exceeded_size = Some(total_needed);
                    }
                }
                Err(Error::Extract) => {
                    debug!(
                        "Failed to extract ALZ file {:?}. Continuing with next entry.",
                        local_fileheader.file_name
                    );
                }
                Err(err) => return Err(err),
            }

            for file in &self.embedded_files[files_start..] {
                if !file.counts_toward_scan_limits() {
                    continue;
                }

                self.scan_counted_files = self.scan_counted_files.saturating_add(1);

                let Ok(file_size) = u64::try_from(file.data.len()) else {
                    self.extracted_size = u64::MAX;
                    break;
                };

                self.extracted_size = self.extracted_size.saturating_add(file_size);
            }
        } else if !local_fileheader.has_valid_compressed_data_bounds() {
            return Err(Error::Parse("Invalid compressed data length"));
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn parse_central_directoryheader(&self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
        /*
         * This is ignored in unalz (UnAlz.cpp ReadCentralDirectoryStructure).
         *
         * It actually reads 12 bytes, and I think it happens to work because EOF is hit on the next
         * read, which it does not consider an error.
         */
        let ret = cursor.read_u64::<LittleEndian>();
        ret.is_ok()
    }

    #[must_use]
    pub const fn new() -> Self {
        Self {
            embedded_files: Vec::new(),
            file_limit_exceeded_size: None,
            total_limit_exceeded_size: None,
            file_count_limit_exceeded: false,
            extracted_size: 0,
            scan_counted_files: 0,
            parse_error: false,
        }
    }

    pub const fn has_parse_error(&self) -> bool {
        self.parse_error
    }

    /// # Errors
    /// Will return `Error::Parse` if file headers are not correct or are inconsistent.
    pub fn from_bytes(bytes: &'aa [u8]) -> Result<Self, Error> {
        Self::from_bytes_with_filter(bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: usize::MAX,
            })
        })
    }

    /// # Errors
    /// Will return `Error::Parse` if file headers are not correct or are inconsistent.
    pub fn from_bytes_with_filter<F>(bytes: &'aa [u8], mut should_extract: F) -> Result<Self, Error>
    where
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
    {
        let binding = bytes.to_vec();
        let mut cursor = Cursor::new(&binding);

        let mut alz: Self = Self::new();
        let mut filepos: usize = 1;

        if !alz.is_alz(&mut cursor) {
            return Err(Error::Parse("No ALZ file header"));
        }

        //What these bytes are supposed to be in unspecified, but they need to be there.
        let ret = cursor.read_u32::<LittleEndian>();
        if ret.is_err() {
            return Err(Error::Parse("Error reading uint32 from file"));
        }

        loop {
            let Ok(sig) = cursor.read_u32::<LittleEndian>() else {
                break;
            };

            match sig {
                ALZ_LOCAL_FILE_HEADER => {
                    match alz.parse_local_fileheader(&mut cursor, &mut filepos, &mut should_extract)
                    {
                        Ok(()) => {}
                        Err(Error::Stop) => break,
                        Err(Error::Alloc) => return Err(Error::Alloc),
                        Err(err) => {
                            if filepos == 1 {
                                return Err(err);
                            }

                            debug!("Failed to parse ALZ local file header: {err}");
                            alz.parse_error = true;
                            break;
                        }
                    }
                    continue;
                }
                ALZ_CENTRAL_DIRECTORY_HEADER => {
                    if alz.parse_central_directoryheader(&mut cursor) {
                        continue;
                    }
                }
                ALZ_END_OF_CENTRAL_DIRECTORY_HEADER => {
                    break;
                    /*This is the end, nothing really to do here.*/
                }
                _ => {
                    #[allow(clippy::uninlined_format_args)]
                    let err = Error::UnrecognizedSig(format!("{:x}", sig));
                    if filepos == 1 {
                        return Err(err);
                    }

                    debug!("Failed to parse ALZ archive: {err}");
                    alz.parse_error = true;
                    break;
                }
            }
        }

        Ok(alz)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append_local_file(
        alz: &mut Vec<u8>,
        name: &str,
        compression_method: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        append_local_entry(
            alz,
            name,
            AlzFileAttribute::File as u8,
            0x10,
            compression_method,
            uncompressed_size,
            data,
        );
    }

    fn append_local_entry(
        alz: &mut Vec<u8>,
        name: &str,
        file_attribute: u8,
        file_descriptor: u8,
        compression_method: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        let compressed_size = u8::try_from(data.len()).unwrap();
        append_local_entry_with_sizes(
            alz,
            name,
            file_attribute,
            file_descriptor,
            compression_method,
            compressed_size,
            uncompressed_size,
            data,
        );
    }

    fn append_local_entry_with_sizes(
        alz: &mut Vec<u8>,
        name: &str,
        file_attribute: u8,
        file_descriptor: u8,
        compression_method: u8,
        compressed_size: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        let name = name.as_bytes();
        let name_len = u16::try_from(name.len()).unwrap();

        alz.extend_from_slice(&ALZ_LOCAL_FILE_HEADER.to_le_bytes());
        alz.extend_from_slice(&name_len.to_le_bytes());
        alz.push(file_attribute);
        alz.extend_from_slice(&0u32.to_le_bytes());
        alz.push(file_descriptor);
        alz.push(0);
        alz.push(compression_method);
        alz.push(0);
        alz.extend_from_slice(&0u32.to_le_bytes());
        alz.push(compressed_size);
        alz.push(uncompressed_size);
        alz.extend_from_slice(name);
        if file_descriptor & 0x01 != 0 {
            alz.extend_from_slice(&[0; ALZ_ENCR_HEADER_LEN as usize]);
        }
        alz.extend_from_slice(data);
    }

    fn extraction_limits() -> AlzExtractionLimits {
        AlzExtractionLimits {
            max_file_size: u64::MAX,
            max_total_size: u64::MAX,
            max_files_remaining: usize::MAX,
        }
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn bzip2_truncated_after_output() -> Vec<u8> {
        vec![
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xe5, 0x69, 0x95, 0xee,
            0x00, 0x00, 0x01, 0x17, 0x80, 0x00, 0x02, 0x02, 0x00, 0x44, 0x00, 0x2e, 0x24, 0x9c,
            0x20, 0x20, 0x00, 0x31, 0x4c, 0x00, 0x01, 0x4d, 0x31, 0x32, 0x7a, 0x9b, 0x41, 0xa9,
            0x5d, 0x57, 0xa3, 0xe0, 0x0b, 0x2c, 0x6f, 0x98, 0x2e, 0xe4, 0x8a, 0x70, 0xa1,
        ]
    }

    #[test]
    fn extraction_error_does_not_stop_later_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_BZIP2: u8 = 1;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "bad.bz2", ALZ_COMP_BZIP2, 1, &[0]);
        append_local_file(&mut bytes, "good.txt", ALZ_COMP_NOCOMP, 4, b"good");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("good.txt"));
        assert_eq!(alz.embedded_files[0].data, b"good");
    }

    #[test]
    fn bzip2_error_preserves_output_produced_before_error() {
        const ALZ_COMP_BZIP2: u8 = 1;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "truncated.bz2",
            ALZ_COMP_BZIP2,
            18,
            &bzip2_truncated_after_output(),
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("truncated.bz2"));
        assert_eq!(alz.embedded_files[0].data, b"Eicar-Test-Payload");
    }

    #[test]
    fn deflate_error_preserves_output_produced_before_error() {
        struct ErrorAfterOutput {
            output: Option<Vec<u8>>,
        }

        let payload = vec![b'A'; 9000];
        let mut reader = ErrorAfterOutput {
            output: Some(payload.clone()),
        };
        impl Read for ErrorAfterOutput {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let Some(output) = self.output.take() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "corrupt deflate stream",
                    ));
                };

                let len = output.len().min(buf.len());
                buf[..len].copy_from_slice(&output[..len]);
                self.output = if len < output.len() {
                    Some(output[len..].to_vec())
                } else {
                    None
                };

                Ok(len)
            }
        }

        let mut header = AlzLocalFileHeader::new();
        header.file_name = "corrupt.deflate".to_owned();
        let mut files = Vec::new();

        assert!(matches!(
            header.extract_file_deflate_reader(&mut reader, &mut files, u64::MAX),
            Err(Error::Extract)
        ));

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name.as_deref(), Some("corrupt.deflate"));
        assert_eq!(files[0].data, payload);
    }

    #[test]
    fn later_parse_error_preserves_earlier_extracted_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "good.txt", ALZ_COMP_NOCOMP, 4, b"good");
        bytes.extend_from_slice(&ALZ_LOCAL_FILE_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("good.txt"));
        assert_eq!(alz.embedded_files[0].data, b"good");
    }

    #[test]
    fn invalid_payload_bounds_reports_metadata_before_parse_error() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "secret.txt",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            10,
            10,
            b"x",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |entry| {
            metadata.push((
                entry.file_name.to_owned(),
                entry.filepos,
                entry.is_encrypted,
            ));
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(metadata, vec![("secret.txt".to_owned(), 1, true)]);
        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn deflate_limit_uses_decompressed_size_not_header() {
        const ALZ_COMP_DEFLATE: u8 = 2;
        let payload = vec![b'A'; 1024];
        let compressed = raw_deflate(&payload);
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "big.txt", ALZ_COMP_DEFLATE, 1, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 64,
                max_total_size: u64::MAX,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, Some(payload.len() as u64));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("big.txt"));
        assert_eq!(alz.embedded_files[0].data.as_slice(), &payload[..64]);
    }

    #[test]
    fn total_limit_does_not_set_per_file_limit() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        let payload = vec![b'A'; 60];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "a",
            ALZ_COMP_NOCOMP,
            payload.len() as u8,
            &payload,
        );
        append_local_file(
            &mut bytes,
            "b",
            ALZ_COMP_NOCOMP,
            payload.len() as u8,
            &payload,
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 64,
                max_total_size: 100,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, None);
        assert_eq!(alz.total_limit_exceeded_size, Some(120));
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].data.len(), 60);
        assert_eq!(alz.embedded_files[1].data.len(), 40);
    }

    #[test]
    fn exhausted_total_limit_skips_later_extraction() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_uses_stored_size_for_nocomp() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 0, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_records_compressed_entry_with_zero_declared_size() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 0, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_does_not_charge_empty_compressed_entry_by_declared_size() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "empty.deflate", ALZ_COMP_DEFLATE, 6, b"");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn tiny_stored_file_bypasses_partial_size_budget() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 5, b"tiny!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 4,
                max_total_size: 4,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, None);
        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[0].data, b"tiny!");
    }

    #[test]
    fn total_limit_skips_extraction_when_remaining_budget_is_tiny() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 10,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn total_limit_records_compressed_entry_when_remaining_budget_is_tiny() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 1, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 10,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_does_not_record_unsupported_method() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_UNSUPPORTED: u8 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(
            &mut bytes,
            "unsupported.bin",
            ALZ_COMP_UNSUPPORTED,
            6,
            b"second",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn unsupported_method_with_invalid_payload_bounds_reports_parse_error() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_UNSUPPORTED: u8 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "unsupported.bin",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_UNSUPPORTED,
            10,
            10,
            b"x",
        );
        append_local_file(&mut bytes, "later.txt", ALZ_COMP_NOCOMP, 6, b"later!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(metadata_names, vec!["unsupported.bin".to_owned()]);
        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn queued_file_limit_ignores_unsupported_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_entry(
            &mut bytes,
            "encrypted.bin",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            6,
            b"second",
        );
        append_local_entry(
            &mut bytes,
            "descriptor.bin",
            AlzFileAttribute::File as u8,
            0x18,
            ALZ_COMP_NOCOMP,
            5,
            b"third",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec![
                "first.txt".to_owned(),
                "encrypted.bin".to_owned(),
                "descriptor.bin".to_owned()
            ]
        );
        assert!(!alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn total_limit_ignores_tiny_members() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny1.txt", ALZ_COMP_NOCOMP, 1, b"t");
        append_local_file(&mut bytes, "tiny2.txt", ALZ_COMP_NOCOMP, 1, b"u");
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 3);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny1.txt"));
        assert_eq!(alz.embedded_files[0].data, b"t");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("tiny2.txt"));
        assert_eq!(alz.embedded_files[1].data, b"u");
        assert_eq!(alz.embedded_files[2].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[2].data, b"first!");
    }

    #[test]
    fn queued_file_limit_skips_later_extraction() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        append_local_file(&mut bytes, "third.txt", ALZ_COMP_NOCOMP, 6, b"third!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn queued_file_limit_stops_before_later_invalid_payload_bounds() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_entry_with_sizes(
            &mut bytes,
            "truncated.txt",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            10,
            10,
            b"x",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "truncated.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert!(!alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn queued_file_limit_ignores_tiny_members() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 1, b"t");
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec![
                "tiny.txt".to_owned(),
                "first.txt".to_owned(),
                "second.txt".to_owned()
            ]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[0].data, b"t");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[1].data, b"first!");
    }

    #[test]
    fn queued_file_limit_allows_tiny_current_member() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 1, b"t");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "tiny.txt".to_owned()]
        );
        assert!(!alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[1].data, b"t");
    }

    #[test]
    fn queued_file_limit_does_not_trust_compressed_tiny_hint() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 0, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn stop_decision_stops_archive_traversal() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Stop
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(metadata_names, vec!["first.txt".to_owned()]);
    }

    #[test]
    fn stop_decision_runs_for_directory_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry(
            &mut bytes,
            "dir/",
            AlzFileAttribute::Directory as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Stop
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(metadata_names, vec!["dir/".to_owned()]);
    }

    #[test]
    fn stop_decision_preserves_earlier_extracted_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            if metadata.file_name == "second.txt" {
                AlzExtractionDecision::Stop
            } else {
                AlzExtractionDecision::Extract(extraction_limits())
            }
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first");
    }

    #[test]
    fn metadata_file_positions_are_one_based_and_include_skipped_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry(
            &mut bytes,
            "dir/",
            AlzFileAttribute::Directory as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_entry(
            &mut bytes,
            "encrypted.bin",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_positions = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_positions.push((
                metadata.file_name.to_owned(),
                metadata.filepos,
                metadata.is_encrypted,
                metadata.is_directory,
            ));
            AlzExtractionDecision::Skip
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(
            metadata_positions,
            vec![
                ("dir/".to_owned(), 1, false, true),
                ("encrypted.bin".to_owned(), 2, true, false),
                ("first.txt".to_owned(), 3, false, false),
                ("second.txt".to_owned(), 4, false, false),
            ]
        );
    }
}
