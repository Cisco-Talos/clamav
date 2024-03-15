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
use bzip2::read::BzDecoder;
use inflate::InflateStream;
use log::debug;

/// File header
const ALZ_FILE_HEADER: u32 = 0x015a_4c41;
///Local file header
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a_4c42;
///Central directory header
const ALZ_CENTRAL_DIRECTORY_HEADER: u32 = 0x015a_4c43;
///End of Central directory header
const ALZ_END_OF_CENTRAL_DIRECTORY_HEADER: u32 = 0x025a_4c43;

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
        }
    }

    pub fn parse_internal(
        &mut self,
        cursor: &mut std::io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.head.file_name_length = cursor.read_u16::<LittleEndian>()?;
        self.head.file_attribute = cursor.read_u8()?;
        self.head.file_time_date = cursor.read_u32::<LittleEndian>()?;
        self.head.file_descriptor = cursor.read_u8()?;
        self.head.unknown = cursor.read_u8()?;

        if 0 == self.head.file_name_length {
            return Err(Box::new(ALZParseError::new("File Name Length is zero")));
        }

        let byte_len = self.head.file_descriptor / 0x10;
        if byte_len > 0 {
            self.compression_method = cursor.read_u8()?;
            self.unknown = cursor.read_u8()?;
            self.file_crc = cursor.read_u32::<LittleEndian>()?;

            match byte_len {
                1 => {
                    self.compressed_size = u64::from(cursor.read_u8()?);
                    self.uncompressed_size = u64::from(cursor.read_u8()?);
                }
                2 => {
                    self.compressed_size = u64::from(cursor.read_u16::<LittleEndian>()?);
                    self.uncompressed_size = u64::from(cursor.read_u16::<LittleEndian>()?);
                }
                4 => {
                    self.compressed_size = u64::from(cursor.read_u32::<LittleEndian>()?);
                    self.uncompressed_size = u64::from(cursor.read_u32::<LittleEndian>()?);
                }
                8 => {
                    self.compressed_size = cursor.read_u64::<LittleEndian>()?;
                    self.uncompressed_size = cursor.read_u64::<LittleEndian>()?;
                }
                _ => return Err(Box::new(ALZParseError::new("Unsupported File Descriptor"))),
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let idx0: usize = cursor.position() as usize;
        let idx1: usize = idx0 + self.head.file_name_length as usize;

        if idx1 > cursor.get_ref().len() {
            return Err(Box::new(ALZParseError::new("Invalid file name length")));
        }

        let filename = &cursor.get_ref().as_slice()[idx0..idx1];
        cursor.set_position(idx1 as u64);

        self.file_name = String::from_utf8_lossy(filename).into_owned();

        if self.is_encrypted() {
            cursor.read_exact(&mut self.enc_chk)?;
        }

        self.start_of_compressed_data = cursor.position();
        cursor.set_position(self.start_of_compressed_data + self.compressed_size);

        if self.start_of_compressed_data + self.compressed_size > cursor.get_ref().len() as u64 {
            return Err(Box::new(ALZParseError::new(
                "Invalid compressed data length",
            )));
        }

        Ok(())
    }

    pub fn parse(&mut self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> Result<(), ALZParseError> {
        let result = self.parse_internal(cursor);
        if result.is_err() {
            let e = result.err().unwrap();
            if e.is::<ALZParseError>() {
                let ape: ALZParseError = *e.downcast::<ALZParseError>().unwrap();
                return Err(ape);
            }
            return Err(ALZParseError::new("Not ALZ"));
        }

        Ok(())
    }

    pub fn is_supported(&self) -> Result<(), ALZUnsupportedError> {
        if self.is_encrypted() {
            return Err(ALZUnsupportedError::new(
                "Encryption Unsupported".to_string(),
            ));
        }

        if self.is_data_descriptor() {
            return Err(ALZUnsupportedError::new(
                "Data Descriptors are Unsupported".to_string(),
            ));
        }

        Ok(())
    }

    /*
     * This has no header/checksum validation.
     */
    fn extract_file_deflate(
        &mut self,
        cursor: &std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
    ) -> Result<(), ALZExtractError> {
        #[allow(clippy::cast_possible_truncation)]
        let start: usize = self.start_of_compressed_data as usize;
        #[allow(clippy::cast_possible_truncation)]
        let end: usize = start + self.compressed_size as usize;
        if end >= cursor.get_ref().len() {
            return Err(ALZExtractError {});
        }
        let data: &[u8] = &cursor.get_ref().as_slice()[start..end];

        let mut inflater = InflateStream::new();
        let mut out: Vec<u8> = Vec::<u8>::new();
        let mut n: usize = 0;

        while n < data.len() {
            let res = inflater.update(&data[n..]);
            if let Ok((num_bytes_read, result)) = res {
                n += num_bytes_read;
                out.extend(result.iter().copied());
            } else {
                return Err(ALZExtractError {});
            }
        }

        self.write_file(&out, files);

        Ok(())
    }

    fn write_file(&mut self, buffer: &[u8], files: &mut Vec<ExtractedFile>) {
        let extracted_file: ExtractedFile = ExtractedFile {
            name: Some(self.file_name.to_string()),
            data: buffer.to_vec(),
        };

        files.push(extracted_file);
    }

    fn extract_file_nocomp(
        &mut self,
        cursor: &mut std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
    ) -> Result<(), ALZExtractError> {
        #[allow(clippy::cast_possible_truncation)]
        let idx0: usize = self.start_of_compressed_data as usize;

        let mut len = self.compressed_size;
        if self.compressed_size != self.uncompressed_size {
            info!("Uncompressed file has different lengths for compressed vs uncompressed, using the shorter");
            if self.compressed_size > self.uncompressed_size {
                len = self.uncompressed_size;
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let idx1: usize = idx0 + len as usize;
        if idx1 > cursor.get_ref().len() {
            info!("Invalid data length");
            return Err(ALZExtractError {});
        }

        let contents = &cursor.get_ref().as_slice()[idx0..idx1];
        cursor.set_position(idx1 as u64);

        self.write_file(contents, files);
        Ok(())
    }

    fn extract_file_bzip2(
        &mut self,
        cursor: &std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
    ) -> Result<(), ALZExtractError> {
        #[allow(clippy::cast_possible_truncation)]
        let idx0: usize = self.start_of_compressed_data as usize;
        #[allow(clippy::cast_possible_truncation)]
        let idx1: usize = idx0 + self.compressed_size as usize;

        let contents = &cursor.get_ref().as_slice()[idx0..idx1];

        /*
         * Create vector of the needed capacity.
         */
        let mut out: Vec<u8> = Vec::new();
        for _i in 0..self.uncompressed_size {
            out.push(0);
        }

        let mut decompressor = BzDecoder::new(contents);
        let ret = decompressor.read_exact(&mut out);
        if ret.is_err() {
            info!("Unable to decompress bz2 data");
            return Err(ALZExtractError {});
        }

        self.write_file(&out, files);
        Ok(())
    }

    fn extract_file(
        &mut self,
        cursor: &mut std::io::Cursor<&Vec<u8>>,
        files: &mut Vec<ExtractedFile>,
    ) -> Result<(), ALZExtractError> {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_BZIP2: u8 = 1;
        const ALZ_COMP_DEFLATE: u8 = 2;

        match self.compression_method {
            ALZ_COMP_NOCOMP => self.extract_file_nocomp(cursor, files),
            ALZ_COMP_BZIP2 => self.extract_file_bzip2(cursor, files),
            ALZ_COMP_DEFLATE => self.extract_file_deflate(cursor, files),
            _ => Err(ALZExtractError {}),
        }
    }
}

/*TODO: Merge this with the onenote extracted_file struct, and use the same one everywhere.*/
pub struct ExtractedFile {
    pub name: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct Alz {
    pub embedded_files: Vec<ExtractedFile>,
}

impl<'aa> Alz {
    /* Check for the ALZ file header. */
    #[allow(clippy::unused_self)]
    fn is_alz(&self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
        cursor
            .read_u32::<LittleEndian>()
            .map_or(false, |n| ALZ_FILE_HEADER == n)
    }

    fn parse_local_fileheader(&mut self, cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
        let mut local_fileheader = AlzLocalFileHeader::new();

        let parse_result = local_fileheader.parse(cursor);
        if parse_result.is_err() {
            /*This is safe, since I called is_err*/
            let e: ALZParseError = parse_result.err().unwrap();
            info!("{}", e.get_description());
            return false;
        }

        if let Err(err) = local_fileheader.is_supported() {
            info!("{err}");
            return false;
        }

        if !local_fileheader.is_directory() {
            /* The is_file flag doesn't appear to always be set, so we'll just assume it's a file if
             * it's not marked as a directory.*/
            let res2 = local_fileheader.extract_file(cursor, &mut self.embedded_files);
            if res2.is_err() {
                return false;
            }
        }

        true
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
        }
    }

    /// # Errors
    /// Will return `ALZParseError` if file headers are not correct or are inconsistent.
    pub fn from_bytes(bytes: &'aa [u8]) -> Result<Self, ALZParseError> {
        let binding = bytes.to_vec();
        let mut cursor = Cursor::new(&binding);

        let mut alz: Self = Self::new();

        if !alz.is_alz(&mut cursor) {
            return Err(ALZParseError::new("No ALZ file header"));
        }

        //What these bytes are supposed to be in unspecified, but they need to be there.
        let ret = cursor.read_u32::<LittleEndian>();
        if ret.is_err() {
            return Err(ALZParseError::new("Error reading uint32 from file"));
        }

        loop {
            let Ok(sig) = cursor.read_u32::<LittleEndian>() else {
                break;
            };

            match sig {
                ALZ_LOCAL_FILE_HEADER => {
                    if alz.parse_local_fileheader(&mut cursor) {
                        continue;
                    }
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
                    return Err(ALZParseError::new(format!(
                        "Parse Error, unrecognized sig = '{:x}'",
                        sig
                    )));
                }
            }
        }

        Ok(alz)
    }
}
