//! LZIP format implementation.

mod reader;
mod stream;

#[cfg(feature = "std")]
mod reader_mt;

#[cfg(feature = "encoder")]
mod writer;

#[cfg(all(feature = "encoder", feature = "std"))]
mod writer_mt;

#[cfg(feature = "std")]
use std::io::{Seek, SeekFrom};

pub use reader::LzipReader;
#[cfg(feature = "std")]
pub use reader_mt::LzipReaderMt;
pub use stream::LzipStream;
#[cfg(feature = "encoder")]
pub use writer::{LzipOptions, LzipWriter};
#[cfg(all(feature = "encoder", feature = "std"))]
pub use writer_mt::LzipWriterMt;

use crate::{ByteReader, Read, Result, error_invalid_data, error_invalid_input};

const LZIP_MAGIC: [u8; 4] = *b"LZIP";

const LZIP_VERSION: u8 = 1;

const HEADER_SIZE: usize = 6;

const TRAILER_SIZE: usize = 20;

const MIN_DICT_SIZE: u32 = 4 * 1024;

const MAX_DICT_SIZE: u32 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct LzipHeader {
    version: u8,
    dict_size: u32,
}

impl LzipHeader {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if magic != LZIP_MAGIC {
            return Err(error_invalid_data("invalid LZIP magic bytes"));
        }

        let version = reader.read_u8()?;
        if version != LZIP_VERSION {
            return Err(error_invalid_data("unsupported LZIP version"));
        }

        let dict_size_byte = reader.read_u8()?;
        let dict_size = decode_dict_size(dict_size_byte)?;

        Ok(LzipHeader { version, dict_size })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LzipTrailer {
    crc32: u32,
    data_size: u64,
    member_size: u64,
}

impl LzipTrailer {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        let crc32 = reader.read_u32()?;
        let data_size = reader.read_u64()?;
        let member_size = reader.read_u64()?;

        Ok(LzipTrailer {
            crc32,
            data_size,
            member_size,
        })
    }
}

/// Decode LZIP dictionary size from encoded byte:
///
/// The dictionary size is calculated by taking a power of 2 (the base size)
/// and subtracting from it a fraction between 0/16 and 7/16 of the base size.
///
/// - Bits 4-0: contain the base 2 logarithm of the base size (12 to 29)
/// - Bits 7-5: contain the numerator of the fraction (0 to 7) to subtract
///
/// Example: 0xD3 = 2^19 - 6 * 2^15 = 512 KiB - 6 * 32 KiB = 320 KiB
fn decode_dict_size(encoded: u8) -> Result<u32> {
    let base_log2 = (encoded & 0x1F) as u32;
    let fraction_num = (encoded >> 5) as u32;

    if !(12..=29).contains(&base_log2) {
        return Err(error_invalid_data("invalid LZIP dictionary size base"));
    }

    if fraction_num > 7 {
        return Err(error_invalid_data("invalid LZIP dictionary size fraction"));
    }

    let base_size = 1u32 << base_log2;
    let fraction_size = if base_log2 >= 4 {
        (base_size >> 4) * fraction_num
    } else {
        0 // Should not happen with base_log2 >= 12
    };

    let dict_size = base_size - fraction_size;

    if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size) {
        return Err(error_invalid_data("LZIP dictionary size out of range"));
    }

    Ok(dict_size)
}

/// Encode dictionary size to LZIP format.
///
/// The dictionary size is encoded as:
/// - Bits 4-0: base 2 logarithm of the base size (12 to 29)
/// - Bits 7-5: numerator of the fraction (0 to 7) to subtract from base size
fn encode_dict_size(dict_size: u32) -> Result<u8> {
    if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size) {
        return Err(error_invalid_input(
            "LZIP dictionary size out of valid range",
        ));
    }

    // Find the smallest power of 2 that is >= dict_size.
    let mut base_log2 = 32 - dict_size.leading_zeros() - 1;
    if (1u32 << base_log2) < dict_size {
        base_log2 += 1;
    }

    if base_log2 < 12 {
        base_log2 = 12;
    }

    if base_log2 > 29 {
        return Err(error_invalid_input("dictionary size too large"));
    }

    let base_size = 1u32 << base_log2;

    // Calculate the fraction to subtract
    let mut fraction_num = 0u32;
    if base_size > dict_size {
        let diff = base_size - dict_size;
        let fraction_unit = base_size >> 4; // 1/16 of base_size

        if fraction_unit > 0 {
            // Round up.
            fraction_num = diff.div_ceil(fraction_unit);
            if fraction_num > 7 {
                // Need to use a larger base.
                base_log2 += 1;
                if base_log2 > 29 {
                    return Err(error_invalid_input("dictionary size too large"));
                }
                fraction_num = 0;
            }
        }
    }

    Ok(((fraction_num << 5) | (base_log2 & 0x1F)) as u8)
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct LzipMember {
    start_pos: u64,
    compressed_size: u64,
}

/// Scan the LZIP file to collect information about all members.
/// This reads from the back of the file to efficiently locate member boundaries.
#[cfg(feature = "std")]
fn scan_members<R: Read + Seek>(mut reader: R) -> Result<(R, Vec<LzipMember>)> {
    let file_size = reader.seek(SeekFrom::End(0))?;

    if file_size < (HEADER_SIZE + TRAILER_SIZE) as u64 {
        return Err(error_invalid_data(
            "file too small to contain a valid LZIP member",
        ));
    }

    let mut members = Vec::new();
    let mut current_pos = file_size;

    while current_pos > 0 {
        if current_pos < TRAILER_SIZE as u64 {
            break;
        }

        // Seek to read the trailer (last 20 bytes of current member).
        reader.seek(SeekFrom::Start(current_pos - TRAILER_SIZE as u64))?;
        let mut trailer_buf = [0u8; TRAILER_SIZE];
        reader.read_exact(&mut trailer_buf)?;

        // member_size is in bytes 12-19 of the trailer (little endian)
        let member_size = u64::from_le_bytes([
            trailer_buf[12],
            trailer_buf[13],
            trailer_buf[14],
            trailer_buf[15],
            trailer_buf[16],
            trailer_buf[17],
            trailer_buf[18],
            trailer_buf[19],
        ]);

        if member_size == 0 || member_size > current_pos {
            return Err(error_invalid_data("invalid LZIP member size in trailer"));
        }

        let member_start = current_pos - member_size;

        // Verify this looks like a valid LZIP header.
        reader.seek(SeekFrom::Start(member_start))?;
        let mut header_buf = [0u8; 4];
        reader.read_exact(&mut header_buf)?;

        if header_buf != *b"LZIP" {
            return Err(error_invalid_data("invalid LZIP magic bytes"));
        }

        members.push(LzipMember {
            start_pos: member_start,
            compressed_size: member_size,
        });

        current_pos = member_start;
    }

    reader.seek(SeekFrom::Start(0))?;

    if members.is_empty() {
        return Err(error_invalid_data("no valid LZIP members found"));
    }

    // Reverse to get members in forward order.
    members.reverse();

    Ok((reader, members))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_dict_size() {
        let dict_size = decode_dict_size(0xD3).unwrap();
        assert_eq!(dict_size, 320 * 1024);

        // base_log2=12, fraction=0
        let dict_size = decode_dict_size(0x0C).unwrap();
        assert_eq!(dict_size, 4 * 1024);

        // base_log2=29, fraction=0
        let dict_size = decode_dict_size(0x1D).unwrap();
        assert_eq!(dict_size, 512 * 1024 * 1024);

        assert!(decode_dict_size(0x0B).is_err());
        assert!(decode_dict_size(0x1E).is_err());
    }

    #[test]
    fn test_encode_dict_size() {
        assert_eq!(encode_dict_size(4 * 1024).unwrap(), 0x0C);
        assert_eq!(encode_dict_size(512 * 1024 * 1024).unwrap(), 0x1D);

        assert_eq!(encode_dict_size(320 * 1024).unwrap(), 0xD3);

        assert!(encode_dict_size(1024).is_err());
        assert!(encode_dict_size(1024 * 1024 * 1024).is_err());
    }
}
