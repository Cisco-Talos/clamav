// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust `WWPack` PE unpacking helpers.
//!
//! This module ports `ClamAV` `libclamav/wwunpack.c` plus the PE32 dispatch
//! checks from `libclamav/pe.c`. `WWPack` works by reconstructing a mapped PE
//! image, decompressing blocks described by the final packer section, then
//! removing that packer section from the rebuilt image.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> mapped image reconstruction -> final-section block table
//!     -> bounded block decompression -> image with packer section removed
//! ```
//!
//! The mapped image size is capped and PE64 inputs are rejected to preserve
//! `ClamAV`'s PE32-only `WWPack` path.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{PeAnalysis, PeSection},
};

const MAX_WWPACK_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) type WwpackUnpacked = UnpackedArtifact;

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<WwpackUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("wwpack_pe64_not_supported_by_clamav");
    }
    if analysis.sections.len() <= 1 {
        return Err("wwpack_section_count_too_low");
    }
    let ep_rva = analysis.entrypoint_rva.ok_or("wwpack_entrypoint_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep_rva
        != analysis
            .sections
            .last()
            .map_or(0, |section| section.virtual_address)
        || ep.get(..7) != Some(&[0x53, 0x55, 0x8b, 0xe8, 0x33, 0xdb, 0xeb])
        || ep.get(0x68..0x68 + 19)
            != Some(
                &[
                    0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x2d, 0x6d, 0x00, 0x00, 0x00, 0x50, 0x60,
                    0x33, 0xc9, 0x50, 0x58, 0x50, 0x50,
                ][..],
            )
    {
        return Err("wwpack_stub_not_recognized");
    }
    let packer_index = analysis.sections.len() - 1;
    let packer_section = &analysis.sections[packer_index];
    let mut head = packer_section.raw_offset;
    let mut image_size = 0u32;
    for section in &analysis.sections[..packer_index] {
        if section.raw_offset < head {
            head = section.raw_offset;
        }
        let end = section
            .virtual_address
            .checked_add(section.virtual_size)
            .ok_or("wwpack_image_size_overflow")?;
        image_size = image_size.max(end);
    }
    if head == 0 || image_size == 0 || head > image_size {
        return Err("wwpack_image_layout_invalid");
    }
    if u64::from(image_size) > MAX_WWPACK_IMAGE_BYTES {
        return Err("wwpack_image_size_limit_exceeded");
    }
    let mut image =
        vec![0u8; usize::try_from(image_size).map_err(|_| "wwpack_image_size_overflow")?];
    let head = usize::try_from(head).map_err(|_| "wwpack_header_size_overflow")?;
    image
        .get_mut(..head)
        .ok_or("wwpack_header_range_invalid")?
        .copy_from_slice(bytes.get(..head).ok_or("wwpack_header_range_invalid")?);
    for section in &analysis.sections[..packer_index] {
        if section.raw_size == 0 {
            continue;
        }
        let src = source_section_bytes(bytes, section).ok_or("wwpack_section_range_invalid")?;
        let dst =
            usize::try_from(section.virtual_address).map_err(|_| "wwpack_section_rva_overflow")?;
        image
            .get_mut(
                dst..dst
                    .checked_add(src.len())
                    .ok_or("wwpack_mapped_section_range_invalid")?,
            )
            .ok_or("wwpack_mapped_section_range_invalid")?
            .copy_from_slice(src);
    }
    let packer =
        source_section_bytes(bytes, packer_section).ok_or("wwpack_packer_range_invalid")?;
    unpack_blocks(&mut image, packer, &analysis.sections, packer_index)?;
    patch_headers(&mut image, packer, &analysis.sections, packer_index)?;
    Ok(UnpackedArtifact {
        bytes: image,
        source_offset: packer_section.start,
        source_size: u64::from(packer_section.raw_size),
    })
}

fn unpack_blocks(
    image: &mut [u8],
    packer: &[u8],
    sections: &[PeSection],
    packer_index: usize,
) -> Result<(), &'static str> {
    let packer_section = &sections[packer_index];
    let mut structs = 0x2a1usize;
    let mut compd = Vec::new();
    loop {
        if structs.checked_add(17).is_none_or(|end| end > packer.len()) {
            return Err("wwpack_struct_table_out_of_bounds");
        }
        let delta = read_u32_le(packer, structs).ok_or("wwpack_delta_missing")?;
        let src = packer_section
            .virtual_address
            .checked_sub(delta)
            .ok_or("wwpack_source_delta_invalid")?;
        structs += 8;
        let szd = read_u32_le(packer, structs)
            .and_then(|value| value.checked_mul(4))
            .ok_or("wwpack_compressed_size_invalid")?;
        structs += 4;
        let srcend = read_u32_le(packer, structs).ok_or("wwpack_source_end_missing")?;
        structs += 4;
        let unpd = src
            .checked_add(srcend)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_sub(szd))
            .ok_or("wwpack_unpacked_offset_invalid")?;
        let unpd = usize::try_from(unpd).map_err(|_| "wwpack_unpacked_offset_overflow")?;
        let szd = usize::try_from(szd).map_err(|_| "wwpack_compressed_size_overflow")?;
        let unpd_end = unpd
            .checked_add(szd)
            .ok_or("wwpack_compressed_range_invalid")?;
        snapshot_compressed_block(image, unpd, unpd_end, &mut compd)?;
        image
            .get_mut(unpd..unpd_end)
            .ok_or("wwpack_compressed_range_invalid")?
            .fill(0xff);
        decompress_one_block(&compd, image, unpd)?;
        let Some(next) = packer.get(structs).copied() else {
            return Err("wwpack_struct_terminator_missing");
        };
        structs += 1;
        if next == 0 {
            break;
        }
    }
    Ok(())
}

fn snapshot_compressed_block(
    image: &[u8],
    start: usize,
    end: usize,
    scratch: &mut Vec<u8>,
) -> Result<(), &'static str> {
    scratch.clear();
    scratch.extend_from_slice(
        image
            .get(start..end)
            .ok_or("wwpack_compressed_range_invalid")?,
    );
    Ok(())
}

fn decompress_one_block(
    compd: &[u8],
    image: &mut [u8],
    mut ucur: usize,
) -> Result<(), &'static str> {
    let mut bits = WwBitReader::new(compd)?;
    loop {
        if !bits.bit()? {
            let byte = bits.next_byte()?;
            let out = image.get_mut(ucur).ok_or("wwpack_output_out_of_bounds")?;
            *out = byte;
            ucur = ucur.checked_add(1).ok_or("wwpack_output_offset_overflow")?;
            continue;
        }

        let mode = bits.bits(2)?;
        if mode == 3 {
            let Some(backbytes) = decode_mode_three_backref(&mut bits)? else {
                break;
            };
            copy_backref(image, &mut ucur, backbytes, 2)?;
            continue;
        }

        let (backbytes, backsize) = decode_general_backref(&mut bits, mode)?;
        copy_backref(image, &mut ucur, backbytes, backsize)?;
    }
    Ok(())
}

fn decode_mode_three_backref(bits: &mut WwBitReader<'_>) -> Result<Option<usize>, &'static str> {
    let mut shifted = ww_u32_to_u8(
        bits.bits(2)?
            .checked_add(5)
            .ok_or("wwpack_shift_width_overflow")?,
        "wwpack_shift_width_overflow",
    )?;
    let mut subbed = 31u32;
    if shifted >= 7 {
        shifted += 1;
        subbed += 0x80;
    }
    let mut backbytes = (1u32 << shifted) - subbed;
    let value = bits.bits(shifted)?;
    if value == 0x1ff {
        return Ok(None);
    }
    backbytes = backbytes
        .checked_add(value)
        .ok_or("wwpack_backref_overflow")?;
    Ok(Some(ww_u32_to_usize(backbytes, "wwpack_backref_overflow")?))
}

fn decode_general_backref(
    bits: &mut WwBitReader<'_>,
    saved: u32,
) -> Result<(usize, usize), &'static str> {
    let selector = bits.bits(3)?;
    let backbytes = match selector {
        0..=2 => {
            let width = selector + 5;
            bits.bits(ww_u32_to_u8(width, "wwpack_backref_width_overflow")?)?
                .checked_add((1u32 << width) - 31)
                .ok_or("wwpack_backref_overflow")?
        }
        3 | 4 => {
            let width = selector + u32::from(bits.bit()?) + 5 + u32::from(selector == 4);
            bits.bits(ww_u32_to_u8(width, "wwpack_backref_width_overflow")?)?
                .checked_add((1u32 << width) - 31)
                .ok_or("wwpack_backref_overflow")?
        }
        5 => bits
            .bits(12)?
            .checked_add((1u32 << 12) - 31)
            .ok_or("wwpack_backref_overflow")?,
        6 => bits
            .bits(0x0e)?
            .checked_add(0x1fe1)
            .ok_or("wwpack_backref_overflow")?,
        _ => bits
            .bits(0x0f)?
            .checked_add(0x5fe1)
            .ok_or("wwpack_backref_overflow")?,
    };

    let backsize = if saved == 0 {
        if bits.bit()? {
            let short = bits.bits(3)?;
            if short != 0 {
                short + 6
            } else {
                let medium = bits.bits(4)?;
                if medium != 0 {
                    medium + 13
                } else {
                    let mut count = 4u8;
                    let mut shifted = 0x0du32;
                    loop {
                        if count == 7 {
                            count = 0x0e;
                            shifted = 0;
                            break;
                        }
                        shifted = ((shifted + 2) << 1) - 1;
                        let bit = bits.bit()?;
                        count += 1;
                        if bit {
                            break;
                        }
                    }
                    bits.bits(count)?
                        .checked_add(shifted)
                        .ok_or("wwpack_backsize_overflow")?
                }
            }
        } else {
            u32::from(bits.bit()?) + 5
        }
    } else {
        saved + 2
    };
    Ok((
        ww_u32_to_usize(backbytes, "wwpack_backref_overflow")?,
        ww_u32_to_usize(backsize, "wwpack_backsize_overflow")?,
    ))
}

fn patch_headers(
    image: &mut [u8],
    packer: &[u8],
    sections: &[PeSection],
    packer_index: usize,
) -> Result<(), &'static str> {
    let pe = read_u32_le(image, 0x3c)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("wwpack_pe_offset_missing")?;
    let packer_section = &sections[packer_index];
    write_u16(
        image,
        pe.checked_add(6).ok_or("wwpack_pe_offset_overflow")?,
        ww_usize_to_u16(packer_index, "wwpack_section_count_overflow")?,
    )?;
    let ep = read_u32_le(packer, 0x295)
        .ok_or("wwpack_entrypoint_missing")?
        .wrapping_add(packer_section.virtual_address)
        .wrapping_add(0x299);
    write_u32(
        image,
        pe.checked_add(0x28).ok_or("wwpack_pe_offset_overflow")?,
        ep,
    )?;
    let image_size = read_u32_le(
        image,
        pe.checked_add(0x50).ok_or("wwpack_pe_offset_overflow")?,
    )
    .and_then(|value| value.checked_sub(packer_section.virtual_size))
    .ok_or("wwpack_image_size_patch_invalid")?;
    write_u32(
        image,
        pe.checked_add(0x50).ok_or("wwpack_pe_offset_overflow")?,
        image_size,
    )?;

    let optional_header_size = read_u32_le(
        image,
        pe.checked_add(0x14).ok_or("wwpack_pe_offset_overflow")?,
    )
    .ok_or("wwpack_optional_size_missing")?
        & 0xffff;
    let optional_header_size =
        ww_u32_to_usize(optional_header_size, "wwpack_optional_size_overflow")?;
    let mut section_header = pe
        .checked_add(0x18)
        .and_then(|value| value.checked_add(optional_header_size))
        .ok_or("wwpack_section_header_overflow")?;
    for section in &sections[..packer_index] {
        write_u32(
            image,
            section_header
                .checked_add(8)
                .ok_or("wwpack_section_header_overflow")?,
            section.virtual_size,
        )?;
        write_u32(
            image,
            section_header
                .checked_add(12)
                .ok_or("wwpack_section_header_overflow")?,
            section.virtual_address,
        )?;
        write_u32(
            image,
            section_header
                .checked_add(16)
                .ok_or("wwpack_section_header_overflow")?,
            section.virtual_size,
        )?;
        write_u32(
            image,
            section_header
                .checked_add(20)
                .ok_or("wwpack_section_header_overflow")?,
            section.virtual_address,
        )?;
        section_header = section_header
            .checked_add(0x28)
            .ok_or("wwpack_section_header_overflow")?;
    }
    image
        .get_mut(
            section_header
                ..section_header
                    .checked_add(0x28)
                    .ok_or("wwpack_section_header_overflow")?,
        )
        .ok_or("wwpack_packer_section_header_out_of_bounds")?
        .fill(0);
    Ok(())
}

struct WwBitReader<'a> {
    source: &'a [u8],
    cursor: usize,
    bits: u32,
    remaining: u8,
}

impl<'a> WwBitReader<'a> {
    fn new(source: &'a [u8]) -> Result<Self, &'static str> {
        let mut reader = Self {
            source,
            cursor: 0,
            bits: 0,
            remaining: 0,
        };
        reader.reseed()?;
        Ok(reader)
    }

    fn bit(&mut self) -> Result<bool, &'static str> {
        Ok(self.bits(1)? != 0)
    }

    fn bits(&mut self, count: u8) -> Result<u32, &'static str> {
        if count == 0 || count > 31 {
            return Err("wwpack_invalid_bit_count");
        }
        let count_u32 = u32::from(count);
        let mut value = self.bits >> (32 - count_u32);
        if self.remaining >= count {
            self.remaining -= count;
            self.bits <<= count_u32;
            if self.remaining == 0 {
                self.reseed()?;
            }
        } else {
            self.bits =
                read_u32_le(self.source, self.cursor).ok_or("wwpack_bitstream_exhausted")?;
            self.cursor = self
                .cursor
                .checked_add(4)
                .ok_or("wwpack_input_offset_overflow")?;
            self.remaining = self.remaining + 32 - count;
            value |= self.bits >> u32::from(self.remaining);
            self.bits <<= 32 - u32::from(self.remaining);
        }
        Ok(value)
    }

    fn next_byte(&mut self) -> Result<u8, &'static str> {
        let byte = *self
            .source
            .get(self.cursor)
            .ok_or("wwpack_input_out_of_bounds")?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or("wwpack_input_offset_overflow")?;
        Ok(byte)
    }

    fn reseed(&mut self) -> Result<(), &'static str> {
        self.bits = read_u32_le(self.source, self.cursor).ok_or("wwpack_bitstream_exhausted")?;
        self.cursor = self
            .cursor
            .checked_add(4)
            .ok_or("wwpack_input_offset_overflow")?;
        self.remaining = 32;
        Ok(())
    }
}

fn copy_backref(
    image: &mut [u8],
    cursor: &mut usize,
    backbytes: usize,
    backsize: usize,
) -> Result<(), &'static str> {
    if backbytes == 0 {
        return Err("wwpack_zero_backref");
    }
    let mut src = cursor
        .checked_sub(backbytes)
        .ok_or("wwpack_backref_before_start")?;
    let end = cursor
        .checked_add(backsize)
        .ok_or("wwpack_output_offset_overflow")?;
    if end > image.len() {
        return Err("wwpack_output_out_of_bounds");
    }
    while *cursor < end {
        let byte = *image.get(src).ok_or("wwpack_backref_out_of_bounds")?;
        image[*cursor] = byte;
        src = src.checked_add(1).ok_or("wwpack_backref_offset_overflow")?;
        *cursor = cursor
            .checked_add(1)
            .ok_or("wwpack_output_offset_overflow")?;
    }
    Ok(())
}

fn source_section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let start = usize::try_from(section.start).ok()?;
    let size = usize::try_from(section.raw_size).ok()?;
    bytes.get(start..start.checked_add(size)?)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn ww_u32_to_u8(value: u32, error: &'static str) -> Result<u8, &'static str> {
    u8::try_from(value).map_err(|_| error)
}

fn ww_u32_to_usize(value: u32, error: &'static str) -> Result<usize, &'static str> {
    usize::try_from(value).map_err(|_| error)
}

fn ww_usize_to_u16(value: usize, error: &'static str) -> Result<u16, &'static str> {
    u16::try_from(value).map_err(|_| error)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), &'static str> {
    bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or("wwpack_header_write_out_of_bounds")?,
        )
        .ok_or("wwpack_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or("wwpack_header_write_out_of_bounds")?,
        )
        .ok_or("wwpack_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_block_snapshot_reuses_scratch() {
        let image = [0, 1, 2, 3, 4, 5];
        let mut scratch = vec![9, 9, 9, 9];

        snapshot_compressed_block(&image, 2, 5, &mut scratch).unwrap();
        assert_eq!(scratch, vec![2, 3, 4]);

        assert_eq!(
            snapshot_compressed_block(&image, 4, 8, &mut scratch),
            Err("wwpack_compressed_range_invalid")
        );
        assert!(scratch.is_empty());
    }
}
