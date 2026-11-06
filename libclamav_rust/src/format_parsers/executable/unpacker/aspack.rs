// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust `ASPack` PE unpacking helpers.
//!
//! This module ports the `ASPack` 2.12 / 2.1x / 2.42 path from `ClamAV`
//! `libclamav/aspack.c` and the PE32 dispatch checks from `libclamav/pe.c`.
//! `ClamAV` only runs this legacy unpacker after the PE32+ bail, so PE64 inputs
//! are reported as unsupported instead of being guessed.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> ASPack marker/version -> block table + entrypoint buffer
//!     -> decode blocks into bounded image buffer -> rebuild PE sections
//! ```
//!
//! The decoder caps rebuilt image bytes and rejects PE64 inputs to preserve
//! `ClamAV`'s legacy dispatch boundary.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_ASPACK_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

const BLOCKS_OFFSET_212: usize = 0x57c;
const BLOCKS_OFFSET_OTHER: usize = 0x5d8;
const BLOCKS_OFFSET_242: usize = 0x5e4;
const EPBUFF_OFFSET_212: usize = 0x3b9;
const EPBUFF_OFFSET_OTHER: usize = 0x41f;
const EPBUFF_OFFSET_242: usize = 0x42b;
const STR_INIT_MLT_OFFSET_212: usize = 0x70e;
const STR_INIT_MLT_OFFSET_OTHER: usize = 0x76a;
const STR_INIT_MLT_OFFSET_242: usize = 0x776;
const COMP_BLOCK_OFFSET_212: usize = 0x6d6;
const COMP_BLOCK_OFFSET_OTHER: usize = 0x732;
const COMP_BLOCK_OFFSET_242: usize = 0x73e;
const STUFF_TABLE_BYTES: usize = 0x72;
const WRKBUF_OFFSET_212: usize = 0x148;
const WRKBUF_OFFSET_OTHER: usize = 0x13a;
const WRKBUF_OFFSET_242: usize = 0x148;
const OEP_OFFSET_212: usize = 0x39b;
const OEP_OFFSET_OTHER: usize = 0x401;
const OEP_OFFSET_242: usize = 0x40d;

pub(crate) type AspackUnpacked = UnpackedArtifact;

#[derive(Clone, Copy)]
enum AspackVersion {
    V212,
    Other,
    V242,
}

impl AspackVersion {
    fn offsets(self) -> AspackOffsets {
        match self {
            Self::V212 => AspackOffsets {
                blocks: BLOCKS_OFFSET_212,
                stream_init_multiplier: STR_INIT_MLT_OFFSET_212,
                comp_block: COMP_BLOCK_OFFSET_212,
                wrkbuf: WRKBUF_OFFSET_212,
                oep: OEP_OFFSET_212,
                block_step: 8,
            },
            Self::Other => AspackOffsets {
                blocks: BLOCKS_OFFSET_OTHER,
                stream_init_multiplier: STR_INIT_MLT_OFFSET_OTHER,
                comp_block: COMP_BLOCK_OFFSET_OTHER,
                wrkbuf: WRKBUF_OFFSET_OTHER,
                oep: OEP_OFFSET_OTHER,
                block_step: 12,
            },
            Self::V242 => AspackOffsets {
                blocks: BLOCKS_OFFSET_242,
                stream_init_multiplier: STR_INIT_MLT_OFFSET_242,
                comp_block: COMP_BLOCK_OFFSET_242,
                wrkbuf: WRKBUF_OFFSET_242,
                oep: OEP_OFFSET_242,
                block_step: 12,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct AspackOffsets {
    blocks: usize,
    stream_init_multiplier: usize,
    comp_block: usize,
    wrkbuf: usize,
    oep: usize,
    block_step: usize,
}

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<AspackUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("aspack_pe64_not_supported_by_clamav");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "aspack_image_base_out_of_range")?;
    let ep_rva = analysis.entrypoint_rva.ok_or("aspack_entrypoint_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep.len() < 0x3bf || ep.get(..8) != Some(&[0x60, 0xe8, 0x03, 0, 0, 0, 0xe9, 0xeb]) {
        return Err("aspack_stub_not_recognized");
    }
    let version = if ep.get(EPBUFF_OFFSET_212..EPBUFF_OFFSET_212 + 6)
        == Some(&[0x68, 0, 0, 0, 0, 0xc3])
    {
        AspackVersion::V212
    } else if ep.get(EPBUFF_OFFSET_OTHER..EPBUFF_OFFSET_OTHER + 6)
        == Some(&[0x68, 0, 0, 0, 0, 0xc3])
    {
        AspackVersion::Other
    } else if ep.get(EPBUFF_OFFSET_242..EPBUFF_OFFSET_242 + 6) == Some(&[0x68, 0, 0, 0, 0, 0xc3]) {
        AspackVersion::V242
    } else {
        return Err("aspack_version_not_recognized");
    };
    let ep = ep_rva.checked_sub(1).ok_or("aspack_entrypoint_underflow")?;
    let mut image = map_sections_by_rva(bytes, &analysis.sections)?;
    let source_size = bytes.len() as u64;
    let (section_count, oep) = unpack_mapped_image(&mut image, &analysis.sections, ep, version)?;
    let mut rebuild_sections = Vec::with_capacity(section_count);
    for section in analysis.sections.iter().take(section_count) {
        rebuild_sections.push(RebuildSection {
            source_offset: section.virtual_address,
            rva: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_size: section.virtual_size,
        });
    }
    let bytes = rebuild::rebuild_pe_from_sections(
        &image,
        &rebuild_sections,
        RebuildOptions::pe32(image_base, oep),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: 0,
        source_size,
    })
}

fn unpack_mapped_image(
    image: &mut [u8],
    sections: &[PeSection],
    ep: u32,
    version: AspackVersion,
) -> Result<(usize, u32), &'static str> {
    let offsets = version.offsets();
    let ep = usize::try_from(ep).map_err(|_| "aspack_entrypoint_overflow")?;
    let mut stream = AspackStream::new();
    let mut j = 0u32;
    for i in 0..58usize {
        stream.init_array[i] = j;
        let multiplier_offset = ep
            .checked_add(i)
            .and_then(|offset| offset.checked_add(offsets.stream_init_multiplier))
            .ok_or("aspack_init_array_offset_overflow")?;
        if let Some(multiplier) = image.get(multiplier_offset) {
            j = j
                .checked_add(1u32.checked_shl(u32::from(*multiplier)).unwrap_or(0))
                .ok_or("aspack_init_array_overflow")?;
        }
    }

    let mut blocks = ep
        .checked_add(offsets.blocks)
        .ok_or("aspack_blocks_offset_overflow")?;
    let mut first_block = true;
    loop {
        let block_rva = read_u32_le(image, blocks).ok_or("aspack_block_table_out_of_bounds")?;
        let block_size = read_u32_le(
            image,
            blocks
                .checked_add(4)
                .ok_or("aspack_blocks_offset_overflow")?,
        )
        .ok_or("aspack_block_table_out_of_bounds")?;
        if block_rva == 0 {
            break;
        }
        if block_size == 0 {
            return Err("aspack_zero_block_size");
        }
        let block_rva = usize::try_from(block_rva).map_err(|_| "aspack_block_rva_overflow")?;
        let block_size = usize::try_from(block_size).map_err(|_| "aspack_block_size_overflow")?;
        let block_end = block_rva
            .checked_add(block_size)
            .ok_or("aspack_block_range_invalid")?;
        if block_end > image.len() {
            return Err("aspack_block_range_invalid");
        }

        stream.prepare_block_input(&image[block_rva..block_end], block_size)?;
        let stuff_start = ep
            .checked_add(offsets.comp_block)
            .ok_or("aspack_comp_block_offset_overflow")?;
        if stuff_start > image.len() {
            return Err("aspack_comp_block_out_of_bounds");
        }
        if stuff_start >= block_end {
            let (before_stuff, after_stuff) = image.split_at_mut(stuff_start);
            let stuff = bounded_stuff_table(after_stuff);
            let output = before_stuff
                .get_mut(block_rva..block_end)
                .ok_or("aspack_block_range_invalid")?;
            stream.decomp_prepared_block(block_size, stuff, output)?;
        } else {
            let stuff = bounded_stuff_table(
                image
                    .get(stuff_start..)
                    .ok_or("aspack_comp_block_out_of_bounds")?,
            )
            .to_vec();
            let output = image
                .get_mut(block_rva..block_end)
                .ok_or("aspack_block_range_invalid")?;
            stream.decomp_prepared_block(block_size, &stuff, output)?;
        }

        if first_block && block_size > 7 {
            fix_first_block_calls(image, block_rva, block_size, ep, offsets.wrkbuf)?;
        }
        first_block = false;

        blocks = blocks
            .checked_add(offsets.block_step)
            .ok_or("aspack_blocks_offset_overflow")?;
        if offsets.block_step == 12 {
            while read_u32_le(
                image,
                blocks
                    .checked_add(4)
                    .ok_or("aspack_blocks_offset_overflow")?,
            )
            .and_then(|size| size.checked_add(0x10e))
                == Some(0)
            {
                blocks = blocks
                    .checked_add(12)
                    .ok_or("aspack_blocks_offset_overflow")?;
            }
        }
    }

    patch_headers(image, sections, ep, offsets.oep)
}

fn bounded_stuff_table(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(STUFF_TABLE_BYTES)]
}

fn fix_first_block_calls(
    image: &mut [u8],
    block_rva: usize,
    block_size: usize,
    ep: usize,
    wrkbuf_offset: usize,
) -> Result<(), &'static str> {
    let marker = *image
        .get(
            ep.checked_add(wrkbuf_offset)
                .ok_or("aspack_wrkbuf_offset_overflow")?,
        )
        .ok_or("aspack_wrkbuf_marker_missing")?;
    let mut i = 0usize;
    while i < block_size - 6 {
        let block_offset = block_rva
            .checked_add(i)
            .ok_or("aspack_block_offset_overflow")?;
        let cur = image[block_offset];
        let marker_offset = block_offset
            .checked_add(1)
            .ok_or("aspack_block_offset_overflow")?;
        if (cur == 0xe8 || cur == 0xe9) && image.get(marker_offset) == Some(&marker) {
            let target_offset = marker_offset;
            let mut target = read_u32_le(image, target_offset)
                .ok_or("aspack_call_target_missing")?
                & 0xffff_ff00;
            target = target.rotate_left(0x18);
            let patched =
                target.wrapping_sub(u32::try_from(i).map_err(|_| "aspack_block_offset_overflow")?);
            write_u32(image, target_offset, patched)?;
            i = i.checked_add(4).ok_or("aspack_block_offset_overflow")?;
        }
        i = i.checked_add(1).ok_or("aspack_block_offset_overflow")?;
    }
    Ok(())
}

fn patch_headers(
    image: &mut [u8],
    sections: &[PeSection],
    ep: usize,
    oep_offset: usize,
) -> Result<(usize, u32), &'static str> {
    let pe = read_u32_le(image, 0x3c)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("aspack_pe_offset_missing")?;
    let mut section_count = sections.len();
    if section_count > 2
        && Some(u32::try_from(ep).map_err(|_| "aspack_entrypoint_overflow")?)
            == sections
                .get(section_count - 2)
                .map(|section| section.virtual_address)
        && sections
            .get(section_count - 1)
            .is_some_and(|section| section.raw_size == 0)
    {
        section_count -= 2;
    }
    write_u16(
        image,
        pe + 6,
        u16::try_from(section_count).map_err(|_| "aspack_section_count_overflow")?,
    )?;
    let oep = read_u32_le(
        image,
        ep.checked_add(oep_offset)
            .ok_or("aspack_oep_offset_overflow")?,
    )
    .ok_or("aspack_oep_missing")?;
    write_u32(image, pe + 0x28, oep)?;
    let optional_header_size =
        read_u16_le(image, pe + 0x14).ok_or("aspack_optional_size_missing")?;
    let mut section_header = pe
        .checked_add(0x18)
        .and_then(|value| value.checked_add(optional_header_size as usize))
        .ok_or("aspack_section_header_overflow")?;
    for section in sections.iter().take(section_count) {
        write_u32(image, section_header + 16, section.virtual_size)?;
        write_u32(image, section_header + 20, section.virtual_address)?;
        section_header = section_header
            .checked_add(0x28)
            .ok_or("aspack_section_header_overflow")?;
    }
    for _ in section_count..sections.len() {
        let end = section_header
            .checked_add(0x28)
            .ok_or("aspack_section_header_overflow")?;
        if let Some(raw) = image.get_mut(section_header..end) {
            raw.fill(0);
        }
        section_header = end;
    }
    Ok((section_count, oep))
}

struct AspackStream {
    bitpos: u32,
    hash: u32,
    init_array: [u32; 58],
    dict_starts: [Vec<u32>; 4],
    dict_ends: [[u8; 256]; 4],
    dict_sizes: [usize; 4],
    input: Vec<u8>,
    cursor: usize,
    decrypt_dict: [u8; 757],
    decarray3: [[u32; 24]; 4],
    decarray4: [[u32; 24]; 4],
    dict_ok: bool,
    array2: [u8; 758],
    array1: [u8; 19],
}

impl AspackStream {
    fn new() -> Self {
        Self {
            bitpos: 0,
            hash: 0x10000,
            init_array: [0; 58],
            dict_starts: [vec![0; 721], vec![0; 28], vec![0; 8], vec![0; 19]],
            dict_ends: [[0; 256]; 4],
            dict_sizes: [721, 28, 8, 19],
            input: Vec::new(),
            cursor: 0,
            decrypt_dict: [0; 757],
            decarray3: [[0; 24]; 4],
            decarray4: [[0; 24]; 4],
            dict_ok: false,
            array2: [0; 758],
            array1: [0; 19],
        }
    }

    fn prepare_block_input(&mut self, input: &[u8], size: usize) -> Result<(), &'static str> {
        if input.len() != size {
            return Err("aspack_input_size_mismatch");
        }
        self.decarray3 = [[0; 24]; 4];
        self.decarray4 = [[0; 24]; 4];
        self.decrypt_dict = [0; 757];
        self.bitpos = 0x20;
        self.hash = 0x10000;
        let work_size = size.checked_add(0x10e).ok_or("aspack_work_size_overflow")?;
        self.input.clear();
        self.input.resize(work_size, 0);
        self.input[..size].copy_from_slice(input);
        self.cursor = 0;
        self.build_decrypt_dictionaries()
    }

    fn decomp_prepared_block(
        &mut self,
        size: usize,
        stuff: &[u8],
        output: &mut [u8],
    ) -> Result<(), &'static str> {
        self.decrypt(stuff, size, output)
    }

    fn readstream(&mut self) -> Result<(), &'static str> {
        while self.bitpos >= 8 {
            let byte = *self
                .input
                .get(self.cursor)
                .ok_or("aspack_input_out_of_bounds")?;
            self.hash = (self.hash << 8) | u32::from(byte);
            self.cursor = self
                .cursor
                .checked_add(1)
                .ok_or("aspack_input_offset_overflow")?;
            self.bitpos -= 8;
        }
        Ok(())
    }

    fn getbits(&mut self, num: u32) -> Result<u8, &'static str> {
        self.readstream()?;
        let value = ((self.hash >> (8 - self.bitpos)) & 0x00ff_ffff) >> (24 - num);
        self.bitpos = self
            .bitpos
            .checked_add(num)
            .ok_or("aspack_bitpos_overflow")?;
        u8::try_from(value).map_err(|_| "aspack_bit_value_overflow")
    }

    fn getdec(&mut self, which: usize) -> Result<u32, &'static str> {
        self.readstream()?;
        let ret = (self.hash >> (8 - self.bitpos)) & 0x00ff_fe00;
        let d3 = self.decarray3[which];
        let d4 = self.decarray4[which];
        let pos = if ret < d3[8] {
            let index = usize::try_from(ret >> 16).map_err(|_| "aspack_decode_index_overflow")?;
            if index >= 0x100 {
                return Err("aspack_decode_index_out_of_bounds");
            }
            let pos = self.dict_ends[which][index];
            if pos == 0 || pos >= 24 {
                return Err("aspack_decode_position_invalid");
            }
            pos
        } else if ret < d3[10] {
            if ret < d3[9] { 9 } else { 10 }
        } else if ret < d3[11] {
            11
        } else if ret < d3[12] {
            12
        } else if ret < d3[13] {
            13
        } else if ret < d3[14] {
            14
        } else {
            15
        };
        self.bitpos = self
            .bitpos
            .checked_add(u32::from(pos))
            .ok_or("aspack_bitpos_overflow")?;
        let pos = usize::from(pos);
        let value = ((ret - d3[pos - 1]) >> (24 - pos)) + d4[pos];
        let index = usize::try_from(value).map_err(|_| "aspack_decode_value_overflow")?;
        if index >= self.dict_sizes[which] {
            return Err("aspack_decode_value_out_of_bounds");
        }
        Ok(self.dict_starts[which][index])
    }

    fn build_decrypt_array(&mut self, array: &[u8], which: usize) -> Result<(), &'static str> {
        let mut sum = 0u32;
        let mut counter = 23u32;
        let mut endoff = 0u32;
        let mut bus = [0u32; 18];
        let mut dict = [0u32; 18];
        self.dict_ends[which] = [0; 256];
        for &value in array.iter().take(self.dict_sizes[which]) {
            if value > 17 {
                return Err("aspack_dictionary_width_invalid");
            }
            bus[usize::from(value)] += 1;
        }
        self.decarray3[which][0] = 0;
        self.decarray4[which][0] = 0;
        let mut i = 0usize;
        while counter >= 9 {
            sum = sum
                .checked_add(bus[i + 1].checked_shl(counter).unwrap_or(0))
                .ok_or("aspack_dictionary_sum_overflow")?;
            if sum > 0x0100_0000 {
                return Err("aspack_dictionary_sum_invalid");
            }
            self.decarray3[which][i + 1] = sum;
            self.decarray4[which][i + 1] = bus[i] + self.decarray4[which][i];
            dict[i + 1] = self.decarray4[which][i + 1];
            if counter >= 0x10 {
                let old = endoff;
                endoff = self.decarray3[which][i + 1] >> 0x10;
                if endoff < old || endoff > 0x100 {
                    return Err("aspack_dictionary_end_invalid");
                }
                let start = usize::try_from(old).map_err(|_| "aspack_dictionary_end_invalid")?;
                let end = usize::try_from(endoff).map_err(|_| "aspack_dictionary_end_invalid")?;
                let pos = u8::try_from(i + 1).map_err(|_| "aspack_dictionary_end_invalid")?;
                for slot in &mut self.dict_ends[which][start..end] {
                    *slot = pos;
                }
            }
            i += 1;
            counter -= 1;
        }
        if sum != 0x0100_0000 {
            return Err("aspack_dictionary_sum_incomplete");
        }
        for (i, &width) in array.iter().take(self.dict_sizes[which]).enumerate() {
            if width == 0 {
                continue;
            }
            if width > 17 {
                return Err("aspack_dictionary_width_invalid");
            }
            let width_index = usize::from(width);
            let dict_index = usize::try_from(dict[width_index])
                .map_err(|_| "aspack_dictionary_index_overflow")?;
            if dict_index >= self.dict_sizes[which] {
                return Err("aspack_dictionary_index_out_of_bounds");
            }
            self.dict_starts[which][dict_index] =
                u32::try_from(i).map_err(|_| "aspack_dictionary_index_overflow")?;
            dict[width_index] += 1;
        }
        Ok(())
    }

    fn build_decrypt_dictionaries(&mut self) -> Result<(), &'static str> {
        if self.getbits(1)? == 0 {
            self.decrypt_dict = [0; 757];
        }
        for counter in 0..19usize {
            self.array1[counter] = self.getbits(4)?;
        }
        let array1 = self.array1;
        self.build_decrypt_array(&array1, 3)?;
        let mut counter = 0usize;
        while counter < 757 {
            let ret = self.getdec(3)?;
            if ret >= 16 {
                if ret == 16 {
                    let mut count = 3 + u32::from(self.getbits(2)?);
                    while count != 0 {
                        if counter >= 757 {
                            break;
                        }
                        self.array2[1 + counter] = self.array2[counter];
                        counter += 1;
                        count -= 1;
                    }
                } else {
                    let mut count = if ret == 17 {
                        3 + u32::from(self.getbits(3)?)
                    } else {
                        11 + u32::from(self.getbits(7)?)
                    };
                    while count != 0 {
                        if counter >= 757 {
                            break;
                        }
                        self.array2[1 + counter] = 0;
                        counter += 1;
                        count -= 1;
                    }
                }
            } else {
                let ret_low = u8::try_from(ret).map_err(|_| "aspack_dictionary_width_invalid")?;
                self.array2[1 + counter] = (self.decrypt_dict[counter] + ret_low) & 0x0f;
                counter += 1;
            }
        }
        let array2 = self.array2;
        self.build_decrypt_array(&array2[1..758], 0)?;
        self.build_decrypt_array(&array2[722..758], 1)?;
        self.build_decrypt_array(&array2[750..758], 2)?;
        self.dict_ok = self.array2[750..758].iter().any(|&value| value != 3);
        self.decrypt_dict.copy_from_slice(&self.array2[1..758]);
        Ok(())
    }

    fn decrypt(
        &mut self,
        stuff: &[u8],
        size: usize,
        output: &mut [u8],
    ) -> Result<(), &'static str> {
        let mut counter = 0usize;
        let mut hist = [0u32; 4];
        while counter < size {
            let token = self.getdec(0)?;
            if token < 256 {
                let byte = u8::try_from(token).map_err(|_| "aspack_literal_out_of_bounds")?;
                *output
                    .get_mut(counter)
                    .ok_or("aspack_output_out_of_bounds")? = byte;
                counter += 1;
                continue;
            }
            if token >= 720 {
                self.build_decrypt_dictionaries()?;
                continue;
            }
            let mut backbytes = (token - 256) >> 3;
            let mut backsize = ((token - 256) & 7) + 2;
            if backsize - 2 == 7 {
                let index = self.getdec(1)?;
                if index >= 0x56 {
                    return Err("aspack_length_index_out_of_bounds");
                }
                let index =
                    usize::try_from(index).map_err(|_| "aspack_length_index_out_of_bounds")?;
                let width = *stuff
                    .get(index + 0x1c)
                    .ok_or("aspack_length_table_missing")?;
                self.readstream()?;
                let extra = ((self.hash >> (8 - self.bitpos)) & 0x00ff_ffff) >> (0x18 - width);
                self.bitpos += u32::from(width);
                backsize = backsize
                    .checked_add(u32::from(
                        *stuff.get(index).ok_or("aspack_length_table_missing")?,
                    ))
                    .and_then(|value| value.checked_add(extra))
                    .ok_or("aspack_backsize_overflow")?;
            }
            let backbytes_index =
                usize::try_from(backbytes).map_err(|_| "aspack_init_array_out_of_bounds")?;
            let mut useold = self
                .init_array
                .get(backbytes_index)
                .copied()
                .ok_or("aspack_init_array_out_of_bounds")?;
            let mut width = u32::from(
                *stuff
                    .get(backbytes_index + 0x38)
                    .ok_or("aspack_backref_table_missing")?,
            );
            if !self.dict_ok || width < 3 {
                self.readstream()?;
                useold = useold
                    .checked_add(((self.hash >> (8 - self.bitpos)) & 0x00ff_ffff) >> (24 - width))
                    .ok_or("aspack_backref_overflow")?;
                self.bitpos += width;
            } else {
                width -= 3;
                self.readstream()?;
                useold = useold
                    .checked_add(
                        (((self.hash >> (8 - self.bitpos)) & 0x00ff_ffff) >> (24 - width)) * 8,
                    )
                    .ok_or("aspack_backref_overflow")?;
                self.bitpos += width;
                useold = useold
                    .checked_add(self.getdec(2)?)
                    .ok_or("aspack_backref_overflow")?;
            }
            if useold < 3 {
                let useold_index = usize::try_from(useold).map_err(|_| "aspack_history_invalid")?;
                backbytes = hist[useold_index];
                if useold != 0 {
                    hist[useold_index] = hist[0];
                    hist[0] = backbytes;
                }
            } else {
                hist[2] = hist[1];
                hist[1] = hist[0];
                backbytes = useold - 3;
                hist[0] = backbytes;
            }
            backbytes = backbytes.checked_add(1).ok_or("aspack_backref_overflow")?;
            let backbytes = usize::try_from(backbytes).map_err(|_| "aspack_backref_overflow")?;
            let backsize = usize::try_from(backsize).map_err(|_| "aspack_backsize_overflow")?;
            if backbytes == 0 || backbytes > counter || backsize > size - counter {
                return Err("aspack_backref_out_of_bounds");
            }
            for _ in 0..backsize {
                output[counter] = output[counter - backbytes];
                counter += 1;
            }
        }
        Ok(())
    }
}

fn map_sections_by_rva(bytes: &[u8], sections: &[PeSection]) -> Result<Vec<u8>, &'static str> {
    let mut size = 0u32;
    let mut header_size = None::<u32>;
    for section in sections {
        header_size =
            Some(header_size.map_or(section.raw_offset, |size| size.min(section.raw_offset)));
        size = size.max(
            section
                .virtual_address
                .checked_add(section.virtual_size)
                .ok_or("aspack_image_size_overflow")?,
        );
    }
    if size == 0 || u64::from(size) > MAX_ASPACK_IMAGE_BYTES {
        return Err("aspack_image_size_limit_exceeded");
    }
    let mut image = vec![0u8; usize::try_from(size).map_err(|_| "aspack_image_size_overflow")?];
    let header_size = usize::try_from(header_size.ok_or("aspack_missing_sections")?)
        .map_err(|_| "aspack_header_size_overflow")?;
    image
        .get_mut(..header_size)
        .ok_or("aspack_header_range_invalid")?
        .copy_from_slice(
            bytes
                .get(..header_size)
                .ok_or("aspack_header_range_invalid")?,
        );
    for section in sections {
        if section.raw_size == 0 {
            continue;
        }
        let src = section_bytes(bytes, section).ok_or("aspack_section_range_invalid")?;
        let dst =
            usize::try_from(section.virtual_address).map_err(|_| "aspack_section_rva_overflow")?;
        let end = dst
            .checked_add(src.len())
            .ok_or("aspack_mapped_section_range_invalid")?;
        image
            .get_mut(dst..end)
            .ok_or("aspack_mapped_section_range_invalid")?
            .copy_from_slice(src);
    }
    Ok(image)
}

fn section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let start = usize::try_from(section.start).ok()?;
    let size = usize::try_from(section.raw_size).ok()?;
    bytes.get(start..start.checked_add(size)?)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), &'static str> {
    bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or("aspack_header_write_out_of_bounds")?,
        )
        .ok_or("aspack_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or("aspack_header_write_out_of_bounds")?,
        )
        .ok_or("aspack_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_aspack_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "aspack_entrypoint_missing"
        );
    }

    #[test]
    fn stuff_table_view_is_bounded_to_decoder_indices() {
        let bytes = vec![0u8; STUFF_TABLE_BYTES + 64];

        assert_eq!(bounded_stuff_table(&bytes).len(), STUFF_TABLE_BYTES);
        assert_eq!(bounded_stuff_table(&bytes[..16]).len(), 16);
    }

    #[test]
    fn block_input_is_loaded_with_decoder_padding() {
        let mut stream = AspackStream::new();
        let input = [0u8; 4];

        assert_eq!(
            stream.prepare_block_input(&input[..3], input.len()),
            Err("aspack_input_size_mismatch")
        );
        let _ = stream.prepare_block_input(&input, input.len());

        assert_eq!(stream.input.len(), input.len() + 0x10e);
        assert_eq!(&stream.input[..input.len()], &input);
        assert!(stream.input[input.len()..].iter().all(|byte| *byte == 0));
    }
}
