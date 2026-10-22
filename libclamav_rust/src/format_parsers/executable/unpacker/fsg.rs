// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust FSG PE unpacking helpers.
//!
//! This module ports the bounded FSG decompression primitive from `ClamAV`
//! `libclamav/packlibs.c` plus the PE32 FSG 2.00 / 1.33 / 1.31 dispatch logic
//! from `libclamav/pe.c`. `ClamAV` does not run these legacy FSG paths for PE32+
//! inputs; this module records that distinction explicitly instead of trying to
//! guess a PE64 variant.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> FSG version dispatch -> compressed section stream
//!     -> bounded FSG decode -> rebuilt PE artifact
//! ```
//!
//! The decoder uses ClamAV-compatible PE32 version checks and caps unpacked
//! bytes before emitting an artifact for the shared rebuild path.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_FSG_UNPACKED_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) type FsgUnpacked = UnpackedArtifact;

pub(crate) fn unpack_pe(bytes: &[u8], analysis: &PeAnalysis) -> Result<FsgUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("fsg_pe64_not_supported_by_clamav");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "fsg_image_base_out_of_range")?;
    let pair = find_empty_section_pair(&analysis.sections).ok_or("fsg_section_pair_not_found")?;
    let empty = &analysis.sections[pair];
    let packed = &analysis.sections[pair + 1];
    let ep_rva = analysis.entrypoint_rva.ok_or("fsg_entrypoint_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);

    if ep.get(0..2) == Some(&[0x87, 0x25]) {
        return unpack_200(bytes, image_base, empty, packed, ep);
    }

    let min_rva = analysis
        .sections
        .iter()
        .map(|section| section.virtual_address)
        .min()
        .unwrap_or_default();
    let size_of_headers = analysis.size_of_headers.unwrap_or_default();
    if ep.first() == Some(&0xbe)
        && read_u32_le(ep, 1)
            .and_then(|value| va_to_rva(value, image_base))
            .is_some_and(|rva| rva < min_rva)
    {
        return unpack_133(
            bytes,
            image_base,
            size_of_headers,
            empty,
            packed,
            ep_rva,
            ep,
        );
    }

    if ep.first() == Some(&0xbb)
        && ep.get(5) == Some(&0xbf)
        && ep.get(10) == Some(&0xbe)
        && read_u32_le(ep, 1)
            .and_then(|value| va_to_rva(value, image_base))
            .is_some_and(|rva| rva < min_rva)
        && ep_rva >= packed.virtual_address
        && ep_rva
            .checked_sub(packed.virtual_address)
            .zip(packed.virtual_address.checked_sub(0xe0))
            .is_some_and(|(entry_delta, virtual_slack)| entry_delta > virtual_slack)
    {
        return unpack_131(
            bytes,
            image_base,
            size_of_headers,
            empty,
            packed,
            ep_rva,
            ep,
        );
    }

    Err("fsg_stub_not_recognized")
}

#[expect(
    clippy::similar_names,
    reason = "local names mirror unpacker x86 register names"
)]
fn unpack_200(
    bytes: &[u8],
    image_base: u32,
    empty: &PeSection,
    packed: &PeSection,
    ep: &[u8],
) -> Result<FsgUnpacked, &'static str> {
    let source = section_bytes(bytes, packed).ok_or("fsg_source_range_invalid")?;
    let source_offset = packed.start;
    let source_size = u64::from(packed.raw_size);
    let dsize = checked_dsize(empty.virtual_size)?;

    let mut stack_rva = read_u32_le(ep, 2)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_stack_pointer_invalid")?;
    if !section_contains_rva(packed, stack_rva, 4) {
        return Err("fsg_stack_pointer_out_of_bounds");
    }
    let stack_offset = usize::try_from(stack_rva - packed.virtual_address)
        .map_err(|_| "fsg_stack_offset_overflow")?;
    stack_rva = read_u32_le(source, stack_offset)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_stack_target_invalid")?;
    if !section_contains_rva(packed, stack_rva, 32) {
        return Err("fsg_stack_target_out_of_bounds");
    }
    let stack_offset = usize::try_from(stack_rva - packed.virtual_address)
        .map_err(|_| "fsg_stack_offset_overflow")?;

    let newedi = read_u32_le(source, stack_offset)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_destination_invalid")?;
    let newesi = read_u32_le(
        source,
        stack_offset
            .checked_add(4)
            .ok_or("fsg_stack_offset_overflow")?,
    )
    .and_then(|value| va_to_rva(value, image_base))
    .ok_or("fsg_source_invalid")?;
    let newebx = read_u32_le(
        source,
        stack_offset
            .checked_add(16)
            .ok_or("fsg_stack_offset_overflow")?,
    )
    .and_then(|value| va_to_rva(value, image_base))
    .ok_or("fsg_function_table_invalid")?;

    if newedi != empty.virtual_address {
        return Err("fsg_destination_mismatch");
    }
    if !section_contains_rva(packed, newesi, 1) {
        return Err("fsg_source_out_of_bounds");
    }
    if !section_contains_rva(packed, newebx, 16) {
        return Err("fsg_function_table_out_of_bounds");
    }
    let function_table_offset = usize::try_from(newebx - packed.virtual_address)
        .map_err(|_| "fsg_function_table_offset_overflow")?;
    let old_ep = read_u32_le(
        source,
        function_table_offset
            .checked_add(12)
            .ok_or("fsg_function_table_offset_overflow")?,
    )
    .and_then(|value| va_to_rva(value, image_base))
    .ok_or("fsg_old_entrypoint_invalid")?;

    let compressed_offset = usize::try_from(newesi - packed.virtual_address)
        .map_err(|_| "fsg_source_offset_overflow")?;
    let decompressed = unfsg_to_vec(&source[compressed_offset..], dsize)?;
    let bytes = rebuild::rebuild_pe_from_sections(
        &decompressed,
        &[RebuildSection {
            source_offset: 0,
            rva: empty.virtual_address,
            virtual_size: u32::try_from(dsize).map_err(|_| "fsg_unpacked_size_overflow")?,
            raw_size: u32::try_from(decompressed.len())
                .map_err(|_| "fsg_unpacked_size_overflow")?,
        }],
        RebuildOptions::pe32(image_base, old_ep),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: source_offset
            .checked_add(compressed_offset as u64)
            .ok_or("fsg_source_offset_overflow")?,
        source_size: source_size
            .checked_sub(compressed_offset as u64)
            .ok_or("fsg_source_size_underflow")?,
    })
}

#[expect(
    clippy::similar_names,
    reason = "local names mirror unpacker x86 register names"
)]
fn unpack_133(
    bytes: &[u8],
    image_base: u32,
    size_of_headers: u32,
    empty: &PeSection,
    packed: &PeSection,
    ep_rva: u32,
    ep: &[u8],
) -> Result<FsgUnpacked, &'static str> {
    let support_rva = read_u32_le(ep, 1)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_support_rva_invalid")?;
    let support_offset = rawaddr_header_only(support_rva, bytes.len(), size_of_headers)
        .ok_or("fsg_support_offset_invalid")?;
    let gp = usize::try_from(packed.raw_offset)
        .ok()
        .and_then(|raw| raw.checked_sub(support_offset))
        .ok_or("fsg_support_size_invalid")?;
    let support = bytes
        .get(
            support_offset
                ..support_offset
                    .checked_add(gp)
                    .ok_or("fsg_support_size_invalid")?,
        )
        .ok_or("fsg_support_range_invalid")?;
    if support.len() < 16 {
        return Err("fsg_support_too_short");
    }
    let newedi = read_u32_le(support, 4)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_destination_invalid")?;
    let newesi = read_u32_le(support, 8)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_source_invalid")?;
    if newedi != empty.virtual_address {
        return Err("fsg_destination_mismatch");
    }
    if !section_contains_rva(packed, newesi, 1) {
        return Err("fsg_source_out_of_bounds");
    }

    let mut section_rvas = vec![newedi];
    let mut cursor = 12usize;
    while cursor
        .checked_add(4)
        .is_some_and(|end| end <= support.len())
    {
        let Some(raw_rva) = read_u32_le(support, cursor) else {
            break;
        };
        if raw_rva == 0 {
            break;
        }
        let rva = raw_rva
            .checked_sub(image_base)
            .and_then(|value| value.checked_sub(1))
            .ok_or("fsg_original_section_rva_invalid")?;
        if !rva_within_unpacked(empty, rva) {
            return Err("fsg_original_section_out_of_bounds");
        }
        section_rvas.push(rva);
        cursor = cursor
            .checked_add(4)
            .ok_or("fsg_section_table_offset_overflow")?;
    }
    if cursor.checked_add(4).is_none_or(|end| end > support.len())
        || read_u32_le(support, cursor) != Some(0)
    {
        return Err("fsg_section_table_terminator_missing");
    }

    let old_ep = read_i32_le(ep, 163)
        .and_then(|delta| {
            i64::from(ep_rva)
                .checked_add(161)
                .and_then(|value| value.checked_add(6))
                .and_then(|value| value.checked_add(i64::from(delta)))
        })
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("fsg_old_entrypoint_invalid")?;
    unpack_segments(
        bytes,
        image_base,
        packed,
        empty.virtual_size,
        newesi,
        &section_rvas,
        old_ep,
    )
}

#[expect(
    clippy::similar_names,
    reason = "local names mirror unpacker x86 register names"
)]
fn unpack_131(
    bytes: &[u8],
    image_base: u32,
    size_of_headers: u32,
    empty: &PeSection,
    packed: &PeSection,
    ep_rva: u32,
    ep: &[u8],
) -> Result<FsgUnpacked, &'static str> {
    let support_rva = read_u32_le(ep, 1)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_support_rva_invalid")?;
    let support_offset = rawaddr_header_only(support_rva, bytes.len(), size_of_headers)
        .ok_or("fsg_support_offset_invalid")?;
    let gp = usize::try_from(packed.raw_offset)
        .ok()
        .and_then(|raw| raw.checked_sub(support_offset))
        .ok_or("fsg_support_size_invalid")?;
    let support = bytes
        .get(
            support_offset
                ..support_offset
                    .checked_add(gp)
                    .ok_or("fsg_support_size_invalid")?,
        )
        .ok_or("fsg_support_range_invalid")?;
    let newedi = read_u32_le(ep, 6)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_destination_invalid")?;
    let newesi = read_u32_le(ep, 11)
        .and_then(|value| va_to_rva(value, image_base))
        .ok_or("fsg_source_invalid")?;
    if newedi != empty.virtual_address {
        return Err("fsg_destination_mismatch");
    }
    if !section_contains_rva(packed, newesi, 1) {
        return Err("fsg_source_out_of_bounds");
    }

    let mut section_rvas = vec![newedi];
    let mut cursor = 0usize;
    while cursor
        .checked_add(2)
        .is_some_and(|end| end <= support.len())
    {
        let raw = u32::from(u16::from_le_bytes([support[cursor], support[cursor + 1]]));
        if raw == 1 || raw == 2 {
            break;
        }
        let rva = raw
            .checked_sub(2)
            .and_then(|value| value.checked_shl(12))
            .and_then(|value| value.checked_sub(image_base))
            .ok_or("fsg_original_section_rva_invalid")?;
        if !rva_within_unpacked(empty, rva) {
            return Err("fsg_original_section_out_of_bounds");
        }
        section_rvas.push(rva);
        cursor = cursor
            .checked_add(2)
            .ok_or("fsg_section_table_offset_overflow")?;
    }
    if cursor.checked_add(2).is_none_or(|end| end > support.len()) {
        return Err("fsg_section_table_terminator_missing");
    }

    let old_ep = ep_rva
        .checked_sub(packed.virtual_address)
        .ok_or("fsg_old_entrypoint_invalid")?;
    unpack_segments(
        bytes,
        image_base,
        packed,
        empty.virtual_size,
        newesi,
        &section_rvas,
        old_ep,
    )
}

fn unpack_segments(
    bytes: &[u8],
    image_base: u32,
    packed: &PeSection,
    dsize: u32,
    source_rva: u32,
    section_rvas: &[u32],
    old_ep: u32,
) -> Result<FsgUnpacked, &'static str> {
    let source = section_bytes(bytes, packed).ok_or("fsg_source_range_invalid")?;
    let dsize = checked_dsize(dsize)?;
    let first_source_offset = usize::try_from(source_rva - packed.virtual_address)
        .map_err(|_| "fsg_source_offset_overflow")?;
    let mut source_cursor = first_source_offset;
    let mut dest = vec![0u8; dsize];
    let mut dest_cursor = 0usize;
    let mut rebuild_sections = Vec::with_capacity(section_rvas.len());
    for &rva in section_rvas {
        let section_dest_start = dest_cursor;
        let (consumed, written) = unfsg_into(&source[source_cursor..], &mut dest[dest_cursor..])?;
        source_cursor = source_cursor
            .checked_add(consumed)
            .ok_or("fsg_source_offset_overflow")?;
        dest_cursor = dest_cursor
            .checked_add(written)
            .ok_or("fsg_output_offset_overflow")?;
        if source_cursor > source.len() || dest_cursor > dest.len() {
            return Err("fsg_segment_out_of_bounds");
        }
        rebuild_sections.push(RebuildSection {
            source_offset: u32::try_from(section_dest_start)
                .map_err(|_| "fsg_output_offset_overflow")?,
            rva,
            virtual_size: u32::try_from(written).map_err(|_| "fsg_segment_size_overflow")?,
            raw_size: u32::try_from(written).map_err(|_| "fsg_segment_size_overflow")?,
        });
    }
    rebuild_sections.sort_by_key(|section| section.rva);
    let mut remaining = u32::try_from(dsize).map_err(|_| "fsg_unpacked_size_overflow")?;
    for index in 0..rebuild_sections.len() {
        if let Some(next) = rebuild_sections.get(index + 1) {
            let virtual_size = next
                .rva
                .checked_sub(rebuild_sections[index].rva)
                .ok_or("fsg_section_rva_order_invalid")?;
            rebuild_sections[index].virtual_size = virtual_size;
            remaining = remaining
                .checked_sub(virtual_size)
                .ok_or("fsg_section_size_underflow")?;
        } else {
            rebuild_sections[index].virtual_size = remaining;
        }
    }
    let bytes = rebuild::rebuild_pe_from_sections(
        &dest,
        &rebuild_sections,
        RebuildOptions::pe32(image_base, old_ep),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: packed
            .start
            .checked_add(first_source_offset as u64)
            .ok_or("fsg_source_offset_overflow")?,
        source_size: (source.len() - first_source_offset) as u64,
    })
}

pub(super) fn unfsg_to_vec(source: &[u8], dsize: usize) -> Result<Vec<u8>, &'static str> {
    let mut dest = vec![0u8; dsize];
    let (_, written) = unfsg_into(source, &mut dest)?;
    dest.truncate(written.max(1));
    Ok(dest)
}

pub(super) fn unfsg_into(source: &[u8], dest: &mut [u8]) -> Result<(usize, usize), &'static str> {
    if source.is_empty() || dest.is_empty() {
        return Err("fsg_empty_stream");
    }
    let mut bits = FsgBitReader::new(source);
    let mut dcur = 0usize;
    let mut oldback = 0usize;
    let mut lostbit = true;
    copy_literal(source, dest, &mut bits.scur, &mut dcur)?;
    loop {
        if bits.double()? {
            let mut backsize = 0usize;
            let backbytes;
            if bits.double()? {
                if bits.double()? {
                    lostbit = true;
                    backsize += 1;
                    let mut value = 0x10usize;
                    while value < 0x100 {
                        let bit = usize::from(bits.double()?);
                        value = value
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("fsg_integer_overflow")?;
                    }
                    let value = value & 0xff;
                    if value == 0 {
                        let out = dest.get_mut(dcur).ok_or("fsg_output_out_of_bounds")?;
                        *out = 0;
                        dcur += 1;
                        continue;
                    }
                    backbytes = value;
                } else {
                    let byte = next_source_byte(source, &mut bits.scur)? as usize;
                    backsize = backsize
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(byte & 1))
                        .ok_or("fsg_integer_overflow")?;
                    let value = byte >> 1;
                    if value == 0 {
                        break;
                    }
                    backsize = backsize.checked_add(2).ok_or("fsg_integer_overflow")?;
                    oldback = value;
                    lostbit = false;
                    backbytes = value;
                }
            } else {
                backsize = 1;
                loop {
                    let bit = usize::from(bits.double()?);
                    backsize = backsize
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(bit))
                        .ok_or("fsg_integer_overflow")?;
                    if !bits.double()? {
                        break;
                    }
                }
                backsize = backsize
                    .checked_sub(1 + usize::from(lostbit))
                    .ok_or("fsg_backsize_underflow")?;
                if backsize == 0 {
                    backsize = 1;
                    loop {
                        let bit = usize::from(bits.double()?);
                        backsize = backsize
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("fsg_integer_overflow")?;
                        if !bits.double()? {
                            break;
                        }
                    }
                    backbytes = oldback;
                } else {
                    let byte = next_source_byte(source, &mut bits.scur)? as usize;
                    backbytes = byte
                        .checked_add(
                            backsize
                                .checked_sub(1)
                                .and_then(|value| value.checked_shl(8))
                                .ok_or("fsg_integer_overflow")?,
                        )
                        .ok_or("fsg_integer_overflow")?;
                    backsize = 1;
                    loop {
                        let bit = usize::from(bits.double()?);
                        backsize = backsize
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("fsg_integer_overflow")?;
                        if !bits.double()? {
                            break;
                        }
                    }
                    if backbytes >= 0x7d00 {
                        backsize += 1;
                    }
                    if backbytes >= 0x500 {
                        backsize += 1;
                    }
                    if backbytes <= 0x7f {
                        backsize += 2;
                    }
                    oldback = backbytes;
                }
                lostbit = false;
            }
            copy_backref(dest, &mut dcur, backbytes, backsize)?;
        } else {
            copy_literal(source, dest, &mut bits.scur, &mut dcur)?;
            lostbit = true;
        }
    }
    Ok((bits.scur, dcur))
}

struct FsgBitReader<'a> {
    source: &'a [u8],
    mydl: u8,
    scur: usize,
}

impl<'a> FsgBitReader<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            mydl: 0x80,
            scur: 0,
        }
    }

    fn double(&mut self) -> Result<bool, &'static str> {
        let olddl = self.mydl;
        self.mydl = self.mydl.wrapping_mul(2);
        if olddl == 0 || olddl == 0x80 {
            let byte = *self
                .source
                .get(self.scur)
                .ok_or("fsg_input_out_of_bounds")?;
            self.mydl = byte.wrapping_mul(2).wrapping_add(1);
            self.scur = self
                .scur
                .checked_add(1)
                .ok_or("fsg_source_offset_overflow")?;
            Ok(byte >> 7 != 0)
        } else {
            Ok(olddl >> 7 != 0)
        }
    }
}

fn copy_literal(
    source: &[u8],
    dest: &mut [u8],
    scur: &mut usize,
    dcur: &mut usize,
) -> Result<(), &'static str> {
    let byte = next_source_byte(source, scur)?;
    let out = dest.get_mut(*dcur).ok_or("fsg_output_out_of_bounds")?;
    *out = byte;
    *dcur = dcur.checked_add(1).ok_or("fsg_output_offset_overflow")?;
    Ok(())
}

fn next_source_byte(source: &[u8], scur: &mut usize) -> Result<u8, &'static str> {
    let byte = *source.get(*scur).ok_or("fsg_input_out_of_bounds")?;
    *scur = scur.checked_add(1).ok_or("fsg_source_offset_overflow")?;
    Ok(byte)
}

fn copy_backref(
    dest: &mut [u8],
    dcur: &mut usize,
    backbytes: usize,
    backsize: usize,
) -> Result<(), &'static str> {
    if backbytes == 0 {
        return Err("fsg_zero_backref");
    }
    let mut src = dcur
        .checked_sub(backbytes)
        .ok_or("fsg_backref_before_start")?;
    let end = dcur
        .checked_add(backsize)
        .ok_or("fsg_output_offset_overflow")?;
    if end > dest.len() {
        return Err("fsg_output_out_of_bounds");
    }
    while *dcur < end {
        let byte = *dest.get(src).ok_or("fsg_backref_out_of_bounds")?;
        dest[*dcur] = byte;
        src = src.checked_add(1).ok_or("fsg_backref_offset_overflow")?;
        *dcur = dcur.checked_add(1).ok_or("fsg_output_offset_overflow")?;
    }
    Ok(())
}

fn find_empty_section_pair(sections: &[PeSection]) -> Option<usize> {
    sections.windows(2).position(|pair| {
        pair[0].raw_size == 0
            && pair[0].virtual_size != 0
            && pair[1].raw_size != 0
            && pair[1].virtual_size != 0
    })
}

fn section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let start = usize::try_from(section.start).ok()?;
    let size = usize::try_from(section.raw_size).ok()?;
    bytes.get(start..start.checked_add(size)?)
}

fn section_contains_rva(section: &PeSection, rva: u32, size: u32) -> bool {
    let Some(end) = rva.checked_add(size) else {
        return false;
    };
    let start = section.virtual_address;
    let Some(section_end) = start.checked_add(section.raw_size) else {
        return false;
    };
    rva >= start && end <= section_end
}

fn rva_within_unpacked(empty: &PeSection, rva: u32) -> bool {
    rva >= empty.virtual_address
        && rva
            .checked_sub(empty.virtual_address)
            .is_some_and(|delta| delta < empty.virtual_size)
}

fn checked_dsize(size: u32) -> Result<usize, &'static str> {
    if size == 0 || u64::from(size) > MAX_FSG_UNPACKED_BYTES {
        return Err("fsg_unpacked_size_limit_exceeded");
    }
    usize::try_from(size).map_err(|_| "fsg_unpacked_size_overflow")
}

fn rawaddr_header_only(rva: u32, file_len: usize, size_of_headers: u32) -> Option<usize> {
    if rva < size_of_headers && usize::try_from(rva).ok()? < file_len {
        usize::try_from(rva).ok()
    } else {
        None
    }
}

fn va_to_rva(value: u32, image_base: u32) -> Option<u32> {
    value.checked_sub(image_base)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfsg_rejects_empty_inputs() {
        assert_eq!(unfsg_to_vec(&[], 16), Err("fsg_empty_stream"));
        assert_eq!(unfsg_to_vec(&[0], 0), Err("fsg_empty_stream"));
    }
}
