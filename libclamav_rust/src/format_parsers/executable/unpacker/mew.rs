// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust MEW PE unpacking helpers.
//!
//! This module ports the bounded MEW 1.1 paths from `ClamAV`
//! `libclamav/packlibs.c`, `libclamav/mew.c`, and the PE32 dispatch checks in
//! `libclamav/pe.c`. `ClamAV` does not run this legacy path for PE32+ inputs.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> MEW marker and segment table -> bounded LZMA/MEW decode
//!     -> reconstructed section set -> ClamAV-style PE rebuild
//! ```
//!
//! Segment counts, temporary buffers, decoded bytes, and PE64 dispatch are
//! bounded to match the legacy scanner behavior without unbounded allocation.

use std::io::Read;

use lzma_rust2::LzmaReader;

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_MEW_BUFFER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MEW_SEGMENTS: usize = 64;
const INITIAL_LZMA_OUTPUT_CAPACITY: usize = 64 * 1024;

pub(crate) type MewUnpacked = UnpackedArtifact;

pub(crate) fn unpack_pe(bytes: &[u8], analysis: &PeAnalysis) -> Result<MewUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("mew_pe64_not_supported_by_clamav");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "mew_image_base_out_of_range")?;
    let pair = find_empty_section_pair(&analysis.sections).ok_or("mew_section_pair_not_found")?;
    let empty = &analysis.sections[pair];
    let packed = &analysis.sections[pair + 1];
    let ep_rva = analysis.entrypoint_rva.ok_or("mew_entrypoint_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep.len() < 16 || ep.first() != Some(&0xe9) {
        return Err("mew_stub_not_recognized");
    }

    let rel = read_u32_le(ep, 1).ok_or("mew_jump_target_missing")?;
    let fileoffset = ep_rva.wrapping_add(rel).wrapping_add(5);
    if fileoffset != 0x154 && fileoffset != 0x158 {
        return Err("mew_jump_target_not_recognized");
    }
    let tbuff_offset = usize::try_from(fileoffset).map_err(|_| "mew_tbuff_offset_overflow")?;
    let tbuff = bytes
        .get(
            tbuff_offset
                ..tbuff_offset
                    .checked_add(0xb0)
                    .ok_or("mew_tbuff_range_invalid")?,
        )
        .ok_or("mew_tbuff_range_invalid")?;
    let mut offdiff = read_u32_le(tbuff, 1)
        .and_then(|value| value.checked_sub(image_base))
        .ok_or("mew_source_offset_invalid")?;
    if offdiff <= packed.virtual_address
        || offdiff
            >= packed
                .virtual_address
                .checked_add(packed.raw_offset)
                .and_then(|value| value.checked_sub(4))
                .ok_or("mew_source_offset_invalid")?
    {
        return Err("mew_source_offset_out_of_bounds");
    }
    offdiff = offdiff
        .checked_sub(packed.virtual_address)
        .ok_or("mew_source_offset_underflow")?;

    let ssize = packed.virtual_size;
    let dsize = empty.virtual_size;
    let total = ssize.checked_add(dsize).ok_or("mew_buffer_size_overflow")?;
    if total == 0 || u64::from(total) > MAX_MEW_BUFFER_BYTES {
        return Err("mew_buffer_size_limit_exceeded");
    }
    let minimum_raw_size = offdiff.checked_add(12).ok_or("mew_size_mismatch")?;
    if offdiff >= total || packed.raw_size < minimum_raw_size {
        return Err("mew_size_mismatch");
    }
    if packed.raw_size > ssize {
        return Err("mew_raw_size_mismatch");
    }

    let packed_bytes = section_bytes(bytes, packed).ok_or("mew_source_range_invalid")?;
    let total = usize::try_from(total).map_err(|_| "mew_buffer_size_overflow")?;
    let dsize_usize = usize::try_from(dsize).map_err(|_| "mew_destination_size_overflow")?;
    let mut src = vec![0u8; total];
    let copy_len = packed_bytes.len().min(
        total
            .checked_sub(dsize_usize)
            .ok_or("mew_buffer_size_underflow")?,
    );
    let copy_end = dsize_usize
        .checked_add(copy_len)
        .ok_or("mew_copy_range_overflow")?;
    src[dsize_usize..copy_end].copy_from_slice(&packed_bytes[..copy_len]);
    let old_ep = read_u32_le(
        &src,
        dsize_usize
            .checked_add(usize::try_from(offdiff).map_err(|_| "mew_source_offset_overflow")?)
            .and_then(|value| value.checked_add(4))
            .ok_or("mew_entrypoint_record_missing")?,
    )
    .and_then(|value| value.checked_sub(image_base))
    .ok_or("mew_entrypoint_invalid")?;
    let payload = if tbuff.get(0x7b) == Some(&0xe8) {
        unmew11_lzma(
            &mut src,
            offdiff,
            ssize,
            dsize,
            image_base,
            empty.virtual_address,
            tbuff,
        )?
    } else {
        unmew11_non_lzma(
            &mut src,
            offdiff,
            ssize,
            dsize,
            image_base,
            empty.virtual_address,
        )?
    };
    let bytes = rebuild::rebuild_pe_from_sections(
        payload,
        &[RebuildSection {
            source_offset: 0,
            rva: empty.virtual_address,
            virtual_size: dsize,
            raw_size: u32::try_from(payload.len()).map_err(|_| "mew_payload_size_overflow")?,
        }],
        RebuildOptions {
            section_alignment_override: Some(0x1000),
            ..RebuildOptions::pe32(image_base, old_ep)
        },
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: packed
            .start
            .checked_add(u64::from(offdiff))
            .ok_or("mew_source_offset_overflow")?,
        source_size: u64::from(
            packed
                .raw_size
                .checked_sub(offdiff)
                .ok_or("mew_source_size_underflow")?,
        ),
    })
}

#[expect(
    clippy::similar_names,
    reason = "local names mirror unpacker x86 register names"
)]
fn unmew11_non_lzma(
    src: &mut [u8],
    off: u32,
    ssize: u32,
    dsize: u32,
    base: u32,
    vadd: u32,
) -> Result<&[u8], &'static str> {
    let vma = base.checked_add(vadd).ok_or("mew_vma_overflow")?;
    let size_sum = ssize.checked_add(dsize).ok_or("mew_size_sum_overflow")?;
    let off = usize::try_from(off).map_err(|_| "mew_offset_overflow")?;
    let dsize_usize = usize::try_from(dsize).map_err(|_| "mew_destination_size_overflow")?;
    let ssize_usize = usize::try_from(ssize).map_err(|_| "mew_source_size_overflow")?;
    if dsize_usize
        .checked_add(off)
        .and_then(|value| value.checked_add(12))
        .is_none_or(|end| end > src.len())
    {
        return Err("mew_data_reference_out_of_bounds");
    }
    let source = dsize_usize
        .checked_add(off)
        .ok_or("mew_source_offset_overflow")?;
    let entry_point = read_u32_le(src, source + 4).ok_or("mew_entrypoint_record_missing")?;
    let newedi = read_u32_le(src, source + 8).ok_or("mew_destination_record_missing")?;
    if entry_point < base {
        return Err("mew_entrypoint_invalid");
    }
    let mut lesi = source.checked_add(12).ok_or("mew_source_offset_overflow")?;
    let mut ledi = usize::try_from(newedi.checked_sub(vma).ok_or("mew_destination_underflow")?)
        .map_err(|_| "mew_destination_offset_overflow")?;
    let mut loc_ds = usize::try_from(
        size_sum
            .checked_sub(newedi.checked_sub(vma).ok_or("mew_destination_underflow")?)
            .ok_or("mew_destination_size_underflow")?,
    )
    .map_err(|_| "mew_destination_size_overflow")?;
    let mut loc_ss = ssize_usize
        .checked_sub(12)
        .and_then(|value| value.checked_sub(off))
        .ok_or("mew_source_size_underflow")?;

    for _ in 0..MAX_MEW_SEGMENTS {
        if lesi.checked_add(loc_ss).is_none_or(|end| end > src.len())
            || ledi.checked_add(loc_ds).is_none_or(|end| end > src.len())
        {
            return Err("mew_segment_out_of_bounds");
        }
        let (consumed, written) = unmew_into(src, lesi, loc_ss, ledi, loc_ds)?;
        let f1 = lesi
            .checked_add(consumed)
            .ok_or("mew_source_offset_overflow")?;
        if f1.checked_add(4).is_none_or(|end| end > src.len()) {
            return Err("mew_next_section_out_of_bounds");
        }
        let next_va = read_u32_le(src, f1).ok_or("mew_next_section_missing")?;
        let f2 = ledi
            .checked_add(written)
            .ok_or("mew_destination_offset_overflow")?;
        if f2 > dsize_usize {
            return Err("mew_unpacked_payload_out_of_bounds");
        }
        loc_ss = loc_ss
            .checked_sub(consumed.checked_add(4).ok_or("mew_source_size_underflow")?)
            .ok_or("mew_source_size_underflow")?;
        lesi = f1.checked_add(4).ok_or("mew_source_offset_overflow")?;
        if next_va == 0 {
            return Ok(&src[..dsize_usize]);
        }
        let next = usize::try_from(
            next_va
                .checked_sub(vma)
                .ok_or("mew_next_section_underflow")?,
        )
        .map_err(|_| "mew_next_section_offset_overflow")?;
        ledi = next;
        loc_ds = usize::try_from(
            size_sum
                .checked_sub(
                    next_va
                        .checked_sub(vma)
                        .ok_or("mew_next_section_underflow")?,
                )
                .ok_or("mew_destination_size_underflow")?,
        )
        .map_err(|_| "mew_destination_size_overflow")?;
    }
    Err("mew_segment_limit_exceeded")
}

#[expect(
    clippy::similar_names,
    reason = "local names mirror unpacker x86 register names"
)]
fn unmew11_lzma<'a>(
    src: &'a mut [u8],
    off: u32,
    ssize: u32,
    dsize: u32,
    base: u32,
    vadd: u32,
    tbuff: &[u8],
) -> Result<&'a [u8], &'static str> {
    let vma = base.checked_add(vadd).ok_or("mew_vma_overflow")?;
    let size_sum = ssize.checked_add(dsize).ok_or("mew_size_sum_overflow")?;
    let off = usize::try_from(off).map_err(|_| "mew_offset_overflow")?;
    let dsize_usize = usize::try_from(dsize).map_err(|_| "mew_destination_size_overflow")?;
    let ssize_usize = usize::try_from(ssize).map_err(|_| "mew_source_size_overflow")?;
    if dsize_usize
        .checked_add(off)
        .and_then(|value| value.checked_add(12))
        .is_none_or(|end| end > src.len())
    {
        return Err("mew_data_reference_out_of_bounds");
    }
    let source = dsize_usize
        .checked_add(off)
        .ok_or("mew_source_offset_overflow")?;
    let entry_point = read_u32_le(src, source + 4).ok_or("mew_entrypoint_record_missing")?;
    let newedi = read_u32_le(src, source + 8).ok_or("mew_destination_record_missing")?;
    if entry_point < base {
        return Err("mew_entrypoint_invalid");
    }
    let mut lesi = source.checked_add(12).ok_or("mew_source_offset_overflow")?;
    let mut ledi = usize::try_from(newedi.checked_sub(vma).ok_or("mew_destination_underflow")?)
        .map_err(|_| "mew_destination_offset_overflow")?;
    let mut loc_ds = usize::try_from(
        size_sum
            .checked_sub(newedi.checked_sub(vma).ok_or("mew_destination_underflow")?)
            .ok_or("mew_destination_size_underflow")?,
    )
    .map_err(|_| "mew_destination_size_overflow")?;
    let mut loc_ss = ssize_usize
        .checked_sub(12)
        .and_then(|value| value.checked_sub(off))
        .ok_or("mew_source_size_underflow")?;

    for _ in 0..MAX_MEW_SEGMENTS {
        if lesi.checked_add(loc_ss).is_none_or(|end| end > src.len())
            || ledi.checked_add(loc_ds).is_none_or(|end| end > src.len())
        {
            return Err("mew_segment_out_of_bounds");
        }
        let (consumed, written) = unmew_into(src, lesi, loc_ss, ledi, loc_ds)?;
        let f1 = lesi
            .checked_add(consumed)
            .ok_or("mew_source_offset_overflow")?;
        if f1.checked_add(4).is_none_or(|end| end > src.len()) {
            return Err("mew_next_section_out_of_bounds");
        }
        let next_va = read_u32_le(src, f1).ok_or("mew_next_section_missing")?;
        let f2 = ledi
            .checked_add(written)
            .ok_or("mew_destination_offset_overflow")?;
        if f2 > dsize_usize {
            return Err("mew_unpacked_payload_out_of_bounds");
        }
        loc_ss = loc_ss
            .checked_sub(consumed.checked_add(4).ok_or("mew_source_size_underflow")?)
            .ok_or("mew_source_size_underflow")?;
        lesi = f1.checked_add(4).ok_or("mew_source_offset_overflow")?;
        if next_va == 0 {
            let special = tbuff.get(0x83) == Some(&0x50);
            let lzma_source = parse_mew_lzma_payload(src, lesi, dsize_usize, vma, special)?;
            let decoded =
                try_mew_lzma_standard(lzma_source, dsize_usize).ok_or("mew_lzma_decode_failed")?;
            let copy_len = decoded.len().min(dsize_usize);
            src[..copy_len].copy_from_slice(&decoded[..copy_len]);
            return Ok(&src[..dsize_usize]);
        }
        let next = usize::try_from(
            next_va
                .checked_sub(vma)
                .ok_or("mew_next_section_underflow")?,
        )
        .map_err(|_| "mew_next_section_offset_overflow")?;
        ledi = next;
        loc_ds = usize::try_from(
            size_sum
                .checked_sub(
                    next_va
                        .checked_sub(vma)
                        .ok_or("mew_next_section_underflow")?,
                )
                .ok_or("mew_destination_size_underflow")?,
        )
        .map_err(|_| "mew_destination_size_overflow")?;
    }
    Err("mew_segment_limit_exceeded")
}

fn parse_mew_lzma_payload(
    src: &[u8],
    offset: usize,
    dsize: usize,
    vma: u32,
    special: bool,
) -> Result<&[u8], &'static str> {
    let mut cursor = offset;
    if special {
        cursor = cursor.checked_add(4).ok_or("mew_lzma_offset_overflow")?;
    }
    let prob_base = read_u32_le(src, cursor)
        .and_then(|value| value.checked_sub(vma))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("mew_lzma_probability_base_invalid")?;
    cursor = cursor.checked_add(4).ok_or("mew_lzma_offset_overflow")?;
    if prob_base
        .checked_add(0x6e6c)
        .is_none_or(|end| end > dsize || end > src.len())
    {
        return Err("mew_lzma_probability_base_out_of_bounds");
    }
    let output_size = read_u32_le(src, cursor).ok_or("mew_lzma_output_size_missing")?;
    cursor = cursor.checked_add(4).ok_or("mew_lzma_offset_overflow")?;
    let dest = read_u32_le(src, cursor)
        .and_then(|value| value.checked_sub(vma))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("mew_lzma_destination_invalid")?;
    cursor = cursor.checked_add(4).ok_or("mew_lzma_offset_overflow")?;
    let compressed_size = usize::try_from(read_u32_le(src, cursor).ok_or("mew_lzma_size_missing")?)
        .map_err(|_| "mew_lzma_size_overflow")?;
    cursor = cursor.checked_add(5).ok_or("mew_lzma_offset_overflow")?;
    if output_size == 0 || dest >= dsize {
        return Err("mew_lzma_destination_out_of_bounds");
    }
    src.get(
        cursor
            ..cursor
                .checked_add(compressed_size)
                .ok_or("mew_lzma_source_overflow")?,
    )
    .ok_or("mew_lzma_source_out_of_bounds")
}

fn try_mew_lzma_standard(source: &[u8], output_size: usize) -> Option<Vec<u8>> {
    if source.len() < 6 || output_size == 0 {
        return None;
    }
    let props = *source.first()?;
    let lc = u32::from(props % 9);
    let remainder = u32::from(props / 9);
    let lp = remainder % 5;
    let pb = remainder / 5;
    if lc >= 9 || lp >= 5 || pb >= 5 {
        return None;
    }
    let dict_size = read_u32_le(source, 1)?.max(lzma_rust2::DICT_SIZE_MIN);
    let reader = LzmaReader::new(
        &source[5..],
        output_size as u64,
        lc,
        lp,
        pb,
        dict_size,
        None,
    )
    .ok()?;
    let mut output = Vec::with_capacity(output_size.min(INITIAL_LZMA_OUTPUT_CAPACITY));
    let read_limit = (output_size as u64).checked_add(1)?;
    reader.take(read_limit).read_to_end(&mut output).ok()?;
    (!output.is_empty() && output.len() <= output_size).then_some(output)
}

fn unmew_into(
    buffer: &mut [u8],
    source_offset: usize,
    ssize: usize,
    dest_offset: usize,
    dsize: usize,
) -> Result<(usize, usize), &'static str> {
    if ssize == 0 || dsize == 0 {
        return Err("mew_empty_stream");
    }
    let mut bits = MewBitReader::new(buffer, source_offset, ssize);
    let mut dcur = dest_offset;
    let dend = dest_offset
        .checked_add(dsize)
        .ok_or("mew_output_offset_overflow")?;
    let mut oldback = 0usize;
    let mut lostbit = true;
    copy_literal(buffer, &mut bits.scur, bits.send, &mut dcur, dend)?;
    loop {
        if bits.double(buffer)? {
            let mut backsize = 0usize;
            let backbytes;
            if bits.double(buffer)? {
                if bits.double(buffer)? {
                    lostbit = true;
                    backsize += 1;
                    let mut value = 0x10usize;
                    while value < 0x100 {
                        let bit = usize::from(bits.double(buffer)?);
                        value = value
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("mew_integer_overflow")?;
                    }
                    let value = value & 0xff;
                    if value == 0 {
                        let out = buffer.get_mut(dcur).ok_or("mew_output_out_of_bounds")?;
                        *out = 0;
                        dcur += 1;
                        continue;
                    }
                    backbytes = value;
                } else {
                    let byte = next_source_byte(buffer, &mut bits.scur, bits.send)? as usize;
                    backsize = backsize
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(byte & 1))
                        .ok_or("mew_integer_overflow")?;
                    let value = byte >> 1;
                    if value == 0 {
                        break;
                    }
                    backsize = backsize.checked_add(2).ok_or("mew_integer_overflow")?;
                    oldback = value;
                    lostbit = false;
                    backbytes = value;
                }
            } else {
                backsize = 1;
                loop {
                    let bit = usize::from(bits.double(buffer)?);
                    backsize = backsize
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(bit))
                        .ok_or("mew_integer_overflow")?;
                    if !bits.double(buffer)? {
                        break;
                    }
                }
                backsize = backsize
                    .checked_sub(1 + usize::from(lostbit))
                    .ok_or("mew_backsize_underflow")?;
                if backsize == 0 {
                    backsize = 1;
                    loop {
                        let bit = usize::from(bits.double(buffer)?);
                        backsize = backsize
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("mew_integer_overflow")?;
                        if !bits.double(buffer)? {
                            break;
                        }
                    }
                    backbytes = oldback;
                } else {
                    let byte = next_source_byte(buffer, &mut bits.scur, bits.send)? as usize;
                    backbytes = byte
                        .checked_add(
                            backsize
                                .checked_sub(1)
                                .and_then(|value| value.checked_shl(8))
                                .ok_or("mew_integer_overflow")?,
                        )
                        .ok_or("mew_integer_overflow")?;
                    backsize = 1;
                    loop {
                        let bit = usize::from(bits.double(buffer)?);
                        backsize = backsize
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(bit))
                            .ok_or("mew_integer_overflow")?;
                        if !bits.double(buffer)? {
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
            copy_backref(buffer, &mut dcur, dest_offset, dend, backbytes, backsize)?;
        } else {
            copy_literal(buffer, &mut bits.scur, bits.send, &mut dcur, dend)?;
            lostbit = true;
        }
    }
    Ok((bits.scur - source_offset, dcur - dest_offset))
}

struct MewBitReader {
    mydl: u8,
    scur: usize,
    send: usize,
}

impl MewBitReader {
    fn new(buffer: &[u8], source_offset: usize, ssize: usize) -> Self {
        Self {
            mydl: 0x80,
            scur: source_offset,
            send: source_offset
                .checked_add(ssize)
                .unwrap_or(buffer.len())
                .min(buffer.len()),
        }
    }

    fn double(&mut self, buffer: &[u8]) -> Result<bool, &'static str> {
        let olddl = self.mydl;
        self.mydl = self.mydl.wrapping_mul(2);
        if olddl == 0 || olddl == 0x80 {
            let byte = *buffer.get(self.scur).ok_or("mew_input_out_of_bounds")?;
            if self.scur >= self.send {
                return Err("mew_input_out_of_bounds");
            }
            self.mydl = byte.wrapping_mul(2).wrapping_add(1);
            self.scur = self
                .scur
                .checked_add(1)
                .ok_or("mew_source_offset_overflow")?;
            Ok(byte >> 7 != 0)
        } else {
            Ok(olddl >> 7 != 0)
        }
    }
}

fn copy_literal(
    buffer: &mut [u8],
    scur: &mut usize,
    send: usize,
    dcur: &mut usize,
    dend: usize,
) -> Result<(), &'static str> {
    let byte = next_source_byte(buffer, scur, send)?;
    if *dcur >= dend {
        return Err("mew_output_out_of_bounds");
    }
    let out = buffer.get_mut(*dcur).ok_or("mew_output_out_of_bounds")?;
    *out = byte;
    *dcur = dcur.checked_add(1).ok_or("mew_output_offset_overflow")?;
    Ok(())
}

fn next_source_byte(buffer: &[u8], scur: &mut usize, send: usize) -> Result<u8, &'static str> {
    if *scur >= send {
        return Err("mew_input_out_of_bounds");
    }
    let byte = *buffer.get(*scur).ok_or("mew_input_out_of_bounds")?;
    *scur = scur.checked_add(1).ok_or("mew_source_offset_overflow")?;
    Ok(byte)
}

fn copy_backref(
    buffer: &mut [u8],
    dcur: &mut usize,
    dest_start: usize,
    dend: usize,
    backbytes: usize,
    backsize: usize,
) -> Result<(), &'static str> {
    if backbytes == 0 {
        return Err("mew_zero_backref");
    }
    let mut src = dcur
        .checked_sub(backbytes)
        .ok_or("mew_backref_before_start")?;
    if src < dest_start {
        return Err("mew_backref_before_start");
    }
    let end = dcur
        .checked_add(backsize)
        .ok_or("mew_output_offset_overflow")?;
    if end > dend || end > buffer.len() {
        return Err("mew_output_out_of_bounds");
    }
    while *dcur < end {
        let byte = *buffer.get(src).ok_or("mew_backref_out_of_bounds")?;
        buffer[*dcur] = byte;
        src = src.checked_add(1).ok_or("mew_backref_offset_overflow")?;
        *dcur = dcur.checked_add(1).ok_or("mew_output_offset_overflow")?;
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

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_mew_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "mew_section_pair_not_found"
        );
    }
}
