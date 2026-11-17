// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust `PESpin` PE unpacking helpers.
//!
//! This module ports `ClamAV` `libclamav/spin.c` and the `PESpin` 1.1 dispatch
//! checks from `libclamav/pe.c`. The original `ClamAV` code comments note that
//! the rebuilt executable is imperfect; this port keeps the same
//! scanner-oriented behavior while using the shared ClamAV-style PE rebuild
//! module.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> PESpin marker checks -> Spin stream decode
//!     -> derived rebuild sections -> ClamAV-style PE rebuild
//! ```
//!
//! Decode buffers and rebuilt output are capped. The imperfect rebuild behavior
//! is intentional compatibility with `ClamAV`'s scanner-oriented `PESpin` path.

use super::fsg;

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_PESPIN_IMAGE_BYTES: usize = 128 * 1024 * 1024;
const MAX_PESPIN_OUTPUT_BYTES: u64 = MAX_PESPIN_IMAGE_BYTES as u64;

pub(crate) type PESpinUnpacked = UnpackedArtifact;

struct SpinDecoded {
    bytes: Vec<u8>,
    sections: Vec<RebuildSection>,
}

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<PESpinUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("pespin_pe64_not_supported_by_clamav");
    }
    if analysis.sections.len() <= 1 {
        return Err("pespin_section_count_too_low");
    }
    let ep_rva = analysis.entrypoint_rva.ok_or("pespin_entrypoint_missing")?;
    let last_index = analysis.sections.len() - 1;
    let spin_section = &analysis.sections[last_index];
    if ep_rva < spin_section.virtual_address
        || spin_section
            .virtual_address
            .checked_add(spin_section.raw_size)
            .is_none_or(|end| 0x3217 - 4 > end)
        || spin_section
            .virtual_address
            .checked_add(spin_section.raw_size)
            .and_then(|end| end.checked_sub(0x3217 + 4))
            .is_none_or(|limit| ep_rva >= limit)
    {
        return Err("pespin_entrypoint_out_of_spin_section");
    }
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep.get(4..14) != Some(&[0xe8, 0, 0, 0, 0, 0x8b, 0x1c, 0x24, 0x83, 0xc3]) {
        return Err("pespin_stub_not_recognized");
    }
    let decoded = unspin(bytes, &analysis.sections, last_index, ep_rva)?;
    let bytes = rebuild::rebuild_pe_from_sections(
        &decoded.bytes,
        &decoded.sections,
        RebuildOptions::pe32(0x0040_0000, 0x1000),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: spin_section.start,
        source_size: u64::from(spin_section.raw_size),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the PE-Spin transform is a translated unpacker state machine"
)]
fn unspin(
    bytes: &[u8],
    sections: &[PeSection],
    spin_index: usize,
    nep: u32,
) -> Result<SpinDecoded, &'static str> {
    let spin_section = &sections[spin_index];
    if bytes.len() > MAX_PESPIN_IMAGE_BYTES {
        return Err("pespin_image_size_limit_exceeded");
    }
    let mut spinned = section_bytes(bytes, spin_section)
        .ok_or("pespin_spin_section_range_invalid")?
        .to_vec();
    let ep_off = usize::try_from(
        nep.checked_sub(spin_section.virtual_address)
            .ok_or("pespin_entrypoint_underflow")?,
    )
    .map_err(|_| "pespin_entrypoint_offset_overflow")?;

    let curr = ep_off.checked_add(0xdb).ok_or("pespin_offset_overflow")?;
    if spinned.get(curr) != Some(&0xbb) {
        return Err("pespin_version_marker_missing");
    }
    let mut key8 = *spinned
        .get(checked_offset(curr, 1, "pespin_offset_overflow")?)
        .ok_or("pespin_key8_missing")?;
    if spinned.get(checked_offset(curr, 5, "pespin_offset_overflow")?) != Some(&0xb9) {
        return Err("pespin_length_marker_missing");
    }
    let src_len = mutable_section_prefix_len(bytes, sections, spin_index)?;
    let mut src = bytes[..src_len].to_vec();
    let mut len = read_u32_le(&spinned, checked_offset(curr, 6, "pespin_offset_overflow")?)
        .ok_or("pespin_first_length_missing")?;
    if len != 0x11fe {
        return Err("pespin_first_length_invalid");
    }
    if ep_off
        .checked_add(0x1fe5)
        .and_then(|value| value.checked_add(len as usize))
        .is_none_or(|end| end > spinned.len())
    {
        return Err("pespin_first_range_invalid");
    }
    let mut pos = ep_off
        .checked_add(0x1fe5)
        .and_then(|value| value.checked_add(len as usize))
        .and_then(|value| value.checked_sub(1))
        .ok_or("pespin_first_offset_overflow")?;
    while len != 0 {
        spinned[pos] ^= key8;
        key8 = key8.wrapping_sub(1);
        pos = pos.saturating_sub(1);
        len -= 1;
    }

    let key_marker = ep_off.checked_add(0x3217).ok_or("pespin_offset_overflow")?;
    let curr = ep_off.checked_add(0x26eb).ok_or("pespin_offset_overflow")?;
    let mut key32 = read_u32_le(&spinned, curr).ok_or("pespin_second_key_missing")?;
    len = read_u32_le(&spinned, checked_offset(curr, 5, "pespin_offset_overflow")?)
        .ok_or("pespin_second_length_missing")?;
    if len != 0x5a0 {
        return Err("pespin_second_length_invalid");
    }
    let mut curr = ep_off.checked_add(0x2d5).ok_or("pespin_offset_overflow")?;
    decrypt_lfsr(&mut spinned, curr, len as usize, &mut key32, 0x8c32_8834)?;

    let subtract = read_u32_le(
        &spinned,
        checked_offset(ep_off, 0x429, "pespin_offset_overflow")?,
    )
    .ok_or("pespin_crc_size_missing")?;
    let checksum_len = bytes
        .len()
        .checked_sub(usize::try_from(subtract).map_err(|_| "pespin_crc_size_overflow")?)
        .ok_or("pespin_crc_size_invalid")?;
    if checksum_len >= bytes.len() {
        return Err("pespin_crc_size_invalid");
    }
    key32 = read_u32_le(&spinned, key_marker)
        .ok_or("pespin_crc_key_missing")?
        .wrapping_sub(summit(&bytes[..checksum_len]));

    let spin_start =
        usize::try_from(spin_section.raw_offset).map_err(|_| "pespin_spin_offset_overflow")?;
    let spin_end = spin_start
        .checked_add(spinned.len())
        .ok_or("pespin_spin_write_range_invalid")?;
    src.get_mut(spin_start..spin_end)
        .ok_or("pespin_spin_write_range_invalid")?
        .copy_from_slice(&spinned);
    let ep_abs = spin_start
        .checked_add(ep_off)
        .ok_or("pespin_entrypoint_abs_overflow")?;

    let mut bitmap = read_u32_le(
        &src,
        checked_offset(ep_abs, 0x3207, "pespin_offset_overflow")?,
    )
    .ok_or("pespin_xor_bitmap_missing")?;
    for section in &sections[..spin_index] {
        if bitmap & 1 != 0 {
            xor_decrypt_section(&mut src, section, key32)?;
        }
        bitmap >>= 1;
    }

    curr = ep_abs.checked_add(0x644).ok_or("pespin_offset_overflow")?;
    len = read_u32_le(&src, curr).ok_or("pespin_third_length_missing")?;
    if len != 0x180 {
        return Err("pespin_third_length_invalid");
    }
    key32 = read_u32_le(&src, checked_offset(curr, 0x0c, "pespin_offset_overflow")?)
        .ok_or("pespin_third_key_missing")?;
    curr = ep_abs.checked_add(0x28d3).ok_or("pespin_offset_overflow")?;
    decrypt_lfsr(&mut src, curr, len as usize, &mut key32, 0xed43_af32)?;

    curr = ep_abs.checked_add(0x28dd).ok_or("pespin_offset_overflow")?;
    len = read_u32_le(&src, curr).ok_or("pespin_poly_length_missing")?;
    if len != 0x1a1 {
        return Err("pespin_poly_length_invalid");
    }
    let poly = curr.checked_add(0x0f).ok_or("pespin_offset_overflow")?;
    let mut emu = ep_abs.checked_add(0x6d4).ok_or("pespin_offset_overflow")?;
    let mut remaining = len;
    while remaining != 0 {
        let byte = *src.get(emu).ok_or("pespin_poly1_out_of_bounds")?;
        *src.get_mut(emu).ok_or("pespin_poly1_out_of_bounds")? = exec86(
            byte,
            low_byte_u32(remaining),
            src.get(
                poly..poly
                    .checked_add(0x25)
                    .ok_or("pespin_poly_code_out_of_bounds")?,
            )
            .ok_or("pespin_poly_code_out_of_bounds")?,
        )?;
        emu = emu.checked_add(1).ok_or("pespin_offset_overflow")?;
        remaining -= 1;
    }

    bitmap = read_u32_le(
        &src,
        checked_offset(ep_abs, 0x6f1, "pespin_offset_overflow")?,
    )
    .ok_or("pespin_poly_bitmap_missing")?;
    let poly = ep_abs.checked_add(0x755).ok_or("pespin_offset_overflow")?;
    for section in &sections[..spin_index] {
        if bitmap & 1 != 0 {
            let start = usize::try_from(section.raw_offset)
                .map_err(|_| "pespin_section_offset_overflow")?;
            let size =
                usize::try_from(section.raw_size).map_err(|_| "pespin_section_size_overflow")?;
            for i in 0..size {
                let pos = start
                    .checked_add(i)
                    .ok_or("pespin_section_offset_overflow")?;
                let byte = *src.get(pos).ok_or("pespin_section_out_of_bounds")?;
                *src.get_mut(pos).ok_or("pespin_section_out_of_bounds")? = exec86(
                    byte,
                    low_byte_usize(size - i),
                    src.get(
                        poly..poly
                            .checked_add(0x25)
                            .ok_or("pespin_poly_code_out_of_bounds")?,
                    )
                    .ok_or("pespin_poly_code_out_of_bounds")?,
                )?;
            }
        }
        bitmap >>= 1;
    }

    bitmap = read_u32_le(
        &src,
        checked_offset(ep_abs, 0x3061, "pespin_offset_overflow")?,
    )
    .ok_or("pespin_compression_bitmap_missing")?;
    let compression_bitmap = bitmap;
    let mut decoded_sections = Vec::with_capacity(spin_index);
    let mut output_size = 0u64;
    for section in &sections[..spin_index] {
        let raw = section_bytes(&src, section).ok_or("pespin_section_range_invalid")?;
        let decoded = if bitmap & 1 != 0 {
            fsg::unfsg_to_vec(
                raw,
                usize::try_from(section.virtual_size)
                    .map_err(|_| "pespin_section_size_overflow")?,
            )?
        } else {
            raw.to_vec()
        };
        output_size = output_size
            .checked_add(decoded.len() as u64)
            .ok_or("pespin_output_size_overflow")?;
        if output_size > MAX_PESPIN_OUTPUT_BYTES {
            return Err("pespin_output_size_limit_exceeded");
        }
        decoded_sections.push(decoded);
        bitmap >>= 1;
    }

    if let Some(resource_offset) = read_u32_le(
        &src,
        checked_offset(ep_abs, 0x2fee, "pespin_offset_overflow")?,
    )
    .filter(|value| *value != 0)
    {
        maybe_grow_resource_section(
            &src,
            sections,
            &mut decoded_sections,
            compression_bitmap,
            resource_offset,
        )?;
    }

    let payload_size = decoded_sections.iter().try_fold(0usize, |total, section| {
        total
            .checked_add(section.len())
            .ok_or("pespin_output_size_overflow")
    })?;
    if u64::try_from(payload_size).map_or(true, |size| size > MAX_PESPIN_OUTPUT_BYTES) {
        return Err("pespin_output_size_limit_exceeded");
    }
    let mut payload = Vec::with_capacity(payload_size);
    let mut rebuild_sections = Vec::with_capacity(decoded_sections.len());
    for (index, section) in decoded_sections.into_iter().enumerate() {
        let source_offset =
            u32::try_from(payload.len()).map_err(|_| "pespin_output_size_overflow")?;
        let original = sections
            .get(index)
            .ok_or("pespin_decoded_section_index_invalid")?;
        let raw_size = u32::try_from(section.len()).map_err(|_| "pespin_output_size_overflow")?;
        rebuild_sections.push(RebuildSection {
            source_offset,
            rva: original.virtual_address,
            virtual_size: original.virtual_size.max(raw_size),
            raw_size,
        });
        payload.extend_from_slice(&section);
    }
    if payload.is_empty() {
        return Err("pespin_empty_output");
    }
    Ok(SpinDecoded {
        bytes: payload,
        sections: rebuild_sections,
    })
}

fn maybe_grow_resource_section(
    src: &[u8],
    sections: &[PeSection],
    decoded_sections: &mut [Vec<u8>],
    compression_bitmap: u32,
    key32: u32,
) -> Result<(), &'static str> {
    for (index, section) in sections[..decoded_sections.len()].iter().enumerate() {
        if section.virtual_address <= key32
            && key32
                .checked_sub(section.virtual_address)
                .is_some_and(|delta| delta < section.virtual_size && delta <= section.raw_size)
            && compression_bitmap & (1 << index) == 0
        {
            let delta = usize::try_from(key32 - section.virtual_address)
                .map_err(|_| "pespin_resource_delta_overflow")?;
            let raw = section_bytes(src, section).ok_or("pespin_resource_range_invalid")?;
            if delta >= raw.len() {
                return Ok(());
            }
            let mut grown = vec![
                0u8;
                usize::try_from(section.virtual_size)
                    .map_err(|_| "pespin_resource_size_overflow")?
            ];
            grown[..delta].copy_from_slice(&raw[..delta]);
            if fsg::unfsg_into(&raw[delta..], &mut grown[delta..]).is_ok() {
                decoded_sections[index] = grown;
            }
            return Ok(());
        }
    }
    Ok(())
}

fn decrypt_lfsr(
    bytes: &mut [u8],
    offset: usize,
    len: usize,
    key: &mut u32,
    xor_constant: u32,
) -> Result<(), &'static str> {
    let end = offset
        .checked_add(len)
        .ok_or("pespin_decrypt_range_invalid")?;
    if end > bytes.len() {
        return Err("pespin_decrypt_range_invalid");
    }
    for byte in &mut bytes[offset..end] {
        if *key & 1 != 0 {
            *key >>= 1;
            *key ^= xor_constant;
        } else {
            *key >>= 1;
        }
        *byte ^= low_byte_u32(*key);
    }
    Ok(())
}

fn xor_decrypt_section(
    bytes: &mut [u8],
    section: &PeSection,
    key: u32,
) -> Result<(), &'static str> {
    let start =
        usize::try_from(section.raw_offset).map_err(|_| "pespin_section_offset_overflow")?;
    let size = usize::try_from(section.raw_size).map_err(|_| "pespin_section_size_overflow")?;
    let end = start
        .checked_add(size)
        .ok_or("pespin_section_range_invalid")?;
    if end > bytes.len() {
        return Err("pespin_section_range_invalid");
    }
    let mut keydup = key;
    for byte in &mut bytes[start..end] {
        if keydup & 1 == 0 {
            keydup >>= 1;
            keydup ^= 0xed43_af31;
        } else {
            keydup >>= 1;
        }
        *byte ^= low_byte_u32(keydup);
    }
    Ok(())
}

fn exec86(mut al: u8, cl: u8, emu: &[u8]) -> Result<u8, &'static str> {
    let mut len = 0usize;
    while len < 0x24 {
        let opcode = *emu.get(len).ok_or("pespin_exec86_out_of_bounds")?;
        len += 1;
        match opcode {
            0xeb => {
                len += 1;
                len += 1;
            }
            0x0a => {
                len += 1;
            }
            0x90 | 0xf8 | 0xf9 => {}
            0x02 => {
                al = al.wrapping_add(cl);
                len += 1;
            }
            0x2a => {
                al = al.wrapping_sub(cl);
                len += 1;
            }
            0x04 => {
                al = al.wrapping_add(*emu.get(len).ok_or("pespin_exec86_out_of_bounds")?);
                len += 1;
            }
            0x2c => {
                al = al.wrapping_sub(*emu.get(len).ok_or("pespin_exec86_out_of_bounds")?);
                len += 1;
            }
            0x32 => {
                al ^= cl;
                len += 1;
            }
            0x34 => {
                al ^= *emu.get(len).ok_or("pespin_exec86_out_of_bounds")?;
                len += 1;
            }
            0xfe => {
                if emu.get(len) == Some(&0xc0) {
                    al = al.wrapping_add(1);
                } else {
                    al = al.wrapping_sub(1);
                }
                len += 1;
            }
            0xc0 => {
                let support = *emu.get(len).ok_or("pespin_exec86_out_of_bounds")?;
                len += 1;
                let count = *emu.get(len).ok_or("pespin_exec86_out_of_bounds")?;
                if support == 0xc0 {
                    al = al.rotate_left(u32::from(count & 7));
                } else {
                    al = al.rotate_right(u32::from(count & 7));
                }
                len += 1;
            }
            _ => return Err("pespin_exec86_unknown_opcode"),
        }
    }
    if len != 0x24 || emu.get(len) != Some(&0xaa) {
        return Err("pespin_exec86_bad_terminator");
    }
    Ok(al)
}

fn summit(src: &[u8]) -> u32 {
    let mut eax = 0xffff_ffffu32;
    let mut ebx = 0xffff_ffffu32;
    for &byte in src {
        eax ^= (u32::from(byte) << 8) & 0xff00;
        eax = (eax >> 3) & 0x1fff_ffff;
        for _ in 0..4 {
            eax ^= (ebx >> 8) & 0xff;
            eax = eax.wrapping_add(0x7801_a108);
            eax ^= ebx;
            eax = eax.rotate_right(ebx & 0xff);
            std::mem::swap(&mut eax, &mut ebx);
        }
    }
    ebx
}

fn section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let start = usize::try_from(section.start).ok()?;
    let size = usize::try_from(section.raw_size).ok()?;
    bytes.get(start..start.checked_add(size)?)
}

fn mutable_section_prefix_len(
    bytes: &[u8],
    sections: &[PeSection],
    spin_index: usize,
) -> Result<usize, &'static str> {
    let mut end = 0usize;
    for section in sections
        .get(..=spin_index)
        .ok_or("pespin_section_index_invalid")?
    {
        let raw_size =
            usize::try_from(section.raw_size).map_err(|_| "pespin_section_size_overflow")?;
        if raw_size == 0 {
            continue;
        }
        let start = usize::try_from(section.start).map_err(|_| "pespin_section_offset_overflow")?;
        end = end.max(
            start
                .checked_add(raw_size)
                .ok_or("pespin_section_range_invalid")?,
        );
        let raw_offset =
            usize::try_from(section.raw_offset).map_err(|_| "pespin_section_offset_overflow")?;
        end = end.max(
            raw_offset
                .checked_add(raw_size)
                .ok_or("pespin_section_range_invalid")?,
        );
    }
    if end > bytes.len() {
        return Err("pespin_section_range_invalid");
    }
    Ok(end)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn checked_offset(base: usize, addend: usize, error: &'static str) -> Result<usize, &'static str> {
    base.checked_add(addend).ok_or(error)
}

fn low_byte_u32(value: u32) -> u8 {
    u8::try_from(value & 0xff).expect("masked low byte fits in u8")
}

fn low_byte_usize(value: usize) -> u8 {
    u8::try_from(value & 0xff).expect("masked low byte fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_pespin_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "pespin_section_count_too_low"
        );
    }

    #[test]
    fn mutable_section_prefix_ignores_overlay_bytes() {
        let bytes = vec![0u8; 4096];
        let sections = vec![
            PeSection {
                start: 0x200,
                raw_offset: 0x200,
                raw_size: 0x100,
                ..PeSection::default()
            },
            PeSection {
                start: 0x400,
                raw_offset: 0x400,
                raw_size: 0x80,
                ..PeSection::default()
            },
        ];

        assert_eq!(
            mutable_section_prefix_len(&bytes, &sections, 1).unwrap(),
            0x480
        );
    }
}
