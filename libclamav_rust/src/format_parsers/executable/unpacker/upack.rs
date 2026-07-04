// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust Upack PE unpacking helpers.
//!
//! This module ports the bounded Upack PE dispatch and the custom legacy LZMA
//! range decoder from `ClamAV` `libclamav/pe.c`, `libclamav/upack.c`, and
//! `libclamav/mew.c`. Decoded memory is emitted through the shared
//! ClamAV-style PE rebuild module.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> Upack layout variant -> custom range/LZMA decode context
//!     -> bounded memory image -> ClamAV-style PE rebuild
//! ```
//!
//! Decode context size, output buffers, and variant-specific section layouts are
//! bounded before rebuilt bytes are emitted.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_UPACK_BUFFER_BYTES: u64 = 128 * 1024 * 1024;
const UPACK_CONTEXT_LIMIT: usize = 0x100 * 0xff;

pub(crate) type UpackUnpacked = UnpackedArtifact;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpackKind {
    ThreeSection,
    TwoSection039,
    TwoSection1112,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpackVersion {
    V0399,
    V0297729,
    V0151477,
    V1112,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpackDecodedRange {
    source_offset: u32,
    size: u32,
    entrypoint_rva: u32,
}

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<UpackUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("upack_pe64_not_supported_by_clamav");
    }
    if analysis.sections.len() < 2 {
        return Err("upack_section_count_too_low");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "upack_image_base_out_of_range")?;
    let entrypoint_file = analysis
        .entrypoint_offset
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("upack_entrypoint_offset_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep.len() < 168 {
        return Err("upack_entrypoint_sample_too_short");
    }
    let min_rva = analysis
        .sections
        .iter()
        .map(|section| section.virtual_address)
        .min()
        .unwrap_or_default();
    let kind = classify_upack_kind(ep, analysis, image_base, min_rva)?;

    let (mut dest, vma, va, source_size) = prepare_memory_image(bytes, analysis, kind, image_base)?;
    let source_offset = 0;
    let decoded = decode_upack(kind, &mut dest, ep, vma, entrypoint_file, image_base, va)?;
    let bytes = rebuild::rebuild_pe_from_sections(
        &dest,
        &[RebuildSection {
            source_offset: decoded.source_offset,
            rva: va,
            virtual_size: decoded.size,
            raw_size: decoded.size,
        }],
        RebuildOptions::pe32(image_base, decoded.entrypoint_rva),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset,
        source_size,
    })
}

fn classify_upack_kind(
    ep: &[u8],
    analysis: &PeAnalysis,
    image_base: u32,
    min_rva: u32,
) -> Result<UpackKind, &'static str> {
    if analysis.sections.len() == 3
        && ep.first() == Some(&0xbe)
        && read_u32_le(ep, 1)
            .and_then(|value| value.checked_sub(image_base))
            .is_some_and(|rva| rva > min_rva)
        && ((ep.get(5) == Some(&0xad) && ep.get(6) == Some(&0x50))
            || (ep.get(5) == Some(&0xff) && ep.get(6) == Some(&0x36)))
    {
        return Ok(UpackKind::ThreeSection);
    }
    if analysis.sections.len() == 2
        && ep.first() == Some(&0x60)
        && ep.get(1) == Some(&0xe8)
        && read_u32_le(ep, 2) == Some(0x9)
    {
        return Ok(UpackKind::TwoSection039);
    }
    if analysis.sections.len() == 2
        && ep.first() == Some(&0xbe)
        && read_u32_le(ep, 1).is_some_and(|value| {
            value > image_base
                && value
                    .checked_sub(image_base)
                    .is_some_and(|rva| rva < min_rva)
        })
        && ep.get(5) == Some(&0xad)
        && ep.get(6) == Some(&0x8b)
        && ep.get(7) == Some(&0xf8)
    {
        return Ok(UpackKind::TwoSection1112);
    }
    Err("upack_stub_not_recognized")
}

fn prepare_memory_image(
    bytes: &[u8],
    analysis: &PeAnalysis,
    kind: UpackKind,
    image_base: u32,
) -> Result<(Vec<u8>, u32, u32, u64), &'static str> {
    let s0 = &analysis.sections[0];
    let s1 = &analysis.sections[1];
    let (dsize, ssize, off, vma) = match kind {
        UpackKind::ThreeSection => {
            let s2 = analysis
                .sections
                .get(2)
                .ok_or("upack_section_count_too_low")?;
            let dsize = s0
                .virtual_size
                .checked_add(s1.virtual_size)
                .and_then(|value| value.checked_add(s2.virtual_size))
                .ok_or("upack_destination_size_overflow")?;
            let ssize = s0
                .raw_size
                .checked_add(s0.raw_offset)
                .ok_or("upack_source_size_overflow")?;
            let vma = image_base
                .checked_add(s0.virtual_address)
                .ok_or("upack_vma_overflow")?;
            (dsize, ssize, s0.virtual_address, vma)
        }
        UpackKind::TwoSection039 | UpackKind::TwoSection1112 => {
            let dsize = s0
                .virtual_size
                .checked_add(s1.virtual_size)
                .and_then(|value| value.checked_add(s1.virtual_address))
                .ok_or("upack_destination_size_overflow")?;
            let ssize = s1.raw_offset;
            let vma = s1
                .virtual_address
                .checked_sub(s1.raw_offset)
                .ok_or("upack_vma_underflow")?;
            (dsize, ssize, 0, vma)
        }
    };
    if dsize == 0 || u64::from(dsize) > MAX_UPACK_BUFFER_BYTES || ssize > dsize {
        return Err("upack_size_limit_exceeded");
    }
    let section1_start = s1
        .virtual_address
        .checked_sub(off)
        .ok_or("upack_section_placement_invalid")?;
    if !contains_u32(dsize, section1_start, s1.raw_size) {
        return Err("upack_section_placement_invalid");
    }
    let section2_start = if matches!(kind, UpackKind::ThreeSection) {
        let s2 = &analysis.sections[2];
        let start = s2
            .virtual_address
            .checked_sub(s0.virtual_address)
            .ok_or("upack_section_placement_invalid")?;
        if !contains_u32(dsize, start, ssize) {
            return Err("upack_section_placement_invalid");
        }
        Some(start)
    } else {
        None
    };

    let dsize_usize = usize::try_from(dsize).map_err(|_| "upack_destination_size_overflow")?;
    let ssize_usize = usize::try_from(ssize).map_err(|_| "upack_source_size_overflow")?;
    if ssize_usize > bytes.len() {
        return Err("upack_source_range_invalid");
    }
    let mut dest = vec![0u8; dsize_usize];
    dest[..ssize_usize].copy_from_slice(&bytes[..ssize_usize]);
    if let Some(section2_start) = section2_start {
        let move_to = usize::try_from(section2_start).map_err(|_| "upack_section_move_overflow")?;
        if move_to
            .checked_add(ssize_usize)
            .is_none_or(|end| end > dest.len())
        {
            return Err("upack_section_move_out_of_bounds");
        }
        dest.copy_within(0..ssize_usize, move_to);
    }
    let section1_offset =
        usize::try_from(section1_start).map_err(|_| "upack_section_copy_offset_overflow")?;
    let section1 = section_bytes(bytes, s1).ok_or("upack_section_copy_range_invalid")?;
    let section1_end = section1_offset
        .checked_add(section1.len())
        .ok_or("upack_section_copy_out_of_bounds")?;
    if section1_end > dest.len() {
        return Err("upack_section_copy_out_of_bounds");
    }
    dest[section1_offset..section1_end].copy_from_slice(section1);
    Ok((dest, vma, s0.virtual_address, u64::from(ssize)))
}

#[allow(unused_assignments, unused_variables)]
#[expect(
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "local names and control flow mirror the translated UPack x86 decoder"
)]
fn decode_upack(
    kind: UpackKind,
    dest: &mut [u8],
    epbuff: &[u8],
    vma: u32,
    ep_file: u32,
    base: u32,
    va: u32,
) -> Result<UpackDecodedRange, &'static str> {
    let dsize = dest.len();
    let mut version = match kind {
        UpackKind::TwoSection1112 => UpackVersion::V1112,
        UpackKind::ThreeSection if epbuff.get(5) == Some(&0xff) && epbuff.get(6) == Some(&0x36) => {
            UpackVersion::V0297729
        }
        _ => UpackVersion::V0399,
    };
    let mut alvalue = 0usize;
    let mut loc_ecx = 0u32;
    let mut save3 = 0u32;
    let mut pushed_esi = 0usize;
    let mut end_edi = 0usize;
    let mut loc_edi = 0usize;
    let original_ep: u32;
    let rebuild_source_offset: u32;
    let rebuild_start: usize;

    if matches!(kind, UpackKind::ThreeSection) {
        let mut loc_esi =
            offset_from_va(read_u32_le(epbuff, 1).ok_or("upack_stub_esi_missing")?, vma)?;
        require(dest, loc_esi, 12)?;
        original_ep = read_u32_le(dest, loc_esi)
            .and_then(|value| value.checked_sub(vma))
            .ok_or("upack_original_ep_invalid")?;
        rebuild_source_offset = 0;
        loc_esi += 8;
        let (mut loc_esi2, lngjmpoff) = if matches!(version, UpackVersion::V0399) {
            loc_edi = offset_from_va(
                read_u32_le(dest, loc_esi).ok_or("upack_destination_missing")?,
                vma,
            )?;
            let ep = usize::try_from(ep_file).map_err(|_| "upack_entrypoint_offset_overflow")?;
            require(dest, ep + 0x0a, 2)?;
            if dest[ep + 0x0a] != 0xeb {
                return Err("upack_stub_jump_missing");
            }
            let loc = ep
                .checked_add(0x0c)
                .and_then(|value| value.checked_add(dest[ep + 0x0b] as usize))
                .ok_or("upack_stub_jump_overflow")?;
            let mut al = loc.checked_add(0x1a).ok_or("upack_alvalue_overflow")?;
            require(dest, al, 2)?;
            if dest[al] != 0xeb {
                return Err("upack_stub_jump_missing");
            }
            al = al
                .checked_add(usize::from(dest[al + 1]))
                .and_then(|value| value.checked_add(2 + 0x0a))
                .ok_or("upack_alvalue_overflow")?;
            alvalue = al;
            (loc, 8usize)
        } else {
            let ep = usize::try_from(ep_file).map_err(|_| "upack_entrypoint_offset_overflow")?;
            require(dest, ep + 7, 5)?;
            if dest[ep + 7] != 0xe9 {
                return Err("upack_stub_long_jump_missing");
            }
            let loc = checked_add_signed(
                ep + 0x0c,
                read_i32_le(dest, ep + 8).ok_or("upack_jump_delta_missing")?,
            )
            .ok_or("upack_jump_target_invalid")?;
            alvalue = loc.checked_add(0x25).ok_or("upack_alvalue_overflow")?;
            (loc, 10usize)
        };
        require(dest, alvalue, lngjmpoff + 5)?;
        if dest[alvalue] != 0xb5 {
            return Err("upack_context_count_missing");
        }
        alvalue += 1;
        let count = u32::from(dest[alvalue])
            .checked_mul(0x100)
            .ok_or("upack_context_count_overflow")?;
        let count_usize =
            usize::try_from(count).map_err(|_| "upack_context_count_limit_exceeded")?;
        if count_usize > UPACK_CONTEXT_LIMIT {
            return Err("upack_context_count_limit_exceeded");
        }
        if dest[alvalue + lngjmpoff] != 0xe9 {
            return Err("upack_unpacker_jump_missing");
        }
        let mut shlsize = read_i32_le(dest, alvalue + lngjmpoff + 1)
            .and_then(|delta| {
                let base = i64::try_from(loc_esi2).ok()?;
                let add = if matches!(version, UpackVersion::V0399) {
                    let jump = i64::from(*dest.get(loc_esi2 + 0x1b)?);
                    jump + 0x1c + 0x18
                } else {
                    0x35
                };
                base.checked_add(i64::from(delta))?.checked_add(add)
            })
            .and_then(|value| usize::try_from(value).ok())
            .ok_or("upack_shlsize_invalid")?;
        let (aljump, shroff) = {
            let mut candidate = shlsize.checked_add(43).ok_or("upack_jecxz_overflow")?;
            if candidate == 0 || !matches!(dest.get(candidate - 1), Some(0xe3)) {
                candidate = shlsize.checked_add(46).ok_or("upack_jecxz_overflow")?;
                require(dest, candidate.saturating_sub(1), 2)?;
                if dest[candidate - 1] != 0xe3 {
                    return Err("upack_jecxz_missing");
                }
                if !matches!(version, UpackVersion::V0297729) {
                    version = UpackVersion::V0151477;
                }
                (7usize, 26usize)
            } else {
                (8usize, 24usize)
            }
        };
        let jecxz = shlsize
            .checked_add(if matches!(version, UpackVersion::V0151477) {
                46
            } else {
                43
            })
            .ok_or("upack_jecxz_overflow")?;
        alvalue = jecxz
            .checked_add(usize::from(
                *dest.get(jecxz).ok_or("upack_jecxz_range_invalid")?,
            ))
            .and_then(|value| value.checked_add(1))
            .ok_or("upack_jecxz_target_overflow")?;
        require(dest, alvalue, aljump + 5)?;
        if dest[alvalue + aljump] != 0xe9 {
            return Err("upack_long_jump_missing");
        }
        let ret = read_i32_le(dest, alvalue + aljump + 1).ok_or("upack_long_jump_delta_missing")?;
        alvalue = checked_add_signed(alvalue + aljump + 1 + 4 + 27, ret)
            .ok_or("upack_alvalue_invalid")?;
        if matches!(version, UpackVersion::V0297729) {
            alvalue = alvalue.checked_add(2).ok_or("upack_alvalue_overflow")?;
        }
        require(dest, shlsize + shroff, 3)?;
        if dest[shlsize + shroff] != 0xc1 || dest[shlsize + shroff + 1] != 0xed {
            return Err("upack_context_bits_missing");
        }
        shlsize = usize::from(dest[shlsize + shroff + 2]);
        if !(2..=8).contains(&shlsize) {
            return Err("upack_context_bits_out_of_bounds");
        }
        let shlsize_u32 = u32::try_from(shlsize).map_err(|_| "upack_context_bits_out_of_bounds")?;

        if matches!(version, UpackVersion::V0297729) {
            require(dest, loc_esi2 + 6, 10)?;
            if dest[loc_esi2 + 6] != 0xbe || dest[loc_esi2 + 11] != 0xbf {
                return Err("upack_mov_pair_missing");
            }
            let source_va = read_u32_le(dest, loc_esi2 + 7).ok_or("upack_mov_esi_missing")?;
            if source_va < base || source_va > vma {
                return Err("upack_mov_esi_invalid");
            }
            loc_edi = offset_from_va(
                read_u32_le(dest, loc_esi2 + 12).ok_or("upack_mov_edi_missing")?,
                vma,
            )?;
            loc_esi2 = offset_from_va(source_va, base)?;
            require(dest, loc_edi, 0x58 + 24 + 4 * count_usize)?;
            require(dest, loc_esi2, 0x58 + 0x64 + 4)?;
            for _ in 0..0x16 {
                let value = read_u32_le(dest, loc_esi2).ok_or("upack_probability_missing")?;
                write_u32_le(dest, loc_edi, value)?;
                loc_esi2 += 4;
                loc_edi += 4;
            }
        } else {
            require(dest, loc_esi2 + 7, 5)?;
            if dest[loc_esi2 + 7] != 0xbe {
                return Err("upack_mov_esi_missing");
            }
            loc_esi2 = offset_from_va(
                read_u32_le(dest, loc_esi2 + 8).ok_or("upack_mov_esi_value_missing")?,
                vma,
            )?;
            require(dest, loc_edi, 0x9c + 24 + 4 * count_usize)?;
            require(dest, loc_esi2, 0x9c + 0x34 + 4)?;
            for _ in 0..0x27 {
                let value = read_u32_le(dest, loc_esi2).ok_or("upack_probability_missing")?;
                write_u32_le(dest, loc_edi, value)?;
                loc_esi2 += 4;
                loc_edi += 4;
            }
        }
        save3 = read_u32_le(dest, loc_esi2 + 4).ok_or("upack_callfix_count_missing")?;
        let paddr = offset_from_va(
            read_u32_le(dest, loc_edi - 4).ok_or("upack_range_pointer_missing")?,
            vma,
        )?;
        let loc_ebx = loc_edi;
        initialize_probability_tail(dest, &mut loc_edi, count)?;
        loc_edi = if matches!(version, UpackVersion::V0297729) {
            offset_from_va(vma, base)?
        } else {
            offset_from_va(
                read_u32_le(dest, loc_esi2 + 0x0c).ok_or("upack_destination_missing")?,
                vma,
            )?
        };
        pushed_esi = loc_edi;
        end_edi = if matches!(version, UpackVersion::V0297729) {
            save3 = read_u32_le(dest, loc_esi2 + 0x40).ok_or("upack_callfix_count_missing")?;
            offset_from_va(
                read_u32_le(dest, loc_esi2 + 0x64).ok_or("upack_end_missing")?,
                vma,
            )?
        } else {
            offset_from_va(
                read_u32_le(dest, loc_esi2 + 0x34).ok_or("upack_end_missing")?,
                vma,
            )?
        };
        if loc_edi > end_edi {
            return Err("upack_destination_range_invalid");
        }
        rebuild_start = loc_edi;
        unupack399(dest, 0, loc_ebx, 0, loc_edi, end_edi, shlsize_u32, paddr)?;
    } else {
        let ep = usize::try_from(ep_file).map_err(|_| "upack_entrypoint_offset_overflow")?;
        let loc_esi_start = usize::try_from(
            u64::from(vma)
                .checked_add(u64::from(ep_file))
                .ok_or("upack_entrypoint_overflow")?,
        )
        .map_err(|_| "upack_entrypoint_overflow")?;
        let (ep_jmp_offs, rep_stosd_count_offs, context_bits_offs, mut loc_esi) =
            if matches!(version, UpackVersion::V1112) {
                (0x1a4usize, 0x1busize, 0x41usize, loc_esi_start + 0x184)
            } else {
                (0x217usize, 0x3ausize, 0x5fusize, loc_esi_start + 0x1c1)
            };
        require(dest, loc_esi_start, ep_jmp_offs + 4)?;
        original_ep = checked_add_signed(
            loc_esi_start + ep_jmp_offs + 4,
            read_i32_le(dest, loc_esi_start + ep_jmp_offs)
                .ok_or("upack_original_ep_delta_missing")?,
        )
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("upack_original_ep_invalid")?;
        rebuild_source_offset = va;
        let count = u32::from(dest[loc_esi_start + rep_stosd_count_offs])
            .checked_mul(0x100)
            .ok_or("upack_context_count_overflow")?;
        let count_usize =
            usize::try_from(count).map_err(|_| "upack_context_count_limit_exceeded")?;
        if count_usize > UPACK_CONTEXT_LIMIT {
            return Err("upack_context_count_limit_exceeded");
        }
        let shlsize = 8u32
            .checked_sub(u32::from(dest[loc_esi_start + context_bits_offs]))
            .ok_or("upack_context_bits_out_of_bounds")?;
        if !(2..=8).contains(&shlsize) {
            return Err("upack_context_bits_out_of_bounds");
        }

        let loc_ebx;
        if matches!(version, UpackVersion::V0399) {
            loc_esi = loc_esi_start
                .checked_add(4)
                .ok_or("upack_offset_overflow")?;
            loc_ecx = read_u32_le(dest, loc_esi + 2).ok_or("upack_relocation_missing")?;
            write_u32_le(dest, loc_esi + 2, 0)?;
            if loc_ecx == 0 {
                return Err("upack_relocation_invalid");
            }
            loc_esi = loc_esi
                .checked_sub(usize::try_from(loc_ecx - 2).map_err(|_| "upack_relocation_overflow")?)
                .ok_or("upack_relocation_underflow")?;
            require(dest, loc_esi, 12)?;
            let loc_ebx_u = i64::try_from(loc_esi)
                .ok()
                .and_then(|loc| {
                    let ptr = offset_from_va(read_u32_le(dest, loc_esi)?, base).ok()?;
                    loc.checked_sub(i64::try_from(ptr).ok()?)
                })
                .ok_or("upack_ebx_invalid")?;
            loc_esi += 4;
            loc_edi = offset_from_va(
                read_u32_le(dest, loc_esi).ok_or("upack_destination_missing")?,
                base,
            )?;
            let save2 = loc_edi;
            loc_esi += 4;
            let j = read_i32_le(dest, loc_esi).ok_or("upack_probability_count_missing")?;
            if j < 0 {
                return Err("upack_probability_count_invalid");
            }
            let j_usize = usize::try_from(j).map_err(|_| "upack_probability_count_invalid")?;
            loc_esi += 4;
            require(dest, loc_esi, j_usize.saturating_mul(4))?;
            require(
                dest,
                loc_edi,
                count_usize
                    .checked_add(j_usize)
                    .and_then(|value| value.checked_mul(4))
                    .ok_or("upack_probability_range_overflow")?,
            )?;
            for _ in 0..j {
                let value = read_u32_le(dest, loc_esi).ok_or("upack_probability_missing")?;
                write_u32_le(dest, loc_edi, value)?;
                loc_edi += 4;
                loc_esi += 4;
            }
            require(dest, save2, 8)?;
            loc_ecx = read_u32_le(dest, save2).ok_or("upack_state_count_missing")?;
            let mut p = save2 + 4;
            for _ in 0..loc_ecx {
                p = checked_add_signed(
                    p + 4,
                    i32::try_from(loc_ebx_u).map_err(|_| "upack_ebx_overflow")?,
                )
                .ok_or("upack_state_walk_invalid")?;
            }
            save3 = read_u32_le(dest, p).ok_or("upack_state_value_missing")?;
            p += 4;
            for _ in 0..count {
                write_u32_le(dest, loc_edi, save3)?;
                loc_edi += 4;
            }
            require(dest, p + 0x10, 4)?;
            let pointer_adjust =
                usize::try_from(read_u32_le(dest, p + 0x10).ok_or("upack_pointer_adjust_missing")?)
                    .map_err(|_| "upack_pointer_adjust_invalid")?;
            let adjusted = checked_add_signed(
                pointer_adjust,
                i32::try_from(loc_ebx_u).map_err(|_| "upack_ebx_overflow")?,
            )
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("upack_pointer_adjust_invalid")?;
            write_u32_le(dest, p + 0x10, adjusted)?;
            loc_ebx = p + 0x14;
            let loc_esi2 = save2 + 4;
            require(dest, loc_ebx - 4, 12 + 4 * 4)?;
            require(dest, loc_esi2 + 0x40, 4)?;
            let paddr = offset_from_va(
                read_u32_le(dest, loc_ebx - 4).ok_or("upack_range_pointer_missing")?,
                base,
            )?;
            save3 = loc_ecx;
            pushed_esi = offset_from_va(
                read_u32_le(dest, loc_esi2).ok_or("upack_destination_missing")?,
                base,
            )?;
            loc_edi = pushed_esi;
            end_edi = offset_from_va(
                read_u32_le(dest, loc_esi2 + 0x24).ok_or("upack_end_missing")?,
                base,
            )?;
            let vma_swap = read_u32_le(dest, loc_ebx).ok_or("upack_vma_swap_missing")?;
            let next = read_u32_le(dest, loc_ebx + 4).ok_or("upack_vma_swap_missing")?;
            write_u32_le(dest, loc_ebx, next)?;
            write_u32_le(dest, loc_ebx + 4, vma_swap)?;
            if loc_edi > end_edi {
                return Err("upack_destination_range_invalid");
            }
            rebuild_start = loc_edi;
            unupack399(
                dest, loc_ecx, loc_ebx, loc_ecx, loc_edi, end_edi, shlsize, paddr,
            )?;
        } else {
            loc_esi = 0x148;
            loc_edi = offset_from_va(
                read_u32_le(dest, loc_esi).ok_or("upack_destination_missing")?,
                base,
            )?;
            let save_edi = loc_edi;
            loc_esi += 4;
            let paddr = offset_from_va(
                read_u32_le(dest, loc_esi).ok_or("upack_range_pointer_missing")?,
                base,
            )?;
            loc_esi += 4;
            loc_edi += 4;
            loc_ebx = loc_edi;
            initialize_probability_tail(dest, &mut loc_edi, count)?;
            loc_edi = offset_from_va(
                read_u32_le(dest, loc_esi).ok_or("upack_destination_missing")?,
                base,
            )?;
            pushed_esi = loc_edi;
            loc_esi += 8;
            end_edi = offset_from_va(
                read_u32_le(dest, loc_esi - 0x28).ok_or("upack_end_missing")?,
                base,
            )?;
            loc_esi = save_edi;
            if loc_edi > end_edi {
                return Err("upack_destination_range_invalid");
            }
            rebuild_start = loc_edi;
            unupack399(dest, 0, loc_ebx, 0, loc_edi, end_edi, shlsize, paddr)?;
            save3 = read_u32_le(dest, ep + 0x174).ok_or("upack_callfix_count_missing")?;
            let _ = loc_esi;
        }
    }

    apply_call_fixes(dest, alvalue, save3, pushed_esi)?;
    let size = end_edi
        .checked_sub(rebuild_start)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("upack_rebuild_size_invalid")?;
    if usize::try_from(rebuild_source_offset)
        .map_err(|_| "upack_rebuild_offset_overflow")?
        .checked_add(usize::try_from(size).map_err(|_| "upack_rebuild_size_invalid")?)
        .is_none_or(|end| end > dest.len())
    {
        return Err("upack_rebuild_range_invalid");
    }
    Ok(UpackDecodedRange {
        source_offset: rebuild_source_offset,
        size,
        entrypoint_rva: original_ep,
    })
}

fn initialize_probability_tail(
    dest: &mut [u8],
    loc_edi: &mut usize,
    count: u32,
) -> Result<(), &'static str> {
    write_u32_le(dest, *loc_edi, 0xffff_ffff)?;
    *loc_edi += 4;
    write_u32_le(dest, *loc_edi, 0)?;
    *loc_edi += 4;
    for _ in 0..4 {
        write_u32_le(dest, *loc_edi, 1)?;
        *loc_edi += 4;
    }
    for _ in 0..count {
        write_u32_le(dest, *loc_edi, 0x400)?;
        *loc_edi += 4;
    }
    Ok(())
}

fn apply_call_fixes(
    dest: &mut [u8],
    alvalue: usize,
    mut count: u32,
    pushed_esi: usize,
) -> Result<(), &'static str> {
    if count == 0 {
        return Ok(());
    }
    let searchval = *dest.get(alvalue).ok_or("upack_callfix_marker_missing")?;
    let mut loc_ecx = 0usize;
    while count != 0 {
        let cursor = pushed_esi
            .checked_add(loc_ecx)
            .ok_or("upack_callfix_offset_overflow")?;
        require(dest, cursor, 1)?;
        if dest[cursor] == 0xe8 || dest[cursor] == 0xe9 {
            let adr = cursor
                .checked_add(1)
                .ok_or("upack_callfix_offset_overflow")?;
            loc_ecx += 1;
            require(dest, adr, 4)?;
            let value = read_u32_le(dest, adr).ok_or("upack_callfix_value_missing")?;
            if (value & 0xff) != u32::from(searchval) {
                continue;
            }
            let adjustment = loc_ecx
                .checked_add(4)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or("upack_callfix_offset_overflow")?;
            let fixed = value.swap_bytes().wrapping_sub(adjustment);
            write_u32_le(dest, adr, fixed)?;
            loc_ecx += 4;
            count -= 1;
        } else {
            loc_ecx += 1;
        }
        if loc_ecx > dest.len() {
            return Err("upack_callfix_limit_exceeded");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[expect(
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "parameters, locals, and control flow mirror the translated UPack x86 decoder"
)]
fn unupack399(
    bs: &mut [u8],
    init_eax: u32,
    init_ebx: usize,
    init_ecx: u32,
    init_edi: usize,
    end_edi: usize,
    shlsize: u32,
    paddr: usize,
) -> Result<(), &'static str> {
    require(bs, init_ebx, 24)?;
    require(bs, paddr, 5)?;
    require(bs, init_edi, 0)?;
    require(bs, end_edi, 0)?;
    if init_edi > end_edi {
        return Err("upack_lzma_destination_invalid");
    }
    let mut p = UpackRangeState {
        p0: paddr,
        p1: read_u32_le(bs, init_ebx).ok_or("upack_lzma_state_missing")?,
        p2: read_u32_le(bs, init_ebx + 4).ok_or("upack_lzma_state_missing")?,
    };
    let mut state = [0u32; 6];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = read_u32_le(bs, init_ebx + (i << 2)).ok_or("upack_lzma_state_missing")?;
    }
    let mut eax_copy = init_eax;
    let mut loc_ecx = init_ecx;
    let mut loc_edi = init_edi;
    while loc_edi < end_edi {
        let mut loc_eax = eax_copy;
        let mut loc_edx = upack_probability_offset(init_ebx, loc_eax, 0x58)?;
        if upack_bit(&mut p, loc_edx, bs)? {
            let loc_al = if u32::from(low_u8(loc_eax)) + 0xf9 > 0xff {
                11u32
            } else {
                8u32
            };
            loc_eax = (loc_eax & 0xffff_ff00) | loc_al;
            let mut loc_ebp = state[2];
            loc_ecx = (loc_ecx & 0xffff_ff00) | 0x30;
            loc_edx = upack_checked_add_u32(loc_edx, loc_ecx)?;
            if upack_bit(&mut p, loc_edx, bs)? {
                loc_edx = upack_checked_add_u32(loc_edx, loc_ecx)?;
                if upack_bit(&mut p, loc_edx, bs)? {
                    loc_edx = loc_edx
                        .checked_add(0x60)
                        .ok_or("upack_lzma_index_overflow")?;
                    if upack_bit(&mut p, loc_edx, bs)? {
                        loc_edx = upack_checked_add_u32(loc_edx, loc_ecx)?;
                        let ret = upack_bit(&mut p, loc_edx, bs)?;
                        let temp_ebp = loc_ebp;
                        loc_ebp = state[4];
                        state[4] = state[3];
                        state[3] = temp_ebp;
                        if ret {
                            std::mem::swap(&mut loc_ebp, &mut state[5]);
                        }
                    } else {
                        std::mem::swap(&mut loc_ebp, &mut state[3]);
                    }
                    eax_copy = loc_eax;
                    loc_edx = init_ebx + 0x778;
                    let temp = upack_esi_54(&mut p, loc_eax, &mut loc_ecx, &mut loc_edx, bs)?;
                    loc_eax = loc_ecx;
                    loc_ecx = temp;
                } else {
                    loc_edx = upack_checked_add_u32(loc_edx, loc_ecx)?;
                    if upack_bit(&mut p, loc_edx, bs)? {
                        eax_copy = loc_eax;
                        loc_edx = init_ebx + 0x778;
                        let temp = upack_esi_54(&mut p, loc_eax, &mut loc_ecx, &mut loc_edx, bs)?;
                        loc_eax = loc_ecx;
                        loc_ecx = temp;
                    } else {
                        loc_eax |= 1;
                        eax_copy = loc_eax;
                        let src = upack_checked_sub_backref(loc_edi, state[2])?;
                        loc_ecx = (loc_ecx & 0xffff_ff00) | 0x80;
                        require(bs, src, 1)?;
                        require(bs, loc_edi, 1)?;
                        bs[loc_edi] = bs[src];
                        loc_edi += 1;
                        continue;
                    }
                }
            } else {
                let temp_ebp = loc_ebp;
                loc_ebp = state[4];
                state[4] = state[3];
                state[3] = temp_ebp;
                eax_copy = loc_eax.wrapping_sub(1);
                loc_edx = init_ebx + 0xbc0;
                state[5] = loc_ebp;
                let temp = upack_esi_54(&mut p, eax_copy, &mut loc_ecx, &mut loc_edx, bs)?;
                loc_ecx = 3;
                let copy_len = temp;
                loc_eax = temp.wrapping_sub(1).min(loc_ecx);
                loc_ecx = 0x40;
                loc_eax <<= 6;
                let loc_ebp8 = upack_probability_offset(init_ebx, loc_eax, 0x378)?;
                loc_eax = upack_esi_50(&mut p, 1, loc_ecx, loc_ebp8, bs)?;
                loc_ebp = loc_eax;
                if (loc_eax & 0xff) >= 4 {
                    loc_ebp = 2 + (loc_eax & 1);
                    loc_eax >>= 1;
                    loc_eax = loc_eax.wrapping_sub(1);
                    let temp_ebp = loc_eax;
                    let mut bits = temp_ebp;
                    loc_ebp <<= bits & 0xff;
                    loc_edx = upack_probability_offset(init_ebx, loc_ebp, 0x178)?;
                    if (bits & 0xff) > 5 {
                        bits = (bits & 0xffff_ff00) | (((bits & 0xff) - 4) & 0xff);
                        let mut direct = 0u32;
                        for _ in 0..bits {
                            direct <<= 1;
                            let threshold = p.p1 >> 1;
                            let code =
                                read_u32_be_at(bs, p.p0).ok_or("upack_lzma_input_missing")?;
                            p.p1 = threshold;
                            if code.wrapping_sub(p.p2) >= p.p1 {
                                direct |= 1;
                                p.p2 = p.p2.wrapping_add(p.p1);
                            }
                            if p.p1 & 0xff00_0000 == 0 {
                                p.p2 <<= 8;
                                p.p1 <<= 8;
                                p.p0 += 1;
                            }
                        }
                        bits = 4;
                        loc_ebp = loc_ebp.wrapping_add(direct << 4);
                        loc_edx = init_ebx + 0x18;
                    }
                    let loc_ebp8 = loc_edx;
                    let mut rev = upack_esi_50(
                        &mut p,
                        1,
                        1u32.checked_shl(bits & 0xff)
                            .ok_or("upack_lzma_shift_overflow")?,
                        loc_ebp8,
                        bs,
                    )?;
                    let mut reverse = (rev.cast_signed() >> 31).cast_unsigned();
                    for _ in 0..bits {
                        reverse = (reverse << 1) | (rev & 1);
                        rev >>= 1;
                    }
                    loc_ebp = loc_ebp.wrapping_add(reverse);
                }
                loc_ebp = loc_ebp.wrapping_add(1);
                loc_ecx = copy_len;
            }
            let distance = usize::try_from(loc_ebp).map_err(|_| "upack_lzma_distance_overflow")?;
            let copy_len = usize::try_from(loc_ecx).map_err(|_| "upack_lzma_copy_overflow")?;
            copy_backref(bs, &mut loc_edi, init_edi, end_edi, distance, copy_len)?;
            state[2] = loc_ebp;
            let src = loc_edi
                .checked_sub(distance)
                .ok_or("upack_lzma_backref_before_start")?;
            loc_eax = (loc_eax & 0xffff_ff00)
                | u32::from(*bs.get(src).ok_or("upack_lzma_backref_out_of_bounds")?);
            loc_ecx = 0x80;
        } else {
            loop {
                let loc_al = low_u8(loc_eax);
                let next = if u32::from(loc_al) + 0xfd > 0xff {
                    loc_al.wrapping_sub(3)
                } else {
                    0
                };
                loc_eax = (loc_eax & 0xffff_ff00) | u32::from(next);
                if next < 7 {
                    break;
                }
            }
            eax_copy = loc_eax;
            let loc_ebp = if loc_edi > init_edi && loc_edi < bs.len() {
                u32::from(bs[loc_edi - 1]) >> (shlsize & 0xff)
            } else {
                0
            }
            .wrapping_mul(0x300);
            let loc_ebp8 = upack_probability_offset(init_ebx, loc_ebp, 0x1008)?;
            let edi_copy = loc_edi;
            loc_eax = (loc_eax & 0xffff_ff00) | 1;
            if loc_ecx != 0 {
                let mut loc_cl = low_u8(loc_ecx);
                let match_src = upack_checked_sub_backref(loc_edi, state[2])?;
                require(bs, match_src, 1)?;
                let mut match_cursor = match_src;
                loop {
                    loc_eax = (loc_eax & 0xffff_00ff)
                        | if bs[match_cursor] & loc_cl != 0 {
                            0x200
                        } else {
                            0x100
                        };
                    loc_edx = upack_probability_offset(loc_ebp8, loc_eax, 0)?;
                    let ret = u32::from(upack_bit(&mut p, loc_edx, bs)?);
                    let loc_al = (low_u8(loc_eax) << 1).wrapping_add(u8::from(ret != 0));
                    loc_eax = (loc_eax & 0xffff_ff00) | u32::from(loc_al);
                    loc_cl >>= 1;
                    if loc_cl == 0 {
                        break;
                    }
                    let loc_ah = (low_u8(loc_eax >> 8).wrapping_sub(loc_al)) & 1;
                    if loc_ah == 0 {
                        loc_eax =
                            (loc_eax & 0xffff_0000) | (u32::from(loc_ah) << 8) | u32::from(loc_al);
                        loc_eax = upack_esi_50(&mut p, loc_eax, 0x100, loc_ebp8, bs)?;
                        break;
                    }
                    match_cursor = match_src;
                }
            } else {
                loc_eax = upack_esi_50(&mut p, loc_eax, 0x100, loc_ebp8, bs)?;
            }
            loc_ecx = 0;
            loc_edi = edi_copy;
        }
        require(bs, loc_edi, 1)?;
        bs[loc_edi] = low_u8(loc_eax);
        loc_edi += 1;
    }
    Ok(())
}

fn upack_bit(
    p: &mut UpackRangeState,
    prob_offset: usize,
    bs: &mut [u8],
) -> Result<bool, &'static str> {
    require(bs, prob_offset, 4)?;
    require(bs, p.p0, 4)?;
    let prob = read_u32_le(bs, prob_offset).ok_or("upack_lzma_probability_missing")?;
    let ret = prob;
    let bound = (p.p1 >> 11).wrapping_mul(ret);
    let code = read_u32_be_at(bs, p.p0).ok_or("upack_lzma_input_missing")?;
    if code.wrapping_sub(p.p2) < bound {
        p.p1 = bound;
        let updated = prob.wrapping_add((0x800u32.wrapping_sub(prob)) >> 5);
        write_u32_le(bs, prob_offset, updated)?;
        normalize_upack_range(p, bs)?;
        Ok(false)
    } else {
        p.p2 = p.p2.wrapping_add(bound);
        p.p1 = p.p1.wrapping_sub(bound);
        let updated = prob.wrapping_sub(prob >> 5);
        write_u32_le(bs, prob_offset, updated)?;
        normalize_upack_range(p, bs)?;
        Ok(true)
    }
}

fn normalize_upack_range(p: &mut UpackRangeState, bs: &[u8]) -> Result<(), &'static str> {
    if p.p1 & 0xff00_0000 == 0 {
        require(bs, p.p0, 1)?;
        p.p2 <<= 8;
        p.p1 <<= 8;
        p.p0 = p.p0.checked_add(1).ok_or("upack_lzma_input_overflow")?;
    }
    Ok(())
}

fn upack_probability_offset(base: usize, index: u32, addend: usize) -> Result<usize, &'static str> {
    let scaled = usize::try_from(index)
        .map_err(|_| "upack_lzma_index_overflow")?
        .checked_mul(4)
        .ok_or("upack_lzma_index_overflow")?;
    base.checked_add(scaled)
        .and_then(|value| value.checked_add(addend))
        .ok_or("upack_lzma_index_overflow")
}

fn upack_checked_add_u32(base: usize, value: u32) -> Result<usize, &'static str> {
    base.checked_add(usize::try_from(value).map_err(|_| "upack_lzma_index_overflow")?)
        .ok_or("upack_lzma_index_overflow")
}

fn upack_checked_sub_backref(base: usize, value: u32) -> Result<usize, &'static str> {
    let offset = usize::try_from(value).map_err(|_| "upack_lzma_backref_before_start")?;
    base.checked_sub(offset)
        .ok_or("upack_lzma_backref_before_start")
}

fn low_u8(value: u32) -> u8 {
    u8::try_from(value & 0xff).expect("masked UPack register byte fits in u8")
}

fn upack_esi_50(
    p: &mut UpackRangeState,
    mut loc_eax: u32,
    old_ecx: u32,
    old_ebp: usize,
    bs: &mut [u8],
) -> Result<u32, &'static str> {
    while loc_eax < old_ecx {
        let prob = upack_probability_offset(old_ebp, loc_eax, 0)?;
        let bit = u32::from(upack_bit(p, prob, bs)?);
        loc_eax = loc_eax
            .checked_mul(2)
            .and_then(|value| value.checked_add(bit))
            .ok_or("upack_lzma_integer_overflow")?;
    }
    Ok(loc_eax - old_ecx)
}

#[expect(
    clippy::similar_names,
    reason = "parameters mirror unpacker x86 register names"
)]
fn upack_esi_54(
    p: &mut UpackRangeState,
    old_eax: u32,
    old_ecx: &mut u32,
    old_edx: &mut usize,
    bs: &mut [u8],
) -> Result<u32, &'static str> {
    *old_ecx = (*old_ecx & 0xffff_ff00) | 8;
    let first = upack_bit(p, *old_edx, bs)?;
    *old_edx = old_edx.checked_add(4).ok_or("upack_lzma_index_overflow")?;
    let mut ret = (old_eax & 0xffff_ff00) | 1;
    if first {
        let second = upack_bit(p, *old_edx, bs)?;
        ret |= 8;
        if second {
            *old_ecx <<= 5;
            ret = 0x11;
        }
    }
    let loc = upack_esi_50(
        p,
        1,
        *old_ecx,
        upack_probability_offset(*old_edx, ret, 0)?,
        bs,
    )?;
    Ok(ret + loc)
}

#[derive(Clone, Copy)]
struct UpackRangeState {
    p0: usize,
    p1: u32,
    p2: u32,
}

fn copy_backref(
    bytes: &mut [u8],
    cursor: &mut usize,
    _start: usize,
    end: usize,
    distance: usize,
    len: usize,
) -> Result<(), &'static str> {
    if distance == 0 {
        return Err("upack_lzma_zero_distance");
    }
    let mut src = cursor
        .checked_sub(distance)
        .ok_or("upack_lzma_backref_before_start")?;
    let stop = cursor
        .checked_add(len)
        .ok_or("upack_lzma_output_overflow")?;
    if stop > end || stop > bytes.len() {
        return Err("upack_lzma_output_out_of_bounds");
    }
    while *cursor < stop {
        let value = *bytes.get(src).ok_or("upack_lzma_backref_out_of_bounds")?;
        bytes[*cursor] = value;
        src += 1;
        *cursor += 1;
    }
    Ok(())
}

fn section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let start = usize::try_from(section.start).ok()?;
    let size = usize::try_from(section.raw_size).ok()?;
    bytes.get(start..start.checked_add(size)?)
}

fn offset_from_va(value: u32, base: u32) -> Result<usize, &'static str> {
    value
        .checked_sub(base)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("upack_pointer_out_of_bounds")
}

fn checked_add_signed(base: usize, delta: i32) -> Option<usize> {
    let value = i64::try_from(base).ok()?.checked_add(i64::from(delta))?;
    usize::try_from(value).ok()
}

fn contains_u32(total: u32, start: u32, size: u32) -> bool {
    start
        .checked_add(size)
        .is_some_and(|end| start <= total && end <= total)
}

fn require(bytes: &[u8], offset: usize, len: usize) -> Result<(), &'static str> {
    if offset
        .checked_add(len)
        .is_some_and(|end| end <= bytes.len())
    {
        Ok(())
    } else {
        Err("upack_range_out_of_bounds")
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u32_be_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    let target = bytes
        .get_mut(offset..offset.checked_add(4).ok_or("upack_write_overflow")?)
        .ok_or("upack_write_out_of_bounds")?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_upack_image() {
        assert_eq!(
            unpack_pe(&[], &PeAnalysis::default()).unwrap_err(),
            "upack_section_count_too_low"
        );
    }
}
