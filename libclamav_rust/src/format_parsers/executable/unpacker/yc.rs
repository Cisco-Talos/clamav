// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust yC PE decryptor.
//!
//! This module ports `ClamAV` `libclamav/yc.c` plus the PE32 yC dispatch checks
//! from `libclamav/pe.c`. yC is an in-place decryptor rather than a stream
//! decompressor: the unpacked child is the original PE with decrypted sections
//! and the final yC section removed.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> yC entrypoint emulator -> key/section discovery
//!     -> in-place section decrypt -> PE image without final yC section
//! ```
//!
//! Emulator jumps, emulator bytes, image size, and PE32 dispatch are bounded so
//! malformed yC candidates cannot force unbounded emulation.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{PeAnalysis, PeSection},
};

const MAX_YC_IMAGE_BYTES: usize = 128 * 1024 * 1024;
const MAX_YC_EMU_JUMPS: u32 = 1_000_000;
const MAX_YC_EMU_BYTES: usize = 16 * 1024 * 1024;

pub(crate) type YcUnpacked = UnpackedArtifact;

pub(crate) fn unpack_pe(bytes: &[u8], analysis: &PeAnalysis) -> Result<YcUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("yc_pe64_not_supported_by_clamav");
    }
    if analysis.sections.len() <= 1 {
        return Err("yc_section_count_too_low");
    }
    let ep_rva = analysis.entrypoint_rva.ok_or("yc_entrypoint_missing")?;
    let last_index = analysis.sections.len() - 1;
    let yc_section = &analysis.sections[last_index];
    if ep_rva != yc_section.virtual_address.saturating_add(0x60) {
        return Err("yc_entrypoint_not_recognized");
    }
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    let (ecx, offset) = detect_yc_variant(ep).ok_or("yc_stub_not_recognized")?;
    let marker_offset = checked_add_signed(0x63, offset as isize)?;
    let marker_end = marker_offset
        .checked_add(3)
        .ok_or("yc_tail_marker_range_invalid")?;
    if ep.get(marker_offset..marker_end) != Some(&[0xaa, 0xe2, 0xcc]) {
        return Err("yc_tail_marker_missing");
    }
    let decryptor_end = checked_add_signed(
        usize::try_from(yc_section.raw_offset)
            .map_err(|_| "yc_section_offset_overflow")?
            .checked_add(0xc6)
            .and_then(|value| value.checked_add(ecx as usize))
            .ok_or("yc_decryptor_range_invalid")?,
        offset as isize,
    )?;
    if decryptor_end > bytes.len() {
        return Err("yc_decryptor_range_invalid");
    }
    let raw_size = usize::try_from(yc_section.raw_size).map_err(|_| "yc_raw_size_overflow")?;
    let output_len = bytes
        .len()
        .checked_sub(raw_size)
        .ok_or("yc_output_size_underflow")?;
    if bytes.len() > MAX_YC_IMAGE_BYTES || output_len > MAX_YC_IMAGE_BYTES {
        return Err("yc_image_size_limit_exceeded");
    }
    let working_len = yc_working_len(yc_section, ecx, offset, output_len)?;
    if working_len > bytes.len() {
        return Err("yc_decryptor_range_invalid");
    }
    let mut fbuf = bytes[..working_len].to_vec();
    yc_decrypt(
        &mut fbuf,
        &analysis.sections,
        last_index,
        ecx,
        offset,
        output_len,
    )?;
    fbuf.truncate(output_len);
    Ok(UnpackedArtifact {
        bytes: fbuf,
        source_offset: yc_section.start,
        source_size: u64::from(yc_section.raw_size),
    })
}

fn detect_yc_variant(ep: &[u8]) -> Option<(u32, i16)> {
    if ep.get(..15)
        == Some(&[
            0x55, 0x8b, 0xec, 0x53, 0x56, 0x57, 0x60, 0xe8, 0, 0, 0, 0, 0x5d, 0x81, 0xed,
        ])
        && ep.get(0x26..0x33)
            == Some(&[
                0x8d, 0x3a, 0x8b, 0xf7, 0x33, 0xc0, 0xeb, 0x04, 0x90, 0xeb, 0x01, 0xc2, 0xac,
            ])
        && ep.get(0x13) == Some(&0xb9)
        && read_u16_le(ep, 0x18) == Some(0xe981)
        && ep.get(0x1e..0x22) == Some(&[0x8b, 0xd5, 0x81, 0xc2])
        && 0x6c_u32
            .wrapping_sub(read_u32_le(ep, 0x0f)?)
            .wrapping_add(read_u32_le(ep, 0x22)?)
            == 0xc6
    {
        return Some((
            read_u32_le(ep, 0x14)?.wrapping_sub(read_u32_le(ep, 0x1a)?),
            0,
        ));
    }

    if ep.get(..9) == Some(&[0x55, 0x8b, 0xec, 0x83, 0xec, 0x40, 0x53, 0x56, 0x57])
        && ep.get(0x17..0x1f) == Some(&[0xe8, 0, 0, 0, 0, 0x5d, 0x81, 0xed])
        && ep.get(0x23) == Some(&0xb9)
        && 0x6c_u32
            .wrapping_sub(read_u32_le(ep, 0x1f)?)
            .wrapping_add(read_u32_le(ep, 0x32)?)
            == 0xc6
    {
        return Some((
            read_u32_le(ep, 0x24)?.wrapping_sub(read_u32_le(ep, 0x2a)?),
            0x10,
        ));
    }

    if ep.get(..9) == Some(&[0x60, 0xe8, 0, 0, 0, 0, 0x5d, 0x81, 0xed])
        && ep.get(0x0d) == Some(&0xb9)
        && read_u16_le(ep, 0x12) == Some(0xbd8d)
        && ep.get(0x18..0x1b) == Some(&[0x8b, 0xf7, 0xac])
        && 0x66_u32
            .wrapping_sub(read_u32_le(ep, 0x09)?)
            .wrapping_add(read_u32_le(ep, 0x14)?)
            == 0xae
    {
        return Some((read_u32_le(ep, 0x0e)?, -0x18));
    }

    None
}

fn yc_working_len(
    yc_section: &PeSection,
    ecx: u32,
    offset: i16,
    output_len: usize,
) -> Result<usize, &'static str> {
    let ycsect = section_offset_with_delta(yc_section, offset)?;
    let code_end_base = ycsect
        .checked_add(0xc6)
        .and_then(|value| value.checked_add(ecx as usize))
        .ok_or("yc_decryptor_range_invalid")?;
    let first_decryptor_end = ycsect
        .checked_add(0x93)
        .and_then(|value| value.checked_add(0x32))
        .ok_or("yc_decryptor_range_invalid")?;
    let section_decryptor_delta = if offset == -0x18 { 0x3ea } else { 0x457 };
    let section_decryptor_end = ycsect
        .checked_add(section_decryptor_delta)
        .and_then(|value| value.checked_add(0x32))
        .ok_or("yc_decryptor_range_invalid")?;
    let oep_end = ycsect
        .checked_add(0xa0f)
        .and_then(|value| value.checked_add(4))
        .ok_or("yc_decryptor_range_invalid")?;
    Ok(output_len
        .max(code_end_base)
        .max(first_decryptor_end)
        .max(section_decryptor_end)
        .max(oep_end))
}

fn yc_decrypt(
    fbuf: &mut [u8],
    sections: &[PeSection],
    last_index: usize,
    ecx: u32,
    offset: i16,
    output_len: usize,
) -> Result<(), &'static str> {
    if !(0x801..0x2000).contains(&ecx) {
        return Err("yc_ecx_out_of_range");
    }
    let yc_section = &sections[last_index];
    let ycsect = section_offset_with_delta(yc_section, offset)?;
    let code_end_base = ycsect
        .checked_add(0xc6)
        .and_then(|value| value.checked_add(ecx as usize))
        .ok_or("yc_decryptor_range_invalid")?;
    if code_end_base > fbuf.len() {
        return Err("yc_decryptor_range_invalid");
    }

    let decryptor = ycsect.checked_add(0x93).ok_or("yc_offset_overflow")?;
    let code = ycsect.checked_add(0xc6).ok_or("yc_offset_overflow")?;
    yc_poly_emulator(fbuf, decryptor, code, ecx as usize, ecx as usize)?;

    let section_decryptor_delta = if offset == -0x18 { 0x3ea } else { 0x457 };
    let section_decryptor = ycsect
        .checked_add(section_decryptor_delta)
        .ok_or("yc_offset_overflow")?;
    for section in &sections[..last_index] {
        if section.raw_offset == 0 || section.raw_size == 0 || should_skip_section(&section.name) {
            continue;
        }
        let code = usize::try_from(section.raw_offset).map_err(|_| "yc_section_offset_overflow")?;
        let max_emu = output_len
            .checked_sub(code)
            .ok_or("yc_section_range_invalid")?;
        let raw_size = usize::try_from(section.raw_size).map_err(|_| "yc_raw_size_overflow")?;
        yc_poly_emulator(fbuf, section_decryptor, code, raw_size, max_emu)?;
    }

    let pe = read_u32_le(fbuf, 0x3c)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("yc_pe_offset_missing")?;
    write_u16(
        fbuf,
        pe + 6,
        u16::try_from(last_index).map_err(|_| "yc_section_count_overflow")?,
    )?;
    let import_dir_start = pe
        .checked_add(0x80)
        .ok_or("yc_import_directory_out_of_bounds")?;
    let import_dir_end = import_dir_start
        .checked_add(8)
        .ok_or("yc_import_directory_out_of_bounds")?;
    fbuf.get_mut(import_dir_start..import_dir_end)
        .ok_or("yc_import_directory_out_of_bounds")?
        .fill(0);
    let oep = read_u32_le(
        fbuf,
        ycsect
            .checked_add(0xa0f)
            .ok_or("yc_original_entrypoint_overflow")?,
    )
    .ok_or("yc_original_entrypoint_missing")?;
    write_u32(fbuf, pe + 0x28, oep)?;
    let image_size = read_u32_le(fbuf, pe + 0x50)
        .and_then(|value| value.checked_sub(yc_section.virtual_size))
        .ok_or("yc_image_size_patch_invalid")?;
    write_u32(fbuf, pe + 0x50, image_size)?;
    Ok(())
}

fn yc_poly_emulator(
    fbuf: &mut [u8],
    decryptor_offset: usize,
    code_offset: usize,
    ecx: usize,
    max_emu: usize,
) -> Result<(), &'static str> {
    let mut cl = low_byte_usize(ecx);
    let steps = ecx.min(max_emu);
    if steps > MAX_YC_EMU_BYTES {
        return Err("yc_emulation_size_limit_exceeded");
    }
    let mut max_jmp_loop = MAX_YC_EMU_JUMPS;
    for i in 0..steps {
        let code_index = code_offset
            .checked_add(i)
            .ok_or("yc_code_offset_overflow")?;
        let mut al = *fbuf.get(code_index).ok_or("yc_code_out_of_bounds")?;
        let mut j = 0usize;
        while j < 0x30 {
            let op_index = decryptor_offset
                .checked_add(j)
                .ok_or("yc_decryptor_offset_overflow")?;
            let opcode = *fbuf.get(op_index).ok_or("yc_decryptor_out_of_bounds")?;
            match opcode {
                0xeb => {
                    j += 1;
                    let delta = fbuf
                        .get(decryptor_offset + j)
                        .copied()
                        .ok_or("yc_decryptor_out_of_bounds")?
                        .cast_signed();
                    if max_jmp_loop == 0 {
                        return Err("yc_jump_loop_limit_exceeded");
                    }
                    max_jmp_loop -= 1;
                    j = checked_add_signed(j, delta as isize)?;
                }
                0xfe => {
                    al = al.wrapping_sub(1);
                    j += 1;
                }
                0x2a => {
                    al = al.wrapping_sub(cl);
                    j += 1;
                }
                0x02 => {
                    al = al.wrapping_add(cl);
                    j += 1;
                }
                0x32 => {
                    al ^= cl;
                    j += 1;
                }
                0x04 => {
                    j += 1;
                    al = al.wrapping_add(
                        *fbuf
                            .get(decryptor_offset + j)
                            .ok_or("yc_decryptor_out_of_bounds")?,
                    );
                }
                0x34 => {
                    j += 1;
                    al ^= *fbuf
                        .get(decryptor_offset + j)
                        .ok_or("yc_decryptor_out_of_bounds")?;
                }
                0x2c => {
                    j += 1;
                    al = al.wrapping_sub(
                        *fbuf
                            .get(decryptor_offset + j)
                            .ok_or("yc_decryptor_out_of_bounds")?,
                    );
                }
                0xc0 => {
                    j += 1;
                    let support = *fbuf
                        .get(decryptor_offset + j)
                        .ok_or("yc_decryptor_out_of_bounds")?;
                    j += 1;
                    let count = *fbuf
                        .get(decryptor_offset + j)
                        .ok_or("yc_decryptor_out_of_bounds")?;
                    if support == 0xc0 {
                        al = al.rotate_left(u32::from(count & 7));
                    } else {
                        al = al.rotate_right(u32::from(count & 7));
                    }
                }
                0xd2 => {
                    j += 1;
                    let support = *fbuf
                        .get(decryptor_offset + j)
                        .ok_or("yc_decryptor_out_of_bounds")?;
                    j += 1;
                    if support == 0xc8 {
                        al = al.rotate_right(u32::from(cl & 7));
                    } else {
                        al = al.rotate_left(u32::from(cl & 7));
                    }
                }
                0x90 | 0xf8 | 0xf9 => {}
                _ => return Err("yc_unhandled_opcode"),
            }
            j += 1;
        }
        *fbuf.get_mut(code_index).ok_or("yc_code_out_of_bounds")? = al;
        cl = cl.wrapping_sub(1);
    }
    Ok(())
}

fn should_skip_section(name: &str) -> bool {
    const SKIPPED_SECTION_NAMES: &[&str] = &[
        "rsrc", ".rsr", "relo", ".rel", ".eda", ".rda", ".ida", ".tls",
    ];

    SKIPPED_SECTION_NAMES
        .iter()
        .any(|skip| name.eq_ignore_ascii_case(skip))
        || name
            .as_bytes()
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"yc"))
}

fn section_offset_with_delta(section: &PeSection, delta: i16) -> Result<usize, &'static str> {
    let raw = usize::try_from(section.raw_offset).map_err(|_| "yc_section_offset_overflow")?;
    checked_add_signed(raw, isize::from(delta))
}

fn checked_add_signed(value: usize, delta: isize) -> Result<usize, &'static str> {
    if delta >= 0 {
        value
            .checked_add(usize::try_from(delta).map_err(|_| "yc_offset_overflow")?)
            .ok_or("yc_offset_overflow")
    } else {
        value
            .checked_sub(delta.unsigned_abs())
            .ok_or("yc_offset_underflow")
    }
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
                    .ok_or("yc_header_write_out_of_bounds")?,
        )
        .ok_or("yc_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or("yc_header_write_out_of_bounds")?,
        )
        .ok_or("yc_header_write_out_of_bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn low_byte_usize(value: usize) -> u8 {
    u8::try_from(value & 0xff).expect("masked low byte fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_yc_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "yc_section_count_too_low"
        );
    }

    #[test]
    fn skip_section_match_is_ascii_case_insensitive_without_allocation() {
        assert!(should_skip_section(".TLS"));
        assert!(should_skip_section("Yc0"));
        assert!(!should_skip_section(".text"));
    }

    #[test]
    fn working_len_omits_unused_yc_section_tail() {
        let yc_section = PeSection {
            raw_offset: 0x2000,
            raw_size: 0x10_0000,
            start: 0x2000,
            end: 0x10_2000,
            ..PeSection::default()
        };
        let output_len = 0x2000usize;
        let working_len = yc_working_len(&yc_section, 0x900, 0, output_len).unwrap();

        assert_eq!(working_len, 0x2a13);
        assert!(working_len < output_len + yc_section.raw_size as usize);
    }
}
