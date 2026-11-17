// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust Petite PE unpacking helpers.
//!
//! This module ports `ClamAV` `libclamav/petite.c` plus the PE32 dispatch logic
//! from `libclamav/pe.c`. `ClamAV` does not support Petite level-zero compression
//! and neither does this port.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> Petite section descriptors -> bounded section decode
//!     -> rebuilt PE sections -> ClamAV-style PE rebuild
//! ```
//!
//! The parser caps temporary buffers and section descriptors. Petite level-zero
//! compression is reported unsupported to match `ClamAV`.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_PETITE_BUFFER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PETITE_SECTIONS: usize = 96;

pub(crate) type PetiteUnpacked = UnpackedArtifact;

#[derive(Clone, Debug)]
struct PetiteSection {
    rva: u32,
    vsz: u32,
    rsz: u32,
}

struct PetiteDecoded {
    bytes: Vec<u8>,
    sections: Vec<RebuildSection>,
    entrypoint_rva: u32,
}

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<PetiteUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("petite_pe64_not_supported_by_clamav");
    }
    if analysis.sections.len() < 2 {
        return Err("petite_section_count_too_low");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "petite_image_base_out_of_range")?;
    let ep_rva = analysis.entrypoint_rva.ok_or("petite_entrypoint_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    if ep.len() < 200 {
        return Err("petite_entrypoint_sample_too_short");
    }
    let found = if ep.first() == Some(&0xb8)
        && read_u32_le(ep, 1)
            == analysis
                .sections
                .last()
                .and_then(|section| section.virtual_address.checked_add(image_base))
    {
        2
    } else if ep.first() == Some(&0xb8)
        && read_u32_le(ep, 1)
            == analysis
                .sections
                .get(analysis.sections.len() - 2)
                .and_then(|section| section.virtual_address.checked_add(image_base))
    {
        1
    } else {
        return Err("petite_stub_not_recognized");
    };
    if read_u32_le(ep, 0x80) == Some(0x163c_988d) {
        return Err("petite_level_zero_not_supported_by_clamav");
    }
    let min_rva = analysis
        .sections
        .iter()
        .map(|section| section.virtual_address)
        .min()
        .ok_or("petite_min_rva_missing")?;
    let max_rva = analysis
        .sections
        .iter()
        .filter_map(|section| section.virtual_address.checked_add(section.virtual_size))
        .max()
        .ok_or("petite_max_rva_missing")?;
    let dsize = max_rva
        .checked_sub(min_rva)
        .ok_or("petite_image_range_invalid")?;
    if dsize == 0 || u64::from(dsize) > MAX_PETITE_BUFFER_BYTES {
        return Err("petite_buffer_size_limit_exceeded");
    }
    let mut mapped = vec![0u8; usize::try_from(dsize).map_err(|_| "petite_buffer_size_overflow")?];
    for section in &analysis.sections {
        if section.raw_offset == 0 || section.raw_size == 0 {
            continue;
        }
        let src = section_bytes(bytes, section).ok_or("petite_section_range_invalid")?;
        let dst = usize::try_from(
            section
                .virtual_address
                .checked_sub(min_rva)
                .ok_or("petite_section_rva_underflow")?,
        )
        .map_err(|_| "petite_section_rva_overflow")?;
        let len = src.len().min(
            usize::try_from(section.virtual_size.max(section.raw_size))
                .map_err(|_| "petite_section_size_overflow")?,
        );
        let end = dst
            .checked_add(len)
            .ok_or("petite_mapped_section_range_invalid")?;
        mapped
            .get_mut(dst..end)
            .ok_or("petite_mapped_section_range_invalid")?
            .copy_from_slice(&src[..len]);
    }
    let sect_count = analysis.sections.len() - usize::from(found == 1);
    let decoded = inflate_petite(
        &mut mapped,
        min_rva,
        &analysis.sections[..sect_count],
        image_base,
        ep_rva,
        found,
    )?;
    let source_size = bytes.len() as u64;
    let mut options = RebuildOptions::pe32(image_base, decoded.entrypoint_rva);
    if let Some(resource) = analysis
        .data_directories
        .iter()
        .find(|directory| directory.index == 2 && directory.rva != 0 && directory.size != 0)
    {
        options.resource_rva = resource.rva;
        options.resource_size = resource.size;
    }
    let bytes = rebuild::rebuild_pe_from_sections(&decoded.bytes, &decoded.sections, options)?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: 0,
        source_size,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the Petite bitstream decoder is kept contiguous to mirror the packed stub state machine"
)]
fn inflate_petite(
    buf: &mut [u8],
    min_rva: u32,
    sections: &[PeSection],
    image_base: u32,
    pep: u32,
    version: u32,
) -> Result<PetiteDecoded, &'static str> {
    let mut packed = if version == 2 {
        rva_index(
            sections
                .last()
                .ok_or("petite_packed_section_missing")?
                .virtual_address
                .checked_add(0x1b8)
                .ok_or("petite_packed_offset_overflow")?,
            min_rva,
            buf.len(),
        )?
    } else {
        rva_index(
            sections
                .last()
                .ok_or("petite_packed_section_missing")?
                .virtual_address
                .checked_add(0x178)
                .ok_or("petite_packed_offset_overflow")?,
            min_rva,
            buf.len(),
        )?
    };
    let mut grown = if version == 1 { 0x323u32 } else { 0x355u32 };
    let skew = if version == 1 { 0x34u32 } else { 0x35u32 };
    let mut bottom = 0u32;
    let mut usects = Vec::<PetiteSection>::new();
    let mut check4resources = 0usize;
    let mut enc_ep = 0u32;
    let mut irva = 0u32;
    let mut mangled = false;

    loop {
        let srva_raw = read_u32_le(buf, packed).ok_or("petite_packed_table_out_of_bounds")?;
        if srva_raw == 0 {
            if usects.is_empty() {
                return Err("petite_no_output_sections");
            }
            usects.sort_by_key(|section| section.rva);
            for i in 0..usects.len().saturating_sub(1) {
                let next = usects[i + 1].rva;
                if let Some(vsz) = next.checked_sub(usects[i].rva)
                    && usects[i].vsz != vsz
                {
                    usects[i].vsz = vsz;
                }
            }
            let output_capacity = usects
                .iter()
                .filter(|section| section.rsz != 0)
                .filter_map(|section| usize::try_from(section.rsz).ok())
                .try_fold(0usize, usize::checked_add)
                .unwrap_or(buf.len())
                .min(buf.len());
            let mut output = Vec::with_capacity(output_capacity);
            let mut rebuild_sections = Vec::with_capacity(usects.len());
            for section in &usects {
                if section.rsz == 0 {
                    continue;
                }
                let start = rva_index(section.rva, min_rva, buf.len())?;
                let size =
                    usize::try_from(section.rsz).map_err(|_| "petite_section_size_overflow")?;
                let end = start
                    .checked_add(size)
                    .ok_or("petite_output_section_range_invalid")?;
                if end <= buf.len() {
                    let source_offset =
                        u32::try_from(output.len()).map_err(|_| "petite_output_size_overflow")?;
                    output.extend_from_slice(&buf[start..end]);
                    rebuild_sections.push(RebuildSection {
                        source_offset,
                        rva: section.rva,
                        virtual_size: section.vsz,
                        raw_size: section.rsz,
                    });
                }
            }
            if output.is_empty() || rebuild_sections.is_empty() {
                return Err("petite_empty_output");
            }
            let entrypoint_rva = if enc_ep != 0 && !mangled {
                enc_ep.checked_sub(image_base).unwrap_or(pep)
            } else {
                pep
            };
            return Ok(PetiteDecoded {
                bytes: output,
                sections: rebuild_sections,
                entrypoint_rva,
            });
        }
        let srva = srva_raw & 0x7fff_ffff;
        if srva_raw != srva {
            check4resources = 0;
            let size = srva;
            let bottom_raw = read_u32_le(buf, packed + 8).ok_or("petite_bottom_missing")?;
            bottom = bottom_raw.checked_add(4).ok_or("petite_bottom_overflow")?;
            let byte_count = size.checked_mul(4).ok_or("petite_copy_size_overflow")?;
            let ssrc_rva = read_u32_le(buf, packed + 4)
                .and_then(|value| value.checked_sub((size - 1).checked_mul(4)?))
                .ok_or("petite_copy_source_invalid")?;
            let ddst_rva = read_u32_le(buf, packed + 8)
                .and_then(|value| value.checked_sub((size - 1).checked_mul(4)?))
                .ok_or("petite_copy_dest_invalid")?;
            let ssrc = rva_index(ssrc_rva, min_rva, buf.len())?;
            let ddst = rva_index(ddst_rva, min_rva, buf.len())?;
            let len = usize::try_from(byte_count).map_err(|_| "petite_copy_size_overflow")?;
            copy_within_checked(buf, ssrc, ddst, len)?;
            packed = packed
                .checked_add(0x0c)
                .ok_or("petite_packed_offset_overflow")?;
            continue;
        }

        let mut size = read_u32_le(buf, packed + 4).ok_or("petite_unpack_size_missing")?;
        let thisrva = read_u32_le(buf, packed + 8).ok_or("petite_section_rva_missing")?;
        packed = packed
            .checked_add(0x10)
            .ok_or("petite_packed_offset_overflow")?;
        if usects.len() >= MAX_PETITE_SECTIONS {
            return Err("petite_section_limit_exceeded");
        }
        let mut out_section = PetiteSection {
            rva: thisrva,
            rsz: size,
            vsz: bottom
                .checked_sub(thisrva)
                .filter(|value| *value > 0)
                .unwrap_or(size),
        };
        if size == 0 {
            usects.push(out_section);
            continue;
        }
        let mut ssrc = rva_index(srva, min_rva, buf.len())?;
        let mut ddst = rva_index(thisrva, min_rva, buf.len())?;
        let containing = sections
            .iter()
            .find(|section| {
                section.virtual_address <= out_section.rva
                    && out_section
                        .rva
                        .checked_sub(section.virtual_address)
                        .is_some_and(|delta| delta < section.virtual_size)
            })
            .ok_or("petite_output_section_not_contained")?;
        if check4resources == 0 {
            out_section.rva = containing.virtual_address;
            out_section.rsz = thisrva
                .checked_sub(containing.virtual_address)
                .and_then(|value| value.checked_add(size))
                .ok_or("petite_resource_section_size_invalid")?;
        }
        usects.push(out_section);

        let (check1, check2, goback) = if size < 0x10000 {
            (0xffff_c060u32, 0xffff_fc60u32, 5u8)
        } else if size < 0x40000 {
            (0xffff_8180u32, 0xffff_f980u32, 7u8)
        } else {
            (0xffff_8300u32, 0xffff_fb00u32, 8u8)
        };
        size = size.checked_sub(1).ok_or("petite_unpack_size_underflow")?;
        let first = *buf.get(ssrc).ok_or("petite_source_out_of_bounds")?;
        *buf.get_mut(ddst).ok_or("petite_dest_out_of_bounds")? = first;
        ssrc += 1;
        ddst += 1;
        let mut mydl = 0u8;
        let mut oldback = 0i32;
        let mut backbytes = 0i32;
        while size > 0 {
            if !double_dl(buf, &mut ssrc, &mut mydl)? {
                let byte =
                    *buf.get(ssrc).ok_or("petite_source_out_of_bounds")? ^ low_byte_u32(size);
                *buf.get_mut(ddst).ok_or("petite_dest_out_of_bounds")? = byte;
                ssrc += 1;
                ddst += 1;
                size -= 1;
                continue;
            }
            let mut addsize = 0u32;
            backbytes = backbytes
                .checked_add(1)
                .ok_or("petite_backbytes_overflow")?;
            loop {
                let bit = i32::from(double_dl(buf, &mut ssrc, &mut mydl)?);
                backbytes = backbytes
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(bit))
                    .ok_or("petite_backbytes_overflow")?;
                if !double_dl(buf, &mut ssrc, &mut mydl)? {
                    break;
                }
            }
            backbytes -= 3;
            let mut backsize;
            if backbytes >= 0 {
                let mut count = goback;
                while count != 0 {
                    let bit = i32::from(double_dl(buf, &mut ssrc, &mut mydl)?);
                    backbytes = backbytes
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(bit))
                        .ok_or("petite_backbytes_overflow")?;
                    count -= 1;
                }
                backbytes ^= -1;
                let back_u32 = backbytes.cast_unsigned();
                addsize += 1 + u32::from(back_u32 < check2) + u32::from(back_u32 < check1);
                oldback = backbytes;
                backsize = 0;
            } else {
                backsize = (backbytes + 1).cast_unsigned();
                backbytes = oldback;
            }
            let bit = u32::from(double_dl(buf, &mut ssrc, &mut mydl)?);
            backsize = backsize
                .checked_mul(2)
                .and_then(|value| value.checked_add(bit))
                .ok_or("petite_backsize_overflow")?;
            let bit = u32::from(double_dl(buf, &mut ssrc, &mut mydl)?);
            backsize = backsize
                .checked_mul(2)
                .and_then(|value| value.checked_add(bit))
                .ok_or("petite_backsize_overflow")?;
            if backsize == 0 {
                backsize = 1;
                loop {
                    let bit = u32::from(double_dl(buf, &mut ssrc, &mut mydl)?);
                    backsize = backsize
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(bit))
                        .ok_or("petite_backsize_overflow")?;
                    if !double_dl(buf, &mut ssrc, &mut mydl)? {
                        break;
                    }
                }
                backsize += 2;
            }
            backsize = backsize
                .checked_add(addsize)
                .ok_or("petite_backsize_overflow")?;
            size = size.wrapping_sub(backsize);
            copy_from_signed_backref(buf, &mut ddst, backbytes, backsize as usize)?;
            backbytes = 0;
        }

        if let Some(last) = usects.last_mut() {
            maybe_strip_petite_code(
                buf,
                ddst,
                last,
                grown,
                skew,
                &mut enc_ep,
                &mut irva,
                &mut mangled,
            );
        }
        check4resources += 1;
        if version == 1 {
            grown = 0x323;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn maybe_strip_petite_code(
    buf: &[u8],
    ddst: usize,
    section: &mut PetiteSection,
    grown: u32,
    skew: u32,
    enc_ep: &mut u32,
    irva: &mut u32,
    mangled: &mut bool,
) {
    if section.rsz <= grown {
        return;
    }
    let candidates = [0u32, skew];
    for reloc in candidates {
        let Some(grown_with_reloc) = grown.checked_add(reloc) else {
            continue;
        };
        if section.rsz <= grown_with_reloc {
            continue;
        }
        let Some(base) = usize::try_from(grown_with_reloc)
            .ok()
            .and_then(|offset| ddst.checked_sub(offset))
        else {
            continue;
        };
        let Some(test_offset) = base.checked_add(5 + 0x4f) else {
            continue;
        };
        if read_u32_le(buf, test_offset) == Some(0x645e_c033)
            && read_u32_le(buf, test_offset + 4) == Some(0x1b8b_188b)
        {
            let Some(code_offset) = base.checked_add(0x0f) else {
                continue;
            };
            if code_offset >= 8
                && read_u32_le(buf, code_offset - 8)
                    .zip(read_u32_le(buf, code_offset - 4))
                    .is_some_and(|(a, b)| {
                        let test1 = a ^ 0x9d66_61aa;
                        let test2 = b ^ 0xe908_c483;
                        test1 == test2
                    })
            {
                let test1 = read_u32_le(buf, code_offset - 8).unwrap_or_default() ^ 0x9d66_61aa;
                *irva = read_u32_le(buf, code_offset + 0x112).unwrap_or_default();
                *enc_ep = read_u32_le(buf, code_offset).unwrap_or_default() ^ test1;
                *mangled = read_u32_le(buf, code_offset + 0x1b1) != Some(0x9090_9090);
            }
            section.rsz = section.rsz.saturating_sub(grown_with_reloc);
            break;
        }
    }
}

fn copy_from_signed_backref(
    buf: &mut [u8],
    ddst: &mut usize,
    backbytes: i32,
    backsize: usize,
) -> Result<(), &'static str> {
    let mut src = if backbytes >= 0 {
        ddst.checked_add(usize::try_from(backbytes).map_err(|_| "petite_backref_out_of_bounds")?)
    } else {
        ddst.checked_sub(
            usize::try_from(backbytes.unsigned_abs())
                .map_err(|_| "petite_backref_out_of_bounds")?,
        )
    }
    .ok_or("petite_backref_out_of_bounds")?;
    let end = ddst
        .checked_add(backsize)
        .ok_or("petite_output_offset_overflow")?;
    if end > buf.len() {
        return Err("petite_output_out_of_bounds");
    }
    while *ddst < end {
        let byte = *buf.get(src).ok_or("petite_backref_out_of_bounds")?;
        buf[*ddst] = byte;
        src = src.checked_add(1).ok_or("petite_backref_out_of_bounds")?;
        *ddst = ddst.checked_add(1).ok_or("petite_output_offset_overflow")?;
    }
    Ok(())
}

fn double_dl(buf: &[u8], scur: &mut usize, mydl: &mut u8) -> Result<bool, &'static str> {
    let olddl = *mydl;
    *mydl = mydl.wrapping_mul(2);
    if olddl == 0 || olddl == 0x80 {
        let byte = *buf.get(*scur).ok_or("petite_input_out_of_bounds")?;
        *mydl = byte.wrapping_mul(2).wrapping_add(1);
        *scur = scur.checked_add(1).ok_or("petite_source_offset_overflow")?;
        Ok(byte >> 7 != 0)
    } else {
        Ok(olddl >> 7 != 0)
    }
}

fn copy_within_checked(
    buf: &mut [u8],
    source: usize,
    dest: usize,
    len: usize,
) -> Result<(), &'static str> {
    let source_end = source.checked_add(len).ok_or("petite_copy_range_invalid")?;
    let dest_end = dest.checked_add(len).ok_or("petite_copy_range_invalid")?;
    if source_end > buf.len() || dest_end > buf.len() {
        return Err("petite_copy_range_invalid");
    }
    buf.copy_within(source..source_end, dest);
    Ok(())
}

fn rva_index(rva: u32, min_rva: u32, len: usize) -> Result<usize, &'static str> {
    let index = rva.checked_sub(min_rva).ok_or("petite_rva_underflow")?;
    let index = usize::try_from(index).map_err(|_| "petite_rva_overflow")?;
    if index > len {
        return Err("petite_rva_out_of_bounds");
    }
    Ok(index)
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

fn low_byte_u32(value: u32) -> u8 {
    u8::try_from(value & 0xff).expect("masked low byte fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_petite_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "petite_section_count_too_low"
        );
    }

    #[test]
    fn strip_code_skips_overflowing_relocation_candidate() {
        let bytes = vec![0u8; 128];
        let mut section = PetiteSection {
            rva: 0,
            vsz: 0,
            rsz: u32::MAX,
        };
        let mut enc_ep = 0;
        let mut irva = 0;
        let mut mangled = false;

        maybe_strip_petite_code(
            &bytes,
            64,
            &mut section,
            u32::MAX - 1,
            4,
            &mut enc_ep,
            &mut irva,
            &mut mangled,
        );

        assert_eq!(section.rsz, u32::MAX);
        assert_eq!(enc_ep, 0);
        assert_eq!(irva, 0);
        assert!(!mangled);
    }
}
