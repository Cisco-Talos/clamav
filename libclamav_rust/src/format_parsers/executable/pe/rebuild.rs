// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! ClamAV-style PE rebuild helpers.
//!
//! `ClamAV`'s legacy PE unpackers usually decode one or more in-memory sections
//! and then call `cli_rebuildpe()` or `cli_rebuildpe_align()` to wrap those
//! bytes in a synthetic, parseable PE. This module ports that bounded rebuild
//! behavior into safe Rust so packer-specific modules can concentrate on
//! decoding and section discovery instead of each inventing a PE wrapper.
//!
//! ## References
//!
//! The compatibility baseline is `ClamAV` `rebuildpe.c` and `rebuildpe.h`.
//! Rebuilt headers are shaped as valid PE/COFF files according to the Microsoft
//! PE/COFF specification:
//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>.
//!
//! ## Layout
//!
//! ```text
//! rebuilt PE32 layout, multi-section capable
//!
//!   0000  MZ stub with e_lfanew = 0xd0
//!   00d0  PE signature + COFF header + PE32 optional header
//!   0148  zeroed data directory table
//!         resource directory RVA/size copied from RebuildOptions
//!   01c8  section table: optional "empty" ghost, then .clam01, .clam02...
//!   raw   aligned section bytes copied from decoded packer output
//!
//! rebuilt PE64 layout, single-section only in this pass
//!
//!   0000  MZ stub with e_lfanew = 0xd0
//!   00d0  PE signature + AMD64 COFF header + PE32+ optional header
//!   0158  zeroed data directory table
//!         resource directory RVA/size copied from RebuildOptions
//!   01d8  one .clam01 section table record
//!   raw   one aligned section copied from decoded packer output
//! ```
//!
//! ## Bounds And Recovery
//!
//! Rebuild inputs are caller-supplied decoded byte buffers. The helper checks
//! source ranges, section counts, alignment arithmetic, image sizes, and the
//! global rebuilt-output cap before writing. PE32 supports ClamAV-style ghost
//! sections for RVA gaps. PE64 intentionally supports only the single-section
//! wrapper used by current packer paths; multi-section PE64 rebuilds return a
//! stable unsupported reason instead of emitting a malformed image.

const PE_OFFSET: usize = 0xd0;
const PE32_OPTIONAL_HEADER_SIZE: usize = 0xe0;
const PE64_OPTIONAL_HEADER_SIZE: usize = 0xf0;
const PE32_NT_HEADER_SIZE: usize = 4 + 20 + PE32_OPTIONAL_HEADER_SIZE;
const PE64_NT_HEADER_SIZE: usize = 4 + 20 + PE64_OPTIONAL_HEADER_SIZE;
const PE32_DATA_DIRECTORY_OFFSET: usize = PE_OFFSET + 4 + 20 + 96;
const PE64_DATA_DIRECTORY_OFFSET: usize = PE_OFFSET + 4 + 20 + 112;
const DATA_DIRECTORY_SIZE: usize = 0x80;
const SECTION_HEADER_SIZE: usize = 0x28;
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const MAX_REBUILD_SECTIONS: usize = 96;
const MAX_REBUILT_PE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeRebuildArch {
    Pe32,
    Pe64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RebuildSection {
    pub(crate) source_offset: u32,
    pub(crate) rva: u32,
    pub(crate) virtual_size: u32,
    pub(crate) raw_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RebuildOptions {
    pub(crate) arch: PeRebuildArch,
    pub(crate) image_base: u64,
    pub(crate) entrypoint_rva: u32,
    pub(crate) resource_rva: u32,
    pub(crate) resource_size: u32,
    pub(crate) section_alignment_override: Option<u32>,
}

impl RebuildOptions {
    pub(crate) fn pe32(image_base: u32, entrypoint_rva: u32) -> Self {
        Self {
            arch: PeRebuildArch::Pe32,
            image_base: u64::from(image_base),
            entrypoint_rva,
            resource_rva: 0,
            resource_size: 0,
            section_alignment_override: None,
        }
    }

    pub(crate) fn pe64(image_base: u64, entrypoint_rva: u32) -> Self {
        Self {
            arch: PeRebuildArch::Pe64,
            image_base,
            entrypoint_rva,
            resource_rva: 0,
            resource_size: 0,
            section_alignment_override: None,
        }
    }
}

pub(crate) fn rebuild_pe_from_sections(
    buffer: &[u8],
    sections: &[RebuildSection],
    options: RebuildOptions,
) -> Result<Vec<u8>, &'static str> {
    if sections.is_empty() {
        return Err("pe_rebuild_no_sections");
    }
    if sections.len() > MAX_REBUILD_SECTIONS {
        return Err("pe_rebuild_section_limit_exceeded");
    }
    match options.arch {
        PeRebuildArch::Pe32 => rebuild_pe32_from_sections(buffer, sections, options),
        PeRebuildArch::Pe64 => {
            if sections.len() != 1 {
                return Err("pe64_multi_section_rebuild_not_supported");
            }
            rebuild_pe64_from_sections(buffer, sections, options)
        }
    }
}

pub(crate) fn wrap_payload_as_single_section_pe(
    payload: &[u8],
    arch: PeRebuildArch,
    image_base: u64,
    entrypoint_rva: u32,
    section_rva: u32,
) -> Result<Vec<u8>, &'static str> {
    let raw_size = u32::try_from(payload.len()).map_err(|_| "pe_rebuild_size_overflow")?;
    let options = match arch {
        PeRebuildArch::Pe32 => RebuildOptions::pe32(
            u32::try_from(image_base).map_err(|_| "pe_rebuild_image_base_out_of_range")?,
            entrypoint_rva,
        ),
        PeRebuildArch::Pe64 => RebuildOptions::pe64(image_base, entrypoint_rva),
    };
    rebuild_pe_from_sections(
        payload,
        &[RebuildSection {
            source_offset: 0,
            rva: section_rva,
            virtual_size: raw_size,
            raw_size,
        }],
        options,
    )
}

fn rebuild_pe32_from_sections(
    buffer: &[u8],
    sections: &[RebuildSection],
    options: RebuildOptions,
) -> Result<Vec<u8>, &'static str> {
    let rawbase_without_ghost = pe32_rawbase(sections.len())?;
    let header_image_size = align_u32(
        u32::try_from(rawbase_without_ghost).map_err(|_| "pe_rebuild_size_overflow")?,
        SECTION_ALIGNMENT,
    )
    .ok_or("pe_rebuild_size_overflow")?;
    let has_ghost = sections[0].rva > header_image_size;
    let output_section_count = sections
        .len()
        .checked_add(usize::from(has_ghost))
        .ok_or("pe_rebuild_section_count_overflow")?;
    if output_section_count > MAX_REBUILD_SECTIONS {
        return Err("pe_rebuild_section_limit_exceeded");
    }
    let rawbase = if has_ghost {
        pe32_rawbase(output_section_count)?
    } else {
        rawbase_without_ghost
    };
    let raw_data_size = rebuilt_raw_data_size(sections, options.section_alignment_override)?;
    let total = rawbase
        .checked_add(raw_data_size)
        .ok_or("pe_rebuild_size_overflow")?;
    if total as u64 > MAX_REBUILT_PE_BYTES {
        return Err("pe_rebuild_size_limit_exceeded");
    }

    validate_section_sources(buffer, sections)?;

    let mut out = vec![0u8; total];
    write_mz_stub(&mut out, PE_OFFSET)?;
    write_pe32_header(&mut out, output_section_count, rawbase, options)?;

    let mut cur_section = PE32_DATA_DIRECTORY_OFFSET
        .checked_add(DATA_DIRECTORY_SIZE)
        .ok_or("pe_rebuild_header_overflow")?;
    let mut image_size = align_u32(
        u32::try_from(rawbase).map_err(|_| "pe_rebuild_size_overflow")?,
        SECTION_ALIGNMENT,
    )
    .ok_or("pe_rebuild_size_overflow")?;
    if has_ghost {
        let virtual_size = sections[0]
            .rva
            .checked_sub(image_size)
            .ok_or("pe_rebuild_ghost_section_underflow")?;
        write_section_header(
            &mut out,
            cur_section,
            b"empty\0\0\0",
            virtual_size,
            image_size,
            0,
            0,
            0xffff_ffff,
        )?;
        cur_section += SECTION_HEADER_SIZE;
        image_size = max_aligned_image_end(image_size, image_size, virtual_size)?;
    }

    let mut raw_cursor = rawbase;
    for (index, section) in sections.iter().enumerate() {
        let (header_vsize, header_rva, header_raw_size, copy_raw_size, raw_advance) =
            rebuilt_section_sizes(*section, options.section_alignment_override)?;
        write_section_header(
            &mut out,
            cur_section,
            &section_name(index + 1),
            header_vsize,
            header_rva,
            header_raw_size,
            u32::try_from(raw_cursor).map_err(|_| "pe_rebuild_size_overflow")?,
            0xffff_ffff,
        )?;
        let src = usize::try_from(section.source_offset)
            .map_err(|_| "pe_rebuild_source_offset_overflow")?;
        let copy = usize::try_from(copy_raw_size).map_err(|_| "pe_rebuild_size_overflow")?;
        out[raw_cursor..raw_cursor + copy].copy_from_slice(&buffer[src..src + copy]);
        cur_section += SECTION_HEADER_SIZE;
        raw_cursor = raw_cursor
            .checked_add(usize::try_from(raw_advance).map_err(|_| "pe_rebuild_size_overflow")?)
            .ok_or("pe_rebuild_size_overflow")?;
        image_size = max_aligned_image_end(image_size, header_rva, header_vsize)?;
    }
    write_u32_checked(&mut out, PE_OFFSET + 4 + 20 + 56, image_size)?;
    Ok(out)
}

fn rebuild_pe64_from_sections(
    buffer: &[u8],
    sections: &[RebuildSection],
    options: RebuildOptions,
) -> Result<Vec<u8>, &'static str> {
    let section = sections[0];
    validate_section_sources(buffer, sections)?;
    let rawbase = align_usize(PE_OFFSET + PE64_NT_HEADER_SIZE + SECTION_HEADER_SIZE, 0x200)
        .ok_or("pe_rebuild_size_overflow")?;
    let raw_size = align_usize(
        usize::try_from(section.raw_size).map_err(|_| "pe_rebuild_size_overflow")?,
        0x200,
    )
    .ok_or("pe_rebuild_size_overflow")?;
    let total = rawbase
        .checked_add(raw_size)
        .ok_or("pe_rebuild_size_overflow")?;
    if total as u64 > MAX_REBUILT_PE_BYTES {
        return Err("pe_rebuild_size_limit_exceeded");
    }
    let mut out = vec![0u8; total];
    write_mz_stub(&mut out, PE_OFFSET)?;
    write_pe64_header(&mut out, 1, rawbase, options)?;
    write_section_header(
        &mut out,
        PE_OFFSET + PE64_NT_HEADER_SIZE,
        b".clam01\0",
        section.virtual_size,
        section.rva,
        section.raw_size,
        u32::try_from(rawbase).map_err(|_| "pe_rebuild_size_overflow")?,
        0xffff_ffff,
    )?;
    let src = usize::try_from(section.source_offset).map_err(|_| "pe_rebuild_size_overflow")?;
    let copy = usize::try_from(section.raw_size).map_err(|_| "pe_rebuild_size_overflow")?;
    out[rawbase..rawbase + copy].copy_from_slice(&buffer[src..src + copy]);
    let image_size = align_u32(
        section
            .rva
            .checked_add(section.virtual_size)
            .ok_or("pe_rebuild_size_overflow")?,
        SECTION_ALIGNMENT,
    )
    .ok_or("pe_rebuild_size_overflow")?;
    write_u32_checked(&mut out, PE_OFFSET + 4 + 20 + 56, image_size)?;
    Ok(out)
}

fn pe32_rawbase(section_count: usize) -> Result<usize, &'static str> {
    let table_end = PE32_DATA_DIRECTORY_OFFSET
        .checked_add(DATA_DIRECTORY_SIZE)
        .and_then(|value| value.checked_add(section_count.checked_mul(SECTION_HEADER_SIZE)?))
        .ok_or("pe_rebuild_header_overflow")?;
    align_usize(table_end, FILE_ALIGNMENT as usize).ok_or("pe_rebuild_header_overflow")
}

fn rebuilt_raw_data_size(
    sections: &[RebuildSection],
    align_override: Option<u32>,
) -> Result<usize, &'static str> {
    let mut total = 0usize;
    for section in sections {
        let (_, _, _, _, raw_advance) = rebuilt_section_sizes(*section, align_override)?;
        total = total
            .checked_add(usize::try_from(raw_advance).map_err(|_| "pe_rebuild_size_overflow")?)
            .ok_or("pe_rebuild_size_overflow")?;
    }
    Ok(total)
}

fn rebuilt_section_sizes(
    section: RebuildSection,
    align_override: Option<u32>,
) -> Result<(u32, u32, u32, u32, u32), &'static str> {
    let copy_raw_size = section.raw_size;
    let (header_vsize, header_rva, header_raw_size) = if let Some(align) = align_override {
        if align == 0 {
            return Err("pe_rebuild_alignment_invalid");
        }
        (
            align_u32(section.virtual_size, align).ok_or("pe_rebuild_size_overflow")?,
            align_u32(section.rva, align).ok_or("pe_rebuild_size_overflow")?,
            align_u32(section.raw_size, align).ok_or("pe_rebuild_size_overflow")?,
        )
    } else {
        (section.virtual_size, section.rva, section.raw_size)
    };
    let raw_advance =
        align_u32(header_raw_size, FILE_ALIGNMENT).ok_or("pe_rebuild_size_overflow")?;
    Ok((
        header_vsize,
        header_rva,
        header_raw_size,
        copy_raw_size,
        raw_advance,
    ))
}

fn max_aligned_image_end(current: u32, rva: u32, virtual_size: u32) -> Result<u32, &'static str> {
    let end = rva
        .checked_add(virtual_size)
        .ok_or("pe_rebuild_size_overflow")?;
    let aligned_end = align_u32(end, SECTION_ALIGNMENT).ok_or("pe_rebuild_size_overflow")?;
    Ok(current.max(aligned_end))
}

fn validate_section_sources(
    buffer: &[u8],
    sections: &[RebuildSection],
) -> Result<(), &'static str> {
    for section in sections {
        let start = usize::try_from(section.source_offset)
            .map_err(|_| "pe_rebuild_source_offset_overflow")?;
        let size = usize::try_from(section.raw_size).map_err(|_| "pe_rebuild_size_overflow")?;
        if start.checked_add(size).is_none_or(|end| end > buffer.len()) {
            return Err("pe_rebuild_source_range_invalid");
        }
    }
    Ok(())
}

fn write_pe32_header(
    out: &mut [u8],
    section_count: usize,
    rawbase: usize,
    options: RebuildOptions,
) -> Result<(), &'static str> {
    require_range(out, PE_OFFSET, PE32_NT_HEADER_SIZE)?;
    out[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    write_u16(out, PE_OFFSET + 4, 0x14c);
    write_u16_checked(out, PE_OFFSET + 6, section_count)?;
    write_u32(out, PE_OFFSET + 8, 0x4d41_4c43);
    write_u16_checked(out, PE_OFFSET + 20, PE32_OPTIONAL_HEADER_SIZE)?;
    write_u16(out, PE_OFFSET + 22, 0x8f83);

    let opt = PE_OFFSET + 24;
    write_u16(out, opt, 0x10b);
    write_u32(out, opt + 4, 0x1000);
    write_u32(out, opt + 8, 0x1000);
    write_u32(out, opt + 16, options.entrypoint_rva);
    write_u32(out, opt + 20, 0x1000);
    write_u32(out, opt + 24, 0x1000);
    write_u32_checked(out, opt + 28, options.image_base)?;
    write_u32(out, opt + 32, SECTION_ALIGNMENT);
    write_u32(out, opt + 36, FILE_ALIGNMENT);
    write_u16(out, opt + 40, 1);
    write_u16(out, opt + 48, 3);
    write_u16(out, opt + 50, 10);
    write_u32_checked(out, opt + 60, rawbase)?;
    write_u16(out, opt + 68, 2);
    write_u32(out, opt + 72, 0x0010_0000);
    write_u32(out, opt + 76, 0x1000);
    write_u32(out, opt + 80, 0x0010_0000);
    write_u32(out, opt + 84, 0x1000);
    write_u32(out, opt + 92, 16);
    write_u32(out, PE32_DATA_DIRECTORY_OFFSET + 0x10, options.resource_rva);
    write_u32(
        out,
        PE32_DATA_DIRECTORY_OFFSET + 0x14,
        options.resource_size,
    );
    Ok(())
}

fn write_pe64_header(
    out: &mut [u8],
    section_count: usize,
    rawbase: usize,
    options: RebuildOptions,
) -> Result<(), &'static str> {
    require_range(out, PE_OFFSET, PE64_NT_HEADER_SIZE)?;
    out[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    write_u16(out, PE_OFFSET + 4, 0x8664);
    write_u16_checked(out, PE_OFFSET + 6, section_count)?;
    write_u32(out, PE_OFFSET + 8, 0x4d41_4c43);
    write_u16_checked(out, PE_OFFSET + 20, PE64_OPTIONAL_HEADER_SIZE)?;
    write_u16(out, PE_OFFSET + 22, 0x002f);

    let opt = PE_OFFSET + 24;
    write_u16(out, opt, 0x20b);
    write_u32(out, opt + 4, 0x1000);
    write_u32(out, opt + 8, 0x1000);
    write_u32(out, opt + 16, options.entrypoint_rva);
    write_u32(out, opt + 20, 0x1000);
    write_u64(out, opt + 24, options.image_base);
    write_u32(out, opt + 32, SECTION_ALIGNMENT);
    write_u32(out, opt + 36, FILE_ALIGNMENT);
    write_u16(out, opt + 40, 1);
    write_u16(out, opt + 48, 3);
    write_u16(out, opt + 50, 10);
    write_u32_checked(out, opt + 60, rawbase)?;
    write_u16(out, opt + 68, 2);
    write_u64(out, opt + 72, 0x0010_0000);
    write_u64(out, opt + 80, 0x1000);
    write_u64(out, opt + 88, 0x0010_0000);
    write_u64(out, opt + 96, 0x1000);
    write_u32(out, opt + 108, 16);
    write_u32(out, PE64_DATA_DIRECTORY_OFFSET + 0x10, options.resource_rva);
    write_u32(
        out,
        PE64_DATA_DIRECTORY_OFFSET + 0x14,
        options.resource_size,
    );
    Ok(())
}

pub(crate) fn write_mz_stub(out: &mut [u8], pe_offset: usize) -> Result<(), &'static str> {
    require_range(out, 0, pe_offset)?;
    out[0..2].copy_from_slice(b"MZ");
    write_u16(out, 2, 0x0090);
    write_u16(out, 4, 0x0002);
    write_u16(out, 8, 0x0004);
    write_u16(out, 0x0a, 0x000f);
    write_u16(out, 0x0c, 0xffff);
    write_u32(out, 0x10, 0x0000_00b0);
    write_u16(out, 0x18, 0x0040);
    write_u16(out, 0x1a, 0x001a);
    write_u32_checked(out, 0x3c, pe_offset)?;
    if let Some(message) = out.get_mut(0x40..pe_offset) {
        const TEXT: &[u8] =
            b"This file was created by ClamAV for internal use and should not be run.\r\n$";
        let len = TEXT.len().min(message.len());
        message[..len].copy_from_slice(&TEXT[..len]);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_section_header(
    out: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) -> Result<(), &'static str> {
    require_range(out, offset, SECTION_HEADER_SIZE)?;
    let dst = &mut out[offset..offset + 8];
    dst.fill(0);
    let copy = name.len().min(8);
    dst[..copy].copy_from_slice(&name[..copy]);
    write_u32(out, offset + 8, virtual_size);
    write_u32(out, offset + 12, rva);
    write_u32(out, offset + 16, raw_size);
    write_u32(out, offset + 20, raw_offset);
    write_u32(out, offset + 36, characteristics);
    Ok(())
}

fn section_name(index: usize) -> [u8; 8] {
    const DIGITS: &[u8; 10] = b"0123456789";
    let tens = DIGITS[(index / 10) % 10];
    let ones = DIGITS[index % 10];
    [b'.', b'c', b'l', b'a', b'm', tens, ones, 0]
}

fn require_range(out: &[u8], offset: usize, len: usize) -> Result<(), &'static str> {
    if offset.checked_add(len).is_some_and(|end| end <= out.len()) {
        Ok(())
    } else {
        Err("pe_rebuild_range_out_of_bounds")
    }
}

fn align_usize(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return Some(value);
    }
    let addend = alignment.checked_sub(1)?;
    Some(value.checked_add(addend)? / alignment * alignment)
}

fn align_u32(value: u32, alignment: u32) -> Option<u32> {
    if alignment == 0 {
        return Some(value);
    }
    let addend = alignment.checked_sub(1)?;
    Some(value.checked_add(addend)? / alignment * alignment)
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u16_checked(out: &mut [u8], offset: usize, value: usize) -> Result<(), &'static str> {
    write_u16(
        out,
        offset,
        u16::try_from(value).map_err(|_| "pe_rebuild_u16_overflow")?,
    );
    Ok(())
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_checked<T>(out: &mut [u8], offset: usize, value: T) -> Result<(), &'static str>
where
    T: TryInto<u32>,
{
    write_u32(
        out,
        offset,
        value.try_into().map_err(|_| "pe_rebuild_u32_overflow")?,
    );
    Ok(())
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_section_pe32_rebuild_uses_clamav_layout() {
        let payload = b"you made me ink";
        let rebuilt = wrap_payload_as_single_section_pe(
            payload,
            PeRebuildArch::Pe32,
            0x0040_0000,
            0x1000,
            0x1000,
        )
        .expect("rebuilt PE");

        assert_eq!(&rebuilt[..2], b"MZ");
        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(rebuilt.get(0x1c8..0x1d0), Some(&b".clam01\0"[..]));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 4 + 20 + 16), Some(0x1000));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 4 + 20 + 28), Some(0x0040_0000));
        assert!(
            rebuilt
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }

    #[test]
    fn multi_section_pe32_rebuild_preserves_section_ranges() {
        let mut payload = vec![0u8; 0x80];
        payload[0..4].copy_from_slice(b"one!");
        payload[0x40..0x44].copy_from_slice(b"two!");
        let rebuilt = rebuild_pe_from_sections(
            &payload,
            &[
                RebuildSection {
                    source_offset: 0,
                    rva: 0x1000,
                    virtual_size: 0x40,
                    raw_size: 0x40,
                },
                RebuildSection {
                    source_offset: 0x40,
                    rva: 0x2000,
                    virtual_size: 0x40,
                    raw_size: 0x40,
                },
            ],
            RebuildOptions::pe32(0x0040_0000, 0x1000),
        )
        .expect("rebuilt PE");

        assert_eq!(rebuilt.get(0x1c8..0x1d0), Some(&b".clam01\0"[..]));
        assert_eq!(rebuilt.get(0x1f0..0x1f8), Some(&b".clam02\0"[..]));
        assert_eq!(read_u32_le(&rebuilt, 0x1c8 + 20), Some(0x400));
        assert_eq!(read_u32_le(&rebuilt, 0x1f0 + 20), Some(0x600));
        assert_eq!(rebuilt.get(0x400..0x404), Some(&b"one!"[..]));
        assert_eq!(rebuilt.get(0x600..0x604), Some(&b"two!"[..]));
    }

    #[test]
    fn multi_section_pe32_size_of_image_uses_max_section_end() {
        let payload = vec![0x41; 0x80];
        let rebuilt = rebuild_pe_from_sections(
            &payload,
            &[
                RebuildSection {
                    source_offset: 0,
                    rva: 0x1000,
                    virtual_size: 0x1000,
                    raw_size: 0x40,
                },
                RebuildSection {
                    source_offset: 0x40,
                    rva: 0x5000,
                    virtual_size: 0x1000,
                    raw_size: 0x40,
                },
            ],
            RebuildOptions::pe32(0x0040_0000, 0x1000),
        )
        .expect("rebuilt PE");

        assert_eq!(read_u32_le(&rebuilt, PE_OFFSET + 4 + 20 + 56), Some(0x6000));
    }

    #[test]
    fn align_override_aligns_header_sizes_and_rvas() {
        let payload = vec![0x41; 0x321];
        let options = RebuildOptions {
            section_alignment_override: Some(0x1000),
            ..RebuildOptions::pe32(0x0040_0000, 0x1234)
        };
        let rebuilt = rebuild_pe_from_sections(
            &payload,
            &[RebuildSection {
                source_offset: 0,
                rva: 0x1000,
                virtual_size: 0x321,
                raw_size: 0x321,
            }],
            options,
        )
        .expect("rebuilt PE");

        assert_eq!(read_u32_le(&rebuilt, 0x1c8 + 8), Some(0x1000));
        assert_eq!(read_u32_le(&rebuilt, 0x1c8 + 12), Some(0x1000));
        assert_eq!(read_u32_le(&rebuilt, 0x1c8 + 16), Some(0x1000));
    }

    #[test]
    fn ghost_section_fills_gap_before_first_section() {
        let payload = vec![0x41; 4];
        let rebuilt = rebuild_pe_from_sections(
            &payload,
            &[RebuildSection {
                source_offset: 0,
                rva: 0x3000,
                virtual_size: 4,
                raw_size: 4,
            }],
            RebuildOptions::pe32(0x0040_0000, 0x3000),
        )
        .expect("rebuilt PE");

        assert_eq!(rebuilt.get(0x1c8..0x1d0), Some(&b"empty\0\0\0"[..]));
        assert_eq!(rebuilt.get(0x1f0..0x1f8), Some(&b".clam01\0"[..]));
        assert_eq!(
            rebuilt.get(0xd0 + 6..0xd0 + 8),
            Some(&2u16.to_le_bytes()[..])
        );
    }

    #[test]
    fn invalid_source_range_is_rejected() {
        let err = rebuild_pe_from_sections(
            b"tiny",
            &[RebuildSection {
                source_offset: 2,
                rva: 0x1000,
                virtual_size: 8,
                raw_size: 8,
            }],
            RebuildOptions::pe32(0x0040_0000, 0x1000),
        )
        .expect_err("range rejected");

        assert_eq!(err, "pe_rebuild_source_range_invalid");
    }

    #[test]
    fn single_section_pe64_rebuild_is_parseable() {
        let payload = b"you made me ink";
        let rebuilt = wrap_payload_as_single_section_pe(
            payload,
            PeRebuildArch::Pe64,
            0x0000_0001_4000_0000,
            0x1000,
            0x1000,
        )
        .expect("rebuilt PE64");

        assert_eq!(&rebuilt[..2], b"MZ");
        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(
            rebuilt.get(0xd0 + 24..0xd0 + 26),
            Some(&0x20bu16.to_le_bytes()[..])
        );
        assert!(
            rebuilt
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }
}
