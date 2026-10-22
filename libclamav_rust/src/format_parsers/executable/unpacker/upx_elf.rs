// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust UPX ELF unpacking helpers.
//!
//! This module follows `ClamAV` `upx_elf.c` for the common UPX 2.x/3.x+ block
//! format used by ELF32 and ELF64 files. It reuses the PE UPX NRV and LZMA
//! primitives because the compressed block formats are shared. The legacy UPX
//! 1.x raw-block layout and ELF64 zeroed-`l_info` layout are handled with the
//! same bounds checks as `ClamAV`'s native implementation.
//! Trailer searches for zeroed-`l_info` variants are bounded so ordinary large
//! ELF files do not pay for whole-file marker scans during packer detection.
//!
//! ## State Machine
//!
//! ```text
//! ELF analysis -> UPX pack header / l_info discovery
//!     -> shared NRV/LZMA block decode -> unpacked ELF byte artifact
//! ```
//!
//! Trailer scans, pack-header reads, compressed block sizes, and decoded output
//! are bounded before an unpacked child artifact is returned.

#![forbid(unsafe_code)]

use crate::format_parsers::executable::{
    UnpackedArtifact,
    elf::{ElfAnalysis, ElfSegment},
};

use super::upx::{self, NrvVariant};

const L_INFO_SIZE: usize = 12;
const P_INFO_SIZE: usize = 12;
const B_INFO_SIZE: usize = 12;
const V1_PACK_HDR_SIZE: usize = 32;
const V1_MIN_FILE_SIZE: usize = 189;
const V1_PACK_METHOD_OFFSET: usize = 6;
const V1_PACK_UNCOMPRESSED_LEN_OFFSET: usize = 16;
const UPX_MAGIC_V2: u32 = 0x2158_5055;
const UPX_MAGIC_V1: u32 = 0x5850_557f;
const UPX_MAGIC_V2_BYTES: [u8; 4] = [0x55, 0x50, 0x58, 0x21];
const UPX_MAGIC_V1_BYTES: [u8; 4] = [0x7f, 0x55, 0x50, 0x58];
const METHOD_NRV2B32: u8 = 2;
const METHOD_NRV2D32: u8 = 5;
const METHOD_NRV2E32: u8 = 8;
const METHOD_LZMA: u8 = 14;
const MAX_UPX_ELF_UNPACKED_BYTES: usize = 128 * 1024 * 1024;
const MAX_UPX_ELF_BLOCKS: usize = 64;
const INITIAL_UPX_ELF_OUTPUT_CAPACITY: usize = 64 * 1024;
const MAX_UPX_ELF_END_L_INFO_SCAN: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct UpxElfLayout {
    l_info_offset: usize,
    version: u8,
}

pub(super) fn unpack_elf(
    bytes: &[u8],
    analysis: &ElfAnalysis,
) -> Result<UnpackedArtifact, &'static str> {
    if !analysis.is_elf {
        return Err("elf_upx_not_elf");
    }
    if analysis.endian != Some("little") {
        return Err("elf_upx_big_endian_unsupported");
    }
    let layout = locate_upx_layout(bytes, analysis).ok_or("elf_upx_layout_not_found")?;
    let unpacked = if layout.version == 1 {
        decompress_v1_blocks(bytes, layout)?
    } else {
        decompress_modern_blocks(bytes, layout)?
    };
    if !unpacked.starts_with(b"\x7fELF") {
        return Err("elf_upx_output_not_elf");
    }
    Ok(UnpackedArtifact {
        bytes: unpacked,
        source_offset: layout.l_info_offset as u64,
        source_size: bytes
            .len()
            .checked_sub(layout.l_info_offset)
            .ok_or("elf_upx_source_size_underflow")? as u64,
    })
}

fn locate_upx_layout(bytes: &[u8], analysis: &ElfAnalysis) -> Option<UpxElfLayout> {
    let phdr_end: usize = analysis
        .program_header_offset?
        .checked_add(
            u64::from(analysis.program_header_entry_size?)
                .checked_mul(u64::from(analysis.program_header_count?))?,
        )?
        .try_into()
        .ok()?;
    let magic = read_u32_le(bytes, phdr_end.checked_add(4)?)?;
    if matches!(magic, UPX_MAGIC_V2 | UPX_MAGIC_V1) {
        return Some(UpxElfLayout {
            l_info_offset: phdr_end,
            version: upx_version_for_magic(magic)?,
        });
    }
    if analysis.is_64bit {
        let extended_magic = read_u32_le(bytes, phdr_end.checked_add(8)?)?;
        if extended_magic == UPX_MAGIC_V2 {
            return Some(UpxElfLayout {
                l_info_offset: phdr_end.checked_add(4)?,
                version: 3,
            });
        }
    }
    if analysis.is_64bit
        && bytes
            .get(phdr_end..phdr_end.checked_add(L_INFO_SIZE)?)?
            .iter()
            .all(|b| *b == 0)
        && p_info_original_size_plausible(bytes, phdr_end)
    {
        let search_end = phdr_end
            .checked_add(L_INFO_SIZE)?
            .checked_add(P_INFO_SIZE)?
            .checked_add(B_INFO_SIZE)?
            .checked_add(1)?;
        return find_end_l_info(bytes, search_end).map(|_| UpxElfLayout {
            l_info_offset: phdr_end,
            version: 4,
        });
    }
    find_after_adjacent_note(bytes, analysis, phdr_end)
        .or_else(|| scan_near_phdr_end_for_l_info(bytes, phdr_end))
}

fn find_after_adjacent_note(
    bytes: &[u8],
    analysis: &ElfAnalysis,
    phdr_end: usize,
) -> Option<UpxElfLayout> {
    let note = analysis
        .segments
        .iter()
        .filter(|segment| segment.segment_type == 4)
        .filter(|segment| usize::try_from(segment.offset).ok() == Some(phdr_end))
        .max_by_key(|segment| segment.file_size)?;
    let offset = segment_end(note)?;
    let magic = read_u32_le(bytes, offset.checked_add(4)?)?;
    Some(UpxElfLayout {
        l_info_offset: offset,
        version: upx_version_for_magic(magic)?,
    })
}

fn scan_near_phdr_end_for_l_info(bytes: &[u8], phdr_end: usize) -> Option<UpxElfLayout> {
    let scan_end = phdr_end.checked_add(1024)?.min(bytes.len());
    let search_start = phdr_end.checked_add(4)?;
    let search_end = scan_end.checked_add(7)?.min(bytes.len());
    bytes
        .get(search_start..search_end)?
        .windows(4)
        .enumerate()
        .find_map(|(relative_offset, window)| {
            let version = if window == UPX_MAGIC_V2_BYTES {
                3
            } else if window == UPX_MAGIC_V1_BYTES {
                1
            } else {
                return None;
            };
            let magic_offset = search_start.checked_add(relative_offset)?;
            let l_info_offset = magic_offset.checked_sub(4)?;
            Some(UpxElfLayout {
                l_info_offset,
                version,
            })
        })
}

fn segment_end(segment: &ElfSegment) -> Option<usize> {
    usize::try_from(segment.offset.checked_add(segment.file_size)?).ok()
}

fn upx_version_for_magic(magic: u32) -> Option<u8> {
    match magic {
        UPX_MAGIC_V1 => Some(1),
        UPX_MAGIC_V2 => Some(3),
        _ => None,
    }
}

fn find_end_l_info(bytes: &[u8], search_end: usize) -> Option<usize> {
    if bytes.len() < L_INFO_SIZE {
        return None;
    }
    let min_offset = bytes
        .len()
        .saturating_sub(MAX_UPX_ELF_END_L_INFO_SCAN)
        .max(search_end);
    let mut offset = bytes.len().saturating_sub(L_INFO_SIZE);
    loop {
        if offset < min_offset {
            break;
        }
        if read_u32_le(bytes, offset.checked_add(4)?) == Some(UPX_MAGIC_V2) {
            let loader_size = read_u16_le(bytes, offset.checked_add(8)?)?;
            let version = *bytes.get(offset.checked_add(10)?)?;
            if (0x80..=0x4000).contains(&loader_size)
                && usize::from(loader_size) <= offset
                && (11..=14).contains(&version)
            {
                return Some(offset);
            }
        }
        if offset == 0 {
            break;
        }
        offset -= 1;
    }
    None
}

fn p_info_original_size_plausible(bytes: &[u8], l_info_offset: usize) -> bool {
    let Some(size_offset) = l_info_offset
        .checked_add(L_INFO_SIZE)
        .and_then(|offset| offset.checked_add(4))
    else {
        return false;
    };
    read_u32_le(bytes, size_offset).is_some_and(|size| {
        size != 0 && usize::try_from(size).is_ok_and(|size| size <= MAX_UPX_ELF_UNPACKED_BYTES)
    })
}

fn decompress_modern_blocks(bytes: &[u8], layout: UpxElfLayout) -> Result<Vec<u8>, &'static str> {
    let p_info = layout
        .l_info_offset
        .checked_add(L_INFO_SIZE)
        .ok_or("elf_upx_p_info_offset_overflow")?;
    let original_size = read_u32_le(
        bytes,
        p_info
            .checked_add(4)
            .ok_or("elf_upx_p_info_offset_overflow")?,
    )
    .ok_or("elf_upx_p_filesize_missing")? as usize;
    let block_size = read_u32_le(
        bytes,
        p_info
            .checked_add(8)
            .ok_or("elf_upx_p_info_offset_overflow")?,
    )
    .ok_or("elf_upx_blocksize_missing")? as usize;
    if original_size == 0 || original_size > MAX_UPX_ELF_UNPACKED_BYTES {
        return Err("elf_upx_original_size_invalid");
    }
    if block_size == 0 || block_size > MAX_UPX_ELF_UNPACKED_BYTES {
        return Err("elf_upx_block_size_invalid");
    }
    let mut output = Vec::with_capacity(original_size.min(INITIAL_UPX_ELF_OUTPUT_CAPACITY));
    let mut offset = p_info
        .checked_add(P_INFO_SIZE)
        .ok_or("elf_upx_block_offset_overflow")?;
    let mut clean_stop = false;
    let mut overlap_stop = false;
    for _ in 0..MAX_UPX_ELF_BLOCKS {
        if offset
            .checked_add(B_INFO_SIZE)
            .is_none_or(|end| end > bytes.len())
        {
            break;
        }
        let out_len = read_u32_le(bytes, offset).ok_or("elf_upx_chunk_out_len_missing")? as usize;
        let in_len = read_u32_le(
            bytes,
            offset
                .checked_add(4)
                .ok_or("elf_upx_chunk_offset_overflow")?,
        )
        .ok_or("elf_upx_chunk_in_len_missing")? as usize;
        let method = *bytes
            .get(
                offset
                    .checked_add(8)
                    .ok_or("elf_upx_chunk_offset_overflow")?,
            )
            .ok_or("elf_upx_method_missing")?;
        offset = offset
            .checked_add(B_INFO_SIZE)
            .ok_or("elf_upx_chunk_offset_overflow")?;
        if out_len == 0 {
            clean_stop = true;
            break;
        }
        if out_len > block_size {
            clean_stop = true;
            break;
        }
        if output
            .len()
            .checked_add(out_len)
            .is_none_or(|end| end > MAX_UPX_ELF_UNPACKED_BYTES)
        {
            return Err("elf_upx_chunk_output_size_invalid");
        }
        if in_len == 0
            || out_len
                .checked_add(1024)
                .is_none_or(|max_in_len| in_len > max_in_len)
        {
            overlap_stop = true;
            break;
        }
        if out_len >= 64 && in_len < out_len / 64 {
            overlap_stop = true;
            break;
        }
        let Some(block_end) = offset.checked_add(in_len) else {
            break;
        };
        if block_end > bytes.len() {
            break;
        }
        let block = &bytes[offset..block_end];
        decode_block_into(
            &mut output,
            block,
            in_len,
            out_len,
            method,
            "elf_upx_chunk_size_mismatch",
        )?;
        offset = block_end;
        if output.len() >= original_size {
            clean_stop = true;
            break;
        }
    }
    if output.is_empty() {
        return Err("elf_upx_no_blocks");
    }
    if !clean_stop && !overlap_stop {
        return Err("elf_upx_block_walk_unclean");
    }
    Ok(output)
}

fn decompress_v1_blocks(bytes: &[u8], layout: UpxElfLayout) -> Result<Vec<u8>, &'static str> {
    if bytes.len() < V1_MIN_FILE_SIZE {
        return Err("elf_upx_v1_too_small");
    }
    let loader_size =
        read_u32_le(bytes, bytes.len() - 4).ok_or("elf_upx_v1_loader_missing")? as usize;
    let lower_loader_bound = layout
        .l_info_offset
        .checked_add(L_INFO_SIZE)
        .ok_or("elf_upx_v1_loader_bound_overflow")?;
    let upper_loader_bound = bytes
        .len()
        .checked_sub(61)
        .ok_or("elf_upx_v1_loader_bound_underflow")?;
    if loader_size < lower_loader_bound || loader_size > upper_loader_bound {
        return Err("elf_upx_v1_loader_size_invalid");
    }

    let pack_header_offset = bytes
        .len()
        .checked_sub(4 + V1_PACK_HDR_SIZE)
        .ok_or("elf_upx_v1_pack_header_offset_underflow")?;
    let eof_marker_offset = pack_header_offset
        .checked_sub(4)
        .ok_or("elf_upx_v1_eof_marker_offset_underflow")?;
    if read_u32_le(bytes, pack_header_offset) != Some(UPX_MAGIC_V2) {
        return Err("elf_upx_v1_pack_header_magic_invalid");
    }
    if read_u32_le(bytes, eof_marker_offset) != Some(0) {
        return Err("elf_upx_v1_eof_marker_invalid");
    }

    let method = *bytes
        .get(
            pack_header_offset
                .checked_add(V1_PACK_METHOD_OFFSET)
                .ok_or("elf_upx_v1_pack_header_offset_overflow")?,
        )
        .ok_or("elf_upx_v1_method_missing")?;
    if nrv_variant_for_method(method).is_none() {
        return Err("elf_upx_v1_method_unsupported");
    }

    let program_info = loader_size;
    if program_info
        .checked_add(P_INFO_SIZE + 8)
        .is_none_or(|end| end > eof_marker_offset)
    {
        return Err("elf_upx_v1_program_info_invalid");
    }
    let original_size = read_u32_le(
        bytes,
        program_info
            .checked_add(4)
            .ok_or("elf_upx_v1_program_info_offset_overflow")?,
    )
    .ok_or("elf_upx_v1_original_size_missing")? as usize;
    let block_size = read_u32_le(
        bytes,
        program_info
            .checked_add(8)
            .ok_or("elf_upx_v1_program_info_offset_overflow")?,
    )
    .ok_or("elf_upx_v1_block_size_missing")? as usize;
    if original_size == 0 || original_size > MAX_UPX_ELF_UNPACKED_BYTES {
        return Err("elf_upx_v1_original_size_invalid");
    }
    if block_size == 0 || block_size > MAX_UPX_ELF_UNPACKED_BYTES {
        return Err("elf_upx_v1_block_size_invalid");
    }

    let _pack_original_size = read_u32_le(
        bytes,
        pack_header_offset
            .checked_add(V1_PACK_UNCOMPRESSED_LEN_OFFSET)
            .ok_or("elf_upx_v1_pack_header_offset_overflow")?,
    )
    .ok_or("elf_upx_v1_pack_original_size_missing")? as usize;

    let mut output = Vec::with_capacity(original_size.min(INITIAL_UPX_ELF_OUTPUT_CAPACITY));
    let mut offset = program_info
        .checked_add(P_INFO_SIZE)
        .ok_or("elf_upx_v1_block_offset_overflow")?;
    for _ in 0..MAX_UPX_ELF_BLOCKS {
        if offset
            .checked_add(8)
            .is_none_or(|end| end > eof_marker_offset)
        {
            break;
        }
        let out_len =
            read_u32_le(bytes, offset).ok_or("elf_upx_v1_block_out_len_missing")? as usize;
        if out_len == 0 {
            break;
        }
        let in_len = read_u32_le(
            bytes,
            offset
                .checked_add(4)
                .ok_or("elf_upx_v1_block_offset_overflow")?,
        )
        .ok_or("elf_upx_v1_block_in_len_missing")? as usize;
        if out_len > block_size {
            break;
        }
        if in_len == 0 || in_len > out_len {
            return Err("elf_upx_v1_block_input_size_invalid");
        }
        let data_offset = offset
            .checked_add(8)
            .ok_or("elf_upx_v1_block_data_offset_overflow")?;
        let Some(block_end) = data_offset.checked_add(in_len) else {
            return Err("elf_upx_v1_block_data_truncated");
        };
        if block_end > eof_marker_offset {
            return Err("elf_upx_v1_block_data_truncated");
        }
        if output
            .len()
            .checked_add(out_len)
            .is_none_or(|end| end > original_size)
        {
            return Err("elf_upx_v1_output_overflow");
        }
        let block = &bytes[data_offset..block_end];
        decode_block_into(
            &mut output,
            block,
            in_len,
            out_len,
            method,
            "elf_upx_v1_block_size_mismatch",
        )?;
        offset = block_end;
        if output.len() >= original_size {
            break;
        }
    }

    if output.is_empty() {
        return Err("elf_upx_v1_no_blocks");
    }
    if output.len() != original_size {
        return Err("elf_upx_v1_output_size_mismatch");
    }
    Ok(output)
}

fn decode_block_into(
    output: &mut Vec<u8>,
    block: &[u8],
    in_len: usize,
    out_len: usize,
    method: u8,
    size_mismatch_error: &'static str,
) -> Result<(), &'static str> {
    if in_len == out_len {
        output.extend_from_slice(block);
        return Ok(());
    }
    let decoded = match method {
        METHOD_NRV2B32 | METHOD_NRV2D32 | METHOD_NRV2E32 => {
            let Some(variant) = nrv_variant_for_method(method) else {
                return Err("elf_upx_method_unsupported");
            };
            let mut output = vec![0u8; out_len];
            let written = upx::inflate_nrv(block, &mut output, variant)
                .map_err(|()| "elf_upx_nrv_decode_failed")?;
            output.truncate(written);
            output
        }
        METHOD_LZMA => {
            let properties = upx_lzma_properties(block).ok_or("elf_upx_lzma_properties_invalid")?;
            upx::try_lzma(block, out_len, properties).ok_or("elf_upx_lzma_decode_failed")?
        }
        _ => return Err("elf_upx_method_unsupported"),
    };
    if decoded.len() != out_len {
        return Err(size_mismatch_error);
    }
    output.extend_from_slice(&decoded);
    Ok(())
}

fn nrv_variant_for_method(method: u8) -> Option<NrvVariant> {
    match method {
        METHOD_NRV2B32 => Some(NrvVariant::Nrv2b),
        METHOD_NRV2D32 => Some(NrvVariant::Nrv2d),
        METHOD_NRV2E32 => Some(NrvVariant::Nrv2e),
        _ => None,
    }
}

fn upx_lzma_properties(block: &[u8]) -> Option<u32> {
    let b0 = *block.first()?;
    let b1 = *block.get(1)?;
    let lc = u32::from(b1 & 0x0f);
    let lp = u32::from(b1 >> 4);
    let pb = u32::from(b0 & 0x07);
    if u32::from(b0 >> 3) != lc + lp || lc >= 9 || lp >= 5 || pb >= 5 {
        return None;
    }
    Some(lc | (lp << 8) | (pb << 16))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_usize_to_u32(value: usize) -> u32 {
        u32::try_from(value).expect("fixture value fits u32")
    }

    fn write_end_l_info_marker(bytes: &mut [u8], offset: usize) {
        bytes[offset + 4..offset + 8].copy_from_slice(&UPX_MAGIC_V2.to_le_bytes());
        bytes[offset + 8..offset + 10].copy_from_slice(&0x80u16.to_le_bytes());
        bytes[offset + 10] = 12;
    }

    #[test]
    fn lzma_properties_validate_redundant_header() {
        let block = [0x18, 0x03, 0x00];
        assert_eq!(upx_lzma_properties(&block), Some(3));
        assert_eq!(upx_lzma_properties(&[0xff, 0x03, 0x00]), None);
    }

    #[test]
    fn locate_layout_rejects_overflowing_probe_offsets_without_panic() {
        let analysis = ElfAnalysis {
            is_elf: true,
            is_64bit: true,
            endian: Some("little"),
            program_header_offset: Some((usize::MAX - 4) as u64),
            program_header_entry_size: Some(56),
            program_header_count: Some(0),
            ..ElfAnalysis::default()
        };

        assert!(locate_upx_layout(&[], &analysis).is_none());
    }

    #[test]
    fn near_phdr_scan_returns_l_info_start_not_magic_start() {
        let phdr_end = 128usize;
        let l_info_offset = phdr_end + 32;
        let mut bytes = vec![0u8; l_info_offset + L_INFO_SIZE + 16];
        bytes[l_info_offset + 4..l_info_offset + 8].copy_from_slice(&UPX_MAGIC_V2.to_le_bytes());

        let layout = scan_near_phdr_end_for_l_info(&bytes, phdr_end).expect("nearby UPX layout");

        assert_eq!(layout.l_info_offset, l_info_offset);
        assert_eq!(layout.version, 3);
    }

    #[test]
    fn near_phdr_scan_preserves_v1_magic_version() {
        let phdr_end = 128usize;
        let l_info_offset = phdr_end + 32;
        let mut bytes = vec![0u8; l_info_offset + L_INFO_SIZE + 16];
        bytes[l_info_offset + 4..l_info_offset + 8].copy_from_slice(&UPX_MAGIC_V1.to_le_bytes());

        let layout = scan_near_phdr_end_for_l_info(&bytes, phdr_end).expect("nearby UPX v1 layout");

        assert_eq!(layout.l_info_offset, l_info_offset);
        assert_eq!(layout.version, 1);
    }

    #[test]
    fn end_l_info_search_is_bounded_to_tail_window() {
        let far_marker = 0x4000usize;
        let mut bytes = vec![0u8; far_marker + MAX_UPX_ELF_END_L_INFO_SCAN + 0x100];
        write_end_l_info_marker(&mut bytes, far_marker);

        assert_eq!(find_end_l_info(&bytes, 0), None);

        let near_marker = bytes.len() - 0x80;
        write_end_l_info_marker(&mut bytes, near_marker);

        assert_eq!(find_end_l_info(&bytes, 0), Some(near_marker));
    }

    #[test]
    fn v1_stored_blocks_decode_with_pack_trailer() {
        let original = b"\x7fELFstored-v1";
        let loader_size = 64usize;
        let eof_marker_offset = 160usize;
        let pack_header_offset = eof_marker_offset + 4;
        let mut bytes = vec![0u8; pack_header_offset + V1_PACK_HDR_SIZE + 4];
        bytes[loader_size + 4..loader_size + 8]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[loader_size + 8..loader_size + 12]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        let block_offset = loader_size + P_INFO_SIZE;
        bytes[block_offset..block_offset + 4]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block_offset + 4..block_offset + 8]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block_offset + 8..block_offset + 8 + original.len()].copy_from_slice(original);
        bytes[eof_marker_offset..eof_marker_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[pack_header_offset..pack_header_offset + 4]
            .copy_from_slice(&UPX_MAGIC_V2.to_le_bytes());
        bytes[pack_header_offset + V1_PACK_METHOD_OFFSET] = METHOD_NRV2B32;
        bytes[pack_header_offset + V1_PACK_UNCOMPRESSED_LEN_OFFSET
            ..pack_header_offset + V1_PACK_UNCOMPRESSED_LEN_OFFSET + 4]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        let len = bytes.len();
        bytes[len - 4..].copy_from_slice(&fixture_usize_to_u32(loader_size).to_le_bytes());

        let decoded = decompress_v1_blocks(
            &bytes,
            UpxElfLayout {
                l_info_offset: 0,
                version: 1,
            },
        )
        .expect("stored UPX 1.x block should decode");

        assert_eq!(decoded, original);
    }

    #[test]
    fn zeroed_l_info_modern_stored_blocks_decode() {
        let original = b"\x7fELF";
        let mut bytes =
            vec![0u8; L_INFO_SIZE + P_INFO_SIZE + B_INFO_SIZE + original.len() + B_INFO_SIZE];
        let p_info = L_INFO_SIZE;
        bytes[p_info + 4..p_info + 8]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[p_info + 8..p_info + 12]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        let block = p_info + P_INFO_SIZE;
        bytes[block..block + 4]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block + 4..block + 8]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block + 8] = METHOD_NRV2B32;
        bytes[block + B_INFO_SIZE..block + B_INFO_SIZE + original.len()].copy_from_slice(original);

        let decoded = decompress_modern_blocks(
            &bytes,
            UpxElfLayout {
                l_info_offset: 0,
                version: 4,
            },
        )
        .expect("zeroed-l_info stored UPX block should decode");

        assert_eq!(decoded, original);
    }

    #[test]
    fn modern_overlap_stop_accepts_partial_elf_output() {
        let original = b"\x7fELFpartial";
        let mut bytes =
            vec![0u8; L_INFO_SIZE + P_INFO_SIZE + B_INFO_SIZE + original.len() + B_INFO_SIZE];
        let p_info = L_INFO_SIZE;
        bytes[p_info + 4..p_info + 8].copy_from_slice(&4096u32.to_le_bytes());
        bytes[p_info + 8..p_info + 12].copy_from_slice(&4096u32.to_le_bytes());
        let block = p_info + P_INFO_SIZE;
        bytes[block..block + 4]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block + 4..block + 8]
            .copy_from_slice(&fixture_usize_to_u32(original.len()).to_le_bytes());
        bytes[block + B_INFO_SIZE..block + B_INFO_SIZE + original.len()].copy_from_slice(original);
        let overlap = block + B_INFO_SIZE + original.len();
        bytes[overlap..overlap + 4].copy_from_slice(&272u32.to_le_bytes());
        bytes[overlap + 4..overlap + 8].copy_from_slice(&1860u32.to_le_bytes());
        bytes[overlap + 8] = 243;

        let decoded = decompress_modern_blocks(
            &bytes,
            UpxElfLayout {
                l_info_offset: 0,
                version: 3,
            },
        )
        .expect("implausible overlap block should stop after valid ELF output");

        assert_eq!(decoded, original);
    }
}
