// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Bounded embedded-child candidate probing.
//!
//! These helpers validate a child candidate that starts at a known byte range.
//! They are deliberately not a broad scanner: callers choose the candidate
//! range, such as a structured resource or a parser-computed overlay.
//!
//! The first-phase allowlist covers PE, ZIP, PDF, common image types, and
//! documented SFX archive candidates. Probing is capped to a bounded prefix and
//! only exact-range validators return extractable candidates. Tail-bounded or
//! unsupported candidates remain metadata so callers do not silently scan
//! parent tails with polluted object hashes.
//!
//! ## References
//!
//! The probing policy follows Inkie's file-type parser parity design for
//! parser-owned children and bounded SFX/overlay discovery. PE, ZIP, and PDF
//! validation details should be checked against the corresponding parser module
//! docs.
//!
//! ## Record Graph
//!
//! ```text
//! caller-provided byte range
//!   +-- bounded prefix probe
//!   +-- exact-range validator for an allowlisted embedded format
//!   +-- EmbeddedChildProbe::Valid or metadata-only rejection
//! ```

use std::cmp;

pub(crate) const MAX_EMBEDDED_CHILD_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedChildCandidate {
    pub(crate) mime: &'static str,
    pub(crate) size: u64,
    pub(crate) range_status: &'static str,
    pub(crate) range_basis: &'static str,
    pub(crate) extension: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedChildRejection {
    pub(crate) mime: &'static str,
    pub(crate) source_size: u64,
    pub(crate) range_status: &'static str,
    pub(crate) range_basis: &'static str,
    pub(crate) skip_reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmbeddedChildProbe {
    Valid(EmbeddedChildCandidate),
    Rejected(EmbeddedChildRejection),
}

pub(crate) fn probe_embedded_child(bytes: &[u8]) -> Option<EmbeddedChildProbe> {
    if bytes.is_empty() {
        return None;
    }
    let probe_limit = usize::try_from(MAX_EMBEDDED_CHILD_BYTES.checked_add(1)?).ok()?;
    let source_size = bytes.len() as u64;
    let bytes = &bytes[..bytes.len().min(probe_limit)];
    if bytes.starts_with(b"MZ") {
        return Some(validated(
            "application/x-dosexec",
            "exe",
            "pe_headers",
            source_size,
            validate_pe_size(bytes),
        ));
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return Some(validated(
            "application/zip",
            "zip",
            "zip_eocd",
            source_size,
            validate_zip_size(bytes),
        ));
    }
    if bytes.starts_with(b"%PDF-") {
        return Some(match validate_pdf_size(bytes) {
            Ok(size) => valid_candidate("application/pdf", "pdf", size, "pdf_eof"),
            Err("pdf_eof_not_found") => rejected(
                "application/pdf",
                source_size,
                "tail_bounded",
                "magic_to_parent_end",
                "tail_bounded_range_not_extracted",
            ),
            Err(reason) => rejected(
                "application/pdf",
                source_size,
                "unknown",
                "pdf_header",
                reason,
            ),
        });
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(validated(
            "image/png",
            "png",
            "png_iend",
            source_size,
            validate_png_size(bytes),
        ));
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return Some(validated(
            "image/jpeg",
            "jpg",
            "jpeg_eoi",
            source_size,
            validate_jpeg_size(bytes),
        ));
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(validated(
            "image/gif",
            "gif",
            "gif_trailer",
            source_size,
            validate_gif_size(bytes),
        ));
    }
    if bytes.starts_with(b"BM") {
        return Some(validated(
            "image/bmp",
            "bmp",
            "bmp_file_size",
            source_size,
            validate_bmp_size(bytes),
        ));
    }
    if bytes.starts_with(b"Rar!\x1a\x07\x00") || bytes.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some(unsupported_candidate("application/x-rar", source_size));
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some(unsupported_candidate(
            "application/x-7z-compressed",
            source_size,
        ));
    }
    if bytes.starts_with(b"MSCF") {
        return Some(unsupported_candidate(
            "application/vnd.ms-cab-compressed",
            source_size,
        ));
    }
    if bytes.starts_with(b"\x60\xea") {
        return Some(unsupported_candidate("application/x-arj", source_size));
    }
    None
}

fn validated(
    mime: &'static str,
    extension: &'static str,
    range_basis: &'static str,
    source_size: u64,
    result: Result<u64, &'static str>,
) -> EmbeddedChildProbe {
    match result {
        Ok(size) => valid_candidate(mime, extension, size, range_basis),
        Err(reason) => rejected(mime, source_size, "unknown", range_basis, reason),
    }
}

fn valid_candidate(
    mime: &'static str,
    extension: &'static str,
    size: u64,
    range_basis: &'static str,
) -> EmbeddedChildProbe {
    if size == 0 {
        return rejected(mime, size, "unknown", range_basis, "embedded_child_empty");
    }
    if size > MAX_EMBEDDED_CHILD_BYTES {
        return rejected(
            mime,
            size,
            "exact",
            range_basis,
            "embedded_child_size_limit_exceeded",
        );
    }
    EmbeddedChildProbe::Valid(EmbeddedChildCandidate {
        mime,
        size,
        range_status: "exact",
        range_basis,
        extension,
    })
}

fn unsupported_candidate(mime: &'static str, source_size: u64) -> EmbeddedChildProbe {
    rejected(
        mime,
        source_size,
        "tail_bounded",
        "magic_to_parent_end",
        "unsupported_overlay_candidate",
    )
}

fn rejected(
    mime: &'static str,
    source_size: u64,
    range_status: &'static str,
    range_basis: &'static str,
    skip_reason: &'static str,
) -> EmbeddedChildProbe {
    EmbeddedChildProbe::Rejected(EmbeddedChildRejection {
        mime,
        source_size,
        range_status,
        range_basis,
        skip_reason,
    })
}

fn validate_zip_size(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() < 22 {
        return Err("zip_candidate_too_short");
    }
    let search_start = bytes.len().saturating_sub(65_557);
    for offset in (search_start..=bytes.len() - 22).rev() {
        let Some(signature_end) = offset.checked_add(4) else {
            continue;
        };
        if bytes.get(offset..signature_end) != Some(b"PK\x05\x06") {
            continue;
        }
        let comment_len_offset = offset.checked_add(20).ok_or("zip_eocd_size_overflow")?;
        let comment_len =
            read_u16_le(bytes, comment_len_offset).ok_or("zip_eocd_not_found")? as usize;
        let end = offset
            .checked_add(22)
            .and_then(|end| end.checked_add(comment_len))
            .ok_or("zip_eocd_size_overflow")?;
        if end <= bytes.len() {
            return Ok(end as u64);
        }
    }
    Err("zip_eocd_not_found")
}

fn validate_pdf_size(bytes: &[u8]) -> Result<u64, &'static str> {
    let Some(eof) = find_last(bytes, b"%%EOF") else {
        return Err("pdf_eof_not_found");
    };
    let mut end = eof.checked_add(5).ok_or("pdf_size_overflow")?;
    while end < bytes.len() && matches!(bytes[end], b'\r' | b'\n') {
        end += 1;
    }
    Ok(end as u64)
}

fn validate_png_size(bytes: &[u8]) -> Result<u64, &'static str> {
    let mut offset = 8usize;
    loop {
        let header_end = offset.checked_add(8).ok_or("png_chunk_offset_overflow")?;
        if header_end > bytes.len() {
            return Err("png_chunk_truncated");
        }
        let length_raw = bytes
            .get(offset..offset.checked_add(4).ok_or("png_chunk_offset_overflow")?)
            .ok_or("png_chunk_truncated")?;
        let length =
            u32::from_be_bytes([length_raw[0], length_raw[1], length_raw[2], length_raw[3]])
                as usize;
        let chunk_type_start = offset.checked_add(4).ok_or("png_chunk_offset_overflow")?;
        let chunk_type = &bytes[chunk_type_start..header_end];
        let chunk_end = header_end
            .checked_add(length)
            .and_then(|end| end.checked_add(4))
            .ok_or("png_chunk_size_overflow")?;
        if chunk_end > bytes.len() {
            return Err("png_chunk_truncated");
        }
        if chunk_type == b"IEND" {
            return Ok(chunk_end as u64);
        }
        offset = chunk_end;
    }
}

fn validate_jpeg_size(bytes: &[u8]) -> Result<u64, &'static str> {
    for offset in 2..bytes.len().saturating_sub(1) {
        let eoi_end = offset.checked_add(2).ok_or("jpeg_size_overflow")?;
        if bytes.get(offset..eoi_end) == Some(b"\xff\xd9") {
            return Ok(eoi_end as u64);
        }
    }
    Err("jpeg_eoi_not_found")
}

fn validate_gif_size(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() < 13 {
        return Err("gif_header_truncated");
    }
    let packed = bytes[10];
    let mut offset = 13usize;
    if packed & 0x80 != 0 {
        let table_size = 3usize
            .checked_mul(1usize << ((packed & 0x07) + 1))
            .ok_or("gif_color_table_size_overflow")?;
        offset = offset
            .checked_add(table_size)
            .ok_or("gif_color_table_offset_overflow")?;
    }
    loop {
        let Some(&kind) = bytes.get(offset) else {
            return Err("gif_trailer_not_found");
        };
        offset = offset.checked_add(1).ok_or("gif_offset_overflow")?;
        match kind {
            0x3b => return Ok(offset as u64),
            0x21 => {
                offset = offset.checked_add(1).ok_or("gif_extension_overflow")?;
                offset = skip_gif_subblocks(bytes, offset)?;
            }
            0x2c => {
                let descriptor_end = offset
                    .checked_add(9)
                    .ok_or("gif_image_descriptor_overflow")?;
                if descriptor_end > bytes.len() {
                    return Err("gif_image_descriptor_truncated");
                }
                let image_packed = bytes[descriptor_end - 1];
                offset = descriptor_end;
                if image_packed & 0x80 != 0 {
                    let table_size = 3usize
                        .checked_mul(1usize << ((image_packed & 0x07) + 1))
                        .ok_or("gif_local_color_table_size_overflow")?;
                    offset = offset
                        .checked_add(table_size)
                        .ok_or("gif_local_color_table_offset_overflow")?;
                }
                offset = offset.checked_add(1).ok_or("gif_lzw_offset_overflow")?;
                offset = skip_gif_subblocks(bytes, offset)?;
            }
            _ => return Err("gif_block_type_invalid"),
        }
    }
}

fn skip_gif_subblocks(bytes: &[u8], mut offset: usize) -> Result<usize, &'static str> {
    loop {
        let Some(&size) = bytes.get(offset) else {
            return Err("gif_subblock_truncated");
        };
        offset += 1;
        if size == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(size as usize)
            .ok_or("gif_subblock_offset_overflow")?;
        if offset > bytes.len() {
            return Err("gif_subblock_truncated");
        }
    }
}

fn validate_bmp_size(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() < 14 {
        return Err("bmp_header_truncated");
    }
    let size = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if size < 14 {
        return Err("bmp_size_invalid");
    }
    if size > bytes.len() {
        return Err("bmp_truncated");
    }
    Ok(size as u64)
}

fn validate_pe_size(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() < 0x40 {
        return Err("pe_candidate_too_short");
    }
    let pe_offset = read_u32_le(bytes, 0x3c).ok_or("pe_lfanew_missing")? as usize;
    if bytes.get(pe_offset..pe_offset.checked_add(4).ok_or("pe_offset_overflow")?)
        != Some(b"PE\0\0")
    {
        return Err("pe_signature_missing");
    }
    let coff = pe_offset.checked_add(4).ok_or("pe_coff_offset_overflow")?;
    let section_count = read_u16_le(bytes, coff + 2).ok_or("pe_coff_truncated")? as usize;
    let optional_size = read_u16_le(bytes, coff + 16).ok_or("pe_coff_truncated")? as usize;
    let optional = coff.checked_add(20).ok_or("pe_optional_offset_overflow")?;
    let section_table = optional
        .checked_add(optional_size)
        .ok_or("pe_section_table_overflow")?;
    if section_table > bytes.len() {
        return Err("pe_optional_header_truncated");
    }
    let mut end = section_table
        .checked_add(
            section_count
                .checked_mul(40)
                .ok_or("pe_section_table_size_overflow")?,
        )
        .ok_or("pe_section_table_size_overflow")?;
    if optional_size >= 64
        && let Some(size_of_headers) = read_u32_le(bytes, optional + 60)
    {
        end = cmp::max(end, size_of_headers as usize);
    }
    for index in 0..section_count {
        let section = section_table
            .checked_add(index.checked_mul(40).ok_or("pe_section_offset_overflow")?)
            .ok_or("pe_section_offset_overflow")?;
        if section.checked_add(40).is_none_or(|end| end > bytes.len()) {
            return Err("pe_section_table_truncated");
        }
        let raw_size = read_u32_le(bytes, section + 16).unwrap_or_default() as usize;
        let raw_offset = read_u32_le(bytes, section + 20).unwrap_or_default() as usize;
        if raw_size != 0 {
            end = cmp::max(
                end,
                raw_offset
                    .checked_add(raw_size)
                    .ok_or("pe_raw_size_overflow")?,
            );
        }
    }
    if let Some((cert_offset, cert_size)) = pe_certificate_directory(bytes, optional, optional_size)
        && cert_size != 0
    {
        end = cmp::max(
            end,
            cert_offset
                .checked_add(cert_size)
                .ok_or("pe_certificate_size_overflow")?,
        );
    }
    if end > bytes.len() {
        return Err("pe_candidate_truncated");
    }
    Ok(end as u64)
}

fn pe_certificate_directory(
    bytes: &[u8],
    optional: usize,
    optional_size: usize,
) -> Option<(usize, usize)> {
    let magic = read_u16_le(bytes, optional)?;
    let data_directories = match magic {
        0x10b => optional.checked_add(96)?,
        0x20b => optional.checked_add(112)?,
        _ => return None,
    };
    let cert = data_directories.checked_add(4 * 8)?;
    if cert.checked_add(8)? > optional.checked_add(optional_size)? {
        return None;
    }
    Some((
        read_u32_le(bytes, cert)? as usize,
        read_u32_le(bytes, cert + 4)? as usize,
    ))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_exact_png_size() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\0IEND\xae\x42\x60\x82tail";
        let Some(EmbeddedChildProbe::Valid(candidate)) = probe_embedded_child(png) else {
            panic!("expected png candidate");
        };
        assert_eq!(candidate.mime, "image/png");
        assert_eq!(candidate.size, 20);
        assert_eq!(candidate.range_status, "exact");
    }

    #[test]
    fn records_tail_bounded_pdf_without_eof_as_rejected() {
        let Some(EmbeddedChildProbe::Rejected(rejection)) = probe_embedded_child(b"%PDF-1.7\n")
        else {
            panic!("expected pdf rejection");
        };
        assert_eq!(rejection.mime, "application/pdf");
        assert_eq!(rejection.range_status, "tail_bounded");
        assert_eq!(rejection.skip_reason, "tail_bounded_range_not_extracted");
    }
}
