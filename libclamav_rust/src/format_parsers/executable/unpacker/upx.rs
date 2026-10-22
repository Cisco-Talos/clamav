// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust UPX PE unpacking helpers.
//!
//! This module ports the bounded UPX NRV2B/NRV2D/NRV2E decompression paths
//! from `ClamAV` `libclamav/upx.c` into scanner-independent Rust. The PE parser
//! supplies the already-parsed section table and entrypoint context; this module
//! returns a rebuilt PE byte object for the file-type handler to scan as an
//! unpacked child. The rebuild path ports `ClamAV` `pefromupx()` and
//! `pe64fromupx()`:
//! import-table pointer discovery, backward PE header scan, forged fallback,
//! section-table rewrite, and PE32/PE32+ output assembly.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> UPX method/section facts -> NRV2B/NRV2D/NRV2E or LZMA decode
//!     -> import-table/header discovery -> PE32/PE32+ rebuild artifact
//! ```
//!
//! The decoder caps unpacked bytes, rebuild headroom, and section copies. It
//! preserves `ClamAV`'s forged-header fallback when a normal rebuilt header cannot
//! be recovered.

use std::io::Read;

use lzma_rust2::LzmaReader;

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, PeRebuildArch},
    },
};

const MAX_UPX_UNPACKED_BYTES: u64 = 128 * 1024 * 1024;
const UPX_REBUILD_HEADROOM: usize = 8192;
const INITIAL_LZMA_OUTPUT_CAPACITY: usize = 64 * 1024;
const PE32_REBUILD_HEADER_SIZE: usize = 0xf8;
const PE64_REBUILD_HEADER_SIZE: usize = 0x108;
const MAX_REBUILD_SECTIONS: usize = 96;
const MAX_IMPORT_VALIGN_SCAN: usize = 1024 * 1024;
const MAX_REBUILT_PE_BACKSCAN: usize = 1024 * 1024;
const UPX_METHOD_LZMA: u8 = 14;

const MAGIC_2B_PE32: &[u32] = &[0x108, 0x110, 0xd5];
const MAGIC_2D_PE32: &[u32] = &[0x11c, 0x124];
const MAGIC_2E_PE32: &[u32] = &[0x128, 0x130];
const MAGIC_LZMA_PE32: &[u32] = &[0xb16, 0xb1e];
const MAGIC_2B_PE64: &[u32] = &[0x153, 0x15b];
const MAGIC_2D_PE64: &[u32] = &[0x161, 0x169];
const MAGIC_2E_PE64: &[u32] = &[0x17a, 0x182];
const MAGIC_LZMA_PE64: &[u32] = &[0xae1, 0xae9];

const X86_LZMA1_FIRST: &[u8] = &[0x56, 0x83, 0xc3, 0x04, 0x53, 0x50, 0xc7, 0x03];
const X86_LZMA2: &[u8] = &[
    0x56, 0x83, 0xc3, 0x04, 0x53, 0x50, 0xc7, 0x03, 0x03, 0x00, 0x02, 0x00, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x55, 0x57, 0x56,
];

const X64_NRV_HEAD: &[u8] = &[0x31, 0xdb, 0x31, 0xc9, 0x48, 0x83, 0xcd, 0xff];
const X64_SETUP: &[u8] = &[0xfc, 0x41, 0x5b];
const X64_NRV2B: &[u8] = &[
    0x41, 0xff, 0xd3, 0x11, 0xc0, 0x01, 0xdb, 0x75, 0x0a, 0x8b, 0x1e, 0x48, 0x83,
];
const X64_NRV2D_OR_2E: &[u8] = &[
    0xeb, 0x07, 0xff, 0xc8, 0x41, 0xff, 0xd3, 0x11, 0xc0, 0x41, 0xff, 0xd3, 0x11,
];
const X64_LZMA: &[u8] = &[
    0x50, 0x48, 0x89, 0xe1, 0x48, 0x89, 0xfa, 0x48, 0x89, 0xf7, 0xbe,
];

pub(crate) type UpxUnpacked = UnpackedArtifact;

struct RawUpxUnpacked {
    bytes: Vec<u8>,
    dend: usize,
    magic: &'static [u32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NrvVariant {
    Nrv2b,
    Nrv2d,
    Nrv2e,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StubKind {
    Unknown,
    Nrv(NrvVariant),
    Nrv2dOr2e,
    Lzma,
}

pub(crate) fn unpack_pe(bytes: &[u8], analysis: &PeAnalysis) -> Result<UpxUnpacked, &'static str> {
    let ep_sample = super::pe_entrypoint_sample(bytes, analysis);
    let pair = find_upx_section_pair(&analysis.sections).ok_or("upx_section_pair_not_found")?;
    let upx0 = &analysis.sections[pair];
    let upx1 = &analysis.sections[pair + 1];
    let source_offset = upx1.start;
    let source_size = u64::from(upx1.raw_size);
    let source = section_bytes(bytes, upx1).ok_or("upx_source_range_invalid")?;
    let dest_size = u64::from(upx0.virtual_size)
        .checked_add(u64::from(upx1.virtual_size))
        .ok_or("upx_unpacked_size_overflow")?;
    if source.len() <= 0x19 || dest_size <= source.len() as u64 {
        return Err("upx_size_mismatch");
    }
    if dest_size > MAX_UPX_UNPACKED_BYTES {
        return Err("upx_unpacked_size_limit_exceeded");
    }
    let dest_size = usize::try_from(dest_size).map_err(|_| "upx_unpacked_size_overflow")?;
    let ep_rva = analysis.entrypoint_rva.ok_or("upx_entrypoint_missing")?;
    let raw = if analysis.is_64bit {
        match unpack_pe64_raw(source, dest_size, ep_sample) {
            Ok(result) => result,
            Err(reason) => packheader_lzma_fallback(bytes, source).ok_or(reason)?,
        }
    } else {
        let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
            .map_err(|_| "upx_image_base_out_of_range")?;
        unpack_pe32_raw(
            source,
            dest_size,
            upx0.virtual_address,
            upx1.virtual_address,
            ep_rva,
            image_base,
            ep_sample,
        )?
    };
    let bytes = rebuild_from_upx(
        source,
        &raw,
        dest_size,
        ep_rva,
        upx0.virtual_address,
        upx1.virtual_address,
        analysis.is_64bit,
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset,
        source_size,
    })
}

fn find_upx_section_pair(sections: &[PeSection]) -> Option<usize> {
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

fn unpack_pe32_raw(
    source: &[u8],
    dest_size: usize,
    upx0_rva: u32,
    upx1_rva: u32,
    ep_rva: u32,
    image_base: u32,
    ep_sample: &[u8],
) -> Result<RawUpxUnpacked, &'static str> {
    let skew = x86_skew(source.len(), upx1_rva, image_base, ep_sample);
    for (variant, magic) in [
        (NrvVariant::Nrv2b, MAGIC_2B_PE32),
        (NrvVariant::Nrv2d, MAGIC_2D_PE32),
        (NrvVariant::Nrv2e, MAGIC_2E_PE32),
    ] {
        if let Some(result) = try_nrv(
            source, dest_size, upx0_rva, upx1_rva, ep_rva, variant, skew, magic,
        ) {
            return Ok(result);
        }
        if skew != 0
            && let Some(result) = try_nrv(
                source, dest_size, upx0_rva, upx1_rva, ep_rva, variant, 0, magic,
            )
        {
            return Ok(result);
        }
        if source.len() > 0x15
            && let Some(adjusted_ep_rva) = ep_rva.checked_sub(0x15)
            && let Some(result) = try_nrv(
                &source[0x15..],
                dest_size,
                upx0_rva,
                upx1_rva,
                adjusted_ep_rva,
                variant,
                0,
                magic,
            )
        {
            return Ok(result);
        }
    }
    if let Some((properties, strict_size)) = x86_lzma_properties(dest_size, ep_sample) {
        let output_size = strict_size.min(dest_size);
        if let Some(result) = try_lzma(source, output_size, properties) {
            return Ok(RawUpxUnpacked {
                dend: result.len(),
                bytes: result,
                magic: MAGIC_LZMA_PE32,
            });
        }
    }
    Err("upx_decompression_failed")
}

#[allow(clippy::too_many_arguments)]
fn try_nrv(
    source: &[u8],
    dest_size: usize,
    _upx0_rva: u32,
    _upx1_rva: u32,
    _ep_rva: u32,
    variant: NrvVariant,
    skew: usize,
    magic: &'static [u32],
) -> Option<RawUpxUnpacked> {
    if skew > source.len() {
        return None;
    }
    let source = &source[skew..];
    let dest_len = dest_size.checked_add(UPX_REBUILD_HEADROOM)?;
    let mut dest = vec![0u8; dest_len];
    let written = match variant {
        NrvVariant::Nrv2b => inflate2b(source, &mut dest).ok()?,
        NrvVariant::Nrv2d => inflate2d(source, &mut dest).ok()?,
        NrvVariant::Nrv2e => inflate2e(source, &mut dest).ok()?,
    };
    dest.truncate(written);
    (!dest.is_empty()).then_some(RawUpxUnpacked {
        bytes: dest,
        dend: written,
        magic,
    })
}

fn unpack_pe64_raw(
    source: &[u8],
    dest_size: usize,
    ep_sample: &[u8],
) -> Result<RawUpxUnpacked, &'static str> {
    match x64_stub_kind(ep_sample) {
        StubKind::Nrv(variant) => {
            if let Some(result) = try_nrv(
                source,
                dest_size,
                0,
                0,
                0,
                variant,
                0,
                x64_magic_for_variant(variant),
            ) {
                return Ok(result);
            }
        }
        StubKind::Nrv2dOr2e => {
            for (variant, magic) in [
                (NrvVariant::Nrv2d, MAGIC_2D_PE64),
                (NrvVariant::Nrv2e, MAGIC_2E_PE64),
            ] {
                if let Some(result) = try_nrv(source, dest_size, 0, 0, 0, variant, 0, magic) {
                    return Ok(result);
                }
            }
        }
        StubKind::Lzma => {
            if let Some(properties) = x64_lzma_properties(source) {
                let strict_size = read_u32_le(ep_sample, 0x14)
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| *value != 0 && *value <= dest_size)
                    .unwrap_or(dest_size);
                if let Some(result) = try_lzma(source, strict_size, properties) {
                    return Ok(RawUpxUnpacked {
                        dend: result.len(),
                        bytes: result,
                        magic: MAGIC_LZMA_PE64,
                    });
                }
            }
        }
        StubKind::Unknown => {}
    }
    for (variant, magic) in [
        (NrvVariant::Nrv2b, MAGIC_2B_PE64),
        (NrvVariant::Nrv2d, MAGIC_2D_PE64),
        (NrvVariant::Nrv2e, MAGIC_2E_PE64),
    ] {
        if let Some(result) = try_nrv(source, dest_size, 0, 0, 0, variant, 0, magic) {
            return Ok(result);
        }
    }
    Err("upx_decompression_failed")
}

fn packheader_lzma_fallback(file: &[u8], source: &[u8]) -> Option<RawUpxUnpacked> {
    let properties = x64_lzma_properties(source)?;
    for cursor in memchr::memmem::find_iter(file, b"UPX!") {
        let Some(header_end) = cursor.checked_add(20) else {
            continue;
        };
        if header_end > file.len() {
            continue;
        }
        let header = &file[cursor..header_end];
        if header.get(6).copied() == Some(UPX_METHOD_LZMA)
            && let Some(length_offset) = cursor.checked_add(16)
            && let Some(u_len) = read_u32_le(file, length_offset)
            && u_len != 0
            && u64::from(u_len) <= MAX_UPX_UNPACKED_BYTES
            && let Ok(output_size) = usize::try_from(u_len)
            && let Some(result) = try_lzma(source, output_size, properties)
            && result.len() == output_size
        {
            return Some(RawUpxUnpacked {
                dend: result.len(),
                bytes: result,
                magic: MAGIC_LZMA_PE64,
            });
        }
    }
    None
}

fn x64_magic_for_variant(variant: NrvVariant) -> &'static [u32] {
    match variant {
        NrvVariant::Nrv2b => MAGIC_2B_PE64,
        NrvVariant::Nrv2d => MAGIC_2D_PE64,
        NrvVariant::Nrv2e => MAGIC_2E_PE64,
    }
}

fn x86_skew(source_len: usize, upx1_rva: u32, image_base: u32, ep_sample: &[u8]) -> usize {
    if ep_sample.len() < 6 || ep_sample[1] != 0xbe {
        return 0;
    }
    let Some(imm32) = read_u32_le(ep_sample, 2) else {
        return 0;
    };
    let skew = imm32.wrapping_sub(image_base).wrapping_sub(upx1_rva);
    if skew > 0 && skew <= 0xfff && usize::try_from(skew).is_ok_and(|skew| skew <= source_len) {
        skew as usize
    } else {
        0
    }
}

fn x86_lzma_properties(dest_size: usize, ep_sample: &[u8]) -> Option<(u32, usize)> {
    let scan_limit = if ep_sample.len() >= 0x70 + X86_LZMA2.len() {
        0x70
    } else {
        0
    };
    if scan_limit == 0 {
        return None;
    }
    for offset in 0x20usize..scan_limit {
        let end = offset.checked_add(X86_LZMA2.len())?;
        if ep_sample
            .get(offset..end)
            .is_some_and(|slice| slice == X86_LZMA2)
        {
            return Some((
                0x20003,
                nearby_push_size(ep_sample, offset).unwrap_or(dest_size),
            ));
        }
    }
    for offset in 0x20usize..scan_limit {
        let end = offset.checked_add(X86_LZMA1_FIRST.len())?;
        if ep_sample
            .get(offset..end)
            .is_some_and(|slice| slice == X86_LZMA1_FIRST)
        {
            let properties = read_u32_le(ep_sample, offset.checked_add(8)?)?;
            return Some((
                properties,
                nearby_push_size(ep_sample, offset).unwrap_or(dest_size),
            ));
        }
    }
    None
}

fn nearby_push_size(ep_sample: &[u8], offset: usize) -> Option<usize> {
    let mut values = Vec::with_capacity(2);
    let mut cursor = offset.saturating_sub(1);
    while cursor >= 0x10 && values.len() < 2 {
        if ep_sample[cursor] == 0x68
            && let Some(value) = read_u32_le(ep_sample, cursor.checked_add(1)?)
                .and_then(|value| usize::try_from(value).ok())
        {
            values.push(value);
        }
        if cursor == 0 {
            break;
        }
        cursor -= 1;
    }
    values.into_iter().max()
}

fn x64_stub_kind(ep_sample: &[u8]) -> StubKind {
    if ep_sample.len() < 0xc0 {
        return StubKind::Nrv(NrvVariant::Nrv2b);
    }
    let nrv_ok = ep_sample
        .get(0x13..0x13 + X64_NRV_HEAD.len())
        .is_some_and(|slice| slice == X64_NRV_HEAD);
    let setup_ok = ep_sample
        .get(0x70..0x70 + X64_SETUP.len())
        .is_some_and(|slice| slice == X64_SETUP);
    if nrv_ok && setup_ok {
        if ep_sample
            .get(0x92..0x92 + X64_NRV2B.len())
            .is_some_and(|slice| slice == X64_NRV2B)
        {
            return StubKind::Nrv(NrvVariant::Nrv2b);
        }
        if ep_sample
            .get(0x92..0x92 + X64_NRV2D_OR_2E.len())
            .is_some_and(|slice| slice == X64_NRV2D_OR_2E)
        {
            return match ep_sample.get(0xb4).copied() {
                Some(0x17) => StubKind::Nrv(NrvVariant::Nrv2d),
                Some(0x19) => StubKind::Nrv(NrvVariant::Nrv2e),
                _ => StubKind::Nrv2dOr2e,
            };
        }
    }
    if ep_sample
        .get(0x18..0x18 + X64_LZMA.len())
        .is_some_and(|slice| slice == X64_LZMA)
    {
        return StubKind::Lzma;
    }
    StubKind::Unknown
}

fn x64_lzma_properties(source: &[u8]) -> Option<u32> {
    let b0 = *source.first()?;
    let b1 = *source.get(1)?;
    let pb = b0 & 7;
    let lp = b1 >> 4;
    let lc = b1 & 0x0f;
    if (b0 >> 3) != lc + lp || lc >= 9 || lp >= 5 || pb >= 5 {
        return None;
    }
    Some(u32::from(lc) | (u32::from(lp) << 8) | (u32::from(pb) << 16))
}

pub(super) fn try_lzma(source: &[u8], output_size: usize, properties: u32) -> Option<Vec<u8>> {
    if source.len() < 3 || output_size == 0 {
        return None;
    }
    let lc = properties & 0xff;
    let lp = (properties >> 8) & 0xff;
    let pb = (properties >> 16) & 0xff;
    if lc >= 9 || lp >= 5 || pb >= 5 {
        return None;
    }
    let dict_size = u32::try_from(output_size)
        .ok()?
        .max(lzma_rust2::DICT_SIZE_MIN);
    let reader = LzmaReader::new(
        &source[2..],
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

pub(super) fn inflate_nrv(
    source: &[u8],
    dest: &mut [u8],
    variant: NrvVariant,
) -> Result<usize, ()> {
    match variant {
        NrvVariant::Nrv2b => inflate2b(source, dest),
        NrvVariant::Nrv2d => inflate2d(source, dest),
        NrvVariant::Nrv2e => inflate2e(source, dest),
    }
}

fn rebuild_from_upx(
    source: &[u8],
    raw: &RawUpxUnpacked,
    dsize: usize,
    ep: u32,
    upx0: u32,
    upx1: u32,
    is_64bit: bool,
) -> Result<Vec<u8>, &'static str> {
    let capacity = dsize
        .checked_add(UPX_REBUILD_HEADROOM)
        .ok_or("upx_rebuild_size_overflow")?
        .max(raw.bytes.len());
    if capacity as u64 > MAX_UPX_UNPACKED_BYTES + UPX_REBUILD_HEADROOM as u64 {
        return Err("upx_rebuild_size_limit_exceeded");
    }
    let mut dst = vec![0u8; capacity];
    dst[..raw.bytes.len()].copy_from_slice(&raw.bytes);
    if is_64bit {
        pe64_from_upx(source, &mut dst, dsize, ep, upx0, upx1, raw.magic, raw.dend)
    } else {
        pe32_from_upx(source, &mut dst, dsize, ep, upx0, upx1, raw.magic, raw.dend)
    }
}

#[allow(clippy::too_many_arguments)]
fn pe32_from_upx(
    source: &[u8],
    dst: &mut [u8],
    dsize: usize,
    ep: u32,
    upx0: u32,
    upx1: u32,
    magic: &[u32],
    dend: usize,
) -> Result<Vec<u8>, &'static str> {
    pe_from_upx(
        source,
        dst,
        dsize,
        ep,
        upx0,
        upx1,
        magic,
        dend,
        PeRebuildFlavor::Pe32,
    )
}

#[allow(clippy::too_many_arguments)]
fn pe64_from_upx(
    source: &[u8],
    dst: &mut [u8],
    dsize: usize,
    ep: u32,
    upx0: u32,
    upx1: u32,
    magic: &[u32],
    dend: usize,
) -> Result<Vec<u8>, &'static str> {
    pe_from_upx(
        source,
        dst,
        dsize,
        ep,
        upx0,
        upx1,
        magic,
        dend,
        PeRebuildFlavor::Pe64,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeRebuildFlavor {
    Pe32,
    Pe64,
}

impl PeRebuildFlavor {
    fn header_size(self) -> usize {
        match self {
            Self::Pe32 => PE32_REBUILD_HEADER_SIZE,
            Self::Pe64 => PE64_REBUILD_HEADER_SIZE,
        }
    }

    fn section_table_offset(self) -> usize {
        self.header_size()
    }

    fn header_magic(self) -> Option<u16> {
        match self {
            Self::Pe32 => None,
            Self::Pe64 => Some(0x20b),
        }
    }

    fn section_alignment_offset(self) -> usize {
        match self {
            Self::Pe32 => 0x38,
            Self::Pe64 => 0x3c,
        }
    }

    #[expect(
        clippy::unused_self,
        reason = "kept with PE rebuild flavor layout helpers even though both flavors share this offset"
    )]
    fn file_alignment_offset(self) -> usize {
        0x3c
    }
}

#[allow(clippy::too_many_arguments)]
fn pe_from_upx(
    source: &[u8],
    dst: &mut [u8],
    dsize: usize,
    ep: u32,
    upx0: u32,
    upx1: u32,
    magic: &[u32],
    dend: usize,
    flavor: PeRebuildFlavor,
) -> Result<Vec<u8>, &'static str> {
    if dsize == 0 || dsize > dst.len() {
        return Err("upx_rebuild_destination_invalid");
    }
    let dend = dend.min(dsize);
    let mut realstuffsz = 0usize;
    let mut pehdr = None;
    let mut sections = None;
    let mut valign = 0usize;
    let mut sectcnt = 0usize;

    if let Some(candidate) = find_import_valign(source, ep, upx1, magic)
        && let Some((header, align, count, section_offset, real_size)) =
            header_after_upx_imports(dst, dsize, source, ep, upx1, candidate, flavor)
    {
        realstuffsz = real_size;
        pehdr = Some(header);
        sections = Some(section_offset);
        valign = align;
        sectcnt = count;
    }

    if pehdr.is_none()
        && let Some((header, align, count, section_offset, real_size)) =
            scan_backwards_for_pe(dst, dsize, dend, flavor)
    {
        realstuffsz = real_size;
        pehdr = Some(header);
        sections = Some(section_offset);
        valign = align;
        sectcnt = count;
    }

    let Some(pehdr) = pehdr else {
        return forge_upx_pe(dst, dend, flavor);
    };
    let mut sections = if let Some(sections) = sections {
        sections
    } else {
        sectcnt = 0;
        pehdr + flavor.section_table_offset()
    };
    if valign == 0 {
        return Err("upx_rebuild_alignment_missing");
    }

    let mut foffset = align_usize(
        0xd0usize
            .checked_add(flavor.header_size())
            .and_then(|value| value.checked_add(0x28usize.checked_mul(sectcnt)?))
            .ok_or("upx_rebuild_header_size_overflow")?,
        valign,
    )
    .ok_or("upx_rebuild_header_size_overflow")?;

    for _ in 0..sectcnt {
        require_range(dst, sections, 0x28, dsize)?;
        let vsize = align_usize(
            usize::try_from(read_u32_le(dst, sections + 8).ok_or("upx_section_vsize_missing")?)
                .map_err(|_| "upx_section_vsize_overflow")?,
            valign,
        )
        .ok_or("upx_section_vsize_overflow")?;
        let urva = floor_align_usize(
            usize::try_from(read_u32_le(dst, sections + 12).ok_or("upx_section_rva_missing")?)
                .map_err(|_| "upx_section_rva_overflow")?,
            valign,
        );
        if vsize == 0 || !contained_int(upx0 as usize, realstuffsz, urva, vsize) {
            return Err("upx_section_out_of_bounds");
        }
        if foffset
            .checked_add(vsize)
            .is_none_or(|end| end > dsize + UPX_REBUILD_HEADROOM)
        {
            return Err("upx_rebuild_raw_size_overflow");
        }
        write_u32_checked(dst, sections + 8, vsize)?;
        write_u32_checked(dst, sections + 12, urva)?;
        write_u32_checked(dst, sections + 16, vsize)?;
        write_u32_checked(dst, sections + 20, foffset)?;
        foffset += vsize;
        sections += 0x28;
    }

    write_u32_checked(dst, pehdr + 8, 0x4d41_4c43)?;
    write_u32_checked(dst, pehdr + flavor.file_alignment_offset(), valign)?;

    if foffset == 0 || foffset > dsize + UPX_REBUILD_HEADROOM {
        return Err("upx_rebuild_final_size_invalid");
    }
    let mut out = vec![0u8; foffset];
    rebuild::write_mz_stub(&mut out, 0xd0)?;
    let header_copy = flavor
        .header_size()
        .checked_add(
            sectcnt
                .checked_mul(0x28)
                .ok_or("upx_rebuild_header_copy_overflow")?,
        )
        .ok_or("upx_rebuild_header_copy_overflow")?;
    require_range(dst, pehdr, header_copy, dsize)?;
    require_range(&out, 0xd0, header_copy, out.len())?;
    out[0xd0..0xd0 + header_copy].copy_from_slice(&dst[pehdr..pehdr + header_copy]);

    let mut section = pehdr + flavor.section_table_offset();
    for _ in 0..sectcnt {
        require_range(dst, section, 0x28, dsize)?;
        let raw_off =
            usize::try_from(read_u32_le(dst, section + 20).ok_or("upx_section_raw_missing")?)
                .map_err(|_| "upx_section_raw_overflow")?;
        let raw_size =
            usize::try_from(read_u32_le(dst, section + 16).ok_or("upx_section_size_missing")?)
                .map_err(|_| "upx_section_size_overflow")?;
        let rva = usize::try_from(read_u32_le(dst, section + 12).ok_or("upx_section_rva_missing")?)
            .map_err(|_| "upx_section_rva_overflow")?;
        let src_off = rva
            .checked_sub(upx0 as usize)
            .ok_or("upx_section_source_before_upx0")?;
        require_range(&out, raw_off, raw_size, out.len())?;
        require_range(dst, src_off, raw_size, dsize)?;
        out[raw_off..raw_off + raw_size].copy_from_slice(&dst[src_off..src_off + raw_size]);
        section += 0x28;
    }
    Ok(out)
}

fn find_import_valign(source: &[u8], ep: u32, upx1: u32, magic: &[u32]) -> Option<u32> {
    let base = ep.checked_sub(upx1)?;
    for &candidate in magic {
        let probe = base.checked_add(candidate)?;
        if probe >= 2 {
            let offset = usize::try_from(probe - 2).ok()?;
            let probe_usize = usize::try_from(probe).ok()?;
            if source.get(offset..offset.checked_add(2)?) == Some(&[0x8d, 0xbe][..])
                && probe_usize
                    .checked_add(4)
                    .is_some_and(|end| end <= source.len())
            {
                return Some(candidate);
            }
        }
    }
    let mut cursor = usize::try_from(base.checked_add(0x80)?).ok()?;
    let scan_end = cursor
        .checked_add(MAX_IMPORT_VALIGN_SCAN)?
        .min(source.len());
    while cursor.checked_add(8).is_some_and(|end| end <= scan_end) {
        let Some(relative) = find_subslice(&source[cursor..scan_end], &[0x8d, 0xbe]) else {
            break;
        };
        cursor = cursor.checked_add(relative)?;
        if source.get(cursor.checked_add(6)?) == Some(&0x8b)
            && source.get(cursor.checked_add(7)?) == Some(&0x07)
        {
            let derived = u32::try_from(cursor.checked_add(2)?).ok()?;
            return derived.checked_sub(base);
        }
        cursor = cursor.checked_add(1)?;
    }
    None
}

fn header_after_upx_imports(
    dst: &[u8],
    dsize: usize,
    source: &[u8],
    ep: u32,
    upx1: u32,
    valign: u32,
    flavor: PeRebuildFlavor,
) -> Option<(usize, usize, usize, usize, usize)> {
    let base = ep.checked_sub(upx1)?;
    let probe = usize::try_from(base.checked_add(valign)?).ok()?;
    if probe.checked_add(4)? > source.len() {
        return None;
    }
    let imports = usize::try_from(read_u32_le(source, probe)?).ok()?;
    if imports == 0 || imports >= dsize {
        return None;
    }
    let mut cursor = imports;
    while cursor.checked_add(8)? <= dsize && read_u32_le(dst, cursor)? != 0 {
        cursor = cursor.checked_add(8)?;
        while cursor.checked_add(2)? <= dsize && *dst.get(cursor)? != 0 {
            cursor = cursor.checked_add(1)?;
            while cursor.checked_add(2)? <= dsize && *dst.get(cursor)? != 0 {
                cursor = cursor.checked_add(1)?;
            }
            cursor = cursor.checked_add(1)?;
        }
        cursor = cursor.checked_add(1)?;
    }
    let pehdr = cursor.checked_add(4)?;
    let (align, count, sections) = check_rebuilt_pe(dst, dsize, pehdr, flavor)?;
    Some((pehdr, align, count, sections, imports))
}

fn scan_backwards_for_pe(
    dst: &[u8],
    dsize: usize,
    dend: usize,
    flavor: PeRebuildFlavor,
) -> Option<(usize, usize, usize, usize, usize)> {
    let minimum = flavor.header_size().checked_add(0x28)?;
    if dend <= minimum {
        return None;
    }
    let mut pehdr = dend.checked_sub(minimum)?;
    let stop = pehdr.saturating_sub(MAX_REBUILT_PE_BACKSCAN);
    while pehdr > stop {
        if let Some((align, count, sections)) = check_rebuilt_pe(dst, dsize, pehdr, flavor) {
            return Some((pehdr, align, count, sections, pehdr));
        }
        pehdr -= 1;
    }
    None
}

fn check_rebuilt_pe(
    dst: &[u8],
    dsize: usize,
    pehdr: usize,
    flavor: PeRebuildFlavor,
) -> Option<(usize, usize, usize)> {
    require_range(dst, pehdr, flavor.header_size(), dsize).ok()?;
    if dst.get(pehdr..pehdr + 4) != Some(b"PE\0\0") {
        return None;
    }
    if let Some(magic) = flavor.header_magic()
        && u16::from_le_bytes([*dst.get(pehdr + 24)?, *dst.get(pehdr + 25)?]) != magic
    {
        return None;
    }
    let align =
        usize::try_from(read_u32_le(dst, pehdr + flavor.section_alignment_offset())?).ok()?;
    if align == 0 {
        return None;
    }
    if flavor == PeRebuildFlavor::Pe64 && (!align.is_power_of_two() || align > 0x20_0000) {
        return None;
    }
    let count = usize::from(u16::from_le_bytes([
        *dst.get(pehdr + 6)?,
        *dst.get(pehdr + 7)?,
    ]));
    if count == 0 || count > MAX_REBUILD_SECTIONS {
        return None;
    }
    let sections = pehdr.checked_add(flavor.section_table_offset())?;
    require_range(dst, sections, count.checked_mul(0x28)?, dsize).ok()?;
    Some((align, count, sections))
}

fn forge_upx_pe(dst: &[u8], dend: usize, flavor: PeRebuildFlavor) -> Result<Vec<u8>, &'static str> {
    let copy_len = dend.min(dst.len());
    match flavor {
        PeRebuildFlavor::Pe32 => rebuild::wrap_payload_as_single_section_pe(
            &dst[..copy_len],
            PeRebuildArch::Pe32,
            0x0040_0000,
            0x1000,
            0x1000,
        ),
        PeRebuildFlavor::Pe64 => rebuild::wrap_payload_as_single_section_pe(
            &dst[..copy_len],
            PeRebuildArch::Pe64,
            0x0000_0001_4000_0000,
            0x1000,
            0x1000,
        ),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contained_int(base: usize, size: usize, start: usize, len: usize) -> bool {
    let Some(limit) = base.checked_add(size) else {
        return false;
    };
    start >= base && start.checked_add(len).is_some_and(|end| end <= limit)
}

fn floor_align_usize(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        value
    } else {
        value / alignment * alignment
    }
}

fn require_range(
    bytes: &[u8],
    offset: usize,
    len: usize,
    visible_len: usize,
) -> Result<(), &'static str> {
    if visible_len <= bytes.len()
        && offset
            .checked_add(len)
            .is_some_and(|end| end <= visible_len)
    {
        Ok(())
    } else {
        Err("upx_rebuild_range_out_of_bounds")
    }
}

fn write_u32_checked(out: &mut [u8], offset: usize, value: usize) -> Result<(), &'static str> {
    let value = u32::try_from(value).map_err(|_| "upx_rebuild_u32_overflow")?;
    write_u32(out, offset, value);
    Ok(())
}

fn inflate2b(source: &[u8], dest: &mut [u8]) -> Result<usize, ()> {
    let mut bits = BitReader::new(source);
    let mut dcur = 0usize;
    let mut unp_offset = -1i32;
    loop {
        while bits.double()? {
            copy_literal(source, dest, &mut bits.scur, &mut dcur)?;
        }
        let mut backbytes = 1i32;
        loop {
            backbytes = checked_double_i32(backbytes, bits.double()?)?;
            if bits.double()? {
                break;
            }
        }
        backbytes -= 3;
        if backbytes >= 0 {
            let byte = i32::from(next_source_byte(source, &mut bits.scur)?);
            backbytes = !((backbytes << 8) + byte);
            if backbytes == 0 {
                break;
            }
            unp_offset = backbytes;
        }
        let mut backsize = u32::from(bits.double()?);
        backsize = checked_double_u32(backsize, bits.double()?)?;
        if backsize == 0 {
            backsize = 1;
            loop {
                backsize = checked_double_u32(backsize, bits.double()?)?;
                if bits.double()? {
                    break;
                }
            }
            backsize = backsize.checked_add(2).ok_or(())?;
        }
        if (unp_offset.cast_unsigned()) < 0xffff_f300 {
            backsize = backsize.checked_add(1).ok_or(())?;
        }
        backsize = backsize.checked_add(1).ok_or(())?;
        copy_backref(dest, &mut dcur, unp_offset, backsize as usize)?;
    }
    Ok(dcur)
}

fn inflate2d(source: &[u8], dest: &mut [u8]) -> Result<usize, ()> {
    let mut bits = BitReader::new(source);
    let mut dcur = 0usize;
    let mut unp_offset = -1i32;
    loop {
        while bits.double()? {
            copy_literal(source, dest, &mut bits.scur, &mut dcur)?;
        }
        let mut backbytes = 1i32;
        loop {
            backbytes = checked_double_i32(backbytes, bits.double()?)?;
            if bits.double()? {
                break;
            }
            backbytes -= 1;
            backbytes = checked_double_i32(backbytes, bits.double()?)?;
        }
        let mut backsize;
        backbytes -= 3;
        if backbytes >= 0 {
            let byte = i32::from(next_source_byte(source, &mut bits.scur)?);
            backbytes = !((backbytes << 8) + byte);
            if backbytes == 0 {
                break;
            }
            backsize = (backbytes & 1).cast_unsigned();
            backbytes >>= 1;
            unp_offset = backbytes;
        } else {
            backsize = u32::from(bits.double()?);
        }
        backsize = checked_double_u32(backsize, bits.double()?)?;
        if backsize == 0 {
            backsize = 1;
            loop {
                backsize = checked_double_u32(backsize, bits.double()?)?;
                if bits.double()? {
                    break;
                }
            }
            backsize = backsize.checked_add(2).ok_or(())?;
        }
        if (unp_offset.cast_unsigned()) < 0xffff_fb00 {
            backsize = backsize.checked_add(1).ok_or(())?;
        }
        backsize = backsize.checked_add(1).ok_or(())?;
        copy_backref(dest, &mut dcur, unp_offset, backsize as usize)?;
    }
    Ok(dcur)
}

fn inflate2e(source: &[u8], dest: &mut [u8]) -> Result<usize, ()> {
    let mut bits = BitReader::new(source);
    let mut dcur = 0usize;
    let mut unp_offset = -1i32;
    loop {
        while bits.double()? {
            copy_literal(source, dest, &mut bits.scur, &mut dcur)?;
        }
        let mut backbytes = 1i32;
        loop {
            backbytes = checked_double_i32(backbytes, bits.double()?)?;
            if bits.double()? {
                break;
            }
            backbytes -= 1;
            backbytes = checked_double_i32(backbytes, bits.double()?)?;
        }
        backbytes -= 3;
        let mut backsize;
        if backbytes >= 0 {
            let byte = i32::from(next_source_byte(source, &mut bits.scur)?);
            backbytes = !((backbytes << 8) + byte);
            if backbytes == 0 {
                break;
            }
            backsize = (backbytes & 1).cast_unsigned();
            backbytes >>= 1;
            unp_offset = backbytes;
        } else {
            backsize = u32::from(bits.double()?);
        }
        if backsize != 0 {
            backsize = u32::from(bits.double()?);
        } else {
            backsize = 1;
            if bits.double()? {
                backsize = 2 + u32::from(bits.double()?);
            } else {
                loop {
                    backsize = checked_double_u32(backsize, bits.double()?)?;
                    if bits.double()? {
                        break;
                    }
                }
                backsize = backsize.checked_add(2).ok_or(())?;
            }
        }
        if (unp_offset.cast_unsigned()) < 0xffff_fb00 {
            backsize = backsize.checked_add(1).ok_or(())?;
        }
        backsize = backsize.checked_add(2).ok_or(())?;
        copy_backref(dest, &mut dcur, unp_offset, backsize as usize)?;
    }
    Ok(dcur)
}

struct BitReader<'a> {
    source: &'a [u8],
    myebx: u32,
    scur: usize,
}

impl<'a> BitReader<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            myebx: 0,
            scur: 0,
        }
    }

    fn double(&mut self) -> Result<bool, ()> {
        let oldebx = self.myebx;
        self.myebx = self.myebx.wrapping_mul(2);
        if oldebx == 0 || oldebx == 0x8000_0000 {
            let oldebx = read_u32_le(self.source, self.scur).ok_or(())?;
            self.myebx = oldebx.wrapping_mul(2).wrapping_add(1);
            self.scur = self.scur.checked_add(4).ok_or(())?;
            Ok(oldebx >> 31 != 0)
        } else {
            Ok(oldebx >> 31 != 0)
        }
    }
}

fn copy_literal(
    source: &[u8],
    dest: &mut [u8],
    scur: &mut usize,
    dcur: &mut usize,
) -> Result<(), ()> {
    let byte = next_source_byte(source, scur)?;
    let out = dest.get_mut(*dcur).ok_or(())?;
    *out = byte;
    *dcur = dcur.checked_add(1).ok_or(())?;
    Ok(())
}

fn next_source_byte(source: &[u8], scur: &mut usize) -> Result<u8, ()> {
    let byte = *source.get(*scur).ok_or(())?;
    *scur = scur.checked_add(1).ok_or(())?;
    Ok(byte)
}

fn copy_backref(
    dest: &mut [u8],
    dcur: &mut usize,
    unp_offset: i32,
    backsize: usize,
) -> Result<(), ()> {
    if unp_offset >= 0 {
        return Err(());
    }
    let distance = usize::try_from(unp_offset.checked_neg().ok_or(())?).map_err(|_| ())?;
    let mut src = dcur.checked_sub(distance).ok_or(())?;
    let end = dcur.checked_add(backsize).ok_or(())?;
    if end > dest.len() {
        return Err(());
    }
    while *dcur < end {
        let byte = *dest.get(src).ok_or(())?;
        dest[*dcur] = byte;
        src = src.checked_add(1).ok_or(())?;
        *dcur = dcur.checked_add(1).ok_or(())?;
    }
    Ok(())
}

fn checked_double_i32(value: i32, bit: bool) -> Result<i32, ()> {
    value
        .checked_mul(2)
        .and_then(|value| value.checked_add(i32::from(bit)))
        .ok_or(())
}

fn checked_double_u32(value: u32, bit: bool) -> Result<u32, ()> {
    value
        .checked_mul(2)
        .and_then(|value| value.checked_add(u32::from(bit)))
        .ok_or(())
}

fn align_usize(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return Some(value);
    }
    let addend = alignment.checked_sub(1)?;
    Some(value.checked_add(addend)? / alignment * alignment)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_usize_to_u32(value: usize) -> u32 {
        u32::try_from(value).expect("fixture value fits u32")
    }

    fn fixture_u32_to_u8(value: u32) -> u8 {
        u8::try_from(value).expect("fixture LZMA property fits u8")
    }

    fn pe_section(name: &str, raw_size: u32, virtual_size: u32) -> PeSection {
        PeSection {
            name: name.to_owned(),
            raw_size,
            virtual_size,
            ..PeSection::default()
        }
    }

    fn packheader_file(method: u8, u_len: u32) -> Vec<u8> {
        let offset = 7usize;
        let mut bytes = vec![0u8; offset + 20];
        bytes[offset..offset + 4].copy_from_slice(b"UPX!");
        bytes[offset + 6] = method;
        bytes[offset + 16..offset + 20].copy_from_slice(&u_len.to_le_bytes());
        bytes
    }

    fn upx_lzma_source(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;

        let options = lzma_rust2::LzmaOptions::with_preset(0);
        assert_eq!((options.lc, options.lp, options.pb), (3, 0, 2));
        let mut compressed = Vec::new();
        {
            let mut writer = lzma_rust2::LzmaWriter::new_no_header(&mut compressed, &options, true)
                .expect("test LZMA writer");
            writer.write_all(payload).expect("write test LZMA payload");
            writer.finish().expect("finish test LZMA payload");
        }

        let property_0 = ((options.lc + options.lp) << 3) | options.pb;
        let property_1 = (options.lp << 4) | options.lc;
        let mut source = vec![fixture_u32_to_u8(property_0), fixture_u32_to_u8(property_1)];
        source.extend_from_slice(&compressed);
        source
    }

    #[test]
    fn upx_section_pair_accepts_renamed_structural_pair() {
        let sections = [
            pe_section("UNIS", 0, 0x4000),
            pe_section("SOFT", 0x2000, 0x3000),
            pe_section(".rsrc", 0x400, 0x400),
        ];

        assert_eq!(find_upx_section_pair(&sections), Some(0));
    }

    #[test]
    fn upx_section_pair_rejects_non_structural_layouts() {
        assert_eq!(
            find_upx_section_pair(&[
                pe_section(".text", 0x200, 0x4000),
                pe_section(".data", 0x200, 0x2000)
            ]),
            None
        );
        assert_eq!(
            find_upx_section_pair(&[pe_section("empty", 0, 0), pe_section("data", 0x200, 0x2000)]),
            None
        );
        assert_eq!(
            find_upx_section_pair(&[
                pe_section("empty", 0, 0x4000),
                pe_section("zero", 0, 0x2000)
            ]),
            None
        );
    }

    #[test]
    fn upx_section_pair_selects_first_normal_upx_pair() {
        let sections = [
            pe_section("UPX0", 0, 0x4000),
            pe_section("UPX1", 0x2000, 0x3000),
            pe_section("UPX2", 0x400, 0x400),
        ];

        assert_eq!(find_upx_section_pair(&sections), Some(0));
    }

    #[test]
    fn packheader_lzma_fallback_rejects_invalid_headers() {
        let source = upx_lzma_source(b"synthetic upx lzma");
        let oversized = u32::try_from(MAX_UPX_UNPACKED_BYTES + 1).expect("UPX limit fits in u32");

        assert!(packheader_lzma_fallback(&[], &source).is_none());
        assert!(packheader_lzma_fallback(&packheader_file(UPX_METHOD_LZMA, 0), &source).is_none());
        assert!(
            packheader_lzma_fallback(&packheader_file(UPX_METHOD_LZMA, oversized), &source)
                .is_none()
        );
        assert!(packheader_lzma_fallback(&packheader_file(1, 16), &source).is_none());

        let mut invalid_properties = source.clone();
        invalid_properties[0] = 0xff;
        assert!(
            packheader_lzma_fallback(&packheader_file(UPX_METHOD_LZMA, 16), &invalid_properties)
                .is_none()
        );
    }

    #[test]
    fn packheader_lzma_fallback_decodes_exact_packheader_length() {
        let payload = b"MZ synthetic x64 UPX LZMA payload";
        let source = upx_lzma_source(payload);
        let result = packheader_lzma_fallback(
            &packheader_file(UPX_METHOD_LZMA, u32::try_from(payload.len()).unwrap()),
            &source,
        )
        .expect("PackHeader LZMA fallback should decode");

        assert_eq!(result.magic, MAGIC_LZMA_PE64);
        assert_eq!(result.dend, payload.len());
        assert_eq!(result.bytes, payload);
    }

    #[test]
    fn pe32_lzma_detection_accepts_modern_stub_without_second_legacy_marker() {
        let mut ep_sample = vec![0x90; 0x90];
        ep_sample[0x20] = 0x68;
        ep_sample[0x21..0x25].copy_from_slice(&0x4000u32.to_le_bytes());
        ep_sample[0x2f..0x2f + X86_LZMA1_FIRST.len()].copy_from_slice(X86_LZMA1_FIRST);
        ep_sample[0x2f + 8..0x2f + 12].copy_from_slice(&0x20003u32.to_le_bytes());

        assert_eq!(
            x86_lzma_properties(0x8000, &ep_sample),
            Some((0x20003, 0x4000))
        );
    }

    #[test]
    fn import_valign_fallback_scan_is_bounded() {
        let mut source = vec![0u8; 0x80 + MAX_IMPORT_VALIGN_SCAN + 16];
        let marker = 0x80 + MAX_IMPORT_VALIGN_SCAN + 1;
        source[marker..marker + 2].copy_from_slice(&[0x8d, 0xbe]);
        source[marker + 6] = 0x8b;
        source[marker + 7] = 0x07;

        assert_eq!(find_import_valign(&source, 0x1000, 0x1000, &[]), None);
    }

    #[test]
    fn rebuilt_pe_backscan_is_bounded() {
        let minimum = PeRebuildFlavor::Pe32
            .header_size()
            .checked_add(0x28)
            .unwrap();
        let dsize = MAX_REBUILT_PE_BACKSCAN + minimum + 0x200;
        let dend = dsize;
        let initial = dend - minimum;
        let pehdr = initial - MAX_REBUILT_PE_BACKSCAN;
        let mut dst = vec![0u8; dsize + UPX_REBUILD_HEADROOM];
        dst[pehdr..pehdr + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut dst, pehdr + 6, 1);
        write_u32(&mut dst, pehdr + 0x38, 0x1000);

        assert_eq!(
            scan_backwards_for_pe(&dst, dsize, dend, PeRebuildFlavor::Pe32),
            None
        );
    }

    #[test]
    fn upx_rebuild_forge_path_uses_clamav_style_pe32_offset() {
        let payload = b"you made me ink";
        let rebuilt = rebuild_from_upx(
            &[],
            &RawUpxUnpacked {
                bytes: payload.to_vec(),
                dend: payload.len(),
                magic: &[],
            },
            payload.len(),
            0,
            0x1000,
            0x2000,
            false,
        )
        .expect("forged PE32");

        assert_eq!(&rebuilt[..2], b"MZ");
        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(
            rebuilt.get(0xd0 + 0xf8..0xd0 + 0x100),
            Some(&b".clam01\0"[..])
        );
        assert!(
            rebuilt
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }

    #[test]
    fn upx_rebuild_forge_path_uses_clamav_style_pe64_offset() {
        let payload = b"you made me ink";
        let rebuilt = rebuild_from_upx(
            &[],
            &RawUpxUnpacked {
                bytes: payload.to_vec(),
                dend: payload.len(),
                magic: &[],
            },
            payload.len(),
            0,
            0x1000,
            0x2000,
            true,
        )
        .expect("forged PE64");

        assert_eq!(&rebuilt[..2], b"MZ");
        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(
            rebuilt.get(0xd0 + 24..0xd0 + 26),
            Some(&0x20bu16.to_le_bytes()[..])
        );
        assert_eq!(
            rebuilt.get(0xd0 + 0x108..0xd0 + 0x110),
            Some(&b".clam01\0"[..])
        );
        assert!(
            rebuilt
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }

    #[test]
    fn upx_pe32_rebuild_path_rewrites_sections() {
        let payload = b"you made me ink";
        let pehdr = 0x400usize;
        let header_size = PE32_REBUILD_HEADER_SIZE;
        let dend = pehdr + header_size + 0x28;
        let mut unpacked = vec![0u8; dend];
        unpacked[..payload.len()].copy_from_slice(payload);
        unpacked[pehdr..pehdr + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut unpacked, pehdr + 6, 1);
        write_u32(&mut unpacked, pehdr + 0x38, 0x200);
        let section = pehdr + header_size;
        unpacked[section..section + 8].copy_from_slice(b".text\0\0\0");
        write_u32(
            &mut unpacked,
            section + 8,
            fixture_usize_to_u32(payload.len()),
        );
        write_u32(&mut unpacked, section + 12, 0x1000);

        let rebuilt = rebuild_from_upx(
            &[],
            &RawUpxUnpacked {
                bytes: unpacked,
                dend,
                magic: &[],
            },
            dend,
            0,
            0x1000,
            0,
            false,
        )
        .expect("rebuilt PE32 from decompressed header");

        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 8), Some(0x4d41_4c43));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 0x3c), Some(0x200));
        assert_eq!(
            rebuilt.get(0xd0 + header_size..0xd0 + header_size + 8),
            Some(&b".text\0\0\0"[..])
        );
        assert_eq!(
            rebuilt.get(0x200..0x200 + payload.len()),
            Some(&payload[..])
        );
    }

    #[test]
    fn upx_pe64_rebuild_path_rewrites_sections() {
        let payload = b"you made me ink";
        let pehdr = 0x400usize;
        let header_size = PE64_REBUILD_HEADER_SIZE;
        let dend = pehdr + header_size + 0x28;
        let mut unpacked = vec![0u8; dend];
        unpacked[..payload.len()].copy_from_slice(payload);
        unpacked[pehdr..pehdr + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut unpacked, pehdr + 6, 1);
        write_u16(&mut unpacked, pehdr + 24, 0x20b);
        write_u32(&mut unpacked, pehdr + 0x3c, 0x200);
        let section = pehdr + header_size;
        unpacked[section..section + 8].copy_from_slice(b".text\0\0\0");
        write_u32(
            &mut unpacked,
            section + 8,
            fixture_usize_to_u32(payload.len()),
        );
        write_u32(&mut unpacked, section + 12, 0x1000);

        let rebuilt = rebuild_from_upx(
            &[],
            &RawUpxUnpacked {
                bytes: unpacked,
                dend,
                magic: &[],
            },
            dend,
            0,
            0x1000,
            0,
            true,
        )
        .expect("rebuilt PE64 from decompressed header");

        assert_eq!(read_u32_le(&rebuilt, 0x3c), Some(0xd0));
        assert_eq!(rebuilt.get(0xd0..0xd4), Some(&b"PE\0\0"[..]));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 8), Some(0x4d41_4c43));
        assert_eq!(read_u32_le(&rebuilt, 0xd0 + 0x3c), Some(0x200));
        assert_eq!(
            rebuilt.get(0xd0 + header_size..0xd0 + header_size + 8),
            Some(&b".text\0\0\0"[..])
        );
        assert_eq!(
            rebuilt.get(0x200..0x200 + payload.len()),
            Some(&payload[..])
        );
    }
}
