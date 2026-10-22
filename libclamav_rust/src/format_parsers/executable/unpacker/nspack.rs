// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Safe Rust `NsPack` PE unpacking helpers.
//!
//! This module ports `ClamAV` `libclamav/unsp.c` plus the `NsPack` PE32 dispatch
//! logic from `libclamav/pe.c`. `ClamAV` rebuilds the decoded bytes as a
//! single-section PE using the shared ClamAV-style PE rebuild module.
//!
//! ## State Machine
//!
//! ```text
//! PE analysis -> NsPack entrypoint/table checks -> bounded table decode
//!     -> decompressed byte image -> single-section PE rebuild
//! ```
//!
//! Output bytes and table bytes are capped. PE64 inputs are reported as
//! unsupported because `ClamAV`'s legacy path is PE32-only.

use crate::format_parsers::executable::{
    UnpackedArtifact,
    pe::{
        PeAnalysis, PeSection,
        rebuild::{self, RebuildOptions, RebuildSection},
    },
};

const MAX_NSPACK_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NSPACK_TABLE_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) type NsPackUnpacked = UnpackedArtifact;

pub(crate) fn unpack_pe(
    bytes: &[u8],
    analysis: &PeAnalysis,
) -> Result<NsPackUnpacked, &'static str> {
    if analysis.is_64bit {
        return Err("nspack_pe64_not_supported_by_clamav");
    }
    if analysis.sections.is_empty() {
        return Err("nspack_section_count_too_low");
    }
    let image_base = u32::try_from(analysis.image_base.unwrap_or_default())
        .map_err(|_| "nspack_image_base_out_of_range")?;
    let mut eprva = analysis.entrypoint_rva.ok_or("nspack_entrypoint_missing")?;
    let mut rep = analysis
        .entrypoint_offset
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("nspack_entrypoint_offset_missing")?;
    let ep = super::pe_entrypoint_sample(bytes, analysis);
    let mut src = ep;

    if src.first() == Some(&0xe9) {
        eprva = read_i32_le(src, 1)
            .and_then(|delta| {
                i64::from(eprva)
                    .checked_add(i64::from(delta))
                    .and_then(|value| value.checked_add(5))
            })
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("nspack_jump_target_invalid")?;
        rep = rva_to_offset(eprva, &analysis.sections, bytes.len())
            .ok_or("nspack_jump_target_out_of_bounds")?;
        src = bytes
            .get(rep..rep.checked_add(24).ok_or("nspack_jump_sample_invalid")?)
            .ok_or("nspack_jump_sample_invalid")?;
    }

    if src.get(..13) != Some(&[0x9c, 0x60, 0xe8, 0, 0, 0, 0, 0x5d, 0xb8, 0x07, 0, 0, 0]) {
        return Err("nspack_stub_not_recognized");
    }

    let nowinldr = 0x54_i64
        .checked_sub(i64::from(
            read_i32_le(src, 17).ok_or("nspack_loader_delta_missing")?,
        ))
        .ok_or("nspack_loader_delta_overflow")?;
    let loader_ref = checked_add_signed(rep, -nowinldr).ok_or("nspack_loader_ref_invalid")?;
    let start_delta = read_i32_le(bytes, loader_ref).ok_or("nspack_start_delta_missing")?;
    let start_of_stuff = i64::try_from(rep)
        .ok()
        .and_then(|rep| rep.checked_add(i64::from(start_delta)))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("nspack_start_offset_invalid")?;
    let mut start_of_stuff = start_of_stuff;
    let mut header = bytes
        .get(
            start_of_stuff
                ..start_of_stuff
                    .checked_add(20)
                    .ok_or("nspack_header_range_invalid")?,
        )
        .ok_or("nspack_header_range_invalid")?;
    if read_u32_le(header, 0) == Some(0) {
        start_of_stuff = start_of_stuff
            .checked_add(4)
            .ok_or("nspack_start_offset_overflow")?;
        header = bytes
            .get(
                start_of_stuff
                    ..start_of_stuff
                        .checked_add(20)
                        .ok_or("nspack_header_range_invalid")?,
            )
            .ok_or("nspack_header_range_invalid")?;
    }
    let ssize = read_u32_le(header, 5).ok_or("nspack_compressed_size_missing")? | 0xff;
    let dsize = read_u32_le(header, 9).ok_or("nspack_decompressed_size_missing")?;
    if ssize == 0 || dsize == 0 || dsize != analysis.sections[0].virtual_size {
        return Err("nspack_size_mismatch");
    }
    if u64::from(dsize) > MAX_NSPACK_OUTPUT_BYTES {
        return Err("nspack_output_size_limit_exceeded");
    }
    let source_size = usize::try_from(ssize).map_err(|_| "nspack_compressed_size_overflow")?;
    let source = bytes
        .get(
            start_of_stuff
                ..start_of_stuff
                    .checked_add(source_size)
                    .ok_or("nspack_source_range_invalid")?,
        )
        .ok_or("nspack_source_range_invalid")?;

    eprva = eprva.checked_add(0x27a).ok_or("nspack_oep_overflow")?;
    let oep_ref =
        rva_to_offset(eprva, &analysis.sections, bytes.len()).ok_or("nspack_oep_ref_invalid")?;
    let oep_delta = read_i32_le(
        bytes,
        oep_ref.checked_add(1).ok_or("nspack_oep_ref_invalid")?,
    )
    .ok_or("nspack_oep_delta_missing")?;
    let oep = i64::from(eprva)
        .checked_add(5)
        .and_then(|value| value.checked_add(i64::from(oep_delta)))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("nspack_oep_invalid")?;

    let decoded = unspack_section(source)?;
    let bytes = rebuild::rebuild_pe_from_sections(
        &decoded,
        &[RebuildSection {
            source_offset: 0,
            rva: analysis.sections[0].virtual_address,
            virtual_size: analysis.sections[0].virtual_size,
            raw_size: u32::try_from(decoded.len()).map_err(|_| "nspack_output_size_overflow")?,
        }],
        RebuildOptions::pe32(image_base, oep),
    )?;
    Ok(UnpackedArtifact {
        bytes,
        source_offset: start_of_stuff as u64,
        source_size: u64::from(ssize),
    })
}

fn unspack_section(source: &[u8]) -> Result<Vec<u8>, &'static str> {
    let c0 = *source.first().ok_or("nspack_header_empty")?;
    if c0 >= 0xe1 {
        return Err("nspack_header_invalid");
    }
    let mut c = c0;
    let firstbyte = if c >= 0x2d {
        let mut i = c / 0x2d;
        let firstbyte = i;
        while i != 0 {
            c = c.wrapping_add(0xd3);
            i -= 1;
        }
        firstbyte
    } else {
        0
    };
    let allocsz = if c >= 9 {
        let mut i = c / 9;
        let allocsz = i;
        while i != 0 {
            c = c.wrapping_add(0xf7);
            i -= 1;
        }
        allocsz
    } else {
        0
    };
    let tre = c;
    let c = tre.wrapping_add(allocsz);
    let table_entries = (0x300usize
        .checked_shl(u32::from(c))
        .ok_or("nspack_table_size_overflow")?)
    .checked_add(0x736)
    .ok_or("nspack_table_size_overflow")?;
    let table_bytes = table_entries
        .checked_mul(2)
        .ok_or("nspack_table_size_overflow")?;
    if table_bytes as u64 > MAX_NSPACK_TABLE_BYTES {
        return Err("nspack_table_size_limit_exceeded");
    }
    let dsize = read_u32_le(source, 9).ok_or("nspack_decompressed_size_missing")?;
    let ssize = read_u32_le(source, 5).ok_or("nspack_compressed_size_missing")?;
    if ssize <= 13 || u64::from(dsize) > MAX_NSPACK_OUTPUT_BYTES {
        return Err("nspack_size_invalid");
    }
    let dsize_usize = usize::try_from(dsize).map_err(|_| "nspack_output_size_overflow")?;
    let ssize_usize = usize::try_from(ssize).map_err(|_| "nspack_input_size_overflow")?;
    if source.len() < ssize_usize {
        return Err("nspack_input_range_invalid");
    }
    let mut table = vec![0x400u16; table_entries];
    let mut dst = vec![0u8; dsize_usize];
    very_real_unpack(
        &mut table,
        tre.into(),
        allocsz.into(),
        firstbyte.into(),
        &source[0x0d..ssize_usize],
        ssize,
        &mut dst,
    )?;
    Ok(dst)
}

fn very_real_unpack(
    table: &mut [u16],
    tre: u32,
    allocsz: u32,
    firstbyte: u32,
    src: &[u8],
    ssize: u32,
    dst: &mut [u8],
) -> Result<(), &'static str> {
    let required_entries = (0x300usize
        .checked_shl((allocsz + tre) & 0xff)
        .ok_or("nspack_table_size_overflow")?)
    .checked_add(0x736)
    .ok_or("nspack_table_size_overflow")?;
    if table.len() < required_entries {
        return Err("nspack_table_too_small");
    }
    table.fill(0x400);
    let read_limit = usize::try_from(ssize)
        .ok()
        .and_then(|size| size.checked_sub(13))
        .ok_or("nspack_input_size_underflow")?;
    let mut read = UnspReader::new(src, read_limit);
    for _ in 0..5 {
        read.oldval = (read.oldval << 8) | read.get_byte();
    }
    read.check()?;
    let firstbyte_mask = (1u32 << (firstbyte & 0xff)).wrapping_sub(1);
    let put = (1u32 << (allocsz & 0xff)).wrapping_sub(1);
    let mut previous_bit = 0u32;
    let mut unpacked_so_far = 0usize;
    let mut backbytes = 1u32;
    let mut oldbackbytes = 1u32;
    let mut old_oldbackbytes = 1u32;
    let mut old_old_oldbackbytes = 1u32;
    let mut damian = 0u32;
    let mut bielle = 0u32;

    loop {
        read.check()?;
        let unpacked_so_far_u32 =
            u32::try_from(unpacked_so_far).map_err(|_| "nspack_output_offset_overflow")?;
        let backsize_seed = firstbyte_mask & unpacked_so_far_u32;
        let mut tpos;
        if !getbit_from_table(
            table,
            table_offset((damian << 4) as usize, backsize_seed as usize)?,
            &mut read,
        )? {
            let shft = (8u32.wrapping_sub(tre)) & 0xff;
            tpos = (bielle >> shft) + ((put & unpacked_so_far_u32) << (tre & 0xff));
            tpos = tpos
                .checked_mul(3)
                .and_then(|value| value.checked_shl(8))
                .ok_or("nspack_table_index_overflow")?;
            if (damian.cast_signed()) >= 4 {
                if (damian.cast_signed()) >= 0x0a {
                    damian = damian.wrapping_sub(6);
                } else {
                    damian = damian.wrapping_sub(3);
                }
            } else {
                damian = 0;
            }
            if previous_bit != 0 {
                if backbytes as usize > unpacked_so_far {
                    return Err("nspack_backref_before_start");
                }
                let previous = dst[unpacked_so_far - backbytes as usize];
                let adjusted_ssize = (ssize & 0xffff_ff00) | u32::from(previous);
                bielle = get_100_bits_from_tablesize(
                    table,
                    table_offset(tpos as usize, 0x736)?,
                    &mut read,
                    adjusted_ssize,
                )?;
                previous_bit = 0;
            } else {
                bielle =
                    get_100_bits_from_table(table, table_offset(tpos as usize, 0x736)?, &mut read)?;
            }
            *dst.get_mut(unpacked_so_far)
                .ok_or("nspack_output_out_of_bounds")? =
                u8::try_from(bielle).map_err(|_| "nspack_literal_out_of_bounds")?;
            unpacked_so_far += 1;
            if unpacked_so_far >= dst.len() {
                return Ok(());
            }
            continue;
        }

        bielle = 1;
        previous_bit = 1;
        let mut backsize;
        if getbit_from_table(table, table_offset(damian as usize, 0xc0)?, &mut read)? {
            if getbit_from_table(table, table_offset(damian as usize, 0xcc)?, &mut read)? {
                if getbit_from_table(table, table_offset(damian as usize, 0xd8)?, &mut read)? {
                    if getbit_from_table(table, table_offset(damian as usize, 0xe4)?, &mut read)? {
                        tpos = old_old_oldbackbytes;
                        old_old_oldbackbytes = old_oldbackbytes;
                    } else {
                        tpos = old_oldbackbytes;
                    }
                    old_oldbackbytes = oldbackbytes;
                } else {
                    tpos = oldbackbytes;
                }
                oldbackbytes = backbytes;
                backbytes = tpos;
                backsize = get_n_bits_from_tablesize(table, 0x534, &mut read, backsize_seed)?;
                damian = u32::from(damian.cast_signed() >= 7).wrapping_sub(1) & 0xffff_fffd;
                damian += 0x0b;
            } else {
                tpos = damian + 0x0f;
                tpos = (tpos << 4) + backsize_seed;
                if getbit_from_table(table, tpos as usize, &mut read)? {
                    backsize = get_n_bits_from_tablesize(table, 0x534, &mut read, backsize_seed)?;
                    damian = u32::from(damian.cast_signed() >= 7).wrapping_sub(1) & 0xffff_fffd;
                    damian += 0x0b;
                } else {
                    if unpacked_so_far == 0 {
                        return Err("nspack_empty_backref");
                    }
                    damian = 2 * u32::from(damian.cast_signed() >= 7) + 9;
                    if backbytes as usize > unpacked_so_far {
                        return Err("nspack_backref_before_start");
                    }
                    bielle = u32::from(dst[unpacked_so_far - backbytes as usize]);
                    dst[unpacked_so_far] =
                        u8::try_from(bielle).map_err(|_| "nspack_literal_out_of_bounds")?;
                    unpacked_so_far += 1;
                    if unpacked_so_far >= dst.len() {
                        return Ok(());
                    }
                    continue;
                }
            }
        } else {
            old_oldbackbytes = oldbackbytes;
            oldbackbytes = backbytes;
            damian = u32::from(damian.cast_signed() >= 7).wrapping_sub(1) & 0xffff_fffd;
            damian += 0x0a;
            backsize = get_n_bits_from_tablesize(table, 0x332, &mut read, backsize_seed)?;
            tpos = if (backsize.cast_signed()) >= 4 {
                3
            } else {
                backsize
            };
            tpos = get_n_bits_from_table(
                table,
                table_offset(0x1b0, (tpos << 6) as usize)?,
                6,
                &mut read,
            )?;
            let temp = if (tpos.cast_signed()) >= 4 {
                let mut s = tpos;
                s >>= 1;
                s = s.wrapping_sub(1);
                let mut temp = (tpos & bielle) | 2;
                temp <<= s & 0xff;
                if (tpos.cast_signed()) < 0x0e {
                    temp += get_bb(
                        table,
                        table_offset((temp - tpos) as usize, 0x2af)?,
                        s,
                        &mut read,
                    )?;
                } else {
                    s = s.wrapping_sub(4);
                    tpos = get_bitmap(&mut read, s);
                    tpos <<= 4;
                    temp += tpos;
                    temp += get_bb(table, 0x322, 4, &mut read)?;
                }
                temp
            } else {
                tpos
            };
            backbytes = temp + 1;
        }

        if backbytes == 0 {
            return Ok(());
        }
        if backbytes as usize > unpacked_so_far {
            return Err("nspack_backref_before_start");
        }
        backsize = backsize.checked_add(2).ok_or("nspack_backsize_overflow")?;
        let backsize_usize = usize::try_from(backsize).map_err(|_| "nspack_backsize_overflow")?;
        let backbytes_usize = usize::try_from(backbytes).map_err(|_| "nspack_backref_overflow")?;
        let end = unpacked_so_far
            .checked_add(backsize_usize)
            .ok_or("nspack_output_offset_overflow")?;
        if end > dst.len() {
            return Err("nspack_output_out_of_bounds");
        }
        for _ in 0..backsize_usize {
            let byte = dst[unpacked_so_far - backbytes_usize];
            dst[unpacked_so_far] = byte;
            unpacked_so_far += 1;
            if unpacked_so_far >= dst.len() {
                return Ok(());
            }
        }
        bielle = u32::from(dst[unpacked_so_far - 1]);
    }
}

struct UnspReader<'a> {
    src: &'a [u8],
    src_curr: usize,
    src_end: usize,
    oldval: u32,
    bitmap: u32,
    error: bool,
}

impl<'a> UnspReader<'a> {
    fn new(src: &'a [u8], src_end: usize) -> Self {
        Self {
            src,
            src_curr: 0,
            src_end: src_end.min(src.len()),
            oldval: 0,
            bitmap: 0xffff_ffff,
            error: false,
        }
    }

    fn get_byte(&mut self) -> u32 {
        if self.src_curr >= self.src_end {
            self.error = true;
            return 0xff;
        }
        let ret = self.src[self.src_curr];
        self.src_curr += 1;
        u32::from(ret)
    }

    fn check(&self) -> Result<(), &'static str> {
        if self.error {
            Err("nspack_input_out_of_bounds")
        } else {
            Ok(())
        }
    }
}

fn getbit_from_table(
    table: &mut [u16],
    index: usize,
    read: &mut UnspReader<'_>,
) -> Result<bool, &'static str> {
    let current = u32::from(*table.get(index).ok_or("nspack_table_index_out_of_bounds")?);
    let nval = current.wrapping_mul(read.bitmap >> 0x0b);
    let bit = if read.oldval < nval {
        read.bitmap = nval;
        let sval = ((0x800_i32 - current.cast_signed()) >> 5).cast_unsigned() + current;
        *table
            .get_mut(index)
            .ok_or("nspack_table_index_out_of_bounds")? =
            u16::try_from(sval).map_err(|_| "nspack_table_value_overflow")?;
        false
    } else {
        read.bitmap = read.bitmap.wrapping_sub(nval);
        read.oldval = read.oldval.wrapping_sub(nval);
        *table
            .get_mut(index)
            .ok_or("nspack_table_index_out_of_bounds")? =
            u16::try_from(current - (current >> 5)).map_err(|_| "nspack_table_value_overflow")?;
        true
    };
    if read.bitmap < 0x0100_0000 {
        read.oldval = (read.oldval << 8) | read.get_byte();
        read.bitmap <<= 8;
    }
    read.check()?;
    Ok(bit)
}

fn get_100_bits_from_tablesize(
    table: &mut [u16],
    base: usize,
    read: &mut UnspReader<'_>,
    mut ssize: u32,
) -> Result<u32, &'static str> {
    let mut count = 1u32;
    while count < 0x100 {
        let mut lpos = ssize & 0xff;
        ssize = (ssize & 0xffff_ff00) | ((lpos << 1) & 0xff);
        lpos >>= 7;
        let bit = getbit_from_table(
            table,
            table_offset(base, (((lpos + 1) << 8) + count) as usize)?,
            read,
        )?;
        let tpos = u32::from(bit);
        count = (count * 2) | tpos;
        if lpos != tpos {
            while count < 0x100 {
                count = (count * 2)
                    | u32::from(getbit_from_table(
                        table,
                        table_offset(base, count as usize)?,
                        read,
                    )?);
            }
        }
    }
    Ok(count & 0xff)
}

fn get_100_bits_from_table(
    table: &mut [u16],
    base: usize,
    read: &mut UnspReader<'_>,
) -> Result<u32, &'static str> {
    let mut count = 1u32;
    while count < 0x100 {
        count = (count * 2)
            | u32::from(getbit_from_table(
                table,
                table_offset(base, count as usize)?,
                read,
            )?);
    }
    Ok(count & 0xff)
}

fn get_n_bits_from_table(
    table: &mut [u16],
    base: usize,
    bits: u32,
    read: &mut UnspReader<'_>,
) -> Result<u32, &'static str> {
    let mut count = 1u32;
    for _ in 0..bits {
        count = count
            .checked_mul(2)
            .and_then(|value| {
                value.checked_add(u32::from(
                    getbit_from_table(table, table_offset(base, count as usize).ok()?, read)
                        .ok()?,
                ))
            })
            .ok_or("nspack_bit_count_overflow")?;
    }
    Ok(count - (1 << (bits & 0xff)))
}

fn get_n_bits_from_tablesize(
    table: &mut [u16],
    base: usize,
    read: &mut UnspReader<'_>,
    backsize: u32,
) -> Result<u32, &'static str> {
    if !getbit_from_table(table, base, read)? {
        return get_n_bits_from_table(
            table,
            table_offset(base, ((backsize << 3) + 2) as usize)?,
            3,
            read,
        );
    }
    if !getbit_from_table(table, table_offset(base, 1)?, read)? {
        return Ok(8 + get_n_bits_from_table(
            table,
            table_offset(base, ((backsize << 3) + 0x82) as usize)?,
            3,
            read,
        )?);
    }
    Ok(0x10 + get_n_bits_from_table(table, table_offset(base, 0x102)?, 8, read)?)
}

fn get_bb(
    table: &mut [u16],
    base: usize,
    back: u32,
    read: &mut UnspReader<'_>,
) -> Result<u32, &'static str> {
    if (back.cast_signed()) <= 0 {
        return Ok(0);
    }
    let mut pos = 1u32;
    let mut bb = 0u32;
    for i in 0..back {
        let bit = u32::from(getbit_from_table(
            table,
            table_offset(base, pos as usize)?,
            read,
        )?);
        pos = (pos * 2) + bit;
        bb |= bit << i;
    }
    Ok(bb)
}

fn table_offset(base: usize, offset: usize) -> Result<usize, &'static str> {
    base.checked_add(offset)
        .ok_or("nspack_table_index_overflow")
}

fn get_bitmap(read: &mut UnspReader<'_>, mut bits: u32) -> u32 {
    let mut retv = 0u32;
    if (bits.cast_signed()) <= 0 {
        return 0;
    }
    while bits != 0 {
        read.bitmap >>= 1;
        retv <<= 1;
        if read.oldval >= read.bitmap {
            read.oldval -= read.bitmap;
            retv |= 1;
        }
        if read.bitmap < 0x0100_0000 {
            read.bitmap <<= 8;
            read.oldval = (read.oldval << 8) | read.get_byte();
        }
        bits -= 1;
    }
    retv
}

fn checked_add_signed(value: usize, delta: i64) -> Option<usize> {
    if delta >= 0 {
        value.checked_add(usize::try_from(delta).ok()?)
    } else {
        value.checked_sub(usize::try_from(delta.unsigned_abs()).ok()?)
    }
}

fn rva_to_offset(rva: u32, sections: &[PeSection], file_len: usize) -> Option<usize> {
    for section in sections {
        let section_span = section.virtual_size.max(section.raw_size);
        let start = section.virtual_address;
        let Some(end) = start.checked_add(section_span) else {
            continue;
        };
        if section_span != 0 && rva >= start && rva < end {
            let delta = rva.checked_sub(start)?;
            if delta >= section.raw_size {
                return None;
            }
            let offset = section.raw_offset.checked_add(delta)?;
            let offset = usize::try_from(offset).ok()?;
            return (offset < file_len).then_some(offset);
        }
    }
    usize::try_from(rva)
        .ok()
        .filter(|offset| *offset <= file_len)
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    read_u32_le(bytes, offset).map(u32::cast_signed)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_nspack_image() {
        let analysis = PeAnalysis::default();
        assert_eq!(
            unpack_pe(&[], &analysis).unwrap_err(),
            "nspack_section_count_too_low"
        );
    }

    #[test]
    fn rva_mapping_rejects_virtual_section_tail_without_raw_bytes() {
        let sections = [PeSection {
            index: 1,
            name: ".packed".to_owned(),
            virtual_size: 0x400,
            virtual_address: 0x1000,
            raw_size: 0x200,
            raw_offset: 0x200,
            characteristics: 0,
            start: 0x200,
            end: 0x400,
            hash_size: None,
            md5: None,
            sha1: None,
            sha256: None,
        }];

        assert_eq!(rva_to_offset(0x11ff, &sections, 0x500), Some(0x3ff));
        assert_eq!(rva_to_offset(0x1200, &sections, 0x500), None);
        assert_eq!(rva_to_offset(0x1300, &sections, 0x500), None);
    }
}
