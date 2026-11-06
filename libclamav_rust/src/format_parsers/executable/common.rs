// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Shared helpers for executable parsers.
//!
//! These helpers keep low-level bounds checks and endian reads consistent
//! across PE, ELF, and Mach-O without introducing a third-party production
//! object parser. They intentionally expose only parser-local primitives.
//!
//! ## References
//!
//! Format-specific references are documented in the PE, ELF, and Mach-O parser
//! modules that consume these helpers.
//!
//! Structure aid: not applicable. This module provides shared endian, bounds,
//! string, and range helpers rather than parsing one file layout.

#![forbid(unsafe_code)]

use std::{borrow::Cow, ops::Range};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Endian {
    Little,
    Big,
}

impl Endian {
    pub(crate) fn read_u16(self, bytes: &[u8], offset: usize) -> Option<u16> {
        let raw = read_array::<2>(bytes, offset)?;
        Some(match self {
            Self::Little => u16::from_le_bytes(raw),
            Self::Big => u16::from_be_bytes(raw),
        })
    }

    pub(crate) fn read_i32(self, bytes: &[u8], offset: usize) -> Option<i32> {
        let raw = read_array::<4>(bytes, offset)?;
        Some(match self {
            Self::Little => i32::from_le_bytes(raw),
            Self::Big => i32::from_be_bytes(raw),
        })
    }

    pub(crate) fn read_u32(self, bytes: &[u8], offset: usize) -> Option<u32> {
        let raw = read_array::<4>(bytes, offset)?;
        Some(match self {
            Self::Little => u32::from_le_bytes(raw),
            Self::Big => u32::from_be_bytes(raw),
        })
    }

    pub(crate) fn read_u64(self, bytes: &[u8], offset: usize) -> Option<u64> {
        let raw = read_array::<8>(bytes, offset)?;
        Some(match self {
            Self::Little => u64::from_le_bytes(raw),
            Self::Big => u64::from_be_bytes(raw),
        })
    }

    pub(crate) fn read_i64(self, bytes: &[u8], offset: usize) -> Option<i64> {
        let raw = read_array::<8>(bytes, offset)?;
        Some(match self {
            Self::Little => i64::from_le_bytes(raw),
            Self::Big => i64::from_be_bytes(raw),
        })
    }
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

pub(crate) fn checked_range(offset: u64, size: u64, len: usize) -> Option<Range<usize>> {
    let start = usize::try_from(offset).ok()?;
    let size = usize::try_from(size).ok()?;
    let end = start.checked_add(size)?;
    (end <= len).then_some(start..end)
}

pub(crate) fn bounded_range(offset: u64, size: u64, len: usize) -> Option<Range<usize>> {
    let start = usize::try_from(offset).ok()?;
    if start >= len {
        return None;
    }
    let size = usize::try_from(size).ok()?;
    let end = start.saturating_add(size).min(len);
    (end > start).then_some(start..end)
}

pub(crate) fn read_c_string(bytes: &[u8], offset: usize, max_len: usize) -> Option<String> {
    if offset >= bytes.len() {
        return None;
    }
    let limit = offset.saturating_add(max_len).min(bytes.len());
    let end = offset.checked_add(nul_terminated_len(&bytes[offset..limit]))?;
    if end == offset {
        return Some(String::new());
    }
    Some(String::from_utf8_lossy(&bytes[offset..end]).into_owned())
}

pub(crate) fn read_string_table_entry(table: &[u8], offset: u32, max_len: usize) -> Option<String> {
    let offset = usize::try_from(offset).ok()?;
    read_c_string(table, offset, max_len)
}

pub(crate) fn fixed_name(bytes: &[u8]) -> String {
    let end = nul_terminated_len(bytes);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn nul_terminated_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn ascii_lowercase_cow(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}
