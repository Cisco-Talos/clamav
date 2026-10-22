// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Scanner-independent executable format parsers.
//!
//! This module owns ClamAV's crate-local executable parsing model. The scanner
//! file-type handlers adapt the parser facts into metadata JSON, child scans,
//! and legacy matcher hooks; parser code deliberately does not know about
//! scanner callbacks or scan outcomes.
//!
//! PE/COFF, ELF, and Mach-O use crate-local parsers. The PE parser follows the
//! Microsoft PE/COFF structure and uses ClamAV's historical C PE, rebuild, and
//! packer code as compatibility references. ELF and Mach-O follow ClamAV's
//! historical `elf.c`, `elf.h`, `upx_elf.c`, `macho.c`, and `macho.h`, plus the
//! platform format specifications and YARA/YARA-X module parity goals. Generic
//! decoded PE32 sections are rebuilt through the PE-specific `pe::rebuild`
//! module, which mirrors `cli_rebuildpe()` / `cli_rebuildpe_align()` behavior
//! for fake headers, `.clamNN` sections, ghost sections, alignment, and bounded
//! section copies. Packer-family decoders live under `unpacker` so UPX and
//! similar families can span PE, ELF, and future Mach-O paths without sharing
//! format-specific layout assumptions.
//!
//! ```text
//! PE/COFF high-level layout
//!
//!   +-------------------------+  file offset 0
//!   | DOS header ("MZ")       |
//!   | e_lfanew --------------+----+
//!   +-------------------------+    |
//!   | DOS stub / overlay-ish  |    |
//!   +-------------------------+    |
//!   | PE signature ("PE\0\0") | <--+
//!   | COFF file header        |
//!   | Optional header         | ---- data directories (RVA + size)
//!   | Section table           | ---- RVA/file-offset translation
//!   +-------------------------+
//!   | section raw bytes       |
//!   +-------------------------+
//!   | overlay / signatures    |
//!   +-------------------------+
//!
//! Unpacked children are derived bytes produced by an unpacker. Resource
//! children are existing bounded byte ranges inside the PE. Overlay children
//! are bounded trailing SFX/overlay byte ranges found at the parser-computed PE
//! overlay offset. The scanner file-type handlers map each child kind onto
//! ClamAV's nested-buffer or nested-fmap scan path; broad arbitrary-offset
//! embedded carving remains future work.
//! ```

#[allow(dead_code)]
pub(crate) mod coff;
pub(crate) mod common;
pub(crate) mod elf;
pub(crate) mod macho;
pub(crate) mod pe;
pub(crate) mod unpacker;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnpackedArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) source_offset: u64,
    pub(crate) source_size: u64,
}
