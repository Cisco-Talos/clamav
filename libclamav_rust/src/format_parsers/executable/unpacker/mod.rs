// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

//! Packer-family unpackers for executable formats.
//!
//! Individual modules are organized by packer family rather than executable
//! format so UPX and similar packers can grow ELF or Mach-O paths later. The
//! current dispatcher wires PE packer paths plus ELF UPX and converts packer
//! output into format-specific unpacked-child metadata.
//!
//! ## References
//!
//! Individual unpacker modules name the `ClamAV` packer source files they port,
//! such as `upx.c`, `aspack.c`, `fsg.c`, `petite.c`, `mew.c`, `upack.c`,
//! `wwunpack.c`, and `upx_elf.c`. PE rebuild output is handled by
//! `pe::rebuild`, which follows `ClamAV` `rebuildpe.c`.
//!
//! ## Container Graph
//!
//! ```text
//! executable parser analysis
//!   +-- detected packer facts
//!   +-- packer-family decoder
//!   +-- UnpackedArtifact bytes
//!   +-- PE rebuild, when needed for PE packers
//!   +-- direct ELF unpacked bytes for ELF UPX
//!   +-- file-type handler scans a generated unpacked child
//! ```
//!
//! ## Bounds And Recovery
//!
//! Dispatch samples only bounded entrypoint bytes. Individual decoders own
//! their packer-specific caps and return stable unsupported or malformed
//! reasons instead of panicking.

use super::{
    UnpackedArtifact,
    elf::{ElfAnalysis, ElfSegment, ElfUnpackedChild},
    pe::{PeAnalysis, PeSection, PeUnpackedChild},
};

mod aspack;
mod fsg;
mod mew;
mod nspack;
mod pespin;
mod petite;
mod upack;
mod upx;
mod upx_elf;
mod wwpack;
mod yc;

type PeUnpackFn = fn(&[u8], &PeAnalysis) -> Result<UnpackedArtifact, &'static str>;

const MAX_PE_ENTRYPOINT_SAMPLE: usize = 4096;

pub(super) fn pe_entrypoint_sample<'a>(bytes: &'a [u8], analysis: &PeAnalysis) -> &'a [u8] {
    let Some(offset) = analysis
        .entrypoint_offset
        .and_then(|offset| usize::try_from(offset).ok())
    else {
        return &[];
    };
    bytes
        .get(offset..)
        .map(|tail| &tail[..tail.len().min(MAX_PE_ENTRYPOINT_SAMPLE)])
        .unwrap_or_default()
}

pub(super) fn unpack_pe(bytes: &[u8], analysis: &PeAnalysis) -> Vec<PeUnpackedChild> {
    let (source_offset, source_size) = pe_source_span(&analysis.sections);
    let mut children: Vec<_> = analysis
        .packers
        .iter()
        .enumerate()
        .map(|(index, packer)| {
            let index = index + 1;
            if let Some(unpack) = pe_unpacker(packer.name) {
                return unpack(bytes, analysis).map_or_else(
                    |reason| {
                        skipped_pe_unpacked_child(
                            index,
                            packer.name,
                            source_offset,
                            source_size,
                            reason,
                        )
                    },
                    |unpacked| unpacked_child_from_artifact(index, packer.name, unpacked),
                );
            }
            skipped_pe_unpacked_child(
                index,
                packer.name,
                source_offset,
                source_size,
                "unsupported_packer_family",
            )
        })
        .collect();
    if analysis.upx_layout_candidate
        && !analysis.packers.iter().any(|packer| packer.name == "upx")
        && let Ok(unpacked) = upx::unpack_pe(bytes, analysis)
    {
        children.push(unpacked_child_from_artifact(
            children.len() + 1,
            "upx",
            unpacked,
        ));
    }
    children
}

type ElfUnpackFn = fn(&[u8], &ElfAnalysis) -> Result<UnpackedArtifact, &'static str>;

pub(super) fn unpack_elf(bytes: &[u8], analysis: &ElfAnalysis) -> Vec<ElfUnpackedChild> {
    if analysis.packers.is_empty() {
        return Vec::new();
    }
    let (source_offset, source_size) = elf_source_span(&analysis.segments);
    analysis
        .packers
        .iter()
        .enumerate()
        .map(|(index, packer)| {
            let index = index + 1;
            if let Some(unpack) = elf_unpacker(packer.name) {
                return unpack(bytes, analysis).map_or_else(
                    |reason| {
                        skipped_elf_unpacked_child(
                            index,
                            packer.name,
                            source_offset,
                            source_size,
                            reason,
                        )
                    },
                    |artifact| elf_unpacked_child_from_artifact(index, packer.name, artifact),
                );
            }
            skipped_elf_unpacked_child(
                index,
                packer.name,
                source_offset,
                source_size,
                "unsupported_packer_family",
            )
        })
        .collect()
}

fn pe_unpacker(name: &str) -> Option<PeUnpackFn> {
    match name {
        "upx" => Some(upx::unpack_pe),
        "fsg" => Some(fsg::unpack_pe),
        "wwpack" => Some(wwpack::unpack_pe),
        "aspack" => Some(aspack::unpack_pe),
        "mew" => Some(mew::unpack_pe),
        "yc" => Some(yc::unpack_pe),
        "nspack" => Some(nspack::unpack_pe),
        "petite" => Some(petite::unpack_pe),
        "pespin" => Some(pespin::unpack_pe),
        "upack" => Some(upack::unpack_pe),
        _ => None,
    }
}

fn elf_unpacker(name: &str) -> Option<ElfUnpackFn> {
    match name {
        "upx" => Some(upx_elf::unpack_elf),
        _ => None,
    }
}

fn pe_source_span(sections: &[PeSection]) -> (Option<u64>, Option<u64>) {
    source_span(
        sections
            .iter()
            .filter(|section| section.raw_size != 0)
            .map(|section| (section.start, section.end)),
    )
}

fn elf_source_span(segments: &[ElfSegment]) -> (Option<u64>, Option<u64>) {
    source_span(
        segments
            .iter()
            .filter(|segment| segment.file_size != 0)
            .filter_map(|segment| {
                Some((
                    segment.offset,
                    segment.offset.checked_add(segment.file_size)?,
                ))
            }),
    )
}

fn source_span(ranges: impl Iterator<Item = (u64, u64)>) -> (Option<u64>, Option<u64>) {
    let mut source_offset = None::<u64>;
    let mut source_end = None::<u64>;
    for (start, end) in ranges {
        source_offset = Some(source_offset.map_or(start, |offset| offset.min(start)));
        source_end = Some(source_end.map_or(end, |current| current.max(end)));
    }
    let source_size = source_offset
        .zip(source_end)
        .and_then(|(start, end)| end.checked_sub(start));
    (source_offset, source_size)
}

fn elf_unpacked_child_from_artifact(
    index: usize,
    packer: &'static str,
    artifact: UnpackedArtifact,
) -> ElfUnpackedChild {
    let unpacked_size = artifact.bytes.len() as u64;
    ElfUnpackedChild {
        index,
        packer,
        status: "unpacked",
        source_offset: Some(artifact.source_offset),
        source_size: Some(artifact.source_size),
        unpacked_size: Some(unpacked_size),
        mime: "application/x-elf",
        skip_reason: None,
        bytes: Some(artifact.bytes),
    }
}

fn unpacked_child_from_artifact(
    index: usize,
    packer: &'static str,
    artifact: UnpackedArtifact,
) -> PeUnpackedChild {
    let unpacked_size = artifact.bytes.len() as u64;
    PeUnpackedChild {
        index,
        packer,
        status: "unpacked",
        source_offset: Some(artifact.source_offset),
        source_size: Some(artifact.source_size),
        unpacked_size: Some(unpacked_size),
        mime: "application/x-dosexec",
        skip_reason: None,
        bytes: Some(artifact.bytes),
    }
}

fn skipped_pe_unpacked_child(
    index: usize,
    packer: &'static str,
    source_offset: Option<u64>,
    source_size: Option<u64>,
    reason: &'static str,
) -> PeUnpackedChild {
    PeUnpackedChild {
        index,
        packer,
        status: "not_unpacked",
        source_offset,
        source_size,
        unpacked_size: None,
        mime: "application/x-dosexec",
        skip_reason: Some(reason),
        bytes: None,
    }
}

fn skipped_elf_unpacked_child(
    index: usize,
    packer: &'static str,
    source_offset: Option<u64>,
    source_size: Option<u64>,
    reason: &'static str,
) -> ElfUnpackedChild {
    ElfUnpackedChild {
        index,
        packer,
        status: "not_unpacked",
        source_offset,
        source_size,
        unpacked_size: None,
        mime: "application/x-elf",
        skip_reason: Some(reason),
        bytes: None,
    }
}
