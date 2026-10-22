//! Security regression tests for malicious-archive handling in the decode paths.

#![cfg(all(feature = "compress", feature = "util"))]

use std::io::Cursor;

use sevenz_rust2::{ArchiveEntry, ArchiveReader, ArchiveWriter, Password, decompress};
use tempfile::tempdir;

/// Builds a valid single-file archive whose only entry has the given (attacker-chosen) name.
fn archive_with_entry_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        let entry = ArchiveEntry::new_file(name);
        writer
            .push_archive_entry(entry, Some(b"pwned" as &[u8]))
            .unwrap();
        writer.finish().unwrap();
    }
    bytes
}

/// A Windows-style backslash-traversal entry name must be rejected on every platform when
/// extracting through the public `decompress` API (the sibling tests in
/// `decompression_tests.rs` cover the `..` and absolute `/` vectors). This exercises the
/// backslash-normalization branch of the internal path guard end-to-end.
#[test]
fn decompress_rejects_backslash_traversal() {
    let temp = tempdir().unwrap();
    let dest = temp.path().join("out");

    // `..\..\sevenz_pwned_backslash` escapes up out of `dest` on a Windows-authored
    // archive; the target sits inside the sandbox so a stray write is detectable.
    let escaped = temp.path().join("sevenz_pwned_backslash");
    assert!(!escaped.exists());

    let bytes = archive_with_entry_name("..\\..\\sevenz_pwned_backslash");
    let result = decompress(Cursor::new(bytes.as_slice()), &dest);

    assert!(result.is_err(), "backslash traversal must be rejected");
    assert!(
        !escaped.exists(),
        "file must not be written outside the destination"
    );
}

const SEVEN_Z_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// CRC-32/ISO-HDLC over the start/next headers, reusing the crate's own `crc32fast`
/// dependency (available to integration tests) so the crafted archives pass verification.
fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

// 7z structure IDs used by the crafted headers.
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUB_STREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_NAME: u8 = 0x11;
const K_DUMMY: u8 = 0x19;

/// Encodes a value using the 7z NUMBER varint format, matching the reader's decoder.
fn write_number(out: &mut Vec<u8>, value: u64) {
    let mut first: u8 = 0;
    let mut mask: u8 = 0x80;
    let mut low = Vec::new();
    let mut i = 0u32;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        low.push((value >> (8 * i)) as u8);
        i += 1;
    }
    out.push(first);
    out.extend_from_slice(&low);
}

/// Reference decoder mirroring `reader::read_variable_u64`, used only to prove the
/// `write_number` encoder above round-trips (so the crafted headers are well-formed).
fn read_number(bytes: &[u8]) -> u64 {
    let first = bytes[0] as u64;
    let mut mask = 0x80u64;
    let mut value = 0u64;
    let mut rest = bytes[1..].iter();
    for i in 0..8 {
        if (first & mask) == 0 {
            return value | ((first & (mask - 1)) << (8 * i));
        }
        value |= (*rest.next().unwrap() as u64) << (8 * i);
        mask >>= 1;
    }
    value
}

#[test]
fn number_codec_roundtrips() {
    for v in [
        0u64,
        1,
        127,
        128,
        0x1234,
        0xFFFF,
        1 << 32,
        1 << 62,
        u64::MAX - 1,
    ] {
        let mut buf = Vec::new();
        write_number(&mut buf, v);
        assert_eq!(read_number(&buf), v, "roundtrip failed for {v:#x}");
    }
}

/// Assembles a raw 7z file: signature header + (empty pack area) + `next_header` placed
/// immediately after the signature header, with `declared_next_header_size` written into
/// the start header (normally the real length, but overridable to fake an oversized one).
fn raw_7z(next_header: &[u8], declared_next_header_size: u64) -> Vec<u8> {
    let mut start = [0u8; 20];
    start[0..8].copy_from_slice(&0u64.to_le_bytes()); // next_header_offset
    start[8..16].copy_from_slice(&declared_next_header_size.to_le_bytes());
    start[16..20].copy_from_slice(&crc32(next_header).to_le_bytes());
    let start_crc = crc32(&start);

    let mut out = Vec::new();
    out.extend_from_slice(&SEVEN_Z_SIGNATURE);
    out.extend_from_slice(&[0x00, 0x04]); // format version major.minor
    out.extend_from_slice(&start_crc.to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(next_header);
    out
}

/// Convenience: build a file whose start header truthfully describes `next_header`.
fn raw_7z_exact(next_header: &[u8]) -> Vec<u8> {
    raw_7z(next_header, next_header.len() as u64)
}

fn open_err(bytes: &[u8]) -> Result<(), String> {
    match ArchiveReader::new(Cursor::new(bytes.to_vec()), Password::empty()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// A tiny archive declaring a multi-exabyte next-header size must be rejected before
/// the `vec![0; next_header_size]` allocation.
#[test]
fn oversized_next_header_size_is_rejected() {
    let bytes = raw_7z(&[], 1u64 << 63);
    assert!(
        open_err(&bytes).is_err(),
        "an oversized next-header size must be rejected, not allocated"
    );
}

/// A start header whose `next_header_offset` is near `u64::MAX` must be rejected, not overflow
/// the `SIGNATURE_HEADER_SIZE + next_header_offset` addition (a panic under the overflow checks
/// enabled in debug/test builds; a wrap to a bogus seek in release).
#[test]
fn overflowing_next_header_offset_is_rejected() {
    let next_header: &[u8] = &[K_HEADER, K_END];
    let mut start = [0u8; 20];
    start[0..8].copy_from_slice(&u64::MAX.to_le_bytes()); // next_header_offset
    start[8..16].copy_from_slice(&(next_header.len() as u64).to_le_bytes());
    start[16..20].copy_from_slice(&crc32(next_header).to_le_bytes());
    let start_crc = crc32(&start);

    let mut out = Vec::new();
    out.extend_from_slice(&SEVEN_Z_SIGNATURE);
    out.extend_from_slice(&[0x00, 0x04]);
    out.extend_from_slice(&start_crc.to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(next_header);

    assert!(
        open_err(&out).is_err(),
        "an overflowing next_header_offset must be rejected, not panic"
    );
}

/// A tiny header declaring an astronomically large `num_files` must be rejected before
/// the `vec![Default::default(); num_files]` allocation.
#[test]
fn oversized_num_files_is_rejected() {
    let mut nh = vec![K_HEADER, K_FILES_INFO];
    write_number(&mut nh, 1u64 << 62); // num_files
    assert!(
        open_err(&raw_7z_exact(&nh)).is_err(),
        "an oversized num_files must be rejected"
    );
}

/// A coder declaring an astronomically large properties size must be rejected before the
/// `vec![0u8; properties_size]` allocation.
#[test]
fn oversized_properties_size_is_rejected() {
    let mut nh = vec![
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks = 1
        0x00, // external = 0
        0x01, // num_coders = 1
        0x21, // coder flags: id_size=1, has_attributes
        0x00, // coder id byte
    ];
    write_number(&mut nh, 1u64 << 62); // properties_size
    assert!(
        open_err(&raw_7z_exact(&nh)).is_err(),
        "an oversized properties size must be rejected"
    );
}

/// `num_files == 1` but the names blob encodes two (empty) names. The reader must not
/// index `files[1]` out of bounds.
#[test]
fn names_blob_longer_than_num_files_is_rejected() {
    let mut nh = vec![K_HEADER, K_FILES_INFO];
    write_number(&mut nh, 1); // num_files = 1
    nh.push(K_NAME);
    write_number(&mut nh, 5); // property size = external(1) + 4 name bytes
    nh.push(0x00); // external = 0
    nh.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // two empty UTF-16 names
    nh.push(K_END);
    assert!(
        open_err(&raw_7z_exact(&nh)).is_err(),
        "more names than files must be rejected, not panic"
    );
}

/// `num_files` streamed files but only one sub-stream. Indexing the per-sub-stream CRC /
/// size arrays by the file counter must be bounds-checked, not panic.
#[test]
fn more_streamed_files_than_substreams_is_rejected() {
    let nh: &[u8] = &[
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        0x06, // K_PACK_INFO
        0x00, // pack_pos
        0x01, // num_pack_streams
        0x09, // K_SIZE
        0x01, // pack_sizes[0] = 1
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
        0x01, // num_coders
        0x00, // coder flags: id_size=0, simple, no attributes
        0x0C, // K_CODERS_UNPACK_SIZE
        0x05, // unpack_sizes[0] = 5
        K_END,
        0x08,  // K_SUB_STREAMS_INFO
        K_END, // (empty -> total_unpack_streams stays 1)
        K_END, // streams_info end
        K_FILES_INFO,
        0x02,  // num_files = 2 (both streamed, no kEmptyStream)
        K_END, // files_info property list end
        K_END, // header end
    ];
    assert!(
        open_err(&raw_7z_exact(nh)).is_err(),
        "more streamed files than sub-streams must be rejected, not panic"
    );
}

/// The reverse of `more_streamed_files_than_substreams_is_rejected`: a block declaring more
/// sub-streams than the archive has files must not make `BlockDecoder` index `files` out of
/// bounds. Here `num_files = 1` but the single block sets `num_unpack_sub_streams = 2`, so the
/// decode-time iteration over `files[0..2]` panics at `files[1]` pre-fix.
#[test]
fn more_substreams_than_files_is_rejected() {
    let nh: &[u8] = &[
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        K_PACK_INFO,
        0x00, // pack_pos
        0x01, // num_pack_streams
        K_SIZE,
        0x05, // pack_sizes[0] = 5
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
        0x01, // num_coders
        0x01, // coder flags: id_size=1, simple, no attributes
        0x00, // coder id = COPY
        K_CODERS_UNPACK_SIZE,
        0x05, // unpack_sizes[0] = 5 (block total)
        K_END,
        K_SUB_STREAMS_INFO,
        K_NUM_UNPACK_STREAM,
        0x02, // block0 num_unpack_sub_streams = 2 (but only 1 file exists)
        K_SIZE,
        0x02,  // sub-stream 0 size = 2 (last one derived as 5 - 2 = 3)
        K_END, // sub_streams_info end
        K_END, // streams_info end
        K_FILES_INFO,
        0x01,  // num_files = 1
        K_END, // files_info props end
        K_END, // header end
    ];
    // COPY block with 5 bytes of packed data, so sub-stream 0 (size 2) decodes successfully.
    let bytes = raw_7z_with_packed(&[0xAA; 5], nh);
    assert!(
        decode_err(&bytes).is_err(),
        "more sub-streams than files must be rejected, not panic"
    );
}

/// A Delta filter with distance 256 encodes its distance as the property byte `0xFF`. Pre-fix
/// the decoder computed `0xFF_u8.wrapping_add(1) == 0`, decoding with a distance of 0 and
/// producing wrong output; the fix widens before the `+1` so the payload round-trips exactly.
/// The payload is longer than 256 bytes so the distance genuinely affects the transform.
#[test]
fn delta_distance_256_round_trips() {
    use sevenz_rust2::encoder_options::DeltaOptions;

    let original: Vec<u8> = (0..1024u32).map(|i| i.wrapping_mul(31) as u8).collect();

    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        writer.set_content_methods(vec![DeltaOptions::from_distance(256).into()]);
        writer
            .push_archive_entry(ArchiveEntry::new_file("data"), Some(original.as_slice()))
            .unwrap();
        writer.finish().unwrap();
    }

    let mut reader = ArchiveReader::new(Cursor::new(bytes.as_slice()), Password::empty()).unwrap();
    let decoded = reader.read_file("data").unwrap();
    assert_eq!(
        decoded, original,
        "Delta distance-256 payload must round-trip exactly (distance not wrapped to 0)"
    );
}

/// A block whose packed-stream span runs past `pack_sizes` must not slice
/// `pack_stream_offsets`/`pack_sizes` out of bounds in `build_decode_stack2`. The block has a
/// single 2-in/1-out coder (so `total_input > total_output` routes to the multi-stream path)
/// declaring 2 packed streams, while only 1 pack stream exists. The existing guard validates
/// only the block's *first* pack index, so pre-fix the `offsets[..2]` slice panics.
#[test]
fn block_pack_stream_span_beyond_pack_sizes_is_rejected() {
    let block: &[u8] = &[
        0x01, // num_coders = 1
        0x11, 0x00, 0x02, 0x01, // coder: id_size=1, complex; id=COPY; num_in=2, num_out=1
        // num_bind_pairs = total_out - 1 = 0 (none)
        0x00, 0x01, // packed_streams = [0, 1] (2 streams, but only 1 pack size exists)
    ];
    let mut nh = vec![
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        K_PACK_INFO,
        0x00, // pack_pos
        0x01, // num_pack_streams = 1
        K_SIZE,
        0x05, // pack_sizes[0] = 5
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
    ];
    nh.extend_from_slice(block);
    nh.push(K_CODERS_UNPACK_SIZE);
    nh.push(0x05); // unpack_sizes[0] = 5 (one output stream)
    nh.push(K_END); // unpack_info end
    nh.push(K_SUB_STREAMS_INFO);
    nh.push(K_END); // empty -> num_unpack_sub_streams defaults to 1
    nh.push(K_END); // streams_info end
    nh.push(K_FILES_INFO);
    nh.push(0x01); // num_files = 1
    nh.push(K_END); // files_info props end
    nh.push(K_END); // header end

    assert!(
        decode_err(&raw_7z_with_packed(&[0xAA; 5], &nh)).is_err(),
        "a pack-stream span beyond pack_sizes must be rejected, not panic"
    );
}

/// A files-info property carrying an unbounded skip size must not seek the header cursor
/// backwards and loop forever. `K_DUMMY` (or any unknown property id) followed by a size of
/// `2^64 - 10` casts to `-10` as `i64`, seeking the in-memory cursor back to the `K_DUMMY`
/// byte and re-reading the same bytes indefinitely pre-fix.
#[test]
fn files_info_property_with_unbounded_skip_is_rejected() {
    let mut nh = vec![K_HEADER, K_FILES_INFO];
    write_number(&mut nh, 1); // num_files = 1
    nh.push(K_DUMMY);
    write_number(&mut nh, u64::MAX - 9); // size as i64 == -10 -> seeks back to K_DUMMY
    // No K_END: pre-fix the reader never reaches it (infinite loop).
    assert!(
        open_err(&raw_7z_exact(&nh)).is_err(),
        "an unbounded files-info skip size must be rejected, not loop forever"
    );
}

/// A BCJ2 coder declaring a number of input streams other than four must be rejected rather
/// than handing a mismatched input list to the BCJ2 decoder (which indexes exactly four).
/// Here the lone BCJ2 coder declares 2 inputs, routing to the multi-stream decode path.
#[test]
fn bcj2_coder_with_wrong_input_count_is_rejected() {
    let block: &[u8] = &[
        0x01, // num_coders = 1
        0x14, 0x03, 0x03, 0x01, 0x1B, // coder: id_size=4, complex; id = BCJ2
        0x02, 0x01, // num_in = 2 (should be 4), num_out = 1
        // num_bind_pairs = 0
        0x00, 0x01, // packed_streams = [0, 1]
    ];
    let mut nh = vec![
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        K_PACK_INFO,
        0x00, // pack_pos
        0x02, // num_pack_streams = 2
        K_SIZE,
        0x01,
        0x01, // pack_sizes = [1, 1]
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
    ];
    nh.extend_from_slice(block);
    nh.push(K_CODERS_UNPACK_SIZE);
    nh.push(0x01); // unpack_sizes[0] = 1
    nh.push(K_END); // unpack_info end
    nh.push(K_SUB_STREAMS_INFO);
    nh.push(K_END); // empty
    nh.push(K_END); // streams_info end
    nh.push(K_FILES_INFO);
    nh.push(0x01); // num_files = 1
    nh.push(K_END); // files_info props end
    nh.push(K_END); // header end

    assert!(
        decode_err(&raw_7z_with_packed(&[0xAA, 0xBB], &nh)).is_err(),
        "a BCJ2 coder with the wrong input-stream count must be rejected, not panic"
    );
}

/// A block whose bind pairs form a cycle among single-in/single-out coders must not make
/// `OrderedCoderIter` yield coders forever (nesting decoders until memory is exhausted).
///
/// Layout: three coders. A(1in/1out), B(1in/1out), C(3in/1out, only present so
/// `num_packed_streams > 1` and `packed_streams` is read raw) with bind pairs
/// (out=0,in=1) and (out=1,in=0) wiring A<->B into a cycle, and `packed_streams[0] = 0`
/// entering that cycle. Reached at open time through the encoded-header decode path.
#[test]
fn cyclic_coder_bind_pairs_are_rejected() {
    // read_block: num_coders, then per-coder [flags,id,...], bind pairs (in,out), packed streams.
    let block: &[u8] = &[
        0x03, // num_coders = 3
        0x01, 0x00, // coder A: id_size=1, simple, id=COPY
        0x01, 0x00, // coder B: id_size=1, simple, id=COPY
        0x11, 0x00, 0x03, 0x01, // coder C: id_size=1, complex; id=COPY; num_in=3, num_out=1
        0x01, 0x00, // bind pair 0: in_index=1, out_index=0
        0x00, 0x01, // bind pair 1: in_index=0, out_index=1
        0x00, 0x02, 0x03, // packed_streams = [0, 2, 3] (enter the cycle at stream 0)
    ];

    let mut streams_info = vec![
        K_PACK_INFO,
        0x00, // pack_pos = 0
        0x01, // num_pack_streams = 1
        K_SIZE,
        0x01, // pack_sizes[0] = 1
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks = 1
        0x00, // external = 0
    ];
    streams_info.extend_from_slice(block);
    streams_info.push(K_CODERS_UNPACK_SIZE);
    streams_info.extend_from_slice(&[0x01, 0x01, 0x01]); // unpack_sizes for 3 output streams
    streams_info.push(K_END); // end unpack_info
    streams_info.push(K_END); // end streams_info

    let mut nh = vec![0x17]; // K_ENCODED_HEADER
    nh.extend_from_slice(&streams_info);

    assert!(
        open_err(&raw_7z_exact(&nh)).is_err(),
        "a cyclic coder bind-pair graph must be rejected, not loop forever"
    );
}

/// Drives full extraction so decode-path issues are exercised.
fn decode_err(bytes: &[u8]) -> Result<(), String> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec()), Password::empty())
        .map_err(|e| e.to_string())?;
    reader
        .for_each_entries(&mut |_e: &ArchiveEntry, rd: &mut dyn std::io::Read| {
            std::io::copy(rd, &mut std::io::sink())?;
            Ok(true)
        })
        .map_err(|e| e.to_string())
}

#[test]
fn lzma_coder_with_short_properties_is_rejected() {
    let nh: &[u8] = &[
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        0x06, // K_PACK_INFO
        0x00, // pack_pos
        0x01, // num_pack_streams
        0x09, // K_SIZE
        0x01, // pack_sizes[0] = 1
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
        0x01, // num_coders
        0x23, // coder flags: id_size=3, simple, has_attributes
        0x03,
        0x01,
        0x01, // coder id = LZMA
        0x02, // properties_size = 2 (too short: get_lzma_dic_size needs >= 5)
        0x00,
        0x00, // the 2 property bytes
        0x0C, // K_CODERS_UNPACK_SIZE
        0x05, // unpack_sizes[0] = 5
        K_END,
        0x08,  // K_SUB_STREAMS_INFO
        K_END, // empty
        K_END, // streams_info end
        K_FILES_INFO,
        0x01,  // num_files = 1
        K_END, // files_info props end
        K_END, // header end
    ];
    // Must be a clean error (parse or decode), never a panic.
    let parsed = ArchiveReader::new(Cursor::new(raw_7z_exact(nh)), Password::empty());
    match parsed {
        Err(_) => {} // rejected during parse, which is fine
        Ok(_) => assert!(decode_err(&raw_7z_exact(nh)).is_err()),
    }
}

/// Like `raw_7z_exact` but places `packed` bytes right after the signature header and puts
/// the next header after them (so coders have real packed data to read during decode).
fn raw_7z_with_packed(packed: &[u8], next_header: &[u8]) -> Vec<u8> {
    let mut start = [0u8; 20];
    start[0..8].copy_from_slice(&(packed.len() as u64).to_le_bytes()); // next_header_offset
    start[8..16].copy_from_slice(&(next_header.len() as u64).to_le_bytes());
    start[16..20].copy_from_slice(&crc32(next_header).to_le_bytes());
    let start_crc = crc32(&start);

    let mut out = Vec::new();
    out.extend_from_slice(&SEVEN_Z_SIGNATURE);
    out.extend_from_slice(&[0x00, 0x04]);
    out.extend_from_slice(&start_crc.to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(packed);
    out.extend_from_slice(next_header);
    out
}

/// A reader that yields at most one byte per `read` call, to emulate the short, non-16-aligned
/// reads an upstream coder can deliver to a layered AES decoder.
#[cfg(feature = "aes256")]
struct DripReader<R>(R);

#[cfg(feature = "aes256")]
impl<R: std::io::Read> std::io::Read for DripReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0.read(&mut buf[..1])
    }
}

#[cfg(feature = "aes256")]
impl<R: std::io::Seek> std::io::Seek for DripReader<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

/// The AES CBC stream must tolerate short reads without panicking. When AES receives data one
/// byte at a time, a partial 16-byte block sits in `Cipher::buf` and the next call arrives with
/// `data.len() < 16 - buf.len()`; pre-fix, `Cipher::update` sliced `data[..end]` out of bounds.
/// Decoding must instead buffer the bytes and still recover the original content.
#[cfg(feature = "aes256")]
#[test]
fn aes_decode_survives_one_byte_reads() {
    use sevenz_rust2::encoder_options::AesEncoderOptions;

    let original: Vec<u8> = (0..200u32).map(|i| i as u8).collect();

    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        writer.set_encrypt_header(false); // keep the header plaintext; only the content is AES
        writer.set_content_methods(vec![AesEncoderOptions::new(Password::from("pw")).into()]);
        writer
            .push_archive_entry(ArchiveEntry::new_file("data"), Some(original.as_slice()))
            .unwrap();
        writer.finish().unwrap();
    }

    // Read the content stream one byte per `read`, forcing AES to see partial blocks.
    let src = DripReader(Cursor::new(bytes.clone()));
    let mut reader = ArchiveReader::new(src, Password::from("pw")).unwrap();
    let decoded = reader.read_file("data").unwrap();
    assert_eq!(
        decoded, original,
        "AES content must decode correctly even with one-byte reads (no slice panic)"
    );
}

/// An AES coder whose `num_cycles_power` byte is `0x3F` (the "raw key" mode) used to make
/// `get_aes_key` run `aes_key.copy_from_slice(&salt)` with mismatched lengths. A guaranteed
/// panic for any password-protected archive. Decoding must not panic.
#[cfg(feature = "aes256")]
#[test]
fn aes_raw_key_mode_does_not_panic() {
    let nh: &[u8] = &[
        K_HEADER,
        K_MAIN_STREAMS_INFO,
        0x06, // K_PACK_INFO
        0x00, // pack_pos
        0x01, // num_pack_streams
        0x09, // K_SIZE
        0x10, // pack_sizes[0] = 16
        K_END,
        K_UNPACK_INFO,
        K_FOLDER,
        0x01, // num_blocks
        0x00, // external
        0x01, // num_coders
        0x24, // coder flags: id_size=4, simple, has_attributes
        0x06,
        0xF1,
        0x07,
        0x01, // coder id = AES256-SHA256
        0x02, // properties_size = 2
        0x3F,
        0x00, // num_cycles_power = 0x3F, salt/iv sizes = 0
        0x0C, // K_CODERS_UNPACK_SIZE
        0x05, // unpack_sizes[0] = 5
        K_END,
        0x08,  // K_SUB_STREAMS_INFO
        K_END, // empty
        K_END, // streams_info end
        K_FILES_INFO,
        0x01,  // num_files = 1
        K_END, // files_info props end
        K_END, // header end
    ];
    let bytes = raw_7z_with_packed(&[0u8; 16], nh);

    // The assertion is simply that neither parsing nor decoding panics. A returned error
    // is a perfectly acceptable outcome; a panic (pre-fix) fails the test.
    if let Ok(mut reader) = ArchiveReader::new(Cursor::new(bytes), Password::from("x")) {
        let _ = reader.for_each_entries(&mut |_e: &ArchiveEntry, rd: &mut dyn std::io::Read| {
            let _ = std::io::copy(rd, &mut std::io::sink());
            Ok(true)
        });
    }
}
