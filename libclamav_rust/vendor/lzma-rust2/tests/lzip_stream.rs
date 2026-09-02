use std::{
    io::{ErrorKind, Read, Write},
    num::NonZeroU64,
};

use lzma_rust2::{Action, LzipOptions, LzipReader, LzipStream, LzipWriter, Status};

static EXECUTABLE: &str = "tests/data/executable.exe";
static PG100: &str = "tests/data/pg100.txt";
static PG6800: &str = "tests/data/pg6800.txt";
static INPUT_HTML: &str = "tests/data/input.html";
static APACHE2: &str = "tests/data/apache2.txt";
static REFERENCE: &str = "tests/data/executable.exe.lz";

/// Chunk size meaning "hand over everything that is left".
const ENTIRE: usize = usize::MAX;

const HEADER_SIZE: usize = 6;

/// The 19/20/21 and 39/40/41 rows are where a finished member hands back more
/// than the 20 byte trailer, so what it gives back reaches into the next
/// member's header and payload.
const CHUNK_SIZES: &[usize] = &[1, 2, 3, 5, 19, 20, 21, 39, 40, 41, 4096, ENTIRE];
const OUTPUT_SIZES: &[usize] = &[1, 7, 4096];

fn compress(data: &[u8], preset: u32, member_size: Option<u64>) -> Vec<u8> {
    let mut options = LzipOptions::with_preset(preset);
    options.set_member_size(member_size.and_then(NonZeroU64::new));
    let mut writer = LzipWriter::new(Vec::new(), options);
    writer.write_all(data).unwrap();
    writer.finish().unwrap()
}

/// Compresses `data` in pieces and concatenates the results, which is a
/// multi member file with members as small as we like.
fn compress_members(data: &[u8], preset: u32, piece: usize) -> Vec<u8> {
    let mut compressed = Vec::new();
    for part in data.chunks(piece) {
        compressed.extend_from_slice(&compress(part, preset, None));
    }
    compressed
}

/// Drives a stream to completion, feeding at most `chunk` bytes and accepting at
/// most `out_size` bytes per call. The stream is borrowed so that a test can ask
/// it about the file afterwards.
fn decode(
    stream: &mut LzipStream,
    compressed: &[u8],
    chunk: usize,
    out_size: usize,
) -> std::io::Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut output = vec![0u8; out_size];
    let mut pos = 0usize;

    loop {
        let end = pos.saturating_add(chunk).min(compressed.len());
        let action = if end >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };

        let result = stream.process(&compressed[pos..end], &mut output, action)?;
        pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output[..result.bytes_produced]);

        if result.status == Status::StreamEnd {
            assert!(stream.is_finished());
            assert_eq!(stream.total_out(), decompressed.len() as u64);
            return Ok(decompressed);
        }

        // Neither consuming nor producing anything while output space is
        // available is a stall: the caller would loop forever.
        assert!(
            result.bytes_consumed != 0 || result.bytes_produced != 0,
            "stalled at input {pos}/{} after {} bytes of output",
            compressed.len(),
            decompressed.len()
        );
    }
}

/// Same as [`decode`], for the cases that have to fail.
fn decode_err(
    stream: &mut LzipStream,
    compressed: &[u8],
    chunk: usize,
    out_size: usize,
) -> std::io::Error {
    match decode(stream, compressed, chunk, out_size) {
        Ok(decompressed) => panic!("{} bytes decoded without an error", decompressed.len()),
        Err(error) => error,
    }
}

/// The reference: same compressed bytes through the blocking reader.
fn decode_with_reader(compressed: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    LzipReader::new(compressed).read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn test_round_trip(path: &str, preset: u32) {
    let data = std::fs::read(path).unwrap();

    let compressed = compress(&data, preset, None);
    let decompressed = decode(&mut LzipStream::new(), &compressed, ENTIRE, 4096).unwrap();
    assert!(decompressed == data, "preset {preset}");
    assert_eq!(decompressed.len(), data.len(), "preset {preset}");
}

macro_rules! round_trip_tests {
    ($($name:ident => ($path:expr, $preset:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                test_round_trip($path, $preset);
            }
        )*
    };
}

round_trip_tests! {
    round_trip_executable_0 => (EXECUTABLE, 0),
    round_trip_executable_1 => (EXECUTABLE, 1),
    round_trip_executable_2 => (EXECUTABLE, 2),
    round_trip_executable_3 => (EXECUTABLE, 3),
    round_trip_executable_4 => (EXECUTABLE, 4),
    round_trip_executable_5 => (EXECUTABLE, 5),
    round_trip_executable_6 => (EXECUTABLE, 6),
    round_trip_executable_7 => (EXECUTABLE, 7),
    round_trip_executable_8 => (EXECUTABLE, 8),
    round_trip_executable_9 => (EXECUTABLE, 9),
    round_trip_pg100_0 => (PG100, 0),
    round_trip_pg100_1 => (PG100, 1),
    round_trip_pg100_2 => (PG100, 2),
    round_trip_pg100_3 => (PG100, 3),
    round_trip_pg100_4 => (PG100, 4),
    round_trip_pg100_5 => (PG100, 5),
    round_trip_pg100_6 => (PG100, 6),
    round_trip_pg100_7 => (PG100, 7),
    round_trip_pg100_8 => (PG100, 8),
    round_trip_pg100_9 => (PG100, 9),
    round_trip_pg6800_0 => (PG6800, 0),
    round_trip_pg6800_1 => (PG6800, 1),
    round_trip_pg6800_2 => (PG6800, 2),
    round_trip_pg6800_3 => (PG6800, 3),
    round_trip_pg6800_4 => (PG6800, 4),
    round_trip_pg6800_5 => (PG6800, 5),
    round_trip_pg6800_6 => (PG6800, 6),
    round_trip_pg6800_7 => (PG6800, 7),
    round_trip_pg6800_8 => (PG6800, 8),
    round_trip_pg6800_9 => (PG6800, 9),
    round_trip_input_html_0 => (INPUT_HTML, 0),
    round_trip_input_html_1 => (INPUT_HTML, 1),
    round_trip_input_html_2 => (INPUT_HTML, 2),
    round_trip_input_html_3 => (INPUT_HTML, 3),
    round_trip_input_html_4 => (INPUT_HTML, 4),
    round_trip_input_html_5 => (INPUT_HTML, 5),
    round_trip_input_html_6 => (INPUT_HTML, 6),
    round_trip_input_html_7 => (INPUT_HTML, 7),
    round_trip_input_html_8 => (INPUT_HTML, 8),
    round_trip_input_html_9 => (INPUT_HTML, 9),
    round_trip_apache2_0 => (APACHE2, 0),
    round_trip_apache2_1 => (APACHE2, 1),
    round_trip_apache2_2 => (APACHE2, 2),
    round_trip_apache2_3 => (APACHE2, 3),
    round_trip_apache2_4 => (APACHE2, 4),
    round_trip_apache2_5 => (APACHE2, 5),
    round_trip_apache2_6 => (APACHE2, 6),
    round_trip_apache2_7 => (APACHE2, 7),
    round_trip_apache2_8 => (APACHE2, 8),
    round_trip_apache2_9 => (APACHE2, 9),
}

/// Members written by `LzipWriter` itself. It raises the member size to the
/// dictionary size, so this needs an input of a few megabytes to split at all.
#[test]
fn writer_split_members_round_trip() {
    let data = std::fs::read(PG100).unwrap();

    for preset in [0, 1] {
        let compressed = compress(&data, preset, Some(256 * 1024));
        let mut stream = LzipStream::new();
        let decompressed = decode(&mut stream, &compressed, ENTIRE, 4096).unwrap();

        assert!(decompressed == data, "preset {preset}");
        assert!(
            stream.member_count() > 1,
            "preset {preset} produced a single member"
        );
    }
}

#[test]
fn concatenated_members_round_trip() {
    let data = &std::fs::read(APACHE2).unwrap()[..2048];

    for piece in [1usize, 7, 512, 4096] {
        let compressed = compress_members(data, 0, piece);
        let decompressed = decode(&mut LzipStream::new(), &compressed, 4096, 4096).unwrap();
        assert!(decompressed == data, "piece {piece}");
    }
}

/// Members short enough that what one of them hands back can cover the whole of
/// the next one.
#[test]
fn tiny_members_decode() {
    let compressed = compress_members(b"aaaaaaaa", 0, 1);

    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let decompressed = decode(&mut LzipStream::new(), &compressed, chunk, out_size)
                .unwrap_or_else(|error| panic!("chunk {chunk} out {out_size}: {error}"));
            assert_eq!(decompressed, b"aaaaaaaa", "chunk {chunk} out {out_size}");
        }
    }
}

#[test]
fn empty_members_decode() {
    let mut compressed = Vec::new();
    for _ in 0..8 {
        compressed.extend_from_slice(&compress(b"", 0, None));
    }

    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let decompressed = decode(&mut LzipStream::new(), &compressed, chunk, out_size)
                .unwrap_or_else(|error| panic!("chunk {chunk} out {out_size}: {error}"));
            assert!(decompressed.is_empty(), "chunk {chunk} out {out_size}");
        }
    }

    assert!(decode_with_reader(&compressed).unwrap().is_empty());
}

/// The file is 11 MiB compressed, so it gets the chunk sizes that matter and a
/// single output size instead of the whole matrix. The small output buffers run
/// against the smaller multi member files above.
#[test]
fn reference_file_decodes() {
    let compressed = std::fs::read(REFERENCE).unwrap();
    let data = std::fs::read(EXECUTABLE).unwrap();

    for &chunk in &[19usize, 20, 21, 39, 40, 41, 4096, ENTIRE] {
        let decompressed = decode(&mut LzipStream::new(), &compressed, chunk, 4096)
            .unwrap_or_else(|error| panic!("chunk {chunk}: {error}"));
        assert!(decompressed == data, "chunk {chunk}");
    }

    let decompressed = decode(&mut LzipStream::new(), &compressed, 41, 64).unwrap();
    assert!(decompressed == data, "small output");
}

#[test]
fn reference_file_has_twelve_members() {
    let compressed = std::fs::read(REFERENCE).unwrap();
    let mut stream = LzipStream::new();
    decode(&mut stream, &compressed, ENTIRE, 4096).unwrap();

    assert_eq!(stream.member_count(), 12);
    assert_eq!(stream.total_in(), compressed.len() as u64);
}

fn test_chunk_matrix(compressed: &[u8], data: &[u8], label: &str) {
    let reference = decode_with_reader(compressed).unwrap();
    assert!(reference == data, "{label}");

    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let decompressed = decode(&mut LzipStream::new(), compressed, chunk, out_size)
                .unwrap_or_else(|error| panic!("{label} chunk {chunk} out {out_size}: {error}"));
            assert!(
                decompressed == reference,
                "{label} chunk {chunk} out {out_size}"
            );
        }
    }
}

#[test]
fn chunk_matrix_apache2() {
    let data = std::fs::read(APACHE2).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&compress(&data, preset, None), &data, "single member");
    }
}

#[test]
fn chunk_matrix_input_html() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&compress(&data, preset, None), &data, "single member");
    }
}

/// Low presets only: every member allocates its own dictionary, and a file of
/// hundreds of tiny members at preset 9 would allocate 64 MiB for each of them.
#[test]
fn chunk_matrix_multi_member() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    for preset in [0, 1] {
        for piece in [64usize, 1024] {
            test_chunk_matrix(
                &compress_members(&data, preset, piece),
                &data,
                "multi member",
            );
        }
    }
}

#[test]
fn chunk_matrix_empty_input() {
    for preset in 0..=9 {
        test_chunk_matrix(&compress(&[], preset, None), &[], "empty");
    }
}

#[test]
fn chunk_matrix_executable_prefix() {
    let data = std::fs::read(EXECUTABLE).unwrap();
    let data = &data[..64 * 1024];
    for preset in 0..=9 {
        test_chunk_matrix(&compress(data, preset, None), data, "single member");
    }
    test_chunk_matrix(&compress_members(data, 0, 8192), data, "multi member");
}

#[test]
fn matches_reader_on_corpus() {
    for path in [EXECUTABLE, PG100, PG6800, INPUT_HTML, APACHE2] {
        let data = std::fs::read(path).unwrap();
        for preset in [0, 6] {
            let compressed = compress(&data, preset, None);
            let reference = decode_with_reader(&compressed).unwrap();
            let decompressed = decode(&mut LzipStream::new(), &compressed, 4096, 4096).unwrap();
            assert!(decompressed == reference, "{path} preset {preset}");
        }
    }
}

#[test]
fn matches_reader_on_multi_member_files() {
    for path in [INPUT_HTML, APACHE2] {
        let data = std::fs::read(path).unwrap();
        for preset in [0, 6] {
            let compressed = compress_members(&data, preset, 1024);
            let reference = decode_with_reader(&compressed).unwrap();
            let decompressed = decode(&mut LzipStream::new(), &compressed, 4096, 4096).unwrap();
            assert!(decompressed == reference, "{path} preset {preset}");
        }
    }
}

#[test]
fn a_corrupted_payload_is_caught() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress(&data, 6, None);

    // Late in the payload, clear of both the header and the trailer.
    let mut corrupted = compressed.clone();
    corrupted[compressed.len() - 40] ^= 0x01;

    // Which check trips first depends on the target, so only the failure is
    // asserted.
    decode_err(&mut LzipStream::new(), &corrupted, ENTIRE, 4096);
}

#[test]
fn tampered_trailer_fields_are_caught() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress(&data, 6, None);
    let trailer = compressed.len() - 20;

    for (offset, field) in [(0, "crc32"), (4, "data size"), (12, "member size")] {
        let mut corrupted = compressed.clone();
        corrupted[trailer + offset] ^= 0x01;

        let error = decode_err(&mut LzipStream::new(), &corrupted, ENTIRE, 4096);
        assert_eq!(error.kind(), ErrorKind::InvalidData, "tampered {field}");
    }
}

#[test]
fn a_corrupted_member_in_the_middle_is_caught() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_members(&data, 0, 1024);
    let trailer = compressed.len() / 2;

    let mut corrupted = compressed.clone();
    corrupted[trailer] ^= 0x01;

    // Either the member fails to decode, or it stops early because the flipped
    // byte no longer looks like a header. What it must not do is decode as if
    // nothing had happened.
    if let Ok(decompressed) = decode(&mut LzipStream::new(), &corrupted, ENTIRE, 4096) {
        assert!(decompressed != data);
    }
}

#[test]
fn bit_flips_never_panic() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress_members(&data[..2048], 0, 512);

    // Every byte, one bit each, walking the bit position along so all eight get
    // exercised without running the full 8x matrix.
    for index in 0..compressed.len() {
        let mut corrupted = compressed.clone();
        corrupted[index] ^= 1 << (index % 8);
        let _ = decode(&mut LzipStream::new(), &corrupted, ENTIRE, 4096);
    }
}

#[test]
fn every_truncated_prefix_errors() {
    let data = &std::fs::read(APACHE2).unwrap()[..4096];
    let piece = 1024;

    // Built piece by piece, so we know where every member ends.
    let mut compressed = Vec::new();
    let mut boundaries = Vec::new();
    for part in data.chunks(piece) {
        compressed.extend_from_slice(&compress(part, 0, None));
        boundaries.push(compressed.len());
    }

    for prefix in 1..compressed.len() {
        let result = decode(&mut LzipStream::new(), &compressed[..prefix], ENTIRE, 4096);

        // A file that stops on a member boundary is complete, and so is one
        // that stops a few bytes into the next header: too little to tell a
        // member that never arrived from trailing data.
        let complete = boundaries
            .iter()
            .position(|&end| (end..end + HEADER_SIZE).contains(&prefix));

        if let Some(index) = complete {
            let decompressed =
                result.unwrap_or_else(|error| panic!("prefix of {prefix} bytes errored: {error}"));
            let decoded_len = ((index + 1) * piece).min(data.len());
            assert!(decompressed == data[..decoded_len], "prefix {prefix}");
        } else {
            assert!(
                result.is_err(),
                "prefix of {prefix}/{} bytes decoded without an error",
                compressed.len()
            );
        }
    }
}

#[test]
fn truncation_is_detected_at_every_chunk_size() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress(&data, 6, None);
    let truncated = &compressed[..compressed.len() - 2];

    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let result = decode(&mut LzipStream::new(), truncated, chunk, out_size);
            assert!(result.is_err(), "chunk {chunk} out {out_size}");
        }
    }
}

#[test]
fn a_truncated_last_member_errors() {
    let data = std::fs::read(APACHE2).unwrap();
    let mut compressed = compress_members(&data, 0, 1024);
    compressed.truncate(compressed.len() - 25);

    for &chunk in CHUNK_SIZES {
        decode_err(&mut LzipStream::new(), &compressed, chunk, 4096);
    }
}

/// Feeds `input` and returns the decoded bytes plus everything the stream did
/// not use up.
fn decode_recovering_tail(
    stream: &mut LzipStream,
    input: &[u8],
    chunk: usize,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut decompressed = Vec::new();
    let mut output = [0u8; 4096];
    let mut pos = 0usize;

    loop {
        let end = pos.saturating_add(chunk).min(input.len());
        let action = if end >= input.len() {
            Action::Finish
        } else {
            Action::Run
        };

        let result = stream.process(&input[pos..end], &mut output, action)?;
        pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output[..result.bytes_produced]);

        if result.status == Status::StreamEnd {
            // Bytes taken in but never used come first, then whatever is left
            // of the input.
            let mut unused = stream.unused_input().to_vec();
            unused.extend_from_slice(&input[pos..]);
            assert_eq!(stream.total_in(), pos as u64);
            return Ok((decompressed, unused));
        }

        assert!(result.bytes_consumed != 0 || result.bytes_produced != 0);
    }
}

#[test]
fn trailing_data_is_recoverable() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let garbage: Vec<u8> = (0u8..=255).cycle().take(300).collect();

    for &chunk in CHUNK_SIZES {
        let mut input = compress_members(&data, 0, 1024);
        input.extend_from_slice(&garbage);

        let (decompressed, unused) =
            decode_recovering_tail(&mut LzipStream::new(), &input, chunk).unwrap();

        assert!(decompressed == data, "chunk {chunk}");
        assert_eq!(unused, garbage, "chunk {chunk}");
    }
}

/// A tail shorter than a header cannot even be told apart from a header that
/// has not fully arrived, and has to come back just the same.
#[test]
fn a_short_trailing_tail_is_recoverable() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    for tail_len in 1..=8 {
        let garbage: Vec<u8> = (0..tail_len).map(|byte| byte as u8).collect();
        for &chunk in CHUNK_SIZES {
            let mut input = compress(&data, 0, None);
            input.extend_from_slice(&garbage);

            let (decompressed, unused) =
                decode_recovering_tail(&mut LzipStream::new(), &input, chunk).unwrap();

            assert!(decompressed == data, "tail {tail_len} chunk {chunk}");
            assert_eq!(unused, garbage, "tail {tail_len} chunk {chunk}");
        }
    }
}

#[test]
fn non_lzip_input_errors() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    for &chunk in CHUNK_SIZES {
        let error = decode_err(&mut LzipStream::new(), &data, chunk, 4096);
        assert_eq!(error.kind(), ErrorKind::InvalidData, "chunk {chunk}");
    }
}

#[test]
fn empty_input_errors() {
    let mut stream = LzipStream::new();
    let mut output = [0u8; 64];
    let error = stream
        .process(&[], &mut output, Action::Finish)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}

#[test]
fn empty_input_asks_for_more() {
    let mut stream = LzipStream::new();
    let mut output = [0u8; 64];
    let result = stream.process(&[], &mut output, Action::Run).unwrap();

    assert_eq!(result.status, Status::Ok);
    assert_eq!(result.bytes_consumed, 0);
    assert_eq!(result.bytes_produced, 0);
    assert!(!stream.is_finished());
}

/// Memory a member with the given dictionary size needs, in KiB. LZIP fixes
/// lc=3 and lp=0.
fn member_memory(dict_size: u32) -> u32 {
    lzma_rust2::lzma_get_memory_usage(dict_size, 3, 0).unwrap()
}

#[test]
fn memory_limit_is_enforced_from_process() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress(&data, 9, None);

    // The constructor cannot fail; the limit is checked once a member header
    // has been parsed.
    let mut stream = LzipStream::new_mem_limit(1);
    let mut output = [0u8; 4096];
    let error = stream
        .process(&compressed, &mut output, Action::Finish)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::OutOfMemory);

    // A generous limit works on the same bytes.
    let decompressed = decode(&mut LzipStream::new(), &compressed, ENTIRE, 4096).unwrap();
    assert!(decompressed == data);
}

#[test]
fn memory_limit_is_enforced_when_the_header_arrives_byte_by_byte() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress(&data, 9, None);
    let result = decode(&mut LzipStream::new_mem_limit(1), &compressed, 1, 4096);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::OutOfMemory);
}

#[test]
fn memory_limit_is_enforced_on_a_later_member() {
    let data = std::fs::read(APACHE2).unwrap();

    // Preset 0 uses a 256 KiB dictionary, preset 9 a 64 MiB one.
    let mut input = compress(&data, 0, None);
    let limit = member_memory(1 << 18);
    let decompressed = decode(&mut LzipStream::new_mem_limit(limit), &input, ENTIRE, 4096).unwrap();
    assert!(decompressed == data);

    input.extend_from_slice(&compress(&data, 9, None));
    let error = decode_err(&mut LzipStream::new_mem_limit(limit), &input, ENTIRE, 4096);
    assert_eq!(error.kind(), ErrorKind::OutOfMemory);
}
