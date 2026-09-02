use std::io::{ErrorKind, Read, Write};

use lzma_rust2::{Action, LzmaOptions, LzmaReader, LzmaStream, LzmaWriter, Status};

static EXECUTABLE: &str = "tests/data/executable.exe";
static PG100: &str = "tests/data/pg100.txt";
static PG6800: &str = "tests/data/pg6800.txt";
static INPUT_HTML: &str = "tests/data/input.html";
static APACHE2: &str = "tests/data/apache2.txt";

/// Chunk size meaning "hand over everything that is left".
const ENTIRE: usize = usize::MAX;

/// Everything the decoder needs to know about a raw (headerless) stream.
#[derive(Clone, Copy)]
struct RawProps {
    uncomp_size: u64,
    props: u8,
    dict_size: u32,
}

fn compress_header(data: &[u8], preset: u32, known_size: bool) -> Vec<u8> {
    let options = LzmaOptions::with_preset(preset);
    let size = known_size.then_some(data.len() as u64);
    let mut writer = LzmaWriter::new_use_header(Vec::new(), &options, size).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap()
}

fn compress_raw(data: &[u8], preset: u32, use_end_marker: bool) -> (Vec<u8>, RawProps) {
    let options = LzmaOptions::with_preset(preset);
    let mut writer = LzmaWriter::new_no_header(Vec::new(), &options, use_end_marker).unwrap();
    let props = writer.props();
    writer.write_all(data).unwrap();
    let compressed = writer.finish().unwrap();
    (
        compressed,
        RawProps {
            uncomp_size: if use_end_marker {
                u64::MAX
            } else {
                data.len() as u64
            },
            props,
            dict_size: options.dict_size,
        },
    )
}

fn raw_stream(raw: RawProps) -> LzmaStream {
    LzmaStream::new_with_props(raw.uncomp_size, raw.props, raw.dict_size, None).unwrap()
}

/// Drives a stream to completion, feeding at most `chunk` bytes and accepting at
/// most `out_size` bytes per call.
fn decode(
    mut stream: LzmaStream,
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

/// The reference: same compressed bytes through the blocking reader.
fn decode_with_reader(compressed: &[u8], raw: Option<RawProps>) -> std::io::Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    match raw {
        None => {
            LzmaReader::new_mem_limit(compressed, u32::MAX, None)?.read_to_end(&mut decompressed)?
        }
        Some(raw) => {
            LzmaReader::new_with_props(compressed, raw.uncomp_size, raw.props, raw.dict_size, None)?
                .read_to_end(&mut decompressed)?
        }
    };
    Ok(decompressed)
}

fn test_round_trip(path: &str, preset: u32) {
    let data = std::fs::read(path).unwrap();

    // .lzma header, known uncompressed size.
    let compressed = compress_header(&data, preset, true);
    let decompressed = decode(
        LzmaStream::new_mem_limit(u32::MAX, None),
        &compressed,
        ENTIRE,
        4096,
    )
    .unwrap();
    assert!(decompressed == data, "header/known size, preset {preset}");

    // .lzma header, unknown size, terminated by an end of payload marker.
    let compressed = compress_header(&data, preset, false);
    let decompressed = decode(
        LzmaStream::new_mem_limit(u32::MAX, None),
        &compressed,
        ENTIRE,
        4096,
    )
    .unwrap();
    assert!(decompressed == data, "header/EOPM, preset {preset}");

    // Raw LZMA1 with an end of payload marker.
    let (compressed, raw) = compress_raw(&data, preset, true);
    let decompressed = decode(raw_stream(raw), &compressed, ENTIRE, 4096).unwrap();
    assert!(decompressed == data, "raw/EOPM, preset {preset}");

    // Raw LZMA1 with a known size and no marker.
    let (compressed, raw) = compress_raw(&data, preset, false);
    let decompressed = decode(raw_stream(raw), &compressed, ENTIRE, 4096).unwrap();
    assert!(decompressed == data, "raw/known size, preset {preset}");
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

/// The 19/20/21 rows straddle `IN_REQUIRED`, the 39/40/41 rows straddle the
/// carry capacity. Those are the sizes where the carry logic actually changes
/// behaviour.
const CHUNK_SIZES: &[usize] = &[1, 2, 3, 5, 19, 20, 21, 39, 40, 41, 4096, ENTIRE];
const OUTPUT_SIZES: &[usize] = &[1, 7, 4096];

fn test_chunk_matrix(data: &[u8], preset: u32) {
    // Header mode, known size.
    let compressed = compress_header(data, preset, true);
    let reference = decode_with_reader(&compressed, None).unwrap();
    assert!(reference == data);
    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let decompressed = decode(
                LzmaStream::new_mem_limit(u32::MAX, None),
                &compressed,
                chunk,
                out_size,
            )
            .unwrap_or_else(|error| panic!("header chunk {chunk} out {out_size}: {error}"));
            assert!(
                decompressed == reference,
                "header chunk {chunk} out {out_size}"
            );
        }
    }

    // Raw mode with an end of payload marker, so the EOPM path gets the same
    // treatment.
    let (compressed, raw) = compress_raw(data, preset, true);
    let reference = decode_with_reader(&compressed, Some(raw)).unwrap();
    assert!(reference == data);
    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let decompressed = decode(raw_stream(raw), &compressed, chunk, out_size)
                .unwrap_or_else(|error| panic!("raw chunk {chunk} out {out_size}: {error}"));
            assert!(
                decompressed == reference,
                "raw chunk {chunk} out {out_size}"
            );
        }
    }
}

#[test]
fn chunk_matrix_apache2() {
    let data = std::fs::read(APACHE2).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&data, preset);
    }
}

#[test]
fn chunk_matrix_input_html() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&data, preset);
    }
}

/// A 64 KiB prefix is long enough to wrap the small dictionaries of the low
/// presets, which is what exercises `flush_partial` wrapping `pos` back to 0.
#[test]
fn chunk_matrix_pg100_prefix() {
    let data = std::fs::read(PG100).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&data[..64 * 1024], preset);
    }
}

#[test]
fn chunk_matrix_executable_prefix() {
    let data = std::fs::read(EXECUTABLE).unwrap();
    for preset in 0..=9 {
        test_chunk_matrix(&data[..64 * 1024], preset);
    }
}

#[test]
fn chunk_matrix_empty_input() {
    for preset in 0..=9 {
        test_chunk_matrix(&[], preset);
    }
}

/// The margin and carry capacity edges against the whole corpus, at full size.
/// Too slow for the default run, but it does finish in a few minutes.
#[test]
#[ignore = "slow: full corpus against the carry boundary chunk sizes"]
fn chunk_boundaries_on_the_full_corpus() {
    for path in [EXECUTABLE, PG100, PG6800, INPUT_HTML, APACHE2] {
        let data = std::fs::read(path).unwrap();
        for preset in [0, 6, 9] {
            let compressed = compress_header(&data, preset, true);
            let (raw_compressed, raw) = compress_raw(&data, preset, true);
            for &chunk in &[19usize, 20, 21, 39, 40, 41] {
                let decompressed = decode(
                    LzmaStream::new_mem_limit(u32::MAX, None),
                    &compressed,
                    chunk,
                    4096,
                )
                .unwrap_or_else(|error| panic!("{path} preset {preset} chunk {chunk}: {error}"));
                assert!(decompressed == data, "{path} preset {preset} chunk {chunk}");

                let decompressed = decode(raw_stream(raw), &raw_compressed, chunk, 4096)
                    .unwrap_or_else(|error| {
                        panic!("{path} preset {preset} chunk {chunk} raw: {error}")
                    });
                assert!(
                    decompressed == data,
                    "{path} preset {preset} chunk {chunk} raw"
                );
            }
        }
    }
}

#[test]
fn matches_reader_on_corpus() {
    for path in [EXECUTABLE, PG100, PG6800, INPUT_HTML, APACHE2] {
        let data = std::fs::read(path).unwrap();
        for preset in [0, 6, 9] {
            let compressed = compress_header(&data, preset, true);
            let reference = decode_with_reader(&compressed, None).unwrap();
            let decompressed = decode(
                LzmaStream::new_mem_limit(u32::MAX, None),
                &compressed,
                4096,
                4096,
            )
            .unwrap();
            assert!(decompressed == reference, "{path} preset {preset}");

            let (compressed, raw) = compress_raw(&data, preset, true);
            let reference = decode_with_reader(&compressed, Some(raw)).unwrap();
            let decompressed = decode(raw_stream(raw), &compressed, 4096, 4096).unwrap();
            assert!(decompressed == reference, "{path} preset {preset} raw");
        }
    }
}

#[test]
fn preset_dict_round_trip() {
    let data = std::fs::read(APACHE2).unwrap();
    let preset_dict = data[..2048].to_vec();

    for preset in 0..=9 {
        for use_end_marker in [false, true] {
            let mut options = LzmaOptions::with_preset(preset);
            options.preset_dict = Some(preset_dict.clone());

            let mut writer =
                LzmaWriter::new_no_header(Vec::new(), &options, use_end_marker).unwrap();
            let props = writer.props();
            writer.write_all(&data).unwrap();
            let compressed = writer.finish().unwrap();

            let uncomp_size = if use_end_marker {
                u64::MAX
            } else {
                data.len() as u64
            };

            for &chunk in CHUNK_SIZES {
                let stream = LzmaStream::new_with_props(
                    uncomp_size,
                    props,
                    options.dict_size,
                    Some(&preset_dict),
                )
                .unwrap();
                let decompressed = decode(stream, &compressed, chunk, 4096).unwrap();
                assert!(
                    decompressed == data,
                    "preset {preset} eopm {use_end_marker} chunk {chunk}"
                );
            }
        }
    }
}

/// Every prefix of a valid stream must be rejected, with one unavoidable
/// exception: the final byte of the range coder flush carries no information the
/// decoder ever reads back, so dropping just that one byte is undetectable. It
/// is however harmless, because the output is still complete and correct;
/// `LzmaReader` accepts the same prefix. Anything shorter must error.
fn assert_truncation_errors(compressed: &[u8], data: &[u8], make: impl Fn() -> LzmaStream) {
    for prefix in 0..compressed.len() {
        let result = decode(make(), &compressed[..prefix], ENTIRE, 4096);
        if prefix == compressed.len() - 1 {
            if let Ok(decompressed) = result {
                assert!(
                    decompressed == data,
                    "dropping the last byte silently changed the output"
                );
            }
            continue;
        }
        assert!(
            result.is_err(),
            "prefix of {prefix}/{} bytes decoded without error",
            compressed.len()
        );
    }
}

#[test]
fn truncated_header_stream_errors() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress_header(&data, 1, true);
    assert_truncation_errors(&compressed, &data, || {
        LzmaStream::new_mem_limit(u32::MAX, None)
    });
}

#[test]
fn truncated_eopm_stream_errors() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress_header(&data, 1, false);
    assert_truncation_errors(&compressed, &data, || {
        LzmaStream::new_mem_limit(u32::MAX, None)
    });
}

#[test]
fn truncated_raw_stream_errors() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let (compressed, raw) = compress_raw(&data, 1, true);
    assert_truncation_errors(&compressed, &data, || raw_stream(raw));
}

#[test]
fn truncation_is_detected_at_every_chunk_size() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_header(&data, 6, true);
    let truncated = &compressed[..compressed.len() - 2];
    for &chunk in CHUNK_SIZES {
        for &out_size in OUTPUT_SIZES {
            let result = decode(
                LzmaStream::new_mem_limit(u32::MAX, None),
                truncated,
                chunk,
                out_size,
            );
            assert!(result.is_err(), "chunk {chunk} out {out_size}");
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress_header(&data, 1, true);

    // Every byte, one bit each, walking the bit position along so all eight get
    // exercised without running the full 8x matrix.
    for index in 0..compressed.len() {
        let mut corrupted = compressed.clone();
        corrupted[index] ^= 1 << (index % 8);

        for &out_size in OUTPUT_SIZES {
            // Decoding may legitimately succeed with different data, the format
            // has no integrity check of its own. It must not panic or stall.
            let _ = decode(
                LzmaStream::new_mem_limit(u32::MAX, None),
                &corrupted,
                ENTIRE,
                out_size,
            );
        }
    }
}

#[test]
fn truncated_and_corrupted_never_panics() {
    let data = std::fs::read(APACHE2).unwrap();
    let (compressed, raw) = compress_raw(&data, 3, true);

    for index in (0..compressed.len()).step_by(7) {
        let mut corrupted = compressed[..compressed.len() - index / 2].to_vec();
        if index < corrupted.len() {
            corrupted[index] ^= 0x80;
        }
        for &chunk in &[1usize, 20, 40, ENTIRE] {
            let _ = decode(raw_stream(raw), &corrupted, chunk, 4096);
        }
    }
}

#[test]
fn memory_limit_is_enforced_from_process() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_header(&data, 9, true);

    // The constructor cannot fail; the limit is checked once the header has
    // been parsed.
    let mut stream = LzmaStream::new_mem_limit(1, None);
    let mut output = [0u8; 4096];
    let error = stream
        .process(&compressed, &mut output, Action::Finish)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::OutOfMemory);

    // A generous limit works on the same bytes.
    let decompressed = decode(
        LzmaStream::new_mem_limit(u32::MAX, None),
        &compressed,
        ENTIRE,
        4096,
    )
    .unwrap();
    assert!(decompressed == data);
}

#[test]
fn memory_limit_is_enforced_when_the_header_arrives_byte_by_byte() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_header(&data, 9, true);
    let result = decode(LzmaStream::new_mem_limit(1, None), &compressed, 1, 4096);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::OutOfMemory);
}

/// Feeds `input` and returns the decoded bytes plus everything the stream did
/// not use up.
fn decode_recovering_tail(
    mut stream: LzmaStream,
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
        let presented_end = end;
        pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output[..result.bytes_produced]);

        if result.status == Status::StreamEnd {
            // Bytes taken into the carry but never decoded come first, then
            // whatever is left of the slice we last presented.
            let mut unused = stream.unused_input().to_vec();
            unused.extend_from_slice(&input[pos..presented_end]);
            unused.extend_from_slice(&input[presented_end..]);
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
        let compressed = compress_header(&data, 6, true);
        let mut input = compressed.clone();
        input.extend_from_slice(&garbage);

        let (decompressed, unused) =
            decode_recovering_tail(LzmaStream::new_mem_limit(u32::MAX, None), &input, chunk)
                .unwrap();

        assert!(decompressed == data, "chunk {chunk}");
        assert_eq!(unused, garbage, "chunk {chunk}");
    }
}

#[test]
fn trailing_data_is_recoverable_after_an_eopm_stream() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let garbage: Vec<u8> = (0u8..=255).cycle().take(300).collect();

    for &chunk in CHUNK_SIZES {
        let (compressed, raw) = compress_raw(&data, 6, true);
        let mut input = compressed.clone();
        input.extend_from_slice(&garbage);

        let (decompressed, unused) =
            decode_recovering_tail(raw_stream(raw), &input, chunk).unwrap();

        assert!(decompressed == data, "chunk {chunk}");
        assert_eq!(unused, garbage, "chunk {chunk}");
    }
}

#[test]
fn empty_input_with_finish_is_a_legal_call() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_header(&data, 6, true);

    let mut stream = LzmaStream::new_mem_limit(u32::MAX, None);
    let mut output = [0u8; 4096];
    let mut decompressed = Vec::new();
    let mut pos = 0usize;

    loop {
        // Alternate between handing over real bytes and an empty flush call.
        let end = (pos + 128).min(compressed.len());
        let result = stream
            .process(&compressed[pos..end], &mut output, Action::Run)
            .unwrap();
        pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output[..result.bytes_produced]);

        let result = stream.process(&[], &mut output, Action::Run).unwrap();
        decompressed.extend_from_slice(&output[..result.bytes_produced]);
        assert_eq!(result.bytes_consumed, 0);

        if pos >= compressed.len() {
            break;
        }
    }

    loop {
        let result = stream.process(&[], &mut output, Action::Finish).unwrap();
        decompressed.extend_from_slice(&output[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }

    assert!(decompressed == data);
}

#[test]
fn process_after_stream_end_keeps_reporting_stream_end() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = compress_header(&data, 6, true);

    let mut stream = LzmaStream::new_mem_limit(u32::MAX, None);
    let mut output = vec![0u8; data.len() + 1024];
    let result = stream
        .process(&compressed, &mut output, Action::Finish)
        .unwrap();
    assert_eq!(result.status, Status::StreamEnd);
    assert!(output[..result.bytes_produced] == data[..]);

    for _ in 0..3 {
        let result = stream.process(&[], &mut output, Action::Finish).unwrap();
        assert_eq!(result.status, Status::StreamEnd);
        assert_eq!(result.bytes_consumed, 0);
        assert_eq!(result.bytes_produced, 0);
    }
}

#[test]
fn totals_are_accurate() {
    let data = std::fs::read(APACHE2).unwrap();
    let compressed = compress_header(&data, 6, true);

    let mut stream = LzmaStream::new_mem_limit(u32::MAX, None);
    let mut output = [0u8; 64];
    let mut pos = 0usize;
    let mut produced_total = 0u64;

    loop {
        let end = (pos + 13).min(compressed.len());
        let action = if end >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = stream
            .process(&compressed[pos..end], &mut output, action)
            .unwrap();
        pos += result.bytes_consumed;
        produced_total += result.bytes_produced as u64;
        if result.status == Status::StreamEnd {
            break;
        }
    }

    assert_eq!(stream.total_in(), pos as u64);
    assert_eq!(stream.total_out(), produced_total);
    assert_eq!(produced_total, data.len() as u64);
    assert!(!stream.has_output());
}

#[test]
fn invalid_props_are_rejected_by_the_constructor() {
    assert!(LzmaStream::new_with_props(0, 255, 1 << 20, None).is_err());
    assert!(LzmaStream::new(0, 9, 0, 2, 1 << 20, None).is_err());
    assert!(LzmaStream::new(0, 3, 5, 2, 1 << 20, None).is_err());
    assert!(LzmaStream::new(0, 3, 0, 5, 1 << 20, None).is_err());
}

#[test]
fn a_non_zero_first_range_coder_byte_is_rejected() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let (mut compressed, raw) = compress_raw(&data, 1, true);
    compressed[0] = 0x01;
    let error = decode(raw_stream(raw), &compressed, ENTIRE, 4096).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
