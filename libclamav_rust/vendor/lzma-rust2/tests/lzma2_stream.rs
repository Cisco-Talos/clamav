use std::io::{Read, Write};

use lzma_rust2::{Action, Lzma2Options, Lzma2Stream, Lzma2Writer, Status};

static EXECUTABLE: &str = "tests/data/executable.exe";
static PG100: &str = "tests/data/pg100.txt";
static PG6800: &str = "tests/data/pg6800.txt";
static INPUT_HTML: &str = "tests/data/input.html";

fn test_round_trip(path: &str, preset: u32) {
    let data = std::fs::read(path).unwrap();

    let opts = Lzma2Options::with_preset(preset);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let compressed = writer.finish().unwrap();

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    loop {
        let action = if in_pos >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&compressed[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }
    assert!(decompressed == data);
}

#[test]
fn round_trip_executable_0() {
    test_round_trip(EXECUTABLE, 0);
}
#[test]
fn round_trip_executable_1() {
    test_round_trip(EXECUTABLE, 1);
}
#[test]
fn round_trip_executable_2() {
    test_round_trip(EXECUTABLE, 2);
}
#[test]
fn round_trip_executable_3() {
    test_round_trip(EXECUTABLE, 3);
}
#[test]
fn round_trip_executable_4() {
    test_round_trip(EXECUTABLE, 4);
}
#[test]
fn round_trip_executable_5() {
    test_round_trip(EXECUTABLE, 5);
}
#[test]
fn round_trip_executable_6() {
    test_round_trip(EXECUTABLE, 6);
}
#[test]
fn round_trip_executable_7() {
    test_round_trip(EXECUTABLE, 7);
}
#[test]
fn round_trip_executable_8() {
    test_round_trip(EXECUTABLE, 8);
}
#[test]
fn round_trip_executable_9() {
    test_round_trip(EXECUTABLE, 9);
}

#[test]
fn round_trip_pg100_0() {
    test_round_trip(PG100, 0);
}
#[test]
fn round_trip_pg100_1() {
    test_round_trip(PG100, 1);
}
#[test]
fn round_trip_pg100_2() {
    test_round_trip(PG100, 2);
}
#[test]
fn round_trip_pg100_3() {
    test_round_trip(PG100, 3);
}
#[test]
fn round_trip_pg100_4() {
    test_round_trip(PG100, 4);
}
#[test]
fn round_trip_pg100_5() {
    test_round_trip(PG100, 5);
}
#[test]
fn round_trip_pg100_6() {
    test_round_trip(PG100, 6);
}
#[test]
fn round_trip_pg100_7() {
    test_round_trip(PG100, 7);
}
#[test]
fn round_trip_pg100_8() {
    test_round_trip(PG100, 8);
}
#[test]
fn round_trip_pg100_9() {
    test_round_trip(PG100, 9);
}

#[test]
fn round_trip_pg6800_0() {
    test_round_trip(PG6800, 0);
}
#[test]
fn round_trip_pg6800_1() {
    test_round_trip(PG6800, 1);
}
#[test]
fn round_trip_pg6800_2() {
    test_round_trip(PG6800, 2);
}
#[test]
fn round_trip_pg6800_3() {
    test_round_trip(PG6800, 3);
}
#[test]
fn round_trip_pg6800_4() {
    test_round_trip(PG6800, 4);
}
#[test]
fn round_trip_pg6800_5() {
    test_round_trip(PG6800, 5);
}
#[test]
fn round_trip_pg6800_6() {
    test_round_trip(PG6800, 6);
}
#[test]
fn round_trip_pg6800_7() {
    test_round_trip(PG6800, 7);
}
#[test]
fn round_trip_pg6800_8() {
    test_round_trip(PG6800, 8);
}
#[test]
fn round_trip_pg6800_9() {
    test_round_trip(PG6800, 9);
}

#[test]
fn cross_compat_with_reader() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    let opts = Lzma2Options::with_preset(3);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let compressed = writer.finish().unwrap();

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut decompressed_stream = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;
    loop {
        let action = if in_pos >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&compressed[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        decompressed_stream.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }

    let mut reader = lzma_rust2::Lzma2Reader::new(compressed.as_slice(), dict_size, None);
    let mut decompressed_reader = Vec::new();
    reader.read_to_end(&mut decompressed_reader).unwrap();

    assert_eq!(decompressed_stream, decompressed_reader);
    assert!(decompressed_stream == data);
}

#[test]
fn zero_length_output_buffer() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    let opts = Lzma2Options::with_preset(1);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let compressed = writer.finish().unwrap();

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut output_buf = [0u8; 0];
    let result = decoder
        .process(&compressed, &mut output_buf, Action::Run)
        .unwrap();
    assert_eq!(result.bytes_produced, 0);
}

#[test]
fn error_on_corrupted_payload() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    let opts = Lzma2Options::with_preset(1);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let mut compressed = writer.finish().unwrap();

    let mid = compressed.len() / 2;
    compressed[mid] ^= 0xFF;

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    let mut errored = false;
    for _ in 0..1000 {
        let action = if in_pos >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };
        match decoder.process(&compressed[in_pos..], &mut output_buf, action) {
            Ok(result) => {
                in_pos += result.bytes_consumed;
                if result.status == Status::StreamEnd {
                    break;
                }
            }
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    assert!(errored, "Expected error on corrupted payload");
}

#[test]
fn process_after_stream_end() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    let opts = Lzma2Options::with_preset(1);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let compressed = writer.finish().unwrap();

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    loop {
        let action = if in_pos >= compressed.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&compressed[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        if result.status == Status::StreamEnd {
            break;
        }
    }

    let result = decoder.process(&[], &mut output_buf, Action::Finish);
    match result {
        Ok(r) => {
            assert_eq!(r.bytes_consumed, 0);
            assert_eq!(r.bytes_produced, 0);
        }
        Err(_) => {}
    }
}

#[test]
fn incomplete_chunk_produces_error() {
    let data = std::fs::read(INPUT_HTML).unwrap();

    let opts = Lzma2Options::with_preset(6);
    let dict_size = opts.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), opts);
    writer.write_all(&data).unwrap();
    let compressed = writer.finish().unwrap();

    let truncated = &compressed[..compressed.len() / 2];

    let mut decoder = Lzma2Stream::new(dict_size);
    let mut output_buf = [0u8; 4096];

    let mut in_pos = 0;
    let mut errored = false;
    for _ in 0..100 {
        let action = if in_pos >= truncated.len() {
            Action::Finish
        } else {
            Action::Run
        };
        match decoder.process(&truncated[in_pos..], &mut output_buf, action) {
            Ok(result) => {
                in_pos += result.bytes_consumed;
                if result.status == Status::StreamEnd {
                    break;
                }
            }
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    assert!(errored, "Expected error on truncated LZMA2 stream");
}

/// Regression test for issue 1: uncompressed LZMA2 chunks that exceed
/// the LZ dictionary buffer capacity must not silently drop bytes.
/// Uses a tiny dict size (4096) to force the LZ buffer to fill mid-chunk.
#[test]
fn uncompressed_chunk_exceeds_dict() {
    let data_len: usize = 8192;
    let original: Vec<u8> = (0..data_len).map(|i| (i % 251) as u8).collect();

    let mut lzma2_stream: Vec<u8> = Vec::new();
    let mut offset = 0;
    while offset < data_len {
        let chunk = (data_len - offset).min(65535);
        let control = if offset == 0 { 0x01u8 } else { 0x02u8 };
        lzma2_stream.push(control);
        let size_minus_one = (chunk - 1) as u16;
        lzma2_stream.extend_from_slice(&size_minus_one.to_be_bytes());
        lzma2_stream.extend_from_slice(&original[offset..offset + chunk]);
        offset += chunk;
    }
    lzma2_stream.push(0x00);

    let dict_size: u32 = 4096;
    let mut decoder = Lzma2Stream::new(dict_size);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    loop {
        let action = if in_pos >= lzma2_stream.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&lzma2_stream[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(decompressed.len(), original.len());
    assert_eq!(decompressed, original);
}
