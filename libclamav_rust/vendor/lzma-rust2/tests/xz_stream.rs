use std::io::{Read, Write};

use lzma_rust2::{Action, Status, XzOptions, XzStream, XzWriter};

static EXECUTABLE: &str = "tests/data/executable.exe";
static PG100: &str = "tests/data/pg100.txt";
static PG6800: &str = "tests/data/pg6800.txt";
static INPUT_HTML: &str = "tests/data/input.html";

fn encode_xz(data: &[u8], preset: u32) -> Vec<u8> {
    let options = XzOptions::with_preset(preset);
    let mut writer = XzWriter::new(Vec::new(), options).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap()
}

fn decode_with_stream(data: &[u8]) -> Vec<u8> {
    let mut decoder = XzStream::new(false);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    loop {
        let action = if in_pos >= data.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&data[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }
    decompressed
}

fn test_round_trip(path: &str, preset: u32) {
    let data = std::fs::read(path).unwrap();
    let compressed = encode_xz(&data, preset);
    let decompressed = decode_with_stream(&compressed);
    assert!(decompressed == data);

    let mut liblzma_decompressed = Vec::new();
    {
        use liblzma::read::XzDecoder;
        let mut decoder = XzDecoder::new(compressed.as_slice());
        decoder.read_to_end(&mut liblzma_decompressed).unwrap();
    }
    assert!(liblzma_decompressed == data);
}

#[test]
fn round_trip_empty() {
    let compressed = encode_xz(b"", 6);
    let decompressed = decode_with_stream(&compressed);
    assert!(decompressed.is_empty());
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
fn decode_tiny_output_buffer() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = encode_xz(&data, 6);

    let mut decoder = XzStream::new(false);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 1];
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
    assert_eq!(decoder.total_out(), data.len() as u64);
    assert_eq!(decoder.total_in(), compressed.len() as u64);
}

#[test]
fn cross_compat_with_xzreader() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = encode_xz(&data, 6);

    let stream_result = decode_with_stream(&compressed);

    let mut reader = lzma_rust2::XzReader::new(compressed.as_slice(), false);
    let mut reader_result = Vec::new();
    reader.read_to_end(&mut reader_result).unwrap();

    assert_eq!(stream_result, reader_result);
    assert!(stream_result == data);
}

#[test]
fn decoder_total_tracking() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = encode_xz(&data, 6);

    let mut decoder = XzStream::new(false);
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;
    let mut total_produced = 0;

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
        total_produced += result.bytes_produced;
        if result.status == Status::StreamEnd {
            break;
        }
    }

    assert_eq!(decoder.total_in(), compressed.len() as u64);
    assert_eq!(decoder.total_out(), data.len() as u64);
    assert_eq!(total_produced, data.len());
}

#[test]
fn concatenated_streams() {
    let data_a = std::fs::read(INPUT_HTML).unwrap();
    let data_b = b"Second stream payload.";

    let mut concatenated = encode_xz(&data_a, 6);
    concatenated.extend_from_slice(&encode_xz(data_b, 3));

    let mut decoder = XzStream::new(true);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    loop {
        let action = if in_pos >= concatenated.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&concatenated[in_pos..], &mut output_buf, action)
            .unwrap();
        in_pos += result.bytes_consumed;
        decompressed.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            break;
        }
    }

    let mut expected = data_a.clone();
    expected.extend_from_slice(data_b);
    assert!(decompressed == expected);
}

#[test]
fn zero_length_output_buffer() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = encode_xz(&data, 1);

    let mut decoder = XzStream::new(false);
    let mut output_buf = [0u8; 0];
    let result = decoder
        .process(&compressed, &mut output_buf, Action::Run)
        .unwrap();
    assert_eq!(result.bytes_produced, 0);
}

#[test]
fn error_on_corrupted_payload() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let mut compressed = encode_xz(&data, 1);
    let mid = compressed.len() / 2;
    compressed[mid] ^= 0xFF;

    let mut decoder = XzStream::new(false);
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
    let compressed = encode_xz(&data, 1);
    let mut decoder = XzStream::new(false);
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
fn error_on_corrupted_magic() {
    let mut compressed = encode_xz(b"test", 1);
    compressed[0] = 0xFF;

    let mut decoder = XzStream::new(false);
    let mut output_buf = [0u8; 4096];
    let result = decoder.process(&compressed, &mut output_buf, Action::Run);
    assert!(result.is_err());
}

#[test]
fn error_on_truncated_input() {
    let data = std::fs::read(INPUT_HTML).unwrap();
    let compressed = encode_xz(&data, 1);
    let truncated = &compressed[..compressed.len() / 2];

    let mut decoder = XzStream::new(false);
    let mut output_buf = [0u8; 4096];
    let mut in_pos = 0;

    let mut errored = false;
    for _ in 0..1000 {
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
                if in_pos >= truncated.len()
                    && result.bytes_consumed == 0
                    && result.bytes_produced == 0
                {
                    match decoder.process(&[], &mut output_buf, Action::Finish) {
                        Ok(_) => break,
                        Err(_) => {
                            errored = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    assert!(errored, "Expected error on truncated input");
}

fn decode_bcj_xz(compressed_path: &str, original_path: &str) {
    let compressed = std::fs::read(compressed_path).unwrap();
    let original = std::fs::read(original_path).unwrap();

    let mut decoder = XzStream::new(false);
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
    assert_eq!(decompressed.len(), original.len());
    assert!(decompressed == original);
}

#[test]
fn decode_bcj_x86() {
    decode_bcj_xz("tests/data/wget-x86.xz", "tests/data/wget-x86");
}

#[test]
fn decode_bcj_arm() {
    decode_bcj_xz("tests/data/wget-arm.xz", "tests/data/wget-arm");
}

#[test]
fn decode_bcj_arm64() {
    decode_bcj_xz("tests/data/wget-arm64.xz", "tests/data/wget-arm64");
}

#[test]
fn decode_bcj_arm_thumb() {
    decode_bcj_xz("tests/data/wget-arm-thumb.xz", "tests/data/wget-arm-thumb");
}

#[test]
fn decode_bcj_ia64() {
    decode_bcj_xz("tests/data/wget-ia64.xz", "tests/data/wget-ia64");
}

#[test]
fn decode_bcj_ppc() {
    decode_bcj_xz("tests/data/wget-ppc.xz", "tests/data/wget-ppc");
}

#[test]
fn decode_bcj_sparc() {
    decode_bcj_xz("tests/data/wget-sparc.xz", "tests/data/wget-sparc");
}

#[test]
fn decode_bcj_riscv() {
    decode_bcj_xz("tests/data/wget-riscv.xz", "tests/data/wget-riscv");
}

#[test]
fn decode_bcj_x86_byte_at_a_time() {
    let compressed = std::fs::read("tests/data/wget-x86.xz").unwrap();
    let original = std::fs::read("tests/data/wget-x86").unwrap();

    let mut decoder = XzStream::new(false);
    let mut decompressed = Vec::new();
    let mut output_buf = [0u8; 4096];
    let mut ci = 0;

    while ci < compressed.len() {
        let action = if ci == compressed.len() - 1 {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder
            .process(&compressed[ci..ci + 1], &mut output_buf, action)
            .unwrap();
        decompressed.extend_from_slice(&output_buf[..result.bytes_produced]);
        if result.bytes_consumed == 0 {
            continue;
        }
        ci += result.bytes_consumed;
        if result.status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(decompressed.len(), original.len());
    assert!(decompressed == original);
}
