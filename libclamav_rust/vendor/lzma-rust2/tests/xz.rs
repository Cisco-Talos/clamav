use std::io::{Read, Write};

use lzma_rust2::{XzOptions, XzReader, XzWriter};

static EXECUTABLE: &str = "tests/data/executable.exe";
static PG100: &str = "tests/data/pg100.txt";
static PG6800: &str = "tests/data/pg6800.txt";

fn test_round_trip(path: &str, level: u32) {
    let data = std::fs::read(path).unwrap();

    let option = XzOptions::with_preset(level);

    let mut compressed = Vec::new();

    {
        let mut writer = XzWriter::new(&mut compressed, option).unwrap();
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
    }

    // Test decompression with our own reader
    let mut uncompressed = Vec::new();
    {
        let mut reader = XzReader::new(compressed.as_slice(), false);
        reader.read_to_end(&mut uncompressed).unwrap();
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == data);

    // Also test decompression with liblzma to ensure compatibility
    let mut liblzma_uncompressed = Vec::new();
    {
        use liblzma::read::XzDecoder;
        let mut decoder = XzDecoder::new(compressed.as_slice());
        decoder.read_to_end(&mut liblzma_uncompressed).unwrap();
    }

    assert!(liblzma_uncompressed.as_slice() == data);
}

#[test]
fn empty_input_is_valid_empty_stream() {
    let encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(6)).unwrap();
    let compressed = encoder.finish().unwrap();

    let reference = {
        use liblzma::write::XzEncoder;

        let encoder = XzEncoder::new(Vec::new(), 6);
        encoder.finish().unwrap()
    };

    assert_eq!(compressed, reference);

    let mut uncompressed = Vec::new();
    let mut reader = XzReader::new(compressed.as_slice(), false);
    reader.read_to_end(&mut uncompressed).unwrap();
    assert!(uncompressed.is_empty());

    let mut liblzma_uncompressed = Vec::new();
    {
        use liblzma::read::XzDecoder;
        let mut decoder = XzDecoder::new(compressed.as_slice());
        decoder.read_to_end(&mut liblzma_uncompressed).unwrap();
    }
    assert!(liblzma_uncompressed.is_empty());
}

#[test]
fn small_writes_with_flush_round_trip() {
    let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(6)).unwrap();
    encoder.write_all(&[0]).unwrap();
    encoder.flush().unwrap();
    encoder.write_all(&[0]).unwrap();
    encoder.flush().unwrap();
    let compressed = encoder.finish().unwrap();

    let mut uncompressed = Vec::new();
    let mut reader = XzReader::new(compressed.as_slice(), false);
    reader.read_to_end(&mut uncompressed).unwrap();
    assert_eq!(uncompressed, [0, 0]);

    let mut liblzma_uncompressed = Vec::new();
    {
        use liblzma::read::XzDecoder;
        let mut decoder = XzDecoder::new(compressed.as_slice());
        decoder.read_to_end(&mut liblzma_uncompressed).unwrap();
    }
    assert_eq!(liblzma_uncompressed, [0, 0]);
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
