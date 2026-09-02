use std::{
    io::{Cursor, Read, Write},
    num::NonZeroU64,
};

use lzma_rust2::{
    LzipOptions, LzipReaderMt, LzipWriter, Lzma2Options, Lzma2ReaderMt, Lzma2Writer, XzOptions,
    XzReaderMt, XzWriter,
};

static EXECUTABLE: &str = "tests/data/executable.exe";
const LEVEL: u32 = 3;

#[test]
fn multi_writer_lzma2() {
    let data = std::fs::read(EXECUTABLE).unwrap();

    let mut option = Lzma2Options::with_preset(LEVEL);
    let dict_size = option.lzma_options.dict_size;
    option.set_chunk_size(NonZeroU64::new(dict_size as u64));

    let mut compressed = Vec::new();

    {
        let mut writer = Lzma2Writer::new(&mut compressed, option);
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
    }

    let mut uncompressed = Vec::new();

    {
        let mut reader = Lzma2ReaderMt::new(Cursor::new(compressed), dict_size, None, 1);
        reader.read_to_end(&mut uncompressed).unwrap();
        assert!(reader.chunk_count() > 1);
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == data);
}

#[test]
fn multi_writer_lzip2() {
    let data = std::fs::read(EXECUTABLE).unwrap();

    let mut option = LzipOptions::with_preset(LEVEL);
    let dict_size = option.lzma_options.dict_size;
    option.set_member_size(NonZeroU64::new(dict_size as u64));

    let mut compressed = Vec::new();

    {
        let mut writer = LzipWriter::new(&mut compressed, option);
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
    }

    let mut uncompressed = Vec::new();

    {
        let mut reader = LzipReaderMt::new(Cursor::new(compressed), 1).unwrap();
        reader.read_to_end(&mut uncompressed).unwrap();
        assert!(reader.member_count() > 1);
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == data);
}

#[test]
fn multi_writer_xz() {
    let data = std::fs::read(EXECUTABLE).unwrap();

    let mut option = XzOptions::with_preset(LEVEL);
    let dict_size = option.lzma_options.dict_size;
    option.set_block_size(NonZeroU64::new(dict_size as u64));

    let mut compressed = Vec::new();

    {
        let mut writer = XzWriter::new(&mut compressed, option).unwrap();
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
    }

    let mut uncompressed = Vec::new();

    {
        let mut reader = XzReaderMt::new(Cursor::new(compressed), false, 1).unwrap();
        reader.read_to_end(&mut uncompressed).unwrap();
        assert!(reader.block_count() > 1);
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == data);
}
