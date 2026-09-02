use std::io::{Read, Write};

use liblzma::{bufread::*, stream};
use lzma_rust2::{Lzma2Options, Lzma2Writer, LzmaOptions, LzmaWriter};

fn compress_liblzma_lzma1(level: u32, data: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    let options = stream::LzmaOptions::new_preset(level).unwrap();
    let stream = stream::Stream::new_lzma_encoder(&options).unwrap();
    let mut encoder = XzEncoder::new_stream(data, stream);
    encoder.read_to_end(&mut compressed).unwrap();
    compressed
}

fn compress_lzmarust2_lzma1(level: u32, data: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    let options = LzmaOptions::with_preset(level);
    let mut writer = LzmaWriter::new_no_header(&mut compressed, &options, true).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    compressed
}

fn compress_liblzma_lzma2(level: u32, data: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    let stream = stream::Stream::new_easy_encoder(level, stream::Check::None).unwrap();
    let mut encoder = XzEncoder::new_stream(data, stream);
    encoder.read_to_end(&mut compressed).unwrap();
    compressed
}

fn compress_lzmarust2_lzma2(level: u32, data: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    let options = Lzma2Options::with_preset(level);
    let mut writer = Lzma2Writer::new(&mut compressed, options);
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    compressed
}

fn compare_compression_sizes(data: &[u8]) {
    println!("\nComparing compression sizes against liblzma (baseline)");
    println!("Original data size: {} bytes", data.len());
    println!("{:-<80}", "");
    println!(
        "{:<6} | {:<8} | {:<18} | {:<20} | {:<18}",
        "Level", "Algo", "liblzma (bytes)", "lzma-rust2 (bytes)", "Size Difference (%)"
    );
    println!("{:-<80}", "");

    for level in 0..=9 {
        let liblzma_compressed = compress_liblzma_lzma1(level, data);
        let lzmarust2_compressed = compress_lzmarust2_lzma1(level, data);

        let liblzma_size = liblzma_compressed.len();
        let lzmarust2_size = lzmarust2_compressed.len();

        let diff_percent = (lzmarust2_size as f64 / liblzma_size as f64 - 1.0) * 100.0;

        println!(
            "{:<6} | {:<8} | {:<18} | {:<20} | {:>+17.2}%",
            level, "LZMA", liblzma_size, lzmarust2_size, diff_percent
        );
    }

    println!("{:-<80}", "");

    for level in 0..=9 {
        let liblzma_compressed = compress_liblzma_lzma2(level, data);
        let lzmarust2_compressed = compress_lzmarust2_lzma2(level, data);

        let liblzma_size = liblzma_compressed.len();
        let lzmarust2_size = lzmarust2_compressed.len();

        let diff_percent = (lzmarust2_size as f64 / liblzma_size as f64 - 1.0) * 100.0;

        println!(
            "{:<6} | {:<8} | {:<18} | {:<20} | {:>+17.2}%",
            level, "LZMA2", liblzma_size, lzmarust2_size, diff_percent
        );
    }
    println!("{:-<80}", "");
}

#[test]
#[ignore]
fn compare_executable() {
    let data = std::fs::read("tests/data/executable.exe").unwrap();
    compare_compression_sizes(data.as_slice())
}

#[test]
#[ignore]
fn compare_pg100() {
    let data = std::fs::read("tests/data/pg100.txt").unwrap();
    compare_compression_sizes(data.as_slice())
}

#[test]
#[ignore]
fn compare_pg6800() {
    let data = std::fs::read("tests/data/pg6800.txt").unwrap();
    compare_compression_sizes(data.as_slice())
}
