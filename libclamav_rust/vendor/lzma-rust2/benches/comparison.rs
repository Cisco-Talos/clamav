use std::{
    hint::black_box,
    io::{Cursor, Read, Write},
    num::NonZeroU64,
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use liblzma::{bufread::*, stream};
use lzma_rust2::{
    LzipOptions, LzipReaderMt, LzipWriter, LzipWriterMt, Lzma2Options, Lzma2Reader, Lzma2ReaderMt,
    Lzma2Writer, Lzma2WriterMt, LzmaOptions, LzmaReader, LzmaWriter, XzOptions, XzReaderMt,
    XzWriter, XzWriterMt,
};

static TEST_DATA: &[u8] = include_bytes!("../tests/data/executable.exe");

fn bench_compression_lzma(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression lzma");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(25);

    for level in 0..=9 {
        group.bench_with_input(
            BenchmarkId::new("lzma-rust2", level),
            &level,
            |b, &level| {
                let option = LzmaOptions::with_preset(level);

                b.iter(|| {
                    let mut compressed = Vec::new();
                    let mut writer =
                        LzmaWriter::new_no_header(black_box(&mut compressed), &option, true)
                            .unwrap();
                    writer.write_all(black_box(TEST_DATA)).unwrap();
                    writer.finish().unwrap();
                    black_box(compressed)
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("liblzma", level), &level, |b, &level| {
            let option = stream::LzmaOptions::new_preset(level).unwrap();
            b.iter(|| {
                let mut compressed = Vec::new();
                let stream = stream::Stream::new_lzma_encoder(&option).unwrap();
                let mut encoder = XzEncoder::new_stream(black_box(TEST_DATA), stream);
                encoder.read_to_end(black_box(&mut compressed)).unwrap();
                black_box(compressed)
            });
        });
    }

    group.finish();
}

fn bench_compression_lzma2(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression lzma2");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(25);

    for level in 0..=9 {
        group.bench_with_input(
            BenchmarkId::new("lzma-rust2", level),
            &level,
            |b, &level| {
                b.iter(|| {
                    let mut compressed = Vec::new();
                    let option = Lzma2Options::with_preset(level);
                    let mut writer = Lzma2Writer::new(black_box(&mut compressed), option);
                    writer.write_all(black_box(TEST_DATA)).unwrap();
                    writer.finish().unwrap();
                    black_box(compressed)
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("liblzma", level), &level, |b, &level| {
            b.iter(|| {
                let mut compressed = Vec::new();
                let stream = stream::Stream::new_easy_encoder(level, stream::Check::None).unwrap();
                let mut encoder = XzEncoder::new_stream(black_box(TEST_DATA), stream);
                encoder.read_to_end(black_box(&mut compressed)).unwrap();
                black_box(compressed)
            });
        });
    }

    group.finish();
}

fn bench_decompression_lzma(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression lzma");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(100);

    let mut lzma_data = Vec::new();
    let mut liblzma_data = Vec::new();

    for level in 0..=9 {
        {
            let option = LzmaOptions::with_preset(level);
            let mut compressed = Vec::new();
            let mut writer = LzmaWriter::new_no_header(&mut compressed, &option, true).unwrap();
            writer.write_all(TEST_DATA).unwrap();
            writer.finish().unwrap();
            lzma_data.push((compressed, option));
        }

        {
            let option = stream::LzmaOptions::new_preset(level).unwrap();
            let mut compressed = Vec::new();
            let stream = stream::Stream::new_lzma_encoder(&option).unwrap();
            let mut encoder = XzEncoder::new_stream(TEST_DATA, stream);
            encoder.read_to_end(black_box(&mut compressed)).unwrap();
            liblzma_data.push(compressed);
        }
    }

    for level in 0..=9 {
        group.bench_with_input(
            BenchmarkId::new("lzma-rust2", level),
            &lzma_data[level],
            |b, (compressed, option)| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let mut reader = LzmaReader::new(
                        black_box(compressed.as_slice()),
                        TEST_DATA.len() as u64,
                        option.lc,
                        option.lp,
                        option.pb,
                        option.dict_size,
                        option.preset_dict.as_ref().map(|dict| dict.as_ref()),
                    )
                    .unwrap();
                    reader.read_to_end(black_box(&mut uncompressed)).unwrap();
                    black_box(uncompressed)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("liblzma", level),
            &liblzma_data[level],
            |b, compressed| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let stream = stream::Stream::new_lzma_decoder(256 * 1024 * 1024).unwrap();
                    let mut r = XzDecoder::new_stream(black_box(compressed.as_slice()), stream);
                    r.read_to_end(black_box(&mut uncompressed)).unwrap();
                    black_box(uncompressed)
                });
            },
        );
    }

    group.finish();
}

fn bench_decompression_lzma2(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression lzma2");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(100);

    let mut lzma2_data = Vec::new();
    let mut liblzma_data = Vec::new();

    for level in 0..=9 {
        let option = Lzma2Options::with_preset(level);
        {
            let mut compressed = Vec::new();
            let mut writer = Lzma2Writer::new(&mut compressed, option.clone());
            writer.write_all(TEST_DATA).unwrap();
            writer.finish().unwrap();
            lzma2_data.push((compressed, option));
        }

        {
            let mut compressed = Vec::new();
            let stream = stream::Stream::new_easy_encoder(level, stream::Check::None).unwrap();
            let mut encoder = XzEncoder::new_stream(TEST_DATA, stream);
            encoder.read_to_end(black_box(&mut compressed)).unwrap();
            liblzma_data.push(compressed);
        }
    }

    for level in 0..=9 {
        group.bench_with_input(
            BenchmarkId::new("lzma-rust2", level),
            &lzma2_data[level],
            |b, (compressed, option)| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let mut reader = Lzma2Reader::new(
                        black_box(compressed.as_slice()),
                        option.lzma_options.dict_size,
                        None,
                    );
                    reader.read_to_end(black_box(&mut uncompressed)).unwrap();
                    black_box(uncompressed)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("liblzma", level),
            &liblzma_data[level],
            |b, compressed| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let mut r = XzDecoder::new(black_box(compressed.as_slice()));
                    r.read_to_end(black_box(&mut uncompressed)).unwrap();
                    black_box(uncompressed)
                });
            },
        );
    }

    group.finish();
}

fn bench_compression_mt(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression mt");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(25);

    let num_workers = std::thread::available_parallelism().unwrap().get() as u32;

    group.bench_function(BenchmarkId::new("lzma2", 3), |b| {
        let mut option = Lzma2Options::with_preset(3);
        option.set_chunk_size(NonZeroU64::new(option.lzma_options.dict_size as u64));

        b.iter(|| {
            let mut compressed = Vec::new();
            let mut writer =
                Lzma2WriterMt::new(black_box(&mut compressed), option.clone(), num_workers)
                    .unwrap();
            writer.write_all(black_box(TEST_DATA)).unwrap();
            writer.finish().unwrap();
            black_box(compressed)
        });
    });

    group.bench_function(BenchmarkId::new("lzip", 3), |b| {
        let mut option = LzipOptions::with_preset(3);
        option.set_member_size(NonZeroU64::new(option.lzma_options.dict_size as u64));

        b.iter(|| {
            let mut compressed = Vec::new();
            let mut writer =
                LzipWriterMt::new(black_box(&mut compressed), option.clone(), num_workers).unwrap();
            writer.write_all(black_box(TEST_DATA)).unwrap();
            writer.finish().unwrap();
            black_box(compressed)
        });
    });

    group.bench_function(BenchmarkId::new("xz", 3), |b| {
        let mut option = XzOptions::with_preset(3);
        option.set_block_size(NonZeroU64::new(option.lzma_options.dict_size as u64));

        b.iter(|| {
            let mut compressed = Vec::new();
            let mut writer =
                XzWriterMt::new(black_box(&mut compressed), option.clone(), num_workers).unwrap();
            writer.write_all(black_box(TEST_DATA)).unwrap();
            writer.finish().unwrap();
            black_box(compressed)
        });
    });

    group.finish();
}

fn bench_decompression_mt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression mt");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(100);

    let num_workers = std::thread::available_parallelism().unwrap().get() as u32;

    let mut lzma2_option = Lzma2Options::with_preset(3);
    lzma2_option.set_chunk_size(NonZeroU64::new(lzma2_option.lzma_options.dict_size as u64));
    let mut lzma2_data = Vec::new();
    let mut writer = Lzma2Writer::new(&mut lzma2_data, lzma2_option.clone());
    writer.write_all(TEST_DATA).unwrap();
    writer.finish().unwrap();

    let mut lzip_option = LzipOptions::with_preset(3);
    lzip_option.set_member_size(NonZeroU64::new(lzip_option.lzma_options.dict_size as u64));
    let mut lzip_data = Vec::new();
    let mut writer = LzipWriter::new(&mut lzip_data, lzip_option.clone());
    writer.write_all(TEST_DATA).unwrap();
    writer.finish().unwrap();

    let mut xz_option = XzOptions::with_preset(3);
    xz_option.set_block_size(NonZeroU64::new(xz_option.lzma_options.dict_size as u64));
    let mut xz_data = Vec::new();
    let mut writer = XzWriter::new(&mut xz_data, xz_option.clone()).unwrap();
    writer.write_all(TEST_DATA).unwrap();
    writer.finish().unwrap();

    group.bench_function(BenchmarkId::new("lzma2", 3), |b| {
        b.iter(|| {
            let mut uncompressed = Vec::new();
            let mut reader = Lzma2ReaderMt::new(
                black_box(lzma2_data.as_slice()),
                lzma2_option.lzma_options.dict_size,
                None,
                num_workers,
            );
            reader.read_to_end(black_box(&mut uncompressed)).unwrap();
            black_box(uncompressed)
        });
    });

    group.bench_function(BenchmarkId::new("lzip", 3), |b| {
        b.iter(|| {
            let mut uncompressed = Vec::new();
            let mut reader =
                LzipReaderMt::new(black_box(Cursor::new(lzip_data.as_slice())), num_workers)
                    .unwrap();
            reader.read_to_end(black_box(&mut uncompressed)).unwrap();
            black_box(uncompressed)
        });
    });

    group.bench_function(BenchmarkId::new("xz", 3), |b| {
        b.iter(|| {
            let mut uncompressed = Vec::new();
            let mut reader = XzReaderMt::new(
                black_box(Cursor::new(xz_data.as_slice())),
                false,
                num_workers,
            )
            .unwrap();
            reader.read_to_end(black_box(&mut uncompressed)).unwrap();
            black_box(uncompressed)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_compression_lzma,
    bench_compression_lzma2,
    bench_compression_mt,
    bench_decompression_lzma,
    bench_decompression_lzma2,
    bench_decompression_mt,
);
criterion_main!(benches);
