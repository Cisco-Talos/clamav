use std::io::{Read, Seek, SeekFrom, Write};

use lzma_rust2::{
    LzipOptions, LzipReaderMt, LzipWriter, Lzma2Options, Lzma2Reader, Lzma2ReaderMt, Lzma2Writer,
    LzmaOptions, LzmaReader, LzmaWriter, XzReader, XzReaderMt,
};

fn regression_lzma2_reader_mt(input_data: &[u8], expected_output: &[u8], dict_size: u32) {
    let mut uncompressed = Vec::new();

    {
        let mut reader = Lzma2ReaderMt::new(input_data, dict_size, None, 1);
        reader.read_to_end(&mut uncompressed).unwrap();
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == expected_output);
}

/// Issue: Decompressing: Corrupted input data (LZMA2:0)
///
/// https://github.com/hasenbanck/sevenz-rust2/issues/44
#[test]
fn issue_44_7z() {
    let input = std::fs::read("tests/data/issue_44_7z.lzma2").unwrap();
    let output = std::fs::read("tests/data/issue_44_7z.bin").unwrap();
    regression_lzma2_reader_mt(input.as_slice(), output.as_slice(), 8388608);
}

fn regression_xz_reader(input_data: &[u8], expected_output: &[u8]) {
    let mut uncompressed = Vec::new();

    {
        let mut reader = XzReader::new(input_data, true);
        reader.read_to_end(&mut uncompressed).unwrap();
    }

    // We don't use assert_eq since the debug output would be too big.
    assert!(uncompressed.as_slice() == expected_output);
}

/// Issue: Can't read XZ with multiple streams
///
/// https://github.com/hasenbanck/lzma-rust2/issues/56
#[test]
fn issue_56() {
    let input = std::fs::read("tests/data/issue_56.xz").unwrap();
    let output = [b'O', b'n', b'e', b'\n', b'T', b'w', b'o', b'\n'];
    regression_xz_reader(input.as_slice(), output.as_slice());
}

/// Issue: lzma2_reader overflow-checks (attempt to add with overflow)
///
/// https://github.com/hasenbanck/lzma-rust2/issues/64
#[test]
fn issue_64() {
    let input = std::fs::read("tests/data/issue_64.bin").unwrap();

    let option = Lzma2Options::with_preset(0);
    let dict_size = option.lzma_options.dict_size;

    let mut uncompressed = Vec::new();

    let mut reader = Lzma2Reader::new(input.as_slice(), dict_size, None);
    let _ = reader.read_to_end(&mut uncompressed);
}

/// Issue: LZMA roundtrip fails with "dist overflow" when using preset dictionary
///
/// https://github.com/hasenbanck/lzma-rust2/issues/94
#[test]
fn issue_94() {
    let dict = b"section></summary><div class=</a></li".to_vec();
    let data = std::fs::read("tests/data/input.html").unwrap();

    let options = {
        let mut options = LzmaOptions::with_preset(9);
        options.preset_dict = Some(dict.clone());
        options
    };

    let output = std::io::Cursor::new(Vec::new());
    let mut encoder = LzmaWriter::new_no_header(output, &options, false).unwrap();
    std::io::copy(&mut std::io::Cursor::new(data.clone()), &mut encoder).unwrap();
    let compressed = encoder.finish().unwrap().into_inner();
    println!("Encode OK");

    let mut out = std::io::Cursor::new(Vec::new());
    let mut decoder = LzmaReader::new_with_props(
        compressed.as_slice(),
        data.len() as u64,
        options.get_props(),
        options.dict_size,
        options.preset_dict.as_deref(),
    )
    .unwrap();
    std::io::copy(&mut decoder, &mut out).unwrap();
    let decompressed = out.into_inner();
    println!("Decode OK");

    // We don't use assert_eq since the debug output would be too big.
    assert!(decompressed.as_slice() == data);
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn encode_multibyte(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// A crafted single-block XZ stream whose index declares a `unpadded_size` far
/// larger than the file. The multi-threaded reader must reject it instead of
/// trying to allocate a buffer of that size.
fn xz_with_huge_index_record(unpadded_size: u64) -> Vec<u8> {
    let mut stream = Vec::new();

    stream.extend_from_slice(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]);
    let stream_flags = [0u8, 0u8];
    stream.extend_from_slice(&stream_flags);
    stream.extend_from_slice(&crc32(&stream_flags).to_le_bytes());

    let mut index_body = vec![0x00];
    index_body.extend_from_slice(&encode_multibyte(1));
    index_body.extend_from_slice(&encode_multibyte(unpadded_size));
    index_body.extend_from_slice(&encode_multibyte(0));
    while index_body.len() % 4 != 0 {
        index_body.push(0);
    }
    let index_crc = crc32(&index_body);

    let index_size = index_body.len() + 4;
    let backward_size = (index_size / 4 - 1) as u32;

    stream.extend_from_slice(&index_body);
    stream.extend_from_slice(&index_crc.to_le_bytes());

    let mut footer_crc_input = Vec::new();
    footer_crc_input.extend_from_slice(&backward_size.to_le_bytes());
    footer_crc_input.extend_from_slice(&stream_flags);
    stream.extend_from_slice(&crc32(&footer_crc_input).to_le_bytes());
    stream.extend_from_slice(&backward_size.to_le_bytes());
    stream.extend_from_slice(&stream_flags);
    stream.extend_from_slice(b"YZ");

    stream
}

/// Malicious XZ where the index claims a 2^60-byte block. Previously the
/// multi-threaded reader did `vec![0u8; unpadded_size]` and aborted with OOM.
#[test]
fn xz_mt_huge_index_record_does_not_oom() {
    let input = xz_with_huge_index_record(1 << 60);

    let mut reader = XzReaderMt::new(std::io::Cursor::new(input), false, 2).unwrap();
    let mut output = Vec::new();
    assert!(reader.read_to_end(&mut output).is_err());
}

struct FaultyReader {
    inner: std::io::Cursor<Vec<u8>>,
    armed: bool,
}

impl Read for FaultyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.armed && buf.len() > 24 {
            return Err(std::io::Error::other("injected read failure"));
        }
        self.inner.read(buf)
    }
}

impl Seek for FaultyReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// An I/O error while the multi-threaded LZIP reader fetches a member must
/// surface as an error instead of panicking a `.unwrap()`.
#[test]
fn lzip_mt_read_error_does_not_panic() {
    let mut compressed = Vec::new();
    {
        let mut writer = LzipWriter::new(&mut compressed, LzipOptions::with_preset(6));
        writer.write_all(b"hello lzip multithreaded world").unwrap();
        writer.finish().unwrap();
    }

    let reader = FaultyReader {
        inner: std::io::Cursor::new(compressed),
        armed: true,
    };

    let mut reader = LzipReaderMt::new(reader, 2).unwrap();
    let mut output = Vec::new();
    assert!(reader.read_to_end(&mut output).is_err());
}

const CHUNK_LEN: usize = 1 << 20;

fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Generates the ~2 GiB test input on the fly so that it never has to be
/// buffered: a long run of a single byte followed by a pseudo random tail.
///
/// The run is a single repeated byte on purpose. It leaves all but one hash slot
/// at `0`, which is exactly the state that normalization corrupts, and the
/// random tail then reaches those slots.
struct Input {
    filler_left: u64,
    tail_left: u64,
    state: u64,
}

impl Input {
    fn new(filler_len: u64, tail_len: u64) -> Self {
        Self {
            filler_left: filler_len,
            tail_left: tail_len,
            state: 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Writes the next bytes into `buf` and returns how many were produced.
    /// A chunk never straddles the filler / tail boundary, which keeps the
    /// output independent of how the chunks line up.
    fn next_chunk(&mut self, buf: &mut [u8]) -> usize {
        if self.filler_left > 0 {
            let len = (buf.len() as u64).min(self.filler_left) as usize;
            buf[..len].fill(b'A');
            self.filler_left -= len as u64;
            return len;
        }

        let len = (buf.len() as u64).min(self.tail_left) as usize;
        for chunk in buf[..len].chunks_mut(8) {
            let bytes = xorshift64(&mut self.state).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        self.tail_left -= len as u64;
        len
    }
}

/// Pushes enough data through a single stream to make the match finder
/// normalize its position tables, then feeds varied data so that the
/// normalized entries get looked up again.
fn regression_normalization(preset: u32) {
    let dict_size = LzmaOptions::with_preset(preset).dict_size;

    // Normalization fires at `lz_pos == 0x7FFFFFFF`, and `lz_pos` starts at
    // `dict_size + 1`.
    let filler_len = 0x7FFF_FFFF - dict_size as u64 - 1;
    let tail_len = 4 << 20;

    // The filler compresses down to almost nothing, so keeping the whole
    // compressed stream costs only about as much as the random tail.
    let mut compressed = Vec::new();
    let mut writer = Lzma2Writer::new(&mut compressed, Lzma2Options::with_preset(preset));

    let mut chunk = vec![0u8; CHUNK_LEN];
    let mut input = Input::new(filler_len, tail_len);
    loop {
        let len = input.next_chunk(&mut chunk);
        if len == 0 {
            break;
        }
        writer.write_all(&chunk[..len]).unwrap();
    }

    writer.finish().unwrap();

    // Silent corruption is just as bad as the panic, so decode the stream back
    // and compare it against a freshly generated copy of the input.
    let mut reader = Lzma2Reader::new(compressed.as_slice(), dict_size, None);
    let mut decoded = vec![0u8; CHUNK_LEN];
    let mut input = Input::new(filler_len, tail_len);
    let mut position = 0u64;
    loop {
        let len = input.next_chunk(&mut chunk);
        if len == 0 {
            break;
        }
        reader.read_exact(&mut decoded[..len]).unwrap();

        if decoded[..len] != chunk[..len] {
            let offset = (0..len).find(|&i| decoded[i] != chunk[i]).unwrap();
            panic!(
                "decoded byte at {} is {:#04X}, expected {:#04X}",
                position + offset as u64,
                decoded[offset],
                chunk[offset]
            );
        }
        position += len as u64;
    }

    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "{} trailing bytes decoded", rest.len());
}

/// Issue: Encoder: `normalize_scalar` leaves negative positions, causing an
/// out-of-bounds panic after ~2 GiB in one stream
///
/// https://github.com/hasenbanck/lzma-rust2/issues/107
///
/// Both tests are `#[ignore]`d because the encoder only normalizes after
/// `0x7FFFFFFF` positions, so there is no way to reach the bug without pushing
/// ~2 GiB through a single stream. Run them with:
///
/// ```text
/// cargo test --release --test regression -- --ignored issue_107
/// ```
#[test]
#[ignore = "pushes ~2 GiB through the encoder; run with --release"]
fn issue_107_hc4() {
    regression_normalization(0);
}

/// See [`issue_107_hc4`]. Preset 6 is the default and uses the Bt4 match
/// finder, which is what the issue was reported with. Before the fix this
/// panicked in `LzEncoderData::get_byte_backward` after about a minute.
#[test]
#[ignore = "pushes ~2 GiB through the encoder; run with --release"]
fn issue_107_bt4() {
    regression_normalization(6);
}
