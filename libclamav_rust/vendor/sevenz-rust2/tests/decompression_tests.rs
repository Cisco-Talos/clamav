use std::fs::File;
#[cfg(feature = "util")]
use std::{
    fs::{read, read_to_string},
    path::PathBuf,
};

#[cfg(feature = "util")]
use sevenz_rust2::decompress_file;
use sevenz_rust2::{Archive, ArchiveReader, BlockDecoder, Password};
#[cfg(feature = "util")]
use tempfile::tempdir;

#[cfg(feature = "util")]
#[test]
fn decompress_single_empty_file_unencoded_header() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/single_empty_file.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("empty.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "");
}

#[cfg(feature = "util")]
#[test]
fn decompress_two_empty_files_unencoded_header() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/two_empty_file.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("file1.txt");
    let mut file2_path = target.clone();
    file2_path.push("file2.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "");
    assert_eq!(read_to_string(file2_path).unwrap(), "");
}

#[cfg(feature = "util")]
#[test]
fn decompress_lzma_single_file_unencoded_header() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/single_file_with_content_lzma.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("file.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "this is a file\n");
}

#[cfg(feature = "util")]
#[test]
fn decompress_lzma2_bcj_x86_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/decompress_example_lzma2_bcj_x86.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("decompress.exe");

    decompress_file(source_file, target).unwrap();

    let mut expected_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    expected_file.push("tests/resources/decompress_x86.exe");

    assert_eq!(
        read(file1_path).unwrap(),
        read(expected_file).unwrap(),
        "decompressed files do not match!"
    );
}

#[cfg(feature = "util")]
#[test]
fn decompress_bcj_arm64_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/decompress_example_bcj_arm64.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("decompress_arm64.exe");

    decompress_file(source_file, target).unwrap();

    let mut expected_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    expected_file.push("tests/resources/decompress_arm64.exe");

    assert_eq!(
        read(file1_path).unwrap(),
        read(expected_file).unwrap(),
        "decompressed files do not match!"
    );
}

#[cfg(feature = "util")]
#[test]
fn decompress_lzma_multiple_files_encoded_header() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/two_files_with_content_lzma.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("file1.txt");
    let mut file2_path = target.clone();
    file2_path.push("file2.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "file one content\n");
    assert_eq!(read_to_string(file2_path).unwrap(), "file two content\n");
}

#[cfg(feature = "util")]
#[test]
fn decompress_delta_lzma_single_file_unencoded_header() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/delta.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("delta.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "aaaabbbbcccc");
}

#[cfg(feature = "util")]
#[test]
fn decompress_copy_lzma2_single_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/copy.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("copy.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(file1_path).unwrap(), "simple copy encoding");
}

#[cfg(all(feature = "util", feature = "ppmd"))]
#[test]
fn decompress_ppmd_single_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/ppmd.7z");

    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("apache2.txt");

    decompress_file(source_file, target).unwrap();
    let decompressed_content = read_to_string(file1_path).unwrap();

    let expected = read_to_string("tests/resources/apache2.txt").unwrap();

    assert_eq!(decompressed_content, expected);
}

#[cfg(all(feature = "util", feature = "bzip2"))]
#[test]
fn decompress_bzip2_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/bzip2_file.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();

    let mut hello_path = target.clone();
    hello_path.push("hello.txt");

    let mut foo_path = target.clone();
    foo_path.push("foo.txt");

    decompress_file(source_file, target).unwrap();

    assert_eq!(read_to_string(hello_path).unwrap(), "world\n");
    assert_eq!(read_to_string(foo_path).unwrap(), "bar\n");
}

/// zstdmt (which 7zip ZS uses), does encapsulate brotli data in a special frames,
/// for which we need to have custom logic to decode and encode to.
#[cfg(all(feature = "util", feature = "brotli"))]
#[test]
fn decompress_zstdmt_brotli_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/zstdmt-brotli.7z");

    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();

    let mut license_path = target.clone();
    license_path.push("LICENSE");

    decompress_file(source_file, target).unwrap();

    assert!(
        read_to_string(license_path)
            .unwrap()
            .contains("Apache License")
    );
}

#[cfg(all(feature = "util", feature = "lz4"))]
#[test]
fn decompress_zstdmt_lz4_file() {
    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/zstdmt-lz4.7z");

    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();

    let mut license_path = target.clone();
    license_path.push("LICENSE");

    decompress_file(source_file, target).unwrap();

    assert!(
        read_to_string(license_path)
            .unwrap()
            .contains("Apache License")
    );
}

#[test]
fn test_bcj2() {
    let mut file = File::open("tests/resources/7za433_7zip_lzma2_bcj2.7z").unwrap();
    let archive = Archive::read(&mut file, &Password::empty()).unwrap();
    for i in 0..archive.blocks.len() {
        let password = Password::empty();
        let fd = BlockDecoder::new(1, i, &archive, &password, &mut file);
        println!("entry_count:{}", fd.entry_count());
        fd.for_each_entries(&mut |entry, reader| {
            println!("{}=>{:?}", entry.has_stream, entry.name());
            std::io::copy(reader, &mut std::io::sink())?;
            Ok(true)
        })
        .unwrap();
    }
}

#[test]
fn test_delta_bcj2() {
    // Regression test for a multi-coder folder that chains a Delta filter on top of a
    // BCJ2 coder (`Method = Delta BCJ2`). Such folders used to fail to decode with
    // `Unsupported method` because the decoder required the folder's main (final
    // output) coder to be BCJ2 itself and could not handle a single-input filter
    // layered on top of it. The fixture was produced by 7-Zip and contains three
    // entries; every entry has a stored CRC that is verified during decoding, so a
    // successful read of every entry also asserts byte correctness.
    let mut file = File::open("tests/resources/delta_bcj2.7z").unwrap();
    let archive = Archive::read(&mut file, &Password::empty()).unwrap();

    let mut decoded = Vec::new();
    for i in 0..archive.blocks.len() {
        let password = Password::empty();
        let fd = BlockDecoder::new(1, i, &archive, &password, &mut file);
        fd.for_each_entries(&mut |entry, reader| {
            let mut data = Vec::new();
            std::io::copy(reader, &mut data)?;
            decoded.push((entry.name().to_string(), data.len()));
            Ok(true)
        })
        .unwrap();
    }

    assert_eq!(
        decoded,
        vec![
            ("c/code1.bin".to_string(), 9000),
            ("c/code2.bin".to_string(), 7000),
            ("c/wave.bin".to_string(), 16000),
        ]
    );
}

#[test]
fn test_entry_compressed_size() {
    let dir = std::fs::read_dir("tests/resources").unwrap();
    for entry in dir {
        let path = entry.unwrap().path();
        if path.to_string_lossy().ends_with("7z") {
            println!("{path:?}");
            let mut file = File::open(path).unwrap();
            let archive = Archive::read(&mut file, &Password::empty()).unwrap();
            for i in 0..archive.blocks.len() {
                let fi = archive.stream_map.block_first_file_index[i];
                let file = &archive.files[fi];
                println!(
                    "\t:{}\tsize={}, \tcompressed={}",
                    file.name(),
                    file.size,
                    file.compressed_size
                );
                if file.has_stream && file.size > 0 {
                    assert!(file.compressed_size > 0);
                }
            }
        }
    }
}

#[test]
fn test_get_file_by_path() {
    // non_solid.7z and solid.7z are expected to have the same content.
    let mut non_solid_reader =
        ArchiveReader::open("tests/resources/non_solid.7z", Password::empty()).unwrap();
    let mut solid_reader =
        ArchiveReader::open("tests/resources/solid.7z", Password::empty()).unwrap();

    let paths: Vec<String> = non_solid_reader
        .archive()
        .files
        .iter()
        .filter(|file| !file.is_directory)
        .map(|file| file.name.clone())
        .collect();

    for path in paths.iter() {
        let data0 = non_solid_reader.read_file(path.as_str()).unwrap();
        let data1 = solid_reader.read_file(path.as_str()).unwrap();

        assert!(!data0.is_empty());
        assert!(!data1.is_empty());
        assert_eq!(&data0, &data1);
    }
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn anti_item_deletes_file_on_extract() {
    use std::io::Cursor;

    use sevenz_rust2::{
        ArchiveEntry, ArchiveWriter, decompress_with_extract_fn_and_password,
        default_entry_extract_fn,
    };

    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().join("to_delete.txt");
    std::fs::write(&target, "will be deleted").unwrap();
    assert!(target.exists());

    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        let mut entry = ArchiveEntry::new_file("to_delete.txt");
        entry.is_anti_item = true;
        writer.push_archive_entry::<&[u8]>(entry, None).unwrap();
        writer.finish().unwrap();
    }

    let dest = temp_dir.path().to_path_buf();
    decompress_with_extract_fn_and_password(
        Cursor::new(bytes.as_slice()),
        &dest,
        Password::empty(),
        |entry, reader, dest_path| {
            if entry.is_anti_item() {
                std::fs::remove_file(dest_path).ok();
                return Ok(true);
            }
            default_entry_extract_fn(entry, reader, dest_path)
        },
    )
    .unwrap();

    assert!(!target.exists(), "anti-item should have been deleted");
}

#[cfg(all(feature = "compress", feature = "util"))]
fn build_archive_with_entry_name(name: &str) -> Vec<u8> {
    use std::io::Cursor;

    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};

    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        let entry = ArchiveEntry::new_file(name);
        let content = b"pwned" as &[u8];
        writer.push_archive_entry(entry, Some(content)).unwrap();
        writer.finish().unwrap();
    }
    bytes
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn path_traversal_relative_entry_is_rejected() {
    use std::io::Cursor;

    use sevenz_rust2::decompress;

    let temp_dir = tempdir().unwrap();
    let dest = temp_dir.path().join("out");
    // Escapes `dest` up into the tempdir root, where we can detect a stray write
    // without touching anything outside the test sandbox.
    let escaped = temp_dir.path().join("sevenz_pwned_relative");
    assert!(!escaped.exists());

    // `dest/../sevenz_pwned_relative` resolves to `escaped` above.
    let bytes = build_archive_with_entry_name("../sevenz_pwned_relative");
    let result = decompress(Cursor::new(bytes.as_slice()), &dest);

    assert!(result.is_err(), "traversal entry must be rejected");
    assert!(
        !escaped.exists(),
        "file must not be written outside the destination"
    );
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn path_traversal_absolute_entry_is_rejected() {
    use std::io::Cursor;

    use sevenz_rust2::decompress;

    let temp_dir = tempdir().unwrap();
    let dest = temp_dir.path().join("out");
    // Absolute path inside the tempdir: `dest.join(abs)` would discard `dest`.
    let escaped = temp_dir.path().join("sevenz_pwned_abs");
    let abs_name = escaped.to_string_lossy().to_string();
    assert!(escaped.is_absolute());
    assert!(!escaped.exists());

    let bytes = build_archive_with_entry_name(&abs_name);
    let result = decompress(Cursor::new(bytes.as_slice()), &dest);

    assert!(result.is_err(), "absolute entry must be rejected");
    assert!(
        !escaped.exists(),
        "file must not be written outside the destination"
    );
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn path_traversal_normal_nested_entry_still_extracts() {
    use std::io::Cursor;

    use sevenz_rust2::decompress;

    let temp_dir = tempdir().unwrap();
    let dest = temp_dir.path().join("out");

    let bytes = build_archive_with_entry_name("a/b/c.txt");
    decompress(Cursor::new(bytes.as_slice()), &dest).unwrap();

    let extracted = dest.join("a").join("b").join("c.txt");
    assert_eq!(std::fs::read(&extracted).unwrap(), b"pwned");
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn default_entry_extract_fn_rejects_parent_dir_component() {
    use sevenz_rust2::{ArchiveEntry, default_entry_extract_fn};

    // Defense-in-depth: a caller that bypasses `decompress_impl` and hands an
    // already-joined path containing `..` directly to the default extractor must
    // still be rejected.
    let temp_dir = tempdir().unwrap();
    let escaped = temp_dir.path().join("sevenz_pwned_direct");
    let traversed = temp_dir
        .path()
        .join("out")
        .join("..")
        .join("sevenz_pwned_direct");
    assert!(!escaped.exists());

    let entry = ArchiveEntry::new_file("sevenz_pwned_direct");
    let mut data = b"pwned" as &[u8];
    let result = default_entry_extract_fn(&entry, &mut data, &traversed);

    assert!(result.is_err(), "parent-dir path must be rejected");
    assert!(!escaped.exists(), "no file may be written via a `..` path");
}

/// Regression test for <https://github.com/hasenbanck/sevenz-rust2/issues/127>.
#[test]
fn malformed_coder_stream_counts_are_rejected() {
    let mut file = File::open("tests/resources/issue_127_coder_stream_overflow.bin").unwrap();

    let result = Archive::read(&mut file, &Password::empty());

    assert!(
        result.is_err(),
        "malformed archive must be rejected, got: {result:?}"
    );
}
