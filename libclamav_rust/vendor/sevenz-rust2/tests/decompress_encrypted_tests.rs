#[cfg(feature = "aes256")]
#[test]
fn test_decompress_file_with_password() {
    use std::{fs::read_to_string, path::PathBuf};

    use sevenz_rust2::decompress_file_with_password;
    use tempfile::tempdir;

    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/encrypted.7z");
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().to_path_buf();
    let mut file1_path = target.clone();
    file1_path.push("encripted/7zFormat.txt");
    let r = decompress_file_with_password(source_file, target.as_path(), "sevenz-rust".into());
    assert!(r.is_ok());
    assert!(
        read_to_string(file1_path)
            .unwrap()
            .starts_with("7z is the new archive format, providing high compression ratio.")
    )
}

#[cfg(feature = "aes256")]
#[test]
fn test_decompress_file_with_password_small() {
    use std::path::PathBuf;

    use sevenz_rust2::ArchiveReader;

    let mut source_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_file.push("tests/resources/aes_small_test.7z");

    let password = "iBlm8NTigvru0Jr0".into();
    let mut seven =
        ArchiveReader::new(std::fs::File::open(source_file).unwrap(), password).unwrap();
    seven.for_each_entries(|_entry, _reader| Ok(true)).unwrap();
}
