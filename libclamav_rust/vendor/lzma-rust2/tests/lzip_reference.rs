use std::io::Read;

use lzma_rust2::LzipReader;

fn reference_test(compressed: &[u8], original: &[u8]) {
    let mut reader = LzipReader::new(compressed);

    let mut uncompressed = Vec::with_capacity(original.len());
    let count = reader.read_to_end(&mut uncompressed).unwrap();

    assert_eq!(count, original.len());

    let inner = reader.into_inner();
    assert_eq!(
        inner.len(),
        0,
        "not all bytes of the LZIP stream where read"
    );

    assert!(original == uncompressed);
}

#[test]
fn executable_executable() {
    let compressed = std::fs::read("tests/data/executable.exe.lz").unwrap();
    let original = std::fs::read("tests/data/executable.exe").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}
