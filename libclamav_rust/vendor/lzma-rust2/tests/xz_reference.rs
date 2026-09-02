use std::io::Read;

use lzma_rust2::XzReader;

fn reference_test(compressed: &[u8], original: &[u8]) {
    let mut reader = XzReader::new(compressed, false);

    let mut uncompressed = Vec::with_capacity(original.len());
    let count = reader.read_to_end(&mut uncompressed).unwrap();
    assert_eq!(count, original.len());

    let inner = reader.into_inner();
    assert_eq!(inner.len(), 0, "not all bytes of the XZ stream where read");

    assert!(original == uncompressed);
}

#[test]
fn executable_bcj_arm() {
    let compressed = std::fs::read("tests/data/wget-arm.xz").unwrap();
    let original = std::fs::read("tests/data/wget-arm").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_arm64() {
    let compressed = std::fs::read("tests/data/wget-arm64.xz").unwrap();
    let original = std::fs::read("tests/data/wget-arm64").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_arm_thumb() {
    let compressed = std::fs::read("tests/data/wget-arm-thumb.xz").unwrap();
    let original = std::fs::read("tests/data/wget-arm-thumb").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_ia64() {
    let compressed = std::fs::read("tests/data/wget-ia64.xz").unwrap();
    let original = std::fs::read("tests/data/wget-ia64").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_ppc() {
    let compressed = std::fs::read("tests/data/wget-ppc.xz").unwrap();
    let original = std::fs::read("tests/data/wget-ppc").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_riscv() {
    let compressed = std::fs::read("tests/data/wget-riscv.xz").unwrap();
    let original = std::fs::read("tests/data/wget-riscv").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_sparc() {
    let compressed = std::fs::read("tests/data/wget-sparc.xz").unwrap();
    let original = std::fs::read("tests/data/wget-sparc").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}

#[test]
fn executable_bcj_x84() {
    let compressed = std::fs::read("tests/data/wget-x86.xz").unwrap();
    let original = std::fs::read("tests/data/wget-x86").unwrap();
    reference_test(compressed.as_slice(), original.as_slice());
}
