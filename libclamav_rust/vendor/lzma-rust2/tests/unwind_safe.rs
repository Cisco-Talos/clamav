use std::panic::{RefUnwindSafe, UnwindSafe};

fn assert_unwind_safe<T: UnwindSafe + RefUnwindSafe>() {}

#[test]
fn readers_are_unwind_safe() {
    assert_unwind_safe::<lzma_rust2::LzmaReader<&[u8]>>();
    assert_unwind_safe::<lzma_rust2::Lzma2Reader<&[u8]>>();
    #[cfg(feature = "lzip")]
    assert_unwind_safe::<lzma_rust2::LzipReader<&[u8]>>();
    #[cfg(feature = "xz")]
    assert_unwind_safe::<lzma_rust2::XzReader<&[u8]>>();
}

#[test]
#[cfg(feature = "encoder")]
fn writers_are_unwind_safe() {
    assert_unwind_safe::<lzma_rust2::LzmaWriter<Vec<u8>>>();
    assert_unwind_safe::<lzma_rust2::AutoFinisher<lzma_rust2::LzmaWriter<Vec<u8>>>>();
    assert_unwind_safe::<lzma_rust2::Lzma2Writer<Vec<u8>>>();
    assert_unwind_safe::<lzma_rust2::AutoFinisher<lzma_rust2::Lzma2Writer<Vec<u8>>>>();
    #[cfg(feature = "lzip")]
    {
        assert_unwind_safe::<lzma_rust2::LzipWriter<Vec<u8>>>();
        assert_unwind_safe::<lzma_rust2::AutoFinisher<lzma_rust2::LzipWriter<Vec<u8>>>>();
    }
    #[cfg(feature = "xz")]
    {
        assert_unwind_safe::<lzma_rust2::XzWriter<Vec<u8>>>();
        assert_unwind_safe::<lzma_rust2::AutoFinisher<lzma_rust2::XzWriter<Vec<u8>>>>();
    }
}

#[test]
fn filter_readers_are_unwind_safe() {
    assert_unwind_safe::<lzma_rust2::filter::bcj::BcjReader<&[u8]>>();
    assert_unwind_safe::<lzma_rust2::filter::bcj2::Bcj2Reader<&[u8]>>();
    assert_unwind_safe::<lzma_rust2::filter::delta::DeltaReader<&[u8]>>();
}

#[test]
fn filter_writers_are_unwind_safe() {
    assert_unwind_safe::<lzma_rust2::filter::bcj::BcjWriter<Vec<u8>>>();
    assert_unwind_safe::<lzma_rust2::filter::delta::DeltaWriter<Vec<u8>>>();
}

#[test]
fn filter_coders_are_unwind_safe() {
    assert_unwind_safe::<lzma_rust2::filter::bcj2::Bcj2Coder>();
}
