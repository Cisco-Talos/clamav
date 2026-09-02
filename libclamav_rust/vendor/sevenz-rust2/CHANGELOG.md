# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.21.5 - 2026-08-16

### Changed

- Bumped `lzma_rust2` to 0.19.
- Batch AES-CBC decryption to improve performance.

## 0.21.4 - 2026-08-01

### Fixed

- Fixed an integer overflow when summing attacker-controlled coder stream counts while parsing a block header. Malformed
  archives panicked in debug builds and bypassed the stream-count bound in release builds. They are now rejected with an
  error. (#127, thanks @tyrex-vberthier)

## 0.21.3 - 2026-07-05

### Changed

- Cache most recent AES key derivation to improve performance (#118, thanks @jdlien)

### Fixed

- Hardened the library against malicious or malformed archives that could otherwise cause a panic, an infinite loop, or
  an unbounded allocation while parsing or decoding.

## 0.21.2 - 2026-07-01

### Fixed

- Decode 7z folders that layer a single-input filter (e.g. Delta) on top of a BCJ2 coder (`Method = Delta BCJ2`). These
  folders previously failed to decode with an
  `Unsupported method` error because the decoder required the folder's final output coder to be BCJ2 itself. (#117,
  thanks @trevorWieland)

## 0.21.1 - 2026-06-23

### Fixed

- Fix security issue were malicious 7z files could write files outside the destination directory. Reported by @lintowe
  (#116)

## 0.21.0 - 2026-04-25

### Changed

- Bumped MSRV to 1.93 (required by `nt-time` 0.15)

### Updated

- Bumped `nt-time` to 0.15 (#105)
- Bumped `aes` to 0.9 and `cbc` to 0.2 (cipher 0.5) (#111, #110)

### Fixed

- `K_ANTI` property block was not written for archives containing only anti-items, so anti-items were extracted as
  0-byte files instead of acting as deletion markers (#112, thanks @uraf)
- `compress_path` no longer emits a spurious entry for the root directory itself when compressing a directory tree (#79,
  thanks @super1207)

## 0.20.2 - 2026-02-24

### Fixed

- Updated internal dependencies `lzma-rust2` to v0.16 and `getrandom` to v0.4

## 0.20.1 - 2026-01-01

### Fixed

- Fix bug where small headers of encrypted files were not encrypted (#98)

## 0.20.0 - 2025-12-07

### Changed

- Expose public getters for streaming archive data @vihu (#93)

### Fixed

- Brotli codec decompression is not working without compress (#95)

## 0.19.4 - 2025-11-26

### Fixed

- Fixed "AES256 properties too short" bug (#91)

## 0.19.3 - 2025-11-01

### Updated

- Target ppmd-rust v1. Since ppmd-rust is stable and has a major version, we will target it directly to reduce
  maintenance burden.

## 0.19.2 - 2025-10-29

### Updated

- Target lzma-rust2 v0.15.

## 0.19.1 - 2025-09-23

### Fixed

- Removed too strict debug_assert as reported in #81
- Removed incompatibility issues when using the `ArchiveWriter::push_source_path()` with single files. We now properly
  handle both cases were a file or a directory is given to the function.

## 0.19.0 - 2025-09-20

### Changed

- Breaking change: Rename identifiers to follow Rust API Guidelines @sorairolake (#59)

### Updated

- Target lzma-rust2 v0.14.
- Updated the documentation to include the BCJ2 codec again. It was never gone, only overlooked.

### Fixed

- Improved compatibility with third party utilities when creating 7z files (esp. Windows's Explorer and macOS's Finder).
- Improve docs.rs feature compatibility @sorairolake (#56)

### Removed

- Removed the dependency to `byteorder`.

## 0.18.0 - 2025-08-25

### Added

- Add support for BCJ IA64 filter.
- Add support for BCJ RISC-V filter.
- Added encoder support for all BCJ filter.

### Updated

- Target lzma-rust2 v0.10.

### Changed

- Changed one of LZMA2Options::from_level_mt's parameter name.

## 0.17.1 - 2025-07-26

### Updated

- Target lzma-rust2 v0.6.

## 0.17.0 - 2025-07-25

### Added

- Added muti-threading support for LZMA2 compression & decompression.
- Added `ArchiveReader::set_thread_count()` to set the thread count when decoding with multiple threads. Only LZMA2 is
  supported right now. `ArchiveReader` will set the thread_count with the help of
  `std::thread::available_parallelism` as default.
- Added missing documentation for the public API.

### Changed

- Split `LZMA2Option` into `LZMAOptions` and `LZMA2Options` to better support multi-threading encoding for LZMA2.
- Removed `EncoderOptions::Num` enum, which means encoders needs to be configured with their respected option struct.

## 0.16.2 - 2025-07-16

### Updated

- Target lzma-rust2 v0.4 which increases the encoding speed.

## 0.16.1 - 2025-07-12

### Updated

- Target lzma-rust2 v0.3 which increases the decoding speed dramatically (around 50% on x86_64).

## 0.16.0 - 2025-07-04

### Changed

- Removed a lot of exports that were not used in the public facing API.
- Expose all compression and filter method options via the `encoder_options` module.
- Renamed the following structs in an attempt to make the API easier to navigate:
    - `SevenZArchiveEntry` -> `ArchiveEntry`
    - `SevenZReader` -> `ArchiveReader`
    - `SevenZWriter` -> `ArchiveWriter`
    - `SevenZMethod` -> `EncoderMethod`
    - `SevenZMethodConfiguration` -> `EncoderConfiguration`
    - `MethodOptions` -> `EncoderOptions`
    - `Folder` -> `Block`
- Renamed all instances of "folder" in the API to "directory" instead to clearly distinct from the "folder" in the 7z
  format specification and align with the std fs module.
- Internal `Archive`, `SteamMap`, `Coder` and `Block` fields are removed from the public API.
- What the 7z specification calls "folders" are a false friend and we instead call them "blocks".
- Every API that takes a password now uses the `Password` struct instead. Added helper functions to create password from
  strings and raw bytes.
- The needed features for WASM changed. Please use the "default_wasm" feature.
- Removed the hard dependency to `nt-time` by creating our own time struct `NtTime`. The feature can be used to convert
  to and from `nt-time::FileTime`.

### Removed

- Removed the dependency to `bit-set` and `filetime_creation`.
- `nt-time` dependency is now optional.

### Updated

- PPMd crate to version v1.2, which fixes the compatibility issues with existing 7z files using PPMd7.

## 0.15.3 - 2025-06-28

### Fixed

- Properly finish PPMd files.

## 0.15.2 - 2025-06-27

### Fixed

- No functional updates.
- Moved lzma-rust2 and ppmd-rust into their own crates.

## 0.15.1 - 2025-06-22

### Fixed

- Updated outdated documentation.

## 0.15.0 - 2025-06-22

### Updated

- Target optional dependency bzip2 v0.6.

### Changed

- The PPMd crate is using a native Rust version that is validated with Miri. All 7zip supported compression algorithms
  (LZMA, LZMA2, BZIP2 and PPMd) have now Rust native implementations and don't need a C compiler.
- All standard compression algorithms of 7zip are enabled by default.
- Use default feature of lz4_flex

## 0.14.1 - 2025-06-02

### Added

- Added support for ARM64 BCJ filter (by Benkol003).
- Add support for encoding LZ4 with skippable frames.

### Fixed

- Fixed decompressing LZ4 that contain skippable frames.

### Changed

- Use lz4_flex instead of lz4, which is a faster Rust native implementation. The only downside is, that only one
  compression level is supported.

## 0.13.2 - 2025-05-01

### Fixed

- Loose version restrictions on some dependencies.

## 0.13.1 - 2025-04-05

### Fixed

- Fix broken WASM build.

## 0.13.0 - 2025-03-31

### Fixed

- Fix the bug where the optional compression methods did not finish properly and created invalid entries when writing 7z
  archives.

### Changed

- Moved `CountingWriter` from lzma to sevenz crate, since it was an internal implementation detail of the sevenz crate.
- Remove implicit way to call `finish()` by `calling write(&[])` on the lzma and lzma2 writer. This was again an
  implementation detail of the sevenz. `finish()` now also takes `self`, like other compression libraries.

### Added

- `LZMAWriter` and `LZMA2Writer` now expose the inner writer and also return it when calling `finish(self)`.

## 0.12.1 - 2025-03-10

### Fixed

- Fix broken LZ4 feature compilation

## 0.12.0 - 2025-02-28

### Added

- Support for Delta filter compression
- Support for PPDm compression / decompression

## 0.11.0 - 2025-02-26

### Updated

- Updated dependency nt-time to 0.11

### Changed

- Introduced a new feature "util", so that users can deactivate those functionality, if not needed
- Added a lot of documentation tags for docs.rs
- Update of nt-time introduce the need to increase MSRV to 1.85

## 0.10.0 - 2025-02-26

### Changed

- The Brotli codec now supports the skippable frame encoding found in zstdmt (used by 7zip ZS and NanaZip). This is the
  default format, since it seems to be the default for user facing programs. The default data a frame contains is 128
  KiB.

## 0.9.0 - 2025-02-25

### Added

- Add `SevenZReader::file_compression_methods()`.

### Fixed

- Improve compatibility with third party programs (tested with 7-Zip ZS 1.5.6)
  bzip2, LZ4 and ZSTD now work flawless. BROTLI isn't compatible right now.

## 0.8.0 - 2025-02-25

### Added

- Optional support for compressing / decompressing with BROTLI
- Optional support for compressing with bzip2
- Optional support for compressing / decompressing with DEFLATE
- Optional support for compressing / decompressing with LZ4
- Optional support for compressing with ZStandard

### Changed

- Replaced all unsafe code from sevenz-rust2 and lzma-rust2 with safe alternatives
- sha2 is now an optional dependency that is activated when using the aes256 features
- Update of the documentation
- Removed the need to provide the length of a reader when reading an archive file

## 0.7.0 - 2025-02-24

This release should be mostly compatible with the old 0.6.1. The breaking changes are:

- Previously deprecated functionality were removed
- Spelling issues were fixed in some API names

### Added

- `SevenZReader::readFile()` added
- `SevenZArchiveEntry::new_file()` and `SevenZArchiveEntry::new_folder()` factory functions added
- Compression method COPY is now supported

### Changed

- Updated dependency bit-set v0.8
- Updated dependency bzip2 v0.5
- Updated dependency nt-time v0.10
- Use crc32fast instead of crc

### Fixed

- Replaces insecure usage of rand with getrandom
- Renamed `get_memery_usage()` into `get_memory_usage()`
- Renamed `compress_encypted()` into `compress_encrypted()`

### Removed

- Removed deprecated `FolderDecoder`. Use `BlockDecoder` instead
- Removed deprecated `SevenZWriter::create_archive_entry()`. Use `SevenZArchiveEntry::from_path()` instead

## 0.6.1 - 2024-07-17

- Fixed 'unsafe precondition (s) violated'. Closed #63

## 0.6.0 - 2024-04-05

- Added support for encrypted headers - close #55
- Return a consistent error in case the password is invalid - close #53

## 0.5.4 - 2023-12-13

- Added docs
- Renamed `FolderDecoder` to `BlockDecoder`
- Added method to compress paths in non-solid mode
- Fixed entry's compressed_size is always 0 when reading archives.

## 0.5.3

Fixed 'Too many open files' Reduce unnecessary public items #37

## 0.5.2 - 2023-08-24

Fixed file separator issue on Windows system #35

## 0.5.1 - 2023-08-23

Sub crate `lzma-rust` code optimization

## 0.5.0 - 2023-08-19

- Added support for BCJ2.
- Added multi-thread decompress example

## 0.4.3 - 2023-06-16

- Support write encoded header
- Added `LZMAWriter`

## 0.4.2 - 2023-06-10

- Removed unsafe code
- Changed `SevenZWriter.finish` method return inner writer
- Added wasm compress function
- Updates bzip dependency to the patch version of 0.4.4 ([#23](https://github.com/dyz1990/sevenz-rust/pull/23))

## 0.4.1 - 2023-06-07

- Fixed unable to build without default features

## 0.4.0 - 2023-06-03 - Solid compression

## 0.3.0 - 2023-06-02 - Encrypted compression

- Added Encrypted compression

## 0.2.11 - 2023-05-24

- Fixed numerical overflow

## 0.2.10 - 2023-04-18

- Change to use nt-time crate ([#20](https://github.com/dyz1990/sevenz-rust/pull/20))
- Fix typo ([#18](https://github.com/dyz1990/sevenz-rust/pull/18))
- make function generics less restrictive ([#17](https://github.com/dyz1990/sevenz-rust/pull/17))
- Solve warnings ([#16](https://github.com/dyz1990/sevenz-rust/pull/16))
- run rustfmt on code ([#15](https://github.com/dyz1990/sevenz-rust/pull/15))

## 0.2.9 - 2023-03-16

- Added bzip2 support ([#14](https://github.com/dyz1990/sevenz-rust/pull/14))

## 0.2.8 - 2023-03-06

- Fixed write bitset bugs

## 0.2.7 - 2023-03-05

- Fixed bug while read files info

## 0.2.6 - 2023-02-23

- Added zstd support and use enhanced filetime lib ([#11](https://github.com/dyz1990/sevenz-rust/pull/11))
- Fixed lzma encoder bugs

## 0.2.4 - 2023-02-16

- Changed return entry ref when pushing to writer ([#10](https://github.com/dyz1990/sevenz-rust/pull/10))

## 0.2.3 - 2023-02-07

- Fixed incorrect handling of 7z time

## 0.2.2 - 2023-01-31 - Create sub crate `lzma-rust`

- Move mod `lzma` to sub crate `lzma-rust`
- Modify GitHub Actions to run tests with --all-features

## 0.2.0 - 2023-01-08 - Added compression supporting

- Added compression supporting

## 0.1.5 - 2022-11-01 - Encrypted 7z files decompression supported

- Added aes256sha256 decode method
- Added wasm support
- Added new tests (for Delta and Copy) and GitHub Actions CI ([#5](https://github.com/dyz1990/sevenz-rust/pull/5))
  by [bfrazho](https://github.com/bfrazho)

## 0.1.4 - 2022-09-20 - Replace lzma/lzma2 decoder

- Chnaged new lzma/lzma2 decoder

## 0.1.3 - 2022-09-18 - add more bcj filters

- Added bcj arm/ppc/sparc and delta filters
- Added test for bcj x86 ([#3](https://github.com/dyz1990/sevenz-rust/pull/3)) by [bfrazho](https://github.com/bfrazho)

## 0.1.2 - 2022-09-14 - bcj x86 filter supported

- Added bcj x86 filter
- Added LZMA tests ([#2](https://github.com/dyz1990/sevenz-rust/pull/2)) by [bfrazho](https://github.com/bfrazho)
- Fixed extract empty file

## 0.1.1 - 2022-08-10 - Modify decompression function

## 0.1.0 - 2022-08-10 - Decompression
