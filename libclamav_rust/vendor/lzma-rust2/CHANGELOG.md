# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.19.0 - 2026-08-16

- Add sans-I/O decoders for LZMA1 and LZIP. Thanks @Black-Frost (#109)

## 0.18.1 - 2026-08-05

### Fixed

- Fixed an out-of-bounds panic when encoding more than ~2 GiB through a single stream (#107)

## 0.18.0 - 2026-07-26

### Added

- Add check_type () getter to XzStream. Thanks @Black-Frost (#106)

## 0.17.0 - 2026-07-15

### Added

- Add sans-I/O decoders for LZMA2 and XZ, which allows to better implement async and also multithreaded abstractions.
  Thanks @Black-Frost (#105)

## 0.16.5 - 2026-07-05

### Fixed

- Hardened the library against malicious or malformed archives.

## 0.16.4 - 2026-05-31

### Fixed

- Fix invalid XZ output for empty streams
- Fix debug assertion panic on valid flushes

## 0.16.3 - 2026-05-20

### Fixed

- Fixed an issue were custom dictionaries could not be used when using LZMA

## 0.16.2 - 2026-02-16

### Fixed

- We provide our own CRC implementation for lzip and xz, which removes the dependency to the crc crate. No functional
  change to v0.16.0 or v0.16.1

## 0.16.1 - 2026-02-11

### Fixed

- Make sure to at least use crc version 3.2. No functional updates or changes compared to v0.16.1

## 0.16.0 - 2026-02-10

### Fixed

- Fix compatibility issues with the crc crate by raising MSRV to 1.85. No functional updates or changes compared to
  v0.15.7

## 0.15.7 - 2026-01-13

### Fixed

- Add missing From<TryReserveError> for the no_std Error

## 0.15.6 - 2026-01-06

### Fixed

- Fix possible panic on out of bound access when reading u32_be correctly

## 0.15.5 - 2026-01-05

### Fixed

- Fix possible panic in the range decoder when trying to read u32_be data
- Fix race condition in multithreaded code in error conditions

## 0.15.4 - 2025-12-07

### Changed

- Fix CRC dependency to exactly 3.3 or else it could break some builds, wrongly selecting a different major version.

## 0.15.3 - 2025-12-02

### Changed

- Pin CRC dependency to not break MSRV. Most likely we will increase the MSRV in the next minor release.

## 0.15.2 - 2025-11-26

### Fixed

- Fix possible underflow in BCJ filters (#72)

## 0.15.1 - 2025-10-31

### Fixed

- Fix fuzzing issues found for the LZMA decoder (#69)

## 0.15.0 - 2025-10-29

### Changed

- Breaking change: `LzipReader::new()` does not return a `Return` type anymore, but only itself.

### Fixed

- Fix issue when reading some compressed lzma2 data, which could lead to an integer overflow (#64)

## 0.14.3 - 2025-10-07

### Fixed

- Fix issue when compiling with feature `xz` but without including the feature `encoder` (#61)
- Fix issue when reading XZ files that allocate too many records (#62)

## 0.14.2 - 2025-09-25

### Fixed

- Fix reading XZ files with multiple streams (#57)
- Fix integer overflow when using LZMA2 dictionary sizes near 4 GiB (#58)

## 0.14.1 - 2025-09-21

### Fixed

- Fix the safe build without the "optimization" feature.

## 0.14.0 - 2025-09-20

### Changed

- Breaking change: Changed CheckType's default from CRC32 to CRC64 @sorairolake (#37)
- Breaking change: All Writer now use the AutoFinisher struct to provide auto finishing writer @sorairolake (#46)

### Fixed

- Export missing `FilterConfig` and `FilterType` @sorairolake (#50)

## 0.13.0 - 2025-09-03

### Changed

- Breaking change: Rename identifiers to follow Rust API Guidelines @sorairolake (#35)
- Breaking change: All single threaded reader / writer are now implementing UnwindSafe and RefUnwindSafe. Before they
  saved the last std::io:error and kept returning it for all following red/writes. Now they only return that particular
  error once.

## 0.12.0 - 2025-09-02

- Reduced MSRV to 1.82

### Fixed

- Fixed documentation @sorairolake
- Improve docs.rs feature compatibility @sorairolake
- Internal cleanup @sorairolake

## 0.11.0 - 2025-08-27

### Changed

- Add writers for lzip and xz that finishes the stream on drop. @sorairolake (#26)

## 0.10.2 - 2025-08-25

### Fixed

- Fixed missing call to .finish () when creating files with BCJ filter with XZ.

## 0.10.1 - 2025-08-25

### Fixed

- Fix broken BCJWriter that couldn't properly finish it's encoding process. Now has a proper finish () function.

## 0.10.0 - 2025-08-22

### Fixed

- Add missing "inner ()" and "inner_mut ()" function to the XZ and LZIP reader and writer.

## 0.9.0 - 2025-08-15

### Changed

- `XZReader` and `XZWriter` are now Send.
- Most reader and writer now have "inner ()" and "inner_mut ()" functions.

### Updated

- Internally refactoring to reduce code duplication for multi-threading code.

## 0.8.2 - 2025-08-13

### Fixed

- Make sure that LZMA reader errors when going out of bound. This could happen if no EOS was found. This was not a
  memory a safety issue, but instead a problem in how we propagated a fail state in light of certain optimizations.
- Bound the multithreaded reader as to not use too much memory.

## 0.8.1 - 2025-08-13

### Fixed

- Internally we updated the hash function for the match finders to use a golden ratio based hash instead of the old CRC
  table based hash. In our test data this was a net win, but it turned out, once tested with bigger datasets, this is a
  net loss. So we returned back to the CRC table approach (we speak here about a change below 0.01%, but measurable).

## 0.8.0 - 2025-08-10

### Added

- Added single threaded and multithreaded encoder and decoder for the LZIP file format.
- Added multithreaded encoder and decoder for the XZ file format.

### Changed

- Renamed LZMA2's "independent work unit" naming from "stream" to "chunk" to not confuse it with XZ streams.
- LZMA2Writer now take a LZMA2Option struct. This enables both the LZMA2Writer and LZMA2WriterMT to encode multiple
  chunks for multithreaded decoding.
- Changed block size of XZOptions to NonZero type.
- Unified the API of the writers as far as possible.

### Fixed

- Fixed unbounded spawning of threads when using the multithreaded version of LZMA2 encoder & decoder.
- Fixed performance regression on linux as reported by @chenxiaolong (#10)
- Fixed compatibility with liblzma when creating XZ files as reported by @chenxiaolong (#14)
- XZWriter properly writes out multiple blocks respecting the block_size.

## 0.7.0 - 2025-08-08

### Added

- Added single threaded encoder and decoder for the XZ file format.
- Ported all pre-filters used by both 7zip and XZ.

## 0.6.1 - 2025-08-03

### Fixed

- Fixed issue with the MT reader discovered by the downstream sevenz-rust2 crate because of incorrect chunk cuts
  (https://github.com/hasenbanck/sevenz-rust2/issues/44).

### Updated

- The multithreading now works more efficient, since new threads are only spawned if really needed.

## 0.6.0 - 2025-07-26

### Added

- Added no_std support by disabling the new `std` feature that is enabled by default. Custom traits and default
  implementation for &[u8] and &mut [u8] are provided.

## 0.5.1 - 2025-07-25

### Fixed

- Fixed possible deadlocks in the multithreaded encoder and decoder.

## 0.5.0 - 2025-07-24

### Added

- Added multithreaded compression for LZMA2.
- Added multithreaded decompression for LZMA2.

### Updated

- Renamed LZMA2Options to LZMAOptions, since it described the way we encode the LZMA encoder, which is shared between
  LZMA and LZMA2.

## 0.4.0 - 2025-07-16

### Updated

- Increased the encoding performance. For level 0-3 this crate now is faster than lzma. For 4-9 this crate is on same
  level with liblzma.

### Changed

- Feature "asm" changed to "optimization" and is also enabled by default. Have a look at the "Safety" section of the
  README.md for more details.

## 0.3.1 - 2025-07-12

### Fixed

- No functional changes.
- Fixed the links to the repository.

## 0.3.0 - 2025-07-12

### Updated

- Increased MSRV to v1.85
- Increased the decoding performance while using only safe Rust. On x86-64 the speed-up was quite large when compared to
  the v0.2 branch (+50% throughput). Have a look at the "Performance" section of the README.md for more details.
- Added feature flag "asm" which is activated at default which increases the decoding speed when using LZMA2. Have a
  look at the "Safety" section of the README.md for more details.
- Add EncodeMode and MFType enums to public interface (used for the encoder options).

### Removed

- Remove byteorder dependency.
- Remove internal types from public interface.

## 0.2.2 - 2025-06-28

### Updated

- No functional updated.
- Moved into its own repository.

## 0.2.1 - 2025-05-01

### Fixed

- Fix integer overflow when decompressing uncompressed files over u32::MAX
- Allow all byteorder versions with major release 1
