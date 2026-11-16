# OSS-Fuzz

ClamAV has chosen to integrate with [oss-fuzz](https://github.com/google/oss-fuzz).

What this means is that this repository includes:

- Fuzz targets:
  - A function to which we apply fuzzing.
  - For ClamAV, clamav_scanfile_fuzzer.cc may be compiled with specific macros defined to produce multiple fuzz targets.
  - Additional fuzz targets may be added to fuzz other ClamAV inputs.
  
- Seed corpora:
  - A set of minimal test inputs that generate maximal code coverage.
  - Each ClamAV fuzz target has a seed corpus located under: fuzz/corpus/<target>

- Fuzzing dictionaries:
  - A simple dictionary of tokens used by the input language. This can have a dramatic positive effect on fuzzing efficiency. For example, when fuzzing an XML parser, a dictionary of XML tokens will help.
  - Some ClamAV fuzz targets have a dictionary located under: fuzz/dictionaries/<target>.dict

For more information on how this is set up, see: [ideal OSS-Fuzz integration](https://github.com/google/oss-fuzz/blob/master/docs/ideal_integration.md)

## RAR interface fuzz target

`clamav_unrar_iface_fuzzer` drives the five `libclamunrar_iface` functions (`unrar_open`,
`unrar_peek_file_header`, `unrar_extract_file`, `unrar_skip_file`, `unrar_close`) over one archive file, the way
`cli_scanrar_file()` does. It exists when ClamAV is built with UnRAR support (`-DENABLE_UNRAR=ON`, the default). If the
input holds more RAR signatures after the first, each piece is written as the next volume of the set, so volume handling
is reached.

Build and run (clang, AddressSanitizer + UndefinedBehaviorSanitizer):

    export CC=clang CXX=clang++ SANITIZER=address,undefined
    cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_FUZZ=ON \
        -DENABLE_APP=OFF -DENABLE_EXAMPLES=OFF -DENABLE_MAN_PAGES=OFF
    cmake --build build-fuzz --target clamav_unrar_iface_fuzzer
    UBSAN_OPTIONS=halt_on_error=1 TMPDIR=/dev/shm build-fuzz/fuzz/clamav_unrar_iface_fuzzer \
        -max_len=2097152 -timeout=10 -rss_limit_mb=2048 -dict=fuzz/dictionaries/clamav_unrar_iface_fuzzer.dict \
        -jobs=4 -workers=4 -max_total_time=1800 corpus/ seeds/

`seeds/` is any set of RAR files, such as `unit_tests/input/other_scanfiles/rar` and the decoded `clam-v2.rar` and
`clam-v3.rar` (see `unit_tests/input/xor_testfile.py`). A volume set can be seeded as its parts concatenated in order.

The UnRAR library itself is compiled without UBSan's enum and alignment checks: it casts the header type byte to an enum
without a range check, and on x86 it loads words from unaligned addresses on purpose. Everything else stays checked, and
the interface code and the harness keep all checks.

Every input that once failed is kept in `fuzz/regression/clamav_unrar_iface_fuzzer/` and replayed by
`clamav_unrar_iface_regression` (the same code without the fuzzing engine) as one CTest test per file:

    cmake --build build-fuzz --target clamav_unrar_iface_regression
    ctest --test-dir build-fuzz -R unrar_iface_regression
