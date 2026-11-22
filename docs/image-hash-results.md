# Image fuzzy-hash optimization — 2026-09-23

Implemented a grayscale-specific Lanczos3 resize in
`libclamav_rust/src/fuzzy_hash/resize.rs`, called by `fuzzy_hash.rs`.
The benchmarked image build is preserved in `build/perf-results/matcher/before-lib`.
`build/perf-baseline` now also contains the subsequent
[AC matcher changes](matcher-results.md). No service was installed or restarted.

## Implementation and compatibility

The previous image-crate resize used a four-channel floating-point intermediate
even for grayscale input. The new implementation stores only luminance, reducing
that intermediate from `width × 32 × 16` to `width × 32 × 4` bytes. It traverses
contiguous source rows during the vertical pass, improving locality and allowing
vectorization across independent output pixels.

The Lanczos3 kernel, sample bounds, coefficient normalization, vertical-before-
horizontal ordering, per-pixel accumulation order, final clamping, and rounding
match image 0.25.8. There is no intermediate quantization. Empty images and images
already sized 32×32 keep the previous special-case behavior.

Two smaller changes avoid cloning already-decoded RGB buffers (`into_rgb8`) and
iterate grayscale pixels linearly instead of repeatedly calculating coordinates.
The RGB-to-luminance arithmetic, DCT, median selection, hash packing, scan options,
and detection rules are unchanged. No unsafe code or new dependencies were added
to the scanner. The specialized resize includes the upstream MIT license notice.

Validation:

- 865 generated grayscale images compare every output pixel against the existing
  image-crate resize: empty, tiny, 32×32, upsampled, downsampled, narrow/tall,
  1920×1080, random dimensions, solid colors, checkerboards, gradients, and noise.
- All 120 encoded test images produced identical final 64-bit hashes before and
  after. Inputs cover grayscale, grayscale+alpha, RGB, RGBA, 16-bit grayscale,
  PNG, JPEG, GIF, BMP, TIFF, WebP, PPM, and two repository PNGs. The repository
  logo still hashes to `af2ad01ed42993c7`.
- The native libclamav, Rust, clamscan, and sigtool CTest suites passed. The Rust
  suite passed 66 tests; clamscan passed 134 with one skip, including existing
  fuzzy-image signature and embedded-image detection tests.

The pixel-comparison test deliberately uses the dependency's generic resize as
the reference. If an image-crate update changes its results, review compatibility
rather than silently accepting changed hashes.

## Hash calculation benchmark

Both libraries include the preceding PCRE optimization and use the same compiler
settings: C/C++ `-O2`, Rust release, no LTO, no CPU-specific flags. Six rounds
alternate library order, pinned to CPU 2. Each process warms the image before
timing repeated hash calculations. Timings include image decoding and the Python
FFI/check loop, but exclude file reads and library loading.

| Encoded input | Before ms/hash | After ms/hash | Time reduction |
| --- | ---: | ---: | ---: |
| 32×32 RGB gradient PNG | 0.0165 | 0.0158 | 4.5% |
| 641×479 RGB gradient PNG | 3.930 | 1.671 | 57.5% |
| 641×479 RGB random JPEG | 5.456 | 3.537 | 35.2% |
| 1920×1080 RGB gradient PNG | 25.655 | 11.803 | 54.0% |

All 123,876 timed hash calls matched their original hash. These are generated
inputs, not a production image distribution. Results, encoded inputs, and build
hashes are saved under `build/perf-results/image-hash/hashes`.

## Full-engine corpus benchmark

The existing persistent-engine harness scans the same 60 repository fixtures,
with cache disabled, startup and warmup excluded, and all its parsers enabled.
The database contains one HDB signature; the clean case substitutes an unmatched
hash. Each of six alternating rounds targets two seconds per sample. One worker
uses CPU 2, and four workers use CPUs 2, 0, 4, and 5.

| Workload | Workers | Before files/s | After files/s | Throughput change |
| --- | ---: | ---: | ---: | ---: |
| Clean corpus | 1 | 89.77 | 92.42 | +3.0% |
| Clean corpus | 4 | 195.99 | 202.36 | +3.2% |
| Detection corpus | 1 | 152.00 | 136.13 | -10.4% |
| Detection corpus | 4 | 330.23 | 321.02 | -2.8% |

All 18,000 timed scans returned their expected verdicts and signature names.
The clean OneNote fixture's median single-worker scan time fell from 83.33 ms to
59.04 ms (29.2% less time). Installer scans were largely unchanged. The mixed
corpus benefits less because many files do not perform expensive image hashing.

The detection slowdown triggered a separate investigation. The largest affected
installer, `clam_IScab_int.exe`, executes effectively the same instructions in
Callgrind: 783,604,257 before and 783,607,282 after, a difference below 0.001%.
The C matcher/scanner function addresses are also unchanged. This input reaches
the test detection without the expensive image-hash work. Instruction counts
are not CPU-cycle measurements and cannot by themselves exclude a regression.

A longer detection-only rerun (three seconds per sample, CPU 0 for one worker,
and CPUs 0, 2, 4, 5 for four workers) produced:

| Workers | Before files/s | After files/s | Ratio-of-medians change | Median change within paired rounds |
| --- | ---: | ---: | ---: | ---: |
| 1 | 150.95 | 149.96 | -0.7% | +1.3% |
| 4 | 296.95 | 273.50 | -7.9% | -2.4% |

The different summary statistics reflect substantial drift and variation across
rounds. This rerun verified another 16,560 scan verdicts. An unchanged-build
control, running the same saved library under both labels, then showed -2.5%
and +2.2% ratio-of-medians differences for one and four workers respectively
(9,360 more correct scan verdicts). That confirms measurement noise, but does
not prove every observed slowdown is noise. A smaller multithreaded regression
in the mixed detection workload remains possible. Do not infer a general scan
throughput improvement from the image-specific gains.

Those follow-up data sets are in `build/perf-results/image-hash/detection-recheck`
and `build/perf-results/image-hash/unchanged-control`. Their `summary.json` files
include both summary statistics and the range of within-round changes.

This is a busy shared i5-1235U host. Treat the mixed-corpus results as synthetic
measurements, not production speed guarantees. The benchmark does not include
clamd queueing, TCP command handling, or a full signature database. No scan
coverage or limits were reduced. Raw scan data is under
`build/perf-results/image-hash/scans`; installer profiles are under
`build/perf-results/image-hash/*-installer*`.

## Reproduction

The before library (including only the PCRE optimization) is preserved at
`build/perf-results/image-hash/before-lib/libclamav.so.14.0.0`, SHA-256
`9e95fcfb4d4f3293610fe688459c1fa4512d489aafd5cdf28ff32c58168ef024`.
The new library is `build/perf-baseline/libclamav/libclamav.so.14.0.0`, SHA-256
`78e3adb9e1e249066f92fd9632399db5bc006561c4365748201365c674446cce`.

```sh
# Requires Pillow for deterministic test-image generation (11.1.0 was used).
python3 benchmarks/compare-image-hash.py \
  --before build/perf-results/image-hash/before-lib/libclamav.so \
  --after build/perf-baseline/libclamav/libclamav.so \
  --output build/perf-results/image-hash/hash-reproduction --cpu 2

# Reuse the persistent-engine before/after harness for the repository corpus.
python3 benchmarks/compare-pcre-reuse.py \
  --before build/perf-results/image-hash/before-lib \
  --after build/perf-baseline/libclamav \
  --output build/perf-results/image-hash/scan-reproduction \
  --cpus 2 0 4 5 --seconds 2 --workloads corpus-clean corpus-detections
```

Select available CPUs appropriate to the host. On another checkout, build and
save the before library prior to applying the image changes. Earlier LTO and
PCRE reports describe historical binaries; `build/perf-baseline` now includes
both scanner optimizations.
