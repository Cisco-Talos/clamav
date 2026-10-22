# PCRE2 match-data reuse and scan profiling

The subsequent [image optimization](image-hash-results.md) is now also built into
`build/perf-baseline`. The PCRE-only library measured below is preserved in
`build/perf-results/image-hash/before-lib`.

Measured on 2026-09-23, following the [LTO comparison](lto-results.md).
The scanner change is in `libclamav/matcher-pcre.c`; the running clamd service
has not been replaced.

## Implemented change

`cli_pcre_scanbuf()` now allocates PCRE2 match data once per executed pattern,
then reuses it through that pattern's global-match loop. ClamAV's error and
offset fields are cleared before each match. Switching patterns still creates
fresh data sized for the new pattern's capture count. Cleanup remains on the
existing exit path.

The allocation is local to the scan, not stored in the shared engine. Matching
options, match limits, per-iteration timeout checks, offset progression, and
signature evaluation are unchanged. This does not enable JIT or change scan
coverage. PCRE2 may retain interpreter workspace between matches; its lifetime
is bounded by the current pattern/scan rather than cached across files.

## Full-engine benchmark

These are `cl_scanfile()` measurements with a persistent engine, all the harness's
parsers enabled, and the clean cache disabled. Engine initialization and a warmup
pass are excluded. The before/after libraries have identical compiler settings:
GCC 14.2, C/C++ `-O2`, Rust release, no LTO. Only the PCRE scanner source differs.
The same harness executable loads each library using `LD_LIBRARY_PATH`.

Six rounds alternate before/after order. One worker runs on CPU 2; four workers
use CPUs 2, 0, 4, and 5, as in the earlier experiments. This is a busy shared
i5-1235U host, so run-to-run variation remains material.

Median files/second from the initial comparison:

| Workload | Workers | Before | After | Throughput change |
| --- | ---: | ---: | ---: | ---: |
| Global regex, 1,024 matches | 1 | 5,331 | 6,730 | +26.2% |
| Global regex, 1,024 matches | 4 | 11,277 | 14,477 | +28.4% |
| Global regex with captures, 1,024 matches | 1 | 4,118 | 5,325 | +29.3% |
| Global regex with captures, 1,024 matches | 4 | 10,266 | 11,816 | +15.1% |
| Single regex match | 1 | 14,067 | 14,870 | +5.7% |
| Single regex match | 4 | 28,883 | 26,891 | -6.9% |
| Regex with no match | 1 | 12,881 | 12,956 | +0.6% |
| Regex with no match | 4 | 29,193 | 30,336 | +3.9% |
| Repository corpus, clean verdicts | 1 | 85.0 | 88.3 | +3.9% |
| Repository corpus, clean verdicts | 4 | 198.7 | 195.8 | -1.5% |
| Repository corpus, detections | 1 | 157.6 | 156.5 | -0.7% |
| Repository corpus, detections | 4 | 351.6 | 348.4 | -0.9% |

The regex workloads are synthetic 4,102-byte files and one logical signature.
Positive cases assert the expected signature name; global cases also require
exactly 1,024 matches. The repository workloads use the same 60 decoded files
as the LTO comparison and one HDB signature (an unmatched hash for clean scans).
They do not exercise a production signature database.

All 818,592 timed scans in this initial comparison returned their expected
verdicts and signature names. The global-regex cases also reduced median CPU
time per file by about 14–23%, depending on the case and worker count. This is
evidence for a targeted optimization, not a general 15–29% production speedup.
The repository corpus shows no consistent improvement.

Raw results are under `build/perf-results/pcre-reuse/comparison`. The initial
short control runs hit the harness's 10,000-repetition cap, making some samples
shorter than one second. The benchmark now repeats the synthetic pathname eight
times per pass to allow longer runs. RSS values in the recorded runs are not
used: they include an inherited launcher high-water mark from hashing the
libraries. Library hashing now streams the input to avoid that allocation.

Longer control runs targeted two seconds per sample with six alternating rounds:

| Workload | Workers | Before files/s | After files/s | Throughput change |
| --- | ---: | ---: | ---: | ---: |
| Single regex match | 1 | 15,496 | 15,518 | +0.1% |
| Single regex match | 4 | 33,554 | 32,532 | -3.0% |
| Regex with no match | 1 | 15,499 | 15,472 | -0.2% |
| Regex with no match | 4 | 31,072 | 31,309 | +0.8% |

These additional 2,132,544 timed scans also returned all expected verdicts.
Single-worker controls were essentially unchanged. The four-worker single-match
case remained lower, although its ranges overlap substantially (before
30,876–36,658 files/s; after 29,843–36,208). This busy-host experiment cannot
exclude a small regression in that workload. Do not claim the patch speeds up
every regex scan. Raw follow-up data is in
`build/perf-results/pcre-reuse/longer-controls`.

## Validation

- Incremental build passed, including clamd and freshclam.
- Native libclamav, clamscan, and sigtool CTest suites passed.
- Eight new regression cases passed against both original and changed libraries:
  global match counts, a negative count condition, optional captures, many
  matches, switching capture counts, empty matches, and a limited regex followed
  by another pattern.
- The new regression cases also passed Valgrind's memory/leak checks.
- Concurrent synthetic scans shared one engine across four workers and checked
  every returned verdict.

The Rust implementation was unchanged in this follow-up. Daemon/socket tests
were unavailable during this experiment; timings measure the engine, not clamd
queueing or TCP command handling.

## Profiling the expensive fixtures

In the earlier single-worker clean runs, four InstallShield fixtures accounted
for about 69% of aggregate scan time and `clam.exe.2010.one` another 12%.
Built-in `--dev-performance` timing confirms nested processing: those five files
contain 7.08 MiB of input but scan 31.07 MiB. Its stage timers overlap and must
not be added as exclusive percentages.

Although kernel perf events are unavailable, Valgrind Callgrind works. A profile
of `clam_IScab_ext.exe` plus `clam.exe.2010.one`, collecting only during
`scan_common()`, gives these instruction counts:

| Function or path | Share of recorded instructions | Accounting |
| --- | ---: | --- |
| Image fuzzy-hash calculation | 50.8% | Inclusive of image decoding, conversion, resizing and hashing |
| Image resizing | About 30% | Within fuzzy hashing; do not add to its inclusive total |
| `cli_bm_scanbuff` | 18.2% | Self |
| `cli_ac_scanbuff` | 8.2% | Self |
| `filter_search_ext` | 4.9% | Self |
| LZX decompression | 5.2% | Inclusive |

These are instrumented instruction counts for two fixtures, not wall-time
percentages or a production profile. Even with a one-signature database, built-in
file-type recognition and nested-content matching still execute.

The next substantial candidate is image fuzzy hashing, especially resizing and
grayscale conversion. Any optimized implementation must preserve existing hash
values; changing the resize filter or numerical results can change detections.
Matcher-layout changes need a full signature database before making performance
claims. No image/hash algorithm was changed in this patch.

Callgrind output and built-in timing logs are in
`build/perf-results/pcre-reuse/callgrind-scan*` and
`build/perf-results/pcre-reuse/expensive-files-performance.log`.

## Reproduction and build identity

The original library was preserved before rebuilding:

- Before: `build/perf-results/pcre-reuse/baseline-lib/libclamav.so.14.0.0`,
  SHA-256 `b4af37a482518b9c29b6e47e22bd95b6086b6afcbdd60026fc217caac8bff0cd`.
- After: `build/perf-baseline/libclamav/libclamav.so.14.0.0`,
  SHA-256 `9e95fcfb4d4f3293610fe688459c1fa4512d489aafd5cdf28ff32c58168ef024`.

`build/perf-baseline` now contains this source change. The earlier LTO report
describes the binaries as they existed before this follow-up; the other LTO
build directories have not been rebuilt with this patch.

```sh
python3 benchmarks/compare-pcre-reuse.py \
  --before build/perf-results/pcre-reuse/baseline-lib \
  --after build/perf-baseline/libclamav \
  --output build/perf-results/pcre-reuse/reproduction \
  --cpus 2 0 4 5
```

Choose available CPUs appropriate to the machine. Use `--seconds 2` and
`--workloads single no-match` for longer control measurements. The original
library must be built/saved before applying the patch when reproducing elsewhere.
