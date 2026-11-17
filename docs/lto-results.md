# LTO build and scan experiment — 2026-09-23

Subsequent work rebuilt `build/perf-baseline` with PCRE allocation and
[image hashing](image-hash-results.md) optimizations.
The results below describe the original binaries; the original baseline library
was preserved. See [the follow-up report](pcre-reuse-results.md) for locations and
before/after build hashes.

All three variants built successfully, including **clamd and freshclam**, and
passed the libclamav, libclamav_rust, clamscan, and sigtool test suites.

**There was no consistent scan-speed improvement on this test corpus.** Median
throughput changes versus baseline ranged from −1.6% to +1.3%, with substantial
overlap between individual runs. Rust ThinLTO substantially reduced library
size. These results support it as a size optimization; they do not establish it
as a solution to the deployment's scan latency or throughput problem.

## Configurations

Checkout: `72cd48c` (1.6.0 development), plus the common offline header-generation
fix described below. Host: Intel Core i5-1235U, Ubuntu 25.04, GCC/G++ 14.2.0,
Rust 1.98.1, CMake 3.31.6.

| Variant | C/C++ | Rust | Build directory |
| --- | --- | --- | --- |
| Baseline | RelWithDebInfo, `-O2`, no IPO | Release, `opt-level=3`, `lto=false`, 16 codegen units, debug info | `build/perf-baseline` |
| C/C++ LTO | Same, plus CMake IPO (`-flto=auto`) | Same as baseline | `build/perf-c-lto` |
| C/C++ + Rust LTO | Same C/C++ LTO | Release, `lto=thin`, 1 codegen unit, debug info | `build/perf-c-rust-lto` |

Assertions, scanner features, and bytecode interpreter selection were kept the
same. No CPU-specific instruction flags, PGO, or cross-language LTO were used.
The combined variant tests Rust ThinLTO and fewer codegen units together; it does
not isolate their individual effects. Compiler commands confirmed the flags,
and all three generated identical `clamav_rust.h` files.

## Throughput

Median original files per second over six runs per cell, with CPU affinity fixed:

| Workload | Workers | Baseline | C/C++ LTO | C/C++ + Rust LTO |
| --- | ---: | ---: | ---: | ---: |
| Test-signature detections | 1 | 172.3 | 169.6 (−1.6%) | 171.6 (−0.4%) |
| Test-signature detections | 4 | 355.9 | 357.9 (+0.6%) | 357.2 (+0.4%) |
| No-match scans | 1 | 97.5 | 98.0 (+0.5%) | 97.7 (+0.2%) |
| No-match scans | 4 | 211.7 | 209.2 (−1.2%) | 214.5 (+1.3%) |

The percentages are descriptive differences between medians, not established
causal speedups. For example, four-worker no-match throughput ranged from
196.7–239.0 files/s for baseline, 132.0–215.4 for C/C++ LTO, and 174.7–225.0 for
combined LTO. The shared host still introduced variation despite CPU affinity.
Earlier runs without affinity were also inconsistent and are retained separately.

Scan-call latency, median of each run's p99, in milliseconds:

| Workload | Workers | Baseline | C/C++ LTO | C/C++ + Rust LTO |
| --- | ---: | ---: | ---: | ---: |
| Test-signature detections | 1 | 118.0 | 120.5 | 119.1 |
| Test-signature detections | 4 | 190.3 | 193.7 | 191.7 |
| No-match scans | 1 | 128.8 | 128.2 | 128.6 |
| No-match scans | 4 | 223.4 | 227.4 | 225.9 |

CPU time per file showed similarly small differences. In the four-worker
no-match case, it was 17.01 ms for baseline, 17.04 ms for C/C++ LTO, and 16.81 ms
for combined LTO. There is no demonstrated tail-latency improvement here.

## Size and memory

| libclamav.so measurement | Baseline | C/C++ LTO | C/C++ + Rust LTO |
| --- | ---: | ---: | ---: |
| File bytes, including debug info | 131,610,472 | 131,803,384 | 64,624,112 |
| GNU `size` text column (code and read-only sections) | 12,358,849 | 12,331,194 | 6,156,373 |

The combined variant reduced the file size by about **51%** and the GNU `size`
text total by about **50%**. Its actual ELF `.text` section fell from 8,804,514 to
4,489,170 bytes. C/C++ LTO alone barely changed size.

This does not halve runtime memory. Median process peak RSS for four-worker
no-match scans was 64.4 MiB, 64.5 MiB, and 60.9 MiB respectively. Those small
test-database footprints do not predict memory use with production signatures.

## Method and limits

- 60 decoded fixtures from `unit_tests/input/clamav_hdb_scanfiles`, totaling
  10,051,695 input bytes: archives, packed executables, documents, and mail.
- Detection workload: the repository's `clamav.hdb`, containing one test hash
  signature. Every fixture had to return `ClamAV-Test-File.UNOFFICIAL`, including
  the RAR fixtures. This checks parser/plugin availability as well as equivalence.
- No-match workload: the same fixtures, with the signature's hash replaced by an
  unmatched sentinel of the same hash type and target size. Every fixture had to
  return clean. This prevents an early test-signature detection from ending scans.
- One engine loaded and compiled per process. Engine startup and one full warmup
  pass were excluded from timing. The filesystem cache was warm, the ClamAV clean
  cache was explicitly disabled, and default scan limits were retained.
- Parsing enabled for archives, ELF, PDF, SWF, HWP3, XML documents, mail, OLE2,
  HTML, PE, OneNote, and images, including image fuzzy hashing. General heuristic
  alerts enabled. The same settings applied to every variant.
- In-process `cl_scanfile()` calls, with one or four worker threads. Wall timing
  includes thread creation and scheduling; per-file latency measures the scan
  call, excluding client queueing. CPU time covers the timed phase; peak RSS
  covers the process lifetime, including startup/warmup.
- Six repetitions of each variant/worker combination. Run order covered all six
  permutations of the three variants. All recorded return codes and detection
  names were compared per file. **No verdict mismatches or scan errors occurred.**
- One worker pinned to logical CPU 2; four workers to CPUs 2, 0, 4, and 5. These
  represent four distinct physical cores here (two performance, two efficiency).
- Listening sockets are prohibited in this session, so TCP/Unix daemon tests and
  freshclam socket integration tests could not run. These are engine measurements,
  not daemon request-latency measurements. The production client's TCP path scans
  likewise read files directly, but also include protocol and queueing costs.

The single-signature database is a major limitation: this experiment exercises
parsers, extraction, hashing, and basic matching, but not a production-sized
signature matcher or its memory pressure. The no-match scenario also uses test
fixtures, not representative clean customer documents. Treat the throughput
values as comparisons within this experiment, not capacity estimates.

## Changes and reproduction

[`libclamav_rust/cbindgen.toml`](../libclamav_rust/cbindgen.toml) now enables
`only_target_dependencies`. Cargo supplies the build target, so header generation
uses the dependencies fetched for that target instead of requesting unrelated
Android/other-platform packages during an offline build. Scanner algorithms and
detection policy were not changed.

Build each variant, using the already populated `build/perf-cargo-home`:

```sh
bash benchmarks/build-lto.sh baseline
bash benchmarks/build-lto.sh c-lto
bash benchmarks/build-lto.sh c-rust-lto
```

The build script uses two native build jobs and one Cargo job. Fresh variant
directories are seeded with baseline Cargo dependency artifacts; the project's
own Rust crate and header are regenerated, and Cargo fingerprints determine
which dependencies can be reused for each profile.

Run the measured benchmark (the CPU numbers below are specific to this host):

```sh
python3 benchmarks/compare-lto.py --workload detections \
  --cpus 2 0 4 5 --output build/perf-results/pinned
python3 benchmarks/compare-lto.py --workload clean \
  --cpus 2 0 4 5 --output build/perf-results/pinned
```

The selected CTest suites were `libclamav`, `libclamav_rust`, `clamscan`, and
`sigtool`. Rust tests used the same Cargo release-profile environment values as
their corresponding build, with offline mode and the same Cargo home.

Artifacts in `build/perf-results` include configure/build logs, test logs,
`build-metadata.json`, and both benchmark sets. Under `pinned/detections` and
`pinned/clean`, `summary.json` contains aggregates, `samples.json` contains every
timed batch, `manifest.json` records input hashes/sizes, and the TSV files contain
every timed scan's status, name, and duration. The driver verifies that each
harness loads its intended libclamav and supplies that build's UnRAR libraries.

For a decision about production speed, the next measurement should use the real
signature database and file mix. The current evidence shows a worthwhile size
reduction from combined LTO, but no reliable throughput gain.
