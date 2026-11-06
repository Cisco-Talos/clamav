# Scanner optimizations versus original ClamAV

## Scope

The baseline is original scanner code at upstream commit
`72cd48c9faed4fa4afc22bc4ed0b9b19f8d3f8f7`. The candidate includes PCRE2 match-data
reuse, grayscale Lanczos specialization, packed AC candidate lists, compact
logical-signature scan state, and shared compiled logical expressions. It does
not remove signatures or narrow file-type/offset coverage.

Both native libraries use GCC 14.2 with C/C++ `-O2`, Rust 1.98.1 release, 16 Rust
codegen units, no LTO, and interpreted bytecode on Ubuntu 25.04 x86-64. The original
library was saved before scanner changes; build-target-only cbindgen dependency
discovery is a build-environment adjustment, not a scan algorithm change.

## Method

The one- and four-worker runs loaded 7,497,205 signatures. The later twelve-worker
run loads 7,497,219: four database files changed between experiments. Each paired
comparison uses the same database for both builds and verifies that it remains
unchanged during the run. The saved libraries and input corpus are identical
across worker configurations. Inputs are the 60 decoded repository HDB fixtures,
including archives, packed executables,
documents, installers and mail. The supplied database is not redistributed.
These fixtures are not a representative production distribution.

`benchmarks/compare-database.py` builds the same persistent-engine harness for
both libraries, verifies which library is loaded, and records library, database
and corpus hashes. All parsers enabled by the harness are identical in both
variants. The clean cache is disabled. Engine loading and one corpus warmup pass
are excluded from scan timing. Peak RSS includes the entire process, including
loading and warmup. Every timed status and exact detection name must match.

Two rounds alternate original/candidate, then candidate/original. One worker
scans 60 files per pass on CPU 2. Four workers share one engine and scan 120 files
per pass on CPUs 2, 0, 4 and 5. The twelve-worker follow-up also scans 120 files
per pass, sharing one engine across all available logical CPUs (0–11). It uses
the same two alternating rounds and saved libraries. The machine is a shared
Intel i5-1235U host.
Builds, tests and other database-heavy diagnostics are not run during measurement.
Small sample counts and host scheduling limit the precision of these results.

## Results

| Workload | Original time | Modified time | Time reduction | Original peak RSS | Modified peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 worker, 60 scans | 30.483 s | 13.238 s | 56.6% | 1,627.9 MiB | 1,584.5 MiB |
| 4 workers, 120 scans | 30.622 s | 13.771 s | 55.0% | 2,123.5 MiB | 1,684.8 MiB |
| 12 workers, 120 scans | 29.954 s | 11.988 s | 60.0% | 3,223.3 MiB | 1,924.3 MiB |

All 1,200 timed scan statuses and exact detection names match within their
paired comparisons, including 480 scans in the twelve-worker follow-up. Library,
database and corpus hashes remained unchanged during each comparison.

Additional medians:

- 1 worker, 60 scans: CPU 30.476 -> 13.235 s; load+compile 10.372 -> 10.754 s; RSS saved 43.5 MiB (2.7%).
- 4 workers, 120 scans: CPU 103.456 -> 46.374 s; load+compile 10.394 -> 10.579 s; RSS saved 438.7 MiB (20.7%).
- 12 workers, 120 scans: CPU 169.364 -> 63.964 s; load+compile 10.140 -> 9.853 s; RSS saved 1,299.0 MiB (40.3%).

One-worker wall times span 30.470–30.496 s originally and 12.152–14.325 s
afterward. Four-worker wall times span 29.750–31.495 s originally and
12.918–14.624 s afterward. Twelve-worker wall times span 29.108–30.800 s
originally and 11.822–12.155 s afterward. Two samples are not enough for a
confidence interval.

The twelve-worker run started with 1,572.8 MiB of available host RAM and
4,641.2 MiB already in swap. Available RAM fell to
361.6 MiB. System-wide counters recorded 1.35 GiB swapped in and 2.22 GiB
swapped out across loading, warmups and timed scans; these counters include other
host processes and cannot be attributed solely to the benchmark. Peak RSS counts
resident pages, not swapped-out pages. This is a shared-host result under memory
pressure. The changed database and host conditions prevent treating the older
four-worker timings as a controlled worker-scaling comparison. Host snapshots
are retained in `corpus-twelve/host-memory.json`.

RSS reflects active scanning, not idle engine size. Earlier isolated AC-locality
measurements found about 100 MiB more engine memory: candidate records grow from
24 to 32 bytes and the pool retains freed construction blocks. Compact scan
state offsets that during active scans but does not eliminate the idle cost.
PE plus generic logical counter/offset arrays request 219.91 MiB originally and
16.13 MiB afterward per live scan context. Requested allocation savings and RSS
savings differ because zero-filled pages may remain shared until written.

Compiled expressions add bounded engine storage: at most 1 MiB requested tree
and table storage per target matcher. All 313,309 ordinary logical signatures in
this database use 1,830 shared trees. Original strings remain allocated for
fallback and ownership compatibility.

These measurements do not establish a production throughput guarantee, daemon
TCP latency, or a Docker-specific improvement. Database composition, clean-cache
hits, file mix, nesting, worker count and memory pressure can change the result.

## Validation

The native libclamav, Rust, clamscan and sigtool suites pass. Thirteen native
matcher cases pass under Valgrind with zero memory errors and no definitely,
indirectly or possibly lost bytes (1,531 bytes remain reachable). The database
expression checker passes 2,187,229 comparisons with the original interpreter,
checking return values, counts and matched-ID sets. Rust regression tests compare
specialized resize pixels with the generic image implementation. These checks do
not prove equivalence for every possible signature/file combination.

## Reproduction

Build and preserve the original library before applying the optimization series,
then build the candidate with the same toolchain and flags. Both builds need
CMake tests enabled to decode the fixtures. This workspace uses
`build/perf-baseline` for the candidate and saves libraries separately.
Generate the corpus list after building and running the clamscan suite:

```sh
python3 - <<'PY'
from pathlib import Path
corpus = Path('build/perf-baseline/unit_tests/input/clamav_hdb_scanfiles')
files = sorted(p.resolve() for p in corpus.iterdir() if p.is_file())
assert len(files) == 60
Path('build/corpus.txt').write_text(''.join(str(p) + '\n' for p in files))
PY
python3 benchmarks/compare-database.py \
  --before /absolute/path/to/original-lib \
  --after /absolute/path/to/candidate-lib \
  --database /absolute/path/to/signatures \
  --files build/corpus.txt --output build/comparison-one \
  --rounds 2 --cpus 2
```

For four workers, use `--cpus 2 0 4 5 --repetitions 2` and another output directory.
For twelve workers, use `--cpus 0 1 2 3 4 5 6 7 8 9 10 11 --repetitions 2`.
Choose CPU IDs available on your machine. `--build` selects a candidate CMake
build tree other than the default `build/perf-baseline`.

The twelve-worker follow-up in this workspace is reproduced with:

```sh
python3 benchmarks/compare-database.py \
  --before build/perf-results/pcre-reuse/baseline-lib \
  --after build/perf-results/original-comparison/after-lib \
  --database db --files build/perf-results/matcher/corpus.txt \
  --output build/perf-results/original-comparison/corpus-twelve-recheck \
  --rounds 2 --repetitions 2 --cpus 0 1 2 3 4 5 6 7 8 9 10 11
```

Compile and run the full-database expression checker against the candidate:

```sh
cc -O2 -std=gnu11 -fgnu89-inline -DHAVE_CONFIG_H \
  -Ilibclamav -Ibuild/perf-baseline -Ilibclamav_rust \
  -Ilibclammspack -Ilibclamunrar_iface -I/usr/include/json-c \
  benchmarks/check-logical-expressions.c \
  -Lbuild/perf-baseline/libclamav \
  -Wl,-rpath,"$PWD/build/perf-baseline/libclamav" -lclamav \
  -o build/check-expressions
build/check-expressions /absolute/path/to/signatures certs
```

Local raw comparison artifacts are in
`build/perf-results/original-comparison/corpus-one`, `corpus-four` and
`corpus-twelve`; they are
excluded from Git. The JSON metadata contains full input/database identities;
TSV files contain every timed verdict and per-file measurement.

Saved shared-library SHA-256:

- Original: `b4af37a482518b9c29b6e47e22bd95b6086b6afcbdd60026fc217caac8bff0cd`.
- Candidate: `1c05255b57cae86ed2e936799b0654690cfb4d2c53b446b1f2c3a3fcc2c4ddaa`.
