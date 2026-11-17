# Full-database matcher experiment — 2026-09-23

Follow-up: [compact scan state and shared logical expressions](performance-memory-results.md)
measure additional speed and memory improvements on top of this experiment.
The results below describe the earlier AC-locality snapshot; the current
`build/perf-baseline` includes the follow-up changes.

This experiment uses the user-supplied `db/` directory, which loads **7,497,205
signatures**. It includes official main/daily/bytecode CLDs and third-party
databases. The official headers identify main version 63, daily 28049 and
bytecode 339. Database contents are not modified. File hashes are recorded in
each benchmark's local `metadata.json`; the signature files are not part of the
source changes.

The input workload remains the 60 decoded repository HDB fixtures, as requested.
These are test detections, including archives, packed executables, installers,
documents and mail, not a sample of production uploads. The older archived daily
database found earlier was superseded by `db/` before these measurements.

## Bottleneck and implementation

The exported-matcher timing probe in `benchmarks/matcher-profile.c` uses thread
CPU time, excluding database loading and compilation. On `clam_IScab_int.exe`,
the baseline spends 4.685 CPU seconds in the PE-target Aho–Corasick matcher,
0.293 seconds in generic AC matching, 0.639 seconds in PCRE and 0.160 seconds in
Boyer–Moore matching. These calls are part of a full scan, not separate
microbenchmarks. The probe adds overhead and this run was not CPU-pinned.

Linux `profil()` sampling points primarily at AC candidate traversal, especially
the access to the full pattern's multipart number. Sampling also identifies
per-scan logical-signature state initialization as a remaining cost. Sampling
continues through cleanup and covers only the first 16 MiB of libclamav's mapped
address space; the matcher timers are the more precise attribution above.

Two related changes in `matcher-ac.c`, `matcher-ac.h` and `matcher.h` reduce
scattered reads:

- Cache the multipart number and the first exact suffix byte in the candidate
  entry. Reject a mismatching byte before fetching the full pattern. Case-folded
  bytes, wildcards and empty suffixes retain full matching. The full matcher
  still validates every surviving candidate.
- During compilation, copy candidates into contiguous storage grouped by their
  owning trie node before linking them. Keep the existing candidate order,
  identical-pattern chains and failure links. Free the packed allocation once
  at engine destruction. If allocation fails, retain the original lists.

The trie depth, signature contents, scan limits, timeouts and detection options
are unchanged. All new runtime data is immutable after engine compilation.

A preliminary next-byte-only experiment was noisy and inconclusive. Increasing
the existing developer AC-depth option from 3 to 4 exhausted available memory
during loading and was interrupted. Neither is presented as a deployment
recommendation.

## Measurement method

`benchmarks/compare-database.py` builds the persistent-engine harness, selects
each saved library through `LD_LIBRARY_PATH`, verifies selection using `ldd`,
and alternates before/after order. Database startup and a full warmup pass are
excluded from scan timing. The engine scan cache is disabled, all harness
parsers are enabled, and files are scanned by local path. The driver checks
every result and detection name against the baseline and verifies that the
database, inputs and libraries did not change during the run.

Both libraries include the earlier PCRE and image-hash changes, use C/C++ `-O2`
and Rust release, and do not use LTO or CPU-specific compilation. The comparison
isolates the AC changes. Peak RSS includes engine startup and warmup; it is not
an incremental allocation measurement. Tests and builds are not run concurrently
with the full-corpus timing runs. Shared-host activity and clock variation remain
possible.

## Results

Final-build single-worker results use two alternating rounds, pinned to CPU 2.
Each timed pass scans all 60 fixtures once.

| Metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Median scan wall time | 30.326 s | 25.990 s | 14.3% less time |
| Median scan CPU time | 30.287 s | 25.979 s | 14.2% less CPU time |
| Median peak RSS | 1,618.7 MiB | 1,718.3 MiB | +99.5 MiB |
| Median database load + compile | 9.913 s | 10.380 s | +0.467 s |

The scan-time reduction corresponds to about 16.7% greater throughput for this
particular workload. Individual paired reductions are 15.5% and 13.0%. An
earlier build of the same approach gave 9.6% and 32.6%; its slower baseline
outlier illustrates why the larger preliminary result is not the headline.

| Fixture | Before median | After median | Time reduction |
| --- | ---: | ---: | ---: |
| `clam_IScab_int.exe` | 11.651 s | 9.308 s | 20.1% |
| `clam_IScab_ext.exe` | 6.562 s | 5.361 s | 18.3% |
| `clam_ISmsi_int.exe` | 3.013 s | 2.516 s | 16.5% |
| `clam_ISmsi_ext.exe` | 1.276 s | 0.938 s | 26.5% |
| `clam.ole.doc` | 0.896 s | 0.990 s | -10.5% |

This is not a uniform improvement across formats. The DOC result is a measured
regression in these two rounds; smaller files also show mixed results. A real
deployment's file distribution, cache hit rate and memory budget determine
whether the overall tradeoff is beneficial.

Four-worker results use CPUs 2, 0, 4 and 5, with two alternating rounds and two
corpus repetitions (120 scans) per timed pass. Workers share a single engine.

| Metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Median scan wall time | 34.614 s | 27.189 s | 21.4% less time |
| Median scan CPU time | 119.293 s | 91.064 s | 23.7% less CPU time |
| Median peak RSS | 2,123.9 MiB | 2,216.8 MiB | +92.9 MiB |
| Median database load + compile | 9.987 s | 10.159 s | +0.172 s |

This is about 27.3% greater throughput. The individual paired wall-time
reductions are 21.8% and 21.1%. All **720 timed scans** in the final single- and
four-worker comparisons returned the baseline verdict and detection name.
Database and input hashes remained identical. The extra memory is roughly
93–100 MiB in these runs; the four workers do not each get a copy of the index.

These are two-round engine measurements on one shared machine, not confidence
intervals or an end-to-end clamd deployment benchmark. Recheck with the production
file mix before choosing a deployment on the strength of the percentages alone.

Final library identities (SHA-256):

- Before: `78e3adb9e1e249066f92fd9632399db5bc006561c4365748201365c674446cce`.
- After: `ed1f5d015826374353465e66126a2a173637e237a3ad2b3270e725f18ee5d2aa`.

Raw final-build measurements are under `build/perf-results/matcher/corpus-final`
and `corpus-four`. Earlier exploratory results are kept separately in `installer`
and `corpus`. The `matcher/final-lib` snapshot preserves this experiment's final
candidate; the current build also includes the follow-up linked above. No
running daemon was changed.

## Validation

The native libclamav, Rust, clamscan and sigtool suites pass with the packed
matcher. Clamscan passes 134 tests with one skip. A new native regression test
covers 18 inputs, including failed candidates followed by a failure-link match,
empty suffixes, truncated input, wildcard and case-insensitive suffixes, shared
patterns with different offsets, multipart ordering, zero and high-bit bytes.
Existing all-match tests also pass.

Valgrind runs all 10 matcher tests on the final build with `CK_FORK=no`: zero
memory errors, zero definitely/indirectly/possibly lost bytes. Its 1,531 bytes of
still-reachable allocations are not lost allocations. This exercises candidate
storage construction, scanning and destruction.

The benchmark checks exact per-file verdicts and detection names with the full
database. It cannot establish equivalence for every possible signature or file.
The source change is a necessary-byte rejection plus a storage-layout change;
the existing full matcher remains responsible for acceptance.

## Reproduction

From the repository root, with the saved baseline and candidate libraries:

```sh
python3 benchmarks/compare-database.py \
  --before build/perf-results/matcher/before-lib \
  --after build/perf-results/matcher/final-lib \
  --database db \
  --files build/perf-results/matcher/corpus.txt \
  --output build/perf-results/matcher/recheck \
  --rounds 2 --cpus 2
```

Use `--cpus 2 0 4 5 --repetitions 2` for four workers sharing the same engine. The file list must
contain one absolute input path per line. Raw per-file timings and stderr are
saved alongside summaries. No service installation or daemon restart is needed
for these measurements. This environment cannot listen on sockets, so the
measurements exercise the engine used by clamd rather than its TCP queue.
