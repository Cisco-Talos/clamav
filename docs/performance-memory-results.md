# Compact scan state and shared logical expressions

This follow-up implements the first two opportunities identified in the memory
analysis: allocate counters and offsets to each logical signature's actual
width, and compile repeated logical expressions once. It retains the earlier
PCRE, image-hash and AC candidate-locality changes.

## Implementation

Ordinary logical signatures previously received 64 counters, 64 first-match
offsets and 64 last-match offsets on every scan. The compiled engine now records
each signature's required width. Scan-local arrays remain contiguous, with the
existing row pointers preserving the indexing used by matching code. First/last
offset arrays are allocated without an unnecessary zero-fill before initializing
them to `CLI_OFF_NONE`.

Bytecode, YARA, macros, byte-comparison owners, and signatures with missing or
out-of-range width metadata retain 64 slots. Bytecode exposes whole rows through
its hooks and copies all 64 entries. Byte-comparison references are not currently
validated against the owner's subsignature count. Retaining their old allocation
avoids introducing a narrower bound. The old private initializer remains
available for callers that do not have a compiled matcher.

For the supplied database, PE plus generic counter/offset storage decreases from
230,593,536 to 16,915,632 requested bytes: **219.91 to 16.13 MiB**, a 203.78 MiB
reduction per simultaneously allocated PE/generic scan context. This excludes
row-pointer arrays, multipart matches, YARA state, and other scan allocations.
Nested scans can have multiple live contexts. It is not a prediction of the RSS
saving: zero-filled counters can use shared kernel pages until written.

The expression compiler records a tree using the existing parser, preserving its
operator grouping. Runtime evaluation preserves count overflow, matched-ID
sets, zero-match conditions and block modifiers, including the existing rule
that a modified block does not propagate its IDs. Both operands are evaluated
because Boolean short-circuiting would change enclosing count conditions.

Identical expressions share an immutable tree within each target matcher. The
16-bit reference fits in existing `cli_ac_lsig` padding; that structure remains
168 bytes on this build. All 313,309 ordinary logical signatures in the supplied
database use 1,830 shared trees. The 1,409 distinct strings found previously were
counted across all targets; trees are shared within a target, so the totals differ.

Compilation is bounded to 4,096-character expressions, 16-bit tree IDs, and
1 MiB of requested compiled-tree/table storage per target matcher. Expressions
outside those limits use the original interpreter. Original expression strings
are retained for that fallback and existing ownership rules. This change does
not claim to reclaim their allocations. The temporary deduplication hash table
is freed after compilation. Rust's checked-in C bindings are regenerated to
match the updated structures, including the earlier AC list changes.

## Measurement method

The database is the unchanged user-supplied `db/` directory: 7,497,205 loaded
signatures. Inputs are the 60 decoded repository HDB fixtures selected earlier.
These contain archives, packed executables, documents, installers and mail;
they are test detections, not a production upload distribution.

The persistent-engine harness disables the scan cache, enables the same parsers
in both builds, warms up on the corpus, and excludes database loading and warmup
from timed scans. The baseline is the previous AC-locality build, already
including the PCRE and image-hash improvements. Results therefore measure these
new changes, rather than comparing against unmodified ClamAV.

Runs alternate before/after and after/before. One worker scans 60 files per
timed pass on CPU 2. Four workers share one engine and scan 120 files per timed
pass on CPUs 2, 0, 4 and 5. Peak RSS covers the entire process, including loading
and warmup. Builds, tests and database-heavy diagnostics are kept outside the
timed comparisons. Database, corpus and shared-library hashes are recorded and
verified; exact detection statuses and names are compared for every timed scan.

These are engine measurements on one shared host, not a TCP clamd benchmark.
Socket access was unavailable during these experiments; subsequent Docker TCP
validation is documented separately in `docker/README.md`. Production file distribution, cache
hits, nesting, CPU scheduling and concurrency will affect the result.

## Results

Final-build results are medians of two alternating rounds per configuration.

| One worker, 60 scans per pass | Previous optimized build | This build |
| --- | ---: | ---: |
| Scan wall time | 22.367 s | 11.318 s |
| Scan CPU time | 22.363 s | 11.316 s |
| Process peak RSS | 1,719.6 MiB | 1,584.7 MiB |
| Database load + compile | 8.539 s | 8.645 s |

This is **49.4% less scan time**, about **97.6% more throughput**, and
**134.9 MiB less peak RSS**. Paired time reductions are 48.9% and 49.8%.

| Four workers, 120 scans per pass | Previous optimized build | This build |
| --- | ---: | ---: |
| Scan wall time | 26.394 s | 11.718 s |
| Scan CPU time | 76.027 s | 39.308 s |
| Process peak RSS | 2,216.6 MiB | 1,685.0 MiB |
| Database load + compile | 8.602 s | 8.839 s |

This is **55.6% less scan time**, about **125.2% more throughput**, and
**531.6 MiB less peak RSS** (24.0%). Paired time reductions are 60.4% and 49.3%:
the baseline wall times vary from 22.85 to 29.94 seconds, while the candidate
takes 11.59 to 11.84 seconds. Median CPU consumption falls 48.3%. These are
small-sample results; the spread in baseline scheduling is a reason not to treat
the median wall-time percentage as a production guarantee.

Selected single-worker fixture medians:

| Fixture | Before | After | Time reduction |
| --- | ---: | ---: | ---: |
| `clam_IScab_int.exe` | 8.055 s | 4.814 s | 40.2% |
| `clam_IScab_ext.exe` | 4.542 s | 2.993 s | 34.1% |
| `clam_ISmsi_int.exe` | 2.146 s | 1.258 s | 41.4% |
| `clam.ole.doc` | 0.806 s | 0.186 s | 77.0% |
| `clam_ISmsi_ext.exe` | 0.802 s | 0.599 s | 25.3% |

All **720 timed scans** across the final one- and four-worker comparisons retain
the baseline status and exact detection name. Database and corpus hashes remain
unchanged. Raw output is in `build/perf-results/logical-expressions/corpus-final`
and `corpus-four`.

The earlier compact-state-only experiment, before expression compilation,
measured 25.434 to 19.996 seconds (21.4% less time) and 1,706.6 to 1,584.3 MiB
peak RSS with one worker. That is a separate experiment with different clock
and scheduling conditions; its percentages must not be added to the combined
results above. Raw data is in `build/perf-results/scan-state/corpus`.

A separate two-round comparison keeps compact scan state in both builds and
adds the expression compiler in the candidate. Median scan time falls from
**16.564 to 11.300 seconds**, a further **31.8% reduction**. Peak RSS is
1,584.6 versus 1,586.1 MiB: approximately 1.5 MiB more in that comparison,
including shared trees and allocator variation. All 240 timed results and names
match. Raw data is in `build/perf-results/logical-expressions/expressions-isolated`.

## Validation

The native libclamav, Rust, clamscan and sigtool suites **pass** on the final
build. Native regression tests cover compact row boundaries and initialization,
independent scan contexts, compatibility fallbacks, and the original initializer.
Expression tests compare return values, counts and ID sets against the
interpreter, including zero counters, maximum counters, mixed operators,
repeated IDs, nested count/distinct-ID modifiers, shared trees, and interpreter
fallback after size or memory limits.

`benchmarks/check-logical-expressions.c` additionally validates the full database:
every ordinary signature mapping is checked with zero counters, and every shared
tree is compared against the interpreter with 1,024 additional counter vectors.
All **2,187,229 comparisons pass**. All 13 matcher tests also pass under Valgrind
with in-process fixtures (`CK_FORK=no`): zero memory errors and zero
definitely/indirectly/possibly lost bytes. The 1,531 still-reachable bytes are not
lost allocations. This test coverage cannot establish equivalence for every
possible signature and input file.

## Memory scope and next opportunity

The large saving is in active-scan state. This does not compact the resident
signature database, transition tables, candidate records, or freed construction
blocks retained by the engine's memory pool. The earlier candidate-locality
change's roughly 100 MiB engine cost still exists. Reduced working memory can
more than offset it during concurrent scans without removing that underlying
cost. Compact matcher indexes and construction storage remain the next work
for reducing idle-engine memory.

No signatures, file-type coverage or scan windows are removed. Existing
container, target-description, macro, bytecode, cache and reporting checks remain
in their original order. No running daemon is installed or restarted.

## Reproduction and artifacts

Final shared-library SHA-256 identities:

- Previous optimized build:
  `ed1f5d015826374353465e66126a2a173637e237a3ad2b3270e725f18ee5d2aa`.
- Compact state only:
  `8ceef31f059091c1bc8241346ff7ed52bb7eebad8e91dc119bd615a88b7f1cfe`.
- Final combined build:
  `579a0b6ab8ef0c2633d45916b14c9101f1305cce7205dfd40480bf573227877c`.

`build/perf-baseline` contains the final combined build. Saved shared libraries
allow comparing implementations without repeatedly rebuilding the source tree.
The earlier `logical-expressions/corpus` run predates the binding refresh and
storage cap; the headline tables use `corpus-final` and `corpus-four` instead.

From the repository root:

```sh
python3 benchmarks/compare-database.py \
  --before build/perf-results/matcher/final-lib \
  --after build/perf-results/logical-expressions/final-lib \
  --database db \
  --files build/perf-results/matcher/corpus.txt \
  --output build/perf-results/logical-expressions/recheck \
  --rounds 2 --cpus 2
```

Use `--cpus 2 0 4 5 --repetitions 2` for four workers. For expression compilation
with compact scan state in both builds, change `--before` to
`build/perf-results/scan-state/after-lib` and select a different output directory.

The full-database differential checker uses private headers from this build:

```sh
cc -O2 -std=gnu11 -fgnu89-inline -DHAVE_CONFIG_H \
  -Ilibclamav -Ibuild/perf-baseline -Ilibclamav_rust \
  -Ilibclammspack -Ilibclamunrar_iface -I/usr/include/json-c \
  benchmarks/check-logical-expressions.c \
  -Lbuild/perf-baseline/libclamav \
  -Wl,-rpath,"$PWD/build/perf-baseline/libclamav" -lclamav \
  -o build/perf-results/logical-expressions/check-expressions
taskset -c 2 build/perf-results/logical-expressions/check-expressions db certs
```

Final test output is retained in `tests-final.log`, `valgrind-final.log`, and
`database-check-final.log` under `build/perf-results/logical-expressions/`.
