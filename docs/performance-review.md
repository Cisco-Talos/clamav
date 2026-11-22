# Scan performance review

Reviewed checkout: `72cd48c`, identifying itself as ClamAV 1.6.0 development.
Focus: clamd scan throughput and latency, with freshclam maintaining signatures.
The client and clamd share a host/filesystem, and the client sends local paths
over TCP. File contents are not uploaded with INSTREAM in this deployment.
Deployment CPU quota, file mix, exact scan command, and production profiles were not
available. The findings below are source observations and experiments to test,
not a measured explanation of the deployment's slowness.

The user subsequently supplied `db/`, loading 7,497,205 signatures. The latest
[matcher experiment](matcher-results.md) profiles and benchmarks that database
against the repository corpus and implements AC candidate locality improvements.

## Recommended order

| Priority | Experiment | When it helps | Evidence |
| --- | --- | --- | --- |
| 1 | Measure client concurrency and queue time | Idle scan workers or serial callers | TCP path scanning already avoids an upload copy |
| 2 | Profile expensive input formats | CPU-bound parsing and matching | Callgrind identifies image fuzzy hashing and matching as hotspots; see [follow-up results](pcre-reuse-results.md) |
| Completed | Specialize grayscale image resizing | Image fuzzy hashing | Identical pixels/hashes in compatibility checks; see [image optimization results](image-hash-results.md) |
| Completed | Pack AC candidates and cache rejection data | Large signature databases | Full-database results and memory tradeoff in [matcher results](matcher-results.md) |
| 3 | Reuse PCRE2 match data within a pattern's global-match loop | Triggered regexes with many matches | Implemented and tested; see [follow-up results](pcre-reuse-results.md) |
| Completed | Compare C/C++ LTO and Rust ThinLTO | CPU-bound scans | No consistent scan-speed improvement; see [LTO results](lto-results.md) |
| N/A here | Increase receive buffering only for active INSTREAM uploads | Receive thread/syscalls limit upload throughput | Current deployment sends paths, so this does not apply |
| 5 | Profile-guided optimization or compact matcher representation | Matching dominates CPU/cache misses | Larger experiments requiring production-like training and regression coverage |

The follow-ups implement scan-local PCRE2 match-data reuse, a grayscale image
resize that preserves hash results, and AC candidate locality improvements, without changing signature matching rules
or scan settings. No running service was replaced.
The accompanying benchmarks measure both the isolated loop and full engine scans.

## Wire path and concurrency

This deployment sends paths over TCP, so clamd reads files directly. There is no
INSTREAM upload or upload temporary copy to eliminate. Prioritize concurrency,
CPU profiling, and build comparisons. The INSTREAM findings below apply to other
deployment modes, not this client's current path.

[`session.c`](../clamd/session.c), `COMMAND_INSTREAM`, creates a temporary file.
[`server-th.c`](../clamd/server-th.c), `handle_stream()`, writes incoming payloads
to it and dispatches `COMMAND_INSTREAMSCAN` only after the zero-length end chunk.
The receive loop performs these writes synchronously, so a stalled write can also
delay other uploads handled by that loop. Increasing `MaxThreads` does not add
more receive loops.

[`clamd_others.c`](../clamd/clamd_others.c), `buf_init()` and `read_fd_data()`,
limits each receive to the remaining space in a `PATH_MAX + 8` buffer. Here,
`PATH_MAX` is 4096: only 4104 bytes fit per receive. Large client chunks alone
cannot remove that receive-side cap. At 100 MiB, even ideal full-buffer reads
require roughly 25,550 receive calls, plus spooling writes and protocol overhead.

An implementation experiment should grow the buffer to 64 or 256 KiB when entering
stream mode, preserve already received bytes, and keep a separate command-length
limit. It must handle fragmented chunk headers, several chunks per read,
`IDSESSION` transitions back to commands, quotas, allocation failure, disconnects,
and fairness between uploads. A larger buffer per idle connection is unnecessary.
This changes syscall frequency, not the signature matching algorithm.

For local clients, compare Unix-socket `FILDES` / `clamdscan --fdpass`: it passes an
open descriptor instead of uploading another copy. It requires a same-host Unix
socket with descriptor passing, and the file must remain stable during scanning.
For a genuinely remote client, retain INSTREAM and compare fast local temp storage
with a bounded tmpfs if RAM permits. Temp storage may also contain extracted
archive contents; budget for concurrent uploads, extraction, and database reloads.
Spooling to a file does not necessarily mean every byte reaches physical disk:
the page cache and backing filesystem matter. See the official
[clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).

Sweep in-flight requests at 1, 2, 4, 8, and up to the deployment's useful CPU
capacity. Match `MaxThreads` to measured CPU and memory limits rather than the
host's advertised core count. More workers can improve throughput while worsening
p99 latency under contention. More queue capacity does not increase scan capacity.
`MULTISCAN` parallelizes files; it does not automatically split one expensive PDF
or archive scan across all CPUs. This checkout's client also supports parallel
stream/fd submissions with `--multiscan` using IDSESSION; see
[`client.c`](../clamdscan/client.c) and the official
[scanning guide](https://docs.clamav.net/manual/Usage/Scanning.html).

## Build experiments

Completed builds on 2026-09-23, after installing the missing dependencies:

| Check | Result |
| --- | --- |
| CMake C/C++ IPO support probe | Passed actual compiler/linker probes with GCC/G++ 14.2.0 |
| Baseline ClamAV build | Passed, including clamd and freshclam |
| C/C++ LTO ClamAV build | Passed |
| C/C++ LTO plus Rust ThinLTO build | Passed |
| libclamav, Rust, clamscan, sigtool suites | Passed for all three variants |
| Daemon/socket integration tests | Not run: listening sockets are blocked in this session |

Build and test logs are in `build/perf-results`. Header generation now uses
cbindgen's `only_target_dependencies` setting so the target-specific Cargo cache
is sufficient for an offline build. Detailed measurements and reproducible
commands are in [the LTO experiment report](lto-results.md).

The default single-configuration build is already `RelWithDebInfo`
([`CMakeLists.txt`](../CMakeLists.txt)). With the local GCC toolchain its usual
optimization level is `-O2`; Release uses `-O3`. Debug symbols do not mean an
unoptimized executable. The project deliberately retains C/C++ assertions even
in Release. Preserve that behavior.

[`FindRust.cmake`](../cmake/FindRust.cmake) selects Cargo `--release` for both
Release and RelWithDebInfo, adding Rust debug information in the latter case.
[`Cargo.toml`](../Cargo.toml) has no custom release profile. CMake's IPO switch
does not itself optimize across Rust crates or across the C/Rust boundary.

Use a single-configuration generator for these comparisons. In this checkout,
the Rust helper chooses its profile at configure time using `CMAKE_BUILD_TYPE`;
when that is empty it chooses debug. A multi-configuration CMake Release build
therefore deserves explicit inspection of the actual Cargo command.

Baseline, once build dependencies from `INSTALL.md` are available:

```sh
cmake -S . -B build/perf-baseline \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/perf-baseline --parallel 4
ctest --test-dir build/perf-baseline --output-on-failure
```

C/C++ LTO candidate, retaining the baseline optimization level:

```sh
cmake -S . -B build/perf-lto \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/perf-lto --parallel 4
ctest --test-dir build/perf-lto --output-on-failure
```

Use CMake's [IPO support check](https://cmake.org/cmake/help/v3.31/module/CheckIPOSupported.html)
when incorporating this into a supported build preset. Benchmark a separate
`-O3` variant by setting `CMAKE_C_FLAGS_RELWITHDEBINFO` and
`CMAKE_CXX_FLAGS_RELWITHDEBINFO` to `-O3 -g`. Do not assume `-O3` always wins.

Then build another fresh directory with the same C/C++ options and pass these
Cargo profile overrides to the **build** command (Cargo runs during the build):

```sh
CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  cmake --build build/perf-rust-lto --parallel 4
```

Configure `build/perf-rust-lto` first using the preceding LTO configure command
with that directory name. A fresh directory avoids reusing a Rust archive built
with different environment settings. Cargo's documented
[release profile controls](https://doc.rust-lang.org/cargo/reference/profiles.html)
allow these settings without changing the project's default profile. This is
Rust-only LTO plus C/C++ LTO, not cross-language LTO.

Further candidates are `-march=<deployment CPU baseline>` for C/C++ and matching
Rust `-C target-cpu=...`, followed by profile-guided optimization. Use `native`
only when the build CPU's instruction set is valid throughout the deployment.
Train PGO on representative clean files, infected test fixtures, archives,
document formats, and error/limit paths. Keep a held-out evaluation corpus;
training only on repeated cache hits optimizes the wrong workload. GCC documents
these controls in its [optimization options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html).

Bytecode execution defaults to the interpreter (`CMakeOptions.cmake`). LLVM
bytecode JIT is separate from PCRE2 JIT and only helps bytecode-heavy workloads.
This checkout's CMake explicitly accepts LLVM 8–13, so enabling it is a dependency
and maintenance decision, not a general compiler flag for all matching.

## Measured candidate: regex result allocation

[`matcher-pcre.c`](../libclamav/matcher-pcre.c), `cli_pcre_scanbuf()`, calls
`cli_pcre_results_reset()` on every iteration of its global-match loop.
[`regex_pcre.c`](../libclamav/regex_pcre.c) implements that reset by freeing
`pcre2_match_data` and allocating it again from the same compiled pattern.

A follow-up patch allocates once after a pattern's trigger and offset checks,
clears ClamAV's result/error fields for each iteration, reuses the match data for
that pattern, and frees it when initializing another pattern or leaving the scan.
It stays scan-local: compiled patterns are shared by daemon workers, mutable
match data must not be. It does not reuse data across different patterns, whose
capture counts and retained memory needs can differ. PCRE2 documents match data
and its retained interpreter memory in the
[native API reference](https://pcre.org/current/doc/html/pcre2api.html).

Reproduce the isolated allocation experiment:

```sh
cc -O2 -std=c99 -Wall -Wextra -Werror \
  benchmarks/pcre-match-data.c -lpcre2-8 -o /tmp/clamav-pcre-match-data
/tmp/clamav-pcre-match-data > /tmp/clamav-pcre-match-data.csv
```

Local result: GCC 14.2.0, PCRE2 10.45, Intel i5-1235U; median of five samples,
500 synthetic files per sample, 1,024 matches per file, JIT disabled. This is a
short, uncontrolled-host microbenchmark, not a production capacity estimate.

| Case | Allocate each match | Reuse within each file | Time reduction |
| --- | ---: | ---: | ---: |
| Repeated matches, no capture groups | 43.20 ms | 24.66 ms | 42.9% |
| Repeated matches, two capture groups | 52.84 ms | 35.36 ms | 33.1% |

Match-data allocations fell from 512,000 to 500 per sample. Both modes produced
identical match counts and checksums of all returned capture offsets. The
no-match control allocates once per file in both modes; its sub-millisecond
timings do not establish a speedup. Single-match patterns have little allocation
work to save. If this loop were 10% of scan time, even reducing its time by 40%
would reduce total time by only about 4%.

Before applying the scanner patch, run the existing regex, logical-signature,
offset, and all-match regressions, and specifically cover global matches,
unmatched captures, zero-length matches, pattern switches, resource-limit errors,
and concurrent scans. The isolated benchmark does not establish all those
properties. It passed compiler warnings and address/undefined-behavior sanitizer
checks with leak detection disabled because this environment prevents
LeakSanitizer's process inspection. The system PCRE2 library was not rebuilt
with sanitizers.

## Larger matcher changes

The current matcher already combines a Shift-Or-like two-byte prefilter,
Boyer–Moore, Aho–Corasick, and conditionally triggered PCRE2 signatures. Replacing
it with another general string search routine is not automatically an improvement.

| Candidate | Source evidence | Implementation and validation needed |
| --- | --- | --- |
| More compact AC transitions | `matcher-ac.c`: non-leaf transition tables have 256 pointers; the scan loop follows `current->trans[buffer[i]]` | Dense arrays with 32-bit state indices could reduce transition storage from 2 KiB to 1 KiB per allocated table on 64-bit hosts; this does not halve total engine RAM. Preserve leaf/failure-table sharing and measure the extra addressing work versus cache savings. |
| Faster prefilter | `filtering.c`: byte-at-a-time state recurrence with table lookups | Try unrolling or independent block processing with proven overlap/state handling. A SIMD rewrite must preserve the no-false-negative property for wildcards, alternatives, and boundary matches. Profile how much data the existing prefilter already skips. |
| PCRE2 JIT | `regex_pcre.c` calls `pcre2_compile` and `pcre2_match`, but never `pcre2_jit_compile` | Requires explicit application integration; installing a JIT-enabled PCRE2 library alone will not enable it here. Test fallback paths, stack exhaustion, memory, and reload cost. |
| Cache redesign | `cache.c` already shards its splay trees and mutexes; default 65,536 entries gives 256 shards | Measure hit rate and mutex time first. A hash-table replacement is only compelling if this cache is materially expensive. Cache hits still need the file hash and, over INSTREAM, the upload. |

PCRE2 JIT changes resource-limit semantics: it does not use the interpreter depth
limit and can return JIT stack-limit errors. It therefore needs a deliberate
policy and error handling, not a one-line enablement. See
[PCRE2's JIT documentation](https://pcre.org/current/doc/html/pcre2jit.html).

`fmap_get_hash()` already caches computed digests and can calculate several
requested digests in one file pass. Additional fusion with ingest/scanning would
need to account for request timing, nested maps, and file stability. Establish
that duplicate reads are expensive before adding another hashing path.

## Cache, updates, and an end-to-end measurement plan

Keep detection settings, limits, databases, and verdict handling equal between
variants. Lowering scan limits or disabling document/archive/bytecode scanning
can make a benchmark finish sooner by doing less security work.

Measure unique-file scans and repeat-file scans separately. The clean cache is
per engine, and reload replaces the engine. Do not warm it with the same corpus
and then report that as uncached matcher performance. Increasing `CacheSize`
may help a repeated working set; it will not accelerate predominantly new files
through cache hits. Metadata collection bypasses cache hits in this checkout.
The sample config's MD5 cache comment is stale relative to `cache.c`, which
requests SHA-256.

Freshclam is not in the steady-state scan path. During updates, its database
validation and clamd's reload compete for CPU/RAM. Keep incremental updates and
measure scan p99 during a real reload. `ConcurrentDatabaseReload` defaults to yes:
old and new engines can coexist until old scans finish. Sufficient memory prevents
swapping or reclaim stalls. `CompressLocalDatabase` already defaults to no.
Disabling update validation is not a scan-algorithm optimization.

For each variant, use the same database snapshot and representative file corpus,
split results by file type/size, and record files/s, original-input MiB/s,
p50/p95/p99 latency, errors/limit outcomes, CPU seconds, peak RSS, temporary bytes,
and CPU throttling. Compare detection names and outcomes per file, not just totals.
Repeat runs in alternating order; keep a separate reload-under-load run.

Use the actual production client to capture upload and total request timing.
On the daemon host, a sampling profile can identify whether time is in matching,
decompression, hashing, allocation, or kernel I/O. For an explicitly selected
daemon PID, example commands are:

```sh
perf record -F 99 -g --call-graph dwarf -p <clamd-pid> -- sleep 30
perf report
perf stat -p <clamd-pid> \
  -e task-clock,cycles,instructions,cache-misses,context-switches,page-faults \
  -- sleep 30
```

Run the workload concurrently with profiling. Hardware events and attach access
depend on host permissions. Use short syscall tracing separately if diagnosing
receive/write sizes; tracing perturbs timings. A CPU profile alone cannot
measure client network time or queueing delays.

The build comparison has now been executed with the repository's test corpus;
see [the LTO experiment report](lto-results.md). Its in-process engine measurements
exclude daemon protocol and queueing costs. The later [matcher experiment](matcher-results.md)
uses the supplied production-sized database. Representative production files and
a profile from the actual daemon remain necessary to establish deployment
throughput or latency improvements.
