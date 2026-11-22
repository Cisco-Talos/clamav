# Normative instructions for this ClamAV customization

These instructions apply throughout this workspace. MUST and MUST NOT denote
requirements; SHOULD denotes the default unless the task provides a reason to
change it. Explicit user instructions take precedence.

## Purpose and invariants

This fork improves scanning throughput and active-scan memory use while retaining
ClamAV detection behavior. Production uses `clamd` over TCP with local/shared
file paths, and `freshclam` for signature updates.

- Changes MUST preserve signature coverage, hash values, match counts, detection
  names, error handling and scan limits. Do not skip signatures or parsers merely
  to improve a benchmark. Existing target/offset restrictions still apply.
- Scan-local mutable state MUST NOT be shared between concurrent scans. Compiled
  engine plans shared by workers MUST remain immutable during scanning.
- C structure layout changes MUST be reflected in checked-in Rust bindings in
  `libclamav_rust/src/sys.rs` and validated by both C and Rust suites.
- `db/` contains the user's signatures. Treat it as read-only during testing.
  It MUST NOT be committed, uploaded, or included in Docker build context.
- `docker/config/freshclam.conf` contains private download URLs. Do not print,
  commit or publish its contents. Imported configuration is intentionally ignored.
- Builds and tests MUST NOT replace a production daemon, delete unrelated images,
  update production signatures, or publish an image without task authorization.

## Implemented changes

1. PCRE2 match data is allocated once per executed pattern in a scan and reused
   through its global-match loop. Error/offset fields reset before each match.
   Match limits, timeout checks and matching options remain intact.
2. Fuzzy-image hashing specializes the image crate's Lanczos resize for a single
   grayscale channel and avoids an unnecessary RGB copy. Pixel rounding and
   floating-point operation order preserve existing hash results. The adapted
   resize code retains its MIT notice. Dependency upgrades MUST recheck pixel
   equivalence against the generic implementation.
3. Aho–Corasick candidate lists are packed and cache `partno` and the first byte
   for early candidate rejection. On x86-64 each list record grows from 24 to
   32 bytes. Pool-retained construction allocations contribute to about 100 MiB
   of extra idle-engine memory in the measured database. This tradeoff remains.
4. Ordinary logical signatures allocate scan-local counters/offsets to their
   actual subsignature width. Bytecode, YARA, macros, byte-comparison owners and
   uncertain metadata retain 64 slots. PE plus generic arrays in the supplied
   database request 219.91 MiB before and 16.13 MiB afterward per live context.
   These are requested bytes, not an equivalent guaranteed RSS reduction.
5. Repeated logical expressions share compiled immutable trees per target.
   Compilation uses the existing parser and preserves count/ID semantics, mixed
   operators, overflow and zero-count behavior. Both operands are evaluated.
   Limits are 4,096 expression characters, 65,535 tree IDs and 1 MiB requested
   tree/table storage per target; the original interpreter remains the fallback.
   All 313,309 ordinary logical signatures in the supplied database map to 1,830
   trees. Original strings are retained for ownership and fallback.
6. cbindgen resolves only build-target dependencies, supporting offline builds.

## Benchmarks versus original

The direct comparison and full methodology are recorded in
`docs/optimization-results.md`. Its baseline is the original scanner at upstream
commit `72cd48c9faed4fa4afc22bc4ed0b9b19f8d3f8f7`, with the same native compiler
settings. The earlier one- and four-worker runs used 7,497,205 signatures; the
twelve-worker follow-up uses 7,497,219 after database updates. Each paired
comparison uses one unchanged database. The corpus consists of the same 60
decoded repository HDB fixtures. It is not a representative production upload sample.

| Workload | Original time | Modified time | Time reduction | Original peak RSS | Modified peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 worker, 60 scans | 30.483 s | 13.238 s | 56.6% | 1,627.9 MiB | 1,584.5 MiB |
| 4 workers, 120 scans | 30.622 s | 13.771 s | 55.0% | 2,123.5 MiB | 1,684.8 MiB |
| 12 workers, 120 scans | 29.954 s | 11.988 s | 60.0% | 3,223.3 MiB | 1,924.3 MiB |

All 1,200 timed scan statuses and exact detection names match within their
paired comparisons, including 480 scans in the twelve-worker follow-up. Library,
database and corpus hashes remained unchanged during each comparison.

The twelve-worker follow-up experienced host swap activity. Combined with the
database update, this means comparison with the older worker counts is not a
controlled scaling test; see the report for memory-pressure measurements.

Timings use a persistent engine with the clean cache disabled. Database loading
and corpus warmup are excluded from scan time; peak RSS includes the whole
process. Two alternating rounds are run per worker configuration on a shared
Intel i5-1235U host. Docker builds, tests and other heavy work MUST NOT overlap
comparative timings. Both detection status and exact name MUST match, and
library, database and corpus hashes MUST remain unchanged.

These native engine measurements are not a TCP latency measurement or a Docker
performance guarantee. Historical incremental comparisons in `docs/*-results.md`
use different baselines and MUST NOT be presented as comparisons with original
ClamAV. Reducing active memory does not remove the AC idle-engine tradeoff above.

## Build the native binaries

On Debian/Ubuntu, install a supported Rust toolchain (the Docker recipe uses
Rust 1.90) and the C/C++ build dependencies. Use a versioned libclang package
available in your distribution; the unversioned `libclang-dev` metapackage was
broken in this host's package sources. The Debian 13 recipe uses `libclang-19-dev`.
Do not mix distribution repositories to satisfy that metapackage.

```sh
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build pkg-config git \
  libclang-19-dev libbz2-dev libcurl4-openssl-dev libjson-c-dev libncurses-dev \
  libpcre2-dev libssl-dev libxml2-dev zlib1g-dev check python3 python3-pytest

export CARGO_HOME="$PWD/build/perf-cargo-home"
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
cargo fetch --locked
export CARGO_NET_OFFLINE=true
cmake -S . -B build/perf-baseline -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO='-O2 -g -DNDEBUG' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O2 -g -DNDEBUG' \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
  -DBYTECODE_RUNTIME=interpreter -DMAINTAINER_MODE=OFF \
  -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF \
  -DENABLE_SYSTEMD=OFF -DENABLE_MAN_PAGES=OFF \
  -DENABLE_TESTS=ON -DENABLE_UNRAR=ON -DENABLE_JSON_SHARED=ON
cmake --build build/perf-baseline --parallel 2
ctest --test-dir build/perf-baseline --output-on-failure \
  -R '^(libclamav|libclamav_rust|clamscan|sigtool)$'
```

Binaries are `build/perf-baseline/clamd/clamd`,
`build/perf-baseline/freshclam/freshclam`, and
`build/perf-baseline/clamscan/clamscan`; the shared library is under
`build/perf-baseline/libclamav/`. This does not install them over system binaries.
The initial Cargo fetch needs network access. A fresh machine MUST fetch before
setting offline mode. C/C++ uses `-O2`, Rust release, no LTO; earlier LTO trials did
not establish a general benefit on the corpus. Do not silently switch flags when
comparing algorithm changes.

Run appropriate regression suites after scanner changes. Matcher changes SHOULD
also run the full-database differential checker described in the performance
report, and Valgrind when changing allocation/ownership. Existing validation
includes all four suites, 13 native matcher cases under Valgrind, and 2,187,229
full-database logical-expression comparisons. New C edits MUST follow upstream's
clang-format 16 style; Rust edits MUST pass rustfmt. `git diff --check` MUST pass.

## Custom Docker image

The default `docker/build-image.sh` uses `Dockerfile.fast` to reuse already-built
binaries and their Debian runtime from `antivirus:optimized-binaries`. The files
`docker/config/clamd.conf` and `docker/config/freshclam.conf` are authoritative
workspace copies imported from `/home/ramez/Work/oneoffice/antivirus`. Builds MUST
use these copies and MUST NOT automatically reimport the old deployment folder
over local edits. Configuration changes belong here. Fast mode performs no compilation.
Fast mode MUST NOT be described as incorporating new scanner source changes.

`BUILD_MODE=source ./docker/build-image.sh` updates that reusable binary image.
`docker/Dockerfile` builds from source in Rust 1.90 on Debian 13 and installs into
Debian 13 slim. It runs the four test suites during the build and strips installed
binaries. It omits milter, on-access scanning, systemd integration, static
libraries and development files; it retains normal parsers, UnRAR and interpreted
bytecode. Do not copy host Ubuntu binaries into the Debian runtime.

```sh
./docker/build-image.sh
./docker/smoke-test.sh "$PWD/db"
```

Fast mode tags `antivirus:latest` and `antivirus:<version>`, using
`version=${VERSION:-3.00}` in `docker/build-image.sh`. Source mode defaults to
`antivirus:optimized`. The source-built base and fast packaging
retain separate provenance labels. See `docker/README.md` for build overrides,
optional image export and the deployment command. Set `NOSAVE=1 NOPUSH=1` for
build-only operation; otherwise the script exports an archive and uploads it to
the configured S3 destination. Do not execute publication without task authorization.
Config import removes active Unix-socket settings
and preserves the supplied TCP settings. Keeping Unix-socket support in the
binary costs little; disabling it at runtime is sufficient for this deployment.

`CLAMD_MAX_THREADS` sets clamd's concurrent scan-worker limit at container startup.
When unset, the authoritative config's `MaxThreads` applies. Overrides MUST use
a runtime config copy and MUST NOT rewrite the workspace or a mounted config.
The variable does not control Docker CPU quotas or the number of daemon processes.

The image runs clamd and FreshClam under a supervisor with signal forwarding and
failure propagation. FreshClam needs a database volume writable by `clamav`
(UID 100). `CLAMAV_NO_FRESHCLAMD=true` permits an externally managed/read-only
signature volume. Do not recursively chown a production mount without assessing
its ownership requirements. The TCP pathname sent by a client MUST exist inside
the container; mount the shared files at the same absolute path and read-only.
The example exposes port 3310 on host loopback without privileged mode.

The smoke test starts an isolated temporary container, mounts `db/` read-only,
disables FreshClam, and checks TCP PING, clean/EICAR verdicts, absence of the Unix
socket and graceful shutdown. Native benchmark results MUST NOT be claimed as
container benchmarks; Debian's compiler/runtime differ from the native host.
The image contains private imported URLs and MUST NOT be published publicly.

## Upstream PR and future updates

`upstream` is Cisco-Talos/clamav. Keep `main` pristine. Scanner changes and their
regressions belong on `perf/scan-throughput-memory`; local deployment, this file
and maintenance material belong on `custom/optimized-antivirus`. Merge scanner
fixes into the custom branch so the public review stays free of local deployment
configuration. A PR body is prepared in `maintenance/PR.md`; publishing is deferred
until the user connects their GitHub account/fork.

Use `./maintenance/update-upstream.sh` on the custom branch with a clean tree.
It merges upstream into the review branch, then review into custom. It preserves
commits and only deepens the depth-1 clone if a common ancestor is unavailable.
Do not use `--allow-unrelated-histories`, discard local changes, force-push, or
unshallow by default. Resolve conflicts before continuing and rerun validation.
See `maintenance/README.md` for the full update and eventual publishing commands.
