# Optimized ClamAV on Debian

The default build reuses the already-built, stripped Debian binaries in the local
`antivirus:optimized-binaries` image and refreshes deployment configuration.
It performs no compilation or package downloads. `Dockerfile.fast` retains that
Debian 13 runtime and its binary provenance. Runtime services are `clamd` and
`freshclam`.

The optional source builder uses Rust 1.90 and C/C++ `-O2`, Rust release with LTO disabled and 16
codegen units, matching the optimization choices in the native experiments.
The actual compiler versions and C libraries differ from the Ubuntu build, so
native benchmark percentages are not a Docker-specific performance measurement.
Mail filtering, on-access scanning, systemd integration, examples, static
libraries, development headers and debug symbols are excluded from the runtime.
UnRAR, bytecode interpretation, file parsers and normal signature coverage remain.

## Build

From the repository root:

```sh
NOSAVE=1 NOPUSH=1 ./docker/build-image.sh
```

`docker/config/clamd.conf` and `docker/config/freshclam.conf` are the authoritative
configuration. They were copied from `/home/ramez/Work/oneoffice/antivirus`; builds
read only these workspace copies and never refresh them from the old folder.
Edit these files for future deployment changes. They live in ignored
`docker/config/` because they contain private settings. A new checkout needs a
secure copy of this directory or an explicit one-time import:

```sh
./docker/import-config.py /path/to/antivirus
```

Do not rerun the importer over local edits you want to keep.
The latter includes your existing private signature-download URLs. Keep those
files out of Git and the upstream PR. Importing removes active `LocalSocket`,
`LocalSocketGroup`, `LocalSocketMode`, and `FixStaleSocket` options; other settings
remain as supplied. The configurations are included in the resulting local image.

Fast mode creates `antivirus:latest` and `antivirus:3.00` by default. Both tags
refer to the same image. The script's `version=${VERSION:-3.00}` selects the
version; override `VERSION` or edit that default. `IMAGE` adds an optional extra
tag in fast mode. For example, to build without exporting or uploading:

```sh
VERSION=3.01 NOSAVE=1 NOPUSH=1 ./docker/build-image.sh
```

The reusable binary image is already present in this workspace's Docker daemon.
To incorporate new scanner source changes, or bootstrap another machine:

```sh
BUILD_MODE=source BUILD_JOBS=2 NOSAVE=1 NOPUSH=1 ./docker/build-image.sh
```

That mode compiles this working tree using `docker/Dockerfile`, tests it, updates
`antivirus:optimized-binaries`, then packages `antivirus:optimized` (or `IMAGE`).
Run fast mode afterward to refresh `latest` and the versioned tag. Fast mode
does **not** rebuild modified source. `BINARY_IMAGE` selects a different existing
image built with the same recipe; it must differ from every output tag.

`RUST_IMAGE` and `DEBIAN_IMAGE` can override the builder and runtime image
references in source mode, including digest-pinned references. Keep both on the same Debian
release. Cargo dependencies are fetched from the checked-in lockfile, then the
compile and test steps run with Cargo offline. BuildKit caches downloaded crates.
The builder runs the native libclamav, Rust, clamscan and sigtool test suites.

The script retains the deployment's export and S3 upload steps: unless `NOSAVE`
is nonempty, it saves the newly built output tags to `antivirus.tgz` in the current
directory. Unless `NOPUSH` is nonempty, it uploads that archive to the configured
S3 destination. Set both to `1` for a build only. No services are replaced by the
build script.

## Verify

```sh
./docker/smoke-test.sh "$PWD/db"
```

This starts a temporary isolated container with the database mounted read-only,
FreshClam disabled, and no published ports. It checks binary versions, TCP PING,
TCP `SCAN` commands carrying local paths, clean-file scanning, EICAR detection,
absence of the Unix socket, and graceful
shutdown. It removes its temporary container and input files afterward.

The local build and this smoke test passed on 2026-09-23 (Toronto time). All four
Debian build suites passed, and runtime shared-library dependencies resolved.
FreshClam's version and dependencies were checked; live signature downloads were
not attempted. The user-supplied database was mounted read-only for the scan test.

The reusable source-built artifact is tagged `antivirus:optimized-binaries`, image ID
`sha256:b4361aac9caae85a283a70cde6bc1b5e28f54e6288340aefc690bd9b4d1c1c69`.
Docker reports 123,465,640 bytes (117.7 MiB), excluding signature volumes and build
cache. Stripped clamd is approximately 216 KiB, FreshClam 80 KiB, and libclamav
13 MiB; the scanner's main implementation is in that shared library.

The image records core commit `5f21f35c47075e8953f6f337e479cfa90a9a3dab` and working
tree fingerprint `c3bf30c841f312f2b0be90879ee7c32ddffc5b23c8152f2a570371420ceac427`.
Later benchmark/documentation commits do not change the scanner in this artifact.
Build and smoke-test logs remain in ignored `docker/build.log` and `docker/test.log`.

The fast repack also passed the smoke test, including a four-worker override
confirmed through TCP `STATS`. Its `antivirus:optimized` image ID is
`sha256:8ff3cbb5e5b6d76de8dd736a7736bb3963f66ad253ddcc3fa87655b6f8bc531f`;
Docker reports 123,479,833 bytes. Its build log is `docker/fast-build.log`.

## Run

For the existing signature directory and shared-file scanning, for example:

```sh
docker run -d --name antivirus-optimized \
  --restart unless-stopped \
  -e CLAMD_MAX_THREADS=4 \
  -p 127.0.0.1:3310:3310 \
  --mount type=bind,source=/home/ramez/Work/oneoffice/antivirus/antivirus,target=/var/lib/clamav \
  --mount type=bind,source=/absolute/shared-files,target=/absolute/shared-files,readonly \
  antivirus:latest
```

Replace `/absolute/shared-files` with the directory whose paths the client sends.
The pathname sent over TCP must exist **inside the container**; mounting it at the
same absolute path avoids translation. The example exposes TCP only on the host's
loopback address and does not require privileged mode or host networking.

FreshClam runs alongside clamd by default. It uses the imported mirrors and
custom URLs and notifies clamd using its TCP configuration. The database directory
must be writable by `clamav` (UID 100), and scanned files must be readable by it.
The entrypoint does not recursively change ownership of host-mounted files.
Set `CLAMAV_NO_FRESHCLAMD=true` when another updater owns the database or when
mounting it read-only. An empty writable database volume triggers an initial
FreshClam download before clamd starts.

The daemon and health check use TCP port 3310. Disabling the Unix socket is a
runtime configuration choice, not a meaningful binary-size optimization.
The runtime still contains the standard socket-capable ClamAV binaries.

`CLAMD_MAX_THREADS` overrides clamd's `MaxThreads`: the maximum concurrent scan
workers in this one daemon. If unset, the value in `docker/config/clamd.conf`
applies (12 in the imported configuration). The override is written to a runtime
copy in `/run/clamav/clamd.conf`; the authoritative file is unchanged. Values must
be positive decimal integers. This does not set the container CPU allocation;
use Docker's `--cpus` separately if needed. More active workers also require more
scan memory. `MaxQueue` remains controlled by clamd's configuration and its
existing resource-limit checks.

Image labels record the binary build's Git revision and working-tree fingerprint.
Fast packaging preserves those labels and adds a separate packaging revision;
configuration changes do not pretend to rebuild the scanner.
