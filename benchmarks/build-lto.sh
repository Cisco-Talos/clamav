#!/usr/bin/env bash
# Build comparable variants without installing or replacing the running service.
set -euo pipefail
cd "$(dirname "$0")/.."
variant=${1:?Usage: bash benchmarks/build-lto.sh baseline|c-lto|c-rust-lto}
case "$variant" in
    baseline) ipo=OFF; rust_lto=false; units=16 ;;
    c-lto) ipo=ON; rust_lto=false; units=16 ;;
    c-rust-lto) ipo=ON; rust_lto=thin; units=1 ;;
    *) echo "Unknown variant: $variant" >&2; exit 2 ;;
esac

export CARGO_HOME="$PWD/build/perf-cargo-home"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_RELEASE_LTO="$rust_lto"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$units"
mkdir -p build/perf-results
# Seed only Cargo's cache in fresh variant directories. Always rebuild this
# project's Rust crate (including its generated header) in its own build tree.
# Cargo fingerprints decide whether dependency artifacts match the new profile.
if [[ "$variant" != baseline ]]; then
    python3 - "$variant" <<'PY'
from pathlib import Path
import shutil
import subprocess
import sys

host = next(line.split(': ', 1)[1] for line in
            subprocess.check_output(['rustc', '-vV'], text=True).splitlines()
            if line.startswith('host: '))
base = Path('build/perf-baseline')
dest = Path('build/perf-' + sys.argv[1])
for relative in (Path('release'), Path(host) / 'release'):
    source, target = base / relative, dest / relative
    if source.exists() and not target.exists():
        shutil.copytree(source, target, symlinks=True)
        for directory in (target, target / '.fingerprint', target / 'build', target / 'deps'):
            for artifact in directory.glob('*clamav_rust*'):
                if artifact.is_dir() and not artifact.is_symlink():
                    shutil.rmtree(artifact)
                else:
                    artifact.unlink()
PY
fi
cmake -S . -B "build/perf-$variant" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION="$ipo" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DMAINTAINER_MODE=OFF -DENABLE_TESTS=ON \
    -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF \
    -DENABLE_MAN_PAGES=OFF -DENABLE_SYSTEMD=OFF \
    > "build/perf-results/$variant-configure.log" 2>&1
cmake --build "build/perf-$variant" --parallel 2 \
    > "build/perf-results/$variant-build.log" 2>&1
printf 'Built %s\n' "$variant"
