#!/usr/bin/env python3
"""Compose the `clamav_cvdload_fuzzer` seed corpus (OSS-Fuzz fuzz-build infra).

Seeds are database containers:

    [512-byte CVD header][gzip-compressed tar of signature files]

- The in-tree unit-test `bytecode.cvd` (a real container holding a compiled
  bytecode signature) is included as-is.
- Synthetic `.cld`-style containers are built from real signature files in
  the clamav-fuzz-corpus database directories, with a correct header (magic,
  time, version, sig count, functionality level, payload md5, dsig
  placeholder, builder).
- A few malformed variants cover header/verify error paths.
"""
import glob
import gzip
import hashlib
import io
import os
import sys
import tarfile
import zipfile

SRC = os.environ.get("SRC", "/src")
OUT = os.environ.get("OUT", "/out")
CLAMAV = os.path.join(SRC, "clamav")
CORPUS = os.path.join(SRC, "clamav-fuzz-corpus")

HEADER_SIZE = 512
MAX_SEEDS = 12


def db_files(types, per_type=2, max_size=60000):
    files = []
    for t in types:
        got = 0
        for path in sorted(glob.glob(os.path.join(CORPUS, "database", t, "*"))):
            if os.path.isfile(path) and 0 < os.path.getsize(path) <= max_size:
                files.append(path)
                got += 1
                if got >= per_type:
                    break
    return files


def make_container(paths, version="90", sigs=None, fl="130"):
    """Build [header][tar.gz payload]; header md5 = md5(payload)."""
    tarbuf = io.BytesIO()
    with tarfile.open(fileobj=tarbuf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for p in paths:
            with open(p, "rb") as f:
                data = f.read()
            info = tarfile.TarInfo(os.path.basename(p))
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    payload = gzip.compress(tarbuf.getvalue(), mtime=0)
    nsigs = sigs if sigs is not None else str(len(paths))
    head = "ClamAV-VDB:02 Nov 2026 00-00 +0000:clamav-1.5:%s:%s:%s:%s:clamav-fuzzer" % (
        version, nsigs, fl, hashlib.md5(payload).hexdigest())
    head = head + ":" + "0" * 64  # dsig placeholder (unverified for .cld)
    assert len(head) <= HEADER_SIZE, "header too long"
    head = head.ljust(HEADER_SIZE, " ")
    return head.encode() + payload


def main():
    seeds = []

    # Real in-tree container with a compiled bytecode signature inside.
    bc_cvd = os.path.join(CLAMAV, "unit_tests", "input", "bytecode_sigs",
                          "bytecode.cvd")
    if os.path.isfile(bc_cvd):
        with open(bc_cvd, "rb") as f:
            seeds.append(f.read())

    # Synthetic containers: ndb+ftm, ldb+hdb, ndb+ftm+ldb+idb mixes.
    picks = db_files(["NDB", "FTM", "LDB", "HDB", "IDB", "CDB"])
    if picks:
        seeds.append(make_container(picks[:1]))
        seeds.append(make_container(picks[:2]))
        seeds.append(make_container(picks[:3], sigs="9"))
        if len(picks) > 3:
            seeds.append(make_container(picks[:4], fl="999"))

    # Header-only and bad-magic error variants.
    hdr1 = (b"ClamAV-VDB:02 Nov 2026 00-00 +0000:clamav-1.5:1:130:" +
            b"0" * 32 + b":" + b"0" * 64 + b":clamav-fuzzer")
    seeds.append(hdr1.ljust(HEADER_SIZE, b" "))
    seeds.append(b"NOT-A-CVD:" + b"\x00" * 100)
    hdr2 = (b"ClamAV-VDB:02 Nov 2026 00-00 +0000:clamav-1.5:x:130:zz:" +
            b"0" * 64 + b":builder")
    seeds.append(hdr2.ljust(HEADER_SIZE, b" "))

    with zipfile.ZipFile(os.path.join(OUT, "clamav_cvdload_fuzzer_seed_corpus.zip"),
                         "w", zipfile.ZIP_DEFLATED) as z:
        for i, seed in enumerate(seeds[:MAX_SEEDS]):
            z.writestr("seed_%03d" % i, seed)
    print("gen_cvdload_seeds: wrote %d seeds" % min(len(seeds), MAX_SEEDS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
