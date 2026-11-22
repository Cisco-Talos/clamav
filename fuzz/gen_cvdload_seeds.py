#!/usr/bin/env python3
"""Compose the `clamav_cvdload_fuzzer` seed corpus (OSS-Fuzz fuzz-build infra).

Seeds are database containers:

    [512-byte CVD header][gzip-compressed tar of signature files]

- The in-tree unit-test `bytecode.cvd` (a real container holding a compiled
  bytecode signature) is included as-is.
- Synthetic `.cld`-style containers are built from real signature files in
  the clamav-fuzz-corpus database directories, with a correct header field order
  (magic:time:version:sigs:flevel:md5:dsig:builder:epoch), a matching
  `.info` manifest (required by cli_cvdload), and mixed signature types.
- A few malformed variants cover header parse error paths.
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
# Must match between the outer CVD header and the .info ClamAV-VDB line.
CREATION = "02 Nov 2026 00-00 +0000"
EPOCH = "1762041600"
BUILDER = "clamav-fuzzer"


def db_files_by_type(types, per_type=2, max_size=60000):
    """Return {type: [paths...]} with up to per_type files each."""
    by_type = {}
    for t in types:
        files = []
        for path in sorted(glob.glob(os.path.join(CORPUS, "database", t, "*"))):
            if os.path.isfile(path) and 0 < os.path.getsize(path) <= max_size:
                files.append(path)
                if len(files) >= per_type:
                    break
        by_type[t] = files
    return by_type


def cvd_header_line(version, nsigs, fl, md5_hex, dsig="x"):
    """CVD header fields in the order parsed by CVD::from_file / cl_cvdparse."""
    return "ClamAV-VDB:%s:%s:%s:%s:%s:%s:%s:%s" % (
        CREATION, version, nsigs, fl, md5_hex, dsig, BUILDER, EPOCH)


def make_info(members, version, nsigs, fl):
    """Build a .info manifest: CVD header line + name:size:sha2-256 per member.

    No DSIG line: the fuzzer also loads with CL_DB_UNSIGNED so synthetic
    containers can pass cli_loadinfo without a forged RSA signature.
    """
    # Real containers use X:X for md5/dsig inside .info; version/sigs/fl/epoch
    # must still match the outer header for cli_cvdload's consistency check.
    lines = [cvd_header_line(version, nsigs, fl, "X", "X")]
    for name, data in members:
        lines.append("%s:%d:%s" % (name, len(data),
                                   hashlib.sha256(data).hexdigest()))
    return ("\n".join(lines) + "\n").encode()


def make_container(paths, version="90", sigs=None, fl="130"):
    """Build [header][tar.gz payload] with a required .info member."""
    members = []
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        members.append((os.path.basename(p), data))

    nsigs = sigs if sigs is not None else str(len(members))
    info_body = make_info(members, version, nsigs, fl)

    tarbuf = io.BytesIO()
    with tarfile.open(fileobj=tarbuf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("daily.info")
        info.size = len(info_body)
        info.mtime = 0
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(info_body))
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 0
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))

    payload = gzip.compress(tarbuf.getvalue(), mtime=0)
    head = cvd_header_line(version, nsigs, fl,
                           hashlib.md5(payload).hexdigest(), "x")
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

    # Synthetic containers with mixed signature types (not alphabetical
    # prefixes of a flat NDB,NDB,FTM,... list).
    by_type = db_files_by_type(["NDB", "FTM", "LDB", "HDB", "IDB", "CDB"])
    ndb, ftm = by_type.get("NDB", []), by_type.get("FTM", [])
    ldb, hdb = by_type.get("LDB", []), by_type.get("HDB", [])
    idb, cdb = by_type.get("IDB", []), by_type.get("CDB", [])

    if ndb:
        seeds.append(make_container([ndb[0]]))
    if ndb and ftm:
        seeds.append(make_container([ndb[0], ftm[0]]))
    if ndb and ftm and ldb:
        seeds.append(make_container([ndb[0], ftm[0], ldb[0]], sigs="9"))
    if ndb and ftm and ldb and hdb:
        seeds.append(make_container([ndb[0], ftm[0], ldb[0], hdb[0]], fl="999"))
    if ldb and hdb:
        seeds.append(make_container([ldb[0], hdb[0]]))
    if idb and cdb:
        seeds.append(make_container([idb[0], cdb[0]]))

    # Header-only and bad-magic error variants (correct field order where
    # applicable so the parser reaches the intended failure mode).
    hdr1 = cvd_header_line("1", "1", "130", "0" * 32, "0" * 64).encode()
    seeds.append(hdr1.ljust(HEADER_SIZE, b" "))
    seeds.append(b"NOT-A-CVD:" + b"\x00" * 100)
    # Non-integer version field
    hdr2 = ("ClamAV-VDB:%s:notanint:1:130:%s:x:%s:%s" % (
        CREATION, "0" * 32, BUILDER, EPOCH)).encode()
    seeds.append(hdr2.ljust(HEADER_SIZE, b" "))

    with zipfile.ZipFile(os.path.join(OUT, "clamav_cvdload_fuzzer_seed_corpus.zip"),
                         "w", zipfile.ZIP_DEFLATED) as z:
        for i, seed in enumerate(seeds[:MAX_SEEDS]):
            z.writestr("seed_%03d" % i, seed)
    print("gen_cvdload_seeds: wrote %d seeds" % min(len(seeds), MAX_SEEDS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
