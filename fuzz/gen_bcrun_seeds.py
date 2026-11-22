#!/usr/bin/env python3
"""Compose the `clamav_bcrun_fuzzer` seed corpus (OSS-Fuzz fuzz-build infra).

Pairs the in-tree unit-test bytecode signatures with scan inputs so the
load -> prepare -> execute bytecode pipeline starts from real bytecode:

    [bytecode .cbc bytes][\\n;;CFDB;;\\n][file to scan]

Bytecode signatures come from ${SRC}/clamav/unit_tests/input/bytecode_sigs/
(valid, compiled bytecode); scan inputs are the unit-test API fixture plus a
few real samples from the clamav-fuzz-corpus scantype directories.

Only CBCs with kinds that `cli_loadcbc` accepts are used. BC_GENERIC (0) is
rejected with CL_EMALFDB and would otherwise fill MAX_SEEDS first because
those files sort alphabetically before lsig/pdf/hooks.
"""
import glob
import os
import sys
import zipfile

SEP = b"\n;;CFDB;;\n"
SRC = os.environ.get("SRC", "/src")
OUT = os.environ.get("OUT", "/out")
CLAMAV = os.path.join(SRC, "clamav")
CORPUS = os.path.join(SRC, "clamav-fuzz-corpus")
MAX_BC = 200000
MAX_SEEDS = 40

# Mirrors enum BytecodeKind / cli_loadcbc acceptance in libclamav/readdb.c.
BC_STARTUP = 1
_BC_START_HOOKS = 256
_BC_LAST_HOOK = 263  # after BC_MACHO_UNPACKER


def read_number(data, off):
    """Decode a ClamBC header number (see libclamav/bytecode.c readNumber)."""
    p0 = data[off]
    lim = p0 - 0x60
    if lim < 0 or lim > 0x10:
        raise ValueError("invalid number type")
    newoff = off + lim + 1
    if newoff > len(data):
        raise ValueError("truncated number")
    if p0 == 0x60:
        return 0, newoff
    n = 0
    shift = 0
    for i in range(off + 1, newoff):
        v = data[i]
        if (v & 0xF0) != 0x60:
            raise ValueError("invalid number part")
        n |= (v & 0xF) << shift
        shift += 4
    return n, newoff


def read_data(data, off):
    """Decode a ClamBC |<len><nibbles>| data blob."""
    if data[off] != ord("|"):
        raise ValueError("missing data marker")
    off += 1
    length, off = read_number(data, off)
    if length == 0:
        return b"", off
    newoff = off + 2 * length
    if newoff > len(data):
        raise ValueError("truncated data")
    out = bytearray()
    for i in range(off, newoff, 2):
        v0, v1 = data[i], data[i + 1]
        if (v0 & 0xF0) != 0x60 or (v1 & 0xF0) != 0x60:
            raise ValueError("invalid data part")
        out.append((v0 & 0xF) | ((v1 & 0xF) << 4))
    return bytes(out), newoff


def cbc_kind(path):
    """Return the bytecode kind from the first header line, or None on error."""
    try:
        with open(path, "rb") as f:
            line = f.readline().rstrip(b"\r\n")
        if not line.startswith(b"ClamBC"):
            return None
        off = len(b"ClamBC")
        # formatlevel, timestamp, sigmaker, targetExclude, kind
        _, off = read_number(line, off)
        _, off = read_number(line, off)
        _, off = read_data(line, off)  # sigmaker string
        _, off = read_number(line, off)
        kind, _ = read_number(line, off)
        return kind
    except (OSError, ValueError, IndexError):
        return None


def is_loadable_kind(kind):
    """True if cli_loadcbc will accept this kind (not BC_GENERIC default)."""
    if kind is None:
        return False
    if kind == BC_STARTUP:
        return True
    return _BC_START_HOOKS <= kind < _BC_LAST_HOOK


def first_file(directory, max_size=200000):
    """Return the first regular file under directory (or None)."""
    if not os.path.isdir(directory):
        return None
    for path in sorted(glob.glob(os.path.join(directory, "*"))):
        if os.path.isfile(path) and 0 < os.path.getsize(path) <= max_size:
            return path
    return None


def main():
    bc_files = sorted(glob.glob(os.path.join(CLAMAV, "unit_tests", "input",
                                             "bytecode_sigs", "*.cbc")))
    # Prefer CBCs that survive cl_load; BC_GENERIC would otherwise dominate
    # the alphabetical MAX_SEEDS window and never reach prepare/execute.
    bc_files = [p for p in bc_files if is_loadable_kind(cbc_kind(p))]
    samples = []
    api = os.path.join(CLAMAV, "unit_tests", "input", "bytecode_scanfiles",
                       "apitestfile")
    if os.path.isfile(api):
        samples.append(api)
    for scantype in ("PDF", "PE", "ELF", "HTML"):
        path = first_file(os.path.join(CORPUS, "scantype", scantype))
        if path:
            samples.append(path)
    if not samples:
        print("gen_bcrun_seeds: no samples found", file=sys.stderr)
        return 1
    if not bc_files:
        print("gen_bcrun_seeds: no loadable bytecode signatures found",
              file=sys.stderr)
        return 1

    seeds = []
    for bc in bc_files:
        with open(bc, "rb") as f:
            bc_bytes = f.read()
        if not (0 < len(bc_bytes) <= MAX_BC):
            continue
        for sample in samples:
            with open(sample, "rb") as f:
                seeds.append(bc_bytes + SEP + f.read())
        if len(seeds) >= MAX_SEEDS:
            break

    with zipfile.ZipFile(os.path.join(OUT, "clamav_bcrun_fuzzer_seed_corpus.zip"),
                         "w", zipfile.ZIP_DEFLATED) as z:
        for i, seed in enumerate(seeds[:MAX_SEEDS]):
            z.writestr("seed_%03d" % i, seed)
    print("gen_bcrun_seeds: wrote %d seeds from %d loadable CBCs" %
          (min(len(seeds), MAX_SEEDS), len(bc_files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
