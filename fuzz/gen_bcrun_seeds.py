#!/usr/bin/env python3
"""Compose the `clamav_bcrun_fuzzer` seed corpus (OSS-Fuzz fuzz-build infra).

Pairs the in-tree unit-test bytecode signatures with scan inputs so the
load -> prepare -> execute bytecode pipeline starts from real bytecode:

    [bytecode .cbc bytes][\\n;;CFDB;;\\n][file to scan]

Bytecode signatures come from ${SRC}/clamav/unit_tests/input/bytecode_sigs/
(valid, compiled bytecode); scan inputs are the unit-test API fixture plus a
few real samples from the clamav-fuzz-corpus scantype directories.
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
        for i, seed in enumerate(seeds):
            z.writestr("seed_%03d" % i, seed)
    print("gen_bcrun_seeds: wrote %d seeds" % len(seeds))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
