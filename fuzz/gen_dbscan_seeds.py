#!/usr/bin/env python3
"""Compose the `clamav_dbscan_<TYPE>_fuzzer` seed corpora (OSS-Fuzz fuzz-build infra).

Pairs real signature databases with scan inputs so the load -> compile ->
scan pipeline starts from valid, matching data:

    [signature DB bytes][\\n;;CFDB;;\\n][file to scan]

Databases come from the clamav-fuzz-corpus database directories plus
ClamAV's in-tree unit-test signature files; scan inputs include crafted
files that actually match unit-test signatures (so detection paths fire)
and real samples from the corpus scantype directories.
"""
import glob
import os
import sys
import zipfile

SEP = b"\n;;CFDB;;\n"
SRC = os.environ.get("SRC", "/src")
OUT = os.environ.get("OUT", "/out")
CORPUS = os.path.join(SRC, "clamav-fuzz-corpus")
CLAMAV = os.path.join(SRC, "clamav")

TYPES = ["LDB", "NDB", "HDB", "YARA", "WDB", "FTM"]
MAX_DB = 200000
MAX_COMPOSITES = 30

UNIT_TEST_MAGIC = b"CLAMAV-TEST-STRING-NOT-EICAR"


def db_files(dbtype, per_type=15, max_size=MAX_DB):
    files = []
    # In-tree unit-test signature files first (small, valid, purpose-made).
    intree = {
        "NDB": "Clamav-Unit-Test-Signature.ndb",
        "HDB": "clamav.hdb",
        "WDB": "daily.wdb",
        "HDB2": "logo.hsb",
    }
    for key in (dbtype, dbtype + "2"):
        name = intree.get(key)
        if name:
            path = os.path.join(CLAMAV, "unit_tests", "input", "other_sigs", name)
            if os.path.isfile(path):
                files.append(path)
    for path in sorted(glob.glob(os.path.join(CORPUS, "database", dbtype, "*"))):
        if os.path.isfile(path) and 0 < os.path.getsize(path) <= max_size:
            files.append(path)
            if len(files) >= per_type:
                break
    return files


def sample_files():
    samples = []
    # A file whose content matches the in-tree unit-test NDB signature.
    samples.append(UNIT_TEST_MAGIC * 4)
    api = os.path.join(CLAMAV, "unit_tests", "input", "bytecode_scanfiles",
                       "apitestfile")
    if os.path.isfile(api):
        with open(api, "rb") as f:
            samples.append(f.read())
    for scantype in ("PE", "ELF", "HTML", "MAIL", "PDF"):
        d = os.path.join(CORPUS, "scantype", scantype)
        if not os.path.isdir(d):
            continue
        for path in sorted(glob.glob(os.path.join(d, "*"))):
            if os.path.isfile(path) and 0 < os.path.getsize(path) <= 200000:
                with open(path, "rb") as f:
                    samples.append(f.read())
                break
    return samples


def main():
    total = 0
    for dbtype in TYPES:
        composites = []
        samples = sample_files()
        for dbpath in db_files(dbtype):
            with open(dbpath, "rb") as f:
                db_bytes = f.read()
            if not (0 < len(db_bytes) <= MAX_DB):
                continue
            for i, sample in enumerate(samples):
                composites.append(db_bytes + SEP + sample)
        with zipfile.ZipFile(
                os.path.join(OUT, "clamav_dbscan_%s_fuzzer_seed_corpus.zip" % dbtype),
                "w", zipfile.ZIP_DEFLATED) as z:
            for i, comp in enumerate(composites[:MAX_COMPOSITES]):
                z.writestr("seed_%03d" % i, comp)
        total += min(len(composites), MAX_COMPOSITES)

    # Shared signature-syntax dictionary for all dbscan variants.
    dict_path = os.path.join(SRC, "clamav_dbscan_fuzzer.dict")
    if os.path.isfile(dict_path):
        for dbtype in TYPES:
            with open(dict_path, "rb") as src, \
                 open(os.path.join(OUT, "clamav_dbscan_%s_fuzzer.dict" % dbtype),
                      "wb") as dst:
                dst.write(src.read())

    print("gen_dbscan_seeds: wrote %d composite seeds across %d types" %
          (total, len(TYPES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
