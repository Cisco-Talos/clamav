#!/usr/bin/env python3
"""Compose the `clamav_openioc_fuzzer` seed corpus (OSS-Fuzz fuzz-build infra).

Pairs crafted OpenIOC XML databases with scan inputs so the .ioc load ->
engine-compile -> scan-evaluation pipeline starts from valid documents:

    [OpenIOC XML bytes][\\n;;CFDB;;\\n][file to scan]

The crafted IOCs embed the real md5/sha1/sha256 digests of their paired
sample (so scan-time hash matching fires), plus nested-indicator and
non-hash-context variants and a few malformed XMLs for parser error paths.
"""
import glob
import hashlib
import os
import sys
import zipfile

SEP = b"\n;;CFDB;;\n"
SRC = os.environ.get("SRC", "/src")
OUT = os.environ.get("OUT", "/out")
CLAMAV = os.path.join(SRC, "clamav")
CORPUS = os.path.join(SRC, "clamav-fuzz-corpus")
MAX_IOC = 200000
MAX_SEEDS = 30

IOC_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<openioc>
  <criteria>
    <Indicator operator="AND">
      <IndicatorItem condition="is">
        <Context document="FileItem" search="FileItem/{ctx}" type="{typ}"/>
        <Content>{digest}</Content>
      </IndicatorItem>
    </Indicator>
  </criteria>
</openioc>
"""

NESTED_IOC = """<?xml version="1.0" encoding="utf-8"?>
<openioc>
  <criteria operator="OR">
    <Indicator operator="AND">
      <Indicator operator="OR">
        <IndicatorItem condition="is">
          <Context document="FileItem" search="FileItem/Md5sum" type="md5"/>
          <Content>{md5}</Content>
        </IndicatorItem>
        <IndicatorItem condition="is">
          <Context document="FileItem" search="FileItem/Sha1sum" type="sha1"/>
          <Content>{sha1}</Content>
        </IndicatorItem>
      </Indicator>
      <IndicatorItem condition="is">
        <Context document="FileItem" search="FileItem/FileExtension" type="string"/>
        <Content>{ext}</Content>
      </IndicatorItem>
    </Indicator>
  </criteria>
</openioc>
"""

PATH_IOC = """<?xml version="1.0" encoding="utf-8"?>
<openioc>
  <criteria>
    <IndicatorItem condition="contains">
      <Context document="FileItem" search="FileItem/FullPath" type="string"/>
      <Content>fuzz</Content>
    </IndicatorItem>
  </criteria>
</openioc>
"""

MALFORMED_IOCS = [
    b"<?xml version=\"1.0\"?><openioc><criteria><Indicator><IndicatorItem>"
    b"<Context search=\"FileItem/Md5sum\"><Content>zz",
    b"<openioc><Indicator><IndicatorItem>"
    b"<Context document=\"FileItem\" search=\"FileItem/Md5sum\" type=\"md5\"/>"
    b"<Content>short</Content>",
    b"\x00\x01\x02 not xml at all",
]


def digests(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def first_file(directory, max_size=200000):
    if not os.path.isdir(directory):
        return None
    for path in sorted(glob.glob(os.path.join(directory, "*"))):
        if os.path.isfile(path) and 0 < os.path.getsize(path) <= max_size:
            return path
    return None


def main():
    import sys

    samples = []
    api = os.path.join(CLAMAV, "unit_tests", "input", "bytecode_scanfiles",
                       "apitestfile")
    if os.path.isfile(api):
        samples.append(api)
    for scantype in ("PE", "HTML", "ELF"):
        path = first_file(os.path.join(CORPUS, "scantype", scantype))
        if path:
            samples.append(path)
    if not samples:
        print("gen_openioc_seeds: no samples found", file=sys.stderr)
        return 1
    seeds = []
    for sample in samples:
        with open(sample, "rb") as f:
            data = f.read()
        if not data:
            continue
        dg = digests(data)
        for ctx, typ in (("Md5sum", "md5"), ("Sha1sum", "sha1"),
                         ("Sha256sum", "sha256")):
            ioc = IOC_TEMPLATE.format(ctx=ctx, typ=typ, digest=dg[typ]).encode()
            seeds.append(ioc + SEP + data)
        nested = NESTED_IOC.format(md5=dg["md5"], sha1=dg["sha1"],
                                   ext=os.path.splitext(sample)[1]).encode()
        seeds.append(nested + SEP + data)
        seeds.append(PATH_IOC.encode() + SEP + data)
        if len(seeds) >= MAX_SEEDS:
            break
    for bad in MALFORMED_IOCS:
        seeds.append(bad + SEP + b"fuzz")

    with zipfile.ZipFile(os.path.join(OUT, "clamav_openioc_fuzzer_seed_corpus.zip"),
                         "w", zipfile.ZIP_DEFLATED) as z:
        for i, seed in enumerate(seeds):
            z.writestr("seed_%03d" % i, seed)

    with open(os.path.join(OUT, "clamav_openioc_fuzzer.dict"), "w") as d:
        for tok in (
            "<openioc>", "</openioc>", "<criteria", "</criteria>",
            "<Indicator", "</Indicator>", "<IndicatorItem", "</IndicatorItem>",
            "condition=", "is", "contains", "operator=", "AND", "OR",
            "<Context", "/>", "document=", "search=", "type=",
            "FileItem", "FileItem/Md5sum", "FileItem/Sha1sum",
            "FileItem/Sha256sum", "FileItem/FullPath", "FileItem/FileExtension",
            "md5", "sha1", "sha256", "string", "<Content>", "</Content>",
            "0123456789abcdef",
        ):
            d.write('"%s"\n' % tok)

    print("gen_openioc_seeds: wrote %d seeds + dict" % len(seeds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
