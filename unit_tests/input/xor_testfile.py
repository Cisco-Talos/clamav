#!/usr/bin/env python3

"""
Decrypt (or encrypt) a file with a hardcoded xor key (below).

This feature is to prevent other malware detection engines from alerting on our
suspicious-looking-but-benign test files, such as the packed executables.
The test files are xor'ed so our source and source tarball aren't quarantined.
"""

import argparse
import os
from pathlib import Path
import sys

xor_key = b'\
bhcftqarohcdiayfohalohkgmoefxrrg\
fnczssgybajvkzjaahpfrlqsratkhhfv\
pxytculmwgmtyzujlbjlgrhtwxhzpjaz\
libbwepffyjyfkjwzyofgpopoueurinp\
dujkphxwhnaxfkaiwrpzdqsnwughtejr\
'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_file", help="Input file", required=True)
    parser.add_argument("--out_file", help="Output file (will over-write!)", required=True)
    args = parser.parse_args()

    in_file = Path(args.in_file)
    if not in_file.exists():
        print("Error: Input file to be XOR'd does not exist: {}".format(in_file))
        sys.exit(1)

    out_file = Path(args.out_file)
    if out_file.exists():
        print("Warning: Replacing existing file: {}".format(out_file))
        os.remove(str(out_file))

    in_file_bytes = in_file.read_bytes()
    out_file_bytes = bytearray()

    # XOR the source file with the XOR key
    i = 0
    while i < len(in_file_bytes):
        for j in range(0, len(xor_key)):
            if i + j == len(in_file_bytes):
                break

            out_file_bytes.append(in_file_bytes[i + j] ^ xor_key[j])

        i += len(xor_key)

    # Write out the result to the destination file.
    try:
        with out_file.open('w+b') as out_file_fd:
            out_file_fd.write(out_file_bytes)

        print("Created: '{}'".format(out_file))

    except Exception as exc:
        print("Failed to create file: {}. Exception: {}".format(out_file, exc))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
