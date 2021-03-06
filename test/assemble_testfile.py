#!/usr/bin/env python3

import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("test_file")
    parser.add_argument("--split_dir", help="Location of split files", required=True)
    parser.add_argument("--build_dir", help="Location to assemble file", required=True)
    args = parser.parse_args()

    split_dir = Path(args.split_dir)
    if not split_dir.exists():
        print("Error: Split directory does not exist: {}".format(args.split_dir))

    match_pattern = Path(split_dir, "split.{}a*".format(args.test_file))

    input_files = [
        x for x in split_dir.iterdir() if (x.is_file() and x.match("{}".format(match_pattern)))
    ]

    if len(input_files) == 0:
        print("Error: No splits matching '{}' in: {}".format(args.test_file, args.split_dir))
        exit(1)

    test_file_path = Path(args.build_dir, args.test_file)
    try:
        test_file_path.touch(0o666, exist_ok=True)
    except FileNotFoundError:
        print("Failed to create file: {}".format(test_file_path))
        exit(1)

    input_files.sort()
    file_data = bytes()
    for split_file in input_files:
        file_data += split_file.read_bytes()

    test_file_path.write_bytes(file_data)

    print("Assembled: '{}'".format(test_file_path))


if __name__ == "__main__":
    main()
