#!/usr/bin/env python
# Copyright (C) 2018-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

'''
This script is a convenience tool to run a standalone fuzz target against each
item in its associated fuzz corpus.
'''

from __future__ import print_function, division, absolute_import

import argparse
import os
import subprocess
import sys
import tempfile
import threading

def which(program):
    '''
    Implements bash "which" feature.
    Find the full path to a program located in the PATH.

    https://stackoverflow.com/a/377028
    '''
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def cmd(command):
    '''
    Run a command in a subprocess.

    https://stackoverflow.com/a/4408409
    https://stackoverflow.com/a/10012262
    '''
    with tempfile.TemporaryFile() as tempf:
        p = subprocess.Popen(command, stderr=tempf)
        is_killed = {'value': False}

        def timeout(p, is_killed):
            is_killed['value'] = True
            p.kill()

        timer = threading.Timer(2, timeout, [p, is_killed])

        try:
            timer.start()
            p.wait()
            tempf.seek(0)
            text = tempf.read().decode("utf-8").strip()
            returncode = p.returncode
        finally:
            timer.cancel()

        if is_killed['value']:
            text = 'error: timeout, ' + text
            returncode = 1

        return text, returncode

def run_test(fuzzer, corpus_path):
    '''
    Test a standalone fuzz target with each item from the fuzz corpus.
    '''
    builddir = os.environ.get("builddir", ".")
    fuzz_target = os.path.join(builddir, fuzzer)

    print("Fuzz Target:  {fuzzer}".format(fuzzer=fuzzer))
    print("Corpus Path:  {corpus_path}".format(corpus_path=corpus_path))

    if not os.path.exists(fuzz_target):
        print("Failed to find fuzz target: {binary}!".format(binary=fuzz_target))
        sys.exit(1)

    failures = 0

    valgrind = None
    if os.environ.get('VG', ''):
        valgrind = which('valgrind')

    for fname in os.listdir(corpus_path):
        seedpath = os.path.join(corpus_path, fname)

        text, returncode = cmd([fuzz_target, seedpath])
        if text.strip():
            print(text)

        failed = False
        if returncode != 0 or 'error' in text:
            print('failure on %s' % fname)
            failed = True

        if valgrind:
            text, returncode = cmd(
                [valgrind, '--error-exitcode=1', fuzz_target, seedpath])
            if returncode:
                print(text)
                print('failure on %s' % fname)
                failed = True

        if failed:
            failures = failures + 1

    if failures:
        print("%i scanfile fuzzer related tests failed." % failures)
        sys.exit(1)

def main():
    '''
    Get command line options to support this tool.
    '''
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        '-f',
        '--fuzzer',
        required=True,
        help="The fuzz target to test.")
    parser.add_argument(
        '-c',
        '--corpus',
        required=True,
        help="Path of the fuzz corpus.")

    args = parser.parse_args()

    run_test(args.fuzzer, args.corpus)

if __name__ == '__main__':
    main()
