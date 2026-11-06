#!/usr/bin/env python3
"""Fingerprint tracked source contents plus new files in implementation trees."""
import hashlib
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).split(b'\0')
new = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--others',
                               '--exclude-standard', '--', 'libclamav', 'libclamav_rust']).split(b'\0')
digest = hashlib.sha256()
for name in sorted(set(tracked + new)):
    if not name:
        continue
    path = root / name.decode()
    if not path.is_file():
        continue
    digest.update(name + b'\0')
    digest.update(hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
