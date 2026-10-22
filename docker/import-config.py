#!/usr/bin/env python3
"""Import existing production configuration, disabling Unix-domain sockets."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit(f"Usage: {sys.argv[0]} /path/to/antivirus")
source = Path(sys.argv[1]).resolve()
destination = Path(__file__).resolve().parent / 'config'
clamd = (source / 'clamd.conf').read_text()
freshclam = (source / 'freshclam.conf').read_bytes()
socket_options = {'LocalSocket', 'LocalSocketGroup', 'LocalSocketMode', 'FixStaleSocket'}
clamd = ''.join(line for line in clamd.splitlines(keepends=True)
                if not line.strip() or line.lstrip().startswith('#')
                or line.split()[0] not in socket_options)
if not any(line.split()[:1] == ['TCPSocket'] for line in clamd.splitlines()):
    raise SystemExit('Source clamd.conf must specify TCPSocket for TCP-only operation.')
destination.mkdir(exist_ok=True)
for name, content in [('clamd.conf', ('# Custom optimized image: TCP only.\n' + clamd).encode()),
                      ('freshclam.conf', freshclam)]:
    path = destination / name
    path.touch(mode=0o600)
    path.chmod(0o600)
    path.write_bytes(content)
print(f'Imported configuration into {destination}; Unix-socket options removed.')
