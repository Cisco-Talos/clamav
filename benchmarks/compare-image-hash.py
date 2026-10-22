#!/usr/bin/env python3
"""Check and time image fuzzy hashes against a saved libclamav (requires Pillow).

Each library is loaded in a separate process. Inputs are deterministic generated
images plus repository PNGs. Hash timing excludes input reads and library loading.
"""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def worker(library, manifest, iterations, cpu):
    os.sched_setaffinity(0, {int(cpu)})
    lib = ctypes.CDLL(library)
    calculate = lib.fuzzy_hash_calculate_image
    calculate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
    calculate.restype = ctypes.c_bool
    files = json.loads(Path(manifest).read_text())
    counts = json.loads(Path(iterations).read_text()) if iterations != '-' else None
    results = {}
    for filename in files:
        if counts is not None and filename not in counts:
            continue
        data = Path(filename).read_bytes()
        source = ctypes.create_string_buffer(data)
        dest = (ctypes.c_ubyte * 8)()
        error = ctypes.c_void_p()

        def run():
            if not calculate(source, len(data), dest, 8, ctypes.byref(error)):
                # End this worker on failure; error storage is reclaimed at exit.
                raise RuntimeError('cannot hash valid fixture: ' + filename)
            return bytes(dest).hex()

        expected = run()  # Untimed warmup.
        repetitions = counts[filename] if counts else 1
        start = time.perf_counter()
        for _ in range(repetitions):
            if run() != expected:
                raise RuntimeError('unstable hash: ' + filename)
        results[filename] = {'hash': expected, 'iterations': repetitions,
                             'seconds': time.perf_counter() - start}
    print(json.dumps(results))


def main():
    from PIL import Image

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--rounds', type=int, default=6)
    parser.add_argument('--seconds', type=float, default=0.5)
    args = parser.parse_args()
    if args.cpu not in os.sched_getaffinity(0) or args.rounds < 2 or args.seconds <= 0:
        parser.error('invalid CPU, rounds, or duration')
    out = args.output.resolve()
    inputs = out / 'inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    paths, benchmark = [], []
    rng = random.Random(20260923)
    for width, height in [(1, 1), (1, 65), (65, 1), (7, 11), (31, 33),
                          (32, 32), (33, 31), (127, 65), (641, 479), (1920, 1080)]:
        for mode, channels in [('L', 1), ('LA', 2), ('RGB', 3), ('RGBA', 4), ('I;16', 2)]:
            size = width * height * channels
            for pattern in ('gradient', 'random'):
                data = (bytes(range(256)) * math.ceil(size / 256))[:size] if pattern == 'gradient' else rng.randbytes(size)
                source = Image.frombytes(mode, (width, height), data)
                path = inputs / f'{mode.replace(";", "")}-{pattern}-{width}x{height}.png'
                source.save(path)
                paths.append(str(path))
                if mode == 'RGB' and pattern == 'gradient' and width in (32, 641, 1920):
                    benchmark.append(str(path))
        if width in (7, 33, 641):
            source = Image.frombytes('RGB', (width, height), rng.randbytes(width * height * 3))
            for suffix in ('jpg', 'gif', 'bmp', 'tiff', 'webp', 'ppm'):
                path = inputs / f'RGB-random-{width}x{height}.{suffix}'
                source.save(path)
                paths.append(str(path))
                if suffix == 'jpg' and width == 641:
                    benchmark.append(str(path))
    paths += [str(ROOT / 'logo.png'), str(ROOT / 'unit_tests/input/pe_allmatch/test-exe-src/test.png')]
    manifest = out / 'files.json'
    manifest.write_text(json.dumps(paths, indent=2) + '\n')
    libraries = {'before': args.before.resolve(), 'after': args.after.resolve()}
    identity = {}
    for name, library in libraries.items():
        with library.open('rb') as stream:
            identity[name] = {'path': str(library), 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    (out / 'metadata.json').write_text(json.dumps({'libraries': identity, 'cpu': args.cpu,
        'rounds': args.rounds, 'seconds': args.seconds, 'pillow': Image.__version__}, indent=2) + '\n')

    def invoke(variant, label, counts='-'):
        result = subprocess.check_output([sys.executable, str(Path(__file__).resolve()),
            '--worker', str(libraries[variant]), str(manifest), str(counts), str(args.cpu)], text=True)
        (out / f'{label}-{variant}.json').write_text(result)
        return json.loads(result)

    original = invoke('before', 'compatibility')
    changed = invoke('after', 'compatibility')
    if {p: v['hash'] for p, v in original.items()} != {p: v['hash'] for p, v in changed.items()}:
        raise RuntimeError('hash compatibility failure')
    if original[str(ROOT / 'logo.png')]['hash'] != 'af2ad01ed42993c7':
        raise RuntimeError('known logo hash changed')
    print(f'Identical hashes for {len(original)} encoded images', flush=True)
    counts = {p: max(1, min(10000, math.ceil(args.seconds / original[p]['seconds']))) for p in benchmark}
    countfile = out / 'iterations.json'
    countfile.write_text(json.dumps(counts, indent=2) + '\n')
    samples = []
    for round_number in range(args.rounds):
        for variant in (('before', 'after') if round_number % 2 == 0 else ('after', 'before')):
            result = invoke(variant, f'round-{round_number}', countfile)
            for path, sample in result.items():
                if sample['hash'] != original[path]['hash']:
                    raise RuntimeError('hash changed during benchmark')
                samples.append(dict(sample, file=path, variant=variant, round=round_number,
                                    ms_per_hash=1000 * sample['seconds'] / sample['iterations']))
    (out / 'samples.json').write_text(json.dumps(samples, indent=2) + '\n')
    for path in benchmark:
        medians = {v: statistics.median(s['ms_per_hash'] for s in samples if s['file'] == path and s['variant'] == v)
                   for v in libraries}
        print(f'{Path(path).name}: {medians}, time reduction '
              f'{100 * (1 - medians["after"] / medians["before"]):.1f}%', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        worker(*sys.argv[2:])
    else:
        main()
