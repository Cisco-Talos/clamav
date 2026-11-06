#!/usr/bin/env python3
"""Compare persistent-engine builds using a supplied signature database.

The database and input files are read only. Engine loading and one corpus warmup
are excluded from scan timing. Every repetition must preserve each baseline
verdict and detection name. Raw output, hashes and peak RSS are retained.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def database_manifest(path):
    files = sorted(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else [path]
    return {str(p): {'bytes': p.stat().st_size, 'sha256': digest(p)}
            for p in files if p.suffix not in ('.pid', '.sock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--files', type=Path, required=True, help='One absolute pathname per line')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build', type=Path, default=ROOT / 'build/perf-baseline')
    parser.add_argument('--rounds', type=int, default=4)
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--cpus', type=int, nargs='+', default=[2])
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if (args.rounds < 1 or not 1 <= args.repetitions <= 10000 or not 1 <= len(args.cpus) <= 64 or
            len(set(args.cpus)) != len(args.cpus) or
            not set(args.cpus).issubset(os.sched_getaffinity(0))):
        parser.error('invalid rounds, repetitions or CPU selection')
    out, build, database = args.output.resolve(), args.build.resolve(), args.database.resolve()
    out.mkdir(parents=True, exist_ok=True)
    files = [Path(p) for p in args.files.read_text().splitlines() if p]
    if not files or any(not p.is_absolute() or not p.is_file() for p in files):
        parser.error('input list must contain absolute paths to existing files')
    filelist = out / 'files.txt'
    filelist.write_text(''.join(str(p) + '\n' for p in files))
    binary = out / 'scan-engine'
    subprocess.run(['cc', '-O2', '-g', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'libclamav'), '-I' + str(build),
                    str(ROOT / 'benchmarks/scan-engine.c'), '-L' + str(build / 'libclamav'),
                    '-lclamav', '-lpthread', '-o', str(binary)], check=True)
    metadata = {'database': database_manifest(database), 'cpus': args.cpus,
                'rounds': args.rounds, 'repetitions': args.repetitions,
                'files': {str(p): digest(p) for p in files}, 'libraries': {}}
    envs = {}
    for variant, directory in [('before', args.before.resolve()), ('after', args.after.resolve())]:
        env = os.environ.copy()
        env.pop('LD_PRELOAD', None)
        env['LD_LIBRARY_PATH'] = ':'.join(map(str, [directory] + [build / d for d in
            ('libclamunrar_iface', 'libclamunrar', 'libclammspack')]))
        links = subprocess.check_output(['ldd', str(binary)], env=env, text=True)
        (out / (variant + '-libraries.txt')).write_text(links)
        if str(directory) not in next(line for line in links.splitlines() if 'libclamav.so' in line):
            raise RuntimeError('wrong libclamav selected')
        library = (directory / 'libclamav.so').resolve()
        metadata['libraries'][variant] = {'path': str(library), 'sha256': digest(library)}
        envs[variant] = env
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    expected, expected_sigs, samples = None, None, []
    for round_number in range(args.rounds):
        order = ('before', 'after') if round_number % 2 == 0 else ('after', 'before')
        for variant in order:
            output = out / f'r{round_number}-{variant}.tsv'
            print(f'round={round_number} variant={variant}', flush=True)
            with output.open('w') as stdout, output.with_suffix('.stderr').open('w') as stderr:
                subprocess.run(['taskset', '-c', ','.join(map(str, args.cpus)),
                    str(binary), str(database), str(filelist), str(args.repetitions),
                    str(len(args.cpus)), str(ROOT / 'certs')], env=envs[variant],
                    stdout=stdout, stderr=stderr, check=True, timeout=args.timeout)
            with output.open() as stream:
                marker, tasks, sigs, workers, wall, cpu, rss = stream.readline().strip().split('\t')
                rows = list(csv.DictReader(stream, delimiter='\t'))
            verdicts = [(r['status'], r['name']) for r in rows]
            if (marker != 'summary' or int(tasks) != len(files) * args.repetitions or
                    len(rows) != int(tasks) or int(workers) != len(args.cpus) or
                    any(r['status'] not in ('0', '1') for r in rows) or
                    any(int(r['file']) != i % len(files) for i, r in enumerate(rows))):
                raise RuntimeError('invalid benchmark output: ' + str(output))
            if expected is None:
                expected, expected_sigs = verdicts[:len(files)], sigs
            if verdicts != expected * args.repetitions or sigs != expected_sigs:
                raise RuntimeError('detection or signature count changed: ' + str(output))
            sample = {'round': round_number, 'variant': variant, 'tasks': int(tasks),
                      'signatures': int(sigs), 'seconds': float(wall), 'cpu_seconds': float(cpu),
                      'rss_kib': int(rss), 'files_per_second': int(tasks) / float(wall)}
            for line in output.with_suffix('.stderr').read_text().splitlines():
                fields = line.split('\t')
                if fields[0] in ('engine_ready', 'warmup_complete'):
                    sample[fields[0] + '_seconds'] = float(fields[2])
            samples.append(sample)
            (out / 'samples.json').write_text(json.dumps(samples, indent=2) + '\n')
            print(json.dumps(sample), flush=True)
    if database_manifest(database) != metadata['database']:
        raise RuntimeError('database changed during benchmark')
    if {str(p): digest(p) for p in files} != metadata['files']:
        raise RuntimeError('input corpus changed during benchmark')
    for variant, data in metadata['libraries'].items():
        if digest(Path(data['path'])) != data['sha256']:
            raise RuntimeError('library changed during benchmark: ' + variant)
    medians = {v: statistics.median(s['seconds'] for s in samples if s['variant'] == v)
               for v in ('before', 'after')}
    print(f'Median wall seconds: {medians}; reduction '
          f'{100 * (1 - medians["after"] / medians["before"]):.1f}%; verdicts identical', flush=True)


if __name__ == '__main__':
    main()
