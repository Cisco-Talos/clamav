#!/usr/bin/env python3
"""Compare two libclamav builds with a persistent engine and identical inputs.

Supply directories containing the original and changed libclamav.so libraries.
The build directory supplies headers and unchanged extraction plugins. Results
include synthetic PCRE workloads and the repository's HDB fixture corpus.
"""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--build', type=Path, default=ROOT / 'build/perf-baseline')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=6)
    parser.add_argument('--seconds', type=float, default=1)
    parser.add_argument('--cpus', type=int, nargs='+', required=True)
    parser.add_argument('--workloads', nargs='+', default=None, choices=[
        'global', 'global-captures', 'single', 'no-match', 'corpus-clean', 'corpus-detections'])
    args = parser.parse_args()
    if (args.rounds < 2 or args.seconds <= 0 or len(args.cpus) < 4 or
            len(set(args.cpus)) != len(args.cpus) or
            not set(args.cpus).issubset(os.sched_getaffinity(0))):
        parser.error('provide positive duration, at least two rounds and four distinct available CPUs')
    out, build = args.output.resolve(), args.build.resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'scan-engine'
    subprocess.run(['cc', '-O2', '-g', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'libclamav'), '-I' + str(build),
                    str(ROOT / 'benchmarks/scan-engine.c'), '-L' + str(build / 'libclamav'),
                    '-lclamav', '-lpthread', '-o', str(binary)], check=True)
    environments, metadata = {}, {'cpus': args.cpus, 'rounds': args.rounds,
                                  'target_seconds': args.seconds, 'libraries': {}}
    for name, directory in [('before', args.before.resolve()), ('after', args.after.resolve())]:
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = ':'.join(map(str, [directory] + [build / d for d in
            ('libclamunrar_iface', 'libclamunrar', 'libclammspack')]))
        links = subprocess.check_output(['ldd', str(binary)], env=env, text=True)
        (out / (name + '-libraries.txt')).write_text(links)
        selected = next(line for line in links.splitlines() if 'libclamav.so' in line)
        if str(directory) not in selected:
            raise RuntimeError('wrong library selected: ' + selected)
        library = (directory / 'libclamav.so').resolve()
        with library.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        metadata['libraries'][name] = {'path': str(library),
            'sha256': digest}
        environments[name] = env

    workloads = []
    for name, regex, expression, expected in [
        ('global', r'0/abc/g', '1=1024', ('1', 'pcre-bench.UNOFFICIAL')),
        ('global-captures', r'0/(a)(b)(c)/g', '1=1024', ('1', 'pcre-bench.UNOFFICIAL')),
        ('single', r'0/(a)(b)(c)/', '1', ('1', 'pcre-bench.UNOFFICIAL')),
        ('no-match', r'0/absent/g', '1', ('0', '')),
    ]:
        directory = out / name
        directory.mkdir(exist_ok=True)
        sample = directory / 'sample.bin'
        sample.write_bytes(b'MZ ' + b'abc ' * 1024 + b'END')
        database = directory / 'test.ldb'
        database.write_text('pcre-bench;Engine:81-255,Target:0;' + expression + ';4d5a;' + regex + '\n')
        # Multiple list entries allow longer control runs without exceeding the
        # harness's repetition limit. The engine's clean cache stays disabled.
        workloads.append((directory, database, [sample] * 8, expected))
    corpus = sorted((build / 'unit_tests/input/clamav_hdb_scanfiles').glob('clam*'))
    if not corpus:
        raise RuntimeError('decoded test corpus is missing')
    for name, expected in [('corpus-clean', ('0', '')),
                           ('corpus-detections', ('1', 'ClamAV-Test-File.UNOFFICIAL'))]:
        directory = out / name
        directory.mkdir(exist_ok=True)
        database = directory / 'test.hdb'
        signature = (ROOT / 'unit_tests/input/clamav.hdb').read_text()
        if name == 'corpus-clean':
            signature = hashlib.sha256(b'nonmatching-benchmark-sentinel').hexdigest() + ':' + signature.split(':', 1)[1]
        database.write_text(signature)
        workloads.append((directory, database, corpus, expected))

    samples = []
    for directory, database, files, expected in workloads:
        if args.workloads and directory.name not in args.workloads:
            continue
        filelist = directory / 'files.txt'
        filelist.write_text(''.join(str(p) + '\n' for p in files))

        def invoke(variant, threads, repetitions, label):
            output = directory / (label + '-' + variant + '.tsv')
            with output.open('w') as stdout, output.with_suffix('.stderr').open('w') as stderr:
                subprocess.run(['taskset', '-c', ','.join(map(str, args.cpus[:threads])),
                    str(binary), str(database), str(filelist), str(repetitions), str(threads), str(ROOT / 'certs')],
                    env=environments[variant], stdout=stdout, stderr=stderr, check=True, timeout=300)
            with output.open() as stream:
                marker, tasks, signatures, workers, wall, cpu, rss = stream.readline().strip().split('\t')
                rows = list(csv.DictReader(stream, delimiter='\t'))
            if (marker != 'summary' or len(rows) != int(tasks) or int(signatures) != 1 or
                    any((row['status'], row['name']) != expected for row in rows)):
                raise RuntimeError('unexpected scan results: ' + str(output))
            return {'workload': directory.name, 'variant': variant, 'threads': int(workers),
                    'tasks': int(tasks), 'seconds': float(wall), 'fps': int(tasks) / float(wall),
                    'cpu_ms_per_file': 1000 * float(cpu) / int(tasks), 'rss_kib': int(rss)}

        for threads in (1, 4):
            calibration_reps = 8 if len(files) == 8 else 1
            calibration = invoke('before', threads, calibration_reps, 'calibration-t' + str(threads))
            repetitions = max(1, min(10000, math.ceil(args.seconds * calibration_reps / calibration['seconds'])))
            for round_number in range(args.rounds):
                order = ('before', 'after') if round_number % 2 == 0 else ('after', 'before')
                for variant in order:
                    sample = invoke(variant, threads, repetitions, f't{threads}-r{round_number}')
                    sample['round'] = round_number
                    samples.append(sample)
            selected = [s for s in samples if s['workload'] == directory.name and s['threads'] == threads]
            medians = {v: statistics.median(s['fps'] for s in selected if s['variant'] == v)
                       for v in ('before', 'after')}
            print(f'{directory.name} threads={threads}: {medians}, throughput change '
                  f'{100 * (medians["after"] / medians["before"] - 1):+.1f}%', flush=True)
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (out / 'samples.json').write_text(json.dumps(samples, indent=2) + '\n')


if __name__ == '__main__':
    main()
