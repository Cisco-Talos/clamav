#!/usr/bin/env python3
"""Compare already-built libclamav variants on decoded repository test fixtures.

No daemon or sockets are used. The C harness keeps one engine loaded, disables
the clean cache, warms every file, and then times scans with 1 or 4 workers.
"""
import argparse
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/perf-results"
CPUS = None


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def build_environment(variant):
    env = os.environ.copy()
    build = ROOT / f"build/perf-{variant}"
    # libclamunrar_iface is loaded dynamically; the main library's RUNPATH
    # alone is insufficient for its companion libclamunrar dependency.
    env["LD_LIBRARY_PATH"] = ":".join(str(build / name) for name in (
        "libclamav", "libclamunrar_iface", "libclamunrar", "libclammspack"))
    return env


def invoke(variant, label, repetitions, threads):
    output = OUT / f"{label}-{variant}.tsv"
    with output.open("w") as stdout, output.with_suffix(".stderr").open("w") as stderr:
        subprocess.run([
            str(OUT / f"scan-engine-{variant}"), str(OUT / "database"),
            str(OUT / "files.txt"), str(repetitions), str(threads), str(ROOT / "certs"),
        ], check=True, stdout=stdout, stderr=stderr, timeout=600, env=build_environment(variant),
            preexec_fn=(lambda: os.sched_setaffinity(0, CPUS[:threads])) if CPUS else None)
    with output.open() as stream:
        marker, tasks, signatures, workers, wall, cpu, rss = stream.readline().strip().split("\t")
        assert marker == "summary"
        rows = list(csv.DictReader(stream, delimiter="\t"))
    assert len(rows) == int(tasks)
    return {
        "variant": variant, "threads": int(workers), "repetitions": repetitions,
        "tasks": int(tasks), "signatures": int(signatures), "wall_seconds": float(wall),
        "files_per_second": int(tasks) / float(wall),
        "cpu_seconds_per_file": float(cpu) / int(tasks), "peak_rss_mib": int(rss) / 1024,
        "p50_ms": 1000 * percentile([float(row["seconds"]) for row in rows], .50),
        "p95_ms": 1000 * percentile([float(row["seconds"]) for row in rows], .95),
        "p99_ms": 1000 * percentile([float(row["seconds"]) for row in rows], .99),
        "raw": str(output.relative_to(ROOT)),
    }, rows


def main():
    global OUT, CPUS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variants", nargs="+", default=["baseline", "c-lto", "c-rust-lto"],
                        choices=["baseline", "c-lto", "c-rust-lto"])
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--target-seconds", type=float, default=2.0)
    parser.add_argument("--threads", nargs="+", type=int, default=[1, 4])
    parser.add_argument("--workload", choices=["detections", "clean"], default="detections")
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--cpus", nargs="+", type=int,
                        help="Pin N workers to the first N listed logical CPUs (Linux)")
    args = parser.parse_args()
    if args.rounds < 1 or args.target_seconds <= 0 or any(t < 1 or t > 64 for t in args.threads):
        parser.error("invalid rounds, target duration, or threads")
    if len(set(args.variants)) != len(args.variants):
        parser.error("variants must be distinct")
    if args.cpus and (len(set(args.cpus)) != len(args.cpus) or len(args.cpus) < max(args.threads)
                      or not set(args.cpus).issubset(os.sched_getaffinity(0))):
        parser.error("provide enough distinct, available CPUs for the requested worker counts")
    CPUS = args.cpus
    OUT = args.output.resolve() / args.workload
    OUT.mkdir(parents=True, exist_ok=True)
    database = OUT / "database"
    database.mkdir(exist_ok=True)
    # Use a dedicated test database, independent of host/production signatures.
    source_db = ROOT / "unit_tests/input/clamav.hdb"
    database_bytes = source_db.read_bytes()
    if args.workload == "clean":
        # Keep the same hash algorithm and target file size, but use an unmatched
        # sentinel so detections do not short-circuit parsing of this corpus.
        _, size, _ = database_bytes.decode().strip().split(":")
        sentinel = hashlib.sha256(b"ClamAV LTO benchmark unmatched sentinel").hexdigest()
        database_bytes = f"{sentinel}:{size}:Benchmark-Unmatched\n".encode()
    (database / "clamav.hdb").write_bytes(database_bytes)
    if sorted(p.name for p in database.iterdir()) != ["clamav.hdb"]:
        raise RuntimeError("benchmark database contains unexpected files")
    corpus = ROOT / "build/perf-baseline/unit_tests/input/clamav_hdb_scanfiles"
    files = sorted(p.resolve() for p in corpus.iterdir() if p.is_file())
    if not files:
        raise RuntimeError("build baseline first to decode test fixtures")
    manifest = [{"path": str(p.relative_to(ROOT)), "bytes": p.stat().st_size,
                 "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (OUT / "files.txt").write_text("".join(str(p) + "\n" for p in files))
    for variant in args.variants:
        build = ROOT / f"build/perf-{variant}"
        subprocess.run([
            "cc", "-O2", "-g", "-std=c99", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ROOT / "libclamav"), "-I" + str(build),
            str(ROOT / "benchmarks/scan-engine.c"), "-L" + str(build / "libclamav"),
            "-Wl,-rpath," + str(build / "libclamav"), "-lclamav", "-lpthread",
            "-o", str(OUT / f"scan-engine-{variant}"),
        ], check=True)
        links = subprocess.check_output(["ldd", str(OUT / f"scan-engine-{variant}")],
                                        text=True, env=build_environment(variant))
        (OUT / f"{variant}-harness-libraries.txt").write_text(links)
        clamav_line = next(line for line in links.splitlines() if "libclamav.so" in line)
        if str(build / "libclamav") not in clamav_line:
            raise RuntimeError("harness selected the wrong libclamav")

    calibration, rows = invoke(args.variants[0], "calibration", 1, 1)
    # These fixtures all contain the HDB test signature, including RAR files.
    # Equality alone would miss a parser/plugin absent from every variant.
    expected_verdict = ("1", "ClamAV-Test-File.UNOFFICIAL") if args.workload == "detections" else ("0", "")
    if any((row["status"], row["name"]) != expected_verdict for row in rows):
        raise RuntimeError("unexpected fixture verdict; verify parser/plugin availability")
    expected = {int(row["file"]): (row["status"], row["name"]) for row in rows}
    orders = list(itertools.permutations(args.variants))
    samples = []
    print(f"Corpus: {len(files)} files; cache disabled", flush=True)
    for threads in args.threads:
        thread_calibration = calibration
        if threads != 1:
            thread_calibration, _ = invoke(args.variants[0], f"calibration-t{threads}", 1, threads)
        repetitions = max(1, min(500, math.ceil(args.target_seconds / thread_calibration["wall_seconds"])))
        print(f"threads={threads}: {repetitions} corpus repetitions per sample", flush=True)
        for round_number in range(args.rounds):
            for variant in orders[round_number % len(orders)]:
                sample, rows = invoke(variant, f"t{threads}-r{round_number}", repetitions, threads)
                for row in rows:
                    if (row["status"], row["name"]) != expected[int(row["file"])]:
                        raise RuntimeError(f"verdict mismatch: {variant}: {row}")
                if sample["signatures"] != calibration["signatures"]:
                    raise RuntimeError("signature count mismatch")
                sample["round"] = round_number
                sample["input_mib_per_second"] = (
                    sum(f["bytes"] for f in manifest) * sample["repetitions"] / 2**20 / sample["wall_seconds"]
                )
                samples.append(sample)
                (OUT / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
                print(f"threads={threads} round={round_number} {variant}: "
                      f"{sample['files_per_second']:.1f} files/s", flush=True)
    summary = []
    for threads in args.threads:
        for variant in args.variants:
            group = [s for s in samples if s["threads"] == threads and s["variant"] == variant]
            summary.append({"variant": variant, "threads": threads, **{
                "median_" + metric: statistics.median(s[metric] for s in group)
                for metric in ("files_per_second", "input_mib_per_second", "p50_ms", "p95_ms", "p99_ms",
                               "cpu_seconds_per_file", "peak_rss_mib")
            }, "min_files_per_second": min(s["files_per_second"] for s in group),
               "max_files_per_second": max(s["files_per_second"] for s in group)})
    report = {
        "method": "in-process libclamav; warm filesystem; scan cache disabled; startup excluded",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "platform": list(os.uname()), "cpu_affinity": CPUS, "files": len(files),
        "input_bytes": sum(f["bytes"] for f in manifest), "rounds": args.rounds,
        "workload": args.workload,
        "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
        "signatures": calibration["signatures"], "verdicts_equal": True,
        "summary": summary,
    }
    (OUT / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
