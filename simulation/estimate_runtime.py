#!/usr/bin/env python3
"""Time short simulation runs and extrapolate the cost of a full-scale run.

    ./estimate_runtime.py [--backend capol|current|both] [--probe N] [--target N]

Runs every (oracle, key size) combination at a small `--probe` size, measures
wall clock, and extrapolates linearly to `--target`. Extrapolation is linear in
the number of experiments; process-pool startup is subtracted out by treating
the smallest probe as overhead only if two probe sizes are given.

The per-experiment cost is dominated by the number of oracle queries, whose
distribution is heavy-tailed, so small probes give noisy estimates. Treat the
output as an order-of-magnitude planning number, not a promise.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run_simulation.py"

ORACLES = ("TTT", "TFT", "FFT")
BITS = (1024, 2048)


def fmt_duration(seconds):
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def probe(backend, oracle, bits, n, processes, workdir):
    cmd = [
        sys.executable,
        str(RUNNER),
        backend,
        str(n),
        oracle,
        str(bits),
        "--out",
        str(workdir),
        "--name",
        f"probe_{backend}_{oracle}_{bits}",
    ]
    if processes:
        cmd += ["--processes", str(processes)]

    start = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start
    if res.returncode != 0:
        print(res.stdout[-2000:], file=sys.stderr)
        print(res.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"probe failed: {backend} {oracle} {bits}")

    meta = json.loads(
        (workdir / f"probe_{backend}_{oracle}_{bits}" / "metadata.json").read_text()
    )
    return elapsed, meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("capol", "current", "both"), default="both")
    parser.add_argument("--probe", type=int, default=200, help="probe size (default 200)")
    parser.add_argument("--target", type=int, default=100000, help="target size (default 100000)")
    parser.add_argument("--processes", type=int, default=None)
    args = parser.parse_args()

    backends = ("capol", "current") if args.backend == "both" else (args.backend,)
    workdir = Path(tempfile.mkdtemp(prefix="sim-estimate-"))

    rows = []
    try:
        for backend in backends:
            for oracle in ORACLES:
                for bits in BITS:
                    elapsed, meta = probe(
                        backend, oracle, bits, args.probe, args.processes, workdir
                    )
                    n = meta["nr_experiments"]
                    rows.append(
                        {
                            "backend": backend,
                            "oracle": oracle,
                            "bits": bits,
                            "probe_n": n,
                            "probe_s": elapsed,
                            "per_exp_s": elapsed / n,
                            "target_s": elapsed / n * args.target,
                            "median": meta["summary"]["total_queries"]["median"],
                            "success": meta["summary"]["success_probability"],
                        }
                    )
                    print(
                        f"  {backend:>7} {oracle} {bits}: {elapsed:7.1f}s "
                        f"-> {fmt_duration(rows[-1]['target_s']):>7} "
                        f"for {args.target}",
                        flush=True,
                    )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    print(f"Extrapolated wall clock for {args.target} experiments "
          f"(probe: {args.probe}, {args.processes or 'all'} processes)")
    print()
    print(f"{'backend':>8} {'oracle':>7} {'bits':>5} {'probe':>9} "
          f"{'per exp':>9} {'target':>9} {'median':>9} {'success':>8}")
    print("-" * 74)
    total = 0.0
    for r in rows:
        total += r["target_s"]
        median = "fail" if r["median"] is None else f"{r['median']:.0f}"
        print(
            f"{r['backend']:>8} {r['oracle']:>7} {r['bits']:>5} "
            f"{r['probe_s']:>8.1f}s {r['per_exp_s']:>8.3f}s "
            f"{fmt_duration(r['target_s']):>9} {median:>9} {r['success']:>7.1%}"
        )
    print("-" * 74)
    print(f"{'TOTAL':>8} {'':>7} {'':>5} {'':>9} {'':>9} {fmt_duration(total):>9}")


if __name__ == "__main__":
    main()
