#!/usr/bin/env python3
"""Run one implementation/oracle/key-size simulation cell."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import multiprocessing as mp
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from adapters import IMPLEMENTATIONS, public_config, run_trial
from key_policy import KEY_POLICY, key_file, load_keys
from proof.bottom_up import BOTTOM_UP_STRATEGIES, DEFAULT_BOTTOM_UP_STRATEGY
from proof.search import DEFAULT_SEARCH_STRATEGY, SEARCH_STRATEGIES
from schema import RESULT_COLUMNS, SCHEMA_VERSION
from trials import MESSAGE_GENERATOR, make_trial


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _relative_to_repo(path: Path) -> str:
    return os.path.relpath(path.resolve(), REPO_ROOT)


def _recorded_path(path: Path, *, legacy_absolute: bool) -> str:
    return str(path.resolve()) if legacy_absolute else _relative_to_repo(path)


def _portable_command(argv: list[str]) -> list[str]:
    command = list(argv)
    command[0] = _relative_to_repo(Path(command[0]))
    for option in ("--keys-dir", "--out"):
        if option in command:
            index = command.index(option) + 1
            command[index] = _relative_to_repo(Path(command[index]))
    return command


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


_WORKER_CONFIG = None
_WORKER_KEYS = None


def _init_worker(
    implementation,
    oracle_type,
    bits,
    master_seed,
    keys_dir,
    proof_search_strategy,
    proof_search_slack,
    proof_bottom_up_strategy,
    proof_bottom_up_r_limit,
):
    global _WORKER_CONFIG, _WORKER_KEYS
    logging.basicConfig(level=logging.WARNING)
    _WORKER_CONFIG = (
        implementation,
        oracle_type,
        bits,
        master_seed,
        proof_search_strategy,
        proof_search_slack,
        proof_bottom_up_strategy,
        proof_bottom_up_r_limit,
    )
    _WORKER_KEYS = load_keys(keys_dir, bits)


def _worker(run):
    (
        implementation,
        oracle_type,
        bits,
        master_seed,
        proof_search_strategy,
        proof_search_slack,
        proof_bottom_up_strategy,
        proof_bottom_up_r_limit,
    ) = _WORKER_CONFIG
    trial = make_trial(_WORKER_KEYS, master_seed, bits, run)
    try:
        return run_trial(
            implementation,
            trial,
            oracle_type,
            bits,
            proof_search_strategy=proof_search_strategy,
            proof_search_slack=proof_search_slack,
            proof_bottom_up_strategy=proof_bottom_up_strategy,
            proof_bottom_up_r_limit=proof_bottom_up_r_limit,
        )
    except Exception as exc:
        return _internal_row(trial, exc)


def _internal_row(trial, exc: BaseException) -> dict[str, object]:
    return {
        "run": trial.run,
        "key_index": trial.key_index,
        "outcome": "internal_error",
        "step": "harness",
        "correct": 0,
        "error_type": type(exc).__name__,
        "error_message": str(exc),
        "tau_found": "",
        "tau_available": "",
        "trimmer_has_divisor": "",
        "trimmer_detectable": "",
        "total_queries": "",
        "trimmer_queries": "",
        "search_queries": "",
        "other_queries": "",
        "bottom_up_queries": "",
    }


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("implementation", choices=IMPLEMENTATIONS)
    parser.add_argument("experiments", type=int)
    parser.add_argument("oracle", choices=("TTT", "TFT", "FFT"))
    parser.add_argument("bits", type=int, choices=(1024, 2048))
    parser.add_argument("--master-seed", type=int, required=True)
    parser.add_argument("--processes", type=int, default=os.cpu_count() or 1)
    parser.add_argument(
        "--proof-search-strategy",
        choices=SEARCH_STRATEGIES,
        default=DEFAULT_SEARCH_STRATEGY,
    )
    parser.add_argument("--proof-search-slack", type=int)
    parser.add_argument(
        "--proof-bottom-up-strategy",
        choices=BOTTOM_UP_STRATEGIES,
        default=DEFAULT_BOTTOM_UP_STRATEGY,
    )
    parser.add_argument("--proof-bottom-up-r-limit", type=int, default=2048)
    parser.add_argument("--keys-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    # A resume runner started before portable manifests were introduced still
    # validates new cells against absolute key_file metadata. Its invocation
    # uses absolute paths for the script, key pool, and output directory.
    legacy_absolute = (
        Path(sys.argv[0]).is_absolute()
        and args.keys_dir.is_absolute()
        and args.out.is_absolute()
    )
    if args.experiments < 1:
        parser.error("experiments must be positive")
    if args.processes < 1:
        parser.error("--processes must be positive")
    if args.proof_bottom_up_r_limit < 1:
        parser.error("--proof-bottom-up-r-limit must be positive")
    if args.proof_search_slack is not None and args.proof_search_slack < 0:
        parser.error("--proof-search-slack cannot be negative")

    cell_dir = args.out.resolve() / args.name
    if cell_dir.exists():
        parser.error(f"refusing to overwrite existing cell: {cell_dir}")
    try:
        pool = load_keys(args.keys_dir, args.bits)
        config = public_config(
            args.implementation,
            args.bits,
            args.oracle,
            proof_search_strategy=args.proof_search_strategy,
            proof_search_slack=args.proof_search_slack,
            proof_bottom_up_strategy=args.proof_bottom_up_strategy,
            proof_bottom_up_r_limit=args.proof_bottom_up_r_limit,
        )
    except (OSError, ValueError, ImportError) as exc:
        parser.error(str(exc))
    cell_dir.mkdir(parents=True)
    started = _now()
    start_time = time.monotonic()
    rows = {}
    workers = min(args.processes, args.experiments)
    chunk_size = max(1, args.experiments // (8 * workers))
    worker_error = None
    try:
        with mp.Pool(
            processes=workers,
            initializer=_init_worker,
            initargs=(
                args.implementation,
                args.oracle,
                args.bits,
                args.master_seed,
                args.keys_dir,
                args.proof_search_strategy,
                args.proof_search_slack,
                args.proof_bottom_up_strategy,
                args.proof_bottom_up_r_limit,
            ),
        ) as executor:
            for row in executor.imap_unordered(
                _worker, range(args.experiments), chunksize=chunk_size
            ):
                rows[row["run"]] = row
    except Exception as exc:
        worker_error = exc
    for run in range(args.experiments):
        if run not in rows:
            trial = make_trial(pool, args.master_seed, args.bits, run)
            rows[run] = _internal_row(
                trial, worker_error or RuntimeError("worker returned no result")
            )

    result_path = cell_dir / "results.csv"
    temporary = result_path.with_suffix(".csv.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=RESULT_COLUMNS,
            extrasaction="raise",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows[run] for run in range(args.experiments))
    temporary.replace(result_path)

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "implementation": args.implementation,
        "implementation_dir": _recorded_path(
            HERE / (
                "capol_baseline"
                if args.implementation == "capol"
                else args.implementation
            ),
            legacy_absolute=legacy_absolute,
        ),
        "oracle": args.oracle,
        "bits": args.bits,
        "nr_experiments": args.experiments,
        "master_seed": args.master_seed,
        "message_generator": MESSAGE_GENERATOR,
        "key_policy": KEY_POLICY,
        "key_pool_size": len(pool),
        "key_file": _recorded_path(
            key_file(args.keys_dir, args.bits), legacy_absolute=legacy_absolute
        ),
        "processes": args.processes,
        "algorithm_config": config,
        "command": list(sys.argv) if legacy_absolute else _portable_command(sys.argv),
        "started_at": started,
        "finished_at": _now(),
        "wall_clock_seconds": time.monotonic() - start_time,
        "git_commit": _git_commit(),
        "python": sys.version,
    }
    _write_json(cell_dir / "metadata.json", metadata)
    print(cell_dir)


if __name__ == "__main__":
    main()
