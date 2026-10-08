#!/usr/bin/env python3
"""Replay a small paired sample of historical proof failures.

Plaintext is used only to select/report historical causal classes.  Every
attack under test receives only its oracle and public modulus.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from key_policy import load_keys
from oracle import CountingOracle
from reversebleichenbacher import ProofAttack, SequentialExecutor
from reversebleichenbacher.search import SEARCH_STRATEGIES
from reporting import reported_outcome, trimmer_missed_power_of_two
from trials import generate_message, make_trial


DEFAULT_SOURCE = REPO_ROOT / "simulation" / "results" / "proofs-test"
DEFAULT_KEYS = REPO_ROOT / "simulation" / "keys"


def _even_sample(values: list[int], limit: int) -> list[int]:
    if limit >= len(values):
        return values
    if limit == 1:
        return [values[0]]
    return [values[round(i * (len(values) - 1) / (limit - 1))] for i in range(limit)]


def selected_runs(
    cell: Path, bits: int, kind: str, limit: int
) -> tuple[dict, list[int]]:
    metadata = json.loads((cell / "metadata.json").read_text())
    selected = []
    with (cell / "results.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row["outcome"] not in {
                "search_failed", "search_coverage_exhausted",
                "search_false_negative_exhausted",
            }:
                continue
            run = int(row["run"])
            tau = int(row["tau_found"])
            encoded, _suffix = generate_message(metadata["master_seed"], bits, run)
            missed = trimmer_missed_power_of_two(int.from_bytes(encoded, "big"), tau)
            if (kind == "missed-power" and missed) or (kind == "search" and not missed):
                selected.append(run)
    return metadata, _even_sample(selected, limit)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--keys-dir", type=Path, default=DEFAULT_KEYS)
    parser.add_argument("--bits", type=int, choices=(1024, 2048), required=True)
    parser.add_argument("--kind", choices=("missed-power", "search"), required=True)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--strategies", default="standard_coverage,halving_full_grid"
    )
    parser.add_argument("--search-slack-factors", default="1,2,3")
    parser.add_argument("--bottom-up-start-bits", type=int, default=4)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    strategies = tuple(x.strip() for x in args.strategies.split(",") if x.strip())
    if not strategies or any(x not in SEARCH_STRATEGIES for x in strategies):
        parser.error(f"strategies must come from {SEARCH_STRATEGIES}")
    try:
        factors = tuple(
            int(x.strip()) for x in args.search_slack_factors.split(",") if x.strip()
        )
    except ValueError:
        parser.error("--search-slack-factors must be comma-separated integers")
    if not factors or any(value < 0 for value in factors):
        parser.error("search slack factors must be nonnegative")

    cell = args.source / f"proof_FFT_{args.bits}"
    metadata, runs = selected_runs(cell, args.bits, args.kind, args.limit)
    if not runs:
        parser.error(f"no {args.kind} rows found in {cell}")
    keys = load_keys(args.keys_dir, args.bits)
    logging.disable(logging.CRITICAL)

    fields = (
        "bits",
        "run",
        "historical_cause",
        "strategy",
        "search_slack",
        "bottom_up_start_bits",
        "outcome",
        "causal_outcome",
        "correct",
        "tau_found",
        "trimmer_queries",
        "search_queries",
        "bottom_up_queries",
        "total_queries",
        "error",
    )
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    totals = Counter()

    for run in runs:
        trial = make_trial(keys, metadata["master_seed"], args.bits, run)
        for strategy in strategies:
            for factor in factors:
                probe = ProofAttack(search_strategy=strategy)
                params = probe.init_optimized("FFT", args.bits)
                search_slack = factor * (params["config"].t_slack + 1)
                attack = ProofAttack(
                    search_strategy=strategy,
                    search_slack=search_slack,
                    bottom_up_start_bits=args.bottom_up_start_bits,
                )
                attack.init_process(**params)
                oracle = CountingOracle(
                    trial.plaintext, trial.key.n, args.bits, "FFT"
                )
                recovered = None
                error = ""
                try:
                    recovered, _stats = attack.attack(SequentialExecutor(oracle), trial.key.n)
                    outcome = "ok"
                except Exception as exc:
                    outcome = f"{getattr(oracle, '_phase', 'harness')}_failed"
                    error = str(exc)
                correct = bool(
                    recovered is not None
                    and recovered & ((1 << (8 * 46)) - 1)
                    == int.from_bytes(trial.target_suffix, "big")
                )
                if recovered is not None and not correct:
                    outcome = "wrong_result"
                causal_outcome = reported_outcome(
                    "proof", outcome, trial.plaintext, attack.tau_found
                )
                counts = oracle.counts
                totals[(strategy, search_slack, causal_outcome)] += 1
                writer.writerow(
                    {
                        "bits": args.bits,
                        "run": run,
                        "historical_cause": args.kind,
                        "strategy": strategy,
                        "search_slack": search_slack,
                        "bottom_up_start_bits": args.bottom_up_start_bits,
                        "outcome": outcome,
                        "causal_outcome": causal_outcome,
                        "correct": int(correct),
                        "tau_found": attack.tau_found,
                        "trimmer_queries": counts["trimmer"],
                        "search_queries": counts["search"],
                        "bottom_up_queries": counts["bottom_up"],
                        "total_queries": sum(counts.values()),
                        "error": error,
                    }
                )

    print("# summary", file=sys.stderr)
    for key, count in sorted(totals.items()):
        print(f"# {key}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
