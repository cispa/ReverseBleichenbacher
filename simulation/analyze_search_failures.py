#!/usr/bin/env python3
"""Replay and causally refine finished proof Searching failures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from analysis import (
    SEARCH_COVERAGE_EXHAUSTED,
    SEARCH_FALSE_NEGATIVE_EXHAUSTED,
    classify_search_transcript,
    upper_median,
)
from key_policy import load_keys
from oracle import CountingOracle
from reversebleichenbacher import ProofAttack, SequentialExecutor
from trials import MESSAGE_GENERATOR, make_trial
from validate_run import read_results, validate_run


class SearchTranscriptOracle(CountingOracle):
    """Record public Search queries without changing oracle decisions."""

    def __init__(self, plaintext: int, modulus: int, bits: int, oracle_type: str):
        super().__init__(plaintext, modulus, bits, oracle_type)
        self.phase = "other"
        self.search_multipliers: list[int] = []
        self.search_replies: list[bool] = []

    def set_phase(self, phase: str) -> None:
        super().set_phase(phase)
        self.phase = phase

    def __call__(self, multiplier: int) -> bool:
        reply = super().__call__(multiplier)
        if self.phase == "search":
            self.search_multipliers.append(multiplier)
            self.search_replies.append(reply)
        return reply


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = (
        "run",
        "key_index",
        "reported_outcome",
        "tau_found",
        "search_queries",
        "classification",
        "ttt_positive_queries",
        "first_ttt_positive_query",
        "tft_prefix_rejected_queries",
        "fft_missing_zero_queries",
        "false_negative_pattern",
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def _distribution(values: list[int]) -> dict[str, int | float | None]:
    if not values:
        return {"count": 0, "min": None, "median": None, "mean": None, "max": None}
    return {
        "count": len(values),
        "min": min(values),
        "median": upper_median(values),
        "mean": sum(values) / len(values),
        "max": max(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cell", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--keys-dir", type=Path, default=HERE / "keys")
    args = parser.parse_args()

    validation = validate_run(args.cell, require_publication_ready=True)
    metadata = json.loads((args.cell / "metadata.json").read_text())
    if metadata.get("implementation") != "proof":
        parser.error("search failure replay requires a proof cell")
    if metadata.get("message_generator") != MESSAGE_GENERATOR:
        parser.error("search failure replay requires the current message generator")

    config = metadata["algorithm_config"]
    bits = int(metadata["bits"])
    oracle_type = metadata["oracle"]
    keys = load_keys(args.keys_dir, bits)
    source_rows = read_results(args.cell)
    failed_rows = [
        row for row in source_rows
        if row["outcome"] in {
            "search_failed", SEARCH_COVERAGE_EXHAUSTED,
            SEARCH_FALSE_NEGATIVE_EXHAUSTED,
        }
    ]
    output_rows = []

    for row in failed_rows:
        run = int(row["run"])
        trial = make_trial(keys, int(metadata["master_seed"]), bits, run)
        attack = ProofAttack(
            search_strategy=config["search_strategy"],
            search_slack=int(config["search_slack"]),
            search_full_grid_fallback=bool(config.get("search_full_grid_fallback", False)),
            bottom_up_strategy=config["bottom_up_strategy"],
            bottom_up_start_bits=int(config["bottom_up_start_bits"]),
            bottom_up_r_limit=int(config["bottom_up_r_limit"]),
            bottom_up_full_setting_limit=int(
                config["bottom_up_full_setting_limit"]
            ),
        )
        params = attack.init_optimized(oracle_type, bits)
        attack.init_process(**params)
        oracle = SearchTranscriptOracle(
            trial.plaintext, trial.key.n, bits, oracle_type
        )
        try:
            attack.attack(SequentialExecutor(oracle), trial.key.n)
        except Exception:
            pass
        else:
            raise RuntimeError(f"run {run}: replay unexpectedly succeeded")

        expected_counts = {
            "trimmer": int(row["trimmer_queries"]),
            "search": int(row["search_queries"]),
            "other": int(row["other_queries"]),
            "bottom_up": int(row["bottom_up_queries"]),
        }
        if oracle.phase != "search" or oracle.counts != expected_counts:
            raise RuntimeError(
                f"run {run}: replay transcript differs: "
                f"phase={oracle.phase}, counts={oracle.counts}, "
                f"expected={expected_counts}"
            )
        if attack.tau_found != int(row["tau_found"]):
            raise RuntimeError(
                f"run {run}: replay tau={attack.tau_found}, "
                f"expected={row['tau_found']}"
            )
        if any(oracle.search_replies):
            raise RuntimeError(f"run {run}: failed replay contains a positive reply")
        if len(oracle.search_multipliers) != len(set(oracle.search_multipliers)):
            raise RuntimeError(f"run {run}: replay contains duplicate Search queries")

        classification, ttt_positives, first_positive = classify_search_transcript(
            trial.plaintext,
            trial.key.n,
            1 << (8 * (bits // 8 - 2)),
            oracle.search_multipliers,
        )
        if row["outcome"] != "search_failed" and row["outcome"] != classification:
            raise RuntimeError(f"run {run}: recorded Search cause disagrees with replay")
        prefix_rejected = 0
        missing_zero = 0
        B = 1 << (8 * (bits // 8 - 2))
        for multiplier in oracle.search_multipliers:
            value = (trial.plaintext * multiplier) % trial.key.n
            if not 2 * B <= value < 3 * B:
                continue
            encoded = value.to_bytes(bits // 8, "big")
            if any(byte == 0 for byte in encoded[2:10]):
                prefix_rejected += 1
            elif 0 not in encoded[10:]:
                missing_zero += 1
            else:
                raise RuntimeError(
                    f"run {run}: TTT-positive query should have been FFT-positive"
                )
        if prefix_rejected and missing_zero:
            pattern = "mixed"
        elif prefix_rejected:
            pattern = "tft_prefix_only"
        elif missing_zero:
            pattern = "fft_missing_zero_only"
        else:
            pattern = "no_ttt_positive"
        output_rows.append(
            {
                "run": run,
                "key_index": int(row["key_index"]),
                "reported_outcome": row["outcome"],
                "tau_found": int(row["tau_found"]),
                "search_queries": int(row["search_queries"]),
                "classification": classification,
                "ttt_positive_queries": ttt_positives,
                "first_ttt_positive_query": (
                    "" if first_positive is None else first_positive
                ),
                "tft_prefix_rejected_queries": prefix_rejected,
                "fft_missing_zero_queries": missing_zero,
                "false_negative_pattern": pattern,
            }
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "search_failure_analysis.csv"
    json_path = args.out_dir / "search_failure_summary.json"
    _write_csv(csv_path, output_rows)
    classifications = Counter(
        {SEARCH_COVERAGE_EXHAUSTED: 0, SEARCH_FALSE_NEGATIVE_EXHAUSTED: 0}
    )
    classifications.update(row["classification"] for row in output_rows)
    missed_power = sum(
        row["outcome"] == "trimmer_missed_power_of_two"
        and row["step"] == "search"
        for row in source_rows
    )
    _write_json(
        json_path,
        {
            "analysis": "search-failure-causal-replay-v1",
            "classifications": dict(sorted(classifications.items())),
            "message_generator": metadata["message_generator"],
            "missed_power_of_two_search_aborts": missed_power,
            "replayed_search_failures": len(output_rows),
            "search_query_distribution": _distribution(
                [int(row["search_queries"]) for row in output_rows]
            ),
            "ttt_positive_query_distribution": _distribution(
                [int(row["ttt_positive_queries"]) for row in output_rows]
            ),
            "first_ttt_positive_query_distribution": _distribution(
                [
                    int(row["first_ttt_positive_query"])
                    for row in output_rows
                    if row["first_ttt_positive_query"] != ""
                ]
            ),
            "false_negative_patterns": dict(
                sorted(
                    Counter(
                        row["false_negative_pattern"] for row in output_rows
                    ).items()
                )
            ),
            "tft_prefix_rejected_query_distribution": _distribution(
                [int(row["tft_prefix_rejected_queries"]) for row in output_rows]
            ),
            "fft_missing_zero_query_distribution": _distribution(
                [int(row["fft_missing_zero_queries"]) for row in output_rows]
            ),
            "source_cell": str(args.cell.resolve()),
            "source_results_sha256": hashlib.sha256(
                (args.cell / "results.csv").read_bytes()
            ).hexdigest(),
            "source_validation": validation,
        },
    )
    print(json.dumps(json.loads(json_path.read_text()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
