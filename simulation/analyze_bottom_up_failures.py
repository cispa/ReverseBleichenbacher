#!/usr/bin/env python3
"""Replay pinned proof Bottom-Up aborts and classify the failed round.

An exhausted round with a queried TTT-conforming multiplier was stopped by
the stricter oracle's false negative. Otherwise the finite public query
schedule did not cover the true residue. Replay checks the original result,
query counts, and achieved trimmer before publishing either classification.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from key_policy import load_keys
from oracle import CountingOracle
from proof import ProofAttack
from proof import attack as attack_module
from proof.bottom_up import BottomUpFailure, BottomUpRecovery
from trials import MESSAGE_GENERATOR, make_trial
from validate_run import validate_run


OUTPUT_FIELDS = (
    "source_run_name", "source_results_sha256", "oracle", "bits", "run",
    "key_index", "tau_found", "tau_available", "failed_round_bits",
    "failed_round_queries", "ttt_positive_queries",
    "tft_prefix_rejected_queries", "fft_missing_zero_queries", "classification",
)


class TranscriptOracle(CountingOracle):
    def __init__(self, plaintext: int, modulus: int, bits: int, oracle_type: str):
        super().__init__(plaintext, modulus, bits, oracle_type)
        self.bottom_up_queries: list[tuple[int, bool]] = []
        self.failed_round_start: int | None = None
        self.failed_round_D: int | None = None

    def __call__(self, multiplier: int) -> bool:
        answer = super().__call__(multiplier)
        if self._phase == "bottom_up":
            self.bottom_up_queries.append((multiplier, answer))
        return answer


class TracedBottomUpRecovery(BottomUpRecovery):
    def _recover_round(self, oracle: TranscriptOracle, D: int, guesses):
        start = len(oracle.bottom_up_queries)
        try:
            return super()._recover_round(oracle, D, guesses)
        except BottomUpFailure:
            oracle.failed_round_start = start
            oracle.failed_round_D = D
            raise


def replay_cell(cell: Path, keys_dir: Path) -> list[dict[str, object]]:
    validate_run(cell, require_publication_ready=True)
    metadata = json.loads((cell / "metadata.json").read_text())
    if metadata["implementation"] != "proof":
        raise ValueError(f"{cell}: expected a proof cell")
    if metadata["message_generator"] != MESSAGE_GENERATOR:
        raise ValueError(f"{cell}: message generator differs from replay code")
    bits = int(metadata["bits"])
    oracle_type = metadata["oracle"]
    config = metadata["algorithm_config"]
    keys = load_keys(keys_dir, bits)
    results_path = cell / "results.csv"
    source_hash = hashlib.sha256(results_path.read_bytes()).hexdigest()
    with results_path.open(newline="") as handle:
        failed = [
            row for row in csv.DictReader(handle)
            if row["outcome"] == "bottom_up_failed"
        ]

    output = []
    for row in failed:
        run = int(row["run"])
        trial = make_trial(keys, int(metadata["master_seed"]), bits, run)
        if trial.key_index != int(row["key_index"]):
            raise ValueError(f"{cell}: run {run} key differs from recorded trial")
        attack = ProofAttack(
            search_strategy=config["search_strategy"],
            search_slack=int(config["search_slack"]),
            search_full_grid_fallback=bool(config["search_full_grid_fallback"]),
            bottom_up_strategy=config["bottom_up_strategy"],
            bottom_up_start_bits=int(config["bottom_up_start_bits"]),
            bottom_up_r_limit=int(config["bottom_up_r_limit"]),
            bottom_up_full_setting_limit=int(config["bottom_up_full_setting_limit"]),
        )
        attack.init_process(**attack.init_optimized(oracle_type, bits))
        oracle = TranscriptOracle(trial.plaintext, trial.key.n, bits, oracle_type)
        try:
            attack.attack(oracle, trial.key.n)
        except Exception as error:
            if (
                getattr(error, "error_type", type(error).__name__)
                != row["error_type"]
                or str(error) != row["error_message"]
            ):
                raise ValueError(f"{cell}: run {run} replay error differs") from error
        else:
            raise ValueError(f"{cell}: run {run} unexpectedly succeeded")

        expected_counts = {
            phase: int(row[f"{field}_queries"])
            for phase, field in (
                ("trimmer", "trimmer"), ("search", "search"),
                ("other", "other"), ("bottom_up", "bottom_up"),
            )
        }
        if (
            oracle._phase != "bottom_up"
            or oracle.counts != expected_counts
            or attack.tau_found != int(row["tau_found"])
            or oracle.failed_round_start is None
            or oracle.failed_round_D is None
        ):
            raise ValueError(f"{cell}: run {run} replay transcript differs")

        final_round = oracle.bottom_up_queries[oracle.failed_round_start:]
        if any(reply for _, reply in final_round):
            raise ValueError(f"{cell}: run {run} failed round had an accepted query")
        B = 1 << (bits - 16)
        ttt_positive = prefix_rejected = suffix_rejected = 0
        for multiplier, _reply in final_round:
            value = (trial.plaintext * multiplier) % trial.key.n
            if not 2 * B <= value < 3 * B:
                continue
            ttt_positive += 1
            if oracle_type != "TTT":
                encoded = value.to_bytes(bits // 8, "big")
                if any(byte == 0 for byte in encoded[2:10]):
                    prefix_rejected += 1
                elif oracle_type == "FFT" and 0 not in encoded[10:]:
                    suffix_rejected += 1
                else:
                    raise ValueError(
                        f"{cell}: run {run} TTT-positive query should have been accepted"
                    )
        classification = (
            "bottom_up_false_negative_exhausted"
            if ttt_positive else "bottom_up_coverage_exhausted"
        )
        output.append({
            "source_run_name": f"{cell.parent.name}/{cell.name}",
            "source_results_sha256": source_hash,
            "oracle": oracle_type,
            "bits": bits,
            "run": run,
            "key_index": trial.key_index,
            "tau_found": attack.tau_found,
            "tau_available": int(row["tau_available"]),
            "failed_round_bits": oracle.failed_round_D.bit_length() - 1,
            "failed_round_queries": len(final_round),
            "ttt_positive_queries": ttt_positive,
            "tft_prefix_rejected_queries": prefix_rejected,
            "fft_missing_zero_queries": suffix_rejected,
            "classification": classification,
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grid", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--keys-dir", type=Path,
        default=Path(__file__).resolve().parent / "keys",
    )
    args = parser.parse_args()

    original = attack_module.BottomUpRecovery
    attack_module.BottomUpRecovery = TracedBottomUpRecovery
    try:
        rows = [
            row
            for oracle in ("TTT", "TFT", "FFT")
            for bits in (1024, 2048)
            for row in replay_cell(args.grid / f"proof_{oracle}_{bits}", args.keys_dir)
        ]
    finally:
        attack_module.BottomUpRecovery = original

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {args.out}: {len(rows)} checked aborts")
    for oracle in ("TTT", "TFT", "FFT"):
        for bits in (1024, 2048):
            counts = Counter(
                row["classification"] for row in rows
                if row["oracle"] == oracle and row["bits"] == bits
            )
            print(f"{oracle}-{bits}: {dict(counts)}")


if __name__ == "__main__":
    main()
