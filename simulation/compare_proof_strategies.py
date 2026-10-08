#!/usr/bin/env python3
"""Compare paired standard-coverage and halving-coverage proof grids."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from analysis import failure_aware_median, load_results, upper_median
from reversebleichenbacher.search import (
    HALVING_FULL_GRID,
    HALVING_SPARSE_ASYMMETRIC,
    HALVING_SPARSE_GRID,
)
from validate_run import validate_grid


HALVING_STRATEGIES = {
    HALVING_FULL_GRID,
    HALVING_SPARSE_GRID,
    HALVING_SPARSE_ASYMMETRIC,
}

FAILURE_ORDER = (
    "trimmer_no_divisor",
    "trimmer_no_multiplier",
    "trimmer_false_negative",
    "trimmer_missed_power_of_two",
    "search_failed",
    "search_coverage_exhausted",
    "search_false_negative_exhausted",
    "other_failed",
    "bottom_up_failed",
    "wrong_result",
    "internal_error",
)

SUMMARY_FIELDS = (
    "oracle",
    "bits",
    "attempts",
    "standard_successes",
    "halving_successes",
    "success_delta_halving_minus_standard",
    "standard_success_pct",
    "halving_success_pct",
    "success_delta_percentage_points",
    "both_succeeded",
    "standard_only_succeeded",
    "halving_only_succeeded",
    "both_failed",
    "standard_failure_aware_median_queries",
    "halving_failure_aware_median_queries",
    "failure_aware_median_delta",
    "standard_success_only_upper_median_queries",
    "halving_success_only_upper_median_queries",
    "success_only_median_delta",
    "paired_both_success_upper_median_total_query_delta",
    "paired_both_success_upper_median_search_query_delta",
    "paired_both_success_upper_median_bottom_up_query_delta",
)

FAILURE_FIELDS = (
    "oracle",
    "bits",
    "outcome",
    "standard_count",
    "halving_count",
    "delta_halving_minus_standard",
)

TRANSITION_FIELDS = (
    "oracle",
    "bits",
    "standard_outcome",
    "halving_outcome",
    "count",
)


class ComparisonError(ValueError):
    pass


def _difference(right: int | None, left: int | None) -> int | None:
    if right is None or left is None:
        return None
    return right - left


def _check_paired_rows(standard, halving) -> None:
    if len(standard) != len(halving):
        raise ComparisonError("paired cells have different row counts")
    for index, (left, right) in enumerate(zip(standard, halving)):
        identity_left = (left["run"], left["key_index"])
        identity_right = (right["run"], right["key_index"])
        if identity_left != identity_right:
            raise ComparisonError(
                f"row {index}: run/key pairing differs: "
                f"{identity_left} != {identity_right}"
            )


def summarize_pair(standard, halving, oracle: str, bits: int):
    _check_paired_rows(standard, halving)
    attempts = len(standard)
    standard_successes = sum(row["outcome"] == "ok" for row in standard)
    halving_successes = sum(row["outcome"] == "ok" for row in halving)

    both = [
        (left, right)
        for left, right in zip(standard, halving)
        if left["outcome"] == right["outcome"] == "ok"
    ]
    standard_only = sum(
        left["outcome"] == "ok" and right["outcome"] != "ok"
        for left, right in zip(standard, halving)
    )
    halving_only = sum(
        left["outcome"] != "ok" and right["outcome"] == "ok"
        for left, right in zip(standard, halving)
    )
    both_failed = attempts - len(both) - standard_only - halving_only

    standard_fa = failure_aware_median(standard)
    halving_fa = failure_aware_median(halving)
    standard_success_median = upper_median(
        [row["total_queries"] for row in standard if row["outcome"] == "ok"]
    )
    halving_success_median = upper_median(
        [row["total_queries"] for row in halving if row["outcome"] == "ok"]
    )

    summary = {
        "oracle": oracle,
        "bits": bits,
        "attempts": attempts,
        "standard_successes": standard_successes,
        "halving_successes": halving_successes,
        "success_delta_halving_minus_standard": (
            halving_successes - standard_successes
        ),
        "standard_success_pct": 100 * standard_successes / attempts,
        "halving_success_pct": 100 * halving_successes / attempts,
        "success_delta_percentage_points": (
            100 * (halving_successes - standard_successes) / attempts
        ),
        "both_succeeded": len(both),
        "standard_only_succeeded": standard_only,
        "halving_only_succeeded": halving_only,
        "both_failed": both_failed,
        "standard_failure_aware_median_queries": standard_fa,
        "halving_failure_aware_median_queries": halving_fa,
        "failure_aware_median_delta": _difference(halving_fa, standard_fa),
        "standard_success_only_upper_median_queries": standard_success_median,
        "halving_success_only_upper_median_queries": halving_success_median,
        "success_only_median_delta": _difference(
            halving_success_median, standard_success_median
        ),
        "paired_both_success_upper_median_total_query_delta": upper_median(
            [right["total_queries"] - left["total_queries"] for left, right in both]
        ),
        "paired_both_success_upper_median_search_query_delta": upper_median(
            [right["search_queries"] - left["search_queries"] for left, right in both]
        ),
        "paired_both_success_upper_median_bottom_up_query_delta": upper_median(
            [
                right["bottom_up_queries"] - left["bottom_up_queries"]
                for left, right in both
            ]
        ),
    }

    standard_failures = Counter(
        row["outcome"] for row in standard if row["outcome"] != "ok"
    )
    halving_failures = Counter(
        row["outcome"] for row in halving if row["outcome"] != "ok"
    )
    outcomes = list(FAILURE_ORDER)
    outcomes.extend(
        sorted((standard_failures | halving_failures).keys() - set(outcomes))
    )
    failures = [
        {
            "oracle": oracle,
            "bits": bits,
            "outcome": outcome,
            "standard_count": standard_failures[outcome],
            "halving_count": halving_failures[outcome],
            "delta_halving_minus_standard": (
                halving_failures[outcome] - standard_failures[outcome]
            ),
        }
        for outcome in outcomes
        if standard_failures[outcome] or halving_failures[outcome]
    ]
    transition_counts = Counter(
        (left["outcome"], right["outcome"])
        for left, right in zip(standard, halving)
    )
    transitions = [
        {
            "oracle": oracle,
            "bits": bits,
            "standard_outcome": left,
            "halving_outcome": right,
            "count": count,
        }
        for (left, right), count in sorted(transition_counts.items())
    ]
    return summary, failures, transitions


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _check_grids(
    standard_dir: Path,
    halving_dir: Path,
    *,
    allow_bundled_variant: bool,
) -> tuple[dict, dict]:
    validate_grid(standard_dir)
    validate_grid(halving_dir)
    standard = _read_json(standard_dir / "manifest.json")
    halving = _read_json(halving_dir / "manifest.json")
    paired_fields = [
        "master_seed",
        "key_policy",
        "experiments_per_cell",
        "oracles",
        "bits",
        "keys_dir",
    ]
    if not allow_bundled_variant:
        paired_fields.extend(
            (
                "proof_search_slack",
                "proof_bottom_up_strategy",
                "proof_bottom_up_r_limit",
            )
        )
    for field in paired_fields:
        if standard.get(field) != halving.get(field):
            raise ComparisonError(f"grid manifests differ in {field}")
    if (
        "proof" not in standard["implementations"]
        or "proof" not in halving["implementations"]
    ):
        raise ComparisonError("both grids must contain the proof implementation")
    if standard.get("proof_search_strategy") != "standard_coverage":
        raise ComparisonError("first grid is not standard_coverage")
    if halving.get("proof_search_strategy") not in HALVING_STRATEGIES:
        raise ComparisonError("second grid is not a halving strategy")
    return standard, halving


def _check_cell_metadata(
    left: dict, right: dict, *, allow_bundled_variant: bool
) -> None:
    for field in (
        "implementation",
        "oracle",
        "bits",
        "nr_experiments",
        "master_seed",
        "message_generator",
        "key_policy",
        "key_pool_size",
        "key_file",
    ):
        if left.get(field) != right.get(field):
            raise ComparisonError(f"paired cell metadata differs in {field}")
    if left["algorithm_config"].get("search_strategy") != "standard_coverage":
        raise ComparisonError("standard cell metadata has the wrong strategy")
    if right["algorithm_config"].get("search_strategy") not in HALVING_STRATEGIES:
        raise ComparisonError("halving cell metadata has the wrong strategy")
    if not allow_bundled_variant:
        left_config = dict(left["algorithm_config"])
        right_config = dict(right["algorithm_config"])
        left_config.pop("search_strategy", None)
        right_config.pop("search_strategy", None)
        if left_config != right_config:
            raise ComparisonError(
                "paired cell algorithm settings differ beyond search strategy"
            )


def compare_grids(
    standard_dir: Path,
    halving_dir: Path,
    *,
    allow_bundled_variant: bool = False,
):
    standard_manifest, _halving_manifest = _check_grids(
        standard_dir,
        halving_dir,
        allow_bundled_variant=allow_bundled_variant,
    )
    summaries = []
    failures = []
    transitions = []
    for oracle in standard_manifest["oracles"]:
        for bits in standard_manifest["bits"]:
            cell = f"proof_{oracle}_{bits}"
            standard_cell = standard_dir / cell
            halving_cell = halving_dir / cell
            _check_cell_metadata(
                _read_json(standard_cell / "metadata.json"),
                _read_json(halving_cell / "metadata.json"),
                allow_bundled_variant=allow_bundled_variant,
            )
            summary, cell_failures, cell_transitions = summarize_pair(
                load_results(standard_cell),
                load_results(halving_cell),
                oracle,
                bits,
            )
            summaries.append(summary)
            failures.extend(cell_failures)
            transitions.extend(cell_transitions)
    return summaries, failures, transitions


def _write_csv(path: Path, fields, rows) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def _display(value) -> str:
    if value is None:
        return "infinity"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _print_summary(rows) -> None:
    print(
        "oracle bits  successes standard/halving  failure-aware median "
        "standard/halving  paired median query delta"
    )
    for row in rows:
        print(
            f"{row['oracle']:>3} {row['bits']:>4}  "
            f"{row['standard_successes']}/{row['halving_successes']}  "
            f"{_display(row['standard_failure_aware_median_queries'])}/"
            f"{_display(row['halving_failure_aware_median_queries'])}  "
            f"{_display(row['paired_both_success_upper_median_total_query_delta'])}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("standard_grid", type=Path)
    parser.add_argument("halving_grid", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument(
        "--allow-bundled-variant",
        action="store_true",
        help=(
            "compare complete named variants even when non-Searching proof "
            "settings differ"
        ),
    )
    args = parser.parse_args()
    try:
        summaries, failures, transitions = compare_grids(
            args.standard_grid.resolve(),
            args.halving_grid.resolve(),
            allow_bundled_variant=args.allow_bundled_variant,
        )
    except (OSError, KeyError, ValueError) as exc:
        parser.error(str(exc))
    _print_summary(summaries)
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        _write_csv(args.out_dir / "strategy_summary.csv", SUMMARY_FIELDS, summaries)
        _write_csv(args.out_dir / "strategy_failures.csv", FAILURE_FIELDS, failures)
        _write_csv(
            args.out_dir / "strategy_transitions.csv",
            TRANSITION_FIELDS,
            transitions,
        )
        print(f"wrote comparison tables to {args.out_dir.resolve()}")


if __name__ == "__main__":
    main()
