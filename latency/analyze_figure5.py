#!/usr/bin/env python3
"""Generate conditional and failure-aware Figure 5 runtime summaries.

The conditional CSV describes successful attacks only. The failure-aware CSV
excludes measurement-infrastructure errors and assigns positive infinity to
every other attempt that did not recover the target. It also records post-exclusion
success percentages, both overall and within the browser timeout; Figure 5's
lower panel uses the latter.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path

BROWSER_TIMEOUT_SECONDS = 30
PARALLEL_BATCHED_MAX_RTT_MS = 100
PARALLEL_SEQUENTIAL_MAX_RTT_MS = 30


MODES = ("normal", "parallel")
MAX_RTT_MS = {
    "normal": PARALLEL_SEQUENTIAL_MAX_RTT_MS,
    "parallel": PARALLEL_BATCHED_MAX_RTT_MS,
}
EXPECTED_ATTEMPTS = 100
INFINITY_PLOT_Y = 90.0
INFRASTRUCTURE_ERROR_MARKERS = (
    "Cannot assign requested address",
    "Too many open files",
    "Address already in use",
    "Cannot allocate memory",
    "Resource temporarily unavailable",
)

LATENCY_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = LATENCY_ROOT / "evaluation" / "results_runtime"
DEFAULT_OUTPUT = LATENCY_ROOT / "analysis" / "parallel_times_summary.csv"
DEFAULT_INFINITY_OUTPUT = LATENCY_ROOT / "analysis" / "parallel_times_infinity_summary.csv"


def parse_result_path(path: Path) -> tuple[str, float]:
    try:
        mode, raw_delay = path.stem.split("_", 1)
        delay_ms = float(raw_delay)
    except ValueError as error:
        raise ValueError(f"unexpected Figure 5 filename: {path.name}") from error

    if mode not in MODES:
        raise ValueError(f"unexpected Figure 5 mode in {path.name}: {mode}")
    return mode, delay_ms


def successful_measurements(
    path: Path,
) -> tuple[int, list[float]]:
    with path.open(encoding="utf-8") as handle:
        records = json.load(handle)

    if not isinstance(records, list):
        raise ValueError(f"{path}: expected a JSON list")
    if len(records) != EXPECTED_ATTEMPTS:
        raise ValueError(
            f"{path}: expected {EXPECTED_ATTEMPTS} attempts, found {len(records)}"
        )

    runtimes = []
    for index, record in enumerate(records):
        if not record.get("success"):
            continue

        stats = record.get("stats")
        if not isinstance(stats, dict):
            raise ValueError(f"{path}: successful attempt {index} has no statistics")

        runtime = float(stats["runtime"])
        if not math.isfinite(runtime) or runtime < 0:
            raise ValueError(f"{path}: invalid runtime for attempt {index}: {runtime}")

        runtimes.append(runtime)

    return len(records), runtimes


def failure_aware_measurements(
    path: Path,
) -> tuple[int, int, int, list[float]]:
    with path.open(encoding="utf-8") as handle:
        records = json.load(handle)

    if not isinstance(records, list):
        raise ValueError(f"{path}: expected a JSON list")
    if len(records) != EXPECTED_ATTEMPTS:
        raise ValueError(
            f"{path}: expected {EXPECTED_ATTEMPTS} attempts, found {len(records)}"
        )

    successful = 0
    infrastructure_errors = 0
    values = []
    for index, record in enumerate(records):
        stats = record.get("stats")
        if record.get("success"):
            if not isinstance(stats, dict):
                raise ValueError(
                    f"{path}: successful attempt {index} has no statistics"
                )
            runtime = float(stats["runtime"])
            if not math.isfinite(runtime) or runtime < 0:
                raise ValueError(
                    f"{path}: invalid runtime for attempt {index}: {runtime}"
                )
            successful += 1
            values.append(runtime)
            continue

        # The measurement harness did not clear results.json between attempts.
        # An exact repeat therefore denotes stale output from a timed-out run,
        # even when the repeated error text looks like an infrastructure error.
        stale_stats = (
            index > 0
            and stats is not None
            and stats == records[index - 1].get("stats")
        )
        error = stats.get("error", "") if isinstance(stats, dict) else ""
        infrastructure_error = not stale_stats and any(
            marker in str(error) for marker in INFRASTRUCTURE_ERROR_MARKERS
        )
        if infrastructure_error:
            infrastructure_errors += 1
            continue

        # Algorithm failures and attacks that hit the measurement timeout both
        # have infinite time to successful recovery in the failure-aware view.
        values.append(math.inf)

    return len(records), successful, infrastructure_errors, values


def quartiles(values: list[float]) -> tuple[float, float, float]:
    if not values:
        return math.nan, math.nan, math.nan
    median = statistics.median(values)
    if len(values) == 1:
        return median, median, median
    q1, _, q3 = statistics.quantiles(values, n=4, method="exclusive")
    return q1, median, q3


def extended_quantile(values: list[float], probability: float) -> float:
    """Exclusive sample quantile over finite values and positive infinity."""
    if not values:
        return math.nan

    ordered = sorted(values)
    position = probability * (len(ordered) + 1) - 1
    if position <= 0:
        return ordered[0]
    if position >= len(ordered) - 1:
        return ordered[-1]

    lower_index = math.floor(position)
    fraction = position - lower_index
    lower = ordered[lower_index]
    upper = ordered[lower_index + 1]
    if fraction == 0 or lower == upper:
        return lower
    if math.isinf(upper):
        return math.inf
    return lower + fraction * (upper - lower)


def summarize(path: Path) -> dict[str, float | int]:
    attempted, runtimes = successful_measurements(path)
    q1, median, q3 = quartiles(runtimes)
    return {
        "attempted": attempted,
        "successful": len(runtimes),
        "median_s": median,
        "q1_s": q1,
        "q3_s": q3,
    }


def summarize_failure_aware(path: Path) -> dict[str, float | int | None]:
    attempted, successful, infrastructure_errors, values = (
        failure_aware_measurements(path)
    )
    q1 = extended_quantile(values, 0.25)
    median = extended_quantile(values, 0.5)
    q3 = extended_quantile(values, 0.75)

    under_timeout = sum(1 for value in values if value <= BROWSER_TIMEOUT_SECONDS)
    median_is_infinite = math.isinf(median)
    q3_is_infinite = math.isinf(q3)
    return {
        "attempted": attempted,
        "included": len(values),
        "successful": successful,
        "noncompletion": len(values) - successful,
        "infrastructure_excluded": infrastructure_errors,
        "success_pct": (
            100.0 * successful / len(values) if values else math.nan
        ),
        "under_timeout_pct": (
            100.0 * under_timeout / len(values) if values else math.nan
        ),
        "median_s": median,
        "q1_s": q1,
        "q3_s": q3,
        "finite_median_plot_s": None if median_is_infinite else median,
        "infinite_median_plot_s": INFINITY_PLOT_Y if median_is_infinite else None,
        "q1_plot_s": INFINITY_PLOT_Y if math.isinf(q1) else q1,
        "q3_plot_s": INFINITY_PLOT_Y if q3_is_infinite else q3,
        "infinite_q3_plot_s": (
            INFINITY_PLOT_Y if q3_is_infinite and not median_is_infinite else None
        ),
    }


def generated_rows(
    input_dir: Path,
    summarizer,
    summary_fields: tuple[str, ...],
) -> list[dict[str, float | int | None]]:
    summaries: dict[tuple[float, str], dict[str, float | int | None]] = {}
    for path in sorted(input_dir.glob("*.json")):
        mode, delay_ms = parse_result_path(path)
        if delay_ms <= 0 or delay_ms > MAX_RTT_MS[mode]:
            continue
        key = (delay_ms, mode)
        if key in summaries:
            raise ValueError(f"duplicate Figure 5 input for {mode} at {delay_ms} ms")
        summaries[key] = summarizer(path)

    if not summaries:
        raise ValueError(f"no Figure 5 JSON files found in {input_dir}")

    rows = []
    for delay_ms in sorted({delay for delay, _ in summaries}):
        row: dict[str, float | int | None] = {"delay_ms": delay_ms}
        for mode in MODES:
            summary = summaries.get((delay_ms, mode))
            for field in summary_fields:
                row[f"{mode}_{field}"] = summary[field] if summary else None
        rows.append(row)
    return rows


def csv_value(value: float | int | None) -> float | int | str:
    return "nan" if value is None else value


def write_csv(
    path: Path,
    rows: list[dict[str, float | int | None]],
    summary_fields: tuple[str, ...],
) -> None:
    fieldnames = ["delay_ms"]
    for mode in MODES:
        fieldnames.extend(f"{mode}_{field}" for field in summary_fields)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(
            {key: csv_value(value) for key, value in row.items()} for row in rows
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--infinity-output", type=Path, default=DEFAULT_INFINITY_OUTPUT
    )
    args = parser.parse_args()

    successful_fields = (
        "median_s",
        "q1_s",
        "q3_s",
        "attempted",
        "successful",
    )
    infinity_fields = (
        "median_s",
        "q1_s",
        "q3_s",
        "finite_median_plot_s",
        "infinite_median_plot_s",
        "q1_plot_s",
        "q3_plot_s",
        "infinite_q3_plot_s",
        "attempted",
        "included",
        "successful",
        "noncompletion",
        "infrastructure_excluded",
        "success_pct",
        "under_timeout_pct",
    )
    write_csv(
        args.output,
        generated_rows(args.input_dir, summarize, successful_fields),
        successful_fields,
    )
    write_csv(
        args.infinity_output,
        generated_rows(
            args.input_dir, summarize_failure_aware, infinity_fields
        ),
        infinity_fields,
    )


if __name__ == "__main__":
    main()
