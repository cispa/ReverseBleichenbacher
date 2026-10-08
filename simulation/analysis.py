"""Read-only views over the single canonical simulation result table."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from validate_run import failure_aware_median as canonical_failure_aware_median
from validate_run import read_results


SEARCH_COVERAGE_EXHAUSTED = "search_coverage_exhausted"
SEARCH_FALSE_NEGATIVE_EXHAUSTED = "search_false_negative_exhausted"


def classify_search_transcript(
    plaintext: int,
    modulus: int,
    B: int,
    multipliers: list[int],
) -> tuple[str, int, int | None]:
    """Classify a finished negative Search transcript using plaintext offline."""
    positive_indices = [
        index
        for index, multiplier in enumerate(multipliers, start=1)
        if 2 * B <= (plaintext * multiplier) % modulus < 3 * B
    ]
    if positive_indices:
        return (
            SEARCH_FALSE_NEGATIVE_EXHAUSTED,
            len(positive_indices),
            positive_indices[0],
        )
    return SEARCH_COVERAGE_EXHAUSTED, 0, None


def load_results(cell_dir: Path | str) -> list[dict[str, object]]:
    rows = read_results(cell_dir)
    integer_fields = {
        "run",
        "key_index",
        "correct",
        "tau_found",
        "tau_available",
        "trimmer_has_divisor",
        "trimmer_detectable",
        "total_queries",
        "trimmer_queries",
        "search_queries",
        "other_queries",
        "bottom_up_queries",
    }
    return [
        {
            field: (int(value) if field in integer_fields and value != "" else value)
            for field, value in row.items()
        }
        for row in rows
    ]


def success_rate(rows: list[dict[str, object]]) -> float:
    return sum(row["outcome"] == "ok" for row in rows) / len(rows)


def success_rate_under_budget(rows: list[dict[str, object]], budget: int) -> float:
    return sum(
        row["outcome"] == "ok" and row["total_queries"] <= budget for row in rows
    ) / len(rows)


def failure_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    return dict(
        sorted(
            Counter(
                row["outcome"] for row in rows if row["outcome"] != "ok"
            ).items()
        )
    )


def upper_median(values: list[int]) -> int | None:
    """Return the higher central observation, never an averaged query count."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def failure_aware_median(rows: list[dict[str, object]]) -> int | None:
    return canonical_failure_aware_median(rows, len(rows))
