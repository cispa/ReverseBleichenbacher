#!/usr/bin/env python3
"""Summarize and plot Bottom-Up queries in a canonical proof simulation grid.

Distributions condition on entering Bottom-Up (at least one Bottom-Up query),
so attempts that stop in Trimmers or Search do not appear as zero-cost attacks.
The summary also reports successful attempts separately. Percentiles use the
nearest-rank convention, with the upper central value for the median.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import tempfile
from collections import Counter
from pathlib import Path


ORACLES = ("TTT", "TFT", "FFT")
BITS = (1024, 2048)
GROUPS = ("3-5", "6-12", ">=13", "all")
FIELDNAMES = (
    "oracle", "bits", "scope", "tau_found_group", "runs", "median", "p90",
    "p99", "p999", "maximum", "over_1500_runs", "over_1500_pct",
)


def tau_group(tau: int) -> str:
    if 3 <= tau <= 5:
        return "3-5"
    if 6 <= tau <= 12:
        return "6-12"
    if tau >= 13:
        return ">=13"
    raise ValueError(f"Bottom-Up entered with unexpected tau_found={tau}")


def percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    rank = len(ordered) // 2 if fraction == 0.5 else math.ceil(fraction * len(ordered)) - 1
    return ordered[rank]


def read_cell(grid: Path, oracle: str, bits: int) -> dict[str, dict[str, list[int]]]:
    values = {
        scope: {group: [] for group in GROUPS}
        for scope in ("entered", "succeeded")
    }
    cell = grid / f"proof_{oracle}_{bits}"
    metadata = json.loads((cell / "metadata.json").read_text())
    expected = {"implementation": "proof", "oracle": oracle,
                "bits": bits, "nr_experiments": 100000}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError(f"Unexpected cell metadata in {cell / 'metadata.json'}")
    configuration = metadata.get("algorithm_config", {})
    if (configuration.get("search_strategy") != "halving_sparse_asymmetric"
            or configuration.get("bottom_up_strategy") != "best_effort"):
        raise ValueError(f"Unexpected proof strategies in {cell / 'metadata.json'}")
    path = cell / "results.csv"
    row_count = 0
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            row_count += 1
            queries = int(row["bottom_up_queries"])
            if queries == 0:
                continue
            group = tau_group(int(row["tau_found"]))
            values["entered"][group].append(queries)
            values["entered"]["all"].append(queries)
            if row["outcome"] == "ok":
                values["succeeded"][group].append(queries)
                values["succeeded"]["all"].append(queries)
    if row_count != metadata["nr_experiments"]:
        raise ValueError(f"Expected {metadata['nr_experiments']} rows in {path}; found {row_count}")
    return values


def summarize(oracle: str, bits: int, values: dict[str, dict[str, list[int]]]):
    for scope in ("entered", "succeeded"):
        for group in GROUPS:
            queries = values[scope][group]
            if not queries:
                continue
            high = sum(value > 1500 for value in queries)
            yield {
                "oracle": oracle,
                "bits": bits,
                "scope": scope,
                "tau_found_group": group,
                "runs": len(queries),
                "median": percentile(queries, 0.5),
                "p90": percentile(queries, 0.9),
                "p99": percentile(queries, 0.99),
                "p999": percentile(queries, 0.999),
                "maximum": max(queries),
                "over_1500_runs": high,
                "over_1500_pct": f"{100 * high / len(queries):.4f}",
            }


def survival(values: list[int]) -> tuple[list[int], list[float]]:
    counts = Counter(values)
    remaining = len(values)
    xs, ys = [], []
    for value in sorted(counts):
        xs.append(value)
        ys.append(remaining / len(values))
        remaining -= counts[value]
    return xs, ys


def plot(distributions, output: Path) -> None:
    os.environ.setdefault(
        "MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "rb-bottom-up-mpl-cache")
    )
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"3-5": "#b44635", "6-12": "#bc8629", ">=13": "#24679e"}
    fig, axes = plt.subplots(3, 2, figsize=(10.8, 9.0), sharex=True, sharey=True)
    for row, oracle in enumerate(ORACLES):
        for col, bits in enumerate(BITS):
            ax = axes[row, col]
            values = distributions[(oracle, bits)]["entered"]
            for group in GROUPS[:-1]:
                if values[group]:
                    xs, ys = survival(values[group])
                    ax.plot(xs, ys, color=colors[group], linewidth=1.8,
                            label=rf"$\tau_{{found}}$ {group} (n={len(values[group]):,})")
            ax.axvline(1500, color="0.35", linestyle=":", linewidth=1)
            ax.set_title(f"{oracle}, {bits} bits")
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_xlim(200, 10000)
            ax.set_ylim(1e-5, 1.1)
            ax.grid(True, which="major", alpha=0.25)
            ax.legend(fontsize=7, loc="upper right", frameon=False)
    fig.supylabel("Fraction with at least this many queries", x=0.025)
    fig.supxlabel("Bottom-Up oracle queries", y=0.025)
    fig.suptitle("Bottom-Up query tails, conditional on entering Bottom-Up\n"
                 "Pinned optimized-proof 100k grid; dotted line = 1,500 queries",
                 y=0.975)
    fig.subplots_adjust(left=0.12, right=0.985, bottom=0.11, top=0.87,
                        hspace=0.30, wspace=0.08)
    fig.savefig(output)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grid", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    distributions = {
        (oracle, bits): read_cell(args.grid, oracle, bits)
        for oracle in ORACLES for bits in BITS
    }
    rows = [
        row for oracle in ORACLES for bits in BITS
        for row in summarize(oracle, bits, distributions[(oracle, bits)])
    ]
    stem = "bottom_up_query_distribution_proof-100k"
    csv_path = args.out_dir / f"{stem}.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    figure_path = args.out_dir / f"{stem}.pdf"
    plot(distributions, figure_path)
    print(f"Wrote {csv_path} and {figure_path}")


if __name__ == "__main__":
    main()
