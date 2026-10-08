#!/usr/bin/env python3
"""Validate a canonical simulation cell or complete grid without changing it."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from schema import OUTCOMES, QUERY_COLUMNS, RESULT_COLUMNS, SCHEMA_VERSION, STEPS
from reporting import reported_outcome
from trials import MESSAGE_GENERATOR, generate_message


BLOCKERS = {"wrong_result", "internal_error"}


class ValidationError(ValueError):
    pass


def failure_aware_median(
    rows: list[Mapping[str, object]], attempts: int
) -> int | None:
    """Return the upper observed median after ranking failures at infinity."""
    successes = sorted(
        int(row["total_queries"]) for row in rows if row["outcome"] == "ok"
    )
    padded = successes + [math.inf] * (attempts - len(successes))
    value = padded[attempts // 2]
    return None if math.isinf(value) else value


def _integer(row, field, where, *, optional=False):
    value = row.get(field, "")
    if optional and value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where}: {field} must be an integer") from exc


def read_results(cell_dir: Path | str) -> list[dict[str, str]]:
    path = Path(cell_dir) / "results.csv"
    if not path.is_file():
        raise ValidationError(f"missing results.csv: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != RESULT_COLUMNS:
            raise ValidationError(
                "results.csv does not have the exact canonical schema"
            )
        return list(reader)


def validate_run(cell_dir: Path | str, *, require_publication_ready=False):
    cell_dir = Path(cell_dir)
    metadata_path = cell_dir / "metadata.json"
    if not metadata_path.is_file():
        raise ValidationError(f"missing metadata.json: {metadata_path}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError("unsupported schema version")
    if metadata.get("key_policy") != "seeded-with-replacement-v1":
        raise ValidationError("wrong key selection policy")
    if int(metadata.get("key_pool_size", 0)) != 1000:
        raise ValidationError("metadata must record a 1,000-key pool")
    attempts = int(metadata["nr_experiments"])
    rows = read_results(cell_dir)
    if len(rows) != attempts:
        raise ValidationError(f"results.csv has {len(rows)} rows; expected {attempts}")

    counts = Counter()
    blockers = Counter()
    for index, row in enumerate(rows):
        where = f"results.csv row {index + 2}"
        if _integer(row, "run", where) != index:
            raise ValidationError(f"{where}: run must equal {index}")
        key_index = _integer(row, "key_index", where)
        if not 0 <= key_index < 1000:
            raise ValidationError(f"{where}: key_index is outside 0..999")
        outcome, step = row["outcome"], row["step"]
        if outcome not in OUTCOMES or step not in STEPS:
            raise ValidationError(f"{where}: unknown outcome or step")
        if outcome == "search_false_negative_exhausted" and metadata["oracle"] == "TTT":
            raise ValidationError(f"{where}: a TTT oracle cannot reject a conforming query")
        if outcome in {
            "search_coverage_exhausted", "search_false_negative_exhausted"
        } and metadata["implementation"] != "proof":
            raise ValidationError(f"{where}: causal Search outcomes require proof backend")
        correct = _integer(row, "correct", where)
        if correct not in (0, 1) or correct != int(outcome == "ok"):
            raise ValidationError(f"{where}: correct must be 1 exactly for ok")
        if outcome == "ok" and (row["error_type"] or row["error_message"]):
            raise ValidationError(f"{where}: success rows cannot contain errors")

        query_values = [
            _integer(row, field, where, optional=True) for field in QUERY_COLUMNS
        ]
        total = _integer(row, "total_queries", where, optional=True)
        if total is None or any(value is None for value in query_values):
            if outcome != "internal_error" or not all(
                value is None for value in [total, *query_values]
            ):
                raise ValidationError(f"{where}: partial query counts are invalid")
        elif total < 0 or any(value < 0 for value in query_values):
            raise ValidationError(f"{where}: query counts cannot be negative")
        elif total != sum(query_values):
            raise ValidationError(f"{where}: phase queries do not sum to total")

        has_divisor = _integer(row, "trimmer_has_divisor", where, optional=True)
        detectable = _integer(row, "trimmer_detectable", where, optional=True)
        if has_divisor not in (None, 0, 1) or detectable not in (None, 0, 1):
            raise ValidationError(f"{where}: invalid trimmer diagnostic boolean")
        expected = {
            "trimmer_no_divisor": (0, None),
            "trimmer_no_multiplier": (1, 0),
            "trimmer_false_negative": (1, 1),
        }
        if outcome in expected and (has_divisor, detectable) != expected[outcome]:
            raise ValidationError(f"{where}: trimmer outcome contradicts diagnostics")
        if outcome in expected and query_values[1:] != [0, 0, 0]:
            raise ValidationError(f"{where}: trimmer failure has later queries")
        if outcome in {
            "search_failed", "search_coverage_exhausted",
            "search_false_negative_exhausted",
        } and query_values[2:] != [0, 0]:
            raise ValidationError(f"{where}: search failure has later queries")
        if outcome == "trimmer_missed_power_of_two" and step not in {
            "search", "bottom_up"
        }:
            raise ValidationError(
                f"{where}: missed power of two must retain its later abort step"
            )
        if (
            outcome == "trimmer_missed_power_of_two"
            and step == "search"
            and query_values[2:] != [0, 0]
        ):
            raise ValidationError(f"{where}: search failure has later queries")
        if outcome == "other_failed" and query_values[3] != 0:
            raise ValidationError(f"{where}: other failure has bottom-up queries")

        tau_found = _integer(row, "tau_found", where, optional=True)
        reported = outcome
        if (
            metadata.get("implementation") == "proof"
            and outcome in {
                "search_failed", "search_coverage_exhausted",
                "search_false_negative_exhausted", "bottom_up_failed",
            }
            and metadata.get("message_generator") == MESSAGE_GENERATOR
        ):
            encoded, _suffix = generate_message(
                int(metadata["master_seed"]), int(metadata["bits"]), index
            )
            reported = reported_outcome(
                metadata["implementation"],
                outcome,
                int.from_bytes(encoded, "big"),
                tau_found,
            )
        counts[reported] += 1
        if outcome in BLOCKERS:
            blockers[outcome] += 1
        if (
            reported == "search_coverage_exhausted"
            and metadata.get("oracle") == "TTT"
            and metadata.get("algorithm_config", {}).get("search_full_grid_fallback")
            and tau_found is not None
            and tau_found >= 13
        ):
            blockers["ttt_coverage_after_full_grid"] += 1

    publication_ready = not blockers
    if require_publication_ready and not publication_ready:
        detail = ", ".join(f"{name}={count}" for name, count in blockers.items())
        raise ValidationError(f"publication gate failed: {detail}")
    return {
        "cell": str(cell_dir.resolve()),
        "experiments": attempts,
        "outcomes": dict(sorted(counts.items())),
        "failure_aware_upper_median": failure_aware_median(rows, attempts),
        "publication_ready": publication_ready,
        "publication_blockers": dict(sorted(blockers.items())),
    }


def validate_grid(grid_dir: Path | str, *, require_publication_ready=False):
    grid_dir = Path(grid_dir)
    manifest = json.loads((grid_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "complete":
        raise ValidationError("grid manifest is not complete")
    reports = []
    paired_keys = {}
    for cell in manifest["cells"]:
        if cell.get("status") != "complete":
            raise ValidationError(f"{cell['name']}: manifest cell is not complete")
        cell_dir = grid_dir / cell["name"]
        reports.append(
            validate_run(
                cell_dir, require_publication_ready=require_publication_ready
            )
        )
        metadata = json.loads((cell_dir / "metadata.json").read_text())
        if metadata["master_seed"] != manifest["master_seed"]:
            raise ValidationError(f"{cell['name']}: master seed differs from grid")
        for row in read_results(cell_dir):
            identity = (cell["bits"], int(row["run"]))
            key_index = int(row["key_index"])
            if identity in paired_keys and paired_keys[identity] != key_index:
                raise ValidationError(f"{cell['name']}: paired key selection differs")
            paired_keys[identity] = key_index
        digest = hashlib.sha256((cell_dir / "results.csv").read_bytes()).hexdigest()
        if digest != cell.get("results_sha256"):
            raise ValidationError(f"{cell['name']}: results checksum differs")
    return {"grid": str(grid_dir.resolve()), "cells": reports}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--publication-ready", action="store_true")
    args = parser.parse_args()
    try:
        if (args.path / "manifest.json").is_file():
            report = validate_grid(
                args.path, require_publication_ready=args.publication_ready
            )
        else:
            report = validate_run(
                args.path, require_publication_ready=args.publication_ready
            )
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f"validation failed: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
