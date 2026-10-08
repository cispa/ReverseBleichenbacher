#!/usr/bin/env python3
"""Run a canonical simulation grid."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from adapters import IMPLEMENTATIONS
from key_policy import KEY_POLICY, key_file, load_keys
from proof.bottom_up import BOTTOM_UP_STRATEGIES, DEFAULT_BOTTOM_UP_STRATEGY
from proof.search import DEFAULT_SEARCH_STRATEGY, SEARCH_STRATEGIES
from validate_run import validate_grid, validate_run


DEFAULT_IMPLEMENTATIONS = ("proof", "capol")
ORACLES = ("TTT", "TFT", "FFT")
KEY_SIZES = (1024, 2048)
DEFAULT_KEYS = REPO_ROOT / "simulation" / "keys"
DEFAULT_OUT = REPO_ROOT / "simulation" / "results"
DEFAULT_KEYS_RELATIVE = Path("simulation/keys")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _git(*arguments: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), *arguments],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _choices(raw: str, allowed, name: str, convert=str):
    values = [convert(part.strip()) for part in raw.split(",") if part.strip()]
    if not values or len(values) != len(set(values)):
        raise ValueError(f"{name} must be a nonempty list without duplicates")
    invalid = [value for value in values if value not in allowed]
    if invalid:
        raise ValueError(f"unsupported {name}: {invalid}")
    return values


def _run_id(value: str) -> str:
    if value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError("run ID may contain letters, digits, '.', '_' and '-'")
    return value


def _relative_to_repo(path: Path) -> str:
    """Record a path relative to the checkout, including paths outside it."""
    return os.path.relpath(path.resolve(), REPO_ROOT)


def _portable_executable() -> str:
    executable = Path(sys.executable).absolute()
    try:
        return str(executable.relative_to(REPO_ROOT))
    except ValueError:
        return executable.name


def _resume_keys_dir(manifest: dict) -> Path:
    recorded = Path(manifest["keys_dir"])
    if not recorded.is_absolute():
        return (REPO_ROOT / recorded).resolve()
    if recorded.is_dir():
        return recorded.resolve()
    # Grids written before portable paths stored the creator's absolute path.
    # The checked-in key pool can be found in another checkout by its suffix.
    if recorded.parts[-len(DEFAULT_KEYS_RELATIVE.parts):] == DEFAULT_KEYS_RELATIVE.parts:
        return DEFAULT_KEYS
    raise ValueError(
        f"recorded key directory is unavailable: {recorded}; "
        "resume requires the same key pool"
    )


def _check_dependencies(implementations) -> None:
    required = {"Crypto"}
    if "capol" in implementations:
        required.update({"numpy", "pandas"})
    missing = sorted(
        name for name in required if importlib.util.find_spec(name) is None
    )
    if missing:
        raise ValueError(
            "missing simulation dependencies: "
            + ", ".join(missing)
            + "; install simulation/requirements.txt"
        )


def _cell_command(manifest: dict, output: Path, cell: dict, keys_dir: Path) -> list[str]:
    command = [
        sys.executable,
        _relative_to_repo(HERE / "run_simulation.py"),
        cell["implementation"],
        str(manifest["experiments_per_cell"]),
        cell["oracle"],
        str(cell["bits"]),
        "--master-seed",
        str(manifest["master_seed"]),
        "--processes",
        str(manifest["processes"]),
        "--keys-dir",
        _relative_to_repo(keys_dir),
        "--out",
        _relative_to_repo(output),
        "--name",
        cell["name"],
    ]
    if cell["implementation"] == "proof":
        command.extend(
            [
                "--proof-search-strategy",
                manifest["proof_search_strategy"],
                "--proof-bottom-up-strategy",
                manifest["proof_bottom_up_strategy"],
                "--proof-bottom-up-r-limit",
                str(manifest["proof_bottom_up_r_limit"]),
            ]
        )
        if manifest["proof_search_slack"] is not None:
            command.extend(
                ["--proof-search-slack", str(manifest["proof_search_slack"])]
            )
    return command


def _validate_cell_identity(cell_dir: Path, manifest: dict, cell: dict) -> None:
    metadata = json.loads((cell_dir / "metadata.json").read_text(encoding="utf-8"))
    expected = {
        "implementation": cell["implementation"],
        "oracle": cell["oracle"],
        "bits": cell["bits"],
        "nr_experiments": manifest["experiments_per_cell"],
        "master_seed": manifest["master_seed"],
        "key_policy": manifest["key_policy"],
    }
    for name, value in expected.items():
        if metadata.get(name) != value:
            raise ValueError(f"{cell['name']}: metadata {name} differs from manifest")
    recorded_key_file = Path(metadata.get("key_file", ""))
    key_name = f"rsa-{cell['bits']}.csv"
    expected_key_files = {
        Path(manifest["keys_dir"]) / key_name,
        Path(_relative_to_repo(_resume_keys_dir(manifest))) / key_name,
    }
    if recorded_key_file not in expected_key_files:
        raise ValueError(f"{cell['name']}: metadata key_file differs from manifest")


def _portable_report(report: dict, cell_name: str) -> dict:
    if Path(report["cell"]).name != cell_name:
        raise ValueError(f"{cell_name}: validation report names another cell")
    return {**report, "cell": cell_name}


def _validated_cell(cell_dir: Path, manifest: dict, cell: dict) -> tuple[dict, str]:
    _validate_cell_identity(cell_dir, manifest, cell)
    report = _portable_report(
        validate_run(cell_dir, require_publication_ready=True), cell["name"]
    )
    digest = hashlib.sha256((cell_dir / "results.csv").read_bytes()).hexdigest()
    return report, digest


def _execute_cell(
    manifest: dict, manifest_path: Path, output: Path, cell: dict, keys_dir: Path
) -> None:
    command = _cell_command(manifest, output, cell, keys_dir)
    cell.update(status="running", command=[_portable_executable(), *command[1:]],
                started_at=_now())
    _write_json(manifest_path, manifest)
    print(f"# running {cell['name']}", flush=True)
    completed = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True)
    cell_dir = output / cell["name"]
    if cell_dir.is_dir():
        (cell_dir / "run.log").write_text(
            completed.stdout + completed.stderr, encoding="utf-8"
        )
    cell.update(returncode=completed.returncode, finished_at=_now())
    if completed.returncode:
        raise RuntimeError(
            f"{cell['name']} exited with status {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    report, digest = _validated_cell(cell_dir, manifest, cell)
    cell.update(status="complete", validation=report, results_sha256=digest)
    _write_json(manifest_path, manifest)


def resume_grid(output: Path, run_id: str, *, dry_run: bool = False) -> list[str]:
    """Validate a grid and finish only cells absent from its manifest."""
    output = output.resolve() / _run_id(run_id)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("run_id") != run_id:
        raise ValueError("resume manifest has a different schema or run ID")
    if manifest.get("key_policy") != KEY_POLICY:
        raise ValueError("resume manifest has a different key policy")
    implementations = manifest["implementations"]
    oracles = manifest["oracles"]
    bits = manifest["bits"]
    if (
        not implementations or set(implementations) - set(IMPLEMENTATIONS)
        or not oracles or set(oracles) - set(ORACLES)
        or not bits or set(bits) - set(KEY_SIZES)
        or int(manifest["experiments_per_cell"]) < 1
        or int(manifest["processes"]) < 1
    ):
        raise ValueError("resume manifest has invalid grid settings")
    expected_cells = [
        (implementation, oracle, key_bits, f"{implementation}_{oracle}_{key_bits}")
        for implementation in implementations for oracle in oracles for key_bits in bits
    ]
    actual_cells = [
        (cell["implementation"], cell["oracle"], cell["bits"], cell["name"])
        for cell in manifest["cells"]
    ]
    if actual_cells != expected_cells:
        raise ValueError("resume manifest cell list differs from grid settings")
    keys_dir = _resume_keys_dir(manifest)
    for key_bits in bits:
        load_keys(keys_dir, key_bits)
        expected_hash = manifest.get("key_files_sha256", {}).get(str(key_bits))
        if expected_hash is not None:
            actual_hash = hashlib.sha256(key_file(keys_dir, key_bits).read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise ValueError(f"rsa-{key_bits}.csv differs from the original key pool")
    _check_dependencies(implementations)

    incomplete = []
    recoverable = []
    for cell in manifest["cells"]:
        cell_dir = output / cell["name"]
        if cell["status"] == "complete":
            report, digest = _validated_cell(cell_dir, manifest, cell)
            saved = cell.get("validation")
            if (digest != cell.get("results_sha256")
                    or not isinstance(saved, dict)
                    or report != _portable_report(saved, cell["name"])):
                raise ValueError(f"{cell['name']}: completed cell differs from manifest")
            continue
        if cell["status"] not in {"pending", "running", "failed"}:
            raise ValueError(f"{cell['name']}: invalid status {cell['status']!r}")
        incomplete.append(cell)
        if cell_dir.exists():
            if not cell_dir.is_dir() or cell_dir.is_symlink():
                raise ValueError(f"{cell['name']}: unexpected cell path {cell_dir}")
            contents = list(cell_dir.iterdir())
            if (cell_dir / "results.csv").is_file() and (cell_dir / "metadata.json").is_file():
                _validated_cell(cell_dir, manifest, cell)
                recoverable.append(cell["name"])
            elif contents:
                raise ValueError(
                    f"{cell['name']}: incomplete directory is not empty; "
                    "inspect it before resuming"
                )

    names = [cell["name"] for cell in incomplete]
    for cell in incomplete:
        action = "recover" if cell["name"] in recoverable else "run"
        print(f"# {action} {cell['name']}", flush=True)
    if dry_run:
        return names
    if not incomplete and manifest["status"] == "complete":
        validate_grid(output, require_publication_ready=True)
        print(f"# simulation grid already complete: {output}", flush=True)
        return []

    manifest.setdefault("resume_history", []).append(
        {
            "started_at": _now(),
            "source_git_commit": _git("rev-parse", "HEAD"),
            "source_git_dirty": bool(_git("status", "--porcelain", "--untracked-files=no")),
            "incomplete_cells": names,
        }
    )
    manifest["status"] = "running"
    manifest.pop("finished_at", None)
    manifest.pop("error", None)
    _write_json(manifest_path, manifest)
    try:
        for cell in incomplete:
            cell_dir = output / cell["name"]
            if cell["name"] in recoverable:
                report, digest = _validated_cell(cell_dir, manifest, cell)
                metadata = json.loads((cell_dir / "metadata.json").read_text())
                cell.update(
                    status="complete", returncode=0,
                    finished_at=metadata["finished_at"],
                    validation=report, results_sha256=digest,
                )
                _write_json(manifest_path, manifest)
                continue
            if cell_dir.is_dir():
                cell_dir.rmdir()  # Only an empty interrupted directory reaches here.
            if cell.get("started_at"):
                cell.setdefault("interrupted_attempts", []).append(
                    {"started_at": cell["started_at"], "status": cell["status"]}
                )
            _execute_cell(manifest, manifest_path, output, cell, keys_dir)
        manifest.update(status="complete", finished_at=_now())
        _write_json(manifest_path, manifest)
        validate_grid(output, require_publication_ready=True)
    except Exception as exc:
        for cell in manifest["cells"]:
            if cell["status"] == "running":
                cell["status"] = "failed"
        manifest.update(status="failed", finished_at=_now(), error=str(exc))
        _write_json(manifest_path, manifest)
        raise
    print(f"# simulation grid complete: {output}", flush=True)
    return names


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--implementations", default=",".join(DEFAULT_IMPLEMENTATIONS)
    )
    parser.add_argument("--oracles", default=",".join(ORACLES))
    parser.add_argument("--bits", default="1024,2048")
    parser.add_argument("--experiments", "-n", type=int, default=100000)
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
    parser.add_argument("--master-seed", type=int, default=20250930)
    parser.add_argument("--keys-dir", type=Path, default=DEFAULT_KEYS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--run-id")
    parser.add_argument("--resume", metavar="RUN_ID")
    parser.add_argument("--dry-run", action="store_true", help="plan a resume without changing files")
    args = parser.parse_args()
    if args.resume:
        if args.run_id:
            parser.error("--resume and --run-id cannot be combined")
        try:
            resume_grid(args.out, args.resume, dry_run=args.dry_run)
        except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
            parser.exit(1, f"resume failed: {exc}\n")
        return
    if args.dry_run:
        parser.error("--dry-run requires --resume")
    if (
        args.experiments < 1
        or args.processes < 1
        or args.proof_bottom_up_r_limit < 1
        or (args.proof_search_slack is not None and args.proof_search_slack < 0)
    ):
        parser.error(
            "experiments, processes, and Bottom-Up r limit must be positive; "
            "search slack cannot be negative"
        )
    try:
        implementations = _choices(
            args.implementations, IMPLEMENTATIONS, "implementation"
        )
        oracles = _choices(args.oracles, ORACLES, "oracle")
        bits = _choices(args.bits, KEY_SIZES, "key size", int)
        for key_bits in bits:
            load_keys(args.keys_dir, key_bits)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    try:
        _check_dependencies(implementations)
    except ValueError as exc:
        parser.error(str(exc))

    run_id = args.run_id or datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
    try:
        _run_id(run_id)
    except ValueError as exc:
        parser.error(str(exc))
    output = args.out.resolve() / run_id
    if output.exists():
        parser.error(f"refusing to overwrite existing grid: {output}")
    output.mkdir(parents=True)

    cells = [
        {
            "implementation": implementation,
            "oracle": oracle,
            "bits": key_bits,
            "name": f"{implementation}_{oracle}_{key_bits}",
            "status": "pending",
        }
        for implementation in implementations
        for oracle in oracles
        for key_bits in bits
    ]
    manifest = {
        "schema_version": 1,
        "status": "running",
        "run_id": run_id,
        "created_at": _now(),
        "master_seed": args.master_seed,
        "key_policy": KEY_POLICY,
        "key_files_sha256": {
            str(key_bits): hashlib.sha256(
                key_file(args.keys_dir, key_bits).read_bytes()
            ).hexdigest()
            for key_bits in bits
        },
        "implementations": implementations,
        "oracles": oracles,
        "bits": bits,
        "experiments_per_cell": args.experiments,
        "processes": args.processes,
        "proof_search_strategy": args.proof_search_strategy,
        "proof_search_slack": args.proof_search_slack,
        "proof_bottom_up_strategy": args.proof_bottom_up_strategy,
        "proof_bottom_up_r_limit": args.proof_bottom_up_r_limit,
        "keys_dir": _relative_to_repo(args.keys_dir),
        "source": {
            "git_commit": _git("rev-parse", "HEAD"),
            # A committed implementation remains reproducible even when the
            # workspace contains unrelated ignored/untracked experiment data.
            "git_dirty": bool(
                _git("status", "--porcelain", "--untracked-files=no")
            ),
            "git_untracked_files_present": bool(
                _git("ls-files", "--others", "--exclude-standard")
            ),
            "python": sys.version,
            "executable": _portable_executable(),
        },
        "cells": cells,
    }
    manifest_path = output / "manifest.json"
    _write_json(manifest_path, manifest)

    try:
        for cell in cells:
            _execute_cell(manifest, manifest_path, output, cell, args.keys_dir.resolve())
    except Exception as exc:
        for cell in cells:
            if cell["status"] == "running":
                cell["status"] = "failed"
        manifest.update(status="failed", finished_at=_now(), error=str(exc))
        _write_json(manifest_path, manifest)
        parser.exit(1, f"simulations failed: {exc}\npartial grid: {output}\n")

    manifest.update(status="complete", finished_at=_now())
    _write_json(manifest_path, manifest)
    print(f"# simulation grid complete: {output}")


if __name__ == "__main__":
    main()
