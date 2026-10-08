"""Headerless RSA key pools and deterministic sampling with replacement."""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path


KEY_POLICY = "seeded-with-replacement-v1"
EXPECTED_POOL_SIZE = 1000


@dataclass(frozen=True)
class KeyRecord:
    row: int
    label: int
    n: int
    e: int
    d: int


def key_file(keys_dir: Path | str, bits: int) -> Path:
    return Path(keys_dir).resolve() / f"rsa-{bits}.csv"


def load_keys(
    keys_dir: Path | str, bits: int, *, expected_size: int = EXPECTED_POOL_SIZE
) -> tuple[KeyRecord, ...]:
    """Load all physical rows as data and reject headers or shifted pools."""
    path = key_file(keys_dir, bits)
    records = []
    with path.open(newline="", encoding="utf-8") as handle:
        for line_number, fields in enumerate(csv.reader(handle), start=1):
            if not fields or all(not field.strip() for field in fields):
                raise ValueError(f"{path}:{line_number}: blank key rows are not allowed")
            if len(fields) != 4:
                raise ValueError(
                    f"{path}:{line_number}: expected four columns (label,n,e,d)"
                )
            try:
                label, n, e, d = (int(field) for field in fields)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_number}: key files are headerless; all fields "
                    "must be integers"
                ) from exc
            row = line_number - 1
            if n.bit_length() != bits:
                raise ValueError(
                    f"{path}:{line_number}: modulus has {n.bit_length()} bits, "
                    f"expected {bits}"
                )
            records.append(KeyRecord(row, label, n, e, d))
    if len(records) != expected_size:
        raise ValueError(
            f"{path}: expected exactly {expected_size} keys, found {len(records)}"
        )
    return tuple(records)


def selected_key_index(master_seed: int, bits: int, run: int, pool_size: int) -> int:
    if run < 0 or pool_size < 1:
        raise ValueError("run must be nonnegative and key pool nonempty")
    rng = random.Random(
        f"bleichenbacher-key-selection-v1:{master_seed}:{bits}:{run}"
    )
    return rng.randrange(pool_size)


def select_key(
    pool: tuple[KeyRecord, ...], master_seed: int, bits: int, run: int
) -> KeyRecord:
    return pool[selected_key_index(master_seed, bits, run, len(pool))]
