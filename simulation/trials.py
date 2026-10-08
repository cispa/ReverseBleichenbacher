"""Deterministic messages and paired simulation trials."""

from __future__ import annotations

import random
from dataclasses import dataclass

from key_policy import KeyRecord, select_key


MESSAGE_GENERATOR = "bleichenbacher-simulation-v1"


@dataclass(frozen=True)
class Trial:
    run: int
    key_index: int
    key: KeyRecord
    encoded_message: bytes
    plaintext: int
    target_suffix: bytes


def generate_message(master_seed: int, bits: int, run: int) -> tuple[bytes, bytes]:
    """Return a TLS PKCS#1 v1.5 encoding and its 46-byte random suffix."""
    if bits % 8 or bits // 8 < 59:
        raise ValueError("RSA size must be a whole number of bytes and fit TLS PMS")
    rng = random.Random(f"{MESSAGE_GENERATOR}:{master_seed}:{bits}:{run}")
    suffix = bytes(rng.randrange(256) for _ in range(46))
    padding_length = bits // 8 - 3 - 48
    padding = bytearray()
    while len(padding) < padding_length:
        byte = rng.randrange(256)
        if byte:
            padding.append(byte)
    encoded = b"\x00\x02" + bytes(padding) + b"\x00\x03\x03" + suffix
    return encoded, suffix


def make_trial(
    key_pool: tuple[KeyRecord, ...], master_seed: int, bits: int, run: int
) -> Trial:
    key = select_key(key_pool, master_seed, bits, run)
    encoded, suffix = generate_message(master_seed, bits, run)
    return Trial(run, key.row, key, encoded, int.from_bytes(encoded, "big"), suffix)
