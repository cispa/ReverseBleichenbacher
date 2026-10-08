"""One common sequential oracle used by every simulation backend."""

from __future__ import annotations

from collections import Counter


PHASES = ("trimmer", "search", "other", "bottom_up")


class CountingOracle:
    def __init__(self, plaintext: int, modulus: int, bits: int, oracle_type: str):
        if oracle_type not in {"TTT", "TFT", "FFT"}:
            raise ValueError(f"unsupported oracle type: {oracle_type}")
        self._plaintext = plaintext
        self._modulus = modulus
        self._key_bytes = bits // 8
        self._type = oracle_type
        self._phase = "other"
        self._counts = Counter({phase: 0 for phase in PHASES})
        self._search_had_ttt_positive = False

    def set_phase(self, phase: str) -> None:
        if phase not in PHASES:
            raise ValueError(f"unknown oracle phase: {phase}")
        self._phase = phase

    def __call__(self, multiplier: int) -> bool:
        self._counts[self._phase] += 1
        value = (self._plaintext * multiplier) % self._modulus
        B = 1 << (8 * (self._key_bytes - 2))
        if self._phase == "search" and 2 * B <= value < 3 * B:
            self._search_had_ttt_positive = True
        if not 2 * B <= value < 3 * B:
            return False
        if self._type == "TTT":
            return True
        encoded = value.to_bytes(self._key_bytes, "big")
        if any(byte == 0 for byte in encoded[2:10]):
            return False
        if self._type == "TFT":
            return True
        return 0 in encoded[10:]

    @property
    def counts(self) -> dict[str, int]:
        return {phase: self._counts[phase] for phase in PHASES}

    @property
    def total(self) -> int:
        return sum(self._counts.values())

    @property
    def search_had_ttt_positive(self) -> bool:
        """Offline diagnostic; attack code sees only Boolean query replies."""
        return self._search_had_ttt_positive
