"""Core types and integer arithmetic for the proof implementation."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_TARGET_BITS = 8 * 46


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


class BleichenBacherException(Exception):
    """Expected failure of one of the attack phases."""


class PKCS1Bounds:
    @staticmethod
    def compute_B(key_bytes: int) -> int:
        return 1 << (8 * (key_bytes - 2))

    @staticmethod
    def initial_interval(B: int) -> tuple[int, int]:
        return 2 * B, 3 * B - 1

    @staticmethod
    def lower_bound(B: int) -> int:
        return 2 * B

    @staticmethod
    def upper_bound(B: int) -> int:
        return 3 * B - 1


@dataclass
class AttackConfig:
    oracle_type: str
    keylength: int
    trimmer_cutoff: int = 50
    t_slack: int = 0
    bs_slack: int = 0

    @classmethod
    def optimized(cls, oracle_type: str, keylength: int) -> "AttackConfig":
        if oracle_type not in {"TTT", "TFT", "FFT"}:
            raise ValueError(f"unknown oracle type: {oracle_type}")
        config = cls(oracle_type=oracle_type, keylength=keylength)
        if oracle_type == "FFT":
            if keylength == 512:
                config.t_slack, config.bs_slack = 10, 21
            elif keylength == 1024:
                config.t_slack, config.bs_slack = 4, 9
            elif keylength == 2048:
                config.t_slack, config.bs_slack = 1, 3
        return config


@dataclass
class AttackState:
    a: int
    b: int
    n: int
    B: int

    @property
    def interval_size(self) -> int:
        return self.b - self.a + 1

    def update_interval(self, new_a: int, new_b: int) -> None:
        if new_a > new_b:
            raise ValueError(f"invalid interval: {new_a} > {new_b}")
        self.a = new_a
        self.b = new_b


@dataclass
class AttackStatistics:
    calls_trimmers: int = 0
    calls_improved_step2a: int = 0
    calls_bottom_up: int = 0
    trim_value: float = 1.0
    low: tuple[int, int] | int = 1
    high: tuple[int, int] | int = 1

    @property
    def total_calls(self) -> int:
        return (
            self.calls_trimmers
            + self.calls_improved_step2a
            + self.calls_bottom_up
        )
