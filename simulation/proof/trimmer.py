"""Plaintext-independent Trimmers implementation."""

from __future__ import annotations

import math
from typing import Callable

from .core import AttackConfig, ceil_div
from .primes import TRIMMER_PRIMES


TRIM_VALUE_THRESHOLD = 20


class Trimmer:
    def __init__(
        self,
        *,
        modulus: int,
        B: int,
        config: AttackConfig,
        oracle: Callable[[int], bool],
    ):
        self.modulus = modulus
        self.B = B
        self.config = config
        self.oracle = oracle
        self.gen_trimmers_count = 0
        # The oracle is deterministic for a fixed ciphertext. Several
        # overlapping trimmer searches revisit the same multiplier with a
        # larger slack radius, so reuse the first response.
        self._oracle_cache: dict[int, bool] = {}

    def _query(self, multiplier: int) -> tuple[bool, bool]:
        """Return ``(response, queried)`` and memoize oracle responses."""
        if multiplier in self._oracle_cache:
            return self._oracle_cache[multiplier], False
        response = self.oracle(multiplier)
        self._oracle_cache[multiplier] = response
        return response, True

    @staticmethod
    def u_min(t: int) -> int:
        return 2 * t // 3 + 1

    @staticmethod
    def u_max(t: int) -> int:
        return ceil_div(3 * t, 2) - 1

    def check_t(self, t: int, slack: int | None = None) -> bool:
        """Test the center-out candidate multipliers for divisor ``t``."""
        if slack is None:
            slack = self.config.t_slack + 1
        inverse_t = pow(t, -1, self.modulus)
        lower = self.u_min(t)
        upper = self.u_max(t)
        for offset in range(1, slack + 1):
            if t - offset < lower and t + offset > upper:
                break
            if t - offset >= lower and math.gcd(t - offset, t) == 1:
                response, queried = self._query(
                    ((t - offset) * inverse_t) % self.modulus
                )
                self.gen_trimmers_count += int(queried)
                if response:
                    return True
            if t + offset <= upper and math.gcd(t + offset, t) == 1:
                response, queried = self._query(
                    ((t + offset) * inverse_t) % self.modulus
                )
                self.gen_trimmers_count += int(queried)
                if response:
                    return True
        return False

    def generate_and_test(self) -> tuple[int, int]:
        """Return the accumulated trimmer and its oracle-query count."""
        tau = 1
        max_t = ceil_div(2 * self.modulus, 9 * self.B)
        self.gen_trimmers_count = 0

        cutoff_prime = 0
        for prime in TRIMMER_PRIMES:
            valid = sum(
                math.gcd(value, prime) == 1
                for value in range(self.u_min(prime), self.u_max(prime) + 1)
            )
            if valid > 2 * (self.config.t_slack + 1):
                break
            cutoff_prime = prime

        full_sweep = (
            self.config.trimmer_cutoff
            if self.config.oracle_type == "FFT"
            else 0
        )
        sweep_bound = max(cutoff_prime**2, full_sweep)
        candidates = list(range(3, sweep_bound + 1)) + [
            prime
            for prime in TRIMMER_PRIMES
            if sweep_bound <= prime < max_t
        ]
        for candidate in candidates:
            if tau >= self.config.trimmer_cutoff and candidate > full_sweep:
                break
            if full_sweep and tau % candidate == 0:
                continue
            if self.check_t(candidate):
                tau = math.lcm(tau, candidate)

        # Accumulate higher powers of prime factors already found.
        for prime in [value for value in TRIMMER_PRIMES if value <= tau]:
            if tau % prime:
                continue
            while self.check_t(prime * tau):
                tau = math.lcm(tau, prime * tau)

        # Try the remaining small factors. The special radius for two is
        # retained here; the attack then performs its stronger recursive check.
        for factor in range(2, cutoff_prime):
            if tau % factor == 0:
                continue
            slack = (
                4 * self.config.t_slack + 1
                if factor == 2
                else self.config.t_slack + 1
            )
            while self.check_t(tau * factor, slack=slack):
                tau *= factor

        return tau, self.gen_trimmers_count

    def find_low_high(
        self, tau: int
    ) -> tuple[tuple[int, int], tuple[int, int], int]:
        """Locate the accepted numerator range for the accumulated trimmer."""
        inverse_tau = pow(tau, -1, self.modulus)
        low = self.u_min(tau)
        high = self.u_max(tau)
        u_low = tau
        u_high = tau
        calls = 0

        while True:
            new_low, calls = self._binary_bound(
                low, u_low, inverse_tau, find_min=True, calls=calls
            )
            new_high, calls = self._binary_bound(
                u_high, high, inverse_tau, find_min=False, calls=calls
            )
            a = 2 * self.B * tau // new_low
            b = (3 * self.B - 1) * tau // new_high + 1
            trim_value = (self.B - 1) / (b - a + 1)
            if trim_value > TRIM_VALUE_THRESHOLD or (
                new_high == u_high and new_low == u_low
            ):
                return (new_low, tau), (new_high, tau), calls
            u_low, u_high = new_low, new_high

    def _binary_bound(
        self,
        low: int,
        high: int,
        inverse_tau: int,
        *,
        find_min: bool,
        calls: int,
    ) -> tuple[int, int]:
        if low >= high:
            return (high if find_min else low), calls
        mid = (low + high) // 2 if find_min else ceil_div(low + high, 2)
        response, queried = self._query((mid * inverse_tau) % self.modulus)
        calls += int(queried)
        if response:
            if find_min:
                return self._binary_bound(
                    low, mid, inverse_tau, find_min=find_min, calls=calls
                )
            return self._binary_bound(
                mid, high, inverse_tau, find_min=find_min, calls=calls
            )

        if find_min:
            for offset in range(1, self.config.bs_slack + 1):
                if mid - offset < low:
                    return self._binary_bound(
                        mid + 1,
                        high,
                        inverse_tau,
                        find_min=find_min,
                        calls=calls,
                    )
                response, queried = self._query(
                    ((mid - offset) * inverse_tau) % self.modulus
                )
                calls += int(queried)
                if response:
                    return self._binary_bound(
                        low,
                        mid - offset,
                        inverse_tau,
                        find_min=find_min,
                        calls=calls,
                    )
            return self._binary_bound(
                mid + 1,
                high,
                inverse_tau,
                find_min=find_min,
                calls=calls,
            )

        for offset in range(1, self.config.bs_slack + 1):
            if mid + offset > high:
                return self._binary_bound(
                    low,
                    mid - 1,
                    inverse_tau,
                    find_min=find_min,
                    calls=calls,
                )
            response, queried = self._query(
                ((mid + offset) * inverse_tau) % self.modulus
            )
            calls += int(queried)
            if response:
                return self._binary_bound(
                    mid + offset,
                    high,
                    inverse_tau,
                    find_min=find_min,
                    calls=calls,
                )
        return self._binary_bound(
            low,
            mid - 1,
            inverse_tau,
            find_min=find_min,
            calls=calls,
        )


def power_two_slack(t_slack: int) -> int:
    if t_slack < 0:
        raise ValueError("t_slack cannot be negative")
    return 3 * (t_slack + 1)


def extend_power_of_two(
    trimmer: Trimmer, tau: int, *, slack: int
) -> tuple[int, int]:
    """Retry and recursively extend the full two-adic part of ``tau``."""
    if tau < 1 or slack < 1:
        raise ValueError("tau and slack must be positive")
    before = trimmer.gen_trimmers_count
    while trimmer.check_t(2 * tau, slack=slack):
        tau *= 2
    return tau, trimmer.gen_trimmers_count - before
