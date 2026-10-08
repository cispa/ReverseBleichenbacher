"""Offline, plaintext-aware trimmer diagnostics.

Nothing in this module is imported by an attack implementation.  It runs only
after an attack has returned or raised and never calls the oracle.
"""

from __future__ import annotations

import math
from functools import lru_cache

from proof.core import ceil_div
from proof.primes import TRIMMER_PRIMES


def _multipliers(t: int, slack: int):
    lower = 2 * t // 3 + 1
    upper = ceil_div(3 * t, 2) - 1
    for offset in range(1, slack + 1):
        if t - offset < lower and t + offset > upper:
            break
        if t - offset >= lower and math.gcd(t - offset, t) == 1:
            yield t - offset
        if t + offset <= upper and math.gcd(t + offset, t) == 1:
            yield t + offset


def _proof_candidates(n: int, B: int, config: dict):
    slack = config["t_slack"]
    cutoff = 0
    for prime in TRIMMER_PRIMES:
        valid = sum(
            math.gcd(value, prime) == 1
            for value in range(
                2 * prime // 3 + 1, ceil_div(3 * prime, 2)
            )
        )
        if valid > 2 * (slack + 1):
            break
        cutoff = prime
    full_sweep = config["trimmer_cutoff"] if config["oracle_type"] == "FFT" else 0
    bound = max(cutoff**2, full_sweep)
    yield 2, 4 * slack + 1
    for t in range(3, bound + 1):
        yield t, slack + 1
    maximum = ceil_div(2 * n, 9 * B)
    for prime in TRIMMER_PRIMES:
        if prime >= bound and prime < maximum:
            yield prime, slack + 1


def _capol_candidates(n: int, B: int, config: dict):
    remaining = config["trimmer_values"]
    slack = config["t_slack"] + 1
    for t in range(3, ceil_div(2 * n, 9 * B)):
        tested = []
        for multiplier in _multipliers(t, slack):
            if remaining == 0:
                return
            remaining -= 1
            tested.append(multiplier)
        if tested:
            yield t, tuple(tested)


def _schedule(implementation: str, n: int, B: int, config: dict):
    if implementation == "proof":
        for t, slack in _proof_candidates(n, B, config):
            yield t, tuple(_multipliers(t, slack))
    elif implementation == "capol":
        yield from _capol_candidates(n, B, config)
    else:
        raise ValueError(f"unknown implementation: {implementation}")


@lru_cache(maxsize=2048)
def _candidate_lcm(
    implementation: str,
    n: int,
    B: int,
    oracle_type: str,
    t_slack: int,
    trimmer_cutoff: int,
    trimmer_values: int,
) -> int:
    config = {
        "oracle_type": oracle_type,
        "t_slack": t_slack,
        "trimmer_cutoff": trimmer_cutoff,
        "trimmer_values": trimmer_values,
    }
    value = 1
    for t, _multipliers_for_t in _schedule(implementation, n, B, config):
        value = math.lcm(value, t)
    return value


def trimmer_report(
    implementation: str,
    plaintext: int,
    modulus: int,
    bits: int,
    config: dict,
    *,
    classify_multiplier: bool,
) -> dict[str, int | None]:
    """Compute failure diagnostics without influencing the completed attack."""
    B = 1 << (bits - 16)
    candidate_lcm = _candidate_lcm(
        implementation,
        modulus,
        B,
        config["oracle_type"],
        config["t_slack"],
        config.get("trimmer_cutoff", 0),
        config.get("trimmer_values", 0),
    )
    available = math.gcd(plaintext, candidate_lcm)
    odd_part = available >> ((available & -available).bit_length() - 1)
    has_divisor = odd_part > 1 or available % 4 == 0

    detectable = None
    if classify_multiplier and has_divisor:
        detectable = 0
        for t, multipliers in _schedule(implementation, modulus, B, config):
            if plaintext % t:
                continue
            reduced = plaintext // t
            if any(2 * B <= u * reduced <= 3 * B - 1 for u in multipliers):
                detectable = 1
                break
    return {
        "tau_available": available,
        "trimmer_has_divisor": int(has_divisor),
        "trimmer_detectable": detectable,
    }


def trimmer_outcome(report: dict[str, int | None]) -> str:
    if not report["trimmer_has_divisor"]:
        return "trimmer_no_divisor"
    if report["trimmer_detectable"]:
        return "trimmer_false_negative"
    return "trimmer_no_multiplier"


def trimmer_missed_power_of_two(plaintext: int, tau_found: int | None) -> bool:
    """Whether a later phase was entered after missing a factor of two.

    Bottom-Up (and the optional halving search) assumes that
    ``plaintext / tau_found`` is odd.  A nonzero even quotient proves that
    ``2 * tau_found`` was another usable divisor that Trimmers failed to
    accumulate.  Standard coverage can itself proceed with an even quotient,
    so the observed abort phase is retained separately.  This check is
    strictly offline: it runs only after the attack has returned or raised.
    """
    return bool(
        tau_found
        and plaintext % tau_found == 0
        and (plaintext // tau_found) % 2 == 0
    )


def reported_outcome(
    implementation: str,
    outcome: str,
    plaintext: int,
    tau_found: int | None,
) -> str:
    """Return the causal reporting outcome without changing attack behavior."""
    if (
        implementation == "proof"
        and outcome in {
            "search_failed", "search_coverage_exhausted",
            "search_false_negative_exhausted", "bottom_up_failed",
        }
        and trimmer_missed_power_of_two(plaintext, tau_found)
    ):
        return "trimmer_missed_power_of_two"
    return outcome
