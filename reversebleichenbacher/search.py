"""Plaintext-independent Searching candidate schedules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .core import ceil_div
from .executor import QueryExecutor, execute_candidates


STANDARD_COVERAGE = "standard_coverage"
HALVING_FULL_GRID = "halving_full_grid"
HALVING_SPARSE_GRID = "halving_sparse_grid"
HALVING_SPARSE_ASYMMETRIC = "halving_sparse_asymmetric"
DEFAULT_SEARCH_STRATEGY = HALVING_SPARSE_ASYMMETRIC
SEARCH_STRATEGIES = (
    STANDARD_COVERAGE,
    HALVING_FULL_GRID,
    HALVING_SPARSE_GRID,
    HALVING_SPARSE_ASYMMETRIC,
)


class SearchFailure(RuntimeError):
    pass


def normalize_search_strategy(strategy: str) -> str:
    if strategy not in SEARCH_STRATEGIES:
        raise ValueError(f"unknown search strategy: {strategy}")
    return strategy


@dataclass(frozen=True)
class SearchCandidate:
    multiplier: int
    reduced_low: int
    reduced_high: int
    numerator: int
    denominator: int
    slice_index: int
    offset: int


def _offsets(slack: int) -> Iterator[int]:
    if slack < 0:
        raise ValueError("search slack cannot be negative")
    yield 0
    for distance in range(1, slack + 1):
        yield -distance
        yield distance


def _asymmetric_offsets(slack: int) -> Iterator[int]:
    """Prioritize December's asymmetric side, then retain completeness."""
    if slack < 0:
        raise ValueError("search slack cannot be negative")
    yield 0
    deferred = []
    for distance in range(1, slack + 1):
        if distance % 2:
            yield -distance
            deferred.append(distance)
        else:
            yield distance
            deferred.append(-distance)
    yield from deferred

def _standard_preimage(
    numerator: int, modulus: int, B: int, low: int, high: int
) -> tuple[int, int] | None:
    # -s*x mod N is in [2B,3B) exactly when
    # N-3B < s*x <= N-2B on the branch used by this construction.
    # The next congruent target interval starts one modulus later.  Values may
    # cross N without becoming accepting, so do not reject a candidate merely
    # because the top of the whole working interval crosses N.
    if numerator <= 0 or numerator * high >= 2 * modulus - 3 * B + 1:
        return None
    accepted_low = max(low, (modulus - 3 * B) // numerator + 1)
    accepted_high = min(high, (modulus - 2 * B) // numerator)
    if accepted_low > accepted_high:
        return None
    return accepted_low, accepted_high


def _halving_preimage(
    numerator: int, modulus: int, B: int, low: int, high: int
) -> tuple[int, int] | None:
    # For odd x and odd p, querying -p/(2*tau) uses the exact branch
    # N-6B < p*x <= N-4B.
    # Odd p*x repeats this effective target after 2N, not after N.
    if (
        numerator <= 0
        or numerator % 2 != 1
        or numerator * high >= 3 * modulus - 6 * B + 2
    ):
        return None
    accepted_low = max(low, (modulus - 6 * B) // numerator + 1)
    accepted_high = min(high, (modulus - 4 * B) // numerator)
    if accepted_low > accepted_high:
        return None
    return accepted_low, accepted_high


def _relaxed_halving_coverage(
    numerator: int, modulus: int, B: int
) -> tuple[int, int]:
    """Return the historical outward-rounded nominal coverage.

    This interval is used only to schedule queries.  A positive query is
    always narrowed with :func:`_halving_preimage`, never with these bounds.
    """
    half_modulus = modulus // 2
    nominal_low = 2 * (half_modulus - 3 * B) // numerator
    nominal_high = ceil_div(2 * (half_modulus - 2 * B), numerator)
    return nominal_low, nominal_high


def _sparse_halving_bases(
    modulus: int,
    B: int,
    low: int,
    high: int,
) -> list[tuple[int, int, int]]:
    """Construct the historical partial-coverage grid.

    It chooses the first odd numerator whose nominal interval ends below the
    current endpoint, reproducing December's sparse base grid.
    """
    half_modulus = modulus // 2
    max_distance = half_modulus - 2 * B
    shift_lower = max_distance // high
    shift_upper = ceil_div(max_distance, low)
    highest_not_scheduled = high
    last_shift = shift_lower - 1
    bases: list[tuple[int, int, int]] = []

    while highest_not_scheduled > low:
        left = last_shift + 1
        right = shift_upper
        if left > right:
            break
        while left < right:
            shift = (left + right) // 2
            numerator = 2 * shift + 1
            _nominal_low, nominal_high = _relaxed_halving_coverage(
                numerator, modulus, B
            )
            if nominal_high < highest_not_scheduled:
                right = shift
            else:
                left = shift + 1

        # ``left`` is the first shift below the current endpoint, so the
        # resulting base grid deliberately leaves gaps.
        shift = left
        numerator = 2 * shift + 1
        nominal_low, _nominal_high = _relaxed_halving_coverage(
            numerator, modulus, B
        )
        bases.append((numerator, 2, len(bases)))
        last_shift = shift
        highest_not_scheduled = nominal_low - 1

    return bases


def search_candidates(
    strategy: str,
    modulus: int,
    B: int,
    tau: int,
    low: int,
    high: int,
    *,
    slack: int = 0,
) -> Iterator[SearchCandidate]:
    """Yield plaintext-independent candidates in the selected schedule.

    Full-grid coverage tiles ``[low, high]`` exactly. Sparse-grid coverage
    reproduces the historical December base grid.
    Every yielded candidate carries its exact accepting preimage regardless
    of the scheduling grid. Ordinary candidates are ordered breadth-first by
    retry offset. The asymmetric schedule prioritizes December's side of
    the same finite offset set before visiting its complement.
    """
    strategy = normalize_search_strategy(strategy)
    if not 0 < low <= high or tau <= 0:
        raise ValueError("invalid reduced interval or tau")

    inverse_tau = pow(tau, -1, modulus)
    inverse_two_tau = pow(2 * tau, -1, modulus)
    base_slices: list[tuple[int, int, int]] = []
    if strategy in (HALVING_SPARSE_GRID, HALVING_SPARSE_ASYMMETRIC):
        base_slices = _sparse_halving_bases(modulus, B, low, high)
    else:
        slice_high = high
        slice_index = 0
        while slice_high >= low:
            if strategy == STANDARD_COVERAGE:
                base = (modulus - 2 * B) // slice_high
                base_preimage = _standard_preimage(
                    base, modulus, B, low, slice_high
                )
                step = 1
            else:
                base = (modulus - 4 * B) // slice_high
                if base % 2 == 0:
                    base -= 1
                base_preimage = _halving_preimage(
                    base, modulus, B, low, slice_high
                )
                step = 2

            if base_preimage is None:
                raise SearchFailure(
                    f"empty {strategy} base slice at [{low}, {slice_high}]"
                )
            base_low, base_high = base_preimage
            if base_high != slice_high:
                raise SearchFailure(
                    f"{strategy} left a coverage gap below {slice_high}"
                )

            base_slices.append((base, step, slice_index))
            slice_high = base_low - 1
            slice_index += 1

    seen: set[int] = set()
    if strategy == HALVING_SPARSE_ASYMMETRIC:
        offsets = _asymmetric_offsets(slack)
    else:
        offsets = _offsets(slack)
    for offset in offsets:
        for base, step, slice_index in base_slices:
            numerator = base + step * offset
            if strategy == STANDARD_COVERAGE:
                preimage = _standard_preimage(
                    numerator, modulus, B, low, high
                )
                multiplier = (-numerator * inverse_tau) % modulus
                denominator = 1
            else:
                preimage = _halving_preimage(
                    numerator, modulus, B, low, high
                )
                multiplier = (-numerator * inverse_two_tau) % modulus
                denominator = 2
            if preimage is None or multiplier in seen:
                continue
            seen.add(multiplier)
            yield SearchCandidate(
                multiplier=multiplier,
                reduced_low=preimage[0],
                reduced_high=preimage[1],
                numerator=numerator,
                denominator=denominator,
                slice_index=slice_index,
                offset=offset,
            )


def run_search(
    executor: QueryExecutor,
    strategy: str,
    modulus: int,
    B: int,
    tau: int,
    low: int,
    high: int,
    *,
    slack: int = 0,
    complete_sparse: bool = False,
) -> tuple[SearchCandidate, int]:
    strategy = normalize_search_strategy(strategy)
    started_at = executor.submitted_queries
    queried: set[int] = set()
    for reply in execute_candidates(
        executor,
        search_candidates(strategy, modulus, B, tau, low, high, slack=slack),
    ):
        candidate = reply.candidate
        queried.add(candidate.multiplier)
        if reply.accepted:
            return candidate, executor.submitted_queries - started_at
    if strategy == HALVING_SPARSE_ASYMMETRIC and complete_sparse:
        # Sparse scheduling is a query-order heuristic. Complete the exact
        # halving grid before declaring Search exhausted, preserving the
        # theorem's odd-quotient coverage even for a perfect oracle.
        remaining = (
            candidate
            for candidate in search_candidates(
                HALVING_FULL_GRID, modulus, B, tau, low, high
            )
            if candidate.multiplier not in queried
        )
        for reply in execute_candidates(executor, remaining):
            candidate = reply.candidate
            queried.add(candidate.multiplier)
            if reply.accepted:
                return candidate, executor.submitted_queries - started_at
    calls = executor.submitted_queries - started_at
    raise SearchFailure(
        f"{strategy} exhausted interval [{low}, {high}] after {calls} queries"
    )
