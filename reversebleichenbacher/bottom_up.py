"""Proved and publicly certified best-effort Bottom-Up recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator, Sequence

from .core import ceil_div
from .executor import QueryExecutor, as_executor, execute_candidates


PROVED = "proved"
BEST_EFFORT = "best_effort"
DEFAULT_BOTTOM_UP_STRATEGY = BEST_EFFORT
BOTTOM_UP_STRATEGIES = (PROVED, BEST_EFFORT)
DELTA_POLICY = "center-near-quartiles-extremes-v1"
PROVED_QUERY_ORDER = "full-only-v1"
BEST_EFFORT_QUERY_ORDER = "certified-partial-then-full-v1"


class BottomUpFailure(RuntimeError):
    """Expected exhaustion of a Bottom-Up candidate family."""


class BottomUpNoFullContainment(BottomUpFailure):
    pass


class BottomUpFullQueriesRejected(BottomUpFailure):
    pass


class BottomUpNoUnambiguousCandidate(BottomUpFailure):
    pass


class BottomUpCoverageExhausted(BottomUpFailure):
    pass


def _odd_center_out(low: int, high: int, center: int) -> Iterator[int]:
    low = low if low % 2 else low + 1
    high = high if high % 2 else high - 1
    if low > high:
        return
    center = min(high, max(low, center))
    if center % 2 == 0:
        center = center - 1 if center - 1 >= low else center + 1
    yield center
    distance = 2
    while center - distance >= low or center + distance <= high:
        if center - distance >= low:
            yield center - distance
        if center + distance <= high:
            yield center + distance
        distance += 2


def delta_landmarks(low: int, high: int) -> tuple[int, ...]:
    """Return local and broad representatives of an inclusive delta range."""
    if low > high:
        return ()
    center = (low + high) // 2
    width = high - low
    ordered = (
        center,
        center - 1,
        center + 1,
        low + width // 4,
        low + (3 * width) // 4,
        low,
        high,
    )
    seen: set[int] = set()
    result = []
    for value in ordered:
        if low <= value <= high and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def heuristic_r(D: int, B: int, modulus: int) -> int:
    value = D - ceil_div(5 * B * D, 2 * modulus)
    if value % 2 == 0:
        value -= 1
    return value


def proved_r_bounds(
    D: int, modulus: int, B: int, low: int, high: int
) -> tuple[int, int] | None:
    """Integer points in the sufficient real interval from the paper."""
    if low >= high:
        return None
    width = high - low
    lower_num = (
        D * modulus * width
        - B * D * (3 * high - 2 * low)
        + D * D * low
        + 2 * D * low * high
    )
    lower_den = modulus * width
    upper_num = D * modulus - 2 * B * D - D * D - 2 * D * high
    lower = max(1, ceil_div(lower_num, lower_den))
    upper = min(D - 1, upper_num // modulus)
    return None if lower > upper else (lower, upper)


def r_candidates(
    D: int,
    modulus: int,
    B: int,
    low: int,
    high: int,
    *,
    limit: int,
) -> Iterator[int]:
    """Try the concrete r, the proved interval, then nearby odd extensions."""
    if limit < 1:
        raise ValueError("Bottom-Up r limit must be positive")
    r0 = heuristic_r(D, B, modulus)
    proved = proved_r_bounds(D, modulus, B, low, high)
    seen: set[int] = set()
    emitted = 0

    def emit(values: Iterator[int]) -> Iterator[int]:
        nonlocal emitted
        for value in values:
            if value in seen or not (1 <= value < D) or value % 2 == 0:
                continue
            seen.add(value)
            emitted += 1
            yield value
            if emitted >= limit:
                return

    if 1 <= r0 < D and r0 % 2:
        yield from emit(iter((r0,)))
        if emitted >= limit:
            return
    if proved is not None:
        yield from emit(_odd_center_out(proved[0], proved[1], r0))
        if emitted >= limit:
            return
    yield from emit(_odd_center_out(1, D - 1, r0))


def full_delta_bounds(
    D: int, r: int, modulus: int, B: int, low: int, high: int
) -> tuple[int, int] | None:
    """Deltas whose complete public interval lies in the negated range."""
    lower_num = D * (modulus - 3 * B) - r * modulus
    delta_low = max(0, lower_num // (D * low) + 1)
    upper_num = D * (modulus - 2 * B - D - high) - r * modulus
    delta_high = upper_num // (D * high)
    return None if delta_low > delta_high else (delta_low, delta_high)


def partial_delta_bounds(
    D: int, r: int, modulus: int, B: int, low: int, high: int
) -> tuple[int, int] | None:
    """Over-approximate deltas whose query coverage may intersect [low,high]."""
    base_distance = (D - r) * (modulus // D)
    if base_distance <= 2 * B:
        return None
    distance_low = base_distance - 3 * B
    distance_high = base_distance - 2 * B
    delta_low = max(0, distance_low // high)
    delta_high = ceil_div(distance_high, low)
    return None if delta_low > delta_high else (delta_low, delta_high)


def _distance_mod(value: int, modulus: int) -> int:
    residue = value % modulus
    return min(residue, modulus - residue)


def _k_for_guess(D: int, r: int, h: int, guess: int) -> int:
    return (r * pow((h * guess) % D, -1, D)) % D


def _distinguishes_all(
    D: int,
    r: int,
    inverse_D: int,
    h: int,
    guesses: Sequence[int],
    B: int,
    modulus: int,
) -> bool:
    for guess in guesses:
        k = _k_for_guess(D, r, h, guess)
        for possible in guesses:
            if possible == guess:
                continue
            if _distance_mod(
                k * (guess - possible) * inverse_D, modulus
            ) < B:
                return False
    return True


@dataclass(frozen=True)
class ResidueInterval:
    """The values D*q+residue for quotient_low <= q <= quotient_high."""

    D: int
    residue: int
    quotient_low: int
    quotient_high: int

    @property
    def low(self) -> int:
        return self.D * self.quotient_low + self.residue

    @property
    def high(self) -> int:
        return self.D * self.quotient_high + self.residue


@dataclass(frozen=True)
class BottomUpCandidate:
    multiplier: int
    guess: int
    preimage: tuple[ResidueInterval, ...] | None = None


def accepting_preimage(
    *,
    modulus: int,
    B: int,
    D: int,
    delta: int,
    k: int,
    residue: int,
    low: int,
    high: int,
    inverse_D: int | None = None,
) -> tuple[ResidueInterval, ...]:
    """Exact public TTT preimage for one possible residue modulo D."""
    if low > high:
        raise ValueError("invalid Bottom-Up interval")
    if not 0 <= residue < D:
        raise ValueError("residue is outside the Bottom-Up modulus")
    if delta < 0 or not 0 < k < D:
        raise ValueError("delta and k are outside their Bottom-Up ranges")
    if inverse_D is None:
        inverse_D = pow(D, -1, modulus)

    quotient_low = ceil_div(low - residue, D)
    quotient_high = (high - residue) // D
    if quotient_low > quotient_high:
        return ()

    slope = delta * D + k
    constant = (residue * delta + k * residue * inverse_D) % modulus
    target_low = modulus - 3 * B
    target_high = modulus - 2 * B
    transformed_low = slope * quotient_low + constant
    transformed_high = slope * quotient_high + constant
    z_low = ceil_div(transformed_low - target_high, modulus)
    z_high = ceil_div(transformed_high - target_low, modulus) - 1

    result = []
    for z in range(z_low, z_high + 1):
        accepted_low = max(
            quotient_low,
            (z * modulus + target_low - constant) // slope + 1,
        )
        accepted_high = min(
            quotient_high,
            (z * modulus + target_high - constant) // slope,
        )
        if accepted_low <= accepted_high:
            result.append(
                ResidueInterval(D, residue, accepted_low, accepted_high)
            )
    return tuple(result)


@dataclass(frozen=True)
class BottomUpParameters:
    r: int
    delta: int


def parameter_candidates(
    D: int,
    modulus: int,
    B: int,
    low: int,
    high: int,
    guesses: Sequence[int],
    *,
    limit: int,
    r_limit: int = 2048,
) -> Iterator[BottomUpParameters]:
    """Emit full-containment settings, trying delta landmarks per r."""
    if limit < 1:
        raise ValueError("full-containment setting limit must be positive")
    inverse_D = pow(D, -1, modulus)
    h = (D * inverse_D - 1) // modulus
    emitted = 0
    for r in r_candidates(
        D, modulus, B, low, high, limit=r_limit
    ):
        bounds = full_delta_bounds(D, r, modulus, B, low, high)
        if bounds is None or not _distinguishes_all(
            D, r, inverse_D, h, guesses, B, modulus
        ):
            continue
        for delta in delta_landmarks(*bounds):
            yield BottomUpParameters(r, delta)
            emitted += 1
            if emitted >= limit:
                return


def partial_parameter_candidates(
    D: int,
    modulus: int,
    B: int,
    low: int,
    high: int,
    *,
    r_limit: int,
) -> Iterator[BottomUpParameters]:
    """Emit partial-coverage candidates; exact certification happens later."""
    for r in r_candidates(
        D, modulus, B, low, high, limit=r_limit
    ):
        bounds = partial_delta_bounds(D, r, modulus, B, low, high)
        if bounds is None:
            continue
        for delta in delta_landmarks(*bounds):
            yield BottomUpParameters(r, delta)


def certified_preimage(
    *,
    modulus: int,
    B: int,
    D: int,
    delta: int,
    k: int,
    intended: int,
    guesses: Sequence[int],
    low: int,
    high: int,
    inverse_D: int,
) -> tuple[ResidueInterval, ...]:
    """Return the intended preimage iff no competing residue can accept."""
    intended_preimage = accepting_preimage(
        modulus=modulus,
        B=B,
        D=D,
        delta=delta,
        k=k,
        residue=intended,
        low=low,
        high=high,
        inverse_D=inverse_D,
    )
    if not intended_preimage:
        return ()
    for possible in guesses:
        if possible == intended:
            continue
        if accepting_preimage(
            modulus=modulus,
            B=B,
            D=D,
            delta=delta,
            k=k,
            residue=possible,
            low=low,
            high=high,
            inverse_D=inverse_D,
        ):
            return ()
    return intended_preimage


class BottomUpRecovery:
    def __init__(
        self,
        *,
        modulus: int,
        B: int,
        tau: int,
        low: int,
        high: int,
        start_bits: int,
        strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
        r_limit: int = 2048,
        full_setting_limit: int = 7,
    ):
        if start_bits < 2:
            raise ValueError("Bottom-Up start_bits must be at least 2")
        if strategy not in BOTTOM_UP_STRATEGIES:
            raise ValueError(f"unknown Bottom-Up strategy: {strategy}")
        if r_limit < 1:
            raise ValueError("Bottom-Up r limit must be positive")
        if full_setting_limit < 1:
            raise ValueError("Bottom-Up full-setting limit must be positive")
        self.modulus = modulus
        self.B = B
        self.tau = tau
        self.low = low
        self.high = high
        self.start_bits = start_bits
        self.strategy = strategy
        self.r_limit = r_limit
        self.full_setting_limit = full_setting_limit
        self._inverse_tau = pow(tau, -1, modulus)
        self.calls = 0

    def _multiplier(self, delta: int, k: int, inverse_D: int) -> int:
        symbolic = (delta + k * inverse_D) % self.modulus
        return (-symbolic * self._inverse_tau) % self.modulus

    def _recover_round(
        self, oracle: Callable[[int], bool] | QueryExecutor, D: int, guesses: Sequence[int]
    ) -> int:
        executor = as_executor(oracle)
        observed_queries = executor.submitted_queries

        def record_submissions() -> None:
            nonlocal observed_queries
            self.calls += executor.submitted_queries - observed_queries
            observed_queries = executor.submitted_queries

        inverse_D = pow(D, -1, self.modulus)
        h = (D * inverse_D - 1) // self.modulus
        queried: set[int] = set()
        partial_settings = 0
        certified_queries = 0
        full_settings = 0

        if self.strategy == BEST_EFFORT:
            for setting in partial_parameter_candidates(
                D,
                self.modulus,
                self.B,
                self.low,
                self.high,
                r_limit=self.r_limit,
            ):
                partial_settings += 1

                def partial_queries() -> Iterator[BottomUpCandidate]:
                    for guess in guesses:
                        k = _k_for_guess(D, setting.r, h, guess)
                        preimage = certified_preimage(
                            modulus=self.modulus,
                            B=self.B,
                            D=D,
                            delta=setting.delta,
                            k=k,
                            intended=guess,
                            guesses=guesses,
                            low=self.low,
                            high=self.high,
                            inverse_D=inverse_D,
                        )
                        if not preimage:
                            continue
                        multiplier = self._multiplier(
                            setting.delta, k, inverse_D
                        )
                        if multiplier in queried:
                            continue
                        queried.add(multiplier)
                        yield BottomUpCandidate(multiplier, guess, preimage)

                try:
                    for reply in execute_candidates(executor, partial_queries()):
                        certified_queries += 1
                        if reply.accepted:
                            preimage = reply.candidate.preimage
                            assert preimage is not None
                            self.low = max(
                                self.low, min(part.low for part in preimage)
                            )
                            self.high = min(
                                self.high, max(part.high for part in preimage)
                            )
                            return reply.candidate.guess
                finally:
                    record_submissions()

        for setting in parameter_candidates(
            D,
            self.modulus,
            self.B,
            self.low,
            self.high,
            guesses,
            limit=self.full_setting_limit,
            r_limit=self.r_limit,
        ):
            full_settings += 1

            def full_queries() -> Iterator[BottomUpCandidate]:
                for guess in guesses:
                    k = _k_for_guess(D, setting.r, h, guess)
                    multiplier = self._multiplier(setting.delta, k, inverse_D)
                    if multiplier in queried:
                        continue
                    queried.add(multiplier)
                    yield BottomUpCandidate(multiplier, guess)

            try:
                for reply in execute_candidates(executor, full_queries()):
                    if reply.accepted:
                        return reply.candidate.guess
            finally:
                record_submissions()

        if self.strategy == PROVED:
            if full_settings == 0:
                raise BottomUpNoFullContainment(
                    f"no full-containment setting for D={D}"
                )
            raise BottomUpFullQueriesRejected(
                f"all full-containment queries rejected for D={D}; "
                f"settings={full_settings}, queries={len(queried)}"
            )

        if certified_queries == 0:
            raise BottomUpNoUnambiguousCandidate(
                f"no publicly unambiguous partial query for D={D}; "
                f"full_settings={full_settings}, "
                f"partial_settings={partial_settings}"
            )
        raise BottomUpCoverageExhausted(
            f"best-effort coverage exhausted for D={D}; "
            f"full_settings={full_settings}, "
            f"partial_settings={partial_settings}, "
            f"certified_queries={certified_queries}, queries={len(queried)}"
        )

    def recover(
        self, oracle: Callable[[int], bool], target_bits: int
    ) -> tuple[int, int]:
        if self.low == self.high:
            return (self.low * self.tau) % (1 << target_bits), 0

        first_bits = min(self.start_bits, target_bits)
        D = 1 << first_bits
        guesses = tuple(range(1, D, 2))
        known = self._recover_round(oracle, D, guesses)
        known_bits = first_bits

        while known_bits < target_bits:
            previous_D = 1 << known_bits
            D = previous_D << 1
            known = self._recover_round(
                oracle, D, (known, known + previous_D)
            )
            known_bits += 1

        return (known * self.tau) % (1 << target_bits), self.calls
