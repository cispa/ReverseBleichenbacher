"""Execute public attack candidates against a sequential or batched oracle.

Candidate generation belongs to the attack. An executor returns each answer
with its candidate, so a later concurrent executor may complete work out of
order without losing the bounds or residue associated with that query.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
from typing import (
    Callable,
    Generic,
    Iterable,
    Iterator,
    Protocol,
    Sequence,
    TypeVar,
    runtime_checkable,
)


class QueryCandidate(Protocol):
    multiplier: int


CandidateT = TypeVar("CandidateT", bound=QueryCandidate)


@dataclass(frozen=True)
class QueryResult(Generic[CandidateT]):
    candidate: CandidateT
    accepted: bool


@runtime_checkable
class QueryExecutor(Protocol):
    """Return labelled replies, including out-of-order replies from a batch.

    ``submitted_queries`` counts every query actually sent, even when a later
    positive reply causes pending work to be canceled. A batch with no positive
    reply must yield every answer. Closing a partially consumed batch must
    cancel any work that can still be canceled.
    """

    @property
    def batch_size(self) -> int: ...

    @property
    def submitted_queries(self) -> int: ...

    def set_phase(self, phase: str) -> None: ...

    def query(self, multiplier: int) -> bool: ...

    def execute_batch(
        self, candidates: Sequence[CandidateT]
    ) -> Iterator[QueryResult[CandidateT]]: ...


class SequentialExecutor:
    """Adapt the existing callable oracle without changing query order."""

    batch_size = 1

    def __init__(self, oracle: Callable[[int], bool]):
        self._oracle = oracle
        self._submitted_queries = 0

    @property
    def submitted_queries(self) -> int:
        return self._submitted_queries

    def set_phase(self, phase: str) -> None:
        setter = getattr(self._oracle, "set_phase", None)
        if setter is not None:
            setter(phase)

    def query(self, multiplier: int) -> bool:
        self._submitted_queries += 1
        return bool(self._oracle(multiplier))

    def execute_batch(
        self, candidates: Sequence[CandidateT]
    ) -> Iterator[QueryResult[CandidateT]]:
        for candidate in candidates:
            yield QueryResult(candidate, self.query(candidate.multiplier))


def as_executor(oracle: Callable[[int], bool] | QueryExecutor) -> QueryExecutor:
    if isinstance(oracle, QueryExecutor):
        return oracle
    if not callable(oracle):
        raise TypeError("oracle must be callable or implement QueryExecutor")
    return SequentialExecutor(oracle)


def execute_candidates(
    executor: QueryExecutor, candidates: Iterable[CandidateT]
) -> Iterator[QueryResult[CandidateT]]:
    """Submit finite windows while retaining each candidate's metadata."""
    if executor.batch_size < 1:
        raise ValueError("executor batch_size must be positive")
    pending = iter(candidates)
    while batch := tuple(islice(pending, executor.batch_size)):
        yield from executor.execute_batch(batch)
