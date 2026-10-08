"""Prime schedule used by the proof trimmer search.

The historical implementation checked in a literal table ending at 14563.
Building the same table with a tiny sieve keeps this implementation local and
avoids importing message-generation utilities merely to obtain primes.
"""

from __future__ import annotations


MAX_TRIMMER_PRIME = 14563


def _primes_up_to(limit: int) -> tuple[int, ...]:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[:2] = b"\x00\x00"
    for value in range(2, int(limit**0.5) + 1):
        if sieve[value]:
            start = value * value
            sieve[start : limit + 1 : value] = b"\x00" * (
                (limit - start) // value + 1
            )
    return tuple(index for index, is_prime in enumerate(sieve) if is_prime)


TRIMMER_PRIMES = _primes_up_to(MAX_TRIMMER_PRIME)
