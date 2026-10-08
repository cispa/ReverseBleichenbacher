"""Run against either artifact copy by setting PYTHONPATH to its attacker dir."""

import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Until the TLS adapter uses the shared package, exercise its own attack copy.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacker"))

from reversebleichenbacher import bottom_up, search, utils


class PlaintextOracle:
    """Exercise the real query multipliers against an exact TTT oracle."""

    def __init__(self, N, B, plaintext, reject_first=0):
        self.N, self.B, self.plaintext = N, B, plaintext
        self.reject_first = reject_first
        self.calls = 0

    def query(self, multiplier):
        self.calls += 1
        if self.calls > 10000:
            raise AssertionError("oracle query budget exhausted")
        value = self.plaintext * multiplier % self.N
        return self.calls > self.reject_first and 2 * self.B <= value < 3 * self.B

    def submit(self, work):
        return [(metadata, self.query(multiplier)) for multiplier, metadata in work]

    def as_completed(self, work):
        return iter(work)

    def cancel(self, work):
        work.clear()


class ExactCoverageTest(unittest.TestCase):
    def test_open_lower_closed_upper_and_negative_multipliers(self):
        for s in range(-9, 10):
            if not s:
                continue
            for lower in range(-20, 21):
                for upper in (lower + 1, lower + 7):
                    a, b = utils.get_scaled_coverage(s, lower, upper)
                    expected = [x for x in range(-30, 31) if lower < s * x <= upper]
                    self.assertEqual(list(range(a, b + 1)), expected)

    def test_fractional_cluster_origin_is_not_rounded_away(self):
        # D does not divide N. This query accepts x=3 exactly at 2B,
        # but the old rounded distance gives an upper bound of only 2.
        N, B, D, r = 101, 16, 32, 21
        h = (D * pow(D, -1, N) - 1) // N
        v, delta = 3, 0
        k = r * pow(h * v, -1, D) % D
        s = delta * D + k
        lower = (D - r) * N - 3 * B * D
        upper = (D - r) * N - 2 * B * D
        a, b = utils.get_scaled_coverage(s, lower, upper)
        old_upper = utils.ceil_div(((D - r) * (N // D) - 2 * B) * D, s)
        self.assertEqual(old_upper, 2)
        self.assertEqual(b, 3)
        self.assertEqual(-3 * s * pow(D, -1, N) % N, 2 * B)
        for x in range(v, N, D):
            if lower < s * x <= upper:
                self.assertLessEqual(a, x)
                self.assertLessEqual(x, b)
                self.assertTrue(2 * B <= -x * s * pow(D, -1, N) % N < 3 * B)


class BottomUpCoverageTest(unittest.TestCase):
    def test_accepted_endpoint_remains_in_returned_interval(self):
        for try_s in (bottom_up._try_s_values, bottom_up._try_s_values_parallel):
            with self.subTest(try_s=try_s.__name__):
                oracle = PlaintextOracle(101, 16, 3)
                result = try_s(21, 32, [3], 1, oracle, -425, 87, 0, 0, 101)
                residue, low, high = result
                self.assertEqual(residue, 3)
                self.assertLessEqual(low, 3)
                self.assertEqual(high, 3)

    def test_reindexed_odd_offset_example(self):
        for try_s in (bottom_up._try_s_values, bottom_up._try_s_values_parallel):
            oracle = PlaintextOracle(16777219, 65536, 151)
            residue, low, high = bottom_up._recover_bit_position(
                8, 151, 201, 1, list(range(1, 256, 2)), 65536, 16777219, oracle, try_s)
            self.assertEqual(residue, 151)
            self.assertLessEqual(low, 151)
            self.assertGreaterEqual(high, 151)
            self.assertLessEqual(oracle.calls, 128)

    def test_false_negatives_still_reach_the_retry_search(self):
        oracle = PlaintextOracle(16777219, 65536, 151, reject_first=128)
        attempts = []

        def try_offsets(*args):
            attempts.append((args[0], args[7], args[8]))
            return bottom_up._try_s_values_parallel(*args)

        residue, low, high = bottom_up._recover_bit_position(
            8, 151, 201, 1, list(range(1, 256, 2)), 65536, 16777219, oracle, try_offsets)
        self.assertEqual(residue, 151)
        self.assertTrue(low <= 151 <= high)
        self.assertEqual(attempts[0][1], attempts[0][2])
        self.assertGreater(len(attempts), 1)
        self.assertGreater(oracle.calls, 128)

    def test_just_outside_the_width_bound_still_uses_the_heuristic(self):
        self.assertIsNone(bottom_up._certified_offsets(256, 128, 150, 201, 65536, 16777219))
        oracle = PlaintextOracle(16777219, 65536, 151)
        residue, low, high = bottom_up._recover_bit_position(
            8, 150, 201, 1, list(range(1, 256, 2)), 65536, 16777219, oracle,
            bottom_up._try_s_values_parallel)
        self.assertEqual(residue, 151)
        self.assertTrue(low <= 151 <= high)

    def test_singleton_and_noninvertible_query_denominator(self):
        oracle = PlaintextOracle(115, 20, 3)
        result = bottom_up._recover_bit_position(
            2, 3, 3, 1, [1, 3], 20, 115, oracle, bottom_up._try_s_values)
        self.assertEqual(result, (3, 3, 3))
        self.assertEqual(oracle.calls, 0)
        with self.assertRaisesRegex(ValueError, "invertible"):
            bottom_up._recover_bit_position(
                2, 10, 20, 5, [1, 3], 20, 115, oracle, bottom_up._try_s_values)


class CertifiedOffsetsTest(unittest.TestCase):
    def test_reindexed_counterexample_has_full_coverage_and_unique_answers(self):
        N, B, D, a, b = 16777219, 65536, 256, 151, 201
        r, delta = bottom_up._certified_offsets(D, 128, a, b, B, N)
        self.assertTrue(1 <= r < D and r % 2)
        self.assertGreater(delta * a * D + r * N, (N - 3 * B) * D)
        self.assertLessEqual((delta + 1) * b * D + r * N + D * D, (N - 2 * B) * D)
        inverse = pow(D, -1, N)
        h = (D * inverse - 1) // N
        for x in range(a, b + 1, 2):
            passing = []
            for v in range(1, D, 2):
                k = r * pow(h * v, -1, D) % D
                value = x * (delta + k * inverse) % N
                if N - 3 * B < value <= N - 2 * B:
                    passing.append(v)
            self.assertEqual(passing, [x % D])

    def test_failed_sufficient_conditions_leave_the_heuristic_available(self):
        # Original counterexample lacks the known parity bit in its batch.
        self.assertIsNone(bottom_up._certified_offsets(4, 4, 2, 3, 20, 115))
        # Payload/current modulus too large, interval too wide, even N,
        # or too many candidates for the required residue separation.
        self.assertIsNone(bottom_up._certified_offsets(32768, 2, 151, 152, 65536, 16777219))
        self.assertIsNone(bottom_up._certified_offsets(256, 128, 100, 201, 65536, 16777219))
        self.assertIsNone(bottom_up._certified_offsets(256, 128, 151, 201, 65536, 16777218))
        self.assertIsNone(bottom_up._certified_offsets(1024, 512, 2000, 2001, 65536, 16777219))


class SearchCoverageTest(unittest.TestCase):
    def test_first_slice_does_not_skip_the_top_point(self):
        N, B = 16777219, 65536
        multiplier, (a, b) = next(search.search_iter_oracle_args(1, 14882, 15000, N, B))
        self.assertTrue(a <= 14999 <= b)
        self.assertTrue(PlaintextOracle(N, B, 14999).query(multiplier))

    def test_slices_cover_every_odd_message_and_preserve_accepted_bounds(self):
        N, B = 16777219, 65536
        remaining = set(range(5001, 6000, 2))
        for count, (multiplier, (a, b)) in enumerate(
                search.search_iter_oracle_args(1, 5000, 6000, N, B), 1):
            self.assertLess(count, 100)
            for x in range(5001, 6000, 2):
                if 2 * B <= x * multiplier % N < 3 * B:
                    self.assertTrue(a <= x <= b)
                    remaining.discard(x)
            if not remaining:
                break
        self.assertFalse(remaining)

    def test_singleton_search_and_false_negative_retry(self):
        N, B = 16777219, 65536
        rsa = SimpleNamespace(N=N, bits=32)
        for parallel in (False, True):
            method = search.search_parallel if parallel else search.search
            oracle = PlaintextOracle(N, B, 151)
            self.assertEqual(method(1, 151, 151, rsa, oracle, None), (151, 151))
            oracle = PlaintextOracle(N, B, 14999, reject_first=1)
            low, high = method(1, 14882, 15000, rsa, oracle, None)
            self.assertTrue(low <= 14999 <= high)
            self.assertGreater(oracle.calls, 1)


class IntegratedRecoveryTest(unittest.TestCase):
    def test_search_then_recovery_with_large_exact_integers(self):
        for bits in (1024, 2048):
            # Arithmetic fixtures near the lower end of each byte length;
            # these odd moduli are not asserted to be RSA key products.
            B = 1 << (bits - 16)
            N = (1 << (bits - 8)) + 3
            tau = 13
            x = (5 * B // (2 * tau)) | 1
            message = tau * x
            for parallel in (False, True):
                with self.subTest(bits=bits, parallel=parallel):
                    rsa = SimpleNamespace(N=N, bits=bits)
                    config = SimpleNamespace(total_bits=368, parallel_bits=4)
                    oracle = PlaintextOracle(N, B, message)
                    find = search.search_parallel if parallel else search.search
                    recover = bottom_up.bottom_up_parallel if parallel else bottom_up.bottom_up
                    low, high = find(tau, 2 * B, 3 * B - 1, rsa, oracle, config)
                    self.assertTrue(low <= message <= high)
                    search_calls = oracle.calls
                    result = recover(logging.getLogger(__name__), oracle, rsa,
                                     tau, low, high, config)
                    self.assertEqual(result, message % (1 << config.total_bits))
                    if parallel:
                        # The optimized-search guarantee applies to this
                        # four-bit batch and payload. Serial retries need
                        # not satisfy the same sufficient width condition.
                        rounds = (config.total_bits - 1 + 3) // 4
                        self.assertLessEqual(oracle.calls - search_calls, rounds * 16)


class RecoveryRoundsTest(unittest.TestCase):
    def test_known_parity_and_last_batch(self):
        for parallel in (False, True):
            for ell in ((1, 2, 4) if parallel else (1,)):
                for n in (1, 2, 5, 9, 368, 369):
                    with self.subTest(parallel=parallel, ell=ell, n=n):
                        x, tau = 0xDEADBEEF, 13
                        positions = []

                        def recover(position, low, high, lcm, candidates, *args):
                            D = 1 << position
                            self.assertEqual(lcm, tau)
                            self.assertTrue(all(0 < v < D and v % 2 for v in candidates))
                            self.assertEqual(len(set(candidates)), 1 << ell)
                            self.assertIn(x % D, candidates)
                            positions.append(position)
                            return x % D, low, high

                        config = SimpleNamespace(parallel_bits=ell, total_bits=n)
                        rsa = SimpleNamespace(bits=2048, N=(1 << 2048) - 1)
                        oracle = SimpleNamespace(calls=0)
                        method = bottom_up.bottom_up_parallel if parallel else bottom_up.bottom_up
                        with patch.object(bottom_up, "_recover_bit_position", side_effect=recover):
                            result = method(logging.getLogger(__name__), oracle, rsa,
                                            tau, (x - 2) * tau, (x + 2) * tau, config)
                        rounds = (n - 1 + ell - 1) // ell
                        self.assertEqual(positions, [1 + ell * j for j in range(1, rounds + 1)])
                        self.assertEqual(result, tau * x % (1 << n))


if __name__ == "__main__":
    unittest.main()
