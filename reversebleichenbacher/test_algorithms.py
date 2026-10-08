from __future__ import annotations

import unittest
from unittest import mock

from . import bottom_up
from .bottom_up import (
    BEST_EFFORT,
    PROVED,
    BottomUpFailure,
    BottomUpRecovery,
    accepting_preimage,
    certified_preimage,
    delta_landmarks,
    parameter_candidates,
    proved_r_bounds,
)
from .core import AttackConfig
from .primes import TRIMMER_PRIMES
from .search import (
    HALVING_FULL_GRID,
    HALVING_SPARSE_ASYMMETRIC,
    HALVING_SPARSE_GRID,
    STANDARD_COVERAGE,
    _asymmetric_offsets,
    SearchFailure,
    run_search,
    search_candidates,
)
from .trimmer import Trimmer, extend_power_of_two, power_two_slack


class PowerOfTwoTests(unittest.TestCase):
    def test_local_prime_schedule_has_expected_historical_boundary(self):
        self.assertEqual(len(TRIMMER_PRIMES), 1708)
        self.assertEqual(TRIMMER_PRIMES[:5], (2, 3, 5, 7, 11))
        self.assertEqual(TRIMMER_PRIMES[-1], 14563)

    def test_slack_is_always_three_times_configured_radius(self):
        self.assertEqual(power_two_slack(0), 3)
        self.assertEqual(power_two_slack(1), 6)
        self.assertEqual(power_two_slack(4), 15)

    def test_extension_recurses_until_first_rejected_level(self):
        class FakeTrimmer:
            gen_trimmers_count = 0

            def check_t(self, value, *, slack):
                self.gen_trimmers_count += 1
                self.asserted_slack = slack
                return value in {12, 24}

        trimmer = FakeTrimmer()
        tau, calls = extend_power_of_two(trimmer, 6, slack=9)
        self.assertEqual(tau, 24)
        self.assertEqual(calls, 3)
        self.assertEqual(trimmer.asserted_slack, 9)

    def test_larger_slack_reuses_identical_oracle_queries(self):
        multipliers = []

        def oracle(multiplier):
            multipliers.append(multiplier)
            return False

        trimmer = Trimmer(
            modulus=101,
            B=5,
            config=AttackConfig("FFT", 2048, t_slack=1, bs_slack=3),
            oracle=oracle,
        )
        self.assertFalse(trimmer.check_t(10, slack=1))
        self.assertEqual(len(multipliers), 2)
        self.assertFalse(trimmer.check_t(10, slack=3))
        self.assertEqual(len(multipliers), 4)
        self.assertEqual(len(multipliers), len(set(multipliers)))
        self.assertEqual(trimmer.gen_trimmers_count, 4)


class SearchingTests(unittest.TestCase):
    N = 65537
    B = 256
    TAU = 13
    LOW = 40
    HIGH = 59

    def _oracle(self, reduced, multiplier):
        value = (self.TAU * reduced * multiplier) % self.N
        return 2 * self.B <= value < 3 * self.B

    def test_base_slices_tile_the_reduced_interval(self):
        for strategy in (STANDARD_COVERAGE, HALVING_FULL_GRID):
            with self.subTest(strategy=strategy):
                candidates = list(
                    search_candidates(
                        strategy,
                        self.N,
                        self.B,
                        self.TAU,
                        self.LOW,
                        self.HIGH,
                    )
                )
                covered = []
                for candidate in candidates:
                    covered.extend(
                        range(candidate.reduced_low, candidate.reduced_high + 1)
                    )
                expected = list(range(self.LOW, self.HIGH + 1))
                if strategy == HALVING_FULL_GRID:
                    covered = [value for value in covered if value % 2]
                    expected = [value for value in expected if value % 2]
                self.assertEqual(sorted(covered), expected)

    def test_candidate_preimages_match_direct_oracle(self):
        for strategy in (STANDARD_COVERAGE, HALVING_FULL_GRID):
            candidates = search_candidates(
                strategy,
                self.N,
                self.B,
                self.TAU,
                self.LOW,
                self.HIGH,
                slack=3,
            )
            for candidate in candidates:
                for reduced in range(self.LOW, self.HIGH + 1):
                    if strategy == HALVING_FULL_GRID and reduced % 2 == 0:
                        continue
                    expected = (
                        candidate.reduced_low
                        <= reduced
                        <= candidate.reduced_high
                    )
                    self.assertEqual(
                        self._oracle(reduced, candidate.multiplier),
                        expected,
                        (strategy, candidate, reduced),
                    )

    def test_retry_offsets_are_swept_across_all_slices(self):
        for strategy in (STANDARD_COVERAGE, HALVING_FULL_GRID):
            with self.subTest(strategy=strategy):
                candidates = list(
                    search_candidates(
                        strategy,
                        self.N,
                        self.B,
                        self.TAU,
                        self.LOW,
                        self.HIGH,
                        slack=3,
                    )
                )
                offset_rank = {
                    0: 0,
                    -1: 1,
                    1: 2,
                    -2: 3,
                    2: 4,
                    -3: 5,
                    3: 6,
                }
                ranks = [offset_rank[candidate.offset] for candidate in candidates]
                self.assertEqual(ranks, sorted(ranks))

                base_candidates = [
                    candidate for candidate in candidates if candidate.offset == 0
                ]
                self.assertGreater(len(base_candidates), 1)
                self.assertEqual(
                    [candidate.slice_index for candidate in base_candidates],
                    list(range(len(base_candidates))),
                )

    def test_asymmetric_retry_order_keeps_the_complete_radius(self):
        self.assertEqual(
            tuple(_asymmetric_offsets(4)),
            (0, -1, 2, -3, 4, 1, -2, 3, -4),
        )

    def test_sparse_grid_has_fewer_base_candidates_than_full_grid(self):
        B = 1024
        full = list(
            search_candidates(
                HALVING_FULL_GRID,
                self.N,
                B,
                self.TAU,
                self.LOW,
                self.HIGH,
            )
        )
        partial = list(
            search_candidates(
                HALVING_SPARSE_GRID,
                self.N,
                B,
                self.TAU,
                self.LOW,
                self.HIGH,
            )
        )
        self.assertGreater(len(full), len(partial))

    def test_sparse_grid_still_reports_exact_positive_preimages(self):
        B = 1024
        for strategy in (
            HALVING_SPARSE_GRID,
            HALVING_SPARSE_ASYMMETRIC,
        ):
            candidates = search_candidates(
                strategy,
                self.N,
                B,
                self.TAU,
                self.LOW,
                self.HIGH,
                slack=2,
            )
            for candidate in candidates:
                for reduced in range(self.LOW, self.HIGH + 1):
                    if reduced % 2 == 0:
                        continue
                    value = (
                        self.TAU * reduced * candidate.multiplier
                    ) % self.N
                    expected = 2 * B <= value < 3 * B
                    reported = (
                        candidate.reduced_low
                        <= reduced
                        <= candidate.reduced_high
                    )
                    self.assertEqual(expected, reported)

    def test_sparse_search_retries_then_completes_full_grid(self):
        modulus, B, tau, low, high, reduced = 65537, 1024, 13, 40, 59, 41
        def accepts(multiplier):
            value = tau * reduced * multiplier % modulus
            return 2 * B <= value < 3 * B

        with self.assertRaises(SearchFailure):
            run_search(
                accepts, HALVING_SPARSE_ASYMMETRIC, modulus, B, tau,
                low, high, slack=0, complete_sparse=False,
            )
        retry, retry_calls = run_search(
            accepts, HALVING_SPARSE_ASYMMETRIC, modulus, B, tau,
            low, high, slack=1, complete_sparse=False,
        )
        self.assertEqual(retry.offset, -1)
        self.assertEqual(retry_calls, 10)

        queried = []
        def recorded(multiplier):
            queried.append(multiplier)
            return accepts(multiplier)

        fallback, calls = run_search(
            recorded, HALVING_SPARSE_ASYMMETRIC, modulus, B, tau,
            low, high, slack=0, complete_sparse=True,
        )
        self.assertTrue(fallback.reduced_low <= reduced <= fallback.reduced_high)
        self.assertEqual(calls, len(queried))
        self.assertEqual(calls, len(set(queried)))


class BottomUpTests(unittest.TestCase):
    def test_delta_landmarks_try_local_then_broad_values(self):
        self.assertEqual(
            delta_landmarks(10, 30),
            (20, 19, 21, 15, 25, 10, 30),
        )
        self.assertEqual(delta_landmarks(4, 5), (4, 5))

    def test_public_preimages_match_direct_modular_multiplication(self):
        modulus, B = 101, 5
        for D in (4, 8):
            inverse_D = pow(D, -1, modulus)
            for delta in range(12):
                for k in range(1, D, 2):
                    symbolic = (delta + k * inverse_D) % modulus
                    for residue in range(1, D, 2):
                        with self.subTest(
                            D=D, delta=delta, k=k, residue=residue
                        ):
                            intervals = accepting_preimage(
                                modulus=modulus,
                                B=B,
                                D=D,
                                delta=delta,
                                k=k,
                                residue=residue,
                                low=1,
                                high=modulus - 1,
                                inverse_D=inverse_D,
                            )
                            actual = {
                                value
                                for part in intervals
                                for value in range(
                                    part.low, part.high + 1, part.D
                                )
                            }
                            expected = {
                                value
                                for value in range(1, modulus)
                                if value % D == residue
                                and modulus - 3 * B
                                < (value * symbolic) % modulus
                                <= modulus - 2 * B
                            }
                            self.assertEqual(actual, expected)

    def test_ambiguous_partial_query_is_not_certified(self):
        modulus, B, D = 101, 5, 4
        inverse_D = pow(D, -1, modulus)
        h = (D * inverse_D - 1) // modulus
        guesses = (1, 3)
        k = bottom_up._k_for_guess(D, 1, h, 1)
        self.assertTrue(
            accepting_preimage(
                modulus=modulus,
                B=B,
                D=D,
                delta=0,
                k=k,
                residue=1,
                low=1,
                high=modulus - 1,
                inverse_D=inverse_D,
            )
        )
        self.assertEqual(
            certified_preimage(
                modulus=modulus,
                B=B,
                D=D,
                delta=0,
                k=k,
                intended=1,
                guesses=guesses,
                low=1,
                high=modulus - 1,
                inverse_D=inverse_D,
            ),
            (),
        )

    def test_exact_parameters_can_be_found_outside_sufficient_r_range(self):
        params = list(
            parameter_candidates(
                8,
                65537,
                256,
                40,
                41,
                (1, 3, 5, 7),
                limit=3,
            )
        )
        self.assertTrue(params)
        bounds = proved_r_bounds(8, 65537, 256, 40, 41)
        self.assertTrue(
            bounds is None or not bounds[0] <= params[0].r <= bounds[1]
        )

    def test_large_first_round_then_binary_round(self):
        modulus, B, tau, reduced = 65537, 256, 13, 41

        def oracle(multiplier):
            value = (tau * reduced * multiplier) % modulus
            return 2 * B <= value < 3 * B

        recovery = BottomUpRecovery(
            modulus=modulus,
            B=B,
            tau=tau,
            low=40,
            high=41,
            start_bits=3,
            full_setting_limit=3,
        )
        result, calls = recovery.recover(oracle, target_bits=4)
        self.assertEqual(result, (tau * reduced) % 16)
        self.assertGreaterEqual(calls, 2)

    def test_best_effort_uses_partial_coverage_and_keeps_safe_hull(self):
        modulus, B, tau, reduced = 65537, 256, 13, 21

        def oracle(multiplier):
            value = (tau * reduced * multiplier) % modulus
            return 2 * B <= value < 3 * B

        proved = BottomUpRecovery(
            modulus=modulus,
            B=B,
            tau=tau,
            low=20,
            high=22,
            start_bits=4,
            strategy=PROVED,
            r_limit=32,
            full_setting_limit=7,
        )
        with self.assertRaises(BottomUpFailure):
            proved.recover(oracle, target_bits=4)

        best_effort = BottomUpRecovery(
            modulus=modulus,
            B=B,
            tau=tau,
            low=20,
            high=22,
            start_bits=4,
            strategy=BEST_EFFORT,
            r_limit=32,
            full_setting_limit=7,
        )
        result, calls = best_effort.recover(oracle, target_bits=4)
        self.assertEqual(result, (tau * reduced) % 16)
        self.assertGreater(calls, 0)
        self.assertLessEqual(best_effort.low, reduced)
        self.assertGreaterEqual(best_effort.high, reduced)
        self.assertEqual((best_effort.low, best_effort.high), (21, 21))

    def test_best_effort_tries_certified_partial_before_full(self):
        recovery = BottomUpRecovery(
            modulus=101,
            B=5,
            tau=1,
            low=1,
            high=1,
            start_bits=2,
            strategy=BEST_EFFORT,
            r_limit=1,
            full_setting_limit=1,
        )
        partial = bottom_up.BottomUpParameters(1, 0)
        preimage = (bottom_up.ResidueInterval(4, 1, 0, 0),)

        with (
            mock.patch.object(
                bottom_up,
                "partial_parameter_candidates",
                return_value=iter((partial,)),
            ),
            mock.patch.object(
                bottom_up,
                "certified_preimage",
                return_value=preimage,
            ),
            mock.patch.object(
                bottom_up,
                "parameter_candidates",
                side_effect=AssertionError(
                    "full containment ran before a successful partial query"
                ),
            ),
        ):
            result = recovery._recover_round(
                lambda _multiplier: True, 4, (1, 3)
            )

        self.assertEqual(result, 1)
        self.assertEqual(recovery.calls, 1)
        self.assertEqual((recovery.low, recovery.high), (1, 1))


if __name__ == "__main__":
    unittest.main()
