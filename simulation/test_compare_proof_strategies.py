from __future__ import annotations

import unittest

from .compare_proof_strategies import (
    ComparisonError,
    _check_cell_metadata,
    summarize_pair,
)


def _row(run, key, outcome, total, search, bottom):
    return {
        "run": run,
        "key_index": key,
        "outcome": outcome,
        "total_queries": total,
        "search_queries": search,
        "bottom_up_queries": bottom,
    }


class StrategyComparisonTests(unittest.TestCase):
    def test_summary_is_paired_and_failure_aware(self):
        standard = [
            _row(0, 10, "ok", 100, 40, 20),
            _row(1, 11, "search_failed", 80, 60, 0),
            _row(2, 12, "ok", 140, 70, 30),
            _row(3, 13, "bottom_up_failed", 160, 50, 70),
        ]
        halving = [
            _row(0, 10, "ok", 70, 10, 20),
            _row(1, 11, "ok", 120, 30, 40),
            _row(2, 12, "search_failed", 90, 60, 0),
            _row(3, 13, "bottom_up_failed", 150, 40, 70),
        ]
        summary, failures, transitions = summarize_pair(
            standard, halving, "FFT", 1024
        )
        self.assertEqual(summary["standard_successes"], 2)
        self.assertEqual(summary["halving_successes"], 2)
        self.assertEqual(summary["both_succeeded"], 1)
        self.assertEqual(summary["standard_only_succeeded"], 1)
        self.assertEqual(summary["halving_only_succeeded"], 1)
        # Exactly half successful means the upper failure-aware median is the
        # first failure, hence infinity (represented as None).
        self.assertIsNone(summary["standard_failure_aware_median_queries"])
        self.assertIsNone(summary["halving_failure_aware_median_queries"])
        self.assertEqual(
            summary["standard_success_only_upper_median_queries"], 140
        )
        self.assertEqual(
            summary["halving_success_only_upper_median_queries"], 120
        )
        self.assertEqual(
            summary["paired_both_success_upper_median_total_query_delta"], -30
        )
        self.assertTrue(any(row["outcome"] == "search_failed" for row in failures))
        self.assertTrue(
            any(
                row["standard_outcome"] == "ok"
                and row["halving_outcome"] == "search_failed"
                and row["count"] == 1
                for row in transitions
            )
        )

    def test_pairing_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ComparisonError, "pairing differs"):
            summarize_pair(
                [_row(0, 10, "ok", 1, 1, 0)],
                [_row(0, 99, "ok", 1, 1, 0)],
                "TTT",
                1024,
            )

    def test_bundled_variant_requires_explicit_opt_in(self):
        common = {
            "implementation": "proof",
            "oracle": "FFT",
            "bits": 2048,
            "nr_experiments": 1000,
            "master_seed": 20261006,
            "message_generator": "bleichenbacher-simulation-v1",
            "key_policy": "seeded-with-replacement-v1",
            "key_pool_size": 1000,
            "key_file": "rsa-2048.csv",
        }
        standard = {
            **common,
            "algorithm_config": {
                "search_strategy": "standard_coverage",
                "bottom_up_strategy": "proved",
            },
        }
        optimized = {
            **common,
            "algorithm_config": {
                "search_strategy": "halving_sparse_asymmetric",
                "bottom_up_strategy": "best_effort",
            },
        }
        with self.assertRaisesRegex(ComparisonError, "beyond search strategy"):
            _check_cell_metadata(
                standard, optimized, allow_bundled_variant=False
            )
        _check_cell_metadata(
            standard, optimized, allow_bundled_variant=True
        )


if __name__ == "__main__":
    unittest.main()
