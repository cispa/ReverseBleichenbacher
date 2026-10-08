"""Check that short runs keep failures in the Figure 5 summary."""

import json
import math
import tempfile
import unittest
from pathlib import Path

from latency.analyze_figure5 import summarize, summarize_failure_aware


class Figure5AnalysisTests(unittest.TestCase):
    def test_algorithm_completion_without_tls_handshake_is_failure(self):
        records = [{"success": False, "stats": {"result": "ok", "runtime": 4.0}}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parallel_1.json"
            path.write_text(json.dumps(records), encoding="utf-8")
            conditional = summarize(path, expected_attempts=1)
            failure_aware = summarize_failure_aware(path, expected_attempts=1)

        self.assertEqual(conditional["successful"], 0)
        self.assertEqual(failure_aware["noncompletion"], 1)
        self.assertTrue(math.isinf(failure_aware["median_s"]))

    def test_short_run_uses_its_count_and_retains_noncompletion(self):
        records = [
            {"success": True, "stats": {"runtime": 8.0}},
            {"success": False, "stats": {"error": "search exhausted"}},
            {"success": True, "stats": {"runtime": 12.0}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parallel_10.json"
            path.write_text(json.dumps(records), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "expected 100 attempts"):
                summarize(path)

            conditional = summarize(path, expected_attempts=3)
            failure_aware = summarize_failure_aware(path, expected_attempts=3)

        self.assertEqual(conditional["successful"], 2)
        self.assertEqual(conditional["median_s"], 10.0)
        self.assertEqual((conditional["q1_s"], conditional["q3_s"]), (8.0, 12.0))
        self.assertEqual(failure_aware["included"], 3)
        self.assertEqual(failure_aware["noncompletion"], 1)
        self.assertEqual(failure_aware["success_pct"], 200 / 3)
        self.assertEqual(failure_aware["median_s"], 12.0)


if __name__ == "__main__":
    unittest.main()
