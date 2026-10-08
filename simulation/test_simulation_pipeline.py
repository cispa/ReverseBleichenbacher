from __future__ import annotations

import csv
import hashlib
import inspect
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import adapters
from analysis import (
    SEARCH_COVERAGE_EXHAUSTED,
    SEARCH_FALSE_NEGATIVE_EXHAUSTED,
    classify_search_transcript,
)
from key_policy import KEY_POLICY, KeyRecord, load_keys, selected_key_index
from oracle import CountingOracle
from reporting import reported_outcome, trimmer_missed_power_of_two
from schema import QUERY_COLUMNS, RESULT_COLUMNS
from trials import Trial, generate_message, make_trial
from validate_run import (
    ValidationError,
    failure_aware_median,
    validate_grid,
    validate_run,
)


REAL_KEYS = REPO_ROOT / "simulation" / "keys"


class MessageTests(unittest.TestCase):
    def test_known_answer_and_tls_layout(self):
        encoded, suffix = generate_message(20250930, 1024, 0)
        self.assertEqual(
            suffix.hex(),
            "d3a9e470a19b96b270ee5e67f3c4e32e58f3d7c813b719dcaf2e598b8280245a7997e523c5b16cf6a209789626ed",
        )
        self.assertEqual(len(encoded), 128)
        self.assertEqual(encoded[:2], b"\x00\x02")
        separator = len(encoded) - 49
        self.assertNotIn(0, encoded[2:separator])
        self.assertEqual(encoded[separator : separator + 3], b"\x00\x03\x03")
        self.assertEqual(encoded[-46:], suffix)

    def test_generator_does_not_touch_global_rng(self):
        random.seed(12345)
        expected = random.random()
        random.seed(12345)
        generate_message(9, 2048, 17)
        self.assertEqual(random.random(), expected)


class KeyTests(unittest.TestCase):
    def test_real_headerless_pool_includes_row_zero(self):
        keys = load_keys(REAL_KEYS, 1024)
        self.assertEqual(len(keys), 1000)
        self.assertEqual(keys[0].row, 0)
        self.assertEqual(keys[-1].row, 999)
        self.assertEqual(keys[0].n.bit_length(), 1024)

    def test_selector_is_seeded_with_replacement_and_rng_isolated(self):
        random.seed(88)
        expected = random.random()
        random.seed(88)
        indices = [selected_key_index(17, 1024, run, 1000) for run in range(2000)]
        self.assertEqual(random.random(), expected)
        self.assertTrue(all(0 <= index < 1000 for index in indices))
        self.assertLess(len(set(indices)), len(indices))
        self.assertEqual(indices, [selected_key_index(17, 1024, run, 1000) for run in range(2000)])

    def test_header_and_wrong_pool_size_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rsa-1024.csv").write_text("label,n,e,d\n")
            with self.assertRaisesRegex(ValueError, "headerless"):
                load_keys(root, 1024)


class OracleTests(unittest.TestCase):
    def _oracle(self, encoded: bytes, kind: str):
        return CountingOracle(int.from_bytes(encoded, "big"), 1 << 1024, 1024, kind)

    def test_oracle_taxonomy_and_phase_counts(self):
        base = bytearray(128)
        base[:2] = b"\x00\x02"
        base[2:10] = b"12345678"
        base[10:] = b"A" * 118
        self.assertTrue(self._oracle(base, "TTT")(1))
        self.assertTrue(self._oracle(base, "TFT")(1))
        self.assertFalse(self._oracle(base, "FFT")(1))
        base[20] = 0
        oracle = self._oracle(base, "FFT")
        oracle.set_phase("search")
        self.assertTrue(oracle(1))
        self.assertEqual(oracle.counts["search"], 1)
        self.assertEqual(oracle.total, 1)
        self.assertTrue(oracle.search_had_ttt_positive)

    def test_offline_search_transcript_classification(self):
        self.assertEqual(
            classify_search_transcript(1, 101, 5, [1, 2]),
            (SEARCH_COVERAGE_EXHAUSTED, 0, None),
        )
        self.assertEqual(
            classify_search_transcript(1, 101, 5, [1, 11, 12]),
            (SEARCH_FALSE_NEGATIVE_EXHAUSTED, 2, 2),
        )


class BoundaryTests(unittest.TestCase):
    def test_proof_search_strategy_defaults_to_sparse_asymmetric(self):
        config = adapters.public_config("proof", 1024, "TTT")
        self.assertEqual(
            config["search_strategy"], "halving_sparse_asymmetric"
        )
        self.assertEqual(config["search_slack"], 1)
        self.assertTrue(config["search_full_grid_fallback"])
        fft_config = adapters.public_config("proof", 2048, "FFT")
        self.assertFalse(fft_config["search_full_grid_fallback"])
        proved_config = adapters.public_config(
            "proof", 1024, "TTT", proof_search_strategy="standard_coverage"
        )
        self.assertEqual(proved_config["search_slack"], 0)
        self.assertFalse(proved_config["search_full_grid_fallback"])

    def test_proof_bottom_up_strategy_defaults_to_best_effort(self):
        config = adapters.public_config("proof", 1024, "TTT")
        self.assertEqual(config["bottom_up_strategy"], "best_effort")

    def test_proof_backend_loads_no_historical_attack_modules(self):
        before = set(sys.modules)
        config = adapters.public_config("proof", 1024, "TTT")
        self.assertNotIn("bottom_up_legacy_fallback", config)
        loaded_paths = {
            str(Path(module.__file__).resolve())
            for name, module in sys.modules.items()
            if name not in before
            if getattr(module, "__file__", None)
        }
        self.assertFalse(
            any(
                "/latency/attacker/reversebleichenbacher/" in path
                for path in loaded_paths
            )
        )

    def test_proof_search_strategy_is_explicit_in_public_config(self):
        config = adapters.public_config(
            "proof",
            1024,
            "TTT",
            proof_search_strategy="standard_coverage",
        )
        self.assertEqual(config["search_strategy"], "standard_coverage")

    def test_sparse_grid_and_search_slack_are_explicit_in_public_config(self):
        config = adapters.public_config(
            "proof",
            2048,
            "FFT",
            proof_search_strategy="halving_sparse_grid",
            proof_search_slack=5,
        )
        self.assertEqual(config["search_strategy"], "halving_sparse_grid")
        self.assertEqual(config["search_slack"], 5)

    def test_proof_bottom_up_strategy_is_explicit_in_public_config(self):
        config = adapters.public_config(
            "proof",
            1024,
            "TTT",
            proof_bottom_up_strategy="best_effort",
        )
        self.assertEqual(config["bottom_up_strategy"], "best_effort")
        self.assertEqual(config["bottom_up_start_bits"], 4)
        self.assertEqual(config["bottom_up_r_limit"], 2048)
        self.assertEqual(
            config["bottom_up_delta_policy"],
            "center-near-quartiles-extremes-v1",
        )
        self.assertEqual(
            config["bottom_up_query_order"],
            "certified-partial-then-full-v1",
        )

    def test_fft_search_radii_reflect_false_negative_rates(self):
        config_1024 = adapters.public_config("proof", 1024, "FFT")
        config_2048 = adapters.public_config("proof", 2048, "FFT")
        self.assertEqual(config_1024["search_slack"], 10)
        self.assertEqual(config_2048["search_slack"], 4)

    def test_proof_attack_api_has_no_plaintext(self):
        from reversebleichenbacher import ProofAttack

        self.assertEqual(
            tuple(inspect.signature(ProofAttack.attack).parameters),
            ("self", "oracle", "modulus"),
        )

    def test_explicit_sequential_executor_matches_callable_oracle(self):
        from reversebleichenbacher import SequentialExecutor

        trial = make_trial(load_keys(REAL_KEYS, 1024), 20261006, 1024, 0)
        direct_attack, _ = adapters._proof(1024, "TTT")
        wrapped_attack, _ = adapters._proof(1024, "TTT")
        direct_oracle = CountingOracle(trial.plaintext, trial.key.n, 1024, "TTT")
        wrapped_oracle = CountingOracle(trial.plaintext, trial.key.n, 1024, "TTT")
        executor = SequentialExecutor(wrapped_oracle)

        direct_result, direct_stats = direct_attack.attack(direct_oracle, trial.key.n)
        wrapped_result, wrapped_stats = wrapped_attack.attack(executor, trial.key.n)

        self.assertEqual(wrapped_result, direct_result)
        self.assertEqual(wrapped_stats.total_calls, direct_stats.total_calls)
        self.assertEqual(wrapped_oracle.counts, direct_oracle.counts)
        self.assertEqual(executor.submitted_queries, wrapped_oracle.total)

    def test_adapter_passes_only_oracle_and_modulus(self):
        calls = []

        class FakeAttack:
            tau_found = 7

            def attack(self, *args):
                calls.append(args)
                return 0, None

        key = KeyRecord(3, 0, (1 << 1023) + 643, 65537, 1)
        encoded, suffix = generate_message(1, 1024, 0)
        trial = Trial(0, 3, key, encoded, int.from_bytes(encoded, "big"), suffix)
        diagnostics = {
            "tau_available": 1,
            "trimmer_has_divisor": 0,
            "trimmer_detectable": None,
        }
        with mock.patch.object(adapters, "_proof", return_value=(FakeAttack(), {})), mock.patch.object(
            adapters, "trimmer_report", return_value=diagnostics
        ):
            row = adapters.run_trial("proof", trial, "TTT", 1024)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]), 2)
        self.assertIsInstance(calls[0][0], CountingOracle)
        self.assertEqual(calls[0][1], key.n)
        self.assertEqual(row["outcome"], "wrong_result")

    def test_offline_reporter_cannot_add_queries(self):
        class FakeAttack:
            tau_found = 1

            def attack(self, oracle, modulus):
                oracle.set_phase("search")
                oracle(1)
                return 0, None

        key = KeyRecord(2, 0, (1 << 1023) + 643, 65537, 1)
        encoded, suffix = generate_message(2, 1024, 0)
        trial = Trial(0, 2, key, encoded, int.from_bytes(encoded, "big"), suffix)

        def malicious_report(*args, **kwargs):
            return {"tau_available": 1, "trimmer_has_divisor": 0, "trimmer_detectable": None}

        with mock.patch.object(adapters, "_proof", return_value=(FakeAttack(), {})), mock.patch.object(
            adapters, "trimmer_report", side_effect=malicious_report
        ):
            row = adapters.run_trial("proof", trial, "TTT", 1024)
        self.assertEqual(row["total_queries"], 1)
        self.assertEqual(row["search_queries"], 1)

    def test_expected_failure_keeps_phase_queries(self):
        class BleichenBacherException(Exception):
            pass

        class FakeAttack:
            tau_found = 1

            def attack(self, oracle, modulus):
                oracle.set_phase("trimmer")
                oracle(1)
                raise BleichenBacherException("no trimmer")

        key = KeyRecord(2, 0, (1 << 1023) + 643, 65537, 1)
        encoded, suffix = generate_message(2, 1024, 0)
        trial = Trial(0, 2, key, encoded, int.from_bytes(encoded, "big"), suffix)
        diagnostics = {
            "tau_available": 3,
            "trimmer_has_divisor": 1,
            "trimmer_detectable": 0,
        }
        with mock.patch.object(adapters, "_proof", return_value=(FakeAttack(), {})), mock.patch.object(
            adapters, "trimmer_report", return_value=diagnostics
        ):
            row = adapters.run_trial("proof", trial, "TTT", 1024)
        self.assertEqual(row["outcome"], "trimmer_no_multiplier")
        self.assertEqual(row["trimmer_queries"], 1)
        self.assertEqual(row["total_queries"], 1)

    def test_detailed_bottom_up_error_keeps_bottom_up_classification(self):
        class BleichenBacherException(Exception):
            pass

        class FakeAttack:
            tau_found = 3

            def attack(self, oracle, modulus):
                oracle.set_phase("bottom_up")
                oracle(1)
                error = BleichenBacherException("partial coverage exhausted")
                error.error_type = "BottomUpCoverageExhausted"
                raise error

        key = KeyRecord(2, 0, (1 << 1023) + 643, 65537, 1)
        encoded, suffix = generate_message(2, 1024, 0)
        trial = Trial(0, 2, key, encoded, int.from_bytes(encoded, "big"), suffix)
        diagnostics = {
            "tau_available": 3,
            "trimmer_has_divisor": 1,
            "trimmer_detectable": None,
        }
        with mock.patch.object(
            adapters, "_proof", return_value=(FakeAttack(), {})
        ), mock.patch.object(
            adapters, "trimmer_report", return_value=diagnostics
        ):
            row = adapters.run_trial("proof", trial, "TTT", 1024)
        self.assertEqual(row["outcome"], "bottom_up_failed")
        self.assertEqual(row["step"], "bottom_up")
        self.assertEqual(row["error_type"], "BottomUpCoverageExhausted")
        self.assertEqual(row["bottom_up_queries"], 1)
        self.assertEqual(row["total_queries"], 1)

    def test_missed_power_of_two_is_classified_only_after_search_aborts(self):
        class BleichenBacherException(Exception):
            pass

        class FakeAttack:
            tau_found = 2

            def attack(self, oracle, modulus):
                oracle.set_phase("search")
                oracle(1)
                raise BleichenBacherException("search exhausted")

        key = KeyRecord(2, 0, (1 << 1023) + 643, 65537, 1)
        encoded, _suffix = generate_message(2, 1024, 0)
        encoded = encoded[:-1] + b"\x04"
        trial = Trial(0, 2, key, encoded, int.from_bytes(encoded, "big"), encoded[-46:])
        diagnostics = {
            "tau_available": 4,
            "trimmer_has_divisor": 1,
            "trimmer_detectable": None,
        }
        with mock.patch.object(
            adapters, "_proof", return_value=(FakeAttack(), {})
        ), mock.patch.object(
            adapters, "trimmer_report", return_value=diagnostics
        ):
            row = adapters.run_trial("proof", trial, "FFT", 1024)
        self.assertEqual(row["outcome"], "trimmer_missed_power_of_two")
        self.assertEqual(row["step"], "search")
        self.assertEqual(row["search_queries"], 1)

    def test_proof_search_failure_reports_coverage_or_false_negative(self):
        class BleichenBacherException(Exception):
            pass

        class FakeAttack:
            tau_found = 3

            def __init__(self, multiplier):
                self.multiplier = multiplier

            def attack(self, oracle, modulus):
                oracle.set_phase("search")
                oracle(self.multiplier)
                raise BleichenBacherException("search exhausted")

        key = KeyRecord(2, 0, (1 << 1023) + 643, 65537, 1)
        encoded, _suffix = generate_message(2, 1024, 0)
        encoded = bytearray(encoded)
        encoded[2] = 0  # TTT-conforming, but TFT rejects the prefix.
        encoded[-1] |= 1
        encoded = bytes(encoded)
        trial = Trial(0, 2, key, encoded, int.from_bytes(encoded, "big"), encoded[-46:])
        diagnostics = {
            "tau_available": 3,
            "trimmer_has_divisor": 1,
            "trimmer_detectable": None,
        }
        for oracle_type, multiplier, expected in (
            ("TTT", 0, SEARCH_COVERAGE_EXHAUSTED),
            ("TFT", 1, SEARCH_FALSE_NEGATIVE_EXHAUSTED),
        ):
            with self.subTest(oracle=oracle_type), mock.patch.object(
                adapters, "_proof", return_value=(FakeAttack(multiplier), {})
            ), mock.patch.object(
                adapters, "trimmer_report", return_value=diagnostics
            ):
                row = adapters.run_trial("proof", trial, oracle_type, 1024)
            self.assertEqual(row["outcome"], expected)
            self.assertEqual(row["step"], "search")


class ReportingTests(unittest.TestCase):
    def test_power_of_two_cause_requires_divisibility_and_even_quotient(self):
        self.assertTrue(trimmer_missed_power_of_two(60, 6))
        self.assertFalse(trimmer_missed_power_of_two(42, 6))
        self.assertFalse(trimmer_missed_power_of_two(41, 6))
        self.assertEqual(
            reported_outcome("proof", "search_failed", 60, 6),
            "trimmer_missed_power_of_two",
        )
        self.assertEqual(
            reported_outcome("proof", "search_failed", 42, 6),
            "search_failed",
        )
        self.assertEqual(
            reported_outcome("proof", "bottom_up_failed", 60, 6),
            "trimmer_missed_power_of_two",
        )
        self.assertEqual(
            reported_outcome("capol", "search_failed", 60, 6),
            "search_failed",
        )


def _valid_row(run=0, key_index=4, outcome="ok"):
    row = {column: "" for column in RESULT_COLUMNS}
    row.update(
        run=run,
        key_index=key_index,
        outcome=outcome,
        step="done" if outcome == "ok" else "harness",
        correct=int(outcome == "ok"),
        tau_found=3,
        tau_available=3,
        trimmer_has_divisor=1,
        total_queries=10,
        trimmer_queries=2,
        search_queries=3,
        other_queries=0,
        bottom_up_queries=5,
    )
    if outcome != "ok":
        row.update(error_type="TestError", error_message="test failure")
    return row


class ValidatorTests(unittest.TestCase):
    def _cell(self, rows):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        metadata = {
            "schema_version": 1,
            "key_policy": KEY_POLICY,
            "key_pool_size": 1000,
            "nr_experiments": len(rows),
        }
        (root / "metadata.json").write_text(json.dumps(metadata))
        with (root / "results.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        return temporary, root

    def test_single_mixed_result_file_validates(self):
        failure = _valid_row(1, 9, "trimmer_no_divisor")
        failure.update(
            step="trimmer",
            tau_found=1,
            tau_available=1,
            trimmer_has_divisor=0,
            trimmer_detectable="",
            search_queries=0,
            bottom_up_queries=0,
            total_queries=2,
        )
        temporary, root = self._cell([_valid_row(), failure])
        self.addCleanup(temporary.cleanup)
        report = validate_run(root)
        self.assertEqual(report["outcomes"]["ok"], 1)

    def test_theorem_eligible_ttt_coverage_miss_blocks_publication(self):
        row = _valid_row(0, 4, SEARCH_COVERAGE_EXHAUSTED)
        row.update(
            step="search", tau_found=13, tau_available=13,
            total_queries=5, trimmer_queries=2, search_queries=3,
            other_queries=0, bottom_up_queries=0,
        )
        temporary, root = self._cell([row])
        self.addCleanup(temporary.cleanup)
        metadata = json.loads((root / "metadata.json").read_text())
        metadata.update(
            oracle="TTT", implementation="proof",
            algorithm_config={"search_full_grid_fallback": True},
        )
        (root / "metadata.json").write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValidationError, "ttt_coverage_after_full_grid"):
            validate_run(root, require_publication_ready=True)

    def test_query_total_mutation_fails(self):
        row = _valid_row()
        row["total_queries"] = 11
        temporary, root = self._cell([row])
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValidationError, "do not sum"):
            validate_run(root)

    def test_missed_power_of_two_retains_search_step_and_queries(self):
        row = _valid_row(0, 4, "trimmer_missed_power_of_two")
        row.update(
            step="search",
            total_queries=5,
            trimmer_queries=2,
            search_queries=3,
            other_queries=0,
            bottom_up_queries=0,
            trimmer_detectable="",
        )
        temporary, root = self._cell([row])
        self.addCleanup(temporary.cleanup)
        report = validate_run(root)
        self.assertEqual(
            report["outcomes"]["trimmer_missed_power_of_two"], 1
        )

    def test_missed_power_of_two_retains_bottom_up_step_and_queries(self):
        row = _valid_row(0, 4, "trimmer_missed_power_of_two")
        row.update(
            step="bottom_up",
            total_queries=10,
            trimmer_queries=2,
            search_queries=3,
            other_queries=0,
            bottom_up_queries=5,
            trimmer_detectable="",
        )
        temporary, root = self._cell([row])
        self.addCleanup(temporary.cleanup)
        report = validate_run(root)
        self.assertEqual(
            report["outcomes"]["trimmer_missed_power_of_two"], 1
        )

    def test_paper_median_uses_higher_central_rank(self):
        rows = [
            {"outcome": "ok", "total_queries": "10"},
            {"outcome": "ok", "total_queries": "20"},
            {"outcome": "ok", "total_queries": "30"},
            {"outcome": "ok", "total_queries": "40"},
        ]
        self.assertEqual(failure_aware_median(rows, 4), 30)
        rows[2]["outcome"] = "failed"
        rows[3]["outcome"] = "failed"
        self.assertIsNone(failure_aware_median(rows, 4))

    def test_schema_has_no_round_trip_or_batch_fields(self):
        self.assertFalse(any("round" in field or "batch" in field for field in RESULT_COLUMNS))
        self.assertEqual(
            QUERY_COLUMNS,
            ("trimmer_queries", "search_queries", "other_queries", "bottom_up_queries"),
        )


class ResumeTests(unittest.TestCase):
    def test_relocated_checkout_resumes_old_absolute_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            relocated = root / "relocated"
            copied_script = original / "simulation"
            copied_keys = original / "simulation" / "keys"
            shutil.copytree(HERE, copied_script,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            shutil.copytree(REPO_ROOT / "reversebleichenbacher",
                            original / "reversebleichenbacher",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            grid_relative = Path("simulation/results/moved")
            subprocess.run(
                [sys.executable, str(copied_script / "run_simulations.py"),
                 "--implementations", "proof,capol", "--oracles", "TTT",
                 "--bits", "1024", "--experiments", "1", "--processes", "1",
                 "--run-id", "moved"],
                cwd=original, check=True, capture_output=True, text=True,
            )
            grid = original / grid_relative
            manifest_path = grid / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["keys_dir"], "simulation/keys")
            self.assertIn("1024", manifest["key_files_sha256"])
            self.assertEqual(manifest["cells"][0]["validation"]["cell"], "proof_TTT_1024")
            self.assertNotIn(str(original), json.dumps(manifest))
            proof_metadata_path = grid / "proof_TTT_1024" / "metadata.json"
            proof_metadata = json.loads(proof_metadata_path.read_text())
            self.assertEqual(proof_metadata["key_file"],
                             "simulation/keys/rsa-1024.csv")
            capol_dir = grid / "capol_TTT_1024"
            original_capol_hash = hashlib.sha256(
                (capol_dir / "results.csv").read_bytes()
            ).hexdigest()

            # Emulate a grid produced before paths became relative.
            manifest["keys_dir"] = str(copied_keys)
            manifest["cells"][0]["validation"]["cell"] = str(grid / "proof_TTT_1024")
            proof_metadata["key_file"] = str(copied_keys / "rsa-1024.csv")
            proof_metadata_path.write_text(json.dumps(proof_metadata))
            shutil.rmtree(capol_dir)
            manifest["cells"][1]["status"] = "running"
            manifest["cells"][1].pop("validation")
            manifest["cells"][1].pop("results_sha256")
            manifest["status"] = "running"
            manifest_path.write_text(json.dumps(manifest))

            shutil.move(original, relocated)
            relocated_keys = relocated / "simulation/keys/rsa-1024.csv"
            original_keys = relocated_keys.read_bytes()
            relocated_keys.write_bytes(b"1" + original_keys[1:])
            rejected = subprocess.run(
                [sys.executable,
                 str(relocated / "simulation/run_simulations.py"),
                 "--resume", "moved", "--out", str(relocated / grid_relative.parent),
                 "--dry-run"],
                cwd=relocated, capture_output=True, text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("differs from the original key pool", rejected.stderr)
            relocated_keys.write_bytes(original_keys)
            subprocess.run(
                [sys.executable,
                 str(relocated / "simulation/run_simulations.py"),
                 "--resume", "moved", "--out", str(relocated / grid_relative.parent)],
                cwd=relocated, check=True, capture_output=True, text=True,
            )
            resumed_grid = relocated / grid_relative
            self.assertEqual(
                hashlib.sha256((resumed_grid / "capol_TTT_1024" / "results.csv").read_bytes()).hexdigest(),
                original_capol_hash,
            )
            validate_grid(resumed_grid, require_publication_ready=True)

    def test_resume_preserves_completed_cell_and_reruns_empty_interrupted_cell(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = HERE / "run_simulations.py"
            command = [
                sys.executable, str(script),
                "--implementations", "proof,capol",
                "--oracles", "TTT", "--bits", "1024",
                "--experiments", "2", "--processes", "1",
                "--master-seed", "20261006",
                "--keys-dir", str(REAL_KEYS),
                "--out", str(root), "--run-id", "resume-test",
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            grid = root / "resume-test"
            manifest_path = grid / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            completed_path = grid / "proof_TTT_1024" / "results.csv"
            original_hash = hashlib.sha256(completed_path.read_bytes()).hexdigest()

            interrupted = grid / "capol_TTT_1024"
            shutil.rmtree(interrupted)
            interrupted.mkdir()
            cell = manifest["cells"][1]
            cell["status"] = "running"
            cell.pop("validation")
            cell.pop("results_sha256")
            manifest["status"] = "running"
            manifest.pop("finished_at")
            manifest_path.write_text(json.dumps(manifest))
            before_plan = manifest_path.read_bytes()

            resume_command = [
                sys.executable, str(script), "--resume", "resume-test",
                "--out", str(root),
            ]
            partial_file = interrupted / "partial.csv"
            partial_file.write_text("interrupted output")
            blocked = subprocess.run(
                resume_command, capture_output=True, text=True,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("not empty", blocked.stderr)
            self.assertEqual(manifest_path.read_bytes(), before_plan)
            self.assertTrue(partial_file.is_file())
            partial_file.unlink()

            plan = subprocess.run(
                [*resume_command, "--dry-run"],
                check=True, capture_output=True, text=True,
            )
            self.assertIn("# run capol_TTT_1024", plan.stdout)
            self.assertEqual(manifest_path.read_bytes(), before_plan)
            self.assertTrue(interrupted.is_dir())

            subprocess.run(resume_command, check=True, capture_output=True, text=True)
            after = json.loads(manifest_path.read_text())
            self.assertEqual(after["status"], "complete")
            self.assertEqual([c["status"] for c in after["cells"]], ["complete", "complete"])
            self.assertEqual(
                hashlib.sha256(completed_path.read_bytes()).hexdigest(), original_hash
            )
            self.assertEqual(after["resume_history"][0]["incomplete_cells"], ["capol_TTT_1024"])
            validate_grid(grid, require_publication_ready=True)

            recovered_hash = hashlib.sha256((interrupted / "results.csv").read_bytes()).hexdigest()
            after["status"] = "running"
            after["cells"][1]["status"] = "running"
            after["cells"][1].pop("validation")
            after["cells"][1].pop("results_sha256")
            manifest_path.write_text(json.dumps(after))
            recovered = subprocess.run(
                resume_command, check=True, capture_output=True, text=True,
            )
            self.assertIn("# recover capol_TTT_1024", recovered.stdout)
            self.assertEqual(
                hashlib.sha256((interrupted / "results.csv").read_bytes()).hexdigest(),
                recovered_hash,
            )
            validate_grid(grid, require_publication_ready=True)

            complete_manifest = manifest_path.read_bytes()
            subprocess.run(resume_command, check=True, capture_output=True, text=True)
            self.assertEqual(manifest_path.read_bytes(), complete_manifest)


if __name__ == "__main__":
    unittest.main()
