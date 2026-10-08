"""Integration checks for the shared attack's parallel TLS schedule."""

from contextlib import closing
import json
import unittest
from unittest import mock

from reversebleichenbacher import ProofAttack, QueryResult
from reversebleichenbacher.bottom_up import BottomUpRecovery
from reversebleichenbacher.core import AttackConfig, ceil_div
from reversebleichenbacher.executor import execute_candidates
from reversebleichenbacher.search import (
    HALVING_FULL_GRID,
    SearchCandidate,
    run_search,
)
from tls_attack import SharedTLSAttack, TLSBatchExecutor
from tls_transport import global_recv_n


class ReorderedPlaintextExecutor:
    batch_size = 256

    def __init__(self, plaintext, modulus, B):
        self.plaintext = plaintext
        self.modulus = modulus
        self.B = B
        self.submitted_queries = 0
        self.phases = []

    def set_phase(self, phase):
        self.phases.append(phase)

    def accepts(self, multiplier):
        value = self.plaintext * multiplier % self.modulus
        return 2 * self.B <= value < 3 * self.B

    def query(self, multiplier):
        self.submitted_queries += 1
        return self.accepts(multiplier)

    def execute_batch(self, candidates):
        self.submitted_queries += len(candidates)
        for candidate in reversed(candidates):
            yield QueryResult(candidate, self.accepts(candidate.multiplier))


class SharedParallelTests(unittest.TestCase):
    def test_tls_setup_failure_is_recorded(self):
        rsa = mock.Mock(bits=2048, e=65537, N=(1 << 2048) - 159)
        attack = SharedTLSAttack("server", 443, rsa, b"prefix")
        with (
            mock.patch("tls_attack.TLSOracle", side_effect=TimeoutError("setup stalled")),
            mock.patch("tls_attack.open", mock.mock_open(), create=True) as output,
        ):
            with self.assertRaisesRegex(TimeoutError, "setup stalled"):
                attack.decrypt(123)

        stats = json.loads(
            "".join(call.args[0] for call in output().write.call_args_list)
        )
        self.assertEqual(stats["result"], "init")
        self.assertEqual(stats["exception_type"], "TimeoutError")
        self.assertEqual(stats["total_queries"], 0)

    def test_tls_record_read_stops_on_early_close(self):
        class ClosingSocket:
            def __init__(self):
                self.chunks = iter((b"ab", b""))

            def recv(self, _amount):
                return next(self.chunks)

        with self.assertRaisesRegex(ConnectionError, "closed during record"):
            global_recv_n(ClosingSocket(), 5)

    def test_premaster_secret_preserves_zeroes_and_internal_version_bytes(self):
        suffix = b"\x00" + b"\x01" * 20 + b"\x03\x03" + b"\x02" * 23
        self.assertEqual(len(suffix), 46)
        self.assertEqual(
            SharedTLSAttack.premaster_secret(int.from_bytes(suffix, "big")),
            b"\x03\x03" + suffix,
        )

    def test_full_attack_survives_out_of_order_batch_replies(self):
        modulus, B = 16777219, 65536
        plaintext = 13 * ((5 * B // 26) | 1)
        executor = ReorderedPlaintextExecutor(plaintext, modulus, B)
        attack = ProofAttack()
        attack.init_process(
            "FFT",
            32,
            AttackConfig("FFT", 32, t_slack=1, bs_slack=3),
            nr_bits=11,
            parallel=True,
        )

        recovered, stats = attack.attack(executor, modulus)

        self.assertEqual(recovered, plaintext % (1 << 11))
        self.assertEqual(executor.phases, ["trimmer", "search", "bottom_up"])
        self.assertEqual(stats.total_calls, executor.submitted_queries)
        self.assertGreater(stats.calls_trimmers, 0)
        self.assertGreater(stats.calls_improved_step2a, 0)
        self.assertGreater(stats.calls_bottom_up, 0)

    def test_bottom_up_uses_D0_16_then_ell_bit_batches(self):
        reduced = 0x5AB
        recovery = BottomUpRecovery(
            modulus=65537,
            B=256,
            tau=13,
            low=100,
            high=200,
            start_bits=4,
            batch_bits=4,
        )
        observed = []

        def recover_round(_executor, D, guesses):
            observed.append((D, guesses))
            self.assertIn(reduced % D, guesses)
            return reduced % D

        with mock.patch.object(recovery, "_recover_round", side_effect=recover_round):
            recovered, _ = recovery.recover(object(), target_bits=13)

        self.assertEqual(recovered, 13 * reduced % (1 << 13))
        self.assertEqual([D for D, _ in observed], [16, 256, 4096, 8192])
        self.assertEqual([len(guesses) for _, guesses in observed], [8, 16, 16, 2])

    def test_large_integer_search_and_batched_recovery(self):
        for bits in (1024, 2048):
            with self.subTest(bits=bits):
                B = 1 << (bits - 16)
                modulus = (1 << (bits - 8)) + 3
                tau = 13
                reduced = (5 * B // (2 * tau)) | 1
                plaintext = tau * reduced
                executor = ReorderedPlaintextExecutor(plaintext, modulus, B)

                candidate, _ = run_search(
                    executor,
                    HALVING_FULL_GRID,
                    modulus,
                    B,
                    tau,
                    ceil_div(2 * B, tau),
                    (3 * B - 1) // tau,
                    slack=1,
                )
                self.assertLessEqual(candidate.reduced_low, reduced)
                self.assertGreaterEqual(candidate.reduced_high, reduced)

                recovery = BottomUpRecovery(
                    modulus=modulus,
                    B=B,
                    tau=tau,
                    low=candidate.reduced_low,
                    high=candidate.reduced_high,
                    start_bits=4,
                    batch_bits=4,
                )
                recovered, _ = recovery.recover(executor, target_bits=11)
                self.assertEqual(recovered, plaintext % (1 << 11))

    def test_tls_batch_keeps_reply_labels_and_cancels_unused_work(self):
        class FakeOracle:
            calls = 1
            round_trips = 1

            def __init__(self):
                self.cancelled = False

            def submit(self, work):
                self.calls += len(work)
                self.round_trips += 1
                return work

            def query(self, multiplier):
                self.calls += 1
                self.round_trips += 1
                return multiplier == 11

            def as_completed(self, work):
                for multiplier, candidate in reversed(work):
                    yield candidate, multiplier == 11

            def cancel(self, work):
                self.cancelled = True

        oracle = FakeOracle()
        executor = TLSBatchExecutor(oracle)
        executor.set_phase("search")
        candidates = (
            SearchCandidate(7, 1, 2, 1, 2, 0, 0),
            SearchCandidate(11, 3, 4, 3, 2, 1, 0),
        )

        with closing(execute_candidates(executor, candidates)) as replies:
            first = next(replies)
            self.assertIs(first.candidate, candidates[1])
            self.assertTrue(first.accepted)

        self.assertTrue(oracle.cancelled)
        self.assertEqual(executor.submitted_queries, 2)
        self.assertEqual(executor.oracle_queries, {"init": 1, "search": 2})
        self.assertEqual(executor.round_trips, {"init": 1, "search": 1})


if __name__ == "__main__":
    unittest.main()
