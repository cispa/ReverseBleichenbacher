"""Profile one reproducible parallel attack against the Docker TLS oracle.

Run inside the attacker container, with the working directory set to the
ignored tlslite-ng checkout. The output separates main-process work from
worker CPU and elapsed TLS query time. Profiling slightly changes runtimes;
use the normal evaluation runner for performance measurements.
"""

import argparse
import cProfile
import json
import pstats
import random
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

import tls_attack
from diagnose_schedules import make_message
from tls_attack import SharedTLSAttack, TLSBatchExecutor
from tls_transport import TLSOracle, get_rsa_from_server, global_query, make_cke_prefix


LAST_ORACLE = None
LAST_EXECUTOR = None
PROFILE_WORKERS = 128
PROFILE_EXECUTOR = "process"


def timed_global_query(*args):
    started = time.perf_counter()
    cpu_clock = time.thread_time if PROFILE_EXECUTOR == "thread" else time.process_time
    cpu_started = cpu_clock()
    accepted = global_query(*args)
    return accepted, time.perf_counter() - started, cpu_clock() - cpu_started


class ProfileTLSOracle(TLSOracle):
    def __init__(self, *args):
        global LAST_ORACLE
        super().__init__(*args)
        if PROFILE_WORKERS != self.workers or PROFILE_EXECUTOR == "thread":
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.workers = PROFILE_WORKERS
            executor_class = (
                ThreadPoolExecutor if PROFILE_EXECUTOR == "thread"
                else ProcessPoolExecutor
            )
            self.executor = executor_class(max_workers=self.workers)
        self.profile = defaultdict(float)
        LAST_ORACLE = self

    def query(self, multiplier, batch=False):
        started = time.perf_counter()
        try:
            return super().query(multiplier, batch=batch)
        finally:
            self.profile["sequential_query_wall_s"] += time.perf_counter() - started
            self.profile["sequential_queries"] += 1

    def submit(self, work):
        started = time.perf_counter()
        self.round_trips += (len(work) + self.workers - 1) // self.workers
        futures = []
        for multiplier, candidate in work:
            self._count()
            future = self.executor.submit(
                timed_global_query,
                multiplier, self.e, self.N, self.C, self.modulus_bits,
                self.good, self.message_flow, self.ip, self.port,
                self.client_hello, self.server_version,
                self.client_key_exchange_prefix,
            )
            future.extra = candidate
            futures.append(future)
        self.profile["submit_wall_s"] += time.perf_counter() - started
        self.profile["batches"] += 1
        self.profile["submitted_queries"] += len(futures)
        return futures

    def as_completed(self, work):
        last = time.perf_counter()
        for future in as_completed(work):
            self.profile["wait_for_reply_s"] += time.perf_counter() - last
            if not future.cancelled():
                accepted, worker_wall, worker_cpu = future.result()
                self.profile["completed_queries"] += 1
                self.profile["worker_wall_sum_s"] += worker_wall
                self.profile["worker_cpu_sum_s"] += worker_cpu
                yield future.extra, accepted
            last = time.perf_counter()


class ProfileBatchExecutor(TLSBatchExecutor):
    def __init__(self, oracle):
        global LAST_EXECUTOR
        super().__init__(oracle)
        self.phase_wall = defaultdict(float)
        self.current_phase = None
        self.phase_started = None
        LAST_EXECUTOR = self

    def set_phase(self, phase):
        self.finish_phase()
        super().set_phase(phase)
        self.current_phase = phase
        self.phase_started = time.perf_counter()

    def finish_phase(self):
        if self.current_phase is not None:
            self.phase_wall[self.current_phase] += (
                time.perf_counter() - self.phase_started
            )
            self.current_phase = None


def main():
    global PROFILE_WORKERS, PROFILE_EXECUTOR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--message-index", type=int, default=2)
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--executor", choices=("process", "thread"),
                        default="process")
    parser.add_argument("--output", type=Path, default=Path("parallel_profile.json"))
    parser.add_argument("--cprofile", type=Path,
                        help="Optional path for main-process cProfile data")
    args = parser.parse_args()
    if args.message_index < 0 or args.workers < 1:
        parser.error("--message-index must be nonnegative and --workers positive")
    PROFILE_WORKERS = args.workers
    PROFILE_EXECUTOR = args.executor

    rsa = get_rsa_from_server("server", 443)
    rng = random.Random(args.seed)
    for _ in range(args.message_index + 1):
        plaintext, suffix = make_message(rng, rsa.bits // 8)
    ciphertext = pow(plaintext, rsa.e, rsa.N)

    tls_attack.TLSOracle = ProfileTLSOracle
    tls_attack.TLSBatchExecutor = ProfileBatchExecutor
    attack = SharedTLSAttack(
        "server", 443, rsa, make_cke_prefix(rsa), parallel=True
    )

    profiler = cProfile.Profile() if args.cprofile else None
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    try:
        if profiler:
            profiler.enable()
        recovered = attack.decrypt(ciphertext)
        error = None
    except Exception as exc:
        recovered = None
        error = f"{type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if profiler:
            profiler.disable()
            profiler.dump_stats(str(args.cprofile))
    wall = time.perf_counter() - wall_started
    cpu = time.process_time() - cpu_started

    if LAST_EXECUTOR:
        LAST_EXECUTOR.finish_phase()
    stats_path = Path("results.json")
    stats = json.loads(stats_path.read_text()) if stats_path.exists() else None
    report = {
        "message_index": args.message_index,
        "workers": args.workers,
        "executor": args.executor,
        "correct": recovered == int.from_bytes(suffix, "big"),
        "error": error,
        "main_wall_s": wall,
        "main_cpu_s": cpu,
        "setup_wall_s": (
            wall - sum(LAST_EXECUTOR.phase_wall.values())
            if LAST_EXECUTOR else None
        ),
        "phase_wall_s": dict(LAST_EXECUTOR.phase_wall) if LAST_EXECUTOR else {},
        "transport": dict(LAST_ORACLE.profile) if LAST_ORACLE else {},
        "attack_stats": stats,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if profiler:
        pstats.Stats(profiler).sort_stats("cumulative").print_stats(18)


if __name__ == "__main__":
    main()
