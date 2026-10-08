"""Small adapters from common trials to the attack implementations."""

from __future__ import annotations

from oracle import CountingOracle
from analysis import SEARCH_COVERAGE_EXHAUSTED, SEARCH_FALSE_NEGATIVE_EXHAUSTED
from proof.bottom_up import DEFAULT_BOTTOM_UP_STRATEGY
from proof.search import DEFAULT_SEARCH_STRATEGY
from reporting import reported_outcome, trimmer_outcome, trimmer_report
from trials import Trial


IMPLEMENTATIONS = ("proof", "capol")


def _proof(
    bits: int,
    oracle_type: str,
    *,
    search_strategy: str = DEFAULT_SEARCH_STRATEGY,
    search_slack: int | None = None,
    bottom_up_strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
    bottom_up_r_limit: int = 2048,
):
    from proof import ProofAttack

    attack = ProofAttack(
        search_strategy=search_strategy,
        search_slack=search_slack,
        bottom_up_strategy=bottom_up_strategy,
        bottom_up_r_limit=bottom_up_r_limit,
    )
    params = attack.init_optimized(oracle_type, bits)
    attack.init_process(**params)
    return attack, attack.algorithm_config


def _capol(bits: int, oracle_type: str):
    from capol_baseline.bleichenbacher import CapolBleichenAttack

    attack = CapolBleichenAttack()
    params = attack.init_optimized(oracle_type, bits)
    attack.init_process(**params)
    config = {
        "oracle_type": oracle_type,
        "t_slack": attack.t_slack,
        "bs_slack": attack.bs_slack,
        "trimmer_values": attack.trimmer_values,
    }
    return attack, config


def _build_attack(
    implementation: str,
    bits: int,
    oracle_type: str,
    *,
    proof_search_strategy: str = DEFAULT_SEARCH_STRATEGY,
    proof_search_slack: int | None = None,
    proof_bottom_up_strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
    proof_bottom_up_r_limit: int = 2048,
) -> tuple[object, dict[str, object]]:
    if implementation not in IMPLEMENTATIONS:
        raise ValueError(f"unknown implementation: {implementation}")
    if implementation == "proof":
        return _proof(
            bits,
            oracle_type,
            search_strategy=proof_search_strategy,
            search_slack=proof_search_slack,
            bottom_up_strategy=proof_bottom_up_strategy,
            bottom_up_r_limit=proof_bottom_up_r_limit,
        )
    if implementation == "capol":
        return _capol(bits, oracle_type)
    raise ValueError(f"unknown implementation: {implementation}")


def public_config(
    implementation: str,
    bits: int,
    oracle_type: str,
    *,
    proof_search_strategy: str = DEFAULT_SEARCH_STRATEGY,
    proof_search_slack: int | None = None,
    proof_bottom_up_strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
    proof_bottom_up_r_limit: int = 2048,
) -> dict[str, object]:
    _attack, config = _build_attack(
        implementation,
        bits,
        oracle_type,
        proof_search_strategy=proof_search_strategy,
        proof_search_slack=proof_search_slack,
        proof_bottom_up_strategy=proof_bottom_up_strategy,
        proof_bottom_up_r_limit=proof_bottom_up_r_limit,
    )
    return config


def run_trial(
    implementation: str,
    trial: Trial,
    oracle_type: str,
    bits: int,
    *,
    proof_search_strategy: str = DEFAULT_SEARCH_STRATEGY,
    proof_search_slack: int | None = None,
    proof_bottom_up_strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
    proof_bottom_up_r_limit: int = 2048,
) -> dict[str, object]:
    """Run one attempt and report it; plaintext never enters attack methods."""
    attack, config = _build_attack(
        implementation,
        bits,
        oracle_type,
        proof_search_strategy=proof_search_strategy,
        proof_search_slack=proof_search_slack,
        proof_bottom_up_strategy=proof_bottom_up_strategy,
        proof_bottom_up_r_limit=proof_bottom_up_r_limit,
    )
    oracle = CountingOracle(trial.plaintext, trial.key.n, bits, oracle_type)
    recovered = None
    step = "done"
    error_type = ""
    error_message = ""

    try:
        result = attack.attack(oracle, trial.key.n)
        recovered = result[0]
    except Exception as exc:  # every requested attempt must become one row
        exception_class = type(exc).__name__
        error_type = getattr(exc, "error_type", type(exc).__name__)
        error_message = str(exc)
        if exception_class == "BleichenBacherException":
            step = {
                "trimmer": "trimmer",
                "search": "search",
                "other": "other",
                "bottom_up": "bottom_up",
            }.get(getattr(oracle, "_phase", ""), "harness")
        else:
            step = "harness"

    suffix_mask = (1 << (8 * 46)) - 1
    correct = recovered is not None and recovered & suffix_mask == int.from_bytes(
        trial.target_suffix, "big"
    )
    if recovered is not None:
        outcome = "ok" if correct else "wrong_result"
        if not correct:
            error_type = "wrong_result"
            error_message = "recovered value does not match the 46-byte PMS suffix"
    elif step == "trimmer":
        outcome = "trimmer_no_divisor"  # refined by the offline reporter below
    elif step == "search":
        if implementation == "proof":
            outcome = (
                SEARCH_FALSE_NEGATIVE_EXHAUSTED
                if oracle.search_had_ttt_positive
                else SEARCH_COVERAGE_EXHAUSTED
            )
        else:
            outcome = "search_failed"
    elif step == "other":
        outcome = "other_failed"
    elif step == "bottom_up":
        outcome = "bottom_up_failed"
    else:
        outcome = "internal_error"

    tau_found = getattr(attack, "tau_found", getattr(attack, "lcm", None))
    counts_before_reporting = oracle.counts
    try:
        diagnostics = trimmer_report(
            implementation,
            trial.plaintext,
            trial.key.n,
            bits,
            config,
            classify_multiplier=(step == "trimmer"),
        )
        if step == "trimmer":
            outcome = trimmer_outcome(diagnostics)
        outcome = reported_outcome(
            implementation, outcome, trial.plaintext, tau_found
        )
    except Exception as exc:
        diagnostics = {
            "tau_available": None,
            "trimmer_has_divisor": None,
            "trimmer_detectable": None,
        }
        outcome = "internal_error"
        step = "harness"
        error_type = type(exc).__name__
        error_message = f"offline reporter failed: {exc}"
        correct = False
    if oracle.counts != counts_before_reporting:
        raise AssertionError("offline reporting changed the oracle transcript")

    counts = oracle.counts
    return {
        "run": trial.run,
        "key_index": trial.key_index,
        "outcome": outcome,
        "step": step,
        "correct": int(correct),
        "error_type": error_type,
        "error_message": error_message,
        "tau_found": "" if tau_found is None else tau_found,
        **diagnostics,
        "total_queries": sum(counts.values()),
        "trimmer_queries": counts["trimmer"],
        "search_queries": counts["search"],
        "other_queries": counts["other"],
        "bottom_up_queries": counts["bottom_up"],
    }
