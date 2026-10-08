"""Self-contained implementation of the attack described in the paper.

The attack boundary receives only the public modulus and a query executor. The target
plaintext is deliberately unavailable here; it is used only by the simulation
adapter after the attack has finished, for correctness and failure reporting.
"""

from __future__ import annotations

from .bottom_up import (
    BEST_EFFORT,
    BEST_EFFORT_QUERY_ORDER,
    BOTTOM_UP_STRATEGIES,
    DEFAULT_BOTTOM_UP_STRATEGY,
    DELTA_POLICY,
    PROVED_QUERY_ORDER,
    BottomUpFailure,
    BottomUpRecovery,
)
from .core import (
    DEFAULT_TARGET_BITS,
    AttackConfig,
    AttackState,
    AttackStatistics,
    BleichenBacherException,
    PKCS1Bounds,
    ceil_div,
)
from .executor import QueryExecutor
from .search import (
    DEFAULT_SEARCH_STRATEGY,
    HALVING_SPARSE_ASYMMETRIC,
    SearchFailure,
    normalize_search_strategy,
    run_search,
)
from .trimmer import Trimmer, extend_power_of_two, power_two_slack


def _phase(executor: QueryExecutor, name: str) -> None:
    executor.set_phase(name)


class ProofAttack:
    def __init__(
        self,
        *,
        search_strategy: str = DEFAULT_SEARCH_STRATEGY,
        search_slack: int | None = None,
        search_full_grid_fallback: bool | None = None,
        bottom_up_strategy: str = DEFAULT_BOTTOM_UP_STRATEGY,
        bottom_up_start_bits: int = 4,
        bottom_up_batch_bits: int | None = None,
        bottom_up_r_limit: int = 2048,
        bottom_up_full_setting_limit: int | None = None,
    ):
        search_strategy = normalize_search_strategy(search_strategy)
        if search_slack is not None and search_slack < 0:
            raise ValueError("search_slack cannot be negative")
        if search_full_grid_fallback and search_strategy != HALVING_SPARSE_ASYMMETRIC:
            raise ValueError("full-grid fallback requires sparse asymmetric Search")
        if bottom_up_strategy not in BOTTOM_UP_STRATEGIES:
            raise ValueError(f"unknown Bottom-Up strategy: {bottom_up_strategy}")
        if bottom_up_start_bits < 2:
            raise ValueError("Bottom-Up start_bits must be at least 2")
        if bottom_up_batch_bits is not None and bottom_up_batch_bits < 1:
            raise ValueError("Bottom-Up batch_bits must be positive")
        if bottom_up_r_limit < 1:
            raise ValueError("Bottom-Up r limit must be positive")
        if (
            bottom_up_full_setting_limit is not None
            and bottom_up_full_setting_limit < 1
        ):
            raise ValueError("Bottom-Up full-setting limit must be positive")
        self._config = AttackConfig.optimized("FFT", 2048)
        self.nr_bits = DEFAULT_TARGET_BITS
        self.tau_found = 1
        self.search_strategy = search_strategy
        self._search_slack_override = search_slack
        self._search_full_grid_fallback_override = search_full_grid_fallback
        self.bottom_up_strategy = bottom_up_strategy
        self.bottom_up_start_bits = bottom_up_start_bits
        self._bottom_up_batch_bits_override = bottom_up_batch_bits
        self.bottom_up_batch_bits = bottom_up_batch_bits or 1
        self.bottom_up_r_limit = bottom_up_r_limit
        self._bottom_up_full_setting_limit = bottom_up_full_setting_limit

    def init_optimized(
        self, oracle: str, keylength_: int
    ) -> dict[str, object]:
        return {
            "oracle": oracle,
            "keylength_": keylength_,
            "config": AttackConfig.optimized(oracle, keylength_),
        }

    def init_process(
        self,
        oracle: str,
        keylength_: int,
        config: AttackConfig,
        nr_bits: int = DEFAULT_TARGET_BITS,
        parallel: bool = False,
    ) -> None:
        if oracle != config.oracle_type or keylength_ != config.keylength:
            raise ValueError("attack configuration does not match its parameters")
        self._config = config
        self.nr_bits = nr_bits
        self.bottom_up_batch_bits = (
            self._bottom_up_batch_bits_override or (4 if parallel else 1)
        )

    @property
    def configured_power_two_slack(self) -> int:
        return power_two_slack(self._config.t_slack)

    @property
    def configured_search_slack(self) -> int:
        if self._search_slack_override is not None:
            return self._search_slack_override
        if self._config.oracle_type == "FFT":
            # The optimized t_slack values give radii 10 and 4 for the
            # 1024- and 2048-bit experiments. Their 21 and 9 center-out
            # sweeps leave heuristic all-false probabilities below 0.01%
            # and 0.03%. Breadth-first scheduling keeps successful runs cheap.
            return 2 * (self._config.t_slack + 1)
        if self._config.oracle_type == "TFT":
            return self._config.t_slack + 1
        # The historical sparse base grid has gaps. One nearby odd numerator
        # reaches every coverage miss in the pinned TTT sample; run_search also
        # completes the full grid if this finite retry still misses.
        return 1 if self.search_strategy == HALVING_SPARSE_ASYMMETRIC else 0

    @property
    def configured_search_full_grid_fallback(self) -> bool:
        if self._search_full_grid_fallback_override is not None:
            return self._search_full_grid_fallback_override
        # Only the noiseless TTT oracle can use this fallback as a guaranteed
        # coverage completion. The existing finite FFT/TFT retry sweeps are
        # retained to avoid large all-negative tails by default.
        return (
            self._config.oracle_type == "TTT"
            and self.search_strategy == HALVING_SPARSE_ASYMMETRIC
        )

    @property
    def configured_bottom_up_full_setting_limit(self) -> int:
        if self._bottom_up_full_setting_limit is not None:
            return self._bottom_up_full_setting_limit
        if self._config.oracle_type == "FFT":
            legacy_limit = 6 * (self._config.t_slack + 1)
        else:
            legacy_limit = 3 * (self._config.t_slack + 1)
        # Always reach the complete seven-point per-r delta schedule.
        return max(7, legacy_limit)

    @property
    def bottom_up_delta_policy(self) -> str:
        return DELTA_POLICY

    @property
    def bottom_up_query_order(self) -> str:
        if self.bottom_up_strategy == BEST_EFFORT:
            return BEST_EFFORT_QUERY_ORDER
        return PROVED_QUERY_ORDER

    @property
    def algorithm_config(self) -> dict[str, object]:
        """Return the public parameters needed to reproduce this attack."""
        config = {
            "oracle_type": self._config.oracle_type,
            "t_slack": self._config.t_slack,
            "bs_slack": self._config.bs_slack,
            "trimmer_cutoff": self._config.trimmer_cutoff,
            "power_two_slack": self.configured_power_two_slack,
            "search_strategy": self.search_strategy,
            "search_slack": self.configured_search_slack,
            "search_full_grid_fallback": self.configured_search_full_grid_fallback,
            "bottom_up_strategy": self.bottom_up_strategy,
            "bottom_up_start_bits": self.bottom_up_start_bits,
            "bottom_up_r_limit": self.bottom_up_r_limit,
            "bottom_up_full_setting_limit": (
                self.configured_bottom_up_full_setting_limit
            ),
            "bottom_up_delta_policy": self.bottom_up_delta_policy,
            "bottom_up_query_order": self.bottom_up_query_order,
        }
        if self.bottom_up_batch_bits != 1:
            config["bottom_up_batch_bits"] = self.bottom_up_batch_bits
        return config

    def trimming_step(self, executor: QueryExecutor) -> tuple[int, int]:
        trimmer = Trimmer(
            modulus=self._state.n,
            B=self._state.B,
            config=self._config,
            executor=executor,
        )
        tau, calls = trimmer.generate_and_test()
        tau, extra_calls = extend_power_of_two(
            trimmer, tau, slack=self.configured_power_two_slack
        )
        calls += extra_calls
        self.tau_found = tau  # reporting only; the local value drives the attack
        if tau == 1:
            raise BleichenBacherException("No trimmers found (tau_found=1)")

        low, high, bound_calls = trimmer.find_low_high(tau)
        calls += bound_calls
        self._statistics.low = low
        self._statistics.high = high
        new_a = PKCS1Bounds.lower_bound(self._state.B) * low[1] // low[0]
        new_b = PKCS1Bounds.upper_bound(self._state.B) * high[1] // high[0] + 1
        self._state.update_interval(new_a, new_b)
        self._statistics.trim_value = (
            self._state.B - 1
        ) / self._state.interval_size
        return tau, calls

    def _execute_search(self, executor: QueryExecutor, tau: int) -> int:
        reduced_low = ceil_div(self._state.a, tau)
        reduced_high = self._state.b // tau
        try:
            candidate, calls = run_search(
                executor,
                self.search_strategy,
                self._state.n,
                self._state.B,
                tau,
                reduced_low,
                reduced_high,
                slack=self.configured_search_slack,
                complete_sparse=self.configured_search_full_grid_fallback,
            )
        except SearchFailure as exc:
            raise BleichenBacherException(str(exc)) from exc
        self._state.update_interval(
            max(self._state.a, candidate.reduced_low * tau),
            min(self._state.b, candidate.reduced_high * tau),
        )
        return calls

    def attack(self, executor: QueryExecutor, modulus: int):
        key_bytes = self._config.keylength // 8
        B = PKCS1Bounds.compute_B(key_bytes)
        lower, upper = PKCS1Bounds.initial_interval(B)
        self.tau_found = 1
        self._state = AttackState(lower, upper, modulus, B)
        self._statistics = AttackStatistics()
        phase = "init"

        try:
            phase = "trimmer"
            _phase(executor, "trimmer")
            tau, self._statistics.calls_trimmers = self.trimming_step(executor)

            phase = "search"
            _phase(executor, "search")
            self._statistics.calls_improved_step2a = self._execute_search(
                executor, tau
            )

            phase = "bottom_up"
            _phase(executor, "bottom_up")
            recovery = BottomUpRecovery(
                modulus=self._state.n,
                B=self._state.B,
                tau=tau,
                low=ceil_div(self._state.a, tau),
                high=self._state.b // tau,
                start_bits=self.bottom_up_start_bits,
                batch_bits=self.bottom_up_batch_bits,
                strategy=self.bottom_up_strategy,
                r_limit=self.bottom_up_r_limit,
                full_setting_limit=(
                    self.configured_bottom_up_full_setting_limit
                ),
            )
            try:
                recovered, self._statistics.calls_bottom_up = recovery.recover(
                    executor, self.nr_bits
                )
            except BottomUpFailure as exc:
                wrapped = BleichenBacherException(str(exc))
                wrapped.error_type = type(exc).__name__
                raise wrapped from exc
            return recovered, self._statistics
        except BleichenBacherException as exc:
            phases = {
                "trimmer": "trimmers",
                "search": "searching",
                "bottom_up": "bottom_up",
            }
            exc.step = phases.get(phase, "internal_error")
            raise
