"""Canonical schema for sequential simulation results."""

RESULT_COLUMNS = (
    "run",
    "key_index",
    "outcome",
    "step",
    "correct",
    "error_type",
    "error_message",
    "tau_found",
    "tau_available",
    "trimmer_has_divisor",
    "trimmer_detectable",
    "total_queries",
    "trimmer_queries",
    "search_queries",
    "other_queries",
    "bottom_up_queries",
)

OUTCOMES = {
    "ok",
    "wrong_result",
    "trimmer_no_divisor",
    "trimmer_no_multiplier",
    "trimmer_false_negative",
    "trimmer_missed_power_of_two",
    "search_failed",
    "search_coverage_exhausted",
    "search_false_negative_exhausted",
    "other_failed",
    "bottom_up_failed",
    "internal_error",
}

STEPS = {"done", "trimmer", "search", "other", "bottom_up", "harness"}
QUERY_COLUMNS = (
    "trimmer_queries",
    "search_queries",
    "other_queries",
    "bottom_up_queries",
)

SCHEMA_VERSION = 1
