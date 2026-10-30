#!/usr/bin/env python3
"""Utility to read ROBOT scanner status counts from Redis."""

import os
import sys
from typing import Dict

import redis


def require_env(var: str) -> str:
    value = os.getenv(var)
    if not value:
        print(f"{var} environment variable must be set", file=sys.stderr)
        sys.exit(1)
    return value


def main() -> None:
    redis_host = require_env("REDIS_HOST")
    results_queue = require_env("RESULTS_QUEUE")
    status_key = os.getenv("STATUS_COUNTS_KEY", f"{results_queue}:status-counts")

    host, port = redis_host.split(":")
    r = redis.Redis(host=host, port=int(port), decode_responses=True)

    try:
        counts: Dict[str, str] = r.hgetall(status_key)
    except Exception as exc:
        print(f"Failed to read counts from Redis: {exc}", file=sys.stderr)
        sys.exit(1)

    if not counts:
        print(f"No counts found in {status_key}")
        return

    print(f"Status counts in {status_key}:")
    for status, count in sorted(counts.items(), key=lambda item: int(item[1]), reverse=True):
        print(f"{status}: {count}")


if __name__ == "__main__":
    main()
