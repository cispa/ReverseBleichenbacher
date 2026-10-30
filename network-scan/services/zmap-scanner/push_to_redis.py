#!/usr/bin/env python3
"""
Consumes zmap CSV output from stdin and pushes responding IPs into a Redis queue.
Acts as the lightweight "simple program" that ztee feeds.
"""

import json
import logging
import os
import sys
import time
from typing import Tuple

import redis
from redis.exceptions import RedisError


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)
LOG = logging.getLogger(__name__)


def parse_host_port(value: str) -> Tuple[str, int]:
    """Parse host:port string into tuple of (host, port)."""
    host, port = value.rsplit(":", 1)
    return host, int(port)


def require_env(var: str) -> str:
    """Get required environment variable or exit with error."""
    value = os.getenv(var)
    if not value:
        LOG.error("%s environment variable must be set", var)
        sys.exit(1)
    return value


def main() -> None:
    """Stream zmap CSV output from stdin to Redis queue."""
    redis_host = require_env("REDIS_HOST")
    queue_name = require_env("OUTPUT_QUEUE")
    log_interval = int(os.getenv("LOG_INTERVAL", "30"))

    host, port = parse_host_port(redis_host)
    client = redis.Redis(host=host, port=port, decode_responses=True)

    try:
        client.ping()
        LOG.info("Connected to Redis at %s:%s (queue: %s)",
                 host, port, queue_name)
    except RedisError as exc:
        LOG.error("Failed to connect to Redis: %s", exc)
        sys.exit(1)

    loaded = 0
    last_log_time = time.time()

    for raw in sys.stdin:
        line = raw.strip()
        if not line or line == "saddr":
            continue

        entry: str = json.dumps({"ip": line, "target": line, "target_type": "ip"})
        try:
            client.rpush(queue_name, entry)
            loaded += 1

            # Log at regular time intervals
            now = time.time()
            if now - last_log_time >= log_interval:
                LOG.info("Queued %d IPs so far", loaded)
                last_log_time = now
        except RedisError as exc:
            LOG.warning("Failed to push %s: %s", line, exc)

    LOG.info("Finished streaming %d IPs into %s", loaded, queue_name)


if __name__ == "__main__":
    main()
