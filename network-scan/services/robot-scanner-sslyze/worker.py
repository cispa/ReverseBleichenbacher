#!/usr/bin/env python3
"""
ROBOT vulnerability scanner worker using SSLyze.

Stateless worker:
1. Receives batch of hosts from Redis queue
2. Scans with SSLyze (parallel scanning with configurable concurrency)
3. Pushes individual results to results queue as they complete
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import redis
from redis.exceptions import RedisError
from sslyze import (
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    RobotScanResultEnum,
    ServerScanStatusEnum,
    ServerScanResultAsJson,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)
LOG = logging.getLogger(__name__)


def require_env(var: str) -> str:
    """Get required environment variable or exit with error."""
    value = os.getenv(var)
    if not value:
        LOG.error("%s environment variable must be set", var)
        sys.exit(1)
    return value


class ROBOTWorker:
    """ROBOT vulnerability scanner using SSLyze."""

    def __init__(self) -> None:
        self.redis_host = require_env("REDIS_HOST")
        self.batch_queue = require_env("BATCH_QUEUE")
        self.results_file = require_env("RESULTS_FILE")
        self.results_queue = require_env("RESULTS_QUEUE")
        self.worker_id = os.getenv("HOSTNAME", "worker")
        self.max_workers = int(require_env("CONCURRENCY"))
        self.network_timeout = int(require_env("TIMEOUT"))

        if ":" in self.redis_host:
            host, port = self.redis_host.split(":")
            self.redis = redis.Redis(
                host=host, port=int(port), decode_responses=True)
        else:
            self.redis = redis.Redis(
                host=self.redis_host, decode_responses=True)

        try:
            self.redis.ping()
            LOG.info("Connected to Redis at %s", self.redis_host)
        except RedisError as e:
            LOG.error("Failed to connect to Redis: %s", e)
            sys.exit(1)

        self.results_file_handle = open(
            self.results_file, "a", encoding="utf-8")
        LOG.info("Results will be written to %s", self.results_file)
        LOG.info("Normalized results queue: %s", self.results_queue)
        LOG.info("Concurrent connections: %s, network timeout: %ss",
                 self.max_workers, self.network_timeout)

        self.scanned = 0
        self.vulnerable = 0
        self.last_log_time = time.time()

    def run(self) -> None:
        """Main worker loop that processes batches from Redis."""
        LOG.info("SSLyze ROBOT Scanner Worker started (ID: %s)", self.worker_id)
        LOG.info("Batch queue: %s", self.batch_queue)

        while True:
            _, batch_json = self.redis.blpop(self.batch_queue)
            batch = json.loads(batch_json)
            batch_id = batch.get("batch_id")
            hosts = batch.get("hosts", [])
            if batch_id and hosts:
                self.process_batch(batch_id, hosts)

    def process_batch(self, batch_id: str, hosts: list) -> None:
        """Process a batch of hosts using SSLyze's built-in parallelism."""
        if not hosts:
            return

        LOG.info("[%s] Batch %s: scanning %s hosts",
                 self.worker_id, batch_id, len(hosts))

        # Create scan requests for all hosts (ROBOT scan only)
        scan_requests = []
        request_metadata = {}
        for host in hosts:
            ip = host.get("ip")
            domain = host.get("domain")
            port = host.get("port", 443)
            hostname = ip or domain
            if not hostname:
                continue

            sni_name = domain or hostname
            server_location = ServerNetworkLocation(hostname=hostname, port=port)
            network_cfg = ServerNetworkConfiguration(
                tls_server_name_indication=sni_name,
                network_timeout=self.network_timeout,
            )
            scan_request = ServerScanRequest(
                server_location=server_location,
                network_configuration=network_cfg,
                scan_commands={ScanCommand.ROBOT},  # Only scan for ROBOT
            )
            scan_requests.append(scan_request)
            request_metadata[(hostname, port)] = {"domain": domain, "ip": ip or hostname}

        # Create scanner with parallelism and queue all scans
        scanner = Scanner(
            per_server_concurrent_connections_limit=self.max_workers)
        scanner.queue_scans(scan_requests)

        # Process results as they come in
        for server_scan_result in scanner.get_results():
            key = (
                server_scan_result.server_location.hostname,
                server_scan_result.server_location.port,
            )
            scan_result = self.parse_scan_result(server_scan_result, request_metadata.get(key))
            self.write_result(scan_result)
            self.push_normalized_result(batch_id, scan_result)

            self.scanned += 1
            if scan_result.get("vulnerable"):
                self.vulnerable += 1

            # Time-based logging (every 30 seconds)
            now = time.time()
            if now - self.last_log_time >= 30:
                LOG.info(
                    "[%s] Scanned %s hosts, found %s vulnerable",
                    self.worker_id, self.scanned, self.vulnerable
                )
                self.last_log_time = now

    def parse_scan_result(self, server_scan_result, meta: dict | None) -> dict:
        """Parse SSLyze scan result into our result format."""
        # obj = ServerScanResultAsJson.model_validate(server_scan_result)
        # print(obj.model_dump_json())
        ip = (meta or {}).get("ip") or server_scan_result.server_location.hostname
        domain = (meta or {}).get("domain")
        port = server_scan_result.server_location.port

        result = {
            "ip": ip,
            "port": port,
            "domain": domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "sslyze",
            "vulnerable": False,
        }

        # Check if we could connect to the server
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            result["error"] = "Connection failed"
            return result

        # Parse ROBOT scan result
        assert server_scan_result.scan_result
        robot_attempt = server_scan_result.scan_result.robot

        if robot_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            robot_result_enum = robot_attempt.result.robot_result
            is_vulnerable = robot_result_enum in (
                RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
            )
            result["vulnerable"] = is_vulnerable

            if is_vulnerable:
                vuln_level = "strong" if robot_result_enum == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE else "weak"
                result["vulnerability_level"] = vuln_level
            else:
                result["vulnerability_level"] = "not_vulnerable"

            result["details"] = {
                "robot_result": robot_result_enum.name
            }
        elif robot_attempt.error_reason:
            result["error"] = str(robot_attempt.error_reason)
        else:
            result["error"] = f"ROBOT scan failed: {robot_attempt.status}"

        return result

    def write_result(self, result: dict) -> None:
        """Write scan result to file."""
        json_line = json.dumps(result)
        self.results_file_handle.write(json_line + "\n")
        self.results_file_handle.flush()

    def push_normalized_result(self, batch_id: str, scan_result: dict) -> None:
        """Push normalized result to Redis queue."""
        payload = {
            "batch_id": batch_id,
            "ip": scan_result["ip"],
            "domain": scan_result.get("domain"),
            "port": scan_result["port"],
            "scanner": "sslyze",
            "scanned_at": scan_result.get("scanned_at"),
            "vulnerable": scan_result.get("vulnerable", False),
            "vulnerability_level": scan_result.get("vulnerability_level", "unknown"),
            "error": scan_result.get("error"),
            "to_retry": scan_result.get("error") is not None,
            "details": scan_result.get("details"),
        }
        self.redis.rpush(self.results_queue, json.dumps(payload))

    def close(self) -> None:
        """Close the results file handle."""
        self.results_file_handle.close()


def main() -> None:
    """Main entry point for the SSLyze ROBOT scanner worker."""
    worker = ROBOTWorker()
    try:
        worker.run()
    except KeyboardInterrupt:
        LOG.info("Shutting down...")
    finally:
        worker.close()


if __name__ == "__main__":
    main()
