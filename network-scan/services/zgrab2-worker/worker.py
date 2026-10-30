#!/usr/bin/env python3
"""
ZGrab2 Worker - Stateless TLS Scanner

Receives batch requests from job-manager, scans with zgrab2, returns results.
Simple request-response worker with timestamp logging.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

import redis
from redis.exceptions import RedisError


# RSA key exchange cipher suites for ROBOT/Bleichenbacher scanning
# These are TLS_RSA_WITH_* ciphers (static RSA key transport, not ECDHE-RSA or DHE-RSA)
RSA_CIPHER_SUITES = (
    "0x009d,0xc0a1,0xc09d,0x003d,0x0035,0x00c0,0x0084,0xc03d,0xc051,0xc07b,"
    "0xc0a0,0xc09c,0x009c,0x003c,0x002f,0x00ba,0x0096,0x0041,0x0007,0xc03c,"
    "0xc050,0xc07a,0x0005,0x0004,0x000a,0x0062,0x0009,0x0061,0x0064,0x0060,"
    "0x0008,0x0006,0x0003,0x003b,0x0002,0x0001"
)

level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=level,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)
LOG = logging.getLogger(__name__)
LOG.setLevel(level)


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


@dataclass
class ScanResult:
    """Result of a zgrab2 scan with timestamp."""
    batch_id: str
    ip: str
    port: int
    zgrab_json: str
    zgrab2_scanned_at: str
    is_rsa: bool
    status: str  # rsa, no_rsa, timeout, offline, error, etc.
    target_type: Optional[str] = None
    domain: Optional[str] = None
    original_input: Optional[str] = None
    should_retry: bool = False  # If true, host might be temporarily unavailable


class ZGrab2Scanner:
    """Scans batches of IPs with zgrab2."""

    def __init__(
        self,
        scan_port: int,
        results_file: Path,
        connect_timeout: str = "5s",
        target_timeout: str = "30s"
    ):
        self.scan_port = scan_port
        self.results_file = results_file
        self.connect_timeout = connect_timeout
        self.target_timeout = target_timeout
        self.results_file.parent.mkdir(parents=True, exist_ok=True)

    def scan_batch(self, batch_id: str, targets: List[Dict]) -> Tuple[List[ScanResult], set, Dict[str, Dict]]:
        """
        Scan a batch of IPs/domains with zgrab2 and return results with timestamps.

        Returns:
            (results, seen_inputs, input_metadata): Results list and set of inputs that zgrab2 produced output for,
            along with the normalized input metadata mapping.
        """
        if not targets:
            return [], set(), {}

        LOG.info("[scanner] Scanning batch %s with %d targets", batch_id, len(targets))
        LOG.debug("[scanner] Raw targets: %s", targets)

        cmd = [
            "zgrab2",
            "tls",
            "--port",
            str(self.scan_port),
            "--connect-timeout",
            self.connect_timeout,
            "--target-timeout",
            self.target_timeout,
            "--min-version=0x0303",
            "--max-version=0x0303",
            "--no-ecdhe",
            "--cipher-suite",
            RSA_CIPHER_SUITES,
        ]

        inputs: List[str] = []
        input_metadata: Dict[str, Dict] = {}
        for target in targets:
            if not isinstance(target, dict):
                continue
            scan_value = target.get("target")
            target_type = target.get("target_type")
            if not scan_value:
                continue
            normalized = {
                "target": scan_value,
                "target_type": target_type,
            }

            inputs.append(scan_value)
            # Preserve the first metadata entry for a given input to avoid overwriting
            input_metadata.setdefault(scan_value, normalized)
        # LOG.debug("[scanner] Batch %s normalized targets: %s", batch_id, input_metadata)

        # Run zgrab2 with IPs/domains as input
        input_data = "\n".join(inputs) + "\n"

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(input=input_data, timeout=max(60, len(inputs) * 2))
        except subprocess.TimeoutExpired:
            LOG.error("zgrab2 batch scan timed out for batch %s", batch_id)
            proc.kill()
            return [], set(), input_metadata
        except Exception as e:
            LOG.error("zgrab2 batch scan failed for batch %s: %s", batch_id, e)
            return [], set(), input_metadata

        # if stderr:
        #     LOG.info("[scanner] zgrab2 stderr: %s", stderr.strip())
        # LOG.info("[scanner] zgrab2 stdout for batch %s\n%s", batch_id, stdout.strip())

        # Parse results - zgrab2 outputs one JSON line per input (success or failure)
        results = []
        seen_inputs = set()  # Track which inputs we got output for

        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue

            # Write to audit file
            with self.results_file.open(mode="a") as f:
                f.write(line + "\n")

            # Parse zgrab2 output and track which input this is for
            original_input: Optional[str] = None
            meta: Optional[Dict] = None
            try:
                raw_result = json.loads(line)
                # Get the original input (domain or IP)
                domain = raw_result.get("domain")
                ip = raw_result.get("ip")
                if domain and domain in input_metadata and input_metadata[domain]["target_type"] == "domain":
                    meta = input_metadata[domain]
                elif ip and ip in input_metadata and input_metadata[ip]["target_type"] == "ip":
                    meta = input_metadata[ip]
                if meta:
                    original_input = meta.get("target")
                else:
                    LOG.warning("Could not find metadata for zgrab2 result: %s", line)
            except json.JSONDecodeError:
                raw_result = None

            if original_input:
                # meta = input_metadata.get(original_input)
                seen_inputs.add(original_input)

            # Parse and check if RSA
            result = self._parse_result(batch_id, line, meta)
            if result:
                results.append(result)

        # Log missing inputs (zgrab2 didn't output anything for these)
        missing = len(inputs) - len(seen_inputs)
        if missing > 0:
            LOG.warning("Batch %s: zgrab2 produced no output for %d/%d inputs",
                       batch_id, missing, len(inputs))

        rsa_count = sum(1 for r in results if r.is_rsa)
        LOG.info("Batch %s complete: %d outputs received, %d RSA-capable",
                 batch_id, len(results), rsa_count)

        return results, seen_inputs, input_metadata

    def _parse_result(self, batch_id: str, line: str, meta: Optional[Dict]) -> ScanResult | None:
        """
        Parse zgrab2 JSON result and determine if RSA-capable or should retry.

        Returns None if the result should be filtered out (permanent failure).
        Returns ScanResult with is_rsa=True for RSA hosts.
        Returns ScanResult with should_retry=True for temporary failures.
        """
        try:
            result = json.loads(line)
        except json.JSONDecodeError as e:
            LOG.warning("JSON decode error: %s", e)
            return None

        target_type = (meta or {}).get("target_type")
        display_target = (meta or {}).get("target")
        domain = result.get("domain") or result.get("name") or (meta or {}).get("domain")
        original_input = (meta or {}).get("target") or domain or result.get("ip")
        # Get IP address - skip if not available (DNS resolution failure)
        ip = result.get("ip") or (meta or {}).get("ip")
        if not ip:
            LOG.debug("Result for %s: no IP (DNS failure - permanent)", display_target or domain or "unknown")
            return ScanResult(
                batch_id=batch_id,
                ip=original_input or domain or "unknown",
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=datetime.now(timezone.utc).isoformat(),
                is_rsa=False,
                status="no_dns",
                target_type=target_type,
                domain=domain,
                original_input=original_input or display_target,
                should_retry=False,
            )

        # Record scan timestamp
        scanned_at = datetime.now(timezone.utc).isoformat()

        # Check for top-level errors (rare)
        if "error" in result:
            LOG.debug("Target %s: top-level error - marking retry", display_target or ip)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status="error",
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=True
            )

        tls_data = (result.get("data") or {}).get("tls") or {}
        status = tls_data.get("status", "unknown")
        error_msg = tls_data.get("error") or result.get("error") or ""

        # Check if this is a retryable error (temporary network/host issues)
        if status in ("connection-timeout", "connection-closed", "io-timeout"):
            LOG.debug("Target %s: temporary error (%s) - marking for retry", display_target or ip, status)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status="timeout",
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=True
            )

        # Hosts that reject RSA cipher suites often respond with a handshake failure
        if "handshake failure" in error_msg.lower():
            LOG.debug("Target %s: handshake failure indicates no RSA support", display_target or ip)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status="no_rsa",
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=False
            )

        # Permanent failures - filter these out
        if status in ("connection-refused", "blocklisted-target", "protocol-error",
                      "application-error", "unknown-error"):
            LOG.debug("Target %s: permanent error (%s) - filtering out", display_target or ip, status)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status="offline",
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=False
            )

        # If not success, filter out
        if status != "success":
            LOG.debug("Target %s: non-success status (%s) - filtering out", display_target or ip, status)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status=status,
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=False
            )

        # Success - check for RSA key exchange
        # Since we're using RSA-only cipher suites, if TLS handshake succeeded
        # and there's no server_key_exchange, the server uses RSA key exchange
        handshake = (tls_data.get("result") or {}).get("handshake_log") or {}
        if "server_key_exchange" in handshake:
            LOG.debug("Target %s: has server_key_exchange (not RSA) - filtering out", display_target or ip)
            return ScanResult(
                batch_id=batch_id,
                ip=ip,
                port=self.scan_port,
                zgrab_json=line,
                zgrab2_scanned_at=scanned_at,
                is_rsa=False,
                status="no_rsa",
                target_type=target_type,
                domain=domain,
                original_input=original_input,
                should_retry=False
            )

        # RSA-capable host!
        LOG.debug("RSA-capable host found: %s", display_target or ip)
        return ScanResult(
            batch_id=batch_id,
            ip=ip,
            port=self.scan_port,
            zgrab_json=line,
            zgrab2_scanned_at=scanned_at,
            is_rsa=True,
            status="rsa",
            target_type=target_type,
            domain=domain,
            original_input=original_input,
            should_retry=False
        )


class Worker:
    """ZGrab2 worker - receives requests, scans, returns results."""

    def __init__(self) -> None:
        redis_host = require_env("REDIS_HOST")
        self.request_queue = require_env("REQUEST_QUEUE")
        self.results_queue = require_env("RESULTS_QUEUE")
        self.status_counts_key = os.getenv(
            "STATUS_COUNTS_KEY",
            f"{self.results_queue}:status-counts"
        )
        self.total_inputs_key = os.getenv(
            "TOTAL_INPUTS_KEY",
            f"{self.results_queue}:inputs-total"
        )
        self.scan_port = int(require_env("SCAN_PORT"))
        self.results_file = Path(require_env("RESULTS_FILE"))
        self.connect_timeout = os.getenv("CONNECT_TIMEOUT", "5s")
        self.target_timeout = os.getenv("TARGET_TIMEOUT", "30s")

        host, port = parse_host_port(redis_host)
        self.redis = redis.Redis(host=host, port=port, decode_responses=True)
        self.redis.ping()

        LOG.info(
            "Connected to Redis at %s:%s (request=%s results=%s)",
            host,
            port,
            self.request_queue,
            self.results_queue,
        )

        self.scanner = ZGrab2Scanner(
            scan_port=self.scan_port,
            results_file=self.results_file,
            connect_timeout=self.connect_timeout,
            target_timeout=self.target_timeout,
        )

    def run(self) -> None:
        """Main worker loop."""
        LOG.info("Waiting for scan requests on queue %s", self.request_queue)

        while True:
            # Wait for scan request
            item = self.redis.blpop(self.request_queue, timeout=5)
            if not item:
                continue

            _, payload = item
            try:
                request = json.loads(payload)
                batch_id = request["batch_id"]
                targets = request.get("targets")
            except (json.JSONDecodeError, KeyError) as e:
                LOG.warning("Skipping malformed request: %s", e)
                continue

            if targets:
                new_hosts = sum(1 for t in targets if isinstance(t, dict) and t.get("is_new"))
                self._increment_total_inputs(new_hosts)
                LOG.info("Received batch %s with %s targets (new=%s)",
                         batch_id, len(targets), new_hosts)
            else:
                LOG.warning("Batch %s has no valid targets", batch_id)

            # Scan batch (targets can be domains or IPs)
            results, seen_inputs, input_metadata = self.scanner.scan_batch(batch_id, targets)
            LOG.info("Batch %s scan produced %s raw results (seen_inputs=%s)", batch_id, len(results), len(seen_inputs))   

            # Build responses with explicit status for all processed targets
            responses = []
            filtered_count = 0

            for result in results:
                if result:
                    response = {
                        "batch_id": result.batch_id,
                        "ip": result.ip,
                        "domain": result.domain,
                        "target": result.original_input or result.domain or result.ip,
                        "target_type": result.target_type,
                        "port": result.port,
                        "zgrab_json": result.zgrab_json,
                        "zgrab2_scanned_at": result.zgrab2_scanned_at,
                        "is_rsa": result.is_rsa,
                        "should_retry": result.should_retry,
                        "status": getattr(result, "status", None),
                    }
                    self._increment_status(response.get("status"))
                    responses.append(response)
                else:
                    filtered_count += 1

            # Add error results for inputs that zgrab2 produced no output for
            # These should be retried (zgrab2 crashed/hung)
            for original_input, meta in input_metadata.items():
                if original_input not in seen_inputs:
                    error_response = {
                        "batch_id": batch_id,
                        "ip": meta.get("ip"),
                        "domain": meta.get("domain"),
                        "target": meta.get("target") or meta.get("ip"),
                        "target_type": meta.get("target_type"),
                        "port": self.scan_port,
                        "zgrab_json": None,
                        "zgrab2_scanned_at": None,
                        "is_rsa": False,
                        "should_retry": True,
                        "status": "missing_output",
                    }
                    self._increment_status(error_response.get("status"))
                    responses.append(error_response)

            # Push filtered results as a single JSON array (one message)
            rsa_count = sum(1 for r in responses if r.get("is_rsa"))
            retry_count = sum(1 for r in responses if r.get("should_retry"))

            try:
                batch_response = {
                    "batch_id": batch_id,
                    "results": responses
                }
                self.redis.rpush(self.results_queue, json.dumps(batch_response))
                LOG.info("Batch %s: %d RSA hosts, %d retry candidates, %d filtered out",
                         batch_id, rsa_count, retry_count, filtered_count)
            except RedisError as e:
                LOG.error("Failed to push results for batch %s: %s", batch_id, e)

    def _increment_status(self, status: Optional[str], amount: int = 1) -> None:
        """Increment a status counter in Redis."""
        if not status or amount <= 0:
            return
        try:
            self.redis.hincrby(self.status_counts_key, status, amount)
        except Exception as exc:
            LOG.debug("Failed to increment status %s by %d: %s", status, amount, exc)

    def _increment_total_inputs(self, amount: int) -> None:
        """Increment the total received inputs counter in Redis."""
        if amount <= 0:
            return
        try:
            self.redis.incrby(self.total_inputs_key, amount)
        except Exception as exc:
            LOG.debug("Failed to increment total inputs by %d: %s", amount, exc)


def main() -> None:
    """Main entry point for the zgrab2 worker."""
    worker = Worker()
    worker.run()


if __name__ == "__main__":
    main()
