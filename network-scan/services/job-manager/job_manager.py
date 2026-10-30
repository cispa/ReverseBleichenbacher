#!/usr/bin/env python3
"""
Job Manager - Central Pipeline Scheduler

Orchestrates the entire scanning pipeline:
1. Reads IPs from input-targets queue
2. Batches and sends to zgrab2 for TLS scanning
3. Waits for zgrab2 results
4. Filters RSA-capable hosts
5. Distributes to ROBOT scanner queues

This prevents congestion and minimizes time gap between TLS and vulnerability scans.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import redis

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


@dataclass
class Config:
    redis_host: str
    input_queue: str
    zgrab2_request_queue: str
    zgrab2_results_queue: str
    scanner_queues: List[str]
    scanner_queue_map: Dict[str, str]
    scanner_retry_delay: int
    results_queue: str
    zgrab_batch_size: int
    zgrab_batch_timeout: int
    scanner_batch_size: int
    scanner_batch_timeout: int
    max_backlog: int
    zgrab2_max_retries: int
    zgrab_log_file: Path
    batch_log_file: Path
    results_file: Path
    vulnerable_file: Path


class JobManager:
    """Central scheduler orchestrating TLS and vulnerability scanning."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        host, port = self.parse_host_port(cfg.redis_host)
        self.redis = redis.Redis(host=host, port=port, decode_responses=True)
        self.redis.ping()

        LOG.info("Job manager connected to Redis at %s:%s", host, port)
        LOG.info("Input queue: %s", cfg.input_queue)
        LOG.info("ZGrab2 request queue: %s", cfg.zgrab2_request_queue)
        LOG.info("ZGrab2 results queue: %s", cfg.zgrab2_results_queue)
        LOG.info(
            "Scanner queues: %s",
            ", ".join(f"{name}->{queue}" for name, queue in cfg.scanner_queue_map.items()),
        )
        LOG.info("ZGrab batch: size=%d timeout=%ds", cfg.zgrab_batch_size, cfg.zgrab_batch_timeout)
        LOG.info("Scanner batch: size=%d timeout=%ds", cfg.scanner_batch_size, cfg.scanner_batch_timeout)
        LOG.info("ZGrab2 max retries: %d", cfg.zgrab2_max_retries)
        LOG.info("Scanner retry delay: %ds", cfg.scanner_retry_delay)

        # Ensure result directories exist
        cfg.zgrab_log_file.parent.mkdir(parents=True, exist_ok=True)
        cfg.batch_log_file.parent.mkdir(parents=True, exist_ok=True)
        cfg.results_file.parent.mkdir(parents=True, exist_ok=True)

        self.zgrab_log = cfg.zgrab_log_file.open("a", encoding="utf-8")
        self.batch_log = cfg.batch_log_file.open("a", encoding="utf-8")
        self.results_log = cfg.results_file.open("a", encoding="utf-8")
        self._log_lock = threading.Lock()

        # Retry queue: stores hosts that need retry with their attempt count
        # Format: {"ip": str, "domain": Optional[str], "port": int, "attempts": int, "target": str}
        self.retry_queue: List[Dict] = []
        self._retry_lock = threading.Lock()
        self.retry_base_delay = 10  # seconds
        self.retry_max_delay = 600  # cap backoff at 10 minutes
        self.scanner_retry_delay = cfg.scanner_retry_delay
        self.scanner_retry_buffer: Dict[str, List[Dict]] = defaultdict(list)
        self._scanner_retry_lock = threading.Lock()

        self.counter_key = "stats:counters"
        self.start_time_key = "stats:job_manager_start"

        # Record start time (seconds since epoch) for UI uptime display
        try:
            # Only set if not already set to preserve uptime across restarts within same run
            self.redis.setnx(self.start_time_key, int(time.time()))
        except Exception:
            pass

    @staticmethod
    def parse_host_port(value: str) -> Tuple[str, int]:
        """Parse host:port string into tuple of (host, port)."""
        host, port = value.rsplit(":", 1)
        return host, int(port)

    def start(self) -> None:
        """Start the job manager."""
        # Start results collector thread
        results_thread = threading.Thread(
            target=self._collect_results, daemon=True)
        results_thread.start()

        # Start scanner retry scheduler
        scanner_retry_thread = threading.Thread(
            target=self._scanner_retry_loop, daemon=True)
        scanner_retry_thread.start()

        # Start main orchestration loop
        self._orchestrate_pipeline()

    def _normalize_host_payload(self, data: Dict) -> Dict:
        """Normalize input payload. Expects well-formed {'target': ..., 'target_type': 'ip|domain'}."""
        if not isinstance(data, dict):
            return {}

        target_value = data.get("target")
        raw_target_type = data.get("target_type")
        target_type = raw_target_type.lower() if isinstance(raw_target_type, str) else None

        if not target_value or target_type not in ("ip", "domain"):
            return {}

        return {
            "target": target_value,
            "target_type": target_type,
            "ip": target_value if target_type == "ip" else None,
            "domain": target_value if target_type == "domain" else None,
        }

    def _read_new_hosts(self) -> List[Dict]:
        """Read a batch of new hosts from the input queue only."""
        new_hosts: List[Dict] = []
        start_time = time.time()

        while len(new_hosts) < self.cfg.zgrab_batch_size:
            elapsed = time.time() - start_time

            if elapsed >= self.cfg.zgrab_batch_timeout and new_hosts:
                LOG.info("ZGrab batch timeout reached with %d new hosts", len(new_hosts))
                break

            remaining = max(1, self.cfg.zgrab_batch_timeout - int(elapsed))
            item = self.redis.blpop(self.cfg.input_queue, timeout=remaining)
            if not item:
                if new_hosts:
                    LOG.info("No more hosts, got %d new hosts", len(new_hosts))
                    break
                continue

            _, payload = item
            try:
                data = json.loads(payload)
                host = self._normalize_host_payload(data)
                if host.get("target"):
                    new_hosts.append(host)
            except (json.JSONDecodeError, KeyError) as e:
                LOG.warning("Skipping malformed input: %s (%s)", payload, e)
                continue

        return new_hosts

    def _interleave_retries(self, new_hosts: List[Dict]) -> Tuple[List[Dict], int]:
        """Interleave retry queue entries with new hosts, or serve retries if no new hosts."""
        with self._retry_lock:
            if not new_hosts and self.retry_queue:
                retry_hosts = self._consume_retries(self.cfg.zgrab_batch_size)
                LOG.info(
                    "No new hosts available, retrying %d hosts (queue remaining: %d)",
                    len(retry_hosts),
                    len(self.retry_queue),
                )
                return retry_hosts, 0

            if not self.retry_queue:
                return new_hosts, len(new_hosts)

            batch: List[Dict] = []
            available_slots = max(0, self.cfg.zgrab_batch_size - len(new_hosts))
            retries_to_schedule = available_slots if available_slots > 0 else len(new_hosts)
            retries_ready = self._consume_retries(retries_to_schedule) if retries_to_schedule > 0 else []

            if not retries_ready:
                return new_hosts, len(new_hosts)

            interval = max(1, len(new_hosts) // max(1, len(retries_ready)))
            retry_idx = 0

            for i, new_host in enumerate(new_hosts):
                batch.append(new_host)
                if (
                    retry_idx < len(retries_ready)
                    and (i + 1) % interval == 0
                    and len(batch) < self.cfg.zgrab_batch_size
                ):
                    batch.append(retries_ready[retry_idx])
                    retry_idx += 1

            while retry_idx < len(retries_ready) and len(batch) < self.cfg.zgrab_batch_size:
                batch.append(retries_ready[retry_idx])
                retry_idx += 1

            if retry_idx > 0:
                LOG.info(
                    "Interleaved %d retries into batch (queue remaining: %d)",
                    retry_idx,
                    len(self.retry_queue),
                )

            return batch, len(new_hosts)

    def _consume_retries(self, max_hosts: int) -> List[Dict]:
        """Pop up to max_hosts entries from the retry queue that are due, preserving order."""
        if max_hosts <= 0 or not self.retry_queue:
            return []

        now = time.time()
        ready: List[Dict] = []
        remaining: List[Dict] = []

        for entry in self.retry_queue:
            if len(ready) >= max_hosts:
                remaining.append(entry)
                continue
            if entry.get("next_due", 0) <= now:
                ready.append(entry)
            else:
                remaining.append(entry)

        self.retry_queue = remaining
        return ready

    def _send_to_zgrab2(self, batch_id: str, hosts: List[Dict], new_count: int) -> None:
        """Send batch of hosts to zgrab2 for TLS scanning."""
        LOG.info("Sending batch %s (%d hosts, new=%d) to zgrab2", batch_id, len(hosts), new_count)

        retry_batch = new_count == 0
        request = {
            "batch_id": batch_id,
            "targets": [],
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "retry_batch": retry_batch,
            "new_count": new_count,
        }
        for host in hosts:
            request["targets"].append({
                "target": host.get("target") or host.get("ip"),
                "target_type": host.get("target_type") or (
                    "domain" if host.get("domain") else "ip"
                ),
                "is_new": bool(host.get("attempts", 0) == 0),
            })

        self.redis.rpush(self.cfg.zgrab2_request_queue, json.dumps(request))

    def _wait_for_zgrab2_results(self, batch_id: str, expected_count: int) -> List[Dict] | None:
        """Wait for zgrab2 batch results (single message with all results).

        Returns None on timeout so caller can requeue.
        """
        LOG.info("Waiting for zgrab2 results for batch %s", batch_id)

        timeout = expected_count * 2 + 30  # 2 seconds per IP + overhead
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                LOG.warning("Timeout waiting for batch %s after %ds", batch_id, int(elapsed))
                return None

            item = self.redis.blpop(self.cfg.zgrab2_results_queue, timeout=5)
            if not item:
                continue

            _, payload = item
            try:
                batch_response = json.loads(payload)

                # Check if this is for our batch
                if batch_response.get("batch_id") != batch_id:
                    # Wrong batch - put it back
                    self.redis.lpush(self.cfg.zgrab2_results_queue, payload)
                    time.sleep(0.1)
                    continue

                # Extract results array
                results = batch_response.get("results", [])
                LOG.info("Batch %s complete: received %d results", batch_id, len(results))

                # Log full zgrab2 results
                with self._log_lock:
                    for result in results:
                        if result.get("zgrab_json"):
                            self.zgrab_log.write(result["zgrab_json"].rstrip("\n") + "\n")
                    self.zgrab_log.flush()

                return results

            except (json.JSONDecodeError, KeyError) as e:
                LOG.warning("Skipping malformed zgrab2 result: %s", e)
                continue

    def _filter_rsa_hosts(self, zgrab2_results: List[Dict]) -> List[Dict]:
        """Filter zgrab2 results to only RSA-capable hosts and handle retries. Also records status counters."""
        rsa_hosts = []
        retry_candidates = []
        total = len(zgrab2_results)
        rsa_count = 0
        no_rsa_count = 0
        retry_count = 0
        removed_count = 0
        retry_unique_targets = set()
        unique_targets_seen = set()
        unique_removed = set()
        unique_no_rsa = set()
        unique_rsa = set()

        for result in zgrab2_results:
            domain = result.get("domain")
            target = result.get("target") or domain or result.get("ip")
            status = result.get("status") or "unknown"
            if target:
                unique_targets_seen.add(target)

            if result.get("is_rsa"):
                rsa_count += 1
                if target:
                    unique_rsa.add(target)
                rsa_hosts.append({
                    "ip": result["ip"],
                    "domain": domain,
                    "target": target,
                    "port": result.get("port", 443),
                    "zgrab2_scanned_at": result.get("zgrab2_scanned_at"),
                })
                continue

            if result.get("should_retry"):
                retry_count += 1
                if target:
                    retry_unique_targets.add(target)
                retry_candidates.append({
                    "ip": result["ip"],
                    "domain": domain,
                    "target": target,
                    "port": result.get("port", 443),
                    "attempts": result.get("attempts", 0) + 1,
                    "target_type": result.get("target_type"),
                })
                continue

            if status == "no_rsa":
                no_rsa_count += 1
                if target:
                    unique_no_rsa.add(target)
            elif status in ("offline", "error", "timeout", "missing_output"):
                removed_count += 1
                if target:
                    unique_removed.add(target)
            else:
                removed_count += 1
                if target:
                    unique_removed.add(target)

        # Add retry candidates to queue if they haven't exceeded max retries
        if retry_candidates:
            with self._retry_lock:
                for candidate in retry_candidates:
                    if candidate["attempts"] < self.cfg.zgrab2_max_retries:
                        candidate["next_due"] = self._compute_retry_due(candidate["attempts"])
                        self.retry_queue.append(candidate)
                        self._incr_counter("zgrab2_retry_total", 1)
                    else:
                        LOG.debug("Discarding %s after %d attempts", candidate["ip"], candidate["attempts"])

            added_retries = sum(1 for c in retry_candidates if c["attempts"] < self.cfg.zgrab2_max_retries)
            discarded = len(retry_candidates) - added_retries
            LOG.info("Filtered %d RSA hosts, added %d retries, discarded %d (queue: %d)",
                     len(rsa_hosts), added_retries, discarded, len(self.retry_queue))
        else:
            LOG.info("Filtered %d/%d RSA-capable hosts", len(rsa_hosts), len(zgrab2_results))

        # Update counters
        if total:
            self._incr_counter("zgrab2_total", total)
        if unique_targets_seen:
            try:
                self.redis.sadd("stats:zgrab2:results:set", *list(unique_targets_seen))
            except Exception:
                LOG.debug("Failed to add to results unique set")
        if rsa_count:
            self._incr_counter("zgrab2_rsa", rsa_count)
        if unique_rsa:
            try:
                self.redis.sadd("stats:zgrab2:rsa:set", *list(unique_rsa))
            except Exception:
                LOG.debug("Failed to add to rsa unique set")
        if retry_count:
            self._incr_counter("zgrab2_retry", retry_count)
        if retry_unique_targets:
            try:
                self.redis.sadd("stats:zgrab2:retry:set", *list(retry_unique_targets))
            except Exception:
                LOG.debug("Failed to add to retry unique set")
        if no_rsa_count:
            self._incr_counter("zgrab2_no_rsa", no_rsa_count)
        if unique_no_rsa:
            try:
                self.redis.sadd("stats:zgrab2:no_rsa:set", *list(unique_no_rsa))
            except Exception:
                LOG.debug("Failed to add to no_rsa unique set")
        if removed_count:
            self._incr_counter("zgrab2_removed", removed_count)
        if unique_removed:
            try:
                self.redis.sadd("stats:zgrab2:removed:set", *list(unique_removed))
            except Exception:
                LOG.debug("Failed to add to removed unique set")

        return rsa_hosts

    def _distribute_to_scanners(self, batch_id: str, rsa_hosts: List[Dict]) -> None:
        """Distribute RSA hosts to ROBOT scanner queues."""
        if not rsa_hosts:
            LOG.info("No RSA hosts to scan")
            return

        queues = list(self.cfg.scanner_queue_map.values())
        LOG.info("Distributing %d RSA hosts to %d scanner queues",
                 len(rsa_hosts), len(queues))

        # Log batch
        batch_data = {
            "batch_id": batch_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "count": len(rsa_hosts),
            "hosts": rsa_hosts,
        }
        with self._log_lock:
            self.batch_log.write(json.dumps(batch_data) + "\n")
            self.batch_log.flush()

        chunk_size = max(1, self.cfg.scanner_batch_size)
        for idx, start in enumerate(range(0, len(rsa_hosts), chunk_size), start=1):
            chunk_hosts = rsa_hosts[start:start + chunk_size]
            chunk_batch_id = f"{batch_id}-s{idx}" if len(chunk_hosts) != len(rsa_hosts) else batch_id
            payload = {
                "batch_id": chunk_batch_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "count": len(chunk_hosts),
                "hosts": chunk_hosts,
            }
            for queue in queues:
                self.redis.rpush(queue, json.dumps(payload))

    def _orchestrate_pipeline(self) -> None:
        """Main orchestration loop."""
        LOG.info("Starting pipeline orchestration")

        while True:
            try:
                # Step 1: Read batch of new inputs, then interleave retries
                new_hosts = self._read_new_hosts()
                hosts, new_count = self._interleave_retries(new_hosts)
                if not hosts:
                    LOG.debug("No hosts to process, waiting...")
                    time.sleep(5)
                    continue

                batch_id = str(uuid.uuid4())
                LOG.info("Processing batch %s with %d hosts", batch_id, len(hosts))

                # Step 2: Send to zgrab2 for TLS scanning
                self._send_to_zgrab2(batch_id, hosts, new_count)

                # Step 3: Wait for zgrab2 results
                zgrab2_results = self._wait_for_zgrab2_results(batch_id, len(hosts))

                if zgrab2_results is None:
                    LOG.info("Requeueing %d hosts from timed-out batch %s", len(hosts), batch_id)
                    self._requeue_batch(hosts)
                    continue

                # Step 4: Filter RSA-capable hosts
                rsa_hosts = self._filter_rsa_hosts(zgrab2_results)

                # Step 5: Distribute to ROBOT scanners
                if rsa_hosts:
                    # Check scanner queue backlog
                    if self.cfg.max_backlog > 0:
                        queues = list(self.cfg.scanner_queue_map.values())
                        max_len = max(self.redis.llen(q) for q in queues)
                        while max_len >= self.cfg.max_backlog:
                            LOG.info("Scanner queues at max backlog (%d), waiting...", max_len)
                            time.sleep(2)
                            max_len = max(self.redis.llen(q) for q in queues)

                    self._distribute_to_scanners(batch_id, rsa_hosts)

                LOG.info("Batch %s complete", batch_id)

                # Publish retry queue size to Redis for monitoring
                self._publish_stats()

            except KeyboardInterrupt:
                LOG.info("Shutting down...")
                break
            except Exception as e:
                LOG.error("Error in orchestration loop: %s", e, exc_info=True)
                time.sleep(1)

    def _publish_stats(self) -> None:
        """Publish job-manager statistics to Redis for monitoring."""
        try:
            with self._retry_lock:
                retry_queue_size = len(self.retry_queue)
            with self._scanner_retry_lock:
                scanner_retry_size = sum(len(entries) for entries in self.scanner_retry_buffer.values())

            # Publish with 10 second expiry (refreshed every batch)
            self.redis.setex('stats:retry_queue_size', 10, retry_queue_size)
            self.redis.setex('stats:scanner_retry_queue_size', 10, scanner_retry_size)

        except Exception as e:
            LOG.debug("Failed to publish stats: %s", e)

    def _find_scanner_queue(self, scanner_name: Optional[str]) -> Optional[str]:
        if not scanner_name:
            return None

        if scanner_name in self.cfg.scanner_queue_map:
            return self.cfg.scanner_queue_map[scanner_name]

        # Fallback to fuzzy match (e.g., sslyze -> robot-sslyze)
        for name, queue in self.cfg.scanner_queue_map.items():
            if scanner_name.endswith(name) or name.endswith(scanner_name):
                return queue
        return None

    def _enqueue_scanner_retry(self, data: Dict) -> None:
        """Store a scanner retry request to be re-queued later."""
        if not data.get("to_retry", False):
            return

        scanner = data.get("scanner")
        queue = self._find_scanner_queue(scanner)
        if not queue:
            LOG.warning("Received rerun request for unknown scanner '%s'", scanner)
            return

        host = {
            "ip": data.get("ip"),
            "domain": data.get("domain"),
            "port": data.get("port", 443),
            "target": data.get("domain") or data.get("ip"),
        }
        if not host.get("ip") and not host.get("domain"):
            LOG.debug("Skipping rerun with no target: %s", data)
            return

        with self._scanner_retry_lock:
            self.scanner_retry_buffer[queue].append({
                "host": host,
                "scanner": scanner,
                "due_at": time.time() + self.scanner_retry_delay,
            })

        LOG.info("Queued rerun for %s (%s) in %ds", host.get("ip") or host.get("target"),
                 scanner, self.scanner_retry_delay)

    def _pop_ready_scanner_retries(self) -> Dict[str, List[Dict]]:
        now = time.time()
        ready: Dict[str, List[Dict]] = defaultdict(list)
        with self._scanner_retry_lock:
            for queue, entries in list(self.scanner_retry_buffer.items()):
                remaining = []
                for entry in entries:
                    if entry.get("due_at", 0) <= now:
                        ready[queue].append(entry)
                    else:
                        remaining.append(entry)
                if remaining:
                    self.scanner_retry_buffer[queue] = remaining
                else:
                    self.scanner_retry_buffer.pop(queue, None)
        return ready

    def _push_scanner_retry_batch(self, queue: str, entries: List[Dict]) -> None:
        if not entries:
            return

        hosts = [entry.get("host", {}) for entry in entries]
        batch_id = f"retry-{uuid.uuid4()}"
        payload = {
            "batch_id": batch_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "count": len(hosts),
            "hosts": hosts,
        }

        if self.cfg.max_backlog > 0:
            backlog = self.redis.llen(queue)
            while backlog >= self.cfg.max_backlog:
                LOG.info("Retry queue %s backlog %d >= %d, waiting...", queue, backlog, self.cfg.max_backlog)
                time.sleep(2)
                backlog = self.redis.llen(queue)

        self.redis.lpush(queue, json.dumps(payload))
        LOG.info("Scheduled %d retry hosts to %s (batch %s)", len(hosts), queue, batch_id)

    def _scanner_retry_loop(self) -> None:
        """Background loop to flush scanner reruns once their delay elapses."""
        LOG.info("Scanner retry scheduler active (delay %ds)", self.scanner_retry_delay)
        while True:
            ready = self._pop_ready_scanner_retries()
            for queue, hosts in ready.items():
                # Chunk to avoid oversized batches
                chunk_size = max(1, min(self.cfg.scanner_batch_size, len(hosts)))
                for i in range(0, len(hosts), chunk_size):
                    batch_entries = hosts[i:i + chunk_size]
                    # Increment per-scanner requeue counter
                    for entry in batch_entries:
                        scanner = entry.get("scanner")
                        if scanner:
                            self._incr_counter(f"scanner:{scanner}:requeued", 1)
                    self._push_scanner_retry_batch(queue, batch_entries)
            time.sleep(2)

    def _collect_results(self) -> None:
        """Collect normalized results from scanners and write to file."""
        LOG.info("Result collector listening on queue %s", self.cfg.results_queue)

        while True:
            item = self.redis.blpop(self.cfg.results_queue, timeout=5)
            if not item:
                continue

            _, payload = item
            with self._log_lock:
                self.results_log.write(payload.rstrip("\n") + "\n")
                self.results_log.flush()

            try:
                data = json.loads(payload)
                scanner = data.get("scanner")
                if scanner:
                    self._incr_counter(f"scanner:{scanner}:total", 1)
                    if data.get("vulnerable"):
                        self._incr_counter(f"scanner:{scanner}:vulnerable", 1)
                    if data.get("to_retry"):
                        self._incr_counter(f"scanner:{scanner}:to_retry", 1)

                    # Track unique domains/IPs that produced results
                    target_id = data.get("target") or data.get("domain") or data.get("ip")
                    if target_id:
                        if data.get("vulnerable"):
                            self._log_vulnerable_target(target_id)
                        try:
                            self.redis.sadd(f"stats:scanner:{scanner}:results:set", target_id)
                            if data.get("to_retry"):
                                self.redis.sadd(f"stats:scanner:{scanner}:retry:set", target_id)
                        except Exception:
                            LOG.debug("Failed to update unique result sets for %s", scanner)
                self._incr_counter("normalized_total", 1)
                self._enqueue_scanner_retry(data)
            except json.JSONDecodeError:
                continue

    def _log_vulnerable_target(self, target_id: str) -> None:
        """Log a vulnerable target to a dedicated file per scanner."""
        vuln_log_path = self.cfg.vulnerable_file
        try:
            with vuln_log_path.open("a", encoding="utf-8") as vuln_log:
                vuln_log.write(f"{target_id}\n")
        except Exception as exc:
            LOG.debug("Failed to log vulnerable target %s: %s", target_id, exc)

    def _incr_counter(self, field: str, amount: int) -> None:
        if amount <= 0:
            return
        try:
            self.redis.hincrby(self.counter_key, field, amount)
        except Exception as exc:
            LOG.debug("Failed to increment counter %s by %d: %s", field, amount, exc)

    def _requeue_batch(self, hosts: List[Dict]) -> None:
        """Push timed-out batch back into retry queue with initial attempt count."""
        with self._retry_lock:
            for host in hosts:
                self.retry_queue.append({
                    "ip": host.get("ip"),
                    "domain": host.get("domain"),
                    "target": host.get("target") or host.get("ip"),
                    "port": host.get("port", 443),
                    "attempts": 1,
                    "target_type": host.get("target_type"),
                    "next_due": self._compute_retry_due(1),
                })
        LOG.info("Added %d hosts to retry queue (size now %d)", len(hosts), len(self.retry_queue))

    def _compute_retry_due(self, attempts: int) -> float:
        """Compute next retry time with capped exponential backoff (factor 1.5)."""
        delay = self.retry_base_delay * (1.5 ** max(attempts - 1, 0))
        delay = min(delay, self.retry_max_delay)
        return time.time() + delay


def load_config() -> Config:
    """Load configuration from environment variables."""
    def env_int_with_fallback(names, default=None) -> int:
        for name in names:
            val = os.getenv(name)
            if val is not None:
                try:
                    return int(val)
                except ValueError:
                    continue
        if default is not None:
            return default
        return int(require_env(names[0]))

    scanner_raw = require_env("SCANNER_QUEUES")
    scanner_queues: List[str] = []
    scanner_queue_map: Dict[str, str] = {}

    for entry in scanner_raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            name, queue = entry.split(":", 1)
            name = name.strip()
            queue = queue.strip()
        else:
            name = entry
            queue = entry

        if not name or not queue:
            continue
        scanner_queue_map[name] = queue
        scanner_queues.append(queue)

    if not scanner_queues:
        raise ValueError("SCANNER_QUEUES must define at least one queue")

    retry_delay = int(os.getenv("SCANNER_RETRY_DELAY_SECONDS", "120"))
    zgrab_batch_size = env_int_with_fallback(["ZGRAB_BATCH_SIZE", "BATCH_SIZE"])
    zgrab_batch_timeout = env_int_with_fallback(["ZGRAB_BATCH_TIMEOUT_SECONDS", "BATCH_TIMEOUT_SECONDS"])
    scanner_batch_size = env_int_with_fallback(["SCANNER_BATCH_SIZE"], zgrab_batch_size)
    scanner_batch_timeout = env_int_with_fallback(["SCANNER_BATCH_TIMEOUT_SECONDS"], zgrab_batch_timeout)

    return Config(
        redis_host=require_env("REDIS_HOST"),
        input_queue=require_env("INPUT_QUEUE"),
        zgrab2_request_queue=require_env("ZGRAB2_REQUEST_QUEUE"),
        zgrab2_results_queue=require_env("ZGRAB2_RESULTS_QUEUE"),
        scanner_queues=scanner_queues,
        scanner_queue_map=scanner_queue_map,
        scanner_retry_delay=retry_delay,
        results_queue=require_env("RESULTS_QUEUE"),
        zgrab_batch_size=zgrab_batch_size,
        zgrab_batch_timeout=zgrab_batch_timeout,
        scanner_batch_size=scanner_batch_size,
        scanner_batch_timeout=scanner_batch_timeout,
        max_backlog=int(require_env("MAX_QUEUE_BACKLOG")),
        zgrab2_max_retries=int(require_env("ZGRAB2_MAX_RETRIES")),
        zgrab_log_file=Path(require_env("ZGRAB_LOG_FILE")),
        batch_log_file=Path(require_env("BATCH_LOG_FILE")),
        results_file=Path(require_env("RESULTS_FILE")),
        vulnerable_file=Path(require_env("VULNERABLE_FILE")),
    )


def main() -> None:
    cfg = load_config()
    manager = JobManager(cfg)
    manager.start()


if __name__ == "__main__":
    main()
