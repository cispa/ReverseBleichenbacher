#!/usr/bin/env python3
"""ROBOT scanner worker using the python robot-detect implementation."""

import json
import logging
import os
import queue
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import threading

import redis

level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)
LOG = logging.getLogger(__name__)
LOG.setLevel(level)


def require_env(var: str) -> str:
    value = os.getenv(var)
    if not value:
        LOG.error("%s environment variable must be set", var)
        sys.exit(1)
    return value


class RobotPythonWorker:
    """ROBOT vulnerability scanner using robot-detect."""

    def __init__(self) -> None:
        self.redis_host = require_env("REDIS_HOST")
        self.batch_queue = require_env("BATCH_QUEUE")
        self.results_file = require_env("RESULTS_FILE")
        self.results_queue = require_env("RESULTS_QUEUE")
        self.status_counts_key = os.getenv(
            "STATUS_COUNTS_KEY", f"{self.results_queue}:status-counts"
        )
        self.worker_id = os.getenv("HOSTNAME", "worker")
        self.max_workers = int(require_env("CONCURRENCY"))
        self.timeout = int(require_env("TIMEOUT"))
        self.scan_port = int(os.getenv("SCAN_PORT", "443"))
        self.scan_mode = os.getenv("ROBOT_PYTHON_MODE", "standard").strip().lower()
        if self.scan_mode not in ("standard", "fast"):
            LOG.warning("Invalid ROBOT_PYTHON_MODE '%s', falling back to 'standard'", self.scan_mode)
            self.scan_mode = "standard"
        self.detector_script = "./robot-detect-fast.py" if self.scan_mode == "fast" else "./robot-detect"

        host, port = self.redis_host.split(":")
        self.redis = redis.Redis(
            host=host,
            port=int(port),
            decode_responses=True,
        )

        self.results_handle = open(self.results_file, "a", encoding="utf-8")
        LOG.info("Connected to Redis at %s", self.redis_host)
        LOG.info("Results file: %s", self.results_file)
        LOG.info("Normalized results queue: %s", self.results_queue)
        LOG.info("Status counts key: %s", self.status_counts_key)
        LOG.info(
            "Concurrent workers: %s, timeout: %ss, port: %s",
            self.max_workers,
            self.timeout,
            self.scan_port,
        )
        LOG.info("ROBOT scanner mode: %s (%s)", self.scan_mode, self.detector_script)
        self.queue_refill_threshold = int(os.getenv("LOCAL_QUEUE_REFILL", str(self.max_workers)))
        self.local_queue_size = int(os.getenv("LOCAL_QUEUE_SIZE", str(self.max_workers * 4)))

        self.scanned = 0
        self.vulnerable = 0
        self.last_log_time = time.time()
        self._metrics_lock = threading.Lock()

    def run(self) -> None:
        LOG.info("Robot Python Scanner Worker started (ID: %s)", self.worker_id)
        LOG.info("Batch queue: %s", self.batch_queue)

        task_queue: queue.Queue[Tuple[str, Dict]] = queue.Queue(maxsize=self.local_queue_size)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for _ in range(self.max_workers):
                executor.submit(self._scan_worker, task_queue)

            while True:
                try:
                    if task_queue.qsize() >= self.queue_refill_threshold:
                        time.sleep(1)
                        continue

                    _, batch_json = self.redis.blpop(self.batch_queue)
                    batch = json.loads(batch_json)
                    batch_id = batch.get("batch_id")
                    hosts = batch.get("hosts", [])
                    if not batch_id or not hosts:
                        LOG.warning("Received invalid batch: %s", batch)
                        continue

                    LOG.info("[%s] Ingesting batch %s with %s hosts", self.worker_id, batch_id, len(hosts))
                    for host in hosts:
                        task_queue.put((batch_id, host))
                except KeyboardInterrupt:
                    LOG.info("Shutting down...")
                    break

    def _scan_worker(self, task_queue: queue.Queue[Tuple[str, Dict]]) -> None:
        while True:
            batch_id, host = task_queue.get()
            try:
                scan_result = self.scan_host(host)
            except Exception as exc:  # pragma: no cover - defensive path
                target, target_port, target_ip, domain = self._target_details(host)
                LOG.warning("[%s] Scan failed for %s:%s: %s", self.worker_id, target_ip, target_port, exc)
                scan_result = self._result_template(target_ip, target_port, domain, error=str(exc))

            self._increment_status(scan_result.get("status"))
            self.write_result(scan_result)
            self.push_normalized_result(batch_id, scan_result)

            with self._metrics_lock:
                self.scanned += 1
                if scan_result.get("vulnerable"):
                    self.vulnerable += 1

                now = time.time()
                if now - self.last_log_time >= 30:
                    LOG.info(
                        "[%s] Scanned %s hosts, found %s vulnerable",
                        self.worker_id,
                        self.scanned,
                        self.vulnerable,
                    )
                    self.last_log_time = now

            task_queue.task_done()

    def process_batch(self, batch_id: str, hosts: List[Dict]) -> None:
        LOG.info("[%s] Batch %s: scanning %s hosts",
                 self.worker_id, batch_id, len(hosts))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan_host, host): host for host in hosts
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    scan_result = future.result()
                except Exception as exc:  # pragma: no cover - defensive path
                    target, target_port, target_ip, domain = self._target_details(host)
                    LOG.warning("[%s] Scan failed for %s:%s: %s", self.worker_id, target_ip, target_port, exc)
                    scan_result = self._result_template(target_ip, target_port, domain, error=str(exc))

                self._increment_status(scan_result.get("status"))
                self.write_result(scan_result)
                self.push_normalized_result(batch_id, scan_result)

                self.scanned += 1
                if scan_result.get("vulnerable"):
                    self.vulnerable += 1

                now = time.time()
                if now - self.last_log_time >= 30:
                    LOG.info(
                        "[%s] Scanned %s hosts, found %s vulnerable",
                        self.worker_id,
                        self.scanned,
                        self.vulnerable,
                    )
                    self.last_log_time = now

    def scan_host(self, host: Dict) -> Dict:
        target, port, ip, domain = self._target_details(host)
        per_query_timeout = (self.timeout-5)//10 if self.timeout else 5

        cmd = [
            self.detector_script,
            target,
            "-p",
            str(port),
            "--csv",
            # "-q",  # Quiet mode to suppress extra output
        ]
        if self.scan_mode == "fast":
            cmd.extend(["-t", str(self.timeout)])
        else:
            cmd.extend(["--no-retry-flow", "--timeout-standard", str(per_query_timeout)])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._result_template(
                target,
                port,
                domain,
                error="Timeout",
                status="TIMEOUT",
                retry=True,
            )

        raw_stdout = proc.stdout or ""
        raw_stderr = proc.stderr or ""

        if proc.returncode != 0 or raw_stderr != "":
            LOG.warning("Host %s: %s error (return code %s): %s",
                        target, self.detector_script, proc.returncode, raw_stderr.strip())
            return self._result_template(
                target,
                port,
                domain,
                error=f"{self.detector_script} failed",
                status="ERROR",
                extra={
                    "returncode": proc.returncode,
                    "stderr": raw_stderr.strip(),
                    "stdout": raw_stdout.strip(),
                },
                retry=True,
            )

        for line in raw_stdout.strip().splitlines():
            # if line.startswith(("VULNERABLE", "NOT_VULNERABLE")):
            parts = line.split(",")
            if len(parts) < 8:
                continue
            status, hostname, parsed_ip, tls_version, vuln_level, flow, server_answer_good, server_answer_bad1 = parts[:8]
            if status not in ("VULNERABLE", "SAFE", "INCONSISTENT", "NORSA", "NOTLS", "NODNS"):
                LOG.warning("Host %s: unexpected status '%s' in output: %s", target, status, line)
                continue
            result = self._result_template(parsed_ip or ip, port, domain, status=status)
            if hostname and hostname != parsed_ip:
                result["hostname"] = hostname
                result["domain"] = result.get("domain") or hostname
            result["vulnerable"] = status == "VULNERABLE"
            result["vulnerability_level"] = vuln_level if result["vulnerable"] else "not_vulnerable"
            result["details"] = {"tls_version": tls_version, "server_answer_good": server_answer_good, "server_answer_bad": server_answer_bad1, "flow": flow}
            return result

        # Unrecognized output; include raw stdout for debugging
        result = self._result_template(
            target,
            port,
            domain,
            error="Could not parse robot-detect output",
            status="PARSING_ERROR",
            extra={"stdout": raw_stdout.strip(), "stderr": raw_stderr.strip()},
        )
        return result

    def _target_details(self, host: Dict | str) -> Tuple[str, int, str, Optional[str]]:
        if isinstance(host, dict):
            raw_ip = host.get("ip") or host.get("host") or host.get("target") or "unknown"
            domain = host.get("domain")
            ip = str(raw_ip)
            target = domain or host.get("target") or ip
            raw_port = host.get("port", self.scan_port)
            port = int(raw_port) if raw_port is not None else self.scan_port
        else:
            ip = str(host)
            target = ip
            domain = None
            port = self.scan_port
        return target, port, ip, domain

    def _result_template(self, ip: str, port: int, domain: Optional[str], error: Optional[str] = None, retry: Optional[bool] = None, extra: Optional[Dict] = None, status: Optional[str] = None) -> Dict:
        result = {
            "ip": ip,
            "port": port,
            "domain": domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "robot-python",
            "vulnerable": False,
            "vulnerability_level": "not_vulnerable",
        }
        if error:
            result["error"] = error
        if status:
            result["status"] = status
        if extra:
            result["details"] = extra
        # Default behavior: if there's an error and retry is not explicitly set, mark for retry
        if retry is None and error:
            result["to_retry"] = True
        elif retry:
            result["to_retry"] = True
        return result

    def write_result(self, result: Dict) -> None:
        self.results_handle.write(json.dumps(result) + "\n")
        self.results_handle.flush()

    def push_normalized_result(self, batch_id: str, scan_result: Dict) -> None:
        payload = {
            "batch_id": batch_id,
            "ip": scan_result["ip"],
            "domain": scan_result.get("domain"),
            "port": scan_result["port"],
            "scanner": "robot-python",
            "scanned_at": scan_result.get("scanned_at"),
            "vulnerable": scan_result.get("vulnerable", False),
            "vulnerability_level": scan_result.get("vulnerability_level", "unknown"),
            "error": scan_result.get("error"),
            "to_retry": scan_result.get("to_retry", False),
            "details": scan_result.get("details"),
            "status": scan_result.get("status"),
        }
        self.redis.rpush(self.results_queue, json.dumps(payload))

    def close(self) -> None:
        self.results_handle.close()

    def _increment_status(self, status: Optional[str]) -> None:
        """Increment status counters in Redis for quick stats lookup."""
        if not status:
            return
        try:
            self.redis.hincrby(self.status_counts_key, status, 1)
        except Exception as exc:  # pragma: no cover - defensive path
            LOG.warning("Failed to increment status %s: %s", status, exc)


def main() -> None:
    worker = RobotPythonWorker()
    try:
        worker.run()
    except KeyboardInterrupt:
        LOG.info("Shutting down...")
    finally:
        worker.close()


if __name__ == "__main__":
    main()
