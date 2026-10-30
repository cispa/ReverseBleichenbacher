#!/usr/bin/env python3
"""ROBOT Scanning Pipeline - CLI for managing Docker Compose services."""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

import redis
import yaml


def detect_default_interface():
    """
    Detect the default network interface and its parameters.

    Returns dict with keys: interface, subnet, gateway, ip_range
    Returns None if detection fails.
    """
    try:
        # Get the default route to find the default interface
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None

        # Parse: "default via 192.168.10.1 dev enp3s0 proto dhcp ..."
        match = re.search(r'default via (\S+) dev (\S+)', result.stdout)
        if not match:
            return None

        gateway = match.group(1)
        interface = match.group(2)

        # Get interface IP and subnet
        result = subprocess.run(
            ["ip", "-o", "addr", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None

        # Parse: "2: enp3s0    inet 192.168.10.125/24 brd ..."
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
        if not match:
            return None

        host_ip = match.group(1)
        prefix_len = int(match.group(2))

        # Calculate subnet
        network = ipaddress.ip_network(f"{host_ip}/{prefix_len}", strict=False)
        subnet = str(network)

        # Choose IP range for containers: pick .200/28 (16 IPs) if available
        # Avoid the host IP
        base_ip = network.network_address
        # Use .200-.215 range (or equivalent in the subnet)
        ip_range_start = base_ip + 200
        if ip_range_start in network and (base_ip + 215) in network:
            ip_range = f"{ip_range_start}/28"
        else:
            # Fallback: use last /28 of the subnet
            last_usable = network.broadcast_address - 16
            ip_range = f"{last_usable}/28"

        return {
            'interface': interface,
            'subnet': subnet,
            'gateway': gateway,
            'ip_range': ip_range,
            'host_ip': host_ip,
        }

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


class Pipeline:
    """Manages ROBOT scanning pipeline via Docker Compose."""
    
    def __init__(self, config_file="config/default.yaml"):
        """Initialize pipeline with YAML config file."""
        self.config = self._load_config(config_file)
        self.compose_file = self.config['compose']['file']
        self.project_name = self.config['compose']['project_name']
        self._network_enabled = self.config.get('network', {}).get('enabled', False)

    def _load_config(self, config_file):
        """Load and validate YAML config file."""
        config_path = Path(config_file)

        if not config_path.exists():
            print(f"Error: Config file not found: {config_file}")
            print("The default config is at config/default.yaml")
            sys.exit(1)

        try:
            with config_path.open() as f:
                config = yaml.safe_load(f)
                if not config:
                    print(f"Error: Config file {config_file} is empty")
                    sys.exit(1)
                return config
        except Exception as e:
            print(f"Error: Failed to load config from {config_file}: {e}")
            sys.exit(1)

    def _get_compose_files(self):
        """Get list of compose files to use."""
        files = [self.compose_file]
        if self._network_enabled:
            files.append("docker-compose.scannet.yml")
        return files

    def _run_compose(self, args, check=False, capture_output=False):
        """Run docker compose command with project config."""
        cmd = ["docker", "compose"]
        for f in self._get_compose_files():
            cmd.extend(["-f", f])
        cmd.extend(["-p", self.project_name])
        cmd.extend(args)

        if capture_output:
            return subprocess.run(cmd, check=check, capture_output=True, text=True)
        else:
            return subprocess.run(cmd, check=check)

    def _set_env_from_config(self):
        """Set environment variables from config for docker-compose to use."""
        # Network (macvlan for dedicated scan interface)
        network_config = self.config.get('network', {})
        if network_config.get('enabled', False):
            # Auto-detect missing values
            detected = None
            def get_or_detect(key, detected_key):
                nonlocal detected
                if key in network_config and network_config[key] != 'auto':
                    return str(network_config[key])
                if detected is None:
                    detected = detect_default_interface()
                if detected and detected_key in detected:
                    return str(detected[detected_key])
                return None

            interface = get_or_detect('scan-interface', 'interface')
            subnet = get_or_detect('scan-subnet', 'subnet')
            gateway = get_or_detect('scan-gateway', 'gateway')
            ip_range = get_or_detect('scan-ip-range', 'ip_range')

            if interface:
                os.environ['SCAN_INTERFACE'] = interface
            if subnet:
                os.environ['SCAN_SUBNET'] = subnet
            if gateway:
                os.environ['SCAN_GATEWAY'] = gateway
            if ip_range:
                os.environ['SCAN_IP_RANGE'] = ip_range

            # Print detected values
            if detected:
                print(f"[scan.py] Auto-detected network: {interface} ({subnet}, gw {gateway})")
                print(f"[scan.py] Container IP range: {ip_range}")

        # Redis
        redis_config = self.config.get('redis', {})
        if 'port' in redis_config:
            os.environ['REDIS_HOST_PORT'] = str(redis_config['port'])

        # ZMap
        zmap_config = self.config.get('zmap', {})
        if 'scan-port' in zmap_config:
            os.environ['SCAN_PORT'] = str(zmap_config['scan-port'])
        if 'scan-rate' in zmap_config:
            os.environ['SCAN_RATE'] = str(zmap_config['scan-rate'])
        if 'bandwidth' in zmap_config and zmap_config['bandwidth']:
            os.environ['BANDWIDTH'] = str(zmap_config['bandwidth'])
        if 'log-interval' in zmap_config:
            os.environ['LOG_INTERVAL'] = str(zmap_config['log-interval'])

        # ZGrab2
        zgrab2_config = self.config.get('zgrab2', {})
        if 'connect-timeout' in zgrab2_config:
            os.environ['ZGRAB2_CONNECT_TIMEOUT'] = str(zgrab2_config['connect-timeout'])
        if 'target-timeout' in zgrab2_config:
            os.environ['ZGRAB2_TARGET_TIMEOUT'] = str(zgrab2_config['target-timeout'])
        if 'max-retries' in zgrab2_config:
            os.environ['ZGRAB2_MAX_RETRIES'] = str(zgrab2_config['max-retries'])
        if 'log-level' in zgrab2_config:
            os.environ['ZGRAB2_LOG_LEVEL'] = str(zgrab2_config['log-level'])

        # Job Manager
        jm_config = self.config.get('job-manager', {})
        zgrab_cfg = jm_config.get('zgrab', {})
        scanner_cfg = jm_config.get('scanners', {})

        if 'batch-size' in zgrab_cfg:
            os.environ['ZGRAB_BATCH_SIZE'] = str(zgrab_cfg['batch-size'])
        elif 'batch-size' in jm_config:  # backwards compatibility
            os.environ['ZGRAB_BATCH_SIZE'] = str(jm_config['batch-size'])

        if 'batch-timeout-seconds' in zgrab_cfg:
            os.environ['ZGRAB_BATCH_TIMEOUT_SECONDS'] = str(
                zgrab_cfg['batch-timeout-seconds'])
        elif 'batch-timeout-seconds' in jm_config:
            os.environ['ZGRAB_BATCH_TIMEOUT_SECONDS'] = str(
                jm_config['batch-timeout-seconds'])

        if 'batch-size' in scanner_cfg:
            os.environ['SCANNER_BATCH_SIZE'] = str(scanner_cfg['batch-size'])
        if 'batch-timeout-seconds' in scanner_cfg:
            os.environ['SCANNER_BATCH_TIMEOUT_SECONDS'] = str(
                scanner_cfg['batch-timeout-seconds'])

        if 'max-queue-backlog' in jm_config:
            os.environ['MAX_QUEUE_BACKLOG'] = str(
                jm_config['max-queue-backlog'])

        # Scanner configs - unified interface for all scanners
        # All scanners use the same env var names: CONCURRENCY and TIMEOUT
        # Scanners are prefixed with their uppercase scanner name
        bleichenbacher_scanners = self.config.get(
            'bleichenbacher-scanners', {})

        for scanner_name, scanner_config in bleichenbacher_scanners.items():
            if not isinstance(scanner_config, dict):
                continue

            # Convert scanner-name to SCANNER_NAME for env var prefix
            env_prefix = scanner_name.upper().replace('-', '_')

            # Set unified env vars
            if 'concurrency' in scanner_config:
                os.environ[f'{env_prefix}_CONCURRENCY'] = str(
                    scanner_config['concurrency'])
            if 'timeout' in scanner_config:
                os.environ[f'{env_prefix}_TIMEOUT'] = str(
                    scanner_config['timeout'])
            if 'mode' in scanner_config:
                os.environ[f'{env_prefix}_MODE'] = str(
                    scanner_config['mode'])

    def start(self):
        """Start pipeline with all enabled services."""
        print("[scan.py] Starting pipeline...")

        # Set environment variables from config for docker-compose
        self._set_env_from_config()

        # Ensure results directory exists
        results_dir = Path(self.config.get('results', {}).get('directory', 'results'))
        results_dir.mkdir(parents=True, exist_ok=True)
        logs_dir = results_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        scanners_dir = results_dir / "scanners"
        scanners_dir.mkdir(parents=True, exist_ok=True)
        # Make it world-writable so Docker containers can write to it
        os.chmod(results_dir, 0o777)
        os.chmod(logs_dir, 0o777)
        os.chmod(scanners_dir, 0o777)

        # Base services (always started)
        services = [
            "redis",
            "redis-insight",
            "zgrab2-worker",
            "job-manager",
        ]

        # Add enabled scanners from config
        enabled_scanners = []
        scanner_queues = []

        bleichenbacher_scanners = self.config.get(
            'bleichenbacher-scanners', {})
        for scanner_name, scanner_config in bleichenbacher_scanners.items():
            if scanner_config.get('enabled', False):
                # Derive service name from scanner name (e.g., robot-go -> robot-scanner-go)
                service_name = f"robot-scanner-{scanner_name.replace('robot-', '')}"
                services.append(service_name)
                enabled_scanners.append(scanner_name)

                # Derive queue name from scanner name (e.g., robot-go -> robot-go-batches)
                queue_name = f"{scanner_name}-batches"
                scanner_queues.append(f"{scanner_name}:{queue_name}")

        if not enabled_scanners:
            print(
                "[scan.py] WARNING: No Bleichenbacher/ROBOT scanners enabled in config")
            print(
                "[scan.py] Enable at least one scanner in bleichenbacher-scanners to perform ROBOT scans")

        # Set environment variable for job manager with enabled scanner queues
        if scanner_queues:
            os.environ['SCANNER_QUEUES'] = ','.join(scanner_queues)

        print(
            f"[scan.py] Enabled scanners: {', '.join(enabled_scanners) if enabled_scanners else 'none'}")

        # Use --force-recreate to ensure config changes are picked up
        self._run_compose(["up", "-d", "--force-recreate"] + services)
        print("[scan.py] Pipeline started")

    def stop(self):
        """Stop all services except Redis."""
        print("[scan.py] Stopping pipeline services (keeping Redis running)...")

        # Get all services except redis
        services_to_stop = []

        # Base services (except redis)
        services_to_stop.extend(["zgrab2-worker", "job-manager"])

        # Add enabled scanners
        bleichenbacher_scanners = self.config.get('bleichenbacher-scanners', {})
        for scanner_name, scanner_config in bleichenbacher_scanners.items():
            if scanner_config.get('enabled', False):
                service_name = f"robot-scanner-{scanner_name.replace('robot-', '')}"
                services_to_stop.append(service_name)

        self._run_compose(["stop"] + services_to_stop)
        self._run_compose(["rm", "-f"] + services_to_stop)
        print("[scan.py] Pipeline services stopped")

    def inject(self, input_file, redis_host=None, redis_port=None, queue=None, target_type="domain"):
        """Inject domains or IPs from file into Redis queue."""
        if target_type not in ("domain", "ip"):
            print("[scan.py] ERROR: --type must be 'domain' or 'ip'")
            sys.exit(1)

        if not os.path.exists(input_file):
            print(f"[scan.py] ERROR: File not found: {input_file}")
            sys.exit(1)

        # Use config defaults if not specified
        redis_host = redis_host or self.config['redis']['host']
        redis_port = redis_port or self.config['redis']['port']
        queue = queue or 'input-targets'

        print(f"[scan.py] Injecting {target_type}s from {input_file} -> queue '{queue}'")

        try:
            r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            r.ping()
        except Exception as exc:
            print(f"[scan.py] ERROR: Could not connect to Redis at {redis_host}:{redis_port}: {exc}")
            sys.exit(1)

        count = 0
        last_log_time = time.time()
        log_interval = 5.0  # Log every 5 seconds

        with open(input_file, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                payload_obj = {
                    "target": line,
                    "target_type": target_type,
                }

                payload = json.dumps(payload_obj)
                try:
                    r.rpush(queue, payload)
                    count += 1

                    # Time-based logging to avoid spam with large files
                    now = time.time()
                    if now - last_log_time >= log_interval:
                        print(f"[scan.py] Loaded {count} entries...")
                        last_log_time = now

                except Exception as exc:
                    print(f"[scan.py] WARNING: Failed to push {line}: {exc}")

        print(f"[scan.py] Loaded {count} entries into queue '{queue}'")

    def zmap(self, target_range, rate=10000, bandwidth=None):
        """Scan network range with ZMap and inject IPs to pipeline."""
        print(f"[scan.py] Starting ZMap scan: {target_range}")
        print(f"[scan.py] Rate: {rate} pps")
        if bandwidth:
            print(f"[scan.py] Bandwidth: {bandwidth}")

        # Ensure compose env (SCAN_PORT, REDIS_HOST_PORT, etc.) mirrors config defaults
        self._set_env_from_config()

        # Pass parameters as environment variables via docker compose run -e
        # These override the defaults in docker-compose.yml
        # SCAN_PORT is set from config via _set_env_from_config()
        env_args = [
            "-e", f"TARGET_RANGE={target_range}",
            "-e", f"SCAN_RATE={rate}"
        ]
        if bandwidth:
            env_args.extend(["-e", f"BANDWIDTH={bandwidth}"])

        self._run_compose(["run", "--rm"] + env_args + ["zmap-scanner"])
        print("[scan.py] ZMap scan complete")

    def reset(self):
        """Reset pipeline to default ready state: stop services, clear queues, delete results, rebuild."""
        print("[scan.py] Resetting pipeline to default ready state...")

        # Step 1: Stop all services
        print("[scan.py] Stopping services...")
        self._run_compose(["down", "-v"])

        # Step 2: Delete all result files and recreate directory with correct permissions
        print("[scan.py] Clearing result files...")
        results_dir = Path(self.config.get('results', {}).get('directory', 'results'))
        if not results_dir.exists():
            results_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(results_dir, 0o777)
        vulnerable_file = results_dir / "vulnerable.txt"
        logs_dir = results_dir / "logs"
        scanners_dir = results_dir / "scanners"
        # Remove dirs
        shutil.rmtree(logs_dir, ignore_errors=True)
        shutil.rmtree(scanners_dir, ignore_errors=True)
        print(f"[scan.py] Cleared contents of {results_dir}/ (preserving {vulnerable_file.name})")

        # Recreate with current user permissions
        logs_dir.mkdir(parents=True, exist_ok=True)
        scanners_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(scanners_dir, 0o777)
        os.chmod(logs_dir, 0o777)
        print(f"[scan.py] Results directory ready at {results_dir}/")

        # Step 2b: Clear Redis counters used for status
        redis_host = self.config['redis']['host']
        redis_port = self.config['redis']['port']
        try:
            r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            r.delete('stats:counters')
            r.delete('stats:retry_queue_size')
            # Clear scanner unique sets
            keys_to_delete = []
            for pattern in ("stats:scanner:*:results:set", "stats:scanner:*:retry:set",
                            "stats:zgrab2:results:set", "stats:zgrab2:retry:set",
                            "stats:zgrab2:no_rsa:set", "stats:zgrab2:removed:set",
                            "stats:zgrab2:rsa:set"):
                try:
                    keys_to_delete.extend(list(r.scan_iter(match=pattern)))
                except Exception:
                    continue
            if keys_to_delete:
                r.delete(*keys_to_delete)
            print("[scan.py] Cleared Redis stats counters")
        except Exception as exc:
            print(f"[scan.py] WARNING: Failed to clear Redis counters: {exc}")

        # Step 3: Rebuild services
        print("[scan.py] Rebuilding services...")
        self._set_env_from_config()
        self._run_compose(["build"])

        print("[scan.py] Reset complete - pipeline is ready to start")

    def status(self):
        """Show live pipeline status."""
        self._status_simple()

    def _status_simple(self):
        """Display status with queue depths and scan rates."""
        prev_stats = {}
        prev_network = {}

        # ANSI color codes
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        CLEAR = '\033[H\033[J'  # Move cursor to home and CLEAR screen

        # Get config values
        redis_host = self.config['redis']['host']
        redis_port = self.config['redis']['port']

        try:
            while True:
                print(CLEAR, end='')

                try:
                    r = redis.Redis(host=redis_host,
                                    port=redis_port, decode_responses=True)

                    # Get queue depths
                    input_ips = r.llen('input-targets')
                    zgrab2_requests = r.llen('zgrab2-requests')
                    zgrab2_results = r.llen('zgrab2-results')
                    results_queue = r.llen('robot-results')

                    # Get scanner-specific queue depths dynamically
                    scanner_queues = {}
                    bleichenbacher_scanners = self.config.get(
                        'bleichenbacher-scanners', {})
                    for scanner_name, scanner_config in bleichenbacher_scanners.items():
                        if scanner_config.get('enabled', False):
                            queue_name = f"{scanner_name}-batches"
                            scanner_queues[scanner_name] = r.llen(queue_name)

                    # Get result counts
                    stats = self._get_detailed_stats()

                    # Get network stats
                    network_stats = self._get_network_stats()

                    rates = self._calculate_rates(prev_stats, stats)

                    # Calculate network rates (bytes/sec)
                    network_rates = {}
                    if prev_network:
                        for service, net_stat in network_stats.items():
                            if service in prev_network:
                                rx_diff = net_stat['rx_bytes'] - \
                                    prev_network[service]['rx_bytes']
                                tx_diff = net_stat['tx_bytes'] - \
                                    prev_network[service]['tx_bytes']
                                network_rates[service] = {
                                    'rx_rate': rx_diff / 2.0,  # 2 second interval
                                    'tx_rate': tx_diff / 2.0
                                }

                    # Header
                    separator = "-" * 90
                    uptime = self._get_uptime_seconds(r)
                    uptime_str = self._format_uptime(uptime) if uptime else "n/a"
                    print(f"{BOLD}{YELLOW}ROBOT Scan Status{RESET}    {WHITE}Uptime: {uptime_str}{RESET}")
                    print(f"{WHITE}{separator}{RESET}")

                    # Stage 1
                    zgrab2_stats = stats.get('zgrab2', {})
                    hosts_scanned = zgrab2_stats.get('total', 0)
                    total_inputs = zgrab2_stats.get('total_inputs', 0)
                    unique_scanned = zgrab2_stats.get('unique_results', 0)
                    unique_no_rsa = zgrab2_stats.get('unique_no_rsa', 0)
                    unique_removed = zgrab2_stats.get('unique_removed', 0)
                    unique_rsa_hosts = zgrab2_stats.get('unique_rsa', 0)
                    retry_unique = zgrab2_stats.get('retry_unique', 0)
                    retry_count = int(r.get('stats:retry_queue_size') or 0)
                    total_batches_waiting = sum(scanner_queues.values())
                    zgrab_rate = rates.get('zgrab2', 0)
                    zgrab_net = network_rates.get('zgrab2-worker')
                    removed_breakdown = zgrab2_stats.get('removed_by_status', {})

                    print(f"{BOLD}{YELLOW}Stage 1: TLS Scanning (zgrab2){RESET}")
                    print(f"{CYAN}  Input queue:       {input_ips}{RESET}")
                    print(f"{CYAN}  Retry buffer:      {retry_count}{RESET}")
                    print(f"{CYAN}  Batches to ROBOT:  {total_batches_waiting}{RESET}")
                    print(f"{WHITE}  Total inputs seen:   {total_inputs}{RESET}")
                    print(f"{WHITE}  Total scans:         {hosts_scanned} {self._fmt_rate(zgrab_rate)}{RESET}")
                    print(f"{WHITE}  Unique hosts:        {unique_scanned}{RESET}")
                    print(f"{WHITE}   |- RSA:             {unique_rsa_hosts} {self._fmt_pct(unique_rsa_hosts, unique_scanned)}{RESET}")
                    print(f"{WHITE}   |- NO-RSA:          {unique_no_rsa} {self._fmt_pct(unique_no_rsa, unique_scanned)}{RESET}")
                    print(f"{WHITE}   |- Retrying:        {retry_unique} {self._fmt_pct(retry_unique, unique_scanned)}{RESET}")
                    print(f"{WHITE}   `- Removed:         {unique_removed} {self._fmt_pct(unique_removed, unique_scanned)}{RESET}")
                    if removed_breakdown:
                        for status, count in sorted(removed_breakdown.items(), key=lambda item: item[1], reverse=True):
                            print(f"{WHITE}       |- {status}: {count}{RESET}")
                    if zgrab_net:
                        print(f"{WHITE}  Network:           {self._fmt_net(zgrab_net)}{RESET}")
                    print(f"{WHITE}{separator}{RESET}")

                    # Stage 2 (table)
                    print(f"{BOLD}{YELLOW}Stage 2: ROBOT Vulnerability Scanning{RESET}")
                    print(f"{WHITE}{'Scanner':<18}{'Queue':>8}{'Unique':>12}{'Vuln':>10}{'Retries':>10}{'Rate':>12}{'Net':>26}{RESET}")
                    scanner_stat_keys = {
                        'robot-python': 'python',
                        'robot-sslyze': 'sslyze',
                    }
                    total_scans_across_scanners = 0
                    for scanner_name in scanner_queues.keys():
                        stat_key = scanner_stat_keys.get(scanner_name, scanner_name)
                        scanner_stats = stats.get(stat_key, {})
                        total_results = scanner_stats.get('total', 0)
                        unique_total = scanner_stats.get('unique_total', total_results)
                        total_scans_across_scanners += unique_total
                        vuln = scanner_stats.get('vulnerable', 0)
                        retries = scanner_stats.get('unique_to_retry', scanner_stats.get('to_retry', 0))
                        rate = rates.get(stat_key, 0)
                        queue_depth = scanner_queues.get(scanner_name, 0)
                        service_name = f"robot-scanner-{scanner_name.replace('robot-', '')}"
                        net = network_rates.get(service_name)
                        net_str = self._fmt_net(net) if net else ""

                        print(f"{WHITE}{scanner_name:<18}{queue_depth:>8}{unique_total:>12}{vuln:>10}{retries:>10}{self._fmt_rate(rate):>12}{net_str:>26}{RESET}")
                    print(f"{WHITE}{separator}{RESET}")

                    # Stage 3
                    print(f"{BOLD}{YELLOW}Stage 3: Result Aggregation{RESET}")
                    match_stats = self._get_vulnerability_matches()
                    if match_stats:
                        num_scanners = match_stats.get('num_scanners', 0)
                        total_hosts = match_stats.get('total_hosts', 0)
                        print(f"{WHITE}  Scanners agree on:{RESET}")
                        for level in range(num_scanners, 0, -1):
                            key = f"{level}_of_{num_scanners}"
                            count = match_stats.get(key, 0)
                            label = f"{level} of {num_scanners}"
                            print(f"{WHITE}    {label}: {count}{RESET}")
                        print(f"{WHITE}  Vulnerable hosts (unique): {total_hosts}{RESET}")

                    print(f"{WHITE}  Total stage 2 scans: {total_scans_across_scanners}{RESET}")

                    prev_stats = stats
                    prev_network = network_stats

                except Exception as e:
                    print(f"Error: {e}")

                time.sleep(2)

        except KeyboardInterrupt:
            print("\nExiting...")
            return

    def _calculate_rates(self, prev_stats, stats):
        rates = {}
        if prev_stats:
            rate_fields = {
                'zgrab2': 'total',
                'python': 'total',
                'sslyze': 'total',
            }
            for key, field in rate_fields.items():
                if key in stats and key in prev_stats:
                    current = stats[key].get(field)
                    previous = prev_stats[key].get(field)
                    if current is not None and previous is not None:
                        rates[key] = (current - previous) / 2.0
        return rates

    def _get_network_stats(self):
        """Get network statistics for all containers using docker stats."""
        network_stats = {}

        try:
            # Get container IDs for our project
            result = self._run_compose(
                ["ps", "-q"],
                capture_output=True
            )

            if result.returncode != 0:
                return network_stats

            container_ids = result.stdout.strip().split('\n')
            if not container_ids or container_ids == ['']:
                return network_stats

            # Get all stats in one call using docker stats with multiple containers
            # Format: "container_name,network_io"
            stats_result = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.Name}}\t{{.NetIO}}"] + container_ids,
                capture_output=True,
                text=True,
                timeout=3
            )

            if stats_result.returncode != 0:
                return network_stats

            # Parse output line by line
            for line in stats_result.stdout.strip().split('\n'):
                if not line:
                    continue

                try:
                    # Split by tab
                    parts = line.split('\t')
                    if len(parts) != 2:
                        continue

                    container_name = parts[0].lstrip('/')
                    net_io = parts[1]

                    # Extract service name from container name
                    # Format: {project}-{service}-{number} or special case: scan-redis
                    # Examples: net-scan-robot-scanner-go-1 -> robot-scanner-go
                    #           net-scan-zgrab2-worker-1 -> zgrab2-worker
                    #           scan-redis -> redis

                    # Remove trailing -N (instance number)
                    if '-' in container_name and container_name.rsplit('-', 1)[-1].isdigit():
                        name_without_number = container_name.rsplit('-', 1)[0]
                    else:
                        name_without_number = container_name

                    # Remove project prefix (net-scan- or scan-)
                    if name_without_number.startswith('net-scan-'):
                        service_name = name_without_number[9:]
                    elif name_without_number.startswith('scan-'):
                        service_name = name_without_number[5:]
                    else:
                        service_name = name_without_number

                    # Parse network I/O (format: "1.2MB / 3.4MB")
                    if '/' in net_io:
                        rx_str, tx_str = net_io.split('/')
                        rx_bytes = self._parse_bytes(rx_str.strip())
                        tx_bytes = self._parse_bytes(tx_str.strip())

                        network_stats[service_name] = {
                            'rx_bytes': rx_bytes,
                            'tx_bytes': tx_bytes
                        }

                except (ValueError, IndexError):
                    continue

        except (subprocess.TimeoutExpired, Exception):
            pass

        return network_stats

    def _parse_bytes(self, byte_str):
        """Parse byte string like '1.2MB' or '340kB' to bytes."""
        byte_str = byte_str.strip()

        # Docker uses lowercase 'k' but uppercase for others: kB, MB, GB
        # Handle both cases
        multipliers = [
            ('GiB', 1024 * 1024 * 1024),
            ('MiB', 1024 * 1024),
            ('KiB', 1024),
            ('GB', 1000 * 1000 * 1000),
            ('MB', 1000 * 1000),
            ('kB', 1000),  # Docker format
            ('KB', 1000),
            ('B', 1),
        ]

        byte_str_upper = byte_str.upper()
        for suffix, multiplier in multipliers:
            if byte_str_upper.endswith(suffix.upper()):
                try:
                    value = float(byte_str[:-len(suffix)])
                    return int(value * multiplier)
                except ValueError:
                    return 0

        # Try parsing as plain number
        try:
            return int(float(byte_str))
        except ValueError:
            return 0

    def _format_bytes(self, num, suffix="B"):
        """Format bytes to human readable string."""
        for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"

    def _get_vulnerability_matches(self):
        """Calculate how many vulnerable hosts match across multiple scanners."""
        results_dir = Path(self.config.get(
            'results', {}).get('directory', 'results'))
        bleichenbacher_scanners = self.config.get(
            'bleichenbacher-scanners', {})
        enabled_scanners = [name for name, config in bleichenbacher_scanners.items()
                            if config.get('enabled', False)]

        if not enabled_scanners:
            return None

        # Collect vulnerable IPs from each scanner
        scanner_vulns = {}
        for scanner_name in enabled_scanners:
            result_file = results_dir / f"{scanner_name}.jsonl"
            if not result_file.exists():
                continue

            vuln_ips = set()
            try:
                with result_file.open() as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if data.get('vulnerable', False):
                                vuln_ips.add(data.get('ip'))
                        except json.JSONDecodeError:
                            continue
                scanner_vulns[scanner_name] = vuln_ips
            except Exception:
                continue

        if not scanner_vulns:
            return None

        # Count how many scanners found each IP as vulnerable
        ip_counts = {}
        for vuln_ips in scanner_vulns.values():
            for ip in vuln_ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Count matches
        num_scanners = len(scanner_vulns)
        match_counts = {'num_scanners': num_scanners, 'total_hosts': len(ip_counts)}

        for level in range(1, num_scanners + 1):
            match_counts[f"{level}_of_{num_scanners}"] = sum(
                1 for count in ip_counts.values() if count == level
            )

        return match_counts

    def _get_detailed_stats(self):
        """Get detailed statistics from Redis counters (persist across restarts)."""
        stats = {}
        redis_host = self.config['redis']['host']
        redis_port = self.config['redis']['port']
        zgrab_results_queue = os.getenv("ZGRAB2_RESULTS_QUEUE", "zgrab2-results")
        status_counts_key = os.getenv("STATUS_COUNTS_KEY", f"{zgrab_results_queue}:status-counts")
        total_inputs_key = os.getenv("TOTAL_INPUTS_KEY", f"{zgrab_results_queue}:inputs-total")

        try:
            r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            counters = r.hgetall('stats:counters')
            status_counts_raw = r.hgetall(status_counts_key)
            total_inputs_val = r.get(total_inputs_key)
        except Exception:
            counters = {}
            status_counts_raw = {}
            total_inputs_val = None

        # Stage 1 stats
        zgrab_total = int(counters.get('zgrab2_total', 0))
        rsa_hosts = int(counters.get('zgrab2_rsa', 0))
        zgrab_retry = int(counters.get('zgrab2_retry', 0))
        zgrab_retry_total = int(counters.get('zgrab2_retry_total', 0))
        zgrab_no_rsa = int(counters.get('zgrab2_no_rsa', 0))
        zgrab_removed = int(counters.get('zgrab2_removed', 0))
        retry_unique = 0
        unique_results = 0
        unique_no_rsa = 0
        unique_removed = 0
        unique_rsa = 0
        total_inputs = 0
        removed_by_status: Dict[str, int] = {}
        try:
            retry_unique = int(r.scard("stats:zgrab2:retry:set"))
            unique_results = int(r.scard("stats:zgrab2:results:set"))
            unique_no_rsa = int(r.scard("stats:zgrab2:no_rsa:set"))
            unique_removed = int(r.scard("stats:zgrab2:removed:set"))
            unique_rsa = int(r.scard("stats:zgrab2:rsa:set"))
            if total_inputs_val is not None:
                total_inputs = int(total_inputs_val)
        except Exception:
            pass
        retry_statuses = {"timeout", "missing_output", "error"}
        try:
            for status, count in (status_counts_raw or {}).items():
                # rsa/no_rsa are reported separately above
                if status in ("rsa", "no_rsa") or status in retry_statuses:
                    continue
                try:
                    removed_by_status[status] = int(count)
                except (TypeError, ValueError):
                    continue
        except Exception:
            removed_by_status = {}
        stats['zgrab2'] = {
            'total': zgrab_total,
            'rsa_hosts': rsa_hosts,
            'retry': zgrab_retry,
            'retry_total': zgrab_retry_total,
            'no_rsa': zgrab_no_rsa,
            'removed': zgrab_removed,
            'total_inputs': total_inputs,
            'removed_by_status': removed_by_status,
            'retry_unique': retry_unique,
            'unique_results': unique_results,
            'unique_no_rsa': unique_no_rsa,
            'unique_removed': unique_removed,
            'unique_rsa': unique_rsa,
        }

        # Scanner stats
        bleichenbacher_scanners = self.config.get(
            'bleichenbacher-scanners', {})
        scanner_stat_keys = {
            'robot-python': 'python',
            'robot-sslyze': 'sslyze',
        }
        scanner_counter_keys = {
            'robot-sslyze': 'sslyze',
        }

        for scanner_name, scanner_config in bleichenbacher_scanners.items():
            if not scanner_config.get('enabled', False):
                continue
            stat_key = scanner_stat_keys.get(scanner_name, scanner_name)
            counter_name = scanner_counter_keys.get(scanner_name, scanner_name)
            total_key = f"scanner:{counter_name}:total"
            vuln_key = f"scanner:{counter_name}:vulnerable"
            # Unique counts via Redis sets
            unique_results = 0
            unique_retries = 0
            try:
                unique_results = int(r.scard(f"stats:scanner:{counter_name}:results:set"))
                unique_retries = int(r.scard(f"stats:scanner:{counter_name}:retry:set"))
            except Exception:
                pass

            total = int(counters.get(total_key, 0))
            vulnerable = int(counters.get(vuln_key, 0))
            to_retry = int(counters.get(f"scanner:{counter_name}:to_retry", 0))
            requeued = int(counters.get(f"scanner:{counter_name}:requeued", 0))
            stats[stat_key] = {
                'total': total,
                'unique_total': unique_results,
                'vulnerable': vulnerable,
                'to_retry': to_retry,
                'unique_to_retry': unique_retries,
                'requeued': requeued
            }

        # Normalized results
        normalized_total = int(counters.get('normalized_total', 0))
        stats['normalized'] = {'total': normalized_total}

        return stats

    def _fmt_rate(self, rate):
        if rate <= 0:
            return "(0.0/s)"
        return f"({rate:.1f}/s)"

    def _fmt_pct(self, part, whole):
        if whole <= 0:
            return ""
        return f"({100*part/whole:.1f}%)"

    def _fmt_net(self, net):
        rx = self._format_bytes(net['rx_rate']) if isinstance(net, dict) else "0B"
        tx = self._format_bytes(net['tx_rate']) if isinstance(net, dict) else "0B"
        return f"v{rx}/s ^{tx}/s"

    def _get_uptime_seconds(self, redis_client):
        try:
            start_ts = redis_client.get("stats:job_manager_start")
            if start_ts:
                return max(0, int(time.time()) - int(start_ts))
        except Exception:
            return None
        return None

    def _format_uptime(self, seconds):
        from datetime import timedelta
        if seconds is None:
            return "n/a"
        return str(timedelta(seconds=seconds))

    def results(self):
        """Show vulnerability summary."""
        print("[scan.py] Scanning Results\n")

        results_dir = Path(self.config.get(
            'results', {}).get('directory', 'results'))
        bleichenbacher_scanners = self.config.get(
            'bleichenbacher-scanners', {})

        for scanner_name, scanner_config in bleichenbacher_scanners.items():
            if not scanner_config.get('enabled', False):
                continue

            result_file = results_dir / f"{scanner_name}.jsonl"

            if not result_file.exists():
                print(f"{scanner_name}: 0 scans")
                continue

            total = 0
            vulnerable = 0
            strong = 0
            weak = 0

            try:
                with result_file.open() as f:
                    for line in f:
                        total += 1
                        try:
                            data = json.loads(line)
                            if data.get('vulnerable', False):
                                vulnerable += 1
                            vuln_level = data.get('vulnerability_level')
                            if vuln_level == 'strong':
                                strong += 1
                            elif vuln_level == 'weak':
                                weak += 1
                        except json.JSONDecodeError:
                            continue

                print(f"{scanner_name}: {vulnerable}/{total} hosts vulnerable")
                if strong + weak > 0:
                    print(f"  - Strong oracle: {strong}")
                    print(f"  - Weak oracle: {weak}")
            except Exception as e:
                print(f"{scanner_name}: Error reading results - {e}")

    def logs(self, service=None):
        """Show service logs."""
        args = ["logs", "--tail=50", "-f"]
        if service:
            args.append(service)
        self._run_compose(args)

def main():
    parser = argparse.ArgumentParser(
        description="ROBOT Scanning Pipeline - Queue-Based Architecture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start pipeline
  ./scan.py start

  # Use custom config
  ./scan.py --config config/local.yaml start

  # Scan a network range with ZMap
  ./scan.py zmap 192.168.1.0/24
  ./scan.py zmap 10.0.0.0/8 --rate 50000 --bandwidth 100M

  # Load IPs or domains from file
  ./scan.py inject input/targets.txt

  # Watch progress
  ./scan.py status

  # View results
  ./scan.py results
        """
    )

    # Global arguments
    parser.add_argument('--config', default='config/default.yaml',
                        help='Config file to use (default: config/default.yaml)')

    subparsers = parser.add_subparsers(
        dest='command', help='Command to execute')

    # start
    subparsers.add_parser('start', help='Start pipeline (all scanners)')

    # stop
    subparsers.add_parser('stop', help='Stop all services')

    # inject
    inject_parser = subparsers.add_parser(
        'inject', help='Inject IPs/domains from file')
    inject_parser.add_argument(
        'file', help='File containing IPs or domain names (one per line)')
    inject_parser.add_argument(
        '--type', choices=['domain', 'ip'], default='domain',
        help='Treat input lines as domains or IPs (default: domain)')
    inject_parser.add_argument(
        '--redis-host', default='localhost', help='Redis host (default: localhost)')
    inject_parser.add_argument('--redis-port', type=int, default=6380,
                               help='Redis port exposed on host (default: 6380)')
    inject_parser.add_argument(
        '--queue', default='input-targets', help='Redis queue name (default: input-targets)')

    # zmap
    zmap_parser = subparsers.add_parser(
        'zmap', help='Scan network range with ZMap')
    zmap_parser.add_argument('range', help='CIDR range (e.g., 192.168.1.0/24)')
    zmap_parser.add_argument('--rate', type=int, default=10000,
                             help='Packets per second (default: 10000)')
    zmap_parser.add_argument(
        '--bandwidth', help='Bandwidth limit (e.g., 10M, 1G)')

    # status
    subparsers.add_parser(
        'status', help='Show pipeline status and queue depths (auto-refresh)')

    # logs
    logs_parser = subparsers.add_parser('logs', help='Show service logs')
    logs_parser.add_argument('service', nargs='?',
                             help='Service name (optional)')

    # reset
    subparsers.add_parser('reset', help='Reset pipeline to default ready state (stop, clear, rebuild)')

    # results
    subparsers.add_parser('results', help='Show vulnerability summary')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    pipeline = Pipeline(config_file=args.config)

    if args.command == 'start':
        pipeline.start()
    elif args.command == 'stop':
        pipeline.stop()
    elif args.command == 'inject':
        pipeline.inject(args.file, redis_host=args.redis_host,
                        redis_port=args.redis_port, queue=args.queue, target_type=args.type)
    elif args.command == 'zmap':
        pipeline.zmap(args.range, args.rate, args.bandwidth)
    elif args.command == 'status':
        pipeline.status()
    elif args.command == 'logs':
        pipeline.logs(args.service)
    elif args.command == 'reset':
        pipeline.reset()
    elif args.command == 'results':
        pipeline.results()


if __name__ == '__main__':
    main()
