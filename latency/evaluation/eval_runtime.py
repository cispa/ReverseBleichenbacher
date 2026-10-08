import json
import argparse
import subprocess
import time
from pathlib import Path

EVALUATION_DIR = Path(__file__).resolve().parent
LATENCY_DIR = EVALUATION_DIR.parent

# Timeout in seconds
TIMEOUT = 90
# Network delays to test (round-trip) in milliseconds
DELAYS = [
    0, 
    0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9,
    1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 20, 30, 40, 50, 60, 70, 80, 90,
    100, 200
]
# Amount of measurements for each network delay
COUNT = 100
# output directory for results
RESULTS_DIR = EVALUATION_DIR / "results_runtime"

# Path to the json file with statistics created by the bleichenbacher server
RESULTS_JSON = LATENCY_DIR / "attacker" / "tlslite-ng-bleichenbacher" / "results.json"

# restart the docker containers to stop the server after timeout and make sure the containers are not in a weird state
def restart_docker():
    subprocess.run(["docker", "kill", "attacker"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for service in ("attacker", "server"):
        subprocess.run(
            ["docker", "compose", "restart", service],
            cwd=LATENCY_DIR,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    time.sleep(3)

def add_delay(delay):
    subprocess.check_output(["docker", "exec", "server", "tc", "qdisc", "replace", "dev", "eth0", "root", "netem", "delay", f"{str(delay)}ms"])

def start_server(parallel):
    command = [
        "docker", "exec", "attacker", "bash", "-c", f"cd tlslite-ng-bleichenbacher;python3 scripts/tls.py server{' --parallel' if parallel else ''} --bleichenbacher server 0.0.0.0:443"
    ]
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

def kill_server(process):
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        restart_docker()
    process.wait() # should be dead already

def run_attack(parallel, delay, host_port=None, timeout=TIMEOUT, verbose=False):
    # For faster startup, use delay 0
    add_delay(0)

    # A timed-out attempt may leave its predecessor's statistics behind.
    subprocess.run(
        ["docker", "exec", "attacker", "rm", "-f", "tlslite-ng-bleichenbacher/results.json"],
        check=True,
    )

    # Start server
    server_process = start_server(parallel)

    # Wait for server to start up
    time.sleep(1)
    
    if server_process.poll() is not None:
        # server process died (likely because port 443 is occupied by a broken server)
        restart_docker()
        server_process = start_server(parallel)
        time.sleep(1)
    
    # add network delay
    add_delay(delay)

    success = False
    output = ""
    timed_out = False
    curl_returncode = None

    try:
        # Docker Desktop cannot route the private container IP from macOS.
        if host_port is None:
            attacker_ip = subprocess.check_output(
                ["docker", "inspect", "--format", '{{ range .NetworkSettings.Networks }}{{ .IPAddress }}{{ end }}', "attacker"]
            ).decode().strip()
            port = 443
        else:
            attacker_ip = "127.0.0.1"
            port = host_port
        result = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--noproxy", "*",
                "--cacert", str(LATENCY_DIR / "cert" / "server.crt"),
                "--resolve", f"server:{port}:{attacker_ip}", f"https://server:{port}",
                "-m", str(timeout), "--connect-timeout", str(timeout)
            ],
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        curl_returncode = result.returncode
        # Require both a completed TLS request and the expected response.
        success = (
            result.returncode == 0
            and "Better Bleichenbacher MITM Attack Successful" in output
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # Ensure server is fully killed
        kill_server(server_process)

    # Parse stats from results.json — a successful page also needs a completed
    # attack record from this attempt.
    stats = None
    if RESULTS_JSON.exists():
        try:
            stats = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            pass
    if not isinstance(stats, dict) or stats.get("result") != "ok":
        success = False

    if verbose and not success:
        print(f"    curl output: {output[-500:] or '(no output)'}")
        if stats is None:
            print("    attack stats: unavailable")
        else:
            error = str(stats.get("error", ""))
            print(
                "    attack stats:",
                {
                    "result": stats.get("result"),
                    "error": error[:200] + ("..." if len(error) > 200 else ""),
                    "tau": stats.get("tau"),
                    "total_queries": stats.get("total_queries"),
                    "runtime": stats.get("runtime"),
                },
            )

    return {
        "success": success,
        "stats": stats,
        "timed_out": timed_out,
        "curl_returncode": curl_returncode,
        "client_output_tail": output[-500:] if not success else "",
    }

def run_attacks(parallel, delay, samples=COUNT, host_port=None, timeout=TIMEOUT, verbose=False):
    results = list()
    for i in range(samples):
        results.append(run_attack(parallel, delay, host_port=host_port, timeout=timeout, verbose=verbose))
        res  = "fail"
        if results[-1]["success"]:
            res = f'{results[-1]["stats"]["runtime"]:5.01f}s'
        print(f"  Sample {i+1}/{samples}: {res}", flush=True)
        if parallel and i + 1 < samples:
            time.sleep(2) # give erlang server a bit of time to calm down
    return results

def main():
    parser = argparse.ArgumentParser(description="Run the TLS latency experiment")
    parser.add_argument("--count", type=int, default=COUNT, help="Attacks per mode and delay (default: 100)")
    parser.add_argument("--delays", default=",".join(map(str, DELAYS)), help="Comma-separated RTT delays in ms")
    parser.add_argument("--modes", default="normal,parallel", help="Comma-separated modes: normal,parallel")
    parser.add_argument("--host-port", type=int, help="Published attacker TLS port on 127.0.0.1 (macOS: 8443)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Per-attack timeout in seconds")
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR, help="Directory for raw JSON")
    parser.add_argument("--verbose", action="store_true", help="Print curl output and stats on failure")
    args = parser.parse_args()
    if args.count < 1 or args.timeout < 1:
        parser.error("--count and --timeout must be positive")
    try:
        delays = [float(x) for x in args.delays.split(",")]
    except ValueError:
        parser.error("--delays must be comma-separated numbers")
    modes = args.modes.split(",")
    if not modes or any(mode not in ("normal", "parallel") for mode in modes):
        parser.error("--modes must contain normal, parallel, or both")
    if any(delay < 0 for delay in delays):
        parser.error("--delays must be nonnegative")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    restart_docker()
    for delay in delays:
        for mode in modes:
            if (mode == "normal" and 2000 * delay >= 1000 * args.timeout) or (
                mode == "parallel" and 300 * delay >= 1000 * args.timeout
            ):
                continue
            print(f"Running {mode} attack with delay {delay:g}ms...", flush=True)
            results = run_attacks(
                mode == "parallel", delay, samples=args.count, host_port=args.host_port,
                timeout=args.timeout, verbose=args.verbose
            )
            (args.output_dir / f"{mode}_{delay:g}.json").write_text(json.dumps(results))


if __name__ == "__main__":
    main()
