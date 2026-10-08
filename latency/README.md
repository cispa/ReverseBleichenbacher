# TLS latency experiment

This directory runs the attack against a vulnerable Erlang HTTPS server. The
Docker lab contains the server, an attacker TLS proxy, and an optional Firefox
client. `evaluation/eval_runtime.py` tests sequential and batched queries at
different network delays and records the results as JSON.

The attack code lives in `attacker/reversebleichenbacher/`. On first startup,
the attacker container fetches a pinned `tlslite-ng` version and applies the
patch in `attacker/tlslite-ng-bleichenbacher.patch`.

## Try it

From the repository root, with Python 3, Docker Compose, and `curl` installed:

```sh
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml up -d --build server attacker
python3 latency/evaluation/eval_runtime.py --modes normal,parallel --delays 0 --count 1 --host-port 8443 --output-dir latency/evaluation/smoke_results --verbose
cat latency/evaluation/smoke_results/normal_0.json
cat latency/evaluation/smoke_results/parallel_0.json
```

The Compose override publishes the proxy on `127.0.0.1:8443`, which works
with Docker Desktop on macOS and with Docker on Linux. The runner uses `tc`
inside the server container to add network delay. To check the lab or stop it:

```sh
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml ps
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml logs --tail=80 attacker server
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml down
```

## Run the latency experiment

On a Linux measurement host, use the direct container network path used for
the paper's Figure 5 data:

```sh
cd latency
docker compose up -d --build server attacker
python3 evaluation/eval_runtime.py
```

The default runner collects 100 attacks for each configured delay and mode;
the full run can take days. Use `--count`, `--delays`, and `--modes` to select a
smaller experiment. For example, `--count 3 --delays 0,10 --modes parallel`
runs three batched attacks at each of two delays. macOS is suitable for
running and debugging the lab, while measurements intended for comparison
with Figure 5 should use the Linux measurement setup.

From the repository root, summarize a complete run with:

```sh
python3 latency/analyze_figure5.py
```

Raw measurements go to `latency/evaluation/results_runtime/`; generated CSVs
go to `latency/analysis/`. Both directories are ignored by Git. The
certificates and private key in `cert/` are lab fixtures.
