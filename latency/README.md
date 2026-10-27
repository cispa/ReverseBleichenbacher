# TLS latency experiment

This directory runs the attack against a vulnerable Erlang HTTPS server. The
Docker lab contains the server, an attacker TLS proxy, and an optional Firefox
client. `evaluation/eval_runtime.py` tests sequential and batched queries at
different network delays and records the results as JSON.

Both sequential and parallel attacks use the shared `reversebleichenbacher/`
package at the repository root. The parallel mode sends batches of up to 256
TLS queries, starts Bottom-Up at D=16, and advances four bits per round.
`attacker/tls_transport.py` implements the TLS queries. On first startup,
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
inside the server container to add network delay. It requires the Docker host
kernel to support the `netem` traffic-control queueing discipline
(`CONFIG_NET_SCH_NETEM`), even for a zero-delay run. Some WSL2 kernels do not
include this support; in that case, `tc` may report `RTNETLINK answers: No
such file or directory`. To check the lab or stop it:

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

For a shorter run, pass the same attempt count to the analyzer. For example,
this four-delay, three-attempt grid uses the macOS loopback path:

```sh
python3 latency/evaluation/eval_runtime.py \
  --modes normal,parallel --delays 0,1,10,30 --count 3 \
  --host-port 8443 \
  --output-dir latency/evaluation/smoke_results/figure5-small
```

Summarize the nonzero-delay cells with:

```sh
python3 latency/analyze_figure5.py \
  --input-dir latency/evaluation/smoke_results/figure5-small \
  --expected-attempts 3 \
  --output latency/analysis/figure5-small.csv \
  --infinity-output latency/analysis/figure5-small-failure-aware.csv
```

The analyzer excludes the zero-delay cell from its CSVs because the paper's
Figure 5 uses a logarithmic delay axis. Its failure-aware CSV counts attacks
that do not complete as infinite time to success. In each raw record, `success`
means the TLS client completed the attack handshake; `stats.result` only
reports whether the attack algorithm finished. The runner also records curl's
exit code and timeout state for failed handshakes.

## Compare the query schedules on matched messages

The diagnostic below encrypts known TLS premaster secrets, selects messages
whose simulated trimmer reaches at least 50, and attacks each ciphertext with
both schedules against the live TLS oracle. It checks the recovered 46-byte
suffix exactly. This measures the attack and oracle directly; the Figure 5
runner above additionally tests the full TLS proxy handshake.

```sh
docker exec server tc qdisc replace dev eth0 root netem delay 10ms
docker exec -w /attacker/tlslite-ng-bleichenbacher attacker \
  python3 /attacker/diagnose_schedules.py --count 2 --min-trimmer 50
```

Use `--min-trimmer 1 --max-trimmer 1` to examine matched messages where the
simulated trimmer search finds no divisor. `--seed` makes the selected messages
reproducible; `--count 1 --message-index N` replays one generated message.

To profile the same parallel ciphertext, run:

```sh
docker exec server tc qdisc replace dev eth0 root netem delay 10ms
docker exec -w /attacker/tlslite-ng-bleichenbacher attacker \
  python3 /attacker/profile_parallel.py \
  --output parallel_profile_10ms.json --cprofile parallel_profile_10ms.prof
```

The JSON separates phase time, time waiting for query replies, and worker CPU
and wall time. Worker totals sum over concurrent calls and can exceed attack
wall time. `--workers` and `--executor process|thread` are diagnostic options;
the experiment runner continues to use 128 processes. Profile output stays in
the ignored tlslite-ng checkout.

Full measurements go to `latency/evaluation/results_runtime/`; smoke runs can
use `latency/evaluation/smoke_results/`. Generated CSVs go to
`latency/analysis/`. These directories are ignored by Git. The
certificates and private key in `cert/` are lab fixtures.
