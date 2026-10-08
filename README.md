# Reverse-Bleichenbacher

This repository contains code and experiments related to the paper _"Reverse-Bleichenbacher: Bleichenbacher Attacks Are Practical Again"_ by Youheng Lü, Lorenz Hetterich, Riccardo Zanotto, Cas Cremers, Michael Schwarz, and Lukas Gerlach.

There are two self-contained setups: one for large-scale simulations and one
for end-to-end TLS latency measurements. The paper's experiments use these
implementations. The simulation runs with Python;
the TLS lab runs with Docker on macOS or Linux.

| Directory | What is inside |
| --- | --- |
| [`reversebleichenbacher/`](reversebleichenbacher/) | The reusable attack package used by the simulations. |
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

## Credits

The comparison attack builds on Livia Capol's 2021 work. Parts of the TLS
oracle build on the CC0 `robot-detect` project; source notices are kept with
that code.
