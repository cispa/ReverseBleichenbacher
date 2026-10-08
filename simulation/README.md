# Simulation experiments

This directory contains the large-scale query experiments. The shared
`reversebleichenbacher/` package at the repository root implements our attack,
and `capol_baseline/` contains the comparison attack. The harness
runs both against simulated TTT, TFT, and FFT oracles at 1024 and 2048 bits.
It uses the same seed, message, and selected key for each paired trial.

`run_simulations.py` runs the grid, `run_simulation.py` runs one cell,
`validate_run.py` checks output files, and `analysis.py` summarizes the results.
The attack receives a public modulus and an oracle; the harness holds the
plaintext and private key needed to simulate oracle replies.

## Quick check

From the repository root, with Python 3.14:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r simulation/requirements.txt
make simulation-tests PYTHON_BIN=.venv/bin/python
make simulations-smoke PYTHON_BIN=.venv/bin/python RUN_ID=smoke
make simulations-check PYTHON_BIN=.venv/bin/python RUN=simulation/results/smoke
```

## Full experiment

```sh
make simulations PYTHON_BIN=.venv/bin/python RUN_ID=my-run
```

By default this runs `proof,capol × TTT,TFT,FFT × 1024,2048`, with 100,000
trials per cell. Set `N`, `PROCESSES`, `MASTER_SEED`, `ORACLES`, `BIT_SIZES`,
or `IMPLEMENTATIONS` on the Make command line to adjust the run. Results go
to `simulation/results/<run-id>/` and are ignored by Git.

If a run is interrupted, resume its remaining cells with:

```sh
make simulations-resume my-run PYTHON_BIN=.venv/bin/python
```

The manifest records the run configuration and completed cells. The resume
command validates completed data before continuing.

The default attack uses `halving_sparse_asymmetric` for Searching and
`best_effort` for Bottom-Up. The sequential strategies used for the proofs
are `standard_coverage` and `proved`. Choose them with
`PROOF_SEARCH_STRATEGY=standard_coverage` and
`PROOF_BOTTOM_UP_STRATEGY=proved`.

The `keys/` directory contains synthetic RSA key pools for the trials.
