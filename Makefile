PYTHON_BIN ?= python3
IMPLEMENTATIONS ?= proof,capol
N ?= 100000
PROCESSES ?= 8
MASTER_SEED ?= 20261006
ORACLES ?= TTT,TFT,FFT
BIT_SIZES ?= 1024,2048
PROOF_SEARCH_STRATEGY ?= halving_sparse_asymmetric
PROOF_SEARCH_SLACK ?=
PROOF_BOTTOM_UP_STRATEGY ?= best_effort
PROOF_BOTTOM_UP_R_LIMIT ?= 2048
KEYS_DIR ?= simulation/keys
SIMULATIONS_OUT ?= simulation/results
RUN_ID_ARG = $(if $(RUN_ID),--run-id "$(RUN_ID)",)
PROOF_SEARCH_SLACK_ARG = $(if $(PROOF_SEARCH_SLACK),--proof-search-slack "$(PROOF_SEARCH_SLACK)",)

RESUME_POSITIONAL_ID :=
ifeq ($(firstword $(MAKECMDGOALS)),simulations-resume)
RESUME_POSITIONAL_ID := $(word 2,$(MAKECMDGOALS))
ifneq ($(RESUME_POSITIONAL_ID),)
.PHONY: $(RESUME_POSITIONAL_ID)
$(RESUME_POSITIONAL_ID):
	@:
endif
endif
RESUME_ID = $(or $(RUN_ID),$(RESUME_POSITIONAL_ID))

.PHONY: simulations simulations-smoke simulations-resume simulations-check simulation-tests latency-tests latency-compose-check latency-analyze

simulations:
	@$(PYTHON_BIN) simulation/run_simulations.py \
		--implementations "$(IMPLEMENTATIONS)" \
		--experiments "$(N)" \
		--processes "$(PROCESSES)" \
		--master-seed "$(MASTER_SEED)" \
		--oracles "$(ORACLES)" \
		--bits "$(BIT_SIZES)" \
		--proof-search-strategy "$(PROOF_SEARCH_STRATEGY)" \
		--proof-bottom-up-strategy "$(PROOF_BOTTOM_UP_STRATEGY)" \
		--proof-bottom-up-r-limit "$(PROOF_BOTTOM_UP_R_LIMIT)" \
		--keys-dir "$(KEYS_DIR)" \
		--out "$(SIMULATIONS_OUT)" \
		$(PROOF_SEARCH_SLACK_ARG) $(RUN_ID_ARG)

simulations-smoke:
	@$(MAKE) simulations N=2 PROCESSES=2 ORACLES=TTT BIT_SIZES=1024 \
		$(if $(RUN_ID),RUN_ID="$(RUN_ID)",)

simulations-resume:
	@test -n "$(RESUME_ID)" || (echo "usage: make simulations-resume <run-id> [PYTHON_BIN=.venv/bin/python]" >&2; exit 2)
	@$(PYTHON_BIN) simulation/run_simulations.py --resume "$(RESUME_ID)" \
		--out "$(SIMULATIONS_OUT)" $(if $(DRY_RUN),--dry-run,)

simulations-check:
	@test -n "$(RUN)" || (echo "usage: make simulations-check RUN=simulation/results/<run-id>" >&2; exit 2)
	@$(PYTHON_BIN) simulation/validate_run.py "$(RUN)" --publication-ready

simulation-tests:
	@PYTHONPATH=simulation $(PYTHON_BIN) -m unittest -q \
		simulation.proof.test_algorithms \
		simulation.test_simulation_pipeline \
		simulation.test_compare_proof_strategies

latency-tests:
	@PYTHONPATH=latency/attacker $(PYTHON_BIN) -m unittest discover \
		-s latency/tests -p 'test_*.py' -q

latency-compose-check:
	@docker compose -f latency/docker-compose.yml config >/dev/null

latency-analyze:
	@$(PYTHON_BIN) latency/analyze_figure5.py
