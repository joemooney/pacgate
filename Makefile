RULES ?= rules/examples/allow_arp.yaml
GEN_DIR = gen
SIM ?= icarus
LINT_SIM ?= iverilog
SIM_REGRESS_COUNT ?= 1000
SIM_REGRESS_BIN ?= target/debug/pacgate
TOPOLOGY_SCENARIO ?= docs/management/paclab/scenario_v2.example.json

.PHONY: all compile sim sim-axi sim-regress sim-topology clean lint synth formal test-properties

all: compile

compile:
	cargo run -- compile $(RULES)

compile-axi:
	cargo run -- compile $(RULES) --axi

lint: compile
	@if [ "$(LINT_SIM)" = "iverilog" ]; then \
		iverilog -g2012 -o /dev/null $(GEN_DIR)/rtl/*.v rtl/*.v; \
	elif [ "$(LINT_SIM)" = "questa" ]; then \
		rm -rf $(GEN_DIR)/.questa_lint && mkdir -p $(GEN_DIR)/.questa_lint && cd $(GEN_DIR)/.questa_lint && vlib work >/dev/null && vlog -sv -lint ../rtl/*.v ../../rtl/*.v; \
	else \
		echo "Unsupported LINT_SIM='$(LINT_SIM)'. Use 'iverilog' or 'questa'."; \
		exit 2; \
	fi

lint-axi: compile-axi
	@if [ "$(LINT_SIM)" = "iverilog" ]; then \
		iverilog -g2012 -o /dev/null $(GEN_DIR)/rtl/*.v rtl/*.v; \
	elif [ "$(LINT_SIM)" = "questa" ]; then \
		rm -rf $(GEN_DIR)/.questa_lint && mkdir -p $(GEN_DIR)/.questa_lint && cd $(GEN_DIR)/.questa_lint && vlib work >/dev/null && vlog -sv -lint ../rtl/*.v ../../rtl/*.v; \
	else \
		echo "Unsupported LINT_SIM='$(LINT_SIM)'. Use 'iverilog' or 'questa'."; \
		exit 2; \
	fi

sim: compile
	cd $(GEN_DIR)/tb && SIM=$(SIM) make

sim-axi: compile-axi
	cd $(GEN_DIR)/tb-axi && SIM=$(SIM) make

synth: compile-axi
	cd synth && yosys synth_yosys.ys

formal: compile
	cargo run -- formal $(RULES)

test-properties: compile
	cd $(GEN_DIR)/tb && python -m pytest test_properties.py -v

sim-regress:
	@test -x "$(SIM_REGRESS_BIN)" || cargo build
	python3 simulator-app/examples/run_1000.py --bin $(SIM_REGRESS_BIN) --rules $(RULES) --count $(SIM_REGRESS_COUNT) > sim_regress_result.json
	python3 -c "import json; d=json.load(open('sim_regress_result.json')); assert d['mismatches']==0, d; print('sim-regress PASS:', d)"

sim-topology:
	@test -x "$(SIM_REGRESS_BIN)" || cargo build
	python3 simulator-app/tools/paclab_validate.py $(TOPOLOGY_SCENARIO)
	python3 simulator-app/tools/run_topology.py $(TOPOLOGY_SCENARIO) --bin $(SIM_REGRESS_BIN) --output topology_result.json

clean:
	rm -rf $(GEN_DIR)/rtl/* $(GEN_DIR)/tb/* $(GEN_DIR)/tb-axi/*
	cargo clean
