RULES ?= rules/examples/allow_arp.yaml
GEN_DIR = gen

.PHONY: all compile sim sim-axi clean lint synth formal test-properties

all: compile

compile:
	cargo run -- compile $(RULES)

compile-axi:
	cargo run -- compile $(RULES) --axi

lint: compile
	iverilog -g2012 -o /dev/null $(GEN_DIR)/rtl/*.v rtl/*.v

lint-axi: compile-axi
	iverilog -g2012 -o /dev/null $(GEN_DIR)/rtl/*.v rtl/*.v

sim: compile
	cd $(GEN_DIR)/tb && make

sim-axi: compile-axi
	cd $(GEN_DIR)/tb-axi && make

synth: compile-axi
	cd synth && yosys synth_yosys.ys

formal: compile
	cargo run -- formal $(RULES)

test-properties: compile
	cd $(GEN_DIR)/tb && python -m pytest test_properties.py -v

clean:
	rm -rf $(GEN_DIR)/rtl/* $(GEN_DIR)/tb/* $(GEN_DIR)/tb-axi/*
	cargo clean
