RULES ?= rules/examples/allow_arp.yaml
GEN_DIR = gen

.PHONY: all compile sim clean lint

all: compile

compile:
	cargo run -- compile $(RULES)

lint: compile
	iverilog -g2012 -o /dev/null $(GEN_DIR)/rtl/*.v rtl/*.v

sim: compile
	cd $(GEN_DIR)/tb && make

clean:
	rm -rf $(GEN_DIR)/rtl/* $(GEN_DIR)/tb/*
	cargo clean
