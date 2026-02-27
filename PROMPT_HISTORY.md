# Flippy Prompt History

## Session 1 — 2026-02-26: Phase 1 Implementation

### Prompt
Implement Phase 1 of the Flippy FPGA Layer 2 Packet Filter Switch. Build the full end-to-end pipeline: YAML rules → Rust compiler → Verilog RTL + cocotb test harness → Icarus simulation.

### Actions Taken

1. **Project scaffolding**
   - Created directory structure: `rules/`, `src/`, `templates/`, `rtl/`, `gen/`, `synth/`
   - `Cargo.toml` with dependencies: clap, serde, serde_yaml, tera, anyhow, log, env_logger
   - Top-level `Makefile` with compile/sim/lint/clean targets
   - `.gitignore` for Rust target, generated files, sim artifacts

2. **Rust compiler source**
   - `src/model.rs` — Data model structs (Action, MatchCriteria, StatelessRule, FilterConfig, MacAddress with wildcard parsing)
   - `src/loader.rs` — YAML loading with serde_yaml, validation (unique priorities, MAC/ethertype format)
   - `src/verilog_gen.rs` — Tera template rendering for per-rule matchers, decision logic, top-level
   - `src/cocotb_gen.rs` — Test case generation (positive match + negative default action tests)
   - `src/main.rs` — clap CLI with `compile` and `validate` subcommands

3. **YAML rules**
   - `rules/examples/allow_arp.yaml` — minimal one-rule (EtherType 0x0806 → pass, default drop)
   - `rules/schema.yaml` — JSON Schema for rule validation

4. **Hand-written Verilog**
   - `rtl/frame_parser.v` — Ethernet frame parser FSM (IDLE→DST_MAC→SRC_MAC→ETYPE→VLAN→PAYLOAD)
   - Handles 802.1Q VLAN detection (EtherType 0x8100)
   - Outputs: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp, fields_valid pulse

5. **Tera templates**
   - `templates/rule_match.v.tera` — Per-rule combinational matcher
   - `templates/decision_logic.v.tera` — Priority encoder with latched output
   - `templates/packet_filter_top.v.tera` — Top-level module wiring
   - `templates/test_harness.py.tera` — cocotb test bench
   - `templates/test_makefile.tera` — Simulation Makefile

6. **Bug fix: decision latching**
   - Initial implementation: `decision_valid` was high for only 1 clock cycle (when `fields_valid` pulsed)
   - Problem: test checked after full frame was sent, but decision happened mid-frame (after 14 header bytes)
   - Fix: Added `pkt_sof` input to `decision_logic`; decision now latches until next frame starts

7. **Verification**
   - `cargo build` — compiles successfully
   - `iverilog -g2012` lint — passes cleanly
   - cocotb simulation: 2 tests PASS (ARP → pass, unknown EtherType → drop)
   - Fixed cocotb deprecation: `units` → `unit` in Clock constructor
   - Fixed cocotb deprecation: `MODULE` → `COCOTB_TEST_MODULES` in Makefile

8. **Documentation**
   - CLAUDE.md, OVERVIEW.md, REQUIREMENTS.md, PROMPT_HISTORY.md

### Git Operations
- Initial commit with all Phase 1 files
- Pushed to GitHub

## Session 2 — 2026-02-26: Verification Framework Research

### Prompt
Research 8 topics for building an innovative FPGA packet filter verification framework using cocotb: cocotb 2.x features, coverage-driven verification, property-based testing for HDL, mutation testing for hardware, UVM methodology in Python, test harness generation from specs, formal verification integration, and CI/regression best practices.

### Actions Taken

1. **Comprehensive web research** across all 8 topics with multiple search queries per topic
2. **Created docs/RESEARCH.md** — detailed research document with:
   - cocotb 2.0/2.1 new features (Logic/LogicArray types, Copra type stubs, HDL-native indexing)
   - cocotb extension ecosystem (cocotbext-axi, cocotbext-eth, cocotbext-pcie, etc.)
   - cocotb-coverage and PyVSC for functional coverage and constrained random
   - Coverage-driven test generation with runtime-adaptive randomization
   - Hypothesis property-based testing integration architecture for cocotb
   - MCY (Mutation Cover with Yosys) for hardware mutation testing
   - PyUVM 3.0 with RAL support, mapping UVM concepts to Python
   - ML-driven coverage optimization (2025 research papers)
   - Agnisys IDS-Verify comparison and LLM-based testbench generation state of the art
   - SymbiYosys formal verification and SVA property generation from YAML
   - GitHub Actions CI pipeline design with JUnit XML reporting
   - Coverage trending and regression dashboard architecture
3. **Competitive analysis** comparing Flippy to commercial tools (Agnisys) and LLM approaches
4. **Prioritized recommendations** in 3 tiers with implementation order
5. **Updated PROMPT_HISTORY.md and REQUIREMENTS.md** with research session details

### Key Findings
- cocotb 2.0 released Sept 2025 with new type system — Flippy should target it
- cocotb-coverage 2.0 provides coverage-driven test generation from YAML specs
- MCY (YosysHQ) enables mutation testing to measure test harness quality — unique differentiator
- No existing tool generates BOTH hardware and tests from a single specification
- Hypothesis + cocotb integration is unexplored territory — innovation opportunity
- PyUVM 3.0 provides professional UVM methodology in Python
- Recent ML+PyUVM papers show coverage optimization is cutting-edge research

### Git Operations
- Committed docs/RESEARCH.md and updated documentation files
- Pushed to GitHub
