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
