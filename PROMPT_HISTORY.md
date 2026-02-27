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

## Session 3 — 2026-02-26: Phase 2 + Phase 3 Implementation & Comprehensive Documentation

### Prompt
"I want you to go wild on this tonight and be as creative as possible. I want thorough documentation, design diagrams, user guides, test documentation, etc. We need to stun upper management with a new and innovative approach that lends itself to flexible testing. The test harness is really the key selling point and those capabilities are what we want to be as capable as possible."

### Actions Taken

#### Phase 2: Multi-Rule Support + Advanced Verification

1. **Enterprise rule set** — `rules/examples/enterprise.yaml`
   - 7 rules: block_broadcast (pri 200), allow_mgmt_vlan (150), allow_arp (100), allow_ipv4 (90), allow_ipv6 (80), allow_vendor_acme (70), allow_lldp (60)
   - Demonstrates: MAC matching, VLAN matching, ethertype matching, OUI wildcards, priority ordering

2. **Python verification framework** — `verification/`
   - `packet.py` — EthernetFrame dataclass, VlanTag, PacketFactory with methods: arp(), ipv4(), ipv6(), vlan_tagged(), broadcast(), from_vendor(), random_frame(), runt_frame(), jumbo_frame()
   - `scoreboard.py` — PacketFilterScoreboard with predict(), check(), report(). Rule class with matches() method. ScoreboardMismatch exception.
   - `coverage.py` — FilterCoverage with CoverPoint/CoverBin classes. Cover points: ethertype (7 bins), dst_mac_type (4 bins), frame_size (5 bins), vlan_present (2 bins), decision (2 bins), rule_hit (per-rule), corner_cases (6 bins). Cross coverage: ethertype_x_decision, rule_x_decision.
   - `driver.py` — PacketDriver (BFM) with send(), send_burst(), reset(). DecisionMonitor with wait_for_decision().

3. **Updated compiler** for multi-rule support
   - `src/cocotb_gen.rs` — generates per-rule directed tests, scoreboard rule definitions, random test config, corner case tests
   - `templates/test_harness.py.tera` — comprehensive template with 13 test types: 7 directed + default action + random (500 pkts) + back-to-back + jumbo + min-size + reset recovery

4. **Simulation results** — Enterprise: 13 tests PASS, 500/500 scoreboard matches, 0 mismatches

#### Phase 3: Stateful FSM Rules

5. **Data model extensions**
   - `src/model.rs` — Added FsmTransition, FsmState, FsmDefinition types. Changed StatelessRule.action to Option<Action> for FSM support. Added is_stateful() and action() helper methods.

6. **FSM code generation**
   - `src/verilog_gen.rs` — Refactored to separate generate_stateless_rule() and generate_fsm_rule(). Builds state list, computes state_bits, generates transition conditions.
   - `templates/rule_fsm.v.tera` — FSM template with state encoding, combinational next-state logic, 32-bit timeout counters, sequential state register with async reset.
   - `templates/packet_filter_top.v.tera` — Updated for FSM modules (clk/rst_n connections).

7. **FSM validation** — `src/loader.rs` added FSM graph validation (initial state exists, transitions reference valid states)

8. **Example** — `rules/examples/stateful_sequence.yaml` (allow_arp + arp_then_ipv4 with 1000-cycle timeout)

9. **Bug fix** — Option<Action> type change broke cocotb_gen.rs. Fixed by using rule.action() method and filtering stateful rules from directed test generation.

#### Comprehensive Documentation Suite

10. **Design documents** (`docs/design/`)
    - `architecture.md` — Full system architecture with ASCII diagrams, module hierarchy, data flow
    - `design-decisions.md` — 10 design decisions with rationale, alternatives considered, tradeoffs
    - `ci-pipeline.md` — GitHub Actions workflow design with quality gates

11. **Verification documents** (`docs/verification/`)
    - `verification-strategy.md` — Multi-layer verification philosophy (directed + random + corners + formal)
    - `test-plan.md` — Complete test matrix with 30+ test cases and pass/fail status
    - `test-harness-architecture.md` — UVM-inspired verification framework architecture
    - `coverage-model.md` — Functional coverage definitions with bins and cross coverage

12. **User guide** (`docs/user-guide/`)
    - `getting-started.md` — Quick start guide (5 minutes to first simulation)
    - `rule-language-reference.md` — Complete YAML syntax reference with examples

13. **API reference** (`docs/api/`)
    - `compiler-api.md` — CLI interface, internal modules, verification framework API

14. **Management materials** (`docs/management/`)
    - `executive-summary.md` — Problem, solution, ROI analysis, project status
    - `innovation-analysis.md` — Competitive landscape, IP analysis, market opportunity
    - `roadmap.md` — Phase timeline through 2027

15. **Diagrams** (`docs/diagrams/`)
    - `system-diagrams.md` — System context, compilation data flow, verification environment, FSM state diagram, priority encoder, coverage heatmap

16. **Examples** (`docs/examples/`)
    - `enterprise-walkthrough.md` — Step-by-step walkthrough of 7-rule enterprise example with simulation results

17. **Documentation index** — `docs/README.md` with organized links to all documents

### Git Operations
- Committed all Phase 2, Phase 3, verification framework, and documentation
- Pushed to GitHub
