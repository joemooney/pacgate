# PacGate — FPGA Layer 2 Packet Filter Switch

## Vision
PacGate is an FPGA-based packet filtering switch where YAML-defined rules compile into both synthesizable Verilog (the filter hardware) and a cocotb test harness (the validator). The two outputs are generated from the same specification but serve orthogonal purposes: the filter enforces rules in hardware, the harness proves they work correctly in simulation.

## What It Does
1. You define packet filter rules in YAML (match on MAC addresses, EtherType, VLAN tags, etc.)
2. The `pacgate` compiler (written in Rust) reads the YAML and generates:
   - **Verilog RTL** — synthesizable hardware description for an FPGA
   - **cocotb test bench** — Python tests that verify the hardware via simulation
   - **SVA assertions** — formal properties for bounded model checking
   - **Property tests** — Hypothesis-based invariant testing
3. Run simulation with Icarus Verilog + cocotb to verify correctness
4. Synthesize for Xilinx Artix-7 FPGA using Yosys (open-source) or Vivado
5. Run formal verification with SymbiYosys for mathematical proof of correctness

## Innovation / Unique Value
PacGate is unique in that no other open-source tool generates both the hardware implementation (Verilog) and the verification environment (cocotb) from a single specification. Commercial tools like Agnisys IDS-Verify generate tests from register specs but assume the RTL already exists. LLM-based approaches generate one or the other non-deterministically. PacGate generates both, ensuring perfect alignment between specification, implementation, and verification.

## Architecture
The generated hardware has a simple streaming interface (byte-at-a-time Ethernet frames). A hand-written frame parser extracts header fields, generated per-rule matchers evaluate in parallel (combinational), and a priority encoder selects the first matching rule's action (pass or drop).

```
rules.yaml ──> Compiler (Rust) ──┬──> Verilog (DUT)
                                 ├──> cocotb tests (Python)
                                 ├──> SVA assertions (formal)
                                 └──> Property tests (Hypothesis)
                                        │
             Icarus Verilog + cocotb <──┘
```

**Verilog module hierarchy:**
- `packet_filter_axi_top` — AXI-Stream top-level (hand-written)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — generated top-level, wires everything
    - `frame_parser` — hand-written, extracts dst/src MAC, EtherType, VLAN, raw bytes
    - `rule_match_N` — generated per stateless rule, combinational field matching
    - `rule_fsm_N` — generated per stateful rule, registered FSM with timeout
    - `decision_logic` — generated priority encoder, first-match wins
  - `store_forward_fifo` — buffers frames, forwards/discards based on filter decision

## Verification Framework
UVM-inspired Python verification environment with:
- **PacketFactory** — generates directed, random, boundary, and corner-case Ethernet frames
- **PacketDriver** (BFM) — drives frames into the DUT byte-by-byte
- **DecisionMonitor** — captures pass/drop decisions from the DUT
- **Scoreboard** — Python reference model that predicts correct behavior, checks against DUT
- **Coverage** — functional coverage with cover points, bins, cross coverage, and XML export
- **Properties** — Hypothesis-based property testing (determinism, priority, conservation, independence)
- Enterprise example: 7 rules, 13 tests, 500 random packets with 0 scoreboard mismatches

## Formal Verification
- SVA assertions generated from YAML rules (reset, completeness, latency, default action, per-rule)
- SymbiYosys task files for BMC (bounded model checking) and cover mode
- Run via: `pacgate formal rules.yaml` then `cd gen/formal && sby -f packet_filter.sby`

## Project Structure
- `rules/` — YAML rule definitions and schema
- `src/` — Rust compiler source (clap CLI, serde YAML parser, Tera template renderer)
- `templates/` — Tera templates for Verilog, cocotb, SVA, and property test generation
- `rtl/` — Hand-written Verilog (frame parser, AXI adapter, FIFO, AXI top)
- `gen/` — Generated output (rtl/, tb/, tb-axi/, formal/ subdirectories)
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver, properties)
- `synth/` — Synthesis files (Artix-7 XDC constraints, Yosys synthesis script)
- `docs/` — Comprehensive documentation (design, verification, user guide, API, management)

## Technology Stack
- **Compiler**: Rust (clap, serde_yaml, serde_json, tera, anyhow)
- **HDL**: Verilog (IEEE 1364-2005 compatible, portable)
- **Simulation**: Icarus Verilog + cocotb 2.x (Python)
- **Verification**: UVM-inspired Python framework with scoreboard and coverage
- **Formal**: SymbiYosys + SMT solvers (via generated SVA assertions)
- **Property Testing**: Hypothesis (Python) for invariant verification
- **Synthesis**: Yosys (open-source) targeting Xilinx 7-series
- **CI**: GitHub Actions (build, lint, simulate, artifact upload)
- **Target FPGA**: Xilinx 7-series (Artix-7)

## CLI Commands
- `pacgate compile rules.yaml` — Generate Verilog + cocotb tests (with rule summary table)
- `pacgate compile rules.yaml --axi` — Include AXI-Stream wrapper + FIFO + AXI tests
- `pacgate validate rules.yaml` — Validate YAML only
- `pacgate init` — Create a well-commented starter rules file
- `pacgate estimate rules.yaml` — FPGA resource estimation (LUTs/FFs) + timing analysis
- `pacgate diff old.yaml new.yaml` — Compare two rule sets (added/removed/modified)
- `pacgate graph rules.yaml` — DOT graph output for Graphviz visualization
- `pacgate stats rules.yaml` — Rule set analytics (field usage, priority spacing, action balance)
- `pacgate formal rules.yaml` — Generate SVA assertions + SymbiYosys task files
- All commands except `init` and `graph` support `--json` for machine-readable output

## Quality
- 44 Rust unit tests (model parsing, validation, overlap detection)
- 19 Rust integration tests (full compile pipeline, AXI, formal, JSON output, diff, stats, graph)
- 13+ cocotb simulation tests (directed + 500-packet random + corner cases)
- 85%+ functional coverage with varied frame sizes and VLAN-tagged traffic
- Rule overlap and shadow detection with compile-time warnings
- Property-based testing with Hypothesis for invariant verification
- SVA formal assertions for mathematical correctness proofs

## Development Status
- **Phase 1** (complete): Single stateless rule (allow ARP), frame parser, 7 cocotb tests PASS
- **Phase 2** (complete): 7-rule enterprise example, MAC wildcards, VLAN matching, advanced verification framework, 13 tests PASS, 500/500 scoreboard matches, 85% coverage
- **Phase 3** (complete): Stateful FSM rules with timeout counters, sequence detection, FSM Verilog template
- **Phase 4** (complete): AXI-Stream wrapper, store-and-forward FIFO, Yosys synthesis script, Artix-7 constraints, SVA assertions, SymbiYosys formal verification, property-based testing, coverage XML export

## Documentation
See `docs/README.md` for the full documentation index including:
- Design: architecture, design decisions, CI pipeline
- Verification: strategy, test plan, test harness architecture, coverage model
- User guide: getting started, rule language reference
- API reference: compiler CLI and internal modules
- Management: executive summary, innovation analysis, roadmap
- Research: cocotb, coverage, mutation testing, formal verification

See `docs/RESEARCH.md` for the full verification framework research report.
