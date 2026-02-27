# Flippy — FPGA Layer 2 Packet Filter Switch

## Vision
Flippy is an FPGA-based packet filtering switch where YAML-defined rules compile into both synthesizable Verilog (the filter hardware) and a cocotb test harness (the validator). The two outputs are generated from the same specification but serve orthogonal purposes: the filter enforces rules in hardware, the harness proves they work correctly in simulation.

## What It Does
1. You define packet filter rules in YAML (match on MAC addresses, EtherType, VLAN tags, etc.)
2. The `flippy` compiler (written in Rust) reads the YAML and generates:
   - **Verilog RTL** — synthesizable hardware description for an FPGA
   - **cocotb test bench** — Python tests that verify the hardware via simulation
3. Run simulation with Icarus Verilog + cocotb to verify correctness
4. (Future) Synthesize for Xilinx Artix-7 FPGA

## Innovation / Unique Value
Flippy is unique in that no other open-source tool generates both the hardware implementation (Verilog) and the verification environment (cocotb) from a single specification. Commercial tools like Agnisys IDS-Verify generate tests from register specs but assume the RTL already exists. LLM-based approaches generate one or the other non-deterministically. Flippy generates both, ensuring perfect alignment between specification, implementation, and verification.

## Architecture
The generated hardware has a simple streaming interface (byte-at-a-time Ethernet frames). A hand-written frame parser extracts header fields, generated per-rule matchers evaluate in parallel (combinational), and a priority encoder selects the first matching rule's action (pass or drop).

```
rules.yaml ──> Compiler (Rust) ──┬──> Verilog (DUT)
                                 └──> cocotb tests (Python)
                                       │
             Icarus Verilog + cocotb <──┘
```

**Verilog module hierarchy:**
- `packet_filter_top` — generated top-level, wires everything
  - `frame_parser` — hand-written, extracts dst/src MAC, EtherType, VLAN, raw bytes
  - `rule_match_N` — generated per stateless rule, combinational field matching
  - `rule_fsm_N` — generated per stateful rule, registered FSM with timeout
  - `decision_logic` — generated priority encoder, first-match wins

## Verification Framework
UVM-inspired Python verification environment with:
- **PacketFactory** — generates directed, random, boundary, and corner-case Ethernet frames
- **PacketDriver** (BFM) — drives frames into the DUT byte-by-byte
- **DecisionMonitor** — captures pass/drop decisions from the DUT
- **Scoreboard** — Python reference model that predicts correct behavior, checks against DUT
- **Coverage** — functional coverage with cover points, bins, and cross coverage
- Enterprise example: 7 rules, 13 tests, 500 random packets with 0 scoreboard mismatches

## Project Structure
- `rules/` — YAML rule definitions and schema
- `src/` — Rust compiler source (clap CLI, serde YAML parser, Tera template renderer)
- `templates/` — Tera templates for Verilog and cocotb generation
- `rtl/` — Hand-written Verilog (frame parser)
- `gen/` — Generated output (rtl/ and tb/ subdirectories)
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver)
- `docs/` — Comprehensive documentation (design, verification, user guide, API, management)
- `synth/` — Synthesis files (future)

## Technology Stack
- **Compiler**: Rust (clap, serde_yaml, serde_json, tera, anyhow)
- **HDL**: Verilog (IEEE 1364-2005 compatible, portable)
- **Simulation**: Icarus Verilog + cocotb 2.x (Python)
- **Verification**: UVM-inspired Python framework with scoreboard and coverage
- **Target FPGA**: Xilinx 7-series (Artix-7) — future phase

## Development Status
- **Phase 1** (complete): Single stateless rule (allow ARP), frame parser, 2 cocotb tests PASS
- **Phase 2** (complete): 7-rule enterprise example, MAC wildcards, VLAN matching, advanced verification framework, 13 tests PASS, 500/500 scoreboard matches
- **Phase 3** (complete): Stateful FSM rules with timeout counters, sequence detection, FSM Verilog template
- **Phase 4** (future): Synthesis targeting (Vivado, Artix-7 constraints, AXI-Stream, store-and-forward)

## Documentation
See `docs/README.md` for the full documentation index including:
- Design: architecture, design decisions, CI pipeline
- Verification: strategy, test plan, test harness architecture, coverage model
- User guide: getting started, rule language reference
- API reference: compiler CLI and internal modules
- Management: executive summary, innovation analysis, roadmap
- Research: cocotb, coverage, mutation testing, formal verification

See `docs/RESEARCH.md` for the full verification framework research report.
