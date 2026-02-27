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

## Architecture
The generated hardware has a simple streaming interface (byte-at-a-time Ethernet frames). A hand-written frame parser extracts header fields, generated per-rule matchers evaluate in parallel (combinational), and a priority encoder selects the first matching rule's action (pass or drop).

## Project Structure
- `rules/` — YAML rule definitions and schema
- `src/` — Rust compiler source (clap CLI, serde YAML parser, Tera template renderer)
- `templates/` — Tera templates for Verilog and cocotb generation
- `rtl/` — Hand-written Verilog (frame parser)
- `gen/` — Generated output (rtl/ and tb/ subdirectories)
- `synth/` — Synthesis files (future)

## Technology Stack
- **Compiler**: Rust (clap, serde_yaml, tera, anyhow)
- **HDL**: Verilog (IEEE 1364-2005 compatible, portable)
- **Simulation**: Icarus Verilog + cocotb (Python)
- **Target FPGA**: Xilinx 7-series (Artix-7) — future phase

## Development Phases
- **Phase 1** (current): Minimal end-to-end — one stateless rule, frame parser, cocotb tests
- **Phase 2**: Multiple stateless rules, MAC wildcards, VLAN matching, byte_match + advanced verification (coverage model generation, constrained random, negative/boundary tests)
- **Phase 3**: Stateful FSM rules with timeout counters and sequence testing + mutation testing (MCY), formal property generation (SymbiYosys)
- **Phase 4**: Synthesis targeting (Vivado, Artix-7 constraints, AXI-Stream via cocotbext-axi, store-and-forward)

## Innovation / Unique Value
Flippy is unique in that no other open-source tool generates both the hardware implementation (Verilog) and the verification environment (cocotb) from a single specification. Commercial tools like Agnisys IDS-Verify generate tests from register specs but assume the RTL already exists. LLM-based approaches generate one or the other non-deterministically. Flippy generates both, ensuring perfect alignment between specification, implementation, and verification.

See `docs/RESEARCH.md` for the full verification framework research report.
