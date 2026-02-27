# Flippy — FPGA Layer 2 Packet Filter Switch

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness
- Stateless field matching on dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
- MAC wildcard support (e.g., "00:1a:2b:*:*:*" → value/mask matching)
- Priority-based first-match-wins decision logic
- Whitelist/blacklist mode via default action (pass/drop)

## Architecture
```
rules.yaml ──> flippy (Rust) ──┬──> Verilog RTL  (gen/rtl/)
                                └──> cocotb tests (gen/tb/)
                                      │
             Icarus Verilog + cocotb <─┘
```

### Verilog Module Hierarchy
- `packet_filter_top` — generated top-level
  - `frame_parser` — hand-written Ethernet parser (rtl/frame_parser.v)
  - `rule_match_N` — generated per-rule combinational matchers
  - `decision_logic` — generated priority encoder, latches decision per frame

### Packet Interface
- Input: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- Output: `decision_valid`, `decision_pass` (latched until next frame)

## Commands
```bash
cargo run -- compile rules/examples/allow_arp.yaml   # Generate Verilog + tests
cargo run -- validate rules/examples/allow_arp.yaml  # Validate YAML only
make sim RULES=rules/examples/allow_arp.yaml         # Full simulation
make lint                                             # Icarus lint check
```

## Key Files
- `src/model.rs` — Rule model structs (Action, MatchCriteria, StatelessRule, FilterConfig)
- `src/loader.rs` — YAML loading + validation
- `src/verilog_gen.rs` — Tera-based Verilog generation
- `src/cocotb_gen.rs` — cocotb test harness generation
- `rtl/frame_parser.v` — Hand-written Ethernet frame parser FSM
- `templates/*.tera` — Tera templates for code generation

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof) so consumers can read it after frame completes
- Rules sorted by priority (highest first) at compile time; priority encoder is simple if/else chain
- Frame parser handles 802.1Q VLAN tagging (0x8100)
- All rule evaluation is combinational (O(1) clock cycles)

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb
- Icarus Verilog (iverilog/vvp)
- Target: Xilinx 7-series (Artix-7), architecture-portable Verilog

## Current Phase: 1 (Minimal End-to-End)
- Single stateless rule (allow ARP)
- Future: Phase 2 (multi-rule), Phase 3 (stateful FSM), Phase 4 (synthesis)
