# Flippy — FPGA Layer 2 Packet Filter Switch

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness
- **Single-spec, dual-output**: same YAML generates both hardware AND verification
- Stateless field matching: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
- Stateful FSM rules: sequence detection with timeout counters (Phase 3)
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
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful, Phase 3)
  - `decision_logic` — generated priority encoder, latches decision per frame

### Packet Interface
- Input: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- Output: `decision_valid`, `decision_pass` (latched until next frame)

## Verification Framework (verification/)
UVM-inspired Python verification environment:
- `verification/packet.py` — EthernetFrame, VlanTag, PacketFactory (arp, ipv4, ipv6, broadcast, random, jumbo, runt)
- `verification/scoreboard.py` — Reference model with predict/check, 500-packet random test achieves 0 mismatches
- `verification/coverage.py` — Functional coverage: ethertype, MAC type, frame size, VLAN, decisions, rule hits, cross coverage
- `verification/driver.py` — PacketDriver BFM, DecisionMonitor

## Commands
```bash
cargo run -- compile rules/examples/allow_arp.yaml        # Generate Verilog + tests (1 rule)
cargo run -- compile rules/examples/enterprise.yaml        # Generate Verilog + tests (7 rules)
cargo run -- validate rules/examples/allow_arp.yaml        # Validate YAML only
make sim RULES=rules/examples/allow_arp.yaml               # Full simulation (2 tests)
make sim RULES=rules/examples/enterprise.yaml              # Full simulation (13 tests)
make lint                                                   # Icarus lint check
```

## Key Files
- `src/model.rs` — Data model (Action, MatchCriteria, StatelessRule, FilterConfig, MacAddress, FsmDefinition)
- `src/loader.rs` — YAML loading + validation (MAC, ethertype, VLAN, FSM graph)
- `src/verilog_gen.rs` — Tera-based Verilog generation (stateless + FSM)
- `src/cocotb_gen.rs` — cocotb test harness generation (directed + random + corners)
- `rtl/frame_parser.v` — Hand-written Ethernet frame parser FSM
- `templates/*.tera` — Tera templates (rule_match, rule_fsm, decision_logic, top, test, makefile)
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver)

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof) so consumers can read it after frame completes
- Rules sorted by priority (highest first) at compile time; priority encoder is simple if/else chain
- Frame parser handles 802.1Q VLAN tagging (0x8100)
- All stateless rule evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- Verification framework uses UVM-inspired architecture (Driver/Monitor/Scoreboard/Coverage)

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb
- Icarus Verilog (iverilog/vvp)
- Target: Xilinx 7-series (Artix-7), architecture-portable Verilog

## Current Status
- **Phase 1**: Complete — single rule (allow ARP), 2 tests PASS
- **Phase 2**: Complete — 7-rule enterprise example, 13 tests PASS, 500/500 scoreboard
- **Phase 3**: Complete — stateful FSM code generation, rule_fsm.v.tera, stateful_sequence.yaml
- **Phase 4**: Future — synthesis targeting (Vivado, Artix-7, AXI-Stream)

## Documentation
Full documentation suite in `docs/` — see `docs/README.md` for index.
Key docs: architecture, design decisions, verification strategy, test plan, coverage model, user guide, API reference, management materials.
