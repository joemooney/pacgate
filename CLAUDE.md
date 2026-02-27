# PacGate — FPGA Layer 2 Packet Filter Gate

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness
- **Single-spec, dual-output**: same YAML generates both hardware AND verification
- Stateless field matching: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
- Stateful FSM rules: sequence detection with timeout counters
- MAC wildcard support (e.g., "00:1a:2b:*:*:*" -> value/mask matching)
- Priority-based first-match-wins decision logic
- Whitelist/blacklist mode via default action (pass/drop)
- Rule overlap and shadow detection with warnings
- FPGA resource estimation (LUTs/FFs for Artix-7) + timing/pipeline analysis
- `--json` flag on compile/validate/estimate/diff for CI/scripting integration
- `diff` subcommand for rule set change management
- 44 Rust unit tests, 13 cocotb simulation tests, 85%+ functional coverage

## Architecture
```
rules.yaml --> pacgate (Rust) --+--> Verilog RTL  (gen/rtl/)
                                '--> cocotb tests (gen/tb/)
                                      |
             Icarus Verilog + cocotb <-'
```

### Verilog Module Hierarchy
- `packet_filter_top` — generated top-level
  - `frame_parser` — hand-written Ethernet parser (rtl/frame_parser.v)
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful)
  - `decision_logic` — generated priority encoder, latches decision per frame

### Packet Interface
- Input: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- Output: `decision_valid`, `decision_pass` (latched until next frame)

## CLI Commands
```bash
pacgate compile rules.yaml             # Generate Verilog + cocotb tests
pacgate compile rules.yaml --json      # JSON output with warnings
pacgate validate rules.yaml            # Validate YAML only (no output)
pacgate validate rules.yaml --json     # JSON validation with rule list
pacgate init [rules.yaml]              # Create starter rules file
pacgate estimate rules.yaml            # FPGA resource estimate + timing
pacgate estimate rules.yaml --json     # JSON resource/timing data
pacgate diff old.yaml new.yaml         # Compare two rule sets
pacgate diff old.yaml new.yaml --json  # JSON diff output
pacgate graph rules.yaml               # DOT graph output (pipe to dot -Tpng)
pacgate stats rules.yaml               # Rule set analytics
pacgate stats rules.yaml --json        # JSON analytics
make sim RULES=rules/examples/enterprise.yaml   # Full simulation
make lint                                        # Icarus Verilog lint
cargo test                                       # 44 Rust unit tests
```

## Key Files
- `src/model.rs` — Data model + 21 unit tests (Action, MatchCriteria, StatelessRule, MacAddress, FSM types)
- `src/loader.rs` — YAML loading + validation + overlap detection + 23 unit tests
- `src/verilog_gen.rs` — Tera-based Verilog generation (stateless + FSM)
- `src/cocotb_gen.rs` — cocotb test harness generation (directed + random + corners)
- `src/main.rs` — clap CLI (compile, validate, init, estimate, diff, graph, stats)
- `rtl/frame_parser.v` — Hand-written Ethernet frame parser FSM
- `templates/*.tera` — 6 Tera templates for code generation
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver)
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof)
- Rules sorted by priority (highest first); priority encoder is if/else chain
- Frame parser handles 802.1Q VLAN tagging (0x8100)
- Stateless evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- Verification uses UVM-inspired architecture (Driver/Monitor/Scoreboard/Coverage)
- Random test varies frame sizes (runt/min/typical/large/jumbo) and includes VLAN-tagged frames

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb
- Icarus Verilog (iverilog/vvp)
- Target: Xilinx 7-series (Artix-7), architecture-portable Verilog

## Current Status
- **Phase 1**: Complete — single rule (allow ARP), 7 tests PASS
- **Phase 2**: Complete — 7-rule enterprise, 13 tests PASS, 500/500 scoreboard, 85% coverage
- **Phase 3**: Complete — stateful FSM generation, FSM validation, stateful_sequence.yaml
- **Phase 4**: Future — synthesis targeting (Vivado, Artix-7, AXI-Stream)

## Documentation
Full documentation suite in `docs/` — see `docs/README.md` for index.
