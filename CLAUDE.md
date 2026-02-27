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
- `lint` subcommand for best-practice analysis and security checks (7 lint rules)
- FPGA resource estimation (LUTs/FFs for Artix-7) + timing/pipeline analysis
- `--json` flag on compile/validate/estimate/diff/formal/lint for CI/scripting integration
- `diff` subcommand for rule set change management
- Shell completions (bash/zsh/fish) via hidden `completions` subcommand
- AXI-Stream wrapper with store-and-forward FIFO (`--axi` flag)
- SVA assertion generation + SymbiYosys formal verification (`formal` subcommand)
- Property-based testing with Hypothesis strategies
- Coverage XML export with merge support across runs
- Yosys synthesis script + Artix-7 XDC constraints
- 12 real-world YAML examples (data center, industrial OT, automotive, 5G, IoT, campus, stateful)
- 44 Rust unit tests + 21 integration tests, 13+ cocotb simulation tests, 85%+ functional coverage

## Architecture
```
rules.yaml --> pacgate (Rust) --+--> Verilog RTL  (gen/rtl/)
                                +--> cocotb tests (gen/tb/)
                                +--> SVA assertions (gen/formal/)
                                +--> property tests (gen/tb/)
                                |
             Icarus Verilog + cocotb <-'
```

### Verilog Module Hierarchy
- `packet_filter_top` — generated top-level
  - `frame_parser` — hand-written Ethernet parser (rtl/frame_parser.v)
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful)
  - `decision_logic` — generated priority encoder, latches decision per frame
- `packet_filter_axi_top` — AXI-Stream top-level (hand-written, rtl/)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — core filter (above)
  - `store_forward_fifo` — frame buffering, forwards/discards based on decision

### Packet Interface
- Simple: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- AXI-Stream: `s_axis_tdata[7:0]`, `s_axis_tvalid`, `s_axis_tready`, `s_axis_tlast` (in/out)
- Output: `decision_valid`, `decision_pass` (latched until next frame)

## CLI Commands
```bash
pacgate compile rules.yaml             # Generate Verilog + cocotb tests
pacgate compile rules.yaml --axi       # Include AXI-Stream wrapper + tests
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
pacgate lint rules.yaml                # Best-practice analysis
pacgate lint rules.yaml --json         # JSON lint findings
pacgate formal rules.yaml              # Generate SVA + SymbiYosys files
pacgate formal rules.yaml --json       # JSON formal output
make sim RULES=rules/examples/enterprise.yaml   # Full simulation
make sim-axi RULES=rules/examples/enterprise.yaml  # AXI-Stream simulation
make synth RULES=rules/examples/enterprise.yaml  # Yosys synthesis
make formal RULES=rules/examples/enterprise.yaml  # Formal verification
make lint                                        # Icarus Verilog lint
cargo test                                       # 65 tests (44 unit + 21 integration)
```

## Key Files
- `src/model.rs` — Data model + 21 unit tests (Action, MatchCriteria, StatelessRule, MacAddress, FSM types)
- `src/loader.rs` — YAML loading + validation + overlap detection + 23 unit tests
- `src/verilog_gen.rs` — Tera-based Verilog generation (stateless + FSM + AXI copy)
- `src/cocotb_gen.rs` — cocotb test harness + AXI tests + property test generation
- `src/formal_gen.rs` — SVA assertion + SymbiYosys task file generation
- `src/main.rs` — clap CLI (compile, validate, init, estimate, diff, graph, stats, lint, formal)
- `rtl/frame_parser.v` — Hand-written Ethernet frame parser FSM
- `rtl/axi_stream_adapter.v` — AXI-Stream to pkt_* interface bridge
- `rtl/store_forward_fifo.v` — Store-and-forward FIFO with decision-based forwarding
- `rtl/packet_filter_axi_top.v` — AXI-Stream top-level integrating all modules
- `templates/*.tera` — 9 Tera templates for code generation
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver, properties)
- `synth/artix7.xdc` — Artix-7 XDC pin constraints (125 MHz, LVCMOS33)
- `synth/synth_yosys.ys` — Yosys synthesis script for Xilinx 7-series
- `rules/examples/` — 12 YAML examples (enterprise, datacenter, industrial_ot, automotive, 5G, campus, IoT, blacklist, stateful)
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline

## Documentation
- `README.md` — Project showcase with branding
- `docs/WHY_PACGATE.md` — Value proposition for skeptics
- `docs/WORKSHOPS.md` — 8 hands-on tutorials
- `docs/user-guide/USERS_GUIDE.md` — Comprehensive user guide with examples
- `docs/verification/TEST_GUIDE.md` — Test and verification guide
- `docs/management/SLIDESHOW.md` — 13-slide management presentation
- `docs/README.md` — Full documentation index

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof)
- Rules sorted by priority (highest first); priority encoder is if/else chain
- Frame parser handles 802.1Q VLAN tagging (0x8100)
- Stateless evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- Verification uses UVM-inspired architecture (Driver/Monitor/Scoreboard/Coverage)
- Random test varies frame sizes (runt/min/typical/large/jumbo) and includes VLAN-tagged frames
- AXI-Stream modules are hand-written (not generated) since they are infrastructure
- Store-and-forward FIFO uses inferred BRAM (portable across vendors)
- SVA assertions generated from same rule spec, cover reset/completeness/latency/default action
- License: Proprietary (see LICENSE)

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb
- Icarus Verilog (iverilog/vvp)
- Target: Xilinx 7-series (Artix-7), architecture-portable Verilog
- Optional: Yosys (synthesis), SymbiYosys (formal verification), Hypothesis (property testing)

## Current Status
- **Phase 1**: Complete — single rule (allow ARP), 7 tests PASS
- **Phase 2**: Complete — 7-rule enterprise, 13 tests PASS, 500/500 scoreboard, 85% coverage
- **Phase 3**: Complete — stateful FSM generation, FSM validation, stateful_sequence.yaml
- **Phase 4**: Complete — AXI-Stream wrapper, store-and-forward FIFO, synthesis scripts, formal verification, property-based testing, coverage XML export
- **Phase 5**: Complete — 12 real-world examples, lint command, README, User's Guide, Test Guide, Workshops, Slideshow, Why PacGate
