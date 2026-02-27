# PacGate — FPGA Layer 2/3/4 Packet Filter Gate

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness
- **Single-spec, dual-output**: same YAML generates both hardware AND verification
- **L2 matching**: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp (with MAC wildcards)
- **L3 matching**: src_ip, dst_ip (CIDR prefix), ip_protocol
- **L4 matching**: src_port, dst_port (exact or range)
- **VXLAN tunnel**: vxlan_vni matching (24-bit VNI after UDP:4789 detection)
- Stateful FSM rules: sequence detection with timeout counters
- Priority-based first-match-wins decision logic
- Whitelist/blacklist mode via default action (pass/drop)
- Per-rule hardware counters with AXI-Lite CSR readout (`--counters` flag)
- PCAP import for cocotb test stimulus (`pcap` subcommand)
- HTML coverage report generation (`report` subcommand)
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
- 14 real-world YAML examples (data center, industrial OT, automotive, 5G, IoT, campus, stateful, L3/L4 firewall, VXLAN)
- 70 Rust unit tests + 29 integration tests, 13+ cocotb simulation tests, 85%+ functional coverage

## Architecture
```
rules.yaml --> pacgate (Rust) --+--> Verilog RTL  (gen/rtl/)
                                +--> cocotb tests (gen/tb/)
                                +--> SVA assertions (gen/formal/)
                                +--> property tests (gen/tb/)
                                +--> HTML report
                                |
             Icarus Verilog + cocotb <-'
```

### Verilog Module Hierarchy
- `packet_filter_top` — generated top-level
  - `frame_parser` — hand-written parser: L2/L3/L4/VXLAN extraction (rtl/frame_parser.v)
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful)
  - `decision_logic` — generated priority encoder with rule_idx output
- `packet_filter_axi_top` — AXI-Stream top-level (hand-written, rtl/)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — core filter (above)
  - `store_forward_fifo` — frame buffering, forwards/discards based on decision
- `rule_counters` — per-rule 64-bit packet/byte counters (rtl/rule_counters.v)
- `axi_lite_csr` — AXI4-Lite register interface for counter readout (rtl/axi_lite_csr.v)

### Packet Interface
- Simple: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- AXI-Stream: `s_axis_tdata[7:0]`, `s_axis_tvalid`, `s_axis_tready`, `s_axis_tlast` (in/out)
- Output: `decision_valid`, `decision_pass`, `decision_rule_idx`, `decision_default`

## CLI Commands
```bash
pacgate compile rules.yaml             # Generate Verilog + cocotb tests
pacgate compile rules.yaml --axi       # Include AXI-Stream wrapper + tests
pacgate compile rules.yaml --counters  # Include per-rule counters + AXI-Lite CSR
pacgate compile rules.yaml --json      # JSON output with warnings
pacgate validate rules.yaml            # Validate YAML only (no output)
pacgate init [rules.yaml]              # Create starter rules file
pacgate estimate rules.yaml            # FPGA resource estimate + timing
pacgate diff old.yaml new.yaml         # Compare two rule sets
pacgate graph rules.yaml               # DOT graph output (pipe to dot -Tpng)
pacgate stats rules.yaml               # Rule set analytics
pacgate lint rules.yaml                # Best-practice analysis
pacgate formal rules.yaml              # Generate SVA + SymbiYosys files
pacgate report rules.yaml              # Generate HTML coverage report
pacgate pcap capture.pcap              # Import PCAP for cocotb test stimulus
cargo test                             # 99 tests (70 unit + 29 integration)
```

## Key Files
- `src/model.rs` — Data model (Action, MatchCriteria, Ipv4Prefix, PortMatch, MacAddress, FSM types)
- `src/loader.rs` — YAML loading + validation + overlap detection
- `src/verilog_gen.rs` — Tera-based Verilog generation (L2/L3/L4/VXLAN conditions)
- `src/cocotb_gen.rs` — cocotb test harness + AXI tests + property test generation
- `src/formal_gen.rs` — SVA assertion + SymbiYosys task file generation
- `src/pcap.rs` — PCAP file reader + cocotb stimulus generator
- `src/main.rs` — clap CLI (compile, validate, init, estimate, diff, graph, stats, lint, formal, report, pcap)
- `rtl/frame_parser.v` — Hand-written Ethernet/IPv4/TCP/UDP/VXLAN parser FSM
- `rtl/rule_counters.v` — Per-rule 64-bit packet/byte counters
- `rtl/axi_lite_csr.v` — AXI4-Lite register interface for counters
- `rtl/axi_stream_adapter.v` — AXI-Stream to pkt_* interface bridge
- `rtl/store_forward_fifo.v` — Store-and-forward FIFO with decision-based forwarding
- `rtl/packet_filter_axi_top.v` — AXI-Stream top-level integrating all modules
- `templates/*.tera` — 10 Tera templates for code generation (+ HTML coverage report)
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver, properties)
- `rules/examples/` — 14 YAML examples
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof)
- Rules sorted by priority (highest first); priority encoder is if/else chain
- Frame parser handles 802.1Q VLAN, IPv4, TCP/UDP, VXLAN
- Stateless evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- IPv4 CIDR matching: `(ip & mask) == (prefix & mask)` in hardware
- Port range matching: `(port >= low && port <= high)` with 16-bit comparators
- VXLAN detection: UDP dst port == 4789, then 8-byte VXLAN header, extract 24-bit VNI
- AXI-Stream modules are hand-written (not generated) since they are infrastructure
- License: Proprietary (see LICENSE)

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb
- Icarus Verilog (iverilog/vvp)
- Target: Xilinx 7-series (Artix-7), architecture-portable Verilog
- Optional: Yosys (synthesis), SymbiYosys (formal verification), Hypothesis (property testing)

## Current Status
- **Phase 1-3**: Complete — L2 matching, multi-rule, stateful FSM
- **Phase 4**: Complete — AXI-Stream, synthesis, formal verification, property testing
- **Phase 5**: Complete — 12 examples, lint, docs, workshops, proprietary license
- **Phase 6**: Complete — L3/L4 matching (IPv4/TCP/UDP), per-rule counters, PCAP import, HTML reports, VXLAN tunnel parsing
