# PacGate — FPGA Layer 2/3/4 Packet Filter Gate

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness
- **Single-spec, dual-output**: same YAML generates both hardware AND verification
- **L2 matching**: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp (with MAC wildcards)
- **L3 matching**: src_ip, dst_ip (CIDR prefix), ip_protocol
- **L4 matching**: src_port, dst_port (exact or range)
- **VXLAN tunnel**: vxlan_vni matching (24-bit VNI after UDP:4789 detection)
- **GTP-U tunnel**: gtp_teid matching (32-bit TEID after UDP:2152 detection)
- **MPLS label stack**: mpls_label (20-bit), mpls_tc (3-bit), mpls_bos (1-bit bottom-of-stack)
- **IGMP/MLD multicast**: igmp_type (IPv4 protocol 2), mld_type (ICMPv6 types 130-132)
- **Byte-offset matching**: raw byte inspection at any packet offset with value/mask (`byte_match`)
- **Hierarchical State Machines**: nested states, variables (1-32 bit), guards, entry/exit/transition actions
- **Mermaid import/export**: bidirectional stateDiagram-v2 conversion (`from-mermaid`, `to-mermaid`)
- **Multi-port switch fabric**: N independent filter instances (`--ports N`)
- **Connection tracking**: CRC-based hash table with timeout (`--conntrack`)
- **IPv6 matching**: src_ipv6, dst_ipv6 (CIDR prefix), ipv6_next_header
- **Packet simulation**: software dry-run with `simulate` subcommand (no hardware needed)
- **Rate limiting**: per-rule token-bucket rate limiter RTL (`--rate-limit`)
- Stateful FSM rules: sequence detection with timeout counters
- Priority-based first-match-wins decision logic
- Whitelist/blacklist mode via default action (pass/drop)
- Per-rule hardware counters with AXI-Lite CSR readout (`--counters` flag)
- PCAP import for cocotb test stimulus (`pcap` subcommand)
- **PCAP traffic analysis**: automatic rule suggestion from captured traffic (`pcap-analyze` subcommand)
- **PCAP output from simulation**: write Wireshark-compatible PCAP files from simulation results (`--pcap-out`)
- HTML coverage report generation (`report` subcommand)
- **HTML rule documentation**: styled datasheet generation (`doc` subcommand)
- **HTML diff visualization**: color-coded side-by-side HTML diff report (`diff --html`)
- **Performance benchmarking**: compile time, simulation throughput (pkts/sec), LUT/FF scaling curves (`bench` subcommand)
- Rule overlap and shadow detection with warnings
- **Full-stack scoreboard**: Python reference model matches L2/L3/L4/IPv6/VXLAN/byte-match fields
- **Directed L3/L4 tests**: generated tests construct proper IPv4/IPv6/TCP/UDP headers
- **Byte-match simulation**: software simulator evaluates byte_match rules with raw_bytes
- **Enhanced formal**: SVA assertions for IPv6 CIDR, port range, rate limiter, byte-match correctness
- **Conntrack cocotb tests**: 5 tests (new flow, return traffic, timeout, collision, overflow)
- **MCY Verilog mutation testing**: generate MCY config for Yosys-level mutation analysis (`mcy` subcommand)
- **Mutation kill-rate runner**: compile + lint each mutant, report kill/survived/error rates (`mutate --run`)
- **Coverage-directed closure**: CoverageDirector wired into test loop with XML export
- **Boundary test generation**: auto-derived CIDR/port boundary tests + formally-derived negative tests
- **Enhanced property tests**: 9 Hypothesis-based tests including CIDR/port/IPv6 boundary checks
- `lint` subcommand for best-practice analysis and security checks (12 lint rules)
- FPGA resource estimation (LUTs/FFs for Artix-7) + timing/pipeline analysis
- `--json` flag on compile/validate/estimate/diff/formal/lint for CI/scripting integration
- `diff` subcommand for rule set change management
- Shell completions (bash/zsh/fish) via hidden `completions` subcommand
- AXI-Stream wrapper with store-and-forward FIFO (`--axi` flag)
- SVA assertion generation + SymbiYosys formal verification (`formal` subcommand)
- **Synthesis project generation**: Yosys and Vivado project files (`synth` subcommand)
- **Rule templates**: 7 built-in templates with variable substitution (`template` subcommand)
- **Mutation testing**: rule mutation engine with mutant generation (`mutate` subcommand)
- Property-based testing with Hypothesis strategies
- Coverage XML export with merge support across runs
- Coverage-directed test generation (verification/coverage_driven.py)
- Enhanced overlap detection with CIDR containment and port range analysis
- 21 real-world YAML examples (data center, industrial OT, automotive, 5G, IoT, campus, stateful, L3/L4 firewall, VXLAN, byte-match, HSM, IPv6, rate-limited, GTP-U, MPLS, multicast)
- 218 Rust unit tests + 122 integration tests = 340 total, 23 Python scoreboard tests, 13+ cocotb simulation tests, 5 conntrack cocotb tests, 85%+ functional coverage

## Architecture
```
rules.yaml --> pacgate (Rust) --+--> Verilog RTL  (gen/rtl/)
                                +--> cocotb tests (gen/tb/)
                                +--> SVA assertions (gen/formal/)
                                +--> property tests (gen/tb/)
                                +--> HTML report
                                +--> Mermaid diagram (stdout)
                                |
             Icarus Verilog + cocotb <-'

Mermaid .md --> pacgate from-mermaid --> YAML rules
```

### Verilog Module Hierarchy
- `packet_filter_multiport_top` — multi-port wrapper (generated, `--ports N`)
  - N x `packet_filter_top` — per-port filter instance
- `packet_filter_top` — generated top-level
  - `frame_parser` — hand-written parser: L2/L3/L4/IPv6/VXLAN/GTP-U/MPLS/IGMP/MLD extraction (rtl/frame_parser.v)
  - `byte_capture` — generated byte-offset capture module (if byte_match used)
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful, supports HSM)
  - `decision_logic` — generated priority encoder with rule_idx output
- `packet_filter_axi_top` — AXI-Stream top-level (hand-written, rtl/)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — core filter (above)
  - `store_forward_fifo` — frame buffering, forwards/discards based on decision
- `rule_counters` — per-rule 64-bit packet/byte counters (rtl/rule_counters.v)
- `axi_lite_csr` — AXI4-Lite register interface for counter readout (rtl/axi_lite_csr.v)
- `conntrack_table` — connection tracking hash table (rtl/conntrack_table.v)
- `rate_limiter` — token-bucket rate limiter per rule (rtl/rate_limiter.v)

### Packet Interface
- Simple: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- AXI-Stream: `s_axis_tdata[7:0]`, `s_axis_tvalid`, `s_axis_tready`, `s_axis_tlast` (in/out)
- Multi-port: `portN_pkt_data`, `portN_pkt_valid`, etc.
- Output: `decision_valid`, `decision_pass`, `decision_rule_idx`, `decision_default`

## CLI Commands
```bash
pacgate compile rules.yaml             # Generate Verilog + cocotb tests
pacgate compile rules.yaml --axi       # Include AXI-Stream wrapper + tests
pacgate compile rules.yaml --counters  # Include per-rule counters + AXI-Lite CSR
pacgate compile rules.yaml --ports 4   # Multi-port (4 independent filters)
pacgate compile rules.yaml --conntrack # Include connection tracking RTL
pacgate compile rules.yaml --rate-limit # Include rate limiter RTL
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
pacgate from-mermaid fsm.md --name rule --priority 100  # Mermaid → YAML
pacgate to-mermaid rules.yaml          # YAML → Mermaid (stdout)
pacgate simulate rules.yaml --packet "ethertype=0x0800,dst_port=80"  # Dry-run simulation
pacgate simulate rules.yaml --packet "gtp_teid=12345"               # GTP-U tunnel simulation
pacgate simulate rules.yaml --packet "mpls_label=1000,mpls_bos=1"   # MPLS label simulation
pacgate simulate rules.yaml --packet "igmp_type=0x11"               # IGMP multicast simulation
pacgate simulate rules.yaml --packet "..." --pcap-out trace.pcap     # Write simulation results to PCAP
pacgate pcap-analyze capture.pcap      # Analyze PCAP + suggest rules
pacgate pcap-analyze capture.pcap -m whitelist --output-yaml rules.yaml  # Generate rules from PCAP
pacgate synth rules.yaml --target yosys --part artix7  # Generate Yosys synthesis project
pacgate synth rules.yaml --target vivado --part xc7a35t  # Generate Vivado project
pacgate mutate rules.yaml              # Generate mutation test variants
pacgate mutate rules.yaml --run        # Generate + run kill-rate analysis
pacgate mutate rules.yaml --json       # JSON mutation report
pacgate mcy rules.yaml                 # Generate MCY Verilog mutation config
pacgate mcy rules.yaml --run           # Generate + run MCY (requires mcy binary)
pacgate mcy rules.yaml --json          # JSON MCY report
pacgate template list                  # List built-in rule templates
pacgate template show allow_management # Show template details
pacgate template apply web_server --set server_subnet=10.0.0.0/8 -o rules.yaml  # Apply template
pacgate doc rules.yaml                 # Generate HTML rule documentation
pacgate bench rules.yaml               # Benchmark compile time + simulation throughput + LUT/FF scaling
pacgate bench rules.yaml --json        # JSON benchmark report
pacgate diff old.yaml new.yaml --html report.html  # Generate HTML diff visualization report
cargo test                             # 319 tests (214 unit + 105 integration)
pytest verification/test_scoreboard.py # 23 Python scoreboard unit tests
```

## Key Files
- `src/model.rs` — Data model (Action, MatchCriteria, ByteMatch, Ipv6Prefix, RateLimit, FsmVariable, HSM types, ConntrackConfig, GtpTeid, MplsLabel, IgmpType, MldType)
- `src/loader.rs` — YAML loading + validation + CIDR/port overlap detection + HSM/byte_match/conntrack validation
- `src/verilog_gen.rs` — Tera-based Verilog generation (L2/L3/L4/IPv6/VXLAN/GTP-U/MPLS/IGMP/MLD/byte-match, HSM flattening, multiport)
- `src/cocotb_gen.rs` — cocotb test harness + AXI tests + property test generation
- `src/formal_gen.rs` — SVA assertion + SymbiYosys task file generation
- `src/pcap.rs` — PCAP file reader + cocotb stimulus generator
- `src/mermaid.rs` — Mermaid stateDiagram-v2 parser + bidirectional converter
- `src/simulator.rs` — Software packet simulation reference model (IPv4/IPv6 CIDR, ports, MAC wildcards)
- `src/pcap_analyze.rs` — PCAP traffic analysis + automatic rule suggestion engine
- `src/synth_gen.rs` — Synthesis project file generation (Yosys/Vivado)
- `src/mutation.rs` — Rule mutation engine for mutation testing
- `src/templates_lib.rs` — Rule template library (7 built-in templates)
- `src/pcap_writer.rs` — PCAP file writer for simulation output (Wireshark-compatible)
- `src/benchmark.rs` — Performance benchmarking engine (compile time, sim throughput, LUT/FF scaling)
- `src/mcy_gen.rs` — MCY (Mutation Cover with Yosys) config generation
- `src/main.rs` — clap CLI (29 subcommands)
- `rtl/frame_parser.v` — Hand-written Ethernet/IPv4/IPv6/TCP/UDP/VXLAN/GTP-U/MPLS/IGMP/MLD parser FSM
- `rtl/rule_counters.v` — Per-rule 64-bit packet/byte counters
- `rtl/axi_lite_csr.v` — AXI4-Lite register interface for counters
- `rtl/axi_stream_adapter.v` — AXI-Stream to pkt_* interface bridge
- `rtl/store_forward_fifo.v` — Store-and-forward FIFO with decision-based forwarding
- `rtl/packet_filter_axi_top.v` — AXI-Stream top-level integrating all modules
- `rtl/conntrack_table.v` — Connection tracking hash table with CRC hash + timeout
- `rtl/rate_limiter.v` — Token-bucket rate limiter (parameterized PPS, BURST)
- `templates/*.tera` — 19 Tera templates (+ synth scripts, rate limiter TB, HTML docs, diff report, MCY config)
- `templates/diff_report.html.tera` — HTML diff visualization template (color-coded additions/removals/modifications)
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver, properties, coverage_driven, test_scoreboard)
- `rules/examples/` — 21 YAML examples
- `rules/templates/` — 7 rule template YAML snippets
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof)
- Rules sorted by priority (highest first); priority encoder is if/else chain
- Frame parser handles 802.1Q VLAN, IPv4, IPv6, TCP/UDP, VXLAN, GTP-U, MPLS, IGMP, MLD
- Stateless evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- HSM flattening: composite states converted to flat "parent_child" Verilog states (max 4 levels)
- FSM variables: 1-32 bit registers with guards and assignment actions (=, +=, -=, |=)
- IPv4/IPv6 CIDR matching: `(ip & mask) == (prefix & mask)` in hardware (32-bit/128-bit)
- Port range matching: `(port >= low && port <= high)` with 16-bit comparators
- Byte-offset matching: global byte counter + per-offset capture registers
- VXLAN detection: UDP dst port == 4789, then 8-byte VXLAN header, extract 24-bit VNI
- GTP-U detection: UDP dst port == 2152, then 8-byte GTP header, extract 32-bit TEID
- MPLS detection: EtherType 0x8847 (unicast) or 0x8848 (multicast), extract 20-bit label, 3-bit TC, 1-bit BOS
- IGMP detection: IPv4 protocol == 2, extract type byte from IGMP header
- MLD detection: ICMPv6 (next_header 58), types 130-132 (query, report v1, done)
- Multi-port: N independent filter instances sharing same rule set
- Connection tracking: CRC-based hash, open-addressing linear probing, timestamp-based timeout
- Rate limiting: token-bucket per rule (parameterized PPS/BURST, 16-bit tokens, 32-bit refill counter)
- Packet simulation: software reference model evaluates rules without hardware toolchain
- Overlap detection: CIDR prefix containment + port range analysis (not just string equality)
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
- **Phase 7**: Complete — Byte-offset matching, hierarchical state machines, Mermaid import/export, multi-port switch fabric, connection tracking
- **Phase 8**: Complete — IPv6 support, packet simulation, rate limiting, enhanced lint (12 rules), CIDR/port overlap detection
- **Phase 9**: Complete — PCAP analysis, synthesis project generation, advanced test gen (IPv6/rate-limiter/mutation/coverage-driven), rule templates, HTML documentation
- **Phase 10**: Complete — Verification completeness: L3/L4/IPv6/VXLAN/byte-match scoreboard, directed L3/L4 packet construction, byte-match simulation, enhanced formal assertions (IPv6/port-range/rate-limiter/byte-match), conntrack cocotb tests, CI pipeline expansion
- **Phase 11**: Complete — Reachability analysis, PCAP output from simulation (`--pcap-out`), performance benchmarking (`bench`), HTML diff visualization (`diff --html`)
- **Phase 12**: Complete — GTP-U tunnel parsing (gtp_teid), MPLS label stack (mpls_label/mpls_tc/mpls_bos), IGMP/MLD multicast (igmp_type/mld_type)
- **Phase 13**: Complete — Verification framework enhancements: coverage wiring (L3/L4 kwargs, CoverageDirector, XML export), boundary/negative test generation, MCY Verilog mutation testing, mutation kill-rate runner, CI improvements
