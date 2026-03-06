# PacGate — FPGA Layer 2/3/4 Packet Filter Switch

## Vision
PacGate is an FPGA-based packet filtering switch where YAML-defined rules compile into both synthesizable Verilog (the filter hardware) and a cocotb test harness (the validator). The two outputs are generated from the same specification but serve orthogonal purposes: the filter enforces rules in hardware, the harness proves they work correctly in simulation.

## What It Does
1. You define packet filter rules in YAML (match on MAC, IPv4/IPv6, ports, VLAN, QinQ double VLAN, VXLAN VNI, GTP-U TEID, GRE protocol/key, Geneve VNI, MPLS labels, IGMP/MLD, DSCP/ECN, IPv6 TC, TCP flags, ICMP type/code, ICMPv6 type/code, ARP opcode/SPA/TPA, IPv6 hop_limit/flow_label, ip_ttl, IPv4 fragmentation flags, OAM/CFM level+opcode, NSH SPI/SI/next_protocol, PTP message_type/domain/version (IEEE 1588), frame_len_min/max (simulation-only), etc.) with optional rewrite actions (NAT, TTL, MAC, VLAN, VLAN PCP, outer VLAN, DSCP, ECN, IPv6 hop_limit, L4 port rewrite), egress actions (mirror_port, redirect_port), per-rule RSS queue pinning (rss_queue 0-15), and per-rule INT metadata insertion (int_insert). Rules can be organized into sequential match-action stages using the `tables:` YAML key for multi-table pipeline processing
2. The `pacgate` compiler (written in Rust) reads the YAML and generates:
   - **Verilog RTL** — synthesizable hardware description for an FPGA
   - **cocotb test bench** — Python tests that verify the hardware via simulation
   - **SVA assertions** — formal properties for bounded model checking
   - **Property tests** — Hypothesis-based invariant testing
   - **HTML coverage report** — visual coverage analysis
3. Run simulation with Icarus Verilog, Questa/QuestaSim, VCS, or Xcelium + cocotb 2.0 to verify correctness (via `python run_sim.py` or `make`)
4. Synthesize for Xilinx Artix-7 FPGA using Yosys (open-source) or Vivado
5. Run formal verification with SymbiYosys for mathematical proof of correctness
6. Import PCAP captures for real-traffic test stimulus
7. Export to P4_16 PSA programs for software switch / SmartNIC targets (`p4-export` subcommand)
8. Import from P4_16 PSA programs (`p4-import`), Wireshark display filters (`wireshark-import`), or iptables-save dumps (`iptables-import`) — quad input format (YAML + P4 + Wireshark + iptables)
9. Optimize imported/hand-written rule sets with `optimize` subcommand — dead rule removal, deduplication, port/CIDR consolidation, priority normalization
10. Generate a standalone Rust packet filter binary with `--target rust` — compiled match rules, PCAP I/O, per-rule statistics, and optional AF_XDP live capture

## Innovation / Unique Value
PacGate is unique in that no other tool generates both the hardware implementation (Verilog) and the verification environment (cocotb) from a single specification. Commercial tools like Agnisys IDS-Verify generate tests from register specs but assume the RTL already exists. LLM-based approaches generate one or the other non-deterministically. PacGate generates both, ensuring perfect alignment between specification, implementation, and verification.

## Architecture
The generated hardware has a configurable-width streaming interface (`--width 8/64/128/256/512`, default 8-bit byte-at-a-time). A hand-written frame parser (23 states) extracts L2/L3/L4/VXLAN/GTP-U/GRE/Geneve/MPLS/IGMP/MLD/ICMP/ICMPv6/ARP/PTP header fields (including QinQ outer VLAN, IPv6 Traffic Class, TCP flags, hop_limit, flow_label, ip_ttl, IPv4 fragmentation flags, PTP messageType/domain/version), generated per-rule matchers evaluate in parallel (combinational), and a priority encoder selects the first matching rule's action (pass or drop). Rules can optionally be organized into multiple sequential tables (`tables:` YAML key) for multi-stage match-action pipeline processing. An optional RSS (Receive Side Scaling) subsystem (`--rss`) performs Toeplitz hash-based multi-queue dispatch with per-rule queue override support. An optional INT (In-band Network Telemetry) subsystem (`--int`) captures sideband metadata (switch_id, timestamps, hop_latency, queue_id, rule_idx) for network visibility.

```
rules.yaml ──> Compiler (Rust) ──┬──> Verilog RTL (gen/rtl/)
                                 ├──> Rust filter (gen/rust/)
                                 ├──> cocotb tests (Python)
                                 ├──> SVA assertions (formal)
                                 ├──> Property tests (Hypothesis)
                                 ├──> HTML coverage report
                                 └──> PCAP stimulus import
                                        │
             Icarus Verilog + cocotb <──┘
```

**Verilog module hierarchy:**
- `packet_filter_multiport_top` — multi-port wrapper (optional, --ports N)
  - N × `packet_filter_top` instances with independent interfaces
- `packet_filter_axi_top` — AXI-Stream top-level (hand-written)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — generated top-level, wires everything
    - `frame_parser` — hand-written, extracts L2/L3/L4/QinQ/VXLAN/GTP-U/GRE/Geneve/MPLS/IGMP/MLD/ICMP/ICMPv6/ARP/PTP fields + IPv6 TC/hop_limit/flow_label + ip_ttl + TCP flags + IPv4 frag
    - `byte_capture` — generated byte-offset capture module (if byte_match used)
    - `rule_match_N` — generated per stateless rule, combinational field matching
    - `rule_fsm_N` — generated per stateful rule, registered HSM with timeout, variables, guards
    - `decision_logic` — generated priority encoder, first-match wins, outputs rule index
  - `store_forward_fifo` — buffers frames, forwards/discards based on filter decision
  - `rewrite_lut` — generated combinational ROM mapping rule_idx to rewrite operations (if rewrite rules present)
  - `packet_rewrite` — byte substitution engine with RFC 1624 incremental checksum (rtl/packet_rewrite.v)
  - `rule_counters` — per-rule 64-bit packet/byte counters (optional, --counters)
  - `axi_lite_csr` — AXI4-Lite register interface for counter readout
- `conntrack_table` — connection tracking hash table with per-flow counters (optional, --conntrack)
  - Per-entry 64-bit packet/byte counters (`enable_flow_counters: true`)
  - Flow read-back interface for flow export (registered, 1-cycle latency)
- RSS subsystem (optional, --rss)
  - `rss_toeplitz` — Toeplitz hash engine for 5-tuple hashing (rtl/rss_toeplitz.v)
  - `rss_indirection` — 128-entry indirection table with AXI-Lite runtime updates (rtl/rss_indirection.v)
  - `rss_queue_lut` — per-rule queue override LUT (generated from template rss_queue_lut.v.tera)
- INT subsystem (optional, --int)
  - `int_metadata` — sideband metadata capture (switch_id, timestamps, hop_latency, queue_id, rule_idx) (rtl/int_metadata.v)
  - `int_lut` — per-rule INT enable lookup (generated from template int_lut.v.tera)
- `pacgate_opennic_250` — OpenNIC Shell wrapper (optional, --target opennic)
  - `axis_512_to_8` → `packet_filter_axi_top` → `axis_8_to_512`
- `pacgate_corundum_app` — Corundum app block (optional, --target corundum)
  - Same width converter + filter pipeline, with reset inversion + PTP timestamp

## Match Fields
| Layer | Field | Type | Example |
|-------|-------|------|---------|
| L2 | dst_mac | MAC with wildcards | `"00:1a:2b:*:*:*"` |
| L2 | src_mac | MAC with wildcards | `"ff:ff:ff:ff:ff:ff"` |
| L2 | ethertype | 16-bit hex | `"0x0800"` |
| L2 | vlan_id | 12-bit (0-4095) | `100` |
| L2 | vlan_pcp | 3-bit (0-7) | `5` |
| L2 | outer_vlan_id | 12-bit (0-4095) | `100` |
| L2 | outer_vlan_pcp | 3-bit (0-7) | `5` |
| L3 | src_ip | IPv4 / CIDR | `"10.0.0.0/8"` |
| L3 | dst_ip | IPv4 / CIDR | `"192.168.1.1"` |
| L3 | ip_protocol | 8-bit | `6` (TCP) |
| L4 | src_port | Exact or range | `80` or `{range: [1024, 65535]}` |
| L4 | dst_port | Exact or range | `443` |
| Tunnel | vxlan_vni | 24-bit (0-16M) | `1000` |
| Tunnel | geneve_vni | 24-bit (0-16M) | `2000` |
| L3 | src_ipv6 | IPv6 / CIDR | `"2001:db8::/32"` |
| L3 | dst_ipv6 | IPv6 / CIDR | `"fe80::/10"` |
| L3 | ipv6_next_header | 8-bit | `58` (ICMPv6) |
| Tunnel | gtp_teid | 32-bit (0-4G) | `12345` |
| L2.5 | mpls_label | 20-bit (0-1M) | `1000` |
| L2.5 | mpls_tc | 3-bit (0-7) | `5` |
| L2.5 | mpls_bos | 1-bit (0-1) | `1` |
| L3 | igmp_type | 8-bit hex | `"0x11"` (query) |
| L3 | mld_type | 8-bit | `130` (query) |
| L3 | ip_dscp | 6-bit (0-63) | `46` (EF) |
| L3 | ip_ecn | 2-bit (0-3) | `1` (ECT1) |
| L3 | ipv6_dscp | 6-bit (0-63) | `46` (EF) |
| L3 | ipv6_ecn | 2-bit (0-3) | `1` (ECT1) |
| L4 | tcp_flags | 8-bit with mask | `0x02` (SYN) |
| L4 | tcp_flags_mask | 8-bit | `0x3F` |
| L3 | icmp_type | 8-bit (0-255) | `8` (echo request) |
| L3 | icmp_code | 8-bit (0-255) | `0` |
| L3 | icmpv6_type | 8-bit (0-255) | `128` (echo request) |
| L3 | icmpv6_code | 8-bit (0-255) | `0` |
| L2 | arp_opcode | 1-2 (req/reply) | `1` (request) |
| L3 | arp_spa | IPv4 address | `"192.168.1.1"` |
| L3 | arp_tpa | IPv4 address | `"10.0.0.0"` |
| L3 | ipv6_hop_limit | 8-bit (0-255) | `64` |
| L3 | ipv6_flow_label | 20-bit (0-0xFFFFF) | `12345` |
| L3 | ip_ttl | 8-bit (0-255) | `64` |
| L3 | ip_dont_fragment | 1-bit (0-1) | `1` |
| L3 | ip_more_fragments | 1-bit (0-1) | `0` |
| L3 | ip_frag_offset | 13-bit (0-8191) | `0` |
| PTP | ptp_message_type | 4-bit (0-15) | `0` (Sync) |
| PTP | ptp_domain | 8-bit (0-255) | `0` |
| PTP | ptp_version | 4-bit (0-15) | `2` (PTPv2) |
| RSS | rss_queue | 4-bit (0-15) | `3` |
| INT | int_insert | bool | `true` |
| Raw | byte_match | Offset+value+mask | `{offset: 14, value: "45", mask: "F0"}` |
| Sim | frame_len_min | 16-bit (sim-only) | `64` |
| Sim | frame_len_max | 16-bit (sim-only) | `1518` |

## Verification Framework
UVM-inspired Python verification environment with:
- **PacketFactory** — generates directed, random, boundary, and corner-case Ethernet frames (with L3/L4/IPv6 headers, 20+ protocol-specific methods including GRE, OAM, NSH, ARP, ICMP, ICMPv6, QinQ, Geneve, TCP-flags, PTP, RSS queue-tagged, INT-marked packets)
- **PacketDriver** (BFM) — drives frames into the DUT byte-by-byte
- **DecisionMonitor** — captures pass/drop decisions from the DUT
- **Scoreboard** — Python reference model with full L2/L3/L4/IPv6/QinQ/VXLAN/GTP-U/Geneve/MPLS/IGMP/MLD/DSCP/ECN/IPv6-TC/TCP-flags/ICMP/ICMPv6/ARP/IPv6-ext/IPv4-frag/ip_ttl/byte-match/PTP matching + Toeplitz hash RSS queue verification + INT metadata prediction, checks against DUT
- **Coverage** — functional coverage with cover points, bins, cross coverage, and XML export
- **Properties** — Hypothesis-based property testing (determinism, priority, conservation, independence, L3/L4 determinism, 12 protocol-specific strategies: GTP-U/MPLS/IGMP/MLD/GRE/OAM/NSH/ARP/ICMP/ICMPv6/QinQ/TCP-flags)
- **Conntrack Tests** — 5 cocotb tests for connection tracking (new flow, return traffic, timeout, collision, overflow)
- Enterprise example: 7 rules, 13 tests, 500 random packets with 0 scoreboard mismatches

## CLI Commands
- `pacgate compile rules.yaml` — Generate Verilog + cocotb tests (with rule summary table)
- `pacgate compile rules.yaml --axi` — Include AXI-Stream wrapper + FIFO + AXI tests
- `pacgate compile rules.yaml --counters` — Include per-rule counters + AXI-Lite CSR
- `pacgate compile rules.yaml --ports 4` — Generate multi-port switch fabric (4 parallel filters)
- `pacgate compile rules.yaml --conntrack` — Include connection tracking hash table RTL
- `pacgate compile rules.yaml --rate-limit` — Include rate limiter RTL for rules with rate_limit
- `pacgate compile rules.yaml --width 64` — Parameterized data path width (8/64/128/256/512 bit)
- `pacgate compile rules.yaml --rss` — Include RSS multi-queue dispatch (Toeplitz hash + indirection table)
- `pacgate compile rules.yaml --rss --rss-queues 8` — RSS with 8 queues (default 4, max 16)
- `pacgate compile rules.yaml --int` — Include INT sideband metadata output
- `pacgate compile rules.yaml --int --int-switch-id 1` — INT with custom switch ID
- `pacgate compile rules.yaml --target rust` — Generate standalone Rust packet filter binary (compiled match rules, PCAP I/O, per-rule statistics, AF_XDP skeleton)
- `pacgate validate rules.yaml` — Validate YAML only
- `pacgate init` — Create a well-commented starter rules file
- `pacgate estimate rules.yaml` — FPGA resource estimation (LUTs/FFs) + timing analysis
- `pacgate diff old.yaml new.yaml` — Compare two rule sets (added/removed/modified)
- `pacgate graph rules.yaml` — DOT graph output for Graphviz visualization
- `pacgate stats rules.yaml` — Rule set analytics (field usage, priority spacing, action balance)
- `pacgate formal rules.yaml` — Generate SVA assertions + SymbiYosys task files
- `pacgate lint rules.yaml` — Best-practice analysis (security, performance, maintainability)
- `pacgate report rules.yaml` — Generate HTML coverage report
- `pacgate pcap capture.pcap` — Import PCAP for cocotb test stimulus
- `pacgate from-mermaid fsm.md --name rule --priority 100` — Import Mermaid stateDiagram to YAML
- `pacgate to-mermaid rules.yaml` — Export YAML FSM rules to Mermaid stateDiagram-v2
- `pacgate simulate rules.yaml --packet "ethertype=0x0800,dst_port=80"` — Software dry-run simulation
- `pacgate simulate rules.yaml --packet "..." --stateful` — Stateful simulation (rate-limit + conntrack)
- `pacgate simulate rules.yaml --packet "..." --pcap-out trace.pcap` — Write simulation results to Wireshark-compatible PCAP
- `pacgate pcap-analyze capture.pcap` — Analyze PCAP traffic, suggest rules (whitelist/blacklist/auto)
- `pacgate pcap-analyze capture.pcap --output-yaml rules.yaml` — Auto-generate rules from traffic
- `pacgate synth rules.yaml --target yosys --part artix7` — Generate Yosys synthesis project
- `pacgate synth rules.yaml --target vivado --part xc7a35t` — Generate Vivado TCL project
- `pacgate mutate rules.yaml` — Generate mutation test variants (flip action, remove rule, swap priority)
- `pacgate mutate rules.yaml --run` — Generate mutants AND run kill-rate analysis (compile + lint each)
- `pacgate mcy rules.yaml` — Generate MCY (Mutation Cover with Yosys) config for Verilog-level mutation testing
- `pacgate mcy rules.yaml --run` — Generate MCY config AND run MCY (requires mcy binary)
- `pacgate template list` — List built-in rule templates (7 templates across security/access/IoT/etc.)
- `pacgate template show <name>` — Show template details and variables
- `pacgate template apply <name> --set key=value -o rules.yaml` — Apply template with variable substitution
- `pacgate doc rules.yaml` — Generate styled HTML rule documentation datasheet
- `pacgate bench rules.yaml` — Benchmark compile time, simulation throughput (pkts/sec), and LUT/FF scaling curves across 10-500 synthetic rule sets; ASCII bar chart + JSON output
- `pacgate diff old.yaml new.yaml --html report.html` — Generate styled HTML diff report with color-coded additions/removals/modifications and side-by-side comparison
- `pacgate reachability rules.yaml` — Analyze rule reachability (shadowed, unreachable, redundant rules)
- `pacgate scenario validate *.json` — Validate scenario JSON files (v1/v2)
- `pacgate scenario import --in-dir dir/ --store store.json` — Import scenarios to store
- `pacgate scenario export --store store.json --out-dir dir/` — Export scenarios from store
- `pacgate regress --scenario file.json --count 1000` — Run packet regression (direct simulate, ~600K pps)
- `pacgate topology --scenario file.json` — Run topology simulation (RMAC/L3 switch, subnet gating)
- `pacgate p4-export rules.yaml` — Export rules to P4_16 PSA program (software switch / SmartNIC targets, with P4 ActionSelector for RSS)
- `pacgate p4-export rules.yaml --json` — P4 export with JSON metadata
- `pacgate p4-import filter.p4` — Import P4_16 PSA program to YAML rules
- `pacgate wireshark-import --filter "tcp.port == 80"` — Import Wireshark display filter to YAML rules
- `pacgate iptables-import --file iptables.save` — Import iptables-save dump to YAML rules
- `pacgate iptables-import --file iptables.save --json` — iptables import with JSON summary
- `pacgate optimize rules.yaml` — Optimize rule set (dead rules, duplicates, port/CIDR consolidation)
- `pacgate optimize rules.yaml --json` — JSON optimization summary
- `pacgate pcap-gen rules.yaml` — Generate synthetic PCAP traffic from rules
- `pacgate pcap-gen rules.yaml --count 1000 --output traffic.pcap` — 1000 packets to file
- `pacgate pcap-gen rules.yaml --seed 42 --json` — Deterministic generation with JSON summary
- All commands except `init`, `graph`, `report` support `--json` for machine-readable output

## Examples
53 production-quality YAML examples covering real-world deployments:
- Enterprise campus, data center multi-tenant, blacklist mode
- Industrial OT boundary (EtherCAT, PROFINET, PTP, GOOSE)
- Automotive Ethernet gateway (AVB/TSN, ADAS)
- 5G fronthaul (eCPRI, PTP, Sync-E)
- Campus access control, IoT edge gateway
- L3/L4 firewall (SSH, HTTP/S, DNS, ICMP, port ranges)
- VXLAN datacenter (multi-tenant VNI isolation)
- Stateful: SYN flood detection, ARP spoofing detection
- Byte-offset matching (IPv4 version nibble, TCP SYN flag)
- Hierarchical state machine (TCP flow tracker with nested burst detection)
- IPv6 firewall (ICMPv6, CIDR prefix, link-local blocking)
- Rate-limited rules (HTTP/DNS/SSH token-bucket limiting)
- GTP-U 5G mobile core (TEID-based tunnel filtering)
- MPLS provider network (label stack matching, TC classification)
- Multicast filtering (IGMP/MLD type-based control)
- Dynamic firewall (runtime-updateable flow tables via AXI-Lite)
- Packet rewrite actions (NAT, TTL management, MAC/VLAN rewriting, QoS remarking, L4 port rewrite)
- QoS classification (DSCP/ECN matching with DiffServ class filtering)
- TCP flags + ICMP (SYN/ACK/Xmas detection, ICMP echo/reply, IPv6 EF class)
- ARP security (opcode filtering, SPA/TPA validation, gratuitous ARP detection)
- ICMPv6 firewall (NDP permit, echo request/reply, unreachable, MLD multicast)
- QinQ double VLAN (802.1ad carrier network, outer/inner VLAN matching)
- IPv4 fragmentation detection (DF/MF flags, fragment offset attack detection)
- L4 port rewrite (source/destination port NAT with L4 checksum update)
- Geneve datacenter overlay (RFC 8926, UDP:6081, 24-bit VNI matching)
- TTL security (ip_ttl matching for GTSM/TTL-based attack mitigation)
- IPv6 routing (dec_hop_limit, set_hop_limit, set_ecn rewrite actions)
- QoS rewrite (set_vlan_pcp, set_outer_vlan_id for VLAN priority/outer tag rewriting)
- Wide data path (64/128/256/512/1024/2048-bit AXI-Stream bus-width compatibility; V1 uses width converters to 8-bit core parser at ~2 Gbps; native wide parser planned for true 100G+)
- Multi-table pipeline (sequential match-action stages with table chaining)
- P4 export target (P4_16 PSA program generation for SmartNIC/software switches)
- PTP boundary clock (IEEE 1588 domain isolation, Sync/Delay_Req/Follow_Up/Delay_Resp/Announce)
- PTP 5G fronthaul (multi-domain PTP + eCPRI, L2/L4 dual transport)
- RSS datacenter (multi-queue dispatch with per-rule queue pinning)
- RSS NIC offload (Toeplitz hash-based queue distribution for NIC offload)
- INT datacenter (in-band telemetry with sideband metadata capture)
- pcap-gen demo (synthetic traffic generation from rules)
- rust_filter_demo (Rust code generation backend with PCAP I/O and per-rule statistics)

## Quality
- 1154 Rust tests total (726 unit + 428 integration; model parsing, validation, CIDR/port overlap, IPv4/IPv6, PCAP, byte-match, HSM, Mermaid, simulation incl. byte-match/rate-limit/conntrack, PCAP analysis, synthesis, mutation (41 types), templates, benchmarking, reachability (protocol fields), GTP-U, MPLS, IGMP/MLD, DSCP/ECN, IPv6 TC, TCP flags, ICMP type/code, ICMPv6, ARP, IPv6 extensions, QinQ, IPv4 fragmentation, L4 port rewrite, GRE, conntrack state, mirror/redirect, flow counters, OAM/CFM, NSH/SFC, Geneve VNI, ip_ttl, frame_len, IPv6 rewrite, VLAN PCP/outer VLAN rewrite, MCY config generation, rewrite action parsing/validation, cocotb 2.0 runner generation, parameterized width, P4 export, multi-table pipeline, PTP matching, RSS queue pinning/Toeplitz hash/indirection table, INT metadata, pcap-gen traffic generation, P4 import, Wireshark display filter import, iptables-save import, Rust code generation backend)
- 90 Python scoreboard unit tests (IPv4 CIDR, IPv6 CIDR, port matching, VXLAN VNI, byte-match, multi-field L3/L4, GTP-U TEID, MPLS label/TC/BOS, IGMP/MLD type, IPv6 TC, TCP flags mask-aware, ICMP type/code, ICMPv6 type/code, ARP opcode/SPA/TPA, IPv6 hop_limit/flow_label, QinQ outer VLAN, IPv4 fragmentation, GRE protocol/key, conntrack state, OAM level/opcode, NSH SPI/SI, Geneve VNI, ip_ttl, PTP messageType/domain/version, RSS Toeplitz hash queue verification, INT metadata prediction, protocol coverage sampling, protocol determinism checks)
- 13+ cocotb simulation tests (directed with L3/L4 headers + 500-packet random + corner cases)
- 5 conntrack cocotb tests (new flow, return traffic, timeout, hash collision, table overflow)
- 85%+ functional coverage with varied frame sizes and VLAN-tagged traffic
- Rule overlap and shadow detection with CIDR containment and port range analysis
- Best-practice linting with 57 lint rules (LINT001-057, including GTP/MPLS/IGMP/MLD/DSCP/ECN/IPv6-TC/TCP-flags/ICMP/ICMPv6/ARP/IPv6-ext/QinQ/IPv4-frag/L4-port-rewrite/GRE/conntrack-state/mirror/redirect/flow-counters/OAM/NSH/Geneve/ip_ttl/frame_len/IPv6-rewrite/VLAN-rewrite/PTP/RSS/INT prerequisite checks, dynamic mode, rewrite actions)
- Mutation testing: 41 YAML mutation strategies + MCY Verilog-level mutation config generation
- Mutation kill-rate runner: compile + lint each mutant, report kill/survived/error rates
- Coverage-directed test generation with CoverageDirector wired into random test loop
- Coverage XML export for CI artifact tracking
- Boundary test generation: auto-derived CIDR boundary and port boundary test cases
- Formally-derived negative tests: guaranteed no-match frames from unused ethertypes
- Property-based testing with Hypothesis for invariant verification (9 property checks + 12 protocol strategies: GTP-U/MPLS/IGMP/MLD/GRE/OAM/NSH/ARP/ICMP/ICMPv6/QinQ/TCP-flags)
- SVA formal assertions with IPv6 CIDR, port range, rate limiter, byte-match, GTP-U, MPLS, IGMP/MLD, DSCP/ECN, IPv6 TC, TCP flags, ICMP, ICMPv6, ARP, IPv6 extensions, QinQ, IPv4 fragmentation, L4 port rewrite, GRE, conntrack state, OAM, NSH, Geneve, PTP, RSS, INT correctness checks
- Shadow/overlap detection covers all protocol fields (L2/L3/L4/IPv6/QinQ/VXLAN/GTP-U/Geneve/MPLS/IGMP/MLD/DSCP/ECN/IPv6-TC/TCP-flags/ICMP/ICMPv6/ARP/IPv6-ext/IPv4-frag/ip_ttl/PTP/RSS/INT)
- Analysis tools (stats/graph/diff/estimate/doc) fully cover all protocol fields

## Development Status
- **Phase 1** (complete): Single stateless rule (allow ARP), frame parser, 7 cocotb tests PASS
- **Phase 2** (complete): 7-rule enterprise, MAC wildcards, VLAN matching, verification framework, 13 tests PASS, 85% coverage
- **Phase 3** (complete): Stateful FSM rules with timeout counters, sequence detection
- **Phase 4** (complete): AXI-Stream wrapper, store-and-forward FIFO, synthesis, formal verification, property testing
- **Phase 5** (complete): 12 examples, lint command, comprehensive docs, proprietary license
- **Phase 6** (complete): L3/L4 matching, per-rule counters, PCAP import, HTML reports, VXLAN tunnel parsing
- **Phase 7** (complete): Byte-offset matching, hierarchical state machines, Mermaid import/export, multi-port switch fabric, connection tracking
- **Phase 8** (complete): IPv6 support, packet simulation, rate limiting, enhanced lint (12 rules), CIDR/port overlap detection
- **Phase 9** (complete): PCAP analysis + rule suggestions, Yosys/Vivado synthesis projects, advanced test generation (IPv6 cocotb, rate-limiter TB, mutation testing, coverage-driven), rule templates (7 built-in), HTML documentation
- **Phase 10** (complete): Verification completeness — L3/L4/IPv6/VXLAN/byte-match scoreboard, directed test L3/L4 packet construction, byte-match simulation, enhanced formal assertions, conntrack cocotb tests, CI pipeline expansion
- **Phase 11** (complete): Advanced analysis — reachability analysis, PCAP output from simulation, performance benchmarking, HTML diff visualization
- **Phase 12** (complete): Protocol extensions — GTP-U tunnel parsing (gtp_teid), MPLS label stack (mpls_label/mpls_tc/mpls_bos), IGMP/MLD multicast (igmp_type/mld_type)
- **Phase 13** (complete): Verification framework enhancements — Coverage wiring (L3/L4 kwargs, CoverageDirector, XML export), boundary/negative test generation, MCY Verilog mutation testing, mutation kill-rate runner, CI improvements (hypothesis, JUnit, property tests)
- **Phase 14** (complete): Protocol verification completeness — GTP-U/MPLS/IGMP/MLD in Python scoreboard + packet factory + test templates (directed+random) + SVA formal assertions + shadow/overlap detection + all analysis tools (stats/graph/diff/estimate/doc); fixed diff_rules() L3/L4/IPv6 field comparison bug
- **Phase 15** (complete): Verification depth & tool completeness — reachability with protocol fields + stateful rule tracking, 11 mutation types, 5 protocol coverage coverpoints, fixed conntrack assertions, 4 Hypothesis protocol strategies, 9 wired property checks, LINT013-015 protocol prereqs, CI expanded to 8 simulate examples
- **Phase 16** (complete): Simulator completeness & verification depth — rate-limit simulation (token-bucket in software), conntrack simulation (5-tuple hash + reverse lookup), --stateful CLI flag, strengthened SVA assertions (rate-limit enforcement, GTP/MPLS/IGMP/MLD prerequisite + bounds), protocol property tests wired into generated test files, byte_match in HTML docs, CI expansion (conntrack simulate, formal generate, rate-limit simulate)
- **Phase 17** (complete): Runtime-updateable flow tables — `--dynamic` flag replaces static per-rule matchers with register-based `flow_table.v` (AXI-Lite writable, staging+commit atomicity), YAML rules as initial values, `--dynamic-entries N` (1-256), cocotb tests (6 AXI-Lite CRUD tests), estimate/lint/formal support (LINT016-017), 22 examples, 242 unit + 165 integration = 407 tests
- **Phase 18** (complete): Packet rewrite actions — `rewrite:` field with 7 operations (set_dst_mac, set_src_mac, set_vlan_id, set_ttl, dec_ttl, set_src_ip, set_dst_ip) for NAT, TTL management, MAC rewriting, VLAN modification; RewriteAction data model + YAML validation, frame parser ip_ttl/ip_checksum extraction, rewrite_lut.v (generated ROM), packet_rewrite.v (RTL byte substitution with RFC 1624 checksum), templatized AXI top, simulator rewrite info, estimate/lint (LINT018-019)/formal/diff support, 23 examples, 250 unit + 181 integration = 431 tests
- **Phase 19** (complete): Platform integration targets — `--target opennic` and `--target corundum` generate drop-in NIC wrappers with 512↔8-bit width converters, OpenNIC tuser metadata passthrough, Corundum PTP timestamp + reset inversion, estimate/lint (LINT020-021)/synth support, 25 examples, 256 unit + 195 integration = 451 tests
- **Phase 20** (complete): cocotb 2.0 migration — pin cocotb>=2.0.0 + cocotb-tools, fix `.value.integer` → `int(.value)`, generate `run_sim.py` runner scripts (cocotb_tools.runner API) alongside Makefiles for all test modes (main, AXI, conntrack, rate limiter, dynamic), platform target width converter inclusion in runners, CI updated to use runner, 260 unit + 204 integration = 464 tests
- **Phase 21** (complete): DSCP/ECN QoS matching + DSCP rewrite — ip_dscp (6-bit, 0-63) and ip_ecn (2-bit, 0-3) match fields from IPv4 TOS byte, set_dscp rewrite action (QoS remarking) with RFC 1624 incremental checksum, frame parser TOS extraction, qos_classification.yaml example (7 rules: EF/AF41/AF31/CS6/BE+ECT1/CS1→BE remark/ARP), LINT022 (DSCP/ECN without IPv4), SVA DSCP/ECN bounds assertions, Python scoreboard matching, 13 mutation types, all analysis tools updated, 275 unit + 216 integration = 491 tests
- **Phase 22** (complete): IPv6 Traffic Class + TCP Flags + ICMP Type/Code — 6 new match fields (ipv6_dscp 6-bit, ipv6_ecn 2-bit from IPv6 TC byte; tcp_flags 8-bit with tcp_flags_mask for mask-aware matching; icmp_type/icmp_code 0-255), frame parser IPv6 TC byte extraction + TCP flags at byte offset 13 + new S_ICMP_HDR state for ICMP type/code, LINT023-025 (IPv6 TC without IPv6 ethertype, TCP flags without TCP protocol, ICMP without ICMP protocol), SVA assertions (IPv6 TC bounds, TCP flags prerequisite, ICMP covers), 16 mutation types (3 new: remove_tcp_flags, remove_icmp_type, remove_ipv6_dscp), Python scoreboard IPv6 TC/TCP flags (mask-aware)/ICMP matching, tcp_flags_icmp.yaml example (7 rules: SYN/established/Xmas/ICMP echo/reply/IPv6 EF/ARP), 298 unit + 230 integration = 528 tests
- **Phase 23** (complete): ARP + ICMPv6 + IPv6 Extension Fields — 7 new match fields (icmpv6_type/icmpv6_code 0-255 with MLD backward compatibility; arp_opcode 1-2, arp_spa/arp_tpa IPv4 addresses; ipv6_hop_limit 0-255, ipv6_flow_label 20-bit), frame parser S_ICMPV6_HDR (state 15) + S_ARP_HDR (state 16) + IPv6 hop_limit/flow_label extraction, LINT026-028 (ICMPv6/ARP/IPv6-ext prerequisite checks), SVA assertions, 19 mutation types (3 new: remove_icmpv6_type, remove_arp_opcode, remove_ipv6_hop_limit), Python scoreboard ICMPv6/ARP/IPv6-ext matching, arp_security.yaml (5 rules) + icmpv6_firewall.yaml (8 rules) examples, 324 unit + 244 integration = 568 tests
- **Phase 24** (complete): QinQ Double VLAN + IPv4 Fragmentation + L4 Port Rewrite — 5 new match fields (outer_vlan_id 12-bit, outer_vlan_pcp 3-bit for 802.1ad QinQ; ip_dont_fragment 1-bit, ip_more_fragments 1-bit, ip_frag_offset 13-bit for IPv4 fragmentation), 2 new rewrite actions (set_src_port, set_dst_port with RFC 1624 L4 checksum update), frame parser S_OUTER_VLAN state + frame_byte_cnt + frag field extraction, LINT029-032 (QinQ/frag/port-rewrite prerequisite checks), SVA assertions, 22 mutation types (3 new), Python scoreboard QinQ/frag matching, 3 new example YAMLs (QinQ carrier, frag detection, port NAT), 348 unit + 267 integration = 615 tests
- **Phase 25.4** (complete): Per-Flow Counters + Flow Export — enable_flow_counters on ConntrackConfig for per-flow packet/byte counting, conntrack_table.v per-entry 64-bit pkt/byte counters (increment on lookup HIT + INSERT, init on new entry) with registered flow read-back interface (1-cycle latency), has_flow_counters flag in verilog_gen.rs GlobalProtocolFlags, conditional flow counter ports in AXI/OpenNIC/Corundum templates, conntrack_table instantiation in AXI top when enabled, SVA cover properties for flow counter read interface, Mutation 27 (remove_flow_counters), diff_rules() conntrack config change detection, flow_counters.yaml example, 414 unit + 305 integration = 719 tests
- **Phase 25.5** (complete): OAM/CFM (IEEE 802.1ag) support — oam_level (3-bit MD level, 0-7) + oam_opcode (8-bit CFM OpCode) matching on EtherType 0x8902, frame parser S_OAM_HDR state, LINT038 (OAM without ethertype 0x8902), SVA assertions + cover properties, mutation type 28 (remove_oam_level), oam_monitoring.yaml example (5 rules), 426 unit + 317 integration = 743 tests
- **Phase 25.6** (complete): NSH/SFC (RFC 8300) support — nsh_spi (24-bit Service Path Identifier) + nsh_si (8-bit Service Index) + nsh_next_protocol (inner protocol type) matching on EtherType 0x894F, frame parser S_NSH_HDR state (8-byte header parse), LINT039 (NSH without ethertype 0x894F), SVA assertions + cover properties, mutation type 29 (remove_nsh_spi), nsh_sfc.yaml example (5 rules), 439 unit + 327 integration = 766 tests
- **Phase 26** (complete): Geneve tunnel + TTL match + IPv6 rewrite + cocotb/Hypothesis completeness + VLAN rewrite — 6 sub-phases: (26.1) Geneve VNI matching (RFC 8926, UDP:6081, 24-bit VNI) with S_GENEVE_HDR parser state, geneve_datacenter.yaml example; (26.2) ip_ttl match field (0-255) + frame_len_min/max simulation-only fields, ttl_security.yaml example; (26.3) IPv6 rewrite actions (dec_hop_limit, set_hop_limit, set_ecn) with packet_rewrite.v extensions, ipv6_routing.yaml example; (26.4) cocotb test completeness with 14 PacketFactory methods and 13 protocol branches in test_harness; (26.5) Hypothesis property test completeness with 8 new strategies (GRE/OAM/NSH/ARP/ICMP/ICMPv6/QinQ/TCP flags) and 9 conditional blocks; (26.6) VLAN PCP/outer VLAN rewrite (set_vlan_pcp, set_outer_vlan_id), qos_rewrite.yaml example; LINT040-046 (7 new lint rules), mutation types 30-33, rewrite flag bits 10-14, 479 unit + 327 integration = 806 Rust tests + 67 Python tests
- **Phase 27** (complete): Parameterized data path width + P4 export + multi-table pipeline — 3 sub-features: (27.1) `--width` flag (8/64/128/256/512/1024/2048 bit) generates AXI-Stream width converters for NIC bus-width compatibility (V1 throughput ~2 Gbps via 8-bit core parser; native wide parser planned); (27.2) `p4-export` subcommand generates P4_16 PSA (Portable Switch Architecture) programs from YAML rules for software switch and SmartNIC targets (BMv2, Tofino, DPDK); (27.3) `tables:` YAML key enables multi-table pipeline with sequential match-action stages — each table is an independent match-action unit, packets traverse tables in order with metadata passing between stages. 3 new YAML examples, 518 unit + 378 integration = 896 Rust tests + 73 Python tests
- **Phase 28** (complete): IEEE 1588 PTP hardware timestamping — 3 new match fields (ptp_message_type 4-bit, ptp_domain 8-bit, ptp_version 4-bit) with dual L2 (EtherType 0x88F7) and L4 (UDP 319/320) detection, S_PTP_HDR parser state (5'd22), optional ptp_clock.v (64-bit free-running clock with SOF/EOF timestamp latching, `--ptp` flag), Python scoreboard PTP matching + PacketFactory.ptp(), SVA assertions, LINT051-052, mutations 36-37, P4 PTP header+parser, ptp_boundary_clock.yaml + ptp_5g_fronthaul.yaml examples, 50 lint rules, 37 mutation types, 47 examples, 79 Python tests, 518 unit + 378 integration = 896 Rust tests
- **Phase 29** (complete): RSS / Multi-queue Dispatch — per-rule `rss_queue` field (0-15) for queue pinning, `--rss` and `--rss-queues N` CLI flags, Toeplitz hash engine (rss_toeplitz.v) for 5-tuple hashing, 128-entry indirection table (rss_indirection.v) with AXI-Lite runtime updates, per-rule queue override LUT (rss_queue_lut.v.tera), Python scoreboard Toeplitz hash implementation for queue verification, P4 ActionSelector for hash-based queue dispatch, LINT053-055 (RSS prerequisite checks), mutations 38-39, rss_datacenter.yaml + rss_nic_offload.yaml examples, 53 lint rules, 39 mutation types, 49 examples, 85 Python tests, 914 Rust tests
- **Phase 30** (complete): INT (In-band Network Telemetry) + synthetic traffic generation — per-rule `int_insert` field (bool) for INT metadata insertion, `--int` and `--int-switch-id N` CLI flags, int_metadata.v RTL module (sideband metadata capture: switch_id, ingress/egress timestamps, hop_latency, queue_id, rule_idx), int_lut.v.tera template, `pcap-gen` subcommand for protocol-aware synthetic PCAP traffic generation from YAML rules (src/pcap_gen.rs, ~720 LOC) with --count/--seed/--json/--output flags, Python scoreboard predict_int() for INT verification, LINT056-057 (INT prerequisite checks), mutations 40-41, int_datacenter.yaml + pcap_gen_demo.yaml examples, 57 lint rules, 41 mutation types, 51 examples, 90 Python tests, 936 Rust tests
- **Phase 31** (complete): P4 Import (Bidirectional P4 Bridge) — `p4-import` subcommand parses P4_16 PSA programs into PacGate YAML rules, completing the bidirectional P4 bridge (YAML↔P4). Line-by-line state machine parser extracts table keys, const entries, rewrite actions, and extern declarations. Reverse mapping for all 55+ P4 match fields back to PacGate model. Rewrite action parsing (15 operations), extern detection (Register/Meter/ActionSelector warnings), round-trip validation (YAML→P4→YAML equivalence comparison), clean YAML output (null-stripped), JSON summary mode. 2 P4 example files (simple_firewall.p4, datacenter_filter.p4). src/p4_import.rs (~750 LOC), 37 CLI subcommands, 602 unit + 389 integration = 991 Rust tests + 90 Python tests
- **Phase 32** (complete): Wireshark Display Filter Import — `wireshark-import` subcommand converts Wireshark display filter syntax (`tcp.port == 80 && ip.src == 10.0.0.0/8`) into PacGate YAML rules. Tokenizer + recursive descent parser with ~45 field mappings, protocol inference, bidirectional port expansion (tcp.port/udp.port), TCP flag bit accumulation, AND/OR/NOT logic handling. `--filter`/`--filter-file`/`--json`/`--default-action`/`--name` flags. 2 Wireshark filter examples. src/wireshark_import.rs (~700 LOC), 38 CLI subcommands, 638 unit + 399 integration = 1037 Rust tests + 90 Python tests
- **Phase 33** (complete): iptables-save Import — `iptables-import` subcommand parses iptables-save output into PacGate YAML rules, completing the quad input format (YAML + P4 + Wireshark + iptables). Chain-aware rule extraction with protocol/address/port/interface/state/ICMP mapping, LOG/REJECT/MARK target support, `--file`/`--chain`/`--table`/`--json`/`--default-action`/`--name` flags. src/iptables_import.rs, 39 CLI subcommands, 1095 Rust tests + 90 Python tests
- **Phase 34** (complete): Rule Set Optimizer — `optimize` subcommand performs 5 semantics-preserving optimization passes on rule sets: OPT001 dead rule removal (shadow-based), OPT002 duplicate merging (structural equality), OPT003 adjacent port consolidation, OPT004 adjacent CIDR consolidation, OPT005 priority renumbering. Pipeline-aware (per-stage), stateful rules preserved, `--json`/`-o`/`--apply` flags. src/optimize.rs (~500 LOC), 40 CLI subcommands, 1127 Rust tests + 90 Python tests
- **Phase 35** (complete): Rust Code Generation Backend — `--target rust` generates a standalone Rust packet filter binary with compiled match rules, PCAP I/O, per-rule statistics, stdin/stdout pipe mode, and AF_XDP skeleton for live capture. Protocol-conditional code generation produces ~300-900 LOC output depending on rule set complexity. 17 unit + 10 integration tests; 726 unit + 428 integration = 1154 Rust tests + 90 Python tests

## Documentation
- `README.md` — Project showcase and quick start
- `docs/user-guide/USERS_GUIDE.md` — Comprehensive user guide with 11+ examples
- `docs/verification/TEST_GUIDE.md` — Test and verification guide
- `docs/WORKSHOPS.md` — 8 hands-on workshops (beginner to advanced)
- `docs/WHY_PACGATE.md` — Value proposition for skeptics and decision-makers
- `docs/management/SLIDESHOW.md` — 13-slide management presentation
- `docs/RESEARCH.md` — Verification framework research report
- `docs/README.md` — Full documentation index
