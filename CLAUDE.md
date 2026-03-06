# PacGate — Layer 2/3/4 Packet Filter Compiler (FPGA + Software)

## Feature Summary
- YAML-defined packet filter rules compile to synthesizable Verilog + cocotb test harness, **or** a standalone Rust packet filter binary (`--target rust`)
- **Single-spec, multi-output**: same YAML generates hardware (Verilog), verification (cocotb), P4, or software (Rust)
- **L2 matching**: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp (with MAC wildcards)
- **L3 matching**: src_ip, dst_ip (CIDR prefix), ip_protocol
- **L4 matching**: src_port, dst_port (exact or range)
- **VXLAN tunnel**: vxlan_vni matching (24-bit VNI after UDP:4789 detection)
- **GTP-U tunnel**: gtp_teid matching (32-bit TEID after UDP:2152 detection)
- **MPLS label stack**: mpls_label (20-bit), mpls_tc (3-bit), mpls_bos (1-bit bottom-of-stack)
- **IGMP/MLD multicast**: igmp_type (IPv4 protocol 2), mld_type (ICMPv6 types 130-132)
- **QoS matching**: ip_dscp (6-bit DSCP, 0-63), ip_ecn (2-bit ECN, 0-3) from IPv4 TOS byte; ipv6_dscp/ipv6_ecn from IPv6 Traffic Class
- **TCP flags matching**: tcp_flags (8-bit) with tcp_flags_mask for flexible SYN/ACK/FIN/RST/Xmas detection
- **ICMP type/code**: icmp_type (0-255), icmp_code (0-255) for IPv4 ICMP classification
- **ICMPv6 type/code**: icmpv6_type (0-255), icmpv6_code (0-255) for IPv6 ICMPv6 classification (NDP, echo, unreachable)
- **ARP matching**: arp_opcode (1=request, 2=reply), arp_spa/arp_tpa (sender/target protocol address) for ARP security
- **IPv6 extensions**: ipv6_hop_limit (0-255), ipv6_flow_label (20-bit) for IPv6 TTL and flow classification
- **QinQ (802.1ad)**: outer_vlan_id (12-bit), outer_vlan_pcp (3-bit) for double-tagged carrier/ISP networks (0x88A8 + 0x9100 legacy)
- **IPv4 fragmentation**: ip_dont_fragment (DF flag), ip_more_fragments (MF flag), ip_frag_offset (13-bit) for fragment attack detection
- **GRE tunnel**: gre_protocol (16-bit protocol type), gre_key (32-bit key) matching for IP protocol 47 GRE encapsulation
- **Connection tracking state**: conntrack_state ("new"/"established") for stateful firewall rules; TCP state machine tracking (SYN→ESTABLISHED→FIN→CLOSED) in RTL conntrack table
- **Per-flow counters**: enable_flow_counters in conntrack config for per-flow packet/byte counting and flow export
- **OAM (IEEE 802.1ag CFM)**: oam_level (3-bit MD level, 0-7), oam_opcode (8-bit CFM OpCode: 1=CCM, 3=LBR, 47=DMM, 48=DMR) for carrier Ethernet OAM monitoring
- **NSH/SFC (RFC 8300)**: nsh_spi (24-bit Service Path Identifier), nsh_si (8-bit Service Index), nsh_next_protocol (inner protocol type) for Service Function Chaining
- **Geneve tunnel (RFC 8926)**: geneve_vni (24-bit VNI, 0-16777215) matching after UDP:6081 detection
- **IP TTL matching**: ip_ttl (0-255) match field for TTL-based security and traceroute detection
- **PTP (IEEE 1588)**: ptp_message_type (4-bit, 0-15), ptp_domain (8-bit), ptp_version (4-bit) matching via dual L2 (EtherType 0x88F7) and L4 (UDP 319/320) detection; optional `--ptp` flag for hardware timestamping clock (ptp_clock.v)
- **RSS (Receive Side Scaling)**: `rss_queue` per-rule queue override (0-15), `--rss`/`--rss-queues N` CLI flags, Toeplitz hash engine (Microsoft RSS compatible), 128-entry indirection table with AXI-Lite CSR, hash-based multi-queue dispatch for multi-core packet processing
- **INT (In-band Network Telemetry)**: per-rule `int_insert` field, `--int`/`--int-switch-id N` CLI flags, sideband metadata output (switch_id, ingress/egress timestamps, hop_latency, queue_id, rule_idx), int_metadata.v RTL module, int_lut.v.tera template for INT enable lookup
- **Synthetic traffic generation**: `pcap-gen` subcommand generates protocol-aware PCAP files from YAML rules with `--count`/`--seed`/`--json`/`--output` flags
- **Frame length matching**: frame_len_min/frame_len_max (simulation-only, no RTL) for size-based filtering
- **L4 port rewrite**: set_src_port, set_dst_port with RFC 1624 incremental L4 checksum update (TCP/UDP, UDP cksum=0 preserved)
- **Byte-offset matching**: raw byte inspection at any packet offset with value/mask (`byte_match`)
- **Hierarchical State Machines**: nested states, variables (1-32 bit), guards, entry/exit/transition actions
- **Mermaid import/export**: bidirectional stateDiagram-v2 conversion (`from-mermaid`, `to-mermaid`)
- **Multi-port switch fabric**: N independent filter instances (`--ports N`)
- **Connection tracking**: CRC-based hash table with timeout (`--conntrack`)
- **Runtime flow tables**: register-based AXI-Lite-writable match entries with staging+commit atomicity (`--dynamic`)
- **Mirror/redirect egress**: mirror_port (copy packet to egress port), redirect_port (override egress port) per-rule egress actions
- **Packet rewrite actions**: set_dst_mac, set_src_mac, set_vlan_id, set_vlan_pcp, set_outer_vlan_id, set_ttl, dec_ttl, set_src_ip, set_dst_ip, set_dscp, set_ecn, set_src_port, set_dst_port, dec_hop_limit, set_hop_limit (NAT, PAT, TTL management, MAC rewrite, VLAN modification, QoS remarking, port forwarding, IPv6 hop limit, ECN marking)
- **Platform integration**: `--target opennic` and `--target corundum` generate drop-in NIC wrappers with 512↔8-bit width converters (~2 Gbps at 250MHz; bus-width compatibility, core parser is 8-bit)
- **Parameterized data path width**: `--width {8,64,128,256,512,1024,2048}` generates AXI-Stream width converters for NIC bus-width compatibility (V1 throughput limited to ~2 Gbps by 8-bit core parser; native wide parser planned for true 100G+)
- **P4 export**: `p4-export` subcommand generates P4_16 PSA program from YAML rules, targeting P4-programmable ASICs/SmartNICs
- **P4 import**: `p4-import` subcommand parses P4_16 PSA programs into YAML rules, completing the bidirectional P4↔YAML bridge with rewrite action mapping, extern detection, and round-trip validation
- **Wireshark display filter import**: `wireshark-import` subcommand converts Wireshark display filter syntax (`tcp.port == 80 && ip.src == 10.0.0.0/8`) into YAML rules with ~45 field mappings, protocol inference, bidirectional port expansion, and TCP flag accumulation
- **iptables-save import**: `iptables-import` subcommand converts Linux `iptables-save` output into YAML rules with protocol/port/CIDR/TCP-flags/ICMP/conntrack-state/MAC/multiport mapping, DNAT/SNAT rewrite extraction, chain selection — quad input format (YAML + P4 + Wireshark + iptables)
- **Rule set optimizer**: `optimize` subcommand performs 5 semantics-preserving passes: dead rule removal (OPT001), duplicate merging (OPT002), adjacent port consolidation (OPT003), adjacent CIDR consolidation (OPT004), priority renumbering (OPT005) — with `--json`/`-o`/`--apply` flags
- **Rust code generation backend**: `--target rust` generates a standalone Rust packet filter binary with compiled match rules, PCAP I/O, per-rule statistics, stdin/stdout pipe mode, and optional AF_XDP live capture (`afxdp` Cargo feature); protocol-conditional code generation (~300-900 LOC output)
- **Multi-table pipeline**: optional `tables:` YAML key for sequential match-action stages with AND decision combining; per-stage rule matchers and decision logic
- **cocotb 2.0 runner**: `run_sim.py` generated alongside Makefiles using `cocotb_tools.runner` API for programmatic, cross-platform simulation
- **IPv6 matching**: src_ipv6, dst_ipv6 (CIDR prefix), ipv6_next_header
- **Packet simulation**: software dry-run with `simulate` subcommand (no hardware needed)
- **Stateful simulation**: `--stateful` flag enables rate-limit + conntrack in software dry-run
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
- **Full-stack scoreboard**: Python reference model matches L2/L3/L4/IPv6/VXLAN/GTP-U/MPLS/IGMP/MLD/DSCP/ECN/IPv6-TC/TCP-flags/ICMP/ICMPv6/ARP/IPv6-ext/QinQ/IP-frag/GRE/conntrack-state/OAM/NSH/Geneve/ip_ttl/frame_len/byte-match/PTP/RSS/INT fields
- **Directed L3/L4 tests**: generated tests construct proper IPv4/IPv6/TCP/UDP headers
- **Protocol-specific cocotb packets**: 14 PacketFactory methods (geneve, gre, icmp, icmpv6_msg, arp_msg, qinq, ip_frag, tcp_with_flags, dscp_ecn, ipv6_tc, ipv6_ext, ipv4_tcp_conntrack) with 13 protocol branches in test_harness.py.tera
- **Byte-match simulation**: software simulator evaluates byte_match rules with raw_bytes
- **Enhanced formal**: SVA assertions for IPv6 CIDR, port range, rate limiter enforcement, byte-match, GTP-U/MPLS/IGMP/MLD/GRE prerequisite + bounds assertions with protocol cover statements
- **Conntrack cocotb tests**: 5 tests (new flow, return traffic, timeout, collision, overflow)
- **MCY Verilog mutation testing**: generate MCY config for Yosys-level mutation analysis (`mcy` subcommand)
- **Mutation kill-rate runner**: compile + lint each mutant, report kill/survived/error rates (`mutate --run`)
- **Coverage-directed closure**: CoverageDirector wired into test loop with XML export
- **Boundary test generation**: auto-derived CIDR/port boundary tests + formally-derived negative tests
- **Enhanced property tests**: 17 Hypothesis-based tests including CIDR/port/IPv6 boundary checks + 8 protocol strategies (GRE/OAM/NSH/ARP/ICMP/ICMPv6/QinQ/TCP-flags frames)
- **Scenario validation**: validate scenario JSON files (v1 basic + v2 topology-aware) with strict key checking
- **Packet regression**: high-volume regression testing against scenarios using direct `simulate()` calls (~600K pps)
- **Topology simulation**: 2-port RMAC/L3 switch topology simulation with subnet gating, ingress validation, egress routing
- **Scenario store**: import/export scenario files to/from JSON store (merge or replace modes)
- `lint` subcommand for best-practice analysis and security checks (57 lint rules)
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
- 53 real-world YAML examples + 2 P4 + 2 Wireshark + 2 iptables examples (data center, industrial OT, automotive, 5G, IoT, campus, stateful, L3/L4 firewall, VXLAN, byte-match, HSM, IPv6, rate-limited, GTP-U, MPLS, multicast, dynamic, rewrite, OpenNIC, Corundum, TCP flags/ICMP, ARP security, ICMPv6 firewall, QinQ provider, fragment security, port rewrite, GRE tunnel, conntrack firewall, mirror/redirect, flow counters, OAM monitoring, NSH/SFC, Geneve datacenter, TTL security, IPv6 routing, QoS rewrite, wide AXI firewall, P4 export demo, pipeline classify, PTP boundary clock, PTP 5G fronthaul, RSS datacenter, RSS NIC offload, INT datacenter, pcap-gen demo, optimize demo, Rust filter demo)
- 726 Rust unit tests + 428 integration tests = 1154 total, 90 Python scoreboard tests, 13+ cocotb simulation tests, 5 conntrack cocotb tests, 85%+ functional coverage

## Architecture
```
rules.yaml --> pacgate (Rust) --+--> Verilog RTL  (gen/rtl/)
                                +--> cocotb tests (gen/tb/)
                                +--> SVA assertions (gen/formal/)
                                +--> property tests (gen/tb/)
                                +--> Rust filter  (gen/rust/)  [--target rust]
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
  - `frame_parser` — hand-written parser: L2/L3/L4/IPv6/VXLAN/GTP-U/MPLS/IGMP/MLD/OAM/NSH/Geneve extraction (rtl/frame_parser.v)
  - `byte_capture` — generated byte-offset capture module (if byte_match used)
  - `rule_match_N` — generated per-rule combinational matchers (stateless)
  - `rule_fsm_N` — generated per-rule FSM modules (stateful, supports HSM)
  - `decision_logic` — generated priority encoder with rule_idx output
- `packet_filter_axi_top` — AXI-Stream top-level (templatized, templates/packet_filter_axi_top.v.tera)
  - `axi_stream_adapter` — AXI-Stream to pkt_* interface bridge
  - `packet_filter_top` — core filter (above)
  - `store_forward_fifo` — frame buffering, forwards/discards based on decision
  - `rewrite_lut` — generated combinational ROM mapping rule_idx to rewrite ops (if rewrite rules present)
  - `egress_lut` — generated combinational ROM mapping rule_idx to mirror/redirect port params (if mirror/redirect rules present)
  - `packet_rewrite` — hand-written byte substitution engine with RFC 1624 checksum (rtl/packet_rewrite.v)
  - `rss_toeplitz` — Toeplitz hash engine for 5-tuple hashing (rtl/rss_toeplitz.v, optional `--rss`)
  - `rss_indirection` — 128-entry indirection table with AXI-Lite + per-rule override mux (rtl/rss_indirection.v, optional `--rss`)
  - `rss_queue_lut` — generated per-rule queue override ROM (optional, if rss_queue rules present)
  - `int_metadata` — INT sideband metadata capture (switch_id, timestamps, hop_latency, queue_id, rule_idx) (rtl/int_metadata.v, optional `--int`)
  - `int_lut` — generated INT enable lookup table per rule (optional, if int_insert rules present)
- `packet_filter_dynamic_top` — dynamic mode top-level (generated, `--dynamic`)
  - `frame_parser` — same hand-written parser
  - `flow_table` — register-based match entries with AXI-Lite CRUD (generated from template)
- `pacgate_opennic_250` — OpenNIC Shell 250MHz wrapper (generated, `--target opennic`)
  - `axis_512_to_8` — 512→8-bit width converter (rtl/axis_512_to_8.v)
  - `packet_filter_axi_top` — core AXI filter pipeline
  - `axis_8_to_512` — 8→512-bit width converter (rtl/axis_8_to_512.v)
- `pacgate_corundum_app` — Corundum mqnic_app_block replacement (generated, `--target corundum`)
  - Same internal structure: axis_512_to_8 → filter → axis_8_to_512
- `pipeline_top` — multi-table pipeline wrapper (generated, `tables:` present)
  - `frame_parser` — shared parser instance
  - N x `rule_match_s{N}_r{M}` — per-stage per-rule matchers
  - N x `decision_logic_s{N}` — per-stage priority encoders
  - Pipeline decision combining: AND of all stage decisions
- `rule_counters` — per-rule 64-bit packet/byte counters (rtl/rule_counters.v)
- `axi_lite_csr` — AXI4-Lite register interface for counter readout (rtl/axi_lite_csr.v)
- `conntrack_table` — connection tracking hash table with per-flow 64-bit pkt/byte counters + flow read-back interface (rtl/conntrack_table.v)
- `rate_limiter` — token-bucket rate limiter per rule (rtl/rate_limiter.v)

### Packet Interface
- Simple: `pkt_data[7:0]`, `pkt_valid`, `pkt_sof`, `pkt_eof`
- AXI-Stream: `s_axis_tdata[7:0]`, `s_axis_tvalid`, `s_axis_tready`, `s_axis_tlast` (in/out)
- Multi-port: `portN_pkt_data`, `portN_pkt_valid`, etc.
- Output: `decision_valid`, `decision_pass`, `decision_rule_idx`, `decision_default`

## CLI Commands
```bash
pacgate compile rules.yaml             # Generate Verilog + cocotb tests
pacgate compile rules.yaml --axi       # Include AXI-Stream wrapper + tests (required for rewrite actions)
pacgate compile rules.yaml --counters  # Include per-rule counters + AXI-Lite CSR
pacgate compile rules.yaml --ports 4   # Multi-port (4 independent filters)
pacgate compile rules.yaml --conntrack # Include connection tracking RTL
pacgate compile rules.yaml --rate-limit # Include rate limiter RTL
pacgate compile rules.yaml --dynamic   # Runtime-updateable flow table (AXI-Lite)
pacgate compile rules.yaml --dynamic --dynamic-entries 32  # 32-entry flow table
pacgate compile rules.yaml --target opennic   # OpenNIC Shell 250MHz wrapper
pacgate compile rules.yaml --target corundum  # Corundum mqnic_app_block wrapper
pacgate compile rules.yaml --target rust      # Generate standalone Rust packet filter binary
pacgate compile rules.yaml --target rust --json  # JSON summary of Rust generation
# After Rust compile: cd gen/rust && cargo build --release
# Run:   gen/rust/target/release/pacgate_filter input.pcap --output filtered.pcap --stats
pacgate compile rules.yaml --width 128 --axi  # 128-bit AXI-Stream width converters
pacgate compile rules.yaml --width 512 --target opennic  # Native 512-bit (no extra converters)
pacgate compile rules.yaml --axi --ptp                   # Include PTP hardware clock + CSR registers
pacgate compile rules.yaml --axi --rss                   # Enable RSS multi-queue dispatch (4 queues default)
pacgate compile rules.yaml --axi --rss --rss-queues 16   # RSS with 16 queues
pacgate compile rules.yaml --axi --int                   # Enable INT sideband metadata output
pacgate compile rules.yaml --axi --int --int-switch-id 1 # INT with custom switch ID
pacgate compile rules.yaml --json      # JSON output with warnings
# After compile: cd gen/tb && python run_sim.py   # cocotb 2.0 runner (recommended)
# After compile: cd gen/tb && make                 # Makefile-based (legacy, still supported)
pacgate validate rules.yaml            # Validate YAML only (no output)
pacgate init [rules.yaml]              # Create starter rules file
pacgate estimate rules.yaml            # FPGA resource estimate + timing
pacgate diff old.yaml new.yaml         # Compare two rule sets
pacgate graph rules.yaml               # DOT graph output (pipe to dot -Tpng)
pacgate stats rules.yaml               # Rule set analytics
pacgate lint rules.yaml                # Best-practice analysis
pacgate formal rules.yaml              # Generate SVA + SymbiYosys files
pacgate p4-export rules.yaml -o gen/p4/ # Generate P4_16 PSA program from YAML rules
pacgate p4-export rules.yaml -o gen/p4/ --json  # P4 export with JSON summary
pacgate p4-import filter.p4             # Import P4_16 PSA program → YAML (stdout)
pacgate p4-import filter.p4 -o rules.yaml  # Import P4 → YAML file
pacgate p4-import filter.p4 --json      # JSON import summary
pacgate wireshark-import --filter "tcp.port == 80"               # Wireshark filter → YAML (stdout)
pacgate wireshark-import --filter "tcp.port == 80" -o rules.yaml # Wireshark filter → YAML file
pacgate wireshark-import --filter-file filter.txt -o rules.yaml  # From filter file
pacgate wireshark-import --filter "tcp.port == 80" --json        # JSON import summary
pacgate wireshark-import --filter "!arp" --default-action pass   # Custom default action
pacgate iptables-import firewall.rules                       # iptables-save → YAML (stdout)
pacgate iptables-import firewall.rules -o rules.yaml         # iptables-save → YAML file
pacgate iptables-import firewall.rules --chain FORWARD        # Import FORWARD chain
pacgate iptables-import firewall.rules --chain all            # Import all chains
pacgate iptables-import firewall.rules --json                 # JSON import summary
pacgate optimize rules.yaml                        # Optimize rule set (stdout YAML)
pacgate optimize rules.yaml -o optimized.yaml      # Optimize → output file
pacgate optimize rules.yaml --apply                # Optimize in-place
pacgate optimize rules.yaml --json                 # JSON optimization summary
pacgate report rules.yaml              # Generate HTML coverage report
pacgate pcap capture.pcap              # Import PCAP for cocotb test stimulus
pacgate from-mermaid fsm.md --name rule --priority 100  # Mermaid → YAML
pacgate to-mermaid rules.yaml          # YAML → Mermaid (stdout)
pacgate simulate rules.yaml --packet "ethertype=0x0800,dst_port=80"  # Dry-run simulation
pacgate simulate rules.yaml --packet "..." --stateful                # Stateful sim (rate-limit + conntrack)
pacgate simulate rules.yaml --packet "gtp_teid=12345"               # GTP-U tunnel simulation
pacgate simulate rules.yaml --packet "mpls_label=1000,mpls_bos=1"   # MPLS label simulation
pacgate simulate rules.yaml --packet "igmp_type=0x11"               # IGMP multicast simulation
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_dscp=46"  # DSCP QoS classification simulation
pacgate simulate rules.yaml --packet "ethertype=0x86DD,ipv6_dscp=46"  # IPv6 Traffic Class simulation
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=6,tcp_flags=0x02"  # TCP SYN matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=1,icmp_type=8"    # ICMP echo request
pacgate simulate rules.yaml --packet "ethertype=0x86DD,ipv6_next_header=58,icmpv6_type=128"  # ICMPv6 echo request
pacgate simulate rules.yaml --packet "ethertype=0x0806,arp_opcode=1"                 # ARP request matching
pacgate simulate rules.yaml --packet "ethertype=0x86DD,ipv6_hop_limit=64,ipv6_flow_label=12345"  # IPv6 ext fields
pacgate simulate rules.yaml --packet "ethertype=0x88A8,outer_vlan_id=100,outer_vlan_pcp=5"     # QinQ double VLAN
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_dont_fragment=true"                  # IPv4 DF flag
pacgate simulate rules.yaml --packet "ethertype=0x8902,oam_level=3,oam_opcode=1"              # OAM/CFM CCM level 3
pacgate simulate rules.yaml --packet "ethertype=0x894F,nsh_spi=100,nsh_si=254"               # NSH/SFC path matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=17,dst_port=6081,geneve_vni=5000"  # Geneve tunnel matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_ttl=1"                              # TTL-based security matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=47,gre_protocol=0x0800"     # GRE tunnel matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,conntrack_state=established"            # Conntrack state matching
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=6,dst_port=80,conntrack_state=new"  # New TCP connection
pacgate simulate rules.yaml --packet "ethertype=0x88F7,ptp_message_type=0,ptp_domain=0"        # L2 PTP Sync match
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=17,dst_port=319,ptp_message_type=0"  # L4 PTP match
pacgate simulate rules.yaml --packet "ethertype=0x0800,ip_protocol=6,dst_port=80"              # Port rewrite (with rewrite actions)
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
pacgate pcap-gen rules.yaml                        # Generate synthetic PCAP from rules (stdout)
pacgate pcap-gen rules.yaml --count 1000 --output traffic.pcap  # 1000 packets to file
pacgate pcap-gen rules.yaml --seed 42 --json       # Deterministic generation with JSON summary
pacgate scenario validate *.json       # Validate scenario JSON files
pacgate scenario validate --json *.json # JSON validation output
pacgate scenario import --in-dir scenarios/ --store store.json  # Import scenarios to store
pacgate scenario import --in-dir scenarios/ --store store.json --replace  # Replace store
pacgate scenario export --store store.json --out-dir out/  # Export store to individual files
pacgate regress --scenario scenario.json --count 1000       # Run packet regression
pacgate regress --scenario scenario.json --count 1000 --json # JSON regression output
pacgate topology --scenario scenario.json                   # Run topology simulation
pacgate topology --scenario scenario.json --json            # JSON topology output
cargo test                             # 806 tests (479 unit + 327 integration)
pytest verification/test_scoreboard.py # 67 Python scoreboard unit tests
```

## Key Files
- `src/model.rs` — Data model (Action, MatchCriteria, ByteMatch, Ipv6Prefix, RateLimit, FsmVariable, HSM types, ConntrackConfig, RssConfig, IntConfig, GtpTeid, MplsLabel, IgmpType, MldType, IpDscp, IpEcn, Ipv6Dscp, Ipv6Ecn, TcpFlags, IcmpType, IcmpCode, ICMPv6Type, ICMPv6Code, ArpOpcode, ArpSpa, ArpTpa, Ipv6HopLimit, Ipv6FlowLabel, OuterVlanId, OuterVlanPcp, IpDontFragment, IpMoreFragments, IpFragOffset, GreProtocol, GreKey, ConntrackState, OamLevel, OamOpcode, NshSpi, NshSi, NshNextProtocol, GeneveVni, IpTtl, FrameLenMin, FrameLenMax, PtpMessageType, PtpDomain, PtpVersion, IntInsert, RewriteAction with set_src_port/set_dst_port/dec_hop_limit/set_hop_limit/set_ecn/set_vlan_pcp/set_outer_vlan_id)
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
- `src/scenario.rs` — Scenario validation, regression testing, topology simulation (migrated from pacilab)
- `src/p4_gen.rs` — P4_16 PSA code generation from YAML rules (~950 LOC)
- `src/p4_import.rs` — P4_16 PSA import: line-by-line state machine parser, reverse field mapping, rewrite/extern parsing (~750 LOC)
- `src/wireshark_import.rs` — Wireshark display filter import: tokenizer, recursive descent parser, ~45 field mappings with protocol inference (~700 LOC)
- `src/iptables_import.rs` — iptables-save import: line-based parser, protocol/port/CIDR/TCP-flags/ICMP/conntrack mapping, DNAT/SNAT rewrite, multiport expansion (~600 LOC)
- `src/optimize.rs` — Rule set optimizer: 5 passes (dead rule removal, duplicate merging, port consolidation, CIDR consolidation, priority renumber) (~500 LOC)
- `src/rust_gen.rs` — Rust code generation backend: protocol detection, compiled rule matchers, condition builder for 55+ fields, CIDR/MAC/IPv6 constant generation (~400 LOC)
- `src/pcap_gen.rs` — Synthetic PCAP traffic generator with protocol-aware packet construction (~720 LOC)
- `src/main.rs` — clap CLI (40 subcommands)
- `rtl/frame_parser.v` — Hand-written Ethernet/IPv4/IPv6/TCP/UDP/VXLAN/GTP-U/MPLS/IGMP/MLD/ICMP/ICMPv6/ARP/QinQ/OAM/NSH/Geneve/PTP parser FSM (23 states) with TCP flags + IPv6 TC + hop_limit + flow_label + fragmentation + L4 port offset + OAM/CFM + NSH/SFC + Geneve VNI + ip_ttl + PTP messageType/domain/version extraction
- `rtl/ptp_clock.v` — Free-running 64-bit PTP hardware clock with SOF/EOF timestamp latching (optional, `--ptp` flag)
- `rtl/rule_counters.v` — Per-rule 64-bit packet/byte counters
- `rtl/axi_lite_csr.v` — AXI4-Lite register interface for counters
- `rtl/axi_stream_adapter.v` — AXI-Stream to pkt_* interface bridge
- `rtl/store_forward_fifo.v` — Store-and-forward FIFO with decision-based forwarding
- `rtl/packet_filter_axi_top.v` — AXI-Stream top-level integrating all modules
- `rtl/packet_rewrite.v` — Hand-written byte substitution engine with RFC 1624 incremental checksum
- `rtl/conntrack_table.v` — Connection tracking hash table with CRC hash + timeout + TCP state machine (NEW→ESTABLISHED→FIN_WAIT→CLOSED) + per-flow 64-bit pkt/byte counters + flow read-back interface
- `rtl/rate_limiter.v` — Token-bucket rate limiter (parameterized PPS, BURST)
- `rtl/rss_toeplitz.v` — Combinational Toeplitz hash engine (104-bit 5-tuple input, 320-bit key, 32-bit hash output)
- `rtl/rss_indirection.v` — 128-entry RSS indirection table with AXI-Lite interface and per-rule queue override mux
- `rtl/int_metadata.v` — INT sideband metadata capture module (switch_id, ingress/egress timestamps, hop_latency, queue_id, rule_idx)
- `rtl/axis_512_to_8.v` — 512→8-bit AXI-Stream width converter (for platform targets)
- `rtl/axis_8_to_512.v` — 8→512-bit AXI-Stream width converter (for platform targets)
- `templates/*.tera` — 31+ Tera templates (+ synth scripts, rate limiter TB, HTML docs, diff report, MCY config, flow table, dynamic top, rewrite_lut, rss_queue_lut, int_lut, packet_filter_axi_top, cocotb 2.0 runner scripts, rust_cargo.toml, rust_filter.rs)
- `templates/rewrite_lut.v.tera` — Combinational ROM mapping rule_idx to rewrite operations
- `templates/egress_lut.v.tera` — Combinational ROM mapping rule_idx to mirror/redirect port parameters
- `templates/packet_filter_axi_top.v.tera` — Templatized AXI top-level with rewrite engine wiring
- `templates/diff_report.html.tera` — HTML diff visualization template (color-coded additions/removals/modifications)
- `templates/pacgate_opennic_250.v.tera` — OpenNIC Shell 250MHz user box wrapper template
- `templates/pacgate_corundum_app.v.tera` — Corundum mqnic_app_block wrapper template
- `templates/pipeline_top.v.tera` — Multi-table pipeline wrapper template
- `templates/axis_wide_to_8.v.tera` — Parameterized wide-to-narrow AXI-Stream converter template
- `templates/axis_8_to_wide.v.tera` — Parameterized narrow-to-wide AXI-Stream converter template
- `templates/p4_program.p4.tera` — P4_16 PSA program template
- `templates/int_lut.v.tera` — INT enable lookup table per rule_idx
- `verification/` — Python verification framework (packet, scoreboard, coverage, driver, properties, coverage_driven, test_scoreboard)
- `rules/examples/` — 51 YAML examples
- `rules/templates/` — 7 rule template YAML snippets
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline

## Design Decisions
- Decision output is **latched** (stays valid until next pkt_sof)
- Rules sorted by priority (highest first); priority encoder is if/else chain
- Frame parser handles 802.1Q VLAN, IPv4, IPv6, TCP/UDP, VXLAN, GTP-U, MPLS, IGMP, MLD, DSCP/ECN, IPv6 TC, TCP flags, ICMP, ICMPv6, ARP, IPv6 hop_limit/flow_label, OAM/CFM, NSH/SFC, Geneve, PTP (23 parser states)
- Stateless evaluation is combinational (O(1) clock cycles)
- Stateful rules use registered FSM with 32-bit timeout counters
- HSM flattening: composite states converted to flat "parent_child" Verilog states (max 4 levels)
- FSM variables: 1-32 bit registers with guards and assignment actions (=, +=, -=, |=)
- IPv4/IPv6 CIDR matching: `(ip & mask) == (prefix & mask)` in hardware (32-bit/128-bit)
- Port range matching: `(port >= low && port <= high)` with 16-bit comparators
- Byte-offset matching: global byte counter + per-offset capture registers
- VXLAN detection: UDP dst port == 4789, then 8-byte VXLAN header, extract 24-bit VNI
- GTP-U detection: UDP dst port == 2152, then 8-byte GTP header, extract 32-bit TEID
- GRE detection: IP protocol 47, S_GRE_HDR state extracts 16-bit protocol type + optional 32-bit key (K flag in GRE header)
- OAM/CFM detection: EtherType 0x8902, S_OAM_HDR state extracts 3-bit MEL (MD level) from byte 0 bits[7:5] and 8-bit OpCode from byte 1
- NSH detection: EtherType 0x894F, S_NSH_HDR state extracts 8-byte header — byte 2 next_protocol, bytes 4-6 SPI (24-bit), byte 7 SI (8-bit)
- Geneve detection: UDP dst port == 6081, S_GENEVE_HDR state (5'd21) extracts 24-bit VNI from 8-byte Geneve base header
- PTP detection: dual path — L2 (EtherType 0x88F7) and L4 (UDP dst_port 319/320), S_PTP_HDR state (5'd22) extracts messageType[3:0], versionPTP[3:0], domainNumber[7:0]; ptp_clock.v is optional (--ptp flag) for hardware timestamping
- ip_ttl exposure: already extracted by frame parser (ip_ttl register), now exposed as match field for TTL-based security rules
- frame_len: simulation-only match field (frame_len_min/frame_len_max), no RTL generation — evaluated in software simulator only
- IPv6 hop limit rewrite: dec_hop_limit/set_hop_limit (flag bits 10-11), no checksum update needed (IPv6 has no header checksum)
- ECN rewrite: set_ecn (flag bit 12) modifies 2-bit ECN in IPv4 TOS byte or IPv6 Traffic Class, with RFC 1624 checksum for IPv4
- VLAN PCP rewrite: set_vlan_pcp (flag bit 13) modifies 3-bit PCP in 802.1Q VLAN tag
- Outer VLAN rewrite: set_outer_vlan_id (flag bit 14) modifies 12-bit VID in outer 802.1ad QinQ tag
- MPLS detection: EtherType 0x8847 (unicast) or 0x8848 (multicast), extract 20-bit label, 3-bit TC, 1-bit BOS
- IGMP detection: IPv4 protocol == 2, extract type byte from IGMP header
- MLD detection: ICMPv6 (next_header 58), types 130-132 (query, report v1, done)
- ICMPv6 detection: IPv6 next_header 58, S_ICMPV6_HDR state extracts type/code bytes; MLD types 130-132 still set mld_type/mld_valid for backward compatibility
- ARP detection: EtherType 0x0806, S_ARP_HDR state extracts opcode (bytes 6-7), sender protocol address (bytes 14-17), target protocol address (bytes 24-27)
- IPv6 hop_limit: extracted from IPv6 header byte 7; flow_label: extracted from IPv6 header bytes 1-3 (lower 20 bits)
- Multi-port: N independent filter instances sharing same rule set
- Connection tracking: CRC-based hash, open-addressing linear probing, timestamp-based timeout, per-entry TCP state machine (NEW→ESTABLISHED→FIN_WAIT→CLOSED), optional per-flow 64-bit pkt/byte counters with registered read-back interface (enable_flow_counters)
- Rate limiting: token-bucket per rule (parameterized PPS/BURST, 16-bit tokens, 32-bit refill counter)
- Packet simulation: software reference model evaluates rules without hardware toolchain
- Overlap detection: CIDR prefix containment + port range analysis (not just string equality)
- QinQ (802.1ad) detection: EtherType 0x88A8 (IEEE) or 0x9100 (legacy), outer tag → outer_vlan_id/pcp, inner tag → vlan_id/pcp
- IPv4 fragmentation: DF/MF flags at IP header byte 6, 13-bit fragment offset at bytes 6-7, ip_frag_valid set
- L4 port offset: 11-bit frame_byte_cnt tracks absolute position, l4_port_offset latched at L4 header start for rewrite engine
- Rewrite flags: 16-bit (bits 0-7 original, bit 8=set_src_port, bit 9=set_dst_port, bit 10=dec_hop_limit, bit 11=set_hop_limit, bit 12=set_ecn, bit 13=set_vlan_pcp, bit 14=set_outer_vlan_id, 1 remaining)
- ip_base 3-way: has_outer_vlan ? 22 : (has_vlan ? 18 : 14) — QinQ adds 4 bytes for outer TCI
- L4 port rewrite: RFC 1624 incremental checksum; UDP checksum=0 preserved (means "no checksum" per RFC 768)
- Packet rewrite is in-place only (no frame length changes); supports MAC/VLAN/VLAN-PCP/outer-VLAN/TTL/hop-limit/IP/DSCP/ECN/port substitution with RFC 1624 incremental checksum (IPv4 only; IPv6 rewrite needs no checksum)
- AXI-Stream modules are hand-written (not generated) since they are infrastructure
- Platform targets (OpenNIC/Corundum): V1 uses width converters (wide↔8-bit) so core parser throughput is ~2 Gbps regardless of bus width; suitable for 1GbE/dev/prototyping. Width parameter (8-2048) provides bus-width compatibility only. See docs/WIDE_PARSER_ROADMAP.md for native wide parser plan (speculative parallel extraction for true 100G+)
- OpenNIC wrapper preserves tuser_size/tuser_src/tuser_dst metadata; Corundum wrapper inverts active-high reset and passes PTP timestamp
- License: Proprietary (see LICENSE)

## Environment
- Rust toolchain (cargo)
- Python venv at `.venv/` with cocotb>=2.0.0 + cocotb-tools
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
- **Phase 14**: Complete — Protocol verification completeness: GTP-U/MPLS/IGMP/MLD in Python scoreboard + packet factory + test templates (directed+random) + SVA formal assertions + shadow/overlap detection + stats/graph/diff/estimate/doc; fixed diff_rules() L3/L4/IPv6 bug
- **Phase 15**: Complete — Verification depth & tool completeness: reachability analysis with protocol fields + stateful rule tracking, 11 mutation types (6 new: widen_src_ip, shift_dst_port, remove_gtp_teid/mpls_label/igmp_type/vxlan_vni), 5 new coverage coverpoints (tunnel_type, mpls_present, igmp_type_range, mld_type_range, gtp_teid_range), fixed conntrack test assertions, 4 Hypothesis strategies (GTP-U/MPLS/IGMP/MLD frames), 9 property checks wired in runner, LINT013-015 (GTP/MPLS/IGMP/MLD prerequisite checks), CI simulate matrix expanded to 8 examples
- **Phase 16**: Complete — Simulator completeness + verification depth: rate-limit simulation (token-bucket in software), conntrack simulation (5-tuple hash + reverse lookup), --stateful CLI flag, strengthened SVA (rate-limit enforcement, GTP/MPLS/IGMP/MLD prereq + bounds assertions, protocol cover statements), protocol property tests wired into generated test files, byte_match in HTML docs, CI expansion (conntrack-simulate, formal-generate, rate-limit-simulate jobs)
- **Phase 17**: Complete — Runtime-updateable flow tables: `--dynamic` flag replaces static per-rule matchers with register-based `flow_table.v` (AXI-Lite writable, staging+commit atomicity), YAML rules as initial values, `--dynamic-entries N` (1-256), cocotb tests (6 AXI-Lite CRUD tests), estimate/lint/formal support (LINT016-017), dynamic_firewall.yaml example, 242 unit + 165 integration = 407 tests
- **Phase 18**: Complete — Packet rewrite actions: `rewrite:` field with 7 operations (set_dst_mac, set_src_mac, set_vlan_id, set_ttl, dec_ttl, set_src_ip, set_dst_ip), RewriteAction model + YAML validation, frame parser ip_ttl/ip_checksum extraction, rewrite_lut.v (generated ROM), packet_rewrite.v (RTL byte substitution with RFC 1624 checksum), templatized AXI top with rewrite wiring, simulator rewrite info, estimate/lint (LINT018-019)/formal/diff support, rewrite_actions.yaml example, 250 unit + 181 integration = 431 tests
- **Phase 19**: Complete — Platform integration targets: `--target opennic` and `--target corundum` generate drop-in NIC wrappers with 512↔8-bit width converters (axis_512_to_8.v, axis_8_to_512.v), OpenNIC tuser metadata passthrough, Corundum PTP timestamp + reset inversion, estimate/lint (LINT020-021)/synth support, 2 platform examples, CI jobs, 256 unit + 195 integration = 451 tests
- **Phase 20**: Complete — cocotb 2.0 migration: pin cocotb>=2.0.0 + cocotb-tools, fix `.value.integer` → `int(.value)`, generate `run_sim.py` runner scripts (cocotb_tools.runner API) alongside Makefiles for all test modes (main, AXI, conntrack, rate limiter, dynamic), platform target width converter inclusion, CI updated to use runner, 260 unit + 204 integration = 464 tests
- **Phase 21**: Complete — DSCP/ECN QoS matching + DSCP rewrite: ip_dscp (6-bit, 0-63) and ip_ecn (2-bit, 0-3) match fields from IPv4 TOS byte, set_dscp rewrite action with RFC 1624 incremental checksum, frame parser TOS byte extraction, qos_classification.yaml example (7 rules: EF/AF41/AF31/CS6/BE+ECT1/remark/ARP), LINT022 (DSCP/ECN without IPv4), SVA DSCP/ECN bounds assertions, Python scoreboard DSCP/ECN matching, 13 mutation types, 275 unit + 216 integration = 491 tests
- **Phase 22**: Complete — IPv6 Traffic Class + TCP Flags + ICMP Type/Code: 6 new match fields (ipv6_dscp, ipv6_ecn, tcp_flags, tcp_flags_mask, icmp_type, icmp_code), frame parser IPv6 TC extraction + TCP flags at byte 13 + ICMP state machine, mask-aware TCP flags matching, LINT023-025 (IPv6 TC/TCP flags/ICMP prerequisite checks), SVA assertions (IPv6 TC bounds, TCP flags prereq, ICMP covers), 16 mutation types, tcp_flags_icmp.yaml example (7 rules: SYN/established/Xmas/ICMP echo/reply/IPv6 EF/ARP), Python scoreboard + cocotb + formal support, 298 unit + 230 integration = 528 tests
- **Phase 23**: Complete — ARP matching (arp_opcode/arp_spa/arp_tpa), ICMPv6 type/code (icmpv6_type/icmpv6_code with MLD backward compatibility), IPv6 extension fields (ipv6_hop_limit/ipv6_flow_label), frame parser S_ICMPV6_HDR + S_ARP_HDR states, LINT026-028 (ICMPv6/ARP/IPv6-ext prerequisite checks), SVA assertions, 19 mutation types, arp_security.yaml + icmpv6_firewall.yaml examples, 324 unit + 244 integration = 568 tests
- **Phase 24**: Complete — QinQ (802.1ad) double VLAN (outer_vlan_id/outer_vlan_pcp with 0x88A8+0x9100), IPv4 fragmentation (ip_dont_fragment/ip_more_fragments/ip_frag_offset), L4 port rewrite (set_src_port/set_dst_port with RFC 1624 L4 checksum), frame parser S_OUTER_VLAN state + frame_byte_cnt + l4_port_offset, rewrite flags 8→16-bit, ip_base 3-way (14/18/22), LINT029-032, SVA assertions (QinQ/frag/port rewrite), 22 mutation types, qinq_provider.yaml + fragment_security.yaml + port_rewrite.yaml examples, 348 unit + 267 integration = 615 tests
- **Phase 25.1**: Complete — GRE tunnel support: gre_protocol (16-bit) + gre_key (32-bit) matching for IP protocol 47, frame parser S_GRE_HDR state, full verification (scoreboard, SVA assertions, mutation type 23, cocotb generation), gre_tunnel.yaml example, 366 unit + 274 integration = 640 tests
- **Phase 25.2**: Complete — Connection tracking state matching: conntrack_state ("new"/"established") match field, TCP state machine in conntrack_table.v (NEW→ESTABLISHED→FIN_WAIT→CLOSED with SYN/ACK/FIN/RST tracking), enhanced SimConntrackTable with per-flow TcpState, LINT034 (conntrack_state requires --conntrack), mutation type 24, conntrack_firewall.yaml example, 383 unit + 283 integration = 666 tests
- **Phase 25.3**: Complete — Mirror/redirect port egress actions: mirror_port (copy packet to egress port) and redirect_port (override egress port) on StatelessRule, egress_lut.v (generated combinational ROM), packet_filter_top/axi_top egress output ports, verification (scoreboard, SVA cover properties, mutation types 25-26, cocotb generation), LINT035-036, simulator mirror/redirect in results, stats/graph/diff/doc egress support, mirror_redirect.yaml example (5 rules), 399 unit + 295 integration = 694 tests
- **Phase 25.4**: Complete — Per-flow counters + flow export: enable_flow_counters on ConntrackConfig, FlowEntry struct with pkt_count/byte_count in SimConntrackTable, increment_counters()/flow_stats() methods, conntrack_table.v per-entry 64-bit pkt/byte counters + flow read-back interface (flow_read_idx/en/key/valid/pkt_count/byte_count/tcp_state/done), has_flow_counters in verilog_gen/templates (AXI/OpenNIC/Corundum), LINT037 (flow counters require --conntrack), estimate +128 LUT/FF per entry, SVA cover properties (flow_read_done, pkt_count), mutation type 27 (remove_flow_counters), diff_rules() conntrack config diffing, flow_counters.yaml example, 414 unit + 305 integration = 719 tests
- **Phase 25.5**: Complete — OAM/CFM (IEEE 802.1ag) support: oam_level (3-bit MD level, 0-7) + oam_opcode (8-bit CFM OpCode) matching on EtherType 0x8902, frame parser S_OAM_HDR state, LINT038 (OAM without ethertype 0x8902), mutation type 28 (remove_oam_level), oam_monitoring.yaml example (5 rules), 53 Python scoreboard tests, 426 unit + 317 integration = 743 tests
- **Phase 25.6**: Complete — NSH/SFC (RFC 8300) support: nsh_spi (24-bit Service Path Identifier) + nsh_si (8-bit Service Index) + nsh_next_protocol (inner protocol type) matching on EtherType 0x894F, frame parser S_NSH_HDR state (8-byte header), LINT039 (NSH without ethertype 0x894F), mutation type 29 (remove_nsh_spi), nsh_sfc.yaml example (5 rules), 53 Python scoreboard tests, 439 unit + 327 integration = 766 tests
- **Phase 26**: Complete — Geneve tunnel + IP TTL/frame length + IPv6 rewrite + cocotb/Hypothesis completeness + VLAN rewrite:
  - **26.1 Geneve (RFC 8926)**: geneve_vni (24-bit VNI, 0-16777215) matching on UDP:6081, frame parser S_GENEVE_HDR state (5'd21), LINT040 (Geneve without UDP:6081), mutation type 30 (remove_geneve_vni), geneve_datacenter.yaml example
  - **26.2 ip_ttl/frame_len**: ip_ttl (0-255) match field (already extracted by parser, now exposed), frame_len_min/frame_len_max (simulation-only, no RTL), LINT041-042, mutation types 31-32, ttl_security.yaml example
  - **26.3 IPv6 rewrite**: dec_hop_limit, set_hop_limit, set_ecn rewrite actions (flag bits 10-12), no checksum needed for IPv6, ECN in IPv4 TOS or IPv6 TC, LINT043, ipv6_routing.yaml example
  - **26.4 Cocotb test completeness**: 14 new PacketFactory methods (geneve, gre, icmp, icmpv6_msg, arp_msg, qinq, ip_frag, tcp_with_flags, dscp_ecn, ipv6_tc, ipv6_ext, ipv4_tcp_conntrack), test_harness.py.tera updated with 13 protocol branches
  - **26.5 Hypothesis completeness**: 8 new strategies (gre_frames, oam_frames, nsh_frames, arp_frames, icmp_frames, icmpv6_frames, qinq_frames, tcp_flags_frames), test_properties.py.tera updated with 9 conditional blocks
  - **26.6 VLAN rewrite**: set_vlan_pcp (0-7, flag bit 13), set_outer_vlan_id (0-4095, flag bit 14), LINT044-046, mutation type 33, qos_rewrite.yaml example
  - 22 parser states, 15 rewrite flag bits (0-14, 1 remaining), 46 lint rules, 33 mutation types, 42 examples, 67 Python scoreboard tests, 479 unit + 327 integration = 806 tests
- **Phase 27**: Complete — Wide data path + P4 export + multi-table pipeline:
  - **27.1 Width Core**: `--width {8,64,128,256,512}` CLI flag, parameterized axis_wide_to_8.v.tera / axis_8_to_wide.v.tera templates, AXI top conditional width converter instantiation
  - **27.2 P4 Export Core**: `p4-export` subcommand, p4_gen.rs module (~950 LOC), p4_program.p4.tera template, P4_16 PSA with all 55 match fields mapped
  - **27.3 Pipeline Model**: PipelineStage struct, optional `tables:` YAML key, DAG cycle detection, backward-compatible single-table mode
  - **27.4 Width Platform**: Width-aware estimate (converter LUTs), LINT047-048, parameterized platform converters
  - **27.5 P4 Full Coverage**: Conntrack Register extern, Meter extern, pipeline-aware P4 export, rewrite action mapping
  - **27.6 Pipeline Verilog**: pipeline_top.v.tera, per-stage rule matchers (rule_match_s{N}_r{M}), per-stage decision logic, AND-combined final decision
  - **27.7 Pipeline Sim/Ver**: Pipeline simulation (stage-sequential AND semantics), PipelineScoreboard Python class
  - **27.8 Pipeline Tools**: Pipeline-aware stats/lint/estimate/graph/diff/mutations, LINT049-050, mutations 34-35 (swap/remove stage)
  - **27.9 Integration**: 3 new examples (wide_axi_firewall, p4_export_demo, pipeline_classify), docs refresh
  - 48 lint rules, 35 mutation types, 45 examples, 73 Python scoreboard tests, 518 unit + 378 integration = 896 Rust tests
- **Phase 28**: Complete — IEEE 1588 PTP hardware timestamping:
  - **28.1 Model+Loader**: 3 new match fields (ptp_message_type, ptp_domain, ptp_version), validation, shadow/overlap detection
  - **28.2 Parser+RTL**: S_PTP_HDR state (5'd22) with dual L2 (0x88F7) / L4 (UDP 319/320) detection, ptp_clock.v (64-bit clock with SOF/EOF timestamp)
  - **28.3 VerilogGen+CLI**: PTP in GlobalProtocolFlags, condition expressions, --ptp CLI flag, template wiring
  - **28.4 Verification**: Python scoreboard PTP matching, PacketFactory.ptp(), 6 PTP tests, SVA assertions, cocotb generation
  - **28.5 Tools**: LINT051-052, mutations 36-37, estimate/stats/diff/doc/graph PTP support, P4 PTP header+parser
  - **28.6 Examples+Docs**: ptp_boundary_clock.yaml, ptp_5g_fronthaul.yaml, documentation updates
  - 23 parser states, 50 lint rules, 37 mutation types, 47 examples, 79 Python scoreboard tests, 518 unit + 378 integration = 896 Rust tests
- **Phase 29**: Complete — RSS / Multi-queue Dispatch:
  - **29.1 Model+Loader+CLI**: `rss_queue` field on StatelessRule (0-15), `RssConfig` struct, `--rss`/`--rss-queues N` CLI flags, Toeplitz hash in simulator
  - **29.2 RTL**: rss_toeplitz.v (combinational hash engine, 104-bit 5-tuple input, 320-bit key), rss_indirection.v (128-entry table, AXI-Lite, per-rule override mux)
  - **29.3 VerilogGen+Templates**: rss_queue_lut.v.tera (per-rule override ROM), RSS module wiring in AXI top, OpenNIC/Corundum RSS port passthrough
  - **29.4 Verification**: Python Toeplitz hash + compute_rss_queue, predict_rss_queue() scoreboard method, 6 RSS Python tests, SVA assertions (bounds, override priority, covers)
  - **29.5 Tools**: LINT053-055, mutations 38-39, estimate (+200 LUT Toeplitz, +64 FF indirection), stats/diff/doc/graph RSS fields, P4 ActionSelector
  - **29.6 Examples+Docs**: rss_datacenter.yaml, rss_nic_offload.yaml, documentation updates
  - 23 parser states, 53 lint rules, 39 mutation types, 49 examples, 85 Python scoreboard tests, 536 unit + 378 integration = 914 Rust tests
- **Phase 30**: Complete — INT (In-band Network Telemetry) + synthetic traffic generation:
  - **30.1 Model+Loader+CLI**: `int_insert` per-rule field (bool), `IntConfig` struct, `--int`/`--int-switch-id N` CLI flags, pcap-gen subcommand model
  - **30.2 INT RTL**: int_metadata.v (sideband metadata capture: switch_id, ingress/egress timestamps, hop_latency, queue_id, rule_idx)
  - **30.3 INT VerilogGen+Templates**: int_lut.v.tera (INT enable lookup table), has_int flag in GlobalProtocolFlags, AXI/platform template wiring
  - **30.4 pcap-gen**: src/pcap_gen.rs (~720 LOC) — protocol-aware synthetic PCAP generator from YAML rules, --count/--seed/--json/--output flags
  - **30.5 Verification+Tools**: predict_int() in Python scoreboard, SVA assertions, LINT056-057, mutations 40-41, estimate/stats/diff/doc/graph INT support
  - **30.6 Examples+Docs**: int_datacenter.yaml, pcap_gen_demo.yaml, documentation updates
  - 23 parser states, 57 lint rules, 41 mutation types, 51 examples, 90 Python scoreboard tests, 558 unit + 378 integration = 936 Rust tests
- **Phase 31**: Complete — P4 Import (Bidirectional P4 Bridge):
  - **31.1 Core Parser+CLI**: `p4-import` subcommand, line-by-line state machine parser (TopLevel/IngressControl/ActionBody/TableKeys/ConstEntries/ConstEntry), reverse field mapping for 55+ P4 fields
  - **31.2 Rewrite+Extern**: Rewrite action body parsing (15 operations), extern detection (Register/Meter/ActionSelector)
  - **31.3 Round-trip**: configs_equivalent() field-by-field comparison, 7 round-trip integration tests (allow_arp, qos, tcp_flags, arp, gre, geneve, ptp)
  - **31.4 Tool Integration**: JSON summary (import_p4_summary), clean YAML output (null-stripped), don't-care value handling
  - **31.5 Examples+Docs**: rules/examples/p4/simple_firewall.p4, datacenter_filter.p4, documentation updates
  - src/p4_import.rs (~750 LOC), 37 CLI subcommands, 602 unit + 389 integration = 991 Rust tests + 90 Python tests
- **Phase 32**: Complete — Wireshark Display Filter Import:
  - **32.1 Core+CLI+Tests**: `wireshark-import` subcommand, tokenizer + recursive descent parser + ~45 field mappings with protocol inference, bidirectional port expansion (tcp.port/udp.port), TCP flag bit accumulation, AND→merge/OR→split/NOT→invert, `--filter`/`--filter-file`/`--json`/`--default-action`/`--name` flags
  - **32.2 Examples+Docs**: 2 Wireshark filter examples (web_filter.txt, security_filter.txt), documentation updates
  - src/wireshark_import.rs (~700 LOC), 38 CLI subcommands, 638 unit + 399 integration = 1037 Rust tests + 90 Python tests
- **Phase 33**: Complete — iptables-save Import:
  - **33.1 Core Parser+CLI+Tests**: `iptables-import` subcommand, line-based iptables-save parser, protocol/port/CIDR/TCP-flags/ICMP/conntrack-state/MAC mapping, multiport expansion, DNAT/SNAT rewrite extraction, chain selection (INPUT/FORWARD/OUTPUT/all), `--json`/`-o`/`--chain`/`--name` flags
  - **33.2 Examples+Docs**: basic_firewall.rules, nat_gateway.rules, documentation updates
  - src/iptables_import.rs (~600 LOC), 39 CLI subcommands, 685 unit + 410 integration = 1095 Rust tests + 90 Python tests
- **Phase 34**: Complete — Rule Set Optimizer:
  - **34.1 Core+CLI+Tests**: `optimize` subcommand with 5 optimization passes: OPT001 dead rule removal (shadow-based), OPT002 duplicate merging (structural equality), OPT003 adjacent port consolidation (Exact+Range merging), OPT004 adjacent CIDR consolidation (prefix-pair merging), OPT005 priority renumbering (uniform 100-spacing); pipeline-aware (per-stage); stateful rules preserved; `--json`/`-o`/`--apply` flags
  - **34.2 Examples+Docs**: optimize_demo.yaml (exercises all 5 OPT passes), documentation updates
  - src/optimize.rs (~500 LOC), 40 CLI subcommands, 709 unit + 418 integration = 1127 Rust tests + 90 Python tests
- **Phase 35**: Complete — Rust Code Generation Backend (`--target rust`):
  - **35.1 Core Generator+CLI**: `src/rust_gen.rs` (~400 LOC) — protocol detection, compiled rule matchers with 55+ field conditions, CIDR/IPv6/MAC constant generation, pipeline support; `--target rust` CLI intercept with incompatible flag rejection (--axi/--conntrack/--dynamic/--rate-limit/--ports/--ptp/--rss/--int/--counters)
  - **35.2 Tera Templates**: `rust_cargo.toml.tera` (Cargo.toml with optional `afxdp` feature), `rust_filter.rs.tera` (~700 LOC) — single-file generated binary with ParsedPacket struct, frame parser (L2/QinQ/VLAN/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6/ARP/MPLS/GRE/OAM/NSH/PTP/VXLAN/GTP-U/Geneve), compiled rule matchers, priority-ordered decision logic, PCAP reader/writer, per-rule statistics (text+JSON), stdin/stdout pipe mode, AF_XDP skeleton (behind `afxdp` Cargo feature)
  - **35.3 Integration Tests+Example**: `rust_filter_demo.yaml` example (6 rules: HTTP/HTTPS/DNS/internal CIDR/high ports/ARP), 10 integration tests (basic/json/compiles/axi-rejected/conntrack-rejected/ipv6/pipeline/pcap-filter/stdout/demo-example), 17 unit tests (condition builders, protocol detection, JSON summary)
  - src/rust_gen.rs (~400 LOC), 2 Tera templates, 53 examples, 726 unit + 428 integration = 1154 Rust tests + 90 Python tests
