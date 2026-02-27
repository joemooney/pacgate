# PacGate Requirements

## Core Requirements

### Rule Definition
- REQ-001: Rules defined in YAML format with version, defaults, and rule list
- REQ-002: Each rule has a unique name, priority (0-65535), match criteria, and action (pass/drop)
- REQ-003: Default action (pass or drop) applies when no rule matches
- REQ-004: Priorities must be unique; higher priority wins on match
- REQ-005: Support stateless field matching and stateful FSM rules

### Match Fields
- REQ-010: Match on destination MAC address (exact or wildcard octets) [IMPLEMENTED]
- REQ-011: Match on source MAC address (exact or wildcard octets) [IMPLEMENTED]
- REQ-012: Match on EtherType (16-bit hex value) [IMPLEMENTED]
- REQ-013: Match on VLAN ID (12-bit, 0-4095) [IMPLEMENTED]
- REQ-014: Match on VLAN PCP (3-bit, 0-7) [IMPLEMENTED]
- REQ-015: Match on arbitrary byte offset (byte_match) — Phase 4
- REQ-016: MAC wildcard octets ("*") generate mask-based comparison [IMPLEMENTED]

### Compiler
- REQ-020: Rust CLI with `compile`, `validate`, `init`, `estimate`, `diff`, `graph`, `stats`, `lint`, and `formal` subcommands [IMPLEMENTED]
- REQ-021: `compile` generates Verilog RTL and cocotb test bench from YAML [IMPLEMENTED]
- REQ-022: `validate` checks YAML without generating output [IMPLEMENTED]
- REQ-023: Generated Verilog passes Icarus Verilog lint (`-g2012`) [IMPLEMENTED]
- REQ-024: Generated cocotb tests include positive, negative, random, and corner-case tests [IMPLEMENTED]
- REQ-025: `init` creates a well-commented starter rules file [IMPLEMENTED]
- REQ-026: `estimate` reports FPGA resource estimates (LUTs, FFs) + timing analysis for Artix-7 [IMPLEMENTED]
- REQ-027: Rule overlap and shadow detection with compile-time warnings [IMPLEMENTED]
- REQ-028: Duplicate rule name and priority validation [IMPLEMENTED]
- REQ-029: 65 Rust tests (44 unit + 21 integration) covering model, loader, validation, and full CLI [IMPLEMENTED]
- REQ-030b: `--json` flag for machine-readable output on compile/validate/estimate/diff [IMPLEMENTED]
- REQ-030c: `diff` subcommand compares two rule files (added/removed/modified rules) [IMPLEMENTED]
- REQ-030d: Compile output includes formatted rule summary table [IMPLEMENTED]
- REQ-030e: Estimate includes pipeline timing analysis (cycles, latency at 125 MHz) [IMPLEMENTED]
- REQ-030f: Rule count limit warnings for Artix-7 targets (>32 note, >64 warning) [IMPLEMENTED]
- REQ-030g: Overlap warnings captured in JSON output (not just stderr) [IMPLEMENTED]
- REQ-030h: `graph` subcommand outputs DOT (Graphviz) representation of rule set [IMPLEMENTED]
- REQ-030i: `stats` subcommand shows rule set analytics (field usage, action balance, priority spacing) [IMPLEMENTED]
- REQ-030j: Shell completions for bash/zsh/fish via `completions` subcommand [IMPLEMENTED]
- REQ-030k: 21 integration tests covering full CLI pipeline (compile, validate, estimate, diff, stats, graph, init, lint, formal, axi) [IMPLEMENTED]
- REQ-030l: `lint` subcommand for best-practice analysis (7 lint rules: ARP, broadcast, priority gaps, STP, FSM timeouts, rule count, consolidation) [IMPLEMENTED]

### Verilog Architecture
- REQ-030: Hand-written frame parser extracts Ethernet header fields [IMPLEMENTED]
- REQ-031: Frame parser handles 802.1Q VLAN-tagged frames (EtherType 0x8100) [IMPLEMENTED]
- REQ-032: Per-rule matchers are combinational (parallel evaluation, O(1) latency) [IMPLEMENTED]
- REQ-033: Priority encoder selects first-match-wins action [IMPLEMENTED]
- REQ-034: Decision output is latched until next frame starts (pkt_sof) [IMPLEMENTED]
- REQ-035: Simple streaming interface: pkt_data[7:0], pkt_valid, pkt_sof, pkt_eof [IMPLEMENTED]
- REQ-036: Target Xilinx 7-series (Artix-7), architecture-portable Verilog

### Verification
- REQ-040: cocotb simulation with Icarus Verilog [IMPLEMENTED]
- REQ-041: ARP frame (EtherType 0x0806) triggers pass when allow_arp rule is active [IMPLEMENTED]
- REQ-042: Non-matching frame triggers default action (drop in whitelist mode) [IMPLEMENTED]
- REQ-043: All cocotb tests must report PASS for acceptance [IMPLEMENTED]

## Phase 2 Requirements — Multi-Rule + Advanced Verification [IMPLEMENTED]

### Multi-Rule Support
- REQ-050: Multiple stateless rules with different match fields [IMPLEMENTED]
- REQ-051: MAC wildcard/mask matching in hardware [IMPLEMENTED]
- REQ-052: VLAN ID matching [IMPLEMENTED]
- REQ-053: Enterprise example: 7 rules, 13 tests, all PASS [IMPLEMENTED]

### Verification Framework
- REQ-055: UVM-inspired verification architecture (Driver/Monitor/Scoreboard/Coverage) [IMPLEMENTED]
- REQ-056: PacketFactory with directed, random, boundary, and corner-case frame generation [IMPLEMENTED]
- REQ-057: Scoreboard reference model with predict/check achieving 500/500 matches [IMPLEMENTED]
- REQ-058: Functional coverage model with cover points, bins, and cross coverage [IMPLEMENTED]
- REQ-059: Corner-case tests: back-to-back, jumbo, min-size, reset recovery [IMPLEMENTED]

## Phase 3 Requirements — Stateful FSM Rules [IMPLEMENTED]

- REQ-060: Stateful rules with FSM state machines [IMPLEMENTED]
- REQ-061: Timeout counters for state transitions (32-bit configurable) [IMPLEMENTED]
- REQ-062: Sequence-based matching (e.g., ARP then IPv4) [IMPLEMENTED]
- REQ-063: FSM Verilog template (rule_fsm.v.tera) [IMPLEMENTED]
- REQ-064: FSM validation (initial state exists, transitions reference valid states) [IMPLEMENTED]

## Phase 4 Requirements — Synthesis + Advanced Verification [IMPLEMENTED]

- REQ-070: Yosys synthesis targeting Artix-7 (open-source alternative to Vivado) [IMPLEMENTED]
- REQ-071: XDC constraint files for Artix-7 (125 MHz, LVCMOS33, pin assignments) [IMPLEMENTED]
- REQ-072: AXI-Stream packet interface with adapter module [IMPLEMENTED]
- REQ-073: Store-and-forward FIFO for full-frame buffering with decision-based forwarding [IMPLEMENTED]

## Advanced Verification Requirements (Research-Identified)

### Coverage-Driven Verification
- REQ-080: Generate cocotb-coverage cover points from YAML rule specification [IMPLEMENTED]
- REQ-081: Constrained random Ethernet frame generation [IMPLEMENTED]
- REQ-082: Coverage-driven test generation with runtime-adaptive randomization
- REQ-083: Coverage export to XML/YAML format with merge support across runs [IMPLEMENTED]
- REQ-084: Cross coverage for ethertype x decision and rule_index x action [IMPLEMENTED]

### Negative and Boundary Testing
- REQ-085: Auto-generate negative test frames that match no rule (verify default action) [IMPLEMENTED]
- REQ-086: Auto-generate boundary test frames (broadcast MAC, multicast, max payload, etc.) [IMPLEMENTED]

### Mutation Testing
- REQ-090: Integrate MCY (Mutation Cover with Yosys) to measure test harness quality
- REQ-091: Generate mutants of generated Verilog and run against generated cocotb tests
- REQ-092: Report mutation coverage score and identify test gaps

### Formal Verification
- REQ-095: Generate SVA assertions from YAML rule specification [IMPLEMENTED]
- REQ-096: Generate SymbiYosys .sby task files for formal property checking [IMPLEMENTED]
- REQ-097: Formal verification of mutual exclusion, completeness, latency bounds, and reset correctness [IMPLEMENTED]

### Property-Based Testing
- REQ-100: Hypothesis-generated edge-case Ethernet frames for invariant testing [IMPLEMENTED]
- REQ-101: Properties: determinism, termination, priority correctness, conservation, independence [IMPLEMENTED]

## Phase 5 Requirements — Documentation + Examples + Commercial Features [IMPLEMENTED]

### Real-World Examples
- REQ-120: 12 production-quality YAML examples covering diverse industries [IMPLEMENTED]
- REQ-121: Industrial OT boundary filter (EtherCAT, PROFINET, PTP, GOOSE) [IMPLEMENTED]
- REQ-122: Automotive Ethernet gateway (AVB/TSN, ADAS/powertrain VLANs) [IMPLEMENTED]
- REQ-123: 5G fronthaul filter (eCPRI, PTP, Sync-E) [IMPLEMENTED]
- REQ-124: Campus access control (STP guard, VoIP, vendor MAC filtering) [IMPLEMENTED]
- REQ-125: IoT edge gateway (sensor/actuator/camera VLAN isolation) [IMPLEMENTED]
- REQ-126: Stateful SYN flood detection with FSM (ARP→IPv4 pattern) [IMPLEMENTED]
- REQ-127: Stateful ARP spoofing detection with FSM (request/reply pattern) [IMPLEMENTED]

### Documentation
- REQ-130: README.md with branding, quick start, feature showcase [IMPLEMENTED]
- REQ-131: Comprehensive User's Guide with rule reference and 11+ examples [IMPLEMENTED]
- REQ-132: Comprehensive Test Guide covering all verification layers [IMPLEMENTED]
- REQ-133: 8 hands-on workshops (beginner to advanced) [IMPLEMENTED]
- REQ-134: Management slideshow (13 slides) [IMPLEMENTED]
- REQ-135: "Why PacGate?" document for skeptics and decision-makers [IMPLEMENTED]

### Commercial Features
- REQ-140: `lint` subcommand with 7 best-practice checks [IMPLEMENTED]
- REQ-141: `lint --json` output for CI/CD integration [IMPLEMENTED]
- REQ-142: Proprietary license [IMPLEMENTED]

## Phase 6 Requirements — L3/L4 + Commercial Features [IMPLEMENTED]

### L3/L4 Matching
- REQ-150: Match on IPv4 source address with CIDR prefix (e.g., "10.0.0.0/8") [IMPLEMENTED]
- REQ-151: Match on IPv4 destination address with CIDR prefix [IMPLEMENTED]
- REQ-152: Match on IP protocol number (TCP=6, UDP=17, ICMP=1, etc.) [IMPLEMENTED]
- REQ-153: Match on TCP/UDP source port (exact value) [IMPLEMENTED]
- REQ-154: Match on TCP/UDP destination port (exact value) [IMPLEMENTED]
- REQ-155: Match on TCP/UDP port range (e.g., [1024, 65535]) [IMPLEMENTED]
- REQ-156: Frame parser extended with S_IP_HDR (20-byte IPv4) and S_L4_HDR states [IMPLEMENTED]
- REQ-157: IPv4 CIDR prefix matching in hardware: (ip & mask) == (prefix & mask) [IMPLEMENTED]
- REQ-158: Port range matching in hardware: (port >= low && port <= high) [IMPLEMENTED]
- REQ-159: L3/L4 fields wired through all templates (rule_match, rule_fsm, packet_filter_top) [IMPLEMENTED]

### VXLAN Tunnel Parsing
- REQ-160: Detect VXLAN encapsulation (UDP dst port 4789) [IMPLEMENTED]
- REQ-161: Parse VXLAN header, extract 24-bit VNI [IMPLEMENTED]
- REQ-162: Match on vxlan_vni field in YAML rules [IMPLEMENTED]
- REQ-163: Frame parser S_VXLAN_HDR state (12 bytes: UDP remainder + VXLAN header) [IMPLEMENTED]

### Per-Rule Counters
- REQ-170: 64-bit packet counter per rule [IMPLEMENTED]
- REQ-171: 64-bit byte counter per rule [IMPLEMENTED]
- REQ-172: Global counters: total packets, total pass, total drop, total bytes [IMPLEMENTED]
- REQ-173: AXI4-Lite slave register interface for counter readout [IMPLEMENTED]
- REQ-174: Counter clear via AXI-Lite write [IMPLEMENTED]
- REQ-175: `--counters` flag on compile command [IMPLEMENTED]

### PCAP Import
- REQ-180: Read standard PCAP files (libpcap format, Ethernet link type) [IMPLEMENTED]
- REQ-181: Generate cocotb test stimulus (PCAP_FRAMES Python list) [IMPLEMENTED]
- REQ-182: `pcap` subcommand with --json output [IMPLEMENTED]
- REQ-183: Support big-endian and little-endian PCAP files [IMPLEMENTED]

### HTML Coverage Report
- REQ-190: Self-contained HTML coverage report with styled CSS [IMPLEMENTED]
- REQ-191: Field coverage analysis (L2/L3/L4/Tunnel layers) [IMPLEMENTED]
- REQ-192: Per-rule detail table with match field tags [IMPLEMENTED]
- REQ-193: `report` subcommand [IMPLEMENTED]

### Testing
- REQ-200: 70 Rust unit tests (model, loader, pcap) [IMPLEMENTED]
- REQ-201: 29 Rust integration tests (compile, validate, estimate, diff, stats, graph, init, lint, formal, axi, L3/L4, VXLAN, counters, pcap, report) [IMPLEMENTED]
- REQ-202: L3/L4 YAML example (l3l4_firewall.yaml, 8 rules) [IMPLEMENTED]
- REQ-203: VXLAN YAML example (vxlan_datacenter.yaml, 6 rules) [IMPLEMENTED]

### CI/Regression
- REQ-105: GitHub Actions CI pipeline with automated build/compile/simulate
- REQ-106: JUnit XML test result reporting (built into cocotb)
- REQ-107: Coverage trend tracking across CI runs
- REQ-108: Regression dashboard with coverage metrics

### cocotb 2.0 Compatibility
- REQ-110: Target cocotb 2.0+ with Logic/LogicArray types
- REQ-111: Copra type stub generation for DUT signals
- REQ-112: cocotb-coverage 2.0 compatibility
