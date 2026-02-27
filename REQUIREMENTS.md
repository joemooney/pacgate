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

## Phase 7 Requirements — Advanced Stateful Logic, Byte Matching, Multi-Port, Mermaid [IMPLEMENTED]

### Byte-Offset Matching
- REQ-210: Match on arbitrary byte offsets within packet payload (up to offset 1500) [IMPLEMENTED]
- REQ-211: Byte match with value and optional mask (hex strings) [IMPLEMENTED]
- REQ-212: Maximum 4 byte_match entries per rule [IMPLEMENTED]
- REQ-213: Byte value maximum 4 bytes per match entry [IMPLEMENTED]
- REQ-214: Mask length must equal value length when specified [IMPLEMENTED]
- REQ-215: Generated byte_capture module with per-offset capture registers [IMPLEMENTED]
- REQ-216: Byte capture valid signal asserts once all configured offsets reached [IMPLEMENTED]

### Hierarchical State Machines
- REQ-220: Nested/composite FSM states with dot-notation flattening (e.g., parent.child) [IMPLEMENTED]
- REQ-221: Maximum nesting depth of 4 levels [IMPLEMENTED]
- REQ-222: Composite states require initial_substate declaration [IMPLEMENTED]
- REQ-223: FSM variables (1-32 bit registers) with configurable reset values [IMPLEMENTED]
- REQ-224: Guard expressions on transitions (variable comparisons) [IMPLEMENTED]
- REQ-225: Transition actions (variable assignments: =, +=, -=, |=) [IMPLEMENTED]
- REQ-226: Entry/exit actions on states (fire on state transitions) [IMPLEMENTED]
- REQ-227: History support for composite states (return to last active substate) [IMPLEMENTED]
- REQ-228: Sibling state references resolved within composite states [IMPLEMENTED]

### Mermaid Import/Export
- REQ-230: Parse Mermaid stateDiagram-v2 syntax to PacGate YAML [IMPLEMENTED]
- REQ-231: Export PacGate YAML FSM rules to Mermaid stateDiagram-v2 [IMPLEMENTED]
- REQ-232: Transition label syntax: [match_fields]/action with guard support [IMPLEMENTED]
- REQ-233: Timeout from Mermaid notes (note right of state: timeout=Ncycles) [IMPLEMENTED]
- REQ-234: Composite state blocks auto-flatten with dot notation [IMPLEMENTED]
- REQ-235: CLI `from-mermaid` subcommand (Mermaid .md → YAML) [IMPLEMENTED]
- REQ-236: CLI `to-mermaid` subcommand (YAML → Mermaid stdout) [IMPLEMENTED]
- REQ-237: Round-trip structural equivalence (YAML → Mermaid → YAML) [IMPLEMENTED]

### Multi-Port Switch Fabric
- REQ-240: `--ports N` CLI flag for multi-port filter generation (default 1) [IMPLEMENTED]
- REQ-241: Per-port independent packet_filter_top instances [IMPLEMENTED]
- REQ-242: Generated multiport wrapper with arrayed per-port interfaces [IMPLEMENTED]
- REQ-243: Optional per-rule port assignment list in YAML [IMPLEMENTED]
- REQ-244: Reject empty ports list in validation [IMPLEMENTED]

### Connection Tracking
- REQ-250: ConntrackConfig model with table_size, timeout_cycles, fields [IMPLEMENTED]
- REQ-251: Hand-written conntrack_table.v with CRC-based hash, linear probing [IMPLEMENTED]
- REQ-252: Lookup and insert interfaces with per-entry timestamp timeout [IMPLEMENTED]
- REQ-253: Table size must be power of 2, timeout > 0 [IMPLEMENTED]
- REQ-254: `--conntrack` CLI flag copies RTL to output directory [IMPLEMENTED]
- REQ-255: Parameterized TABLE_SIZE, KEY_WIDTH (104-bit 5-tuple), TIMEOUT [IMPLEMENTED]

### Testing
- REQ-260: 89 Rust unit tests (model, loader, pcap, byte-match, HSM, Mermaid) [IMPLEMENTED]
- REQ-261: 36 Rust integration tests (all features through Phase 7) [IMPLEMENTED]
- REQ-262: Byte-match YAML example (byte_match.yaml) [IMPLEMENTED]
- REQ-263: Hierarchical FSM YAML example (hsm_conntrack.yaml) [IMPLEMENTED]

## Phase 8 Requirements — IPv6, Simulation, Rate Limiting, Enhanced Analysis [IMPLEMENTED]

### Packet Simulation
- REQ-270: `simulate` subcommand for software dry-run packet evaluation [IMPLEMENTED]
- REQ-271: SimPacket struct with all match fields (L2/L3/L4/IPv6/VXLAN) as Options [IMPLEMENTED]
- REQ-272: Parse packet spec string (key=value,key=value format) [IMPLEMENTED]
- REQ-273: Evaluate rules in priority order (first-match-wins), return matched rule + action [IMPLEMENTED]
- REQ-274: Per-field match breakdown in simulation results [IMPLEMENTED]
- REQ-275: `--json` output for simulate command [IMPLEMENTED]

### IPv6 Support
- REQ-280: Match on IPv6 source address with CIDR prefix (e.g., "2001:db8::/32") [IMPLEMENTED]
- REQ-281: Match on IPv6 destination address with CIDR prefix [IMPLEMENTED]
- REQ-282: Match on IPv6 next header field (e.g., 58 for ICMPv6) [IMPLEMENTED]
- REQ-283: Ipv6Prefix struct with `::` abbreviation expansion and CIDR parsing [IMPLEMENTED]
- REQ-284: IPv6 CIDR matching in hardware: 128-bit `(ip & mask) == (prefix & mask)` [IMPLEMENTED]
- REQ-285: Frame parser S_IPV6_HDR state (40-byte IPv6 header, 6-bit byte counter) [IMPLEMENTED]
- REQ-286: IPv6 parser outputs: src_ipv6[127:0], dst_ipv6[127:0], ipv6_next_header[7:0], ipv6_valid [IMPLEMENTED]
- REQ-287: IPv6 wiring through all templates (rule_match, rule_fsm, packet_filter_top) [IMPLEMENTED]
- REQ-288: IPv6 YAML example (ipv6_firewall.yaml, 6 rules) [IMPLEMENTED]

### Rate Limiting
- REQ-290: RateLimit model with pps and burst fields [IMPLEMENTED]
- REQ-291: Per-rule rate_limit in YAML (optional) [IMPLEMENTED]
- REQ-292: Token-bucket rate limiter RTL (rtl/rate_limiter.v) [IMPLEMENTED]
- REQ-293: Parameterized CLOCK_FREQ, PPS, BURST in rate limiter [IMPLEMENTED]
- REQ-294: `--rate-limit` flag on compile command [IMPLEMENTED]
- REQ-295: Rate limiter resource estimate (+50 LUTs, +64 FFs per limiter) [IMPLEMENTED]
- REQ-296: Rate-limited YAML example (rate_limited.yaml, 4 rules) [IMPLEMENTED]

### Enhanced Lint Rules
- REQ-300: LINT008 (error): Dead rule — fully shadowed by higher-priority rule with same action [IMPLEMENTED]
- REQ-301: LINT009 (warning): Unused FSM variable — declared but never referenced [IMPLEMENTED]
- REQ-302: LINT010 (warning): Unreachable FSM state — BFS from initial finds no path [IMPLEMENTED]
- REQ-303: LINT011 (info): L3/L4 rules in whitelist mode without generic IPv4 allow [IMPLEMENTED]
- REQ-304: LINT012 (info): byte_match offset > 64 — beyond typical header region [IMPLEMENTED]

### Enhanced Overlap Detection
- REQ-310: CIDR prefix containment check (10.0.0.0/8 contains 10.1.0.0/16) [IMPLEMENTED]
- REQ-311: CIDR prefix overlap check (any common addresses) [IMPLEMENTED]
- REQ-312: Port range containment check (1-1024 contains 80) [IMPLEMENTED]
- REQ-313: Port range overlap check (range intersection) [IMPLEMENTED]
- REQ-314: criteria_shadows() uses CIDR containment + port containment [IMPLEMENTED]
- REQ-315: criteria_overlaps() uses CIDR overlap + port range overlap [IMPLEMENTED]

### Testing
- REQ-320: 125 Rust unit tests (through Phase 8) [IMPLEMENTED]
- REQ-321: 45 Rust integration tests (through Phase 8) [IMPLEMENTED]
- REQ-322: IPv6 simulation tests (CIDR matching, next_header, all-fields) [IMPLEMENTED]
- REQ-323: Rate-limited compile/JSON integration tests [IMPLEMENTED]

## Phase 9 Requirements — PCAP Analysis, Synthesis, Advanced Tests, Templates [IMPLEMENTED]

### PCAP Traffic Analysis
- REQ-330: Parse PCAP files and extract L2/L3/L4/VXLAN fields from each frame [IMPLEMENTED]
- REQ-331: Aggregate packets into 5-tuple flows with statistics (count, bytes, timing) [IMPLEMENTED]
- REQ-332: Analyze traffic: protocol distribution, top talkers, port usage [IMPLEMENTED]
- REQ-333: Suggest rules in whitelist mode (group by service, merge IPs) [IMPLEMENTED]
- REQ-334: Suggest rules in blacklist mode (detect floods, port scans) [IMPLEMENTED]
- REQ-335: Auto mode: pick whitelist/blacklist based on flow count [IMPLEMENTED]
- REQ-336: Generate valid PacGate YAML from suggestions [IMPLEMENTED]
- REQ-337: `pcap-analyze` subcommand with --mode, --output-yaml, --max-rules, --json [IMPLEMENTED]

### Synthesis Project Generation
- REQ-340: Generate Yosys synthesis script targeting Artix-7, iCE40, ECP5 [IMPLEMENTED]
- REQ-341: Generate Vivado TCL project script [IMPLEMENTED]
- REQ-342: Generate XDC timing constraints (clock, I/O delays) [IMPLEMENTED]
- REQ-343: Generate synthesis Makefile with yosys/vivado targets [IMPLEMENTED]
- REQ-344: Collect RTL file list based on feature flags (AXI, counters, conntrack, rate-limit, ports) [IMPLEMENTED]
- REQ-345: Parse Yosys synthesis log for resource utilization [IMPLEMENTED]
- REQ-346: Parse Vivado utilization report [IMPLEMENTED]
- REQ-347: `synth` subcommand with --target, --part, --clock-mhz, feature flags, --parse-results, --json [IMPLEMENTED]

### Advanced Test Generation
- REQ-350: IPv6 directed test generation in cocotb (Ipv6Header construction) [IMPLEMENTED]
- REQ-351: IPv6 fields wired into cocotb test case HashMap (src_ipv6, dst_ipv6, ipv6_next_header) [IMPLEMENTED]
- REQ-352: Rate limiter standalone cocotb testbench (5 tests) [IMPLEMENTED]
- REQ-353: Rate limiter test Makefile [IMPLEMENTED]
- REQ-354: L3/L4/IPv6 coverage bins (ip_protocol, dst_port_range, ipv6_address_type, l3_type) [IMPLEMENTED]
- REQ-355: Coverage-directed test generation (CoverageDirector class) [IMPLEMENTED]
- REQ-356: IPv6 packet factory methods (ipv6_tcp, ipv6_udp, ipv6_icmp, ipv6_link_local) [IMPLEMENTED]
- REQ-357: IPv4 packet factory methods (ipv4_tcp, ipv4_udp) [IMPLEMENTED]

### Mutation Testing
- REQ-360: Mutation engine: flip action on each rule [IMPLEMENTED]
- REQ-361: Mutation engine: remove each rule [IMPLEMENTED]
- REQ-362: Mutation engine: swap priorities of adjacent rules [IMPLEMENTED]
- REQ-363: Mutation engine: flip default action [IMPLEMENTED]
- REQ-364: Mutation engine: remove ethertype match field [IMPLEMENTED]
- REQ-365: Generate mutation report as JSON [IMPLEMENTED]
- REQ-366: `mutate` subcommand with --json, generates mutated YAML + Verilog + tests in gen/mutants/ [IMPLEMENTED]

### Rule Templates
- REQ-370: Rule template library with 7 built-in templates [IMPLEMENTED]
- REQ-371: Template variable substitution (${var} patterns with defaults) [IMPLEMENTED]
- REQ-372: Template categories: access-control, security, rate-limiting, diagnostics, segmentation, application, iot [IMPLEMENTED]
- REQ-373: `template list` subcommand with --category filter and --json [IMPLEMENTED]
- REQ-374: `template show` subcommand with variable details and YAML preview [IMPLEMENTED]
- REQ-375: `template apply` subcommand with --set key=value and -o output [IMPLEMENTED]
- REQ-376: Built-in templates: allow_management, block_bogons, rate_limit_dns, allow_icmp, vlan_isolation, web_server, iot_gateway [IMPLEMENTED]

### HTML Documentation
- REQ-380: Generate styled HTML documentation from rule set [IMPLEMENTED]
- REQ-381: Rule summary table (name, priority, type, action, key match) [IMPLEMENTED]
- REQ-382: Per-rule detail sections with all match criteria [IMPLEMENTED]
- REQ-383: Architecture diagram (ASCII) [IMPLEMENTED]
- REQ-384: Warning display section [IMPLEMENTED]
- REQ-385: `doc` subcommand with -o output path [IMPLEMENTED]

### Testing
- REQ-390: 181 Rust unit tests (through Phase 10) [IMPLEMENTED]
- REQ-391: 82 Rust integration tests (through Phase 10) [IMPLEMENTED]
- REQ-392: PCAP analysis integration tests (basic, json, yaml output, empty error) [IMPLEMENTED]
- REQ-393: Synthesis integration tests (yosys, vivado, json output) [IMPLEMENTED]
- REQ-394: Mutation integration tests (json report, generate mutants, multi-rule) [IMPLEMENTED]
- REQ-395: Template integration tests (list, list json, show, apply, apply with vars) [IMPLEMENTED]
- REQ-396: Doc integration tests (html generation, enterprise rules) [IMPLEMENTED]

### Phase 10: Verification Completeness
- REQ-400: Scoreboard supports L3/L4/IPv6/VXLAN/byte-match matching fields [IMPLEMENTED]
- REQ-401: Scoreboard Rule dataclass extended with src_ip, dst_ip, ip_protocol, ports, port_ranges, vxlan_vni, ipv6, byte_match [IMPLEMENTED]
- REQ-402: Helper functions: ipv4_matches_cidr, ipv6_matches_cidr, port_matches, byte_match_matches [IMPLEMENTED]
- REQ-403: Scoreboard predict/check accept optional extracted dict for L3/L4 fields [IMPLEMENTED]
- REQ-404: Generated test harness builds proper IPv4/TCP/UDP headers for L3/L4 rules [IMPLEMENTED]
- REQ-405: Generated test harness builds proper IPv6 headers with L4 payloads [IMPLEMENTED]
- REQ-406: Random test generates L3/L4 headers for 50% of IPv4/IPv6 frames [IMPLEMENTED]
- REQ-407: Simulator supports raw_bytes field and byte_match rule evaluation [IMPLEMENTED]
- REQ-408: Simulator byte_match: (payload[offset] & mask) == (value & mask) [IMPLEMENTED]
- REQ-409: Hypothesis strategies for IPv4/IPv6 addresses, port numbers, L3/L4 frames [IMPLEMENTED]
- REQ-410: Property test: L3/L4 determinism check [IMPLEMENTED]
- REQ-411: Formal assertions: IPv6 CIDR stability, port range boundary, rate limiter, byte-match [IMPLEMENTED]
- REQ-412: Conntrack cocotb tests: new_flow, return_traffic, timeout, hash_collision, table_full [IMPLEMENTED]
- REQ-413: generate_conntrack_tests() in cocotb_gen.rs when --conntrack flag set [IMPLEMENTED]
- REQ-414: Port range format: Python tuple "(low, high)" not string "low-high" [IMPLEMENTED]
- REQ-415: 23 Python scoreboard unit tests [IMPLEMENTED]
- REQ-416: CI pipeline: python-tests, conntrack-compile, multi-flag-compile jobs [IMPLEMENTED]
- REQ-417: CI simulate matrix expanded: l3l4_firewall, ipv6_firewall examples [IMPLEMENTED]
