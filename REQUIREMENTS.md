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
- REQ-110: Target cocotb 2.0+ with `int(.value)` pattern (no `.value.integer`) [IMPLEMENTED]
- REQ-111: Pin cocotb>=2.0.0 + cocotb-tools in CI/requirements [IMPLEMENTED]
- REQ-112: Generate `run_sim.py` runner scripts using `cocotb_tools.runner` API [IMPLEMENTED]
- REQ-113: Runner scripts generated for all test modes (main, AXI, conntrack, rate limiter, dynamic) [IMPLEMENTED]
- REQ-114: Runner includes platform width converter sources when `--target` is set [IMPLEMENTED]
- REQ-115: Makefiles preserved for backward compatibility alongside runners [IMPLEMENTED]
- REQ-116: Runner supports SIM environment variable override (icarus, verilator, etc.) [IMPLEMENTED]

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

## Phase 11 Requirements — Reachability Analysis, PCAP Output, Benchmarking, HTML Diff [IMPLEMENTED]

### Reachability Analysis
- REQ-500: `reachability` subcommand analyzing all rules for shadowed/unreachable/redundant conditions [IMPLEMENTED]
- REQ-501: Detect fully shadowed rules (a higher-priority rule matches every packet this rule would match) [IMPLEMENTED]
- REQ-502: Detect redundant rules (logically equivalent to another rule at different priority) [IMPLEMENTED]
- REQ-503: Report reachability results with rule names and explanations [IMPLEMENTED]
- REQ-504: `--json` output for reachability command [IMPLEMENTED]

### PCAP Output from Simulation
- REQ-510: `--pcap-out <file>` flag on `simulate` subcommand [IMPLEMENTED]
- REQ-511: Write Wireshark-compatible PCAP file (libpcap format, global header + per-packet records) [IMPLEMENTED]
- REQ-512: Each simulated packet written as an Ethernet frame in the PCAP output [IMPLEMENTED]
- REQ-513: PCAP global header: magic 0xa1b2c3d4, version 2.4, link type LINKTYPE_ETHERNET (1) [IMPLEMENTED]
- REQ-514: `src/pcap_writer.rs` — dedicated PCAP writer module [IMPLEMENTED]

### Performance Benchmarking
- REQ-520: `bench` subcommand measuring compile time across synthetic rule sets [IMPLEMENTED]
- REQ-521: Simulation throughput measurement (packets/sec) across rule set sizes [IMPLEMENTED]
- REQ-522: LUT/FF scaling curves from 10 to 500 synthetic rules [IMPLEMENTED]
- REQ-523: ASCII bar chart output for terminal visualization [IMPLEMENTED]
- REQ-524: `--json` output for bench command with full metric tables [IMPLEMENTED]
- REQ-525: `src/benchmark.rs` — dedicated benchmarking engine [IMPLEMENTED]

### HTML Diff Visualization
- REQ-530: `--html <file>` flag on `diff` subcommand [IMPLEMENTED]
- REQ-531: Styled HTML diff report with color-coded additions (green), removals (red), modifications (yellow) [IMPLEMENTED]
- REQ-532: Side-by-side comparison of old and new rule sets [IMPLEMENTED]
- REQ-533: `templates/diff_report.html.tera` — Tera template for HTML diff rendering [IMPLEMENTED]
- REQ-534: PartialEq derived on PortMatch in model.rs for diff comparison [IMPLEMENTED]

### Testing
- REQ-540: 195 Rust unit tests (through Phase 11) [IMPLEMENTED]
- REQ-541: 92 Rust integration tests (through Phase 11) [IMPLEMENTED]
- REQ-542: Reachability integration tests (basic, json output) [IMPLEMENTED]
- REQ-543: PCAP output integration tests (simulate --pcap-out) [IMPLEMENTED]
- REQ-544: Bench integration tests (basic, json) [IMPLEMENTED]
- REQ-545: HTML diff integration tests (diff --html) [IMPLEMENTED]

## Phase 12 Requirements — Protocol Extensions: GTP-U, MPLS, IGMP/MLD [IMPLEMENTED]

### GTP-U Tunnel Parsing
- REQ-600: Detect GTP-U encapsulation (UDP dst port 2152) [IMPLEMENTED]
- REQ-601: Parse 8-byte GTP-U header, extract 32-bit TEID [IMPLEMENTED]
- REQ-602: Match on gtp_teid field in YAML rules [IMPLEMENTED]
- REQ-603: Frame parser S_GTP_HDR state for GTP-U header extraction [IMPLEMENTED]
- REQ-604: GTP-U TEID matching in hardware: exact 32-bit comparison [IMPLEMENTED]
- REQ-605: GTP-U wiring through all templates (rule_match, rule_fsm, packet_filter_top) [IMPLEMENTED]
- REQ-606: Simulator support for gtp_teid field matching [IMPLEMENTED]
- REQ-607: GTP-U YAML example (gtp_5g.yaml) [IMPLEMENTED]

### MPLS Label Stack
- REQ-610: Detect MPLS encapsulation (EtherType 0x8847 unicast, 0x8848 multicast) [IMPLEMENTED]
- REQ-611: Parse MPLS label entry: 20-bit label, 3-bit TC, 1-bit BOS, 8-bit TTL [IMPLEMENTED]
- REQ-612: Match on mpls_label (20-bit, 0-1048575) in YAML rules [IMPLEMENTED]
- REQ-613: Match on mpls_tc (3-bit, 0-7) in YAML rules [IMPLEMENTED]
- REQ-614: Match on mpls_bos (1-bit, bottom-of-stack flag) in YAML rules [IMPLEMENTED]
- REQ-615: Frame parser S_MPLS_HDR state for MPLS header extraction [IMPLEMENTED]
- REQ-616: MPLS field matching in hardware: label/TC/BOS comparators [IMPLEMENTED]
- REQ-617: Simulator support for mpls_label, mpls_tc, mpls_bos field matching [IMPLEMENTED]
- REQ-618: MPLS YAML example (mpls_network.yaml) [IMPLEMENTED]

### IGMP/MLD Multicast
- REQ-620: Detect IGMP packets (IPv4 protocol number 2) [IMPLEMENTED]
- REQ-621: Extract IGMP type byte from IGMP header [IMPLEMENTED]
- REQ-622: Match on igmp_type field in YAML rules [IMPLEMENTED]
- REQ-623: Detect MLD packets (ICMPv6 next_header 58, types 130-132) [IMPLEMENTED]
- REQ-624: Extract MLD type from ICMPv6 header [IMPLEMENTED]
- REQ-625: Match on mld_type field in YAML rules [IMPLEMENTED]
- REQ-626: Frame parser S_IGMP_HDR state for IGMP/MLD header extraction [IMPLEMENTED]
- REQ-627: IGMP/MLD field matching in hardware: exact type byte comparison [IMPLEMENTED]
- REQ-628: Simulator support for igmp_type, mld_type field matching [IMPLEMENTED]
- REQ-629: Multicast YAML example (multicast.yaml) [IMPLEMENTED]

### Protocol Extension Infrastructure
- REQ-630: Consistent global protocol flags in Verilog port lists (gtp_valid, mpls_valid, igmp_valid, mld_valid) [IMPLEMENTED]
- REQ-631: New match fields added to MatchCriteria model struct [IMPLEMENTED]
- REQ-632: YAML loader validation for new field value ranges [IMPLEMENTED]
- REQ-633: Verilog generation templates updated for new protocol fields [IMPLEMENTED]
- REQ-634: Cocotb test generation supports new protocol match fields [IMPLEMENTED]

### Testing
- REQ-640: 214 Rust unit tests (through Phase 12) [IMPLEMENTED]
- REQ-641: 105 Rust integration tests (through Phase 12) [IMPLEMENTED]
- REQ-642: GTP-U integration tests (compile, simulate, json) [IMPLEMENTED]
- REQ-643: MPLS integration tests (compile, simulate, label/TC/BOS matching) [IMPLEMENTED]
- REQ-644: IGMP/MLD integration tests (compile, simulate, multicast type matching) [IMPLEMENTED]
- REQ-645: All 21 YAML examples compile and lint clean [IMPLEMENTED]

## Phase 13 Requirements — Verification Framework Enhancements [IMPLEMENTED]

### Coverage Framework Wiring
- REQ-700: Pass L3/L4 kwargs (ip_protocol, dst_port, ipv6_src) to coverage.sample() in generated test harness [IMPLEMENTED]
- REQ-701: Wire CoverageDirector into random test (100 closure packets after 500 random) [IMPLEMENTED]
- REQ-702: Export coverage XML (coverage.save_xml("coverage.xml")) at end of random test [IMPLEMENTED]
- REQ-703: GTP-U/MPLS/IGMP/MLD fields plumbed into scoreboard_rules template variable [IMPLEMENTED]
- REQ-704: GTP-U/MPLS/IGMP/MLD fields plumbed into test_cases template variable [IMPLEMENTED]
- REQ-705: GTP-U/MPLS/multicast fields rendered in build_scoreboard() template [IMPLEMENTED]

### Enhanced Property Tests
- REQ-710: Wire check_cidr_boundary Hypothesis test into generated test_properties.py [IMPLEMENTED]
- REQ-711: Wire check_port_range_boundary Hypothesis test into generated test_properties.py [IMPLEMENTED]
- REQ-712: Wire check_ipv6_cidr_match Hypothesis test into generated test_properties.py [IMPLEMENTED]
- REQ-713: Enhanced boundary property functions with rule-aware validation [IMPLEMENTED]

### Boundary + Negative Tests
- REQ-720: Auto-generate CIDR boundary test cases (IP just outside prefix) [IMPLEMENTED]
- REQ-721: Auto-generate port boundary test cases (port just outside range) [IMPLEMENTED]
- REQ-722: Formally-derived negative test frame (unused ethertype selection) [IMPLEMENTED]
- REQ-723: generate_boundary_ip_outside() helper for CIDR boundary IP calculation [IMPLEMENTED]
- REQ-724: generate_boundary_port_outside() helper for port boundary calculation [IMPLEMENTED]

### MCY Verilog Mutation Testing
- REQ-730: `mcy` subcommand generating MCY config + test runner script [IMPLEMENTED]
- REQ-731: mcy.cfg.tera template with [options], [script], [logic], [test], [report] sections [IMPLEMENTED]
- REQ-732: test_mutation.sh.tera template for mutation test runner [IMPLEMENTED]
- REQ-733: mcy_gen.rs module with generate_mcy_config() and generate_mcy_report() [IMPLEMENTED]
- REQ-734: `--run` flag on mcy subcommand (runs MCY binary if available) [IMPLEMENTED]
- REQ-735: `--json` flag on mcy subcommand for JSON output [IMPLEMENTED]

### Mutation Kill-Rate Runner
- REQ-736: `--run` flag on mutate subcommand (compile + lint each mutant, report kill rate) [IMPLEMENTED]
- REQ-737: MutationTestReport struct with total/killed/survived/errors/kill_rate/details [IMPLEMENTED]
- REQ-738: MutantResult struct per mutant (name, status, description) [IMPLEMENTED]
- REQ-739: Mutation kill-rate: iverilog lint on each mutant's generated Verilog [IMPLEMENTED]

### CI Improvements
- REQ-740: Install hypothesis in CI (python-tests and simulate jobs) [IMPLEMENTED]
- REQ-741: JUnit XML output for pytest invocations [IMPLEMENTED]
- REQ-742: Property test step in simulate jobs [IMPLEMENTED]
- REQ-743: Coverage XML artifact upload in simulate jobs [IMPLEMENTED]
- REQ-744: requirements.txt with pinned Python dependencies [IMPLEMENTED]

### Testing
- REQ-745: 218 Rust unit tests (through Phase 13) [IMPLEMENTED]
- REQ-746: 122 Rust integration tests (through Phase 13) [IMPLEMENTED]
- REQ-747: Coverage framework integration tests (CoverageDirector, save_xml, kwargs) [IMPLEMENTED]
- REQ-748: Boundary test integration tests (CIDR, port, negative derived) [IMPLEMENTED]
- REQ-749: MCY integration tests (config generation, JSON output, script content) [IMPLEMENTED]
- REQ-750: Mutation --run integration tests (JSON and human-readable output) [IMPLEMENTED]

## Phase 14 Requirements — Protocol Verification Completeness [IMPLEMENTED]

### Python Verification Framework
- REQ-800: Scoreboard Rule dataclass extended with gtp_teid, mpls_label, mpls_tc, mpls_bos, igmp_type, mld_type fields [IMPLEMENTED]
- REQ-801: Scoreboard matches() supports exact-value comparison for all 6 protocol fields [IMPLEMENTED]
- REQ-802: PacketFactory.gtp_u() constructs Ethernet+IPv4+UDP(2152)+GTP header with TEID [IMPLEMENTED]
- REQ-803: PacketFactory.mpls() constructs Ethernet(0x8847)+MPLS label entry (label/TC/BOS/TTL) [IMPLEMENTED]
- REQ-804: PacketFactory.igmp() constructs Ethernet+IPv4(proto=2)+IGMP header with type [IMPLEMENTED]
- REQ-805: PacketFactory.mld() constructs Ethernet+IPv6(next_header=58)+ICMPv6 MLD with type [IMPLEMENTED]
- REQ-806: 13 Python scoreboard unit tests for GTP/MPLS/IGMP/MLD matching [IMPLEMENTED]

### Test Template Branches
- REQ-810: Directed test branches for GTP-U (teid), MPLS (label/tc/bos), IGMP, MLD in test_harness.py.tera [IMPLEMENTED]
- REQ-811: Random test generation includes GTP-U/MPLS/IGMP/MLD protocol packets (10% probability) [IMPLEMENTED]
- REQ-812: has_igmp and has_mld feature flags plumbed through cocotb_gen.rs to template context [IMPLEMENTED]

### Formal Assertions
- REQ-820: SVA assertion blocks for GTP-U decision stability (conditional on has_gtp_rules) [IMPLEMENTED]
- REQ-821: SVA assertion blocks for MPLS decision stability (conditional on has_mpls_rules) [IMPLEMENTED]
- REQ-822: SVA assertion blocks for IGMP decision stability (conditional on has_igmp_rules) [IMPLEMENTED]
- REQ-823: SVA assertion blocks for MLD decision stability (conditional on has_mld_rules) [IMPLEMENTED]
- REQ-824: Feature flag computation in formal_gen.rs for all 4 protocol types [IMPLEMENTED]

### Analysis Tool Completeness
- REQ-830: Shadow detection (criteria_shadows) covers gtp_teid, mpls_label, mpls_tc, mpls_bos, igmp_type, mld_type, vxlan_vni [IMPLEMENTED]
- REQ-831: Overlap detection (criteria_overlaps) covers same 7 fields [IMPLEMENTED]
- REQ-832: stats command reports usage of GTP/MPLS/IGMP/MLD fields [IMPLEMENTED]
- REQ-833: graph command includes protocol fields in DOT node labels [IMPLEMENTED]
- REQ-834: diff command detects changes to all protocol fields (GTP/MPLS/IGMP/MLD) [IMPLEMENTED]
- REQ-835: diff command detects L3/L4/IPv6 field changes (src_ip, dst_ip, ip_protocol, src_port, dst_port, vxlan_vni, src_ipv6, dst_ipv6, ipv6_next_header) — bug fix [IMPLEMENTED]
- REQ-836: HTML diff includes all protocol fields in criteria strings and field change detection [IMPLEMENTED]
- REQ-837: estimate includes LUT/FF costs for GTP-U (32-bit), MPLS (label/TC/BOS), IGMP/MLD (8-bit) [IMPLEMENTED]
- REQ-838: doc command renders protocol fields in match criteria display [IMPLEMENTED]

### Testing
- REQ-840: 218 Rust unit tests (through Phase 14) [IMPLEMENTED]
- REQ-841: 137 Rust integration tests (through Phase 14) [IMPLEMENTED]
- REQ-842: 36 Python scoreboard unit tests (through Phase 14) [IMPLEMENTED]
- REQ-843: Integration tests for stats/graph/diff/estimate/doc with protocol fields [IMPLEMENTED]
- REQ-844: Integration test verifying L3/L4 diff bug fix (src_ip, dst_port changes detected) [IMPLEMENTED]

## Phase 15 Requirements — Verification Depth & Tool Completeness [IMPLEMENTED]

### Reachability Analysis
- REQ-900: Reachability analysis includes 8 additional protocol fields (vlan_pcp, ipv6_next_header, gtp_teid, mpls_label, mpls_tc, mpls_bos, igmp_type, mld_type) [IMPLEMENTED]
- REQ-901: Stateful rules tracked in ReachabilityReport.stateful_rules instead of silently skipped [IMPLEMENTED]
- REQ-902: Stateful rules section displayed in format_report() output [IMPLEMENTED]
- REQ-903: Protocol fields (gtp_teid, mpls_label, igmp_type, mld_type) shown in query_by_action descriptions [IMPLEMENTED]

### Mutation Testing
- REQ-910: 11 mutation types (6 new: widen_src_ip, shift_dst_port, remove_gtp_teid, remove_mpls_label, remove_igmp_type, remove_vxlan_vni) [IMPLEMENTED]
- REQ-911: widen_src_ip mutation reduces CIDR prefix by 8 bits for rules with prefix > /8 [IMPLEMENTED]
- REQ-912: shift_dst_port mutation increments exact dst_port by 1 [IMPLEMENTED]
- REQ-913: remove_* mutations set protocol fields to None for field-level sensitivity testing [IMPLEMENTED]

### Coverage Model
- REQ-920: 5 new CoverPoints: tunnel_type, mpls_present, igmp_type_range, mld_type_range, gtp_teid_range [IMPLEMENTED]
- REQ-921: tunnel_x_decision cross-coverage tracking [IMPLEMENTED]
- REQ-922: sample() reads vxlan_vni, gtp_teid, mpls_label, igmp_type, mld_type from kwargs [IMPLEMENTED]
- REQ-923: CoverageDirector has 5 protocol generators for targeted packet generation [IMPLEMENTED]

### Conntrack Assertions
- REQ-930: test_conntrack_return_traffic asserts hit==0 (asymmetric hash) [IMPLEMENTED]
- REQ-931: test_conntrack_timeout asserts lookup completes (DUT not stuck) [IMPLEMENTED]
- REQ-932: test_conntrack_hash_collision asserts both flows found (and, not or) [IMPLEMENTED]
- REQ-933: test_conntrack_table_full asserts lookup completes under overflow [IMPLEMENTED]

### Hypothesis Strategies
- REQ-940: 4 Hypothesis strategies for protocol frames: gtp_u_frames, mpls_frames, igmp_frames, mld_frames [IMPLEMENTED]
- REQ-941: check_tunnel_determinism and check_protocol_determinism property functions [IMPLEMENTED]
- REQ-942: All 9 property checks wired in run_property_tests() with L3/L4 extracted fields [IMPLEMENTED]

### Lint Rules
- REQ-950: LINT013: GTP-U without UDP prerequisite (ip_protocol:17, dst_port:2152) [IMPLEMENTED]
- REQ-951: LINT014: MPLS without MPLS EtherType (0x8847/0x8848) [IMPLEMENTED]
- REQ-952: LINT015: IGMP without ip_protocol:2 or MLD without ipv6_next_header:58 [IMPLEMENTED]

### CI Pipeline
- REQ-960: Simulate matrix expanded from 4 to 8 examples (gtp_5g, mpls_network, multicast, vxlan_datacenter) [IMPLEMENTED]
- REQ-961: Property test step uses continue-on-error instead of || true [IMPLEMENTED]

### Testing
- REQ-970: 237 Rust unit tests (through Phase 16) [IMPLEMENTED]
- REQ-971: 151 Rust integration tests (through Phase 16) [IMPLEMENTED]
- REQ-972: 47 Python scoreboard unit tests (through Phase 16) [IMPLEMENTED]
- REQ-973: Integration tests for LINT013/014/015 and reachability protocol fields [IMPLEMENTED]

## Phase 16 — Simulator Completeness & Verification Depth

### Rate Limit Simulation
- REQ-1000: SimRateLimitState with token-bucket per rate-limited rule [IMPLEMENTED]
- REQ-1001: Token refill based on PPS rate and elapsed time, capped at burst [IMPLEMENTED]
- REQ-1002: simulate_with_rate_limit() applies rate limiting after rule match [IMPLEMENTED]
- REQ-1003: Exhausted tokens return default action with rule_name "rate_limited" [IMPLEMENTED]

### Connection Tracking Simulation
- REQ-1010: SimConntrackTable with 5-tuple hashing (src/dst IP, protocol, src/dst port) [IMPLEMENTED]
- REQ-1011: Reverse-flow lookup for return traffic with timeout check [IMPLEMENTED]
- REQ-1012: simulate_stateful() combines rate-limit and conntrack evaluation [IMPLEMENTED]

### Stateful CLI Flag
- REQ-1020: --stateful flag on simulate subcommand enables rate-limit + conntrack [IMPLEMENTED]
- REQ-1021: JSON output includes rate_limited and stateful fields when --stateful [IMPLEMENTED]

### Formal Assertion Strengthening
- REQ-1030: Rate-limit SVA: assert rate_limiter_drop → !decision_pass [IMPLEMENTED]
- REQ-1031: GTP prerequisite: per-rule assert match → parsed_ip_protocol == UDP [IMPLEMENTED]
- REQ-1032: MPLS bounds: assert TC <= 7 and label <= 20-bit when valid [IMPLEMENTED]
- REQ-1033: IGMP prerequisite: per-rule assert match → ip_protocol == 2 [IMPLEMENTED]
- REQ-1034: MLD prerequisite: per-rule assert match → ipv6_next_header == 58 [IMPLEMENTED]
- REQ-1035: Protocol cover statements (parsed_gtp_valid, parsed_mpls_valid, etc.) [IMPLEMENTED]

### Protocol Property Tests
- REQ-1040: Generated test_properties.py includes GTP/MPLS/IGMP/MLD Hypothesis tests when rules use protocol fields [IMPLEMENTED]
- REQ-1041: Protocol strategies (gtp_u_frames, mpls_frames, igmp_frames, mld_frames) imported into generated tests [IMPLEMENTED]

### Documentation Fix
- REQ-1050: byte_match fields displayed in HTML doc output [IMPLEMENTED]

### CI Pipeline
- REQ-1060: conntrack-simulate job: compile + cocotb simulation of hsm_conntrack [IMPLEMENTED]
- REQ-1061: formal-generate job: compile + formal + verify SVA assertions [IMPLEMENTED]
- REQ-1062: rate-limit-simulate job: compile + simulate --stateful [IMPLEMENTED]

### Testing
- REQ-1070: 237 Rust unit tests (through Phase 16) [IMPLEMENTED]
- REQ-1071: 151 Rust integration tests (through Phase 16) [IMPLEMENTED]
- REQ-1072: 47 Python scoreboard unit tests (through Phase 16) [IMPLEMENTED]

## Phase 17: Runtime-Updateable Flow Tables

### CLI Flags
- REQ-1100: `--dynamic` compile flag replaces static per-rule matchers with register-based flow table [IMPLEMENTED]
- REQ-1101: `--dynamic-entries N` flag sets max flow table entries (1-256, default 16) [IMPLEMENTED]
- REQ-1102: `--dynamic` incompatible with stateful/FSM rules (compile-time error) [IMPLEMENTED]
- REQ-1103: `--dynamic` incompatible with `--conntrack` (compile-time error) [IMPLEMENTED]
- REQ-1104: `--dynamic` V1 scope: reject IPv6, GTP-U, MPLS, IGMP/MLD, byte_match, VXLAN rules [IMPLEMENTED]

### Flow Table RTL
- REQ-1110: flow_table.v module with NUM_ENTRIES parameter (register-based match entries) [IMPLEMENTED]
- REQ-1111: Per-entry match fields: ethertype, dst_mac, src_mac, vlan_id, ip_protocol, src_ip, dst_ip, src/dst port range [IMPLEMENTED]
- REQ-1112: Per-entry valid, action, priority registers [IMPLEMENTED]
- REQ-1113: Parallel combinational matching across all entries (O(1) latency) [IMPLEMENTED]
- REQ-1114: Priority encoder selects highest-priority matching entry [IMPLEMENTED]
- REQ-1115: AXI-Lite write interface with staging registers + COMMIT for atomic updates [IMPLEMENTED]
- REQ-1116: AXI-Lite read interface for entry inspection [IMPLEMENTED]
- REQ-1117: Initial values loaded from YAML rules at reset [IMPLEMENTED]

### Dynamic Top-Level
- REQ-1120: packet_filter_dynamic_top.v wires frame_parser → flow_table (no per-rule matchers) [IMPLEMENTED]
- REQ-1121: Same packet interface as static mode (drop-in compatible) [IMPLEMENTED]
- REQ-1122: AXI-Lite port passthrough for flow table updates [IMPLEMENTED]

### cocotb Tests
- REQ-1130: test_initial_rules — verify YAML rules work after reset [IMPLEMENTED]
- REQ-1131: test_axi_lite_modify_entry — modify entry via AXI-Lite, verify new behavior [IMPLEMENTED]
- REQ-1132: test_add_new_entry — enable previously-invalid entry [IMPLEMENTED]
- REQ-1133: test_disable_entry — set valid=0, verify no match [IMPLEMENTED]
- REQ-1134: test_commit_atomicity — partial staging doesn't take effect until commit [IMPLEMENTED]
- REQ-1135: test_priority_ordering — higher priority entry wins [IMPLEMENTED]

### Estimator, Lint, Formal
- REQ-1140: `estimate --dynamic` shows per-entry LUT/FF resource usage [IMPLEMENTED]
- REQ-1141: LINT016 warns when --dynamic-entries > 64 (high resource usage) [IMPLEMENTED]
- REQ-1142: LINT017 info message about V1 field limitations [IMPLEMENTED]
- REQ-1143: `formal --dynamic` generates SVA assertions for rule index bounds, decision stability [IMPLEMENTED]

### Example
- REQ-1150: dynamic_firewall.yaml example with 5 L2/L3/L4 rules [IMPLEMENTED]

### Testing
- REQ-1160: 250 Rust unit tests (through Phase 18) [IMPLEMENTED]
- REQ-1161: 181 Rust integration tests (through Phase 18) [IMPLEMENTED]
- REQ-1162: 47 Python scoreboard unit tests (through Phase 18) [IMPLEMENTED]

## Phase 18 — Packet Rewrite Actions

### Rewrite Data Model
- REQ-1200: `rewrite:` field on rules with list of rewrite operations [IMPLEMENTED]
- REQ-1201: `set_dst_mac` rewrite operation — overwrite destination MAC address [IMPLEMENTED]
- REQ-1202: `set_src_mac` rewrite operation — overwrite source MAC address [IMPLEMENTED]
- REQ-1203: `set_vlan_id` rewrite operation — overwrite 12-bit VLAN ID [IMPLEMENTED]
- REQ-1204: `set_ttl` rewrite operation — set IPv4 TTL to specific value [IMPLEMENTED]
- REQ-1205: `dec_ttl` rewrite operation — decrement IPv4 TTL by 1 [IMPLEMENTED]
- REQ-1206: `set_src_ip` rewrite operation — overwrite source IPv4 address (NAT) [IMPLEMENTED]
- REQ-1207: `set_dst_ip` rewrite operation — overwrite destination IPv4 address (NAT) [IMPLEMENTED]
- REQ-1208: RewriteAction data model with YAML parsing and serde deserialization [IMPLEMENTED]

### Rewrite Validation
- REQ-1210: Validate MAC addresses in set_dst_mac/set_src_mac (6-octet format) [IMPLEMENTED]
- REQ-1211: Validate VLAN ID in set_vlan_id (0-4095) [IMPLEMENTED]
- REQ-1212: Validate TTL value in set_ttl (1-255) [IMPLEMENTED]
- REQ-1213: Validate IPv4 address format in set_src_ip/set_dst_ip [IMPLEMENTED]
- REQ-1214: Rewrite actions only permitted on rules with action: pass [IMPLEMENTED]

### Frame Parser Extensions
- REQ-1220: Frame parser extracts ip_ttl (8-bit) from IPv4 header [IMPLEMENTED]
- REQ-1221: Frame parser extracts ip_checksum (16-bit) from IPv4 header [IMPLEMENTED]

### Rewrite RTL
- REQ-1230: rewrite_lut.v — generated combinational ROM mapping rule_idx to rewrite operations [IMPLEMENTED]
- REQ-1231: packet_rewrite.v — hand-written byte substitution engine [IMPLEMENTED]
- REQ-1232: RFC 1624 incremental IP checksum update for TTL/IP address changes [IMPLEMENTED]
- REQ-1233: In-place rewrite only — no frame length changes [IMPLEMENTED]
- REQ-1234: Rewrite engine integrated into AXI-Stream datapath (requires --axi) [IMPLEMENTED]

### AXI Top-Level
- REQ-1240: packet_filter_axi_top.v templatized (templates/packet_filter_axi_top.v.tera) to conditionally wire rewrite engine [IMPLEMENTED]
- REQ-1241: Rewrite engine sits between store-forward FIFO output and AXI-Stream output [IMPLEMENTED]

### Simulator
- REQ-1250: Simulator displays rewrite information for matching rules [IMPLEMENTED]

### Tool Support
- REQ-1260: `estimate` accounts for rewrite LUT/FF resources [IMPLEMENTED]
- REQ-1261: LINT018 — lint rule for rewrite action validation [IMPLEMENTED]
- REQ-1262: LINT019 — lint rule for rewrite action best practices [IMPLEMENTED]
- REQ-1263: `formal` generates SVA assertions for rewrite operations [IMPLEMENTED]
- REQ-1264: `diff` detects rewrite action changes between rule sets [IMPLEMENTED]

### Example
- REQ-1270: rewrite_actions.yaml example demonstrating NAT, TTL, MAC, VLAN rewrite [IMPLEMENTED]

### Testing
- REQ-1280: 275 Rust unit tests (through Phase 21) [IMPLEMENTED]
- REQ-1281: 216 Rust integration tests (through Phase 21) [IMPLEMENTED]
- REQ-1282: 47 Python scoreboard unit tests (through Phase 18) [IMPLEMENTED]

## Phase 19: Platform Integration Targets

### Platform Target CLI
- REQ-1300: `--target` flag on `compile` command (standalone/opennic/corundum) [IMPLEMENTED]
- REQ-1301: Platform target implicitly enables `--axi` mode [IMPLEMENTED]
- REQ-1302: Platform target incompatible with `--dynamic` (V1) [IMPLEMENTED]
- REQ-1303: Platform target incompatible with `--ports > 1` (V1) [IMPLEMENTED]
- REQ-1304: Platform target compatible with `--counters`, `--rate-limit`, `--conntrack`, rewrite [IMPLEMENTED]
- REQ-1305: JSON compile output includes `"target"` field [IMPLEMENTED]

### Width Converters
- REQ-1310: `axis_512_to_8.v` — hand-written 512→8-bit AXI-Stream deserializer [IMPLEMENTED]
- REQ-1311: `axis_8_to_512.v` — hand-written 8→512-bit AXI-Stream serializer [IMPLEMENTED]
- REQ-1312: Width converters pass iverilog lint [IMPLEMENTED]
- REQ-1313: Width converters copied to gen/rtl/ for platform targets [IMPLEMENTED]

### OpenNIC Shell Integration
- REQ-1320: `pacgate_opennic_250.v` generated from template for `--target opennic` [IMPLEMENTED]
- REQ-1321: OpenNIC wrapper has 512-bit AXI-Stream with tuser_size/tuser_src/tuser_dst [IMPLEMENTED]
- REQ-1322: tuser metadata latched on input frame, forwarded on output frame [IMPLEMENTED]
- REQ-1323: Internal pipeline: axis_512_to_8 → packet_filter_axi_top → axis_8_to_512 [IMPLEMENTED]

### Corundum Integration
- REQ-1330: `pacgate_corundum_app.v` generated from template for `--target corundum` [IMPLEMENTED]
- REQ-1331: Corundum wrapper has sync RX/TX interface with PTP timestamp on tuser [IMPLEMENTED]
- REQ-1332: Active-high reset inverted to PacGate's active-low convention [IMPLEMENTED]
- REQ-1333: Parameterized AXIS_DATA_WIDTH and PTP_TS_WIDTH [IMPLEMENTED]

### Tool Support
- REQ-1340: `estimate --target` adds width converter resources (~80 LUTs + ~1100 FFs) [IMPLEMENTED]
- REQ-1341: LINT020 — platform target throughput limitation notice [IMPLEMENTED]
- REQ-1342: LINT021 — platform target implicit AXI notice [IMPLEMENTED]
- REQ-1343: `synth` file list includes width converters for platform targets [IMPLEMENTED]

### Examples
- REQ-1350: opennic_l3l4.yaml — L3/L4 firewall for OpenNIC target [IMPLEMENTED]
- REQ-1351: corundum_datacenter.yaml — data center firewall for Corundum target [IMPLEMENTED]

### CI
- REQ-1360: `opennic-compile` CI job with iverilog lint [IMPLEMENTED]
- REQ-1361: `corundum-compile` CI job with iverilog lint [IMPLEMENTED]

## Phase 20: cocotb 2.0 Migration [IMPLEMENTED]

### Compatibility
- REQ-1400: Pin cocotb>=2.0.0 + cocotb-tools in CI and environment [IMPLEMENTED]
- REQ-1401: Fix `.value.integer` → `int(.value)` pattern in test_rate_limiter.py.tera [IMPLEMENTED]
- REQ-1402: No usage of BinaryValue, TestFactory, TestFailure, cocotb.fork, or .kill() [VERIFIED]

### Runner Script Generation
- REQ-1410: Generate `run_sim.py` runner using `cocotb_tools.runner.get_runner()` API [IMPLEMENTED]
- REQ-1411: Runner for main packet filter tests (tb/run_sim.py) [IMPLEMENTED]
- REQ-1412: Runner for AXI-Stream tests (tb-axi/run_sim.py) [IMPLEMENTED]
- REQ-1413: Runner for conntrack tests (tb-conntrack/run_sim.py) [IMPLEMENTED]
- REQ-1414: Runner for rate limiter tests (tb-rate-limiter/run_sim.py) [IMPLEMENTED]
- REQ-1415: Runner for dynamic flow table tests (tb/run_sim.py in dynamic mode) [IMPLEMENTED]
- REQ-1416: Runner supports SIM environment variable override (default: icarus) [IMPLEMENTED]
- REQ-1417: Runner includes `results_xml` output path for CI artifact collection [IMPLEMENTED]
- REQ-1418: Platform target runners include width converter Verilog sources [IMPLEMENTED]

### Backward Compatibility
- REQ-1420: Makefiles preserved alongside runner scripts for legacy workflows [IMPLEMENTED]
- REQ-1421: Both `python run_sim.py` and `make` produce equivalent simulation results [IMPLEMENTED]

### CI Updates
- REQ-1430: CI simulate job uses `python run_sim.py` (cocotb 2.0 runner) [IMPLEMENTED]
- REQ-1431: CI conntrack-simulate job uses runner [IMPLEMENTED]
- REQ-1432: CI runner lint check verifies generated run_sim.py has correct imports [IMPLEMENTED]

### Testing
- REQ-1440: 4 unit tests for runner template rendering (sources, toplevel, imports, SIM override) [IMPLEMENTED]
- REQ-1441: 9 integration tests for runner generation across all compile modes [IMPLEMENTED]

## Phase 21: DSCP/ECN QoS Matching + DSCP Rewrite [IMPLEMENTED]

### Match Fields
- REQ-1500: Match on IPv4 DSCP (6-bit, 0-63) from TOS byte bits [7:2] [IMPLEMENTED]
- REQ-1501: Match on IPv4 ECN (2-bit, 0-3) from TOS byte bits [1:0] [IMPLEMENTED]
- REQ-1502: DSCP value range validation (0-63, reject >=64) [IMPLEMENTED]
- REQ-1503: ECN value range validation (0-3, reject >=4) [IMPLEMENTED]
- REQ-1504: DSCP/ECN shadow detection in rule overlap analysis [IMPLEMENTED]
- REQ-1505: DSCP/ECN overlap detection in rule overlap analysis [IMPLEMENTED]

### Frame Parser
- REQ-1510: Extract DSCP from IPv4 TOS byte (byte 1 of IP header, bits [7:2]) [IMPLEMENTED]
- REQ-1511: Extract ECN from IPv4 TOS byte (byte 1 of IP header, bits [1:0]) [IMPLEMENTED]
- REQ-1512: ip_dscp and ip_ecn output ports on frame_parser module [IMPLEMENTED]

### Rewrite Actions
- REQ-1520: set_dscp rewrite action (6-bit DSCP value, 0-63) for QoS remarking [IMPLEMENTED]
- REQ-1521: set_dscp range validation (0-63) and IPv4 ethertype prerequisite [IMPLEMENTED]
- REQ-1522: DSCP rewrite with RFC 1624 incremental IP checksum update [IMPLEMENTED]
- REQ-1523: DSCP byte substitution at IP header byte 1 (TOS), preserving ECN bits [IMPLEMENTED]
- REQ-1524: rewrite_flags bit [7] = set_dscp, expanded from 7-bit to 8-bit [IMPLEMENTED]
- REQ-1525: rewrite_lut generates set_dscp output port and per-entry DSCP values [IMPLEMENTED]

### Verilog Generation
- REQ-1530: has_dscp_ecn global protocol flag controlling conditional port generation [IMPLEMENTED]
- REQ-1531: DSCP/ECN condition generation: `ip_dscp == 6'dN`, `ip_ecn == 2'dN` [IMPLEMENTED]
- REQ-1532: Conditional DSCP/ECN ports in rule_match and rule_fsm templates [IMPLEMENTED]
- REQ-1533: Wire DSCP/ECN from frame_parser through packet_filter_top to rule matchers [IMPLEMENTED]
- REQ-1534: AXI top template wires DSCP rewrite signals (rewrite_dscp, orig_ip_dscp, orig_ip_ecn) [IMPLEMENTED]

### Simulation
- REQ-1540: SimPacket supports ip_dscp and ip_ecn fields [IMPLEMENTED]
- REQ-1541: parse_packet_spec handles "ip_dscp=N" and "ip_ecn=N" with range validation [IMPLEMENTED]
- REQ-1542: match_criteria_against_packet evaluates DSCP and ECN matching [IMPLEMENTED]
- REQ-1543: SimRewrite supports set_dscp field [IMPLEMENTED]

### Verification
- REQ-1550: Python scoreboard Rule dataclass includes ip_dscp and ip_ecn fields [IMPLEMENTED]
- REQ-1551: Scoreboard matches() evaluates DSCP/ECN from extracted dict [IMPLEMENTED]
- REQ-1552: cocotb test case generation includes DSCP/ECN fields [IMPLEMENTED]
- REQ-1553: cocotb scoreboard rules include DSCP/ECN fields [IMPLEMENTED]
- REQ-1554: SVA DSCP bounds assertion (ip_dscp <= 63) [IMPLEMENTED]
- REQ-1555: SVA ECN bounds assertion (ip_ecn <= 3) [IMPLEMENTED]
- REQ-1556: SVA cover property for EF traffic (DSCP=46) [IMPLEMENTED]

### Tools
- REQ-1560: LINT022 — DSCP/ECN without IPv4 ethertype prerequisite warning [IMPLEMENTED]
- REQ-1561: Estimate includes DSCP (6-bit) and ECN (2-bit) comparator LUT costs [IMPLEMENTED]
- REQ-1562: Diff compares ip_dscp and ip_ecn fields (text and JSON modes) [IMPLEMENTED]
- REQ-1563: Doc includes ip_dscp and ip_ecn in HTML field listing [IMPLEMENTED]
- REQ-1564: Stats tracks ip_dscp and ip_ecn field usage counts [IMPLEMENTED]
- REQ-1565: Graph includes ip_dscp and ip_ecn in DOT node labels [IMPLEMENTED]

### Mutation Testing
- REQ-1570: remove_ip_dscp mutation type [IMPLEMENTED]
- REQ-1571: remove_ip_ecn mutation type [IMPLEMENTED]

### Example
- REQ-1580: qos_classification.yaml example with 7 rules (EF, AF41, AF31, CS6, BE+ECT1, CS1→BE remark, ARP) [IMPLEMENTED]
- REQ-1581: CI simulate matrix includes qos_classification example [IMPLEMENTED]

### Testing
- REQ-1590: 15 unit tests for DSCP/ECN (8 model + 4 loader + 2 simulator + 2 mutation) [IMPLEMENTED]
- REQ-1591: 12 integration tests for DSCP/ECN (compile, simulate, validate, lint, estimate, diff, formal) [IMPLEMENTED]

## Phase 22: IPv6 Traffic Class + TCP Flags + ICMP Type/Code [IMPLEMENTED]

### Match Fields
- REQ-1600: Match on IPv6 DSCP (ipv6_dscp, 6-bit, 0-63) from IPv6 Traffic Class byte [IMPLEMENTED]
- REQ-1601: Match on IPv6 ECN (ipv6_ecn, 2-bit, 0-3) from IPv6 Traffic Class byte [IMPLEMENTED]
- REQ-1602: Match on TCP flags (tcp_flags, 8-bit) with mask-aware matching: (flags & mask) == (rule_flags & mask) [IMPLEMENTED]
- REQ-1603: TCP flags mask (tcp_flags_mask) for selective bit checking (e.g., SYN-only, ACK-only, Xmas tree) [IMPLEMENTED]
- REQ-1604: Match on ICMP type (icmp_type, 8-bit, 0-255) for IPv4 ICMP classification [IMPLEMENTED]
- REQ-1605: Match on ICMP code (icmp_code, 8-bit, 0-255) for IPv4 ICMP subtype filtering [IMPLEMENTED]

### Frame Parser
- REQ-1606: IPv6 Traffic Class byte extraction from IPv6 header bytes 0-1 (4-bit version + 8-bit TC + 20-bit flow label) [IMPLEMENTED]
- REQ-1607: TCP flags extraction at TCP header byte offset 13 (8-bit flags field) [IMPLEMENTED]
- REQ-1608: New S_ICMP_HDR parser state for ICMP type/code extraction (after IPv4 protocol 1 detection) [IMPLEMENTED]

### Lint Rules
- REQ-1609: LINT023 — IPv6 DSCP/ECN without IPv6 ethertype (0x86DD) prerequisite warning [IMPLEMENTED]
- REQ-1610: LINT024 — TCP flags without TCP protocol (ip_protocol 6) prerequisite warning [IMPLEMENTED]
- REQ-1611: LINT025 — ICMP type/code without ICMP protocol (ip_protocol 1) prerequisite warning [IMPLEMENTED]

### Formal Verification
- REQ-1612: SVA assertions for IPv6 TC bounds (ipv6_dscp <= 63, ipv6_ecn <= 3), TCP flags prerequisite (match → ip_protocol == 6), ICMP cover properties [IMPLEMENTED]

### Mutation Testing
- REQ-1613: 3 new mutation types: remove_tcp_flags, remove_icmp_type, remove_ipv6_dscp (16 total) [IMPLEMENTED]

### Python Verification
- REQ-1614: Python scoreboard Rule dataclass includes ipv6_dscp, ipv6_ecn, tcp_flags, tcp_flags_mask, icmp_type, icmp_code fields with mask-aware TCP flags matching in matches() [IMPLEMENTED]

### Example
- REQ-1615: tcp_flags_icmp.yaml example with 7 rules (allow_tcp_syn, allow_tcp_established, drop_tcp_xmas, allow_icmp_echo, allow_icmp_reply, allow_ipv6_ef, allow_arp) [IMPLEMENTED]

### Testing
- REQ-1616: 23 unit tests for IPv6 TC/TCP flags/ICMP (model, loader, simulator, mutation) [IMPLEMENTED]
- REQ-1617: 14 integration tests for IPv6 TC/TCP flags/ICMP (compile, simulate, validate, lint, estimate, diff, formal) [IMPLEMENTED]

## Phase 23: ARP + ICMPv6 + IPv6 Extension Fields [IMPLEMENTED]

### ICMPv6 Match Fields
- REQ-1700: Match on ICMPv6 type (icmpv6_type, 8-bit, 0-255) for IPv6 ICMPv6 classification (NDP, echo, unreachable) [IMPLEMENTED]
- REQ-1701: Match on ICMPv6 code (icmpv6_code, 8-bit, 0-255) — requires icmpv6_type to be set [IMPLEMENTED]
- REQ-1702: MLD backward compatibility — ICMPv6 types 130-132 still set mld_type/mld_valid for existing MLD rules [IMPLEMENTED]

### ARP Match Fields
- REQ-1703: Match on ARP opcode (arp_opcode, 1=request, 2=reply only, validated at load time) [IMPLEMENTED]
- REQ-1704: Match on ARP sender protocol address (arp_spa, IPv4 dotted-quad format) [IMPLEMENTED]
- REQ-1705: Match on ARP target protocol address (arp_tpa, IPv4 dotted-quad format) [IMPLEMENTED]

### IPv6 Extension Fields
- REQ-1706: Match on IPv6 hop limit (ipv6_hop_limit, 8-bit, 0-255) for IPv6 TTL-based filtering [IMPLEMENTED]
- REQ-1707: Match on IPv6 flow label (ipv6_flow_label, 20-bit, 0-0xFFFFF) for flow classification [IMPLEMENTED]

### Frame Parser
- REQ-1708: S_ICMPV6_HDR parser state (state 15) for ICMPv6 type/code extraction after IPv6 next_header 58 detection [IMPLEMENTED]
- REQ-1709: S_ARP_HDR parser state (state 16) for ARP header extraction (opcode bytes 6-7, SPA bytes 14-17, TPA bytes 24-27) [IMPLEMENTED]

### Lint Rules
- REQ-1710: LINT026 — ICMPv6 type/code without IPv6 ethertype (0x86DD) and ipv6_next_header 58 prerequisite warning [IMPLEMENTED]
- REQ-1711: LINT027 — ARP opcode/SPA/TPA without ARP ethertype (0x0806) prerequisite warning [IMPLEMENTED]
- REQ-1712: LINT028 — IPv6 hop_limit/flow_label without IPv6 ethertype (0x86DD) prerequisite warning [IMPLEMENTED]

### Formal Verification
- REQ-1713: SVA assertions for ICMPv6 bounds (icmpv6_type valid range), ARP prerequisite (match → ethertype == 0x0806), IPv6 extension cover properties [IMPLEMENTED]

### Mutation Testing
- REQ-1714: 3 new mutation types: remove_icmpv6_type, remove_arp_opcode, remove_ipv6_hop_limit (19 total) [IMPLEMENTED]

### Python Verification
- REQ-1715: Python scoreboard Rule dataclass includes icmpv6_type, icmpv6_code, arp_opcode, arp_spa, arp_tpa, ipv6_hop_limit, ipv6_flow_label fields with matching in matches() [IMPLEMENTED]

### Examples
- REQ-1716: arp_security.yaml example with 5 rules for ARP security (opcode filtering, SPA/TPA validation, gratuitous ARP detection) [IMPLEMENTED]
- REQ-1717: icmpv6_firewall.yaml example with 8 rules for ICMPv6 filtering (NDP permit, echo request/reply, unreachable, MLD multicast) [IMPLEMENTED]

### Testing
- REQ-1718: 26 unit tests for ICMPv6/ARP/IPv6-ext (model, loader, simulator, mutation) [IMPLEMENTED]
- REQ-1719: 14 integration tests for ICMPv6/ARP/IPv6-ext (compile, simulate, validate, lint, estimate, diff, formal) [IMPLEMENTED]

## Phase 24: QinQ Double VLAN + IPv4 Fragmentation + L4 Port Rewrite [IMPLEMENTED]

### QinQ (802.1ad) Double VLAN Match Fields
- REQ-1800: Match on outer VLAN ID (outer_vlan_id, 12-bit, 0-4095) for 802.1ad QinQ double-tagged frames [IMPLEMENTED]
- REQ-1801: Match on outer VLAN PCP (outer_vlan_pcp, 3-bit, 0-7) for QinQ priority classification [IMPLEMENTED]
- REQ-1802: Outer VLAN ID range validation (0-4095, reject >= 4096) [IMPLEMENTED]
- REQ-1803: Outer VLAN PCP range validation (0-7, reject >= 8) [IMPLEMENTED]
- REQ-1804: Shadow/overlap detection for outer_vlan_id and outer_vlan_pcp fields [IMPLEMENTED]
- REQ-1805: Frame parser S_OUTER_VLAN state for 802.1ad (EtherType 0x88A8) double-tagged frame parsing [IMPLEMENTED]

### IPv4 Fragmentation Match Fields
- REQ-1810: Match on IPv4 Don't Fragment flag (ip_dont_fragment, 1-bit, 0-1) [IMPLEMENTED]
- REQ-1811: Match on IPv4 More Fragments flag (ip_more_fragments, 1-bit, 0-1) [IMPLEMENTED]
- REQ-1812: Match on IPv4 fragment offset (ip_frag_offset, 13-bit, 0-8191) for fragment attack detection [IMPLEMENTED]
- REQ-1813: Fragment offset range validation (0-8191, reject >= 8192) [IMPLEMENTED]
- REQ-1814: Fragment flags/offset extracted from IPv4 header flags/fragment offset field (bytes 6-7) [IMPLEMENTED]
- REQ-1815: Frame parser frame_byte_cnt tracking for fragment field extraction at correct offset [IMPLEMENTED]

### L4 Port Rewrite Actions
- REQ-1820: set_src_port rewrite action — overwrite TCP/UDP source port (16-bit, 1-65535) [IMPLEMENTED]
- REQ-1821: set_dst_port rewrite action — overwrite TCP/UDP destination port (16-bit, 1-65535) [IMPLEMENTED]
- REQ-1822: Port rewrite range validation (1-65535) [IMPLEMENTED]
- REQ-1823: Port rewrite requires IPv4 ethertype (0x0800) and TCP (ip_protocol 6) or UDP (ip_protocol 17) prerequisite [IMPLEMENTED]
- REQ-1824: RFC 1624 L4 checksum incremental update for port rewrite (TCP/UDP checksum correction) [IMPLEMENTED]
- REQ-1825: packet_rewrite.v extended with 16-bit port substitution at L4 header offsets [IMPLEMENTED]
- REQ-1826: rewrite_lut.v expanded for 16-bit port rewrite output entries [IMPLEMENTED]

### Verilog Generation
- REQ-1830: has_qinq global protocol flag controlling conditional outer VLAN port generation [IMPLEMENTED]
- REQ-1831: has_ip_frag global protocol flag controlling conditional fragmentation port generation [IMPLEMENTED]
- REQ-1832: QinQ/frag/port-rewrite condition expressions in rule matchers [IMPLEMENTED]
- REQ-1833: AXI top template wires L4 port rewrite signals [IMPLEMENTED]

### Lint Rules
- REQ-1840: LINT029 — QinQ outer VLAN fields without 802.1ad ethertype prerequisite warning [IMPLEMENTED]
- REQ-1841: LINT030 — IPv4 fragmentation fields without IPv4 ethertype (0x0800) prerequisite warning [IMPLEMENTED]
- REQ-1842: LINT031 — L4 port rewrite without IPv4 + TCP/UDP protocol prerequisite warning [IMPLEMENTED]
- REQ-1843: LINT032 — fragment offset > 0 without MF flag advisory [IMPLEMENTED]

### Formal Verification
- REQ-1850: SVA assertions for QinQ outer VLAN bounds (outer_vlan_id <= 4095, outer_vlan_pcp <= 7) [IMPLEMENTED]
- REQ-1851: SVA assertions for IPv4 fragmentation bounds (ip_frag_offset <= 8191) [IMPLEMENTED]
- REQ-1852: SVA assertions for L4 port rewrite prerequisite (match → ip_protocol TCP or UDP) [IMPLEMENTED]

### Mutation Testing
- REQ-1860: 3 new mutation types: remove_outer_vlan_id, remove_ip_frag_offset, remove_set_src_port (22 total) [IMPLEMENTED]

### Simulation
- REQ-1870: SimPacket supports outer_vlan_id, outer_vlan_pcp, ip_dont_fragment, ip_more_fragments, ip_frag_offset fields [IMPLEMENTED]
- REQ-1871: parse_packet_spec handles all 5 new match fields with range validation [IMPLEMENTED]
- REQ-1872: match_criteria_against_packet evaluates QinQ and fragmentation matching [IMPLEMENTED]
- REQ-1873: SimRewrite supports set_src_port and set_dst_port fields [IMPLEMENTED]

### Python Verification
- REQ-1880: Scoreboard Rule dataclass includes outer_vlan_id, outer_vlan_pcp, ip_dont_fragment, ip_more_fragments, ip_frag_offset fields [IMPLEMENTED]
- REQ-1881: Scoreboard matches() evaluates QinQ and fragmentation from extracted dict [IMPLEMENTED]
- REQ-1882: PacketFactory.qinq() constructs double-tagged Ethernet frames (outer 0x88A8 + inner 0x8100) [IMPLEMENTED]
- REQ-1883: PacketFactory supports IPv4 fragmentation flag fields [IMPLEMENTED]

### Examples
- REQ-1890: QinQ carrier network YAML example (outer/inner VLAN matching for carrier Ethernet) [IMPLEMENTED]
- REQ-1891: IPv4 fragmentation detection YAML example (DF/MF flags, fragment offset attack detection) [IMPLEMENTED]
- REQ-1892: L4 port rewrite YAML example (source/destination port NAT with checksum update) [IMPLEMENTED]

### Testing
- REQ-1900: 348 Rust unit tests (through Phase 24) [IMPLEMENTED]
- REQ-1901: 267 Rust integration tests (through Phase 24) [IMPLEMENTED]
- REQ-1902: 47 Python scoreboard unit tests (through Phase 24) [IMPLEMENTED]
- REQ-1903: Integration tests for QinQ compile, simulate, validate, lint, estimate, diff, formal [IMPLEMENTED]
- REQ-1904: Integration tests for IPv4 fragmentation compile, simulate, validate, lint [IMPLEMENTED]
- REQ-1905: Integration tests for L4 port rewrite compile, validate, lint, formal [IMPLEMENTED]

## Phase 25 Requirements — GRE Tunnel Support [IMPLEMENTED]

### GRE Tunnel Parsing
- REQ-2000: Detect GRE encapsulation (IP protocol 47) [IMPLEMENTED]
- REQ-2001: Parse GRE header: 16-bit protocol type, optional 32-bit key (K flag) [IMPLEMENTED]
- REQ-2002: Match on gre_protocol and gre_key fields in YAML rules [IMPLEMENTED]
- REQ-2003: Frame parser S_GRE_HDR state for GRE header extraction [IMPLEMENTED]
- REQ-2004: GRE matching in hardware: gre_protocol (16-bit), gre_key (32-bit) [IMPLEMENTED]
- REQ-2005: GRE wiring through all templates (rule_match, rule_fsm, packet_filter_top) [IMPLEMENTED]
- REQ-2006: Simulator support for gre_protocol and gre_key field matching [IMPLEMENTED]
- REQ-2007: GRE YAML example (gre_tunnel.yaml) [IMPLEMENTED]
- REQ-2008: Loader validation: gre_key requires gre_protocol [IMPLEMENTED]
- REQ-2009: Overlap detection for GRE fields [IMPLEMENTED]

### Verification
- REQ-2010: Python scoreboard gre_protocol and gre_key match fields [IMPLEMENTED]
- REQ-2011: SVA formal assertions: GRE prerequisite (ip_protocol==47), cover properties [IMPLEMENTED]
- REQ-2012: Mutation type 23: remove_gre_protocol (removes gre_key too) [IMPLEMENTED]
- REQ-2013: cocotb test generation includes GRE fields in test_cases and scoreboard_rules [IMPLEMENTED]
- REQ-2014: has_gre_rules flag in property test generation context [IMPLEMENTED]

### Testing
- REQ-2020: 366 Rust unit tests (through Phase 25) [IMPLEMENTED]
- REQ-2021: 274 Rust integration tests (through Phase 25) [IMPLEMENTED]
- REQ-2022: 47 Python scoreboard unit tests unchanged [IMPLEMENTED]
- REQ-2023: Integration tests for GRE compile, simulate, validate [IMPLEMENTED]

## Phase 25.3 Requirements — Mirror/Redirect Port Egress Actions [IMPLEMENTED]

### Model
- REQ-2100: mirror_port field on StatelessRule (Option<u8>, 0-255) [IMPLEMENTED]
- REQ-2101: redirect_port field on StatelessRule (Option<u8>, 0-255) [IMPLEMENTED]
- REQ-2102: has_mirror() and has_redirect() convenience methods [IMPLEMENTED]

### Verification
- REQ-2110: Python scoreboard Rule dataclass includes mirror_port/redirect_port (informational, no pass/drop effect) [IMPLEMENTED]
- REQ-2111: SVA cover properties for egress_mirror_valid signal (valid, pass+mirror, drop+mirror) [IMPLEMENTED]
- REQ-2112: SVA cover properties for egress_redirect_valid signal (valid, pass+redirect) [IMPLEMENTED]
- REQ-2113: Formal generation inserts has_mirror/has_redirect flags into template context [IMPLEMENTED]

### Mutation Testing
- REQ-2120: Mutation type 25: remove_mirror_port — clears mirror_port from rules [IMPLEMENTED]
- REQ-2121: Mutation type 26: remove_redirect_port — clears redirect_port from rules [IMPLEMENTED]
- REQ-2122: Unit tests for both new mutation types [IMPLEMENTED]

### cocotb Generation
- REQ-2130: Test cases include mirror_port/redirect_port informational fields [IMPLEMENTED]
- REQ-2131: Property test context includes has_mirror_rules/has_redirect_rules flags [IMPLEMENTED]

### Lint
- REQ-2140: LINT035: redirect_port with action: drop warning [IMPLEMENTED]
- REQ-2141: LINT036: mirror/redirect requires multi-port or platform target info [IMPLEMENTED]

### Example
- REQ-2150: mirror_redirect.yaml example demonstrating both egress actions [IMPLEMENTED]

## Phase 25.4: Per-Flow Counters + Flow Export

### Model & Config
- REQ-2200: enable_flow_counters field on ConntrackConfig (Option<bool>, default None/false) [IMPLEMENTED]
- REQ-2201: StatelessRule::has_flow_counters() helper checks conntrack config [IMPLEMENTED]
- REQ-2202: YAML deserialization of enable_flow_counters: true/false/omitted [IMPLEMENTED]

### RTL
- REQ-2203: conntrack_table.v pkt_len_in[15:0] input for byte counting [IMPLEMENTED]
- REQ-2204: conntrack_table.v per-entry table_pkt_count[63:0] and table_byte_count[63:0] register arrays [IMPLEMENTED]
- REQ-2205: Lookup HIT increments pkt_count by 1 and byte_count by pkt_len_in [IMPLEMENTED]
- REQ-2206: INSERT (new entry) initializes counters to 1/pkt_len_in [IMPLEMENTED]
- REQ-2207: INSERT (existing key update) increments counters [IMPLEMENTED]
- REQ-2208: Flow read-back interface: flow_read_idx, flow_read_en, flow_read_key, flow_read_valid, flow_read_pkt_count, flow_read_byte_count, flow_read_tcp_state, flow_read_done [IMPLEMENTED]
- REQ-2209: Flow read interface is registered (1-cycle latency on flow_read_en) [IMPLEMENTED]

### Code Generation
- REQ-2260: has_flow_counters flag in GlobalProtocolFlags struct [IMPLEMENTED]
- REQ-2261: has_flow_counters computed from conntrack.enable_flow_counters config [IMPLEMENTED]
- REQ-2262: has_flow_counters inserted into top/AXI/OpenNIC/Corundum template contexts [IMPLEMENTED]

### Templates
- REQ-2270: packet_filter_axi_top.v.tera: flow_read_* ports guarded by has_flow_counters [IMPLEMENTED]
- REQ-2271: packet_filter_axi_top.v.tera: conntrack_table instantiation when has_flow_counters [IMPLEMENTED]
- REQ-2272: pacgate_opennic_250.v.tera: flow_read_* port pass-through when has_flow_counters [IMPLEMENTED]
- REQ-2273: pacgate_corundum_app.v.tera: flow_read_* port pass-through when has_flow_counters [IMPLEMENTED]

### Verification
- REQ-2210: Python scoreboard Rule dataclass includes enable_flow_counters: bool (informational, no pass/drop effect) [IMPLEMENTED]
- REQ-2211: SVA cover properties for flow_read_done signal (flow counter read completes) [IMPLEMENTED]
- REQ-2212: SVA cover property for flow_pkt_count > 0 on read [IMPLEMENTED]
- REQ-2213: Formal generation inserts has_flow_counters flag into template context [IMPLEMENTED]

### Mutation Testing
- REQ-2220: Mutation type 27: remove_flow_counters — clears enable_flow_counters from conntrack config [IMPLEMENTED]
- REQ-2221: Unit test for remove_flow_counters mutation (positive and negative cases) [IMPLEMENTED]

### Cocotb Generation
- REQ-2230: Property test context includes has_flow_counters flag [IMPLEMENTED]

### Diff Support
- REQ-2240: diff_rules() detects conntrack config changes (table_size, timeout, enable_flow_counters) [IMPLEMENTED]

### Example
- REQ-2250: flow_counters.yaml example with enable_flow_counters: true (4 rules) [IMPLEMENTED]

## Phase 25.5 Requirements — OAM/CFM (IEEE 802.1ag) Support [IMPLEMENTED]

### Model
- REQ-2300: oam_level field on MatchCriteria (Option<u8>, 0-7, 3-bit Maintenance Domain Level) [IMPLEMENTED]
- REQ-2301: oam_opcode field on MatchCriteria (Option<u8>, 0-255, CFM OpCode) [IMPLEMENTED]
- REQ-2302: uses_oam() helper method on MatchCriteria [IMPLEMENTED]
- REQ-2303: YAML deserialization of oam_level and oam_opcode match fields [IMPLEMENTED]

### Loader/Validation
- REQ-2310: Validate oam_level range 0-7 [IMPLEMENTED]
- REQ-2311: Overlap detection for OAM fields (oam_level, oam_opcode) [IMPLEMENTED]

### Simulator
- REQ-2320: Parse oam_level and oam_opcode from --packet spec [IMPLEMENTED]
- REQ-2321: OAM field matching in software simulator [IMPLEMENTED]

### RTL Frame Parser
- REQ-2330: Detect OAM/CFM frames via EtherType 0x8902 in S_ETYPE, S_ETYPE2, S_OUTER_VLAN [IMPLEMENTED]
- REQ-2331: S_OAM_HDR state: extract MEL from byte 0 bits[7:5], OpCode from byte 1 [IMPLEMENTED]
- REQ-2332: New outputs: oam_level[2:0], oam_opcode[7:0], oam_valid [IMPLEMENTED]
- REQ-2333: OAM field initialization on reset and SOF [IMPLEMENTED]

### Verilog Code Generation
- REQ-2340: has_oam flag in GlobalProtocolFlags [IMPLEMENTED]
- REQ-2341: OAM condition expressions: (oam_valid && oam_level == 3'd{val}) [IMPLEMENTED]
- REQ-2342: has_oam inserted into all template contexts (top, stateless, FSM) [IMPLEMENTED]

### Templates
- REQ-2350: rule_match.v.tera: conditional OAM input ports (oam_level, oam_opcode, oam_valid) [IMPLEMENTED]
- REQ-2351: rule_fsm.v.tera: conditional OAM input ports [IMPLEMENTED]
- REQ-2352: packet_filter_top.v.tera: OAM wire declarations + parser wiring + rule matcher wiring [IMPLEMENTED]

### Verification
- REQ-2360: SVA assertions: oam_level bounds, OAM prerequisite (ethertype==0x8902) [IMPLEMENTED]
- REQ-2361: SVA cover properties: oam_valid, oam_ccm, per-rule OAM covers [IMPLEMENTED]
- REQ-2362: Python scoreboard OAM matching [IMPLEMENTED]
- REQ-2363: cocotb test generation includes OAM fields [IMPLEMENTED]

### Mutation Testing
- REQ-2370: Mutation type 28: remove_oam_level (clears oam_level + oam_opcode) [IMPLEMENTED]

### Lint
- REQ-2380: LINT038: OAM fields without ethertype 0x8902 [IMPLEMENTED]

### Tools (main.rs)
- REQ-2381: Estimate: +8 LUTs per rule with OAM (3-bit level + 8-bit opcode comparators) [IMPLEMENTED]
- REQ-2382: Stats: uses_oam_level and uses_oam_opcode counters (JSON + text) [IMPLEMENTED]
- REQ-2383: Diff: oam_level and oam_opcode field change detection (text + JSON + HTML) [IMPLEMENTED]
- REQ-2384: Doc: oam_level and oam_opcode in rule_info match_fields [IMPLEMENTED]
- REQ-2385: Graph: OAM labels on rule nodes (oam_level={val}, oam_opcode={val}) [IMPLEMENTED]
- REQ-2386: CI: oam_monitoring added to simulate matrix [IMPLEMENTED]

### Example
- REQ-2390: oam_monitoring.yaml example (5 rules: CCM/DMM/DMR/LBR/ARP) [IMPLEMENTED]

### Test Counts
- REQ-2395: 426 Rust unit tests (through Phase 25.5) [IMPLEMENTED]
- REQ-2396: 317 Rust integration tests (through Phase 25.5) [IMPLEMENTED]
- REQ-2397: 47 Python scoreboard unit tests → 53 (added 6 NSH tests) [IMPLEMENTED]

## Phase 25.6 Requirements — NSH/SFC (RFC 8300 Network Service Header) [IMPLEMENTED]

### Match Fields
- REQ-2400: nsh_spi match field — 24-bit Service Path Identifier (0-16777215) [IMPLEMENTED]
- REQ-2401: nsh_si match field — 8-bit Service Index (0-255, position in SFP) [IMPLEMENTED]
- REQ-2402: nsh_next_protocol match field — 8-bit encapsulated protocol (1=IPv4, 2=IPv6, 3=Ethernet) [IMPLEMENTED]
- REQ-2403: uses_nsh() helper on MatchCriteria [IMPLEMENTED]
- REQ-2404: nsh_spi range validation (0-16777215) in loader [IMPLEMENTED]
- REQ-2405: Shadow/overlap detection for nsh_spi, nsh_si, nsh_next_protocol [IMPLEMENTED]

### RTL
- REQ-2410: Detect NSH frames via EtherType 0x894F in S_ETYPE, S_ETYPE2, S_OUTER_VLAN [IMPLEMENTED]
- REQ-2411: S_NSH_HDR parser state (5'd20): 8-byte parse — next_protocol at byte 2, SPI[23:0] at bytes 4-6, SI at byte 7 [IMPLEMENTED]
- REQ-2412: NSH output ports: nsh_spi[23:0], nsh_si[7:0], nsh_next_protocol[7:0], nsh_valid [IMPLEMENTED]

### Verilog Generation
- REQ-2420: has_nsh flag in GlobalProtocolFlags [IMPLEMENTED]
- REQ-2421: NSH condition expressions: nsh_spi (24'd), nsh_si (8'd), nsh_next_protocol (8'd) with nsh_valid guard [IMPLEMENTED]
- REQ-2422: Template wiring: packet_filter_top, rule_match, rule_fsm [IMPLEMENTED]

### Simulation
- REQ-2430: nsh_spi, nsh_si, nsh_next_protocol in SimPacket + parse_packet_spec [IMPLEMENTED]
- REQ-2431: NSH field matching in match_criteria_against_packet [IMPLEMENTED]

### Verification
- REQ-2440: SVA assertions: nsh_spi range, NSH prerequisite (ethertype==0x894F) [IMPLEMENTED]
- REQ-2441: SVA cover properties: nsh_valid, nsh_spi_nonzero, per-rule NSH covers [IMPLEMENTED]
- REQ-2442: Python scoreboard NSH matching (nsh_spi, nsh_si, nsh_next_protocol) [IMPLEMENTED]
- REQ-2443: cocotb test generation includes NSH fields [IMPLEMENTED]
- REQ-2444: PacketFactory.nsh() for NSH frame construction in verification [IMPLEMENTED]

### Mutation Testing
- REQ-2450: Mutation type 29: remove_nsh_spi (clears nsh_spi + nsh_si + nsh_next_protocol) [IMPLEMENTED]

### Lint
- REQ-2460: LINT039: NSH fields without ethertype 0x894F (warning) [IMPLEMENTED]

### Tools (main.rs)
- REQ-2461: Estimate: +8 LUTs per rule with NSH (24-bit SPI + 8-bit SI + 8-bit next_protocol) [IMPLEMENTED]
- REQ-2462: Stats: nsh_spi, nsh_si, nsh_next_protocol field counters (JSON + text) [IMPLEMENTED]
- REQ-2463: Diff: nsh_spi, nsh_si, nsh_next_protocol field change detection [IMPLEMENTED]
- REQ-2464: Doc: NSH fields in rule_info match_fields [IMPLEMENTED]
- REQ-2465: Graph: NSH labels on rule nodes [IMPLEMENTED]
- REQ-2466: CI: nsh_sfc added to simulate matrix [IMPLEMENTED]

### Example
- REQ-2470: nsh_sfc.yaml example (5 rules: proxy chain, firewall chain, IPv4 cache, drop expired, non-NSH bypass) [IMPLEMENTED]

### Test Counts
- REQ-2475: 439 Rust unit tests (through Phase 25.6) [IMPLEMENTED]
- REQ-2476: 327 Rust integration tests (through Phase 25.6) [IMPLEMENTED]
- REQ-2477: 53 Python scoreboard unit tests (through Phase 25.6) [IMPLEMENTED]

## Phase 26 Requirements — Geneve + TTL Match + IPv6 Rewrite + Cocotb/Hypothesis Completeness + VLAN Rewrite [IMPLEMENTED]

### Phase 26.1: Geneve Tunnel Matching (RFC 8926)
- REQ-2500: Detect Geneve encapsulation (UDP dst port 6081) [IMPLEMENTED]
- REQ-2501: Parse Geneve header, extract 24-bit VNI (0-16777215) [IMPLEMENTED]
- REQ-2502: Match on geneve_vni field in YAML rules [IMPLEMENTED]
- REQ-2503: Frame parser S_GENEVE_HDR state for Geneve header extraction [IMPLEMENTED]
- REQ-2504: Geneve VNI matching in hardware: exact 24-bit comparison [IMPLEMENTED]
- REQ-2505: Geneve wiring through all templates (rule_match, rule_fsm, packet_filter_top) [IMPLEMENTED]
- REQ-2506: Simulator support for geneve_vni field matching [IMPLEMENTED]
- REQ-2507: Geneve YAML example (geneve_datacenter.yaml) [IMPLEMENTED]
- REQ-2508: geneve_vni range validation (0-16777215) in loader [IMPLEMENTED]
- REQ-2509: Shadow/overlap detection for geneve_vni field [IMPLEMENTED]
- REQ-2510: SVA formal assertions: Geneve prerequisite, cover properties [IMPLEMENTED]
- REQ-2511: Mutation type 30: remove_geneve_vni [IMPLEMENTED]
- REQ-2512: Python scoreboard geneve_vni match field [IMPLEMENTED]
- REQ-2513: cocotb test generation includes Geneve fields [IMPLEMENTED]

### Phase 26.2: ip_ttl Match + Frame Length (Simulation-Only)
- REQ-2520: Match on ip_ttl (8-bit, 0-255) for GTSM/TTL-based security [IMPLEMENTED]
- REQ-2521: ip_ttl matching in hardware: exact 8-bit comparison [IMPLEMENTED]
- REQ-2522: ip_ttl condition generation in verilog_gen.rs [IMPLEMENTED]
- REQ-2523: Simulator support for ip_ttl field matching [IMPLEMENTED]
- REQ-2524: frame_len_min match field (simulation-only, 16-bit minimum frame length) [IMPLEMENTED]
- REQ-2525: frame_len_max match field (simulation-only, 16-bit maximum frame length) [IMPLEMENTED]
- REQ-2526: frame_len_min/max evaluated in software simulator only (not in RTL) [IMPLEMENTED]
- REQ-2527: TTL security YAML example (ttl_security.yaml) [IMPLEMENTED]
- REQ-2528: ip_ttl range validation (0-255) in loader [IMPLEMENTED]
- REQ-2529: Shadow/overlap detection for ip_ttl field [IMPLEMENTED]
- REQ-2530: Mutation type 31: remove_ip_ttl [IMPLEMENTED]

### Phase 26.3: IPv6 Rewrite Actions
- REQ-2540: dec_hop_limit rewrite action — decrement IPv6 hop limit by 1 [IMPLEMENTED]
- REQ-2541: set_hop_limit rewrite action — set IPv6 hop limit to specific value (1-255) [IMPLEMENTED]
- REQ-2542: set_ecn rewrite action — set IPv4/IPv6 ECN bits (0-3) [IMPLEMENTED]
- REQ-2543: dec_hop_limit requires IPv6 ethertype prerequisite [IMPLEMENTED]
- REQ-2544: set_hop_limit requires IPv6 ethertype prerequisite [IMPLEMENTED]
- REQ-2545: set_ecn range validation (0-3) [IMPLEMENTED]
- REQ-2546: packet_rewrite.v extended with hop_limit byte substitution at IPv6 header offset [IMPLEMENTED]
- REQ-2547: packet_rewrite.v extended with ECN bit substitution in TOS/TC byte [IMPLEMENTED]
- REQ-2548: rewrite_lut generates hop_limit/ecn output ports and per-entry values [IMPLEMENTED]
- REQ-2549: rewrite_flags bits 10-12 for dec_hop_limit/set_hop_limit/set_ecn [IMPLEMENTED]
- REQ-2550: IPv6 routing YAML example (ipv6_routing.yaml) [IMPLEMENTED]

### Phase 26.4: Cocotb Test Completeness
- REQ-2560: 14 PacketFactory methods for protocol-specific frame construction [IMPLEMENTED]
- REQ-2561: PacketFactory methods for GRE, OAM, NSH, Geneve, conntrack, ip_ttl frame types [IMPLEMENTED]
- REQ-2562: 13 protocol branches in test_harness.py.tera for directed test generation [IMPLEMENTED]
- REQ-2563: Protocol-specific directed tests for all supported protocol types [IMPLEMENTED]

### Phase 26.5: Hypothesis Property Test Completeness
- REQ-2570: 8 new Hypothesis strategies: gre_frames, oam_frames, nsh_frames, arp_security_frames, icmp_frames, icmpv6_frames, qinq_frames, tcp_flags_frames [IMPLEMENTED]
- REQ-2571: 9 conditional blocks in test_properties.py.tera for protocol-specific property tests [IMPLEMENTED]
- REQ-2572: Protocol strategies imported and wired into generated test files [IMPLEMENTED]

### Phase 26.6: VLAN PCP / Outer VLAN Rewrite
- REQ-2580: set_vlan_pcp rewrite action — set VLAN PCP priority bits (0-7) [IMPLEMENTED]
- REQ-2581: set_outer_vlan_id rewrite action — set outer VLAN ID for QinQ (0-4095) [IMPLEMENTED]
- REQ-2582: set_vlan_pcp range validation (0-7) [IMPLEMENTED]
- REQ-2583: set_outer_vlan_id range validation (0-4095) [IMPLEMENTED]
- REQ-2584: packet_rewrite.v extended with VLAN PCP bit substitution [IMPLEMENTED]
- REQ-2585: packet_rewrite.v extended with outer VLAN ID substitution [IMPLEMENTED]
- REQ-2586: rewrite_lut generates vlan_pcp/outer_vlan_id output ports [IMPLEMENTED]
- REQ-2587: rewrite_flags bits 13-14 for set_vlan_pcp/set_outer_vlan_id [IMPLEMENTED]
- REQ-2588: QoS rewrite YAML example (qos_rewrite.yaml) [IMPLEMENTED]

### Lint Rules (Phase 26)
- REQ-2600: LINT040 — Geneve VNI without UDP prerequisite (ip_protocol:17, dst_port:6081) [IMPLEMENTED]
- REQ-2601: LINT041 — ip_ttl without IPv4 ethertype (0x0800) prerequisite [IMPLEMENTED]
- REQ-2602: LINT042 — frame_len_min/max is simulation-only (informational) [IMPLEMENTED]
- REQ-2603: LINT043 — dec_hop_limit/set_hop_limit without IPv6 ethertype prerequisite [IMPLEMENTED]
- REQ-2604: LINT044 — set_ecn without IPv4 or IPv6 ethertype prerequisite [IMPLEMENTED]
- REQ-2605: LINT045 — set_vlan_pcp without VLAN prerequisite [IMPLEMENTED]
- REQ-2606: LINT046 — set_outer_vlan_id without QinQ (802.1ad) prerequisite [IMPLEMENTED]

### Test Counts (Phase 26)
- REQ-2610: 479 Rust unit tests (through Phase 26) [IMPLEMENTED]
- REQ-2611: 327 Rust integration tests (through Phase 26) [IMPLEMENTED]
- REQ-2612: 67 Python scoreboard unit tests (through Phase 26) [IMPLEMENTED]
- REQ-2613: 42 YAML examples [IMPLEMENTED]
- REQ-2614: 46 lint rules (LINT001-046) [IMPLEMENTED]
- REQ-2615: 33 mutation types [IMPLEMENTED]

## Phase 27 Requirements — Parameterized Data Path Width + P4 Export + Multi-Table Pipeline

### Phase 27.1: Parameterized Data Path Width

#### CLI Flag
- REQ-2700: `--width` CLI flag on `compile` command accepting values 8, 64, 128, 256, 512
- REQ-2701: Default width remains 8-bit (backward compatible with existing builds)
- REQ-2702: `--width` validation rejects non-power-of-2 or unsupported widths

#### Width Converters
- REQ-2710: `axis_wide_to_8.v` — parameterized wide-to-narrow AXI-Stream deserializer (replaces fixed axis_512_to_8.v for non-512 widths)
- REQ-2711: `axis_8_to_wide.v` — parameterized narrow-to-wide AXI-Stream serializer (replaces fixed axis_8_to_512.v for non-512 widths)
- REQ-2712: Width converters parameterized by DATA_WIDTH (8/64/128/256/512)
- REQ-2713: Width converters pass iverilog lint for all supported widths
- REQ-2714: Platform targets (OpenNIC/Corundum) use width-aware converters based on `--width` setting
- REQ-2715: Width 8 bypasses converters entirely (no width conversion needed)

#### Resource Estimation
- REQ-2720: `estimate --width` adjusts LUT/FF resource estimates based on data path width
- REQ-2721: Width-proportional FIFO and adapter resource scaling in estimates

#### Lint Rules
- REQ-2730: LINT047 — width > 8 without `--axi` flag (width conversion requires AXI-Stream wrapper)
- REQ-2731: LINT048 — width mismatch with platform target (e.g., OpenNIC expects 512-bit, Corundum expects 512-bit)

### Phase 27.2: P4 Export

#### CLI Subcommand
- REQ-2740: `p4-export` subcommand generating P4_16 PSA (Portable Switch Architecture) programs from YAML rules
- REQ-2741: Generated P4 program includes headers, parser, ingress control, deparser
- REQ-2742: `--json` flag on `p4-export` for structured P4 export metadata
- REQ-2743: `-o` output path flag for P4 file destination (default stdout)

#### Match Field Mapping
- REQ-2750: All 55 match fields mapped to P4 match kinds (exact, lpm, ternary, range)
- REQ-2751: L2 fields (dst_mac, src_mac, ethertype, vlan_id, vlan_pcp) mapped as exact/ternary
- REQ-2752: L3 fields (src_ip, dst_ip) mapped as lpm (CIDR → prefix length)
- REQ-2753: L4 fields (src_port, dst_port) mapped as range when port range specified, exact otherwise
- REQ-2754: IPv6 fields (src_ipv6, dst_ipv6) mapped as lpm
- REQ-2755: Tunnel fields (vxlan_vni, gtp_teid, geneve_vni, gre_protocol, gre_key, mpls_label) mapped as exact
- REQ-2756: Protocol fields (ip_protocol, ipv6_next_header, tcp_flags, icmp_type, icmp_code, etc.) mapped as exact/ternary
- REQ-2757: QoS fields (ip_dscp, ip_ecn, ipv6_dscp, ipv6_ecn) mapped as exact
- REQ-2758: Stateful/advanced fields (conntrack_state, byte_match) generate comments noting P4 limitations

#### Rewrite Action Mapping
- REQ-2760: set_dst_mac, set_src_mac mapped to P4 header field assignment actions
- REQ-2761: set_src_ip, set_dst_ip, set_ttl, dec_ttl mapped to P4 IPv4 header actions
- REQ-2762: set_src_port, set_dst_port mapped to P4 L4 header actions
- REQ-2763: set_dscp, set_ecn mapped to P4 QoS rewrite actions
- REQ-2764: set_vlan_id, set_vlan_pcp mapped to P4 VLAN tag modification actions
- REQ-2765: dec_hop_limit, set_hop_limit mapped to P4 IPv6 header actions

#### Extern Support
- REQ-2770: Conntrack mapped to P4 Register extern with hash-based lookup in control block
- REQ-2771: Rate limiting mapped to P4 Meter extern (color-based token bucket)
- REQ-2772: Per-rule counters mapped to P4 Counter extern (packets and bytes)

#### Pipeline-Aware Export
- REQ-2780: Multi-table YAML rules (Phase 27.3) exported as multi-table P4 pipeline
- REQ-2781: Single-table YAML rules exported as single ingress table
- REQ-2782: P4 table entries generated as const entries or separate table-add commands

### Phase 27.3: Multi-Table Pipeline

#### YAML Schema
- REQ-2800: Optional `tables:` top-level YAML key for multi-table pipeline definition
- REQ-2801: Each table entry has `name`, `rules`, `default_action`, and optional `next_table`
- REQ-2802: `next_table` field specifies the next stage to evaluate (DAG structure)
- REQ-2803: Backward compatible — YAML without `tables:` key uses single implicit table (existing behavior preserved)
- REQ-2804: Tables key and rules key are mutually exclusive at the top level (validation error if both present)

#### Data Model
- REQ-2810: PipelineStage struct with fields: name (String), rules (Vec<Rule>), default_action (Action), next_table (Option<String>)
- REQ-2811: Pipeline struct containing ordered Vec<PipelineStage> with stage name uniqueness validation
- REQ-2812: DAG cycle detection for stage graph validation (reject cycles at load time)
- REQ-2813: next_table references validated against declared stage names (reject dangling references)

#### Verilog Generation
- REQ-2820: Shared single frame_parser instance across all pipeline stages
- REQ-2821: Per-stage rule matchers generated independently (rule_match_stageN_ruleM naming)
- REQ-2822: Per-stage decision logic (priority encoder per stage)
- REQ-2823: AND-combined final decision across all stages (packet passes only if all stages pass)
- REQ-2824: Pipeline top-level module wiring all stages with shared parser outputs
- REQ-2825: Stage evaluation order follows DAG topology (topological sort)

#### Simulation
- REQ-2830: Pipeline simulation evaluates stages sequentially in topological order
- REQ-2831: AND semantics — packet passes only if all evaluated stages return pass
- REQ-2832: Per-stage match results in simulation output (which rule matched in each stage)
- REQ-2833: `--json` simulation output includes per-stage breakdown

#### Tool Support
- REQ-2840: `stats` command reports per-stage rule counts and field usage
- REQ-2841: LINT049 — pipeline stage with no rules (empty stage warning)
- REQ-2842: LINT050 — unreachable pipeline stage (not referenced by any next_table and not the first stage)
- REQ-2843: `estimate` computes per-stage and total LUT/FF resource usage
- REQ-2844: `graph` outputs per-stage DOT subgraphs with inter-stage edges
- REQ-2845: `diff` compares pipeline structures (stage added/removed/modified)
- REQ-2846: Mutation type 34: remove_pipeline_stage — removes a non-first stage from the pipeline
- REQ-2847: Mutation type 35: swap_stage_order — swaps two adjacent stages in the pipeline

### Phase 27 Test Counts
- REQ-2900: 896 Rust tests (569 unit + 327 integration) through Phase 27
- REQ-2901: 73 Python scoreboard unit tests through Phase 27
- REQ-2902: 45 YAML examples (42 existing + width_demo + p4_export_demo + multi_table_pipeline)
- REQ-2903: 50 lint rules (LINT001-050)
- REQ-2904: 35 mutation types

## Phase 28 Requirements — IEEE 1588 PTP Hardware Timestamping [IMPLEMENTED]

### Phase 28.1: PTP Match Fields (Model + Loader)
- REQ-2910: ptp_message_type match field — 4-bit (0-15), 0=Sync, 1=Delay_Req, 8=Follow_Up, 9=Delay_Resp, 11=Announce [IMPLEMENTED]
- REQ-2911: ptp_domain match field — 8-bit domain number (0-255) [IMPLEMENTED]
- REQ-2912: ptp_version match field — 4-bit PTP version (0-15, typically 2 for PTPv2) [IMPLEMENTED]
- REQ-2913: uses_ptp() helper method on MatchCriteria [IMPLEMENTED]
- REQ-2914: YAML loader validates ptp_message_type range (0-15) [IMPLEMENTED]
- REQ-2915: YAML loader validates ptp_version range (0-15) [IMPLEMENTED]
- REQ-2916: Shadow detection for PTP fields [IMPLEMENTED]
- REQ-2917: Overlap detection for PTP fields [IMPLEMENTED]
- REQ-2918: Simulator parses and evaluates PTP match fields [IMPLEMENTED]

### Phase 28.2: Frame Parser — S_PTP_HDR State
- REQ-2920: S_PTP_HDR parser state (5'd22) for PTP header extraction [IMPLEMENTED]
- REQ-2921: L2 PTP detection — EtherType 0x88F7 transitions to S_PTP_HDR [IMPLEMENTED]
- REQ-2922: L4 PTP detection — UDP dst_port 319 or 320 transitions to S_PTP_HDR [IMPLEMENTED]
- REQ-2923: PTP header extraction — messageType[3:0], versionPTP[3:0], domainNumber[7:0] [IMPLEMENTED]
- REQ-2924: ptp_valid output flag set after PTP header extraction [IMPLEMENTED]
- REQ-2925: ptp_clock.v — free-running 64-bit PTP hardware clock [IMPLEMENTED]
- REQ-2926: SOF/EOF timestamp latching in ptp_clock.v [IMPLEMENTED]
- REQ-2927: Parameterized CLK_PERIOD_NS (default 4 for 250MHz) [IMPLEMENTED]

### Phase 28.3: Verilog Generation + CLI
- REQ-2930: has_ptp in GlobalProtocolFlags [IMPLEMENTED]
- REQ-2931: PTP condition expressions in build_condition_expr [IMPLEMENTED]
- REQ-2932: --ptp CLI flag on compile command [IMPLEMENTED]
- REQ-2933: PTP wire declarations and port connections in templates [IMPLEMENTED]
- REQ-2934: PTP clock RTL copied when --ptp enabled [IMPLEMENTED]

### Phase 28.4: Verification
- REQ-2940: Python scoreboard PTP field matching [IMPLEMENTED]
- REQ-2941: PacketFactory.ptp() with L2 and L4 modes [IMPLEMENTED]
- REQ-2942: 6 PTP scoreboard unit tests [IMPLEMENTED]
- REQ-2943: SVA assertions — PTP messageType/version bounds [IMPLEMENTED]
- REQ-2944: SVA assertions — PTP prerequisite (ptp_valid required) [IMPLEMENTED]
- REQ-2945: SVA cover properties — PTP Sync message, ptp_valid [IMPLEMENTED]
- REQ-2946: Cocotb PTP test generation [IMPLEMENTED]

### Phase 28.5: Tool Integration
- REQ-2950: LINT051 — PTP fields without EtherType 0x88F7 or UDP 319/320 [IMPLEMENTED]
- REQ-2951: LINT052 — ptp_message_type > 13 (undefined PTP types, info) [IMPLEMENTED]
- REQ-2952: Mutation 36 — remove_ptp_message_type [IMPLEMENTED]
- REQ-2953: Mutation 37 — shift_ptp_domain [IMPLEMENTED]
- REQ-2954: Estimate PTP field costs (+6 LUTs per PTP rule) [IMPLEMENTED]
- REQ-2955: Stats PTP field usage counters [IMPLEMENTED]
- REQ-2956: Diff PTP field comparisons [IMPLEMENTED]
- REQ-2957: Doc PTP field HTML output [IMPLEMENTED]
- REQ-2958: Graph PTP criteria in DOT output [IMPLEMENTED]
- REQ-2959: P4 export PTP header (ptp_t) + parser states [IMPLEMENTED]

### Phase 28.6: Examples + Documentation
- REQ-2960: ptp_boundary_clock.yaml — PTP boundary clock filtering with domain isolation [IMPLEMENTED]
- REQ-2961: ptp_5g_fronthaul.yaml — 5G fronthaul PTP + eCPRI filtering [IMPLEMENTED]

### Phase 28 Test Counts
- REQ-2970: 896 Rust tests (518 unit + 378 integration) through Phase 28 [IMPLEMENTED]
- REQ-2971: 79 Python scoreboard unit tests through Phase 28 [IMPLEMENTED]
- REQ-2972: 47 YAML examples (45 existing + ptp_boundary_clock + ptp_5g_fronthaul) [IMPLEMENTED]
- REQ-2973: 50 lint rules (LINT001-052, some skipped) [IMPLEMENTED]
- REQ-2974: 37 mutation types [IMPLEMENTED]

## Phase 29 Requirements — RSS (Receive Side Scaling) Multi-Queue Dispatch

### Overview
- REQ-3000: RSS (Receive Side Scaling) multi-queue dispatch for multi-core packet processing — distributes incoming packets across multiple hardware queues to enable parallel processing on multi-core CPUs

### Per-Rule RSS Queue Field
- REQ-3010: `rss_queue` match/action field on StatelessRule (Option<u8>, 0-15) for explicit per-rule queue pinning
- REQ-3011: rss_queue range validation (0-15, reject >= 16) in YAML loader
- REQ-3012: rss_queue in MatchCriteria or RewriteAction model (per-rule queue override)
- REQ-3013: Shadow/overlap detection considers rss_queue field

### CLI Flags
- REQ-3020: `--rss` CLI flag on `compile` command to enable RSS hardware generation
- REQ-3021: `--rss-queues N` CLI flag (1-16, default 4) for queue count configuration
- REQ-3022: `--rss-queues` validation rejects values < 1 or > 16
- REQ-3023: `--rss` requires `--axi` for CSR access to indirection table (compile-time error if `--axi` not set)

### Toeplitz Hash Computation
- REQ-3030: Toeplitz hash computation in RTL using Microsoft RSS default key (40-byte standard key)
- REQ-3031: Hash computed over IP source/destination addresses and TCP/UDP source/destination ports (4-tuple for TCP/UDP, 2-tuple for non-TCP/UDP)
- REQ-3032: Hash result used as index into indirection table for queue selection
- REQ-3033: Hash computation pipelined to avoid critical path impact

### Indirection Table
- REQ-3040: 128-entry indirection table mapping hash values to queue IDs
- REQ-3041: AXI-Lite runtime configuration of indirection table entries
- REQ-3042: Default indirection table initialization: round-robin queue assignment across configured queue count
- REQ-3043: Each indirection table entry holds a queue ID (4-bit for 0-15 range)

### Per-Rule Queue Override
- REQ-3050: rss_queue_lut ROM — generated combinational lookup mapping rule_idx to queue override
- REQ-3051: Per-rule rss_queue overrides Toeplitz hash-based queue selection when set
- REQ-3052: Rules without rss_queue use the hash-based indirection table (default behavior)
- REQ-3053: Queue override priority: per-rule rss_queue > indirection table lookup

### Verilog Generation
- REQ-3060: has_rss flag in GlobalProtocolFlags controlling conditional RSS port/logic generation
- REQ-3061: rss_queue output port on packet_filter_top (4-bit queue ID)
- REQ-3062: RSS queue output wired through AXI-Stream top-level and platform wrappers
- REQ-3063: rss_queue_lut.v generated (combinational ROM) when any rule specifies rss_queue

### Simulation
- REQ-3070: Software Toeplitz hash implementation in simulator for RSS queue prediction
- REQ-3071: SimPacket supports rss_queue field
- REQ-3072: Simulation results include predicted RSS queue ID
- REQ-3073: `--json` simulation output includes `rss_queue` field

### Python Verification
- REQ-3080: Python scoreboard predict_rss_queue() function for queue prediction verification
- REQ-3081: Scoreboard Rule dataclass includes rss_queue field
- REQ-3082: Scoreboard matches() considers rss_queue for result comparison
- REQ-3083: PacketFactory supports RSS queue annotation in test packets

### Formal Verification (SVA)
- REQ-3090: SVA assertion: rss_queue output always < configured queue count (queue bounds check)
- REQ-3091: SVA assertion: per-rule rss_queue override has priority over hash-based selection
- REQ-3092: SVA cover property: rss_queue changes across consecutive packets (queue distribution)

### Lint Rules
- REQ-3100: LINT053 — rss_queue specified without `--rss` flag (warning: queue field ignored without RSS hardware)
- REQ-3101: LINT054 — rss_queue >= 16 (error: out of range for 4-bit queue ID)
- REQ-3102: LINT055 — RSS (`--rss`) requires `--axi` for CSR access to indirection table

### Mutation Testing
- REQ-3110: Mutation type 38: remove_rss_queue — clears rss_queue from rules that specify it
- REQ-3111: Mutation type 39: shift_rss_queue — increments rss_queue by 1 (modulo 16)

### P4 Export
- REQ-3120: P4 ActionSelector extern for hash-based queue dispatch
- REQ-3121: P4 action_selector mapped from RSS Toeplitz hash configuration
- REQ-3122: Per-rule queue override mapped to P4 direct action with queue_id parameter

### Tool Support
- REQ-3130: Estimate: RSS hardware resource costs (Toeplitz hash LUTs, indirection table FFs, queue mux)
- REQ-3131: Stats: rss_queue field usage counter (JSON + text)
- REQ-3132: Diff: rss_queue field change detection (text + JSON + HTML)
- REQ-3133: Doc: rss_queue in HTML rule documentation
- REQ-3134: Graph: rss_queue label on DOT rule nodes

### Examples
- REQ-3140: rss_multiqueue.yaml — RSS multi-queue dispatch example with per-rule queue pinning
- REQ-3141: rss_datacenter.yaml — data center RSS example with hash-based distribution + management queue pinning

### Phase 29 Test Counts
- REQ-3150: 914 Rust tests (536 unit + 378 integration) through Phase 29
- REQ-3151: 85 Python scoreboard unit tests through Phase 29
- REQ-3152: 49 YAML examples (47 existing + rss_multiqueue + rss_datacenter)
- REQ-3153: 53 lint rules (LINT001-055, some skipped)
- REQ-3154: 39 mutation types
