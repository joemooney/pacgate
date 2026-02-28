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
