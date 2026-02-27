# PacGate Product Roadmap

**Document ID**: PG-RM-001
**Date**: 2026-02-27

---

## Vision Statement

Make FPGA packet filter development as easy as writing a YAML config file, with verification quality that exceeds hand-crafted testbenches.

## Roadmap Timeline

```
2026 Q1 ████████████████████████████████████████████████████████████████████████
│ Phase 1:  Basic L2 filter (single rule, frame parser, cocotb tests)    DONE │
│ Phase 2:  Multi-rule + coverage (7 rules, scoreboard, 85%+ coverage)   DONE │
│ Phase 3:  Stateful FSM (sequence detection, timeout counters)          DONE │
│ Phase 4:  Synthesis (AXI-Stream, Yosys, formal verification, property) DONE │
│ Phase 5:  Docs + examples (12 examples, lint, workshops, license)      DONE │
│ Phase 6:  L3/L4 matching (IPv4/TCP/UDP, counters, PCAP, VXLAN)        DONE │
│ Phase 7:  Advanced (byte-match, HSM, Mermaid, multi-port, conntrack)   DONE │
│ Phase 8:  IPv6 + simulation (IPv6, rate limiting, overlap detection)   DONE │
│ Phase 9:  Analysis (PCAP analysis, synthesis gen, mutation, templates)  DONE │
│ Phase 10: Verification (full-stack scoreboard, directed L3/L4, formal) DONE │
│ Phase 11: Reachability, PCAP output, benchmarking, HTML diff           DONE │
│ Phase 12: Protocols (GTP-U, MPLS, IGMP/MLD)                           DONE │
│ Phase 13: Verification framework (coverage closure, MCY, boundary)     DONE │
│ Phase 14: Protocol verification (scoreboard, factory, SVA, overlap)    DONE │
│ Phase 15: Verification depth (reachability, mutations, Hypothesis, CI) DONE │
│ Phase 16: Simulator completeness (rate-limit, conntrack, --stateful)   DONE │
████████████████████████████████████████████████████████████████████████████████

Future
├───────────────────┼───────────────────┼───────────────────┤
│                   │                   │                   │
│  P4 Import/Export │  RISC-V           │  Multi-vendor     │
│  Interoperability │  Co-processor     │  FPGA support     │
│                   │  (dynamic rules)  │  (Intel, Lattice) │
│                   │                   │                   │
│  Visual rule      │  Cloud synthesis  │  Hardware-in-loop │
│  editor (web UI)  │  service          │  testing          │
│                   │                   │                   │
```

## Phase Details

### Phase 1: Basic Filter (COMPLETE)
- Single stateless rule (allow ARP)
- Hand-written Ethernet frame parser
- Tera-templated Verilog generation
- Basic cocotb test generation (positive + negative)

### Phase 2: Multi-Rule + Coverage (COMPLETE)
- Multiple stateless rules with diverse match fields
- MAC wildcard/mask support in hardware
- VLAN ID and PCP matching
- Constrained random packet generation (500 packets/run)
- Scoreboard reference model with mismatch detection
- Functional coverage collection and reporting

### Phase 3: Stateful FSM (COMPLETE)
- YAML-defined finite state machines with timeout counters
- Temporal sequence matching (e.g., ARP then IPv4 within N cycles)
- Generated FSM Verilog with state encoding and timeout logic

### Phase 4: AXI-Stream + Synthesis + Formal (COMPLETE)
- AXI-Stream wrapper with store-and-forward FIFO
- Yosys synthesis project generation for Artix-7
- SVA assertion generation + SymbiYosys formal verification
- Hypothesis property-based testing
- FPGA resource estimation (LUTs/FFs) + timing analysis

### Phase 5: Documentation + Examples (COMPLETE)
- 12 production-quality YAML examples
- `lint` subcommand with best-practice analysis
- Comprehensive documentation suite (user guide, test guide, workshops)
- Proprietary license

### Phase 6: L3/L4 Matching (COMPLETE)
- IPv4 header field matching (src_ip, dst_ip CIDR, ip_protocol)
- TCP/UDP port matching (exact and range)
- Per-rule 64-bit packet/byte counters with AXI-Lite CSR
- PCAP import for cocotb test stimulus
- HTML coverage report generation
- VXLAN tunnel parsing (24-bit VNI)

### Phase 7: Advanced Features (COMPLETE)
- Byte-offset matching with value/mask at arbitrary packet offsets
- Hierarchical state machines (nested states, variables, guards)
- Mermaid stateDiagram-v2 import/export
- Multi-port switch fabric (N independent filter instances)
- Connection tracking hash table with CRC hash + timeout

### Phase 8: IPv6 + Simulation (COMPLETE)
- IPv6 matching (src_ipv6, dst_ipv6 CIDR, ipv6_next_header)
- Software packet simulation (dry-run without hardware)
- Per-rule token-bucket rate limiting RTL
- Enhanced lint (12 rules)
- CIDR containment and port range overlap detection

### Phase 9: Analysis + Testing (COMPLETE)
- PCAP traffic analysis + automatic rule suggestion
- Yosys/Vivado synthesis project generation
- Advanced test generation (IPv6 cocotb, rate-limiter TB, mutation, coverage-driven)
- Rule templates (7 built-in with variable substitution)
- HTML rule documentation generation

### Phase 10: Verification Completeness (COMPLETE)
- Full-stack Python scoreboard (L2/L3/L4/IPv6/VXLAN/byte-match)
- Directed L3/L4 packet construction in generated tests
- Byte-match software simulation
- Enhanced SVA assertions (IPv6 CIDR, port range, rate limiter, byte-match)
- 5 conntrack cocotb tests
- CI pipeline expansion

### Phase 11: Advanced Analysis (COMPLETE)
- Reachability analysis (shadowed, unreachable, redundant rules)
- PCAP output from simulation (Wireshark-compatible)
- Performance benchmarking (compile time, sim throughput, LUT/FF scaling)
- HTML diff visualization (color-coded side-by-side comparison)

### Phase 12: Protocol Extensions (COMPLETE)
- GTP-U tunnel parsing (gtp_teid, 32-bit TEID after UDP:2152)
- MPLS label stack (mpls_label/mpls_tc/mpls_bos)
- IGMP/MLD multicast (igmp_type, mld_type)

### Phase 13: Verification Framework (COMPLETE)
- Coverage wiring (L3/L4 kwargs, CoverageDirector, XML export)
- Boundary/negative test generation
- MCY Verilog-level mutation testing config generation
- Mutation kill-rate runner (compile + lint each mutant)
- CI improvements (Hypothesis, JUnit, property tests)

### Phase 14: Protocol Verification (COMPLETE)
- GTP-U/MPLS/IGMP/MLD in Python scoreboard + packet factory
- Protocol-specific test templates (directed + random)
- SVA formal assertions for all protocol fields
- Shadow/overlap detection covers all protocols
- All analysis tools (stats/graph/diff/estimate/doc) fully cover protocol fields

### Phase 15: Verification Depth (COMPLETE)
- Reachability analysis with protocol fields + stateful rule tracking
- 11 mutation types (6 new protocol-specific strategies)
- 5 protocol coverage coverpoints
- 4 Hypothesis protocol strategies (GTP-U, MPLS, IGMP, MLD)
- LINT013-015 protocol prerequisite checks
- CI simulate matrix expanded to 8 examples

### Phase 16: Simulator Completeness (COMPLETE)
- Rate-limit simulation (token-bucket in software)
- Connection tracking simulation (5-tuple hash + reverse lookup)
- `--stateful` CLI flag for combined rate-limit + conntrack simulation
- Strengthened SVA assertions (rate-limit enforcement, protocol prerequisites + bounds)
- Protocol property tests wired into generated test files
- byte_match in HTML documentation output
- CI expansion (conntrack simulate, formal generate, rate-limit simulate)

## Key Milestones

| Milestone | Status |
|-----------|--------|
| First cocotb test passes | DONE |
| Enterprise rule set (7 rules, 13 tests) | DONE |
| Stateful FSM compilation | DONE |
| AXI-Stream + synthesis + formal | DONE |
| L3/L4 + IPv6 matching | DONE |
| Multi-port + connection tracking | DONE |
| GTP-U + MPLS + IGMP/MLD | DONE |
| Full verification completeness (388 Rust + 47 Python tests) | DONE |
| Stateful software simulation (rate-limit + conntrack) | DONE |
| 21 production-quality examples | DONE |
