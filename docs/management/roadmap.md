# PacGate Product Roadmap

**Document ID**: PG-RM-001
**Date**: 2026-02-26

---

## Vision Statement

Make FPGA packet filter development as easy as writing a YAML config file, with verification quality that exceeds hand-crafted testbenches.

## Roadmap Timeline

```
2026 Q1                 Q2                  Q3                  Q4
├───────────────────┼───────────────────┼───────────────────┼───────────────────┤
│                   │                   │                   │                   │
│  Phase 1 ████     │                   │                   │                   │
│  Basic filter     │                   │                   │                   │
│  DONE             │                   │                   │                   │
│                   │                   │                   │                   │
│  Phase 2 ████████ │                   │                   │                   │
│  Multi-rule +     │                   │                   │                   │
│  Coverage         │                   │                   │                   │
│  DONE             │                   │                   │                   │
│                   │                   │                   │                   │
│  Phase 3 ████████████                 │                   │                   │
│  Stateful FSM +   │                   │                   │                   │
│  Sequence tests   │                   │                   │                   │
│  DONE             │                   │                   │                   │
│                   │                   │                   │                   │
│         Phase 4 ██████████████        │                   │                   │
│         Synthesis │                   │                   │                   │
│         Artix-7   │                   │                   │                   │
│                   │                   │                   │                   │
│                   │  Phase 5 █████████│                   │                   │
│                   │  Layer 3 matching │                   │                   │
│                   │  (IP headers)     │                   │                   │
│                   │                   │                   │                   │
│                   │         Phase 6 ██████████████        │                   │
│                   │         Multi-port│switch fabric      │                   │
│                   │                   │                   │                   │
│                   │                   │  Phase 7 █████████████████████        │
│                   │                   │  Production       │                   │
│                   │                   │  hardening +      │                   │
│                   │                   │  AXI integration  │                   │
│                   │                   │                   │                   │

2027 Q1                 Q2
├───────────────────┼───────────────────┤
│                   │                   │
│  Phase 8 █████████│                   │
│  Formal verif.    │                   │
│  integration      │                   │
│                   │                   │
│         Phase 9 ██████████████        │
│         Commercial│pilot              │
│                   │                   │
```

## Phase Details

### Phase 1: Basic Filter (COMPLETE)
- Single stateless rule (allow ARP)
- Hand-written Ethernet frame parser
- Tera-templated Verilog generation
- Basic cocotb test generation (positive + negative)
- **Deliverable**: End-to-end demo, ARP pass/drop

### Phase 2: Multi-Rule + Coverage (COMPLETE)
- Multiple stateless rules with diverse match fields
- MAC wildcard/mask support in hardware
- VLAN ID and PCP matching
- Constrained random packet generation (500 packets/run)
- Scoreboard reference model with mismatch detection
- Functional coverage collection and reporting
- Corner case test suite (jumbo, runt, back-to-back, reset recovery)
- Enterprise rule set example (7 rules)
- **Deliverable**: 13-test suite, scoreboard, coverage report

### Phase 3: Stateful FSM (COMPLETE)
- YAML-defined finite state machines with timeout counters
- Temporal sequence matching (e.g., ARP then IPv4 within N cycles)
- Generated FSM Verilog with state encoding and timeout logic
- **Deliverable**: Stateful rule compilation and Verilog lint

### Phase 4: Synthesis (PLANNED — Q2 2026)
- Vivado project generation for Artix-7
- XDC constraint file templates
- Resource utilization reporting
- Timing analysis integration
- **Deliverable**: Working bitstream on Artix-7 dev board

### Phase 5: Layer 3 Matching (PLANNED — Q2 2026)
- IPv4 header field matching (src_ip, dst_ip, protocol)
- IPv6 header field matching
- TCP/UDP port matching
- Extended frame parser for IP headers
- **Deliverable**: L2-L4 filtering capability

### Phase 6: Multi-Port Switch (PLANNED — Q3 2026)
- Multiple ingress/egress ports
- Per-port rule sets
- Cross-port forwarding decisions
- Port-based VLAN assignment
- **Deliverable**: Multi-port switch fabric

### Phase 7: Production Hardening (PLANNED — Q3-Q4 2026)
- AXI-Stream interface (replacing simple streaming)
- Store-and-forward FIFO with frame buffering
- Error handling (CRC check, oversize frames)
- Performance counters and statistics
- **Deliverable**: Production-ready IP core

### Phase 8: Formal Verification (PLANNED — Q1 2027)
- SVA assertion generation from YAML
- SymbiYosys integration for formal property checking
- MCY mutation testing for test quality measurement
- **Deliverable**: Formal proofs of correctness

### Phase 9: Commercial Pilot (PLANNED — Q2 2027)
- Customer-facing documentation
- Installation packaging
- Support infrastructure
- Performance benchmarks vs. competing solutions
- **Deliverable**: Customer deployment

## Key Milestones

| Milestone | Target | Status |
|-----------|--------|--------|
| First cocotb test passes | 2026-02-26 | DONE |
| Enterprise rule set (7 rules, 13 tests) | 2026-02-26 | DONE |
| Stateful FSM compilation | 2026-02-26 | DONE |
| First FPGA bitstream | 2026 Q2 | PLANNED |
| Layer 3 matching | 2026 Q2 | PLANNED |
| Production IP core | 2026 Q4 | PLANNED |
| Formal verification | 2027 Q1 | PLANNED |
