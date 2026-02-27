# PacGate Test Plan

**Document ID**: PG-TP-001
**Version**: 2.0
**Date**: 2026-02-26
**Status**: Approved

---

## 1. Test Plan Overview

This document defines the complete verification test plan for the PacGate packet filter. All tests are organized by feature area, priority, and automation status.

## 2. Test Matrix

### 2.1 Frame Parser Tests (FP-xxx)

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| FP-001 | Parse standard Ethernet frame (no VLAN) | Directed | P0 | PASS |
| FP-002 | Parse 802.1Q VLAN-tagged frame | Directed | P0 | PASS |
| FP-003 | Runt frame (< 14 bytes header) | Corner | P1 | PASS |
| FP-004 | Maximum size frame (1518 bytes) | Boundary | P1 | PASS |
| FP-005 | Jumbo frame (9000+ bytes) | Boundary | P2 | PASS |
| FP-006 | Back-to-back frames (no gap) | Stress | P1 | PASS |
| FP-007 | Reset during frame parsing | Corner | P0 | PASS |
| FP-008 | Frame with all-zero fields | Boundary | P1 | PASS |
| FP-009 | Frame with all-FF fields | Boundary | P1 | PASS |
| FP-010 | pkt_valid deasserted mid-frame | Error | P1 | PASS |
| FP-011 | pkt_sof without preceding pkt_eof | Error | P1 | PASS |
| FP-012 | Multiple VLAN tags (Q-in-Q) | Corner | P2 | PLANNED |
| FP-013 | Minimum inter-frame gap | Stress | P2 | PASS |
| FP-014 | Parser state after 1000 consecutive frames | Endurance | P2 | PASS |

### 2.2 Stateless Rule Matching Tests (SR-xxx)

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| SR-001 | Single rule: EtherType exact match | Directed | P0 | PASS |
| SR-002 | Single rule: EtherType no match (default action) | Directed | P0 | PASS |
| SR-003 | Single rule: dst_mac exact match | Directed | P0 | PASS |
| SR-004 | Single rule: src_mac exact match | Directed | P0 | PASS |
| SR-005 | Single rule: MAC wildcard match | Directed | P0 | PASS |
| SR-006 | Single rule: MAC wildcard no match | Directed | P0 | PASS |
| SR-007 | Single rule: VLAN ID match | Directed | P1 | PASS |
| SR-008 | Single rule: VLAN PCP match | Directed | P1 | PASS |
| SR-009 | Multi-rule: highest priority wins | Directed | P0 | PASS |
| SR-010 | Multi-rule: lower priority rule not shadowed | Directed | P0 | PASS |
| SR-011 | Multi-rule: all rules miss → default | Directed | P0 | PASS |
| SR-012 | Multi-rule: overlapping match conditions | Directed | P1 | PASS |
| SR-013 | EtherType boundary: 0x0000 | Boundary | P1 | PASS |
| SR-014 | EtherType boundary: 0xFFFF | Boundary | P1 | PASS |
| SR-015 | VLAN ID boundary: 0 | Boundary | P1 | PASS |
| SR-016 | VLAN ID boundary: 4095 | Boundary | P1 | PASS |
| SR-017 | Broadcast MAC (ff:ff:ff:ff:ff:ff) | Directed | P0 | PASS |
| SR-018 | Multicast MAC (bit 0 of octet 0 set) | Directed | P1 | PASS |
| SR-019 | 10 rules: constrained random 1000 packets | Random | P0 | PASS |
| SR-020 | 50 rules: constrained random 5000 packets | Random | P1 | PLANNED |
| SR-021 | 100 rules: stress test | Stress | P2 | PLANNED |

### 2.3 Stateful FSM Rule Tests (SF-xxx) — Phase 3

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| SF-001 | Simple 2-state sequence (ARP → IPv4) | Directed | P0 | PASS |
| SF-002 | Sequence timeout (no second packet within limit) | Directed | P0 | PASS |
| SF-003 | Sequence interrupted by wrong packet type | Directed | P1 | PASS |
| SF-004 | Sequence reset on new SOF during wait | Corner | P1 | PASS |
| SF-005 | Multiple FSM rules active simultaneously | Directed | P1 | PLANNED |
| SF-006 | FSM timeout at exact cycle boundary | Boundary | P1 | PASS |
| SF-007 | FSM with 3+ states | Directed | P1 | PLANNED |
| SF-008 | FSM + stateless rule interaction | Integration | P1 | PLANNED |

### 2.4 Decision Logic Tests (DL-xxx)

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| DL-001 | Decision latches until next pkt_sof | Directed | P0 | PASS |
| DL-002 | Decision clears on pkt_sof | Directed | P0 | PASS |
| DL-003 | Decision clears on reset | Directed | P0 | PASS |
| DL-004 | No decision without fields_valid | Directed | P0 | PASS |
| DL-005 | Priority encoding correctness (N rules) | Parameterized | P0 | PASS |

### 2.5 Integration Tests (IT-xxx)

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| IT-001 | End-to-end: YAML → Verilog → sim → PASS | Integration | P0 | PASS |
| IT-002 | Rule change propagates to both RTL and test | Regression | P0 | PASS |
| IT-003 | Scoreboard matches DUT for 10,000 random packets | Scoreboard | P0 | PASS |
| IT-004 | Coverage target met (>90% functional) | Coverage | P0 | PASS |

### 2.6 Compiler Tests (CT-xxx)

| Test ID | Description | Type | Priority | Status |
|---------|-------------|------|----------|--------|
| CT-001 | Valid YAML parses without error | Unit | P0 | PASS |
| CT-002 | Invalid YAML produces clear error | Unit | P0 | PASS |
| CT-003 | Duplicate priority rejected | Unit | P0 | PASS |
| CT-004 | Invalid MAC format rejected | Unit | P0 | PASS |
| CT-005 | Invalid EtherType rejected | Unit | P0 | PASS |
| CT-006 | Empty rule list rejected | Unit | P0 | PASS |
| CT-007 | Generated Verilog passes iverilog lint | Integration | P0 | PASS |
| CT-008 | MAC wildcard generates correct mask | Unit | P0 | PASS |

## 3. Coverage Goals

| Coverage Type | Target | Current |
|---------------|--------|---------|
| Rule hit (every rule triggered) | 100% | 100% |
| EtherType values (bins) | 95% | 100% |
| MAC pattern types | 90% | 95% |
| VLAN tag present/absent | 100% | 100% |
| Frame size bins | 90% | 90% |
| FSM state coverage | 100% | 100% |
| FSM transition coverage | 95% | 95% |
| Priority encoding paths | 100% | 100% |
| Default action exercised | 100% | 100% |
| **Overall functional** | **95%** | **96%** |

## 4. Regression Strategy

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Quick Smoke    │────▶│  Full Regression │────▶│  Extended       │
│  (< 30 sec)     │     │  (< 5 min)       │     │  (< 30 min)     │
│                 │     │                  │     │                 │
│  • Directed     │     │  • All directed  │     │  • 10K random   │
│    tests only   │     │  • 1K random     │     │  • Coverage     │
│  • 1 rule set   │     │  • Coverage      │     │    closure      │
│                 │     │  • Scoreboard    │     │  • Stress tests │
└─────────────────┘     └──────────────────┘     └─────────────────┘
     CI: every push          CI: every PR            Nightly
```

## 5. Defect Tracking

| Severity | Definition | Response Time |
|----------|-----------|---------------|
| S1 — Critical | Decision incorrect (pass when should drop) | Immediate fix |
| S2 — Major | Coverage regression, test infrastructure broken | Same day |
| S3 — Minor | Non-functional (performance, cosmetic) | Next sprint |
| S4 — Enhancement | New test idea, better coverage | Backlog |
