# PacGate Functional Coverage Model

**Document ID**: PG-COV-001
**Version**: 2.0
**Date**: 2026-02-26
**Status**: Approved

---

## 1. Overview

This document defines the functional coverage model for the PacGate packet filter. Coverage is collected automatically during cocotb simulation and reported in both human-readable and machine-parseable formats.

**Philosophy**: "If it's not covered, it's not verified."

## 2. Coverage Architecture

```
┌──────────────────────────────────────────────────┐
│              Coverage Collection                  │
│                                                  │
│  ┌──────────────┐  ┌──────────────┐             │
│  │ Covergroup:  │  │ Covergroup:  │             │
│  │ packet_fields│  │ rule_hits    │             │
│  │              │  │              │             │
│  │ • ethertype  │  │ • rule_0_hit │             │
│  │ • dst_mac    │  │ • rule_1_hit │             │
│  │ • src_mac    │  │ • ...        │             │
│  │ • vlan_id    │  │ • default_hit│             │
│  │ • frame_size │  │              │             │
│  └──────────────┘  └──────────────┘             │
│                                                  │
│  ┌──────────────┐  ┌──────────────┐             │
│  │ Covergroup:  │  │ Covergroup:  │             │
│  │ decisions    │  │ corner_cases │             │
│  │              │  │              │             │
│  │ • pass_count │  │ • runt_frame │             │
│  │ • drop_count │  │ • jumbo_frame│             │
│  │ • latency    │  │ • reset_mid  │             │
│  └──────────────┘  │ • b2b_frames │             │
│                     └──────────────┘             │
│                                                  │
│  ┌──────────────────────────────────┐            │
│  │ Cross Coverage                    │            │
│  │ • ethertype × rule_action        │            │
│  │ • mac_type × frame_size          │            │
│  │ • vlan_present × rule_hit        │            │
│  └──────────────────────────────────┘            │
└──────────────────────────────────────────────────┘
```

## 3. Covergroup Definitions

### 3.1 CG_PACKET_FIELDS — Input Stimulus Coverage

**Purpose**: Ensure diverse stimulus across all input fields.

| Coverpoint | Bins | Description |
|------------|------|-------------|
| `cp_ethertype` | `ipv4` (0x0800), `arp` (0x0806), `ipv6` (0x86DD), `vlan` (0x8100), `lldp` (0x88CC), `other` | Common protocol types |
| `cp_dst_mac_type` | `broadcast`, `multicast`, `unicast`, `zero` | MAC address categories |
| `cp_src_mac_type` | `unicast`, `zero`, `oui_match`, `random` | Source MAC categories |
| `cp_frame_size` | `runt` (<64), `min` (64), `typical` (64-576), `large` (576-1518), `jumbo` (>1518) | Frame size distribution |
| `cp_vlan_present` | `tagged`, `untagged` | VLAN tag presence |
| `cp_vlan_id` | `zero`, `low` (1-99), `mid` (100-999), `high` (1000-4094), `max` (4095) | VLAN ID ranges |
| `cp_vlan_pcp` | `0` through `7` | All 8 priority levels |

### 3.2 CG_RULE_HITS — Rule Activation Coverage

**Purpose**: Ensure every rule has been triggered at least once.

| Coverpoint | Bins | Description |
|------------|------|-------------|
| `cp_rule_N_hit` | `hit`, `miss` | Per-rule match/no-match (auto-generated) |
| `cp_default_hit` | `hit` | Default action exercised |
| `cp_winning_rule` | One bin per rule + `default` | Which rule won priority |

### 3.3 CG_DECISIONS — Output Decision Coverage

| Coverpoint | Bins | Description |
|------------|------|-------------|
| `cp_decision` | `pass`, `drop` | Both decisions exercised |
| `cp_decision_latency` | `immediate` (1 clk), `normal` (2 clk), `late` (3+ clk) | Decision timing |
| `cp_decision_hold` | `short` (<10 clk), `medium` (10-100), `long` (>100) | How long decision held |

### 3.4 CG_CORNER_CASES — Edge Condition Coverage

| Coverpoint | Bins | Description |
|------------|------|-------------|
| `cp_runt_frame` | `tested` | Frame shorter than Ethernet minimum |
| `cp_jumbo_frame` | `tested` | Frame larger than 1518 bytes |
| `cp_back_to_back` | `tested` | No idle cycles between frames |
| `cp_reset_during` | `tested` | Reset asserted mid-frame |
| `cp_valid_gap` | `tested` | pkt_valid deasserted mid-frame |
| `cp_immediate_sof` | `tested` | pkt_sof before previous pkt_eof |

### 3.5 Cross Coverage

| Cross | Components | Bins | Purpose |
|-------|-----------|------|---------|
| `cx_etype_action` | `cp_ethertype` × `cp_decision` | 12 | Every protocol type gets both decisions |
| `cx_mac_size` | `cp_dst_mac_type` × `cp_frame_size` | 20 | All MAC types tested at all sizes |
| `cx_vlan_rule` | `cp_vlan_present` × `cp_winning_rule` | 2N+2 | VLAN/non-VLAN tested against all rules |
| `cx_rule_action` | `cp_winning_rule` × `cp_decision` | N+1 | Verify each rule produces correct action |

## 4. Coverage Implementation

```python
# Auto-generated coverage model (simplified)
from cocotb_coverage.coverage import CoverPoint, CoverCross, CoverCheck

@CoverPoint("packet.ethertype",
            bins={
                "ipv4":  lambda x: x == 0x0800,
                "arp":   lambda x: x == 0x0806,
                "ipv6":  lambda x: x == 0x86DD,
                "vlan":  lambda x: x == 0x8100,
                "other": lambda x: x not in [0x0800, 0x0806, 0x86DD, 0x8100],
            })
@CoverPoint("packet.dst_mac_type",
            bins={
                "broadcast": lambda x: x == 0xFFFFFFFFFFFF,
                "multicast": lambda x: (x >> 40) & 1 == 1,
                "unicast":   lambda x: (x >> 40) & 1 == 0 and x != 0,
                "zero":      lambda x: x == 0,
            })
@CoverCross("ethertype_x_decision",
            items=["packet.ethertype", "decision.action"])
def sample_packet(ethertype, dst_mac, decision):
    """Sample a packet for coverage."""
    pass
```

## 5. Coverage Targets

| Milestone | Functional Coverage | Timeline |
|-----------|-------------------|----------|
| Phase 1 complete | >80% | Week 1 |
| Phase 2 complete | >90% | Week 3 |
| Phase 3 complete | >95% | Week 6 |
| Release candidate | >98% | Week 8 |

## 6. Coverage Report Format

```
=== PacGate Coverage Report ===
Generated: 2026-02-26 22:30:00
Rules file: rules/examples/enterprise.yaml
Rules count: 12
Simulation: 10,000 random packets + directed suite

COVERGROUP: packet_fields          92.5% (37/40 bins)
  cp_ethertype                     100.0% (6/6)
  cp_dst_mac_type                  100.0% (4/4)
  cp_src_mac_type                   75.0% (3/4)   ◄── HOLE: oui_match
  cp_frame_size                    100.0% (5/5)
  cp_vlan_present                  100.0% (2/2)
  cp_vlan_id                        80.0% (4/5)   ◄── HOLE: max (4095)
  cp_vlan_pcp                      100.0% (8/8)

COVERGROUP: rule_hits             100.0% (13/13)
  [all rules hit at least once]

COVERGROUP: decisions             100.0% (6/6)

COVERGROUP: corner_cases           83.3% (5/6)
  cp_runt_frame                    HIT
  cp_jumbo_frame                   HIT
  cp_back_to_back                  HIT
  cp_reset_during                  HIT
  cp_valid_gap                     HIT
  cp_immediate_sof                 MISS   ◄── HOLE

CROSS: cx_etype_action             91.7% (11/12)
CROSS: cx_mac_size                 85.0% (17/20)
CROSS: cx_vlan_rule                92.9% (26/28)

OVERALL FUNCTIONAL COVERAGE:       91.8%
TARGET:                             95.0%
STATUS:                            ◄── 3.2% gap — 2 directed tests needed
```

## 7. Coverage Closure Strategy

When coverage holes are identified:

1. **Analyze the hole**: What bin was not hit? Why?
2. **Add targeted constraint**: Direct the random generator toward the hole
3. **Add directed test**: If random is unlikely to hit it, write a specific test
4. **Verify closure**: Re-run and confirm the bin is now covered
5. **Document**: Record the closure action in the coverage report

```
Coverage Hole Resolution Log:
─────────────────────────────
HOLE: cp_src_mac_type.oui_match
  Cause: Random generator rarely produces MACs matching rule OUI patterns
  Fix: Added weighted constraint to generate OUI-matching MACs 10% of the time
  Resolution: Covered after 500 additional random packets

HOLE: cp_immediate_sof
  Cause: Test infrastructure always sends EOF before SOF
  Fix: Added directed test IT-011 that injects SOF without preceding EOF
  Resolution: Covered by directed test
```
