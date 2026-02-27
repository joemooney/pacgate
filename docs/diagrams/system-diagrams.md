# PacGate System Diagrams

**Document ID**: PG-DIA-001
**Date**: 2026-02-26

---

## 1. System Context Diagram

```
         ┌───────────────────────────────────────────────────────────┐
         │                    Development Host                        │
         │                                                           │
         │  ┌──────────┐                                             │
         │  │ Engineer  │──── writes ────┐                           │
         │  └──────────┘                 │                           │
         │                               ▼                           │
         │                      ┌─────────────────┐                  │
         │                      │  rules.yaml     │                  │
         │                      │  (specification)│                  │
         │                      └────────┬────────┘                  │
         │                               │                           │
         │                      ┌────────▼────────┐                  │
         │                      │  pacgate compile │                  │
         │                      │  (Rust CLI)     │                  │
         │                      └───┬─────────┬───┘                  │
         │                          │         │                      │
         │              ┌───────────┘         └───────────┐          │
         │              ▼                                 ▼          │
         │     ┌─────────────────┐              ┌─────────────────┐  │
         │     │  Verilog RTL    │              │  cocotb Tests   │  │
         │     │  (gen/rtl/)     │              │  (gen/tb/)      │  │
         │     └────────┬────────┘              └────────┬────────┘  │
         │              │                                │           │
         │              │         ┌──────────┐           │           │
         │              └────────▶│  Icarus  │◄──────────┘           │
         │                        │  Verilog │                       │
         │                        └─────┬────┘                       │
         │                              │                            │
         │                       ┌──────▼──────┐                     │
         │                       │  Simulation │                     │
         │                       │  Results    │                     │
         │                       │  + Coverage │                     │
         │                       └─────────────┘                     │
         └───────────────────────────────────────────────────────────┘
                                        │
                            (Phase 4)   │
                                        ▼
                               ┌─────────────────┐
                               │  Vivado         │
                               │  Synthesis      │
                               │  → Artix-7      │
                               │    Bitstream     │
                               └─────────────────┘
                                        │
                                        ▼
                               ┌─────────────────┐
                               │  FPGA Board     │
                               │  (Network       │
                               │   Interface)    │
                               └─────────────────┘
```

## 2. Compilation Data Flow

```
rules/examples/enterprise.yaml
        │
        │ serde_yaml::from_str()
        ▼
┌───────────────────────┐
│ FilterConfig          │
│ ├─ version: "1.0"     │
│ ├─ defaults.action    │
│ └─ rules[]            │
│    ├─ name            │
│    ├─ priority        │
│    ├─ match_criteria  │
│    │  ├─ ethertype    │──── parse_ethertype() ──── u16
│    │  ├─ dst_mac      │──── MacAddress::parse() ── value[6] + mask[6]
│    │  └─ src_mac      │──── MacAddress::parse() ── value[6] + mask[6]
│    ├─ action          │
│    └─ fsm (optional)  │
│       ├─ initial_state│
│       └─ states{}     │
│          └─ transitions│
└───────────┬───────────┘
            │
     sort by priority
     (highest first)
            │
    ┌───────┴───────┐
    │               │
    ▼               ▼
verilog_gen     cocotb_gen
    │               │
    │               │
    ▼               ▼
┌────────┐    ┌──────────┐
│ Tera   │    │ Tera     │
│ render │    │ render   │
└───┬────┘    └────┬─────┘
    │              │
    ▼              ▼
gen/rtl/       gen/tb/
├─ top.v       ├─ test.py
├─ match_N.v   └─ Makefile
└─ decision.v
```

## 3. Verification Environment Block Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         cocotb Test Environment                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────┐               │
│   │  Test Orchestrator                                       │               │
│   │                                                         │               │
│   │  ┌──────────┐ ┌──────────────┐ ┌─────────────────────┐ │               │
│   │  │ Directed │ │  Constrained │ │  Corner Case        │ │               │
│   │  │ Tests    │ │  Random      │ │  Tests              │ │               │
│   │  │          │ │  (500 pkts)  │ │                     │ │               │
│   │  │ per-rule │ │              │ │ • jumbo, runt       │ │               │
│   │  │ positive │ │ ethertype    │ │ • back-to-back      │ │               │
│   │  │ negative │ │ MAC type     │ │ • reset recovery    │ │               │
│   │  │          │ │ weighted     │ │ • min size          │ │               │
│   │  └────┬─────┘ └──────┬──────┘ └──────────┬──────────┘ │               │
│   └───────┼──────────────┼───────────────────┼────────────┘               │
│           └──────────────┼───────────────────┘                             │
│                          ▼                                                  │
│                ┌─────────────────────┐                                      │
│                │   PacketDriver      │     ┌──────────────────────────────┐ │
│                │   (BFM)             │     │  PacketFactory               │ │
│                │                     │◄────│  .arp() .ipv4() .ipv6()     │ │
│                │ frame → pkt_data    │     │  .broadcast() .random()     │ │
│                │         pkt_valid   │     │  .jumbo() .runt()           │ │
│                │         pkt_sof     │     └──────────────────────────────┘ │
│                │         pkt_eof     │                                      │
│                └─────────┬───────────┘                                      │
│                          │                                                  │
│  ════════════════════════╪══════════════════════════════════════════════    │
│  ║                       │              DUT                           ║    │
│  ║            ┌──────────▼──────────┐                                ║    │
│  ║            │  packet_filter_top  │                                ║    │
│  ║            │                     │                                ║    │
│  ║            │  ┌───────────────┐  │                                ║    │
│  ║            │  │ frame_parser  │  │                                ║    │
│  ║            │  └───────┬───────┘  │                                ║    │
│  ║            │          │          │                                ║    │
│  ║            │  ┌───────▼───────┐  │                                ║    │
│  ║            │  │ rule_match_*  │  │ (N parallel matchers)          ║    │
│  ║            │  └───────┬───────┘  │                                ║    │
│  ║            │          │          │                                ║    │
│  ║            │  ┌───────▼───────┐  │                                ║    │
│  ║            │  │decision_logic │  │                                ║    │
│  ║            │  └───────┬───────┘  │                                ║    │
│  ║            └──────────┼──────────┘                                ║    │
│  ║                       │                                           ║    │
│  ═══════════════════════╪════════════════════════════════════════════    │
│                          │                                                  │
│                ┌─────────▼───────────┐                                      │
│                │  DecisionMonitor    │                                      │
│                │  decision_valid ──┬──│                                      │
│                │  decision_pass  ──┤  │                                      │
│                └──────────────────┤──┘                                      │
│                                   │                                         │
│                    ┌──────────────┼──────────────┐                          │
│                    ▼              ▼               ▼                          │
│           ┌──────────────┐ ┌──────────────┐ ┌────────────┐                  │
│           │  Scoreboard  │ │  Coverage    │ │  Report    │                  │
│           │  (reference  │ │  Collector   │ │  Generator │                  │
│           │   model)     │ │              │ │            │                  │
│           │              │ │  ethertype   │ │  • JUnit   │                  │
│           │  predict()   │ │  MAC type    │ │    XML     │                  │
│           │  check()     │ │  rule hits   │ │  • Text    │                  │
│           │  report()    │ │  decisions   │ │    report  │                  │
│           └──────────────┘ │  corners     │ │  • FST     │                  │
│                            │  cross cov   │ │    waves   │                  │
│                            └──────────────┘ └────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4. FSM State Diagram — arp_then_ipv4 Example

```
                    ┌──────────────────────┐
                    │                      │
         reset ────▶│       IDLE           │
                    │                      │
                    └──────────┬───────────┘
                               │
                    EtherType = 0x0806 (ARP)
                    Action: PASS
                               │
                               ▼
                    ┌──────────────────────┐
                    │                      │
                    │     ARP_SEEN         │
                    │                      │
                    │  timeout: 1000 clks  │
                    │                      │
                    └──────┬─────┬─────────┘
                           │     │
              EtherType =  │     │  timeout expired
              0x0800 (IPv4)│     │  (no IPv4 within
              Action: PASS │     │   1000 cycles)
                           │     │
                           ▼     ▼
                    ┌──────────────────────┐
                    │       IDLE           │
                    │  (back to start)     │
                    └──────────────────────┘
```

## 5. Priority Encoder — Enterprise Rule Set

```
Priority: 200     150      100      90       80       70       60     (default)
          │       │        │        │        │        │        │        │
          ▼       ▼        ▼        ▼        ▼        ▼        ▼        ▼
        ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌──────┐
        │BCAST│ │VLAN │ │ ARP │ │IPv4 │ │IPv6 │ │VENDOR│ │LLDP │ │ DROP │
        │DROP │ │100  │ │PASS │ │PASS │ │PASS │ │ACME │ │PASS │ │      │
        │     │ │PASS │ │     │ │     │ │     │ │PASS │ │     │ │      │
        └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬───┘
           │       │       │       │       │       │       │       │
           ▼       ▼       ▼       ▼       ▼       ▼       ▼       ▼

        if (bcast_hit)        → DROP     ← Highest priority: block bcast
        else if (vlan100_hit) → PASS     ← VLAN 100 management traffic
        else if (arp_hit)     → PASS     ← ARP for address resolution
        else if (ipv4_hit)    → PASS     ← IPv4 data traffic
        else if (ipv6_hit)    → PASS     ← IPv6 data traffic
        else if (vendor_hit)  → PASS     ← Vendor-specific OUI
        else if (lldp_hit)    → PASS     ← Link Layer Discovery
        else                  → DROP     ← Default: whitelist mode

Result: Latched decision_valid + decision_pass (until next pkt_sof)
```

## 6. Test Coverage Heatmap

```
                 ┌─────────────────────────────────────────────────┐
                 │          Rule Hit Coverage Matrix                │
                 │                                                 │
                 │  Rule              Directed  Random  Corner     │
                 │  ─────────────────────────────────────────────  │
                 │  block_broadcast    ██████   ██████  ██████     │
                 │  allow_mgmt_vlan    ██████   ░░░░░░  ░░░░░░     │
                 │  allow_arp          ██████   ██████  ██████     │
                 │  allow_ipv4         ██████   ██████  ██████     │
                 │  allow_ipv6         ██████   ██████  ░░░░░░     │
                 │  allow_vendor       ██████   ██████  ░░░░░░     │
                 │  allow_lldp         ██████   ██████  ░░░░░░     │
                 │  __default__        ██████   ██████  ██████     │
                 │                                                 │
                 │  ██████ = HIT     ░░░░░░ = NOT YET              │
                 │                                                 │
                 │  Coverage: Directed=100%  Random=87.5%          │
                 └─────────────────────────────────────────────────┘
```
