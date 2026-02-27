# Flippy Architecture Document

**Document ID**: FLIP-ARCH-001
**Version**: 2.0
**Date**: 2026-02-26
**Status**: Approved

---

## 1. Executive Summary

Flippy is a **specification-driven FPGA packet filter** that compiles human-readable YAML rules into two orthogonal artifacts from a single source of truth:

1. **Synthesizable Verilog RTL** — the hardware filter
2. **cocotb verification harness** — the proof it works

This "single-spec, dual-output" architecture is the core innovation. Unlike traditional FPGA development where RTL and testbenches are written independently (creating specification drift), Flippy guarantees that **the test always matches the design** because both derive from the same specification.

## 2. System Context

```
                    ┌─────────────────────────────────────────────┐
                    │              Flippy Ecosystem                │
                    │                                             │
  ┌──────────┐     │  ┌──────────┐    ┌──────────────────────┐   │
  │  Network  │────▶│  │  FPGA    │    │  Verification        │   │
  │  Traffic  │     │  │  Filter  │    │  Environment         │   │
  └──────────┘     │  │  (RTL)   │    │  (cocotb + Icarus)   │   │
                    │  └──────────┘    └──────────────────────┘   │
                    │       ▲                    ▲                 │
                    │       │                    │                 │
                    │       └────────┬───────────┘                │
                    │                │                             │
                    │         ┌──────┴──────┐                     │
                    │         │   Flippy    │                     │
                    │         │  Compiler   │                     │
                    │         │   (Rust)    │                     │
                    │         └──────┬──────┘                     │
                    │                │                             │
                    │         ┌──────┴──────┐                     │
                    │         │  YAML Rule  │                     │
                    │         │    Spec     │                     │
                    │         └─────────────┘                     │
                    └─────────────────────────────────────────────┘
```

## 3. Core Architecture Principle: Dual-Generation

```
                         ┌─────────────────┐
                         │   rules.yaml    │
                         │  (Single Source  │
                         │   of Truth)     │
                         └────────┬────────┘
                                  │
                         ┌────────┴────────┐
                         │  Flippy Compiler │
                         │     (Rust)       │
                         │                  │
                         │  ┌────────────┐  │
                         │  │   Parser   │  │
                         │  │  (serde)   │  │
                         │  └─────┬──────┘  │
                         │        │         │
                         │  ┌─────┴──────┐  │
                         │  │ Validated  │  │
                         │  │   Model    │  │
                         │  └──┬─────┬───┘  │
                         │     │     │      │
                         └─────┼─────┼──────┘
                               │     │
                    ┌──────────┘     └──────────┐
                    ▼                            ▼
           ┌───────────────┐           ┌───────────────────┐
           │  Verilog RTL  │           │  cocotb Testbench  │
           │  Generator    │           │  Generator         │
           │  (Tera)       │           │  (Tera)            │
           └───────┬───────┘           └─────────┬─────────┘
                   │                             │
                   ▼                             ▼
           ┌───────────────┐           ┌───────────────────┐
           │ gen/rtl/      │           │ gen/tb/            │
           │               │           │                    │
           │ packet_       │           │ test_packet_       │
           │  filter_top.v │◄─── DUT──▶│  filter.py         │
           │ rule_match_N.v│           │ Makefile            │
           │ decision_     │           │                    │
           │  logic.v      │           │ + verification/    │
           └───────────────┘           │   framework        │
                                       └───────────────────┘
```

**Why this matters**: In traditional FPGA development, a test engineer reads the spec and writes tests manually. This introduces:
- **Specification drift** — the test may not match the actual spec
- **Incomplete coverage** — humans miss edge cases
- **Maintenance burden** — spec changes require manual test updates

Flippy eliminates all three by generating both artifacts from the same source.

## 4. Verilog Module Hierarchy

```
packet_filter_top
├── frame_parser            (hand-written, verified independently)
│   └── Ethernet FSM        (IDLE → DST_MAC → SRC_MAC → ETYPE → [VLAN] → PAYLOAD)
│
├── rule_match_0            (generated, combinational)
│   └── Field comparators   (ethertype == 16'h0806)
│
├── rule_match_1            (generated, combinational)
│   └── Field comparators   (dst_mac & mask == value)
│
├── rule_match_N            (generated, combinational)
│   └── Field comparators   (arbitrary field matching)
│
├── rule_fsm_0              (generated, registered — Phase 3)
│   └── State machine       (temporal sequence matching)
│
└── decision_logic          (generated, priority encoder)
    └── Latched output      (valid until next pkt_sof)
```

### 4.1 Data Flow

```
  pkt_data[7:0] ──┐
  pkt_valid ──────┤
  pkt_sof ────────┤     ┌──────────────┐
  pkt_eof ────────┴────▶│ frame_parser │
                         └──────┬───────┘
                                │
                    ┌───────────┼───────────────────┐
                    │           │                    │
                    │    dst_mac[47:0]               │
                    │    src_mac[47:0]               │
                    │    ethertype[15:0]             │
                    │    vlan_id[11:0]               │
                    │    vlan_pcp[2:0]               │
                    │    fields_valid                │
                    │           │                    │
              ┌─────▼─────┐ ┌──▼──────────┐ ┌──────▼──────┐
              │rule_match_0│ │rule_match_1 │ │rule_match_N │  (parallel)
              └─────┬──┬──┘ └──┬──┬───────┘ └──────┬──┬───┘
                    │  │       │  │                 │  │
                 hit action  hit action          hit action
                    │  │       │  │                 │  │
                    └──┴───────┴──┴─────────────────┴──┘
                                  │
                         ┌────────▼────────┐
                         │ decision_logic  │
                         │ (priority       │
                         │  encoder)       │
                         └────────┬────────┘
                                  │
                    decision_valid ├── decision_pass
```

### 4.2 Timing Diagram

```
  clk      ─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─
             └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘

  pkt_sof  ──┐                                                           ┌──
             └───────────────────────────────────────────────────────────┘
                B0  B1  B2  B3  B4  B5  B6  B7  B8  B9 B10 B11 B12 B13
  pkt_data   │DST MAC (6 bytes) │SRC MAC (6 bytes) │ET │  PAYLOAD...
             ├───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───

  pkt_valid ──────────────────────────────────────────────────────┐
                                                                  └──────

  pkt_eof  ─────────────────────────────────────────────────┐
                                                      ▲     └────────────
                                                      │
  fields_   ──────────────────────────────────────────┐│
  valid                                               └┘─────────────────
                                                       ▲
                                                       │ 1 cycle after
                                                       │ ethertype parsed
  decision_ ───────────────────────────────────────────────┐
  valid                                                    └─────────────
                                                            ▲
  decision_ ───────────────────────────────────────────────┐│
  pass                                                     └┘────────────
                                                            │
                                              Latched until next pkt_sof
```

## 5. Frame Parser State Machine

```
           ┌──────────┐
    reset ─▶│  S_IDLE  │◄───── pkt_eof (from any state)
           └────┬─────┘
                │ pkt_sof && pkt_valid
                ▼
         ┌────────────┐
         │ S_DST_MAC  │  6 bytes (byte_cnt 0→5)
         └─────┬──────┘
               │ byte_cnt == 5
               ▼
         ┌────────────┐
         │ S_SRC_MAC  │  6 bytes (byte_cnt 0→5)
         └─────┬──────┘
               │ byte_cnt == 5
               ▼
         ┌────────────┐
         │  S_ETYPE   │  2 bytes
         └──┬──────┬──┘
            │      │
    ┌───────┘      └───────┐
    │ EtherType            │ EtherType
    │ == 0x8100            │ != 0x8100
    ▼                      ▼
 ┌────────────┐     ┌────────────┐
 │ S_VLAN_TAG │     │ S_PAYLOAD  │──── fields_valid pulse
 └─────┬──────┘     └────────────┘
       │ 2 bytes
       ▼
 ┌────────────┐
 │  S_ETYPE2  │  2 bytes (real ethertype)
 └─────┬──────┘
       │
       ▼
 ┌────────────┐
 │ S_PAYLOAD  │──── fields_valid pulse
 └────────────┘
```

## 6. Decision Logic Architecture

The decision logic implements a **first-match-wins priority encoder**:

```
Priority:   100      90       80       50      (default)
            ┌──┐    ┌──┐    ┌──┐    ┌──┐    ┌────────┐
            │R0│    │R1│    │R2│    │R3│    │ Default │
            │  │    │  │    │  │    │  │    │ Action  │
            └┬─┘    └┬─┘    └┬─┘    └┬─┘    └────┬───┘
             │       │       │       │            │
             ▼       ▼       ▼       ▼            ▼
         ┌───────────────────────────────────────────┐
         │          if (hit_0) action = R0.action    │
         │     else if (hit_1) action = R1.action    │
         │     else if (hit_2) action = R2.action    │
         │     else if (hit_3) action = R3.action    │
         │     else            action = default      │
         └───────────────────┬───────────────────────┘
                             │
                             ▼
                     decision_pass / decision_valid
                     (latched until next pkt_sof)
```

## 7. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Rule Specification | YAML | Human-readable, diff-friendly, tool-ecosystem |
| Compiler | Rust | Memory safety, performance, excellent error messages |
| Template Engine | Tera | Jinja2-compatible, Rust-native, powerful filters |
| HDL | Verilog-2001 | Maximum portability across FPGA vendors |
| Simulation | Icarus Verilog | Open-source, CI-friendly, cocotb-compatible |
| Test Framework | cocotb 2.x | Python-native, no SystemVerilog needed |
| Verification Lib | Custom + cocotb-coverage | Coverage-driven, constrained random |
| Target FPGA | Xilinx Artix-7 | Cost-effective, widely available |

## 8. Design Decisions Log

| ID | Decision | Rationale | Alternatives Considered |
|----|----------|-----------|------------------------|
| DD-001 | YAML over JSON/TOML | Most readable for non-programmers; supports comments | JSON (no comments), TOML (less familiar) |
| DD-002 | Rust compiler over Python | Type safety catches template errors at compile time | Python (slower, no type safety) |
| DD-003 | Tera over Askama | Runtime templates allow user customization | Askama (compile-time, less flexible) |
| DD-004 | Combinational matchers | O(1) latency, predictable timing | Sequential scan (variable latency) |
| DD-005 | Latched decision output | Consumer can read any time during frame | Pulsed (1 cycle, easy to miss) |
| DD-006 | Priority encoder over CAM | Simpler, deterministic, no priority inversion | CAM/TCAM (more area, more flexible) |
| DD-007 | cocotb over SystemVerilog UVM | Lower barrier to entry, Python ecosystem | SV UVM (industry standard, heavier) |
| DD-008 | Active-low async reset | Xilinx 7-series convention, BUFG-friendly | Sync reset (needs clock), active-high |

## 9. Scalability Analysis

| Metric | 1 Rule | 10 Rules | 100 Rules | 1000 Rules |
|--------|--------|----------|-----------|------------|
| LUTs (est.) | ~50 | ~500 | ~5,000 | ~50,000 |
| Decision latency | 1 clk | 1 clk | 1 clk | 1 clk |
| Compile time | <1s | <1s | ~2s | ~10s |
| Sim time (per test) | ~1μs | ~1μs | ~1μs | ~2μs |
| Artix-7 fit? | Yes | Yes | Yes | Maybe (XC7A200T) |

All rule evaluation is **parallel combinational** — latency is O(1) regardless of rule count. Area is O(N).

## 10. Security Considerations

- **No arbitrary code execution**: YAML rules cannot execute code; they only define match patterns
- **Bounded resource usage**: Each rule generates fixed-size hardware; no unbounded allocation
- **Default-deny**: Whitelist mode (default: drop) ensures only explicitly allowed traffic passes
- **No side channels**: Combinational evaluation has constant-time behavior regardless of match
