# Wide Parser Roadmap: Native 100G+ Throughput

## Current Architecture (V1)

PacGate V1 uses an **8-bit serial parser** (`rtl/frame_parser.v`) that processes one byte per clock cycle. At 250 MHz, this yields **~2 Gbps** throughput regardless of AXI-Stream bus width.

```
512-bit AXI-Stream → axis_512_to_8 → [8-bit parser @ 250MHz = ~2 Gbps] → axis_8_to_512
```

The `--width` parameter (8/64/128/256/512/1024/2048) only generates **bus-width compatibility converters** — it does NOT increase throughput. The core parser is always the bottleneck.

## Target Architecture (V2): Speculative Parallel Extraction

### Key Insight

For a 512-bit (64-byte) bus at 250 MHz, a standard Ethernet + IPv4 + TCP/UDP packet (no tunnels) fits **entirely within a single 64-byte bus word**:

| Stack | Bytes | Fits in word 0? |
|-------|-------|:---------------:|
| Eth(14) + IPv4(20) + TCP(20) | 54 | Yes (64 bytes) |
| Eth(14) + VLAN(4) + IPv4(20) + TCP(20) | 58 | Yes |
| Eth(14) + QinQ(8) + IPv4(20) + TCP(20) | 62 | Yes |
| Eth(14) + IPv6(40) + TCP(20) | 74 | Spans 2 words |
| Eth(14) + IPv4(20) + UDP(8) + VXLAN(8) + inner(14+20+4) | 88 | Spans 2 words |

### Architecture: Combinational Multi-Path Extraction

Instead of a byte-by-byte FSM, the wide parser **extracts all fields in parallel** at every possible offset, then selects the correct values based on protocol detection:

```verilog
// All extraction is combinational on the first bus word
// L2: always at fixed byte offsets
wire [47:0] dst_mac = word[47:0];           // bytes 0-5
wire [47:0] src_mac = word[95:48];          // bytes 6-11
wire [15:0] etype   = word[111:96];         // bytes 12-13

// Detect VLAN variants
wire has_vlan = (etype == 16'h8100);
wire has_qinq = (etype == 16'h88A8 || etype == 16'h9100);

// IP header starts at byte 14 (no VLAN), 18 (VLAN), or 22 (QinQ)
// Extract at ALL three offsets simultaneously
wire [31:0] src_ip_at_14 = word[30*8-1 : 26*8];
wire [31:0] src_ip_at_18 = word[34*8-1 : 30*8];
wire [31:0] src_ip_at_22 = word[38*8-1 : 34*8];

// Select based on VLAN detection
wire [31:0] src_ip = has_qinq ? src_ip_at_22 :
                     has_vlan ? src_ip_at_18 :
                     src_ip_at_14;
```

### Two-Stage Pipeline for Deep Headers

Tunneled traffic (VXLAN, GTP-U, Geneve) can push inner headers past byte 64 into the second bus word. A 2-stage pipeline handles this:

- **Stage 1** (word 0): Extract L2/L3/L4 outer headers, detect tunnel type
- **Stage 2** (word 0 concatenated with word 1 = 1024 bits): Extract inner headers at computed offset

This adds 1 clock cycle of latency only for tunnel protocols.

### Protocol Path Enumeration

PacGate's YAML spec already defines which protocols are in use (via `GlobalProtocolFlags`). At compile time, the code generator can enumerate all valid protocol stack paths:

1. Eth → ARP (28 bytes, 1 word)
2. Eth → IPv4 → TCP/UDP (54 bytes, 1 word)
3. Eth → IPv4 → ICMP (38 bytes, 1 word)
4. Eth → IPv4 → GRE → inner (variable, 2 words)
5. Eth → VLAN → IPv4 → TCP/UDP (58 bytes, 1 word)
6. Eth → QinQ → IPv4 → TCP/UDP (62 bytes, 1 word)
7. Eth → IPv6 → TCP/UDP (74 bytes, 2 words)
8. Eth → IPv4 → UDP → VXLAN → inner (88+ bytes, 2 words)
9. Eth → IPv4 → UDP → GTP-U → inner (86+ bytes, 2 words)
10. ... (~20-30 total paths for all supported protocols)

For each path, every field offset is a **compile-time constant**. The generator produces parallel extraction logic for only the paths that the YAML rules actually use — unused protocols generate zero hardware.

### Offset Pruning

Rather than a full 64:1 byte mux (which would need 6 LUT levels), PacGate's fixed protocol set means each field has at most **3-5 valid offsets** (no VLAN, one VLAN, QinQ, plus tunnel variants). This reduces mux width from 64:1 to 3:1-5:1, which fits in a single LUT level.

### Estimated Resources (512-bit, Artix-7)

| Component | LUTs | FFs |
|-----------|------|-----|
| L2 extraction (3 VLAN variants) | ~200 | ~200 |
| L3 IPv4 extraction (3 offsets) | ~500 | ~400 |
| L3 IPv6 extraction (3 offsets) | ~1500 | ~1000 |
| L4 TCP/UDP extraction (6 offsets) | ~400 | ~200 |
| Tunnel extraction (VXLAN/GTP/Geneve) | ~800 | ~400 |
| Protocol detection muxes | ~300 | ~50 |
| Cross-word buffer (1024-bit) | ~100 | ~1024 |
| **Total** | **~3800** | **~3274** |

This is consistent with academic results: CESNET's terabit parser uses 4k-8k LUTs for 320-bit buses.

### Throughput Scaling

| Width | Bytes/clock | Throughput @ 250 MHz |
|-------|------------|---------------------|
| 64 | 8 | ~16 Gbps |
| 128 | 16 | ~32 Gbps |
| 256 | 32 | ~64 Gbps |
| 512 | 64 | ~128 Gbps |
| 1024 | 128 | ~256 Gbps |

### Implementation Plan

**Phase A: Generator Infrastructure**

1. Add `ParserPath` struct to `verilog_gen.rs` — represents one protocol stack path with computed field offsets
2. Add `enumerate_parser_paths()` that walks `GlobalProtocolFlags` to produce all valid paths
3. New Tera template: `frame_parser_wide.v.tera` — generates combinational extraction with offset muxes

**Phase B: Single-Word Parser (covers ~90% of traffic)**

4. Generate wide parser for non-tunneled traffic (all headers fit in word 0)
5. Gate on `--width >= 64`: produce wide parser instead of width converters
6. Output interface remains identical to current `frame_parser.v` (same field registers, same `fields_valid`)
7. Existing rule matchers (`rule_match_N`) and decision logic work unchanged

**Phase C: Two-Word Pipeline (tunnels)**

8. Add `{prev_word, curr_word}` 1024-bit concatenation register
9. Generate tunnel extraction from the concatenated words
10. 1-cycle additional latency for tunnel protocols only

**Phase D: Verification**

11. Same cocotb tests work (packet-level behavior is identical)
12. Add wide-bus-specific tests (packets spanning word boundaries)
13. SVA assertions for wide parser field extraction correctness

### What Does NOT Change

- **YAML specification**: Zero changes. Same rules, same syntax.
- **Rule matchers**: `rule_match_N` modules are purely combinational on extracted fields — bus width irrelevant.
- **Decision logic**: Priority encoder operates on match results — unchanged.
- **AXI-Stream wrapper**: Only the parser module changes; the rest of the AXI pipeline (store-forward FIFO, rewrite engine) already handles wide buses.
- **Simulation/verification**: Software simulator is independent of hardware bus width.

## Prior Art

| Framework | Parser Type | Throughput | Reference |
|-----------|------------|-----------|-----------|
| Vitis Net P4 | HLS-generated parallel extractor | 100G-1T | AMD WP555 |
| CESNET NDK | Pipeline-per-header + barrel shifter | 400G-1T | ACM FPGA 2018 |
| P4-to-VHDL | Per-header pipeline stages | 100G | Liberouter 2016 |
| Corundum | User-defined (NIC framework) | 100G | UCSD FCCM 2020 |
| FlowBlaze | Fixed EFSM architecture | 40G | NSDI 2019 |

## Summary

The V2 wide parser is a **code generation change only** — the Rust compiler produces different Verilog templates based on `--width`. The approach (speculative parallel extraction with offset pruning) is proven in literature and production, generates ~4k LUTs for a full protocol set, and provides true 100G+ throughput. The YAML specification and verification framework require zero changes.
