# Flippy Requirements

## Core Requirements

### Rule Definition
- REQ-001: Rules defined in YAML format with version, defaults, and rule list
- REQ-002: Each rule has a unique name, priority (0-65535), match criteria, and action (pass/drop)
- REQ-003: Default action (pass or drop) applies when no rule matches
- REQ-004: Priorities must be unique; higher priority wins on match
- REQ-005: Support stateless field matching (Phase 1) and stateful FSM (Phase 3)

### Match Fields
- REQ-010: Match on destination MAC address (exact or wildcard octets)
- REQ-011: Match on source MAC address (exact or wildcard octets)
- REQ-012: Match on EtherType (16-bit hex value)
- REQ-013: Match on VLAN ID (12-bit, 0-4095) — Phase 2
- REQ-014: Match on VLAN PCP (3-bit, 0-7) — Phase 2
- REQ-015: Match on arbitrary byte offset (byte_match) — Phase 2
- REQ-016: MAC wildcard octets ("*") generate mask-based comparison

### Compiler
- REQ-020: Rust CLI with `compile` and `validate` subcommands
- REQ-021: `compile` generates Verilog RTL and cocotb test bench from YAML
- REQ-022: `validate` checks YAML without generating output
- REQ-023: Generated Verilog passes Icarus Verilog lint (`-g2012`)
- REQ-024: Generated cocotb tests include positive (match) and negative (default action) cases

### Verilog Architecture
- REQ-030: Hand-written frame parser extracts Ethernet header fields
- REQ-031: Frame parser handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
- REQ-032: Per-rule matchers are combinational (parallel evaluation, O(1) latency)
- REQ-033: Priority encoder selects first-match-wins action
- REQ-034: Decision output is latched until next frame starts (pkt_sof)
- REQ-035: Simple streaming interface: pkt_data[7:0], pkt_valid, pkt_sof, pkt_eof
- REQ-036: Target Xilinx 7-series (Artix-7), architecture-portable Verilog

### Verification
- REQ-040: cocotb simulation with Icarus Verilog
- REQ-041: ARP frame (EtherType 0x0806) triggers pass when allow_arp rule is active
- REQ-042: Non-matching frame triggers default action (drop in whitelist mode)
- REQ-043: All cocotb tests must report PASS for acceptance

## Future Requirements (Not Yet Implemented)

### Phase 2 — Multi-Rule Support
- REQ-050: Multiple stateless rules with different match fields
- REQ-051: MAC wildcard/mask matching in hardware
- REQ-052: VLAN ID and PCP matching
- REQ-053: Arbitrary byte offset matching (byte_match)
- REQ-054: Compiler unit tests

### Phase 3 — Stateful FSM Rules
- REQ-060: Stateful rules with FSM state machines
- REQ-061: Timeout counters for state transitions
- REQ-062: Sequence-based matching (e.g., ARP then IPv4)
- REQ-063: cocotb tests for FSM sequences

### Phase 4 — Synthesis
- REQ-070: Vivado synthesis targeting Artix-7
- REQ-071: XDC constraint files
- REQ-072: AXI-Stream packet interface
- REQ-073: Store-and-forward FIFO for full-frame buffering
