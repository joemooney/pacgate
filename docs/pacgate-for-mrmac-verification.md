# How PacGate Addresses MRMAC Verification Need

## Overview

Instead of building an MRMAC two-channel verification system with a packet switch from scratch, PacGate already implements the bulk of this: packet filtering rules compile to synthesizable Verilog RTL and Python test harnesses from a single YAML specification, with built-in multi-port switching, topology simulation, and high-volume regression.

This document maps the specific requirements to existing PacGate capabilities, and identifies the pieces that remain MRMAC-specific.

---

## MRMAC Two-Channel Verification

**Requirements:**
- MRMAC with two channels (10G/25G), QuestaSim simulation
- 1000-packet verification through the system
- Test error modes + clean packet throughput
- Python-driven test suite (packet_gen, pkt_chk, test_ctrl, err_inject)
- File-based interface, modular architecture

### What PacGate provides

**1000-packet regression — already built:**

```bash
$ pacgate regress --scenario scenario.json --count 1000
  PASS  allow_arp_regression_v1 — 1000 packets, 0.002s (641880 pps), 0 mismatches
```

This runs 1000 packets through the actual rule-matching engine at ~640K packets/sec. No subprocess overhead, no mock mode — real rule evaluation. Your scenario file defines the packets and expected pass/drop outcomes:

```json
{
  "id": "allow_arp_regression_v1",
  "name": "Allow ARP Regression",
  "default_rules_file": "rules/examples/allow_arp.yaml",
  "events": [
    {
      "name": "ARP broadcast should pass",
      "packet": { "ethertype": "0x0806", "src_mac": "00:11:22:33:44:55" },
      "expected_action": "pass"
    },
    {
      "name": "IPv4 packet should drop",
      "packet": { "ethertype": "0x0800", "src_ip": "10.0.0.1", "dst_port": 443 },
      "expected_action": "drop"
    }
  ]
}
```

The regression runner cycles through events for the requested count, checks every result against expectations, and exits non-zero on any mismatch — CI-ready.

**Error injection — built into topology scenarios:**

Scenario v2 supports `inject_rmac_error` per event. The topology simulator tracks RMAC errors, subnet mismatches, and filter drops separately:

```json
{
  "name": "Drop due to injected RMAC error",
  "ingress_port": 1,
  "inject_rmac_error": true,
  "packet": { "ethertype": "0x0800", "src_ip": "10.0.1.15", "dst_ip": "10.0.0.5" },
  "expected_switch_action": "drop"
}
```

**Python verification framework — generated from YAML:**

PacGate generates a complete cocotb test harness including:
- **PacketFactory** — directed, random, boundary, and corner-case frame generation
- **PacketDriver** (BFM) — drives frames into the DUT byte-by-byte
- **DecisionMonitor** — captures pass/drop decisions
- **Scoreboard** — Python reference model matching all L2/L3/L4 fields
- **CoverageDirector** — functional coverage with XML export

This maps directly to your `pkt_gen`, `pkt_chk`, `test_ctrl`, and `err_inject` modules.

**Synthesizable Verilog — generated from rules:**

```bash
$ pacgate compile rules.yaml --axi --counters --ports 2
```

Generates a complete Verilog RTL hierarchy:
- `frame_parser` — L2/L3/L4/VLAN/ARP/ICMP header extraction
- `rule_match_N` — per-rule combinational matchers
- `decision_logic` — priority encoder
- `store_forward_fifo` — frame buffering with decision-based forwarding
- `rule_counters` — per-rule 64-bit packet/byte counters
- `packet_filter_multiport_top` — multi-port wrapper

---

## L2/L3 Packet Switch Between MRMACs

**Requirements:**
- L2/L3 switch with ingress pipeline (VLAN classify, MAC lookup, L3 route match)
- Switch fabric (port bitmap, drop logic, flood/unicast)
- Egress pipeline (output queue, drop counters)
- Network map: ports with subnets and MACs
- Subnet-based packet dropping
- Software switch model in Python
- Drop counting by reason

### What PacGate provides

**Topology definition — scenario v2:**

A network map with 4 ports maps directly to a PacGate topology scenario:

```json
{
  "schema_version": "v2",
  "id": "mrmac_4port_switch",
  "name": "MRMAC 4-Port L3 Switch",
  "default_rules_file": "rules/l3l4_firewall.yaml",
  "topology": {
    "kind": "l3_switch_2port",
    "ports": [
      { "id": 0, "name": "mrmac0_ch0", "subnet": "10.0.0.0/24", "mac": "AA:BB:CC:DD:00:00" },
      { "id": 1, "name": "mrmac0_ch1", "subnet": "10.0.0.0/24", "mac": "AA:BB:CC:DD:00:01" },
      { "id": 2, "name": "mrmac1_ch0", "subnet": "10.0.1.0/24", "mac": "AA:BB:CC:DD:01:00" },
      { "id": 3, "name": "mrmac1_ch1", "subnet": "10.0.1.0/24", "mac": "AA:BB:CC:DD:01:01" }
    ]
  },
  "events": [
    {
      "name": "Forward from port0 to subnet of port2",
      "ingress_port": 0,
      "packet": { "ethertype": "0x0800", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20" },
      "expected_action": "pass",
      "expected_switch_action": "forward",
      "expected_egress_port": 2
    },
    {
      "name": "Drop — ingress subnet mismatch",
      "ingress_port": 0,
      "packet": { "ethertype": "0x0800", "src_ip": "10.0.2.10", "dst_ip": "10.0.1.20" },
      "expected_switch_action": "drop"
    },
    {
      "name": "Drop — RMAC error",
      "ingress_port": 1,
      "inject_rmac_error": true,
      "packet": { "ethertype": "0x0800", "src_ip": "10.0.0.15", "dst_ip": "10.0.1.5" },
      "expected_switch_action": "drop"
    }
  ]
}
```

**Software switch model — already implemented:**

`pacgate topology` implements the exact pipeline you described:

1. **RMAC error check** — `inject_rmac_error` → immediate drop
2. **Ingress subnet validation** — source IP checked against ingress port's CIDR subnet
3. **Packet filter** — `simulate()` evaluates rules (L2/L3/L4 matching)
4. **Egress routing** — destination IP matched against all other ports' subnets

This is a network switch model running at 640K packets/sec in Rust.

**Drop reason tracking is built in:**

```bash
$ pacgate topology --scenario mrmac_switch.json --json
```

```json
{
  "stats": {
    "total_events": 3,
    "rmac_error_count": 1,
    "rmac_dropped": 2,
    "switch_forwarded": 1,
    "switch_dropped": 2,
    "switch_drop_reasons": {
      "rmac_error": 1,
      "ingress_subnet_mismatch": 1,
      "pacgate_drop": 0,
      "no_route": 0
    }
  }
}
```

Every drop is categorized — RMAC error, ingress subnet mismatch, filter rule drop, or no egress route. This provided support for error rate detection in the MRMAC and packets dropped in the switch.

**L3 route matching — CIDR subnet evaluation:**

PacGate's `Ipv4Prefix` handles CIDR matching both in hardware (generated Verilog comparators) and software (topology simulation). Rules use standard CIDR notation:

```yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_subnet_traffic
      priority: 1000
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/24"
        dst_ip: "10.0.1.0/24"
        ip_protocol: 6
      action: pass
```

**Hardware drop counters:**

```bash
$ pacgate compile rules.yaml --axi --counters --ports 2
```

Generates `rule_counters.v` with 64-bit per-rule packet/byte counters readable via AXI-Lite. Each rule that drops or passes a packet increments its counter — directly observable from software.

---

## What PacGate Does NOT Cover

These are MRMAC-specific pieces that sit outside the packet processing logic:

| Component | Why it's separate |
|---|---|
| **MRMAC IP instantiation** (`mrmac_0.tcl`, `mrmac_wrapper.sv`) | Versal hard IP configuration — PHY-layer, not packet processing |
| **10G/25G auto-negotiation** | Physical-layer link management |
| **MRMAC channel controller** (`mrmac_channel_ctrl.sv`) | MAC-layer init/status/reset sequencing |
| **Dynamic MAC learning (CAM table)** | PacGate uses static YAML rules; a learning CAM would be custom RTL (though `--dynamic` flow tables could be adapted) |
| **QuestaSim specifically** | PacGate targets Icarus Verilog + cocotb, but generated Verilog is simulator-portable |

The key insight: the MRMAC IP and channel controller are plumbing that connects the physical interface to the packet processing pipeline. PacGate generates everything from the frame parser inward — which is the majority of the work.

---

## Side-by-Side: Python Implementation File Manifest vs PacGate

### MRMAC Two-Channel Verification

| Python file | PacGate equivalent |
|---|---|
| `verif/regression/python/packet_gen.py` | Generated cocotb PacketFactory + PacketDriver |
| `verif/regression/python/packet_checker.py` | Generated cocotb Scoreboard (full L2/L3/L4 reference model) |
| `verif/regression/python/error_injector.py` | Scenario v2 `inject_rmac_error` + topology simulation |
| `verif/regression/python/test_controller.py` | `pacgate regress` / `pacgate topology` CLI |
| `verif/regression/python/run_tests.py` | `make sim-regress` / Makefile targets |
| `verif/unit/mac_phy/tc/*.sv` | Generated cocotb test bench (10G/25G/error cases) |
| `rtl/mac_phy/mrmac_wrapper.sv` | **Not covered** — MRMAC-specific |
| `rtl/mac_phy/mrmac_channel_ctrl.sv` | **Not covered** — MRMAC-specific |

### L2/L3 Packet Switch Between MRMACs

| Python file | PacGate equivalent |
|---|---|
| `rtl/fabric_if/ingress_pipeline.sv` | Generated `frame_parser` + `rule_match_N` |
| `rtl/fabric_if/route_table.sv` | `Ipv4Prefix` CIDR matching in generated Verilog |
| `rtl/fabric_if/switch_fabric.sv` | `decision_logic` + `packet_filter_multiport_top` |
| `rtl/fabric_if/egress_pipeline.sv` | `store_forward_fifo` + `rule_counters` |
| `rtl/fabric_if/mac_addr_table.sv` | **Not covered** — dynamic MAC learning is custom |
| `verif/regression/python/switch_model.py` | `pacgate topology` (Rust, ~640K pps) |
| `verif/regression/python/network_model.py` | Scenario v2 topology definition |

---

## Getting Started

```bash
# Install
cd pacgate && cargo install --path .

# Define your rules
pacgate init rules.yaml           # starter template, then customize

# Generate hardware + tests
pacgate compile rules.yaml --axi --counters --ports 2

# Validate scenarios
pacgate scenario validate scenarios/*.json

# Run 1000-packet regression
pacgate regress --scenario scenario.json --count 1000 --json

# Run topology simulation with drop tracking
pacgate topology --scenario topology_scenario.json --json

# Generate Vivado project
pacgate synth rules.yaml --target vivado --part xcvm1802
```
