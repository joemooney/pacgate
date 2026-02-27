```
                                    _____
______________ _____________ ______ __  /_____
___  __ \  __ `/  ___/_  __ `/  __ `/  __/  _ \
__  /_/ / /_/ // /__ _  /_/ // /_/ // /_ /  __/
_  .___/\__,_/ \___/ _\__, / \__,_/ \__/ \___/
/_/                  /____/

___FPGA Packet Switch Verification Gateway___
```

<p align="center">
  <img src="docs/images/pacgate_cc.png" alt="PacGate Logo" width="300"/>
</p>

<p align="center">
  <strong>Define rules in YAML. Generate hardware in Verilog. Prove correctness in simulation.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#examples">Examples</a> &bull;
  <a href="#verification">Verification</a> &bull;
  <a href="docs/user-guide/">User Guide</a>
</p>

---

## What is PacGate?

PacGate is an **FPGA packet filtering compiler** that turns YAML rule definitions into both **synthesizable Verilog hardware** and a **complete verification environment** — from a single specification.

No other tool generates both the hardware implementation *and* the test harness from the same spec. Commercial tools assume the RTL already exists. PacGate generates both, guaranteeing perfect alignment between what you specify, what gets built, and what gets tested.

### One Spec, Four Outputs

```
                    ┌────────────────────────────────┐
                    │         rules.yaml             │
                    │  ┌───────────────────────────┐ │
                    │  │ - allow_arp:              │ │
                    │  │     ethertype: 0x0806     │ │
                    │  │     action: pass          │ │
                    │  │ - block_broadcast:        │ │
                    │  │     dst_mac: ff:ff:...:ff │ │
                    │  │     action: drop          │ │
                    │  └───────────────────────────┘ │
                    └──────────────┬─────────────────┘
                                   │
                          pacgate compile
                                   │
              ┌────────────────────┼─────────────────────┐
              ▼                    ▼                     ▼
     ┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐
     │  Verilog RTL   │  │  cocotb Tests   │  │  SVA Assertions  │
     │  (hardware)    │  │  (simulation)   │  │  (formal proof)  │
     └────────────────┘  └─────────────────┘  └──────────────────┘
              │                    │                     │
              ▼                    ▼                     ▼
        Xilinx FPGA       Icarus Verilog +        SymbiYosys
        (Artix-7)         cocotb (PASS/FAIL)      (BMC/cover)
```

## Quick Start

### Install

```bash
# Clone and build
git clone https://github.com/joemooney/pacgate.git
cd pacgate
cargo build --release

# Optional: install to PATH
cargo install --path .
```

### Your First Filter

```bash
# Create a starter rule file
pacgate init my_filter.yaml

# Edit rules (or use an example)
cat rules/examples/enterprise.yaml

# Compile to Verilog + tests
pacgate compile rules/examples/enterprise.yaml -o gen/

# Validate without generating
pacgate validate rules/examples/enterprise.yaml

# See what changed between two rule sets
pacgate diff rules/examples/allow_arp.yaml rules/examples/enterprise.yaml
```

### Run Simulation

```bash
# Prerequisites: Python 3, cocotb, Icarus Verilog
pip install cocotb cocotb-coverage hypothesis

# Compile and simulate
make sim RULES=rules/examples/enterprise.yaml

# Run with AXI-Stream wrapper
pacgate compile rules/examples/enterprise.yaml --axi -o gen/
make sim-axi RULES=rules/examples/enterprise.yaml
```

### Formal Verification

```bash
# Generate SVA assertions + SymbiYosys tasks
pacgate formal rules/examples/enterprise.yaml -o gen/

# Run bounded model checking (requires SymbiYosys)
cd gen/formal && sby -f packet_filter.sby
```

## How It Works

### Rule Language

PacGate rules are defined in YAML. Each rule specifies match criteria and an action (pass or drop). Rules are evaluated by priority — highest priority match wins.

```yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop          # Whitelist mode: block everything by default

  rules:
    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass

    - name: allow_mgmt_vlan
      type: stateless
      priority: 90
      match:
        vlan_id: 100
      action: pass

    - name: allow_vendor_cisco
      type: stateless
      priority: 80
      match:
        src_mac: "00:26:cb:*:*:*"   # Wildcard last 3 octets
      action: pass
```

### Match Fields

| Field | Description | Example |
|-------|------------|---------|
| `dst_mac` | Destination MAC (exact or wildcard) | `"ff:ff:ff:ff:ff:ff"`, `"01:80:c2:*:*:*"` |
| `src_mac` | Source MAC (exact or wildcard) | `"00:1a:2b:*:*:*"` |
| `ethertype` | EtherType (16-bit hex) | `"0x0800"` (IPv4), `"0x0806"` (ARP) |
| `vlan_id` | VLAN ID (0–4095) | `100` |
| `vlan_pcp` | VLAN Priority Code Point (0–7) | `7` |

### Stateful Rules (FSM)

PacGate supports **stateful sequence detection** using finite state machines with configurable timeouts:

```yaml
- name: arp_then_ipv4
  type: stateful
  priority: 50
  fsm:
    initial_state: idle
    states:
      idle:
        transitions:
          - match:
              ethertype: "0x0806"    # ARP
            next_state: arp_seen
            action: pass
      arp_seen:
        timeout_cycles: 1000         # Return to idle after timeout
        transitions:
          - match:
              ethertype: "0x0800"    # IPv4 after ARP
            next_state: idle
            action: pass
```

### Generated Hardware

The compiler generates a pipelined Verilog architecture:

```
AXI-Stream In ──► AXI Adapter ──► Frame Parser ──► Rule Matchers ──► Priority Encoder ──► FIFO ──► AXI-Stream Out
                                       │              (parallel)         (first match)       │
                                       │               ┌─────┐            ┌──────┐           │
                                       └──► fields ──► │ R0  │ ──match──► │      │           │
                                                       │ R1  │ ──match──► │ P.E. │──decision─┘
                                                       │ R2  │ ──match──► │      │
                                                       │ ... │            └──────┘
                                                       └─────┘
```

- **Frame Parser**: Hand-written, extracts Ethernet header fields byte-by-byte (handles 802.1Q VLAN tags)
- **Rule Matchers**: Generated per-rule, combinational evaluation in O(1) cycles
- **Priority Encoder**: Generated if/else chain, highest priority match wins
- **Store-Forward FIFO**: Buffers frames until decision is ready, then forwards or discards
- **AXI-Stream Wrapper**: Standard interface for integration with existing FPGA designs

## Examples

PacGate ships with real-world examples covering common deployment scenarios:

| Example | Scenario | Rules | Mode |
|---------|----------|-------|------|
| [`allow_arp.yaml`](rules/examples/allow_arp.yaml) | Minimal — allow ARP only | 1 | Whitelist |
| [`enterprise.yaml`](rules/examples/enterprise.yaml) | Enterprise campus network | 7 | Whitelist |
| [`blacklist.yaml`](rules/examples/blacklist.yaml) | Threat blocking | 5 | Blacklist |
| [`datacenter.yaml`](rules/examples/datacenter.yaml) | Multi-tenant data center | 8 | Whitelist |
| [`stateful_sequence.yaml`](rules/examples/stateful_sequence.yaml) | Stateful sequence detection | 2 | Whitelist |
| [`industrial_ot.yaml`](rules/examples/industrial_ot.yaml) | Industrial OT/SCADA boundary | 8 | Whitelist |
| [`automotive_gateway.yaml`](rules/examples/automotive_gateway.yaml) | Automotive Ethernet gateway | 7 | Whitelist |
| [`5g_fronthaul.yaml`](rules/examples/5g_fronthaul.yaml) | 5G fronthaul filtering | 7 | Whitelist |
| [`campus_access.yaml`](rules/examples/campus_access.yaml) | Campus access control | 8 | Whitelist |
| [`iot_gateway.yaml`](rules/examples/iot_gateway.yaml) | IoT edge gateway | 7 | Whitelist |
| [`syn_flood_detect.yaml`](rules/examples/syn_flood_detect.yaml) | SYN flood detection (stateful) | 3 | Whitelist |
| [`arp_spoof_detect.yaml`](rules/examples/arp_spoof_detect.yaml) | ARP spoofing detection (stateful) | 3 | Whitelist |

### Try an Example

```bash
# Compile the industrial OT example
pacgate compile rules/examples/industrial_ot.yaml -o gen/

# See resource estimates for automotive gateway
pacgate estimate rules/examples/automotive_gateway.yaml

# Compare two configurations
pacgate diff rules/examples/enterprise.yaml rules/examples/datacenter.yaml

# Visualize rule set as a graph
pacgate graph rules/examples/campus_access.yaml | dot -Tpng -o campus.png

# Get analytics on a rule set
pacgate stats rules/examples/5g_fronthaul.yaml
```

## CLI Reference

```
USAGE: pacgate <COMMAND>

COMMANDS:
  compile      Generate Verilog RTL + cocotb test bench from YAML rules
  validate     Validate YAML rules without generating output
  init         Create a starter rules file with comments
  estimate     FPGA resource estimation (LUTs/FFs) + timing analysis
  diff         Compare two rule sets (added/removed/modified rules)
  graph        Output DOT graph of rule set for Graphviz
  stats        Rule set analytics (field usage, priority spacing)
  formal       Generate SVA assertions + SymbiYosys task files
  completions  Generate shell completions (bash/zsh/fish)

FLAGS:
  --json       Machine-readable JSON output (compile/validate/estimate/diff/stats/formal)
  --axi        Include AXI-Stream wrapper + store-forward FIFO (compile only)
  -o <DIR>     Output directory (default: gen/)
```

## Verification

PacGate generates a comprehensive verification environment inspired by UVM methodology:

### Simulation (cocotb)
- **Directed tests**: Specific frames targeting each rule
- **Random tests**: 500+ constrained-random Ethernet frames with scoreboard checking
- **Corner cases**: Runt frames, jumbo frames, back-to-back, broadcast MAC, VLAN PCP extremes
- **Property tests**: Hypothesis-based invariant testing (determinism, priority, conservation)
- **Coverage**: Functional coverage with cover points, bins, cross coverage, XML export

### Formal Verification (SymbiYosys)
- **SVA assertions** generated from rules: reset correctness, completeness, latency bounds
- **Bounded model checking**: Mathematical proof that rules behave correctly
- **Cover mode**: Verify all rules are reachable

### Results
```
Enterprise example (7 rules):
  13 cocotb tests ................ PASS
  500 random packets ............. 0 mismatches
  Functional coverage ............ 85%+
  Property tests (500 frames) ... 500/500 PASS
  Formal (BMC depth 20) ......... PROVEN
```

## FPGA Targeting

```bash
# Resource estimation
$ pacgate estimate rules/examples/enterprise.yaml

  ┌─────────────────────────────────────────┐
  │     FPGA Resource Estimate (Artix-7)    │
  ├─────────────────┬───────┬───────────────┤
  │ Component       │ LUTs  │ Flip-Flops    │
  ├─────────────────┼───────┼───────────────┤
  │ Frame parser    │ ~120  │ ~80           │
  │ 7 rule matchers │ ~280  │ ~0            │
  │ Decision logic  │ ~35   │ ~2            │
  │ Total           │ ~435  │ ~82           │
  │ Artix-7 usage   │ 2.1%  │ 0.2%          │
  └─────────────────┴───────┴───────────────┘

  Pipeline: 16 cycles @ 125 MHz = 128 ns latency
```

### Synthesis with Yosys

```bash
# Open-source synthesis targeting Xilinx 7-series
make synth RULES=rules/examples/enterprise.yaml
```

## Project Structure

```
pacgate/
├── src/                    # Rust compiler
│   ├── main.rs             # CLI (clap) — compile/validate/init/estimate/diff/graph/stats/formal
│   ├── model.rs            # Data model + 21 unit tests
│   ├── loader.rs           # YAML loader + validation + overlap detection + 23 unit tests
│   ├── verilog_gen.rs      # Tera-based Verilog generation
│   ├── cocotb_gen.rs       # cocotb test harness generation
│   └── formal_gen.rs       # SVA + SymbiYosys generation
├── templates/              # Tera templates for code generation
├── rtl/                    # Hand-written Verilog (parser, AXI adapter, FIFO)
├── rules/examples/         # 12+ YAML rule examples
├── verification/           # Python verification framework
├── synth/                  # Synthesis files (XDC constraints, Yosys script)
├── tests/                  # 19 Rust integration tests
├── gen/                    # Generated output directory
└── docs/                   # Full documentation suite
```

## Quality

| Metric | Value |
|--------|-------|
| Rust unit tests | 44 |
| Rust integration tests | 19 |
| cocotb simulation tests | 13+ |
| Random packet scoreboard | 500/500 matches |
| Functional coverage | 85%+ |
| Property-based tests | 500/500 pass |
| SVA formal assertions | 7+ properties |
| Rule overlap detection | Compile-time warnings |

## Technology Stack

- **Compiler**: Rust (clap, serde_yaml, serde_json, tera)
- **HDL**: Verilog (IEEE 1364-2005 compatible)
- **Simulation**: Icarus Verilog + cocotb 2.x
- **Verification**: UVM-inspired Python framework
- **Formal**: SymbiYosys + SMT solvers
- **Property Testing**: Hypothesis (Python)
- **Synthesis**: Yosys (open-source) targeting Xilinx 7-series
- **Target FPGA**: Xilinx Artix-7 (XC7A35T)

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <em>PacGate — Where rules become hardware, and tests prove it works.</em>
</p>
