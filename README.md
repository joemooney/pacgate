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

<p align="center">
  <img src="docs/images/pacinet_family.png" alt="PaciNet Family" width="300"/>
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

| Layer | Field | Description | Example |
|-------|-------|------------|---------|
| L2 | `dst_mac` | Destination MAC (exact or wildcard) | `"ff:ff:ff:ff:ff:ff"`, `"01:80:c2:*:*:*"` |
| L2 | `src_mac` | Source MAC (exact or wildcard) | `"00:1a:2b:*:*:*"` |
| L2 | `ethertype` | EtherType (16-bit hex) | `"0x0800"` (IPv4), `"0x0806"` (ARP) |
| L2 | `vlan_id` | VLAN ID (0–4095) | `100` |
| L2 | `vlan_pcp` | VLAN Priority Code Point (0–7) | `7` |
| L3 | `src_ip` | IPv4 source (exact or CIDR) | `"10.0.0.0/8"` |
| L3 | `dst_ip` | IPv4 destination (exact or CIDR) | `"192.168.1.1"` |
| L3 | `ip_protocol` | IP protocol number (8-bit) | `6` (TCP), `17` (UDP) |
| L3 | `src_ipv6` | IPv6 source (CIDR prefix) | `"2001:db8::/32"` |
| L3 | `dst_ipv6` | IPv6 destination (CIDR prefix) | `"fe80::/10"` |
| L3 | `ipv6_next_header` | IPv6 next header (8-bit) | `58` (ICMPv6) |
| L4 | `src_port` | TCP/UDP source port (exact or range) | `80` or `{range: [1024, 65535]}` |
| L4 | `dst_port` | TCP/UDP destination port (exact or range) | `443` |
| Tunnel | `vxlan_vni` | VXLAN Network Identifier (24-bit) | `1000` |
| Tunnel | `gtp_teid` | GTP-U Tunnel Endpoint ID (32-bit) | `12345` |
| L2.5 | `mpls_label` | MPLS label (20-bit) | `1000` |
| L2.5 | `mpls_tc` | MPLS Traffic Class (3-bit) | `5` |
| L2.5 | `mpls_bos` | MPLS Bottom of Stack (1-bit) | `1` |
| L3 | `igmp_type` | IGMP message type (8-bit hex) | `"0x11"` (query) |
| L3 | `mld_type` | MLD message type (8-bit) | `130` (query) |
| Raw | `byte_match` | Byte-offset match with mask | `{offset: 14, value: "45", mask: "F0"}` |

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

- **Frame Parser**: Hand-written, extracts L2/L3/L4/IPv6/VXLAN/GTP-U/MPLS/IGMP/MLD fields byte-by-byte
- **Rule Matchers**: Generated per-rule, combinational evaluation in O(1) cycles (stateless) or registered FSM (stateful)
- **Priority Encoder**: Generated if/else chain, highest priority match wins
- **Store-Forward FIFO**: Buffers frames until decision is ready, then forwards or discards
- **AXI-Stream Wrapper**: Standard interface for integration with existing FPGA designs
- **Rate Limiter**: Per-rule token-bucket rate limiting (`--rate-limit`)
- **Connection Tracking**: CRC-based hash table with timeout (`--conntrack`)
- **Runtime Flow Tables**: Register-based match entries with AXI-Lite CRUD + atomic commit (`--dynamic`)
- **Rule Counters**: Per-rule 64-bit packet/byte counters with AXI-Lite readout (`--counters`)

## Examples

PacGate ships with 22 production-quality examples covering real-world deployment scenarios:

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
| [`l3l4_firewall.yaml`](rules/examples/l3l4_firewall.yaml) | L3/L4 firewall (SSH, HTTP/S, DNS) | 7 | Whitelist |
| [`byte_match.yaml`](rules/examples/byte_match.yaml) | Byte-offset matching | 3 | Whitelist |
| [`hsm_conntrack.yaml`](rules/examples/hsm_conntrack.yaml) | Hierarchical FSM + connection tracking | 3 | Whitelist |
| [`ipv6_firewall.yaml`](rules/examples/ipv6_firewall.yaml) | IPv6 firewall (ICMPv6, CIDR) | 6 | Whitelist |
| [`rate_limited.yaml`](rules/examples/rate_limited.yaml) | Rate-limited rules (token-bucket) | 5 | Whitelist |
| [`vxlan_datacenter.yaml`](rules/examples/vxlan_datacenter.yaml) | VXLAN datacenter (VNI isolation) | 6 | Whitelist |
| [`gtp_5g.yaml`](rules/examples/gtp_5g.yaml) | GTP-U 5G mobile core (TEID) | 5 | Whitelist |
| [`mpls_network.yaml`](rules/examples/mpls_network.yaml) | MPLS provider network (label stack) | 5 | Whitelist |
| [`multicast.yaml`](rules/examples/multicast.yaml) | IGMP/MLD multicast filtering | 5 | Whitelist |
| [`dynamic_firewall.yaml`](rules/examples/dynamic_firewall.yaml) | Runtime-updateable flow table (`--dynamic`) | 5 | Whitelist |

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
  compile        Generate Verilog RTL + cocotb test bench from YAML rules
  validate       Validate YAML rules without generating output
  init           Create a starter rules file with comments
  estimate       FPGA resource estimation (LUTs/FFs) + timing analysis
  diff           Compare two rule sets (added/removed/modified rules)
  graph          Output DOT graph of rule set for Graphviz
  stats          Rule set analytics (field usage, priority spacing)
  formal         Generate SVA assertions + SymbiYosys task files
  lint           Best-practice analysis (security, performance, 15 rules)
  report         Generate HTML coverage report
  pcap           Import PCAP capture for cocotb test stimulus
  pcap-analyze   Analyze PCAP traffic + auto-suggest rules
  simulate       Software dry-run simulation (no hardware needed)
  synth          Generate Yosys/Vivado synthesis project files
  mutate         Mutation testing (generate + optional kill-rate analysis)
  mcy            MCY (Mutation Cover with Yosys) config generation
  template       Built-in rule templates (list/show/apply)
  doc            Generate styled HTML rule documentation
  bench          Benchmark compile time, sim throughput, LUT/FF scaling
  from-mermaid   Import Mermaid stateDiagram to YAML rules
  to-mermaid     Export YAML FSM rules to Mermaid stateDiagram-v2
  reachability   Analyze rule reachability (shadowed, redundant rules)
  completions    Generate shell completions (bash/zsh/fish)

COMPILE FLAGS:
  --axi          Include AXI-Stream wrapper + store-forward FIFO
  --counters     Include per-rule 64-bit packet/byte counters + AXI-Lite CSR
  --ports N      Generate multi-port switch fabric (N parallel filters)
  --conntrack    Include connection tracking hash table RTL
  --rate-limit   Include per-rule token-bucket rate limiter RTL
  --dynamic      Runtime-updateable flow table (AXI-Lite writable, replaces static matchers)
  --dynamic-entries N  Max flow table entries (1-256, default 16)

SIMULATE FLAGS:
  --stateful     Enable rate-limit + connection tracking in software simulation
  --pcap-out F   Write simulation results to Wireshark-compatible PCAP file

GLOBAL FLAGS:
  --json         Machine-readable JSON output (most commands)
  -o <DIR>       Output directory (default: gen/)
```

## Verification

PacGate generates a comprehensive verification environment inspired by UVM methodology:

### Simulation (cocotb)
- **Directed tests**: Specific frames targeting each rule with proper L3/L4/IPv6 headers
- **Random tests**: 500+ constrained-random frames with full-stack scoreboard checking
- **Corner cases**: Runt frames, jumbo frames, back-to-back, broadcast MAC, VLAN PCP extremes
- **Property tests**: 9 Hypothesis-based tests including protocol-specific strategies (GTP-U, MPLS, IGMP, MLD)
- **Coverage**: Functional coverage with cover points, bins, cross coverage, XML export, coverage-directed closure
- **Boundary tests**: Auto-derived CIDR boundary and port boundary test cases
- **Mutation testing**: YAML-level (11 strategies + kill-rate runner) and Verilog-level (MCY)
- **Software simulation**: `simulate` command for dry-run testing without hardware toolchain

### Formal Verification (SymbiYosys)
- **SVA assertions** generated from rules: reset correctness, completeness, latency bounds, protocol prerequisites
- **Bounded model checking**: Mathematical proof that rules behave correctly
- **Cover mode**: Verify all rules and protocol paths are reachable
- **Protocol assertions**: GTP-U/MPLS/IGMP/MLD prerequisite and bounds checking

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
├── src/                    # Rust compiler (29 subcommands)
│   ├── main.rs             # CLI (clap)
│   ├── model.rs            # Data model (L2/L3/L4/IPv6/tunnel/multicast/byte_match/HSM)
│   ├── loader.rs           # YAML loader + validation + CIDR/port overlap detection
│   ├── verilog_gen.rs      # Tera-based Verilog generation (all match fields + multi-port)
│   ├── cocotb_gen.rs       # cocotb test harness + property test generation
│   ├── formal_gen.rs       # SVA assertion + SymbiYosys generation
│   ├── simulator.rs        # Software simulation (stateless + stateful rate-limit/conntrack)
│   ├── pcap_analyze.rs     # PCAP traffic analysis + rule suggestion engine
│   ├── synth_gen.rs        # Yosys/Vivado synthesis project generation
│   ├── mutation.rs         # Rule mutation engine (11 strategies)
│   ├── mcy_gen.rs          # MCY Verilog-level mutation config generation
│   ├── benchmark.rs        # Performance benchmarking engine
│   └── ...                 # mermaid, pcap, templates_lib, pcap_writer
├── templates/              # 19 Tera templates (Verilog, cocotb, SVA, HTML, synthesis)
├── rtl/                    # Hand-written Verilog (parser, AXI, FIFO, counters, conntrack, rate limiter)
├── rules/examples/         # 21 YAML rule examples
├── rules/templates/        # 7 built-in rule templates
├── verification/           # Python verification framework (scoreboard, coverage, properties)
├── synth/                  # Synthesis files (XDC constraints, Yosys script)
├── tests/                  # 151 Rust integration tests
├── gen/                    # Generated output directory
└── docs/                   # Full documentation suite
```

## Quality

| Metric | Value |
|--------|-------|
| Rust unit tests | 242 |
| Rust integration tests | 165 |
| Python scoreboard tests | 47 |
| cocotb simulation tests | 13+ |
| Conntrack cocotb tests | 5 |
| Random packet scoreboard | 500/500 matches |
| Functional coverage | 85%+ |
| Hypothesis property tests | 9 strategies (incl. GTP-U/MPLS/IGMP/MLD) |
| SVA formal assertions | 20+ properties (protocol prerequisites, bounds, cover) |
| Lint rules | 17 (LINT001-017) |
| Mutation strategies | 11 YAML-level + MCY Verilog-level |
| Rule overlap detection | Compile-time CIDR/port range analysis |
| YAML examples | 22 production-quality |

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
