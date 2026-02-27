# PacGate — Product Overview

*FPGA Packet Switch Verification Gateway*

---

## Slide 1: The Problem

### FPGA Network Filter Development Is Broken

- **Manual RTL coding** is slow and error-prone
- **Verification is an afterthought** — tests written after hardware, spec drift is inevitable
- **No single source of truth** — specs, RTL, and tests diverge over time
- **Commercial tools cost $100K+/year** (Vivado, Questa, VCS)
- **Verification takes 60-70% of FPGA development time** (industry average)

> "We spent 6 months on the filter RTL, then 8 more months finding bugs in verification."
> — Every FPGA team, every project

---

## Slide 2: The Solution

### PacGate: One Spec, Dual Output

```
rules.yaml ──► pacgate ──┬──► Verilog RTL (hardware)
                          ├──► cocotb tests (simulation)
                          ├──► SVA assertions (formal proof)
                          └──► Property tests (invariants)
```

- Define packet filter rules in **readable YAML**
- Compiler generates **synthesizable Verilog** AND **complete verification**
- **By construction**, hardware and tests can never diverge
- Leverages open-source toolchain: Icarus Verilog, cocotb, SymbiYosys, Yosys

---

## Slide 3: How It Works

### From YAML to FPGA in Minutes

```yaml
pacgate:
  defaults:
    action: drop

  rules:
    - name: allow_arp
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
```

**One command:**
```
$ pacgate compile rules.yaml -o gen/
Generated: 1 rule matcher, decision logic, cocotb tests
```

**Result:**
- Synthesizable Verilog (Artix-7 compatible) with L2/L3/L4/IPv6/tunnel/multicast matching
- 13+ cocotb tests (directed + 500 random packets) + 5 conntrack tests
- 20+ SVA formal assertions with protocol prerequisites and cover statements
- 9 Hypothesis property-based tests with protocol strategies

---

## Slide 4: Market Landscape

### Where PacGate Fits

| Tool | Hardware Gen | Test Gen | Open Source | Single Spec |
|------|:-----------:|:--------:|:-----------:|:-----------:|
| **PacGate** | **Yes** | **Yes** | Proprietary | **Yes** |
| Corundum (UW) | Yes | No | Yes | No |
| NetFPGA | Partial | No | Yes | No |
| P4/Tofino | Yes | No | No | No |
| Vivado HLS | Yes | No | No | No |
| Agnisys IDS | No | Yes | No | No |

**PacGate is the only tool that generates both hardware AND verification from one specification.**

---

## Slide 5: Real-World Applications

### Proven Across Industries

| Sector | Use Case | Example |
|--------|----------|---------|
| **Data Center** | Multi-tenant VLAN isolation | `datacenter.yaml` (8 rules) |
| **Industrial** | OT/SCADA boundary protection | EtherCAT, PROFINET, PTP filtering |
| **Automotive** | Domain gateway (ADAS/powertrain) | AVB/TSN, SOME/IP |
| **Telecom** | 5G fronthaul filtering | eCPRI, PTP, Sync-E |
| **Campus** | Access layer security | STP guard, 802.1X, VLAN segmentation |
| **IoT** | Edge gateway isolation | Sensor/actuator VLAN filtering |
| **Security** | Threat detection | SYN flood, ARP spoofing (stateful FSM) |

**21 production-quality examples included** spanning L2-L4, IPv6, VXLAN, GTP-U, MPLS, IGMP/MLD, rate-limiting, and connection tracking.

---

## Slide 6: Verification Depth

### Enterprise-Grade Quality Assurance

```
                    Verification Pyramid

           ┌──────────────────┐
           │  Formal Proof    │  ◄── SymbiYosys BMC
           │  (mathematical)  │      SVA assertions
           ├──────────────────┤
           │  Property Tests  │  ◄── Hypothesis
           │  (invariants)    │      500+ frame properties
           ├──────────────────┤
           │  Random Tests    │  ◄── cocotb + scoreboard
           │  (500 packets)   │      85%+ coverage
           ├──────────────────┤
           │  Directed Tests  │  ◄── Per-rule regression
           │  (per-rule)      │      Corner cases
           └──────────────────┘
```

- **237 Rust unit tests** + **151 integration tests** + **47 Python tests** (compiler + scoreboard)
- **13+ cocotb simulation tests** + **5 conntrack tests** (hardware)
- **500/500 scoreboard matches** (full L2/L3/L4/IPv6/tunnel/multicast/byte-match verification)
- **85%+ functional coverage** (cover points + cross coverage + XML export)
- **9 Hypothesis property tests** with protocol-specific strategies (GTP-U, MPLS, IGMP, MLD)
- **20+ SVA formal assertions** (protocol prerequisites, bounds, cover statements)
- **15 lint rules** (security, performance, maintainability, protocol prerequisites)
- **11 mutation strategies** + MCY Verilog-level mutation testing

---

## Slide 7: FPGA Targets

### Production-Ready for Xilinx 7-Series

| Metric | Enterprise (7 rules) |
|--------|---------------------|
| LUTs | ~435 (2.1% Artix-7) |
| Flip-Flops | ~82 (0.2% Artix-7) |
| Clock | 125 MHz |
| Latency | 16 cycles (128 ns) |
| Interface | AXI-Stream |

- **AXI-Stream wrapper** for drop-in integration
- **Store-and-forward FIFO** for frame buffering
- **Yosys synthesis** (no Vivado license required)
- Scales linearly: 7 rules = 435 LUTs, 14 rules ≈ 870 LUTs

---

## Slide 8: Developer Experience

### CLI-First, CI-Ready

```bash
# Create rules
pacgate init my_filter.yaml

# Validate (fast feedback)
pacgate validate my_filter.yaml

# Compile (generate everything)
pacgate compile my_filter.yaml --axi -o gen/

# Estimate resources
pacgate estimate my_filter.yaml

# Compare versions
pacgate diff old_rules.yaml new_rules.yaml --json

# Visualize
pacgate graph my_filter.yaml | dot -Tpng -o rules.png

# Formal proof
pacgate formal my_filter.yaml
```

- `--json` flag for CI/CD integration
- Shell completions (bash/zsh/fish)
- Rule overlap and shadow detection (compile-time warnings)

---

## Slide 9: Stateful Detection

### Beyond Simple Matching

```yaml
- name: arp_then_ipv4_flow
  type: stateful
  priority: 100
  fsm:
    initial_state: idle
    states:
      idle:
        transitions:
          - match:
              ethertype: "0x0806"
            next_state: arp_seen
            action: pass
      arp_seen:
        timeout_cycles: 5000
        transitions:
          - match:
              ethertype: "0x0800"
            next_state: active
            action: pass
```

- **FSM state machines** with configurable timeouts
- **Sequence detection**: ARP→IPv4, handshake patterns
- **Attack detection**: SYN floods, ARP spoofing
- Generates registered Verilog FSM with 32-bit timeout counters

---

## Slide 10: Business Case

### ROI and Time-to-Market

| Traditional FPGA Filter | With PacGate |
|--------------------------|-------------|
| 2-4 weeks RTL coding | **Minutes** (YAML) |
| 4-8 weeks verification | **Zero** (auto-generated) |
| Manual spec tracking | **By construction** |
| $100K+ tool licenses | **Fraction of cost** |
| Error-prone updates | **Diff + recompile** |

**Conservative estimate: 10-20x faster development cycle**

### Revenue Opportunities
- **Consulting**: Deploy PacGate for client FPGA projects
- **Enterprise license**: Advanced features (byte_match, L3/L4 filters)
- **Training**: Workshops on FPGA verification methodology
- **Integration**: SmartNIC, OT security, automotive gateway products

---

## Slide 11: Technology Stack

### Mature Technology Foundation

| Component | Technology | Maturity |
|-----------|-----------|----------|
| Compiler | Rust | Production |
| Templates | Tera (Jinja2-like) | Production |
| HDL | Verilog (IEEE 1364-2005) | Decades |
| Simulation | Icarus Verilog + cocotb | Production |
| Formal | SymbiYosys + Z3/Boolector | Production |
| Synthesis | Yosys | Production |
| FPGA Target | Xilinx Artix-7 | Production |

No EDA vendor lock-in. Built on proven open-source simulation and synthesis tools.

---

## Slide 12: Development Status

### Completed Through Phase 16

All core features are implemented and verified:

- **Phase 1-3**: L2 matching, multi-rule, stateful FSM
- **Phase 4-5**: AXI-Stream, synthesis, formal verification, lint, 12 examples, docs
- **Phase 6-7**: L3/L4 matching, counters, PCAP import, VXLAN, byte-match, HSM, multi-port, conntrack
- **Phase 8-9**: IPv6, simulation, rate limiting, PCAP analysis, synthesis projects, mutation testing, templates
- **Phase 10-11**: Full-stack verification, reachability analysis, PCAP output, benchmarking, HTML diff
- **Phase 12-13**: GTP-U, MPLS, IGMP/MLD, coverage-directed closure, MCY, boundary tests
- **Phase 14-16**: Protocol verification completeness, formal assertion strengthening, stateful simulation

### What's Next

**Near-term:**
- P4 program import/export
- RISC-V co-processor for dynamic rule updates
- Multi-vendor FPGA support (Intel, Lattice)

**Long-term:**
- Visual rule editor (web UI)
- Cloud synthesis service
- Hardware-in-the-loop testing framework
- ASIC targeting (for high-volume production)

---

## Slide 13: Call to Action

### Get Started Today

```bash
git clone https://github.com/joemooney/pacgate.git
cd pacgate && cargo build --release
pacgate compile rules/examples/enterprise.yaml -o gen/
```

**Resources:**
- GitHub: github.com/joemooney/pacgate
- 21 production-quality examples included
- Full documentation suite (user guide, test guide, 8 workshops)
- 388 Rust tests + 47 Python tests + 18+ cocotb tests

**PacGate — Where rules become hardware, and tests prove it works.**
