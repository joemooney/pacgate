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
- Open-source toolchain: Icarus Verilog, cocotb, SymbiYosys, Yosys

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
- Synthesizable Verilog (Artix-7 compatible)
- 13+ cocotb tests (directed + 500 random packets)
- SVA formal assertions
- Property-based invariant tests

---

## Slide 4: Market Landscape

### Where PacGate Fits

| Tool | Hardware Gen | Test Gen | Open Source | Single Spec |
|------|:-----------:|:--------:|:-----------:|:-----------:|
| **PacGate** | **Yes** | **Yes** | **Yes** | **Yes** |
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

**12 production-quality examples included.**

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

- **44 Rust unit tests** + **19 integration tests** (compiler)
- **13+ cocotb simulation tests** (hardware)
- **500/500 scoreboard matches** (random verification)
- **85%+ functional coverage** (cover points + cross coverage)
- **SVA formal assertions** (mathematical proof of correctness)

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
| $100K+ tool licenses | **Free** (open source) |
| Error-prone updates | **Diff + recompile** |

**Conservative estimate: 10-20x faster development cycle**

### Revenue Opportunities
- **Consulting**: Deploy PacGate for client FPGA projects
- **Enterprise license**: Advanced features (byte_match, L3/L4 filters)
- **Training**: Workshops on FPGA verification methodology
- **Integration**: SmartNIC, OT security, automotive gateway products

---

## Slide 11: Technology Stack

### Mature, Open-Source Foundation

| Component | Technology | Maturity |
|-----------|-----------|----------|
| Compiler | Rust | Production |
| Templates | Tera (Jinja2-like) | Production |
| HDL | Verilog (IEEE 1364-2005) | Decades |
| Simulation | Icarus Verilog + cocotb | Production |
| Formal | SymbiYosys + Z3/Boolector | Production |
| Synthesis | Yosys | Production |
| FPGA Target | Xilinx Artix-7 | Production |

No vendor lock-in. No license fees. Full stack open source.

---

## Slide 12: Roadmap

### What's Next

**Near-term (Q2 2026):**
- L3/L4 matching (IP address, TCP/UDP ports)
- Byte-offset matching (arbitrary protocol fields)
- Multi-port filter (switch fabric)
- Coverage-driven test generation

**Mid-term (Q3-Q4 2026):**
- P4 program import/export
- Mutation testing (MCY integration)
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
- 12 production-quality examples included
- Full documentation suite
- User guide, test guide, and workshops

**PacGate — Where rules become hardware, and tests prove it works.**
