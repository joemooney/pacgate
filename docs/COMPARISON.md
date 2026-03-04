# PacGate Competitive Comparison

*Feature matrix comparing PacGate against tools in the FPGA packet processing landscape.*

---

## Tool Categories

| Category | Tools | What They Do |
|----------|-------|-------------|
| **P4-to-FPGA** | Vitis Networking P4, Intel P4 Suite, P4->NetFPGA, P4FPGA, P4THLS | Compile P4 programs to synthesizable FPGA RTL |
| **HLS Networking** | Vivado/Vitis HLS | Compile C/C++ to FPGA RTL for packet processing |
| **FPGA NIC Frameworks** | Corundum, NetFPGA SUME, OpenNIC Shell, ESnet SmartNIC | Complete NIC designs with user-extensible packet processing |
| **Stateful FPGA Processing** | FlowBlaze | EFSM-based stateful packet processor on FPGA |
| **FPGA Packet Filtering** | FFShark/fpga-bpf, hXDP, HyPaFilter | Hardware-accelerated packet filtering (BPF, XDP, iptables) |
| **EDA Verification** | Questa, VCS, Xcelium, JasperGold, Agnisys IDS | Commercial simulation, formal, auto-generated verification |
| **Traffic Generators** | Scapy, T-Rex, DPDK Pktgen, MoonGen | Software/hardware packet generation for testing |

---

## Core Feature Comparison

### Input & Output

| Feature | PacGate | Vitis Net P4 | Intel P4 | Corundum | FlowBlaze | FFShark | Vivado HLS |
|---------|:-------:|:------------:|:--------:|:--------:|:---------:|:-------:|:----------:|
| **Input format** | YAML | P4 | P4 | Verilog | EFSM/GUI | BPF | C/C++ |
| **Generates RTL** | Yes | Yes | Yes | N/A (is RTL) | N/A (fixed arch) | N/A (fixed arch) | Yes |
| **Generates tests** | Yes | No | No | No | No | No | No |
| **Generates SVA assertions** | Yes | No | No | No | No | No | No |
| **Generates property tests** | Yes | No | No | No | No | No | No |
| **Generates coverage model** | Yes | No | No | No | No | No | No |
| **Single-spec dual-output** | **Yes** | No | No | No | No | No | No |
| **No HDL/PL knowledge needed** | **Yes** | No (P4) | No (P4) | No (Verilog) | Partial (GUI) | Yes (BPF) | No (C++) |

### Protocol Support

| Protocol | PacGate | P4 Tools | Corundum | FlowBlaze | FFShark | HLS |
|----------|:-------:|:--------:|:--------:|:---------:|:-------:|:---:|
| **L2 (MAC, EtherType, VLAN)** | Yes | Yes | Yes | Yes | Yes | User |
| **QinQ (802.1ad double VLAN)** | Yes | User | No | No | Yes | User |
| **L3 IPv4 (CIDR, protocol)** | Yes | Yes | RSS only | Yes | Yes | User |
| **L3 IPv6 (CIDR, next header)** | Yes | Yes | RSS only | Partial | Yes | User |
| **L4 TCP/UDP (ports, ranges)** | Yes | Yes | RSS only | Yes | Yes | User |
| **TCP flags (mask-aware)** | Yes | User | No | User | Yes | User |
| **ICMP / ICMPv6 type/code** | Yes | User | No | No | Yes | User |
| **ARP opcode/SPA/TPA** | Yes | User | No | No | Yes | User |
| **IPv4 fragmentation flags** | Yes | User | No | No | Yes | User |
| **IPv6 hop limit / flow label** | Yes | User | No | No | Yes | User |
| **IP TTL matching** | Yes | User | No | No | Yes | User |
| **DSCP/ECN (IPv4 + IPv6)** | Yes | User | No | No | Yes | User |
| **VXLAN VNI** | Yes | User | No | No | Yes | User |
| **GTP-U TEID** | Yes | User | No | No | No | User |
| **Geneve VNI (RFC 8926)** | Yes | User | No | No | No | User |
| **GRE protocol/key** | Yes | User | No | No | Yes | User |
| **MPLS label/TC/BOS** | Yes | User | No | No | No | User |
| **IGMP / MLD multicast** | Yes | User | No | No | Yes | User |
| **OAM/CFM (IEEE 802.1ag)** | Yes | User | No | No | No | User |
| **NSH/SFC (RFC 8300)** | Yes | User | No | No | No | User |
| **Byte-offset raw match** | Yes | Yes | No | No | Yes | User |
| **Protocol-independent (any)** | No | **Yes** | No | No | **Yes** | Yes |
| **L7 / DPI** | No | User | No | No | Yes | User |

*"User" = must be manually programmed by the user; "Yes" = built-in; "No" = not supported*

### Verification Capabilities

| Feature | PacGate | P4 Tools | Corundum | Questa | VCS | Agnisys IDS |
|---------|:-------:|:--------:|:--------:|:------:|:---:|:-----------:|
| **Auto-generated directed tests** | Yes | No | No | No | No | Yes (regs) |
| **Auto-generated random tests** | Yes | No | No | No | No | No |
| **Python scoreboard (ref model)** | Yes | No | No | No | No | No |
| **SVA formal assertions** | Yes | No | No | Manual | Manual | No |
| **SymbiYosys BMC + cover** | Yes | No | No | Questa Formal | VC Formal | No |
| **Hypothesis property tests** | Yes | No | No | No | No | No |
| **Functional coverage model** | Yes | No | No | Manual | Manual | No |
| **Coverage-directed generation** | Yes | No | No | Manual | Manual | No |
| **Mutation testing (YAML)** | Yes | No | No | No | No | No |
| **Mutation testing (Verilog/MCY)** | Yes | No | No | No | No | No |
| **Boundary test derivation** | Yes | No | No | No | No | No |
| **cocotb simulation** | Yes | No | Yes | N/A | N/A | No |
| **Software dry-run simulation** | Yes | p4c BMv2 | No | N/A | N/A | No |
| **PCAP traffic analysis** | Yes | No | No | No | No | No |
| **P4 symbolic verification** | No | p4v/p4pktgen | No | No | No | No |
| **AI-assisted verification** | No | No | No | Yes | Yes | No |

### Hardware Features

| Feature | PacGate | Vitis Net P4 | Corundum | FlowBlaze | OpenNIC | NetFPGA |
|---------|:-------:|:------------:|:--------:|:---------:|:-------:|:-------:|
| **Packet rewrite (in-flight)** | Yes (15 actions) | Yes | Checksum | Yes | User | Yes |
| **RFC 1624 incremental cksum** | Yes | N/A | Yes | No | User | User |
| **Stateful FSM rules** | Yes (HSM) | P4 registers | No | **Yes (EFSM)** | User | User |
| **Connection tracking** | Yes | User | No | Yes | User | User |
| **TCP state machine** | Yes | User | No | Yes | User | User |
| **Per-flow counters** | Yes | Yes | No | No | User | No |
| **Per-rule counters** | Yes | Yes | No | No | User | No |
| **Rate limiting (token bucket)** | Yes | P4 meters | TDMA sched | User | User | No |
| **Runtime flow tables (AXI-Lite)** | Yes | P4 tables | No | Yes | User | P4 tables |
| **Mirror / redirect egress** | Yes | Yes | No | No | User | User |
| **Multi-port switch fabric** | Yes | Yes | Multi-if | Yes | Dual 100G | 4x 10G |
| **AXI-Stream interface** | Yes | Yes | Yes | Custom | Yes | AXI |
| **Platform target wrappers** | OpenNIC, Corundum | Alveo | Native | NetFPGA | Native | Native |
| **Store-forward FIFO** | Yes | Yes | Yes | No | Yes | Yes |
| **Hardware timestamping (PTP)** | No | User | **Yes** | No | No | User |
| **DMA / PCIe host interface** | No | User | **Yes** | No | **Yes** | **Yes** |
| **RSS / multi-queue** | No | User | **Yes** | No | **Yes** | No |

### Performance & Targets

| Metric | PacGate | Vitis Net P4 | Corundum | FlowBlaze | OpenNIC | hXDP |
|--------|:-------:|:------------:|:--------:|:---------:|:-------:|:----:|
| **Target throughput** | ~2 Gbps | 100G-1T | 100G | 40G | 200G | 10G |
| **Target FPGA family** | Artix-7 | UltraScale+ | UltraScale+ | Virtex-7 | Alveo | Xilinx |
| **Min FPGA size** | XC7A35T | Alveo U250 | Alveo U50 | NetFPGA | Alveo U250 | NetFPGA |
| **Open-source sim** | Yes (Icarus) | No | Yes (cocotb) | No | Vivado | No |
| **Synthesis (open-source)** | Yes (Yosys) | No | No | No | No | No |
| **Data path width** | 8-bit | 64-512 bit | 64-512 bit | 256 bit | 512 bit | Custom |
| **Clock frequency** | 125 MHz | 250-350 MHz | 250 MHz | 200 MHz | 250 MHz | 156 MHz |

### Tooling & Ecosystem

| Feature | PacGate | P4 Tools | Corundum | FlowBlaze | HLS |
|---------|:-------:|:--------:|:--------:|:---------:|:---:|
| **CLI tool** | Yes (32 cmds) | p4c compiler | Make | GUI + CLI | Vivado |
| **Lint / best-practice rules** | Yes (46 rules) | p4c warnings | No | No | HLS warnings |
| **FPGA resource estimation** | Yes | Vivado reports | Vivado | No | HLS reports |
| **Rule diff / change mgmt** | Yes (+ HTML) | No | No | No | No |
| **HTML documentation gen** | Yes | No | No | No | No |
| **Mermaid FSM import/export** | Yes | No | No | No | No |
| **Rule templates library** | Yes (7 templates) | No | No | No | No |
| **PCAP import for stimulus** | Yes | No | No | No | No |
| **Shell completions** | Yes | No | No | No | No |
| **JSON output for CI** | Yes | No | No | No | No |
| **Benchmarking suite** | Yes | No | No | No | No |
| **Scenario regression** | Yes | No | No | No | No |

### Cost & Accessibility

| Aspect | PacGate | Vitis Net P4 | Intel P4 | Corundum | Questa | Agnisys |
|--------|:-------:|:------------:|:--------:|:--------:|:------:|:-------:|
| **License** | Proprietary | Commercial | Commercial | BSD | $50K-200K/yr | Commercial |
| **Requires vendor tools** | No (Icarus+Yosys) | Vivado+VNP4 | Quartus | Vivado | Questa license | License |
| **Min hardware cost** | ~$50 (Arty) | ~$5K (Alveo) | ~$5K+ | ~$2K (Alveo U50) | N/A | N/A |
| **Learning curve** | YAML (low) | P4 (medium) | P4 (medium) | Verilog (high) | SV/UVM (high) | Medium |

---

## Gap Analysis: Features PacGate Could Add

### High Priority (clear competitive gaps)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| **Wider data paths (64/128/256-bit)** | 10G-100G throughput; currently limited to ~2 Gbps | Corundum, VitisNetP4, OpenNIC | Large — requires rearchitecting frame_parser and rewrite engine |
| **P4 import** | Accept P4 programs as input; tap into P4 ecosystem | All P4 tools | Large — P4 parser frontend + mapping to PacGate model |
| **P4 export** | Generate P4 from YAML rules for P4-compatible targets | Original — no tool does YAML→P4 | Medium — template-based P4 code generation |
| **DMA / host interface** | Software packet injection/extraction; CPU offload | Corundum, NetFPGA, OpenNIC | Large — PCIe DMA is complex; or leverage existing Corundum/OpenNIC |
| **Multi-table pipeline** | Sequential match-action stages (like P4 pipelines) | All P4 tools, FlowBlaze | Medium — extend decision_logic to chain stages |
| **Hardware timestamping (PTP)** | Precise packet timing for telemetry / 5G | Corundum | Medium — PTP timestamp capture at MAC interface |

### Medium Priority (useful differentiators)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| **eBPF/XDP filter expressions** | Accept Linux XDP programs or BPF filters | hXDP, FFShark | Large — soft BPF CPU or BPF-to-match compiler |
| **Wireshark display filter input** | `tcp.port == 80` syntax for rules | FFShark | Medium — parser for Wireshark filter grammar |
| **GUI for FSM design** | Visual state machine editor | FlowBlaze | Medium — web UI generating YAML; Mermaid Live already works |
| **L7 / DPI (regex match)** | Application-layer protocol detection | FFShark (via BPF), P4 (limited) | Large — regex engine in hardware (BRAM-based NFA) |
| **In-band telemetry (INT)** | Insert metadata headers for network visibility | VitisNetP4, Tofino | Medium — INT header insertion in rewrite engine |
| **RSS / multi-queue dispatch** | Distribute flows across CPU queues | Corundum, OpenNIC | Medium — Toeplitz hash + queue assignment |
| **AI-assisted SVA generation** | Auto-generate complex assertions from design | Questa (Property Assist) | Medium — LLM-based assertion suggestion |

### Low Priority (nice-to-have / future)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| **Protocol-independent parsing** | User-defined header formats | All P4 tools | Large — fundamentally different architecture |
| **Multi-Tbps ASIC targeting** | Datacenter-scale throughput | Tofino (EOL) | N/A — different market segment |
| **Emulation support** | Run on Palladium/Veloce/Protium | Questa, VCS, Xcelium | N/A — requires commercial emulator |
| **RISC-V control plane** | Software-driven rule updates via embedded CPU | Academic projects | Large — RISC-V SoC integration |
| **Traffic generation** | Built-in packet generation for testing | T-Rex, Scapy, MoonGen | Small — already has PCAP import; add pcap-gen |

---

## PacGate's Unique Position

No other tool in this landscape offers PacGate's combination:

```
                        Generates RTL
                             │
                    Yes ─────┼───── No
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        Generates Tests      │        Questa/VCS/
              │              │        Xcelium/IDS
         Yes ─┼─ No         │         (verify only)
              │    │         │
           PacGate │         │
           (only   │         │
            one)   │         │
                   │         │
              P4 tools    Corundum/
              HLS         NetFPGA/
              (RTL only)  OpenNIC
                          (hand-written)
```

**PacGate is the only tool that generates both synthesizable hardware AND a complete verification environment from a single declarative specification.** This is its fundamental differentiator.

The closest competitors in specific dimensions:
- **FlowBlaze** — closest in stateful packet processing (EFSM vs HSM), but no verification generation
- **Agnisys IDS-Verify** — closest in "spec-to-verification" philosophy, but for registers not packets
- **P4 tools** — closest in "spec-to-RTL" philosophy, but require P4 expertise and generate no verification
- **FFShark** — closest in accessibility (BPF filter expressions), but fixed architecture with no customization

---

## Recommended Roadmap Priorities

Based on this analysis, the features that would most strengthen PacGate's competitive position:

1. **Wider data paths** — Moving from 8-bit to 64/128-bit would unlock 10G-25G line-rate, making PacGate viable for production SmartNIC deployments rather than prototyping only. This is the single biggest gap.

2. **P4 export** — No tool currently converts declarative YAML rules to P4. This would let PacGate users target both FPGA (via Verilog) and P4-programmable ASICs/SmartNICs from the same YAML spec.

3. **Multi-table pipeline** — Sequential match-action stages would enable more complex processing (e.g., "classify then act") without increasing single-stage complexity.

4. **Hardware timestamping** — Critical for 5G/telecom use cases where PacGate already has strong protocol support (GTP-U, eCPRI, PTP).

5. **P4 import** — Accept P4 as an alternative input format, expanding the user base to existing P4 developers who want PacGate's verification capabilities.
