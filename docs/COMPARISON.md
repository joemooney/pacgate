# PacGate Competitive Comparison

*Feature matrix comparing PacGate against tools in the FPGA packet processing landscape.*

### PacGate at a Glance

| Metric | Count |
|--------|------:|
| CLI commands | 38 |
| Match fields | 57 |
| Rewrite actions | 15 |
| Parser states | 23 |
| Lint rules | 57 |
| Mutation types | 41 |
| YAML examples | 52 (+2 P4, +2 Wireshark, +2 iptables) |
| Tera templates | 42 |
| Rust tests | 1127 |
| Python tests | 90 |
| Data path widths | 5 (8/64/128/256/512 bit) |
| FPGA families | Artix-7, Virtex-7, UltraScale+, Alveo |
| Platform targets | 3 (standalone, OpenNIC, Corundum) |

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

## Competitive Tool Profiles

### 1. FFShark / fpga-bpf (University of Toronto HPRC)

**What it does**: FFShark is a 100G FPGA implementation of Berkeley Packet Filter (BPF) filtering for Wireshark. It builds a soft CPU on FPGA that executes BPF bytecode as its native instruction set, enabling Wireshark-compatible packet capture and filtering at wire speed on 100G links.

**Architecture**:
- **FPGA target**: Xilinx Zynq UltraScale+ XCZU19EG-FFVC1760 (MPSoC)
- **Core design**: 6 parallel BPF soft-processor cores ("Sephirot" design), each executing standard BPF instructions
- **Chopper**: splits the high-speed 100G input stream into multiple lower-speed queues, one per BPF core
- **Forwarder**: collects accepted packets from all cores and forwards them to the output
- **ARM integration**: the on-board ARM CPU manages instruction memory loading and the Forwarder
- **Passthrough Sector**: enables inline insertion into a running 100G network without disruption

**Throughput**: 100 Gbps line-rate (99.41% of 32,768 test packets returned correctly at full 100G bitrate). Architecturally scalable to 400G by adding more BPF cores. Insertion latency approximately 0.3 us for packets >= 100 bytes.

**Protocol support**: Supports any protocol that can be expressed as a BPF filter (Ethernet, IPv4, IPv6, TCP, UDP, VXLAN, ARP, ICMP, etc.). Protocol-independent through BPF's byte-offset load model. Extensions include VXLAN firewall support.

**Limitations**:
- Fixed architecture (no RTL customization or generation)
- No verification output (no tests, assertions, or coverage models generated)
- Packet drops can occur if accepted-packet rate exceeds Forwarder bandwidth for extended periods
- Small packets (< 100 bytes) incur higher latency due to packet-rate limits
- No stateful processing, connection tracking, or rate limiting
- No packet rewrite capability
- Academic project from University of Toronto HPRC group; last significant commit circa 2019-2020
- Non-commercial license ("free for non-commercial use")
- No synthesis/place-and-route project generation
- Single FPGA target (Zynq UltraScale+ MPSoC)

**Sources**: [GitHub - fpga-bpf](https://github.com/UofT-HPRC/fpga-bpf), [FCCM 2020 Paper](https://www.fccm.org/past/2020/proceedings/2020/pdfs/FCCM2020-65FOvhMqzyMYm99lfeVKyl/580300a047/580300a047.pdf), [IEEE Xplore](https://ieeexplore.ieee.org/document/9114665/)

---

### 2. hXDP (Hardware XDP)

**What it does**: hXDP runs Linux eBPF/XDP programs on FPGA NICs. It includes an optimizing compiler that translates eBPF bytecode into a parallelized instruction set optimized for FPGA execution, a soft-processor ("Sephirot") to execute those instructions, and FPGA infrastructure providing XDP maps and helper functions as defined in the Linux kernel.

**Architecture**:
- **Compiler**: static analysis of eBPF programs at compile time to identify instruction-level parallelism; compresses, parallelizes, and eliminates redundant instructions
- **Soft-processor**: single eBPF core with up to 4 parallel execution lanes (performance plateaus after 4 lanes)
- **XDP infrastructure**: FPGA-based implementation of XDP maps (hash maps, array maps) and helper functions
- **Dynamic loading**: programs can be loaded at runtime without FPGA reconfiguration
- **FPGA target**: Xilinx Virtex-7 690T (via NetFPGA SUME board)

**Throughput**: 40 Gbps aggregate (4x 10G ports on NetFPGA SUME). Achieves ~52 Mpps for packet-dropping programs vs. 38 Mpps for an x86 CPU core at 3.7 GHz. 10x lower forwarding latency compared to CPU-based XDP. Clocked at 156.25 MHz.

**Resource usage**: ~10% logic resources, ~2% registers, ~3.4% BRAM of the Virtex-7 690T -- leaving ~85% of FPGA resources available for other accelerators.

**Limitations**:
- Only one helper function call per clock cycle
- Performance plateaus after 4 execution lanes despite available parallelism
- Limited to programs expressible in eBPF (no arbitrary hardware descriptions)
- Tied to NetFPGA SUME hardware (Virtex-7, now retired/legacy)
- No RTL generation or verification output
- No packet rewrite beyond what eBPF programs can express
- Academic project (OSDI 2020); no evidence of active development post-2022
- No synthesis project generation
- eBPF program complexity limited by FPGA clock frequency (5-10x lower than CPU)

**Sources**: [USENIX OSDI 2020](https://www.usenix.org/conference/osdi20/presentation/brunella), [hXDP Paper (PDF)](https://www.usenix.org/system/files/osdi20-brunella.pdf), [GitHub Artifacts](https://github.com/axbryd/hXDP-Artifacts), [Blog Summary](https://pchaigno.github.io/ebpf/2020/11/04/hxdp-efficient-software-packet-processing-on-fpga-nics.html)

---

### 3. NetFPGA SUME

**What it does**: NetFPGA SUME is an FPGA-based PCIe network interface card and development platform designed for research and teaching in high-performance networking. It provides 4x 10G Ethernet interfaces and a complete reference NIC design, enabling researchers to build custom switches, routers, firewalls, and protocol processors.

**Architecture**:
- **FPGA**: Xilinx Virtex-7 XC7VX690T-3FFG1761 (693,120 logic cells, 30 GTH transceivers at up to 13.1 Gbps)
- **Memory**: 27 MB QDRII+ SRAM (3x 72-bit @ 500 MHz) for forwarding tables + up to 8 GB DDR3 DRAM for packet buffering
- **Interfaces**: 4x SFP+ (10 Gbps each), PCIe Gen3 x8, 2x SATA-III (6 Gbps), VITA-57 FMC HPC, SAMTEC QTH-DP
- **Reference designs**: NIC, router, switch, learning switch (Verilog reference projects)
- **P4 support**: P4->NetFPGA project uses Xilinx P4-SDNet compiler to compile P4 programs to the "SimpleSumeSwitch" architecture (parser -> match-action pipeline -> deparser)

**P4->NetFPGA workflow**:
- P4 source compiled by Xilinx SDNet to generate RTL IP cores
- SimpleSumeSwitch architecture wraps generated IP within the NetFPGA SUME reference design
- Python and C control-plane APIs for table management (via Python Scapy integration)
- Vivado-based simulation with generated SDNet testbenches + optional cocotb

**Verification approach**:
- SDNet-generated Verilog testbenches for initial P4 module verification
- SUME simulation framework with `gen_testdata.py` (Python Scapy-based) + `run.py` test runner
- Vivado behavioral simulation with waveform debugging
- No automated formal verification, mutation testing, or coverage-directed generation

**Community/ecosystem**:
- Led by University of Cambridge and Stanford University
- Sponsored by Xilinx (now AMD), Micron, Cypress, with NSF/DARPA/EPSRC/EU Horizon 2020 funding
- Active academic community with SIGCOMM tutorials, summer schools, and published reference designs
- Extensive P4 tutorial assignments (switch, router, firewall, calculator, rate limiter)

**Current status (2025)**:
- **Hardware retired**: Digilent lists the board as "Legacy" -- no longer manufactured or sold. Remaining stock depleted.
- **Software**: Last major release (1.10.0) migrated to Vivado 2020.1 and Python 3. GitHub repositories remain accessible but show limited recent activity.
- **P4-SDNet dependency**: Requires Xilinx P4-SDNet toolchain (commercial, availability uncertain post-AMD acquisition)
- **No announced successor**: No official NetFPGA follow-up board has been announced. The AMD/Xilinx Alveo platform and Corundum framework serve as de facto successors for similar use cases.

**Limitations**:
- Hardware discontinued; no path to purchase new boards
- Requires Vivado (commercial) and P4-SDNet (commercial) toolchains
- Fixed 10G per-port throughput (40G aggregate)
- Virtex-7 FPGA generation is aging (28nm, 2012-era)
- No open-source synthesis flow
- P4-SDNet compiler is closed-source and requires license
- No automated test/verification generation from P4 programs

**Sources**: [NetFPGA SUME Official](https://netfpga.org/NetFPGA-SUME.html), [Digilent Legacy Page](https://digilent.com/reference/programmable-logic/netfpga-sume/start), [P4-NetFPGA Wiki](https://github.com/NetFPGA/P4-NetFPGA-public/wiki), [P4->NetFPGA Paper](https://www.cl.cam.ac.uk/~nz247/publications/ibanez2019p4netfpga.pdf), [SimpleSumeSwitch Architecture](https://build-a-router-instructors.github.io/documentation/simple-sume-switch/)

---

### 4. Intel P4 Suite / Tofino (now Altera)

**Tofino ASIC -- End of Life**:
- Intel acquired Barefoot Networks (creators of Tofino) in 2019
- Intel ceased Tofino ASIC development in 2023, canceling Tofino 3
- PCN 827577-00 (August 7, 2024): formal product discontinuance notice
  - Tofino 1 (Aurora 720/620): EOL effective January 12, 2024
  - Tofino 2 (Aurora 750/710/610): EOL effective July 7, 2025
  - Last order date: October 30, 2024
  - Last shipment date: February 28, 2025
- January 2025: Intel open-sourced the Tofino P4 SDE ([open-p4studio](https://github.com/p4lang/open-p4studio)), including the P4 compiler backend (`p4c` Tofino backend), behavioral model (`tofino_model`), drivers (`bf_driver`), and diagnostics
- Industry reaction: Bryan Cantrill (Oxide Computer) noted the Tofino team "deserved much better than their (former) executive leadership"; Oxide will transition away from Tofino in future hardware generations

**What replaced it -- Altera P4 Suite for FPGA**:
- Intel's Programmable Solutions Group (PSG) spun out as **Altera** (standalone company) in January 2025
- Altera inherited the P4 Suite for FPGA tool, now branded under [altera.com](https://www.altera.com/products/development-tools/p4-suite-fpga)
- Compiles P4 programs into synthesizable RTL for Altera FPGAs
- Generates a runtime API/software framework for control-plane integration
- Target throughput: 200 Gbps and above
- Target FPGAs: Agilex 7 (I-Series, F-Series, M-Series), Agilex 9 families
- Use cases: edge gateways, 5G UPF, aggregation platforms, network security

**Availability concerns**:
- The P4 Suite for FPGA has historically been **limited availability** -- "only for internal use and for customers that the internal team works jointly with" (per Intel Community forums)
- No public download or self-service access as of early 2025
- Requires Quartus Prime Pro (commercial license) for synthesis
- The broader P4 FPGA ecosystem is described as having "more or less gone nowhere" commercially (Hacker News discussion)

**P4 ecosystem status (2025)**:
- P4 language itself remains viable and maintained by the [P4 Language Consortium](https://p4.org/)
- Cisco Silicon One uses P4 internally but does not widely expose it externally
- AMD/Xilinx Vitis Networking P4 is the primary alternative for P4-to-FPGA compilation
- Open-source p4c compiler continues active development with multiple backends (BMv2, eBPF, DPDK, Tofino)

**Limitations**:
- Limited/restricted availability (not publicly downloadable)
- Tofino ASICs are end-of-life with no successor
- Altera FPGA-based P4 requires expensive Agilex hardware (~$5K+ dev kits)
- Quartus Prime Pro license required (commercial)
- No verification generation (tests, assertions, coverage)
- No open-source synthesis path
- Uncertain long-term roadmap as Altera establishes itself as independent company

**Sources**: [Intel Tofino EOL PCN](https://www.intel.com/content/www/us/en/content-details/827577/intel-tofino-products-pcn-827577-00-product-discontinuance-tofino-end-of-life.html), [Phoronix - Tofino Open Source](https://www.phoronix.com/news/Intel-Tofino-P4-Open-Source), [P4.org - Intel Open Source](https://p4.org/intels-tofino-p4-software-is-now-open-source/), [Altera P4 Suite](https://www.altera.com/products/development-tools/p4-suite-fpga), [HN Discussion](https://news.ycombinator.com/item?id=42721890), [open-p4studio GitHub](https://github.com/p4lang/open-p4studio)

---

### 5. AMD/Xilinx Vitis Networking P4 (formerly SDNet)

**What it does**: Compiles P4_16 programs into synthesizable FPGA RTL. Programs are compiled through the P4C frontend into a proprietary Xilinx Switch Architecture (XSA) — a 3-stage pipeline of Parser Engine, Match-Action Engine, and Deparser Engine. The generated IP block integrates into Vivado IP Integrator designs.

**P4 language support**:
- P4_16 (restricted subset compliant with XSA architecture — not full P4_16)
- **Not** standard V1Model or PSA — uses proprietary XSA architecture; P4 code is not portable to BMv2, Tofino, or DPDK without modification
- Table match types: exact (BCAM, up to 64K entries), LPM (STCAM), ternary (soft TCAM, expensive: 60-80K LUTs for 4K x 128-bit entries), direct RAM, HBM-backed BCAM for large tables
- Built-in externs: InternetChecksum, Register, Counter, Stateful Atoms (R/W, RAW, PRAW, ifElseRAW, Sub), Timestamp, LRC
- User externs: custom Verilog, SystemVerilog, or HLS C++ logic integrated via vitisnetp4_igr/egr_extern interfaces

**FPGA targets**: Kintex/Virtex UltraScale(+), Zynq UltraScale+ (MPSoC, RFSoC), Versal (AI Core, AI Edge, HBM, Premium, Prime). Verified on Alveo U25, U50, U55C, U200, U250, U280, and SN1000/SN1022 SmartNICs.

**Throughput**:

| Configuration | Bus Width | Clock | Throughput |
|---|---|---|---|
| Standard 100G | 320-bit | ~312 MHz | 100 Gbps |
| Recommended | 512-bit | ~450 MHz | ~230 Gbps |
| High-performance | 1024-bit | ~400 MHz | ~400 Gbps |
| Ultra-wide | 2048-bit | 384 MHz | ~786 Gbps peak |

Line rate scaling is GUI-driven — change bus width and clock frequency without modifying P4 code. Real-world 100G demonstrated at line rate for 512-byte packets. Parser latency: 19 cycles for Eth/IPv4/IPv6/TCP/UDP at 100G; 25.6 cycles including MPLS/VLAN.

**Verification**: Proprietary behavioral model (p4bm-vitisnet, similar to BMv2) for fast software simulation. Standard Vivado RTL simulation flow (ModelSim, Questa, Xcelium). No built-in formal verification, cocotb support, or automated test generation. Wireshark `.lua` dissector files generated as build artifacts.

**Tooling**: Deep Vivado integration with GUI-based configuration of bus widths, clock domains, and engine types. Auto-generated control-plane SDK (host drivers, AXI-Lite register maps). Works with OpenNIC Shell and Corundum via ESnet SmartNIC reference design. Current version: 2025.2.

**Licensing**: Commercial IP license, separate from (and in addition to) Vivado Design Suite license. Pricing not publicly disclosed — requires direct AMD sales engagement. Industry estimates: tens of thousands of dollars annually.

**Key limitations**:
- AMD/Xilinx FPGAs only (vendor lock-in)
- P4 subset only, not portable to other P4 targets
- Soft-TCAM scaling is very expensive in FPGA resources
- P4 is stateless by default; stateful processing requires HLS/RTL externs
- No automated test generation, formal verification, or coverage models
- Expensive license stack (Vivado + VNP4 + hardware)
- Requires P4, Vivado, AXI, and potentially HLS C++ expertise

**Resource example**: Eth/IPv4/IPv6/TCP/UDP parser at 100G: 4,270 LUTs, 6,163 FFs, 19-cycle latency.

**Sources**: [UG1308 - VNP4 User Guide](https://docs.amd.com/r/en-US/ug1308-vitis-p4-user-guide), [AMD Product Page](https://www.amd.com/en/products/adaptive-socs-and-fpgas/intellectual-property/ef-di-vitisnetp4.html), [WP555 Whitepaper](https://www.xilinx.com/content/dam/xilinx/publications/white-papers/wp555-vitis-networking-p4.pdf), [ESnet SmartNIC](https://github.com/esnet/esnet-smartnic-hw)

---

### 6. Corundum (Open-Source FPGA NIC)

**What it does**: A complete, open-source FPGA-based NIC and in-network compute platform developed at UC San Diego by Alex Forencich et al. Provides a full NIC datapath (DMA, queues, scheduling, timestamping) with a pluggable application block for custom packet processing. Published at FCCM 2020.

**Architecture**:
- `fpga_core` (board-specific top) → `mqnic_core` (NIC core)
  - `mqnic_ptp` / `mqnic_ptp_clock` / `mqnic_ptp_perout` — PTP subsystem
  - `mqnic_app_block` — **pluggable custom application logic** (PacGate's `--target corundum` replaces this)
  - `mqnic_interface` (one per OS network interface)
    - TX: `tx_engine`, `tx_checksum`, `tx_scheduler_rr`, TDMA scheduler
    - RX: `rx_engine`, `rx_checksum`, `rx_hash` (Toeplitz RSS)
    - `queue_manager`, `cpl_queue_manager`, `desc_fetch`, `cpl_write`
- Custom segmented memory interface for DMA (double PCIe AXI stream width)
- AXI-Lite control path, AXI-Stream packet data
- 40+ Verilog RTL modules in common library

**Supported boards** (25 officially supported):
- **Xilinx**: Alveo U50/U200/U250/U280, VCU108/VCU118/VCU1525, ZCU102/ZCU106, KR260
- **Intel**: Stratix 10 MX/DX (Gen3/Gen4 x16), Agilex F (Gen4 x16)
- **Third-party**: Alpha Data ADM-PCIE-9V3, BittWare XUP-P3R/250-SoC, Cisco Nexus K35-S/K3P-S/K3P-Q, Dini Group DNPCIe_40G_KU, Silicom fb2CG@KU15P, Terasic DE10-Agilex, Digilent NetFPGA SUME

**Throughput**: 10G/25G (open-source MAC/PHY from `verilog-ethernet`), 100G (using Xilinx CMAC hard IP, free license). Demonstrated ~94 Gbps in published results. ~58 Mpps max for 64-byte frames (PCIe descriptor overhead limited). Multiple ports per board (up to 4x QSFP28).

**DMA/PCIe**: Custom high-performance DMA engine (not Xilinx DMA IP). PCIe Gen3 x8/x16 on most boards; Gen4 x16 on Intel Stratix 10 DX, Agilex F. Scatter/gather DMA, MSI interrupts, dedicated application BAR.

**Key features**: IEEE 1588 PTP hardware timestamping (nanosecond precision), TDMA scheduling, Toeplitz RSS hashing, TX/RX checksum offload, 1000+ individually-controllable queues (BRAM/URAM), multiple OS-level interfaces per NIC.

**Verification**: Full-system cocotb simulation with PCIe/Ethernet/AXI simulation models (`cocotbext-pcie`, `cocotbext-eth`, `cocotbext-axi` — all by Forencich). Icarus Verilog as primary simulator. No formal verification, SVA assertions, or mutation testing.

**Extensibility** (`mqnic_app_block`): Three streaming interfaces — Direct (MAC-synchronous, lowest latency), Sync (datapath-synchronous), Interface (highest-level with queue integration). Plus AXI-Lite registers and DMA access. User logic replaces the default app block via build system.

**What Corundum does NOT include**: No packet parser/classifier, no TCAM/LPM/exact-match tables, no packet filtering or firewall rules, no packet rewrite/NAT, no connection tracking, no rate limiting. These must be implemented in the application block.

**License**: BSD-2-Clause-Views (very permissive). 10G/25G MAC/PHY is also open-source. 100G CMAC requires free Xilinx license.

**Community**: ~2.2K GitHub stars, ~514 forks. BittWare offers commercial support. Used as base platform in numerous academic papers. CERN White Rabbit PTP integration (2024).

**Sources**: [GitHub](https://github.com/corundum/corundum), [Documentation](https://docs.corundum.io/), [FCCM 2020 Paper](https://cseweb.ucsd.edu/~snoeren/papers/corundum-fccm20.pdf), [FOSDEM 2022](https://archive.fosdem.org/2022/schedule/event/corundum/)

---

### 7. FlowBlaze (Stateful FPGA Packet Processor)

**What it does**: FlowBlaze implements an Extended Finite State Machine (EFSM) abstraction for stateful packet processing on FPGA. It provides a pipeline of stateless and stateful match-action elements, enabling per-flow state tracking directly in the FPGA data plane. Published at NSDI 2019.

**Architecture**: Each stateful element contains:
- **Flow Context Table**: per-flow state in BRAM (128-bit key + 146-bit value: 16-bit state label + 4x 32-bit registers + flags). Scales to hundreds of thousands of flows on Virtex-7.
- **EFSM Table**: 32-entry x 160-bit TCAM mapping (current_state, conditions) → (next_state, actions). The 32-entry limit reflects TCAM cost on FPGAs.
- **Update Function**: crossbar-based operand selection from registers, header fields, and constants for state transitions.

Pipeline provides 1, 2, or 5 configurable stages. A round-robin PHV scheduler ensures flow state consistency. Stateless elements are equivalent to standard match-action tables (like P4/RMT).

**Demonstrated use cases**: Port knocking (multi-step firewall), stateful firewall (connection tracking), heavy hitter detection (flow volume monitoring), MAC learning (dynamic L2 forwarding).

**FPGA target**: NetFPGA SUME only (Xilinx Virtex-7 XC7VX690T). No ports to Alveo, UltraScale+, or any other platform.

**Throughput**: 40 Gbps aggregate (4x 10G ports at line rate). 156.25 MHz clock. Performance independent of active flow count.

**Programming**: Three interfaces — XL Toolchain (Java CLI compiler for `.xl` files), FlowBlaze.p4 GUI (Python visual EFSM editor → P4 table entries), ONOS SDN controller integration.

**Verification**: Minimal — live traffic testing only. No automated tests, formal verification, assertions, or coverage models. Described as research prototype.

**Status (2025)**: **Effectively abandoned** — last commit February 2019 (27 total commits). Requires Vivado 2016.4 (9 years old). No license file in repository. NetFPGA SUME hardware is discontinued.

**Key limitations**: Discontinued hardware, stale codebase (7 years), 32-entry EFSM table limit, limited actions, no verification infrastructure, single FPGA target, 10G per port, research prototype only.

**Sources**: [GitHub](https://github.com/axbryd/FlowBlaze), [NSDI 2019 Paper](https://www.usenix.org/conference/nsdi19/presentation/pontarelli), [FlowBlaze.p4](https://github.com/ANTLab-polimi/flowblaze.p4)

---

### 8. OpenNIC Shell (AMD/Xilinx)

**What it does**: An FPGA-based NIC platform providing a complete shell design with PCIe host interface (QDMA) and dual 100G Ethernet (CMAC), consuming only ~5% of FPGA resources (LUTs/BRAMs on U250) and leaving ~95% for user logic.

**Architecture**: Three clock domains:
- **322 MHz** (`cmac_clk`): CMAC Ethernet subsystem — dual 100G MACs with RS-FEC, jumbo frames up to 9600 bytes, 150 Mpps worst-case
- **250 MHz** (`axis_clk`): QDMA PCIe subsystem — up to 4 physical functions, 2048 total queues
- **125 MHz** (`axil_clk`): AXI-Lite control registers via BAR2

Packet Adapter bridges 250↔322 MHz clock domains with FIFO buffering and back-pressure.

**Supported boards**: Alveo U45N, U50, U55N, U55C, U200, U250, U280.

**Throughput**: 2x 100 Gbps Ethernet (200 Gbps aggregate). QDMA cannot sustain full 150 Mpps at minimum packet size. Kernel driver limited to ~10-20 Gbps; DPDK driver achieves near 100 Gbps.

**User plugin model**: Two user logic boxes — `box_322mhz` (network-side, line-rate) and `box_250mhz` (host-side). Each provides AXI-Stream TX/RX pairs, AXI-Lite registers, and TUSER metadata (packet size, source/destination port ID). Users supply plugins via `-user_plugin` build argument.

**DMA/PCIe**: Xilinx QDMA IP with multi-queue architecture. Up to 4 physical functions. 4 KB max DMA packet size. No SR-IOV or virtual functions in v1.0.

**Verification**: cocotb + ModelSim behavioral simulation. No formal verification, SVA assertions, or automated test generation.

**ESnet SmartNIC fork**: Actively maintained fork adding P4-programmable processing via Vitis Networking P4, DPDK-pktgen integration, probe counters, Docker-based toolchain. Supports Vivado 2023.2.2.

**License**: Apache 2.0 (shell), GPL 2.0 (kernel driver). Requires Vivado (commercial).

**Key limitations**: Vivado-only (no Yosys), 4 KB DMA packet size limit, no partial reconfiguration, no virtual functions, no on-board memory access, last shell commit February 2023, Vivado version compatibility issues reported with 2024.2.

**Sources**: [GitHub - open-nic-shell](https://github.com/Xilinx/open-nic-shell), [OpenNIC Project](https://github.com/Xilinx/open-nic), [ESnet SmartNIC](https://github.com/esnet/esnet-smartnic-hw), [FAQ](https://github.com/Xilinx/open-nic/blob/main/FAQ.md)

---

### 9. EDA Verification Tools

PacGate generates verification artifacts (tests, assertions, coverage) automatically. Commercial EDA tools provide far more powerful verification engines but require manual effort to create verification environments.

**Siemens Questa One** (formerly Mentor ModelSim/Questa):
- ParallelSim: smart auto-partitioning for multi-core simulation (8x DFT speedup)
- Questa Formal: SVA/PSL assertion-based formal verification with IP-level signoff
- AI/ML suite: **Property Assist** (LLM converts English → SVA), Smart Creation (auto-generates testbenches/assertions), Regression Navigator (AI test prioritization), Smart Debug (ML root cause analysis), Agentic AI Toolkit (Feb 2026, NVIDIA Llama-based)
- Unified coverage merging simulation + formal + emulation metrics
- Cost: ~$50K-$150K+/seat/year

**Synopsys VCS**:
- Fine-Grained Parallelism (FGP): native multi-core simulation; add cores at runtime
- VC Formal: exhaustive formal with ML-driven solver selection (10x speedup)
- **VSO.ai**: industry's first AI-driven verification — NVIDIA case study showed 33% more coverage in same test runs, 5x regression reduction
- Intelligent Coverage Optimization (ICO): reinforcement learning for coverage closure
- Xpropagation for security verification
- Cost: ~$50K-$200K+/seat/year

**Cadence Xcelium + JasperGold**:
- First production-proven parallel simulator (3x RTL, 5x gate-level, 10x DFT speedup)
- Distributed multi-machine simulation (Xcelium 25.09)
- Xcelium ML: iterative learning over regressions for 5x faster verification closure
- JasperGold: ML-driven Smart Proof Technology, 2x compilation capacity
- SimAI: "cousin bug hunting" using failure patterns to find similar bugs
- Cost: ~$50K-$150K+/seat/year

**Agnisys IDS** (spec-driven register verification):
- IDS-Verify: takes register specs (natural language, spreadsheet, IP-XACT, SystemRDL) and generates complete UVM testbenches, SVA assertions, Makefiles — claims 100% register coverage "out of the box"
- IDS-Validate: extends to functional tests for custom design blocks
- **iSpec.ai**: LLM converts natural language → SVA using fine-tuned models
- Closest philosophical match to PacGate's "single-spec, dual-output" approach — but for register verification, not packet processing

**Key comparison with PacGate**: EDA tools are horizontal platforms for any ASIC/SoC, costing $50K-$200K+/year per seat. PacGate is a vertical tool specialized for packet filtering — it generates both the design AND verification from YAML, at zero per-seat cost for open-source simulators (Icarus + Yosys). The trade-off: EDA tools offer vastly more powerful simulation/formal engines but require manual testbench creation; PacGate auto-generates everything but relies on simpler simulation infrastructure.

**Sources**: [Siemens Questa One](https://news.siemens.com/en-us/siemens-questa-one/), [Synopsys VCS](https://www.synopsys.com/verification/simulation/vcs.html), [Synopsys VSO.ai](https://www.synopsys.com/ai/ai-powered-eda/vso-ai.html), [Cadence Xcelium](https://www.cadence.com/en_US/home/tools/system-design-and-verification/simulation-and-testbench-verification/xcelium-simulator.html), [JasperGold](https://www.cadence.com/en_US/home/tools/system-design-and-verification/formal-and-static-verification/jasper-verification-platform.html), [Agnisys IDS](https://www.agnisys.com/products/ids-verify/), [Agnisys iSpec.ai](https://www.agnisys.com/blog/unlocking-the-power-of-system-verilog-assertions-with-ispec-ai/)

---

## Core Feature Comparison

### Input & Output

| Feature | PacGate | Vitis Net P4 | Intel P4 | Corundum | FlowBlaze | FFShark | Vivado HLS |
|---------|:-------:|:------------:|:--------:|:--------:|:---------:|:-------:|:----------:|
| **Input format** | YAML + P4 + Wireshark + iptables | P4 | P4 | Verilog | EFSM/GUI | BPF | C/C++ |
| **Generates RTL** | Yes | Yes | Yes | N/A (is RTL) | N/A (fixed arch) | N/A (fixed arch) | Yes |
| **Generates P4 export** | **Yes** (P4_16 PSA) | N/A | N/A | No | No | No | No |
| **Generates tests** | Yes | No | No | No | No | No | No |
| **Generates SVA assertions** | Yes | No | No | No | No | No | No |
| **Generates property tests** | Yes | No | No | No | No | No | No |
| **Generates coverage model** | Yes | No | No | No | No | No | No |
| **Single-spec quad-output** | **Yes** (RTL+tests+P4) | No | No | No | No | No | No |
| **Multi-table pipeline** | **Yes** (`tables:` YAML) | Native (P4) | Native (P4) | No | Yes (EFSM) | No | User |
| **Parameterized data width** | **Yes** (8-512 bit) | Fixed per target | Fixed per target | Fixed | Fixed | Fixed | User |
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
| **Mutation testing (YAML, 41 types)** | Yes | No | No | No | No | No |
| **Mutation testing (Verilog/MCY)** | Yes | No | No | No | No | No |
| **Boundary test derivation** | Yes | No | No | No | No | No |
| **Pipeline scoreboard (multi-stage)** | Yes | No | No | No | No | No |
| **cocotb simulation** | Yes | No | Yes | N/A | N/A | No |
| **Software dry-run simulation** | Yes (+ pipeline) | p4c BMv2 | No | N/A | N/A | No |
| **PCAP traffic analysis** | Yes | No | No | No | No | No |
| **P4 symbolic verification** | No | p4v/p4pktgen | No | No | No | No |
| **AI-assisted verification** | No | No | No | Yes | Yes | No |

### Hardware Features

| Feature | PacGate | Vitis Net P4 | Corundum | FlowBlaze | OpenNIC | NetFPGA |
|---------|:-------:|:------------:|:--------:|:---------:|:-------:|:-------:|
| **Packet rewrite (in-flight)** | Yes (15 actions) | Yes | Checksum | Yes | User | Yes |
| **In-band telemetry (INT)** | **Yes** (sideband metadata) | User | No | No | User | No |
| **RFC 1624 incremental cksum** | Yes | N/A | Yes | No | User | User |
| **Multi-table pipeline** | **Yes** (N stages, AND) | P4 stages | No | **Yes (EFSM)** | User | User |
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
| **Parameterized width (8-512b)** | **Yes** | Fixed | Fixed | Fixed | Fixed | Fixed |
| **Platform target wrappers** | OpenNIC, Corundum | Alveo | Native | NetFPGA | Native | Native |
| **Store-forward FIFO** | Yes | Yes | Yes | No | Yes | Yes |
| **Hardware timestamping (PTP)** | **Yes** (IEEE 1588) | User | **Yes** | No | No | User |
| **DMA / PCIe host interface** | No | User | **Yes** | No | **Yes** | **Yes** |
| **RSS / multi-queue** | **Yes** (Toeplitz) | User | **Yes** | No | **Yes** | No |

### Performance & Targets

| Metric | PacGate | Vitis Net P4 | Corundum | FlowBlaze | OpenNIC | hXDP |
|--------|:-------:|:------------:|:--------:|:---------:|:-------:|:----:|
| **Target throughput** | ~2 Gbps (V1, 8-bit parser); 100G+ planned (wide parser) | 100G-1T | 100G | 40G | 200G | 10G |
| **Target FPGA families** | Artix-7, Virtex-7, UltraScale+, Alveo | UltraScale+, Versal | UltraScale+, Stratix 10, Agilex | Virtex-7 | Alveo UltraScale+ | Virtex-7 |
| **Min FPGA size** | XC7A35T (8b) / Alveo (512b) | Alveo U250 | Alveo U50 | NetFPGA | Alveo U250 | NetFPGA |
| **Open-source sim** | Yes (Icarus) | No | Yes (cocotb) | No | Vivado | No |
| **Synthesis (open-source)** | Yes (Yosys) | No | No | No | No | No |
| **Data path width** | 8-512 bit | 64-512 bit | 64-512 bit | 256 bit | 512 bit | Custom |
| **Clock frequency** | 125 MHz | 250-350 MHz | 250 MHz | 200 MHz | 250 MHz | 156 MHz |

### Tooling & Ecosystem

| Feature | PacGate | P4 Tools | Corundum | FlowBlaze | HLS |
|---------|:-------:|:--------:|:--------:|:---------:|:---:|
| **CLI tool** | Yes (36 cmds) | p4c compiler | Make | GUI + CLI | Vivado |
| **P4 export (YAML → P4_16)** | **Yes** | N/A | No | No | No |
| **Lint / best-practice rules** | Yes (57 rules) | p4c warnings | No | No | HLS warnings |
| **Mutation testing** | Yes (41 types) | No | No | No | No |
| **FPGA resource estimation** | Yes | Vivado reports | Vivado | No | HLS reports |
| **Rule diff / change mgmt** | Yes (+ HTML) | No | No | No | No |
| **HTML documentation gen** | Yes | No | No | No | No |
| **Mermaid FSM import/export** | Yes | No | No | No | No |
| **Rule templates library** | Yes (7 templates) | No | No | No | No |
| **PCAP import + analysis** | Yes | No | No | No | No |
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

## Gap Analysis

### Recently Completed (Phases 27-30)

| Feature | Phase | What Was Delivered |
|---------|-------|-------------------|
| **Wider data paths** | 27 | `--width {8,64,128,256,512,1024,2048}` AXI-Stream bus-width compatibility converters (V1 ~2 Gbps; native wide parser planned for 100G+) |
| **P4 export** | 27 | `p4-export` subcommand generates P4_16 PSA programs with Register/Meter externs — first YAML→P4 tool |
| **Multi-table pipeline** | 27 | Optional `tables:` YAML key with N sequential match-action stages, AND-combined decisions, shared parser |
| **PTP (IEEE 1588)** | 28 | 3 PTP match fields + dual L2/L4 detection + optional ptp_clock.v hardware clock |
| **RSS multi-queue** | 29 | Toeplitz hash + 128-entry indirection table + per-rule queue override + AXI-Lite |
| **INT telemetry** | 30 | Sideband metadata capture (switch_id, timestamps, hop_latency, queue_id, rule_idx) |
| **Synthetic traffic gen** | 30 | `pcap-gen` subcommand — protocol-aware PCAP generation from YAML rules |

### High Priority (remaining competitive gaps)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| ~~**P4 import**~~ | ~~Accept P4 programs as input; tap into P4 ecosystem~~ | ~~All P4 tools~~ | **IMPLEMENTED** (Phase 31) — `p4-import` subcommand with bidirectional P4↔YAML bridge |
| **DMA / host interface** | Software packet injection/extraction; CPU offload | Corundum, NetFPGA, OpenNIC | Large — PCIe DMA is complex; or leverage existing Corundum/OpenNIC |
| ~~**Hardware timestamping (PTP)**~~ | ~~Precise packet timing for telemetry / 5G~~ | ~~Corundum~~ | **IMPLEMENTED** (Phase 28) — IEEE 1588 PTP matching + optional ptp_clock.v |

### Medium Priority (useful differentiators)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| **eBPF/XDP filter expressions** | Accept Linux XDP programs or BPF filters | hXDP, FFShark | Large — soft BPF CPU or BPF-to-match compiler |
| ~~**Wireshark display filter input**~~ | ~~`tcp.port == 80` syntax for rules~~ | ~~FFShark~~ | **IMPLEMENTED** (Phase 32) — `wireshark-import` subcommand with ~45 field mappings |
| **GUI for FSM design** | Visual state machine editor | FlowBlaze | Medium — web UI generating YAML; Mermaid Live already works |
| **L7 / DPI (regex match)** | Application-layer protocol detection | FFShark (via BPF), P4 (limited) | Large — regex engine in hardware (BRAM-based NFA) |
| ~~**In-band telemetry (INT)**~~ | ~~Insert metadata headers for network visibility~~ | ~~VitisNetP4, Tofino~~ | ~~**DONE (Phase 30)**~~ |
| ~~**RSS / multi-queue dispatch**~~ | ~~Distribute flows across CPU queues~~ | ~~Corundum, OpenNIC~~ | ~~**DONE (Phase 29)**~~ |
| **AI-assisted SVA generation** | Auto-generate complex assertions from design | Questa (Property Assist) | Medium — LLM-based assertion suggestion |

### Low Priority (nice-to-have / future)

| Feature | Benefit | Competitors That Have It | Effort |
|---------|---------|--------------------------|--------|
| **Protocol-independent parsing** | User-defined header formats | All P4 tools | Large — fundamentally different architecture |
| **Multi-Tbps ASIC targeting** | Datacenter-scale throughput | Tofino (EOL) | N/A — different market segment |
| **Emulation support** | Run on Palladium/Veloce/Protium | Questa, VCS, Xcelium | N/A — requires commercial emulator |
| **RISC-V control plane** | Software-driven rule updates via embedded CPU | Academic projects | Large — RISC-V SoC integration |
| ~~**Traffic generation**~~ | ~~Built-in packet generation for testing~~ | ~~T-Rex, Scapy, MoonGen~~ | ~~**DONE (Phase 30)** — `pcap-gen` subcommand~~ |

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
          Yes ─┼─── No        │         (verify only)
               │    │         │
          Also exports P4?    │
               │    │         │
          Yes ─┤    │         │
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

**PacGate is the only tool that generates synthesizable hardware, a complete verification environment, AND a P4_16 PSA program — all from a single declarative YAML specification.** With quad input format (YAML + P4 + Wireshark + iptables), it is the most accessible FPGA packet filter tool available.

### What Makes PacGate Unique

| Capability | Only PacGate? | Why It Matters |
|------------|:---:|---|
| **YAML → RTL + tests + P4** | Yes | Single spec, three outputs — no other tool does this |
| **57 lint rules for packet rules** | Yes | Static analysis purpose-built for packet filter correctness |
| **41 mutation types** | Yes | Quantified test quality for network security rules |
| **Multi-table pipeline from YAML** | Yes | P4-style sequential stages without writing P4 |
| **8-512 bit parameterized width** | Yes | Same YAML targets Arty ($50) through Alveo ($5K) |
| **Coverage-directed test gen** | Yes | Automated verification closure for packet processing |
| **Hypothesis property tests** | Yes | Randomized protocol-aware testing (17 strategies) |

The closest competitors in specific dimensions:
- **FlowBlaze** — closest in stateful packet processing (EFSM vs HSM), but no verification generation and no P4 export
- **Agnisys IDS-Verify** — closest in "spec-to-verification" philosophy, but for registers not packets
- **P4 tools** — closest in "spec-to-RTL" philosophy, but require P4 expertise, generate no verification, and cannot import YAML
- **FFShark** — closest in accessibility (BPF filter expressions), but fixed architecture with no customization or pipeline support

---

## Recommended Roadmap Priorities

Based on this analysis, the next features that would most strengthen PacGate's competitive position:

1. ~~**Hardware timestamping (PTP)**~~ — **DONE** (Phase 28). IEEE 1588 PTP matching (ptp_message_type, ptp_domain, ptp_version) with dual L2/L4 detection and optional hardware clock module.

2. ~~**P4 import**~~ — **DONE** (Phase 31). `p4-import` subcommand parses P4_16 PSA programs into YAML rules with rewrite action mapping, extern detection, and round-trip validation. Completes the bidirectional P4↔YAML bridge.

3. **DMA / host interface** — PCIe DMA for software packet injection/extraction. Could leverage existing Corundum/OpenNIC platform targets rather than building from scratch.

4. ~~**RSS / multi-queue dispatch**~~ — **DONE (Phase 29)**: Toeplitz hash + 128-entry indirection table + per-rule queue override.

5. ~~**In-band telemetry (INT)**~~ — **DONE (Phase 30)**: Sideband metadata capture (switch_id, timestamps, hop_latency, queue_id, rule_idx) with per-rule int_insert control.

6. ~~**Traffic generation**~~ — **DONE (Phase 30)**: `pcap-gen` subcommand generates protocol-aware synthetic PCAP from YAML rules.

---

## Completed Roadmap Items

| Priority | Feature | Phase | Delivered |
|----------|---------|-------|-----------|
| 1 | Wider data paths (64-2048 bit) | 27.1/27.4 | `--width {8..2048}` — bus-width compatibility (V1 ~2 Gbps; wide parser planned for 100G+) |
| 2 | P4 export (YAML → P4_16 PSA) | 27.2/27.5 | `p4-export` subcommand — first YAML→P4 tool |
| 3 | Multi-table pipeline | 27.3/27.6-27.8 | `tables:` YAML key — N sequential match-action stages |
| 4 | PTP hardware timestamping | 28 | IEEE 1588 PTP matching + dual L2/L4 detection + ptp_clock.v |
| 5 | RSS multi-queue dispatch | 29 | Toeplitz hash + 128-entry indirection table + per-rule queue override |
| 6 | In-band telemetry (INT) | 30 | Sideband metadata capture (switch_id, timestamps, hop_latency, rule_idx) |
| 7 | Synthetic traffic generation | 30 | `pcap-gen` subcommand — protocol-aware PCAP from YAML rules |
| 8 | Wireshark display filter import | 32 | `wireshark-import` subcommand — ~45 field mappings |
| 9 | P4 import (bidirectional bridge) | 31 | `p4-import` subcommand — 55+ field reverse mappings, round-trip validated |
| 10 | iptables-save import | 33 | `iptables-import` subcommand — protocol/port/CIDR/TCP-flags/ICMP/conntrack/DNAT/SNAT mapping, quad input |
