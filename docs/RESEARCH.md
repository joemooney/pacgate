# PacGate Verification Framework -- Research Report

**Date**: 2026-02-26
**Purpose**: Research findings for building an innovative FPGA packet filter verification framework using cocotb
**Audience**: Engineering team and management

---

## Table of Contents

1. [cocotb Advanced Features (2025-2026)](#1-cocotb-advanced-features-2025-2026)
2. [Coverage-Driven Verification for FPGA](#2-coverage-driven-verification-for-fpga)
3. [Property-Based Testing for HDL](#3-property-based-testing-for-hdl)
4. [Mutation Testing for Hardware](#4-mutation-testing-for-hardware)
5. [UVM-Like Methodology in Python/cocotb](#5-uvm-like-methodology-in-pythoncocotb)
6. [Test Harness Generation from Specifications](#6-test-harness-generation-from-specifications)
7. [Formal Verification Integration](#7-formal-verification-integration)
8. [Regression and CI for FPGA Projects](#8-regression-and-ci-for-fpga-projects)
9. [Recommendations for PacGate](#9-recommendations-for-pacgate)

---

## 1. cocotb Advanced Features (2025-2026)

### cocotb 2.0 -- The Major Release

cocotb 2.0.0 was officially released at ORConf in September 2025, followed by the 2.0.1 patch release. This is the first major version bump, focused on developer experience and cleaning up long-standing API inconsistencies. A 2.1.0 release is currently in development.

**Key changes in cocotb 2.0:**

- **New Type System (Logic / LogicArray)**: The problematic `BinaryValue` class has been replaced entirely. Scalar logic signals now return `Logic` objects and array-of-logic signals return `LogicArray`. LogicArray does not carry an inherent integer representation -- conversion to/from int is explicit. This is a breaking change but produces cleaner, less error-prone testbenches.

- **HDL-Native Indexing**: Array indexing now follows the HDL-defined scheme (e.g., `[7:0]`) rather than forcing Python's 0-to-N left-to-right convention. This eliminates a common source of confusion when porting from SystemVerilog testbenches.

- **Copra -- Type Stubs for DUTs**: A new subproject that automatically generates Python typing stubs from the DUT hierarchy. This enables IDE auto-completion and static type checking on `dut.signal_name` accesses. Previously, these were purely dynamic lookups, and typos would only be caught at simulation runtime. This is a significant productivity improvement.

- **Questa QIS Integration**: A new compilation flow (`qisqrun`) leverages Questa's Information System for faster simulation performance and Visualizer as GUI.

- **Improved Task Management**: `cocotb.start_soon()`, `cocotb.create_task()`, and the scheduler now accept any `collections.abc.Coroutine`, enabling better interoperability with Python's standard async ecosystem.

- **cocotb 2.1 Roadmap**: Development continues with releases planned approximately every 6 months.

### cocotb Extension Ecosystem (cocotbext-*)

The ecosystem of bus functional models and protocol VIPs has matured significantly:

| Extension | Protocols | Source |
|-----------|-----------|--------|
| **cocotbext-axi** | AXI4, AXI4-Lite, AXI4-Stream (AxiStreamSource, AxiStreamSink, AxiStreamMonitor, AxiStreamFrame) | [alexforencich/cocotbext-axi](https://github.com/alexforencich/cocotbext-axi) |
| **cocotbext-eth** | MII, GMII, RGMII, XGMII, PTP timestamping, Ethernet MAC model | [alexforencich/cocotbext-eth](https://github.com/alexforencich/cocotbext-eth) |
| **cocotbext-pcie** | PCIe root complex, switches, devices, config space, BARs, MSI; Xilinx UltraScale and Intel Stratix 10 hard core models | [alexforencich/cocotbext-pcie](https://github.com/alexforencich/cocotbext-pcie) |
| **cocotbext-apb** | APB master, slave, monitor | PyPI |
| **cocotbext-ahb** | AHB master, slave, monitor | PyPI |
| **cocotbext-wishbone** | Wishbone bus | PyPI |
| **cocotbext-uart** | UART interface | PyPI |
| **cocotbext-spi** | SPI bus | PyPI |
| **cocotbext-i2c** | I2C interface | PyPI |

**Relevance to PacGate**: PacGate already generates AXI-Stream wrapper tests (Phase 4, `--axi` flag). Integration with `cocotbext-axi` for production-quality AXI4-Stream source/sink/monitor models would enhance our AXI tests. For Ethernet-specific verification, `cocotbext-eth` provides PHY-level models for more realistic stimulus generation beyond our current byte-level packet injection.

### Sources

- [cocotb 2.0 Release Announcement](https://www.cocotb.org/2025/11/19/cocotb-2.0.html)
- [cocotb 2.0 Release Notes](https://docs.cocotb.org/en/v2.0.0/release_notes.html)
- [Upgrading to cocotb 2.0](https://docs.cocotb.org/en/stable/upgrade-2.0.html)
- [Introducing Copra -- Type Stubs](https://www.cocotb.org/2025/09/09/introducing-copra.html)
- [cocotb Roadmap](https://docs.cocotb.org/en/development/roadmap.html)
- [cocotbext-axi](https://github.com/alexforencich/cocotbext-axi)
- [cocotbext-eth](https://github.com/alexforencich/cocotbext-eth)
- [cocotbext-pcie](https://github.com/alexforencich/cocotbext-pcie)

---

## 2. Coverage-Driven Verification for FPGA

### The Coverage-Driven Verification (CDV) Methodology

Professional verification teams use a plan-driven approach:

1. **Verification Plan**: Stakeholders identify features to verify, prioritize them, and define coverage goals. This is a list of *features* to test, not a list of directed tests.
2. **Functional Coverage Model**: Cover points and cross coverage are defined for DUT inputs, outputs, and internal states. Cover bins organize signal value ranges into meaningful categories.
3. **Constrained Random Stimulus**: Instead of writing exhaustive directed tests, random stimulus is generated within defined constraints, exploring the design space far more thoroughly.
4. **Coverage Closure**: Tests run in regression until all coverage goals are met. Uncovered bins indicate missing test scenarios or unreachable states.

### Tools for Coverage in cocotb

#### cocotb-coverage (v2.0.0 -- updated for cocotb 2.0)

This is the primary coverage and constrained-random library for cocotb. It implements CRV (Constrained Random Verification) and MDV (Metric-Driven Verification) concepts familiar to SystemVerilog users.

**Key capabilities:**

- **Functional Coverage**: Define cover points, cover bins, and cross coverage using Python decorators and classes. Coverage can be sampled at any point in the testbench.
- **Constrained Randomization**: Classes extend `Randomized` base class; random variables and ranges are defined; constraints are Python functions. Hard constraints (return True/False) and soft constraints (return numeric weight) are both supported. Uses the `python-constraint` solver.
- **Coverage-Driven Test Generation (CDTG)**: The critical feature -- coverage metrics are used *at runtime* to dynamically adjust randomization. Already-covered bins are excluded from the randomization set, dramatically reducing simulation time to reach coverage closure.
- **Export/Merge**: Coverage databases can be exported to XML or YAML format, and a merge function combines results from multiple simulation runs.

```python
# Example: cocotb-coverage functional coverage
from cocotb_coverage.coverage import CoverPoint, CoverCross, coverage_db

@CoverPoint("top.ethertype", xf=lambda pkt: pkt.ethertype, bins=["ARP", "IPv4", "IPv6"])
@CoverPoint("top.action", xf=lambda pkt: pkt.action, bins=["pass", "drop"])
@CoverCross("top.ethertype_x_action", items=["top.ethertype", "top.action"])
def sample_coverage(pkt):
    pass  # coverage is sampled by the decorators
```

#### PyVSC (Python Verification Stimulus and Coverage)

An alternative library providing SystemVerilog-style constraints and coverage. Built on the Boolector SMT solver (more powerful than python-constraint for complex constraints). Supports saving coverage in `.xml` or `.libucis` format for visualization with PyUCIS-Viewer.

**Key advantage over cocotb-coverage**: SMT-based constraint solving handles more complex interdependent constraints. PyVSC is used alongside PyUVM.

#### Coverage Categories for PacGate

For our packet filter, we should track:

| Category | Cover Points | Bins |
|----------|-------------|------|
| **Protocol** | ethertype | ARP (0x0806), IPv4 (0x0800), IPv6 (0x86DD), VLAN (0x8100), unknown |
| **Address** | dst_mac, src_mac | broadcast, multicast, unicast, match, no-match |
| **Decision** | decision_pass | pass, drop |
| **Rule Hit** | matched_rule_index | each rule index, no-match (default) |
| **Frame Size** | frame_length | min (64), typical (128-1024), jumbo (>1518) |
| **Cross** | ethertype x decision | all combinations |
| **Cross** | rule_index x action | which rules fire and what they do |

### Sources

- [cocotb-coverage GitHub](https://github.com/mciepluc/cocotb-coverage)
- [cocotb-coverage Documentation](https://cocotb-coverage.readthedocs.io/)
- [cocotb-coverage Introduction](https://github.com/mciepluc/cocotb-coverage/blob/master/documentation/source/introduction.rst)
- [PyVSC Paper (WOSET 2020)](https://woset-workshop.github.io/PDFs/2020/a15.pdf)
- [PyVSC GitHub](https://github.com/fvutils/pyvsc)
- [Effective Design Verification -- Constrained Random with Python and Cocotb (arXiv 2024)](https://arxiv.org/html/2407.10312v1)
- [Coverage-Driven Verification Methodology (Doulos)](https://www.doulos.com/knowhow/systemverilog/uvm/easier-uvm/easier-uvm-deeper-explanations/coverage-driven-verification-methodology/)

---

## 3. Property-Based Testing for HDL

### The Concept

Property-based testing (PBT), popularized by QuickCheck (Haskell) and Hypothesis (Python), generates random inputs to test that *properties* (invariants) hold universally, rather than checking specific input/output pairs. When a failure is found, the framework automatically *shrinks* the failing case to the minimal reproducing example.

### Hypothesis + cocotb: An Unexplored Frontier

There is no established integration between Hypothesis and cocotb. This represents a genuine innovation opportunity for PacGate. The challenge is that Hypothesis expects synchronous functions while cocotb tests are async coroutines interacting with a simulator. However, this can be bridged.

**Proposed architecture for PacGate:**

```python
from hypothesis import given, strategies as st, settings
import cocotb

# Define strategies for Ethernet frames
mac_strategy = st.binary(min_size=6, max_size=6)
ethertype_strategy = st.sampled_from([0x0800, 0x0806, 0x86DD, 0x8100])
payload_strategy = st.binary(min_size=46, max_size=1500)

# Property: "For any valid Ethernet frame, the filter produces a decision within N cycles"
@cocotb.test()
async def test_always_produces_decision(dut):
    """Property: filter always terminates with a valid decision."""
    # Use Hypothesis-generated frames from a pre-generated batch
    for frame in hypothesis_frames:
        await send_frame(dut, frame)
        decision = await wait_for_decision(dut, timeout_cycles=200)
        assert decision in (0, 1), "Decision must be pass or drop"
```

**Alternative approach -- use Hypothesis as a pre-generation step:**

Since cocotb tests run inside a simulator event loop, the cleanest integration is to use Hypothesis to pre-generate test vectors that are then consumed by cocotb tests. Hypothesis strategies can generate thousands of frames with edge cases (broadcast MACs, all-zeros, maximum-length payloads, etc.) and the shrinking capability helps pinpoint exactly which frame properties cause failures.

**Key properties for a packet filter:**

1. **Determinism**: Same frame always produces the same decision
2. **Termination**: Every frame produces a decision within bounded cycles
3. **Priority correctness**: If rule N matches and rule M (lower priority) matches, rule N's action is applied
4. **Conservation**: The decision is always exactly pass or drop (no undefined states)
5. **Independence**: Non-overlapping frames do not interfere with each other's decisions

### Sources

- [Hypothesis -- Property-Based Testing for Python](https://hypothesis.readthedocs.io/)
- [Hypothesis GitHub](https://github.com/HypothesisWorks/hypothesis)
- [Getting Started with Property-Based Testing (Semaphore)](https://semaphore.io/blog/property-based-testing-python-hypothesis-pytest)

---

## 4. Mutation Testing for Hardware

### What Is Mutation Testing for HDL?

Mutation testing assesses *test suite quality* by deliberately introducing small syntactic modifications (mutations) into the design and checking whether the test suite detects them. If a mutant passes all tests, the test suite has a gap.

**Common mutation operators for Verilog/VHDL:**

| Operator | Description | Example |
|----------|-------------|---------|
| Bit-flip | Invert a single bit in a constant or signal | `8'hFF` -> `8'hFE` |
| Operator swap | Change `==` to `!=`, `&` to `|`, `+` to `-` | `a == b` -> `a != b` |
| Signal stuck-at | Force a signal to constant 0 or 1 | `wire x = a & b` -> `wire x = 1'b0` |
| Condition negation | Invert an if-condition | `if (match)` -> `if (!match)` |
| Assignment swap | Swap RHS of two nearby assignments | Rule outputs swapped |
| Dead-code removal | Delete a branch of an if/else | Remove a rule's match logic |

### MCY -- Mutation Cover with Yosys

MCY (from YosysHQ) is the key open-source tool for hardware mutation testing. It operates at the post-synthesis netlist level.

**How MCY works:**

1. Yosys synthesizes the design and generates thousands of mutants by modifying individual signals in the netlist
2. Formal equivalence checking (via SymbiYosys) filters out *equivalent mutants* -- mutations that do not actually change observable behavior. This eliminates false positives that plague other mutation testing approaches
3. Surviving non-equivalent mutants are run against the testbench
4. If the testbench passes a non-equivalent mutant, that is a real coverage gap

**This is a standout feature because** MCY combines simulation-based mutation testing with formal methods to produce a much more meaningful coverage metric than pure code coverage. It answers the question: "Does my testbench actually check the outputs, or does it just exercise the code paths?"

**Application to PacGate (IMPLEMENTED):**

PacGate integrates MCY into its verification flow (Phase 9, Phase 13):
- `pacgate mcy rules.yaml` generates MCY config for the generated Verilog
- `pacgate mcy rules.yaml --run` executes MCY (requires mcy binary)
- `pacgate mutate rules.yaml` generates 11 types of YAML-level mutations
- `pacgate mutate rules.yaml --run` runs kill-rate analysis (compile + lint each mutant)
- PacGate is the first YAML-to-test framework that measures its own test quality through mutation coverage.

### Sources

- [MCY -- Mutation Cover with Yosys (GitHub)](https://github.com/YosysHQ/mcy)
- [MCY Documentation](https://mcy.readthedocs.io/en/latest/index.html)
- [MCY Methodology](https://yosyshq.readthedocs.io/projects/mcy/en/latest/methodology.html)
- [Fault Injection and Test Approach for Behavioural Verilog](https://thesai.org/Downloads/Volume10No4/Paper_7-Fault_Injection_and_Test_Approach.pdf)
- [Functional Verification of RTL Designs driven by Mutation Testing metrics (IEEE)](https://ieeexplore.ieee.org/abstract/document/4341472/)
- [Automated Fault Injection in Verilog (Edinburgh)](https://project-archive.inf.ed.ac.uk/ug4/20201672/ug4_proj.pdf)

---

## 5. UVM-Like Methodology in Python/cocotb

### PyUVM -- The UVM in Python

PyUVM implements the IEEE 1800.2 Universal Verification Methodology in Python, using cocotb as the simulator interface. It is now at version 3.0.0, which adds Register Abstraction Layer (RAL) support.

### Key UVM Concepts and Their Python Translation

| UVM Concept | SystemVerilog | PyUVM (Python) | Purpose |
|-------------|--------------|----------------|---------|
| **Sequence Item** | `class my_txn extends uvm_sequence_item` | `class MyTxn(uvm_sequence_item)` | Data object representing one transaction |
| **Sequence** | `class my_seq extends uvm_sequence` | `class MySeq(uvm_sequence)` | Generates a stream of sequence items |
| **Sequencer** | `class my_sqr extends uvm_sequencer` | `class MySqr(uvm_sequencer)` | Routes sequence items to driver |
| **Driver** | `class my_drv extends uvm_driver` | `class MyDrv(uvm_driver)` | Converts transactions to pin-level wiggling |
| **Monitor** | `class my_mon extends uvm_monitor` | `class MyMon(uvm_monitor)` | Observes DUT interface, reconstructs transactions |
| **Scoreboard** | `class my_sb extends uvm_scoreboard` | `class MySb(uvm_scoreboard)` | Compares expected vs actual results |
| **Agent** | `class my_agent extends uvm_agent` | `class MyAgent(uvm_agent)` | Bundles driver + monitor + sequencer |
| **Environment** | `class my_env extends uvm_env` | `class MyEnv(uvm_env)` | Top-level container for agents and scoreboard |
| **RAL** | `uvm_reg_block` / `uvm_reg` / `uvm_reg_field` | Same hierarchy in Python | Register model abstraction |

### PyUVM Advantages Over SystemVerilog UVM

1. **No strict typing overhead**: Python's dynamic typing eliminates the parameterized class boilerplate that plagues SystemVerilog UVM
2. **Multiple inheritance**: Python supports it natively; SystemVerilog does not
3. **Data collection**: PyUVM testbenches can collect sampled values and coverage data into CSV files at every clock cycle during regression, enabling ML-based analysis
4. **Rapid iteration**: No compilation step for testbench code changes
5. **Library ecosystem**: Full access to numpy, pandas, scikit-learn, matplotlib for analysis

### ML-Driven Coverage Optimization (Cutting Edge)

Recent research (2025) demonstrates using Machine Learning with PyUVM/cocotb to optimize coverage closure:

- During simulation, PyUVM collects randomized stimulus values and coverage bin hit/miss data into CSV files
- Supervised ML models (neural networks, decision trees) learn the mapping from stimulus parameters to coverage outcomes
- The trained model predicts which constraint configurations will hit uncovered bins
- This produces ML-optimized regressions that reach coverage closure faster than random exploration

### Application to PacGate

PacGate currently uses a UVM-inspired but lighter-weight Python verification framework (PacketFactory, PacketDriver, DecisionMonitor, Scoreboard, Coverage, Properties). A future migration to full pyUVM structure could look like:

```
PacGateEnv (uvm_env)
  +-- PktAgent (uvm_agent)
  |     +-- PktDriver     -- sends frames via pkt_data/pkt_valid/pkt_sof/pkt_eof
  |     +-- PktMonitor    -- reconstructs frames from bus, publishes via TLM port
  |     +-- PktSequencer  -- routes PktTxn items from sequences to driver
  +-- DecisionMonitor     -- watches decision_valid/decision_pass
  +-- PktScoreboard       -- reference model: given frame, predict pass/drop; compare
  +-- CoverageCollector   -- functional coverage sampling
```

### Sources

- [PyUVM GitHub](https://github.com/pyuvm/pyuvm)
- [PyUVM Introduction (v3.0.0)](https://pyuvm.github.io/pyuvm/docsources/README.html)
- [Python and the UVM (Siemens)](https://blogs.sw.siemens.com/verificationhorizons/2021/09/09/python-and-the-uvm/)
- [PyUVM RAL Architecture (DeepWiki)](https://deepwiki.com/pyuvm/pyuvm/7.1-ral-architecture)
- [PyUVM RAL Discussion](https://github.com/pyuvm/pyuvm/discussions/200)
- [Constrained Random Verification using PyUVM (arXiv)](https://arxiv.org/pdf/2407.10317)
- [Optimizing Coverage-Driven Verification Using ML and PyUVM (arXiv 2025)](https://arxiv.org/html/2503.11666)

---

## 6. Test Harness Generation from Specifications

### The State of the Art

#### Commercial Tools

**Agnisys IDS-Verify** is the closest commercial analog to PacGate's approach. It takes register specifications (IP-XACT, SystemRDL, or proprietary format) and generates:
- Complete UVM testbenches (bus agents, drivers, adaptors, sequencers, sequences)
- Register tests with 100% functional coverage of cover groups
- Positive and negative test types (read-only protection, indirect access, lock/unlock)
- Makefiles for common simulators

This is a multi-million-dollar EDA product targeting large ASIC teams.

#### LLM-Based Approaches (2025)

Active research is using Large Language Models for testbench generation:

- **AutoBench**: A multi-agent system with a Testbench Generator Agent, Simulator Agent, and Trackback Mechanism that regenerates on failure
- **CorrectBench**: Automatic testbench generation with functional self-correction using LLMs
- **LLM4DV**: An orchestration framework using LLMs for automated hardware test stimuli generation
- **PRO-V-R1**: A reasoning-enhanced agent for RTL verification

Current state-of-the-art LLMs achieve only ~34% pass@1 on hardware verification benchmarks, indicating this space is still immature.

### How PacGate Compares and What Makes It Innovative

| Aspect | Agnisys IDS-Verify | LLM-Based | PacGate |
|--------|-------------------|-----------|--------|
| Input format | IP-XACT, SystemRDL | Natural language / RTL | YAML rule definitions |
| Output | UVM (SystemVerilog) | Mixed | Verilog RTL + cocotb Python |
| Domain | Register access | General RTL | Packet filtering |
| Determinism | Deterministic | Non-deterministic | Deterministic |
| Cost | Commercial ($$$) | API costs | Open source |
| **Unique angle** | Generates tests from register spec | Generates from LLM inference | **Generates BOTH the hardware AND its tests from the same spec** |

**PacGate's key innovation**: No other tool generates both the implementation (Verilog) and the verification (cocotb) from a single specification. Agnisys generates tests from register specs but assumes the RTL exists. LLMs generate one or the other. PacGate generates both, ensuring perfect alignment between specification, implementation, and verification.

**Additional differentiators we should build:**
1. **Negative test generation**: Automatically generate frames that should NOT match any rule, verifying the default action
2. **Boundary testing**: Auto-generate edge cases (broadcast MAC, multicast bit, EtherType boundaries)
3. **Coverage model generation**: Generate cocotb-coverage cover points directly from the YAML specification
4. **Mutation-aware testing**: Integrate MCY to measure test quality and feed back improvements

### Sources

- [Agnisys IDS-Verify](https://www.agnisys.com/products/ids-verify/)
- [Specification-Driven UVM Testbench Generation (Agnisys)](https://www.agnisys.com/blog/specification-driven-uvm-testbench-generation/)
- [AutoBench: Automatic Testbench Generation (ACM)](https://dl.acm.org/doi/pdf/10.1145/3670474.3685956)
- [CorrectBench (arXiv)](https://arxiv.org/html/2411.08510)
- [LLM4DV (OpenReview)](https://openreview.net/forum?id=Srfi0a7vB3)
- [Can LLMs Design Real Hardware? (OpenReview)](https://openreview.net/forum?id=Xobl2VHyVb)

---

## 7. Formal Verification Integration

### SymbiYosys (sby) -- Open Source Formal Verification

SymbiYosys is the front-end for Yosys-based formal hardware verification. It supports:

- **Bounded Model Checking (BMC)**: Verify that assertions hold for all reachable states up to N clock cycles
- **Unbounded Verification**: Prove properties hold for ALL reachable states (k-induction, PDR)
- **Cover Statements**: Generate test benches that reach specified states
- **Liveness Properties**: Verify that something eventually happens

**Assertion types:**
- `assert`: The solver tries to find inputs that make this false (the property to prove)
- `assume`: Restricts the solver's input space (environment constraints)
- `cover`: The solver tries to find inputs that make this true (reachability)

### cocotb + SymbiYosys: Complementary, Not Integrated

There is no direct integration between cocotb and SymbiYosys. They serve complementary roles:

| Aspect | cocotb (Simulation) | SymbiYosys (Formal) |
|--------|-------------------|-------------------|
| Completeness | Samples the state space | Exhaustively explores state space (bounded) |
| Speed | Fast per-test, slow for full coverage | Slow per-property, but proves universally |
| Complexity | Handles any testbench complexity | Limited by state space explosion |
| Stimuli | Generated by testbench | Generated by solver |
| Best for | Protocol sequences, data-path testing | Control logic, FSM correctness, corner cases |

### Integration Architecture for PacGate (IMPLEMENTED)

PacGate generates formal properties alongside simulation tests from the same YAML:

```
rules.yaml --> pacgate --> Verilog RTL (gen/rtl/)
                      --> cocotb tests (gen/tb/)
                      --> SVA assertions (gen/formal/)   ✓ Phase 4+
                      --> sby task file (gen/formal/)     ✓ Phase 4+
                      --> property tests (gen/tb/)        ✓ Phase 8+
```

**Properties formally verified for the packet filter (20+ assertions):**

1. **Mutual exclusion**: Priority encoder correctness
2. **Completeness**: Every frame gets a decision (no stuck states)
3. **Latency bound**: Decision within N cycles of EOF
4. **Reset correctness**: Known output state after reset
5. **Frame isolation**: SOF resets partial match state
6. **Protocol prerequisites**: GTP-U implies UDP, IGMP implies IPv4 proto 2, MLD implies ICMPv6
7. **Field bounds**: MPLS TC <= 7, MPLS label <= 0xFFFFF
8. **Rate-limit enforcement**: rate_limiter_drop implies !decision_pass
9. **Cover statements**: Protocol reachability (GTP, MPLS, IGMP, MLD)

**Example SVA generation from YAML:**

```systemverilog
// Generated from YAML rule: "allow_arp"
// Property: if frame matches ARP ethertype, decision must be pass
property p_arp_pass;
    @(posedge clk) disable iff (!rst_n)
    (decision_valid && parsed_ethertype == 16'h0806) |-> decision_pass;
endproperty
assert property (p_arp_pass);
```

### Sources

- [SymbiYosys GitHub](https://github.com/YosysHQ/sby)
- [SymbiYosys Documentation](https://symbiyosys.readthedocs.io/en/latest/index.html)
- [SymbiYosys Quickstart](https://symbiyosys.readthedocs.io/en/latest/quickstart.html)
- [Formal Extensions to Verilog (SymbiYosys)](https://symbiyosys.readthedocs.io/en/latest/verilog.html)
- [Open Source Formal Verification with SymbiYosys (CERN)](https://indico.cern.ch/event/1381060/contributions/5923296/attachments/2874315/5037748/REDS_2024_06_13_Thoma_formal_verif.pdf)
- [Formal Verification Courseware (ZipCPU)](https://zipcpu.com/tutorial/formal.html)
- [Awesome Formal Verification (GitHub)](https://github.com/ElNiak/awesome-formal-verification)
- [Awesome Open Hardware Verification (GitHub)](https://github.com/ben-marshall/awesome-open-hardware-verification)

---

## 8. Regression and CI for FPGA Projects

### cocotb CI Integration

cocotb's test runner produces results in **JUnit XML format** by default (`results.xml`), which is understood by Jenkins, GitHub Actions, Azure Pipelines, and GitLab CI. The `cocotb-test` package provides a pytest integration layer with the `--cocotbxml` option to combine cocotb and pytest XML reports.

### GitHub Actions Pipeline for PacGate

A practical CI pipeline:

```yaml
# .github/workflows/verify.yml
name: PacGate Verification
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Icarus Verilog
        run: sudo apt-get install -y iverilog
      - name: Install Python dependencies
        run: pip install cocotb cocotb-coverage cocotb-bus
      - name: Build Rust compiler
        run: cargo build --release
      - name: Compile rules
        run: cargo run --release -- compile rules/examples/allow_arp.yaml
      - name: Run simulation
        run: make sim RULES=rules/examples/allow_arp.yaml
      - name: Upload test results
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: gen/tb/results.xml
      - name: Publish JUnit report
        uses: mikepenz/action-junit-report@v4
        with:
          report_paths: gen/tb/results.xml
```

### Coverage Tracking Over Time

**Functional coverage tracking architecture:**

1. **Per-run**: cocotb-coverage exports coverage to XML/YAML after each simulation
2. **Merge**: The cocotb-coverage merge function combines results from multiple test runs (parametric rules, different YAML configurations)
3. **Trend**: Store coverage XML artifacts in CI; a Python script parses them and tracks coverage percentage over time
4. **Dashboard**: Generate coverage trend charts (matplotlib or Plotly) and publish as CI artifacts or GitHub Pages

**Regression management best practices:**

| Practice | Tool | Notes |
|----------|------|-------|
| Test result format | JUnit XML | Built into cocotb |
| Coverage export | XML/YAML | cocotb-coverage native |
| Coverage merge | cocotb-coverage merge | Combine parametric runs |
| CI platform | GitHub Actions | Free for open source |
| Regression dashboard | GitHub Pages + static HTML | Generated by Python script |
| Failure notification | GitHub Actions alerts | On PR checks failure |
| Simulator | Icarus Verilog | Free, fast, CI-friendly |
| Performance baseline | Pytest benchmarks | Track simulation time per test |

### Sources

- [cocotb CI Integration](https://www.cocotb.org/)
- [cocotb-test PyPI](https://pypi.org/project/cocotb-test/)
- [cocotb-example with GitHub Actions](https://github.com/abarajithan11/cocotb-example)
- [cocotb Simulator Support](https://docs.cocotb.org/en/stable/simulator_support.html)
- [FPGA Verification Method Based on Test Coverage Analysis (IEEE)](https://ieeexplore.ieee.org/document/10754172)
- [Coverage & Plan-Driven Verification for FPGAs (Verification Academy)](https://verificationacademy.com/topics/fpga-verification/coverage-and-plan-driven-verification-for-fpgas/)

---

## 9. Recommendations for PacGate

### What Would Make This Project Stand Out to Management

Based on this research, here are the features ranked by impact and feasibility:

### Tier 1: High Impact, Achievable Now (Phase 2)

| Feature | What It Does | Why It Matters |
|---------|-------------|----------------|
| **Coverage model generation from YAML** | Generate cocotb-coverage cover points, bins, and cross coverage directly from the YAML rule spec | No other open-source tool does this. Demonstrates spec-to-verification traceability |
| **Constrained random frame generation** | Use cocotb-coverage's `Randomized` class to generate thousands of diverse Ethernet frames | Moves from "a few directed tests" to "thorough exploration" -- the professional approach |
| **Negative test generation** | Auto-generate frames that should NOT match any rule | Verifies default action works correctly, a common verification gap |
| **GitHub Actions CI pipeline** | Automated build/compile/simulate on every push, with JUnit reporting | Immediately demonstrates professional engineering practice |
| **cocotb 2.0 migration** | Update templates to use Logic/LogicArray types | Shows we are on the cutting edge of the tooling |

### Tier 2: High Impact, Moderate Effort (Phase 2-3)

| Feature | What It Does | Why It Matters |
|---------|-------------|----------------|
| **Mutation testing with MCY** | Measure test harness quality by mutating the generated Verilog | This is the "killer feature" -- a framework that measures its own test quality. Extremely rare in open-source FPGA verification |
| **Formal property generation** | Generate SVA assertions from YAML and verify with SymbiYosys | Dual verification (simulation + formal) from one spec is unprecedented for an open-source tool |
| **Property-based testing** | Use Hypothesis to generate edge-case frames and test invariants | Novel application of software testing technique to hardware verification |
| **Coverage-driven test generation** | Runtime-adaptive randomization that targets uncovered bins | Demonstrates sophisticated verification methodology |

### Tier 3: Differentiation Features (Phase 3-4)

| Feature | What It Does | Why It Matters |
|---------|-------------|----------------|
| **PyUVM testbench architecture** | Structure tests using UVM methodology (agents, scoreboards, sequences) | Professional-grade verification environment, recognizable to ASIC verification engineers |
| **ML-optimized regression** | Train models on coverage data to predict optimal test parameters | Cutting-edge research territory (2025 papers) |
| **AXI-Stream VIP integration** | Use cocotbext-axi for Phase 4 store-and-forward verification | Production-ready protocol verification |
| **Coverage trend dashboard** | Track coverage metrics over time, published to GitHub Pages | Visual proof of verification progress for management |
| **Copra type stubs** | Generate IDE-friendly type stubs for the DUT | Developer productivity improvement |

### The Elevator Pitch

> "PacGate is a specification-driven FPGA packet filter compiler that generates both synthesizable hardware and a complete verification environment from YAML rules. It supports L2-L4 matching, IPv6, tunnel protocols (VXLAN, GTP-U), MPLS, multicast (IGMP/MLD), connection tracking, and rate limiting — all with 388 Rust tests, 47 Python tests, 18+ cocotb simulation tests, 20+ SVA formal assertions, 9 Hypothesis property tests, and 11 mutation strategies. Unlike P4 compilers ($100K+ licenses, no auto-verification) and LLM approaches (non-deterministic, ~70% accuracy), PacGate deterministically generates matched RTL and verification from a single source of truth. No other tool in the market provides this capability."

### Recommended Implementation Order — Status Update (Phase 16)

1. ~~**Coverage model from YAML**~~ **DONE** (Phase 2, enhanced Phase 13: CoverageDirector, L3/L4 kwargs, XML export)
2. ~~**Constrained random + negative tests**~~ **DONE** (Phase 2: 500 random; Phase 13: CIDR/port boundary, negative tests; Phase 14: protocol random)
3. ~~**MCY mutation testing**~~ **DONE** (Phase 9: YAML-level; Phase 13: MCY Verilog-level + kill-rate runner)
4. ~~**Formal property generation**~~ **DONE** (Phase 4: SVA+SBY; Phase 10: IPv6/port/rate; Phase 14: GTP/MPLS/IGMP/MLD; Phase 16: strengthened assertions)
5. ~~**CI pipeline + coverage trending**~~ **DONE** (Phase 10: multi-job; Phase 13: Hypothesis/JUnit; Phase 16: conntrack/formal/rate-limit CI jobs)
6. ~~**Protocol verification completeness**~~ **DONE** (Phase 14-16: full scoreboard, directed tests, formal assertions, property tests for all protocol fields)
7. ~~**Software simulation completeness**~~ **DONE** (Phase 16: rate-limit + conntrack in software simulator, `--stateful` CLI flag)
8. **Future**: PyUVM architecture, ML optimization, cocotb 2.0 migration, Verilator support

### Phase 14-16 Verification Milestones

**Phase 14**: Closed all verification gaps for GTP-U/MPLS/IGMP/MLD protocol fields — Python scoreboard, packet factory, test templates, SVA formal assertions, shadow/overlap detection, all analysis tools. Fixed diff_rules() L3/L4/IPv6 field comparison bug.

**Phase 15**: Verification depth — reachability with protocol fields, 11 mutation types (6 new protocol-specific), 5 protocol coverage coverpoints, 4 Hypothesis protocol strategies, LINT013-015 protocol prerequisite checks, CI expanded to 8 simulate examples.

**Phase 16**: Simulator completeness — token-bucket rate-limit simulation, conntrack simulation (5-tuple hash + reverse lookup), `--stateful` CLI flag, strengthened SVA assertions (rate-limit enforcement, protocol prerequisites + bounds), protocol property tests wired into generated test files, byte_match in HTML docs, CI expansion (conntrack simulate, formal generate, rate-limit simulate).

**Current test counts**: 237 Rust unit + 151 integration = 388 Rust tests, 47 Python scoreboard tests, 13+ cocotb simulation tests, 5 conntrack cocotb tests.

---

## 10. Market Landscape and Competitive Analysis (Feb 2026)

### 10.1 Competitive Positioning

PacGate occupies a genuinely unique position in the market. No other tool provides a declarative YAML-to-verified-Verilog pipeline for packet filtering with dual output (both RTL and verification from the same spec).

| Approach | HW Gen | Test Gen | Single Source | Accessibility | Cost |
|----------|:------:|:--------:|:------------:|:-------------:|:----:|
| **PacGate** | **Yes** | **Yes** | **Yes** | YAML (simple) | Proprietary |
| AMD VitisNetP4 | Yes | No | No | P4 (specialized) | $$$$ |
| Intel/Altera P4 Suite | Yes | No | No | P4 (specialized) | $$$$ |
| eHDL (Princeton) | Yes | No | No | eBPF/XDP (moderate) | Research |
| Corundum | Partial | No | No | Verilog (hard) | Open source |
| ESnet SmartNIC | Yes | Partial | No | P4 via VitisNetP4 | Open source |
| Chisel/SpinalHDL | Yes | No | No | Scala (moderate) | Open source |
| Vitis HLS | Yes | No | No | C++ (moderate) | $$ |
| LLM-based (MAGE, etc.) | Partial | Partial | No | Natural language | API costs |

### 10.2 Key Competitors Detail

**AMD VitisNetP4**: Dominant P4-to-FPGA compiler for Alveo/Versal. Generates pipelined Parser/Match-Action/Deparser. Requires expensive license.

**Intel/Altera P4 Suite**: Targets Agilex/Stratix for 200Gbps+. Showcased at P4 Developer Days (Feb 2026) for SmartNIC deployment.

**eHDL** (ASPLOS'23): Compiles unmodified Linux eBPF/XDP programs to FPGA hardware pipelines. Uses 6.5-13.3% of FPGA resources at line-rate with ~1us latency. Closest conceptual competitor to PacGate — takes a high-level filter spec and generates FPGA hardware. However, requires eBPF programming knowledge (not declarative YAML).

**Corundum**: Leading open-source FPGA NIC — 10G/25G/100G, PCIe Gen 3, IEEE 1588 PTP, 10K+ queues. Provides platform infrastructure that PacGate filter logic could integrate into.

**ESnet SmartNIC**: P4-programmable packet processing on OpenNIC shell for Alveo boards. Provides complete workflow for FPGA network applications.

**OpenNIC** (AMD): NIC shell with 4 PCIe physical functions and 2x 100Gbps Ethernet, ~5% LUT usage on U250. Basis for NetFPGA PLUS.

### 10.3 SmartNIC / DPU Market Context

DPU/SmartNIC market: $1.11B (2024) → projected $4.44B (2034) at 15% CAGR. SmartNICs represent >35% of deployed NICs in hyperscale data centers.

| Vendor | Product | Speed | Market Share |
|--------|---------|-------|:------------:|
| NVIDIA | BlueField-3 / BlueField-4 | 400G / 800G | ~42% |
| Intel | Mount Morgan / Hot Springs Canyon | 400G-800G | ~24% |
| AMD | Pensando Salina / Pollara 400 | 400G | ~17% |
| Broadcom | Stingray | 100G | ~12% |

These platforms use ASIC-based or ARM-based approaches. PacGate targets the FPGA segment, which offers more flexibility but requires RTL expertise — a gap PacGate bridges.

### 10.4 Industry Trends

**P4 and SDN evolution**: Industry shifted from OpenFlow (fixed match fields) to P4 (fully programmable parsing and match-action). FPGA implementations achieving 1Tbps raw throughput. PacGate's YAML approach is more accessible than P4 but currently lacks runtime-programmable tables.

**Cloud FPGA**: AWS EC2 F2 instances (Feb 2025) — AMD Virtex UltraScale+ HBM, 100Gbps networking, up to 60% better price-performance than F1. No tool provides automated cloud FPGA deployment packaging.

**Edge/IoT security**: Global edge computing spending projected $380B by 2028 at 13.8% CAGR. Lightweight FPGA filters for edge gateways are a natural fit for PacGate's resource-efficient designs.

**5G/Open RAN**: FPGA-for-5G market $2.10B (2024) → $4.92B (2034) at 8.9% CAGR. PacGate already supports GTP-U; extending to eCPRI and SCTP would strengthen the 5G story.

**Automotive TSN**: IEEE 802.1DG-2025 (TSN Profile for Automotive) newly published. No open-source tool addresses TSN-aware hardware filtering.

**LLM-assisted hardware design**: LLM mentions in hardware papers grew from 12 (2023) to 274 (2025) — 2,183% growth. Multi-agent workflows (MAGE, VerilogCoder) achieving >70% on Verilog benchmarks. Opportunity for natural-language-to-YAML rule generation.

**Post-quantum cryptography**: NIST finalized ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205). HQC expected 2026-2027. FPGA-based crypto acceleration for PQ algorithms is growing.

### 10.5 Verification Tool Updates

**cocotb 2.0**: Stable with 2.0.1 released. Native async/await, Queue/PriorityQueue/LifoQueue, Lock in `async with`, Verilator improvements, SystemVerilog `bit` type support.

**pyUVM 3.0**: Major addition of Register Abstraction Layer (RAL). Now provides complete UVM methodology in Python atop cocotb, including RAL for counter/CSR verification.

**SymbiYosys**: Actively maintained, distributed via Tabby CAD Suite and OSS CAD Suite. No major feature announcements in 2025-2026.

**AutoSVA** (Princeton): Automatically generates formal testbenches from annotated RTL signal declarations. Potential inspiration for PacGate assertion enhancement.

**AI/ML verification**: Cadence Verisium for AI-driven verification. Siemens unveiled AI-enhanced EDA suite at DAC 2025 (Aprisa AI, Calibrae Vision AI). Research on ML-optimized regression using pyUVM/cocotb data collection.

---

## 11. Feature Gap Analysis and Recommendations

### 11.1 Features Competing Tools Have That PacGate Lacks

| Feature | Who Has It | Impact | Effort |
|---------|-----------|:------:|:------:|
| P4 language input | VitisNetP4, Altera | Medium | High |
| Runtime-updateable flow tables | P4 match-action engines | **High** | Medium |
| Platform integration (PCIe/DMA) | Corundum, OpenNIC, ESnet | **High** | Medium |
| Cloud FPGA packaging | None (opportunity) | **High** | Medium |
| Packet rewrite/NAT actions | P4 compilers, Corundum | **High** | Medium |
| eBPF/XDP rule import | eHDL | Medium | Medium |
| MACsec/IPsec header parsing | AMD Network Security IP | Medium | Low |
| In-band Network Telemetry (INT) | P4-based implementations | Low | High |
| TSN-aware filtering | CAST TSN IP, vendor tools | Medium | Medium |
| cocotb 2.0 testbenches | N/A (migration) | Medium | Low |
| pyUVM testbench option | pyUVM 3.0 | Low | Medium |

### 11.2 Recommended Next Features (Prioritized)

**High Priority** — strong market demand + feasible:

1. **Runtime-updateable flow tables**: `--dynamic` flag generates AXI-Lite-writable match tables. Bridges the biggest gap vs. P4. Enables rule updates without recompilation.

2. **Packet rewrite actions**: Add `rewrite` actions (set VLAN, modify TTL, NAT src/dst, VLAN push/pop) to complement pass/drop. Transforms PacGate from pure filter to lightweight packet processor.

3. **Platform integration targets**: Generate drop-in modules for OpenNIC user boxes and Corundum application pipelines. `--target opennic` and `--target corundum` flags.

4. **AWS F2 deployment packaging**: `pacgate deploy rules.yaml --target aws-f2` generates complete Vivado project for cloud FPGA with synthesis scripts and AFI build automation.

5. **cocotb 2.0 testbench migration**: Upgrade generated tests to async/await patterns, Queue types, improved Verilator compatibility.

**Medium Priority** — growing market + moderate effort:

6. **DDoS mitigation primitives**: Enhanced SYN flood detection (counting with threshold), DNS amplification detection, configurable rate limiting with burst profiles.

7. **TSN-aware filtering**: Match on 802.1Qbv schedule, 802.1CB stream ID, PTP message types. Targets automotive/industrial markets with no open-source competition.

8. **eBPF/XDP rule import**: `pacgate from-xdp filter.c` converts simple XDP filters to PacGate YAML.

9. **Natural language rule input**: LLM-powered `pacgate nl "block SSH brute force"` generates YAML rules.

10. **Flow export (IPFIX/NetFlow)**: Generate hardware flow record exporters from connection tracking data.

**Lower Priority** — emerging + higher effort:

11. **eCPRI / SCTP protocol support**: Extend 5G story with fronthaul eCPRI and control plane SCTP.
12. **MACsec/IPsec header parsing**: Classify encrypted traffic by SPI, SecTAG.
13. **TCAM-style wildcard matching**: Ternary content-addressable memory for flexible prefix/mask.
14. **Multi-table pipeline**: Cascaded match stages (like P4's match-action pipeline).
15. **INT metadata insertion**: Per-rule In-band Network Telemetry header injection.

### Sources

- [ESnet SmartNIC GitHub](https://github.com/esnet/esnet-smartnic-hw)
- [Corundum GitHub](https://github.com/corundum/corundum)
- [OpenNIC GitHub](https://github.com/Xilinx/open-nic)
- [eHDL (ASPLOS'23)](https://pontarelli.di.uniroma1.it/publication/asplos23/asplos23.pdf)
- [AMD VitisNetP4](https://www.xilinx.com/products/intellectual-property/ef-di-vitisnetp4.html)
- [Altera P4 Suite for FPGA](https://www.altera.com/products/development-tools/p4-suite-fpga)
- [AWS EC2 F2 Instances](https://aws.amazon.com/ec2/instance-types/f2/)
- [DPU/SmartNIC Market Analysis](https://introl.com/blog/dpus-smartnics-data-center-infrastructure-bluefield-pensando-2025)
- [FPGA-for-5G Market](https://www.openpr.com/news/4285299/fpga-for-5g-market-to-reach-usd-4-92-billion-by-2034)
- [IEEE 802.1DG-2025 (TSN Automotive)](https://1.ieee802.org/tsn/802-1dg/)
- [LLM for Verilog Survey (2025)](https://arxiv.org/abs/2512.00020)
- [NIST PQC Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [Siemens AI-EDA at DAC 2025](https://www.designnews.com/design-software/siemens-unveils-eda-ai-system-for-semiconductor-pcb-design-at-dac-2025)
- [AutoSVA GitHub](https://github.com/PrincetonUniversity/AutoSVA)
- [Cadence Verisium](https://www.cadence.com/en_US/home/tools/system-design-and-verification/ai-driven-verification.html)

---

## Appendix: Key Library Versions (as of Feb 2026)

| Library | Version | Python | Notes |
|---------|---------|--------|-------|
| cocotb | 2.0.1 | 3.8+ | Major release, new type system |
| cocotb-coverage | 2.0.0 | 3.8+ | Updated for cocotb 2.0 |
| cocotb-bus | 0.2.1 | 3.8+ | Bus interface support |
| cocotbext-axi | latest | 3.8+ | AXI4/AXI4-Stream/AXI4-Lite |
| cocotbext-eth | latest | 3.8+ | Ethernet PHY/MAC models |
| pyuvm | 3.0.0 | 3.8+ | UVM with RAL support |
| PyVSC | 0.x | 3.8+ | SMT-based constraint solver |
| Hypothesis | 6.x | 3.8+ | Property-based testing |
| MCY | latest | N/A | Yosys-based mutation testing |
| SymbiYosys | latest | N/A | Formal verification frontend |
