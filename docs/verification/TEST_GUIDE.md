# PacGate Test Guide

*A comprehensive guide to verification, testing, and using PacGate as a test framework.*

---

## Table of Contents

1. [Test Architecture Overview](#1-test-architecture-overview)
2. [Running Tests](#2-running-tests)
3. [cocotb Simulation Tests](#3-cocotb-simulation-tests)
4. [Property-Based Testing](#4-property-based-testing)
5. [Formal Verification](#5-formal-verification)
6. [Coverage-Driven Verification](#6-coverage-driven-verification)
7. [Using PacGate to Test Other FPGA Designs](#7-using-pacgate-to-test-other-fpga-designs)
8. [Verification Framework API](#8-verification-framework-api)
9. [Writing Custom Tests](#9-writing-custom-tests)
10. [CI/CD Integration](#10-cicd-integration)
11. [Test Quality Metrics](#11-test-quality-metrics)

---

## 1. Test Architecture Overview

PacGate employs a multi-layer verification strategy inspired by the UVM (Universal Verification Methodology) used in commercial FPGA/ASIC verification:

```
                    ┌──────────────────────────────────┐
                    │         Verification Pyramid     │
                    ├──────────────────────────────────┤
                    │    Formal Proof (SymbiYosys)     │  Mathematical
                    │    - SVA assertions              │  certainty
                    │    - BMC + cover modes           │
                    ├──────────────────────────────────┤
                    │    Property Tests (Hypothesis)   │  Statistical
                    │    - Determinism, priority       │  confidence
                    │    - Conservation, independence  │
                    ├──────────────────────────────────┤
                    │    Random Tests (cocotb)         │  Broad
                    │    - 500+ constrained-random     │  coverage
                    │    - Scoreboard checking         │
                    ├──────────────────────────────────┤
                    │    Directed Tests (cocotb)       │  Targeted
                    │    - Per-rule regression         │  validation
                    │    - Corner cases                │
                    ├──────────────────────────────────┤
                    │    Rust Unit Tests (cargo test)  │  Compiler
                    │    - 44 unit + 19 integration    │  correctness
                    └──────────────────────────────────┘
```

### Component Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Test Environment                        │
│                                                            │
│  ┌───────────────┐   ┌───────────┐  ┌────────────────┐     │
│  │ PacketFactory │   │  Driver   │  │    Scoreboard  │     │
│  │ - directed    │──►│  (BFM)    │  │  - predict()   │     │
│  │ - random      │   │  byte-by- │  │  - check()     │     │
│  │ - boundary    │   │  byte     │  │  - report()    │     │
│  │ - corner case │   └─────┬─────┘  └────────▲───────┘     │
│  └───────────────┘         │                 │             │
│                            ▼                 │             │
│                    ┌─────────────┐   ┌───────┴──────────┐  │
│                    │     DUT     │   │    Monitor       │  │
│                    │  (Verilog)  │──►│  - decision_valid│  │
│                    │             │   │  - decision_pass │  │
│                    └─────────────┘   └──────────────────┘  │
│                                                            │
│  ┌───────────────┐  ┌───────────────────────────────────┐  │
│  │   Coverage    │  │    Properties (Hypothesis)        │  │
│  │ - coverpoints │  │  - determinism                    │  │
│  │ - bins        │  │  - priority_correctness           │  │
│  │ - cross       │  │  - conservation                   │  │
│  │ - XML export  │  │  - default_action                 │  │
│  └───────────────┘  └───────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

---

## 2. Running Tests

### Rust Compiler Tests

```bash
# Run all 63 tests (44 unit + 19 integration)
cargo test

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test integration_test

# Run a specific test
cargo test compile_allow_arp

# Run with output (for debugging)
cargo test -- --nocapture
```

### cocotb Simulation Tests

```bash
# Full pipeline: compile + simulate
make sim RULES=rules/examples/enterprise.yaml

# Step-by-step:
pacgate compile rules/examples/enterprise.yaml -o gen/
cd gen/tb && make

# AXI-Stream simulation
pacgate compile rules/examples/enterprise.yaml --axi -o gen/
cd gen/tb-axi && make
```

### Property-Based Tests

```bash
# Generate and run property tests
pacgate compile rules/examples/enterprise.yaml -o gen/
cd gen/tb && python3 test_properties.py
```

### Formal Verification

```bash
# Generate formal files
pacgate formal rules/examples/enterprise.yaml -o gen/

# Run SymbiYosys (requires sby)
cd gen/formal && sby -f packet_filter.sby
```

### All Tests at Once

```bash
# Full verification suite
cargo test && \
  make sim RULES=rules/examples/enterprise.yaml && \
  cd gen/tb && python3 test_properties.py && \
  cd ../formal && sby -f packet_filter.sby
```

---

## 3. cocotb Simulation Tests

### Test Categories

PacGate generates several categories of simulation tests:

#### Directed Tests (Per-Rule)

Each rule in the YAML generates at least one directed test that sends a frame matching that specific rule and verifies the correct action:

```python
@cocotb.test()
async def test_allow_arp(dut):
    """Verify ARP frame (0x0806) triggers pass action."""
    frame = build_frame(ethertype=0x0806)
    await send_frame(dut, frame)
    await wait_for_decision(dut)
    assert dut.decision_pass.value == 1, "ARP should pass"
```

#### Default Action Test

Verifies that frames matching no rule get the configured default action:

```python
@cocotb.test()
async def test_default_drop(dut):
    """Verify non-matching frame triggers default drop."""
    frame = build_frame(ethertype=0x1234)  # No rule matches this
    await send_frame(dut, frame)
    await wait_for_decision(dut)
    assert dut.decision_pass.value == 0, "Unknown should drop"
```

#### Random Tests (Scoreboard)

500+ constrained-random frames with automatic scoreboard checking:

```python
@cocotb.test()
async def test_random_packets(dut):
    """500 random packets with scoreboard verification."""
    scoreboard = Scoreboard(rules, default_action)
    for _ in range(500):
        frame = random_frame()  # Random MAC, EtherType, size, VLAN
        expected = scoreboard.predict(frame)
        await send_frame(dut, frame)
        await wait_for_decision(dut)
        actual = "pass" if dut.decision_pass.value else "drop"
        scoreboard.check(expected, actual)
    scoreboard.report()  # Assert 0 mismatches
```

#### Corner-Case Tests

- **Runt frame** (< 64 bytes): Minimum-size Ethernet frame
- **Jumbo frame** (> 1518 bytes): Oversized frame handling
- **Back-to-back frames**: Two frames with no gap
- **Reset recovery**: Assert correct behavior after reset
- **VLAN-tagged traffic**: 802.1Q tagged frame parsing

### Test Output

```
test_allow_arp ........................... PASS
test_default_drop ....................... PASS
test_allow_ipv4 ......................... PASS
test_broadcast_drop ..................... PASS
test_mgmt_vlan .......................... PASS
test_vendor_mac ......................... PASS
test_lldp_pass .......................... PASS
test_random_packets ..................... PASS (500/500)
test_runt_frame ......................... PASS
test_jumbo_frame ........................ PASS
test_back_to_back ....................... PASS
test_reset_recovery ..................... PASS
test_vlan_tagged ........................ PASS
```

---

## 4. Property-Based Testing

### What Are Property Tests?

Property tests use the [Hypothesis](https://hypothesis.readthedocs.io/) library to generate hundreds of random inputs and verify that certain invariants always hold. Unlike directed tests (which check specific scenarios), property tests check universal properties.

### Properties Verified

#### Determinism
> *The same frame always produces the same decision.*

```python
def check_determinism(rules, default_action, frame):
    """Run the same frame twice; results must match."""
    result1 = evaluate(rules, default_action, frame)
    result2 = evaluate(rules, default_action, frame)
    assert result1 == result2
```

#### Priority Correctness
> *When multiple rules match, the highest-priority rule wins.*

```python
def check_priority_correctness(rules, default_action, frame):
    """If a frame matches multiple rules, highest priority action applies."""
    matching = [r for r in rules if matches(r, frame)]
    if matching:
        expected = max(matching, key=lambda r: r['priority'])
        assert evaluate(rules, default_action, frame) == expected['action']
```

#### Conservation
> *Every frame gets exactly one decision: either pass or drop.*

```python
def check_conservation(rules, default_action, frame):
    """Every frame must get exactly one decision."""
    result = evaluate(rules, default_action, frame)
    assert result in ('pass', 'drop')
```

#### Default Action
> *Frames matching no rule get the configured default action.*

```python
def check_default_action(rules, default_action, frame):
    """Non-matching frames get the default action."""
    matching = [r for r in rules if matches(r, frame)]
    if not matching:
        assert evaluate(rules, default_action, frame) == default_action
```

#### Independence
> *Non-matching fields don't affect the decision.*

```python
def check_independence(rules, default_action, frame):
    """Changing non-matching fields doesn't change the decision."""
    result1 = evaluate(rules, default_action, frame)
    frame2 = mutate_non_matching_fields(frame)
    result2 = evaluate(rules, default_action, frame2)
    assert result1 == result2
```

### Running Property Tests

```bash
# Default: 200 random frames + 100 Hypothesis examples per property
cd gen/tb && python3 test_properties.py

# Output:
# Random suite: 200/200 passed
# Hypothesis determinism: 100/100 passed
# Hypothesis priority: 100/100 passed
# Hypothesis conservation: 100/100 passed
# Hypothesis default_action: 100/100 passed
# Hypothesis independence: 100/100 passed
# TOTAL: 500/500 ALL PASS
```

---

## 5. Formal Verification

### SVA Assertions

PacGate generates SystemVerilog Assertions (SVA) that mathematically prove properties of the filter hardware:

#### Reset Properties
```systemverilog
// After reset, decision outputs are deasserted
property p_reset_decision_valid;
    @(posedge clk) $rose(rst) |-> ##1 !decision_valid;
endproperty
```

#### Completeness
```systemverilog
// Every frame eventually gets a decision
property p_completeness;
    @(posedge clk) $rose(pkt_sof) |-> ##[1:20] decision_valid;
endproperty
```

#### Latency Bound
```systemverilog
// Decision arrives within 4 cycles of frame header parsed
property p_latency_bound;
    @(posedge clk) header_valid |-> ##[1:4] decision_valid;
endproperty
```

#### Per-Rule Correctness
```systemverilog
// If rule 0 matches, action must be correct
property p_rule_0_action;
    @(posedge clk) rule_match[0] && decision_valid |-> decision_pass == 1'b1;
endproperty
```

#### Mutual Exclusion
```systemverilog
// At most one rule fires per frame (priority encoder guarantee)
property p_mutual_exclusion;
    @(posedge clk) $onehot0(rule_match);
endproperty
```

### SymbiYosys Modes

**BMC (Bounded Model Checking):**
Exhaustively checks all possible input sequences up to depth N. If any sequence violates an assertion, produces a counterexample trace.

**Cover mode:**
Verifies that all rules are reachable — proves there exists at least one input sequence that triggers each rule. If a rule is unreachable, the cover check fails.

```bash
# Run both modes
cd gen/formal && sby -f packet_filter.sby

# Check results
cat packet_filter_bmc/status    # PASS or FAIL
cat packet_filter_cover/status  # PASS or FAIL
```

---

## 6. Coverage-Driven Verification

### Cover Points

PacGate tracks functional coverage across these dimensions:

| Cover Point | Bins | Description |
|------------|------|-------------|
| `ethertype` | ipv4, arp, ipv6, vlan_tag, lldp, ptp, other | Which protocols are exercised |
| `dst_mac_type` | broadcast, multicast, unicast, zero | MAC address categories |
| `frame_size` | runt, min, typical, large, jumbo | Frame size distribution |
| `vlan_present` | tagged, untagged | VLAN tag coverage |
| `decision` | pass, drop | Action coverage |
| `rule_hit` | per-rule bins | Which rules are triggered |
| `corner_cases` | runt, jumbo, back-to-back, all-zero, all-FF, pcp7 | Edge cases |

### Cross Coverage

Cross coverage tracks combinations:

| Cross | Dimensions | Purpose |
|-------|-----------|---------|
| `ethertype_x_decision` | ethertype × decision | Every protocol gets both pass and drop |
| `rule_x_decision` | rule_hit × decision | Every rule's action is verified |

### Coverage XML

```bash
# Coverage XML is generated during simulation
cat gen/tb/coverage.xml
```

```xml
<coverage tool="pacgate" version="1.0" samples="513" overall_pct="87.3">
  <coverpoint name="ethertype" coverage_pct="85.7" hit_bins="6" total_bins="7">
    <bin name="ipv4" hit="true" count="142"/>
    <bin name="arp" hit="true" count="89"/>
    ...
  </coverpoint>
  ...
</coverage>
```

### Merging Coverage

Combine coverage from multiple simulation runs:

```python
from verification.coverage import FilterCoverage

# Load two coverage runs
cov1 = FilterCoverage.load_xml("run1/coverage.xml")
cov2 = FilterCoverage.load_xml("run2/coverage.xml")

# Merge
cov1.merge_from(cov2)

# Save combined
cov1.save_xml("merged_coverage.xml")
print(f"Overall coverage: {cov1.overall_coverage():.1f}%")
```

### Coverage Targets

| Level | Target | Meaning |
|-------|--------|---------|
| Basic | 70%+ | All rules hit, both actions exercised |
| Good | 85%+ | Most EtherTypes, frame sizes, corner cases |
| Excellent | 95%+ | Full cross coverage, all bins hit |

---

## 7. Using PacGate to Test Other FPGA Designs

One of PacGate's most valuable capabilities is testing **existing FPGA packet filter implementations** — even those not built with PacGate.

### Approach: Golden Reference Model

```
┌─────────────────┐    ┌──────────────────────┐
│  Your FPGA      │    │  PacGate Reference   │
│  Filter (DUT)   │    │  (generated Verilog) │
│                 │    │                      │
│  pkt_* ──► dec  │    │  pkt_* ──► dec       │
└────────┬────────┘    └──────────┬───────────┘
         │                        │
         ▼                        ▼
    ┌────────────────────────────────┐
    │       Scoreboard               │
    │  Compare DUT vs Reference      │
    │  Report mismatches             │
    └────────────────────────────────┘
```

### Step 1: Define Your Filter's Rules in YAML

Document your existing filter's behavior as PacGate YAML rules:

```yaml
# my_existing_filter_rules.yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    # Mirror your existing filter's rules here
    - name: allow_ipv4
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
    # ... etc
```

### Step 2: Generate Test Infrastructure

```bash
# Generate cocotb tests from your rule spec
pacgate compile my_existing_filter_rules.yaml -o gen/

# The generated tests work against ANY Verilog module with the
# standard PacGate interface:
#   Input:  pkt_data[7:0], pkt_valid, pkt_sof, pkt_eof
#   Output: decision_valid, decision_pass
```

### Step 3: Adapt the cocotb Makefile

Edit `gen/tb/Makefile` to point at your existing RTL:

```makefile
# Change VERILOG_SOURCES to point at your RTL files
VERILOG_SOURCES = \
    /path/to/your/filter_top.v \
    /path/to/your/parser.v \
    /path/to/your/matcher.v

# Change TOPLEVEL to your module name
TOPLEVEL = your_filter_top

# If your interface differs, adapt the signal names in the test
```

### Step 4: Run Comparison Tests

```bash
cd gen/tb && make

# The scoreboard compares your filter's decisions against
# PacGate's reference model. Any mismatch is reported:
# MISMATCH frame 47: expected PASS, got DROP
#   EtherType: 0x0806, dst_mac: 00:11:22:33:44:55
```

### Step 5: Interface Adaptation

If your filter uses a different interface (e.g., AXI-Stream natively), use the AXI adapter:

```bash
pacgate compile my_rules.yaml --axi -o gen/
# Now gen/tb-axi/ has tests for AXI-Stream interface
```

Or write a thin cocotb adapter:

```python
# Custom adapter for non-standard interfaces
async def send_frame_custom(dut, frame):
    """Adapt PacGate frame driver to your DUT's interface."""
    for i, byte in enumerate(frame):
        dut.my_data_in.value = byte
        dut.my_valid.value = 1
        dut.my_sof.value = 1 if i == 0 else 0
        dut.my_eof.value = 1 if i == len(frame)-1 else 0
        await RisingEdge(dut.clk)
    dut.my_valid.value = 0
```

### Example: Testing a NetFPGA Filter

```bash
# 1. Define NetFPGA's filter rules in YAML
cat > netfpga_rules.yaml << 'EOF'
pacgate:
  version: "1.0"
  defaults:
    action: pass
  rules:
    - name: block_broadcast
      priority: 100
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop
EOF

# 2. Generate test harness
pacgate compile netfpga_rules.yaml -o gen/

# 3. Modify Makefile to point at NetFPGA RTL
# 4. Run: cd gen/tb && make
# 5. Review: scoreboard reports any discrepancies
```

### Example: Testing a Corundum Filter Module

```bash
# Corundum's filter uses AXI-Stream natively
pacgate compile corundum_rules.yaml --axi -o gen/

# Modify gen/tb-axi/Makefile:
#   VERILOG_SOURCES = /path/to/corundum/fpga/common/rtl/...
#   TOPLEVEL = eth_mac_filter

# Run AXI-Stream tests
cd gen/tb-axi && make
```

### SVA Assertions for Existing Designs

Generate SVA assertions and bind them to your existing module:

```bash
pacgate formal my_rules.yaml -o gen/

# In your testbench or formal setup:
# `bind your_filter_module packet_filter_assertions u_assert (.*);`
```

This lets you formally verify your existing filter against the YAML spec without modifying its RTL.

---

## 8. Verification Framework API

### PacketFactory (`verification/packet.py`)

```python
from verification.packet import PacketFactory

factory = PacketFactory()

# Directed frames
arp_frame = factory.arp_frame()                    # Standard ARP
ipv4_frame = factory.ipv4_frame()                  # Standard IPv4
broadcast = factory.broadcast_frame()              # ff:ff:ff:ff:ff:ff

# Random frames
random = factory.random_frame()                    # Fully random
random_vlan = factory.random_vlan_frame()          # Random with VLAN tag

# Boundary frames
runt = factory.runt_frame()                        # < 64 bytes
jumbo = factory.jumbo_frame()                      # > 1518 bytes
min_frame = factory.min_frame()                    # Exactly 64 bytes

# Corner cases
all_zero_mac = factory.zero_mac_frame()            # 00:00:00:00:00:00
all_ff_mac = factory.broadcast_frame()             # ff:ff:ff:ff:ff:ff
pcp7 = factory.high_priority_vlan_frame()          # VLAN PCP = 7
```

### Scoreboard (`verification/scoreboard.py`)

```python
from verification.scoreboard import Scoreboard

# Initialize with rules and default action
scoreboard = Scoreboard(rules=[
    {"name": "allow_arp", "priority": 100, "match": {"ethertype": 0x0806}, "action": "pass"},
], default_action="drop")

# Predict expected result
expected = scoreboard.predict(frame)  # Returns "pass" or "drop"

# Check actual result
scoreboard.check(expected, actual)    # Increments match/mismatch counter

# Report
scoreboard.report()                   # Prints summary, asserts 0 mismatches
print(f"Matches: {scoreboard.matches()}/{scoreboard.total()}")
```

### Coverage (`verification/coverage.py`)

```python
from verification.coverage import FilterCoverage

# Initialize coverage
cov = FilterCoverage(rules=["allow_arp", "allow_ipv4", "__default__"])

# Sample a frame
cov.sample(
    ethertype=0x0806,
    dst_mac="ff:ff:ff:ff:ff:ff",
    frame_size=64,
    vlan_present=False,
    decision="pass",
    rule_hit="allow_arp"
)

# Report
print(f"Overall: {cov.overall_coverage():.1f}%")
for cp in cov.coverpoints():
    print(f"  {cp.name}: {cp.coverage_pct:.1f}%")

# Export to XML
cov.save_xml("coverage.xml")

# Merge from another run
other = FilterCoverage.load_xml("other_coverage.xml")
cov.merge_from(other)
```

### Properties (`verification/properties.py`)

```python
from verification.properties import run_property_tests

results = run_property_tests(
    rules=[...],
    default_action="drop",
    num_random=200,
    num_hypothesis=100
)

print(f"Passed: {results.passed}/{results.total}")
assert results.all_passed()
```

---

## 9. Writing Custom Tests

### Adding a Custom cocotb Test

Add tests to the generated `gen/tb/test_packet_filter.py`:

```python
@cocotb.test()
async def test_my_custom_scenario(dut):
    """Test a specific sequence of frames."""
    await reset_dut(dut)

    # Send an ARP frame (should pass)
    arp = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # dst_mac
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  # src_mac
        0x08, 0x06,                            # ethertype (ARP)
    ]) + bytes(46)                             # padding to 60 bytes
    await send_frame(dut, arp)
    await wait_for_decision(dut)
    assert dut.decision_pass.value == 1

    # Immediately send an IPv4 frame (should also pass)
    ipv4 = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00,                            # ethertype (IPv4)
    ]) + bytes(46)
    await send_frame(dut, ipv4)
    await wait_for_decision(dut)
    assert dut.decision_pass.value == 1
```

### Adding a Custom Property

```python
from hypothesis import given, strategies as st
from verification.properties import ethernet_frames, evaluate

@given(frame=ethernet_frames())
def test_my_custom_property(frame):
    """My custom invariant: ARP frames are never dropped."""
    if frame.ethertype == 0x0806:
        result = evaluate(RULES, DEFAULT_ACTION, frame)
        assert result == "pass", f"ARP frame was dropped!"
```

### Adding a Custom Cover Point

```python
from verification.coverage import FilterCoverage

cov = FilterCoverage(rules=rule_names)

# Add a custom cover point
cov.add_coverpoint("src_vendor", bins={
    "cisco": lambda f: f.src_mac.startswith("00:26:cb"),
    "arista": lambda f: f.src_mac.startswith("00:1c:73"),
    "other": lambda f: True,
})
```

---

## 10. CI/CD Integration

### GitHub Actions Workflow

```yaml
name: PacGate Verification
on: [push, pull_request]

jobs:
  rust-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test

  simulation:
    runs-on: ubuntu-latest
    needs: rust-tests
    strategy:
      matrix:
        example: [allow_arp, enterprise, blacklist, datacenter,
                  industrial_ot, automotive_gateway, 5g_fronthaul]
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y iverilog
      - run: pip install cocotb cocotb-coverage hypothesis
      - run: cargo build --release
      - run: |
          pacgate compile rules/examples/${{ matrix.example }}.yaml -o gen/
          cd gen/tb && make
      - uses: actions/upload-artifact@v4
        with:
          name: coverage-${{ matrix.example }}
          path: gen/tb/coverage.xml

  formal:
    runs-on: ubuntu-latest
    needs: rust-tests
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y yosys symbiyosys z3
      - run: cargo build --release
      - run: |
          pacgate formal rules/examples/enterprise.yaml -o gen/
          cd gen/formal && sby -f packet_filter.sby

  coverage-merge:
    runs-on: ubuntu-latest
    needs: simulation
    steps:
      - uses: actions/download-artifact@v4
      - run: |
          python3 -c "
          from verification.coverage import FilterCoverage
          import glob
          merged = None
          for f in glob.glob('coverage-*/coverage.xml'):
              cov = FilterCoverage.load_xml(f)
              if merged is None:
                  merged = cov
              else:
                  merged.merge_from(cov)
          merged.save_xml('merged_coverage.xml')
          print(f'Merged coverage: {merged.overall_coverage():.1f}%')
          "
```

### JSON-Based CI Checks

```bash
#!/bin/bash
# ci_check.sh — Run validation checks

# Validate all example files
for f in rules/examples/*.yaml; do
    result=$(pacgate validate "$f" --json 2>/dev/null)
    status=$(echo "$result" | jq -r '.status')
    if [ "$status" != "valid" ]; then
        echo "FAIL: $f"
        exit 1
    fi
done

# Check resource budgets
for f in rules/examples/*.yaml; do
    estimate=$(pacgate estimate "$f" --json 2>/dev/null)
    luts=$(echo "$estimate" | jq '.total.luts')
    if [ "$luts" -gt 10000 ]; then
        echo "WARNING: $f uses $luts LUTs (budget: 10000)"
    fi
done

echo "All checks passed"
```

---

## 11. Test Quality Metrics

### Current Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Rust unit tests | 44 | All pass |
| Rust integration tests | 19 | All pass |
| cocotb simulation tests | 13+ | All pass |
| Random packet matches | 500/500 | 100% |
| Functional coverage | 85%+ | >85% |
| Property tests | 500/500 | 100% |
| Formal BMC (depth 20) | PROVEN | No counterexample |
| Cover reachability | PASS | All rules reachable |

### Coverage Improvement Strategies

1. **Add more random seeds**: Run simulation multiple times with different seeds
2. **Increase random count**: Bump from 500 to 5000 packets for higher coverage
3. **Merge across examples**: Run all examples and merge coverage XML
4. **Target uncovered bins**: Check coverage report and write directed tests for missing bins
5. **Cross coverage gaps**: Add frames that hit rare protocol×action combinations

### Interpreting Formal Results

| Result | Meaning | Action |
|--------|---------|--------|
| BMC PASS | All assertions hold for N cycles | Good — increase depth for more confidence |
| BMC FAIL | Counterexample found | Bug — examine the trace in VCD viewer |
| Cover PASS | All rules are reachable | Good — filter is fully exercisable |
| Cover FAIL | Some rules unreachable | Review rules — may be shadowed by higher priority |
