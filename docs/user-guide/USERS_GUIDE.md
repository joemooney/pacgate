# PacGate User's Guide

*A comprehensive guide to defining, compiling, verifying, and deploying packet filters — FPGA hardware or Rust software.*

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Rule Language Reference](#2-rule-language-reference)
3. [CLI Command Reference](#3-cli-command-reference)
4. [Stateless Filtering Examples](#4-stateless-filtering-examples)
5. [Stateful FSM Examples](#5-stateful-fsm-examples)
6. [Verification and Simulation](#6-verification-and-simulation)
7. [Formal Verification](#7-formal-verification)
8. [FPGA Synthesis and Deployment](#8-fpga-synthesis-and-deployment)
9. [CI/CD Integration](#9-cicd-integration)
10. [Troubleshooting](#10-troubleshooting)
11. [EtherType Reference](#11-ethertype-reference)
12. [System-Level Simulation Lab](#12-system-level-simulation-lab)

---

## 1. Getting Started

### Prerequisites

- **Rust** (1.70+): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Python 3** (3.8+): For cocotb simulation
- **Icarus Verilog** (11+): `sudo apt install iverilog` or `brew install icarus-verilog`
- **Questa/QuestaSim** (optional): Alternative simulator (`vlog`/`vsim` in PATH, valid license)
- **cocotb** (2.0+): `pip install cocotb cocotb-tools cocotb-coverage`
- **Hypothesis** (optional): `pip install hypothesis` (for property testing)
- **SymbiYosys** (optional): For formal verification
- **Yosys** (optional): For synthesis

### Installation

```bash
git clone https://github.com/joemooney/pacgate.git
cd pacgate
cargo build --release

# Optional: install to PATH
cargo install --path .

# Verify installation
pacgate --help
```

### Your First Filter in 60 Seconds

```bash
# Step 1: Create a starter rule file
pacgate init my_filter.yaml

# Step 2: Edit it (or use as-is)
cat my_filter.yaml

# Step 3: Validate
pacgate validate my_filter.yaml

# Step 4: Compile
pacgate compile my_filter.yaml -o gen/

# Step 5: Inspect the output
ls gen/rtl/   # Verilog files
ls gen/tb/    # cocotb tests

# Step 6: Simulate (requires iverilog or Questa + cocotb)
cd gen/tb && python run_sim.py    # cocotb 2.0 runner (recommended)
# or: cd gen/tb && make           # Makefile (legacy, still supported)
```

---

## 2. Rule Language Reference

### File Structure

Every PacGate rule file follows this structure:

```yaml
pacgate:
  version: "1.0"           # Schema version (always "1.0")
  defaults:
    action: drop            # Default action when no rule matches
                            # "drop" = whitelist mode (block by default)
                            # "pass" = blacklist mode (allow by default)
  rules:
    - name: rule_name       # Unique name (used in Verilog module names)
      type: stateless       # "stateless" or "stateful"
      priority: 100         # 0-65535, higher wins, must be unique
      match:                # Match criteria (all fields must match)
        ethertype: "0x0806"
      action: pass          # "pass" or "drop"
```

### Match Fields

All match fields are optional. If multiple fields are specified, **all must match** (AND logic).

#### `dst_mac` — Destination MAC Address

```yaml
# Exact match
match:
  dst_mac: "ff:ff:ff:ff:ff:ff"

# Wildcard (OUI match) — * matches any byte
match:
  dst_mac: "01:80:c2:*:*:*"

# Wildcard individual octets
match:
  dst_mac: "00:1a:*:*:ee:ff"
```

**Common MAC addresses:**

| Address | Description |
|---------|-------------|
| `ff:ff:ff:ff:ff:ff` | Broadcast |
| `01:80:c2:00:00:00` | STP BPDU |
| `01:80:c2:00:00:02` | LACP / Slow Protocols |
| `01:80:c2:00:00:0e` | LLDP |
| `01:00:5e:*:*:*` | IPv4 multicast |
| `33:33:*:*:*:*` | IPv6 multicast |
| `01:00:0c:cc:cc:cd` | Cisco PVST+ |

#### `src_mac` — Source MAC Address

Same syntax as `dst_mac`. Commonly used for vendor OUI filtering:

```yaml
# Allow only Cisco equipment (OUI 00:26:cb)
match:
  src_mac: "00:26:cb:*:*:*"

# Allow only Arista equipment (OUI 00:1c:73)
match:
  src_mac: "00:1c:73:*:*:*"
```

**Common vendor OUIs:**

| OUI | Vendor |
|-----|--------|
| `00:26:cb:*:*:*` | Cisco |
| `00:1c:73:*:*:*` | Arista |
| `00:1a:1e:*:*:*` | HP/Aruba |
| `00:50:56:*:*:*` | VMware |
| `52:54:00:*:*:*` | QEMU/KVM |
| `00:0d:b9:*:*:*` | Intel NIC |

#### `ethertype` — EtherType (16-bit)

```yaml
# Hex format (recommended)
match:
  ethertype: "0x0800"    # IPv4

# Also accepts uppercase
match:
  ethertype: "0x86DD"    # IPv6
```

**Common EtherTypes:**

| EtherType | Protocol | Use Case |
|-----------|----------|----------|
| `0x0800` | IPv4 | General IP traffic |
| `0x0806` | ARP | Address resolution |
| `0x86DD` | IPv6 | Next-gen IP |
| `0x8100` | 802.1Q VLAN | VLAN tagging (handled by parser) |
| `0x88CC` | LLDP | Link layer discovery |
| `0x8809` | LACP | Link aggregation |
| `0x888E` | 802.1X (EAPoL) | Port authentication |
| `0x88A4` | EtherCAT | Industrial automation |
| `0x8892` | PROFINET | Industrial (Siemens) |
| `0x88F7` | PTP/1588 | Precision time |
| `0x88B8` | GOOSE/IEC 61850 | Substation automation |
| `0xAEFE` | eCPRI | 5G fronthaul |
| `0x22F0` | AVB/TSN | Audio/video bridging |

#### `vlan_id` — VLAN Identifier (12-bit)

```yaml
# Match frames tagged with VLAN 100
match:
  vlan_id: 100    # 0-4095
```

Note: Only matches 802.1Q-tagged frames (EtherType 0x8100). Untagged frames have no VLAN ID and won't match.

#### `vlan_pcp` — VLAN Priority Code Point (3-bit)

```yaml
# Match high-priority traffic (PCP 7 = network control)
match:
  vlan_pcp: 7     # 0-7
```

| PCP | Traffic Class |
|-----|--------------|
| 0 | Best effort (default) |
| 1 | Background |
| 2 | Excellent effort |
| 3 | Critical applications |
| 4 | Video |
| 5 | Voice |
| 6 | Internetwork control |
| 7 | Network control |

#### Combining Fields

Multiple fields create AND conditions — all must match:

```yaml
# Match IPv4 traffic on VLAN 100 from Cisco equipment
match:
  ethertype: "0x0800"
  vlan_id: 100
  src_mac: "00:26:cb:*:*:*"
```

### Priority System

Rules are evaluated by priority (highest first). When a frame matches multiple rules, the **highest priority** rule's action is applied.

```yaml
rules:
  # Priority 200: Block broadcast (checked first)
  - name: block_broadcast
    priority: 200
    match:
      dst_mac: "ff:ff:ff:ff:ff:ff"
    action: drop

  # Priority 100: Allow ARP (checked second)
  # Even ARP broadcasts are dropped because priority 200 wins
  - name: allow_arp
    priority: 100
    match:
      ethertype: "0x0806"
    action: pass
```

**Priority rules:**
- Range: 0–65535
- Higher number = higher priority (checked first)
- Must be unique across all rules
- PacGate warns about overlapping rules at compile time

### Default Action

When no rule matches a frame, the default action applies:

```yaml
defaults:
  action: drop    # Whitelist mode — block unknown traffic
  # OR
  action: pass    # Blacklist mode — allow unknown traffic
```

**Whitelist mode** (`action: drop`): Explicit allow. Best for security-sensitive deployments.
**Blacklist mode** (`action: pass`): Explicit deny. Best for permissive environments.

---

## 3. CLI Command Reference

### `pacgate compile`

Generate Verilog RTL and cocotb test bench from YAML rules.

```bash
pacgate compile rules.yaml                  # Default output to gen/
pacgate compile rules.yaml -o output/       # Custom output directory
pacgate compile rules.yaml --axi            # Include AXI-Stream wrapper + FIFO
pacgate compile rules.yaml --json           # Machine-readable JSON output
pacgate compile rules.yaml --axi --json -o gen/   # All options
```

**Output structure:**
```
gen/
├── rtl/
│   ├── packet_filter_top.v     # Generated top-level
│   ├── rule_match_0.v          # Per-rule matchers
│   ├── decision_logic.v        # Priority encoder
│   ├── frame_parser.v          # Hand-written parser (copied)
│   ├── axi_stream_adapter.v    # (with --axi)
│   ├── store_forward_fifo.v    # (with --axi)
│   └── packet_filter_axi_top.v # (with --axi)
├── tb/
│   ├── test_packet_filter.py   # cocotb tests
│   ├── test_properties.py      # Property-based tests
│   └── Makefile                # Simulation makefile
└── tb-axi/                     # (with --axi)
    ├── test_axi_packet_filter.py
    └── Makefile
```

### `pacgate validate`

Check YAML rules without generating output. Fast feedback loop.

```bash
pacgate validate rules.yaml
pacgate validate rules.yaml --json
```

Reports: rule count, overlap warnings, validation errors.

### `pacgate init`

Create a well-commented starter rule file.

```bash
pacgate init my_rules.yaml          # Create new file
pacgate init                        # Creates pacgate_rules.yaml
```

Will not overwrite existing files (safety check).

### `pacgate estimate`

FPGA resource estimation for the rule set.

```bash
pacgate estimate rules.yaml
pacgate estimate rules.yaml --json
```

Reports: LUTs, flip-flops, Artix-7 utilization percentage, pipeline timing.

### `pacgate diff`

Compare two rule sets and report differences.

```bash
pacgate diff old_rules.yaml new_rules.yaml
pacgate diff old_rules.yaml new_rules.yaml --json
```

Reports: added rules, removed rules, modified rules (priority/action/match changes).

### `pacgate graph`

Output DOT graph of rule set for visualization with Graphviz.

```bash
pacgate graph rules.yaml                     # Print DOT to stdout
pacgate graph rules.yaml | dot -Tpng -o rules.png   # Render to PNG
pacgate graph rules.yaml | dot -Tsvg -o rules.svg   # Render to SVG
```

### `pacgate stats`

Rule set analytics and statistics.

```bash
pacgate stats rules.yaml
pacgate stats rules.yaml --json
```

Reports: field usage, action balance, priority spacing, stateless/stateful counts.

### `pacgate formal`

Generate SVA assertions and SymbiYosys task files for formal verification.

```bash
pacgate formal rules.yaml -o gen/
pacgate formal rules.yaml --json -o gen/
```

### `pacgate completions`

Generate shell completions.

```bash
pacgate completions bash > ~/.local/share/bash-completion/completions/pacgate
pacgate completions zsh > ~/.zfunc/_pacgate
pacgate completions fish > ~/.config/fish/completions/pacgate.fish
```

---

## 4. Stateless Filtering Examples

### Example 1: Simple ARP Allow (Whitelist)

The simplest possible filter — allow only ARP, drop everything else.

```yaml
# allow_arp.yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
```

```bash
$ pacgate compile allow_arp.yaml -o gen/
$ pacgate estimate allow_arp.yaml
  Frame parser: ~120 LUTs, ~80 FFs
  1 rule matcher: ~40 LUTs
  Decision logic: ~5 LUTs, ~2 FFs
  Total: ~165 LUTs, ~82 FFs (0.8% Artix-7)
```

### Example 2: Enterprise Campus (7 Rules)

Full enterprise deployment with vendor filtering, VLAN segmentation, and protocol allowing.

```yaml
# enterprise.yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop

  rules:
    - name: block_broadcast
      type: stateless
      priority: 200
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop

    - name: allow_mgmt_vlan
      type: stateless
      priority: 150
      match:
        vlan_id: 100
      action: pass

    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass

    - name: allow_ipv4
      type: stateless
      priority: 90
      match:
        ethertype: "0x0800"
      action: pass

    - name: allow_ipv6
      type: stateless
      priority: 80
      match:
        ethertype: "0x86DD"
      action: pass

    - name: allow_vendor_acme
      type: stateless
      priority: 70
      match:
        src_mac: "00:1a:2b:*:*:*"
      action: pass

    - name: allow_lldp
      type: stateless
      priority: 60
      match:
        ethertype: "0x88CC"
      action: pass
```

### Example 3: Blacklist Mode (Threat Blocking)

Block known-bad patterns, allow everything else.

```yaml
# blacklist.yaml
pacgate:
  version: "1.0"
  defaults:
    action: pass              # Allow everything by default

  rules:
    - name: block_broadcast
      type: stateless
      priority: 200
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop

    - name: block_stp
      type: stateless
      priority: 190
      match:
        dst_mac: "01:80:c2:00:00:00"
      action: drop

    - name: block_eapol
      type: stateless
      priority: 170
      match:
        ethertype: "0x888E"
      action: drop

    - name: block_rogue_vendor
      type: stateless
      priority: 160
      match:
        src_mac: "aa:bb:cc:*:*:*"
      action: drop
```

### Example 4: Data Center Multi-Tenant

VLAN-per-tenant isolation with vendor restrictions.

```yaml
# datacenter.yaml — 8 rules
# See rules/examples/datacenter.yaml for complete file
pacgate:
  version: "1.0"
  defaults:
    action: drop

  rules:
    # Block broadcast storms (highest priority)
    - name: block_broadcast
      priority: 1000
      match: { dst_mac: "ff:ff:ff:ff:ff:ff" }
      action: drop

    # Tenant A: VLAN 100, Cisco only
    - name: tenant_a_cisco
      priority: 800
      match:
        vlan_id: 100
        src_mac: "00:26:cb:*:*:*"
      action: pass

    # Tenant B: VLAN 200, Arista only
    - name: tenant_b_arista
      priority: 700
      match:
        vlan_id: 200
        src_mac: "00:1c:73:*:*:*"
      action: pass
    # ... more rules
```

### Example 5: Industrial OT Boundary

Protecting a control network from IT traffic. Only industrial protocols allowed.

```yaml
# industrial_ot.yaml — Key rules
pacgate:
  version: "1.0"
  defaults:
    action: drop

  rules:
    - name: allow_ethercat       # Beckhoff PLCs
      priority: 1000
      match: { ethertype: "0x88A4" }
      action: pass

    - name: allow_profinet       # Siemens PLCs
      priority: 900
      match: { ethertype: "0x8892" }
      action: pass

    - name: allow_ptp            # Time sync (critical)
      priority: 800
      match: { ethertype: "0x88F7" }
      action: pass

    - name: allow_goose          # IEC 61850
      priority: 700
      match: { ethertype: "0x88B8" }
      action: pass
```

### Example 6: 5G Fronthaul

Filtering eCPRI traffic on an O-RAN fronthaul link.

```yaml
# 5g_fronthaul.yaml — Key rules
pacgate:
  version: "1.0"
  defaults:
    action: drop

  rules:
    - name: allow_ecpri          # O-RAN fronthaul
      priority: 1000
      match: { ethertype: "0xAEFE" }
      action: pass

    - name: allow_ptp            # Timing (mandatory for 5G)
      priority: 900
      match: { ethertype: "0x88F7" }
      action: pass

    - name: allow_sync_e         # Synchronous Ethernet
      priority: 800
      match: { dst_mac: "01:80:c2:00:00:02" }
      action: pass
```

---

## 5. Stateful FSM Examples

Stateful rules use finite state machines (FSMs) to track sequences of packets. Each state can have transitions triggered by matching criteria and optional timeouts.

### Example 7: ARP-then-IPv4 Sequence

Allow IPv4 only after a valid ARP exchange:

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
              ethertype: "0x0806"      # ARP seen
            next_state: arp_seen
            action: pass
      arp_seen:
        timeout_cycles: 1000           # 8 µs at 125 MHz
        transitions:
          - match:
              ethertype: "0x0800"      # IPv4 after ARP
            next_state: idle
            action: pass
```

**How it works:**
1. FSM starts in `idle` state
2. When an ARP frame arrives, transitions to `arp_seen` and passes the frame
3. If an IPv4 frame arrives within 1000 clock cycles, passes it and returns to `idle`
4. If no IPv4 arrives within the timeout, FSM returns to `idle` (default drop applies to IPv4)

### Example 8: SYN Flood Detection

Track the ARP→IPv4 sequence to detect legitimate flows vs. floods:

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
        timeout_cycles: 5000           # 40 µs window
        transitions:
          - match:
              ethertype: "0x0800"
            next_state: ipv4_active
            action: pass
      ipv4_active:
        timeout_cycles: 10000          # 80 µs keepalive
        transitions:
          - match:
              ethertype: "0x0800"      # Continued IPv4 = legitimate
            next_state: ipv4_active
            action: pass
          - match:
              ethertype: "0x0806"      # New ARP = new flow
            next_state: arp_seen
            action: pass
```

### Example 9: ARP Spoofing Detection

Monitor ARP request/reply patterns:

```yaml
- name: arp_pattern_monitor
  type: stateful
  priority: 100
  fsm:
    initial_state: idle
    states:
      idle:
        transitions:
          - match:
              ethertype: "0x0806"
              dst_mac: "ff:ff:ff:ff:ff:ff"   # ARP request (broadcast)
            next_state: request_seen
            action: pass
      request_seen:
        timeout_cycles: 2000                  # 16 µs for reply
        transitions:
          - match:
              ethertype: "0x0806"            # ARP reply (unicast)
            next_state: idle
            action: pass
          - match:
              ethertype: "0x0800"            # Normal IP after ARP
            next_state: idle
            action: pass
```

### FSM Design Tips

1. **Always have a timeout** on non-idle states to prevent getting stuck
2. **Keep state counts small** (2-4 states) for efficient hardware
3. **Include a path back to `idle`** from every state
4. **Combine with stateless rules** — stateless handles common cases, stateful handles patterns
5. **Timeout units are clock cycles** — at 125 MHz, 1000 cycles = 8 µs

---

## 6. Verification and Simulation

### Running Simulation

```bash
# Compile rules
pacgate compile rules/examples/enterprise.yaml -o gen/

# Run cocotb simulation
cd gen/tb && make

# Or use the Makefile shortcut
make sim RULES=rules/examples/enterprise.yaml

# Or run with Questa/QuestaSim
make sim RULES=rules/examples/enterprise.yaml SIM=questa
```

### Understanding Test Output

cocotb tests output results per test case:

```
test_allow_arp ........................... PASS
test_default_drop ....................... PASS
test_ipv4_pass .......................... PASS
test_broadcast_drop ..................... PASS
test_vlan_match ......................... PASS
test_mac_wildcard ....................... PASS
test_random_packets ..................... PASS (500/500 match)
test_runt_frame ......................... PASS
test_jumbo_frame ........................ PASS
test_back_to_back ....................... PASS
test_reset_recovery ..................... PASS
test_vlan_tagged ........................ PASS
test_coverage_report .................... PASS (85.2% coverage)
```

### Coverage Report

After simulation, coverage is reported as XML:

```bash
# Coverage XML is auto-generated during simulation
cat gen/tb/coverage.xml
```

Cover points include:
- **ethertype**: IPv4, ARP, IPv6, VLAN, LLDP, PTP, other
- **dst_mac_type**: broadcast, multicast, unicast, zero
- **frame_size**: runt, min, typical, large, jumbo
- **vlan_present**: tagged, untagged
- **decision**: pass, drop
- **rule_hit**: per-rule coverage
- **corner_cases**: runt, jumbo, back-to-back, all-zero MAC, all-FF MAC, PCP 7

### Property-Based Testing

PacGate generates Hypothesis-based property tests:

```bash
# Run property tests (requires hypothesis)
cd gen/tb && python3 test_properties.py
```

Properties tested:
- **Determinism**: Same frame always produces same decision
- **Priority correctness**: Higher-priority match always wins
- **Conservation**: Every frame gets exactly one decision (pass or drop)
- **Default action**: Non-matching frames get the configured default
- **Independence**: Non-matching fields don't affect results

### Verification Framework Components

The Python verification framework (`verification/`) provides:

| Component | File | Purpose |
|-----------|------|---------|
| PacketFactory | `packet.py` | Generate directed, random, boundary, corner-case frames |
| PacketDriver | `driver.py` | Drive frames into DUT byte-by-byte |
| DecisionMonitor | `driver.py` | Capture pass/drop decisions from DUT |
| Scoreboard | `scoreboard.py` | Python reference model, predict + check |
| Coverage | `coverage.py` | Functional coverage with XML export |
| Properties | `properties.py` | Hypothesis strategies + property tests |

---

## 7. Formal Verification

### Generating Formal Files

```bash
pacgate formal rules/examples/enterprise.yaml -o gen/

ls gen/formal/
# assertions.sv         — SVA properties
# packet_filter.sby      — SymbiYosys task file
```

### SVA Assertions Generated

| Property | What It Proves |
|----------|---------------|
| `p_reset_decision_valid` | After reset, decision_valid is 0 |
| `p_reset_decision_pass` | After reset, decision_pass is 0 |
| `p_completeness` | Every frame gets a decision |
| `p_latency_bound` | Decision arrives within N cycles of SOF |
| `p_decision_cleared_on_sof` | Decision_valid clears on new frame |
| `p_mutual_exclusion` | At most one rule fires per frame |
| `p_rule_N_action` | Per-rule: if match then correct action |
| `p_default_action` | No match → default action |

### Running Formal Verification

```bash
# Requires SymbiYosys (sby), Yosys, and an SMT solver (z3 or boolector)
cd gen/formal
sby -f packet_filter.sby

# Tasks run:
# - bmc: Bounded model checking (depth 20)
# - cover: Reachability of all rules
```

### Interpreting Results

```
SBY  9:42:01 [bmc] engine_0: Status returned by engine: pass
SBY  9:42:01 [cover] engine_0: Status returned by engine: pass
```

- **bmc PASS**: All assertions hold for 20 clock cycles (no counterexample found)
- **cover PASS**: All cover points are reachable (all rules can fire)

---

## 8. FPGA Synthesis and Deployment

### AXI-Stream Interface

For integration with existing FPGA designs, use the `--axi` flag:

```bash
pacgate compile rules.yaml --axi -o gen/
```

This generates an AXI-Stream wrapper with:

| Signal | Direction | Width | Description |
|--------|-----------|-------|-------------|
| `s_axis_tdata` | Input | 8 | Ingress data |
| `s_axis_tvalid` | Input | 1 | Data valid |
| `s_axis_tready` | Output | 1 | Ready (backpressure) |
| `s_axis_tlast` | Input | 1 | End of frame |
| `m_axis_tdata` | Output | 8 | Egress data |
| `m_axis_tvalid` | Output | 1 | Data valid |
| `m_axis_tready` | Input | 1 | Ready (backpressure) |
| `m_axis_tlast` | Output | 1 | End of frame |

### Synthesis with Yosys

```bash
# Generate RTL
pacgate compile rules.yaml --axi -o gen/

# Run Yosys synthesis
make synth RULES=rules.yaml

# Or manually:
yosys synth/synth_yosys.ys
```

### Artix-7 Constraints

The provided XDC file (`synth/artix7.xdc`) targets the Xilinx XC7A35T with:
- 125 MHz clock
- LVCMOS33 I/O standard
- Pin assignments for AXI-Stream signals

Modify the XDC for your specific board and pin mapping.

### Resource Scaling

| Rules | LUTs | FFs | Artix-7 % |
|-------|------|-----|-----------|
| 1 | ~165 | ~82 | 0.8% |
| 7 | ~435 | ~82 | 2.1% |
| 14 | ~715 | ~82 | 3.4% |
| 32 | ~1,435 | ~82 | 6.9% |
| 64 | ~2,715 | ~82 | 13.1% |

PacGate warns at >32 rules (note) and >64 rules (warning) for Artix-7 targets.

---

## 9. CI/CD Integration

### JSON Output for Scripting

All commands (except `init` and `graph`) support `--json`:

```bash
# Validate in CI pipeline
result=$(pacgate validate rules.yaml --json)
status=$(echo "$result" | jq -r '.status')
if [ "$status" != "valid" ]; then
  echo "Validation failed!"
  exit 1
fi

# Check resource usage in CI
estimate=$(pacgate estimate rules.yaml --json)
luts=$(echo "$estimate" | jq '.total.luts')
if [ "$luts" -gt 5000 ]; then
  echo "Warning: LUT count exceeds budget ($luts)"
fi

# Detect rule changes
diff_result=$(pacgate diff old.yaml new.yaml --json)
added=$(echo "$diff_result" | jq '.added | length')
echo "Rules added: $added"
```

### GitHub Actions Example

```yaml
# .github/workflows/ci.yml
name: PacGate CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo build --release
      - run: cargo test

  simulate:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y iverilog
      - run: pip install cocotb cocotb-coverage
      - run: cargo build --release
      - run: make sim RULES=rules/examples/enterprise.yaml
      - uses: actions/upload-artifact@v4
        with:
          name: simulation-results
          path: gen/tb/results.xml
```

---

## 10. Troubleshooting

### "Empty rules should fail validation"

PacGate requires at least one rule. An empty rule list is rejected:

```yaml
# This will fail validation:
rules: []
```

### "Overlap warnings"

PacGate detects when rules can match the same frame with different actions:

```
Warning: rules 'block_broadcast' and 'allow_arp' overlap with different actions
```

This is a warning, not an error. The higher-priority rule always wins. Review to ensure this is intentional.

### "iverilog not found"

Install Icarus Verilog:
```bash
# Ubuntu/Debian
sudo apt-get install iverilog

# macOS
brew install icarus-verilog

# From source
git clone https://github.com/steveicarus/iverilog.git
cd iverilog && sh autoconf.sh && ./configure && make && sudo make install
```

### "vlog/vsim not found" (Questa/QuestaSim)

Ensure Questa/QuestaSim is installed and available on `PATH`:
```bash
which vlog
which vsim
```

Then run:
```bash
make sim RULES=rules/examples/enterprise.yaml SIM=questa
make lint LINT_SIM=questa
```

### "cocotb module not found"

Install cocotb in your Python environment:
```bash
pip install cocotb cocotb-coverage
```

### "Makefile: COCOTB_TOPLEVEL not set"

The generated Makefile expects to be run from the `gen/tb/` directory:
```bash
cd gen/tb && make
```

---

## 11. EtherType Reference

A comprehensive reference of EtherTypes relevant to packet filtering:

### Standard Protocols

| EtherType | Protocol | Description |
|-----------|----------|-------------|
| `0x0800` | IPv4 | Internet Protocol version 4 |
| `0x0806` | ARP | Address Resolution Protocol |
| `0x8035` | RARP | Reverse ARP |
| `0x86DD` | IPv6 | Internet Protocol version 6 |
| `0x8100` | 802.1Q | VLAN tagging (parsed automatically) |
| `0x88A8` | 802.1ad | Provider bridging (Q-in-Q) |
| `0x9100` | 802.1Q (legacy) | Double VLAN (legacy) |

### Network Management

| EtherType | Protocol | Description |
|-----------|----------|-------------|
| `0x88CC` | LLDP | Link Layer Discovery Protocol |
| `0x8809` | LACP/ESMC | Link Aggregation / Sync Messaging |
| `0x888E` | EAPoL | 802.1X Port Authentication |
| `0x8899` | Realtek | Realtek Remote Control Protocol |

### Industrial / Automation

| EtherType | Protocol | Description |
|-----------|----------|-------------|
| `0x88A4` | EtherCAT | EtherCAT real-time control |
| `0x8892` | PROFINET | Siemens PROFINET |
| `0x88F7` | PTP/1588 | Precision Time Protocol |
| `0x88B8` | GOOSE | IEC 61850 (substations) |
| `0x88BA` | SV | IEC 61850 Sampled Values |
| `0x891D` | TTEthernet | Time-Triggered Ethernet |

### Telecom / 5G

| EtherType | Protocol | Description |
|-----------|----------|-------------|
| `0xAEFE` | eCPRI | Enhanced Common Public Radio Interface |
| `0x22F0` | AVB | IEEE 802.1Qav Audio/Video Bridging |
| `0x88F7` | PTP | Also used for fronthaul sync |

### Multicast MAC Addresses

| MAC Prefix | Protocol | Description |
|------------|----------|-------------|
| `01:80:c2:00:00:00` | STP | Spanning Tree BPDU |
| `01:80:c2:00:00:02` | LACP | Link Aggregation |
| `01:80:c2:00:00:0e` | LLDP | Link Discovery |
| `01:00:5e:*:*:*` | IPv4 mcast | IPv4 Multicast |
| `33:33:*:*:*:*` | IPv6 mcast | IPv6 Multicast |
| `01:00:0c:cc:cc:cd` | PVST+ | Cisco Per-VLAN STP |
| `01:1b:19:*:*:*` | PTP | PTP Multicast |

---

## 12. System-Level Simulation Lab

This section maps a full "RMAC-style" verification request to what PacGate can implement today with high confidence.

### What Fits PacGate Directly

- Python-driven orchestration of traffic events and regressions
- File-based interfaces for packet/event definitions
- Verification of pass/drop behavior against expected outcomes
- Error-mode testing using malformed or edge-case packet fields
- Throughput and scaling checks using repeated simulation calls

### What Is Out of Scope for PacGate Core

- Vendor-specific RMAC IP generation and auto-negotiation setup
- Full PHY bring-up and hardware timing closure workflows
- Deep electrical/PCS/PMA behavior verification

For those, PacGate should be treated as the policy/filter core inside a broader bench.

### Recommended Architecture

1. Use PacGate rules (`rules/examples/*.yaml`) as source of truth.
2. Use the simulator app (`simulator-app/`) for rapid event-driven testing.
3. Use Python scripts for large batch regressions (1000+ packets).
4. Export JSON artifacts for CI pass/fail and diff tracking.

### Fast Start: Web-Driven System Simulation

```bash
cargo build
python3 simulator-app/server.py
```

Then open `http://127.0.0.1:8787` and:

1. Select a rule file.
2. Trigger single packets with expected action checks.
3. Run built-in scenarios.
4. Save custom scenarios for regressions.
5. Inspect scenario diff (expected vs actual action).

### Fast Start: 1000-Packet Python Regression

Create `simulator-app/examples/run_1000.py`:

```python
#!/usr/bin/env python3
import json
import subprocess

RULES = "rules/examples/allow_arp.yaml"
PKT_PASS = "ethertype=0x0806,src_mac=00:11:22:33:44:55,dst_mac=ff:ff:ff:ff:ff:ff"
PKT_DROP = "ethertype=0x0800,src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,dst_port=443"

def run(pkt):
    cmd = [
        "target/debug/pacgate", "simulate", RULES,
        "--packet", pkt, "--json"
    ]
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)

def main():
    mismatches = 0
    for i in range(1000):
        expected = "pass" if i % 2 == 0 else "drop"
        pkt = PKT_PASS if expected == "pass" else PKT_DROP
        got = run(pkt)["action"]
        if got != expected:
            mismatches += 1
    print(json.dumps({"total": 1000, "mismatches": mismatches}, indent=2))

if __name__ == "__main__":
    main()
```

Run:

```bash
python3 simulator-app/examples/run_1000.py
```

### Error Injection Patterns (File-Driven)

Use packet specs with invalid or adversarial values to test parser and policy boundaries:

- Invalid MAC format
- Out-of-range DSCP/ECN values
- Malformed IPv6 flow label
- Unexpected EtherType for protocol-specific rules

Example:

```bash
target/debug/pacgate simulate rules/examples/l3l4_firewall.yaml \
  --packet "ethertype=0x0800,ip_protocol=6,dst_port=443,tcp_flags=0xFF,tcp_flags_mask=0x00" \
  --json
```

### CI Integration Pattern

Use simulator outputs as machine-readable gates:

1. Run scenario pack.
2. Fail build on mismatch count > 0.
3. Archive JSON results per commit.
4. Compare mismatches across branches for regression detection.
