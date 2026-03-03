# PacGate Workshops & Tutorials

*Hands-on exercises to master PacGate from beginner to advanced.*

---

## Workshop 1: Hello PacGate — Your First Packet Filter (30 min)

### Objective
Build and simulate a single-rule packet filter that allows ARP traffic.

### Prerequisites
- Rust toolchain installed (`cargo --version`)
- PacGate built (`cargo build --release`)

### Steps

#### Step 1: Create Your Rules

```bash
pacgate init workshop1.yaml
cat workshop1.yaml
```

The init command creates a commented starter file. Let's replace it with a minimal filter:

```yaml
# workshop1.yaml — Allow ARP, drop everything else
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

#### Step 2: Validate

```bash
pacgate validate workshop1.yaml
# Output: Valid: 1 rules loaded from workshop1.yaml
```

#### Step 3: Compile

```bash
pacgate compile workshop1.yaml -o workshop1_out/
```

#### Step 4: Inspect Generated Verilog

```bash
cat workshop1_out/rtl/packet_filter_top.v
# Look for: module packet_filter_top, frame_parser, rule_match_0, decision_logic
```

#### Step 5: Inspect Generated Tests

```bash
cat workshop1_out/tb/test_packet_filter.py
# Look for: test_allow_arp, test_default_drop, test_random_packets
```

#### Step 6: Simulate (requires iverilog + cocotb)

```bash
cd workshop1_out/tb && make
# All tests should PASS
```

#### Step 7: Get Resource Estimates

```bash
pacgate estimate workshop1.yaml
# Shows LUTs, FFs, and timing for Artix-7
```

### Challenge
Add a second rule that allows IPv4 (`0x0800`) at priority 90. Recompile and verify both rules pass simulation.

---

## Workshop 2: Enterprise Network Security (45 min)

### Objective
Build a multi-rule enterprise filter with VLAN segmentation, vendor MAC filtering, and protocol allowing.

### Steps

#### Step 1: Design Your Policy

| Policy | Rule | Priority | Action |
|--------|------|----------|--------|
| Block broadcast storms | dst_mac = ff:ff:ff:ff:ff:ff | 200 | drop |
| Allow management VLAN | vlan_id = 100 | 150 | pass |
| Allow ARP | ethertype = 0x0806 | 100 | pass |
| Allow IPv4 | ethertype = 0x0800 | 90 | pass |
| Allow ACME vendor | src_mac = 00:1a:2b:*:*:* | 70 | pass |
| Default | — | — | drop |

#### Step 2: Write the YAML

```yaml
# workshop2.yaml
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

    - name: allow_vendor_acme
      type: stateless
      priority: 70
      match:
        src_mac: "00:1a:2b:*:*:*"
      action: pass
```

#### Step 3: Check for Overlaps

```bash
pacgate validate workshop2.yaml
# Note the overlap warnings — broadcast drop vs allow_arp
# This is intentional: broadcast ARP is dropped (priority 200 > 100)
```

#### Step 4: Compile and Examine

```bash
pacgate compile workshop2.yaml -o workshop2_out/
ls workshop2_out/rtl/
# packet_filter_top.v, frame_parser.v, rule_match_0.v through rule_match_4.v, decision_logic.v
```

#### Step 5: Get Stats

```bash
pacgate stats workshop2.yaml
# Shows: 5 rules, field usage, action balance, priority spacing
```

#### Step 6: Visualize

```bash
pacgate graph workshop2.yaml
# Pipe to Graphviz: pacgate graph workshop2.yaml | dot -Tpng -o workshop2.png
```

#### Step 7: Simulate

```bash
cd workshop2_out/tb && make
# 500 random packets with scoreboard — should be 500/500 match
```

### Challenge
1. Add IPv6 (`0x86DD`) support at priority 80
2. Add a LLDP rule (`0x88CC`) at priority 60
3. Run `pacgate diff workshop2.yaml workshop2_v2.yaml` to see the changes

---

## Workshop 3: Blacklist Mode — Threat Blocking (30 min)

### Objective
Build a blacklist (default-allow) filter that blocks specific threats.

### Steps

#### Step 1: Understand the Difference

| Mode | Default | Philosophy |
|------|---------|-----------|
| Whitelist (`action: drop`) | Block unknown | Explicit allow — more secure |
| Blacklist (`action: pass`) | Allow unknown | Explicit deny — more permissive |

#### Step 2: Write the Blacklist

```yaml
# workshop3.yaml
pacgate:
  version: "1.0"
  defaults:
    action: pass              # Everything allowed unless blocked

  rules:
    - name: block_broadcast
      type: stateless
      priority: 200
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop

    - name: block_stp_bpdu
      type: stateless
      priority: 190
      match:
        dst_mac: "01:80:c2:00:00:00"
      action: drop

    - name: block_eapol
      type: stateless
      priority: 180
      match:
        ethertype: "0x888E"
      action: drop

    - name: block_rogue_vendor
      type: stateless
      priority: 170
      match:
        src_mac: "aa:bb:cc:*:*:*"
      action: drop
```

#### Step 3: Compile and Test

```bash
pacgate compile workshop3.yaml -o workshop3_out/
cd workshop3_out/tb && make
```

#### Step 4: Compare Modes

```bash
# Create a whitelist version of the same policy
# Run diff to see the structural difference
pacgate diff workshop3.yaml rules/examples/enterprise.yaml --json | python3 -m json.tool
```

### Challenge
Add a rule to block Cisco PVST+ (`dst_mac: 01:00:0c:cc:cc:cd`). What priority should it have? Why?

---

## Workshop 4: Industrial OT Security (45 min)

### Objective
Build a safety-critical OT boundary filter protecting industrial control systems.

### Scenario
You're deploying an FPGA filter between the IT network and a factory floor running:
- EtherCAT (0x88A4) — Beckhoff motion controllers
- PROFINET (0x8892) — Siemens PLCs
- PTP/1588 (0x88F7) — Time synchronization
- GOOSE (0x88B8) — IEC 61850 protection relays

### Steps

#### Step 1: Design the Policy

```
IT Network ──── [PacGate Filter] ──── OT Network
                  │
                  │ Allow: EtherCAT, PROFINET, PTP, GOOSE, LLDP, ARP
                  │ Block: Everything else (IPv4, IPv6, HTTP, DNS, etc.)
                  │ Block: IT multicast (mDNS, SSDP)
```

#### Step 2: Write and Compile

Use `rules/examples/industrial_ot.yaml` as reference, or write your own.

```bash
pacgate compile rules/examples/industrial_ot.yaml -o workshop4_out/
pacgate estimate rules/examples/industrial_ot.yaml
```

#### Step 3: Formal Verification

For safety-critical applications, simulation isn't enough. Generate formal proofs:

```bash
pacgate formal rules/examples/industrial_ot.yaml -o workshop4_out/

# Examine generated assertions
cat workshop4_out/formal/assertions.sv
# Look for: p_completeness, p_latency_bound, p_default_action

# Run formal verification (requires SymbiYosys)
cd workshop4_out/formal && sby -f packet_filter.sby
```

#### Step 4: Generate AXI-Stream Version

For FPGA deployment:

```bash
pacgate compile rules/examples/industrial_ot.yaml --axi -o workshop4_out/
ls workshop4_out/rtl/
# Includes: axi_stream_adapter.v, store_forward_fifo.v, packet_filter_axi_top.v
```

### Challenge
Add EtherNet/IP (0x00AF) support for Allen-Bradley PLCs. What priority should it get relative to EtherCAT and PROFINET?

---

## Workshop 5: Stateful Detection — Protocol Sequences (60 min)

### Objective
Build a stateful filter that detects and validates protocol sequences using FSM rules.

### Scenario
A legitimate host performs ARP resolution before sending IPv4 traffic. An attacker might skip ARP and flood the network directly. Use PacGate's FSM to detect legitimate patterns.

### Steps

#### Step 1: Understand Stateful Rules

```
Stateless: Each frame evaluated independently
Stateful:  Tracks sequence across multiple frames

       Frame 1 (ARP)         Frame 2 (IPv4)
           │                      │
    ┌──────▼───────┐       ┌──────▼──────┐
    │    idle      │──────►│  arp_seen   │──────► action: pass
    │              │ ARP   │             │ IPv4
    └──────────────┘       └─────────────┘
                              │ timeout
                              ▼
                           back to idle
                           (default: drop)
```

#### Step 2: Write the Stateful Rule

```yaml
# workshop5.yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    # Stateless: always allow ARP
    - name: allow_arp
      type: stateless
      priority: 200
      match:
        ethertype: "0x0806"
      action: pass

    # Stateful: IPv4 only after ARP
    - name: arp_then_ipv4
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
            timeout_cycles: 5000    # 40 µs at 125 MHz
            transitions:
              - match:
                  ethertype: "0x0800"
                next_state: active
                action: pass
          active:
            timeout_cycles: 10000   # 80 µs keepalive
            transitions:
              - match:
                  ethertype: "0x0800"
                next_state: active
                action: pass
              - match:
                  ethertype: "0x0806"
                next_state: arp_seen
                action: pass
```

#### Step 3: Compile and Examine FSM

```bash
pacgate compile workshop5.yaml -o workshop5_out/
cat workshop5_out/rtl/rule_fsm_*.v
# Look for: state registers, timeout counters, transition logic
```

#### Step 4: Test

```bash
cd workshop5_out/tb && make
```

### Challenge
1. Add a third state `blocked` that activates after 3 consecutive timeouts
2. Add LLDP passthrough as a stateless rule
3. What timeout value would you use for a 10 Gbps link?

---

## Workshop 6: AXI-Stream Integration (45 min)

### Objective
Generate a complete AXI-Stream packet filter ready for FPGA integration.

### Steps

#### Step 1: Compile with AXI

```bash
pacgate compile rules/examples/enterprise.yaml --axi -o workshop6_out/
```

#### Step 2: Examine the AXI Top

```bash
cat workshop6_out/rtl/packet_filter_axi_top.v
```

Key signals:
```verilog
module packet_filter_axi_top #(
    parameter FIFO_DEPTH = 2048,
    parameter MAX_FRAME_SIZE = 1522
) (
    input  wire        clk,
    input  wire        rst,
    // AXI-Stream slave (input)
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,
    // AXI-Stream master (output)
    output wire [7:0]  m_axis_tdata,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,
    // Status
    output wire        decision_valid,
    output wire        decision_pass,
    output wire        fifo_overflow,
    output wire        fifo_empty
);
```

#### Step 3: Simulate AXI

```bash
cd workshop6_out/tb-axi && make
# Tests: passthrough, frame drop, backpressure, burst, reset
```

#### Step 4: Synthesize (optional)

```bash
# If Yosys is installed
make synth RULES=rules/examples/enterprise.yaml
```

#### Step 5: Resource Check

```bash
pacgate estimate rules/examples/enterprise.yaml --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'LUTs: {data[\"total\"][\"luts\"]}')
print(f'FFs: {data[\"total\"][\"ffs\"]}')
print(f'Artix-7 LUT usage: {data[\"total\"][\"luts\"] / 20800 * 100:.1f}%')
"
```

---

## Workshop 7: Rule Management and Change Control (30 min)

### Objective
Learn PacGate's tools for managing rule changes over time.

### Steps

#### Step 1: Create v1 Rules

```bash
cp rules/examples/allow_arp.yaml rules_v1.yaml
```

#### Step 2: Create v2 Rules

```bash
cp rules/examples/enterprise.yaml rules_v2.yaml
```

#### Step 3: Diff the Versions

```bash
pacgate diff rules_v1.yaml rules_v2.yaml
# Shows: added, removed, modified rules

pacgate diff rules_v1.yaml rules_v2.yaml --json | python3 -m json.tool
```

#### Step 4: Estimate Impact

```bash
pacgate estimate rules_v1.yaml
pacgate estimate rules_v2.yaml
# Compare: how many more LUTs does v2 need?
```

#### Step 5: Stats Comparison

```bash
pacgate stats rules_v1.yaml
pacgate stats rules_v2.yaml
# Compare: field usage, action balance, priority spacing
```

#### Step 6: Visual Diff

```bash
pacgate graph rules_v1.yaml | dot -Tpng -o v1.png
pacgate graph rules_v2.yaml | dot -Tpng -o v2.png
# Compare the two graphs visually
```

---

## Workshop 8: CI/CD Pipeline for Hardware Filters (45 min)

### Objective
Set up a continuous integration pipeline that validates every rule change.

### Steps

#### Step 1: Validation Gate

```bash
#!/bin/bash
# ci/validate.sh — Run on every PR
set -e
for f in rules/examples/*.yaml; do
    echo "Validating $f..."
    pacgate validate "$f" --json | jq -e '.status == "valid"' > /dev/null
done
echo "All rules valid"
```

#### Step 2: Resource Budget Gate

```bash
#!/bin/bash
# ci/budget_check.sh — Fail if over budget
MAX_LUTS=5000
for f in rules/examples/*.yaml; do
    luts=$(pacgate estimate "$f" --json | jq '.total.luts')
    if [ "$luts" -gt "$MAX_LUTS" ]; then
        echo "FAIL: $f uses $luts LUTs (budget: $MAX_LUTS)"
        exit 1
    fi
done
```

#### Step 3: Regression Test

```bash
#!/bin/bash
# ci/regression.sh — Compile + simulate all examples
set -e
for f in rules/examples/*.yaml; do
    name=$(basename "$f" .yaml)
    echo "Testing $name..."
    pacgate compile "$f" -o "gen_${name}/"
    # Run simulation if iverilog is available
    if command -v iverilog &> /dev/null; then
        cd "gen_${name}/tb" && make && cd ../..
    fi
done
```

#### Step 4: Change Detection

```bash
#!/bin/bash
# ci/change_detect.sh — Report what changed in a PR
OLD_RULES="main:rules/examples/enterprise.yaml"
NEW_RULES="rules/examples/enterprise.yaml"

# Extract old version from main branch
git show "$OLD_RULES" > /tmp/old_rules.yaml 2>/dev/null || exit 0

# Diff
pacgate diff /tmp/old_rules.yaml "$NEW_RULES" --json
```

---

## Workshop 9: System Simulation Regression Lab (45 min)

### Objective
Build a repeatable, Python-driven system simulation flow for 1000+ packets, expected/actual action diffs, and error injection.

### Steps

#### Step 1: Build PacGate and Start Simulator UI

```bash
cargo build
python3 simulator-app/server.py
```

Open `http://127.0.0.1:8787`.

#### Step 2: Run a Built-In Scenario with Diff View

In the UI:

1. Select `allow_arp_then_drop_ipv4`.
2. Click `Run Scenario`.
3. Check `Scenario Diff` and confirm mismatch count is `0`.

#### Step 3: Create and Save a Custom Scenario

Use `Custom Scenario Editor` and paste events like:

```json
[
  {
    "name": "Expected ARP pass",
    "packet": {
      "ethertype": "0x0806",
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "ff:ff:ff:ff:ff:ff"
    },
    "expected_action": "pass"
  },
  {
    "name": "Intentional mismatch",
    "packet": {
      "ethertype": "0x0800",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "ip_protocol": 6,
      "dst_port": 443
    },
    "expected_action": "pass"
  }
]
```

Save, run, and verify mismatch count is `1`.

#### Step 4: Run 1000-Packet Python Regression

```bash
python3 simulator-app/examples/run_1000.py \
  --rules rules/examples/allow_arp.yaml \
  --count 1000
```

Expected output:

```json
{
  "rules": "rules/examples/allow_arp.yaml",
  "count": 1000,
  "mismatches": 0,
  "elapsed_sec": 1.234,
  "packets_per_sec": 810.37
}
```

#### Step 5: Add Error Injection Cases

Run malformed/edge packet specs directly:

```bash
target/debug/pacgate simulate rules/examples/l3l4_firewall.yaml \
  --packet "ethertype=0x0800,ip_protocol=6,dst_port=443,tcp_flags=0xFF,tcp_flags_mask=0x00" \
  --json
```

Add these cases into your custom scenario JSON and set expected actions.

#### Step 6: Gate in CI

Use this pattern in a CI step:

```bash
python3 simulator-app/examples/run_1000.py --count 1000 > sim_result.json
python3 -c "import json; d=json.load(open('sim_result.json')); assert d['mismatches']==0, d"
```

### Outcome

You now have:

1. A web UI flow for scenario authoring and diff analysis.
2. A scriptable high-volume regression path.
3. A practical bridge between policy validation and system-level traffic testing.

---

## Workshop 10: Two-RMAC Switch Topology Lab (60 min)

### Objective
Run a system-level topology simulation with two RMAC endpoints and an L3 switch model that tracks:

1. RMAC error/drop counts
2. PacGate policy decisions
3. Switch forward/drop counts and drop reasons

### Steps

#### Step 1: Build PacGate

```bash
cargo build
```

#### Step 2: Validate Scenario v2

```bash
python3 simulator-app/tools/paclab_validate.py \
  docs/management/paclab/scenario_v2.example.json --json
```

#### Step 3: Run Topology Scenario

```bash
python3 simulator-app/tools/run_topology.py \
  docs/management/paclab/scenario_v2.example.json \
  --bin target/debug/pacgate \
  --output topology_result.json
```

#### Step 4: Inspect Counters

```bash
python3 - <<'PY'
import json
d = json.load(open('topology_result.json'))
print(json.dumps(d['stats'], indent=2))
print('mismatch_count =', d['mismatch_count'])
PY
```

#### Step 5: Add a Drop-Mode Test

Edit the scenario and add an event where destination IP has no matching egress subnet.  
Expected outcome: `expected_switch_action: drop` and drop reason `no_route`.

### Outcome

You now have a practical model for the "network switch between RMACs" request that can be run in CI and expanded into RTL/HIL phases later.
