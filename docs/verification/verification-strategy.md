# PacGate Verification Strategy

**Document ID**: PG-VS-001
**Version**: 2.0
**Date**: 2026-02-26
**Status**: Approved

---

## 1. Verification Philosophy

PacGate employs a **multi-layered verification strategy** inspired by industry UVM methodology but implemented in Python/cocotb for accessibility and auto-generation:

```
    Layer 4: System-Level (Integration with real network stacks)
         ▲
    Layer 3: Regression + Coverage Closure
         ▲
    Layer 2: Constrained Random + Scoreboard
         ▲
    Layer 1: Directed Tests (auto-generated from YAML)
         ▲
    Layer 0: Formal Properties (SVA / SymbiYosys)
```

**Key Innovation**: Layers 1-3 are **auto-generated** from the YAML rule specification. The test harness isn't just a set of tests — it's a complete verification environment that adapts to any rule configuration.

## 2. Verification Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    cocotb Test Environment                       │
│                                                                  │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────────────┐     │
│  │  Test      │  │  Constrained │  │  Sequence             │     │
│  │  Scenarios │  │  Random      │  │  Library              │     │
│  │            │  │  Generator   │  │  (temporal patterns)  │     │
│  └─────┬──────┘  └──────┬───────┘  └────────────┬──────────┘     │
│        │                │                       │                │
│        └────────────────┼───────────────────────┘                │
│                         │                                        │
│                  ┌──────▼───────┐                                │
│                  │   Driver     │  Converts packets to           │
│                  │   (BFM)      │  pkt_data/valid/sof/eof        │
│                  └──────┬───────┘                                │
│                         │                                        │
│  ┌──────────────────────┼──────────────────────────────────────┐ │
│  │          ┌───────────▼───────────┐                          │ │
│  │          │  packet_filter_top    │  (DUT)                   │ │
│  │          │  ┌─────────────────┐  │                          │ │
│  │          │  │  frame_parser   │  │                          │ │
│  │          │  │  rule_match_*   │  │                          │ │
│  │          │  │  decision_logic │  │                          │ │
│  │          │  └─────────────────┘  │                          │ │
│  │          └───────────┬───────────┘                          │ │
│  └──────────────────────┼──────────────────────────────────────┘ │
│                         │                                        │
│                  ┌──────▼───────┐                                │
│                  │   Monitor    │  Captures decision outputs     │
│                  └──┬───────┬───┘                                │
│                     │       │                                    │
│            ┌────────▼──┐ ┌──▼──────────┐                         │
│            │Scoreboard │ │  Coverage   │                         │
│            │(reference │ │  Collector  │                         │
│            │ model)    │ │             │                         │
│            └────────┬──┘ └──────┬──────┘                         │
│                     │           │                                │
│              ┌──────▼───────────▼──────┐                         │
│              │    Report Generator     │                         │
│              │  (pass/fail + coverage) │                         │
│              └─────────────────────────┘                         │
└──────────────────────────────────────────────────────────────────┘
```

## 3. Verification Layers

### Layer 0: Formal Properties

Formal verification provides **mathematical proof** of correctness for critical properties.

**Properties verified**:
| Property | Description | Method |
|----------|-------------|--------|
| No simultaneous pass+drop | `decision_pass` and `!decision_pass` are mutually exclusive when `decision_valid` | Assertion |
| Decision within N cycles | After `fields_valid`, `decision_valid` asserts within 2 clock cycles | Bounded liveness |
| Reset clears all state | After `rst_n` deasserts, all outputs are 0 until first frame | Assertion |
| One decision per frame | `decision_valid` asserts exactly once between `pkt_sof` events | Counter check |
| Parser completeness | Every frame that enters `S_DST_MAC` eventually reaches `S_PAYLOAD` or `S_IDLE` | Liveness |

**Tool**: SymbiYosys (open-source formal verification for Verilog)

### Layer 1: Directed Tests (Auto-Generated)

For every rule in the YAML spec, the compiler generates:

1. **Positive match test**: A packet that should trigger this rule
2. **Negative/default test**: A packet that should NOT match any rule
3. **Boundary tests**: Edge cases for the specific match fields

```
Rule: allow_arp (ethertype: 0x0806, action: pass)
  ├── test_allow_arp_match:     EtherType=0x0806 → expect PASS
  ├── test_default_action:      EtherType=0x88B5 → expect DROP (default)
  └── test_allow_arp_boundary:  EtherType=0x0805 → expect DROP (off-by-one)
```

**Auto-generation guarantee**: If it's in the YAML, it has a test. No exceptions.

### Layer 2: Constrained Random Verification

The **constrained random generator** creates thousands of random packets with controlled properties:

```python
class PacketConstraints:
    """Define the space of valid test packets."""

    # Constrained fields
    ethertype_weights = {
        0x0800: 30,   # IPv4 (common)
        0x0806: 20,   # ARP (rule target)
        0x86DD: 15,   # IPv6
        0x8100: 10,   # VLAN-tagged
        "random": 25,  # Fully random
    }

    mac_strategies = [
        "broadcast",    # ff:ff:ff:ff:ff:ff
        "multicast",    # bit 0 of first octet set
        "unicast",      # normal unicast
        "specific",     # from rule spec
        "random",       # fully random
    ]
```

**Why constrained random beats directed testing**:
- Explores **corner cases** humans don't think of
- Finds **interaction bugs** between rules
- Achieves **higher coverage** with less manual effort
- Discovers **protocol edge cases** (runt frames, VLAN double-tags, etc.)

### Layer 3: Coverage-Driven Closure

Coverage collection tracks **what has been verified**:

```
┌─────────────────────────────────────────────────────┐
│              Coverage Dashboard                     │
│                                                     │
│  Functional Coverage                                │
│  ├── Rule hit coverage:       ████████████░░  85%   │
│  ├── EtherType cross:         ██████████████  100%  │
│  ├── MAC pattern coverage:    ████████░░░░░░  60%   │
│  ├── VLAN tag coverage:       ██████████████  100%  │
│  ├── Priority overlap:        ████████████░░  90%   │
│  └── Default action:          ██████████████  100%  │
│                                                     │
│  Corner Case Coverage                               │
│  ├── Runt frame (<64B):       ██████████████  100%  │
│  ├── Jumbo frame (>1518B):    ██████████████  100%  │
│  ├── Back-to-back frames:     ████████████░░  85%   │
│  ├── Reset during frame:      ██████████████  100%  │
│  └── All-zeros frame:         ██████████████  100%  │
│                                                     │
│  Overall: ████████████░░░  88%                      │
│  Target:  ████████████████ 95%                      │
└─────────────────────────────────────────────────────┘
```

**Coverage types**:
1. **Rule hit coverage**: Has every rule been triggered at least once?
2. **Cross coverage**: Has every rule been tested with every MAC pattern type?
3. **Transition coverage**: Has every FSM state transition been exercised?
4. **Boundary coverage**: Have all field boundary values been tested?
5. **Error coverage**: Have all error conditions been injected?

### Layer 4: System-Level Integration

Integration with real network tools:
- **Scapy**: Generate realistic packet captures
- **tcpreplay**: Replay pcap files through the filter
- **Wireshark**: Inspect waveform-correlated packet data

## 4. Reference Model (Scoreboard)

The scoreboard implements the **same rule matching logic in Python** as a reference model:

```python
class PacketFilterScoreboard:
    """Golden reference model for packet filter decisions."""

    def __init__(self, rules, default_action):
        self.rules = sorted(rules, key=lambda r: -r.priority)
        self.default_action = default_action

    def predict(self, packet):
        """Predict the expected decision for a packet."""
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action
        return self.default_action

    def check(self, packet, actual_decision):
        """Compare DUT decision against reference model."""
        expected = self.predict(packet)
        if actual_decision != expected:
            raise ScoreboardMismatch(packet, expected, actual_decision)
```

**Critical insight**: The scoreboard is **also generated from the YAML spec**, so it's guaranteed to match the hardware. Three independent implementations agree:
1. Verilog RTL (the DUT)
2. Python scoreboard (the reference model)
3. YAML spec (the source of truth)

## 5. Test Categories

| Category | Method | Count | Auto-Generated? |
|----------|--------|-------|-----------------|
| Directed per-rule | cocotb test per rule | N per rule | Yes |
| Boundary | Off-by-one for each field | 2-4 per field | Yes |
| Constrained random | Random within constraints | 1000+ | Yes |
| Corner case | Runt frames, resets, back-to-back | ~20 fixed | Yes |
| Regression | Full suite | All above | Yes |
| Formal | Property proofs | ~10 properties | Template |
| Integration | Scapy/pcap replay | User-defined | No |

## 6. Metrics and Reporting

Every simulation run produces:
1. **Test results** (pass/fail with details)
2. **Functional coverage** (percentage with uncovered bins)
3. **Waveform dump** (FST format for GTKWave)
4. **Performance metrics** (simulation throughput, DUT latency)
5. **Regression trend** (coverage over time, new failures)

## 7. Continuous Integration

```yaml
# .github/workflows/verify.yml
on: [push, pull_request]
jobs:
  verify:
    steps:
      - cargo build              # Compile pacgate
      - pacgate compile rules.yaml # Generate RTL + tests
      - iverilog lint             # Static analysis
      - make sim                  # Run cocotb
      - coverage report           # Check coverage targets
      - formal check              # Run SymbiYosys (optional)
```

**Coverage gates**: PRs cannot merge if functional coverage drops below 90%.
