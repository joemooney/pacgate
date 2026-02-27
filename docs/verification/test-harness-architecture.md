# PacGate Test Harness Architecture

**Document ID**: PG-THA-001
**Version**: 2.0
**Date**: 2026-02-26
**Status**: Approved

---

## 1. Overview

The PacGate test harness is **auto-generated from the same YAML specification** as the hardware. It implements a UVM-inspired verification architecture in Python/cocotb with five major subsystems:

```
┌──────────────────────────────────────────────────────────────────────┐
│                     PacGate Verification Environment                 │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      Test Layer                                 │ │
│  │  ┌──────────┐  ┌──────────────┐  ┌───────────────────────────┐  │ │
│  │  │ Directed │  │ Constrained  │  │ Property-Based            │  │ │
│  │  │ Tests    │  │ Random       │  │ Tests (Hypothesis)        │  │ │
│  │  │ (per     │  │ Generator    │  │                           │  │ │
│  │  │  rule)   │  │ (cocotb-cov) │  │ • Determinism             │  │ │
│  │  └────┬─────┘  └──────┬───────┘  │ • Termination             │  │ │
│  │       │               │          │ • Priority correctness    │  │ │
│  │       └───────┬───────┘          └────────────┬──────────────┘  │ │
│  └───────────────┼───────────────────────────────┼─────────────────┘ │
│                  │                               │                   │
│  ┌───────────────▼───────────────────────────────▼─────────────────┐ │
│  │                    Stimulus Layer                               │ │
│  │                                                                 │ │
│  │  ┌────────────────────┐    ┌──────────────────────────────┐     │ │
│  │  │  Packet Factory    │    │  Sequence Library            │     │ │
│  │  │                    │    │                              │     │ │
│  │  │ • Ethernet builder │    │ • Single frame               │     │ │
│  │  │ • VLAN builder     │    │ • Back-to-back burst         │     │ │
│  │  │ • Random fields    │    │ • Reset-during-frame         │     │ │
│  │  │ • Scapy import     │    │ • Interleaved protocols      │     │ │
│  │  └─────────┬──────────┘    │ • Runt/jumbo frames          │     │ │
│  │            │               └──────────────┬───────────────┘     │ │
│  └────────────┼──────────────────────────────┼─────────────────────┘ │
│               │                              │                       │
│  ┌────────────▼──────────────────────────────▼─────────────────────┐ │
│  │                    Driver Layer (BFM)                           │ │
│  │                                                                 │ │
│  │  ┌─────────────────────────────────────────────────────────┐    │ │
│  │  │  PacketDriver                                           │    │ │
│  │  │  • Converts frame bytes to pkt_data/valid/sof/eof       │    │ │
│  │  │  • Configurable inter-frame gap                         │    │ │
│  │  │  • Error injection: runt frames, mid-frame abort        │    │ │
│  │  └─────────────────────────┬───────────────────────────────┘    │ │
│  └────────────────────────────┼────────────────────────────────────┘ │
│                               │                                      │
│              ┌────────────────▼────────────────┐                     │
│              │     packet_filter_top (DUT)     │                     │
│              └────────────────┬────────────────┘                     │
│                               │                                      │
│  ┌────────────────────────────▼────────────────────────────────────┐ │
│  │                    Monitor Layer                                │ │
│  │                                                                 │ │
│  │  ┌──────────────────┐  ┌───────────────────────────────┐        │ │
│  │  │ DecisionMonitor  │  │ InternalMonitor               │        │ │
│  │  │                  │  │                               │        │ │
│  │  │ • Captures       │  │ • fields_valid timing         │        │ │
│  │  │   decision_valid │  │ • Parser state transitions    │        │ │
│  │  │   decision_pass  │  │ • Per-rule match_hit signals  │        │ │
│  │  │ • Timestamps     │  │ • Latency measurement         │        │ │
│  │  └────────┬─────────┘  └───────────────┬───────────────┘        │ │
│  └───────────┼────────────────────────────┼────────────────────────┘ │
│              │                            │                          │
│  ┌───────────▼────────────────────────────▼────────────────────────┐ │
│  │                    Checking Layer                               │ │
│  │                                                                 │ │
│  │  ┌──────────────────────┐  ┌──────────────────────────────┐     │ │
│  │  │  Scoreboard          │  │  Coverage Collector          │     │ │
│  │  │                      │  │                              │     │ │
│  │  │  Python reference    │  │  • Rule hit coverage         │     │ │
│  │  │  model evaluates     │  │  • Field value bins          │     │ │
│  │  │  same rules as HDL   │  │  • Cross coverage            │     │ │
│  │  │                      │  │  • Corner case tracking      │     │ │
│  │  │  Expected vs actual  │  │  • Coverage-driven feedback  │     │ │
│  │  │  comparison          │  │    to random generator       │     │ │
│  │  └──────────────────────┘  └──────────────────────────────┘     │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    Reporting Layer                              │ │
│  │  • JUnit XML (CI integration)                                   │ │
│  │  • Coverage report (text + HTML)                                │ │
│  │  • Waveform dump (FST for GTKWave)                              │ │
│  │  • Scoreboard mismatch log                                      │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Component Details

### 2.1 Packet Factory

The Packet Factory constructs Ethernet frames for testing. It supports both directed (specific field values) and random (constrained) construction:

```python
class EthernetFrame:
    dst_mac: bytes      # 6 bytes
    src_mac: bytes      # 6 bytes
    ethertype: int      # 16-bit
    vlan_tag: Optional[VlanTag]
    payload: bytes      # 46-1500 bytes

class VlanTag:
    pcp: int            # 3-bit (0-7)
    dei: int            # 1-bit
    vid: int            # 12-bit (0-4095)

class PacketFactory:
    @staticmethod
    def arp(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01") -> EthernetFrame

    @staticmethod
    def ipv4(dst="de:ad:be:ef:00:01", src="02:00:00:00:00:01") -> EthernetFrame

    @staticmethod
    def vlan_tagged(vid, pcp=0, inner_ethertype=0x0800) -> EthernetFrame

    @staticmethod
    def random(constraints=None) -> EthernetFrame

    @staticmethod
    def from_scapy(pkt) -> EthernetFrame  # Import from scapy
```

### 2.2 Constrained Random Generator

Uses `cocotb-coverage` Randomized class for weighted random generation:

```python
class RandomPacket(Randomized):
    def __init__(self, rules):
        super().__init__()
        self.ethertype = 0
        self.dst_mac = bytes(6)
        self.src_mac = bytes(6)

        # Weight ethertypes toward rule-relevant values
        rule_ethertypes = [r.ethertype for r in rules if r.ethertype]
        self.add_rand("ethertype",
                      list(range(0x0600, 0xFFFF)),
                      weights={et: 10 for et in rule_ethertypes})

        self.add_rand("dst_mac_type",
                      ["broadcast", "multicast", "unicast", "specific"],
                      weights={"specific": 5, "unicast": 3})
```

### 2.3 Scoreboard (Reference Model)

The scoreboard re-implements the filter logic in Python as a golden reference:

```python
class PacketFilterScoreboard:
    def __init__(self, rules, default_action):
        # Sort by priority (highest first) — same as hardware
        self.rules = sorted(rules, key=lambda r: -r.priority)
        self.default_action = default_action
        self.match_count = defaultdict(int)
        self.mismatch_count = 0

    def predict(self, frame: EthernetFrame) -> str:
        for rule in self.rules:
            if self._matches(rule, frame):
                self.match_count[rule.name] += 1
                return rule.action
        self.match_count["__default__"] += 1
        return self.default_action

    def check(self, frame, actual_pass):
        expected = self.predict(frame)
        expected_pass = (expected == "pass")
        if actual_pass != expected_pass:
            self.mismatch_count += 1
            raise ScoreboardMismatch(frame, expected, actual_pass)
```

### 2.4 Coverage Collector

Auto-generated from YAML rules:

```python
class FilterCoverage:
    """Auto-generated coverage model.

    For each rule in the YAML, generates:
    - A cover point for the rule being hit
    - Cover points for each match field's value bins
    - Cross coverage between rules and actions
    """

    def sample(self, frame, decision, matched_rule):
        # Sample all cover points
        self._sample_ethertype(frame.ethertype)
        self._sample_mac_type(frame.dst_mac)
        self._sample_decision(decision)
        self._sample_rule_hit(matched_rule)

        # Sample cross coverage
        self._sample_ethertype_x_decision(frame.ethertype, decision)
        self._sample_rule_x_action(matched_rule, decision)

    def report(self) -> str:
        """Generate coverage summary."""
        ...

    def coverage_percent(self) -> float:
        """Overall functional coverage percentage."""
        ...
```

## 3. Auto-Generation Strategy

Every component above is **template-generated** from the YAML spec:

| Component | What's Generated | Template |
|-----------|-----------------|----------|
| Directed tests | One test per rule (positive + negative) | `test_harness.py.tera` |
| Random generator | Constraint weights from rule field values | `verification/random_gen.py.tera` |
| Scoreboard | Rule matching logic in Python | `verification/scoreboard.py.tera` |
| Coverage model | Cover points for each rule's match fields | `verification/coverage.py.tera` |
| Report | HTML coverage dashboard | `verification/report.py.tera` |

### What This Means

When you change a rule in YAML and recompile:
1. The Verilog filter logic changes
2. The directed tests update to match
3. The random generator re-weights toward new patterns
4. The scoreboard reference model updates
5. The coverage model adds/removes bins

**All automatically. Zero manual test maintenance.**

## 4. Test Categories Generated

### 4.1 Per-Rule Directed Tests

For each rule, generate:
- **Positive match**: A frame that triggers this specific rule
- **Boundary**: Off-by-one values for each match field
- **Near-miss**: Frames that almost match but don't (e.g., wrong last MAC octet)

### 4.2 Multi-Rule Interaction Tests

- **Priority test**: Two rules match; verify higher priority wins
- **Shadow test**: Verify lower-priority rules still work when higher don't match
- **Exhaustive**: For N rules, generate N+1 tests (each rule + default)

### 4.3 Constrained Random Suite

- **1,000 packets minimum** per regression
- **Weighted toward rule-relevant values** (70% rule-matching, 30% random)
- **Coverage-driven feedback** targets uncovered bins
- **Scoreboard checks every packet**

### 4.4 Corner Case Suite

Auto-generated corner cases:
| Test | Description | Why |
|------|-------------|-----|
| Runt frame | <14 bytes | Parser robustness |
| Jumbo frame | >1518 bytes | Large frame handling |
| Min frame | Exactly 64 bytes | Boundary |
| Back-to-back | No gap between frames | Stress |
| Reset mid-frame | Assert reset during parsing | Recovery |
| Valid gap | Deassert pkt_valid mid-frame | Pause handling |
| All-zero | 0x00 in every field | Zero-init bugs |
| All-FF | 0xFF in every field | Broadcast + max values |
| SOF without EOF | New frame before previous ends | Error recovery |
| Double VLAN | Q-in-Q tagged frame | Parser edge case |

### 4.5 Endurance Tests

- **10,000 frame soak test**: Continuous random frames, no resets
- **Memory leak check**: Verify no state accumulation over time
- **Throughput measurement**: Frames per second at various sizes

## 5. Error Injection

The driver supports intentional error injection to verify robustness:

```python
class PacketDriver:
    async def send_with_error(self, frame, error_type):
        match error_type:
            case "runt":
                # Send only first 8 bytes
                await self._send_partial(frame, 8)
            case "abort":
                # Deassert valid mid-frame
                await self._send_with_gap(frame, gap_at=7)
            case "double_sof":
                # Send SOF without completing previous frame
                await self._send_overlapping(frame)
            case "no_eof":
                # Send frame without EOF pulse
                await self._send_no_eof(frame)
```

## 6. Integration Points

### 6.1 CI Pipeline

```
Push ──▶ Build ──▶ Compile Rules ──▶ Lint ──▶ Simulate ──▶ Coverage ──▶ Report
                                                │
                                         ┌──────┴──────┐
                                         │  JUnit XML  │
                                         │  Coverage % │
                                         │  Waveforms  │
                                         └─────────────┘
```

### 6.2 Waveform Integration

All simulations dump FST waveforms. Key signals:
- `pkt_data`, `pkt_valid`, `pkt_sof`, `pkt_eof` — input stimulus
- `fields_valid` — parser completion
- `match_hit_N` — per-rule match signals
- `decision_valid`, `decision_pass` — output decision

### 6.3 Formal Verification (Future)

Generated SVA assertions can be verified by SymbiYosys independently of cocotb simulation, providing a second verification methodology from the same YAML spec.
