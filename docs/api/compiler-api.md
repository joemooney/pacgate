# Flippy Compiler API Reference

**Document ID**: FLIP-API-001
**Version**: 2.0
**Date**: 2026-02-26

---

## CLI Interface

### `flippy compile <rules>`

Compiles YAML rules into Verilog RTL and cocotb test harness.

**Arguments**:
| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rules` | Path | Yes | — | Path to YAML rules file |
| `-o, --output` | Path | No | `gen` | Output directory |
| `-t, --templates` | Path | No | `templates` | Templates directory |

**Output files**:
```
<output>/
├── rtl/
│   ├── packet_filter_top.v    # Top-level module
│   ├── decision_logic.v       # Priority encoder
│   ├── rule_match_0.v         # Per-rule matcher (stateless)
│   ├── rule_match_1.v         # Per-rule matcher (or FSM)
│   └── ...
└── tb/
    ├── test_packet_filter.py  # cocotb test harness
    └── Makefile               # Simulation build
```

**Exit codes**:
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | YAML parse error |
| 1 | Validation error (duplicate priority, bad MAC, etc.) |
| 1 | Template rendering error |

### `flippy validate <rules>`

Validates YAML rules without generating output.

**Arguments**:
| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `rules` | Path | Yes | Path to YAML rules file |

---

## Internal Modules

### `model.rs` — Data Model

**Key types**:
| Type | Description |
|------|-------------|
| `FilterConfig` | Top-level: `{ flippy: FlippyConfig }` |
| `FlippyConfig` | `{ version, defaults, rules }` |
| `Defaults` | `{ action: Action }` |
| `StatelessRule` | `{ name, priority, match_criteria, action, rule_type, fsm }` |
| `MatchCriteria` | `{ dst_mac, src_mac, ethertype, vlan_id, vlan_pcp }` |
| `FsmDefinition` | `{ initial_state, states }` |
| `FsmState` | `{ timeout_cycles, transitions }` |
| `FsmTransition` | `{ match_criteria, next_state, action }` |
| `Action` | Enum: `Pass`, `Drop` |
| `MacAddress` | Parsed MAC with `value[6]` and `mask[6]` |

### `loader.rs` — YAML Loading

**Function**: `load_rules(path: &Path) -> Result<FilterConfig>`

Validates:
- At least one rule defined
- Unique priorities
- Valid MAC format (6 colon-separated hex octets or `*`)
- Valid EtherType format (`0xNNNN`)
- VLAN PCP range 0-7
- FSM states form connected graph
- FSM transitions reference valid states

### `verilog_gen.rs` — Verilog Generation

**Function**: `generate(config, templates_dir, output_dir) -> Result<()>`

For each rule (sorted by priority, highest first):
- **Stateless**: Renders `rule_match.v.tera` with condition expression
- **Stateful**: Renders `rule_fsm.v.tera` with state machine definition

Also generates `decision_logic.v` and `packet_filter_top.v`.

### `cocotb_gen.rs` — Test Generation

**Function**: `generate(config, templates_dir, output_dir) -> Result<()>`

Generates:
- Per-rule directed tests (positive match)
- Default action test (negative)
- Constrained random test with scoreboard
- Corner case tests (jumbo, runt, back-to-back, reset)
- Scoreboard rule definitions for reference model
- Coverage model configuration

---

## Verification Framework API

### `verification.packet`

| Class/Function | Description |
|---------------|-------------|
| `EthernetFrame` | Frame data class with `to_bytes()` serialization |
| `VlanTag` | 802.1Q VLAN tag data class |
| `PacketFactory` | Factory methods: `arp()`, `ipv4()`, `ipv6()`, `vlan_tagged()`, `broadcast()`, `random_frame()`, `runt_frame()`, `jumbo_frame()` |
| `mac_to_bytes(str)` | Convert `"aa:bb:cc:dd:ee:ff"` to bytes |
| `mac_matches(bytes, str)` | Check MAC against pattern with wildcards |

### `verification.scoreboard`

| Class | Description |
|-------|-------------|
| `Rule` | Rule definition with `matches(frame)` method |
| `PacketFilterScoreboard` | Reference model: `predict(frame)` → action, `check(frame, result)` |
| `ScoreboardMismatch` | Exception with detailed mismatch info |
| `ScoreboardStats` | Statistics tracking |

### `verification.coverage`

| Class | Description |
|-------|-------------|
| `FilterCoverage` | Coverage collector with `sample()` and `report()` |
| `CoverPoint` | Individual cover point with bins |
| `CoverBin` | Single bin with hit tracking |

### `verification.driver`

| Class | Description |
|-------|-------------|
| `PacketDriver` | BFM: `send(frame)`, `send_burst()`, `reset()` |
| `DecisionMonitor` | Captures `decision_valid`/`decision_pass` |
