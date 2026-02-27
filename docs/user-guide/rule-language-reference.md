# PacGate Rule Language Reference

**Document ID**: PG-UG-002
**Version**: 2.0
**Date**: 2026-02-26

---

## 1. File Format

PacGate rules are defined in YAML format. Every rule file must have the following top-level structure:

```yaml
pacgate:
  version: "1.0"          # Required: schema version
  defaults:                # Required: default behavior
    action: drop           # Required: "pass" or "drop"
  rules:                   # Required: list of rules (at least 1)
    - name: rule_name
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
```

## 2. Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pacgate.version` | String | Yes | Schema version, must be `"1.0"` |
| `pacgate.defaults.action` | String | Yes | `"pass"` or `"drop"` — action when no rule matches |
| `pacgate.rules` | List | Yes | List of rule objects (minimum 1) |

## 3. Rule Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Unique identifier. Pattern: `^[a-z_][a-z0-9_]*$` |
| `type` | String | No | `"stateless"` (default) or `"stateful"` |
| `priority` | Integer | Yes | 0-65535. Higher number = higher priority. Must be unique. |
| `match` | Object | Yes* | Field matching criteria (*required for stateless rules) |
| `action` | String | Yes* | `"pass"` or `"drop"` (*required for stateless rules) |
| `fsm` | Object | No | Finite state machine definition (stateful rules only) |

## 4. Match Fields

### 4.1 `ethertype` — EtherType Matching

**Format**: Hex string `"0xNNNN"`

```yaml
match:
  ethertype: "0x0806"    # ARP
```

**Common values**:
| EtherType | Protocol |
|-----------|----------|
| `0x0800` | IPv4 |
| `0x0806` | ARP |
| `0x8100` | 802.1Q VLAN tag |
| `0x86DD` | IPv6 |
| `0x88CC` | LLDP |
| `0x88F7` | PTP (Precision Time Protocol) |
| `0x8847` | MPLS unicast |

**Hardware implementation**: 16-bit comparator

### 4.2 `dst_mac` — Destination MAC Address

**Format**: Colon-separated hex string with optional `*` wildcards

```yaml
match:
  dst_mac: "ff:ff:ff:ff:ff:ff"    # Exact: broadcast
  dst_mac: "01:00:5e:*:*:*"      # Wildcard: IPv4 multicast OUI
  dst_mac: "*:*:*:*:*:*"          # Match all (not useful alone)
```

**Wildcard behavior**: Each `*` octet matches any value (generates mask `0x00` for that byte).

**Hardware implementation**: `(dst_mac & mask) == value` — 48-bit AND + compare

### 4.3 `src_mac` — Source MAC Address

Same format and behavior as `dst_mac`:

```yaml
match:
  src_mac: "00:1a:2b:*:*:*"      # Match vendor OUI 00:1a:2b
```

### 4.4 `vlan_id` — VLAN Identifier

**Format**: Integer 0-4095

```yaml
match:
  vlan_id: 100                     # Management VLAN
```

**Note**: Only matches if the frame has an 802.1Q tag (EtherType 0x8100).

**Hardware implementation**: 12-bit comparator, gated by `vlan_valid`

### 4.5 `vlan_pcp` — VLAN Priority Code Point

**Format**: Integer 0-7

```yaml
match:
  vlan_pcp: 7                      # Highest priority (network control)
```

**PCP values** (IEEE 802.1p):
| PCP | Priority | Traffic Type |
|-----|----------|-------------|
| 0 | Best Effort | Default |
| 1 | Background | Bulk data |
| 2 | Excellent Effort | Critical apps |
| 3 | Critical Applications | Signaling |
| 4 | Video | < 100ms latency |
| 5 | Voice | < 10ms latency |
| 6 | Internetwork Control | Routing |
| 7 | Network Control | Highest |

### 4.6 Combining Match Fields

Multiple fields in a single `match` block are **ANDed** together:

```yaml
match:
  ethertype: "0x0800"             # IPv4
  src_mac: "00:1a:2b:*:*:*"      # AND from this vendor
  vlan_id: 100                     # AND on VLAN 100
```

This matches frames that are IPv4 **AND** from vendor 00:1a:2b **AND** on VLAN 100.

### 4.7 Match-All Rule

A rule with no match fields (or all wildcards) matches every frame:

```yaml
- name: catch_all
  priority: 1                      # Lowest priority
  match: {}                        # Matches everything
  action: drop
```

## 5. Stateful FSM Rules (Phase 3)

Stateful rules define a finite state machine that tracks packet sequences:

```yaml
- name: arp_then_ip
  type: stateful
  priority: 50
  fsm:
    initial_state: idle
    states:
      idle:
        transitions:
          - match: { ethertype: "0x0806" }
            next_state: arp_seen
            action: pass
      arp_seen:
        timeout_cycles: 1000000    # ~10ms at 100MHz
        transitions:
          - match: { ethertype: "0x0800" }
            next_state: idle
            action: pass
```

### FSM Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fsm.initial_state` | String | Yes | Starting state name |
| `fsm.states` | Map | Yes | State definitions |
| `fsm.states.<name>.timeout_cycles` | Integer | No | Clock cycles before timeout |
| `fsm.states.<name>.transitions` | List | Yes | Transition rules |
| `fsm.states.<name>.transitions[].match` | Object | Yes | Same match fields as stateless |
| `fsm.states.<name>.transitions[].next_state` | String | Yes | Target state |
| `fsm.states.<name>.transitions[].action` | String | Yes | Action on transition |

## 6. Validation Rules

The compiler enforces these constraints:
1. Rule names must match `^[a-z_][a-z0-9_]*$`
2. Priorities must be unique across all rules
3. Priority range: 0-65535
4. MAC format: exactly 6 colon-separated hex octets or `*`
5. EtherType format: `0x` followed by exactly 4 hex digits
6. VLAN ID range: 0-4095
7. VLAN PCP range: 0-7
8. At least one rule must be defined
9. FSM states must form a connected graph from `initial_state`

## 7. Generated Output

For a rule file with N stateless rules and M stateful rules, the compiler generates:

| File | Count | Description |
|------|-------|-------------|
| `rule_match_K.v` | N | One per stateless rule |
| `rule_fsm_K.v` | M | One per stateful rule |
| `decision_logic.v` | 1 | Priority encoder |
| `packet_filter_top.v` | 1 | Top-level wiring |
| `test_packet_filter.py` | 1 | cocotb test bench |
| `Makefile` | 1 | Simulation build |

Total: N + M + 4 files
