# Enterprise Rule Set Walkthrough

**Document ID**: FLIP-EX-001
**Date**: 2026-02-26

---

## The Scenario

A network switch needs to enforce the following policy:

1. **Block all broadcast traffic** (highest priority — prevents broadcast storms)
2. **Allow management VLAN 100** (network ops traffic)
3. **Allow ARP** (required for address resolution)
4. **Allow IPv4 and IPv6** (data plane traffic)
5. **Allow traffic from ACME Corp switches** (vendor OUI 00:1a:2b)
6. **Allow LLDP** (link layer discovery for topology mapping)
7. **Drop everything else** (whitelist security model)

## The YAML

```yaml
flippy:
  version: "1.0"
  defaults:
    action: drop              # ← Whitelist: only explicitly allowed traffic passes
  rules:
    - name: block_broadcast   # ← Priority 200 (highest): blocks even allowed ethertypes
      type: stateless
      priority: 200
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop

    - name: allow_mgmt_vlan   # ← Priority 150: management always gets through
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
        src_mac: "00:1a:2b:*:*:*"   # ← Wildcard: any MAC from OUI 00:1a:2b
      action: pass

    - name: allow_lldp
      type: stateless
      priority: 60
      match:
        ethertype: "0x88CC"
      action: pass
```

## Compilation

```bash
$ flippy compile rules/examples/enterprise.yaml

Loaded 7 rules from rules/examples/enterprise.yaml
Generated Verilog RTL in gen/rtl/
Generated cocotb tests in gen/tb/
Compilation complete.
```

### Generated Files

```
gen/
├── rtl/
│   ├── packet_filter_top.v     # Top-level: parser + 7 matchers + decision
│   ├── rule_match_0.v          # block_broadcast (priority 200)
│   ├── rule_match_1.v          # allow_mgmt_vlan (priority 150)
│   ├── rule_match_2.v          # allow_arp (priority 100)
│   ├── rule_match_3.v          # allow_ipv4 (priority 90)
│   ├── rule_match_4.v          # allow_ipv6 (priority 80)
│   ├── rule_match_5.v          # allow_vendor_acme (priority 70)
│   ├── rule_match_6.v          # allow_lldp (priority 60)
│   └── decision_logic.v        # 7-rule priority encoder
└── tb/
    ├── test_packet_filter.py   # 13 tests (7 directed + random + corners)
    └── Makefile
```

## Simulation Results

```
$ make sim RULES=rules/examples/enterprise.yaml

** TEST                                             STATUS   SIM TIME
** test_block_broadcast_match                       PASS     680ns
** test_allow_mgmt_vlan_match                       PASS     730ns
** test_allow_arp_match                             PASS     690ns
** test_allow_ipv4_match                            PASS     690ns
** test_allow_ipv6_match                            PASS     690ns
** test_allow_vendor_acme_match                     PASS     690ns
** test_allow_lldp_match                            PASS     690ns
** test_default_action                              PASS     690ns
** test_random_with_scoreboard                      PASS     310μs    ← 500 random pkts
** test_back_to_back_frames                         PASS     1.5μs
** test_jumbo_frame                                 PASS     90μs
** test_min_size_frame                              PASS     690ns
** test_reset_recovery                              PASS     660ns
** TESTS=13 PASS=13 FAIL=0 SKIP=0
```

## Scoreboard Report (from random test)

```
============================================================
SCOREBOARD REPORT
============================================================
Total packets checked: 500
Matches:               500
Mismatches:            0
Pass decisions:        320
Drop decisions:        180

Rule Hit Distribution:
  block_broadcast           133 ( 26.6%) #############
  allow_ipv4                 97 ( 19.4%) #########
  allow_ipv6                 96 ( 19.2%) #########
  allow_vendor_acme          68 ( 13.6%) ######
  __default__                47 (  9.4%) ####
  allow_arp                  37 (  7.4%) ###
  allow_lldp                 22 (  4.4%) ##
============================================================
```

## Key Observations

1. **Priority works correctly**: Broadcast ARP (dst=FF:FF:FF:FF:FF:FF, etype=0x0806) is DROPPED by the higher-priority broadcast rule, not passed by the ARP rule.

2. **Vendor OUI matching**: Frames from 00:1a:2b:xx:xx:xx are correctly allowed regardless of EtherType (as long as not broadcast).

3. **VLAN matching**: VLAN 100 frames pass even if their inner EtherType would otherwise be dropped.

4. **Default action**: Unknown protocols (0x88B5) correctly hit the default drop action.

5. **500/500 scoreboard matches**: The Python reference model and Verilog hardware agree on every single packet decision.
