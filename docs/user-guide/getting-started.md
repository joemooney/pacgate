# Getting Started with PacGate

**Document ID**: PG-UG-001
**Version**: 2.0
**Date**: 2026-02-26

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.75+ | PacGate compiler |
| Python | 3.10+ | cocotb test framework |
| Icarus Verilog | 12.0+ | Verilog simulation |
| Questa/QuestaSim | 2022+ | Alternative Verilog/SystemVerilog simulation |
| cocotb | 2.0+ | Python-to-Verilog test bridge |
| GTKWave | 3.3+ | Waveform viewer (optional) |

## Quick Start (5 minutes)

### Step 1: Install Dependencies

```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Icarus Verilog (default simulator)
sudo apt install iverilog  # Ubuntu/Debian
brew install icarus-verilog # macOS

# OR use Questa/QuestaSim (installed/licensed separately)
# Ensure vlog/vsim are in PATH

# Python venv + cocotb
python3 -m venv .venv
source .venv/bin/activate
pip install cocotb
```

### Step 2: Build PacGate

```bash
cargo build --release
```

### Step 3: Write Your First Rule

Create `my_rules.yaml`:

```yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop              # Whitelist mode: drop everything by default
  rules:
    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"   # ARP protocol
      action: pass
```

### Step 4: Compile

```bash
cargo run -- compile my_rules.yaml
```

This generates:
- `gen/rtl/packet_filter_top.v` — Top-level Verilog
- `gen/rtl/rule_match_0.v` — ARP matcher
- `gen/rtl/decision_logic.v` — Priority encoder
- `gen/tb/test_packet_filter.py` — cocotb tests
- `gen/tb/Makefile` — Simulation makefile

### Step 5: Simulate

```bash
source .venv/bin/activate
make sim RULES=my_rules.yaml

# Alternative with Questa/QuestaSim
make sim RULES=my_rules.yaml SIM=questa
```

Expected output:
```
** test_allow_arp_match    PASS    680.00ns
** test_default_action     PASS    690.00ns
** TESTS=2 PASS=2 FAIL=0 SKIP=0
```

### Step 6: View Waveforms (Optional)

```bash
gtkwave gen/tb/sim_build/dump.fst &
```

## Command Reference

### `pacgate compile <rules.yaml>`

Compiles YAML rules into Verilog RTL and cocotb test bench.

```bash
pacgate compile rules.yaml                    # Default output to gen/
pacgate compile rules.yaml -o build/          # Custom output directory
pacgate compile rules.yaml -t my_templates/   # Custom templates
```

**Options**:
| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `gen` | Output directory |
| `-t, --templates` | `templates` | Templates directory |

### `pacgate validate <rules.yaml>`

Validates YAML rules without generating output. Useful for CI.

```bash
pacgate validate rules.yaml
# Output: "Valid: 5 rules loaded from rules.yaml"
```

### `make` Targets

| Target | Command | Description |
|--------|---------|-------------|
| `compile` | `make compile RULES=file.yaml` | Generate RTL + tests |
| `sim` | `make sim RULES=file.yaml` | Compile + simulate |
| `sim` (Questa) | `make sim RULES=file.yaml SIM=questa` | Compile + simulate with Questa |
| `lint` | `make lint` | Icarus Verilog lint check |
| `lint` (Questa) | `make lint LINT_SIM=questa` | Questa `vlog -lint` check |
| `clean` | `make clean` | Remove generated files |

## Writing Rules

### Rule Structure

```yaml
pacgate:
  version: "1.0"
  defaults:
    action: drop          # or "pass" — applies when no rule matches
  rules:
    - name: rule_name     # Unique identifier (lowercase, underscores)
      type: stateless     # or "stateful" (Phase 3)
      priority: 100       # Higher number = higher priority (0-65535)
      match:              # Field matching criteria
        ethertype: "0x0806"
      action: pass        # or "drop"
```

### Match Fields

| Field | Format | Example | Description |
|-------|--------|---------|-------------|
| `ethertype` | Hex string | `"0x0806"` | 16-bit EtherType |
| `dst_mac` | MAC string | `"ff:ff:ff:ff:ff:ff"` | Destination MAC |
| `src_mac` | MAC string | `"00:1a:2b:*:*:*"` | Source MAC (with wildcards) |
| `vlan_id` | Integer | `100` | VLAN ID (0-4095) |
| `vlan_pcp` | Integer | `7` | VLAN Priority (0-7) |

### MAC Wildcards

Use `*` for any octet:

```yaml
# Match any MAC from vendor 00:1a:2b
src_mac: "00:1a:2b:*:*:*"

# Match any MAC with specific last 3 octets
dst_mac: "*:*:*:de:ad:01"
```

### Priority Rules

- Higher number = higher priority
- When multiple rules match, highest priority wins
- Priorities must be unique
- Default action applies when NO rule matches

### Whitelist vs Blacklist Mode

**Whitelist** (default: drop):
```yaml
defaults:
  action: drop    # Drop everything not explicitly allowed
rules:
  - name: allow_arp
    match: { ethertype: "0x0806" }
    action: pass  # Only ARP gets through
```

**Blacklist** (default: pass):
```yaml
defaults:
  action: pass    # Allow everything not explicitly blocked
rules:
  - name: block_broadcast
    match: { dst_mac: "ff:ff:ff:ff:ff:ff" }
    action: drop  # Block broadcast
```

## Example: Enterprise Firewall

```yaml
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
```

## Troubleshooting

### "cocotb-config not found"
```bash
source .venv/bin/activate  # Activate the Python virtual environment
```

### "decision_valid never asserted"
- Check that your frame has at least 14 bytes (6 dst + 6 src + 2 ethertype)
- Verify `pkt_sof` is asserted on the first byte
- Verify `pkt_valid` is high for all frame bytes

### "No rules defined"
- Ensure your YAML has at least one rule under `pacgate.rules`
- Run `pacgate validate` first to check YAML syntax

### "Duplicate priority"
- Each rule must have a unique priority value
- Change one of the conflicting priorities
