# PacLab Scenario Schema (Draft v1)

This folder defines the first draft schema for PacLab scenario files.

## Files

- `scenario_v1.schema.json`: JSON Schema for scenario definitions
- `scenario_v1.example.json`: Valid example scenario
- `scenario_v2.schema.json`: JSON Schema with topology/switch extensions
- `scenario_v2.example.json`: Example 2-port RMAC/switch scenario

## Usage

Validate with your preferred JSON Schema validator (draft 2020-12).

A scenario should then be consumable by:

1. PacLab (future orchestrator)
2. PacGate simulator app custom scenario import (compatible event model)
3. CI regression runners

## Compatibility Notes

The schema intentionally aligns with existing simulator-app fields:

- `id`, `name`, `default_rules_file`, `stateful`
- `events[].packet`
- `events[].expected_action`
- `events[].delay_ms`

This lets us adopt PacLab incrementally without breaking current tooling.

## CLI Utilities

Scenario validation:

```bash
python3 simulator-app/tools/paclab_validate.py \
  docs/management/paclab/scenario_v2.example.json
```

Directory validation:

```bash
python3 simulator-app/tools/scenario_sync.py validate \
  --in-dir docs/management/paclab/scenarios
```

Sync from scenario files into simulator custom storage:

```bash
python3 simulator-app/tools/scenario_sync.py import \
  --in-dir docs/management/paclab/scenarios \
  --store simulator-app/data/custom_scenarios.json \
  --mode merge
```

Sync from simulator custom storage back into scenario files:

```bash
python3 simulator-app/tools/scenario_sync.py export \
  --store simulator-app/data/custom_scenarios.json \
  --out-dir docs/management/paclab/scenarios
```

Run topology simulation:

```bash
python3 simulator-app/tools/run_topology.py \
  docs/management/paclab/scenario_v2.example.json \
  --bin target/debug/pacgate \
  --output topology_result.json
```
