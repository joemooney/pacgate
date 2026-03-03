# PacGate Simulator App

A separate web simulator for driving PacGate behavior through a browser.

## What it does

- Lists available rule YAML files in this repo.
- Runs single packet simulations by calling `pacgate simulate --json`.
- Runs canned multi-event scenarios.
- Lets you save and delete named custom scenarios (persisted on disk).
- Shows latest result JSON and an in-memory execution log.
- Shows expected-vs-actual action diff for scenario events.

## Run

From the repository root:

```bash
cargo build
python3 simulator-app/server.py
```

Then open:

```text
http://127.0.0.1:8787
```

Optional host/port override:

```bash
SIMULATOR_HOST=0.0.0.0 SIMULATOR_PORT=9000 python3 simulator-app/server.py
```

## Scripted Regression

Run a 1000-packet batch check:

```bash
python3 simulator-app/examples/run_1000.py \
  --rules rules/examples/allow_arp.yaml \
  --count 1000
```

Or use the Make target (fails if mismatches > 0):

```bash
make sim-regress RULES=rules/examples/allow_arp.yaml SIM_REGRESS_COUNT=1000
```

## API endpoints

- `GET /api/health`
- `GET /api/rules-files`
- `GET /api/scenarios`
- `GET /api/log`
- `POST /api/simulate`
- `POST /api/scenario/run`
- `POST /api/scenario/save`
- `POST /api/scenario/delete`

## Notes

- The service prefers `target/debug/pacgate` if present; otherwise it falls back to `cargo run -- simulate ...`.
- Log entries are in-memory only (max 200).
- Custom scenarios are stored in `simulator-app/data/custom_scenarios.json`.

## PacLab Scenario Tools

Validate scenario files:

```bash
python3 simulator-app/tools/paclab_validate.py \
  docs/management/paclab/scenario_v2.example.json
```

Import PacLab scenarios into simulator custom scenario storage:

```bash
python3 simulator-app/tools/scenario_sync.py import \
  --in-dir docs/management/paclab/scenarios \
  --store simulator-app/data/custom_scenarios.json \
  --mode merge
```

Export simulator custom scenarios back to PacLab scenario files:

```bash
python3 simulator-app/tools/scenario_sync.py export \
  --store simulator-app/data/custom_scenarios.json \
  --out-dir docs/management/paclab/scenarios
```

Run a topology scenario (2-RMAC switch model):

```bash
python3 simulator-app/tools/run_topology.py \
  docs/management/paclab/scenario_v2.example.json \
  --bin target/debug/pacgate \
  --output topology_result.json
```
