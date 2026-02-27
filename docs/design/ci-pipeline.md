# PacGate CI/CD Pipeline Design

**Document ID**: PG-CI-001
**Version**: 1.0
**Date**: 2026-02-26

---

## Pipeline Architecture

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Push /  │───▶│  Build   │───▶│ Compile  │───▶│  Lint    │───▶│ Simulate │
│  PR      │    │  Rust    │    │  Rules   │    │  Verilog │    │  cocotb  │
└─────────┘    └──────────┘    └──────────┘    └──────────┘    └────┬─────┘
                                                                     │
                ┌──────────┐    ┌──────────┐    ┌──────────┐        │
                │  Report  │◄───│ Coverage │◄───│ Verify   │◄───────┘
                │  Publish │    │  Check   │    │  Results │
                └──────────┘    └──────────┘    └──────────┘
```

## GitHub Actions Workflow

```yaml
name: PacGate Verification Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install Icarus Verilog
        run: sudo apt-get install -y iverilog

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python deps
        run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install cocotb

      - name: Build PacGate compiler
        run: cargo build --release

      - name: Validate all rule files
        run: |
          for f in rules/examples/*.yaml; do
            cargo run --release -- validate "$f"
          done

      - name: Compile enterprise rules
        run: cargo run --release -- compile rules/examples/enterprise.yaml

      - name: Lint generated Verilog
        run: iverilog -g2012 -o /dev/null gen/rtl/*.v rtl/*.v

      - name: Run simulation
        run: |
          source .venv/bin/activate
          cd gen/tb && make

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: gen/tb/results.xml

      - name: Upload waveforms
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: waveforms
          path: gen/tb/sim_build/*.fst
```

## Quality Gates

| Gate | Condition | Blocks PR? |
|------|-----------|:----------:|
| Rust build | `cargo build` succeeds | Yes |
| YAML validation | All example YAMLs validate | Yes |
| Verilog lint | `iverilog -g2012` clean | Yes |
| Directed tests | All per-rule tests pass | Yes |
| Random test | Scoreboard: 0 mismatches | Yes |
| Corner cases | All corner case tests pass | Yes |
| Coverage | Overall > 60% (increasing) | Warning |
