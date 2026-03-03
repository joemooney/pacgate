# Companion Product Proposal: PacLab

**Date**: 2026-03-03  
**Status**: Proposal  
**Family Context**: PaciNet (`pacinet`, `pacgate`, `pacmate`)

## Executive Summary

There is clear scope for a fourth companion product focused on system-level verification orchestration.

Recommended product: **PacLab**

PacLab would provide a unified test orchestration and scenario platform for packet-processing systems, with PacGate as a first-class engine and adapters for external MAC/IP/PHY benches.

## Problem Gap

Current products cover:

- `pacinet`: Network architecture and pipeline context
- `pacgate`: Policy-to-hardware packet filter compiler + verification
- `pacmate`: Developer/operator assistant workflows

Missing layer:

- End-to-end, repeatable, system-level scenario orchestration across multiple components
- Standardized expected-vs-actual analysis across high-volume regressions
- Unified bridge between Python/file-driven labs today and richer benches (cocotb/scapy/HIL) tomorrow

## Product Definition

PacLab is a **verification control plane** with:

1. Scenario definition (`JSON/YAML`) with expected outcomes
2. Runner for local CLI tools and simulator endpoints
3. Adapter framework (file, CLI, REST, cocotb hooks, future hardware-in-loop)
4. Diff/report engine for expected vs actual at event and campaign level
5. CI-native artifacts (JSON, HTML, JUnit)

## Why This Fits the RMAC-Style Need

The RMAC-style request needs a modular system that can:

- generate traffic,
- inject error modes,
- run 1000+ packet regressions,
- and report behavioral correctness.

PacLab directly addresses this without forcing PacGate core to absorb vendor-IP bring-up responsibilities.

## Boundaries and Integration

PacGate remains responsible for:

- rule compilation,
- software simulation semantics,
- RTL/test generation.

PacLab would own:

- campaign orchestration,
- scenario lifecycle,
- adapters,
- aggregated reporting.

## MVP Scope (8-12 weeks)

1. Scenario schema v1
2. Runner for PacGate CLI + simulator-app API
3. Batch engine with concurrency controls
4. Expected/actual diff with mismatch taxonomy
5. Basic HTML dashboard and JUnit export
6. CLI: `paclab run`, `paclab diff`, `paclab report`

Current draft schema and example:

- `docs/management/paclab/scenario_v1.schema.json`
- `docs/management/paclab/scenario_v1.example.json`

## Phase 2 Scope

1. Cocotb adapter
2. Scapy adapter
3. Multi-channel timing model plugins
4. Hardware-in-loop target support
5. Golden baseline management across releases

## Risks

1. Scope creep into full verification framework replacement
2. Adapter maintenance burden
3. Confusion with PacGate ownership boundaries

Mitigation:

1. Keep strict product contract: PacLab orchestrates, engines execute.
2. Ship only PacGate adapter in MVP; add adapters by demand.
3. Publish interface contracts early.

## Success Metrics

1. Time to author first regression scenario under 30 minutes
2. Reproducible 1000-packet campaign with deterministic output in CI
3. Regression triage time reduced by 40%
4. At least 3 reusable scenario packs adopted across family projects

## Recommendation

Proceed with a lightweight PacLab MVP as a companion product initiative.

This fills the current gap between single-tool verification features and full system-level validation workflows, while preserving clean boundaries across `pacinet`, `pacgate`, and `pacmate`.
