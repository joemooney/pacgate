# PacGate Documentation Index

## Design Documents

| Document | Description | Audience |
|----------|-------------|----------|
| [Architecture](design/architecture.md) | System architecture, module hierarchy, data flow | Engineers |
| [Design Decisions](design/design-decisions.md) | All design decisions with rationale | Engineers, Architects |
| [CI Pipeline](design/ci-pipeline.md) | Continuous integration pipeline design | DevOps, Engineers |

## Verification

| Document | Description | Audience |
|----------|-------------|----------|
| [Verification Strategy](verification/verification-strategy.md) | Multi-layer verification philosophy | Engineers, Management |
| [Test Plan](verification/test-plan.md) | Complete test matrix with status | Engineers, QA |
| [Test Harness Architecture](verification/test-harness-architecture.md) | Auto-generated verification framework | Engineers |
| [Coverage Model](verification/coverage-model.md) | Functional coverage definitions | Engineers |

## User Guide

| Document | Description | Audience |
|----------|-------------|----------|
| [Getting Started](user-guide/getting-started.md) | Quick start (5 minutes) | All |
| [Rule Language Reference](user-guide/rule-language-reference.md) | Complete YAML syntax reference | All |

## API Reference

| Document | Description | Audience |
|----------|-------------|----------|
| [Compiler API](api/compiler-api.md) | CLI, internal modules, verification framework | Engineers |

## Management

| Document | Description | Audience |
|----------|-------------|----------|
| [Executive Summary](management/executive-summary.md) | Problem, solution, ROI, status | Leadership |
| [Innovation Analysis](management/innovation-analysis.md) | Competitive landscape, IP, roadmap | Leadership, Strategy |
| [Roadmap](management/roadmap.md) | Phase timeline through 2027 | Leadership, PM |

## Diagrams

| Document | Description |
|----------|-------------|
| [System Diagrams](diagrams/system-diagrams.md) | Architecture, data flow, FSM, verification |

## Research

| Document | Description |
|----------|-------------|
| [Research Report](RESEARCH.md) | cocotb, coverage, mutation testing, formal verification |

## Examples

| Example | Rules | Tests | Description |
|---------|:-----:|:-----:|-------------|
| `allow_arp.yaml` | 1 | 2 | Minimal: allow ARP only |
| `enterprise.yaml` | 7 | 13 | Multi-rule enterprise firewall |
| `stateful_sequence.yaml` | 2 | — | Stateful FSM: ARP → IPv4 sequence |
