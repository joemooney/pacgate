# Design Decisions Record

**Document ID**: FLIP-DDR-001
**Version**: 2.0
**Date**: 2026-02-26

This document records all significant design decisions, their context, rationale, and alternatives considered. Each decision is immutable once recorded — superseded decisions reference their replacement.

---

## DD-001: Rule Specification Format — YAML

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Need a human-readable format for defining packet filter rules that non-FPGA-engineers can author.

**Decision**: Use YAML as the rule specification format.

**Rationale**:
- Supports comments (unlike JSON)
- More readable than TOML for nested structures
- Excellent tooling ecosystem (linters, schema validators, IDE support)
- Familiar to DevOps/NetOps teams who manage network configs
- Diff-friendly in version control

**Alternatives Considered**:
| Format | Pros | Cons | Why Not |
|--------|------|------|---------|
| JSON | Universal, schema validation | No comments, verbose | Network engineers need comments |
| TOML | Good for flat config | Poor for nested/array structures | Rule lists are deeply nested |
| Custom DSL | Optimal syntax | Learning curve, tooling cost | Too much overhead for Phase 1 |
| P4 | Industry standard for packet processing | Complex, overkill for L2 | Scope mismatch |

---

## DD-002: Compiler Language — Rust

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Need a compiler that parses YAML, validates rules, and generates both Verilog and Python.

**Decision**: Implement the compiler in Rust.

**Rationale**:
- Type system catches template generation errors at compile time
- serde provides zero-cost YAML deserialization with derive macros
- Tera template engine is mature and Jinja2-compatible
- Single binary distribution (no runtime dependencies)
- Excellent error messages via `anyhow` + `thiserror`
- Fast compilation (important for edit-compile-simulate loop)

**Alternatives Considered**:
| Language | Pros | Cons | Why Not |
|----------|------|------|---------|
| Python | cocotb ecosystem, rapid prototyping | No type safety, slower | Template bugs found at runtime |
| Go | Fast, good tooling | Weaker template engine | Tera >> Go templates for Verilog |
| TypeScript | JSON/YAML native | Node dependency | Heavy runtime for CLI tool |

---

## DD-003: Template Engine — Tera

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Need to generate syntactically correct Verilog and Python from validated rule models.

**Decision**: Use Tera (Jinja2-compatible template engine for Rust).

**Rationale**:
- Jinja2 syntax is widely known
- Supports loops, conditionals, filters, macros
- Runtime template loading allows user-customizable templates
- Good error messages on template syntax errors
- Well-maintained Rust crate

**Alternatives**:
- **Askama**: Compile-time templates, faster, but prevents user template customization
- **Handlebars-rs**: Less powerful (no `if/else if` chains)
- **Direct codegen (format! strings)**: Unmaintainable for complex Verilog

---

## DD-004: Parallel Combinational Rule Evaluation

**Date**: 2026-02-26
**Status**: Accepted
**Context**: How should multiple rules be evaluated against a parsed frame?

**Decision**: All rules evaluate in parallel as combinational logic. A priority encoder selects the winning rule.

**Rationale**:
- **O(1) clock cycle latency** regardless of rule count
- Predictable, deterministic timing (critical for FPGA timing closure)
- No sequencing logic needed (simpler verification)
- Maps naturally to FPGA fabric (parallel LUT evaluation)

**Trade-offs**:
- Area scales linearly O(N) with rule count
- For >1000 rules, may need TCAM or pipelined approach
- All rules must fit in a single clock domain

**Alternatives**:
- **Sequential scan**: O(N) latency, less area, but variable timing
- **TCAM**: O(1) latency and area-efficient for many rules, but harder to implement in FPGA fabric
- **Pipelined**: O(log N) latency, better for very high clock rates

---

## DD-005: Latched Decision Output

**Date**: 2026-02-26
**Status**: Accepted
**Context**: The `decision_valid` and `decision_pass` signals need clear semantics for downstream consumers.

**Decision**: Latch the decision from when `fields_valid` pulses until the next `pkt_sof`.

**Rationale**:
- Downstream logic can read the decision at any point during the frame
- No need for precise timing alignment between parser and consumer
- Decision persists through the entire payload phase
- Clear semantics: "one decision per frame, valid for frame duration"

**Implementation**:
```verilog
always @(posedge clk or negedge rst_n) begin
    if (!rst_n)          {decision_valid, decision_pass} <= 2'b00;
    else if (pkt_sof)    {decision_valid, decision_pass} <= 2'b00;  // clear
    else if (fields_valid) begin                                     // latch
        decision_valid <= 1'b1;
        decision_pass  <= selected_action;
    end
end
```

**Alternative**: Pulsed output (1 clock cycle) — rejected because consumers would need their own latch, duplicating logic.

---

## DD-006: cocotb Over SystemVerilog UVM

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Need a verification framework that can be auto-generated from YAML specs.

**Decision**: Use cocotb (Python) as the verification framework.

**Rationale**:
- **Generatable**: Python is easier to template-generate than SystemVerilog
- **Accessible**: Python expertise is more common than SystemVerilog
- **Ecosystem**: numpy, scapy, hypothesis, pytest — rich library ecosystem
- **Open source**: No EDA tool licenses required (unlike Synopsys VCS + UVM)
- **CI-friendly**: pip install, runs with Icarus Verilog (free)

**Key Insight**: The auto-generation aspect is the killer feature. UVM testbenches are notoriously hard to auto-generate due to SystemVerilog's complexity. Python's simplicity makes code generation tractable.

**Trade-offs**:
- Not industry-standard for large SoC verification
- Slower simulation than native SystemVerilog testbench
- Less mature coverage tools (but improving rapidly)

---

## DD-007: Active-Low Asynchronous Reset

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Reset strategy for the FPGA design.

**Decision**: Use active-low asynchronous reset (`rst_n`).

**Rationale**:
- Xilinx 7-series FPGAs have dedicated global set/reset (GSR) that's active-low
- Asynchronous assert, synchronous deassert is Xilinx-recommended
- Allows reset without clock running (useful for power-on)
- Convention matches Xilinx IP cores

---

## DD-008: Single-Spec Dual-Generation (Core Innovation)

**Date**: 2026-02-26
**Status**: Accepted
**Context**: How to ensure RTL and testbench always agree on the specification.

**Decision**: Both Verilog RTL and cocotb tests are generated from the same YAML specification by the same compiler.

**Rationale**:
- **Eliminates specification drift**: RTL and tests cannot disagree
- **Automatic coverage**: Every rule generates both hardware and a test
- **Change propagation**: Modifying a rule automatically updates both RTL and tests
- **Audit trail**: YAML diff shows exactly what changed in both hardware and verification

**This is the core innovation of Flippy** and the primary differentiator from traditional FPGA development workflows.

---

## DD-009: Verification Framework Architecture — UVM-Inspired

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Need a structured verification approach that scales beyond basic directed tests.

**Decision**: Implement a UVM-inspired verification framework in Python/cocotb with:
- Constrained random packet generation
- Reference model scoreboard
- Functional coverage collection
- Protocol-aware bus functional models

**Rationale**:
- Brings industry-standard verification methodology to open-source tooling
- Constrained random finds bugs that directed tests miss
- Coverage metrics provide confidence in verification completeness
- Auto-generated from YAML spec (unique to Flippy)

---

## DD-010: Frame Parser as Hand-Written RTL

**Date**: 2026-02-26
**Status**: Accepted
**Context**: Should the Ethernet frame parser be generated or hand-written?

**Decision**: Hand-write the frame parser, generate everything else.

**Rationale**:
- Parser is protocol-fixed (Ethernet doesn't change per-deployment)
- Hand-written allows careful optimization and verification
- Complex FSM with VLAN handling benefits from human engineering
- Parser is independently verifiable with its own test suite
- Generated modules (matchers, decision logic) are deployment-specific

**Future consideration**: If we add Layer 3+ support, a parser generator might be warranted.
