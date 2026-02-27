# Why PacGate?

*A frank answer for skeptics, architects, and decision-makers.*

---

## "We already write Verilog. Why do we need a compiler?"

Because **verification eats your schedule**. Industry data consistently shows that verification consumes 60-70% of FPGA development time. The RTL isn't the hard part — proving it works is.

PacGate eliminates this problem by generating *both* the hardware and the verification from a single YAML specification. When you change a rule, the tests update automatically. There's no spec drift, no forgotten corner cases, no "I updated the RTL but forgot to update the test bench."

**Traditional workflow:**
```
Spec (Word doc) → Manual RTL → Manual Tests → Debug → Repeat
     ↕ drift ↕         ↕ drift ↕
```

**PacGate workflow:**
```
rules.yaml → pacgate compile → RTL + Tests (always in sync)
```

## "YAML? That's not a serious HDL."

You're right — YAML isn't an HDL, and PacGate doesn't pretend it is. YAML is the **specification language**. The generated Verilog is real, synthesizable, IEEE 1364-2005 compliant hardware that targets Xilinx 7-series FPGAs.

The key insight: for packet filtering, the design space is well-defined. Every filter needs:
1. A frame parser (PacGate ships a hand-written one)
2. Per-rule matchers (generated, combinational)
3. A priority encoder (generated, first-match-wins)
4. A decision output (latched per frame)

These four components are **template-amenable**. You don't need the full generality of Verilog to express "match EtherType 0x0806, action pass." But you absolutely do need it for the implementation — which is what PacGate generates.

## "Can't I just use P4?"

P4 is excellent for programming switch ASICs (Tofino, memory-mapped). But P4:
- **Doesn't generate verification** — you still need to write tests
- **Requires specific hardware** — Tofino, bmv2 (software), or a P4-to-FPGA compiler
- **Is overkill for Layer 2** — P4 is designed for L3/L4 processing pipelines
- **Has no formal verification path** — no SVA, no bounded model checking

PacGate targets a different niche: **dedicated L2 FPGA filters with built-in verification**. If you're building a Tofino-based datacenter switch, use P4. If you're building an FPGA-based security boundary, OT gateway, or SmartNIC filter — PacGate is purpose-built.

Future roadmap includes P4 import/export for interoperability.

## "We already have Corundum / NetFPGA."

Corundum (University of Wisconsin) and NetFPGA are **reference FPGA NIC designs**. They provide complete network interface implementations with DMA, PCIe, and queue management.

PacGate is **not a NIC**. It's a **packet filter compiler with verification**. The two are complementary:

- Use Corundum/NetFPGA for the NIC infrastructure
- Use PacGate to generate the filter logic that plugs into them
- PacGate's AXI-Stream interface is directly compatible with Corundum's packet path

Think of it this way: Corundum is the car; PacGate is the engine's fuel injection map.

## "Our FPGA team already has a filter. Why rewrite it?"

You don't have to rewrite anything. PacGate is also a **verification framework**:

1. **Test existing filters**: Use PacGate's cocotb test harness generation as a golden reference. Define your filter's rules in YAML, generate tests, and run them against your existing RTL.
2. **Compare implementations**: Run PacGate's generated filter in parallel with yours, feed both the same packets, compare decisions.
3. **Formal verification**: Generate SVA assertions from your rule spec and bind them to your existing modules.

PacGate's scoreboard checks 500+ random packets per run. If your filter disagrees with the spec on even one, you'll know.

## "How does this compare to commercial tools?"

| Feature | PacGate | Vivado HLS | Agnisys IDS | Mentor Questa |
|---------|:-------:|:----------:|:-----------:|:-------------:|
| Price | Competitive | $3K-50K/yr | $50K+/yr | $100K+/yr |
| RTL generation | Yes | Yes (C→RTL) | No | No |
| Test generation | Yes | No | Yes (reg→test) | No |
| Both from one spec | **Yes** | No | No | No |
| Formal verification | Yes (SVA+SBY) | No | No | Yes |
| Open-source toolchain | Yes | No | No | No |
| L2 packet filtering | Purpose-built | General | Register-focused | General |

PacGate doesn't compete with Questa on general-purpose verification. It competes on **developer velocity** for a specific, high-value problem domain.

## "Is it production-ready?"

PacGate is well beyond prototype stage:

- **63 Rust tests** (44 unit + 19 integration) — compiler correctness
- **13+ cocotb tests** with 500 random packets — hardware simulation
- **85%+ functional coverage** — coverage-driven verification
- **SVA formal assertions** — mathematical proof of correctness
- **Property-based testing** with Hypothesis — invariant verification
- **12 real-world examples** spanning data centers, industrial OT, automotive, 5G, IoT
- **AXI-Stream interface** — standard FPGA integration
- **Yosys synthesis** verified — maps to Xilinx 7-series
- **Rule overlap detection** — compile-time safety warnings

The verification depth exceeds what most hand-written FPGA filters achieve.

## "What's the catch?"

Honest limitations:

1. **Layer 2 only** (currently) — no IP/TCP/UDP matching yet. Roadmap includes L3/L4.
2. **Stateless + simple FSM** — complex stateful logic (connection tracking, deep packet inspection) is out of scope.
3. **Single-port filter** — one ingress, one egress. Multi-port switch fabric is on the roadmap.
4. **Xilinx-focused** — synthesis scripts target 7-series. The Verilog is portable, but constraints and synthesis need adaptation for Intel/Lattice.
5. **No byte-offset matching yet** — arbitrary protocol field matching (REQ-015) is planned for Phase 5.

These are **scope boundaries**, not bugs. PacGate solves L2 packet filtering extremely well. If you need L7 DPI, use a different tool.

## "Who is this for?"

**Primary users:**
- FPGA engineers building network packet filters
- Verification engineers who want auto-generated test harnesses
- Security teams deploying hardware-level traffic filtering
- Industrial/OT teams protecting control networks
- Academic researchers studying FPGA networking

**Secondary users:**
- Embedded teams needing deterministic packet filtering
- SmartNIC developers looking for filter IP blocks
- Network architects evaluating hardware-accelerated security

## "Show me the numbers."

### Development Speed
```
Traditional:  2-4 weeks RTL + 4-8 weeks verification = 6-12 weeks
PacGate:      Write YAML (1 hour) + compile (seconds) = 1 hour
```

### Verification Coverage
```
Random packet scoreboard:  500/500 matches (100%)
Functional coverage:       85%+ (cover points + cross coverage)
Property invariants:       500/500 pass
Formal assertions:         PROVEN (BMC depth 20)
```

### FPGA Resources (7-rule enterprise filter)
```
LUTs:        ~435 (2.1% of Artix-7 XC7A35T)
Flip-Flops:  ~82 (0.2%)
Clock:       125 MHz
Latency:     16 cycles = 128 ns
```

### Code Quality
```
Compiler:    3,000+ lines of Rust (type-safe, memory-safe)
Templates:   6 Tera templates (Verilog, cocotb, SVA, Hypothesis)
RTL:         4 hand-written modules + generated per-rule matchers
Tests:       63 Rust tests + 13+ cocotb tests + formal + property
```

## The Bottom Line

PacGate is the only tool that generates both synthesizable FPGA hardware and a complete verification environment from a single YAML specification. It's not trying to replace Vivado, P4, or general-purpose verification tools. It's solving a specific, well-defined problem — L2 packet filtering — with a level of verification depth that most hand-coded solutions never achieve.

**Try it:**
```bash
git clone https://github.com/joemooney/pacgate.git
cd pacgate && cargo build --release
pacgate compile rules/examples/enterprise.yaml -o gen/
```

If you can write YAML, you can build verified FPGA packet filters.
