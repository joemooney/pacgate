mod model;
mod loader;
mod verilog_gen;
mod cocotb_gen;

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "pacgate", version, about = "FPGA Layer 2 Packet Filter Gate — YAML rules to Verilog RTL + cocotb verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile YAML rules into Verilog RTL and cocotb test bench
    Compile {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated files
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,
    },
    /// Validate YAML rules without generating output
    Validate {
        /// Path to the YAML rules file
        rules: PathBuf,
    },
    /// Create a starter rules file
    Init {
        /// Output file path
        #[arg(default_value = "rules.yaml")]
        output: PathBuf,
    },
    /// Estimate FPGA resource usage for a rule set
    Estimate {
        /// Path to the YAML rules file
        rules: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { rules, output, templates } => {
            log::info!("Compiling rules from {}", rules.display());
            let config = loader::load_rules(&rules)?;
            println!("Loaded {} rules from {}", config.pacgate.rules.len(), rules.display());

            // Generate Verilog
            verilog_gen::generate(&config, &templates, &output)?;
            println!("Generated Verilog RTL in {}/rtl/", output.display());

            // Generate cocotb tests
            cocotb_gen::generate(&config, &templates, &output)?;
            println!("Generated cocotb tests in {}/tb/", output.display());

            println!("Compilation complete.");
        }
        Commands::Validate { rules } => {
            let config = loader::load_rules(&rules)?;
            println!("Valid: {} rules loaded from {}", config.pacgate.rules.len(), rules.display());
        }
        Commands::Init { output } => {
            if output.exists() {
                anyhow::bail!("File already exists: {}. Remove it first or choose a different name.", output.display());
            }
            std::fs::write(&output, INIT_TEMPLATE)?;
            println!("Created starter rules file: {}", output.display());
            println!("Edit it, then run: pacgate compile {}", output.display());
        }
        Commands::Estimate { rules } => {
            let config = loader::load_rules(&rules)?;
            print_resource_estimate(&config);
        }
    }

    Ok(())
}

fn print_resource_estimate(config: &model::FilterConfig) {
    let rules = &config.pacgate.rules;
    let num_stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let num_stateful = rules.iter().filter(|r| r.is_stateful()).count();
    let total = rules.len();

    // Estimate LUTs and FFs per component
    // frame_parser: ~120 LUTs, ~90 FFs (fixed)
    // per stateless rule: ~30-60 LUTs (comparators), ~0 FFs (combinational)
    // per stateful rule: ~80-150 LUTs, ~40-80 FFs (state register + timeout counter)
    // decision_logic: ~10 LUTs per rule (priority encoder) + ~4 FFs (latch)
    // I/O: ~20 LUTs (fixed)

    let parser_luts = 120;
    let parser_ffs = 90;

    let mut rule_luts = 0;
    let mut rule_ffs = 0;

    for rule in rules {
        if rule.is_stateful() {
            let fsm = rule.fsm.as_ref().unwrap();
            let num_states = fsm.states.len();
            let num_transitions: usize = fsm.states.values().map(|s| s.transitions.len()).sum();
            let has_timeout = fsm.states.values().any(|s| s.timeout_cycles.is_some());
            rule_luts += 40 + num_transitions * 30 + if has_timeout { 40 } else { 0 };
            rule_ffs += 4 + num_states * 2 + if has_timeout { 32 } else { 0 };
        } else {
            let mc = &rule.match_criteria;
            let mut fields = 0;
            if mc.ethertype.is_some() { fields += 1; }
            if mc.dst_mac.is_some() { fields += 3; } // 48-bit comparator
            if mc.src_mac.is_some() { fields += 3; }
            if mc.vlan_id.is_some() { fields += 1; }
            if mc.vlan_pcp.is_some() { fields += 1; }
            rule_luts += 10 + fields * 12;
        }
    }

    let decision_luts = 10 * total + 8;
    let decision_ffs = 4;
    let io_luts = 20;

    let total_luts = parser_luts + rule_luts + decision_luts + io_luts;
    let total_ffs = parser_ffs + rule_ffs + decision_ffs;

    // Artix-7 reference: XC7A35T has 20,800 LUTs, 41,600 FFs
    let artix_lut_pct = total_luts as f64 / 20800.0 * 100.0;
    let artix_ff_pct = total_ffs as f64 / 41600.0 * 100.0;

    println!();
    println!("  PacGate Resource Estimate");
    println!("  ════════════════════════════════════════════");
    println!("  Rules:  {} stateless, {} stateful, {} total", num_stateless, num_stateful, total);
    println!();
    println!("  Component             Est. LUTs   Est. FFs");
    println!("  ───────────────────── ────────── ─────────");
    println!("  Frame parser              {:>5}     {:>5}", parser_luts, parser_ffs);
    println!("  Rule matchers             {:>5}     {:>5}", rule_luts, rule_ffs);
    println!("  Decision logic            {:>5}     {:>5}", decision_luts, decision_ffs);
    println!("  I/O logic                 {:>5}         -", io_luts);
    println!("  ───────────────────── ────────── ─────────");
    println!("  TOTAL                     {:>5}     {:>5}", total_luts, total_ffs);
    println!();
    println!("  Artix-7 XC7A35T:  {:.1}% LUTs, {:.1}% FFs", artix_lut_pct, artix_ff_pct);
    println!("  Artix-7 XC7A100T: {:.1}% LUTs, {:.1}% FFs",
             total_luts as f64 / 63400.0 * 100.0,
             total_ffs as f64 / 126800.0 * 100.0);
    println!();
}

const INIT_TEMPLATE: &str = r#"# PacGate Rule File
# Documentation: https://github.com/joemooney/flippy
#
# Quick start:
#   1. Edit the rules below
#   2. Compile:  pacgate compile rules.yaml
#   3. Simulate: cd gen/tb && make
#
# Each rule matches on one or more fields and takes an action (pass or drop).
# Rules are evaluated by priority (highest number wins).
# The default action applies when no rule matches.

pacgate:
  version: "1.0"
  defaults:
    action: drop            # Whitelist mode: only explicitly allowed traffic passes
                            # Change to "pass" for blacklist mode

  rules:
    # Block all broadcast traffic (highest priority)
    - name: block_broadcast
      type: stateless
      priority: 200
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop

    # Allow ARP for address resolution
    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass

    # Allow IPv4 traffic
    - name: allow_ipv4
      type: stateless
      priority: 90
      match:
        ethertype: "0x0800"
      action: pass

    # Allow IPv6 traffic
    - name: allow_ipv6
      type: stateless
      priority: 80
      match:
        ethertype: "0x86DD"
      action: pass

    # --- Uncomment to add more rules ---
    #
    # Match on VLAN ID:
    # - name: allow_mgmt_vlan
    #   type: stateless
    #   priority: 150
    #   match:
    #     vlan_id: 100
    #   action: pass
    #
    # Match on vendor OUI (wildcard MAC):
    # - name: allow_vendor
    #   type: stateless
    #   priority: 70
    #   match:
    #     src_mac: "00:1a:2b:*:*:*"
    #   action: pass
    #
    # Stateful FSM (sequence detection):
    # - name: arp_then_ipv4
    #   type: stateful
    #   priority: 50
    #   fsm:
    #     initial_state: idle
    #     states:
    #       idle:
    #         transitions:
    #           - match:
    #               ethertype: "0x0806"
    #             next_state: arp_seen
    #             action: pass
    #       arp_seen:
    #         timeout_cycles: 1000
    #         transitions:
    #           - match:
    #               ethertype: "0x0800"
    #             next_state: idle
    #             action: pass
"#;
