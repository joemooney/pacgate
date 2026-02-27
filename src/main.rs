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

        /// Output JSON summary instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Validate YAML rules without generating output
    Validate {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output JSON summary instead of human-readable text
        #[arg(long)]
        json: bool,
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

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Output a DOT graph of the rule set for visualization
    Graph {
        /// Path to the YAML rules file
        rules: PathBuf,
    },
    /// Show analytics about a rule set
    Stats {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Compare two rule files and show differences
    Diff {
        /// Original rules file
        old: PathBuf,
        /// Updated rules file
        new: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { rules, output, templates, json } => {
            log::info!("Compiling rules from {}", rules.display());
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;

            // Generate Verilog
            verilog_gen::generate(&config, &templates, &output)?;

            // Generate cocotb tests
            cocotb_gen::generate(&config, &templates, &output)?;

            if json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "rules_file": rules.to_string_lossy(),
                    "rules_count": config.pacgate.rules.len(),
                    "default_action": match config.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "output_dir": output.to_string_lossy(),
                    "generated": {
                        "verilog_dir": format!("{}/rtl", output.display()),
                        "cocotb_dir": format!("{}/tb", output.display()),
                    },
                    "warnings": warnings,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                println!("Loaded {} rules from {}", config.pacgate.rules.len(), rules.display());
                println!();
                println!("  # Name                    Type       Pri   Action");
                println!("  — ——————————————————————— —————————— ————— ——————");
                for (i, r) in config.pacgate.rules.iter().enumerate() {
                    let rtype = if r.is_stateful() { "stateful" } else { "stateless" };
                    let action = match &r.action {
                        Some(model::Action::Pass) => "pass",
                        Some(model::Action::Drop) => "drop",
                        None => "default",
                    };
                    println!("  {} {:<27} {:<10} {:>5} {}", i + 1, r.name, rtype, r.priority, action);
                }
                println!();
                let default_str = match config.pacgate.defaults.action {
                    model::Action::Pass => "pass",
                    model::Action::Drop => "drop",
                };
                println!("  Default action: {}", default_str);
                println!("  Generated Verilog RTL in {}/rtl/", output.display());
                println!("  Generated cocotb tests in {}/tb/", output.display());
                println!("  Compilation complete.");
            }
        }
        Commands::Validate { rules, json } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            if json {
                let rules_info: Vec<serde_json::Value> = config.pacgate.rules.iter().map(|r| {
                    let action_str = match &r.action {
                        Some(model::Action::Pass) => "pass",
                        Some(model::Action::Drop) => "drop",
                        None => "default",
                    };
                    serde_json::json!({
                        "name": r.name,
                        "type": if r.is_stateful() { "stateful" } else { "stateless" },
                        "priority": r.priority,
                        "action": action_str,
                    })
                }).collect();
                let summary = serde_json::json!({
                    "status": "valid",
                    "rules_file": rules.to_string_lossy(),
                    "rules_count": config.pacgate.rules.len(),
                    "default_action": match config.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "rules": rules_info,
                    "warnings": warnings,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                println!("Valid: {} rules loaded from {}", config.pacgate.rules.len(), rules.display());
            }
        }
        Commands::Init { output } => {
            if output.exists() {
                anyhow::bail!("File already exists: {}. Remove it first or choose a different name.", output.display());
            }
            std::fs::write(&output, INIT_TEMPLATE)?;
            println!("Created starter rules file: {}", output.display());
            println!("Edit it, then run: pacgate compile {}", output.display());
        }
        Commands::Graph { rules } => {
            let config = loader::load_rules_with_warnings(&rules)?.0;
            print_dot_graph(&config);
        }
        Commands::Stats { rules, json } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            if json {
                let mut stats = compute_stats(&config);
                stats.as_object_mut().unwrap().insert("warnings".to_string(), serde_json::json!(warnings));
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                print_stats(&config);
            }
        }
        Commands::Diff { old, new, json } => {
            let old_config = loader::load_rules_with_warnings(&old)?.0;
            let new_config = loader::load_rules_with_warnings(&new)?.0;
            diff_rules(&old_config, &new_config, json)?;
        }
        Commands::Estimate { rules, json } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            if json {
                let mut estimate = compute_resource_estimate(&config);
                estimate.as_object_mut().unwrap().insert("warnings".to_string(), serde_json::json!(warnings));
                println!("{}", serde_json::to_string_pretty(&estimate)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                print_resource_estimate(&config);
            }
        }
    }

    Ok(())
}

fn compute_stats(config: &model::FilterConfig) -> serde_json::Value {
    let rules = &config.pacgate.rules;
    let total = rules.len();
    let stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let stateful = rules.iter().filter(|r| r.is_stateful()).count();
    let pass_rules = rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let drop_rules = rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();

    // Field usage
    let mut uses_ethertype = 0;
    let mut uses_dst_mac = 0;
    let mut uses_src_mac = 0;
    let mut uses_vlan_id = 0;
    let mut uses_vlan_pcp = 0;
    let mut match_field_count = Vec::new();

    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let mc = &rule.match_criteria;
        let mut count = 0;
        if mc.ethertype.is_some() { uses_ethertype += 1; count += 1; }
        if mc.dst_mac.is_some() { uses_dst_mac += 1; count += 1; }
        if mc.src_mac.is_some() { uses_src_mac += 1; count += 1; }
        if mc.vlan_id.is_some() { uses_vlan_id += 1; count += 1; }
        if mc.vlan_pcp.is_some() { uses_vlan_pcp += 1; count += 1; }
        match_field_count.push(count);
    }

    // Priority spacing
    let mut priorities: Vec<u32> = rules.iter().map(|r| r.priority).collect();
    priorities.sort();
    let min_gap = if priorities.len() > 1 {
        priorities.windows(2).map(|w| w[1] - w[0]).min().unwrap_or(0)
    } else { 0 };
    let max_gap = if priorities.len() > 1 {
        priorities.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0)
    } else { 0 };
    let avg_fields: f64 = if match_field_count.is_empty() { 0.0 }
        else { match_field_count.iter().sum::<usize>() as f64 / match_field_count.len() as f64 };

    serde_json::json!({
        "total_rules": total,
        "stateless": stateless,
        "stateful": stateful,
        "actions": {
            "pass": pass_rules,
            "drop": drop_rules,
        },
        "default_action": match config.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
        "field_usage": {
            "ethertype": uses_ethertype,
            "dst_mac": uses_dst_mac,
            "src_mac": uses_src_mac,
            "vlan_id": uses_vlan_id,
            "vlan_pcp": uses_vlan_pcp,
        },
        "match_complexity": {
            "avg_fields_per_rule": format!("{:.1}", avg_fields),
            "max_fields": match_field_count.iter().max().unwrap_or(&0),
            "min_fields": match_field_count.iter().min().unwrap_or(&0),
        },
        "priority_range": {
            "min": priorities.first().unwrap_or(&0),
            "max": priorities.last().unwrap_or(&0),
            "min_gap": min_gap,
            "max_gap": max_gap,
        },
    })
}

fn print_stats(config: &model::FilterConfig) {
    let rules = &config.pacgate.rules;
    let total = rules.len();
    let stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let stateful = rules.iter().filter(|r| r.is_stateful()).count();
    let pass_rules = rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let drop_rules = rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();
    let default_str = match config.pacgate.defaults.action {
        model::Action::Pass => "pass",
        model::Action::Drop => "drop",
    };

    // Field usage
    let mut uses_ethertype = 0usize;
    let mut uses_dst_mac = 0usize;
    let mut uses_src_mac = 0usize;
    let mut uses_vlan_id = 0usize;
    let mut uses_vlan_pcp = 0usize;

    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let mc = &rule.match_criteria;
        if mc.ethertype.is_some() { uses_ethertype += 1; }
        if mc.dst_mac.is_some() { uses_dst_mac += 1; }
        if mc.src_mac.is_some() { uses_src_mac += 1; }
        if mc.vlan_id.is_some() { uses_vlan_id += 1; }
        if mc.vlan_pcp.is_some() { uses_vlan_pcp += 1; }
    }

    // Priority spacing
    let mut priorities: Vec<u32> = rules.iter().map(|r| r.priority).collect();
    priorities.sort();

    println!();
    println!("  PacGate Rule Set Analytics");
    println!("  ════════════════════════════════════════════");
    println!("  Total rules:     {}", total);
    println!("  Stateless:       {}    Stateful: {}", stateless, stateful);
    println!("  Pass rules:      {}    Drop rules: {}", pass_rules, drop_rules);
    println!("  Default action:  {}", default_str);
    println!();
    println!("  Field Usage (stateless rules):");
    println!("  ─────────────────────────────────");
    if stateless > 0 {
        let bar = |n: usize| "#".repeat(n).to_string() + &" ".repeat(stateless - n);
        println!("  ethertype  [{:>2}/{}] |{}|", uses_ethertype, stateless, bar(uses_ethertype));
        println!("  dst_mac    [{:>2}/{}] |{}|", uses_dst_mac, stateless, bar(uses_dst_mac));
        println!("  src_mac    [{:>2}/{}] |{}|", uses_src_mac, stateless, bar(uses_src_mac));
        println!("  vlan_id    [{:>2}/{}] |{}|", uses_vlan_id, stateless, bar(uses_vlan_id));
        println!("  vlan_pcp   [{:>2}/{}] |{}|", uses_vlan_pcp, stateless, bar(uses_vlan_pcp));
    }
    println!();
    println!("  Priority Range: {} — {}", priorities.first().unwrap_or(&0), priorities.last().unwrap_or(&0));
    if priorities.len() > 1 {
        let min_gap = priorities.windows(2).map(|w| w[1] - w[0]).min().unwrap_or(0);
        let max_gap = priorities.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
        println!("  Priority gaps:   min={}, max={}", min_gap, max_gap);
        if min_gap < 10 {
            println!("  Note: tight priority spacing — consider leaving gaps for future rules.");
        }
    }
    println!();
}

fn print_dot_graph(config: &model::FilterConfig) {
    let default_action = match config.pacgate.defaults.action {
        model::Action::Pass => "PASS",
        model::Action::Drop => "DROP",
    };

    println!("digraph pacgate {{");
    println!("  rankdir=TB;");
    println!("  node [shape=box, fontname=\"monospace\", fontsize=10];");
    println!("  edge [fontname=\"monospace\", fontsize=9];");
    println!();

    // Input node
    println!("  input [label=\"Incoming\\nPacket\", shape=oval, style=filled, fillcolor=\"#e8e8e8\"];");

    // Frame parser node
    println!("  parser [label=\"Frame Parser\\n(dst_mac, src_mac,\\nethertype, vlan)\", shape=box, style=filled, fillcolor=\"#d4e6f1\"];");
    println!("  input -> parser;");
    println!();

    // Rule nodes
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        let color = if rule.is_stateful() { "#fde9d9" } else { "#d5f5e3" };
        let rtype = if rule.is_stateful() { "FSM" } else { "stateless" };

        let mut criteria = Vec::new();
        if !rule.is_stateful() {
            let mc = &rule.match_criteria;
            if let Some(ref et) = mc.ethertype { criteria.push(format!("ethertype={}", et)); }
            if let Some(ref mac) = mc.dst_mac { criteria.push(format!("dst={}", mac)); }
            if let Some(ref mac) = mc.src_mac { criteria.push(format!("src={}", mac)); }
            if let Some(vid) = mc.vlan_id { criteria.push(format!("vlan={}", vid)); }
            if let Some(pcp) = mc.vlan_pcp { criteria.push(format!("pcp={}", pcp)); }
        } else {
            criteria.push("(FSM states)".to_string());
        }

        let criteria_str = if criteria.is_empty() { "any".to_string() } else { criteria.join("\\n") };
        let action_str = match &rule.action {
            Some(model::Action::Pass) => "PASS",
            Some(model::Action::Drop) => "DROP",
            None => "FSM",
        };

        println!("  rule_{} [label=\"{}\\npri={} [{}]\\n{}\\n-> {}\", style=filled, fillcolor=\"{}\"];",
            i, rule.name, rule.priority, rtype, criteria_str, action_str, color);
        println!("  parser -> rule_{};", i);
    }

    println!();

    // Decision logic
    println!("  decision [label=\"Priority Encoder\\n(first match wins)\", shape=diamond, style=filled, fillcolor=\"#fadbd8\"];");
    for i in 0..config.pacgate.rules.len() {
        println!("  rule_{} -> decision;", i);
    }

    // Output nodes
    println!("  pass_out [label=\"PASS\", shape=oval, style=filled, fillcolor=\"#82e0aa\"];");
    println!("  drop_out [label=\"DROP\", shape=oval, style=filled, fillcolor=\"#f1948a\"];");
    println!("  decision -> pass_out [label=\"match=pass\"];");
    println!("  decision -> drop_out [label=\"match=drop\"];");

    // Default action
    println!("  default [label=\"No Match\\n-> {}\", shape=box, style=\"filled,dashed\", fillcolor=\"#f9e79f\"];", default_action);
    println!("  decision -> default [style=dashed, label=\"no match\"];");
    let default_target = if default_action == "PASS" { "pass_out" } else { "drop_out" };
    println!("  default -> {} [style=dashed];", default_target);

    println!("}}");
}

fn diff_rules(old: &model::FilterConfig, new: &model::FilterConfig, json: bool) -> Result<()> {
    use std::collections::HashMap;

    let old_map: HashMap<&str, &model::StatelessRule> = old.pacgate.rules.iter()
        .map(|r| (r.name.as_str(), r)).collect();
    let new_map: HashMap<&str, &model::StatelessRule> = new.pacgate.rules.iter()
        .map(|r| (r.name.as_str(), r)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged = Vec::new();

    // Check for removed and modified rules
    for (name, old_rule) in &old_map {
        match new_map.get(name) {
            None => removed.push(*name),
            Some(new_rule) => {
                let mut changes = Vec::new();
                if old_rule.priority != new_rule.priority {
                    changes.push(format!("priority: {} -> {}", old_rule.priority, new_rule.priority));
                }
                if old_rule.action != new_rule.action {
                    changes.push(format!("action: {:?} -> {:?}", old_rule.action, new_rule.action));
                }
                if old_rule.match_criteria.ethertype != new_rule.match_criteria.ethertype {
                    changes.push(format!("ethertype: {:?} -> {:?}",
                        old_rule.match_criteria.ethertype, new_rule.match_criteria.ethertype));
                }
                if old_rule.match_criteria.dst_mac != new_rule.match_criteria.dst_mac {
                    changes.push(format!("dst_mac: {:?} -> {:?}",
                        old_rule.match_criteria.dst_mac, new_rule.match_criteria.dst_mac));
                }
                if old_rule.match_criteria.src_mac != new_rule.match_criteria.src_mac {
                    changes.push(format!("src_mac: {:?} -> {:?}",
                        old_rule.match_criteria.src_mac, new_rule.match_criteria.src_mac));
                }
                if old_rule.match_criteria.vlan_id != new_rule.match_criteria.vlan_id {
                    changes.push(format!("vlan_id: {:?} -> {:?}",
                        old_rule.match_criteria.vlan_id, new_rule.match_criteria.vlan_id));
                }
                if old_rule.match_criteria.vlan_pcp != new_rule.match_criteria.vlan_pcp {
                    changes.push(format!("vlan_pcp: {:?} -> {:?}",
                        old_rule.match_criteria.vlan_pcp, new_rule.match_criteria.vlan_pcp));
                }
                if old_rule.is_stateful() != new_rule.is_stateful() {
                    changes.push(format!("type: {} -> {}",
                        if old_rule.is_stateful() { "stateful" } else { "stateless" },
                        if new_rule.is_stateful() { "stateful" } else { "stateless" }));
                }

                if changes.is_empty() {
                    unchanged.push(*name);
                } else {
                    modified.push((*name, changes));
                }
            }
        }
    }

    // Check for added rules
    for name in new_map.keys() {
        if !old_map.contains_key(name) {
            added.push(*name);
        }
    }

    // Sort for deterministic output
    added.sort();
    removed.sort();
    modified.sort_by_key(|(name, _)| *name);

    // Check default action change
    let default_changed = old.pacgate.defaults.action != new.pacgate.defaults.action;

    if json {
        let summary = serde_json::json!({
            "added": added,
            "removed": removed,
            "modified": modified.iter().map(|(name, changes)| {
                serde_json::json!({ "name": name, "changes": changes })
            }).collect::<Vec<_>>(),
            "unchanged": unchanged.len(),
            "default_action_changed": default_changed,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        if default_changed {
            println!("  Default action: {:?} -> {:?}",
                old.pacgate.defaults.action, new.pacgate.defaults.action);
            println!();
        }

        if added.is_empty() && removed.is_empty() && modified.is_empty() && !default_changed {
            println!("No differences found.");
            return Ok(());
        }

        if !added.is_empty() {
            println!("  Added ({}):", added.len());
            for name in &added {
                let r = new_map[name];
                println!("    + {} (priority {}, {:?})", name, r.priority,
                    r.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or("default".to_string()));
            }
            println!();
        }

        if !removed.is_empty() {
            println!("  Removed ({}):", removed.len());
            for name in &removed {
                let r = old_map[name];
                println!("    - {} (priority {})", name, r.priority);
            }
            println!();
        }

        if !modified.is_empty() {
            println!("  Modified ({}):", modified.len());
            for (name, changes) in &modified {
                println!("    ~ {}", name);
                for change in changes {
                    println!("      {}", change);
                }
            }
            println!();
        }

        println!("  Summary: {} added, {} removed, {} modified, {} unchanged",
            added.len(), removed.len(), modified.len(), unchanged.len());
    }

    Ok(())
}

fn compute_resource_estimate(config: &model::FilterConfig) -> serde_json::Value {
    let rules = &config.pacgate.rules;
    let num_stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let num_stateful = rules.iter().filter(|r| r.is_stateful()).count();
    let total = rules.len();

    let parser_luts = 120;
    let parser_ffs = 90;

    let mut rule_luts = 0usize;
    let mut rule_ffs = 0usize;

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
            if mc.dst_mac.is_some() { fields += 3; }
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

    let rule_limit_warning = if total > 64 {
        Some(format!("{} rules exceeds recommended limit of 64 for Artix-7", total))
    } else if total > 32 {
        Some(format!("{} rules — consider pipelining the priority encoder for Fmax > 200 MHz", total))
    } else {
        None
    };

    serde_json::json!({
        "rules": {
            "stateless": num_stateless,
            "stateful": num_stateful,
            "total": total,
        },
        "components": {
            "frame_parser": { "luts": parser_luts, "ffs": parser_ffs },
            "rule_matchers": { "luts": rule_luts, "ffs": rule_ffs },
            "decision_logic": { "luts": decision_luts, "ffs": decision_ffs },
            "io_logic": { "luts": io_luts, "ffs": 0 },
        },
        "total": { "luts": total_luts, "ffs": total_ffs },
        "utilization": {
            "xc7a35t": {
                "lut_percent": format!("{:.1}", total_luts as f64 / 20800.0 * 100.0),
                "ff_percent": format!("{:.1}", total_ffs as f64 / 41600.0 * 100.0),
            },
            "xc7a100t": {
                "lut_percent": format!("{:.1}", total_luts as f64 / 63400.0 * 100.0),
                "ff_percent": format!("{:.1}", total_ffs as f64 / 126800.0 * 100.0),
            },
        },
        "timing": {
            "clock_mhz": 125,
            "parser_cycles": 14,
            "match_decision_cycles": 2,
            "total_cycles": 16,
            "latency_ns": 128,
        },
        "rule_limit_warning": rule_limit_warning,
    })
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

    // Timing estimates
    // Frame parser: 14 cycles (6 dst + 6 src + 2 ethertype), plus 4 if VLAN tagged
    // Rule matching: 1 cycle (combinational, parallel)
    // Decision logic: 1 cycle (registered output)
    // Total pipeline: ~16-20 cycles per frame header
    let parser_cycles = 14; // base Ethernet header
    let match_cycles = 1;   // combinational parallel evaluation
    let decision_cycles = 1; // registered output
    let total_cycles = parser_cycles + match_cycles + decision_cycles;

    // At 125 MHz (common for GbE), clock period = 8ns
    // Decision latency = total_cycles * 8ns
    let clock_mhz = 125.0;
    let latency_ns = total_cycles as f64 * (1000.0 / clock_mhz);

    println!("  Timing (at {:.0} MHz):", clock_mhz);
    println!("  ───────────────────── ──────────");
    println!("  Parser latency           {:>2} cycles", parser_cycles);
    println!("  Match + decision          {:>2} cycles", match_cycles + decision_cycles);
    println!("  Total decision latency   {:>2} cycles ({:.0} ns)", total_cycles, latency_ns);
    println!();

    // Rule count limits
    if total > 64 {
        println!("  WARNING: {} rules exceeds recommended limit of 64 for Artix-7", total);
        println!("           Critical path through priority encoder may limit Fmax.");
    } else if total > 32 {
        println!("  Note: {} rules — consider pipelining the priority encoder for Fmax > 200 MHz.", total);
    }
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
