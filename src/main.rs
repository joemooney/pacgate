mod model;
mod loader;
mod verilog_gen;
mod cocotb_gen;
mod formal_gen;
mod pcap;
mod mermaid;
mod simulator;
mod pcap_analyze;

use std::path::{Path, PathBuf};
use clap::{CommandFactory, Parser, Subcommand};
use anyhow::{Context, Result};

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

        /// Include AXI-Stream wrapper (adapter, FIFO, AXI top-level + tests)
        #[arg(long)]
        axi: bool,

        /// Include per-rule counters with AXI-Lite CSR readout
        #[arg(long)]
        counters: bool,

        /// Generate multi-port wrapper with N independent filter instances
        #[arg(long, default_value = "1")]
        ports: u16,

        /// Include connection tracking table RTL
        #[arg(long)]
        conntrack: bool,

        /// Include rate limiter RTL for rules with rate_limit
        #[arg(long)]
        rate_limit: bool,
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
    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell type (bash, zsh, fish, elvish, powershell)
        shell: clap_complete::Shell,
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
    /// Lint rules for best practices, security issues, and optimization hints
    Lint {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Generate SVA assertions and SymbiYosys formal verification files
    Formal {
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
    /// Generate HTML coverage report for a rule set
    Report {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output HTML file path
        #[arg(short, long, default_value = "gen/coverage_report.html")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,
    },
    /// Import PCAP capture file and generate cocotb test stimulus
    Pcap {
        /// Path to the PCAP capture file
        pcap_file: PathBuf,

        /// Output directory for generated stimulus file
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Output JSON summary instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Import a Mermaid stateDiagram-v2 and convert to PacGate YAML
    FromMermaid {
        /// Path to the Mermaid diagram file (.md)
        diagram: PathBuf,

        /// Rule name for the generated YAML
        #[arg(long, default_value = "fsm_rule")]
        name: String,

        /// Rule priority
        #[arg(long, default_value = "100")]
        priority: u32,

        /// Output YAML file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Export PacGate YAML stateful rules as Mermaid stateDiagram-v2
    ToMermaid {
        /// Path to the YAML rules file
        rules: PathBuf,
    },
    /// Simulate a packet against the rule set (software dry-run)
    Simulate {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Packet specification: key=value pairs separated by commas
        /// e.g. "ethertype=0x0800,src_ip=10.0.0.1,dst_port=80"
        #[arg(short, long)]
        packet: String,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Analyze PCAP traffic and suggest PacGate rules
    PcapAnalyze {
        /// Path to the PCAP capture file
        pcap_file: PathBuf,

        /// Suggestion mode: whitelist, blacklist, or auto
        #[arg(short, long, default_value = "auto")]
        mode: String,

        /// Write suggested rules to YAML file
        #[arg(short, long)]
        output_yaml: Option<PathBuf>,

        /// Maximum number of suggested rules
        #[arg(long, default_value = "20")]
        max_rules: usize,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { rules, output, templates, json, axi, counters, ports, conntrack, rate_limit } => {
            log::info!("Compiling rules from {}", rules.display());
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;

            // Generate Verilog
            verilog_gen::generate(&config, &templates, &output)?;

            // Generate multi-port wrapper if --ports > 1
            if ports > 1 {
                verilog_gen::generate_multiport(&config, &templates, &output, ports)?;
            }

            // Copy conntrack RTL if --conntrack
            if conntrack {
                verilog_gen::copy_conntrack_rtl(&output)?;
            }

            // Copy rate limiter RTL if --rate-limit or any rule has rate_limit
            let has_rate_limit = rate_limit || config.pacgate.rules.iter().any(|r| r.rate_limit.is_some());
            if has_rate_limit {
                verilog_gen::copy_rate_limiter_rtl(&output)?;
            }

            // Copy AXI-Stream wrapper RTL if --axi
            if axi {
                verilog_gen::copy_axi_rtl(&output)?;
            }

            // Copy counter RTL if --counters
            if counters {
                verilog_gen::copy_counter_rtl(&output)?;
            }

            // Generate cocotb tests
            cocotb_gen::generate(&config, &templates, &output)?;

            // Generate AXI-Stream cocotb tests if --axi
            if axi {
                cocotb_gen::generate_axi_tests(&config, &templates, &output)?;
            }

            if json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "rules_file": rules.to_string_lossy(),
                    "rules_count": config.pacgate.rules.len(),
                    "default_action": match config.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "output_dir": output.to_string_lossy(),
                    "axi_stream": axi,
                    "counters": counters,
                    "ports": ports,
                    "conntrack": conntrack,
                    "rate_limit": has_rate_limit,
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
                if axi {
                    println!("  Generated AXI-Stream wrapper in {}/rtl/", output.display());
                    println!("  Generated AXI-Stream tests in {}/tb-axi/", output.display());
                }
                if counters {
                    println!("  Generated per-rule counters + AXI-Lite CSR in {}/rtl/", output.display());
                }
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
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "pacgate", &mut std::io::stdout());
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
        Commands::Lint { rules, json } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            let findings = lint_rules(&config, &warnings);
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                print_lint_results(&findings);
            }
        }
        Commands::Formal { rules, output, templates, json } => {
            log::info!("Generating formal verification files from {}", rules.display());
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;

            // First generate RTL (needed for formal)
            verilog_gen::generate(&config, &templates, &output)?;

            // Generate SVA assertions + SBY task file
            formal_gen::generate(&config, &templates, &output)?;

            if json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "rules_file": rules.to_string_lossy(),
                    "rules_count": config.pacgate.rules.len(),
                    "output_dir": output.to_string_lossy(),
                    "generated": {
                        "assertions": format!("{}/formal/assertions.sv", output.display()),
                        "sby_task": format!("{}/formal/packet_filter.sby", output.display()),
                        "verilog_dir": format!("{}/rtl", output.display()),
                    },
                    "warnings": warnings,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                println!("Generated formal verification files from {} rules", config.pacgate.rules.len());
                println!("  SVA assertions:  {}/formal/assertions.sv", output.display());
                println!("  SymbiYosys task: {}/formal/packet_filter.sby", output.display());
                println!();
                println!("Run formal verification:");
                println!("  cd {}/formal && sby -f packet_filter.sby", output.display());
            }
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
        Commands::Report { rules, output, templates } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            generate_coverage_report(&config, &warnings, &rules, &templates, &output)?;
            println!("Generated coverage report: {}", output.display());
        }
        Commands::Pcap { pcap_file, output, json } => {
            let packets = pcap::read_pcap(&pcap_file)?;

            if packets.is_empty() {
                anyhow::bail!("PCAP file contains no Ethernet frames");
            }

            // Generate stimulus file
            let tb_dir = output.join("tb");
            std::fs::create_dir_all(&tb_dir)?;
            let stimulus = pcap::generate_stimulus(&packets);
            std::fs::write(tb_dir.join("pcap_stimulus.py"), &stimulus)?;

            if json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "pcap_file": pcap_file.to_string_lossy(),
                    "frame_count": packets.len(),
                    "total_bytes": packets.iter().map(|p| p.data.len()).sum::<usize>(),
                    "min_frame_size": packets.iter().map(|p| p.data.len()).min().unwrap_or(0),
                    "max_frame_size": packets.iter().map(|p| p.data.len()).max().unwrap_or(0),
                    "output_file": format!("{}/tb/pcap_stimulus.py", output.display()),
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                pcap::print_summary(&packets);
                println!();
                println!("  Generated stimulus: {}/tb/pcap_stimulus.py", output.display());
                println!("  Use in cocotb: from pcap_stimulus import PCAP_FRAMES");
            }
        }
        Commands::FromMermaid { diagram, name, priority, output } => {
            let contents = std::fs::read_to_string(&diagram)
                .with_context(|| format!("Failed to read Mermaid file: {}", diagram.display()))?;
            let parsed = mermaid::parse_mermaid(&contents)
                .with_context(|| "Failed to parse Mermaid diagram")?;
            let config = mermaid::to_yaml(parsed, &name, priority);
            let yaml = serde_yaml::to_string(&config)?;
            if let Some(out_path) = output {
                std::fs::write(&out_path, &yaml)?;
                eprintln!("Wrote YAML to {}", out_path.display());
            } else {
                println!("{}", yaml);
            }
        }
        Commands::ToMermaid { rules } => {
            let (config, _warnings) = loader::load_rules_with_warnings(&rules)?;
            let mermaid_text = mermaid::from_yaml(&config);
            println!("{}", mermaid_text);
        }
        Commands::Simulate { rules, packet, json } => {
            let config = loader::load_rules(&rules)?;
            let sim_pkt = simulator::parse_packet_spec(&packet)?;
            let result = simulator::simulate(&config, &sim_pkt);

            if json {
                let fields_json: Vec<serde_json::Value> = result.fields.iter().map(|f| {
                    serde_json::json!({
                        "field": f.field,
                        "rule_value": f.rule_value,
                        "packet_value": f.packet_value,
                        "matches": f.matches,
                    })
                }).collect();
                let summary = serde_json::json!({
                    "status": "ok",
                    "matched_rule": result.rule_name,
                    "action": match result.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "is_default": result.is_default,
                    "fields": fields_json,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!();
                println!("  PacGate Packet Simulation");
                println!("  ════════════════════════════════════════════");
                println!("  Packet: {}", packet);
                println!();
                if result.is_default {
                    let action_str = match result.action { model::Action::Pass => "PASS", model::Action::Drop => "DROP" };
                    println!("  Result: DEFAULT action -> {}", action_str);
                    println!("  (No rule matched this packet)");
                } else {
                    let action_str = match result.action { model::Action::Pass => "PASS", model::Action::Drop => "DROP" };
                    println!("  Result: Rule '{}' -> {}", result.rule_name.as_deref().unwrap_or("?"), action_str);
                    println!();
                    println!("  Field Breakdown:");
                    println!("  {:15} {:20} {:20} {}", "Field", "Rule Value", "Packet Value", "Match");
                    println!("  {:15} {:20} {:20} {}", "─────", "──────────", "────────────", "─────");
                    for f in &result.fields {
                        let mark = if f.matches { "YES" } else { "NO" };
                        println!("  {:15} {:20} {:20} {}", f.field, f.rule_value, f.packet_value, mark);
                    }
                }
                println!();
            }
        }
        Commands::PcapAnalyze { pcap_file, mode, output_yaml, max_rules, json } => {
            let packets = pcap::read_pcap(&pcap_file)?;
            if packets.is_empty() {
                anyhow::bail!("PCAP file contains no Ethernet frames");
            }

            let suggest_mode = pcap_analyze::SuggestMode::from_str(&mode)?;
            let parsed: Vec<pcap_analyze::ParsedPacket> = packets.iter().map(|p| pcap_analyze::parse_packet(p)).collect();
            let analysis = pcap_analyze::analyze_traffic(&parsed);
            let suggestions = pcap_analyze::suggest_rules(&analysis, suggest_mode, max_rules);

            // Write YAML if requested
            if let Some(ref yaml_path) = output_yaml {
                let default_action = if suggest_mode == pcap_analyze::SuggestMode::Blacklist { "pass" } else { "drop" };
                let yaml = pcap_analyze::suggestions_to_yaml(&suggestions, default_action);
                std::fs::write(yaml_path, &yaml)?;
                if !json {
                    println!("  Wrote suggested rules to {}", yaml_path.display());
                }
            }

            if json {
                let json_val = pcap_analyze::analysis_to_json(&analysis, &suggestions);
                println!("{}", serde_json::to_string_pretty(&json_val)?);
            } else {
                pcap_analyze::print_analysis(&analysis);
                if !suggestions.is_empty() {
                    println!("  Suggested Rules ({}):", suggestions.len());
                    for (i, s) in suggestions.iter().enumerate() {
                        println!("    {}. {} [{}] pri={} — {}", i + 1, s.name, s.action, s.priority, s.rationale);
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn generate_coverage_report(
    config: &model::FilterConfig,
    warnings: &[String],
    rules_path: &Path,
    templates_dir: &Path,
    output_path: &Path,
) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = tera::Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rules = &config.pacgate.rules;
    let num_stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let num_pass = rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let num_drop = rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();

    // Field usage analysis
    let all_fields = [
        ("ethertype", "L2"), ("dst_mac", "L2"), ("src_mac", "L2"),
        ("vlan_id", "L2"), ("vlan_pcp", "L2"),
        ("src_ip", "L3"), ("dst_ip", "L3"), ("ip_protocol", "L3"),
        ("src_port", "L4"), ("dst_port", "L4"),
        ("vxlan_vni", "Tunnel"),
    ];

    let mut fields_info = Vec::new();
    let mut fields_used = 0usize;

    for (name, layer) in &all_fields {
        let count = rules.iter().filter(|r| !r.is_stateful()).filter(|r| {
            let mc = &r.match_criteria;
            match *name {
                "ethertype" => mc.ethertype.is_some(),
                "dst_mac" => mc.dst_mac.is_some(),
                "src_mac" => mc.src_mac.is_some(),
                "vlan_id" => mc.vlan_id.is_some(),
                "vlan_pcp" => mc.vlan_pcp.is_some(),
                "src_ip" => mc.src_ip.is_some(),
                "dst_ip" => mc.dst_ip.is_some(),
                "ip_protocol" => mc.ip_protocol.is_some(),
                "src_port" => mc.src_port.is_some(),
                "dst_port" => mc.dst_port.is_some(),
                "vxlan_vni" => mc.vxlan_vni.is_some(),
                _ => false,
            }
        }).count();

        let pct = if num_stateless > 0 { (count * 100) / num_stateless } else { 0 };
        if count > 0 { fields_used += 1; }

        fields_info.push(serde_json::json!({
            "name": name,
            "layer": layer,
            "count": count,
            "pct": pct,
        }));
    }

    let field_coverage_pct = (fields_used * 100) / all_fields.len();

    // Build per-rule info
    let mut rules_info = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let mut fields = Vec::new();
        let mc = &rule.match_criteria;
        if mc.ethertype.is_some() { fields.push("ethertype".to_string()); }
        if mc.dst_mac.is_some() { fields.push("dst_mac".to_string()); }
        if mc.src_mac.is_some() { fields.push("src_mac".to_string()); }
        if mc.vlan_id.is_some() { fields.push("vlan_id".to_string()); }
        if mc.vlan_pcp.is_some() { fields.push("vlan_pcp".to_string()); }
        if mc.src_ip.is_some() { fields.push("src_ip".to_string()); }
        if mc.dst_ip.is_some() { fields.push("dst_ip".to_string()); }
        if mc.ip_protocol.is_some() { fields.push("ip_protocol".to_string()); }
        if mc.src_port.is_some() { fields.push("src_port".to_string()); }
        if mc.dst_port.is_some() { fields.push("dst_port".to_string()); }
        if mc.vxlan_vni.is_some() { fields.push("vxlan_vni".to_string()); }

        let action = match &rule.action {
            Some(model::Action::Pass) => "pass",
            Some(model::Action::Drop) => "drop",
            None => "default",
        };
        let rtype = if rule.is_stateful() { "stateful" } else { "stateless" };

        rules_info.push(serde_json::json!({
            "index": i + 1,
            "name": rule.name,
            "type": rtype,
            "priority": rule.priority,
            "action": action,
            "fields": fields,
        }));
    }

    let timestamp = chrono_lite_now();

    let mut ctx = tera::Context::new();
    ctx.insert("rules_file", &rules_path.display().to_string());
    ctx.insert("num_rules", &rules.len());
    ctx.insert("num_stateless", &num_stateless);
    ctx.insert("num_pass", &num_pass);
    ctx.insert("num_drop", &num_drop);
    ctx.insert("field_coverage_pct", &field_coverage_pct);
    ctx.insert("fields", &fields_info);
    ctx.insert("rules", &rules_info);
    ctx.insert("warnings", warnings);
    ctx.insert("timestamp", &timestamp);

    let rendered = tera.render("coverage_report.html.tera", &ctx)?;

    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, &rendered)?;
    Ok(())
}

/// Simple timestamp without chrono dependency
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Simple UTC date formatting
            let days = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;

            // Simple year/month/day from days since epoch
            // Approximate: good enough for timestamps
            let mut y = 1970;
            let mut remaining_days = days as i64;
            loop {
                let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
                if remaining_days < days_in_year { break; }
                remaining_days -= days_in_year;
                y += 1;
            }
            let months = [31, if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29 } else { 28 },
                         31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut m = 0;
            for &dm in &months {
                if remaining_days < dm { break; }
                remaining_days -= dm;
                m += 1;
            }
            format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m + 1, remaining_days + 1, hours, minutes)
        }
        Err(_) => "unknown".to_string(),
    }
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
    let mut uses_src_ip = 0;
    let mut uses_dst_ip = 0;
    let mut uses_ip_protocol = 0;
    let mut uses_src_port = 0;
    let mut uses_dst_port = 0;
    let mut match_field_count = Vec::new();

    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let mc = &rule.match_criteria;
        let mut count = 0;
        if mc.ethertype.is_some() { uses_ethertype += 1; count += 1; }
        if mc.dst_mac.is_some() { uses_dst_mac += 1; count += 1; }
        if mc.src_mac.is_some() { uses_src_mac += 1; count += 1; }
        if mc.vlan_id.is_some() { uses_vlan_id += 1; count += 1; }
        if mc.vlan_pcp.is_some() { uses_vlan_pcp += 1; count += 1; }
        if mc.src_ip.is_some() { uses_src_ip += 1; count += 1; }
        if mc.dst_ip.is_some() { uses_dst_ip += 1; count += 1; }
        if mc.ip_protocol.is_some() { uses_ip_protocol += 1; count += 1; }
        if mc.src_port.is_some() { uses_src_port += 1; count += 1; }
        if mc.dst_port.is_some() { uses_dst_port += 1; count += 1; }
        if mc.vxlan_vni.is_some() { count += 1; }
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
            "src_ip": uses_src_ip,
            "dst_ip": uses_dst_ip,
            "ip_protocol": uses_ip_protocol,
            "src_port": uses_src_port,
            "dst_port": uses_dst_port,
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
            if let Some(ref ip) = mc.src_ip { criteria.push(format!("src_ip={}", ip)); }
            if let Some(ref ip) = mc.dst_ip { criteria.push(format!("dst_ip={}", ip)); }
            if let Some(proto) = mc.ip_protocol { criteria.push(format!("proto={}", proto)); }
            if let Some(ref port) = mc.src_port { criteria.push(format!("src_port={:?}", port)); }
            if let Some(ref port) = mc.dst_port { criteria.push(format!("dst_port={:?}", port)); }
            if let Some(vni) = mc.vxlan_vni { criteria.push(format!("vni={}", vni)); }
            if let Some(ref ip) = mc.src_ipv6 { criteria.push(format!("src_ipv6={}", ip)); }
            if let Some(ref ip) = mc.dst_ipv6 { criteria.push(format!("dst_ipv6={}", ip)); }
            if let Some(nh) = mc.ipv6_next_header { criteria.push(format!("next_hdr={}", nh)); }
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

    // Check if any rule uses L3/L4 fields (affects parser complexity)
    let has_l3l4 = rules.iter().any(|r| r.match_criteria.uses_l3l4());

    // Parser: base L2 + additional for L3/L4 (IPv4 header + TCP/UDP port parsing)
    let parser_luts = if has_l3l4 { 180 } else { 120 };
    let parser_ffs = if has_l3l4 { 160 } else { 90 };

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
            // L3/L4 fields cost more LUTs (wider comparators)
            if mc.src_ip.is_some() { fields += 2; }
            if mc.dst_ip.is_some() { fields += 2; }
            if mc.ip_protocol.is_some() { fields += 1; }
            if mc.src_port.is_some() { fields += 1; }
            if mc.dst_port.is_some() { fields += 1; }
            if mc.vxlan_vni.is_some() { fields += 2; }
            // IPv6 fields: 128-bit comparators are expensive
            if mc.src_ipv6.is_some() { fields += 8; }
            if mc.dst_ipv6.is_some() { fields += 8; }
            if mc.ipv6_next_header.is_some() { fields += 1; }
            rule_luts += 10 + fields * 12;
        }
    }

    // Rate limiter: +50 LUTs, +64 FFs per rate-limited rule
    let num_rate_limited = rules.iter().filter(|r| r.rate_limit.is_some()).count();
    let rate_luts = num_rate_limited * 50;
    let rate_ffs = num_rate_limited * 64;

    let decision_luts = 10 * total + 8;
    let decision_ffs = 4;
    let io_luts = 20;
    let total_luts = parser_luts + rule_luts + decision_luts + io_luts + rate_luts;
    let total_ffs = parser_ffs + rule_ffs + decision_ffs + rate_ffs;

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
            "rate_limiters": { "count": num_rate_limited, "luts": rate_luts, "ffs": rate_ffs },
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
            "parser_cycles": if has_l3l4 { 38 } else { 14 },
            "match_decision_cycles": 2,
            "total_cycles": if has_l3l4 { 40 } else { 16 },
            "latency_ns": if has_l3l4 { 320 } else { 128 },
            "note": if has_l3l4 { "Includes IPv4 header (20B) + TCP/UDP port (4B) parsing" } else { "L2 header parsing only" },
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
            // IPv6 fields: 128-bit comparators are expensive
            if mc.src_ipv6.is_some() { fields += 8; }
            if mc.dst_ipv6.is_some() { fields += 8; }
            if mc.ipv6_next_header.is_some() { fields += 1; }
            rule_luts += 10 + fields * 12;
        }
    }

    // Rate limiter: +50 LUTs, +64 FFs per rate-limited rule
    let num_rate_limited = rules.iter().filter(|r| r.rate_limit.is_some()).count();
    let rate_luts = num_rate_limited * 50;
    let rate_ffs = num_rate_limited * 64;

    let decision_luts = 10 * total + 8;
    let decision_ffs = 4;
    let io_luts = 20;

    let total_luts = parser_luts + rule_luts + decision_luts + io_luts + rate_luts;
    let total_ffs = parser_ffs + rule_ffs + decision_ffs + rate_ffs;

    // Artix-7 reference: XC7A35T has 20,800 LUTs, 41,600 FFs
    let artix_lut_pct = total_luts as f64 / 20800.0 * 100.0;
    let artix_ff_pct = total_ffs as f64 / 41600.0 * 100.0;

    println!();
    println!("  PacGate Resource Estimate");
    println!("  ════════════════════════════════════════════");
    println!("  Rules:  {} stateless, {} stateful, {} total", num_stateless, num_stateful, total);
    if num_rate_limited > 0 {
        println!("  Rate-limited rules: {}", num_rate_limited);
    }
    println!();
    println!("  Component             Est. LUTs   Est. FFs");
    println!("  ───────────────────── ────────── ─────────");
    println!("  Frame parser              {:>5}     {:>5}", parser_luts, parser_ffs);
    println!("  Rule matchers             {:>5}     {:>5}", rule_luts, rule_ffs);
    if num_rate_limited > 0 {
        println!("  Rate limiters             {:>5}     {:>5}", rate_luts, rate_ffs);
    }
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

fn lint_rules(config: &model::FilterConfig, warnings: &[String]) -> serde_json::Value {
    let rules = &config.pacgate.rules;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Check 1: No ARP rule in whitelist mode
    let is_whitelist = matches!(config.pacgate.defaults.action, model::Action::Drop);
    if is_whitelist {
        let has_arp = rules.iter().any(|r| {
            !r.is_stateful() && r.match_criteria.ethertype.as_deref() == Some("0x0806")
                && matches!(r.action(), model::Action::Pass)
        });
        if !has_arp {
            findings.push(serde_json::json!({
                "level": "warning",
                "code": "LINT001",
                "message": "Whitelist mode with no ARP allow rule — hosts won't be able to resolve MAC addresses",
                "suggestion": "Add a rule with ethertype: \"0x0806\" and action: pass"
            }));
        }
    }

    // Check 2: Broadcast block should be highest priority
    let broadcast_rules: Vec<_> = rules.iter().filter(|r| {
        !r.is_stateful() && r.match_criteria.dst_mac.as_deref() == Some("ff:ff:ff:ff:ff:ff")
    }).collect();
    for br in &broadcast_rules {
        let higher = rules.iter().any(|r| r.priority > br.priority && r.name != br.name);
        if higher && matches!(br.action(), model::Action::Drop) {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT002",
                "message": format!("Broadcast drop rule '{}' (priority {}) is not the highest priority — higher rules may pass broadcast frames", br.name, br.priority),
                "suggestion": "Consider making broadcast block the highest priority rule"
            }));
        }
    }

    // Check 3: Priority gaps too tight
    let mut priorities: Vec<(u32, &str)> = rules.iter().map(|r| (r.priority, r.name.as_str())).collect();
    priorities.sort();
    for w in priorities.windows(2) {
        let gap = w[1].0 - w[0].0;
        if gap < 5 {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT003",
                "message": format!("Tight priority gap ({}) between '{}' (pri {}) and '{}' (pri {}) — leaves no room for future rules", gap, w[0].1, w[0].0, w[1].1, w[1].0),
                "suggestion": "Use gaps of 10+ between priorities for future flexibility"
            }));
        }
    }

    // Check 4: Blacklist mode without STP protection
    let is_blacklist = matches!(config.pacgate.defaults.action, model::Action::Pass);
    if is_blacklist {
        let blocks_stp = rules.iter().any(|r| {
            !r.is_stateful() && r.match_criteria.dst_mac.as_deref() == Some("01:80:c2:00:00:00")
                && matches!(r.action(), model::Action::Drop)
        });
        if !blocks_stp {
            findings.push(serde_json::json!({
                "level": "warning",
                "code": "LINT004",
                "message": "Blacklist mode with no STP BPDU block rule — vulnerable to spanning tree attacks",
                "suggestion": "Add a rule to drop dst_mac: \"01:80:c2:00:00:00\" on user-facing ports"
            }));
        }
    }

    // Check 5: Stateful rules without timeout
    for rule in rules.iter().filter(|r| r.is_stateful()) {
        if let Some(fsm) = &rule.fsm {
            let states_without_timeout: Vec<_> = fsm.states.iter()
                .filter(|(name, state)| name.as_str() != &fsm.initial_state && state.timeout_cycles.is_none())
                .map(|(name, _)| name.as_str())
                .collect();
            if !states_without_timeout.is_empty() {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT005",
                    "message": format!("Stateful rule '{}' has states without timeouts: {} — FSM may get stuck", rule.name, states_without_timeout.join(", ")),
                    "suggestion": "Add timeout_cycles to non-idle states to ensure FSM recovery"
                }));
            }
        }
    }

    // Check 6: Large rule count
    if rules.len() > 32 {
        findings.push(serde_json::json!({
            "level": "warning",
            "code": "LINT006",
            "message": format!("{} rules — priority encoder critical path may limit Fmax on Artix-7", rules.len()),
            "suggestion": "Consider pipelining or reducing rule count for timing closure"
        }));
    }

    // Check 7: Single-field rules that could be combined
    let ethertype_pass: Vec<_> = rules.iter().filter(|r| {
        !r.is_stateful()
            && r.match_criteria.ethertype.is_some()
            && r.match_criteria.dst_mac.is_none()
            && r.match_criteria.src_mac.is_none()
            && r.match_criteria.vlan_id.is_none()
            && r.match_criteria.vlan_pcp.is_none()
            && matches!(r.action(), model::Action::Pass)
    }).collect();
    if ethertype_pass.len() > 5 {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT007",
            "message": format!("{} rules match only on ethertype — consider using a future multi-value match feature", ethertype_pass.len()),
            "suggestion": "Group related protocol allows for maintainability"
        }));
    }

    // Check 8: Dead rule — fully shadowed by a higher-priority rule with same action
    {
        let stateless: Vec<_> = rules.iter().filter(|r| !r.is_stateful()).collect();
        let mut sorted = stateless.clone();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let high = sorted[i];
                let low = sorted[j];
                if high.action() == low.action()
                    && loader::criteria_shadows(&high.match_criteria, &low.match_criteria)
                {
                    findings.push(serde_json::json!({
                        "level": "error",
                        "code": "LINT008",
                        "message": format!("Dead rule '{}' (priority {}) — fully shadowed by '{}' (priority {}) with same action",
                            low.name, low.priority, high.name, high.priority),
                        "suggestion": format!("Remove '{}' or change its action/criteria", low.name)
                    }));
                }
            }
        }
    }

    // Check 9: Unused FSM variable — declared but never referenced in guards, actions, entry/exit
    for rule in rules.iter().filter(|r| r.is_stateful()) {
        if let Some(fsm) = &rule.fsm {
            if let Some(vars) = &fsm.variables {
                for var in vars {
                    let var_name = &var.name;
                    let mut used = false;
                    for state in fsm.states.values() {
                        // Check transitions: guards and on_transition actions
                        for tr in &state.transitions {
                            if let Some(guard) = &tr.guard {
                                if guard.contains(var_name.as_str()) { used = true; }
                            }
                            if let Some(actions) = &tr.on_transition {
                                for a in actions {
                                    if a.contains(var_name.as_str()) { used = true; }
                                }
                            }
                        }
                        // Check on_entry/on_exit actions
                        if let Some(actions) = &state.on_entry {
                            for a in actions {
                                if a.contains(var_name.as_str()) { used = true; }
                            }
                        }
                        if let Some(actions) = &state.on_exit {
                            for a in actions {
                                if a.contains(var_name.as_str()) { used = true; }
                            }
                        }
                    }
                    if !used {
                        findings.push(serde_json::json!({
                            "level": "warning",
                            "code": "LINT009",
                            "message": format!("Unused FSM variable '{}' in rule '{}' — declared but never referenced in guards/actions",
                                var_name, rule.name),
                            "suggestion": format!("Remove variable '{}' or reference it in a guard or action", var_name)
                        }));
                    }
                }
            }
        }
    }

    // Check 10: Unreachable FSM state — BFS from initial state finds no path to this state
    for rule in rules.iter().filter(|r| r.is_stateful()) {
        if let Some(fsm) = &rule.fsm {
            let mut reachable = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            reachable.insert(fsm.initial_state.clone());
            queue.push_back(fsm.initial_state.clone());
            while let Some(state_name) = queue.pop_front() {
                if let Some(state) = fsm.states.get(&state_name) {
                    for tr in &state.transitions {
                        if !reachable.contains(&tr.next_state) {
                            reachable.insert(tr.next_state.clone());
                            queue.push_back(tr.next_state.clone());
                        }
                    }
                    // Also check timeout target (goes back to initial by convention)
                }
            }
            for state_name in fsm.states.keys() {
                if !reachable.contains(state_name) {
                    findings.push(serde_json::json!({
                        "level": "warning",
                        "code": "LINT010",
                        "message": format!("Unreachable FSM state '{}' in rule '{}' — no transition path from initial state '{}'",
                            state_name, rule.name, fsm.initial_state),
                        "suggestion": format!("Add a transition to '{}' or remove it", state_name)
                    }));
                }
            }
        }
    }

    // Check 11: L3/L4 rules in whitelist mode without explicit IPv4 (0x0800) allow
    if is_whitelist {
        let has_l3l4_rules = rules.iter().any(|r| !r.is_stateful() && r.match_criteria.uses_l3l4());
        let has_ipv4_allow = rules.iter().any(|r| {
            !r.is_stateful()
                && r.match_criteria.ethertype.as_deref() == Some("0x0800")
                && matches!(r.action(), model::Action::Pass)
                && r.match_criteria.dst_mac.is_none()
                && r.match_criteria.src_mac.is_none()
                && r.match_criteria.src_ip.is_none()
                && r.match_criteria.dst_ip.is_none()
        });
        if has_l3l4_rules && !has_ipv4_allow {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT011",
                "message": "L3/L4 match rules present in whitelist mode but no generic IPv4 (ethertype 0x0800) allow rule",
                "suggestion": "L3/L4 rules already match IPv4 packets; add a broad 0x0800 allow if you want all IPv4 traffic passed"
            }));
        }
    }

    // Check 12: byte_match offset > 64 — beyond typical header region
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        if let Some(byte_matches) = &rule.match_criteria.byte_match {
            for bm in byte_matches {
                if bm.offset > 64 {
                    findings.push(serde_json::json!({
                        "level": "info",
                        "code": "LINT012",
                        "message": format!("byte_match offset {} in rule '{}' — beyond typical header region (>64 bytes)",
                            bm.offset, rule.name),
                        "suggestion": "Verify this offset is intentional; typical L2/L3/L4 headers are within first 64 bytes"
                    }));
                }
            }
        }
    }

    // Include overlap warnings
    for w in warnings {
        findings.push(serde_json::json!({
            "level": "warning",
            "code": "OVERLAP",
            "message": w,
        }));
    }

    let error_count = findings.iter().filter(|f| f["level"] == "error").count();
    let warn_count = findings.iter().filter(|f| f["level"] == "warning").count();
    let info_count = findings.iter().filter(|f| f["level"] == "info").count();

    serde_json::json!({
        "rules_file": "analyzed",
        "total_rules": rules.len(),
        "findings": findings,
        "summary": {
            "errors": error_count,
            "warnings": warn_count,
            "info": info_count,
            "total": findings.len(),
        }
    })
}

fn print_lint_results(results: &serde_json::Value) {
    let findings = results["findings"].as_array().unwrap();
    let total = results["total_rules"].as_u64().unwrap();

    println!();
    println!("  PacGate Lint Results ({} rules analyzed)", total);
    println!("  ════════════════════════════════════════════");
    println!();

    if findings.is_empty() {
        println!("  No issues found. Rules look good!");
        println!();
        return;
    }

    for f in findings {
        let level = f["level"].as_str().unwrap();
        let icon = match level {
            "error" => "ERROR",
            "warning" => " WARN",
            "info" => " INFO",
            _ => "     ",
        };
        let code = f["code"].as_str().unwrap_or("");
        let msg = f["message"].as_str().unwrap();
        println!("  [{}] {} {}", icon, code, msg);
        if let Some(suggestion) = f["suggestion"].as_str() {
            println!("         -> {}", suggestion);
        }
        println!();
    }

    let summary = &results["summary"];
    println!("  Summary: {} errors, {} warnings, {} info",
        summary["errors"], summary["warnings"], summary["info"]);
    println!();
}

const INIT_TEMPLATE: &str = r#"# PacGate Rule File
# Documentation: https://github.com/joemooney/pacgate
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
    #
    # IPv6 CIDR matching:
    # - name: allow_ipv6_subnet
    #   type: stateless
    #   priority: 85
    #   match:
    #     src_ipv6: "2001:db8::/32"
    #     ipv6_next_header: 6    # TCP
    #     dst_port: 80
    #   action: pass
    #
    # Rate limiting (token bucket):
    # - name: rate_limited_http
    #   type: stateless
    #   priority: 95
    #   match:
    #     ethertype: "0x0800"
    #     ip_protocol: 6
    #     dst_port: 80
    #   action: pass
    #   rate_limit:
    #     pps: 10000
    #     burst: 128
"#;
