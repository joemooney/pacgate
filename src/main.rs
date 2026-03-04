#![recursion_limit = "256"]
mod model;
mod loader;
mod verilog_gen;
mod cocotb_gen;
mod formal_gen;
mod pcap;
mod mermaid;
mod simulator;
mod pcap_analyze;
mod synth_gen;
mod mutation;
mod templates_lib;
mod reachability;
mod pcap_writer;
mod benchmark;
mod mcy_gen;
mod scenario;
mod p4_gen;

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

        /// Generate runtime-updateable flow table instead of static matchers
        #[arg(long)]
        dynamic: bool,

        /// Maximum number of flow table entries (1-256, default 16)
        #[arg(long, default_value = "16")]
        dynamic_entries: u16,

        /// Platform integration target: standalone (default), opennic, or corundum
        #[arg(long, default_value = "standalone")]
        target: String,

        /// AXI-Stream data path width in bits (8, 64, 128, 256, 512)
        #[arg(long, default_value = "8")]
        width: u16,

        /// Include PTP hardware clock for IEEE 1588 timestamping
        #[arg(long)]
        ptp: bool,

        /// Enable RSS (Receive Side Scaling) multi-queue dispatch
        #[arg(long)]
        rss: bool,

        /// Number of RSS queues (1-16, default 4; implies --rss)
        #[arg(long, default_value = "4")]
        rss_queues: u8,
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

        /// Estimate for dynamic flow table mode
        #[arg(long)]
        dynamic: bool,

        /// Number of flow table entries (for dynamic estimation)
        #[arg(long, default_value = "16")]
        dynamic_entries: u16,

        /// Platform target: standalone (default), opennic, or corundum
        #[arg(long, default_value = "standalone")]
        target: String,

        /// AXI-Stream data path width in bits (8, 64, 128, 256, 512)
        #[arg(long, default_value = "8")]
        width: u16,
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

        /// Generate HTML diff report
        #[arg(long)]
        html: Option<PathBuf>,

        /// Templates directory (for HTML output)
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,
    },
    /// Lint rules for best practices, security issues, and optimization hints
    Lint {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,

        /// Lint for dynamic flow table mode
        #[arg(long)]
        dynamic: bool,

        /// Number of flow table entries (for dynamic lint)
        #[arg(long, default_value = "16")]
        dynamic_entries: u16,

        /// Platform target for lint checks
        #[arg(long, default_value = "standalone")]
        target: String,

        /// AXI-Stream data path width in bits (8, 64, 128, 256, 512)
        #[arg(long, default_value = "8")]
        width: u16,
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

        /// Generate assertions for dynamic flow table mode
        #[arg(long)]
        dynamic: bool,

        /// Number of flow table entries (for dynamic formal)
        #[arg(long, default_value = "16")]
        dynamic_entries: u16,
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

        /// Write simulation results as PCAP file (Wireshark-compatible)
        #[arg(long)]
        pcap_out: Option<PathBuf>,

        /// Enable stateful simulation (rate-limit + connection tracking)
        #[arg(long)]
        stateful: bool,
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
    /// Generate synthesis project files (Yosys or Vivado)
    Synth {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated files
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,

        /// Synthesis target: yosys or vivado
        #[arg(long, default_value = "yosys")]
        target: String,

        /// Device/part (yosys: artix7/ice40/ecp5, vivado: part number)
        #[arg(long, default_value = "artix7")]
        part: String,

        /// Clock frequency in MHz
        #[arg(long, default_value = "125.0")]
        clock_mhz: f64,

        /// Include AXI-Stream wrapper
        #[arg(long)]
        axi: bool,

        /// Include per-rule counters
        #[arg(long)]
        counters: bool,

        /// Include connection tracking
        #[arg(long)]
        conntrack: bool,

        /// Include rate limiter
        #[arg(long)]
        rate_limit: bool,

        /// Multi-port count
        #[arg(long, default_value = "1")]
        ports: u16,

        /// Parse existing synthesis log instead of generating
        #[arg(long)]
        parse_results: Option<PathBuf>,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Generate mutation test variants for a rule set
    Mutate {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated mutants
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,

        /// Output JSON report instead of human-readable text
        #[arg(long)]
        json: bool,

        /// Run mutation tests (compile + lint each mutant, report kill rate)
        #[arg(long)]
        run: bool,
    },
    /// Generate MCY (Mutation Cover with Yosys) configuration for Verilog-level mutation testing
    Mcy {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated files
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,

        /// Run MCY after generating config (requires mcy binary in PATH)
        #[arg(long)]
        run: bool,
    },
    /// Manage rule templates (list, show, apply)
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },
    /// Analyze rule set reachability (which traffic reaches which action)
    Reachability {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Run performance benchmark (compile time, simulation throughput, scaling)
    Bench {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Generate HTML documentation for a rule set
    Doc {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output HTML file path
        #[arg(short, long, default_value = "gen/rule_documentation.html")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,
    },
    /// Manage scenario files (validate, import, export)
    Scenario {
        #[command(subcommand)]
        action: ScenarioAction,
    },
    /// Run packet regression against a scenario
    Regress {
        /// Path to the scenario JSON file
        #[arg(long)]
        scenario: PathBuf,

        /// Number of packets to simulate
        #[arg(long, default_value = "1000")]
        count: usize,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Run topology simulation against a scenario
    Topology {
        /// Path to the scenario JSON file
        #[arg(long)]
        scenario: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Export YAML rules as a P4_16 PSA program
    P4Export {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated P4 files
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,

        /// Output JSON summary instead of P4 code
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TemplateAction {
    /// List available rule templates
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Output JSON instead of table
        #[arg(long)]
        json: bool,
    },
    /// Show details of a specific template
    Show {
        /// Template name
        name: String,
    },
    /// Apply a template to generate a rules YAML file
    Apply {
        /// Template name
        name: String,

        /// Output YAML file path
        #[arg(short, long, default_value = "rules.yaml")]
        output: PathBuf,

        /// Set template variables (key=value)
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ScenarioAction {
    /// Validate scenario JSON files
    Validate {
        /// Scenario files to validate
        files: Vec<PathBuf>,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Import scenario files into a store
    Import {
        /// Directory containing scenario JSON files
        #[arg(long)]
        in_dir: PathBuf,

        /// Path to the scenario store file
        #[arg(long, default_value = "examples/custom_scenarios.json")]
        store: PathBuf,

        /// Replace entire store instead of merging
        #[arg(long)]
        replace: bool,
    },
    /// Export scenarios from a store to individual files
    Export {
        /// Path to the scenario store file
        #[arg(long)]
        store: PathBuf,

        /// Output directory for exported files
        #[arg(long, default_value = "examples/scenarios")]
        out_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { rules, output, templates, json, axi, counters, ports, conntrack, rate_limit, dynamic, dynamic_entries, target, width, ptp, rss, rss_queues } => {
            // --rss-queues != 4 implies --rss
            let rss = rss || rss_queues != 4;
            // Validate width parameter
            match width {
                8 | 64 | 128 | 256 | 512 => {}
                _ => anyhow::bail!("--width must be 8, 64, 128, 256, or 512 (got {})", width),
            }
            let platform = verilog_gen::PlatformTarget::from_str(&target)?;

            // Validate platform target constraints
            if platform.is_platform() {
                if dynamic {
                    anyhow::bail!("--target {} is incompatible with --dynamic in V1 (AXI-Lite address space conflict)", platform.name());
                }
                if ports > 1 {
                    anyhow::bail!("--target {} is incompatible with --ports > 1 in V1", platform.name());
                }
            }

            // Width > 8 requires AXI wrapper (width converters are part of AXI pipeline)
            if width > 8 && !axi && !platform.is_platform() {
                anyhow::bail!("--width {} requires --axi flag (width converters are part of the AXI pipeline)", width);
            }

            // Validate RSS parameters
            if rss_queues < 1 || rss_queues > 16 {
                anyhow::bail!("--rss-queues must be 1-16 (got {})", rss_queues);
            }
            if rss && !axi && !platform.is_platform() {
                anyhow::bail!("--rss requires --axi flag (RSS uses AXI-Lite CSR for key/indirection table)");
            }

            // Platform targets implicitly enable AXI
            let axi = axi || platform.is_platform();
            log::info!("Compiling rules from {}", rules.display());
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;

            // Validate dynamic mode constraints
            if dynamic {
                loader::validate_dynamic(&config, conntrack, dynamic_entries)?;
            }

            // Generate Verilog
            if dynamic {
                verilog_gen::generate_dynamic(&config, &templates, &output, dynamic_entries)?;
            } else if config.is_pipeline() {
                verilog_gen::generate_pipeline(&config, &templates, &output)?;
            } else {
                verilog_gen::generate(&config, &templates, &output)?;
            }

            // Generate multi-port wrapper if --ports > 1
            if ports > 1 {
                verilog_gen::generate_multiport(&config, &templates, &output, ports)?;
            }

            // Copy conntrack RTL if --conntrack
            if conntrack {
                verilog_gen::copy_conntrack_rtl(&output)?;
            }

            // Copy PTP clock RTL if --ptp
            if ptp {
                let src = std::path::Path::new("rtl").join("ptp_clock.v");
                if src.exists() {
                    let dst = output.join("rtl").join("ptp_clock.v");
                    std::fs::create_dir_all(output.join("rtl"))?;
                    std::fs::copy(&src, &dst)?;
                    log::info!("Copied ptp_clock.v to {}", dst.display());
                }
            }

            // Copy RSS RTL if --rss
            if rss {
                let rtl_dir = output.join("rtl");
                std::fs::create_dir_all(&rtl_dir)?;
                for name in &["rss_toeplitz.v", "rss_indirection.v"] {
                    let src = std::path::Path::new("rtl").join(name);
                    if src.exists() {
                        let dst = rtl_dir.join(name);
                        std::fs::copy(&src, &dst)?;
                        log::info!("Copied {} to {}", name, dst.display());
                    }
                }
            }

            // Copy rate limiter RTL if --rate-limit or any rule has rate_limit
            let has_rate_limit = rate_limit || config.pacgate.rules.iter().any(|r| r.rate_limit.is_some());
            if has_rate_limit {
                verilog_gen::copy_rate_limiter_rtl(&output)?;
            }

            // Copy/generate AXI-Stream wrapper RTL if --axi
            if axi {
                verilog_gen::copy_axi_rtl(&output, &config, &templates, width)?;
            }

            // Copy counter RTL if --counters
            if counters {
                verilog_gen::copy_counter_rtl(&output)?;
            }

            // Platform target: copy width converters and generate wrapper
            // If --width 512 matches platform native width, skip redundant converters
            if platform.is_platform() {
                if width == 512 {
                    // Native width matches — no converters needed
                } else if width > 8 {
                    // Use parameterized converters for non-native widths
                    verilog_gen::generate_width_converters(&templates, &output.join("rtl"), width)?;
                } else {
                    // Default 8-bit: use hardcoded 512↔8 converters
                    verilog_gen::copy_width_converter_rtl(&output)?;
                }
                match &platform {
                    verilog_gen::PlatformTarget::OpenNic => {
                        verilog_gen::generate_opennic_wrapper(&config, &templates, &output)?;
                    }
                    verilog_gen::PlatformTarget::Corundum => {
                        verilog_gen::generate_corundum_wrapper(&config, &templates, &output)?;
                    }
                    _ => {}
                }
            }

            // Generate cocotb tests + runner scripts
            if dynamic {
                cocotb_gen::generate_dynamic_tests(&config, &templates, &output, dynamic_entries)?;
                cocotb_gen::generate_dynamic_runner(&templates, &output)?;
            } else {
                cocotb_gen::generate(&config, &templates, &output)?;
                cocotb_gen::generate_runner(&config, &templates, &output)?;
            }

            // Generate AXI-Stream cocotb tests if --axi
            if axi {
                cocotb_gen::generate_axi_tests(&config, &templates, &output)?;
                cocotb_gen::generate_axi_runner(&config, &templates, &output, platform.is_platform())?;
            }

            // Generate rate limiter testbench if --rate-limit
            if has_rate_limit {
                cocotb_gen::generate_rate_limiter_tests(&templates, &output)?;
                cocotb_gen::generate_rate_limiter_runner(&templates, &output)?;
            }

            // Generate connection tracking testbench if --conntrack
            if conntrack {
                cocotb_gen::generate_conntrack_tests(&templates, &output)?;
                cocotb_gen::generate_conntrack_runner(&templates, &output)?;
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
                    "dynamic": dynamic,
                    "dynamic_entries": if dynamic { Some(dynamic_entries) } else { None },
                    "target": platform.name(),
                    "data_width": width,
                    "ptp": ptp,
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
                if dynamic {
                    println!("  Generated dynamic flow table ({} entries) in {}/rtl/", dynamic_entries, output.display());
                    println!("  Note: simulation evaluates initial rules only; runtime changes require cocotb/RTL sim");
                }
                if platform.is_platform() {
                    println!("  Generated {} platform wrapper in {}/rtl/", platform.name(), output.display());
                    if width == 512 {
                        println!("  Note: --width 512 matches platform native width — no extra converters needed");
                    } else {
                        println!("  Note: V1 uses 512<->8 width converters (~2 Gbps at 250MHz)");
                    }
                }
                if width > 8 {
                    println!("  Data path width: {}-bit AXI-Stream (core remains 8-bit with width converters)", width);
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
        Commands::Diff { old, new, json, html, templates } => {
            let old_config = loader::load_rules_with_warnings(&old)?.0;
            let new_config = loader::load_rules_with_warnings(&new)?.0;
            if let Some(ref html_path) = html {
                generate_diff_html(&old_config, &new_config, &old, &new, &templates, html_path)?;
                println!("  Generated HTML diff report: {}", html_path.display());
            } else {
                diff_rules(&old_config, &new_config, json)?;
            }
        }
        Commands::Lint { rules, json, dynamic, dynamic_entries, target, width } => {
            let platform = verilog_gen::PlatformTarget::from_str(&target)?;
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            let findings = lint_rules(&config, &warnings, dynamic, dynamic_entries, &platform, width);
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                print_lint_results(&findings);
            }
        }
        Commands::Formal { rules, output, templates, json, dynamic, dynamic_entries } => {
            log::info!("Generating formal verification files from {}", rules.display());
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;

            // First generate RTL (needed for formal)
            if dynamic {
                verilog_gen::generate_dynamic(&config, &templates, &output, dynamic_entries)?;
            } else {
                verilog_gen::generate(&config, &templates, &output)?;
            }

            // Generate SVA assertions + SBY task file
            formal_gen::generate_with_dynamic(&config, &templates, &output, dynamic, dynamic_entries)?;

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
        Commands::Estimate { rules, json, dynamic, dynamic_entries, target, width } => {
            let platform = verilog_gen::PlatformTarget::from_str(&target)?;
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            if dynamic {
                let estimate = compute_dynamic_estimate(dynamic_entries);
                if json {
                    let mut est = estimate;
                    est.as_object_mut().unwrap().insert("warnings".to_string(), serde_json::json!(warnings));
                    println!("{}", serde_json::to_string_pretty(&est)?);
                } else {
                    for w in &warnings {
                        eprintln!("Warning: {}", w);
                    }
                    print_dynamic_estimate(dynamic_entries);
                }
            } else {
                // Calculate width converter overhead
                let (converter_luts, converter_ffs) = width_converter_estimate(width, platform.is_platform());

                if json {
                    let mut estimate = compute_resource_estimate(&config);
                    // Add platform target overhead
                    if platform.is_platform() {
                        let obj = estimate.as_object_mut().unwrap();
                        obj.insert("platform_target".to_string(), serde_json::json!(platform.name()));
                        obj.insert("platform_wrapper".to_string(), serde_json::json!({
                            "luts": 20,
                            "ffs": 50,
                            "note": format!("{} wrapper overhead", platform.name())
                        }));
                    }
                    if converter_luts > 0 || converter_ffs > 0 {
                        let obj = estimate.as_object_mut().unwrap();
                        obj.insert("data_width".to_string(), serde_json::json!(width));
                        obj.insert("width_converters".to_string(), serde_json::json!({
                            "luts": converter_luts,
                            "ffs": converter_ffs,
                            "note": format!("axis_{}_to_8 + axis_8_to_{} width converters", width, width)
                        }));
                        // Update totals
                        let wrapper_luts = if platform.is_platform() { 20u64 } else { 0 };
                        let wrapper_ffs = if platform.is_platform() { 50u64 } else { 0 };
                        if let Some(total) = obj.get_mut("total") {
                            let cur_luts = total["luts"].as_u64().unwrap_or(0);
                            let cur_ffs = total["ffs"].as_u64().unwrap_or(0);
                            *total = serde_json::json!({
                                "luts": cur_luts + converter_luts + wrapper_luts,
                                "ffs": cur_ffs + converter_ffs + wrapper_ffs,
                            });
                        }
                    } else if platform.is_platform() {
                        // Platform without extra converters (width==512 matches native)
                        if let Some(total) = estimate.as_object_mut().unwrap().get_mut("total") {
                            let cur_luts = total["luts"].as_u64().unwrap_or(0);
                            let cur_ffs = total["ffs"].as_u64().unwrap_or(0);
                            *total = serde_json::json!({
                                "luts": cur_luts + 20,
                                "ffs": cur_ffs + 50,
                            });
                        }
                    }
                    estimate.as_object_mut().unwrap().insert("warnings".to_string(), serde_json::json!(warnings));
                    println!("{}", serde_json::to_string_pretty(&estimate)?);
                } else {
                    for w in &warnings {
                        eprintln!("Warning: {}", w);
                    }
                    print_resource_estimate(&config);
                    if platform.is_platform() {
                        println!();
                        if width == 512 {
                            println!("  Platform target: {} (native 512-bit — no extra width converters needed)", platform.name());
                        } else {
                            println!("  Platform target: {} (adds ~{} LUTs + ~{} FFs for width converters)", platform.name(), converter_luts, converter_ffs);
                        }
                    } else if width > 8 {
                        println!();
                        println!("  Data path width: {}-bit (adds ~{} LUTs + ~{} FFs for width converters)", width, converter_luts, converter_ffs);
                    }
                }
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
        Commands::Simulate { rules, packet, json, pcap_out, stateful } => {
            let config = loader::load_rules(&rules)?;
            let sim_pkt = simulator::parse_packet_spec(&packet)?;
            let result = if stateful {
                let mut rate_state = simulator::SimRateLimitState::new(&config);
                let conntrack_timeout = config.pacgate.conntrack.as_ref()
                    .map(|c| c.timeout_cycles).unwrap_or(30);
                let mut conntrack = simulator::SimConntrackTable::new(conntrack_timeout);
                simulator::simulate_stateful(&config, &sim_pkt, &mut rate_state, &mut conntrack, 0.01, 0)
            } else {
                simulator::simulate(&config, &sim_pkt)
            };

            // Write PCAP file if requested
            if let Some(ref pcap_path) = pcap_out {
                let action_str = match result.action { model::Action::Pass => "pass", model::Action::Drop => "drop" };
                let frame = pcap_writer::build_frame_from_sim(
                    sim_pkt.src_mac.as_deref().unwrap_or("02:00:00:00:00:01"),
                    sim_pkt.dst_mac.as_deref().unwrap_or("02:00:00:00:00:02"),
                    sim_pkt.ethertype.unwrap_or(0x0800),
                    sim_pkt.src_ip.as_deref(),
                    sim_pkt.dst_ip.as_deref(),
                    sim_pkt.ip_protocol,
                    sim_pkt.src_port,
                    sim_pkt.dst_port,
                );
                let record = pcap_writer::SimPacketRecord {
                    frame_data: frame,
                    rule_name: result.rule_name.clone(),
                    action: action_str.to_string(),
                    seq: 0,
                };
                pcap_writer::write_pcap(pcap_path, &[record])?;
                if !json {
                    println!("  PCAP written to: {}", pcap_path.display());
                }
            }

            if json {
                let fields_json: Vec<serde_json::Value> = result.fields.iter().map(|f| {
                    serde_json::json!({
                        "field": f.field,
                        "rule_value": f.rule_value,
                        "packet_value": f.packet_value,
                        "matches": f.matches,
                    })
                }).collect();
                let mut summary = serde_json::json!({
                    "status": "ok",
                    "matched_rule": result.rule_name,
                    "action": match result.action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "is_default": result.is_default,
                    "fields": fields_json,
                });
                if let Some(ref pcap_path) = pcap_out {
                    summary.as_object_mut().unwrap().insert(
                        "pcap_file".to_string(),
                        serde_json::Value::String(pcap_path.display().to_string()),
                    );
                }
                if let Some(ref rw) = result.rewrite {
                    let mut rw_json = serde_json::Map::new();
                    if let Some(ref v) = rw.set_dst_mac { rw_json.insert("set_dst_mac".into(), serde_json::json!(v)); }
                    if let Some(ref v) = rw.set_src_mac { rw_json.insert("set_src_mac".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_vlan_id { rw_json.insert("set_vlan_id".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_ttl { rw_json.insert("set_ttl".into(), serde_json::json!(v)); }
                    if rw.dec_ttl { rw_json.insert("dec_ttl".into(), serde_json::json!(true)); }
                    if let Some(ref v) = rw.set_src_ip { rw_json.insert("set_src_ip".into(), serde_json::json!(v)); }
                    if let Some(ref v) = rw.set_dst_ip { rw_json.insert("set_dst_ip".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_dscp { rw_json.insert("set_dscp".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_src_port { rw_json.insert("set_src_port".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_dst_port { rw_json.insert("set_dst_port".into(), serde_json::json!(v)); }
                    if rw.dec_hop_limit { rw_json.insert("dec_hop_limit".into(), serde_json::json!(true)); }
                    if let Some(v) = rw.set_hop_limit { rw_json.insert("set_hop_limit".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_ecn { rw_json.insert("set_ecn".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_vlan_pcp { rw_json.insert("set_vlan_pcp".into(), serde_json::json!(v)); }
                    if let Some(v) = rw.set_outer_vlan_id { rw_json.insert("set_outer_vlan_id".into(), serde_json::json!(v)); }
                    summary.as_object_mut().unwrap().insert("rewrite".to_string(), serde_json::Value::Object(rw_json));
                }
                if let Some(port) = result.mirror_port {
                    summary.as_object_mut().unwrap().insert("mirror_port".to_string(), serde_json::json!(port));
                }
                if let Some(port) = result.redirect_port {
                    summary.as_object_mut().unwrap().insert("redirect_port".to_string(), serde_json::json!(port));
                }
                if let Some(q) = result.rss_queue {
                    summary.as_object_mut().unwrap().insert("rss_queue".to_string(), serde_json::json!(q));
                }
                if stateful {
                    let is_rate_limited = result.rule_name.as_deref() == Some("rate_limited");
                    summary.as_object_mut().unwrap().insert(
                        "rate_limited".to_string(),
                        serde_json::Value::Bool(is_rate_limited),
                    );
                    summary.as_object_mut().unwrap().insert(
                        "stateful".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    if model::StatelessRule::has_flow_counters(&config.pacgate) {
                        summary.as_object_mut().unwrap().insert(
                            "flow_counters".to_string(),
                            serde_json::json!({ "enabled": true }),
                        );
                    }
                }
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
                    if let Some(ref rw) = result.rewrite {
                        if !rw.is_empty() {
                            println!();
                            println!("  Rewrite Actions:");
                            if let Some(ref v) = rw.set_dst_mac { println!("    set_dst_mac: {}", v); }
                            if let Some(ref v) = rw.set_src_mac { println!("    set_src_mac: {}", v); }
                            if let Some(v) = rw.set_vlan_id { println!("    set_vlan_id: {}", v); }
                            if let Some(v) = rw.set_ttl { println!("    set_ttl: {}", v); }
                            if rw.dec_ttl { println!("    dec_ttl: true"); }
                            if let Some(ref v) = rw.set_src_ip { println!("    set_src_ip: {}", v); }
                            if let Some(ref v) = rw.set_dst_ip { println!("    set_dst_ip: {}", v); }
                            if let Some(v) = rw.set_dscp { println!("    set_dscp: {}", v); }
                            if let Some(v) = rw.set_src_port { println!("    set_src_port: {}", v); }
                            if let Some(v) = rw.set_dst_port { println!("    set_dst_port: {}", v); }
                            if rw.dec_hop_limit { println!("    dec_hop_limit: true"); }
                            if let Some(v) = rw.set_hop_limit { println!("    set_hop_limit: {}", v); }
                            if let Some(v) = rw.set_ecn { println!("    set_ecn: {}", v); }
                            if let Some(v) = rw.set_vlan_pcp { println!("    set_vlan_pcp: {}", v); }
                            if let Some(v) = rw.set_outer_vlan_id { println!("    set_outer_vlan_id: {}", v); }
                        }
                    }
                    if result.mirror_port.is_some() || result.redirect_port.is_some() {
                        println!();
                        println!("  Egress Actions:");
                        if let Some(port) = result.mirror_port {
                            println!("    mirror_port: {}", port);
                        }
                        if let Some(port) = result.redirect_port {
                            println!("    redirect_port: {}", port);
                        }
                    }
                    if let Some(q) = result.rss_queue {
                        println!();
                        println!("  RSS Queue: {}", q);
                    }
                    if stateful && model::StatelessRule::has_flow_counters(&config.pacgate) {
                        println!();
                        println!("  Flow Counters:");
                        println!("    enabled: true");
                    }
                }
                println!();
            }
        }
        Commands::Synth { rules, output, templates, target, part, clock_mhz, axi, counters, conntrack, rate_limit, ports, parse_results, json } => {
            // If --parse-results, parse an existing synthesis log
            if let Some(ref log_path) = parse_results {
                let results = if target == "vivado" {
                    synth_gen::parse_vivado_utilization(log_path)?
                } else {
                    synth_gen::parse_yosys_log(log_path)?
                };
                if json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    println!("  Synthesis Results ({})", results.tool);
                    println!("  ════════════════════════════════════════════");
                    if let Some(luts) = results.luts { println!("  LUTs:   {}", luts); }
                    if let Some(ffs) = results.ffs { println!("  FFs:    {}", ffs); }
                    if let Some(brams) = results.brams { println!("  BRAMs:  {}", brams); }
                    if let Some(dsps) = results.dsps { println!("  DSPs:   {}", dsps); }
                    if let Some(wns) = results.wns { println!("  WNS:    {} ns", wns); }
                }
            } else {
                // First compile the design to generate RTL
                let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
                verilog_gen::generate(&config, &templates, &output)?;
                if ports > 1 {
                    verilog_gen::generate_multiport(&config, &templates, &output, ports)?;
                }
                if axi { verilog_gen::copy_axi_rtl(&output, &config, &templates, 8)?; }
                if counters { verilog_gen::copy_counter_rtl(&output)?; }
                if conntrack { verilog_gen::copy_conntrack_rtl(&output)?; }
                let has_rate_limit = rate_limit || config.pacgate.rules.iter().any(|r| r.rate_limit.is_some());
                if has_rate_limit { verilog_gen::copy_rate_limiter_rtl(&output)?; }

                let rtl_files = synth_gen::collect_rtl_files(&output, axi, counters, conntrack, has_rate_limit, ports);
                let top_module = if axi { "packet_filter_axi_top".to_string() }
                    else if ports > 1 { "packet_filter_multiport_top".to_string() }
                    else { "packet_filter_top".to_string() };

                let synth_target = if target == "vivado" {
                    synth_gen::SynthTarget::Vivado { part: part.clone() }
                } else {
                    synth_gen::SynthTarget::Yosys { device: synth_gen::YosysDevice::from_str(&part)? }
                };

                let synth_config = synth_gen::SynthConfig {
                    target: synth_target,
                    clock_mhz,
                    top_module: top_module.clone(),
                    rtl_files,
                    has_axi: axi,
                    has_counters: counters,
                    has_conntrack: conntrack,
                    has_rate_limit,
                    ports,
                };

                let generated = synth_gen::generate_synth_project(&synth_config, &templates, &output)?;

                if json {
                    let summary = serde_json::json!({
                        "status": "ok",
                        "rules_file": rules.to_string_lossy(),
                        "rules_count": config.pacgate.rules.len(),
                        "target": target,
                        "part": part,
                        "clock_mhz": clock_mhz,
                        "top_module": top_module,
                        "generated": generated,
                        "warnings": warnings,
                    });
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    for w in &warnings {
                        eprintln!("Warning: {}", w);
                    }
                    println!("  Generated synthesis project for {} ({})", target, part);
                    for f in &generated {
                        println!("    {}/{}", output.display(), f);
                    }
                    println!();
                    println!("  Run synthesis:");
                    if target == "vivado" {
                        println!("    cd {}/synth && make vivado", output.display());
                    } else {
                        println!("    cd {}/synth && make yosys", output.display());
                    }
                }
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
        Commands::Mutate { rules, output, templates, json, run } => {
            let (config, _warnings) = loader::load_rules_with_warnings(&rules)?;

            if run {
                // Run mutation tests: generate + lint each mutant, report kill rate
                let report = mutation::run_mutation_tests(&config, &templates, &output);
                if json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::to_value(&report)?)?);
                } else {
                    println!();
                    println!("  MUTATION TEST REPORT");
                    println!("  ====================");
                    println!("  Total:    {}", report.total);
                    println!("  Killed:   {}", report.killed);
                    println!("  Survived: {}", report.survived);
                    println!("  Errors:   {}", report.errors);
                    println!("  Kill rate: {:.1}%", report.kill_rate);
                    println!();
                    for detail in &report.details {
                        let marker = match detail.status.as_str() {
                            "killed" => "KILLED ",
                            "survived" => "SURVIVED",
                            _ => "ERROR  ",
                        };
                        println!("  [{}] {} — {}", marker, detail.name, detail.description);
                    }
                }
            } else if json {
                let report = mutation::generate_mutation_report(&config);
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let mutations = mutation::generate_mutations(&config);
                let mutants_dir = output.join("mutants");
                std::fs::create_dir_all(&mutants_dir)?;

                for (i, (m, mutated_config)) in mutations.iter().enumerate() {
                    let mutant_dir = mutants_dir.join(format!("mut_{}", i));
                    std::fs::create_dir_all(&mutant_dir)?;

                    // Write mutated YAML
                    let yaml = serde_yaml::to_string(&mutated_config)?;
                    std::fs::write(mutant_dir.join("rules.yaml"), &yaml)?;

                    // Generate mutated Verilog + tests
                    verilog_gen::generate(mutated_config, &templates, &mutant_dir)?;
                    cocotb_gen::generate(mutated_config, &templates, &mutant_dir)?;

                    println!("  Mutant {}: {} — {}", i, m.name, m.description);
                }
                println!();
                println!("  Generated {} mutants in {}/mutants/", mutations.len(), output.display());
                println!("  Each mutant should fail at least one test. Surviving mutants indicate test gaps.");
            }
        }
        Commands::Mcy { rules, output, templates, json, run } => {
            let (config, _warnings) = loader::load_rules_with_warnings(&rules)?;

            // First compile the rules to generate RTL + TB
            verilog_gen::generate(&config, &templates, &output)?;
            cocotb_gen::generate(&config, &templates, &output)?;

            let rtl_dir = output.join("rtl");
            let tb_dir = output.join("tb");
            let result = mcy_gen::generate_mcy_config(&config, &templates, &output, &rtl_dir, &tb_dir)?;

            if json {
                let report = mcy_gen::generate_mcy_report(&result);
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!();
                println!("  MCY Configuration Generated");
                println!("  ===========================");
                println!("  Config: {}", result.config_path.display());
                println!("  Script: {}", result.script_path.display());
                println!("  RTL files: {}", result.rtl_files.len());
                println!("  Mutation count: {}", result.mutation_count);
                println!();
                println!("  To run: cd {} && mcy mcy.cfg", result.config_path.parent().unwrap().display());
            }

            if run {
                // Try to run MCY
                let mcy_dir = result.config_path.parent().unwrap();
                let mcy_result = std::process::Command::new("mcy")
                    .arg("mcy.cfg")
                    .current_dir(mcy_dir)
                    .output();
                match mcy_result {
                    Ok(out) if out.status.success() => {
                        println!("  MCY run completed successfully.");
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        if !stdout.is_empty() {
                            println!("{}", stdout);
                        }
                    }
                    Ok(out) => {
                        eprintln!("  MCY run failed with exit code: {:?}", out.status.code());
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if !stderr.is_empty() {
                            eprintln!("{}", stderr);
                        }
                    }
                    Err(e) => {
                        eprintln!("  MCY binary not found in PATH: {}", e);
                        eprintln!("  Install MCY: pip install mcy");
                    }
                }
            }
        }
        Commands::Template { action } => {
            match action {
                TemplateAction::List { category, json } => {
                    let templates = templates_lib::builtin_templates();
                    let filtered: Vec<_> = if let Some(ref cat) = category {
                        templates.iter().filter(|t| t.category == *cat).collect()
                    } else {
                        templates.iter().collect()
                    };

                    if json {
                        let json_val: Vec<serde_json::Value> = filtered.iter().map(|t| {
                            serde_json::json!({
                                "name": t.name,
                                "category": t.category,
                                "description": t.description,
                                "variables": t.variables.iter().map(|v| {
                                    serde_json::json!({ "name": v.name, "default": v.default, "type": v.var_type })
                                }).collect::<Vec<_>>(),
                            })
                        }).collect();
                        println!("{}", serde_json::to_string_pretty(&json_val)?);
                    } else {
                        println!();
                        println!("  Available Rule Templates:");
                        println!("  {:<22} {:<18} {}", "NAME", "CATEGORY", "DESCRIPTION");
                        println!("  {}", "-".repeat(70));
                        for t in &filtered {
                            println!("  {:<22} {:<18} {}", t.name, t.category, t.description);
                        }
                        println!();
                        println!("  Use 'pacgate template show <name>' for details");
                        println!("  Use 'pacgate template apply <name> -o rules.yaml' to generate rules");
                        println!();
                    }
                }
                TemplateAction::Show { name } => {
                    let t = templates_lib::find_template(&name)
                        .ok_or_else(|| anyhow::anyhow!("Template '{}' not found. Use 'pacgate template list' to see available templates.", name))?;

                    println!();
                    println!("  Template: {}", t.name);
                    println!("  Category: {}", t.category);
                    println!("  Description: {}", t.description);
                    println!();
                    println!("  Variables:");
                    for v in &t.variables {
                        println!("    ${{{}}}: {} (default: {}, type: {})", v.name, v.description, v.default, v.var_type);
                    }
                    println!();
                    println!("  YAML Preview (with defaults):");
                    if let Ok(body) = templates_lib::apply_template(&t, &[]) {
                        for line in body.lines() {
                            println!("    {}", line);
                        }
                    }
                    println!();
                }
                TemplateAction::Apply { name, output, set } => {
                    let t = templates_lib::find_template(&name)
                        .ok_or_else(|| anyhow::anyhow!("Template '{}' not found", name))?;

                    let vars: Vec<(String, String)> = set.iter().map(|s| {
                        let parts: Vec<&str> = s.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            (parts[0].to_string(), parts[1].to_string())
                        } else {
                            (s.clone(), String::new())
                        }
                    }).collect();

                    let yaml = templates_lib::apply_template_to_yaml(&t, &vars, "drop")?;
                    std::fs::write(&output, &yaml)?;
                    println!("  Applied template '{}' -> {}", name, output.display());
                }
            }
        }
        Commands::Reachability { rules, json } => {
            let (config, _warnings) = loader::load_rules_with_warnings(&rules)?;
            let report = reachability::analyze(&config);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", reachability::format_report(&report));
            }
        }
        Commands::Bench { rules, templates, json } => {
            let config = loader::load_rules(&rules)?;
            let report = benchmark::run_benchmark(&config, &templates)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", benchmark::format_report(&report));
            }
        }
        Commands::Doc { rules, output, templates } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            generate_rule_documentation(&config, &warnings, &rules, &templates, &output)?;
            println!("  Generated rule documentation: {}", output.display());
        }
        Commands::Scenario { action } => {
            match action {
                ScenarioAction::Validate { files, json } => {
                    let summary = scenario::validate_files(&files);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&summary)?);
                    } else {
                        if let Some(results) = summary["results"].as_array() {
                            for r in results {
                                println!("OK  {}  id={} events={}",
                                    r["file"].as_str().unwrap_or(""),
                                    r["id"].as_str().unwrap_or(""),
                                    r["events"]);
                            }
                        }
                        if let Some(errors) = summary["errors"].as_array() {
                            for e in errors {
                                println!("ERR {}  {}",
                                    e["file"].as_str().unwrap_or(""),
                                    e["error"].as_str().unwrap_or(""));
                            }
                        }
                    }
                    let failed = summary["failed"].as_u64().unwrap_or(0);
                    if failed > 0 {
                        std::process::exit(1);
                    }
                }
                ScenarioAction::Import { in_dir, store, replace } => {
                    let result = scenario::import_scenarios(&in_dir, &store, replace)?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                ScenarioAction::Export { store, out_dir } => {
                    let result = scenario::export_scenarios(&store, &out_dir)?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
            }
        }
        Commands::Regress { scenario: scenario_path, count, json } => {
            let s = scenario::load_scenario(&scenario_path)?;
            let output = scenario::run_regress(&s, Some(&scenario_path), count, json)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            let mismatches = output["mismatches"].as_u64().unwrap_or(0);
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        Commands::Topology { scenario: scenario_path, json } => {
            let s = scenario::load_scenario(&scenario_path)?;
            let output = scenario::run_topology(&s, Some(&scenario_path), json)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            let mismatches = output["mismatch_count"].as_u64().unwrap_or(0);
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        Commands::P4Export { rules, output, templates, json } => {
            let (config, warnings) = loader::load_rules_with_warnings(&rules)?;
            if json {
                let mut summary = p4_gen::generate_p4_summary(&config);
                summary.as_object_mut().unwrap().insert("rules_file".to_string(),
                    serde_json::Value::String(rules.to_string_lossy().to_string()));
                summary.as_object_mut().unwrap().insert("warnings".to_string(),
                    serde_json::json!(warnings));
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                for w in &warnings {
                    eprintln!("Warning: {}", w);
                }
                p4_gen::generate_p4(&config, &templates, &output)?;
                let has_stateful = config.pacgate.rules.iter().any(|r| r.is_stateful());
                let stateless = config.pacgate.rules.iter().filter(|r| !r.is_stateful()).count();
                println!("Exported {} stateless rules as P4_16 PSA program", stateless);
                println!("  Output: {}/p4/pacgate_filter.p4", output.display());
                if has_stateful {
                    println!("  Note: {} stateful (FSM) rules skipped — require manual P4 Register extern adaptation",
                        config.pacgate.rules.iter().filter(|r| r.is_stateful()).count());
                }
                println!("  Target: PSA (Portable Switch Architecture)");
            }
        }
    }

    Ok(())
}

fn generate_rule_documentation(
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
    let default_action = match config.pacgate.defaults.action {
        model::Action::Pass => "pass",
        model::Action::Drop => "drop",
    };

    // Build rule info for template
    let mut rule_info: Vec<serde_json::Value> = Vec::new();
    for rule in rules {
        let mut match_fields: Vec<String> = Vec::new();
        if let Some(ref et) = rule.match_criteria.ethertype { match_fields.push(format!("ethertype: {}", et)); }
        if let Some(ref mac) = rule.match_criteria.dst_mac { match_fields.push(format!("dst_mac: {}", mac)); }
        if let Some(ref mac) = rule.match_criteria.src_mac { match_fields.push(format!("src_mac: {}", mac)); }
        if let Some(vid) = rule.match_criteria.vlan_id { match_fields.push(format!("vlan_id: {}", vid)); }
        if let Some(pcp) = rule.match_criteria.vlan_pcp { match_fields.push(format!("vlan_pcp: {}", pcp)); }
        if let Some(ref ip) = rule.match_criteria.src_ip { match_fields.push(format!("src_ip: {}", ip)); }
        if let Some(ref ip) = rule.match_criteria.dst_ip { match_fields.push(format!("dst_ip: {}", ip)); }
        if let Some(proto) = rule.match_criteria.ip_protocol { match_fields.push(format!("ip_protocol: {}", proto)); }
        if let Some(ref pm) = rule.match_criteria.src_port { match_fields.push(format!("src_port: {:?}", pm)); }
        if let Some(ref pm) = rule.match_criteria.dst_port { match_fields.push(format!("dst_port: {:?}", pm)); }
        if let Some(ref ipv6) = rule.match_criteria.src_ipv6 { match_fields.push(format!("src_ipv6: {}", ipv6)); }
        if let Some(ref ipv6) = rule.match_criteria.dst_ipv6 { match_fields.push(format!("dst_ipv6: {}", ipv6)); }
        if let Some(nh) = rule.match_criteria.ipv6_next_header { match_fields.push(format!("ipv6_next_header: {}", nh)); }
        if let Some(teid) = rule.match_criteria.gtp_teid { match_fields.push(format!("gtp_teid: {}", teid)); }
        if let Some(label) = rule.match_criteria.mpls_label { match_fields.push(format!("mpls_label: {}", label)); }
        if let Some(tc) = rule.match_criteria.mpls_tc { match_fields.push(format!("mpls_tc: {}", tc)); }
        if let Some(bos) = rule.match_criteria.mpls_bos { match_fields.push(format!("mpls_bos: {}", bos)); }
        if let Some(igmp) = rule.match_criteria.igmp_type { match_fields.push(format!("igmp_type: 0x{:02X}", igmp)); }
        if let Some(mld) = rule.match_criteria.mld_type { match_fields.push(format!("mld_type: {}", mld)); }
        if let Some(dscp) = rule.match_criteria.ip_dscp { match_fields.push(format!("ip_dscp: {}", dscp)); }
        if let Some(ecn) = rule.match_criteria.ip_ecn { match_fields.push(format!("ip_ecn: {}", ecn)); }
        if let Some(dscp) = rule.match_criteria.ipv6_dscp { match_fields.push(format!("ipv6_dscp: {}", dscp)); }
        if let Some(ecn) = rule.match_criteria.ipv6_ecn { match_fields.push(format!("ipv6_ecn: {}", ecn)); }
        if let Some(flags) = rule.match_criteria.tcp_flags {
            let mask_str = rule.match_criteria.tcp_flags_mask.map(|m| format!(", mask=0x{:02X}", m)).unwrap_or_default();
            match_fields.push(format!("tcp_flags: 0x{:02X}{}", flags, mask_str));
        }
        if let Some(t) = rule.match_criteria.icmp_type { match_fields.push(format!("icmp_type: {}", t)); }
        if let Some(c) = rule.match_criteria.icmp_code { match_fields.push(format!("icmp_code: {}", c)); }
        if let Some(t) = rule.match_criteria.icmpv6_type { match_fields.push(format!("icmpv6_type: {}", t)); }
        if let Some(c) = rule.match_criteria.icmpv6_code { match_fields.push(format!("icmpv6_code: {}", c)); }
        if let Some(op) = rule.match_criteria.arp_opcode { match_fields.push(format!("arp_opcode: {}", op)); }
        if let Some(ref spa) = rule.match_criteria.arp_spa { match_fields.push(format!("arp_spa: {}", spa)); }
        if let Some(ref tpa) = rule.match_criteria.arp_tpa { match_fields.push(format!("arp_tpa: {}", tpa)); }
        if let Some(hl) = rule.match_criteria.ipv6_hop_limit { match_fields.push(format!("ipv6_hop_limit: {}", hl)); }
        if let Some(fl) = rule.match_criteria.ipv6_flow_label { match_fields.push(format!("ipv6_flow_label: {}", fl)); }
        if let Some(vid) = rule.match_criteria.outer_vlan_id { match_fields.push(format!("outer_vlan_id: {}", vid)); }
        if let Some(pcp) = rule.match_criteria.outer_vlan_pcp { match_fields.push(format!("outer_vlan_pcp: {}", pcp)); }
        if let Some(df) = rule.match_criteria.ip_dont_fragment { match_fields.push(format!("ip_dont_fragment: {}", df)); }
        if let Some(mf) = rule.match_criteria.ip_more_fragments { match_fields.push(format!("ip_more_fragments: {}", mf)); }
        if let Some(fo) = rule.match_criteria.ip_frag_offset { match_fields.push(format!("ip_frag_offset: {}", fo)); }
        if let Some(gp) = rule.match_criteria.gre_protocol { match_fields.push(format!("gre_protocol: 0x{:04X}", gp)); }
        if let Some(gk) = rule.match_criteria.gre_key { match_fields.push(format!("gre_key: {}", gk)); }
        if let Some(ol) = rule.match_criteria.oam_level { match_fields.push(format!("oam_level: {}", ol)); }
        if let Some(oo) = rule.match_criteria.oam_opcode { match_fields.push(format!("oam_opcode: {}", oo)); }
        if let Some(spi) = rule.match_criteria.nsh_spi { match_fields.push(format!("nsh_spi: {}", spi)); }
        if let Some(si) = rule.match_criteria.nsh_si { match_fields.push(format!("nsh_si: {}", si)); }
        if let Some(np) = rule.match_criteria.nsh_next_protocol { match_fields.push(format!("nsh_next_protocol: {}", np)); }
        if let Some(ref state) = rule.match_criteria.conntrack_state { match_fields.push(format!("conntrack_state: {}", state)); }
        if let Some(vni) = rule.match_criteria.geneve_vni { match_fields.push(format!("geneve_vni: {}", vni)); }
        if let Some(ttl) = rule.match_criteria.ip_ttl { match_fields.push(format!("ip_ttl: {}", ttl)); }
        if let Some(mt) = rule.match_criteria.ptp_message_type { match_fields.push(format!("ptp_message_type: {}", mt)); }
        if let Some(dom) = rule.match_criteria.ptp_domain { match_fields.push(format!("ptp_domain: {}", dom)); }
        if let Some(ver) = rule.match_criteria.ptp_version { match_fields.push(format!("ptp_version: {}", ver)); }
        if let Some(ref bms) = rule.match_criteria.byte_match {
            for bm in bms {
                match_fields.push(format!("byte_match: offset={}, value={}, mask={}", bm.offset, bm.value, bm.mask.as_deref().unwrap_or("FF")));
            }
        }

        let key_match = if match_fields.is_empty() { "any".to_string() } else { match_fields.join(", ") };
        let action = if rule.action() == model::Action::Pass { "pass" } else { "drop" };

        let mut info = serde_json::json!({
            "name": rule.name,
            "priority": rule.priority,
            "action": action,
            "is_stateful": rule.is_stateful(),
            "key_match": key_match,
            "match_fields": match_fields,
        });

        if rule.is_stateful() {
            if let Some(ref fsm) = rule.fsm {
                info["initial_state"] = serde_json::json!(fsm.initial_state);
                info["num_states"] = serde_json::json!(fsm.states.len());
            }
        }

        if let Some(ref rl) = rule.rate_limit {
            info["rate_limit"] = serde_json::json!(format!("{} pps, burst {}", rl.pps, rl.burst));
        }

        if let Some(port) = rule.mirror_port {
            info["mirror_port"] = serde_json::json!(port);
        }
        if let Some(port) = rule.redirect_port {
            info["redirect_port"] = serde_json::json!(port);
        }

        rule_info.push(info);
    }

    let num_stateless = rules.iter().filter(|r| !r.is_stateful()).count();
    let num_pass = rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let num_drop = rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();

    let mut ctx = tera::Context::new();
    ctx.insert("rules_file", &rules_path.display().to_string());
    ctx.insert("generated_at", "auto-generated by pacgate");
    ctx.insert("total_rules", &rules.len());
    ctx.insert("num_stateless", &num_stateless);
    ctx.insert("num_stateful", &(rules.len() - num_stateless));
    ctx.insert("num_pass", &num_pass);
    ctx.insert("num_drop", &num_drop);
    ctx.insert("default_action", default_action);
    ctx.insert("rules", &rule_info);
    ctx.insert("warnings", warnings);

    let rendered = tera.render("rule_documentation.html.tera", &ctx)?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, &rendered)?;
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
    let all_rules = config.all_rules();
    let total = all_rules.len();
    let stateless = all_rules.iter().filter(|r| !r.is_stateful()).count();
    let stateful = all_rules.iter().filter(|r| r.is_stateful()).count();
    let pass_rules = all_rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let drop_rules = all_rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();

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
    let mut uses_gtp_teid = 0;
    let mut uses_mpls_label = 0;
    let mut uses_mpls_tc = 0;
    let mut uses_mpls_bos = 0;
    let mut uses_igmp_type = 0;
    let mut uses_mld_type = 0;
    let mut uses_ip_dscp = 0;
    let mut uses_ip_ecn = 0;
    let mut uses_ipv6_dscp = 0;
    let mut uses_ipv6_ecn = 0;
    let mut uses_tcp_flags = 0;
    let mut uses_icmp_type = 0;
    let mut uses_icmp_code = 0;
    let mut uses_icmpv6_type = 0;
    let mut uses_icmpv6_code = 0;
    let mut uses_arp_opcode = 0;
    let mut uses_arp_spa = 0;
    let mut uses_arp_tpa = 0;
    let mut uses_ipv6_hop_limit = 0;
    let mut uses_ipv6_flow_label = 0;
    let mut uses_outer_vlan_id = 0;
    let mut uses_outer_vlan_pcp = 0;
    let mut uses_ip_dont_fragment = 0;
    let mut uses_ip_more_fragments = 0;
    let mut uses_ip_frag_offset = 0;
    let mut uses_gre_protocol = 0;
    let mut uses_gre_key = 0;
    let mut uses_oam_level = 0;
    let mut uses_oam_opcode = 0;
    let mut uses_nsh_spi = 0;
    let mut uses_nsh_si = 0;
    let mut uses_nsh_next_protocol = 0;
    let mut uses_conntrack_state = 0;
    let mut uses_geneve_vni = 0;
    let mut uses_ip_ttl = 0;
    let mut uses_ptp_message_type = 0;
    let mut uses_ptp_domain = 0;
    let mut uses_ptp_version = 0;
    let mut match_field_count = Vec::new();

    for rule in all_rules.iter().filter(|r| !r.is_stateful()) {
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
        if mc.gtp_teid.is_some() { uses_gtp_teid += 1; count += 1; }
        if mc.mpls_label.is_some() { uses_mpls_label += 1; count += 1; }
        if mc.mpls_tc.is_some() { uses_mpls_tc += 1; count += 1; }
        if mc.mpls_bos.is_some() { uses_mpls_bos += 1; count += 1; }
        if mc.igmp_type.is_some() { uses_igmp_type += 1; count += 1; }
        if mc.mld_type.is_some() { uses_mld_type += 1; count += 1; }
        if mc.ip_dscp.is_some() { uses_ip_dscp += 1; count += 1; }
        if mc.ip_ecn.is_some() { uses_ip_ecn += 1; count += 1; }
        if mc.ipv6_dscp.is_some() { uses_ipv6_dscp += 1; count += 1; }
        if mc.ipv6_ecn.is_some() { uses_ipv6_ecn += 1; count += 1; }
        if mc.tcp_flags.is_some() { uses_tcp_flags += 1; count += 1; }
        if mc.icmp_type.is_some() { uses_icmp_type += 1; count += 1; }
        if mc.icmp_code.is_some() { uses_icmp_code += 1; count += 1; }
        if mc.icmpv6_type.is_some() { uses_icmpv6_type += 1; count += 1; }
        if mc.icmpv6_code.is_some() { uses_icmpv6_code += 1; count += 1; }
        if mc.arp_opcode.is_some() { uses_arp_opcode += 1; count += 1; }
        if mc.arp_spa.is_some() { uses_arp_spa += 1; count += 1; }
        if mc.arp_tpa.is_some() { uses_arp_tpa += 1; count += 1; }
        if mc.ipv6_hop_limit.is_some() { uses_ipv6_hop_limit += 1; count += 1; }
        if mc.ipv6_flow_label.is_some() { uses_ipv6_flow_label += 1; count += 1; }
        if mc.outer_vlan_id.is_some() { uses_outer_vlan_id += 1; count += 1; }
        if mc.outer_vlan_pcp.is_some() { uses_outer_vlan_pcp += 1; count += 1; }
        if mc.ip_dont_fragment.is_some() { uses_ip_dont_fragment += 1; count += 1; }
        if mc.ip_more_fragments.is_some() { uses_ip_more_fragments += 1; count += 1; }
        if mc.ip_frag_offset.is_some() { uses_ip_frag_offset += 1; count += 1; }
        if mc.gre_protocol.is_some() { uses_gre_protocol += 1; count += 1; }
        if mc.gre_key.is_some() { uses_gre_key += 1; count += 1; }
        if mc.oam_level.is_some() { uses_oam_level += 1; count += 1; }
        if mc.oam_opcode.is_some() { uses_oam_opcode += 1; count += 1; }
        if mc.nsh_spi.is_some() { uses_nsh_spi += 1; count += 1; }
        if mc.nsh_si.is_some() { uses_nsh_si += 1; count += 1; }
        if mc.nsh_next_protocol.is_some() { uses_nsh_next_protocol += 1; count += 1; }
        if mc.conntrack_state.is_some() { uses_conntrack_state += 1; count += 1; }
        if mc.geneve_vni.is_some() { uses_geneve_vni += 1; count += 1; }
        if mc.ip_ttl.is_some() { uses_ip_ttl += 1; count += 1; }
        if mc.ptp_message_type.is_some() { uses_ptp_message_type += 1; count += 1; }
        if mc.ptp_domain.is_some() { uses_ptp_domain += 1; count += 1; }
        if mc.ptp_version.is_some() { uses_ptp_version += 1; count += 1; }
        match_field_count.push(count);
    }

    // Egress action counts
    let uses_mirror = config.pacgate.rules.iter().filter(|r| r.mirror_port.is_some()).count();
    let uses_redirect = config.pacgate.rules.iter().filter(|r| r.redirect_port.is_some()).count();

    // Priority spacing
    let mut priorities: Vec<u32> = all_rules.iter().map(|r| r.priority).collect();
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
            "gtp_teid": uses_gtp_teid,
            "mpls_label": uses_mpls_label,
            "mpls_tc": uses_mpls_tc,
            "mpls_bos": uses_mpls_bos,
            "igmp_type": uses_igmp_type,
            "mld_type": uses_mld_type,
            "ip_dscp": uses_ip_dscp,
            "ip_ecn": uses_ip_ecn,
            "ipv6_dscp": uses_ipv6_dscp,
            "ipv6_ecn": uses_ipv6_ecn,
            "tcp_flags": uses_tcp_flags,
            "icmp_type": uses_icmp_type,
            "icmp_code": uses_icmp_code,
            "icmpv6_type": uses_icmpv6_type,
            "icmpv6_code": uses_icmpv6_code,
            "arp_opcode": uses_arp_opcode,
            "arp_spa": uses_arp_spa,
            "arp_tpa": uses_arp_tpa,
            "ipv6_hop_limit": uses_ipv6_hop_limit,
            "ipv6_flow_label": uses_ipv6_flow_label,
            "outer_vlan_id": uses_outer_vlan_id,
            "outer_vlan_pcp": uses_outer_vlan_pcp,
            "ip_dont_fragment": uses_ip_dont_fragment,
            "ip_more_fragments": uses_ip_more_fragments,
            "ip_frag_offset": uses_ip_frag_offset,
            "gre_protocol": uses_gre_protocol,
            "gre_key": uses_gre_key,
            "oam_level": uses_oam_level,
            "oam_opcode": uses_oam_opcode,
            "nsh_spi": uses_nsh_spi,
            "nsh_si": uses_nsh_si,
            "nsh_next_protocol": uses_nsh_next_protocol,
            "conntrack_state": uses_conntrack_state,
            "geneve_vni": uses_geneve_vni,
            "ip_ttl": uses_ip_ttl,
            "ptp_message_type": uses_ptp_message_type,
            "ptp_domain": uses_ptp_domain,
            "ptp_version": uses_ptp_version,
        },
        "egress_actions": {
            "mirror_port": uses_mirror,
            "redirect_port": uses_redirect,
        },
        "flow_counters": {
            "enabled": model::StatelessRule::has_flow_counters(&config.pacgate),
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
        "pipeline": {
            "is_pipeline": config.is_pipeline(),
            "stage_count": config.stage_count(),
            "stages": if let Some(tables) = &config.pacgate.tables {
                tables.iter().map(|s| serde_json::json!({
                    "name": s.name,
                    "rules": s.rules.len(),
                    "default_action": match s.default_action { model::Action::Pass => "pass", model::Action::Drop => "drop" },
                    "next_table": s.next_table,
                })).collect()
            } else {
                Vec::new()
            },
        },
    })
}

fn print_stats(config: &model::FilterConfig) {
    let all_rules = config.all_rules();
    let total = all_rules.len();
    let stateless = all_rules.iter().filter(|r| !r.is_stateful()).count();
    let stateful = all_rules.iter().filter(|r| r.is_stateful()).count();
    let pass_rules = all_rules.iter().filter(|r| matches!(r.action(), model::Action::Pass)).count();
    let drop_rules = all_rules.iter().filter(|r| matches!(r.action(), model::Action::Drop)).count();
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
    let mut uses_gtp_teid = 0usize;
    let mut uses_mpls_label = 0usize;
    let mut uses_igmp_type = 0usize;
    let mut uses_mld_type = 0usize;
    let mut uses_ip_dscp = 0usize;
    let mut uses_ip_ecn = 0usize;
    let mut uses_ipv6_dscp = 0usize;
    let mut uses_ipv6_ecn = 0usize;
    let mut uses_tcp_flags = 0usize;
    let mut uses_icmp_type = 0usize;
    let mut uses_icmpv6_type = 0usize;
    let mut uses_arp_opcode = 0usize;
    let mut uses_ipv6_hop_limit = 0usize;
    let mut uses_outer_vlan_id = 0usize;
    let mut uses_ip_dont_fragment = 0usize;
    let mut uses_ip_frag_offset = 0usize;
    let mut uses_gre_protocol = 0usize;
    let mut uses_gre_key = 0usize;
    let mut uses_oam_level = 0usize;
    let mut uses_oam_opcode = 0usize;
    let mut uses_nsh_spi = 0usize;
    let mut uses_nsh_si = 0usize;
    let mut uses_nsh_next_protocol = 0usize;
    let mut uses_conntrack_state = 0usize;
    let mut uses_geneve_vni = 0usize;
    let mut uses_ip_ttl = 0usize;

    for rule in all_rules.iter().filter(|r| !r.is_stateful()) {
        let mc = &rule.match_criteria;
        if mc.ethertype.is_some() { uses_ethertype += 1; }
        if mc.dst_mac.is_some() { uses_dst_mac += 1; }
        if mc.src_mac.is_some() { uses_src_mac += 1; }
        if mc.vlan_id.is_some() { uses_vlan_id += 1; }
        if mc.vlan_pcp.is_some() { uses_vlan_pcp += 1; }
        if mc.gtp_teid.is_some() { uses_gtp_teid += 1; }
        if mc.mpls_label.is_some() { uses_mpls_label += 1; }
        if mc.igmp_type.is_some() { uses_igmp_type += 1; }
        if mc.mld_type.is_some() { uses_mld_type += 1; }
        if mc.ip_dscp.is_some() { uses_ip_dscp += 1; }
        if mc.ip_ecn.is_some() { uses_ip_ecn += 1; }
        if mc.ipv6_dscp.is_some() { uses_ipv6_dscp += 1; }
        if mc.ipv6_ecn.is_some() { uses_ipv6_ecn += 1; }
        if mc.tcp_flags.is_some() { uses_tcp_flags += 1; }
        if mc.icmp_type.is_some() { uses_icmp_type += 1; }
        if mc.icmpv6_type.is_some() { uses_icmpv6_type += 1; }
        if mc.arp_opcode.is_some() { uses_arp_opcode += 1; }
        if mc.ipv6_hop_limit.is_some() { uses_ipv6_hop_limit += 1; }
        if mc.outer_vlan_id.is_some() { uses_outer_vlan_id += 1; }
        if mc.ip_dont_fragment.is_some() { uses_ip_dont_fragment += 1; }
        if mc.ip_frag_offset.is_some() { uses_ip_frag_offset += 1; }
        if mc.gre_protocol.is_some() { uses_gre_protocol += 1; }
        if mc.gre_key.is_some() { uses_gre_key += 1; }
        if mc.oam_level.is_some() { uses_oam_level += 1; }
        if mc.oam_opcode.is_some() { uses_oam_opcode += 1; }
        if mc.nsh_spi.is_some() { uses_nsh_spi += 1; }
        if mc.nsh_si.is_some() { uses_nsh_si += 1; }
        if mc.nsh_next_protocol.is_some() { uses_nsh_next_protocol += 1; }
        if mc.conntrack_state.is_some() { uses_conntrack_state += 1; }
        if mc.geneve_vni.is_some() { uses_geneve_vni += 1; }
        if mc.ip_ttl.is_some() { uses_ip_ttl += 1; }
    }

    // Priority spacing
    let mut priorities: Vec<u32> = all_rules.iter().map(|r| r.priority).collect();
    priorities.sort();

    println!();
    println!("  PacGate Rule Set Analytics");
    println!("  ════════════════════════════════════════════");
    if config.is_pipeline() {
        println!("  Pipeline:        {} stages", config.stage_count());
    }
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
        if uses_gtp_teid > 0 {
            println!("  gtp_teid   [{:>2}/{}] |{}|", uses_gtp_teid, stateless, bar(uses_gtp_teid));
        }
        if uses_mpls_label > 0 {
            println!("  mpls_label [{:>2}/{}] |{}|", uses_mpls_label, stateless, bar(uses_mpls_label));
        }
        if uses_igmp_type > 0 {
            println!("  igmp_type  [{:>2}/{}] |{}|", uses_igmp_type, stateless, bar(uses_igmp_type));
        }
        if uses_mld_type > 0 {
            println!("  mld_type   [{:>2}/{}] |{}|", uses_mld_type, stateless, bar(uses_mld_type));
        }
        if uses_ip_dscp > 0 {
            println!("  ip_dscp    [{:>2}/{}] |{}|", uses_ip_dscp, stateless, bar(uses_ip_dscp));
        }
        if uses_ip_ecn > 0 {
            println!("  ip_ecn     [{:>2}/{}] |{}|", uses_ip_ecn, stateless, bar(uses_ip_ecn));
        }
        if uses_ipv6_dscp > 0 {
            println!("  ipv6_dscp  [{:>2}/{}] |{}|", uses_ipv6_dscp, stateless, bar(uses_ipv6_dscp));
        }
        if uses_ipv6_ecn > 0 {
            println!("  ipv6_ecn   [{:>2}/{}] |{}|", uses_ipv6_ecn, stateless, bar(uses_ipv6_ecn));
        }
        if uses_tcp_flags > 0 {
            println!("  tcp_flags  [{:>2}/{}] |{}|", uses_tcp_flags, stateless, bar(uses_tcp_flags));
        }
        if uses_icmp_type > 0 {
            println!("  icmp_type  [{:>2}/{}] |{}|", uses_icmp_type, stateless, bar(uses_icmp_type));
        }
        if uses_icmpv6_type > 0 {
            println!("  icmpv6_type [{:>2}/{}] |{}|", uses_icmpv6_type, stateless, bar(uses_icmpv6_type));
        }
        if uses_arp_opcode > 0 {
            println!("  arp_opcode [{:>2}/{}] |{}|", uses_arp_opcode, stateless, bar(uses_arp_opcode));
        }
        if uses_ipv6_hop_limit > 0 {
            println!("  ipv6_hop_limit [{:>2}/{}] |{}|", uses_ipv6_hop_limit, stateless, bar(uses_ipv6_hop_limit));
        }
        if uses_outer_vlan_id > 0 {
            println!("  outer_vlan_id [{:>2}/{}] |{}|", uses_outer_vlan_id, stateless, bar(uses_outer_vlan_id));
        }
        if uses_ip_dont_fragment > 0 {
            println!("  ip_dont_frag [{:>2}/{}] |{}|", uses_ip_dont_fragment, stateless, bar(uses_ip_dont_fragment));
        }
        if uses_ip_frag_offset > 0 {
            println!("  ip_frag_off  [{:>2}/{}] |{}|", uses_ip_frag_offset, stateless, bar(uses_ip_frag_offset));
        }
        if uses_gre_protocol > 0 {
            println!("  gre_protocol [{:>2}/{}] |{}|", uses_gre_protocol, stateless, bar(uses_gre_protocol));
        }
        if uses_gre_key > 0 {
            println!("  gre_key      [{:>2}/{}] |{}|", uses_gre_key, stateless, bar(uses_gre_key));
        }
        if uses_oam_level > 0 {
            println!("  oam_level    [{:>2}/{}] |{}|", uses_oam_level, stateless, bar(uses_oam_level));
        }
        if uses_oam_opcode > 0 {
            println!("  oam_opcode   [{:>2}/{}] |{}|", uses_oam_opcode, stateless, bar(uses_oam_opcode));
        }
        if uses_nsh_spi > 0 {
            println!("  nsh_spi      [{:>2}/{}] |{}|", uses_nsh_spi, stateless, bar(uses_nsh_spi));
        }
        if uses_nsh_si > 0 {
            println!("  nsh_si       [{:>2}/{}] |{}|", uses_nsh_si, stateless, bar(uses_nsh_si));
        }
        if uses_nsh_next_protocol > 0 {
            println!("  nsh_next_proto [{:>2}/{}] |{}|", uses_nsh_next_protocol, stateless, bar(uses_nsh_next_protocol));
        }
        if uses_conntrack_state > 0 {
            println!("  ct_state     [{:>2}/{}] |{}|", uses_conntrack_state, stateless, bar(uses_conntrack_state));
        }
        if uses_geneve_vni > 0 {
            println!("  geneve_vni   [{:>2}/{}] |{}|", uses_geneve_vni, stateless, bar(uses_geneve_vni));
        }
        if uses_ip_ttl > 0 {
            println!("  ip_ttl       [{:>2}/{}] |{}|", uses_ip_ttl, stateless, bar(uses_ip_ttl));
        }
    }

    // Egress actions
    let uses_mirror = config.pacgate.rules.iter().filter(|r| r.mirror_port.is_some()).count();
    let uses_redirect = config.pacgate.rules.iter().filter(|r| r.redirect_port.is_some()).count();
    if uses_mirror > 0 || uses_redirect > 0 {
        let bar = |n: usize| "#".repeat(n).to_string() + &" ".repeat(total.saturating_sub(n));
        println!();
        println!("  Egress Actions:");
        if uses_mirror > 0 {
            println!("  mirror       [{:>2}/{}] |{}|", uses_mirror, total, bar(uses_mirror));
        }
        if uses_redirect > 0 {
            println!("  redirect     [{:>2}/{}] |{}|", uses_redirect, total, bar(uses_redirect));
        }
    }

    // Flow counters
    if model::StatelessRule::has_flow_counters(&config.pacgate) {
        println!();
        println!("  Flow Counters:");
        println!("  ─────────────────────────────────");
        println!("  enabled: true");
        if let Some(ref ct) = config.pacgate.conntrack {
            println!("  conntrack entries: {}", ct.table_size);
        }
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

    // Pipeline stage overview nodes (if pipeline)
    if let Some(tables) = &config.pacgate.tables {
        println!("  // Pipeline stages");
        for (i, stage) in tables.iter().enumerate() {
            let da = match stage.default_action { model::Action::Pass => "pass", model::Action::Drop => "drop" };
            println!("  stage_{} [label=\"Stage {}\\n'{}'\\n{} rules\\ndefault: {}\", shape=box3d, style=filled, fillcolor=\"#d4e6f1\"];",
                i, i, stage.name, stage.rules.len(), da);
            if i == 0 {
                println!("  parser -> stage_{};", i);
            } else {
                println!("  stage_{} -> stage_{};", i - 1, i);
            }
        }
        let last = tables.len() - 1;
        println!("  pass_out [label=\"PASS\", shape=oval, style=filled, fillcolor=\"#82e0aa\"];");
        println!("  drop_out [label=\"DROP\", shape=oval, style=filled, fillcolor=\"#f1948a\"];");
        println!("  stage_{} -> pass_out [label=\"all pass\"];", last);
        println!("  stage_{} -> drop_out [label=\"any drop\"];", last);
        println!("}}");
        return;
    }

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
            if let Some(teid) = mc.gtp_teid { criteria.push(format!("gtp_teid={}", teid)); }
            if let Some(label) = mc.mpls_label { criteria.push(format!("mpls_label={}", label)); }
            if let Some(tc) = mc.mpls_tc { criteria.push(format!("mpls_tc={}", tc)); }
            if let Some(bos) = mc.mpls_bos { criteria.push(format!("mpls_bos={}", bos)); }
            if let Some(igmp) = mc.igmp_type { criteria.push(format!("igmp_type=0x{:02X}", igmp)); }
            if let Some(mld) = mc.mld_type { criteria.push(format!("mld_type={}", mld)); }
            if let Some(dscp) = mc.ip_dscp { criteria.push(format!("ip_dscp={}", dscp)); }
            if let Some(ecn) = mc.ip_ecn { criteria.push(format!("ip_ecn={}", ecn)); }
            if let Some(dscp) = mc.ipv6_dscp { criteria.push(format!("ipv6_dscp={}", dscp)); }
            if let Some(ecn) = mc.ipv6_ecn { criteria.push(format!("ipv6_ecn={}", ecn)); }
            if let Some(flags) = mc.tcp_flags { criteria.push(format!("tcp_flags=0x{:02X}", flags)); }
            if let Some(t) = mc.icmp_type { criteria.push(format!("icmp_type={}", t)); }
            if let Some(c) = mc.icmp_code { criteria.push(format!("icmp_code={}", c)); }
            if let Some(t) = mc.icmpv6_type { criteria.push(format!("icmpv6_type={}", t)); }
            if let Some(c) = mc.icmpv6_code { criteria.push(format!("icmpv6_code={}", c)); }
            if let Some(op) = mc.arp_opcode { criteria.push(format!("arp_opcode={}", op)); }
            if let Some(ref spa) = mc.arp_spa { criteria.push(format!("arp_spa={}", spa)); }
            if let Some(ref tpa) = mc.arp_tpa { criteria.push(format!("arp_tpa={}", tpa)); }
            if let Some(hl) = mc.ipv6_hop_limit { criteria.push(format!("ipv6_hop_limit={}", hl)); }
            if let Some(fl) = mc.ipv6_flow_label { criteria.push(format!("ipv6_flow_label={}", fl)); }
            if let Some(vid) = mc.outer_vlan_id { criteria.push(format!("outer_vlan_id={}", vid)); }
            if let Some(pcp) = mc.outer_vlan_pcp { criteria.push(format!("outer_vlan_pcp={}", pcp)); }
            if let Some(df) = mc.ip_dont_fragment { criteria.push(format!("ip_dont_fragment={}", df)); }
            if let Some(mf) = mc.ip_more_fragments { criteria.push(format!("ip_more_fragments={}", mf)); }
            if let Some(fo) = mc.ip_frag_offset { criteria.push(format!("ip_frag_offset={}", fo)); }
            if let Some(gp) = mc.gre_protocol { criteria.push(format!("gre_protocol=0x{:04X}", gp)); }
            if let Some(gk) = mc.gre_key { criteria.push(format!("gre_key={}", gk)); }
            if let Some(ol) = mc.oam_level { criteria.push(format!("oam_level={}", ol)); }
            if let Some(oo) = mc.oam_opcode { criteria.push(format!("oam_opcode={}", oo)); }
            if let Some(spi) = mc.nsh_spi { criteria.push(format!("nsh_spi={}", spi)); }
            if let Some(si) = mc.nsh_si { criteria.push(format!("nsh_si={}", si)); }
            if let Some(np) = mc.nsh_next_protocol { criteria.push(format!("nsh_next_proto={}", np)); }
            if let Some(ref state) = mc.conntrack_state { criteria.push(format!("ct_state={}", state)); }
            if let Some(vni) = mc.geneve_vni { criteria.push(format!("geneve_vni={}", vni)); }
            if let Some(ttl) = mc.ip_ttl { criteria.push(format!("ip_ttl={}", ttl)); }
            if let Some(mt) = mc.ptp_message_type { criteria.push(format!("ptp_msg_type={}", mt)); }
            if let Some(dom) = mc.ptp_domain { criteria.push(format!("ptp_domain={}", dom)); }
            if let Some(ver) = mc.ptp_version { criteria.push(format!("ptp_version={}", ver)); }
        } else {
            criteria.push("(FSM states)".to_string());
        }
        if let Some(port) = rule.mirror_port { criteria.push(format!("mirror→{}", port)); }
        if let Some(port) = rule.redirect_port { criteria.push(format!("redirect→{}", port)); }

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

    let old_all = old.all_rules();
    let new_all = new.all_rules();
    let old_map: HashMap<&str, &model::StatelessRule> = old_all.iter()
        .map(|r| (r.name.as_str(), *r)).collect();
    let new_map: HashMap<&str, &model::StatelessRule> = new_all.iter()
        .map(|r| (r.name.as_str(), *r)).collect();

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
                // L3/L4 fields
                if old_rule.match_criteria.src_ip != new_rule.match_criteria.src_ip {
                    changes.push(format!("src_ip: {:?} -> {:?}",
                        old_rule.match_criteria.src_ip, new_rule.match_criteria.src_ip));
                }
                if old_rule.match_criteria.dst_ip != new_rule.match_criteria.dst_ip {
                    changes.push(format!("dst_ip: {:?} -> {:?}",
                        old_rule.match_criteria.dst_ip, new_rule.match_criteria.dst_ip));
                }
                if old_rule.match_criteria.ip_protocol != new_rule.match_criteria.ip_protocol {
                    changes.push(format!("ip_protocol: {:?} -> {:?}",
                        old_rule.match_criteria.ip_protocol, new_rule.match_criteria.ip_protocol));
                }
                if old_rule.match_criteria.src_port != new_rule.match_criteria.src_port {
                    changes.push(format!("src_port: {:?} -> {:?}",
                        old_rule.match_criteria.src_port, new_rule.match_criteria.src_port));
                }
                if old_rule.match_criteria.dst_port != new_rule.match_criteria.dst_port {
                    changes.push(format!("dst_port: {:?} -> {:?}",
                        old_rule.match_criteria.dst_port, new_rule.match_criteria.dst_port));
                }
                if old_rule.match_criteria.vxlan_vni != new_rule.match_criteria.vxlan_vni {
                    changes.push(format!("vxlan_vni: {:?} -> {:?}",
                        old_rule.match_criteria.vxlan_vni, new_rule.match_criteria.vxlan_vni));
                }
                // IPv6 fields
                if old_rule.match_criteria.src_ipv6 != new_rule.match_criteria.src_ipv6 {
                    changes.push(format!("src_ipv6: {:?} -> {:?}",
                        old_rule.match_criteria.src_ipv6, new_rule.match_criteria.src_ipv6));
                }
                if old_rule.match_criteria.dst_ipv6 != new_rule.match_criteria.dst_ipv6 {
                    changes.push(format!("dst_ipv6: {:?} -> {:?}",
                        old_rule.match_criteria.dst_ipv6, new_rule.match_criteria.dst_ipv6));
                }
                if old_rule.match_criteria.ipv6_next_header != new_rule.match_criteria.ipv6_next_header {
                    changes.push(format!("ipv6_next_header: {:?} -> {:?}",
                        old_rule.match_criteria.ipv6_next_header, new_rule.match_criteria.ipv6_next_header));
                }
                // Protocol extension fields
                if old_rule.match_criteria.gtp_teid != new_rule.match_criteria.gtp_teid {
                    changes.push(format!("gtp_teid: {:?} -> {:?}",
                        old_rule.match_criteria.gtp_teid, new_rule.match_criteria.gtp_teid));
                }
                if old_rule.match_criteria.mpls_label != new_rule.match_criteria.mpls_label {
                    changes.push(format!("mpls_label: {:?} -> {:?}",
                        old_rule.match_criteria.mpls_label, new_rule.match_criteria.mpls_label));
                }
                if old_rule.match_criteria.mpls_tc != new_rule.match_criteria.mpls_tc {
                    changes.push(format!("mpls_tc: {:?} -> {:?}",
                        old_rule.match_criteria.mpls_tc, new_rule.match_criteria.mpls_tc));
                }
                if old_rule.match_criteria.mpls_bos != new_rule.match_criteria.mpls_bos {
                    changes.push(format!("mpls_bos: {:?} -> {:?}",
                        old_rule.match_criteria.mpls_bos, new_rule.match_criteria.mpls_bos));
                }
                if old_rule.match_criteria.igmp_type != new_rule.match_criteria.igmp_type {
                    changes.push(format!("igmp_type: {:?} -> {:?}",
                        old_rule.match_criteria.igmp_type, new_rule.match_criteria.igmp_type));
                }
                if old_rule.match_criteria.mld_type != new_rule.match_criteria.mld_type {
                    changes.push(format!("mld_type: {:?} -> {:?}",
                        old_rule.match_criteria.mld_type, new_rule.match_criteria.mld_type));
                }
                if old_rule.match_criteria.ip_dscp != new_rule.match_criteria.ip_dscp {
                    changes.push(format!("ip_dscp: {:?} -> {:?}",
                        old_rule.match_criteria.ip_dscp, new_rule.match_criteria.ip_dscp));
                }
                if old_rule.match_criteria.ip_ecn != new_rule.match_criteria.ip_ecn {
                    changes.push(format!("ip_ecn: {:?} -> {:?}",
                        old_rule.match_criteria.ip_ecn, new_rule.match_criteria.ip_ecn));
                }
                if old_rule.match_criteria.ipv6_dscp != new_rule.match_criteria.ipv6_dscp {
                    changes.push(format!("ipv6_dscp: {:?} -> {:?}",
                        old_rule.match_criteria.ipv6_dscp, new_rule.match_criteria.ipv6_dscp));
                }
                if old_rule.match_criteria.ipv6_ecn != new_rule.match_criteria.ipv6_ecn {
                    changes.push(format!("ipv6_ecn: {:?} -> {:?}",
                        old_rule.match_criteria.ipv6_ecn, new_rule.match_criteria.ipv6_ecn));
                }
                if old_rule.match_criteria.tcp_flags != new_rule.match_criteria.tcp_flags {
                    changes.push(format!("tcp_flags: {:?} -> {:?}",
                        old_rule.match_criteria.tcp_flags, new_rule.match_criteria.tcp_flags));
                }
                if old_rule.match_criteria.tcp_flags_mask != new_rule.match_criteria.tcp_flags_mask {
                    changes.push(format!("tcp_flags_mask: {:?} -> {:?}",
                        old_rule.match_criteria.tcp_flags_mask, new_rule.match_criteria.tcp_flags_mask));
                }
                if old_rule.match_criteria.icmp_type != new_rule.match_criteria.icmp_type {
                    changes.push(format!("icmp_type: {:?} -> {:?}",
                        old_rule.match_criteria.icmp_type, new_rule.match_criteria.icmp_type));
                }
                if old_rule.match_criteria.icmp_code != new_rule.match_criteria.icmp_code {
                    changes.push(format!("icmp_code: {:?} -> {:?}",
                        old_rule.match_criteria.icmp_code, new_rule.match_criteria.icmp_code));
                }
                if old_rule.match_criteria.icmpv6_type != new_rule.match_criteria.icmpv6_type {
                    changes.push(format!("icmpv6_type: {:?} -> {:?}",
                        old_rule.match_criteria.icmpv6_type, new_rule.match_criteria.icmpv6_type));
                }
                if old_rule.match_criteria.icmpv6_code != new_rule.match_criteria.icmpv6_code {
                    changes.push(format!("icmpv6_code: {:?} -> {:?}",
                        old_rule.match_criteria.icmpv6_code, new_rule.match_criteria.icmpv6_code));
                }
                if old_rule.match_criteria.arp_opcode != new_rule.match_criteria.arp_opcode {
                    changes.push(format!("arp_opcode: {:?} -> {:?}",
                        old_rule.match_criteria.arp_opcode, new_rule.match_criteria.arp_opcode));
                }
                if old_rule.match_criteria.arp_spa != new_rule.match_criteria.arp_spa {
                    changes.push(format!("arp_spa: {:?} -> {:?}",
                        old_rule.match_criteria.arp_spa, new_rule.match_criteria.arp_spa));
                }
                if old_rule.match_criteria.arp_tpa != new_rule.match_criteria.arp_tpa {
                    changes.push(format!("arp_tpa: {:?} -> {:?}",
                        old_rule.match_criteria.arp_tpa, new_rule.match_criteria.arp_tpa));
                }
                if old_rule.match_criteria.ipv6_hop_limit != new_rule.match_criteria.ipv6_hop_limit {
                    changes.push(format!("ipv6_hop_limit: {:?} -> {:?}",
                        old_rule.match_criteria.ipv6_hop_limit, new_rule.match_criteria.ipv6_hop_limit));
                }
                if old_rule.match_criteria.ipv6_flow_label != new_rule.match_criteria.ipv6_flow_label {
                    changes.push(format!("ipv6_flow_label: {:?} -> {:?}",
                        old_rule.match_criteria.ipv6_flow_label, new_rule.match_criteria.ipv6_flow_label));
                }
                if old_rule.match_criteria.outer_vlan_id != new_rule.match_criteria.outer_vlan_id {
                    changes.push(format!("outer_vlan_id: {:?} -> {:?}",
                        old_rule.match_criteria.outer_vlan_id, new_rule.match_criteria.outer_vlan_id));
                }
                if old_rule.match_criteria.outer_vlan_pcp != new_rule.match_criteria.outer_vlan_pcp {
                    changes.push(format!("outer_vlan_pcp: {:?} -> {:?}",
                        old_rule.match_criteria.outer_vlan_pcp, new_rule.match_criteria.outer_vlan_pcp));
                }
                if old_rule.match_criteria.ip_dont_fragment != new_rule.match_criteria.ip_dont_fragment {
                    changes.push(format!("ip_dont_fragment: {:?} -> {:?}",
                        old_rule.match_criteria.ip_dont_fragment, new_rule.match_criteria.ip_dont_fragment));
                }
                if old_rule.match_criteria.ip_more_fragments != new_rule.match_criteria.ip_more_fragments {
                    changes.push(format!("ip_more_fragments: {:?} -> {:?}",
                        old_rule.match_criteria.ip_more_fragments, new_rule.match_criteria.ip_more_fragments));
                }
                if old_rule.match_criteria.ip_frag_offset != new_rule.match_criteria.ip_frag_offset {
                    changes.push(format!("ip_frag_offset: {:?} -> {:?}",
                        old_rule.match_criteria.ip_frag_offset, new_rule.match_criteria.ip_frag_offset));
                }
                if old_rule.match_criteria.gre_protocol != new_rule.match_criteria.gre_protocol {
                    changes.push(format!("gre_protocol: {:?} -> {:?}",
                        old_rule.match_criteria.gre_protocol, new_rule.match_criteria.gre_protocol));
                }
                if old_rule.match_criteria.gre_key != new_rule.match_criteria.gre_key {
                    changes.push(format!("gre_key: {:?} -> {:?}",
                        old_rule.match_criteria.gre_key, new_rule.match_criteria.gre_key));
                }
                if old_rule.match_criteria.oam_level != new_rule.match_criteria.oam_level {
                    changes.push(format!("oam_level: {:?} -> {:?}",
                        old_rule.match_criteria.oam_level, new_rule.match_criteria.oam_level));
                }
                if old_rule.match_criteria.oam_opcode != new_rule.match_criteria.oam_opcode {
                    changes.push(format!("oam_opcode: {:?} -> {:?}",
                        old_rule.match_criteria.oam_opcode, new_rule.match_criteria.oam_opcode));
                }
                if old_rule.match_criteria.nsh_spi != new_rule.match_criteria.nsh_spi {
                    changes.push(format!("nsh_spi: {:?} -> {:?}",
                        old_rule.match_criteria.nsh_spi, new_rule.match_criteria.nsh_spi));
                }
                if old_rule.match_criteria.nsh_si != new_rule.match_criteria.nsh_si {
                    changes.push(format!("nsh_si: {:?} -> {:?}",
                        old_rule.match_criteria.nsh_si, new_rule.match_criteria.nsh_si));
                }
                if old_rule.match_criteria.nsh_next_protocol != new_rule.match_criteria.nsh_next_protocol {
                    changes.push(format!("nsh_next_protocol: {:?} -> {:?}",
                        old_rule.match_criteria.nsh_next_protocol, new_rule.match_criteria.nsh_next_protocol));
                }
                if old_rule.match_criteria.conntrack_state != new_rule.match_criteria.conntrack_state {
                    changes.push(format!("conntrack_state: {:?} -> {:?}",
                        old_rule.match_criteria.conntrack_state, new_rule.match_criteria.conntrack_state));
                }
                if old_rule.match_criteria.geneve_vni != new_rule.match_criteria.geneve_vni {
                    changes.push(format!("geneve_vni: {:?} -> {:?}",
                        old_rule.match_criteria.geneve_vni, new_rule.match_criteria.geneve_vni));
                }
                if old_rule.match_criteria.ip_ttl != new_rule.match_criteria.ip_ttl {
                    changes.push(format!("ip_ttl: {:?} -> {:?}",
                        old_rule.match_criteria.ip_ttl, new_rule.match_criteria.ip_ttl));
                }
                if old_rule.match_criteria.ptp_message_type != new_rule.match_criteria.ptp_message_type {
                    changes.push(format!("ptp_message_type: {:?} -> {:?}",
                        old_rule.match_criteria.ptp_message_type, new_rule.match_criteria.ptp_message_type));
                }
                if old_rule.match_criteria.ptp_domain != new_rule.match_criteria.ptp_domain {
                    changes.push(format!("ptp_domain: {:?} -> {:?}",
                        old_rule.match_criteria.ptp_domain, new_rule.match_criteria.ptp_domain));
                }
                if old_rule.match_criteria.ptp_version != new_rule.match_criteria.ptp_version {
                    changes.push(format!("ptp_version: {:?} -> {:?}",
                        old_rule.match_criteria.ptp_version, new_rule.match_criteria.ptp_version));
                }
                if old_rule.is_stateful() != new_rule.is_stateful() {
                    changes.push(format!("type: {} -> {}",
                        if old_rule.is_stateful() { "stateful" } else { "stateless" },
                        if new_rule.is_stateful() { "stateful" } else { "stateless" }));
                }
                // Rewrite actions
                if old_rule.rewrite != new_rule.rewrite {
                    let old_rw = old_rule.rewrite.as_ref().map(|r| format!("{:?}", r)).unwrap_or_else(|| "None".to_string());
                    let new_rw = new_rule.rewrite.as_ref().map(|r| format!("{:?}", r)).unwrap_or_else(|| "None".to_string());
                    changes.push(format!("rewrite: {} -> {}", old_rw, new_rw));
                }
                // Egress actions
                if old_rule.mirror_port != new_rule.mirror_port {
                    changes.push(format!("mirror_port: {:?} -> {:?}",
                        old_rule.mirror_port, new_rule.mirror_port));
                }
                if old_rule.redirect_port != new_rule.redirect_port {
                    changes.push(format!("redirect_port: {:?} -> {:?}",
                        old_rule.redirect_port, new_rule.redirect_port));
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

    // Check conntrack config changes
    let mut conntrack_changes: Vec<String> = Vec::new();
    match (&old.pacgate.conntrack, &new.pacgate.conntrack) {
        (None, Some(ct)) => {
            conntrack_changes.push(format!("conntrack: added (table_size={}, timeout={})", ct.table_size, ct.timeout_cycles));
            if ct.enable_flow_counters == Some(true) {
                conntrack_changes.push("flow_counters: enabled".to_string());
            }
        }
        (Some(_), None) => {
            conntrack_changes.push("conntrack: removed".to_string());
        }
        (Some(old_ct), Some(new_ct)) => {
            if old_ct.table_size != new_ct.table_size {
                conntrack_changes.push(format!("conntrack table_size: {} -> {}", old_ct.table_size, new_ct.table_size));
            }
            if old_ct.timeout_cycles != new_ct.timeout_cycles {
                conntrack_changes.push(format!("conntrack timeout_cycles: {} -> {}", old_ct.timeout_cycles, new_ct.timeout_cycles));
            }
            if old_ct.enable_flow_counters != new_ct.enable_flow_counters {
                conntrack_changes.push(format!("conntrack enable_flow_counters: {:?} -> {:?}",
                    old_ct.enable_flow_counters, new_ct.enable_flow_counters));
            }
        }
        (None, None) => {}
    }

    if json {
        let summary = serde_json::json!({
            "added": added,
            "removed": removed,
            "modified": modified.iter().map(|(name, changes)| {
                serde_json::json!({ "name": name, "changes": changes })
            }).collect::<Vec<_>>(),
            "unchanged": unchanged.len(),
            "default_action_changed": default_changed,
            "conntrack_changes": conntrack_changes,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        if default_changed {
            println!("  Default action: {:?} -> {:?}",
                old.pacgate.defaults.action, new.pacgate.defaults.action);
            println!();
        }

        if !conntrack_changes.is_empty() {
            println!("  Conntrack config changes:");
            for change in &conntrack_changes {
                println!("    ~ {}", change);
            }
            println!();
        }

        if added.is_empty() && removed.is_empty() && modified.is_empty() && !default_changed && conntrack_changes.is_empty() {
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

fn generate_diff_html(
    old: &model::FilterConfig,
    new: &model::FilterConfig,
    old_path: &Path,
    new_path: &Path,
    templates_dir: &Path,
    output_path: &Path,
) -> Result<()> {
    use std::collections::HashMap;

    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = tera::Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let old_map: HashMap<&str, &model::StatelessRule> = old.pacgate.rules.iter()
        .map(|r| (r.name.as_str(), r)).collect();
    let new_map: HashMap<&str, &model::StatelessRule> = new.pacgate.rules.iter()
        .map(|r| (r.name.as_str(), r)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged_count = 0usize;

    // Build criteria description
    let criteria_str = |r: &model::StatelessRule| -> String {
        let mc = &r.match_criteria;
        let mut parts = Vec::new();
        if let Some(ref e) = mc.ethertype { parts.push(format!("ethertype={}", e)); }
        if let Some(ref m) = mc.dst_mac { parts.push(format!("dst_mac={}", m)); }
        if let Some(ref m) = mc.src_mac { parts.push(format!("src_mac={}", m)); }
        if let Some(ref ip) = mc.src_ip { parts.push(format!("src_ip={}", ip)); }
        if let Some(ref ip) = mc.dst_ip { parts.push(format!("dst_ip={}", ip)); }
        if let Some(p) = mc.ip_protocol { parts.push(format!("ip_protocol={}", p)); }
        if let Some(ref pm) = mc.src_port { parts.push(format!("src_port={}", format_port_match(pm))); }
        if let Some(ref pm) = mc.dst_port { parts.push(format!("dst_port={}", format_port_match(pm))); }
        if let Some(vid) = mc.vlan_id { parts.push(format!("vlan_id={}", vid)); }
        if let Some(vni) = mc.vxlan_vni { parts.push(format!("vxlan_vni={}", vni)); }
        if let Some(ref ipv6) = mc.src_ipv6 { parts.push(format!("src_ipv6={}", ipv6)); }
        if let Some(ref ipv6) = mc.dst_ipv6 { parts.push(format!("dst_ipv6={}", ipv6)); }
        if let Some(nh) = mc.ipv6_next_header { parts.push(format!("ipv6_next_header={}", nh)); }
        if let Some(teid) = mc.gtp_teid { parts.push(format!("gtp_teid={}", teid)); }
        if let Some(label) = mc.mpls_label { parts.push(format!("mpls_label={}", label)); }
        if let Some(tc) = mc.mpls_tc { parts.push(format!("mpls_tc={}", tc)); }
        if let Some(bos) = mc.mpls_bos { parts.push(format!("mpls_bos={}", bos)); }
        if let Some(igmp) = mc.igmp_type { parts.push(format!("igmp_type=0x{:02X}", igmp)); }
        if let Some(mld) = mc.mld_type { parts.push(format!("mld_type={}", mld)); }
        if let Some(t) = mc.icmpv6_type { parts.push(format!("icmpv6_type={}", t)); }
        if let Some(c) = mc.icmpv6_code { parts.push(format!("icmpv6_code={}", c)); }
        if let Some(op) = mc.arp_opcode { parts.push(format!("arp_opcode={}", op)); }
        if let Some(ref spa) = mc.arp_spa { parts.push(format!("arp_spa={}", spa)); }
        if let Some(ref tpa) = mc.arp_tpa { parts.push(format!("arp_tpa={}", tpa)); }
        if let Some(hl) = mc.ipv6_hop_limit { parts.push(format!("ipv6_hop_limit={}", hl)); }
        if let Some(fl) = mc.ipv6_flow_label { parts.push(format!("ipv6_flow_label={}", fl)); }
        if let Some(vid) = mc.outer_vlan_id { parts.push(format!("outer_vlan_id={}", vid)); }
        if let Some(pcp) = mc.outer_vlan_pcp { parts.push(format!("outer_vlan_pcp={}", pcp)); }
        if let Some(df) = mc.ip_dont_fragment { parts.push(format!("ip_dont_fragment={}", df)); }
        if let Some(mf) = mc.ip_more_fragments { parts.push(format!("ip_more_fragments={}", mf)); }
        if let Some(fo) = mc.ip_frag_offset { parts.push(format!("ip_frag_offset={}", fo)); }
        if let Some(gp) = mc.gre_protocol { parts.push(format!("gre_protocol=0x{:04X}", gp)); }
        if let Some(gk) = mc.gre_key { parts.push(format!("gre_key={}", gk)); }
        if let Some(ol) = mc.oam_level { parts.push(format!("oam_level={}", ol)); }
        if let Some(oo) = mc.oam_opcode { parts.push(format!("oam_opcode={}", oo)); }
        if let Some(spi) = mc.nsh_spi { parts.push(format!("nsh_spi={}", spi)); }
        if let Some(si) = mc.nsh_si { parts.push(format!("nsh_si={}", si)); }
        if let Some(np) = mc.nsh_next_protocol { parts.push(format!("nsh_next_proto={}", np)); }
        if let Some(ref state) = mc.conntrack_state { parts.push(format!("ct_state={}", state)); }
        if let Some(vni) = mc.geneve_vni { parts.push(format!("geneve_vni={}", vni)); }
        if let Some(ttl) = mc.ip_ttl { parts.push(format!("ip_ttl={}", ttl)); }
        if parts.is_empty() { "any".to_string() } else { parts.join(", ") }
    };

    let action_str = |r: &model::StatelessRule| -> String {
        match &r.action {
            Some(model::Action::Pass) => "pass".to_string(),
            Some(model::Action::Drop) => "drop".to_string(),
            None => "default".to_string(),
        }
    };

    // Compute diffs
    for (name, old_rule) in &old_map {
        match new_map.get(name) {
            None => {
                removed.push(serde_json::json!({
                    "name": name,
                    "priority": old_rule.priority,
                    "action": action_str(old_rule),
                    "criteria": criteria_str(old_rule),
                }));
            }
            Some(new_rule) => {
                let mut changes = Vec::new();
                if old_rule.priority != new_rule.priority {
                    changes.push(serde_json::json!({
                        "field": "priority",
                        "old_value": old_rule.priority.to_string(),
                        "new_value": new_rule.priority.to_string(),
                    }));
                }
                if old_rule.action != new_rule.action {
                    changes.push(serde_json::json!({
                        "field": "action",
                        "old_value": action_str(old_rule),
                        "new_value": action_str(new_rule),
                    }));
                }
                if old_rule.match_criteria.ethertype != new_rule.match_criteria.ethertype {
                    changes.push(serde_json::json!({
                        "field": "ethertype",
                        "old_value": format!("{:?}", old_rule.match_criteria.ethertype),
                        "new_value": format!("{:?}", new_rule.match_criteria.ethertype),
                    }));
                }
                if old_rule.match_criteria.dst_mac != new_rule.match_criteria.dst_mac {
                    changes.push(serde_json::json!({
                        "field": "dst_mac",
                        "old_value": format!("{:?}", old_rule.match_criteria.dst_mac),
                        "new_value": format!("{:?}", new_rule.match_criteria.dst_mac),
                    }));
                }
                if old_rule.match_criteria.src_ip != new_rule.match_criteria.src_ip {
                    changes.push(serde_json::json!({
                        "field": "src_ip",
                        "old_value": format!("{:?}", old_rule.match_criteria.src_ip),
                        "new_value": format!("{:?}", new_rule.match_criteria.src_ip),
                    }));
                }
                if old_rule.match_criteria.dst_ip != new_rule.match_criteria.dst_ip {
                    changes.push(serde_json::json!({
                        "field": "dst_ip",
                        "old_value": format!("{:?}", old_rule.match_criteria.dst_ip),
                        "new_value": format!("{:?}", new_rule.match_criteria.dst_ip),
                    }));
                }
                if old_rule.match_criteria.dst_port != new_rule.match_criteria.dst_port {
                    changes.push(serde_json::json!({
                        "field": "dst_port",
                        "old_value": format!("{:?}", old_rule.match_criteria.dst_port),
                        "new_value": format!("{:?}", new_rule.match_criteria.dst_port),
                    }));
                }
                if old_rule.match_criteria.src_port != new_rule.match_criteria.src_port {
                    changes.push(serde_json::json!({
                        "field": "src_port",
                        "old_value": format!("{:?}", old_rule.match_criteria.src_port),
                        "new_value": format!("{:?}", new_rule.match_criteria.src_port),
                    }));
                }
                if old_rule.match_criteria.src_mac != new_rule.match_criteria.src_mac {
                    changes.push(serde_json::json!({
                        "field": "src_mac",
                        "old_value": format!("{:?}", old_rule.match_criteria.src_mac),
                        "new_value": format!("{:?}", new_rule.match_criteria.src_mac),
                    }));
                }
                if old_rule.match_criteria.vlan_id != new_rule.match_criteria.vlan_id {
                    changes.push(serde_json::json!({
                        "field": "vlan_id",
                        "old_value": format!("{:?}", old_rule.match_criteria.vlan_id),
                        "new_value": format!("{:?}", new_rule.match_criteria.vlan_id),
                    }));
                }
                if old_rule.match_criteria.ip_protocol != new_rule.match_criteria.ip_protocol {
                    changes.push(serde_json::json!({
                        "field": "ip_protocol",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_protocol),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_protocol),
                    }));
                }
                if old_rule.match_criteria.vxlan_vni != new_rule.match_criteria.vxlan_vni {
                    changes.push(serde_json::json!({
                        "field": "vxlan_vni",
                        "old_value": format!("{:?}", old_rule.match_criteria.vxlan_vni),
                        "new_value": format!("{:?}", new_rule.match_criteria.vxlan_vni),
                    }));
                }
                if old_rule.match_criteria.src_ipv6 != new_rule.match_criteria.src_ipv6 {
                    changes.push(serde_json::json!({
                        "field": "src_ipv6",
                        "old_value": format!("{:?}", old_rule.match_criteria.src_ipv6),
                        "new_value": format!("{:?}", new_rule.match_criteria.src_ipv6),
                    }));
                }
                if old_rule.match_criteria.dst_ipv6 != new_rule.match_criteria.dst_ipv6 {
                    changes.push(serde_json::json!({
                        "field": "dst_ipv6",
                        "old_value": format!("{:?}", old_rule.match_criteria.dst_ipv6),
                        "new_value": format!("{:?}", new_rule.match_criteria.dst_ipv6),
                    }));
                }
                if old_rule.match_criteria.ipv6_next_header != new_rule.match_criteria.ipv6_next_header {
                    changes.push(serde_json::json!({
                        "field": "ipv6_next_header",
                        "old_value": format!("{:?}", old_rule.match_criteria.ipv6_next_header),
                        "new_value": format!("{:?}", new_rule.match_criteria.ipv6_next_header),
                    }));
                }
                if old_rule.match_criteria.gtp_teid != new_rule.match_criteria.gtp_teid {
                    changes.push(serde_json::json!({
                        "field": "gtp_teid",
                        "old_value": format!("{:?}", old_rule.match_criteria.gtp_teid),
                        "new_value": format!("{:?}", new_rule.match_criteria.gtp_teid),
                    }));
                }
                if old_rule.match_criteria.mpls_label != new_rule.match_criteria.mpls_label {
                    changes.push(serde_json::json!({
                        "field": "mpls_label",
                        "old_value": format!("{:?}", old_rule.match_criteria.mpls_label),
                        "new_value": format!("{:?}", new_rule.match_criteria.mpls_label),
                    }));
                }
                if old_rule.match_criteria.mpls_tc != new_rule.match_criteria.mpls_tc {
                    changes.push(serde_json::json!({
                        "field": "mpls_tc",
                        "old_value": format!("{:?}", old_rule.match_criteria.mpls_tc),
                        "new_value": format!("{:?}", new_rule.match_criteria.mpls_tc),
                    }));
                }
                if old_rule.match_criteria.mpls_bos != new_rule.match_criteria.mpls_bos {
                    changes.push(serde_json::json!({
                        "field": "mpls_bos",
                        "old_value": format!("{:?}", old_rule.match_criteria.mpls_bos),
                        "new_value": format!("{:?}", new_rule.match_criteria.mpls_bos),
                    }));
                }
                if old_rule.match_criteria.igmp_type != new_rule.match_criteria.igmp_type {
                    changes.push(serde_json::json!({
                        "field": "igmp_type",
                        "old_value": format!("{:?}", old_rule.match_criteria.igmp_type),
                        "new_value": format!("{:?}", new_rule.match_criteria.igmp_type),
                    }));
                }
                if old_rule.match_criteria.mld_type != new_rule.match_criteria.mld_type {
                    changes.push(serde_json::json!({
                        "field": "mld_type",
                        "old_value": format!("{:?}", old_rule.match_criteria.mld_type),
                        "new_value": format!("{:?}", new_rule.match_criteria.mld_type),
                    }));
                }
                if old_rule.match_criteria.ip_dscp != new_rule.match_criteria.ip_dscp {
                    changes.push(serde_json::json!({
                        "field": "ip_dscp",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_dscp),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_dscp),
                    }));
                }
                if old_rule.match_criteria.ip_ecn != new_rule.match_criteria.ip_ecn {
                    changes.push(serde_json::json!({
                        "field": "ip_ecn",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_ecn),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_ecn),
                    }));
                }
                if old_rule.match_criteria.ipv6_dscp != new_rule.match_criteria.ipv6_dscp {
                    changes.push(serde_json::json!({
                        "field": "ipv6_dscp",
                        "old_value": format!("{:?}", old_rule.match_criteria.ipv6_dscp),
                        "new_value": format!("{:?}", new_rule.match_criteria.ipv6_dscp),
                    }));
                }
                if old_rule.match_criteria.ipv6_ecn != new_rule.match_criteria.ipv6_ecn {
                    changes.push(serde_json::json!({
                        "field": "ipv6_ecn",
                        "old_value": format!("{:?}", old_rule.match_criteria.ipv6_ecn),
                        "new_value": format!("{:?}", new_rule.match_criteria.ipv6_ecn),
                    }));
                }
                if old_rule.match_criteria.tcp_flags != new_rule.match_criteria.tcp_flags {
                    changes.push(serde_json::json!({
                        "field": "tcp_flags",
                        "old_value": format!("{:?}", old_rule.match_criteria.tcp_flags),
                        "new_value": format!("{:?}", new_rule.match_criteria.tcp_flags),
                    }));
                }
                if old_rule.match_criteria.tcp_flags_mask != new_rule.match_criteria.tcp_flags_mask {
                    changes.push(serde_json::json!({
                        "field": "tcp_flags_mask",
                        "old_value": format!("{:?}", old_rule.match_criteria.tcp_flags_mask),
                        "new_value": format!("{:?}", new_rule.match_criteria.tcp_flags_mask),
                    }));
                }
                if old_rule.match_criteria.icmp_type != new_rule.match_criteria.icmp_type {
                    changes.push(serde_json::json!({
                        "field": "icmp_type",
                        "old_value": format!("{:?}", old_rule.match_criteria.icmp_type),
                        "new_value": format!("{:?}", new_rule.match_criteria.icmp_type),
                    }));
                }
                if old_rule.match_criteria.icmp_code != new_rule.match_criteria.icmp_code {
                    changes.push(serde_json::json!({
                        "field": "icmp_code",
                        "old_value": format!("{:?}", old_rule.match_criteria.icmp_code),
                        "new_value": format!("{:?}", new_rule.match_criteria.icmp_code),
                    }));
                }
                if old_rule.match_criteria.icmpv6_type != new_rule.match_criteria.icmpv6_type {
                    changes.push(serde_json::json!({
                        "field": "icmpv6_type",
                        "old_value": format!("{:?}", old_rule.match_criteria.icmpv6_type),
                        "new_value": format!("{:?}", new_rule.match_criteria.icmpv6_type),
                    }));
                }
                if old_rule.match_criteria.icmpv6_code != new_rule.match_criteria.icmpv6_code {
                    changes.push(serde_json::json!({
                        "field": "icmpv6_code",
                        "old_value": format!("{:?}", old_rule.match_criteria.icmpv6_code),
                        "new_value": format!("{:?}", new_rule.match_criteria.icmpv6_code),
                    }));
                }
                if old_rule.match_criteria.arp_opcode != new_rule.match_criteria.arp_opcode {
                    changes.push(serde_json::json!({
                        "field": "arp_opcode",
                        "old_value": format!("{:?}", old_rule.match_criteria.arp_opcode),
                        "new_value": format!("{:?}", new_rule.match_criteria.arp_opcode),
                    }));
                }
                if old_rule.match_criteria.arp_spa != new_rule.match_criteria.arp_spa {
                    changes.push(serde_json::json!({
                        "field": "arp_spa",
                        "old_value": format!("{:?}", old_rule.match_criteria.arp_spa),
                        "new_value": format!("{:?}", new_rule.match_criteria.arp_spa),
                    }));
                }
                if old_rule.match_criteria.arp_tpa != new_rule.match_criteria.arp_tpa {
                    changes.push(serde_json::json!({
                        "field": "arp_tpa",
                        "old_value": format!("{:?}", old_rule.match_criteria.arp_tpa),
                        "new_value": format!("{:?}", new_rule.match_criteria.arp_tpa),
                    }));
                }
                if old_rule.match_criteria.ipv6_hop_limit != new_rule.match_criteria.ipv6_hop_limit {
                    changes.push(serde_json::json!({
                        "field": "ipv6_hop_limit",
                        "old_value": format!("{:?}", old_rule.match_criteria.ipv6_hop_limit),
                        "new_value": format!("{:?}", new_rule.match_criteria.ipv6_hop_limit),
                    }));
                }
                if old_rule.match_criteria.ipv6_flow_label != new_rule.match_criteria.ipv6_flow_label {
                    changes.push(serde_json::json!({
                        "field": "ipv6_flow_label",
                        "old_value": format!("{:?}", old_rule.match_criteria.ipv6_flow_label),
                        "new_value": format!("{:?}", new_rule.match_criteria.ipv6_flow_label),
                    }));
                }
                if old_rule.match_criteria.outer_vlan_id != new_rule.match_criteria.outer_vlan_id {
                    changes.push(serde_json::json!({
                        "field": "outer_vlan_id",
                        "old_value": format!("{:?}", old_rule.match_criteria.outer_vlan_id),
                        "new_value": format!("{:?}", new_rule.match_criteria.outer_vlan_id),
                    }));
                }
                if old_rule.match_criteria.outer_vlan_pcp != new_rule.match_criteria.outer_vlan_pcp {
                    changes.push(serde_json::json!({
                        "field": "outer_vlan_pcp",
                        "old_value": format!("{:?}", old_rule.match_criteria.outer_vlan_pcp),
                        "new_value": format!("{:?}", new_rule.match_criteria.outer_vlan_pcp),
                    }));
                }
                if old_rule.match_criteria.ip_dont_fragment != new_rule.match_criteria.ip_dont_fragment {
                    changes.push(serde_json::json!({
                        "field": "ip_dont_fragment",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_dont_fragment),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_dont_fragment),
                    }));
                }
                if old_rule.match_criteria.ip_more_fragments != new_rule.match_criteria.ip_more_fragments {
                    changes.push(serde_json::json!({
                        "field": "ip_more_fragments",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_more_fragments),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_more_fragments),
                    }));
                }
                if old_rule.match_criteria.ip_frag_offset != new_rule.match_criteria.ip_frag_offset {
                    changes.push(serde_json::json!({
                        "field": "ip_frag_offset",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_frag_offset),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_frag_offset),
                    }));
                }
                if old_rule.match_criteria.gre_protocol != new_rule.match_criteria.gre_protocol {
                    changes.push(serde_json::json!({
                        "field": "gre_protocol",
                        "old_value": format!("{:?}", old_rule.match_criteria.gre_protocol),
                        "new_value": format!("{:?}", new_rule.match_criteria.gre_protocol),
                    }));
                }
                if old_rule.match_criteria.gre_key != new_rule.match_criteria.gre_key {
                    changes.push(serde_json::json!({
                        "field": "gre_key",
                        "old_value": format!("{:?}", old_rule.match_criteria.gre_key),
                        "new_value": format!("{:?}", new_rule.match_criteria.gre_key),
                    }));
                }
                if old_rule.match_criteria.oam_level != new_rule.match_criteria.oam_level {
                    changes.push(serde_json::json!({
                        "field": "oam_level",
                        "old_value": format!("{:?}", old_rule.match_criteria.oam_level),
                        "new_value": format!("{:?}", new_rule.match_criteria.oam_level),
                    }));
                }
                if old_rule.match_criteria.oam_opcode != new_rule.match_criteria.oam_opcode {
                    changes.push(serde_json::json!({
                        "field": "oam_opcode",
                        "old_value": format!("{:?}", old_rule.match_criteria.oam_opcode),
                        "new_value": format!("{:?}", new_rule.match_criteria.oam_opcode),
                    }));
                }
                if old_rule.match_criteria.nsh_spi != new_rule.match_criteria.nsh_spi {
                    changes.push(serde_json::json!({
                        "field": "nsh_spi",
                        "old_value": format!("{:?}", old_rule.match_criteria.nsh_spi),
                        "new_value": format!("{:?}", new_rule.match_criteria.nsh_spi),
                    }));
                }
                if old_rule.match_criteria.nsh_si != new_rule.match_criteria.nsh_si {
                    changes.push(serde_json::json!({
                        "field": "nsh_si",
                        "old_value": format!("{:?}", old_rule.match_criteria.nsh_si),
                        "new_value": format!("{:?}", new_rule.match_criteria.nsh_si),
                    }));
                }
                if old_rule.match_criteria.nsh_next_protocol != new_rule.match_criteria.nsh_next_protocol {
                    changes.push(serde_json::json!({
                        "field": "nsh_next_protocol",
                        "old_value": format!("{:?}", old_rule.match_criteria.nsh_next_protocol),
                        "new_value": format!("{:?}", new_rule.match_criteria.nsh_next_protocol),
                    }));
                }
                if old_rule.match_criteria.conntrack_state != new_rule.match_criteria.conntrack_state {
                    changes.push(serde_json::json!({
                        "field": "conntrack_state",
                        "old_value": format!("{:?}", old_rule.match_criteria.conntrack_state),
                        "new_value": format!("{:?}", new_rule.match_criteria.conntrack_state),
                    }));
                }
                if old_rule.match_criteria.geneve_vni != new_rule.match_criteria.geneve_vni {
                    changes.push(serde_json::json!({
                        "field": "geneve_vni",
                        "old_value": format!("{:?}", old_rule.match_criteria.geneve_vni),
                        "new_value": format!("{:?}", new_rule.match_criteria.geneve_vni),
                    }));
                }
                if old_rule.match_criteria.ip_ttl != new_rule.match_criteria.ip_ttl {
                    changes.push(serde_json::json!({
                        "field": "ip_ttl",
                        "old_value": format!("{:?}", old_rule.match_criteria.ip_ttl),
                        "new_value": format!("{:?}", new_rule.match_criteria.ip_ttl),
                    }));
                }
                if old_rule.mirror_port != new_rule.mirror_port {
                    changes.push(serde_json::json!({
                        "field": "mirror_port",
                        "old_value": format!("{:?}", old_rule.mirror_port),
                        "new_value": format!("{:?}", new_rule.mirror_port),
                    }));
                }
                if old_rule.redirect_port != new_rule.redirect_port {
                    changes.push(serde_json::json!({
                        "field": "redirect_port",
                        "old_value": format!("{:?}", old_rule.redirect_port),
                        "new_value": format!("{:?}", new_rule.redirect_port),
                    }));
                }

                if changes.is_empty() {
                    unchanged_count += 1;
                } else {
                    modified.push(serde_json::json!({
                        "name": name,
                        "old_priority": old_rule.priority,
                        "new_priority": new_rule.priority,
                        "old_action": action_str(old_rule),
                        "new_action": action_str(new_rule),
                        "old_criteria": criteria_str(old_rule),
                        "new_criteria": criteria_str(new_rule),
                        "changes": changes,
                    }));
                }
            }
        }
    }

    for name in new_map.keys() {
        if !old_map.contains_key(name) {
            let r = new_map[name];
            added.push(serde_json::json!({
                "name": name,
                "priority": r.priority,
                "action": action_str(r),
                "criteria": criteria_str(r),
            }));
        }
    }

    let default_changed = old.pacgate.defaults.action != new.pacgate.defaults.action;
    let old_default = match old.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" };
    let new_default = match new.pacgate.defaults.action { model::Action::Pass => "pass", model::Action::Drop => "drop" };

    let mut ctx = tera::Context::new();
    ctx.insert("old_file", &old_path.display().to_string());
    ctx.insert("new_file", &new_path.display().to_string());
    ctx.insert("old_rule_count", &old.pacgate.rules.len());
    ctx.insert("new_rule_count", &new.pacgate.rules.len());
    ctx.insert("timestamp", &chrono_timestamp());
    ctx.insert("default_changed", &default_changed);
    ctx.insert("old_default", old_default);
    ctx.insert("new_default", new_default);
    ctx.insert("added", &added);
    ctx.insert("removed", &removed);
    ctx.insert("modified", &modified);
    ctx.insert("added_count", &added.len());
    ctx.insert("removed_count", &removed.len());
    ctx.insert("modified_count", &modified.len());
    ctx.insert("unchanged_count", &unchanged_count);

    let html = tera.render("diff_report.html.tera", &ctx)
        .with_context(|| "Failed to render diff_report.html.tera")?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, html)?;

    Ok(())
}

fn format_port_match(pm: &model::PortMatch) -> String {
    match pm {
        model::PortMatch::Exact(p) => p.to_string(),
        model::PortMatch::Range { range } => format!("{}-{}", range[0], range[1]),
    }
}

fn chrono_timestamp() -> String {
    // Simple timestamp without chrono dependency
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let days = secs / 86400;
            let year = 1970 + (days / 365); // approximate
            let remainder = secs % 86400;
            let hours = remainder / 3600;
            let minutes = (remainder % 3600) / 60;
            format!("{}-{:02}-{:02} {:02}:{:02} UTC",
                year, (days % 365) / 30 + 1, (days % 365) % 30 + 1, hours, minutes)
        }
        Err(_) => "unknown".to_string(),
    }
}

/// Estimate LUTs/FFs for width converters based on data path width.
/// Returns (luts, ffs) for both ingress and egress converters combined.
/// For platform targets with default width (8), includes the inherent 512↔8 converters.
fn width_converter_estimate(width: u16, is_platform: bool) -> (u64, u64) {
    // Platform targets at native 512-bit need no extra converters
    if is_platform && width == 512 {
        return (0, 0);
    }
    // Platform targets with default width still need 512↔8 converters
    if is_platform && width <= 8 {
        // Hardcoded 512↔8: ~80 LUTs + ~1100 FFs (established from Phase 19)
        return (80, 1100);
    }
    // Width 8 standalone means no converters
    if width <= 8 {
        return (0, 0);
    }
    // Converter cost scales with width: wider = more shift register / mux logic
    // Each direction (in + out) costs roughly: LUTs ~= width/8 * 3, FFs ~= width + width/8
    let per_dir_luts = (width as u64 / 8) * 3;
    let per_dir_ffs = width as u64 + (width as u64 / 8);
    // Both directions (ingress wide→8 + egress 8→wide)
    (per_dir_luts * 2, per_dir_ffs * 2)
}

fn compute_resource_estimate(config: &model::FilterConfig) -> serde_json::Value {
    let all_rules = config.all_rules();
    let num_stateless = all_rules.iter().filter(|r| !r.is_stateful()).count();
    let num_stateful = all_rules.iter().filter(|r| r.is_stateful()).count();
    let total = all_rules.len();

    // Check if any rule uses L3/L4 fields (affects parser complexity)
    let has_l3l4 = all_rules.iter().any(|r| r.match_criteria.uses_l3l4());

    // Parser: base L2 + additional for L3/L4 (IPv4 header + TCP/UDP port parsing)
    let parser_luts = if has_l3l4 { 180 } else { 120 };
    let parser_ffs = if has_l3l4 { 160 } else { 90 };

    let mut rule_luts = 0usize;
    let mut rule_ffs = 0usize;

    for rule in all_rules.iter() {
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
            // Protocol extension fields
            if mc.gtp_teid.is_some() { fields += 3; }   // 32-bit comparator
            if mc.mpls_label.is_some() { fields += 2; }  // 20-bit comparator
            if mc.mpls_tc.is_some() { fields += 1; }     // 3-bit comparator
            if mc.mpls_bos.is_some() { fields += 1; }    // 1-bit comparator
            if mc.igmp_type.is_some() { fields += 1; }   // 8-bit comparator
            if mc.mld_type.is_some() { fields += 1; }    // 8-bit comparator
            if mc.ip_dscp.is_some() { fields += 1; }     // 6-bit comparator
            if mc.ip_ecn.is_some() { fields += 1; }      // 2-bit comparator
            if mc.ipv6_dscp.is_some() { fields += 1; }   // 6-bit comparator
            if mc.ipv6_ecn.is_some() { fields += 1; }    // 2-bit comparator
            if mc.tcp_flags.is_some() { fields += 2; }   // 8-bit comparator with mask
            if mc.icmp_type.is_some() { fields += 1; }   // 8-bit comparator
            if mc.icmp_code.is_some() { fields += 1; }   // 8-bit comparator
            if mc.icmpv6_type.is_some() { fields += 1; }   // 8-bit comparator
            if mc.icmpv6_code.is_some() { fields += 1; }   // 8-bit comparator
            if mc.arp_opcode.is_some() { fields += 1; }     // 16-bit comparator
            if mc.arp_spa.is_some() { fields += 2; }        // 32-bit comparator
            if mc.arp_tpa.is_some() { fields += 2; }        // 32-bit comparator
            if mc.ipv6_hop_limit.is_some() { fields += 1; } // 8-bit comparator
            if mc.ipv6_flow_label.is_some() { fields += 2; } // 20-bit comparator
            if mc.outer_vlan_id.is_some() { fields += 1; }    // 12-bit comparator
            if mc.outer_vlan_pcp.is_some() { fields += 1; }   // 3-bit comparator
            if mc.ip_dont_fragment.is_some() { fields += 1; } // 1-bit comparator
            if mc.ip_more_fragments.is_some() { fields += 1; } // 1-bit comparator
            if mc.ip_frag_offset.is_some() { fields += 1; }   // 13-bit comparator
            if mc.gre_protocol.is_some() { fields += 1; }     // 16-bit comparator
            if mc.gre_key.is_some() { fields += 2; }          // 32-bit comparator
            if mc.oam_level.is_some() { fields += 1; }        // 3-bit comparator
            if mc.oam_opcode.is_some() { fields += 1; }       // 8-bit comparator
            if mc.nsh_spi.is_some() { fields += 2; }          // 24-bit comparator
            if mc.nsh_si.is_some() { fields += 1; }           // 8-bit comparator
            if mc.nsh_next_protocol.is_some() { fields += 1; } // 8-bit comparator
            if mc.conntrack_state.is_some() { fields += 1; }  // 1-bit comparator
            if mc.geneve_vni.is_some() { fields += 2; }       // 24-bit comparator
            if mc.ip_ttl.is_some() { fields += 1; }           // 8-bit comparator
            if mc.ptp_message_type.is_some() { fields += 1; } // 4-bit comparator
            if mc.ptp_domain.is_some() { fields += 1; }       // 8-bit comparator
            if mc.ptp_version.is_some() { fields += 1; }      // 4-bit comparator
            rule_luts += 10 + fields * 12;
        }
    }

    // OAM: +8 LUTs per rule with OAM fields (3-bit level + 8-bit opcode comparators)
    let num_oam = all_rules.iter().filter(|r| r.match_criteria.uses_oam()).count();
    if num_oam > 0 {
        rule_luts += num_oam * 8;
    }

    // NSH: +8 LUTs per rule with NSH fields (24-bit SPI + 8-bit SI + 8-bit next_protocol comparators)
    let num_nsh = all_rules.iter().filter(|r| r.match_criteria.uses_nsh()).count();
    if num_nsh > 0 {
        rule_luts += num_nsh * 8;
    }

    // PTP: +30 LUTs per rule with PTP fields (4-bit msgType + 8-bit domain + 4-bit version comparators)
    let num_ptp = all_rules.iter().filter(|r| r.match_criteria.uses_ptp()).count();
    if num_ptp > 0 {
        rule_luts += num_ptp * 6;
    }

    // Egress LUT: +4 LUTs per rule with mirror/redirect (8-bit port + valid per action)
    let egress_rules = all_rules.iter()
        .filter(|r| r.mirror_port.is_some() || r.redirect_port.is_some())
        .count();
    if egress_rules > 0 {
        rule_luts += egress_rules * 4;
    }

    // Pipeline registers: +16 FFs per stage for inter-stage pipeline registers
    let pipeline_ffs = if config.is_pipeline() { (config.stage_count() - 1) * 16 } else { 0 };

    // Rate limiter: +50 LUTs, +64 FFs per rate-limited rule
    let num_rate_limited = all_rules.iter().filter(|r| r.rate_limit.is_some()).count();
    let rate_luts = num_rate_limited * 50;
    let rate_ffs = num_rate_limited * 64;

    // Rewrite engine: ~50 LUTs + ~100 FFs (fixed) + ~20 LUTs per rewrite rule (LUT entries)
    let num_rewrite = all_rules.iter().filter(|r| r.has_rewrite()).count();
    let rewrite_luts = if num_rewrite > 0 { 50 + num_rewrite * 20 } else { 0 };
    let rewrite_ffs = if num_rewrite > 0 { 100 } else { 0 };

    // Flow counters: +128 LUTs per conntrack entry (64-bit pkt + 64-bit byte counters)
    let has_flow_counters = model::StatelessRule::has_flow_counters(&config.pacgate);
    let conntrack_entries = config.pacgate.conntrack.as_ref().map(|c| c.table_size).unwrap_or(0) as usize;
    let flow_counter_luts = if has_flow_counters { conntrack_entries * 128 } else { 0 };
    let flow_counter_ffs = if has_flow_counters { conntrack_entries * 128 } else { 0 };

    let decision_luts = 10 * total + 8;
    let decision_ffs = 4;
    let io_luts = 20;
    let total_luts = parser_luts + rule_luts + decision_luts + io_luts + rate_luts + rewrite_luts + flow_counter_luts;
    let total_ffs = parser_ffs + rule_ffs + decision_ffs + rate_ffs + rewrite_ffs + flow_counter_ffs + pipeline_ffs;

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
            "rewrite_engine": { "count": num_rewrite, "luts": rewrite_luts, "ffs": rewrite_ffs },
            "flow_counters": { "enabled": has_flow_counters, "entries": conntrack_entries, "luts": flow_counter_luts, "ffs": flow_counter_ffs },
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
            // Protocol extension fields
            if mc.gtp_teid.is_some() { fields += 3; }
            if mc.mpls_label.is_some() { fields += 2; }
            if mc.mpls_tc.is_some() { fields += 1; }
            if mc.mpls_bos.is_some() { fields += 1; }
            if mc.igmp_type.is_some() { fields += 1; }
            if mc.mld_type.is_some() { fields += 1; }
            if mc.ip_dscp.is_some() { fields += 1; }
            if mc.ip_ecn.is_some() { fields += 1; }
            if mc.ipv6_dscp.is_some() { fields += 1; }
            if mc.ipv6_ecn.is_some() { fields += 1; }
            if mc.tcp_flags.is_some() { fields += 2; }
            if mc.icmp_type.is_some() { fields += 1; }
            if mc.icmp_code.is_some() { fields += 1; }
            if mc.icmpv6_type.is_some() { fields += 1; }
            if mc.icmpv6_code.is_some() { fields += 1; }
            if mc.arp_opcode.is_some() { fields += 1; }
            if mc.arp_spa.is_some() { fields += 2; }
            if mc.arp_tpa.is_some() { fields += 2; }
            if mc.ipv6_hop_limit.is_some() { fields += 1; }
            if mc.ipv6_flow_label.is_some() { fields += 2; }
            if mc.outer_vlan_id.is_some() { fields += 1; }
            if mc.outer_vlan_pcp.is_some() { fields += 1; }
            if mc.ip_dont_fragment.is_some() { fields += 1; }
            if mc.ip_more_fragments.is_some() { fields += 1; }
            if mc.ip_frag_offset.is_some() { fields += 1; }
            if mc.gre_protocol.is_some() { fields += 1; }
            if mc.gre_key.is_some() { fields += 2; }
            if mc.oam_level.is_some() { fields += 1; }
            if mc.oam_opcode.is_some() { fields += 1; }
            if mc.nsh_spi.is_some() { fields += 2; }
            if mc.nsh_si.is_some() { fields += 1; }
            if mc.nsh_next_protocol.is_some() { fields += 1; }
            if mc.conntrack_state.is_some() { fields += 1; }
            if mc.geneve_vni.is_some() { fields += 2; }       // 24-bit comparator
            if mc.ip_ttl.is_some() { fields += 1; }           // 8-bit comparator
            if mc.ptp_message_type.is_some() { fields += 1; } // 4-bit comparator
            if mc.ptp_domain.is_some() { fields += 1; }       // 8-bit comparator
            if mc.ptp_version.is_some() { fields += 1; }      // 4-bit comparator
            rule_luts += 10 + fields * 12;
        }
    }

    // OAM: +8 LUTs per rule with OAM fields (3-bit level + 8-bit opcode comparators)
    let num_oam = rules.iter().filter(|r| r.match_criteria.uses_oam()).count();
    if num_oam > 0 {
        rule_luts += num_oam * 8;
    }

    // NSH: +8 LUTs per rule with NSH fields (24-bit SPI + 8-bit SI + 8-bit next_protocol comparators)
    let num_nsh = rules.iter().filter(|r| r.match_criteria.uses_nsh()).count();
    if num_nsh > 0 {
        rule_luts += num_nsh * 8;
    }

    // PTP: +6 LUTs per rule with PTP fields (4-bit msgType + 8-bit domain + 4-bit version comparators)
    let num_ptp = rules.iter().filter(|r| r.match_criteria.uses_ptp()).count();
    if num_ptp > 0 {
        rule_luts += num_ptp * 6;
    }

    // Rate limiter: +50 LUTs, +64 FFs per rate-limited rule
    let num_rate_limited = rules.iter().filter(|r| r.rate_limit.is_some()).count();
    let rate_luts = num_rate_limited * 50;
    let rate_ffs = num_rate_limited * 64;

    // Rewrite engine: ~50 LUTs + ~100 FFs (fixed) + ~20 LUTs per rewrite rule (LUT entries)
    // Port rewrite adds ~30 LUTs for L4 checksum update
    let num_rewrite = rules.iter().filter(|r| r.has_rewrite()).count();
    let has_port_rewrite = rules.iter().any(|r| {
        r.rewrite.as_ref().map(|rw| rw.set_src_port.is_some() || rw.set_dst_port.is_some()).unwrap_or(false)
    });
    let rewrite_luts = if num_rewrite > 0 { 50 + num_rewrite * 20 + if has_port_rewrite { 30 } else { 0 } } else { 0 };
    let rewrite_ffs = if num_rewrite > 0 { 100 + if has_port_rewrite { 32 } else { 0 } } else { 0 };

    // Flow counters: +128 LUTs per conntrack entry (64-bit pkt + 64-bit byte counters)
    let has_flow_counters = model::StatelessRule::has_flow_counters(&config.pacgate);
    let conntrack_entries = config.pacgate.conntrack.as_ref().map(|c| c.table_size).unwrap_or(0) as usize;
    let flow_counter_luts = if has_flow_counters { conntrack_entries * 128 } else { 0 };
    let flow_counter_ffs = if has_flow_counters { conntrack_entries * 128 } else { 0 };

    let decision_luts = 10 * total + 8;
    let decision_ffs = 4;
    let io_luts = 20;

    let total_luts = parser_luts + rule_luts + decision_luts + io_luts + rate_luts + rewrite_luts + flow_counter_luts;
    let total_ffs = parser_ffs + rule_ffs + decision_ffs + rate_ffs + rewrite_ffs + flow_counter_ffs;

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
    if num_rewrite > 0 {
        println!("  Rewrite rules: {}", num_rewrite);
    }
    if has_flow_counters {
        println!("  Flow counters: enabled ({} entries)", conntrack_entries);
    }
    println!();
    println!("  Component             Est. LUTs   Est. FFs");
    println!("  ───────────────────── ────────── ─────────");
    println!("  Frame parser              {:>5}     {:>5}", parser_luts, parser_ffs);
    println!("  Rule matchers             {:>5}     {:>5}", rule_luts, rule_ffs);
    if num_rate_limited > 0 {
        println!("  Rate limiters             {:>5}     {:>5}", rate_luts, rate_ffs);
    }
    if num_rewrite > 0 {
        println!("  Rewrite engine            {:>5}     {:>5}", rewrite_luts, rewrite_ffs);
    }
    if has_flow_counters {
        println!("  Flow counters             {:>5}     {:>5}", flow_counter_luts, flow_counter_ffs);
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

fn compute_dynamic_estimate(num_entries: u16) -> serde_json::Value {
    let n = num_entries as usize;
    // Per-entry: ~30 LUTs (comparators) + ~295 FFs (registers for all fields)
    let entry_luts = n * 30;
    let entry_ffs = n * 295;
    // AXI-Lite interface: ~100 LUTs + ~50 FFs
    let axil_luts = 100;
    let axil_ffs = 50;
    // Priority encoder: ~10*N LUTs
    let priority_luts = n * 10;
    // Frame parser (same as static)
    let parser_luts = 180;
    let parser_ffs = 160;

    let total_luts = parser_luts + entry_luts + priority_luts + axil_luts;
    let total_ffs = parser_ffs + entry_ffs + axil_ffs;

    serde_json::json!({
        "mode": "dynamic",
        "num_entries": n,
        "components": {
            "frame_parser": { "luts": parser_luts, "ffs": parser_ffs },
            "flow_table_entries": { "luts": entry_luts, "ffs": entry_ffs },
            "priority_encoder": { "luts": priority_luts, "ffs": 0 },
            "axi_lite_interface": { "luts": axil_luts, "ffs": axil_ffs },
        },
        "total": { "luts": total_luts, "ffs": total_ffs },
        "utilization": {
            "xc7a35t": {
                "lut_percent": format!("{:.1}", total_luts as f64 / 20800.0 * 100.0),
                "ff_percent": format!("{:.1}", total_ffs as f64 / 41600.0 * 100.0),
            },
        },
        "note": "Dynamic mode uses significantly more FFs due to register-based entry storage"
    })
}

fn print_dynamic_estimate(num_entries: u16) {
    let n = num_entries as usize;
    let entry_luts = n * 30;
    let entry_ffs = n * 295;
    let axil_luts = 100;
    let axil_ffs = 50;
    let priority_luts = n * 10;
    let parser_luts = 180;
    let parser_ffs = 160;
    let total_luts = parser_luts + entry_luts + priority_luts + axil_luts;
    let total_ffs = parser_ffs + entry_ffs + axil_ffs;

    println!();
    println!("  PacGate Resource Estimate (Dynamic Flow Table)");
    println!("  ════════════════════════════════════════════");
    println!("  Flow table entries: {}", n);
    println!();
    println!("  Component             Est. LUTs   Est. FFs");
    println!("  ───────────────────── ────────── ─────────");
    println!("  Frame parser              {:>5}     {:>5}", parser_luts, parser_ffs);
    println!("  Flow table entries        {:>5}     {:>5}", entry_luts, entry_ffs);
    println!("  Priority encoder          {:>5}         -", priority_luts);
    println!("  AXI-Lite interface        {:>5}     {:>5}", axil_luts, axil_ffs);
    println!("  ───────────────────── ────────── ─────────");
    println!("  TOTAL                     {:>5}     {:>5}", total_luts, total_ffs);
    println!();
    println!("  Artix-7 XC7A35T:  {:.1}% LUTs, {:.1}% FFs",
        total_luts as f64 / 20800.0 * 100.0,
        total_ffs as f64 / 41600.0 * 100.0);
    println!();
    println!("  Note: Dynamic mode uses significantly more FFs than static");
    println!("  due to register-based entry storage (~295 FFs per entry).");
    if n > 64 {
        println!("  WARNING: {} entries is resource-heavy. Consider reducing.", n);
    }
    println!();
}

fn lint_rules(config: &model::FilterConfig, warnings: &[String], dynamic: bool, dynamic_entries: u16, platform: &verilog_gen::PlatformTarget, width: u16) -> serde_json::Value {
    let all_rules = config.all_rules();
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

    // Check 13: GTP-U without UDP prerequisite
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        if rule.match_criteria.gtp_teid.is_some() {
            let has_udp = rule.match_criteria.ip_protocol == Some(17);
            let has_gtp_port = matches!(
                rule.match_criteria.dst_port,
                Some(model::PortMatch::Exact(2152))
            );
            if !has_udp || !has_gtp_port {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT013",
                    "message": format!("Rule '{}' uses gtp_teid but missing UDP prerequisite (ip_protocol:17 and dst_port:2152)",
                        rule.name),
                    "suggestion": "Add ip_protocol: 17 and dst_port: 2152 to ensure GTP-U packets are correctly identified"
                }));
            }
        }
    }

    // Check 14: MPLS without MPLS EtherType
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        if rule.match_criteria.uses_mpls() {
            let et = rule.match_criteria.ethertype.as_deref();
            if et != Some("0x8847") && et != Some("0x8848") {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT014",
                    "message": format!("Rule '{}' uses MPLS fields but missing MPLS EtherType (0x8847 or 0x8848)",
                        rule.name),
                    "suggestion": "Add ethertype: \"0x8847\" (unicast) or \"0x8848\" (multicast) to ensure MPLS parsing"
                }));
            }
        }
    }

    // Check 15: IGMP/MLD without protocol prerequisite
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        if rule.match_criteria.igmp_type.is_some() && rule.match_criteria.ip_protocol != Some(2) {
            findings.push(serde_json::json!({
                "level": "warning",
                "code": "LINT015",
                "message": format!("Rule '{}' uses igmp_type but missing ip_protocol: 2 prerequisite",
                    rule.name),
                "suggestion": "Add ip_protocol: 2 to ensure IGMP packets are correctly identified"
            }));
        }
        if rule.match_criteria.mld_type.is_some() && rule.match_criteria.ipv6_next_header != Some(58) {
            findings.push(serde_json::json!({
                "level": "warning",
                "code": "LINT015",
                "message": format!("Rule '{}' uses mld_type but missing ipv6_next_header: 58 prerequisite",
                    rule.name),
                "suggestion": "Add ipv6_next_header: 58 to ensure MLD (ICMPv6) packets are correctly identified"
            }));
        }
    }

    // Check 18: Rewrite rules present — warn that --axi is required for actual modification
    let has_rewrite = rules.iter().any(|r| r.has_rewrite());
    if has_rewrite {
        findings.push(serde_json::json!({
            "level": "warning",
            "code": "LINT018",
            "message": "Rules contain rewrite actions — ensure --axi flag is used during compilation for packet modification",
            "suggestion": "Without --axi, rewrite_lut is generated but packet_rewrite engine is not instantiated"
        }));
    }

    // Check 19: Rewrite with IP/TTL fields — informational about checksum
    let has_ip_rewrite = rules.iter().any(|r| {
        if let Some(ref rw) = r.rewrite {
            rw.set_src_ip.is_some() || rw.set_dst_ip.is_some() || rw.set_ttl.is_some() || rw.dec_ttl == Some(true)
        } else {
            false
        }
    });
    if has_ip_rewrite {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT019",
            "message": "Rewrite rules modify IP header fields — IP checksum will be incrementally updated (RFC 1624)",
            "suggestion": "No action needed; packet_rewrite engine handles checksum correction automatically"
        }));
    }

    // Check 16: Dynamic mode with large entry count
    if dynamic && dynamic_entries > 64 {
        findings.push(serde_json::json!({
            "level": "warning",
            "code": "LINT016",
            "message": format!("Dynamic flow table with {} entries — high FPGA resource usage (~{} FFs for entry registers)",
                dynamic_entries, dynamic_entries as usize * 295),
            "suggestion": "Consider reducing --dynamic-entries to 64 or fewer for Artix-7 targets"
        }));
    }

    // Check 17: Dynamic mode V1 field limitations reminder
    if dynamic {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT017",
            "message": "Dynamic flow table V1: supports L2/L3/L4 fields only (ethertype, MAC, IP, ports, VLAN)",
            "suggestion": "IPv6, GTP-U, MPLS, IGMP/MLD, byte_match, and VXLAN VNI are not yet supported in dynamic mode"
        }));
    }

    // Check 20: Platform target throughput limitation
    if platform.is_platform() {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT020",
            "message": format!("Platform target '{}': V1 uses 512<->8 width converters limiting throughput to ~2 Gbps at 250MHz", platform.name()),
            "suggestion": "Suitable for 1GbE, development, and prototyping; wide pipeline deferred to future version"
        }));
    }

    // Check 21: Platform target implicitly enables AXI
    if platform.is_platform() {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT021",
            "message": format!("Platform target '{}' implicitly enables AXI-Stream mode", platform.name()),
            "suggestion": "No action needed; --axi is automatically enabled for platform targets"
        }));
    }

    // Check 22: DSCP/ECN without IPv4 ethertype prerequisite
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_dscp_ecn() {
            let has_ipv4 = rule.match_criteria.ethertype.as_ref()
                .map(|et| model::parse_ethertype(et).ok() == Some(0x0800))
                .unwrap_or(false);
            if !has_ipv4 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT022",
                    "message": format!("Rule '{}' uses ip_dscp/ip_ecn without ethertype: 0x0800 — may match non-IPv4 traffic", rule.name),
                    "suggestion": "Add 'ethertype: \"0x0800\"' to ensure DSCP/ECN matching is only applied to IPv4 packets"
                }));
            }
        }
    }

    // Check 23: IPv6 DSCP/ECN without IPv6 ethertype prerequisite
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_ipv6_tc() {
            let has_ipv6 = rule.match_criteria.ethertype.as_ref()
                .map(|et| model::parse_ethertype(et).ok() == Some(0x86DD))
                .unwrap_or(false);
            if !has_ipv6 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT023",
                    "message": format!("Rule '{}' uses ipv6_dscp/ipv6_ecn without ethertype: 0x86DD — may match non-IPv6 traffic", rule.name),
                    "suggestion": "Add 'ethertype: \"0x86DD\"' to ensure IPv6 TC matching is only applied to IPv6 packets"
                }));
            }
        }
    }

    // Check 24: TCP flags without ip_protocol 6 prerequisite
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_tcp_flags() {
            let has_tcp = rule.match_criteria.ip_protocol == Some(6);
            if !has_tcp {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT024",
                    "message": format!("Rule '{}' uses tcp_flags without ip_protocol: 6 — may match non-TCP traffic", rule.name),
                    "suggestion": "Add 'ip_protocol: 6' to ensure TCP flags matching is only applied to TCP packets"
                }));
            }
        }
    }

    // Check 25: ICMP type/code without ip_protocol 1 prerequisite
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_icmp() {
            let has_icmp = rule.match_criteria.ip_protocol == Some(1);
            if !has_icmp {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT025",
                    "message": format!("Rule '{}' uses icmp_type/icmp_code without ip_protocol: 1 — may match non-ICMP traffic", rule.name),
                    "suggestion": "Add 'ip_protocol: 1' to ensure ICMP matching is only applied to ICMP packets"
                }));
            }
        }
    }

    // LINT026: ICMPv6 without IPv6 ethertype or next_header 58
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_icmpv6() {
            let has_ipv6 = rule.match_criteria.ethertype.as_deref() == Some("0x86DD");
            let has_nh58 = rule.match_criteria.ipv6_next_header == Some(58);
            if !has_ipv6 && !has_nh58 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT026",
                    "message": format!("Rule '{}' uses icmpv6_type/icmpv6_code without ethertype: 0x86DD or ipv6_next_header: 58 — may match non-ICMPv6 traffic", rule.name),
                    "suggestion": "Add 'ethertype: \"0x86DD\"' and 'ipv6_next_header: 58' to ensure ICMPv6 matching is only applied to ICMPv6 packets"
                }));
            }
        }
    }

    // LINT027: ARP without ethertype 0x0806
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_arp() {
            let has_arp_etype = rule.match_criteria.ethertype.as_deref() == Some("0x0806");
            if !has_arp_etype {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT027",
                    "message": format!("Rule '{}' uses arp_opcode/arp_spa/arp_tpa without ethertype: 0x0806 — may match non-ARP traffic", rule.name),
                    "suggestion": "Add 'ethertype: \"0x0806\"' to ensure ARP matching is only applied to ARP packets"
                }));
            }
        }
    }

    // LINT028: IPv6 extension fields without IPv6 ethertype
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_ipv6_ext() {
            let has_ipv6 = rule.match_criteria.ethertype.as_deref() == Some("0x86DD");
            if !has_ipv6 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT028",
                    "message": format!("Rule '{}' uses ipv6_hop_limit/ipv6_flow_label without ethertype: 0x86DD — may match non-IPv6 traffic", rule.name),
                    "suggestion": "Add 'ethertype: \"0x86DD\"' to ensure IPv6 extension field matching is only applied to IPv6 packets"
                }));
            }
        }
    }

    // LINT029: QinQ fields without QinQ ethertype
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_qinq() {
            let has_qinq = matches!(rule.match_criteria.ethertype.as_deref(), Some("0x88A8") | Some("0x9100"));
            if !has_qinq {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT029",
                    "message": format!("Rule '{}' uses outer_vlan_id/outer_vlan_pcp without ethertype: 0x88A8 or 0x9100 — may never match", rule.name),
                    "suggestion": "Add 'ethertype: \"0x88A8\"' for 802.1ad QinQ matching"
                }));
            }
        }
    }

    // LINT030: IP fragmentation fields without IPv4 ethertype
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_ip_frag() {
            let has_ipv4 = rule.match_criteria.ethertype.as_deref() == Some("0x0800");
            if !has_ipv4 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT030",
                    "message": format!("Rule '{}' uses ip_dont_fragment/ip_more_fragments/ip_frag_offset without ethertype: 0x0800 — fragmentation is IPv4-only", rule.name),
                    "suggestion": "Add 'ethertype: \"0x0800\"' to ensure fragmentation matching only applies to IPv4 packets"
                }));
            }
        }
    }

    // LINT031: Port rewrite requires --axi
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.set_src_port.is_some() || rw.set_dst_port.is_some() {
                findings.push(serde_json::json!({
                    "level": "info",
                    "code": "LINT031",
                    "message": format!("Rule '{}' uses set_src_port/set_dst_port — requires --axi flag for rewrite engine", rule.name),
                    "suggestion": "Compile with 'pacgate compile rules.yaml --axi' to enable the rewrite pipeline"
                }));
            }
        }
    }

    // LINT032: Port rewrite L4 checksum update
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.set_src_port.is_some() || rw.set_dst_port.is_some() {
                findings.push(serde_json::json!({
                    "level": "info",
                    "code": "LINT032",
                    "message": format!("Rule '{}' port rewrite will apply RFC 1624 incremental L4 checksum update (UDP checksum=0 preserved)", rule.name),
                    "suggestion": "No action needed — L4 checksum is automatically updated by the rewrite engine"
                }));
                break; // Only report once
            }
        }
    }

    // LINT033: GRE fields without ip_protocol=47
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_gre() {
            let has_gre_proto = rule.match_criteria.ip_protocol == Some(47);
            if !has_gre_proto {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT033",
                    "message": format!("Rule '{}' uses gre_protocol/gre_key without ip_protocol: 47 — GRE requires IP protocol 47", rule.name),
                    "suggestion": "Add 'ip_protocol: 47' to ensure GRE matching only applies to GRE-encapsulated packets"
                }));
            }
        }
    }

    // LINT034: conntrack_state without stateful context
    for rule in &config.pacgate.rules {
        if rule.match_criteria.conntrack_state.is_some() {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT034",
                "rule": rule.name,
                "message": format!("Rule '{}' uses conntrack_state — requires --conntrack flag at compile time for RTL support", rule.name),
                "suggestion": "Use --conntrack flag when compiling to enable connection tracking hardware"
            }));
        }
    }

    // LINT035: redirect_port with action: drop (shouldn't happen due to validation, but check anyway)
    for rule in &config.pacgate.rules {
        if rule.redirect_port.is_some() && rule.action == Some(model::Action::Drop) {
            findings.push(serde_json::json!({
                "level": "warning",
                "code": "LINT035",
                "rule": rule.name,
                "message": format!("Rule '{}' has redirect_port but action is drop — redirect will not take effect", rule.name),
            }));
        }
    }

    // LINT036: mirror_port or redirect_port require --ports or multiport context (info)
    for rule in &config.pacgate.rules {
        if rule.mirror_port.is_some() || rule.redirect_port.is_some() {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT036",
                "rule": rule.name,
                "message": format!("Rule '{}' uses egress port actions (mirror/redirect) — requires multi-port or platform target for full functionality", rule.name),
                "suggestion": "Use --ports N for multi-port deployment to enable cross-port egress actions"
            }));
        }
    }

    // LINT038: OAM fields without ethertype 0x8902
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_oam() {
            let has_oam_ethertype = rule.match_criteria.ethertype.as_ref()
                .map(|et| et == "0x8902" || et == "0x8902")
                .unwrap_or(false);
            if !has_oam_ethertype {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT038",
                    "message": format!("Rule '{}' uses oam_level/oam_opcode without ethertype: 0x8902 — OAM/CFM requires EtherType 0x8902", rule.name),
                    "suggestion": "Add 'ethertype: \"0x8902\"' to ensure OAM matching only applies to CFM/Y.1731 frames"
                }));
            }
        }
    }

    // LINT039: NSH fields without ethertype 0x894F
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_nsh() {
            let has_nsh_ethertype = rule.match_criteria.ethertype.as_ref()
                .map(|et| et == "0x894F" || et == "0x894f")
                .unwrap_or(false);
            if !has_nsh_ethertype {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT039",
                    "message": format!("Rule '{}' uses nsh_spi/nsh_si/nsh_next_protocol without ethertype: 0x894F — NSH requires EtherType 0x894F", rule.name),
                    "suggestion": "Add 'ethertype: \"0x894F\"' to ensure NSH matching only applies to NSH (RFC 8300) frames"
                }));
            }
        }
    }

    // LINT040: Geneve VNI without IPv4/UDP ethertype
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_geneve() {
            let has_ipv4 = rule.match_criteria.ethertype.as_deref() == Some("0x0800");
            let has_udp = rule.match_criteria.ip_protocol == Some(17);
            if !has_ipv4 || !has_udp {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT040",
                    "message": format!("Rule '{}' uses geneve_vni without ethertype: 0x0800 + ip_protocol: 17 — Geneve requires IPv4/UDP", rule.name),
                    "suggestion": "Add 'ethertype: \"0x0800\"' and 'ip_protocol: 17' to ensure Geneve matching only applies to Geneve (RFC 8926) frames"
                }));
            }
        }
    }

    // LINT041: ip_ttl without IPv4 ethertype
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_ip_ttl() {
            let has_ipv4 = rule.match_criteria.ethertype.as_deref() == Some("0x0800");
            if !has_ipv4 {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT041",
                    "message": format!("Rule '{}' uses ip_ttl without ethertype: 0x0800 — ip_ttl requires IPv4", rule.name),
                    "suggestion": "Add 'ethertype: \"0x0800\"' to ensure ip_ttl matching only applies to IPv4 packets"
                }));
            }
        }
    }

    // LINT042: frame_len is simulation-only (info)
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_frame_len() {
            findings.push(serde_json::json!({
                "level": "info",
                "code": "LINT042",
                "message": format!("Rule '{}' uses frame_len_min/frame_len_max — simulation-only, not synthesized to hardware", rule.name),
                "suggestion": "frame_len matching is evaluated in software simulation only; no RTL is generated for this field"
            }));
        }
    }

    // LINT043: dec_hop_limit/set_hop_limit without IPv6 ethertype
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.dec_hop_limit == Some(true) || rw.set_hop_limit.is_some() {
                let has_ipv6 = rule.match_criteria.ethertype.as_deref() == Some("0x86DD");
                if !has_ipv6 {
                    findings.push(serde_json::json!({
                        "level": "warning",
                        "code": "LINT043",
                        "message": format!("Rule '{}' uses dec_hop_limit/set_hop_limit without ethertype: 0x86DD — requires IPv6", rule.name),
                        "suggestion": "Add 'ethertype: \"0x86DD\"' to ensure hop limit rewrite only applies to IPv6 packets"
                    }));
                }
            }
        }
    }

    // LINT044: set_ecn without IPv4/IPv6 (info)
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.set_ecn.is_some() {
                let has_ip = rule.match_criteria.ethertype.as_deref() == Some("0x0800")
                    || rule.match_criteria.ethertype.as_deref() == Some("0x86DD");
                if !has_ip {
                    findings.push(serde_json::json!({
                        "level": "info",
                        "code": "LINT044",
                        "message": format!("Rule '{}' uses set_ecn without ethertype 0x0800/0x86DD — ECN requires IP header", rule.name),
                        "suggestion": "Add 'ethertype: \"0x0800\"' or 'ethertype: \"0x86DD\"' to ensure ECN rewrite only applies to IP packets"
                    }));
                }
            }
        }
    }

    // LINT045: set_vlan_pcp without VLAN
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.set_vlan_pcp.is_some() {
                let has_vlan = rule.match_criteria.vlan_id.is_some()
                    || rule.match_criteria.ethertype.as_deref() == Some("0x8100");
                if !has_vlan {
                    findings.push(serde_json::json!({
                        "level": "warning",
                        "code": "LINT045",
                        "message": format!("Rule '{}' uses set_vlan_pcp without vlan_id or ethertype 0x8100 — requires VLAN-tagged frame", rule.name),
                        "suggestion": "Add 'vlan_id' match or 'ethertype: \"0x8100\"' to ensure VLAN PCP rewrite only applies to 802.1Q frames"
                    }));
                }
            }
        }
    }

    // LINT046: set_outer_vlan_id without QinQ
    for rule in &config.pacgate.rules {
        if let Some(ref rw) = rule.rewrite {
            if rw.set_outer_vlan_id.is_some() {
                let has_qinq = rule.match_criteria.outer_vlan_id.is_some()
                    || rule.match_criteria.ethertype.as_deref() == Some("0x88A8")
                    || rule.match_criteria.ethertype.as_deref() == Some("0x9100");
                if !has_qinq {
                    findings.push(serde_json::json!({
                        "level": "warning",
                        "code": "LINT046",
                        "message": format!("Rule '{}' uses set_outer_vlan_id without QinQ ethertype — requires 802.1ad double-tagged frame", rule.name),
                        "suggestion": "Add 'outer_vlan_id' match or 'ethertype: \"0x88A8\"' to ensure outer VLAN rewrite only applies to QinQ frames"
                    }));
                }
            }
        }
    }

    // LINT051: PTP fields without appropriate transport (EtherType 0x88F7 or UDP 319/320)
    for rule in &config.pacgate.rules {
        if rule.match_criteria.uses_ptp() {
            let has_ptp_ethertype = rule.match_criteria.ethertype.as_deref() == Some("0x88F7");
            let has_udp = rule.match_criteria.ip_protocol == Some(17);
            let has_ptp_port = match &rule.match_criteria.dst_port {
                Some(model::PortMatch::Exact(p)) => *p == 319 || *p == 320,
                _ => false,
            };
            if !has_ptp_ethertype && !(has_udp && has_ptp_port) {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT051",
                    "message": format!("Rule '{}' uses PTP fields without EtherType 0x88F7 or UDP dst_port 319/320 — PTP requires L2 or L4 transport", rule.name),
                    "suggestion": "Add 'ethertype: \"0x88F7\"' for L2 PTP or 'ip_protocol: 17' + 'dst_port: 319' for L4 PTP"
                }));
            }
        }
    }

    // LINT052: ptp_message_type > 13 (undefined PTP message types)
    for rule in &config.pacgate.rules {
        if let Some(mt) = rule.match_criteria.ptp_message_type {
            if mt > 13 {
                findings.push(serde_json::json!({
                    "level": "info",
                    "code": "LINT052",
                    "message": format!("Rule '{}' uses ptp_message_type {} — values 14-15 are undefined in IEEE 1588", rule.name, mt),
                    "suggestion": "Common PTP message types: 0=Sync, 1=Delay_Req, 8=Follow_Up, 9=Delay_Resp, 11=Announce"
                }));
            }
        }
    }

    // LINT037: enable_flow_counters requires --conntrack
    if config.pacgate.conntrack.as_ref()
        .and_then(|c| c.enable_flow_counters)
        .unwrap_or(false)
    {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT037",
            "message": "enable_flow_counters is enabled — requires --conntrack flag at compile time for per-flow counter hardware",
            "suggestion": "Use --conntrack flag when compiling to enable connection tracking with per-flow counters"
        }));
    }

    // LINT047: --width > 8 without --axi (width converters require AXI wrapper)
    if width > 8 {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT047",
            "message": format!("Data path width set to {}-bit — width converters will be instantiated at AXI boundary", width),
            "suggestion": "Ensure --axi flag is used when compiling (width converters are part of the AXI pipeline)"
        }));
    }

    // LINT048: --width 512 with standalone target
    if width == 512 && !platform.is_platform() {
        findings.push(serde_json::json!({
            "level": "info",
            "code": "LINT048",
            "message": "512-bit data path typically requires a platform NIC (OpenNIC/Corundum) with native 512-bit AXI-Stream",
            "suggestion": "Consider --target opennic or --target corundum for 512-bit deployment"
        }));
    }

    // LINT049: Pipeline stage with no rules
    if let Some(tables) = &config.pacgate.tables {
        for stage in tables {
            if stage.rules.is_empty() {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT049",
                    "message": format!("Pipeline stage '{}' has no rules — will always use default action ({})",
                        stage.name, match stage.default_action { model::Action::Pass => "pass", model::Action::Drop => "drop" }),
                    "suggestion": "Add rules to this stage or remove it from the pipeline"
                }));
            }
        }
    }

    // LINT050: Unreachable pipeline stage (not referenced by any next_table and not first)
    if let Some(tables) = &config.pacgate.tables {
        let referenced: std::collections::HashSet<&str> = tables.iter()
            .filter_map(|s| s.next_table.as_deref())
            .collect();
        for (idx, stage) in tables.iter().enumerate() {
            if idx > 0 && !referenced.contains(stage.name.as_str()) {
                findings.push(serde_json::json!({
                    "level": "warning",
                    "code": "LINT050",
                    "message": format!("Pipeline stage '{}' is not referenced by any next_table — may be unreachable", stage.name),
                    "suggestion": "Add a next_table reference from a preceding stage or remove this stage"
                }));
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
        "total_rules": all_rules.len(),
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
