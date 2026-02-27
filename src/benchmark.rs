use std::path::Path;
use std::time::Instant;
use anyhow::Result;
use serde::Serialize;

use crate::model::{FilterConfig, PacgateConfig, Defaults, Action, StatelessRule, MatchCriteria, PortMatch};
use crate::simulator::{self, SimPacket};

/// Benchmark report
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    /// Compile time for the input config
    pub compile_time_ms: f64,
    /// Simulation throughput (packets/sec)
    pub sim_throughput_pps: f64,
    /// Number of packets simulated
    pub sim_packet_count: usize,
    /// Resource estimate for input config
    pub input_luts: usize,
    pub input_ffs: usize,
    pub input_rules: usize,
    /// Scaling data points: (rule_count, luts, ffs, compile_ms)
    pub scaling: Vec<ScalingPoint>,
}

/// A single scaling data point
#[derive(Debug, Clone, Serialize)]
pub struct ScalingPoint {
    pub rule_count: usize,
    pub luts: usize,
    pub ffs: usize,
    pub compile_time_ms: f64,
}

/// Generate a synthetic FilterConfig with N stateless rules
fn synthetic_config(num_rules: usize) -> FilterConfig {
    let mut rules = Vec::new();
    for i in 0..num_rules {
        let octet3 = ((i / 256) % 256) as u8;
        let octet4 = (i % 256) as u8;
        rules.push(StatelessRule {
            name: format!("rule_{}", i),
            priority: (num_rules - i) as u32,
            match_criteria: MatchCriteria {
                ethertype: Some("0x0800".to_string()),
                ip_protocol: Some(6),
                dst_ip: Some(format!("10.{}.{}.0/24", octet3, octet4)),
                dst_port: Some(PortMatch::Exact(80 + (i as u16 % 1000))),
                ..Default::default()
            },
            action: Some(if i % 2 == 0 { Action::Pass } else { Action::Drop }),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
        });
    }
    FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: Action::Drop },
            rules,
            conntrack: None,
        },
    }
}

/// Estimate resources for a config (simplified version for benchmark)
fn estimate_resources(config: &FilterConfig) -> (usize, usize) {
    let rules = &config.pacgate.rules;
    let has_l3l4 = rules.iter().any(|r| r.match_criteria.uses_l3l4());
    let parser_luts = if has_l3l4 { 180 } else { 120 };
    let parser_ffs = if has_l3l4 { 160 } else { 90 };

    let mut rule_luts = 0usize;
    let mut rule_ffs = 0usize;

    for rule in rules {
        if rule.is_stateful() {
            let fsm = rule.fsm.as_ref().unwrap();
            let num_transitions: usize = fsm.states.values().map(|s| s.transitions.len()).sum();
            let has_timeout = fsm.states.values().any(|s| s.timeout_cycles.is_some());
            rule_luts += 40 + num_transitions * 30 + if has_timeout { 40 } else { 0 };
            rule_ffs += 4 + fsm.states.len() * 2 + if has_timeout { 32 } else { 0 };
        } else {
            let mc = &rule.match_criteria;
            let mut fields = 0;
            if mc.ethertype.is_some() { fields += 1; }
            if mc.dst_mac.is_some() { fields += 3; }
            if mc.src_mac.is_some() { fields += 3; }
            if mc.vlan_id.is_some() { fields += 1; }
            if mc.vlan_pcp.is_some() { fields += 1; }
            if mc.src_ip.is_some() { fields += 2; }
            if mc.dst_ip.is_some() { fields += 2; }
            if mc.ip_protocol.is_some() { fields += 1; }
            if mc.src_port.is_some() { fields += 1; }
            if mc.dst_port.is_some() { fields += 1; }
            if mc.vxlan_vni.is_some() { fields += 2; }
            if mc.src_ipv6.is_some() { fields += 8; }
            if mc.dst_ipv6.is_some() { fields += 8; }
            if mc.ipv6_next_header.is_some() { fields += 1; }
            rule_luts += 10 + fields * 12;
        }
    }

    let num_rate_limited = rules.iter().filter(|r| r.rate_limit.is_some()).count();
    let decision_luts = 10 * rules.len() + 8;
    let total_luts = parser_luts + rule_luts + decision_luts + 20 + num_rate_limited * 50;
    let total_ffs = parser_ffs + rule_ffs + 4 + num_rate_limited * 64;
    (total_luts, total_ffs)
}

/// Measure compile time for a config using Verilog generation
fn measure_compile_time(config: &FilterConfig, templates_dir: &Path) -> Result<f64> {
    let tmp_base = std::env::temp_dir().join(format!("pacgate_bench_{}", std::process::id()));
    let output_dir = tmp_base.join("gen");
    std::fs::create_dir_all(output_dir.join("rtl"))?;
    std::fs::create_dir_all(output_dir.join("tb"))?;

    let start = Instant::now();
    crate::verilog_gen::generate(config, templates_dir, &output_dir)?;
    let elapsed = start.elapsed();

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_base);

    Ok(elapsed.as_secs_f64() * 1000.0)
}

/// Measure simulation throughput (packets per second)
fn measure_sim_throughput(config: &FilterConfig, packet_count: usize) -> f64 {
    // Generate a mix of test packets
    let test_packets: Vec<SimPacket> = (0..packet_count)
        .map(|i| {
            SimPacket {
                ethertype: Some(0x0800),
                ip_protocol: Some(if i % 3 == 0 { 6 } else { 17 }),
                src_ip: Some(format!("192.168.{}.{}", (i / 256) % 256, i % 256)),
                dst_ip: Some(format!("10.0.{}.{}", (i / 256) % 256, i % 256)),
                src_port: Some(1024 + (i as u16 % 64000)),
                dst_port: Some(80 + (i as u16 % 1000)),
                ..Default::default()
            }
        })
        .collect();

    let start = Instant::now();
    for pkt in &test_packets {
        let _ = simulator::simulate(config, pkt);
    }
    let elapsed = start.elapsed();

    if elapsed.as_secs_f64() > 0.0 {
        packet_count as f64 / elapsed.as_secs_f64()
    } else {
        f64::INFINITY
    }
}

/// Run full benchmark suite
pub fn run_benchmark(config: &FilterConfig, templates_dir: &Path) -> Result<BenchmarkReport> {
    let (input_luts, input_ffs) = estimate_resources(config);
    let input_rules = config.pacgate.rules.len();

    // Measure compile time for the actual config
    let compile_time = measure_compile_time(config, templates_dir)?;

    // Measure simulation throughput
    let sim_count = 10000;
    let sim_pps = measure_sim_throughput(config, sim_count);

    // Scaling curve: generate synthetic configs at various sizes
    let scaling_sizes = [10, 50, 100, 200, 500];
    let mut scaling = Vec::new();

    for &size in &scaling_sizes {
        let synth = synthetic_config(size);
        let (luts, ffs) = estimate_resources(&synth);
        let ct = measure_compile_time(&synth, templates_dir)?;
        scaling.push(ScalingPoint {
            rule_count: size,
            luts,
            ffs,
            compile_time_ms: ct,
        });
    }

    Ok(BenchmarkReport {
        compile_time_ms: compile_time,
        sim_throughput_pps: sim_pps,
        sim_packet_count: sim_count,
        input_luts,
        input_ffs,
        input_rules,
        scaling,
    })
}

/// Format benchmark report for human-readable output
pub fn format_report(report: &BenchmarkReport) -> String {
    let mut lines = Vec::new();

    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push("PERFORMANCE BENCHMARK REPORT".to_string());
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push(String::new());

    lines.push("── Input Config ──────────────────────────────────────────────".to_string());
    lines.push(format!("  Rules:        {}", report.input_rules));
    lines.push(format!("  LUTs:         {}", report.input_luts));
    lines.push(format!("  FFs:          {}", report.input_ffs));
    lines.push(format!("  Compile time: {:.1} ms", report.compile_time_ms));
    lines.push(String::new());

    lines.push("── Simulation Throughput ──────────────────────────────────────".to_string());
    lines.push(format!("  Packets:      {}", report.sim_packet_count));
    lines.push(format!("  Throughput:   {:.0} packets/sec", report.sim_throughput_pps));
    lines.push(String::new());

    lines.push("── Scaling Curve ─────────────────────────────────────────────".to_string());
    lines.push(format!("  {:>6} {:>8} {:>8} {:>12}", "Rules", "LUTs", "FFs", "Compile(ms)"));
    lines.push(format!("  {:>6} {:>8} {:>8} {:>12}", "──────", "────────", "────────", "────────────"));
    for pt in &report.scaling {
        lines.push(format!("  {:>6} {:>8} {:>8} {:>12.1}", pt.rule_count, pt.luts, pt.ffs, pt.compile_time_ms));
    }
    lines.push(String::new());

    // LUT utilization chart (ASCII bar chart)
    lines.push("── LUT Utilization (xc7a35t: 20,800 LUTs) ───────────────────".to_string());
    for pt in &report.scaling {
        let pct = pt.luts as f64 / 20800.0 * 100.0;
        let bar_len = (pct / 2.0).min(50.0) as usize;
        let bar: String = "█".repeat(bar_len);
        lines.push(format!("  {:>4} rules: {:>5.1}% {}", pt.rule_count, pct, bar));
    }
    lines.push(String::new());

    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_config_generates_rules() {
        let config = synthetic_config(10);
        assert_eq!(config.pacgate.rules.len(), 10);
        // All rules should have unique names
        let names: Vec<_> = config.pacgate.rules.iter().map(|r| &r.name).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn synthetic_config_large() {
        let config = synthetic_config(500);
        assert_eq!(config.pacgate.rules.len(), 500);
    }

    #[test]
    fn estimate_resources_scales() {
        let small = synthetic_config(10);
        let large = synthetic_config(100);
        let (small_luts, _) = estimate_resources(&small);
        let (large_luts, _) = estimate_resources(&large);
        assert!(large_luts > small_luts, "more rules should need more LUTs");
    }

    #[test]
    fn sim_throughput_positive() {
        let config = synthetic_config(5);
        let pps = measure_sim_throughput(&config, 100);
        assert!(pps > 0.0, "throughput should be positive");
    }

    #[test]
    fn format_report_contains_sections() {
        let report = BenchmarkReport {
            compile_time_ms: 42.5,
            sim_throughput_pps: 500000.0,
            sim_packet_count: 10000,
            input_luts: 300,
            input_ffs: 100,
            input_rules: 5,
            scaling: vec![
                ScalingPoint { rule_count: 10, luts: 500, ffs: 200, compile_time_ms: 10.0 },
                ScalingPoint { rule_count: 100, luts: 3000, ffs: 800, compile_time_ms: 50.0 },
            ],
        };
        let formatted = format_report(&report);
        assert!(formatted.contains("PERFORMANCE BENCHMARK"));
        assert!(formatted.contains("Scaling Curve"));
        assert!(formatted.contains("LUT Utilization"));
        assert!(formatted.contains("500000"));
    }
}
