use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig};

/// Generate SVA assertions and SymbiYosys task file from the filter configuration.
pub fn generate(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    generate_with_dynamic(config, templates_dir, output_dir, false, 0)
}

/// Generate SVA assertions with optional dynamic flow table assertions.
pub fn generate_with_dynamic(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, dynamic: bool, num_entries: u16) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let formal_dir = output_dir.join("formal");
    std::fs::create_dir_all(&formal_dir)?;

    // Sort rules by priority (highest first) — same order as verilog_gen
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Build rule info for SVA template
    let rule_info: Vec<std::collections::HashMap<String, String>> = rules
        .iter()
        .enumerate()
        .map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), idx.to_string());
            map.insert("name".to_string(), rule.name.clone());
            map.insert("is_fsm".to_string(), rule.is_stateful().to_string());
            let action_pass = if rule.is_stateful() {
                "true".to_string()
            } else {
                (rule.action() == Action::Pass).to_string()
            };
            map.insert("action_pass".to_string(), action_pass);
            let action_str = if rule.is_stateful() {
                "FSM".to_string()
            } else if rule.action() == Action::Pass {
                "pass".to_string()
            } else {
                "drop".to_string()
            };
            map.insert("action_str".to_string(), action_str);
            map
        })
        .collect();

    let default_pass = config.pacgate.defaults.action == Action::Pass;
    let max_decision_latency = 4; // cycles from fields_valid to decision_valid

    // Compute feature flags for conditional assertions
    let has_ipv6_rules = rules.iter().any(|r| r.match_criteria.uses_ipv6());
    let has_port_range_rules = rules.iter().any(|r| {
        matches!(&r.match_criteria.src_port, Some(crate::model::PortMatch::Range { .. }))
        || matches!(&r.match_criteria.dst_port, Some(crate::model::PortMatch::Range { .. }))
    });
    let has_byte_match_rules = rules.iter().any(|r| r.match_criteria.uses_byte_match());
    let has_rate_limit = rules.iter().any(|r| r.rate_limit.is_some());
    let has_gtp_rules = rules.iter().any(|r| r.match_criteria.gtp_teid.is_some());
    let has_mpls_rules = rules.iter().any(|r| r.match_criteria.mpls_label.is_some() || r.match_criteria.mpls_tc.is_some() || r.match_criteria.mpls_bos.is_some());
    let has_igmp_rules = rules.iter().any(|r| r.match_criteria.igmp_type.is_some());
    let has_mld_rules = rules.iter().any(|r| r.match_criteria.mld_type.is_some());
    let has_dscp_ecn_rules = rules.iter().any(|r| r.match_criteria.uses_dscp_ecn());
    let has_ipv6_tc_rules = rules.iter().any(|r| r.match_criteria.uses_ipv6_tc());
    let has_tcp_flags_rules = rules.iter().any(|r| r.match_criteria.uses_tcp_flags());
    let has_icmp_rules = rules.iter().any(|r| r.match_criteria.uses_icmp());
    let has_rewrite_rules = rules.iter().any(|r| r.has_rewrite());

    // Build per-rule protocol index lists for conditional assertions
    let gtp_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.gtp_teid.is_some())
        .map(|(i, _)| i).collect();
    let mpls_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.mpls_label.is_some() || r.match_criteria.mpls_tc.is_some() || r.match_criteria.mpls_bos.is_some())
        .map(|(i, _)| i).collect();
    let igmp_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.igmp_type.is_some())
        .map(|(i, _)| i).collect();
    let mld_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.mld_type.is_some())
        .map(|(i, _)| i).collect();
    let dscp_ecn_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_dscp_ecn())
        .map(|(i, _)| i).collect();
    let ipv6_tc_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_ipv6_tc())
        .map(|(i, _)| i).collect();
    let tcp_flags_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_tcp_flags())
        .map(|(i, _)| i).collect();
    let icmp_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_icmp())
        .map(|(i, _)| i).collect();
    let rewrite_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.has_rewrite())
        .map(|(i, _)| i).collect();

    let has_icmpv6_rules = rules.iter().any(|r| r.match_criteria.uses_icmpv6());
    let has_arp_rules = rules.iter().any(|r| r.match_criteria.uses_arp());
    let has_ipv6_ext_rules = rules.iter().any(|r| r.match_criteria.uses_ipv6_ext());
    let icmpv6_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_icmpv6())
        .map(|(i, _)| i).collect();
    let arp_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_arp())
        .map(|(i, _)| i).collect();
    let ipv6_ext_rule_indices: Vec<usize> = rules.iter().enumerate()
        .filter(|(_, r)| r.match_criteria.uses_ipv6_ext())
        .map(|(i, _)| i).collect();

    // Render SVA assertions
    {
        let mut ctx = tera::Context::new();
        ctx.insert("rules", &rule_info);
        ctx.insert("default_pass", &default_pass);
        ctx.insert("max_decision_latency", &max_decision_latency);
        ctx.insert("has_ipv6_rules", &has_ipv6_rules);
        ctx.insert("has_port_range_rules", &has_port_range_rules);
        ctx.insert("has_byte_match_rules", &has_byte_match_rules);
        ctx.insert("has_rate_limit", &has_rate_limit);
        ctx.insert("has_gtp_rules", &has_gtp_rules);
        ctx.insert("has_mpls_rules", &has_mpls_rules);
        ctx.insert("has_igmp_rules", &has_igmp_rules);
        ctx.insert("has_mld_rules", &has_mld_rules);
        ctx.insert("gtp_rule_indices", &gtp_rule_indices);
        ctx.insert("mpls_rule_indices", &mpls_rule_indices);
        ctx.insert("igmp_rule_indices", &igmp_rule_indices);
        ctx.insert("mld_rule_indices", &mld_rule_indices);
        ctx.insert("has_dscp_ecn_rules", &has_dscp_ecn_rules);
        ctx.insert("dscp_ecn_rule_indices", &dscp_ecn_rule_indices);
        ctx.insert("has_ipv6_tc_rules", &has_ipv6_tc_rules);
        ctx.insert("ipv6_tc_rule_indices", &ipv6_tc_rule_indices);
        ctx.insert("has_tcp_flags_rules", &has_tcp_flags_rules);
        ctx.insert("tcp_flags_rule_indices", &tcp_flags_rule_indices);
        ctx.insert("has_icmp_rules", &has_icmp_rules);
        ctx.insert("icmp_rule_indices", &icmp_rule_indices);
        ctx.insert("has_rewrite_rules", &has_rewrite_rules);
        ctx.insert("rewrite_rule_indices", &rewrite_rule_indices);
        ctx.insert("has_icmpv6_rules", &has_icmpv6_rules);
        ctx.insert("icmpv6_rule_indices", &icmpv6_rule_indices);
        ctx.insert("has_arp_rules", &has_arp_rules);
        ctx.insert("arp_rule_indices", &arp_rule_indices);
        ctx.insert("has_ipv6_ext_rules", &has_ipv6_ext_rules);
        ctx.insert("ipv6_ext_rule_indices", &ipv6_ext_rule_indices);
        ctx.insert("has_dynamic", &dynamic);
        ctx.insert("dynamic_num_entries", &num_entries);

        let rendered = tera.render("assertions.sv.tera", &ctx)?;
        std::fs::write(formal_dir.join("assertions.sv"), &rendered)?;
        log::info!("Generated formal/assertions.sv");
    }

    // Build list of generated Verilog files for SBY
    let rtl_dir = output_dir.join("rtl");
    let mut verilog_files: Vec<String> = Vec::new();
    if rtl_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&rtl_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "v").unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            verilog_files.push(format!("../rtl/{}", entry.file_name().to_string_lossy()));
        }
    }

    // Render SymbiYosys task file
    {
        let mut ctx = tera::Context::new();
        ctx.insert("verilog_files", &verilog_files);
        ctx.insert("bmc_depth", &50);
        ctx.insert("cover_depth", &30);

        let rendered = tera.render("formal.sby.tera", &ctx)?;
        std::fs::write(formal_dir.join("packet_filter.sby"), &rendered)?;
        log::info!("Generated formal/packet_filter.sby");
    }

    Ok(())
}
