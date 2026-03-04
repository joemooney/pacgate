use serde::Serialize;

use crate::model::{FilterConfig, Action, PortMatch};

/// A reachability mapping: which traffic reaches which action
#[derive(Debug, Clone, Serialize)]
pub struct ReachabilityEntry {
    pub rule_name: String,
    pub priority: u32,
    pub action: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub ip_protocol: String,
    pub src_port: String,
    pub dst_port: String,
    pub ethertype: String,
    pub additional: Vec<String>,
}

/// Full reachability report
#[derive(Debug, Clone, Serialize)]
pub struct ReachabilityReport {
    pub entries: Vec<ReachabilityEntry>,
    pub default_action: String,
    pub total_rules: usize,
    pub pass_rules: usize,
    pub drop_rules: usize,
    pub queries: Vec<QueryResult>,
    pub stateful_rules: Vec<String>,
}

/// Result of a specific reachability query
#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub query: String,
    pub matching_rules: Vec<String>,
    pub final_action: String,
}

/// Generate reachability analysis from filter configuration
pub fn analyze(config: &FilterConfig) -> ReachabilityReport {
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    let default_action = match config.pacgate.defaults.action {
        Action::Pass => "pass",
        Action::Drop => "drop",
    };

    let mut entries = Vec::new();
    let mut pass_count = 0;
    let mut drop_count = 0;
    let mut stateful_rules = Vec::new();

    for rule in &rules {
        if rule.is_stateful() {
            stateful_rules.push(rule.name.clone());
            continue;
        }

        let action = match rule.action() {
            Action::Pass => { pass_count += 1; "pass" }
            Action::Drop => { drop_count += 1; "drop" }
        };

        let mc = &rule.match_criteria;
        let mut additional = Vec::new();

        if let Some(ref mac) = mc.dst_mac {
            additional.push(format!("dst_mac={}", mac));
        }
        if let Some(ref mac) = mc.src_mac {
            additional.push(format!("src_mac={}", mac));
        }
        if let Some(vid) = mc.vlan_id {
            additional.push(format!("vlan_id={}", vid));
        }
        if let Some(vni) = mc.vxlan_vni {
            additional.push(format!("vxlan_vni={}", vni));
        }
        if let Some(ref ipv6) = mc.src_ipv6 {
            additional.push(format!("src_ipv6={}", ipv6));
        }
        if let Some(ref ipv6) = mc.dst_ipv6 {
            additional.push(format!("dst_ipv6={}", ipv6));
        }
        if let Some(pcp) = mc.vlan_pcp {
            additional.push(format!("vlan_pcp={}", pcp));
        }
        if let Some(nh) = mc.ipv6_next_header {
            additional.push(format!("ipv6_next_header={}", nh));
        }
        if let Some(teid) = mc.gtp_teid {
            additional.push(format!("gtp_teid={}", teid));
        }
        if let Some(label) = mc.mpls_label {
            additional.push(format!("mpls_label={}", label));
        }
        if let Some(tc) = mc.mpls_tc {
            additional.push(format!("mpls_tc={}", tc));
        }
        if let Some(bos) = mc.mpls_bos {
            additional.push(format!("mpls_bos={}", bos));
        }
        if let Some(t) = mc.igmp_type {
            additional.push(format!("igmp_type=0x{:02x}", t));
        }
        if let Some(t) = mc.mld_type {
            additional.push(format!("mld_type={}", t));
        }
        if mc.uses_byte_match() {
            additional.push("byte_match=yes".to_string());
        }

        entries.push(ReachabilityEntry {
            rule_name: rule.name.clone(),
            priority: rule.priority,
            action: action.to_string(),
            src_ip: format_ip(&mc.src_ip),
            dst_ip: format_ip(&mc.dst_ip),
            ip_protocol: format_protocol(mc.ip_protocol),
            src_port: format_port(&mc.src_port),
            dst_port: format_port(&mc.dst_port),
            ethertype: mc.ethertype.as_deref().unwrap_or("any").to_string(),
            additional,
        });
    }

    // Generate standard queries
    let queries = generate_standard_queries(config, &rules);

    ReachabilityReport {
        entries,
        default_action: default_action.to_string(),
        total_rules: rules.len(),
        pass_rules: pass_count,
        drop_rules: drop_count,
        queries,
        stateful_rules,
    }
}

/// Format IP field for display
fn format_ip(ip: &Option<String>) -> String {
    ip.as_deref().unwrap_or("any").to_string()
}

/// Format protocol number to name
fn format_protocol(proto: Option<u8>) -> String {
    match proto {
        Some(1) => "ICMP".to_string(),
        Some(6) => "TCP".to_string(),
        Some(17) => "UDP".to_string(),
        Some(58) => "ICMPv6".to_string(),
        Some(n) => n.to_string(),
        None => "any".to_string(),
    }
}

/// Format port for display
fn format_port(pm: &Option<PortMatch>) -> String {
    match pm {
        Some(PortMatch::Exact(p)) => p.to_string(),
        Some(PortMatch::Range { range }) => format!("{}-{}", range[0], range[1]),
        None => "any".to_string(),
    }
}

/// Generate standard reachability queries
fn generate_standard_queries(
    config: &FilterConfig,
    sorted_rules: &[crate::model::StatelessRule],
) -> Vec<QueryResult> {
    let mut queries = Vec::new();

    // Query: "What can reach port 80?"
    queries.push(query_by_port(sorted_rules, config, 80, "What can reach port 80 (HTTP)?"));

    // Query: "What can reach port 443?"
    queries.push(query_by_port(sorted_rules, config, 443, "What can reach port 443 (HTTPS)?"));

    // Query: "What can reach port 22?"
    queries.push(query_by_port(sorted_rules, config, 22, "What can reach port 22 (SSH)?"));

    // Query: "What gets dropped?"
    queries.push(query_by_action(sorted_rules, config, Action::Drop, "What traffic gets dropped?"));

    // Query: "What gets passed?"
    queries.push(query_by_action(sorted_rules, config, Action::Pass, "What traffic gets passed?"));

    queries
}

fn query_by_port(
    rules: &[crate::model::StatelessRule],
    config: &FilterConfig,
    port: u16,
    description: &str,
) -> QueryResult {
    let matching: Vec<String> = rules.iter()
        .filter(|r| !r.is_stateful())
        .filter(|r| port_could_match(&r.match_criteria.dst_port, port))
        .map(|r| format!("{} ({})", r.name, if r.action() == Action::Pass { "pass" } else { "drop" }))
        .collect();

    let action = if matching.is_empty() {
        match config.pacgate.defaults.action {
            Action::Pass => "pass (default)",
            Action::Drop => "drop (default)",
        }
    } else {
        // First match wins (already sorted by priority)
        if matching[0].contains("pass") { "pass" } else { "drop" }
    };

    QueryResult {
        query: description.to_string(),
        matching_rules: matching,
        final_action: action.to_string(),
    }
}

fn query_by_action(
    rules: &[crate::model::StatelessRule],
    config: &FilterConfig,
    action: Action,
    description: &str,
) -> QueryResult {
    let matching: Vec<String> = rules.iter()
        .filter(|r| !r.is_stateful() && r.action() == action)
        .map(|r| {
            let mc = &r.match_criteria;
            let mut desc = r.name.clone();
            if let Some(ref ip) = mc.src_ip {
                desc.push_str(&format!(" src_ip={}", ip));
            }
            if let Some(ref ip) = mc.dst_ip {
                desc.push_str(&format!(" dst_ip={}", ip));
            }
            if let Some(ref pm) = mc.dst_port {
                desc.push_str(&format!(" dst_port={}", format_port(&Some(pm.clone()))));
            }
            if let Some(teid) = mc.gtp_teid {
                desc.push_str(&format!(" gtp_teid={}", teid));
            }
            if let Some(label) = mc.mpls_label {
                desc.push_str(&format!(" mpls_label={}", label));
            }
            if let Some(t) = mc.igmp_type {
                desc.push_str(&format!(" igmp_type=0x{:02x}", t));
            }
            if let Some(t) = mc.mld_type {
                desc.push_str(&format!(" mld_type={}", t));
            }
            desc
        })
        .collect();

    let default_matches = match config.pacgate.defaults.action {
        Action::Pass => action == Action::Pass,
        Action::Drop => action == Action::Drop,
    };

    let mut all = matching.clone();
    if default_matches {
        all.push("(default action)".to_string());
    }

    QueryResult {
        query: description.to_string(),
        matching_rules: all,
        final_action: if action == Action::Pass { "pass" } else { "drop" }.to_string(),
    }
}

/// Check if a port could match a rule's port specification
fn port_could_match(pm: &Option<PortMatch>, port: u16) -> bool {
    match pm {
        None => true, // No port constraint → matches all ports
        Some(PortMatch::Exact(p)) => *p == port,
        Some(PortMatch::Range { range }) => port >= range[0] && port <= range[1],
    }
}

/// Format reachability report for human-readable output
pub fn format_report(report: &ReachabilityReport) -> String {
    let mut lines = Vec::new();

    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push("REACHABILITY ANALYSIS".to_string());
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push(format!("Total rules: {} ({} pass, {} drop)", report.total_rules, report.pass_rules, report.drop_rules));
    lines.push(format!("Default action: {}", report.default_action));
    lines.push(String::new());

    // Rule reachability table
    lines.push("── Rule Reachability Map ──────────────────────────────────────".to_string());
    lines.push(format!("  {:<25} {:>5} {:>6} {:>10} {:>10} {:>6} {:>10} {:>10}",
        "Rule", "Pri", "Action", "Src IP", "Dst IP", "Proto", "Src Port", "Dst Port"));
    lines.push(format!("  {:<25} {:>5} {:>6} {:>10} {:>10} {:>6} {:>10} {:>10}",
        "─".repeat(25), "─".repeat(5), "─".repeat(6), "─".repeat(10), "─".repeat(10),
        "─".repeat(6), "─".repeat(10), "─".repeat(10)));

    for entry in &report.entries {
        lines.push(format!("  {:<25} {:>5} {:>6} {:>10} {:>10} {:>6} {:>10} {:>10}",
            truncate(&entry.rule_name, 25),
            entry.priority,
            entry.action,
            truncate(&entry.src_ip, 10),
            truncate(&entry.dst_ip, 10),
            truncate(&entry.ip_protocol, 6),
            truncate(&entry.src_port, 10),
            truncate(&entry.dst_port, 10),
        ));
        for extra in &entry.additional {
            lines.push(format!("    + {}", extra));
        }
    }
    lines.push(String::new());

    // Stateful rules (not analyzed)
    if !report.stateful_rules.is_empty() {
        lines.push("── Stateful Rules (not analyzed) ─────────────────────────────".to_string());
        for name in &report.stateful_rules {
            lines.push(format!("  - {}", name));
        }
        lines.push(String::new());
    }

    // Queries
    lines.push("── Reachability Queries ──────────────────────────────────────".to_string());
    for query in &report.queries {
        lines.push(format!("  Q: {}", query.query));
        lines.push(format!("  A: {} (final action: {})",
            if query.matching_rules.is_empty() { "no specific rules" } else { "" },
            query.final_action));
        for rule in &query.matching_rules {
            lines.push(format!("     - {}", rule));
        }
        lines.push(String::new());
    }

    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.join("\n")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max-1])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_config(rules: Vec<StatelessRule>, default: Action) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: default },
                rules,
                conntrack: None,
                tables: None,
            },
        }
    }

    #[test]
    fn reachability_basic() {
        let rules = vec![
            StatelessRule {
                name: "allow_http".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ip_protocol: Some(6),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].action, "pass");
        assert_eq!(report.pass_rules, 1);
        assert_eq!(report.drop_rules, 0);
    }

    #[test]
    fn reachability_queries() {
        let rules = vec![
            StatelessRule {
                name: "allow_http".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ip_protocol: Some(6),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        // Should have port 80 query that matches
        let port80_query = report.queries.iter().find(|q| q.query.contains("port 80")).unwrap();
        assert!(!port80_query.matching_rules.is_empty());
    }

    #[test]
    fn reachability_port_range() {
        let rules = vec![
            StatelessRule {
                name: "high_ports".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    dst_port: Some(PortMatch::Range { range: [1024, 65535] }),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        // Port 80 is NOT in 1024-65535 range
        let port80_query = report.queries.iter().find(|q| q.query.contains("port 80")).unwrap();
        let has_high_ports = port80_query.matching_rules.iter().any(|r| r.contains("high_ports"));
        assert!(!has_high_ports, "port 80 should not match 1024-65535 range");
    }

    #[test]
    fn format_report_output() {
        let rules = vec![
            StatelessRule {
                name: "allow_http".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        let formatted = format_report(&report);
        assert!(formatted.contains("REACHABILITY ANALYSIS"));
        assert!(formatted.contains("allow_http"));
    }

    #[test]
    fn reachability_default_action_in_queries() {
        let config = make_config(vec![], Action::Pass);
        let report = analyze(&config);
        let pass_query = report.queries.iter().find(|q| q.query.contains("passed")).unwrap();
        assert!(pass_query.matching_rules.iter().any(|r| r.contains("default")));
    }

    #[test]
    fn reachability_gtp_teid_in_additional() {
        let rules = vec![
            StatelessRule {
                name: "gtp_rule".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    gtp_teid: Some(1000),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        assert!(report.entries[0].additional.contains(&"gtp_teid=1000".to_string()));
    }

    #[test]
    fn reachability_mpls_fields_in_additional() {
        let rules = vec![
            StatelessRule {
                name: "mpls_rule".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    mpls_label: Some(200),
                    mpls_tc: Some(5),
                    mpls_bos: Some(true),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        let additional = &report.entries[0].additional;
        assert!(additional.contains(&"mpls_label=200".to_string()));
        assert!(additional.contains(&"mpls_tc=5".to_string()));
        assert!(additional.contains(&"mpls_bos=true".to_string()));
    }

    #[test]
    fn reachability_igmp_mld_in_additional() {
        let rules = vec![
            StatelessRule {
                name: "igmp_rule".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    igmp_type: Some(0x11),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
            StatelessRule {
                name: "mld_rule".to_string(),
                priority: 90,
                match_criteria: MatchCriteria {
                    mld_type: Some(130),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        assert!(report.entries[0].additional.contains(&"igmp_type=0x11".to_string()));
        assert!(report.entries[1].additional.contains(&"mld_type=130".to_string()));
    }

    #[test]
    fn reachability_stateful_rules_reported() {
        let rules = vec![
            StatelessRule {
                name: "stateful_seq".to_string(),
                priority: 100,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Pass),
                rule_type: Some("stateful".to_string()),
                fsm: Some(FsmDefinition {
                    initial_state: "idle".to_string(),
                    states: std::collections::HashMap::new(),
                    variables: None,
                }),
                ports: None,
                rate_limit: None,
                rewrite: None,
                mirror_port: None,
                redirect_port: None,
            },
            StatelessRule {
                name: "stateless_rule".to_string(),
                priority: 90,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Pass),
                rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let report = analyze(&config);
        assert!(report.stateful_rules.contains(&"stateful_seq".to_string()));
        assert!(!report.entries.iter().any(|e| e.rule_name == "stateful_seq"),
            "stateful rule should not be in entries");
        assert!(report.entries.iter().any(|e| e.rule_name == "stateless_rule"));
    }
}
