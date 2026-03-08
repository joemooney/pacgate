// Packet Match Trace: Debug tool for per-rule, per-field evaluation trace.
//
// Unlike `simulate` (which returns only the winning rule), `trace` evaluates
// ALL rules against a packet and reports per-rule, per-field pass/fail for
// debugging packet matching decisions.

use crate::model::{FilterConfig, Action, StatelessRule};
use crate::simulator::{SimPacket, FieldMatch, SimRewrite, match_criteria_against_packet, build_sim_rewrite};

/// Trace result for a single rule evaluation
#[derive(Debug, Clone)]
pub struct RuleTrace {
    pub name: String,
    pub priority: u32,
    pub action: Action,
    pub fields: Vec<FieldMatch>,
    pub all_match: bool,
    pub is_winner: bool,
    pub is_stateful: bool,
    pub rewrite: Option<SimRewrite>,
    pub mirror_port: Option<u8>,
    pub redirect_port: Option<u8>,
    pub rss_queue: Option<u8>,
    pub int_insert: bool,
}

/// Trace result for a full evaluation
#[derive(Debug, Clone)]
pub struct TraceResult {
    pub rules: Vec<RuleTrace>,
    pub winner: Option<String>,
    pub final_action: Action,
    pub is_default: bool,
    pub default_action: Action,
}

/// Trace result for a pipeline stage
#[derive(Debug, Clone)]
pub struct StageTrace {
    pub name: String,
    pub result: TraceResult,
}

/// Trace result for a pipeline evaluation
#[derive(Debug, Clone)]
pub struct PipelineTrace {
    pub stages: Vec<StageTrace>,
    pub final_action: Action,
    pub final_winner: Option<String>,
}

/// Trace all rules against a packet, returning per-rule evaluation breakdown.
pub fn trace_packet(config: &FilterConfig, packet: &SimPacket) -> TraceResult {
    if config.is_pipeline() {
        // For pipeline, return just the last stage's trace for the simple API
        let pt = trace_pipeline(config, packet);
        if let Some(last) = pt.stages.last() {
            let mut result = last.result.clone();
            result.final_action = pt.final_action;
            return result;
        }
    }
    trace_stage(&config.pacgate.rules, &config.pacgate.defaults.action, packet)
}

/// Trace a pipeline evaluation, returning per-stage breakdown.
pub fn trace_pipeline(config: &FilterConfig, packet: &SimPacket) -> PipelineTrace {
    let tables = config.pacgate.tables.as_ref().unwrap();
    let mut stages = Vec::new();
    let mut any_drop = false;
    let mut final_winner = None;

    for (i, stage) in tables.iter().enumerate() {
        let stage_trace = trace_stage(&stage.rules, &stage.default_action, packet);
        if stage_trace.final_action == Action::Drop {
            any_drop = true;
        }
        if !stage_trace.is_default {
            final_winner = stage_trace.winner.clone();
        }
        stages.push(StageTrace {
            name: if stage.name.is_empty() { format!("stage_{}", i) } else { stage.name.clone() },
            result: stage_trace,
        });
    }

    PipelineTrace {
        final_action: if any_drop { Action::Drop } else { Action::Pass },
        final_winner,
        stages,
    }
}

/// Trace all rules in a single stage against a packet.
fn trace_stage(rules: &[StatelessRule], default_action: &Action, packet: &SimPacket) -> TraceResult {
    let mut sorted: Vec<&StatelessRule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut traces = Vec::new();
    let mut winner: Option<String> = None;

    for rule in &sorted {
        if rule.is_stateful() {
            traces.push(RuleTrace {
                name: rule.name.clone(),
                priority: rule.priority,
                action: rule.action(),
                fields: Vec::new(),
                all_match: false,
                is_winner: false,
                is_stateful: true,
                rewrite: None,
                mirror_port: None,
                redirect_port: None,
                rss_queue: None,
                int_insert: false,
            });
            continue;
        }

        let (matches, fields) = match_criteria_against_packet(&rule.match_criteria, packet);

        let is_winner = matches && winner.is_none();
        if is_winner {
            winner = Some(rule.name.clone());
        }

        let rewrite = if is_winner && rule.action() == Action::Pass {
            build_sim_rewrite(rule)
        } else {
            None
        };

        traces.push(RuleTrace {
            name: rule.name.clone(),
            priority: rule.priority,
            action: rule.action(),
            fields,
            all_match: matches,
            is_winner,
            is_stateful: false,
            rewrite,
            mirror_port: if is_winner { rule.mirror_port } else { None },
            redirect_port: if is_winner { rule.redirect_port } else { None },
            rss_queue: if is_winner { rule.rss_queue } else { None },
            int_insert: is_winner && rule.has_int_insert(),
        });
    }

    let final_action = if let Some(ref w) = winner {
        traces.iter().find(|t| t.name == *w).map(|t| t.action.clone()).unwrap_or_else(|| default_action.clone())
    } else {
        default_action.clone()
    };

    let is_default = winner.is_none();
    TraceResult {
        rules: traces,
        winner,
        final_action,
        is_default,
        default_action: default_action.clone(),
    }
}

/// Format a trace result as human-readable text output.
pub fn format_trace(result: &TraceResult, packet_spec: &str) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str("  PacGate Packet Trace\n");
    out.push_str("  ════════════════════════════════════════════\n");
    out.push_str(&format!("  Packet: {}\n", packet_spec));
    out.push('\n');

    let total = result.rules.len();
    let matched = result.rules.iter().filter(|r| r.all_match).count();
    let action_str = match result.final_action { Action::Pass => "PASS", Action::Drop => "DROP" };

    if result.is_default {
        out.push_str(&format!("  Decision: DEFAULT -> {} (no rule matched)\n", action_str));
    } else {
        out.push_str(&format!("  Decision: Rule '{}' -> {}\n", result.winner.as_deref().unwrap_or("?"), action_str));
    }
    out.push_str(&format!("  Rules evaluated: {} total, {} matched\n", total, matched));
    out.push('\n');

    for rt in &result.rules {
        let status = if rt.is_stateful {
            "[SKIP]"
        } else if rt.is_winner {
            "[WIN] "
        } else if rt.all_match {
            "[MATCH]"
        } else {
            "[MISS]"
        };

        let action_str = match rt.action { Action::Pass => "pass", Action::Drop => "drop" };
        out.push_str(&format!("  {} {} (priority {}, action: {})\n", status, rt.name, rt.priority, action_str));

        if rt.is_stateful {
            out.push_str("    (stateful rule — skipped in trace)\n");
        } else if rt.fields.is_empty() {
            out.push_str("    (no match criteria — matches all packets)\n");
        } else {
            for f in &rt.fields {
                let mark = if f.matches { "OK" } else { "FAIL" };
                out.push_str(&format!("    {:4} {:15} rule={:20} pkt={}\n",
                    mark, f.field, f.rule_value, f.packet_value));
            }
        }

        // Show rewrite/egress for winning rule
        if rt.is_winner {
            if let Some(ref rw) = rt.rewrite {
                if !rw.is_empty() {
                    out.push_str("    Rewrite:");
                    if let Some(ref v) = rw.set_dst_mac { out.push_str(&format!(" set_dst_mac={}", v)); }
                    if let Some(ref v) = rw.set_src_mac { out.push_str(&format!(" set_src_mac={}", v)); }
                    if let Some(v) = rw.set_vlan_id { out.push_str(&format!(" set_vlan_id={}", v)); }
                    if let Some(v) = rw.set_ttl { out.push_str(&format!(" set_ttl={}", v)); }
                    if rw.dec_ttl { out.push_str(" dec_ttl"); }
                    if let Some(ref v) = rw.set_src_ip { out.push_str(&format!(" set_src_ip={}", v)); }
                    if let Some(ref v) = rw.set_dst_ip { out.push_str(&format!(" set_dst_ip={}", v)); }
                    if let Some(v) = rw.set_dscp { out.push_str(&format!(" set_dscp={}", v)); }
                    if let Some(v) = rw.set_src_port { out.push_str(&format!(" set_src_port={}", v)); }
                    if let Some(v) = rw.set_dst_port { out.push_str(&format!(" set_dst_port={}", v)); }
                    if rw.dec_hop_limit { out.push_str(" dec_hop_limit"); }
                    if let Some(v) = rw.set_hop_limit { out.push_str(&format!(" set_hop_limit={}", v)); }
                    if let Some(v) = rw.set_ecn { out.push_str(&format!(" set_ecn={}", v)); }
                    if let Some(v) = rw.set_vlan_pcp { out.push_str(&format!(" set_vlan_pcp={}", v)); }
                    if let Some(v) = rw.set_outer_vlan_id { out.push_str(&format!(" set_outer_vlan_id={}", v)); }
                    out.push('\n');
                }
            }
            if let Some(p) = rt.mirror_port { out.push_str(&format!("    mirror_port: {}\n", p)); }
            if let Some(p) = rt.redirect_port { out.push_str(&format!("    redirect_port: {}\n", p)); }
            if let Some(q) = rt.rss_queue { out.push_str(&format!("    rss_queue: {}\n", q)); }
            if rt.int_insert { out.push_str("    INT: metadata insertion enabled\n"); }
        }

        out.push('\n');
    }
    out
}

/// Format a pipeline trace as human-readable text.
pub fn format_pipeline_trace(pt: &PipelineTrace, packet_spec: &str) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str("  PacGate Pipeline Packet Trace\n");
    out.push_str("  ════════════════════════════════════════════\n");
    out.push_str(&format!("  Packet: {}\n", packet_spec));
    out.push('\n');

    let action_str = match pt.final_action { Action::Pass => "PASS", Action::Drop => "DROP" };
    out.push_str(&format!("  Final decision: {}\n", action_str));
    out.push_str(&format!("  Stages: {}\n\n", pt.stages.len()));

    for (i, stage) in pt.stages.iter().enumerate() {
        let stage_action = match stage.result.final_action { Action::Pass => "PASS", Action::Drop => "DROP" };
        out.push_str(&format!("  ── Stage {}: {} ── {}\n", i, stage.name, stage_action));

        for rt in &stage.result.rules {
            let status = if rt.is_stateful {
                "[SKIP]"
            } else if rt.is_winner {
                "[WIN] "
            } else if rt.all_match {
                "[MATCH]"
            } else {
                "[MISS]"
            };

            let action_str = match rt.action { Action::Pass => "pass", Action::Drop => "drop" };
            out.push_str(&format!("    {} {} (priority {}, {})\n", status, rt.name, rt.priority, action_str));

            if !rt.is_stateful {
                for f in &rt.fields {
                    let mark = if f.matches { "OK" } else { "FAIL" };
                    out.push_str(&format!("      {:4} {:15} rule={:20} pkt={}\n",
                        mark, f.field, f.rule_value, f.packet_value));
                }
            }
        }
        out.push('\n');
    }
    out
}

/// Convert a trace result to JSON.
pub fn trace_to_json(result: &TraceResult, packet_spec: &str) -> serde_json::Value {
    let rules_json: Vec<serde_json::Value> = result.rules.iter().map(|rt| {
        let fields_json: Vec<serde_json::Value> = rt.fields.iter().map(|f| {
            serde_json::json!({
                "field": f.field,
                "rule_value": f.rule_value,
                "packet_value": f.packet_value,
                "matches": f.matches,
            })
        }).collect();

        let mut rule_json = serde_json::json!({
            "name": rt.name,
            "priority": rt.priority,
            "action": match rt.action { Action::Pass => "pass", Action::Drop => "drop" },
            "all_match": rt.all_match,
            "is_winner": rt.is_winner,
            "is_stateful": rt.is_stateful,
            "fields": fields_json,
        });

        if let Some(ref rw) = rt.rewrite {
            if !rw.is_empty() {
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
                rule_json.as_object_mut().unwrap().insert("rewrite".to_string(), serde_json::Value::Object(rw_json));
            }
        }
        if let Some(p) = rt.mirror_port { rule_json.as_object_mut().unwrap().insert("mirror_port".into(), serde_json::json!(p)); }
        if let Some(p) = rt.redirect_port { rule_json.as_object_mut().unwrap().insert("redirect_port".into(), serde_json::json!(p)); }
        if let Some(q) = rt.rss_queue { rule_json.as_object_mut().unwrap().insert("rss_queue".into(), serde_json::json!(q)); }
        if rt.int_insert { rule_json.as_object_mut().unwrap().insert("int_insert".into(), serde_json::json!(true)); }

        rule_json
    }).collect();

    serde_json::json!({
        "status": "ok",
        "packet": packet_spec,
        "decision": match result.final_action { Action::Pass => "pass", Action::Drop => "drop" },
        "winner": result.winner,
        "is_default": result.is_default,
        "default_action": match result.default_action { Action::Pass => "pass", Action::Drop => "drop" },
        "rule_count": result.rules.len(),
        "match_count": result.rules.iter().filter(|r| r.all_match).count(),
        "rules": rules_json,
    })
}

/// Convert a pipeline trace to JSON.
pub fn pipeline_trace_to_json(pt: &PipelineTrace, packet_spec: &str) -> serde_json::Value {
    let stages_json: Vec<serde_json::Value> = pt.stages.iter().map(|s| {
        let stage_json = trace_to_json(&s.result, packet_spec);
        serde_json::json!({
            "name": s.name,
            "decision": match s.result.final_action { Action::Pass => "pass", Action::Drop => "drop" },
            "winner": s.result.winner,
            "rules": stage_json["rules"],
        })
    }).collect();

    serde_json::json!({
        "status": "ok",
        "packet": packet_spec,
        "final_decision": match pt.final_action { Action::Pass => "pass", Action::Drop => "drop" },
        "final_winner": pt.final_winner,
        "stage_count": pt.stages.len(),
        "stages": stages_json,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::simulator::parse_packet_spec;

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

    fn make_rule(name: &str, priority: u32, action: Action, mc: MatchCriteria) -> StatelessRule {
        StatelessRule {
            name: name.to_string(),
            priority,
            action: Some(action),
            match_criteria: mc,
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            mirror_port: None,
            redirect_port: None,
            rss_queue: None,
            int_insert: None,
            rewrite: None,
        }
    }

    #[test]
    fn trace_single_match() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        assert_eq!(result.rules.len(), 1);
        assert!(result.rules[0].all_match);
        assert!(result.rules[0].is_winner);
        assert_eq!(result.winner, Some("r1".to_string()));
        assert_eq!(result.final_action, Action::Pass);
        assert!(!result.is_default);
    }

    #[test]
    fn trace_no_match() {
        let mc = MatchCriteria { ethertype: Some("0x0806".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        assert_eq!(result.rules.len(), 1);
        assert!(!result.rules[0].all_match);
        assert!(!result.rules[0].is_winner);
        assert_eq!(result.winner, None);
        assert_eq!(result.final_action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn trace_multiple_rules_first_wins() {
        let mc1 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc2 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let rules = vec![
            make_rule("r1", 200, Action::Pass, mc1),
            make_rule("r2", 100, Action::Drop, mc2),
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        assert_eq!(result.rules.len(), 2);
        // r1 (priority 200) wins
        let r1 = result.rules.iter().find(|r| r.name == "r1").unwrap();
        assert!(r1.all_match);
        assert!(r1.is_winner);
        // r2 matches but doesn't win (shadowed)
        let r2 = result.rules.iter().find(|r| r.name == "r2").unwrap();
        assert!(r2.all_match);
        assert!(!r2.is_winner);

        assert_eq!(result.winner, Some("r1".to_string()));
        assert_eq!(result.final_action, Action::Pass);
    }

    #[test]
    fn trace_partial_field_match() {
        let mc = MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            ip_protocol: Some(6),
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        };
        let rules = vec![make_rule("web", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=17,dst_port=80").unwrap();
        let result = trace_packet(&config, &pkt);

        assert_eq!(result.rules.len(), 1);
        assert!(!result.rules[0].all_match);
        // ethertype OK, ip_protocol FAIL, dst_port OK
        let fields = &result.rules[0].fields;
        let et = fields.iter().find(|f| f.field == "ethertype").unwrap();
        assert!(et.matches);
        let proto = fields.iter().find(|f| f.field == "ip_protocol").unwrap();
        assert!(!proto.matches);
        let port = fields.iter().find(|f| f.field == "dst_port").unwrap();
        assert!(port.matches);
    }

    #[test]
    fn trace_shows_all_rules() {
        let mc1 = MatchCriteria { ethertype: Some("0x0806".to_string()), ..Default::default() };
        let mc2 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc3 = MatchCriteria { ethertype: Some("0x86DD".to_string()), ..Default::default() };
        let rules = vec![
            make_rule("arp", 300, Action::Pass, mc1),
            make_rule("ipv4", 200, Action::Pass, mc2),
            make_rule("ipv6", 100, Action::Pass, mc3),
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        // All 3 rules evaluated
        assert_eq!(result.rules.len(), 3);
        // ipv4 wins (matches, highest priority among matching)
        assert_eq!(result.winner, Some("ipv4".to_string()));
    }

    #[test]
    fn trace_format_text() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);
        let text = format_trace(&result, "ethertype=0x0800");

        assert!(text.contains("PacGate Packet Trace"));
        assert!(text.contains("[WIN]"));
        assert!(text.contains("r1"));
        assert!(text.contains("OK"));
    }

    #[test]
    fn trace_format_text_miss() {
        let mc = MatchCriteria { ethertype: Some("0x0806".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);
        let text = format_trace(&result, "ethertype=0x0800");

        assert!(text.contains("[MISS]"));
        assert!(text.contains("FAIL"));
        assert!(text.contains("DEFAULT -> DROP"));
    }

    #[test]
    fn trace_json_output() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);
        let json = trace_to_json(&result, "ethertype=0x0800");

        assert_eq!(json["status"], "ok");
        assert_eq!(json["winner"], "r1");
        assert_eq!(json["decision"], "pass");
        assert_eq!(json["rule_count"], 1);
        assert_eq!(json["match_count"], 1);
        assert_eq!(json["rules"][0]["is_winner"], true);
    }

    #[test]
    fn trace_json_no_match() {
        let mc = MatchCriteria { ethertype: Some("0x0806".to_string()), ..Default::default() };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);
        let json = trace_to_json(&result, "ethertype=0x0800");

        assert_eq!(json["status"], "ok");
        assert!(json["winner"].is_null());
        assert_eq!(json["decision"], "drop");
        assert_eq!(json["is_default"], true);
        assert_eq!(json["match_count"], 0);
    }

    #[test]
    fn trace_empty_criteria_matches_all() {
        let mc = MatchCriteria::default();
        let rules = vec![make_rule("catch_all", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        assert_eq!(result.rules.len(), 1);
        assert!(result.rules[0].all_match);
        assert!(result.rules[0].is_winner);
    }

    #[test]
    fn trace_shadowed_rule_shown() {
        let mc1 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc2 = MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            ip_protocol: Some(6),
            ..Default::default()
        };
        let rules = vec![
            make_rule("broad", 200, Action::Pass, mc1),
            make_rule("narrow", 100, Action::Pass, mc2),
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=6").unwrap();
        let result = trace_packet(&config, &pkt);

        // broad wins (higher priority), narrow matches but is shadowed
        assert!(result.rules[0].is_winner);
        assert_eq!(result.rules[0].name, "broad");
        assert!(result.rules[1].all_match);
        assert!(!result.rules[1].is_winner);
    }

    #[test]
    fn trace_with_rewrite() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let rw = RewriteAction {
            set_dst_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            set_ttl: Some(64),
            ..Default::default()
        };
        let mut rule = make_rule("r1", 100, Action::Pass, mc);
        rule.rewrite = Some(rw);
        let config = make_config(vec![rule], Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        assert!(result.rules[0].rewrite.is_some());
        let rw = result.rules[0].rewrite.as_ref().unwrap();
        assert_eq!(rw.set_dst_mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(rw.set_ttl, Some(64));
    }

    #[test]
    fn trace_pipeline_stages() {
        let mc1 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc2 = MatchCriteria { ip_protocol: Some(6), ..Default::default() };
        let stage1 = PipelineStage {
            name: "l2_filter".to_string(),
            rules: vec![make_rule("allow_ipv4", 100, Action::Pass, mc1)],
            default_action: Action::Drop,
            next_table: None,
        };
        let stage2 = PipelineStage {
            name: "l4_filter".to_string(),
            rules: vec![make_rule("allow_tcp", 100, Action::Pass, mc2)],
            default_action: Action::Drop,
            next_table: None,
        };
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: Vec::new(),
                conntrack: None,
                tables: Some(vec![stage1, stage2]),
            },
        };
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=6").unwrap();
        let pt = trace_pipeline(&config, &pkt);

        assert_eq!(pt.stages.len(), 2);
        assert_eq!(pt.stages[0].name, "l2_filter");
        assert_eq!(pt.stages[1].name, "l4_filter");
        assert_eq!(pt.final_action, Action::Pass);

        // JSON
        let json = pipeline_trace_to_json(&pt, "ethertype=0x0800,ip_protocol=6");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["final_decision"], "pass");
        assert_eq!(json["stage_count"], 2);
    }

    #[test]
    fn trace_pipeline_stage_drops() {
        let mc1 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc2 = MatchCriteria { ip_protocol: Some(6), ..Default::default() };
        let stage1 = PipelineStage {
            name: "l2_filter".to_string(),
            rules: vec![make_rule("allow_ipv4", 100, Action::Pass, mc1)],
            default_action: Action::Drop,
            next_table: None,
        };
        let stage2 = PipelineStage {
            name: "l4_filter".to_string(),
            rules: vec![make_rule("allow_tcp", 100, Action::Pass, mc2)],
            default_action: Action::Drop,
            next_table: None,
        };
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: Vec::new(),
                conntrack: None,
                tables: Some(vec![stage1, stage2]),
            },
        };
        // UDP packet — stage2 will drop
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=17").unwrap();
        let pt = trace_pipeline(&config, &pkt);

        assert_eq!(pt.final_action, Action::Drop);
    }

    #[test]
    fn trace_pipeline_text_format() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let stage = PipelineStage {
            name: "filter".to_string(),
            rules: vec![make_rule("r1", 100, Action::Pass, mc)],
            default_action: Action::Drop,
            next_table: None,
        };
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: Vec::new(),
                conntrack: None,
                tables: Some(vec![stage]),
            },
        };
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let pt = trace_pipeline(&config, &pkt);
        let text = format_pipeline_trace(&pt, "ethertype=0x0800");

        assert!(text.contains("Pipeline Packet Trace"));
        assert!(text.contains("Stage 0: filter"));
        assert!(text.contains("[WIN]"));
    }

    #[test]
    fn trace_match_count_accuracy() {
        let mc1 = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mc2 = MatchCriteria { ethertype: Some("0x0806".to_string()), ..Default::default() };
        let mc3 = MatchCriteria { ethertype: Some("0x0800".to_string()), ip_protocol: Some(6), ..Default::default() };
        let rules = vec![
            make_rule("r1", 300, Action::Pass, mc1),
            make_rule("r2", 200, Action::Pass, mc2),
            make_rule("r3", 100, Action::Pass, mc3),
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=6").unwrap();
        let result = trace_packet(&config, &pkt);
        let json = trace_to_json(&result, "");

        assert_eq!(json["match_count"], 2); // r1 and r3 match, r2 doesn't
        assert_eq!(json["rule_count"], 3);
    }

    #[test]
    fn trace_cidr_field_values() {
        let mc = MatchCriteria {
            src_ip: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("src_ip=10.1.2.3").unwrap();
        let result = trace_packet(&config, &pkt);

        assert!(result.rules[0].all_match);
        let field = result.rules[0].fields.iter().find(|f| f.field == "src_ip").unwrap();
        assert!(field.matches);
        assert_eq!(field.rule_value, "10.0.0.0/8");
        assert_eq!(field.packet_value, "10.1.2.3");
    }

    #[test]
    fn trace_port_range_field() {
        let mc = MatchCriteria {
            dst_port: Some(PortMatch::Range { range: [1024, 65535] }),
            ..Default::default()
        };
        let rules = vec![make_rule("r1", 100, Action::Pass, mc)];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("dst_port=8080").unwrap();
        let result = trace_packet(&config, &pkt);

        assert!(result.rules[0].all_match);
        let field = result.rules[0].fields.iter().find(|f| f.field == "dst_port").unwrap();
        assert!(field.matches);
    }

    #[test]
    fn trace_egress_actions() {
        let mc = MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() };
        let mut rule = make_rule("r1", 100, Action::Pass, mc);
        rule.mirror_port = Some(3);
        rule.redirect_port = Some(5);
        rule.rss_queue = Some(7);
        rule.int_insert = Some(true);
        let config = make_config(vec![rule], Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = trace_packet(&config, &pkt);

        let rt = &result.rules[0];
        assert!(rt.is_winner);
        assert_eq!(rt.mirror_port, Some(3));
        assert_eq!(rt.redirect_port, Some(5));
        assert_eq!(rt.rss_queue, Some(7));
        assert!(rt.int_insert);
    }
}
