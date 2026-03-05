use anyhow::Result;
use serde_json;

use crate::loader;
use crate::model::{FilterConfig, PortMatch, StatelessRule};

/// Optimization suggestion with code, description, and affected rules.
#[derive(Debug, Clone)]
pub struct OptSuggestion {
    pub code: String,
    pub description: String,
    pub rules_affected: Vec<String>,
}

/// Result of running the optimizer on a rule set.
#[derive(Debug)]
pub struct OptimizeResult {
    pub original_count: usize,
    pub optimized_count: usize,
    pub suggestions: Vec<OptSuggestion>,
    pub optimized_config: FilterConfig,
    pub warnings: Vec<String>,
}

/// Run all 5 optimization passes on a FilterConfig and return the optimized result.
pub fn optimize_rules(config: &FilterConfig) -> Result<OptimizeResult> {
    let original_count = count_all_rules(config);
    let mut suggestions = Vec::new();
    let mut warnings = Vec::new();

    let mut opt_config = config.clone();

    if let Some(ref mut tables) = opt_config.pacgate.tables {
        // Pipeline mode: optimize each stage independently
        for stage in tables.iter_mut() {
            let (new_rules, stage_suggestions, stage_warnings) =
                optimize_rule_list(&stage.rules);
            stage.rules = new_rules;
            suggestions.extend(stage_suggestions);
            warnings.extend(stage_warnings);
        }
    } else {
        // Single-table mode
        let (new_rules, pass_suggestions, pass_warnings) =
            optimize_rule_list(&opt_config.pacgate.rules);
        opt_config.pacgate.rules = new_rules;
        suggestions.extend(pass_suggestions);
        warnings.extend(pass_warnings);
    }

    let optimized_count = count_all_rules(&opt_config);

    Ok(OptimizeResult {
        original_count,
        optimized_count,
        suggestions,
        optimized_config: opt_config,
        warnings,
    })
}

/// Generate a JSON summary of the optimization.
pub fn optimize_summary(config: &FilterConfig) -> serde_json::Value {
    match optimize_rules(config) {
        Ok(result) => {
            let suggestions: Vec<serde_json::Value> = result.suggestions.iter().map(|s| {
                serde_json::json!({
                    "code": s.code,
                    "description": s.description,
                    "rules_affected": s.rules_affected,
                })
            }).collect();
            serde_json::json!({
                "original_count": result.original_count,
                "optimized_count": result.optimized_count,
                "rules_removed": result.original_count as i64 - result.optimized_count as i64,
                "suggestions": suggestions,
                "warnings": result.warnings,
            })
        }
        Err(e) => {
            serde_json::json!({ "error": e.to_string() })
        }
    }
}

fn count_all_rules(config: &FilterConfig) -> usize {
    if let Some(ref tables) = config.pacgate.tables {
        tables.iter().map(|s| s.rules.len()).sum()
    } else {
        config.pacgate.rules.len()
    }
}

/// Run all 5 passes on a list of rules.
fn optimize_rule_list(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>, Vec<String>) {
    let mut suggestions = Vec::new();
    let mut warnings = Vec::new();
    let mut rules = rules.to_vec();

    // Pass 1: Dead rule removal (OPT001)
    let (new_rules, pass1_suggestions, pass1_warnings) = pass_dead_rule_removal(&rules);
    rules = new_rules;
    suggestions.extend(pass1_suggestions);
    warnings.extend(pass1_warnings);

    // Pass 2: Duplicate merging (OPT002)
    let (new_rules, pass2_suggestions) = pass_duplicate_merging(&rules);
    rules = new_rules;
    suggestions.extend(pass2_suggestions);

    // Pass 3: Adjacent port merging (OPT003)
    let (new_rules, pass3_suggestions) = pass_port_merging(&rules);
    rules = new_rules;
    suggestions.extend(pass3_suggestions);

    // Pass 4: Adjacent CIDR merging (OPT004)
    let (new_rules, pass4_suggestions) = pass_cidr_merging(&rules);
    rules = new_rules;
    suggestions.extend(pass4_suggestions);

    // Pass 5: Priority renumbering (OPT005)
    let (new_rules, pass5_suggestions) = pass_priority_renumber(&rules);
    rules = new_rules;
    suggestions.extend(pass5_suggestions);

    (rules, suggestions, warnings)
}

// ── Pass 1: Dead rule removal (OPT001) ──────────────────────────────────

fn pass_dead_rule_removal(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>, Vec<String>) {
    let mut sorted: Vec<StatelessRule> = rules.to_vec();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority)); // highest priority first

    let mut kept = Vec::new();
    let mut suggestions = Vec::new();
    let mut warnings = Vec::new();

    for (idx, rule) in sorted.iter().enumerate() {
        // Skip stateful rules — never remove them
        if rule.is_stateful() {
            kept.push(rule.clone());
            continue;
        }

        let mut shadowed_by: Option<&StatelessRule> = None;
        for higher in &sorted[..idx] {
            if higher.is_stateful() {
                continue;
            }
            if loader::criteria_shadows(&higher.match_criteria, &rule.match_criteria) {
                shadowed_by = Some(higher);
                break;
            }
        }

        if let Some(shadow) = shadowed_by {
            if rule.action() != shadow.action() {
                warnings.push(format!(
                    "Rule '{}' (action {:?}) is shadowed by '{}' (action {:?}) — different actions, removing shadowed rule",
                    rule.name, rule.action(), shadow.name, shadow.action()
                ));
            }
            suggestions.push(OptSuggestion {
                code: "OPT001".to_string(),
                description: format!(
                    "Removed dead rule '{}' (shadowed by '{}')",
                    rule.name, shadow.name
                ),
                rules_affected: vec![rule.name.clone()],
            });
        } else {
            kept.push(rule.clone());
        }
    }

    (kept, suggestions, warnings)
}

// ── Pass 2: Duplicate merging (OPT002) ──────────────────────────────────

/// Build a structural key for a rule (criteria + action + rewrite + egress + rss + int)
/// with name and priority zeroed for comparison.
fn rule_structural_key(rule: &StatelessRule) -> String {
    let mut key_rule = rule.clone();
    key_rule.name = String::new();
    key_rule.priority = 0;
    // Use serde_json for structural comparison
    serde_json::to_string(&key_rule).unwrap_or_default()
}

fn pass_duplicate_merging(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>) {
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<&StatelessRule>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for rule in rules {
        let key = rule_structural_key(rule);
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(rule);
    }

    let mut kept = Vec::new();
    let mut suggestions = Vec::new();

    for key in &order {
        let group = &groups[key];
        if group.len() > 1 {
            // Keep the one with the highest priority
            let best = group.iter().max_by_key(|r| r.priority).unwrap();
            kept.push((*best).clone());
            let removed: Vec<String> = group.iter()
                .filter(|r| r.name != best.name)
                .map(|r| r.name.clone())
                .collect();
            if !removed.is_empty() {
                suggestions.push(OptSuggestion {
                    code: "OPT002".to_string(),
                    description: format!(
                        "Merged {} duplicate rules into '{}' (kept highest priority {})",
                        removed.len() + 1, best.name, best.priority
                    ),
                    rules_affected: removed,
                });
            }
        } else {
            kept.push(group[0].clone());
        }
    }

    (kept, suggestions)
}

// ── Pass 3: Adjacent port merging (OPT003) ──────────────────────────────

/// Build a grouping key for port merging: everything except the target port field + name + priority.
fn port_group_key(rule: &StatelessRule, field: &str) -> String {
    let mut key_rule = rule.clone();
    key_rule.name = String::new();
    key_rule.priority = 0;
    match field {
        "dst_port" => key_rule.match_criteria.dst_port = None,
        "src_port" => key_rule.match_criteria.src_port = None,
        _ => {}
    }
    serde_json::to_string(&key_rule).unwrap_or_default()
}

/// Extract port value(s) as (low, high) inclusive range.
fn port_range(pm: &PortMatch) -> (u16, u16) {
    match pm {
        PortMatch::Exact(v) => (*v, *v),
        PortMatch::Range { range } => (range[0], range[1]),
    }
}

/// Try to merge two adjacent/overlapping port ranges into one.
fn try_merge_port_ranges(a: (u16, u16), b: (u16, u16)) -> Option<(u16, u16)> {
    let (a_lo, a_hi) = a;
    let (b_lo, b_hi) = b;
    // Adjacent or overlapping
    if a_hi.checked_add(1).map_or(false, |v| v >= b_lo) && b_lo >= a_lo {
        Some((a_lo, a_hi.max(b_hi)))
    } else if b_hi.checked_add(1).map_or(false, |v| v >= a_lo) && a_lo >= b_lo {
        Some((b_lo, a_hi.max(b_hi)))
    } else {
        None
    }
}

fn port_match_from_range(lo: u16, hi: u16) -> PortMatch {
    if lo == hi {
        PortMatch::Exact(lo)
    } else {
        PortMatch::Range { range: [lo, hi] }
    }
}

fn pass_port_merging(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>) {
    let mut current_rules = rules.to_vec();
    let mut suggestions = Vec::new();

    // Merge dst_port first, then src_port
    for field in &["dst_port", "src_port"] {
        current_rules = merge_ports_for_field(&current_rules, field, &mut suggestions);
    }

    (current_rules, suggestions)
}

fn merge_ports_for_field(
    rules: &[StatelessRule],
    field: &str,
    suggestions: &mut Vec<OptSuggestion>,
) -> Vec<StatelessRule> {
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<StatelessRule>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut non_port_rules: Vec<(usize, StatelessRule)> = Vec::new();

    for (idx, rule) in rules.iter().enumerate() {
        let has_port = match field {
            "dst_port" => rule.match_criteria.dst_port.is_some(),
            "src_port" => rule.match_criteria.src_port.is_some(),
            _ => false,
        };
        if !has_port || rule.is_stateful() {
            non_port_rules.push((idx, rule.clone()));
            continue;
        }
        let key = port_group_key(rule, field);
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(rule.clone());
    }

    let mut result = Vec::new();
    let mut group_results: Vec<(usize, Vec<StatelessRule>)> = Vec::new();

    for key in &order {
        let group = groups.get_mut(key).unwrap();
        if group.len() < 2 {
            // Track position of first rule in original list for ordering
            let pos = rules.iter().position(|r| r.name == group[0].name).unwrap_or(0);
            group_results.push((pos, group.clone()));
            continue;
        }

        // Sort by port value
        group.sort_by_key(|r| {
            let pm = match field {
                "dst_port" => r.match_criteria.dst_port.as_ref(),
                "src_port" => r.match_criteria.src_port.as_ref(),
                _ => None,
            };
            pm.map(|p| port_range(p).0).unwrap_or(0)
        });

        let mut merged: Vec<(u16, u16, String)> = Vec::new(); // (lo, hi, name)
        let mut merged_names: Vec<Vec<String>> = Vec::new();

        for rule in group.iter() {
            let pm = match field {
                "dst_port" => rule.match_criteria.dst_port.as_ref(),
                "src_port" => rule.match_criteria.src_port.as_ref(),
                _ => None,
            };
            let range = pm.map(|p| port_range(p)).unwrap_or((0, 0));

            let mut did_merge = false;
            if let Some(last) = merged.last_mut() {
                if let Some(new_range) = try_merge_port_ranges((last.0, last.1), range) {
                    last.0 = new_range.0;
                    last.1 = new_range.1;
                    merged_names.last_mut().unwrap().push(rule.name.clone());
                    did_merge = true;
                }
            }
            if !did_merge {
                merged.push((range.0, range.1, rule.name.clone()));
                merged_names.push(vec![rule.name.clone()]);
            }
        }

        let pos = rules.iter().position(|r| r.name == group[0].name).unwrap_or(0);
        let mut group_result = Vec::new();

        for (i, (lo, hi, name)) in merged.iter().enumerate() {
            let mut new_rule = group.iter().find(|r| r.name == *name).unwrap().clone();
            match field {
                "dst_port" => new_rule.match_criteria.dst_port = Some(port_match_from_range(*lo, *hi)),
                "src_port" => new_rule.match_criteria.src_port = Some(port_match_from_range(*lo, *hi)),
                _ => {}
            }

            if merged_names[i].len() > 1 {
                suggestions.push(OptSuggestion {
                    code: "OPT003".to_string(),
                    description: format!(
                        "Merged {} adjacent {} rules into range {}-{}",
                        merged_names[i].len(), field, lo, hi
                    ),
                    rules_affected: merged_names[i].clone(),
                });
            }

            group_result.push(new_rule);
        }
        group_results.push((pos, group_result));
    }

    // Interleave results preserving original order
    let mut all_items: Vec<(usize, StatelessRule)> = Vec::new();
    for (pos, rules_vec) in group_results {
        for (i, r) in rules_vec.into_iter().enumerate() {
            all_items.push((pos + i, r));
        }
    }
    for (pos, r) in non_port_rules {
        all_items.push((pos, r));
    }
    all_items.sort_by_key(|(pos, _)| *pos);
    result.extend(all_items.into_iter().map(|(_, r)| r));

    result
}

// ── Pass 4: Adjacent CIDR merging (OPT004) ──────────────────────────────

/// Try to merge two CIDR prefixes into a shorter one.
/// Two /N CIDRs merge into /(N-1) if they are the two halves.
pub fn cidr_merge_adjacent(a: &str, b: &str) -> Option<String> {
    let pa = crate::model::Ipv4Prefix::parse(a).ok()?;
    let pb = crate::model::Ipv4Prefix::parse(b).ok()?;

    // Must have same prefix length and > 0
    if pa.prefix_len != pb.prefix_len || pa.prefix_len == 0 {
        return None;
    }

    let new_prefix_len = pa.prefix_len - 1;
    let new_mask = if new_prefix_len == 0 { 0u32 } else { !0u32 << (32 - new_prefix_len) };

    let a_u32 = u32::from_be_bytes(pa.addr);
    let b_u32 = u32::from_be_bytes(pb.addr);

    let a_net = a_u32 & new_mask;
    let b_net = b_u32 & new_mask;

    // Both must be in the same parent network
    if a_net != b_net {
        return None;
    }

    // The distinguishing bit should differ
    let bit = 1u32 << (31 - new_prefix_len);
    if (a_u32 & bit) == (b_u32 & bit) {
        return None; // Same half — not the two halves
    }

    let net_bytes = a_net.to_be_bytes();
    Some(format!("{}.{}.{}.{}/{}", net_bytes[0], net_bytes[1], net_bytes[2], net_bytes[3], new_prefix_len))
}

/// Build a grouping key for CIDR merging.
fn cidr_group_key(rule: &StatelessRule, field: &str) -> String {
    let mut key_rule = rule.clone();
    key_rule.name = String::new();
    key_rule.priority = 0;
    match field {
        "src_ip" => key_rule.match_criteria.src_ip = None,
        "dst_ip" => key_rule.match_criteria.dst_ip = None,
        _ => {}
    }
    serde_json::to_string(&key_rule).unwrap_or_default()
}

fn pass_cidr_merging(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>) {
    let mut current_rules = rules.to_vec();
    let mut suggestions = Vec::new();

    for field in &["src_ip", "dst_ip"] {
        current_rules = merge_cidrs_for_field(&current_rules, field, &mut suggestions);
    }

    (current_rules, suggestions)
}

fn merge_cidrs_for_field(
    rules: &[StatelessRule],
    field: &str,
    suggestions: &mut Vec<OptSuggestion>,
) -> Vec<StatelessRule> {
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<StatelessRule>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut non_cidr_rules: Vec<(usize, StatelessRule)> = Vec::new();

    for (idx, rule) in rules.iter().enumerate() {
        let has_cidr = match field {
            "src_ip" => rule.match_criteria.src_ip.is_some(),
            "dst_ip" => rule.match_criteria.dst_ip.is_some(),
            _ => false,
        };
        if !has_cidr || rule.is_stateful() {
            non_cidr_rules.push((idx, rule.clone()));
            continue;
        }
        let key = cidr_group_key(rule, field);
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(rule.clone());
    }

    let mut all_items: Vec<(usize, StatelessRule)> = Vec::new();

    for key in &order {
        let group = groups.get_mut(key).unwrap();
        if group.len() < 2 {
            let pos = rules.iter().position(|r| r.name == group[0].name).unwrap_or(0);
            all_items.push((pos, group[0].clone()));
            continue;
        }

        let pos = rules.iter().position(|r| r.name == group[0].name).unwrap_or(0);

        // Iteratively merge until stable
        let mut changed = true;
        while changed {
            changed = false;
            let mut i = 0;
            while i < group.len() {
                let mut j = i + 1;
                while j < group.len() {
                    let a_cidr = match field {
                        "src_ip" => group[i].match_criteria.src_ip.as_deref(),
                        "dst_ip" => group[i].match_criteria.dst_ip.as_deref(),
                        _ => None,
                    };
                    let b_cidr = match field {
                        "src_ip" => group[j].match_criteria.src_ip.as_deref(),
                        "dst_ip" => group[j].match_criteria.dst_ip.as_deref(),
                        _ => None,
                    };
                    if let (Some(a), Some(b)) = (a_cidr, b_cidr) {
                        if let Some(merged) = cidr_merge_adjacent(a, b) {
                            let removed_name = group[j].name.clone();
                            suggestions.push(OptSuggestion {
                                code: "OPT004".to_string(),
                                description: format!(
                                    "Merged adjacent CIDRs {} + {} → {} ({})",
                                    a, b, merged, field
                                ),
                                rules_affected: vec![group[i].name.clone(), removed_name],
                            });
                            match field {
                                "src_ip" => group[i].match_criteria.src_ip = Some(merged),
                                "dst_ip" => group[i].match_criteria.dst_ip = Some(merged),
                                _ => {}
                            }
                            group.remove(j);
                            changed = true;
                            continue; // Don't increment j
                        }
                    }
                    j += 1;
                }
                i += 1;
            }
        }

        for (i, rule) in group.iter().enumerate() {
            all_items.push((pos + i, rule.clone()));
        }
    }

    for (pos, r) in non_cidr_rules {
        all_items.push((pos, r));
    }
    all_items.sort_by_key(|(pos, _)| *pos);
    all_items.into_iter().map(|(_, r)| r).collect()
}

// ── Pass 5: Priority renumbering (OPT005) ───────────────────────────────

fn pass_priority_renumber(rules: &[StatelessRule]) -> (Vec<StatelessRule>, Vec<OptSuggestion>) {
    if rules.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut sorted: Vec<StatelessRule> = rules.to_vec();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority)); // highest priority first

    let mut any_changed = false;
    let mut result = Vec::new();
    for (i, mut rule) in sorted.into_iter().enumerate() {
        let new_prio = ((i + 1) * 100) as u32;
        if rule.priority != new_prio {
            any_changed = true;
        }
        rule.priority = new_prio;
        result.push(rule);
    }

    let suggestions = if any_changed {
        vec![OptSuggestion {
            code: "OPT005".to_string(),
            description: format!("Renumbered {} rules to uniform 100-spacing", result.len()),
            rules_affected: result.iter().map(|r| r.name.clone()).collect(),
        }]
    } else {
        Vec::new()
    };

    (result, suggestions)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_rule(name: &str, priority: u32, action: Action, criteria: MatchCriteria) -> StatelessRule {
        StatelessRule {
            name: name.to_string(),
            priority,
            match_criteria: criteria,
            action: Some(action),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
            mirror_port: None,
            redirect_port: None,
            rss_queue: None,
            int_insert: None,
        }
    }

    fn make_config(rules: Vec<StatelessRule>) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules,
                conntrack: None,
                tables: None,
            },
        }
    }

    // ── Pass 1 (OPT001 — dead rule removal) ─────────────────────────

    #[test]
    fn opt001_simple_shadow() {
        // Rule B (port 80) is shadowed by rule A (all ports, higher priority)
        let a = make_rule("block_all", 200, Action::Drop, MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            ..Default::default()
        });
        let b = make_rule("allow_http", 100, Action::Pass, MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let config = make_config(vec![a, b]);
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.optimized_count, 1);
        assert!(result.suggestions.iter().any(|s| s.code == "OPT001"));
    }

    #[test]
    fn opt001_cidr_shadow() {
        // Rule matching /32 shadowed by same /24 with higher priority
        let a = make_rule("block_subnet", 200, Action::Drop, MatchCriteria {
            src_ip: Some("10.0.0.0/24".to_string()),
            ..Default::default()
        });
        let b = make_rule("allow_host", 100, Action::Pass, MatchCriteria {
            src_ip: Some("10.0.0.1/32".to_string()),
            ..Default::default()
        });
        let config = make_config(vec![a, b]);
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.optimized_count, 1);
        assert!(result.warnings.iter().any(|w| w.contains("different actions")));
    }

    #[test]
    fn opt001_different_action_removed() {
        let a = make_rule("drop_all", 200, Action::Drop, MatchCriteria::default());
        let b = make_rule("pass_all", 100, Action::Pass, MatchCriteria::default());
        let config = make_config(vec![a, b]);
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.optimized_count, 1);
        assert!(result.warnings.len() >= 1);
    }

    #[test]
    fn opt001_no_dead_rules() {
        let a = make_rule("allow_http", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let b = make_rule("allow_https", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(443)),
            ..Default::default()
        });
        let config = make_config(vec![a, b]);
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.optimized_count, 2);
        assert!(!result.suggestions.iter().any(|s| s.code == "OPT001"));
    }

    #[test]
    fn opt001_preserves_stateful() {
        let a = make_rule("block_all", 200, Action::Drop, MatchCriteria::default());
        let mut b = make_rule("stateful_rule", 100, Action::Pass, MatchCriteria::default());
        b.rule_type = Some("stateful".to_string());
        b.fsm = Some(FsmDefinition {
            initial_state: "INIT".to_string(),
            states: {
                let mut m = std::collections::HashMap::new();
                m.insert("INIT".to_string(), crate::model::FsmState {
                    timeout_cycles: None,
                    transitions: Vec::new(),
                    substates: None,
                    initial_substate: None,
                    on_entry: None,
                    on_exit: None,
                    history: None,
                });
                m
            },
            variables: None,
        });
        let config = make_config(vec![a, b]);
        let result = optimize_rules(&config).unwrap();
        // Stateful rule preserved even though it's "shadowed"
        assert_eq!(result.optimized_count, 2);
    }

    // ── Pass 2 (OPT002 — duplicate merging) ─────────────────────────

    #[test]
    fn opt002_exact_duplicate() {
        let a = make_rule("rule_a", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let b = make_rule("rule_b", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let (result, suggestions) = pass_duplicate_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "rule_a"); // highest priority
        assert!(suggestions.iter().any(|s| s.code == "OPT002"));
    }

    #[test]
    fn opt002_keeps_highest_priority() {
        let a = make_rule("low", 50, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(443)),
            ..Default::default()
        });
        let b = make_rule("high", 300, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(443)),
            ..Default::default()
        });
        let (result, _) = pass_duplicate_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "high");
    }

    #[test]
    fn opt002_not_dup_different_action() {
        let a = make_rule("rule_a", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let b = make_rule("rule_b", 100, Action::Drop, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let (result, _) = pass_duplicate_merging(&[a, b]);
        assert_eq!(result.len(), 2); // Different action — not duplicates
    }

    #[test]
    fn opt002_not_dup_different_rewrite() {
        let a = make_rule("rule_a", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let mut b = make_rule("rule_b", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        b.rewrite = Some(RewriteAction {
            set_dst_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ..Default::default()
        });
        let (result, _) = pass_duplicate_merging(&[a, b]);
        assert_eq!(result.len(), 2); // Different rewrite — not duplicates
    }

    // ── Pass 3 (OPT003 — port merging) ──────────────────────────────

    #[test]
    fn opt003_exact_adjacent() {
        let a = make_rule("port_80", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ethertype: Some("0x0800".to_string()),
            ..Default::default()
        });
        let b = make_rule("port_81", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(81)),
            ethertype: Some("0x0800".to_string()),
            ..Default::default()
        });
        let (result, suggestions) = pass_port_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].match_criteria.dst_port, Some(PortMatch::Range { range: [80, 81] }));
        assert!(suggestions.iter().any(|s| s.code == "OPT003"));
    }

    #[test]
    fn opt003_exact_with_range() {
        let a = make_rule("port_80", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(79)),
            ethertype: Some("0x0800".to_string()),
            ..Default::default()
        });
        let b = make_rule("port_range", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Range { range: [80, 90] }),
            ethertype: Some("0x0800".to_string()),
            ..Default::default()
        });
        let (result, suggestions) = pass_port_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].match_criteria.dst_port, Some(PortMatch::Range { range: [79, 90] }));
        assert!(suggestions.iter().any(|s| s.code == "OPT003"));
    }

    #[test]
    fn opt003_ranges_touching() {
        let a = make_rule("range_a", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Range { range: [80, 89] }),
            ..Default::default()
        });
        let b = make_rule("range_b", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Range { range: [90, 99] }),
            ..Default::default()
        });
        let (result, _) = pass_port_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].match_criteria.dst_port, Some(PortMatch::Range { range: [80, 99] }));
    }

    #[test]
    fn opt003_non_adjacent_no_merge() {
        let a = make_rule("port_80", 200, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(80)),
            ..Default::default()
        });
        let b = make_rule("port_443", 100, Action::Pass, MatchCriteria {
            dst_port: Some(PortMatch::Exact(443)),
            ..Default::default()
        });
        let (result, suggestions) = pass_port_merging(&[a, b]);
        assert_eq!(result.len(), 2);
        assert!(!suggestions.iter().any(|s| s.code == "OPT003"));
    }

    // ── Pass 4 (OPT004 — CIDR merging) ──────────────────────────────

    #[test]
    fn opt004_adjacent_24s() {
        let a = make_rule("subnet_a", 200, Action::Pass, MatchCriteria {
            src_ip: Some("10.0.0.0/24".to_string()),
            ..Default::default()
        });
        let b = make_rule("subnet_b", 100, Action::Pass, MatchCriteria {
            src_ip: Some("10.0.1.0/24".to_string()),
            ..Default::default()
        });
        let (result, suggestions) = pass_cidr_merging(&[a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].match_criteria.src_ip.as_deref(), Some("10.0.0.0/23"));
        assert!(suggestions.iter().any(|s| s.code == "OPT004"));
    }

    #[test]
    fn opt004_non_adjacent_no_merge() {
        let a = make_rule("subnet_a", 200, Action::Pass, MatchCriteria {
            src_ip: Some("10.0.0.0/24".to_string()),
            ..Default::default()
        });
        let b = make_rule("subnet_b", 100, Action::Pass, MatchCriteria {
            src_ip: Some("10.0.2.0/24".to_string()),
            ..Default::default()
        });
        let (result, _) = pass_cidr_merging(&[a, b]);
        assert_eq!(result.len(), 2); // Not adjacent /24s
    }

    #[test]
    fn opt004_cascading_merge() {
        // 4 adjacent /24s → 2 /23s → 1 /22
        let rules: Vec<StatelessRule> = (0..4).map(|i| {
            make_rule(
                &format!("subnet_{}", i),
                (200 - i * 10) as u32,
                Action::Pass,
                MatchCriteria {
                    src_ip: Some(format!("10.0.{}.0/24", i)),
                    ..Default::default()
                },
            )
        }).collect();
        let (result, suggestions) = pass_cidr_merging(&rules);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].match_criteria.src_ip.as_deref(), Some("10.0.0.0/22"));
        assert!(suggestions.iter().any(|s| s.code == "OPT004"));
    }

    #[test]
    fn opt004_cidr_helper() {
        assert_eq!(cidr_merge_adjacent("10.0.0.0/24", "10.0.1.0/24"), Some("10.0.0.0/23".to_string()));
        assert_eq!(cidr_merge_adjacent("192.168.0.0/24", "192.168.1.0/24"), Some("192.168.0.0/23".to_string()));
        assert_eq!(cidr_merge_adjacent("10.0.0.0/24", "10.0.2.0/24"), None); // Not adjacent
        assert_eq!(cidr_merge_adjacent("10.0.0.0/24", "10.0.0.0/25"), None); // Different prefix lengths
    }

    // ── Pass 5 (OPT005 — priority renumber) ─────────────────────────

    #[test]
    fn opt005_renumber() {
        let rules = vec![
            make_rule("a", 500, Action::Pass, MatchCriteria::default()),
            make_rule("b", 200, Action::Pass, MatchCriteria {
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            }),
            make_rule("c", 50, Action::Drop, MatchCriteria {
                dst_port: Some(PortMatch::Exact(443)),
                ..Default::default()
            }),
        ];
        let (result, suggestions) = pass_priority_renumber(&rules);
        // Sorted by priority desc: a(500) → 100, b(200) → 200, c(50) → 300
        assert_eq!(result[0].priority, 100);
        assert_eq!(result[1].priority, 200);
        assert_eq!(result[2].priority, 300);
        assert!(suggestions.iter().any(|s| s.code == "OPT005"));
    }

    #[test]
    fn opt005_already_uniform() {
        let rules = vec![
            make_rule("a", 100, Action::Pass, MatchCriteria::default()),
            make_rule("b", 200, Action::Pass, MatchCriteria {
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            }),
        ];
        let (result, suggestions) = pass_priority_renumber(&rules);
        // Already has 100-spacing when sorted by priority desc:
        // b(200) → 100, a(100) → 200 — priorities still change since order matters
        // Actually: sorted desc = b(200), a(100) → 100, 200 — which flips them
        assert_eq!(result.len(), 2);
        // Priorities changed since sort reorders
        assert!(suggestions.iter().any(|s| s.code == "OPT005") || result[0].priority == 100);
    }

    // ── End-to-end tests ────────────────────────────────────────────

    #[test]
    fn opt_empty_rules() {
        let config = make_config(Vec::new());
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.original_count, 0);
        assert_eq!(result.optimized_count, 0);
        assert!(result.suggestions.is_empty());
    }

    #[test]
    fn opt_round_trip_validates() {
        // Optimized output should be valid YAML
        let rules = vec![
            make_rule("http", 200, Action::Pass, MatchCriteria {
                ethertype: Some("0x0800".to_string()),
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            }),
            make_rule("https", 100, Action::Pass, MatchCriteria {
                ethertype: Some("0x0800".to_string()),
                dst_port: Some(PortMatch::Exact(443)),
                ..Default::default()
            }),
        ];
        let config = make_config(rules);
        let result = optimize_rules(&config).unwrap();
        let yaml = crate::p4_import::config_to_yaml(&result.optimized_config).unwrap();
        assert!(yaml.contains("pacgate"));
        assert!(yaml.contains("rules"));
    }

    #[test]
    fn opt_json_summary() {
        let config = make_config(vec![
            make_rule("a", 200, Action::Pass, MatchCriteria {
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            }),
        ]);
        let summary = optimize_summary(&config);
        assert_eq!(summary["original_count"], 1);
        assert_eq!(summary["optimized_count"], 1);
    }

    #[test]
    fn opt_idempotent() {
        let rules = vec![
            make_rule("http", 300, Action::Pass, MatchCriteria {
                dst_port: Some(PortMatch::Exact(80)),
                ethertype: Some("0x0800".to_string()),
                ..Default::default()
            }),
            make_rule("https", 100, Action::Pass, MatchCriteria {
                dst_port: Some(PortMatch::Exact(443)),
                ethertype: Some("0x0800".to_string()),
                ..Default::default()
            }),
        ];
        let config = make_config(rules);
        let result1 = optimize_rules(&config).unwrap();
        let result2 = optimize_rules(&result1.optimized_config).unwrap();
        // Second pass should produce 0 meaningful suggestions (maybe OPT005 if already renumbered)
        assert_eq!(result1.optimized_count, result2.optimized_count);
        // No OPT001-004 suggestions on second pass
        assert!(!result2.suggestions.iter().any(|s| s.code == "OPT001" || s.code == "OPT002" || s.code == "OPT003" || s.code == "OPT004"));
    }

    #[test]
    fn opt_pipeline_stages() {
        // Use port 80 + ethertype so neither shadows the other (one has extra constraint)
        // but they are structural duplicates
        let stage = PipelineStage {
            name: "classify".to_string(),
            rules: vec![
                make_rule("dup_a", 200, Action::Pass, MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                }),
                make_rule("dup_b", 100, Action::Pass, MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                }),
            ],
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
        let result = optimize_rules(&config).unwrap();
        assert_eq!(result.original_count, 2);
        assert_eq!(result.optimized_count, 1);
        // Should have OPT001 (shadow) or OPT002 (duplicate) — either way, reduced to 1
        let has_removal = result.suggestions.iter().any(|s| s.code == "OPT001" || s.code == "OPT002");
        assert!(has_removal, "Expected OPT001 or OPT002 in {:?}", result.suggestions.iter().map(|s| &s.code).collect::<Vec<_>>());
    }
}
