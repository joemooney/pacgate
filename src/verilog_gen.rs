use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, MacAddress, parse_ethertype};

fn build_condition_expr(mc: &crate::model::MatchCriteria) -> Result<String> {
    let mut conditions: Vec<String> = Vec::new();

    if let Some(ref et) = mc.ethertype {
        let val = parse_ethertype(et)?;
        conditions.push(format!("(ethertype == 16'h{:04x})", val));
    }
    if let Some(ref mac) = mc.dst_mac {
        let m = MacAddress::parse(mac)?;
        conditions.push(format!(
            "((dst_mac & {}) == {})",
            m.to_verilog_mask(), m.to_verilog_value()
        ));
    }
    if let Some(ref mac) = mc.src_mac {
        let m = MacAddress::parse(mac)?;
        conditions.push(format!(
            "((src_mac & {}) == {})",
            m.to_verilog_mask(), m.to_verilog_value()
        ));
    }
    if let Some(vid) = mc.vlan_id {
        conditions.push(format!("(vlan_id == 12'd{})", vid));
    }
    if let Some(pcp) = mc.vlan_pcp {
        conditions.push(format!("(vlan_pcp == 3'd{})", pcp));
    }

    Ok(if conditions.is_empty() {
        "1'b1".to_string()
    } else {
        conditions.join(" && ")
    })
}

pub fn generate(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    // Sort rules by priority (highest first)
    let mut rules = config.flippy.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Separate stateless and stateful rules (both get indices in priority order)
    for (idx, rule) in rules.iter().enumerate() {
        if rule.is_stateful() {
            // Generate FSM module
            generate_fsm_rule(&tera, &rtl_dir, idx, rule)?;
        } else {
            // Generate combinational matcher
            generate_stateless_rule(&tera, &rtl_dir, idx, rule)?;
        }
    }

    // Generate decision logic
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());
        let default_pass = config.flippy.defaults.action == Action::Pass;
        ctx.insert("default_pass", &default_pass);

        let rule_info: Vec<_> = rules.iter().enumerate().map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), idx.to_string());
            map.insert("name".to_string(), rule.name.clone());
            let action_pass = if rule.is_stateful() {
                "true".to_string() // FSM handles action internally
            } else {
                (rule.action() == Action::Pass).to_string()
            };
            map.insert("action_pass".to_string(), action_pass);
            map
        }).collect();
        ctx.insert("rules", &rule_info);

        let rendered = tera.render("decision_logic.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("decision_logic.v"), &rendered)?;
        log::info!("Generated decision_logic.v");
    }

    // Generate top-level
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());

        let rule_info: Vec<_> = rules.iter().enumerate().map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), idx.to_string());
            map.insert("name".to_string(), rule.name.clone());
            map.insert("is_fsm".to_string(), rule.is_stateful().to_string());
            map
        }).collect();
        ctx.insert("rules", &rule_info);

        let rendered = tera.render("packet_filter_top.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("packet_filter_top.v"), &rendered)?;
        log::info!("Generated packet_filter_top.v");
    }

    Ok(())
}

fn generate_stateless_rule(
    tera: &Tera, rtl_dir: &Path, idx: usize, rule: &crate::model::StatelessRule,
) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("rule_index", &idx);
    ctx.insert("rule_name", &rule.name);
    ctx.insert("condition_expr", &build_condition_expr(&rule.match_criteria)?);
    ctx.insert("action_pass", &(rule.action() == Action::Pass));

    let rendered = tera.render("rule_match.v.tera", &ctx)
        .with_context(|| format!("Failed to render rule_match for rule {}", rule.name))?;
    let filename = format!("rule_match_{}.v", idx);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {}", filename);
    Ok(())
}

fn generate_fsm_rule(
    tera: &Tera, rtl_dir: &Path, idx: usize, rule: &crate::model::StatelessRule,
) -> Result<()> {
    let fsm = rule.fsm.as_ref().unwrap();

    // Build state list in deterministic order
    let mut state_names: Vec<String> = fsm.states.keys().cloned().collect();
    state_names.sort();
    // Ensure initial state is index 0
    if let Some(pos) = state_names.iter().position(|s| s == &fsm.initial_state) {
        state_names.swap(0, pos);
    }

    let state_bits = (state_names.len() as f64).log2().ceil().max(1.0) as usize;

    // Build state info for template
    let mut states: Vec<std::collections::HashMap<String, serde_json::Value>> = Vec::new();
    for (si, sname) in state_names.iter().enumerate() {
        let state_def = &fsm.states[sname];
        let mut smap = std::collections::HashMap::new();
        smap.insert("name".to_string(), serde_json::Value::String(sname.clone()));
        smap.insert("index".to_string(), serde_json::json!(si));

        let has_timeout = state_def.timeout_cycles.is_some();
        smap.insert("has_timeout".to_string(), serde_json::json!(has_timeout));
        smap.insert("timeout_cycles".to_string(),
            serde_json::json!(state_def.timeout_cycles.unwrap_or(0)));

        let mut transitions = Vec::new();
        for trans in &state_def.transitions {
            let mut tmap = std::collections::HashMap::new();
            tmap.insert("condition".to_string(),
                serde_json::Value::String(build_condition_expr(&trans.match_criteria)?));
            let next_idx = state_names.iter().position(|s| s == &trans.next_state).unwrap();
            tmap.insert("next_state_idx".to_string(), serde_json::json!(next_idx));
            tmap.insert("next_state_name".to_string(),
                serde_json::Value::String(trans.next_state.clone()));
            tmap.insert("action_pass".to_string(),
                serde_json::json!(trans.action == Action::Pass));
            transitions.push(serde_json::json!(tmap));
        }
        smap.insert("transitions".to_string(), serde_json::json!(transitions));
        states.push(smap);
    }

    let mut ctx = tera::Context::new();
    ctx.insert("rule_index", &idx);
    ctx.insert("rule_name", &rule.name);
    ctx.insert("state_bits", &state_bits);
    ctx.insert("num_states", &state_names.len());
    ctx.insert("states", &states);

    let rendered = tera.render("rule_fsm.v.tera", &ctx)
        .with_context(|| format!("Failed to render rule_fsm for rule {}", rule.name))?;
    let filename = format!("rule_match_{}.v", idx);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {} (FSM)", filename);
    Ok(())
}
