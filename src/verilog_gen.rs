use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, Ipv4Prefix, MacAddress, PortMatch, parse_ethertype};

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

    // L3: IPv4 source IP (CIDR prefix matching)
    if let Some(ref ip) = mc.src_ip {
        let prefix = Ipv4Prefix::parse(ip)?;
        if prefix.prefix_len == 32 {
            conditions.push(format!("(src_ip == {})", prefix.to_verilog_value()));
        } else {
            conditions.push(format!(
                "((src_ip & {}) == ({} & {}))",
                prefix.to_verilog_mask(), prefix.to_verilog_value(), prefix.to_verilog_mask()
            ));
        }
    }

    // L3: IPv4 destination IP (CIDR prefix matching)
    if let Some(ref ip) = mc.dst_ip {
        let prefix = Ipv4Prefix::parse(ip)?;
        if prefix.prefix_len == 32 {
            conditions.push(format!("(dst_ip == {})", prefix.to_verilog_value()));
        } else {
            conditions.push(format!(
                "((dst_ip & {}) == ({} & {}))",
                prefix.to_verilog_mask(), prefix.to_verilog_value(), prefix.to_verilog_mask()
            ));
        }
    }

    // L3: IP protocol
    if let Some(proto) = mc.ip_protocol {
        conditions.push(format!("(ip_protocol == 8'd{})", proto));
    }

    // L4: Source port (exact or range)
    if let Some(ref pm) = mc.src_port {
        match pm {
            PortMatch::Exact(port) => {
                conditions.push(format!("(src_port == 16'd{})", port));
            }
            PortMatch::Range { range } => {
                conditions.push(format!(
                    "(src_port >= 16'd{} && src_port <= 16'd{})",
                    range[0], range[1]
                ));
            }
        }
    }

    // L4: Destination port (exact or range)
    if let Some(ref pm) = mc.dst_port {
        match pm {
            PortMatch::Exact(port) => {
                conditions.push(format!("(dst_port == 16'd{})", port));
            }
            PortMatch::Range { range } => {
                conditions.push(format!(
                    "(dst_port >= 16'd{} && dst_port <= 16'd{})",
                    range[0], range[1]
                ));
            }
        }
    }

    // VXLAN VNI
    if let Some(vni) = mc.vxlan_vni {
        conditions.push(format!("(vxlan_vni == 24'd{})", vni));
    }

    // Byte-offset matching
    if let Some(ref byte_matches) = mc.byte_match {
        for bm in byte_matches {
            let val = bm.to_verilog_value()?;
            let mask = bm.to_verilog_mask()?;
            let has_mask = bm.mask.is_some();
            if has_mask {
                conditions.push(format!(
                    "((byte_cap_{} & {}) == ({} & {}))",
                    bm.offset, mask, val, mask
                ));
            } else {
                conditions.push(format!(
                    "(byte_cap_{} == {})",
                    bm.offset, val
                ));
            }
        }
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
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Collect byte_match offsets for byte_capture generation
    let byte_offsets = collect_byte_match_offsets(config);

    // Separate stateless and stateful rules (both get indices in priority order)
    for (idx, rule) in rules.iter().enumerate() {
        if rule.is_stateful() {
            // Generate FSM module (with HSM flattening if needed)
            generate_fsm_rule(&tera, &rtl_dir, idx, rule, &byte_offsets)?;
        } else {
            // Generate combinational matcher
            generate_stateless_rule(&tera, &rtl_dir, idx, rule, &byte_offsets)?;
        }
    }

    // Generate decision logic
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());
        let default_pass = config.pacgate.defaults.action == Action::Pass;
        ctx.insert("default_pass", &default_pass);

        // Calculate index bit width
        let idx_bits = if rules.is_empty() { 1 } else {
            ((rules.len() as f64).log2().ceil() as usize).max(1)
        };
        ctx.insert("idx_bits", &idx_bits);

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

    // Generate byte_capture module if needed
    let has_byte_capture = !byte_offsets.is_empty();
    if has_byte_capture {
        let mut ctx = tera::Context::new();
        let captures: Vec<std::collections::HashMap<String, serde_json::Value>> = byte_offsets.iter().map(|(offset, len)| {
            let mut map = std::collections::HashMap::new();
            map.insert("offset".to_string(), serde_json::json!(offset));
            map.insert("byte_len".to_string(), serde_json::json!(len));
            map.insert("bit_width".to_string(), serde_json::json!(len * 8));
            map
        }).collect();
        ctx.insert("captures", &captures);
        let rendered = tera.render("byte_capture.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("byte_capture.v"), &rendered)?;
        log::info!("Generated byte_capture.v");
    }

    // Generate top-level
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());
        ctx.insert("has_byte_capture", &has_byte_capture);

        let byte_cap_info: Vec<std::collections::HashMap<String, serde_json::Value>> = byte_offsets.iter().map(|(offset, len)| {
            let mut map = std::collections::HashMap::new();
            map.insert("offset".to_string(), serde_json::json!(offset));
            map.insert("bit_width".to_string(), serde_json::json!(len * 8));
            map
        }).collect();
        ctx.insert("byte_captures", &byte_cap_info);

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

/// Copy hand-written AXI-Stream RTL modules to the output directory.
pub fn copy_axi_rtl(output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let axi_files = [
        "axi_stream_adapter.v",
        "store_forward_fifo.v",
        "packet_filter_axi_top.v",
    ];

    for filename in &axi_files {
        let src = Path::new("rtl").join(filename);
        let dst = rtl_dir.join(filename);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("Failed to copy {} to output", filename))?;
        log::info!("Copied {} to {}", filename, dst.display());
    }

    Ok(())
}

/// Copy hand-written counter + AXI-Lite CSR RTL modules to the output directory.
pub fn copy_counter_rtl(output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let counter_files = [
        "rule_counters.v",
        "axi_lite_csr.v",
    ];

    for filename in &counter_files {
        let src = Path::new("rtl").join(filename);
        let dst = rtl_dir.join(filename);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("Failed to copy {} to output", filename))?;
        log::info!("Copied {} to {}", filename, dst.display());
    }

    Ok(())
}

/// Collect all unique (offset, byte_length) pairs across all rules
pub fn collect_byte_match_offsets(config: &FilterConfig) -> Vec<(u16, usize)> {
    let mut offsets: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for rule in &config.pacgate.rules {
        let mc = if rule.is_stateful() {
            // Check transitions in FSM rules
            if let Some(ref fsm) = rule.fsm {
                for state in fsm.states.values() {
                    for trans in &state.transitions {
                        if let Some(ref bms) = trans.match_criteria.byte_match {
                            for bm in bms {
                                if let Ok(len) = bm.byte_len() {
                                    offsets.entry(bm.offset).and_modify(|e| *e = (*e).max(len)).or_insert(len);
                                }
                            }
                        }
                    }
                }
            }
            continue;
        } else {
            &rule.match_criteria
        };
        if let Some(ref bms) = mc.byte_match {
            for bm in bms {
                if let Ok(len) = bm.byte_len() {
                    offsets.entry(bm.offset).and_modify(|e| *e = (*e).max(len)).or_insert(len);
                }
            }
        }
    }
    offsets.into_iter().collect()
}

fn generate_stateless_rule(
    tera: &Tera, rtl_dir: &Path, idx: usize, rule: &crate::model::StatelessRule,
    byte_offsets: &[(u16, usize)],
) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("rule_index", &idx);
    ctx.insert("rule_name", &rule.name);
    ctx.insert("condition_expr", &build_condition_expr(&rule.match_criteria)?);
    ctx.insert("action_pass", &(rule.action() == Action::Pass));

    let has_byte_capture = !byte_offsets.is_empty();
    ctx.insert("has_byte_capture", &has_byte_capture);
    let byte_cap_info: Vec<std::collections::HashMap<String, serde_json::Value>> = byte_offsets.iter().map(|(offset, len)| {
        let mut map = std::collections::HashMap::new();
        map.insert("offset".to_string(), serde_json::json!(offset));
        map.insert("bit_width".to_string(), serde_json::json!(len * 8));
        map
    }).collect();
    ctx.insert("byte_captures", &byte_cap_info);

    let rendered = tera.render("rule_match.v.tera", &ctx)
        .with_context(|| format!("Failed to render rule_match for rule {}", rule.name))?;
    let filename = format!("rule_match_{}.v", idx);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {}", filename);
    Ok(())
}

/// Flatten hierarchical FSM states into flat "parent.child" states.
/// Also returns merged transitions (children inherit parent transitions).
pub fn flatten_fsm(fsm: &crate::model::FsmDefinition) -> Result<crate::model::FsmDefinition> {
    use crate::model::{FsmState, FsmDefinition};
    let mut flat_states = std::collections::HashMap::new();

    fn flatten_recursive(
        prefix: &str,
        states: &std::collections::HashMap<String, FsmState>,
        parent_transitions: &[crate::model::FsmTransition],
        parent_on_entry: &[String],
        parent_on_exit: &[String],
        flat: &mut std::collections::HashMap<String, FsmState>,
        depth: usize,
    ) -> Result<()> {
        if depth > 4 {
            anyhow::bail!("HSM nesting depth exceeds maximum of 4 levels");
        }
        for (name, state) in states {
            let flat_name = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}.{}", prefix, name)
            };

            if let Some(ref substates) = state.substates {
                // Composite state: recurse into substates
                // Merge entry/exit actions: parent first, then child
                let mut merged_on_entry = parent_on_entry.to_vec();
                if let Some(ref entry) = state.on_entry {
                    merged_on_entry.extend(entry.clone());
                }
                let mut merged_on_exit = Vec::new();
                if let Some(ref exit) = state.on_exit {
                    merged_on_exit.extend(exit.clone());
                }
                merged_on_exit.extend(parent_on_exit.to_vec());

                // Children inherit parent transitions as fallback
                let mut merged_transitions = state.transitions.clone();
                for pt in parent_transitions {
                    // Prefix the next_state if it's a child of same composite
                    let mut new_pt = pt.clone();
                    if substates.contains_key(&pt.next_state) {
                        new_pt.next_state = format!("{}.{}", flat_name, pt.next_state);
                    }
                    merged_transitions.push(new_pt);
                }

                flatten_recursive(
                    &flat_name, substates, &merged_transitions,
                    &merged_on_entry, &merged_on_exit, flat, depth + 1,
                )?;
            } else {
                // Leaf state: merge with parent transitions/actions
                let mut merged_transitions = state.transitions.clone();
                // Resolve sibling references: if next_state is a sibling, prefix with parent
                for trans in &mut merged_transitions {
                    if states.contains_key(&trans.next_state) && !trans.next_state.contains('.') {
                        if !prefix.is_empty() {
                            trans.next_state = format!("{}.{}", prefix, trans.next_state);
                        }
                    }
                }
                merged_transitions.extend(parent_transitions.to_vec());

                let mut merged_on_entry = parent_on_entry.to_vec();
                if let Some(ref entry) = state.on_entry {
                    merged_on_entry.extend(entry.clone());
                }
                let mut merged_on_exit = Vec::new();
                if let Some(ref exit) = state.on_exit {
                    merged_on_exit.extend(exit.clone());
                }
                merged_on_exit.extend(parent_on_exit.to_vec());

                flat.insert(flat_name, FsmState {
                    timeout_cycles: state.timeout_cycles,
                    transitions: merged_transitions,
                    substates: None,
                    initial_substate: None,
                    on_entry: if merged_on_entry.is_empty() { None } else { Some(merged_on_entry) },
                    on_exit: if merged_on_exit.is_empty() { None } else { Some(merged_on_exit) },
                    history: None,
                });
            }
        }
        Ok(())
    }

    flatten_recursive("", &fsm.states, &[], &[], &[], &mut flat_states, 0)?;

    // Resolve initial_state: if it points to a composite, use composite.initial_substate
    let initial = resolve_initial_state(&fsm.initial_state, &fsm.states);

    Ok(FsmDefinition {
        initial_state: initial,
        states: flat_states,
        variables: fsm.variables.clone(),
    })
}

/// Resolve initial state through composite hierarchy
fn resolve_initial_state(
    state_name: &str,
    states: &std::collections::HashMap<String, crate::model::FsmState>,
) -> String {
    if let Some(state) = states.get(state_name) {
        if let Some(ref substates) = state.substates {
            if let Some(ref initial_sub) = state.initial_substate {
                let flat_name = format!("{}.{}", state_name, initial_sub);
                // Recurse in case substate is also composite
                if let Some(sub) = substates.get(initial_sub.as_str()) {
                    if sub.substates.is_some() {
                        return resolve_initial_state(initial_sub, substates)
                            .split('.')
                            .collect::<Vec<_>>()
                            .join(".");
                    }
                }
                return flat_name;
            }
        }
    }
    state_name.to_string()
}

/// Convert guard expression to Verilog (replace variable names with var_ prefix)
pub fn guard_to_verilog(guard: &str, variables: &[crate::model::FsmVariable]) -> String {
    let mut result = guard.to_string();
    // Sort by name length descending to avoid partial replacements
    let mut sorted_vars: Vec<_> = variables.iter().collect();
    sorted_vars.sort_by(|a, b| b.name.len().cmp(&a.name.len()));
    for var in &sorted_vars {
        result = result.replace(&var.name, &format!("var_{}", var.name));
    }
    result
}

/// Parse FSM action expression into Verilog assignment
/// Supported: "var = expr", "var += expr", "var -= expr", "var |= expr"
pub fn parse_fsm_action(action: &str, variables: &[crate::model::FsmVariable]) -> Result<String> {
    let action = action.trim();

    // Try compound assignment operators first
    for op in &["|=", "+=", "-="] {
        if let Some(idx) = action.find(op) {
            let var_name = action[..idx].trim();
            let expr = action[idx + op.len()..].trim();
            let verilog_op = match *op {
                "+=" => "+",
                "-=" => "-",
                "|=" => "|",
                _ => unreachable!(),
            };
            let width = variables.iter().find(|v| v.name == var_name)
                .map(|v| v.width).unwrap_or(16);
            return Ok(format!("var_{} <= var_{} {} {}'d{};",
                var_name, var_name, verilog_op, width, expr));
        }
    }

    // Simple assignment
    if let Some(idx) = action.find('=') {
        let var_name = action[..idx].trim();
        let expr = action[idx + 1..].trim();
        let width = variables.iter().find(|v| v.name == var_name)
            .map(|v| v.width).unwrap_or(16);
        // Check if expr is a simple number
        if let Ok(val) = expr.parse::<u64>() {
            return Ok(format!("var_{} <= {}'d{};", var_name, width, val));
        }
        // Complex expression: replace variable references
        let mut verilog_expr = expr.to_string();
        let mut sorted_vars: Vec<_> = variables.iter().collect();
        sorted_vars.sort_by(|a, b| b.name.len().cmp(&a.name.len()));
        for var in &sorted_vars {
            verilog_expr = verilog_expr.replace(&var.name, &format!("var_{}", var.name));
        }
        return Ok(format!("var_{} <= {};", var_name, verilog_expr));
    }

    anyhow::bail!("Cannot parse FSM action: '{}'", action);
}

fn generate_fsm_rule(
    tera: &Tera, rtl_dir: &Path, idx: usize, rule: &crate::model::StatelessRule,
    byte_offsets: &[(u16, usize)],
) -> Result<()> {
    let raw_fsm = rule.fsm.as_ref().unwrap();

    // Check if HSM (any state has substates) and flatten if needed
    let has_hsm = raw_fsm.states.values().any(|s| s.substates.is_some());
    let fsm = if has_hsm {
        flatten_fsm(raw_fsm)?
    } else {
        raw_fsm.clone()
    };

    let variables = fsm.variables.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);

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
        // Use underscored name for Verilog identifiers (dots not allowed)
        let verilog_name = sname.replace('.', "_");
        smap.insert("name".to_string(), serde_json::Value::String(verilog_name));
        smap.insert("index".to_string(), serde_json::json!(si));

        let has_timeout = state_def.timeout_cycles.is_some();
        smap.insert("has_timeout".to_string(), serde_json::json!(has_timeout));
        smap.insert("timeout_cycles".to_string(),
            serde_json::json!(state_def.timeout_cycles.unwrap_or(0)));

        // On-entry/exit actions
        let on_entry_actions: Vec<String> = state_def.on_entry.as_ref()
            .map(|actions| actions.iter().filter_map(|a| parse_fsm_action(a, variables).ok()).collect())
            .unwrap_or_default();
        let on_exit_actions: Vec<String> = state_def.on_exit.as_ref()
            .map(|actions| actions.iter().filter_map(|a| parse_fsm_action(a, variables).ok()).collect())
            .unwrap_or_default();
        smap.insert("has_on_entry".to_string(), serde_json::json!(!on_entry_actions.is_empty()));
        smap.insert("on_entry_actions".to_string(), serde_json::json!(on_entry_actions));
        smap.insert("has_on_exit".to_string(), serde_json::json!(!on_exit_actions.is_empty()));
        smap.insert("on_exit_actions".to_string(), serde_json::json!(on_exit_actions));

        let mut transitions = Vec::new();
        for trans in &state_def.transitions {
            let mut tmap = std::collections::HashMap::new();

            // Build condition with optional guard
            let match_cond = build_condition_expr(&trans.match_criteria)?;
            let full_cond = if let Some(ref guard) = trans.guard {
                let guard_verilog = guard_to_verilog(guard, variables);
                format!("{} && ({})", match_cond, guard_verilog)
            } else {
                match_cond
            };
            tmap.insert("condition".to_string(), serde_json::Value::String(full_cond));

            // next_state: dot-separated names get underscored
            let next_verilog = trans.next_state.replace('.', "_");
            let next_idx = state_names.iter().position(|s| {
                s.replace('.', "_") == next_verilog
            }).unwrap_or(0);
            tmap.insert("next_state_idx".to_string(), serde_json::json!(next_idx));
            tmap.insert("next_state_name".to_string(),
                serde_json::Value::String(next_verilog));
            tmap.insert("action_pass".to_string(),
                serde_json::json!(trans.action == Action::Pass));

            // Transition actions
            let trans_actions: Vec<String> = trans.on_transition.as_ref()
                .map(|actions| actions.iter().filter_map(|a| parse_fsm_action(a, variables).ok()).collect())
                .unwrap_or_default();
            tmap.insert("has_on_transition".to_string(), serde_json::json!(!trans_actions.is_empty()));
            tmap.insert("on_transition_actions".to_string(), serde_json::json!(trans_actions));

            transitions.push(serde_json::json!(tmap));
        }
        smap.insert("transitions".to_string(), serde_json::json!(transitions));
        states.push(smap);
    }

    // Build variables info for template
    let var_info: Vec<std::collections::HashMap<String, serde_json::Value>> = variables.iter().map(|v| {
        let mut map = std::collections::HashMap::new();
        map.insert("name".to_string(), serde_json::json!(v.name));
        map.insert("width".to_string(), serde_json::json!(v.width));
        map.insert("reset_value".to_string(), serde_json::json!(v.reset_value));
        map
    }).collect();
    let has_variables = !var_info.is_empty();

    let mut ctx = tera::Context::new();
    ctx.insert("rule_index", &idx);
    ctx.insert("rule_name", &rule.name);
    ctx.insert("state_bits", &state_bits);
    ctx.insert("num_states", &state_names.len());
    ctx.insert("states", &states);
    ctx.insert("has_variables", &has_variables);
    ctx.insert("variables", &var_info);

    let has_byte_capture = !byte_offsets.is_empty();
    ctx.insert("has_byte_capture", &has_byte_capture);
    let byte_cap_info: Vec<std::collections::HashMap<String, serde_json::Value>> = byte_offsets.iter().map(|(offset, len)| {
        let mut map = std::collections::HashMap::new();
        map.insert("offset".to_string(), serde_json::json!(offset));
        map.insert("bit_width".to_string(), serde_json::json!(len * 8));
        map
    }).collect();
    ctx.insert("byte_captures", &byte_cap_info);

    let rendered = tera.render("rule_fsm.v.tera", &ctx)
        .with_context(|| format!("Failed to render rule_fsm for rule {}", rule.name))?;
    let filename = format!("rule_match_{}.v", idx);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {} (FSM)", filename);
    Ok(())
}
