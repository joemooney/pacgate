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

    // Collect byte_match offsets for port generation
    let byte_offsets = collect_byte_match_offsets(config);

    // Separate stateless and stateful rules (both get indices in priority order)
    for (idx, rule) in rules.iter().enumerate() {
        if rule.is_stateful() {
            // Generate FSM module
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

    // Collect byte_match offsets and generate byte_capture module if needed
    let byte_offsets = collect_byte_match_offsets(config);
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

fn generate_fsm_rule(
    tera: &Tera, rtl_dir: &Path, idx: usize, rule: &crate::model::StatelessRule,
    byte_offsets: &[(u16, usize)],
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
