use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, MacAddress, parse_ethertype};

pub fn generate(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    // Sort rules by priority (highest first)
    let mut rules = config.flippy.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Generate per-rule matchers
    for (idx, rule) in rules.iter().enumerate() {
        let mut ctx = tera::Context::new();
        ctx.insert("rule_index", &idx);
        ctx.insert("rule_name", &rule.name);

        // Build match conditions
        let mut conditions: Vec<String> = Vec::new();

        if let Some(ref et) = rule.match_criteria.ethertype {
            let val = parse_ethertype(et)?;
            conditions.push(format!("(ethertype == 16'h{:04x})", val));
        }
        if let Some(ref mac) = rule.match_criteria.dst_mac {
            let m = MacAddress::parse(mac)?;
            conditions.push(format!(
                "((dst_mac & {}) == {})",
                m.to_verilog_mask(), m.to_verilog_value()
            ));
        }
        if let Some(ref mac) = rule.match_criteria.src_mac {
            let m = MacAddress::parse(mac)?;
            conditions.push(format!(
                "((src_mac & {}) == {})",
                m.to_verilog_mask(), m.to_verilog_value()
            ));
        }
        if let Some(vid) = rule.match_criteria.vlan_id {
            conditions.push(format!("(vlan_id == 12'd{})", vid));
        }
        if let Some(pcp) = rule.match_criteria.vlan_pcp {
            conditions.push(format!("(vlan_pcp == 3'd{})", pcp));
        }

        let condition_expr = if conditions.is_empty() {
            "1'b1".to_string() // match-all
        } else {
            conditions.join(" && ")
        };

        ctx.insert("condition_expr", &condition_expr);
        ctx.insert("action_pass", &(rule.action == Action::Pass));

        let rendered = tera.render("rule_match.v.tera", &ctx)
            .with_context(|| format!("Failed to render rule_match for rule {}", rule.name))?;
        let filename = format!("rule_match_{}.v", idx);
        std::fs::write(rtl_dir.join(&filename), &rendered)?;
        log::info!("Generated {}", filename);
    }

    // Generate decision logic
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());
        let default_pass = config.flippy.defaults.action == Action::Pass;
        ctx.insert("default_pass", &default_pass);

        // Build rule info for priority encoder
        let rule_info: Vec<_> = rules.iter().enumerate().map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), idx.to_string());
            map.insert("name".to_string(), rule.name.clone());
            map.insert("action_pass".to_string(), (rule.action == Action::Pass).to_string());
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
            map
        }).collect();
        ctx.insert("rules", &rule_info);

        let rendered = tera.render("packet_filter_top.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("packet_filter_top.v"), &rendered)?;
        log::info!("Generated packet_filter_top.v");
    }

    Ok(())
}
