use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, parse_ethertype};

pub fn generate(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_dir = output_dir.join("tb");
    std::fs::create_dir_all(&tb_dir)?;

    // Sort rules by priority (highest first) — same order as verilog_gen
    let mut rules = config.flippy.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Build test cases from stateless rules only (stateful rules need sequence tests)
    let mut test_cases: Vec<std::collections::HashMap<String, String>> = Vec::new();

    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let ethertype = if let Some(ref et) = rule.match_criteria.ethertype {
            format!("0x{:04X}", parse_ethertype(et)?)
        } else {
            "0x0800".to_string()
        };

        let dst_mac = if let Some(ref mac) = rule.match_criteria.dst_mac {
            generate_matching_mac(mac)
        } else {
            "de:ad:be:ef:00:01".to_string()
        };

        let src_mac = if let Some(ref mac) = rule.match_criteria.src_mac {
            generate_matching_mac(mac)
        } else {
            "02:00:00:00:00:01".to_string()
        };

        let expect_pass = rule.action() == Action::Pass;

        let mut tc = std::collections::HashMap::new();
        tc.insert("name".to_string(), format!("test_{}_match", rule.name));
        tc.insert("description".to_string(), format!("Rule '{}' should {}", rule.name, if expect_pass { "PASS" } else { "DROP" }));
        tc.insert("ethertype".to_string(), ethertype.clone());
        tc.insert("dst_mac".to_string(), dst_mac);
        tc.insert("src_mac".to_string(), src_mac);
        tc.insert("expect_pass".to_string(), expect_pass.to_string());
        tc.insert("has_vlan".to_string(), rule.match_criteria.vlan_id.is_some().to_string());
        tc.insert("vlan_id".to_string(), rule.match_criteria.vlan_id.unwrap_or(0).to_string());
        tc.insert("vlan_pcp".to_string(), rule.match_criteria.vlan_pcp.unwrap_or(0).to_string());
        test_cases.push(tc);
    }

    // Add negative test: a frame that should hit default action
    let default_pass = config.flippy.defaults.action == Action::Pass;
    {
        let mut tc = std::collections::HashMap::new();
        tc.insert("name".to_string(), "test_default_action".to_string());
        tc.insert("description".to_string(), format!("Unmatched frame should hit default ({})", if default_pass { "pass" } else { "drop" }));
        tc.insert("ethertype".to_string(), "0x88B5".to_string());
        tc.insert("dst_mac".to_string(), "00:00:00:00:00:99".to_string());
        tc.insert("src_mac".to_string(), "00:00:00:00:00:88".to_string());
        tc.insert("expect_pass".to_string(), default_pass.to_string());
        tc.insert("has_vlan".to_string(), "false".to_string());
        tc.insert("vlan_id".to_string(), "0".to_string());
        tc.insert("vlan_pcp".to_string(), "0".to_string());
        test_cases.push(tc);
    }

    // Build scoreboard rule definitions for the verification framework (stateless only)
    let mut scoreboard_rules: Vec<std::collections::HashMap<String, String>> = Vec::new();
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let mut sr = std::collections::HashMap::new();
        sr.insert("name".to_string(), rule.name.clone());
        sr.insert("priority".to_string(), rule.priority.to_string());
        sr.insert("action".to_string(), if rule.action() == Action::Pass { "pass".to_string() } else { "drop".to_string() });

        if let Some(ref et) = rule.match_criteria.ethertype {
            sr.insert("ethertype".to_string(), format!("0x{:04X}", parse_ethertype(et)?));
        }
        if let Some(ref mac) = rule.match_criteria.dst_mac {
            sr.insert("dst_mac".to_string(), mac.clone());
        }
        if let Some(ref mac) = rule.match_criteria.src_mac {
            sr.insert("src_mac".to_string(), mac.clone());
        }
        if let Some(vid) = rule.match_criteria.vlan_id {
            sr.insert("vlan_id".to_string(), vid.to_string());
        }
        if let Some(pcp) = rule.match_criteria.vlan_pcp {
            sr.insert("vlan_pcp".to_string(), pcp.to_string());
        }
        scoreboard_rules.push(sr);
    }

    // Render test harness
    {
        let mut ctx = tera::Context::new();
        ctx.insert("test_cases", &test_cases);
        ctx.insert("module_name", "packet_filter_top");
        ctx.insert("default_action", if default_pass { "pass" } else { "drop" });
        ctx.insert("scoreboard_rules", &scoreboard_rules);
        ctx.insert("num_rules", &rules.len());

        let rendered = tera.render("test_harness.py.tera", &ctx)?;
        std::fs::write(tb_dir.join("test_packet_filter.py"), &rendered)?;
        log::info!("Generated test_packet_filter.py");
    }

    // Render Makefile
    {
        let mut ctx = tera::Context::new();
        ctx.insert("module_name", "packet_filter_top");

        let rtl_gen_dir = output_dir.join("rtl");
        let mut verilog_files: Vec<String> = Vec::new();
        verilog_files.push("../../rtl/frame_parser.v".to_string());

        if rtl_gen_dir.exists() {
            let mut entries: Vec<_> = std::fs::read_dir(&rtl_gen_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "v").unwrap_or(false))
                .collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                verilog_files.push(format!("../rtl/{}", entry.file_name().to_string_lossy()));
            }
        }

        ctx.insert("verilog_files", &verilog_files);

        let rendered = tera.render("test_makefile.tera", &ctx)?;
        std::fs::write(tb_dir.join("Makefile"), &rendered)?;
        log::info!("Generated tb/Makefile");
    }

    Ok(())
}

/// Generate a MAC address that matches a rule pattern (replacing * with concrete values)
fn generate_matching_mac(pattern: &str) -> String {
    pattern.split(':')
        .map(|octet| {
            if octet == "*" {
                "aa".to_string()
            } else {
                octet.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}
