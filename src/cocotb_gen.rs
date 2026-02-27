use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, PortMatch, parse_ethertype};

pub fn generate(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_dir = output_dir.join("tb");
    std::fs::create_dir_all(&tb_dir)?;

    // Sort rules by priority (highest first) — same order as verilog_gen
    let mut rules = config.pacgate.rules.clone();
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
        // L3/L4 fields
        tc.insert("has_l3".to_string(), rule.match_criteria.uses_l3l4().to_string());
        if let Some(ref ip) = rule.match_criteria.src_ip {
            tc.insert("src_ip".to_string(), generate_matching_ip(ip));
        }
        if let Some(ref ip) = rule.match_criteria.dst_ip {
            tc.insert("dst_ip".to_string(), generate_matching_ip(ip));
        }
        if let Some(proto) = rule.match_criteria.ip_protocol {
            tc.insert("ip_protocol".to_string(), proto.to_string());
        }
        if let Some(ref pm) = rule.match_criteria.src_port {
            tc.insert("src_port".to_string(), generate_matching_port(pm));
        }
        if let Some(ref pm) = rule.match_criteria.dst_port {
            tc.insert("dst_port".to_string(), generate_matching_port(pm));
        }
        test_cases.push(tc);
    }

    // Add negative test: a frame that should hit default action
    let default_pass = config.pacgate.defaults.action == Action::Pass;
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
        // L3/L4 scoreboard fields
        if let Some(ref ip) = rule.match_criteria.src_ip {
            sr.insert("src_ip".to_string(), ip.clone());
        }
        if let Some(ref ip) = rule.match_criteria.dst_ip {
            sr.insert("dst_ip".to_string(), ip.clone());
        }
        if let Some(proto) = rule.match_criteria.ip_protocol {
            sr.insert("ip_protocol".to_string(), proto.to_string());
        }
        if let Some(ref pm) = rule.match_criteria.src_port {
            match pm {
                PortMatch::Exact(p) => { sr.insert("src_port".to_string(), p.to_string()); }
                PortMatch::Range { range } => { sr.insert("src_port_range".to_string(), format!("{}-{}", range[0], range[1])); }
            }
        }
        if let Some(ref pm) = rule.match_criteria.dst_port {
            match pm {
                PortMatch::Exact(p) => { sr.insert("dst_port".to_string(), p.to_string()); }
                PortMatch::Range { range } => { sr.insert("dst_port_range".to_string(), format!("{}-{}", range[0], range[1])); }
            }
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

    // Render property test file
    {
        let mut ctx = tera::Context::new();
        ctx.insert("scoreboard_rules", &scoreboard_rules);
        ctx.insert("default_action", if default_pass { "pass" } else { "drop" });

        let rendered = tera.render("test_properties.py.tera", &ctx)?;
        std::fs::write(tb_dir.join("test_properties.py"), &rendered)?;
        log::info!("Generated test_properties.py");
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

/// Generate AXI-Stream cocotb tests in a separate tb-axi directory.
pub fn generate_axi_tests(_config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_axi_dir = output_dir.join("tb-axi");
    std::fs::create_dir_all(&tb_axi_dir)?;

    // Render AXI test harness
    {
        let ctx = tera::Context::new();
        let rendered = tera.render("test_axi_harness.py.tera", &ctx)?;
        std::fs::write(tb_axi_dir.join("test_axi_packet_filter.py"), &rendered)?;
        log::info!("Generated test_axi_packet_filter.py");
    }

    // Render AXI test Makefile
    {
        let rtl_gen_dir = output_dir.join("rtl");
        let mut verilog_files: Vec<String> = Vec::new();

        // Hand-written RTL
        verilog_files.push("../../rtl/frame_parser.v".to_string());

        // AXI infrastructure (copied to gen/rtl by copy_axi_rtl)
        verilog_files.push("../rtl/axi_stream_adapter.v".to_string());
        verilog_files.push("../rtl/store_forward_fifo.v".to_string());
        verilog_files.push("../rtl/packet_filter_axi_top.v".to_string());

        // Generated rule RTL
        if rtl_gen_dir.exists() {
            let mut entries: Vec<_> = std::fs::read_dir(&rtl_gen_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.ends_with(".v")
                        && name != "axi_stream_adapter.v"
                        && name != "store_forward_fifo.v"
                        && name != "packet_filter_axi_top.v"
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                verilog_files.push(format!("../rtl/{}", entry.file_name().to_string_lossy()));
            }
        }

        // Write a simple Makefile for the AXI testbench
        let makefile_content = format!(
            "# Makefile for AXI-Stream cocotb simulation\n\
             # Generated by pacgate — do not edit\n\
             \n\
             SIM ?= icarus\n\
             TOPLEVEL_LANG ?= verilog\n\
             TOPLEVEL = packet_filter_axi_top\n\
             COCOTB_TEST_MODULES = test_axi_packet_filter\n\
             \n\
             VERILOG_SOURCES = {}\n\
             \n\
             include $(shell cocotb-config --makefiles)/Makefile.sim\n",
            verilog_files.join(" ")
        );
        std::fs::write(tb_axi_dir.join("Makefile"), &makefile_content)?;
        log::info!("Generated tb-axi/Makefile");
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

/// Generate an IP address that matches a CIDR pattern
fn generate_matching_ip(cidr: &str) -> String {
    if let Ok(prefix) = crate::model::Ipv4Prefix::parse(cidr) {
        // Return the network address itself (valid match for any prefix)
        format!("{}.{}.{}.{}", prefix.addr[0], prefix.addr[1], prefix.addr[2], prefix.addr[3])
    } else {
        "10.0.0.1".to_string()
    }
}

/// Generate a port number that matches a PortMatch
fn generate_matching_port(pm: &PortMatch) -> String {
    match pm {
        PortMatch::Exact(p) => p.to_string(),
        PortMatch::Range { range } => range[0].to_string(),
    }
}
