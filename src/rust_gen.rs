use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{
    Action, FilterConfig, Ipv4Prefix, Ipv6Prefix, MacAddress, MatchCriteria, PortMatch,
    parse_ethertype,
};

/// Protocol usage flags for conditional code generation
#[derive(Debug, Clone, serde::Serialize)]
pub struct RustProtocols {
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    pub has_tcp: bool,
    pub has_udp: bool,
    pub has_vlan: bool,
    pub has_vxlan: bool,
    pub has_gtp: bool,
    pub has_mpls: bool,
    pub has_gre: bool,
    pub has_geneve: bool,
    pub has_arp: bool,
    pub has_icmp: bool,
    pub has_icmpv6: bool,
    pub has_oam: bool,
    pub has_nsh: bool,
    pub has_ptp: bool,
    pub has_qinq: bool,
}

/// A pre-computed constant for CIDR/MAC matching
#[derive(Debug, Clone, serde::Serialize)]
pub struct RustConstant {
    pub name: String,
    pub rust_type: String,
    pub value: String,
}

/// A condition check in a rule matcher
#[derive(Debug, Clone, serde::Serialize)]
pub struct RustCondition {
    pub field: String,
    pub fail_expr: String,
}

/// A compiled rule for the Rust filter
#[derive(Debug, Clone, serde::Serialize)]
pub struct RustRule {
    pub name: String,
    pub priority: u32,
    pub action: String,
    pub index: usize,
    pub conditions: Vec<RustCondition>,
    pub constants: Vec<RustConstant>,
}

/// Generate a standalone Rust packet filter project from a PacGate YAML config.
pub fn generate_rust(
    config: &FilterConfig,
    templates_dir: &Path,
    output_dir: &Path,
) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rust_dir = output_dir.join("rust");
    let src_dir = rust_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    let protocols = detect_protocols(config);
    let rules = build_rust_rules(config)?;
    let default_action = match config.pacgate.defaults.action {
        Action::Pass => "Pass",
        Action::Drop => "Drop",
    };

    let has_mac_wildcard = config.all_rules().iter().any(|r| {
        has_mac_wildcard_field(&r.match_criteria.dst_mac)
            || has_mac_wildcard_field(&r.match_criteria.src_mac)
    });
    let has_ipv6_cidr = config.all_rules().iter().any(|r| {
        r.match_criteria.src_ipv6.is_some() || r.match_criteria.dst_ipv6.is_some()
    });
    let has_byte_match = config
        .all_rules()
        .iter()
        .any(|r| r.match_criteria.uses_byte_match());

    let rules_file = "rules.yaml";

    let mut ctx = tera::Context::new();
    ctx.insert("protocols", &protocols);
    ctx.insert("rules_sorted", &rules);
    ctx.insert("default_action", default_action);
    ctx.insert("num_rules", &rules.len());
    ctx.insert("has_mac_wildcard", &has_mac_wildcard);
    ctx.insert("has_ipv6_cidr", &has_ipv6_cidr);
    ctx.insert("has_byte_match", &has_byte_match);
    ctx.insert("is_pipeline", &config.is_pipeline());
    ctx.insert("rules_file", rules_file);

    // Pipeline stages
    if config.is_pipeline() {
        let stages = config.pacgate.tables.as_ref().unwrap();
        let mut stage_infos: Vec<serde_json::Value> = Vec::new();
        for (si, stage) in stages.iter().enumerate() {
            let stage_rules = build_rust_rules_from_slice(&stage.rules, si)?;
            stage_infos.push(serde_json::json!({
                "index": si,
                "name": stage.name,
                "rules": stage_rules,
            }));
        }
        ctx.insert("stages", &stage_infos);
    }

    // Render Cargo.toml
    let cargo = tera.render("rust_cargo.toml.tera", &ctx)?;
    std::fs::write(rust_dir.join("Cargo.toml"), &cargo)?;
    log::info!("Generated Cargo.toml");

    // Render main.rs
    let main_rs = tera.render("rust_filter.rs.tera", &ctx)?;
    std::fs::write(src_dir.join("main.rs"), &main_rs)?;
    log::info!("Generated src/main.rs");

    Ok(())
}

/// Generate Rust export summary as JSON
pub fn generate_rust_summary(config: &FilterConfig) -> serde_json::Value {
    let protocols = detect_protocols(config);
    let all_rules = config.all_rules();
    let has_stateful = all_rules.iter().any(|r| r.is_stateful());

    let mut unsupported: Vec<String> = Vec::new();
    if has_stateful {
        unsupported.push(
            "Stateful FSM rules are not supported in Rust backend (skipped)".to_string(),
        );
    }

    serde_json::json!({
        "status": "ok",
        "target": "rust",
        "rules_count": all_rules.len(),
        "stateless_rules": all_rules.iter().filter(|r| !r.is_stateful()).count(),
        "stateful_rules": all_rules.iter().filter(|r| r.is_stateful()).count(),
        "is_pipeline": config.is_pipeline(),
        "stage_count": config.stage_count(),
        "default_action": match config.pacgate.defaults.action {
            Action::Pass => "pass",
            Action::Drop => "drop",
        },
        "protocols": {
            "ipv4": protocols.has_ipv4,
            "ipv6": protocols.has_ipv6,
            "tcp": protocols.has_tcp,
            "udp": protocols.has_udp,
            "vlan": protocols.has_vlan,
            "vxlan": protocols.has_vxlan,
            "gtp": protocols.has_gtp,
            "mpls": protocols.has_mpls,
            "gre": protocols.has_gre,
            "geneve": protocols.has_geneve,
            "arp": protocols.has_arp,
            "icmp": protocols.has_icmp,
            "icmpv6": protocols.has_icmpv6,
            "oam": protocols.has_oam,
            "nsh": protocols.has_nsh,
            "ptp": protocols.has_ptp,
            "qinq": protocols.has_qinq,
        },
        "unsupported_features": unsupported,
        "build_command": "cd gen/rust && cargo build --release",
        "run_command": "gen/rust/target/release/pacgate_filter input.pcap --output filtered.pcap",
    })
}

/// Detect which protocols are used across all rules
fn detect_protocols(config: &FilterConfig) -> RustProtocols {
    let all_rules = config.all_rules();
    let mut p = RustProtocols {
        has_ipv4: false,
        has_ipv6: false,
        has_tcp: false,
        has_udp: false,
        has_vlan: false,
        has_vxlan: false,
        has_gtp: false,
        has_mpls: false,
        has_gre: false,
        has_geneve: false,
        has_arp: false,
        has_icmp: false,
        has_icmpv6: false,
        has_oam: false,
        has_nsh: false,
        has_ptp: false,
        has_qinq: false,
    };

    for rule in &all_rules {
        let mc = &rule.match_criteria;

        if mc.src_ip.is_some()
            || mc.dst_ip.is_some()
            || mc.ip_protocol.is_some()
            || mc.ip_dscp.is_some()
            || mc.ip_ecn.is_some()
            || mc.ip_ttl.is_some()
            || mc.ip_dont_fragment.is_some()
            || mc.ip_more_fragments.is_some()
            || mc.ip_frag_offset.is_some()
        {
            p.has_ipv4 = true;
        }
        if mc.ethertype.as_deref() == Some("0x0800") {
            p.has_ipv4 = true;
        }
        if mc.uses_ipv6() || mc.uses_ipv6_tc() || mc.uses_ipv6_ext() {
            p.has_ipv6 = true;
        }
        if mc.ethertype.as_deref() == Some("0x86DD") {
            p.has_ipv6 = true;
        }
        if mc.tcp_flags.is_some() || mc.conntrack_state.is_some() {
            p.has_tcp = true;
        }
        if mc.src_port.is_some() || mc.dst_port.is_some() {
            p.has_tcp = true;
            p.has_udp = true;
        }
        if mc.vlan_id.is_some() || mc.vlan_pcp.is_some() {
            p.has_vlan = true;
        }
        if mc.vxlan_vni.is_some() {
            p.has_vxlan = true;
            p.has_udp = true;
        }
        if mc.gtp_teid.is_some() {
            p.has_gtp = true;
            p.has_udp = true;
        }
        if mc.uses_mpls() {
            p.has_mpls = true;
        }
        if mc.uses_gre() {
            p.has_gre = true;
            p.has_ipv4 = true;
        }
        if mc.uses_geneve() {
            p.has_geneve = true;
            p.has_udp = true;
        }
        if mc.uses_arp() {
            p.has_arp = true;
        }
        if mc.uses_icmp() {
            p.has_icmp = true;
            p.has_ipv4 = true;
        }
        if mc.uses_icmpv6() {
            p.has_icmpv6 = true;
            p.has_ipv6 = true;
        }
        if mc.uses_oam() {
            p.has_oam = true;
        }
        if mc.uses_nsh() {
            p.has_nsh = true;
        }
        if mc.uses_ptp() {
            p.has_ptp = true;
        }
        if mc.uses_qinq() {
            p.has_qinq = true;
            p.has_vlan = true;
        }
        if mc.igmp_type.is_some() {
            p.has_ipv4 = true;
        }
        if mc.mld_type.is_some() {
            p.has_ipv6 = true;
            p.has_icmpv6 = true;
        }

        if let Some(proto) = mc.ip_protocol {
            if proto == 6 {
                p.has_tcp = true;
            }
            if proto == 17 {
                p.has_udp = true;
            }
            if proto == 1 {
                p.has_icmp = true;
            }
            if proto == 47 {
                p.has_gre = true;
            }
        }
    }

    p
}

/// Build sorted Vec of RustRule from config (all rules, non-pipeline)
fn build_rust_rules(config: &FilterConfig) -> Result<Vec<RustRule>> {
    let mut rules: Vec<_> = config
        .all_rules()
        .iter()
        .filter(|r| !r.is_stateful())
        .cloned()
        .cloned()
        .collect();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut result = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let (conditions, constants) = build_rust_condition(&rule.match_criteria, i)?;
        let action = match rule.action() {
            Action::Pass => "Pass".to_string(),
            Action::Drop => "Drop".to_string(),
        };
        result.push(RustRule {
            name: rule.name.clone(),
            priority: rule.priority,
            action,
            index: i,
            conditions,
            constants,
        });
    }
    Ok(result)
}

/// Build sorted Vec of RustRule from a slice of rules (for pipeline stages)
fn build_rust_rules_from_slice(
    rules: &[crate::model::StatelessRule],
    stage_idx: usize,
) -> Result<Vec<RustRule>> {
    let mut sorted: Vec<_> = rules.iter().filter(|r| !r.is_stateful()).collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut result = Vec::new();
    for (i, rule) in sorted.iter().enumerate() {
        let global_idx = stage_idx * 1000 + i;
        let (conditions, constants) = build_rust_condition(&rule.match_criteria, global_idx)?;
        let action = match rule.action() {
            Action::Pass => "Pass".to_string(),
            Action::Drop => "Drop".to_string(),
        };
        result.push(RustRule {
            name: rule.name.clone(),
            priority: rule.priority,
            action,
            index: i,
            conditions,
            constants,
        });
    }
    Ok(result)
}

/// Convert MatchCriteria to a list of Rust condition expressions
pub fn build_rust_condition(
    mc: &MatchCriteria,
    rule_idx: usize,
) -> Result<(Vec<RustCondition>, Vec<RustConstant>)> {
    let mut conds = Vec::new();
    let mut consts = Vec::new();

    // Ethertype
    if let Some(ref et) = mc.ethertype {
        let val = parse_ethertype(et)?;
        conds.push(RustCondition {
            field: "ethertype".to_string(),
            fail_expr: format!("pkt.ethertype != Some(0x{:04x})", val),
        });
    }

    // VLAN
    if let Some(vid) = mc.vlan_id {
        conds.push(RustCondition {
            field: "vlan_id".to_string(),
            fail_expr: format!("pkt.vlan_id != Some({})", vid),
        });
    }
    if let Some(pcp) = mc.vlan_pcp {
        conds.push(RustCondition {
            field: "vlan_pcp".to_string(),
            fail_expr: format!("pkt.vlan_pcp != Some({})", pcp),
        });
    }

    // QinQ
    if let Some(ovid) = mc.outer_vlan_id {
        conds.push(RustCondition {
            field: "outer_vlan_id".to_string(),
            fail_expr: format!("pkt.outer_vlan_id != Some({})", ovid),
        });
    }
    if let Some(opcp) = mc.outer_vlan_pcp {
        conds.push(RustCondition {
            field: "outer_vlan_pcp".to_string(),
            fail_expr: format!("pkt.outer_vlan_pcp != Some({})", opcp),
        });
    }

    // MAC addresses
    for (field, mac_str) in [("dst_mac", &mc.dst_mac), ("src_mac", &mc.src_mac)] {
        if let Some(ref ms) = mac_str {
            let mac = MacAddress::parse(ms)?;
            if mac.mask == [0xFF; 6] {
                // Exact match — inline
                let bytes: Vec<String> = mac.value.iter().map(|b| format!("0x{:02x}", b)).collect();
                conds.push(RustCondition {
                    field: field.to_string(),
                    fail_expr: format!("pkt.{} != [{}]", field, bytes.join(", ")),
                });
            } else {
                // Wildcard match — use helper
                let val_name = format!("RULE_{}_{}_VAL", rule_idx, field.to_uppercase());
                let mask_name = format!("RULE_{}_{}_MASK", rule_idx, field.to_uppercase());
                let val_bytes: Vec<String> =
                    mac.value.iter().map(|b| format!("0x{:02x}", b)).collect();
                let mask_bytes: Vec<String> =
                    mac.mask.iter().map(|b| format!("0x{:02x}", b)).collect();
                consts.push(RustConstant {
                    name: val_name.clone(),
                    rust_type: "[u8; 6]".to_string(),
                    value: format!("[{}]", val_bytes.join(", ")),
                });
                consts.push(RustConstant {
                    name: mask_name.clone(),
                    rust_type: "[u8; 6]".to_string(),
                    value: format!("[{}]", mask_bytes.join(", ")),
                });
                conds.push(RustCondition {
                    field: field.to_string(),
                    fail_expr: format!("!mac_match(&pkt.{}, &{}, &{})", field, val_name, mask_name),
                });
            }
        }
    }

    // IPv4 CIDR
    for (field, ip_str) in [("src_ip", &mc.src_ip), ("dst_ip", &mc.dst_ip)] {
        if let Some(ref s) = ip_str {
            let pfx = Ipv4Prefix::parse(s)?;
            let ip_u32 = u32::from_be_bytes(pfx.addr);
            let mask_u32 = u32::from_be_bytes(pfx.mask);
            if pfx.prefix_len == 32 {
                conds.push(RustCondition {
                    field: field.to_string(),
                    fail_expr: format!("pkt.{} != Some(0x{:08x})", field, ip_u32),
                });
            } else {
                conds.push(RustCondition {
                    field: field.to_string(),
                    fail_expr: format!(
                        "pkt.{}.map_or(true, |ip| (ip & 0x{:08x}) != 0x{:08x})",
                        field,
                        mask_u32,
                        ip_u32 & mask_u32
                    ),
                });
            }
        }
    }

    // ip_protocol
    if let Some(proto) = mc.ip_protocol {
        conds.push(RustCondition {
            field: "ip_protocol".to_string(),
            fail_expr: format!("pkt.ip_protocol != Some({})", proto),
        });
    }

    // L4 ports
    for (field, pm) in [("src_port", &mc.src_port), ("dst_port", &mc.dst_port)] {
        if let Some(ref p) = pm {
            match p {
                PortMatch::Exact(v) => {
                    conds.push(RustCondition {
                        field: field.to_string(),
                        fail_expr: format!("pkt.{} != Some({})", field, v),
                    });
                }
                PortMatch::Range { range } => {
                    conds.push(RustCondition {
                        field: field.to_string(),
                        fail_expr: format!(
                            "pkt.{}.map_or(true, |p| p < {} || p > {})",
                            field, range[0], range[1]
                        ),
                    });
                }
            }
        }
    }

    // IPv6 CIDR
    for (field, ipv6_str) in [("src_ipv6", &mc.src_ipv6), ("dst_ipv6", &mc.dst_ipv6)] {
        if let Some(ref s) = ipv6_str {
            let pfx = Ipv6Prefix::parse(s)?;
            let const_pfx = format!("RULE_{}_{}_PFX", rule_idx, field.to_uppercase());
            let const_mask = format!("RULE_{}_{}_MASK", rule_idx, field.to_uppercase());
            let pfx_bytes: Vec<String> = pfx.addr.iter().map(|b| format!("0x{:02x}", b)).collect();
            // Apply mask to prefix bytes
            let masked: Vec<String> = pfx
                .addr
                .iter()
                .zip(pfx.mask.iter())
                .map(|(a, m)| format!("0x{:02x}", a & m))
                .collect();
            let mask_bytes: Vec<String> =
                pfx.mask.iter().map(|b| format!("0x{:02x}", b)).collect();
            // Store masked prefix, not raw
            let _ = pfx_bytes; // raw not needed
            consts.push(RustConstant {
                name: const_pfx.clone(),
                rust_type: "[u8; 16]".to_string(),
                value: format!("[{}]", masked.join(", ")),
            });
            consts.push(RustConstant {
                name: const_mask.clone(),
                rust_type: "[u8; 16]".to_string(),
                value: format!("[{}]", mask_bytes.join(", ")),
            });
            conds.push(RustCondition {
                field: field.to_string(),
                fail_expr: format!(
                    "!ipv6_match(&pkt.{}, &{}, &{})",
                    field, const_pfx, const_mask
                ),
            });
        }
    }

    if let Some(nh) = mc.ipv6_next_header {
        conds.push(RustCondition {
            field: "ipv6_next_header".to_string(),
            fail_expr: format!("pkt.ipv6_next_header != Some({})", nh),
        });
    }

    // DSCP/ECN
    if let Some(v) = mc.ip_dscp {
        conds.push(RustCondition {
            field: "ip_dscp".to_string(),
            fail_expr: format!("pkt.ip_dscp != Some({})", v),
        });
    }
    if let Some(v) = mc.ip_ecn {
        conds.push(RustCondition {
            field: "ip_ecn".to_string(),
            fail_expr: format!("pkt.ip_ecn != Some({})", v),
        });
    }
    if let Some(v) = mc.ipv6_dscp {
        conds.push(RustCondition {
            field: "ipv6_dscp".to_string(),
            fail_expr: format!("pkt.ipv6_dscp != Some({})", v),
        });
    }
    if let Some(v) = mc.ipv6_ecn {
        conds.push(RustCondition {
            field: "ipv6_ecn".to_string(),
            fail_expr: format!("pkt.ipv6_ecn != Some({})", v),
        });
    }

    // TCP flags with mask
    if let Some(flags) = mc.tcp_flags {
        let mask = mc.tcp_flags_mask.unwrap_or(0xFF);
        conds.push(RustCondition {
            field: "tcp_flags".to_string(),
            fail_expr: format!(
                "pkt.tcp_flags.map_or(true, |f| (f & 0x{:02x}) != 0x{:02x})",
                mask,
                flags & mask
            ),
        });
    }

    // ICMP
    if let Some(v) = mc.icmp_type {
        conds.push(RustCondition {
            field: "icmp_type".to_string(),
            fail_expr: format!("pkt.icmp_type != Some({})", v),
        });
    }
    if let Some(v) = mc.icmp_code {
        conds.push(RustCondition {
            field: "icmp_code".to_string(),
            fail_expr: format!("pkt.icmp_code != Some({})", v),
        });
    }

    // ICMPv6
    if let Some(v) = mc.icmpv6_type {
        conds.push(RustCondition {
            field: "icmpv6_type".to_string(),
            fail_expr: format!("pkt.icmpv6_type != Some({})", v),
        });
    }
    if let Some(v) = mc.icmpv6_code {
        conds.push(RustCondition {
            field: "icmpv6_code".to_string(),
            fail_expr: format!("pkt.icmpv6_code != Some({})", v),
        });
    }

    // ARP
    if let Some(v) = mc.arp_opcode {
        conds.push(RustCondition {
            field: "arp_opcode".to_string(),
            fail_expr: format!("pkt.arp_opcode != Some({})", v),
        });
    }
    if let Some(ref s) = mc.arp_spa {
        let pfx = Ipv4Prefix::parse(s)?;
        let ip_u32 = u32::from_be_bytes(pfx.addr);
        let mask_u32 = u32::from_be_bytes(pfx.mask);
        if pfx.prefix_len == 32 {
            conds.push(RustCondition {
                field: "arp_spa".to_string(),
                fail_expr: format!("pkt.arp_spa != Some(0x{:08x})", ip_u32),
            });
        } else {
            conds.push(RustCondition {
                field: "arp_spa".to_string(),
                fail_expr: format!(
                    "pkt.arp_spa.map_or(true, |ip| (ip & 0x{:08x}) != 0x{:08x})",
                    mask_u32,
                    ip_u32 & mask_u32
                ),
            });
        }
    }
    if let Some(ref s) = mc.arp_tpa {
        let pfx = Ipv4Prefix::parse(s)?;
        let ip_u32 = u32::from_be_bytes(pfx.addr);
        let mask_u32 = u32::from_be_bytes(pfx.mask);
        if pfx.prefix_len == 32 {
            conds.push(RustCondition {
                field: "arp_tpa".to_string(),
                fail_expr: format!("pkt.arp_tpa != Some(0x{:08x})", ip_u32),
            });
        } else {
            conds.push(RustCondition {
                field: "arp_tpa".to_string(),
                fail_expr: format!(
                    "pkt.arp_tpa.map_or(true, |ip| (ip & 0x{:08x}) != 0x{:08x})",
                    mask_u32,
                    ip_u32 & mask_u32
                ),
            });
        }
    }

    // IPv6 extension fields
    if let Some(v) = mc.ipv6_hop_limit {
        conds.push(RustCondition {
            field: "ipv6_hop_limit".to_string(),
            fail_expr: format!("pkt.ipv6_hop_limit != Some({})", v),
        });
    }
    if let Some(v) = mc.ipv6_flow_label {
        conds.push(RustCondition {
            field: "ipv6_flow_label".to_string(),
            fail_expr: format!("pkt.ipv6_flow_label != Some({})", v),
        });
    }

    // IPv4 fragmentation
    if let Some(v) = mc.ip_dont_fragment {
        conds.push(RustCondition {
            field: "ip_dont_fragment".to_string(),
            fail_expr: format!("pkt.ip_dont_fragment != Some({})", v),
        });
    }
    if let Some(v) = mc.ip_more_fragments {
        conds.push(RustCondition {
            field: "ip_more_fragments".to_string(),
            fail_expr: format!("pkt.ip_more_fragments != Some({})", v),
        });
    }
    if let Some(v) = mc.ip_frag_offset {
        conds.push(RustCondition {
            field: "ip_frag_offset".to_string(),
            fail_expr: format!("pkt.ip_frag_offset != Some({})", v),
        });
    }

    // Tunnel fields
    if let Some(v) = mc.vxlan_vni {
        conds.push(RustCondition {
            field: "vxlan_vni".to_string(),
            fail_expr: format!("pkt.vxlan_vni != Some({})", v),
        });
    }
    if let Some(v) = mc.gtp_teid {
        conds.push(RustCondition {
            field: "gtp_teid".to_string(),
            fail_expr: format!("pkt.gtp_teid != Some({})", v),
        });
    }
    if let Some(v) = mc.mpls_label {
        conds.push(RustCondition {
            field: "mpls_label".to_string(),
            fail_expr: format!("pkt.mpls_label != Some({})", v),
        });
    }
    if let Some(v) = mc.mpls_tc {
        conds.push(RustCondition {
            field: "mpls_tc".to_string(),
            fail_expr: format!("pkt.mpls_tc != Some({})", v),
        });
    }
    if let Some(v) = mc.mpls_bos {
        conds.push(RustCondition {
            field: "mpls_bos".to_string(),
            fail_expr: format!("pkt.mpls_bos != Some({})", v),
        });
    }
    if let Some(v) = mc.igmp_type {
        conds.push(RustCondition {
            field: "igmp_type".to_string(),
            fail_expr: format!("pkt.igmp_type != Some({})", v),
        });
    }
    if let Some(v) = mc.mld_type {
        conds.push(RustCondition {
            field: "mld_type".to_string(),
            fail_expr: format!("pkt.mld_type != Some({})", v),
        });
    }

    // GRE
    if let Some(v) = mc.gre_protocol {
        conds.push(RustCondition {
            field: "gre_protocol".to_string(),
            fail_expr: format!("pkt.gre_protocol != Some(0x{:04x})", v),
        });
    }
    if let Some(v) = mc.gre_key {
        conds.push(RustCondition {
            field: "gre_key".to_string(),
            fail_expr: format!("pkt.gre_key != Some({})", v),
        });
    }

    // OAM
    if let Some(v) = mc.oam_level {
        conds.push(RustCondition {
            field: "oam_level".to_string(),
            fail_expr: format!("pkt.oam_level != Some({})", v),
        });
    }
    if let Some(v) = mc.oam_opcode {
        conds.push(RustCondition {
            field: "oam_opcode".to_string(),
            fail_expr: format!("pkt.oam_opcode != Some({})", v),
        });
    }

    // NSH
    if let Some(v) = mc.nsh_spi {
        conds.push(RustCondition {
            field: "nsh_spi".to_string(),
            fail_expr: format!("pkt.nsh_spi != Some({})", v),
        });
    }
    if let Some(v) = mc.nsh_si {
        conds.push(RustCondition {
            field: "nsh_si".to_string(),
            fail_expr: format!("pkt.nsh_si != Some({})", v),
        });
    }
    if let Some(v) = mc.nsh_next_protocol {
        conds.push(RustCondition {
            field: "nsh_next_protocol".to_string(),
            fail_expr: format!("pkt.nsh_next_protocol != Some({})", v),
        });
    }

    // Geneve
    if let Some(v) = mc.geneve_vni {
        conds.push(RustCondition {
            field: "geneve_vni".to_string(),
            fail_expr: format!("pkt.geneve_vni != Some({})", v),
        });
    }

    // IP TTL
    if let Some(v) = mc.ip_ttl {
        conds.push(RustCondition {
            field: "ip_ttl".to_string(),
            fail_expr: format!("pkt.ip_ttl != Some({})", v),
        });
    }

    // Frame length (simulation-only, but relevant for Rust software filter)
    if let Some(v) = mc.frame_len_min {
        conds.push(RustCondition {
            field: "frame_len_min".to_string(),
            fail_expr: format!("pkt.frame_len < {}", v),
        });
    }
    if let Some(v) = mc.frame_len_max {
        conds.push(RustCondition {
            field: "frame_len_max".to_string(),
            fail_expr: format!("pkt.frame_len > {}", v),
        });
    }

    // Conntrack state
    if let Some(ref s) = mc.conntrack_state {
        conds.push(RustCondition {
            field: "conntrack_state".to_string(),
            fail_expr: format!("pkt.conntrack_state.as_deref() != Some(\"{}\")", s),
        });
    }

    // PTP
    if let Some(v) = mc.ptp_message_type {
        conds.push(RustCondition {
            field: "ptp_message_type".to_string(),
            fail_expr: format!("pkt.ptp_message_type != Some({})", v),
        });
    }
    if let Some(v) = mc.ptp_domain {
        conds.push(RustCondition {
            field: "ptp_domain".to_string(),
            fail_expr: format!("pkt.ptp_domain != Some({})", v),
        });
    }
    if let Some(v) = mc.ptp_version {
        conds.push(RustCondition {
            field: "ptp_version".to_string(),
            fail_expr: format!("pkt.ptp_version != Some({})", v),
        });
    }

    // Byte match
    if let Some(ref bms) = mc.byte_match {
        for bm in bms {
            let val = u8::from_str_radix(bm.value.trim_start_matches("0x"), 16)
                .unwrap_or(0);
            if let Some(ref mask_str) = bm.mask {
                let mask = u8::from_str_radix(mask_str.trim_start_matches("0x"), 16)
                    .unwrap_or(0xFF);
                conds.push(RustCondition {
                    field: format!("byte_match[{}]", bm.offset),
                    fail_expr: format!(
                        "pkt.raw.get({}).map_or(true, |&b| (b & 0x{:02x}) != 0x{:02x})",
                        bm.offset,
                        mask,
                        val & mask
                    ),
                });
            } else {
                conds.push(RustCondition {
                    field: format!("byte_match[{}]", bm.offset),
                    fail_expr: format!(
                        "pkt.raw.get({}).map_or(true, |&b| b != 0x{:02x})",
                        bm.offset, val
                    ),
                });
            }
        }
    }

    Ok((conds, consts))
}

/// Check if a MAC address string contains wildcards
fn has_mac_wildcard_field(mac: &Option<String>) -> bool {
    mac.as_ref().map_or(false, |m| m.contains('*'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MatchCriteria;

    fn empty_mc() -> MatchCriteria {
        MatchCriteria::default()
    }

    #[test]
    fn condition_ethertype() {
        let mut mc = empty_mc();
        mc.ethertype = Some("0x0800".to_string());
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("0x0800"));
    }

    #[test]
    fn condition_cidr_24() {
        let mut mc = empty_mc();
        mc.src_ip = Some("10.0.0.0/8".to_string());
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("0xff000000")); // /8 mask
        assert!(conds[0].fail_expr.contains("0x0a000000")); // 10.0.0.0
    }

    #[test]
    fn condition_cidr_32() {
        let mut mc = empty_mc();
        mc.dst_ip = Some("192.168.1.1".to_string());
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("0xc0a80101"));
        assert!(!conds[0].fail_expr.contains("map_or")); // exact match
    }

    #[test]
    fn condition_ipv6_cidr() {
        let mut mc = empty_mc();
        mc.src_ipv6 = Some("2001:db8::/32".to_string());
        let (conds, consts) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("ipv6_match"));
        assert_eq!(consts.len(), 2); // prefix + mask
    }

    #[test]
    fn condition_port_exact() {
        let mut mc = empty_mc();
        mc.dst_port = Some(PortMatch::Exact(80));
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("!= Some(80)"));
    }

    #[test]
    fn condition_port_range() {
        let mut mc = empty_mc();
        mc.src_port = Some(PortMatch::Range {
            range: [1024, 65535],
        });
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("< 1024"));
        assert!(conds[0].fail_expr.contains("> 65535"));
    }

    #[test]
    fn condition_mac_wildcard() {
        let mut mc = empty_mc();
        mc.dst_mac = Some("00:1a:2b:*:*:*".to_string());
        let (conds, consts) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("mac_match"));
        assert_eq!(consts.len(), 2); // val + mask
    }

    #[test]
    fn condition_mac_exact() {
        let mut mc = empty_mc();
        mc.src_mac = Some("00:11:22:33:44:55".to_string());
        let (conds, consts) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("pkt.src_mac !="));
        assert_eq!(consts.len(), 0); // no constants needed
    }

    #[test]
    fn condition_tcp_flags_mask() {
        let mut mc = empty_mc();
        mc.tcp_flags = Some(0x02);
        mc.tcp_flags_mask = Some(0x02);
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("0x02"));
    }

    #[test]
    fn condition_byte_match() {
        let mut mc = empty_mc();
        mc.byte_match = Some(vec![crate::model::ByteMatch {
            offset: 14,
            value: "0x45".to_string(),
            mask: None,
        }]);
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("pkt.raw.get(14)"));
        assert!(conds[0].fail_expr.contains("0x45"));
    }

    #[test]
    fn condition_exact_field_ip_ttl() {
        let mut mc = empty_mc();
        mc.ip_ttl = Some(1);
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 1);
        assert!(conds[0].fail_expr.contains("ip_ttl != Some(1)"));
    }

    #[test]
    fn condition_frame_len() {
        let mut mc = empty_mc();
        mc.frame_len_min = Some(64);
        mc.frame_len_max = Some(1518);
        let (conds, _) = build_rust_condition(&mc, 0).unwrap();
        assert_eq!(conds.len(), 2);
        assert!(conds[0].fail_expr.contains("< 64"));
        assert!(conds[1].fail_expr.contains("> 1518"));
    }

    #[test]
    fn protocol_detection_simple_ipv4() {
        let config = make_config(vec![make_rule("r1", |mc| {
            mc.ethertype = Some("0x0800".to_string());
            mc.dst_port = Some(PortMatch::Exact(80));
        })]);
        let p = detect_protocols(&config);
        assert!(p.has_ipv4);
        assert!(p.has_tcp);
        assert!(p.has_udp);
        assert!(!p.has_ipv6);
    }

    #[test]
    fn protocol_detection_ipv6_tunnel() {
        let config = make_config(vec![make_rule("r1", |mc| {
            mc.src_ipv6 = Some("2001:db8::/32".to_string());
            mc.vxlan_vni = Some(100);
        })]);
        let p = detect_protocols(&config);
        assert!(p.has_ipv6);
        assert!(p.has_vxlan);
        assert!(p.has_udp);
    }

    #[test]
    fn protocol_detection_multi_protocol() {
        let config = make_config(vec![
            make_rule("r1", |mc| {
                mc.gtp_teid = Some(1000);
            }),
            make_rule("r2", |mc| {
                mc.oam_level = Some(3);
            }),
            make_rule("r3", |mc| {
                mc.nsh_spi = Some(100);
            }),
        ]);
        let p = detect_protocols(&config);
        assert!(p.has_gtp);
        assert!(p.has_oam);
        assert!(p.has_nsh);
        assert!(p.has_udp); // from GTP
    }

    #[test]
    fn json_summary_structure() {
        let config = make_config(vec![make_rule("r1", |mc| {
            mc.ethertype = Some("0x0800".to_string());
        })]);
        let summary = generate_rust_summary(&config);
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["target"], "rust");
        assert_eq!(summary["rules_count"], 1);
        assert!(summary["build_command"].as_str().unwrap().contains("cargo"));
    }

    #[test]
    fn empty_rules() {
        let config = make_config(vec![]);
        let rules = build_rust_rules(&config).unwrap();
        assert!(rules.is_empty());
        let p = detect_protocols(&config);
        assert!(!p.has_ipv4);
    }

    // Test helpers
    fn make_rule(
        name: &str,
        f: impl FnOnce(&mut MatchCriteria),
    ) -> crate::model::StatelessRule {
        let mut mc = MatchCriteria::default();
        f(&mut mc);
        crate::model::StatelessRule {
            name: name.to_string(),
            priority: 100,
            match_criteria: mc,
            action: Some(Action::Pass),
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

    fn make_config(rules: Vec<crate::model::StatelessRule>) -> FilterConfig {
        FilterConfig {
            pacgate: crate::model::PacgateConfig {
                version: "1.0".to_string(),
                defaults: crate::model::Defaults {
                    action: Action::Drop,
                },
                rules,
                conntrack: None,
                tables: None,
            },
        }
    }
}
