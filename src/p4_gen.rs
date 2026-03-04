use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, MatchCriteria, PortMatch, RewriteAction, parse_ethertype};

/// P4 match kind for a given field
#[derive(Debug, Clone, serde::Serialize)]
pub enum P4MatchKind {
    Exact,
    Lpm,
    Ternary,
    Range,
}

impl std::fmt::Display for P4MatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P4MatchKind::Exact => write!(f, "exact"),
            P4MatchKind::Lpm => write!(f, "lpm"),
            P4MatchKind::Ternary => write!(f, "ternary"),
            P4MatchKind::Range => write!(f, "range"),
        }
    }
}

/// A P4 table key entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct P4Key {
    pub header_field: String,
    pub match_kind: String,
    pub bit_width: u16,
}

/// A P4 table entry (from a rule)
#[derive(Debug, Clone, serde::Serialize)]
pub struct P4Entry {
    pub rule_name: String,
    pub priority: u32,
    pub action_name: String,
    pub key_values: Vec<P4KeyValue>,
}

/// A key-value pair for a P4 table entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct P4KeyValue {
    pub header_field: String,
    pub value: String,
    pub mask: Option<String>,
}

/// Protocol usage flags for conditional header/parser generation
#[derive(Debug, Clone, serde::Serialize)]
pub struct P4Protocols {
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
    pub has_qinq: bool,
}

/// Rewrite action for P4 generation
#[derive(Debug, Clone, serde::Serialize)]
pub struct P4RewriteAction {
    pub action_name: String,
    pub operations: Vec<String>,
}

/// Generate P4_16 PSA program from a PacGate YAML config.
pub fn generate_p4(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let p4_dir = output_dir.join("p4");
    std::fs::create_dir_all(&p4_dir)?;

    let mut ctx = tera::Context::new();

    // Detect protocol usage across all rules
    let protocols = detect_protocols(config);
    ctx.insert("protocols", &protocols);

    // Build keys used across all rules
    let keys = collect_table_keys(config)?;
    ctx.insert("keys", &keys);

    // Build table entries from rules
    let entries = build_table_entries(config)?;
    ctx.insert("entries", &entries);

    // Default action
    let default_pass = config.pacgate.defaults.action == Action::Pass;
    ctx.insert("default_pass", &default_pass);
    ctx.insert("num_rules", &config.pacgate.rules.len());

    // Rewrite actions
    let rewrite_actions = build_rewrite_actions(config);
    ctx.insert("has_rewrite", &!rewrite_actions.is_empty());
    ctx.insert("rewrite_actions", &rewrite_actions);

    // Generate P4 program
    let rendered = tera.render("p4_program.p4.tera", &ctx)?;
    std::fs::write(p4_dir.join("pacgate_filter.p4"), &rendered)?;
    log::info!("Generated pacgate_filter.p4");

    Ok(())
}

/// Generate P4 export summary as JSON
pub fn generate_p4_summary(config: &FilterConfig) -> serde_json::Value {
    let protocols = detect_protocols(config);
    let keys = collect_table_keys(config).unwrap_or_default();
    let has_stateful = config.pacgate.rules.iter().any(|r| r.is_stateful());
    let has_rewrite = config.pacgate.rules.iter().any(|r| r.has_rewrite());
    let has_byte_match = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_byte_match());

    let mut unsupported: Vec<String> = Vec::new();
    if has_stateful {
        unsupported.push("Stateful FSM rules require manual P4 Register extern adaptation".to_string());
    }
    if has_byte_match {
        unsupported.push("byte_match requires custom P4 extern or header field mapping".to_string());
    }

    serde_json::json!({
        "status": "ok",
        "rules_count": config.pacgate.rules.len(),
        "stateless_rules": config.pacgate.rules.iter().filter(|r| !r.is_stateful()).count(),
        "stateful_rules": config.pacgate.rules.iter().filter(|r| r.is_stateful()).count(),
        "table_keys": keys.len(),
        "has_rewrite": has_rewrite,
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
            "qinq": protocols.has_qinq,
        },
        "unsupported_features": unsupported,
    })
}

/// Detect which protocols are used across all rules
fn detect_protocols(config: &FilterConfig) -> P4Protocols {
    let rules = &config.pacgate.rules;
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    let mut has_tcp = false;
    let mut has_udp = false;
    let mut has_vlan = false;
    let mut has_vxlan = false;
    let mut has_gtp = false;
    let mut has_mpls = false;
    let mut has_gre = false;
    let mut has_geneve = false;
    let mut has_arp = false;
    let mut has_icmp = false;
    let mut has_icmpv6 = false;
    let mut has_oam = false;
    let mut has_nsh = false;
    let mut has_qinq = false;

    for rule in rules {
        let mc = &rule.match_criteria;

        if mc.src_ip.is_some() || mc.dst_ip.is_some() || mc.ip_protocol.is_some()
            || mc.ip_dscp.is_some() || mc.ip_ecn.is_some() || mc.ip_ttl.is_some()
            || mc.ip_dont_fragment.is_some() || mc.ip_more_fragments.is_some() || mc.ip_frag_offset.is_some()
        {
            has_ipv4 = true;
        }
        if mc.ethertype.as_deref() == Some("0x0800") { has_ipv4 = true; }
        if mc.uses_ipv6() || mc.uses_ipv6_tc() || mc.uses_ipv6_ext() { has_ipv6 = true; }
        if mc.ethertype.as_deref() == Some("0x86DD") { has_ipv6 = true; }

        if mc.tcp_flags.is_some() || mc.conntrack_state.is_some() { has_tcp = true; }
        if mc.src_port.is_some() || mc.dst_port.is_some() {
            has_tcp = true;
            has_udp = true;
        }
        if mc.vlan_id.is_some() || mc.vlan_pcp.is_some() { has_vlan = true; }
        if mc.vxlan_vni.is_some() { has_vxlan = true; has_udp = true; }
        if mc.gtp_teid.is_some() { has_gtp = true; has_udp = true; }
        if mc.uses_mpls() { has_mpls = true; }
        if mc.uses_gre() { has_gre = true; has_ipv4 = true; }
        if mc.uses_geneve() { has_geneve = true; has_udp = true; }
        if mc.uses_arp() { has_arp = true; }
        if mc.uses_icmp() { has_icmp = true; has_ipv4 = true; }
        if mc.uses_icmpv6() { has_icmpv6 = true; has_ipv6 = true; }
        if mc.uses_oam() { has_oam = true; }
        if mc.uses_nsh() { has_nsh = true; }
        if mc.uses_qinq() { has_qinq = true; has_vlan = true; }
        if mc.igmp_type.is_some() { has_ipv4 = true; }
        if mc.mld_type.is_some() { has_ipv6 = true; has_icmpv6 = true; }

        // L4 protocol detection from ip_protocol
        if let Some(proto) = mc.ip_protocol {
            if proto == 6 { has_tcp = true; }
            if proto == 17 { has_udp = true; }
            if proto == 1 { has_icmp = true; }
            if proto == 47 { has_gre = true; }
        }
    }

    P4Protocols {
        has_ipv4, has_ipv6, has_tcp, has_udp, has_vlan, has_vxlan,
        has_gtp, has_mpls, has_gre, has_geneve, has_arp, has_icmp,
        has_icmpv6, has_oam, has_nsh, has_qinq,
    }
}

/// Collect the union of all match fields used across rules as P4 table keys
fn collect_table_keys(config: &FilterConfig) -> Result<Vec<P4Key>> {
    let mut keys: Vec<P4Key> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for rule in &config.pacgate.rules {
        if rule.is_stateful() { continue; }
        let mc = &rule.match_criteria;

        add_key_if_present(&mut keys, &mut seen, mc.ethertype.is_some(), "hdr.ethernet.etherType", "exact", 16);
        add_key_if_present(&mut keys, &mut seen, mc.dst_mac.is_some(), "hdr.ethernet.dstAddr", "ternary", 48);
        add_key_if_present(&mut keys, &mut seen, mc.src_mac.is_some(), "hdr.ethernet.srcAddr", "ternary", 48);
        add_key_if_present(&mut keys, &mut seen, mc.vlan_id.is_some(), "hdr.vlan.vid", "exact", 12);
        add_key_if_present(&mut keys, &mut seen, mc.vlan_pcp.is_some(), "hdr.vlan.pcp", "exact", 3);

        // IPv4
        add_key_if_present(&mut keys, &mut seen, mc.src_ip.is_some(), "hdr.ipv4.srcAddr", "lpm", 32);
        add_key_if_present(&mut keys, &mut seen, mc.dst_ip.is_some(), "hdr.ipv4.dstAddr", "lpm", 32);
        add_key_if_present(&mut keys, &mut seen, mc.ip_protocol.is_some(), "hdr.ipv4.protocol", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.ip_dscp.is_some(), "hdr.ipv4.dscp", "exact", 6);
        add_key_if_present(&mut keys, &mut seen, mc.ip_ecn.is_some(), "hdr.ipv4.ecn", "exact", 2);
        add_key_if_present(&mut keys, &mut seen, mc.ip_ttl.is_some(), "hdr.ipv4.ttl", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.ip_dont_fragment.is_some(), "hdr.ipv4.flags_df", "exact", 1);
        add_key_if_present(&mut keys, &mut seen, mc.ip_more_fragments.is_some(), "hdr.ipv4.flags_mf", "exact", 1);
        add_key_if_present(&mut keys, &mut seen, mc.ip_frag_offset.is_some(), "hdr.ipv4.fragOffset", "exact", 13);

        // L4 ports
        let has_port = mc.src_port.is_some() || mc.dst_port.is_some();
        if has_port {
            // Use ternary to handle both TCP and UDP in one table
            add_key_if_present(&mut keys, &mut seen, mc.src_port.is_some(), "meta.l4_src_port", "range", 16);
            add_key_if_present(&mut keys, &mut seen, mc.dst_port.is_some(), "meta.l4_dst_port", "range", 16);
        }

        // TCP flags
        add_key_if_present(&mut keys, &mut seen, mc.tcp_flags.is_some(), "hdr.tcp.flags", "ternary", 8);

        // IPv6
        add_key_if_present(&mut keys, &mut seen, mc.src_ipv6.is_some(), "hdr.ipv6.srcAddr", "lpm", 128);
        add_key_if_present(&mut keys, &mut seen, mc.dst_ipv6.is_some(), "hdr.ipv6.dstAddr", "lpm", 128);
        add_key_if_present(&mut keys, &mut seen, mc.ipv6_next_header.is_some(), "hdr.ipv6.nextHdr", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.ipv6_dscp.is_some(), "hdr.ipv6.dscp", "exact", 6);
        add_key_if_present(&mut keys, &mut seen, mc.ipv6_ecn.is_some(), "hdr.ipv6.ecn", "exact", 2);
        add_key_if_present(&mut keys, &mut seen, mc.ipv6_hop_limit.is_some(), "hdr.ipv6.hopLimit", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.ipv6_flow_label.is_some(), "hdr.ipv6.flowLabel", "exact", 20);

        // Tunnel protocols
        add_key_if_present(&mut keys, &mut seen, mc.vxlan_vni.is_some(), "hdr.vxlan.vni", "exact", 24);
        add_key_if_present(&mut keys, &mut seen, mc.gtp_teid.is_some(), "hdr.gtp.teid", "exact", 32);
        add_key_if_present(&mut keys, &mut seen, mc.geneve_vni.is_some(), "hdr.geneve.vni", "exact", 24);
        add_key_if_present(&mut keys, &mut seen, mc.gre_protocol.is_some(), "hdr.gre.protocol", "exact", 16);
        add_key_if_present(&mut keys, &mut seen, mc.gre_key.is_some(), "hdr.gre.key", "exact", 32);
        add_key_if_present(&mut keys, &mut seen, mc.mpls_label.is_some(), "hdr.mpls.label", "exact", 20);
        add_key_if_present(&mut keys, &mut seen, mc.mpls_tc.is_some(), "hdr.mpls.tc", "exact", 3);
        add_key_if_present(&mut keys, &mut seen, mc.mpls_bos.is_some(), "hdr.mpls.bos", "exact", 1);

        // ARP
        add_key_if_present(&mut keys, &mut seen, mc.arp_opcode.is_some(), "hdr.arp.opcode", "exact", 16);
        add_key_if_present(&mut keys, &mut seen, mc.arp_spa.is_some(), "hdr.arp.senderProtoAddr", "lpm", 32);
        add_key_if_present(&mut keys, &mut seen, mc.arp_tpa.is_some(), "hdr.arp.targetProtoAddr", "lpm", 32);

        // ICMP
        add_key_if_present(&mut keys, &mut seen, mc.icmp_type.is_some(), "hdr.icmp.type_", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.icmp_code.is_some(), "hdr.icmp.code", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.icmpv6_type.is_some(), "hdr.icmpv6.type_", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.icmpv6_code.is_some(), "hdr.icmpv6.code", "exact", 8);

        // IGMP/MLD
        add_key_if_present(&mut keys, &mut seen, mc.igmp_type.is_some(), "hdr.igmp.type_", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.mld_type.is_some(), "hdr.mld.type_", "exact", 8);

        // OAM/NSH
        add_key_if_present(&mut keys, &mut seen, mc.oam_level.is_some(), "hdr.oam.level", "exact", 3);
        add_key_if_present(&mut keys, &mut seen, mc.oam_opcode.is_some(), "hdr.oam.opcode", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.nsh_spi.is_some(), "hdr.nsh.spi", "exact", 24);
        add_key_if_present(&mut keys, &mut seen, mc.nsh_si.is_some(), "hdr.nsh.si", "exact", 8);
        add_key_if_present(&mut keys, &mut seen, mc.nsh_next_protocol.is_some(), "hdr.nsh.nextProtocol", "exact", 8);

        // QinQ
        add_key_if_present(&mut keys, &mut seen, mc.outer_vlan_id.is_some(), "hdr.outer_vlan.vid", "exact", 12);
        add_key_if_present(&mut keys, &mut seen, mc.outer_vlan_pcp.is_some(), "hdr.outer_vlan.pcp", "exact", 3);
    }

    Ok(keys)
}

fn add_key_if_present(keys: &mut Vec<P4Key>, seen: &mut std::collections::HashSet<String>, present: bool, field: &str, kind: &str, bits: u16) {
    if present && !seen.contains(field) {
        seen.insert(field.to_string());
        keys.push(P4Key {
            header_field: field.to_string(),
            match_kind: kind.to_string(),
            bit_width: bits,
        });
    }
}

/// Build table entries from rules
fn build_table_entries(config: &FilterConfig) -> Result<Vec<P4Entry>> {
    let mut entries = Vec::new();

    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in &rules {
        if rule.is_stateful() { continue; }

        let action_name = if rule.has_rewrite() {
            format!("rewrite_{}", sanitize_name(&rule.name))
        } else {
            match rule.action() {
                Action::Pass => "pass_action".to_string(),
                Action::Drop => "drop_action".to_string(),
            }
        };

        let key_values = build_key_values(&rule.match_criteria)?;
        entries.push(P4Entry {
            rule_name: rule.name.clone(),
            priority: rule.priority,
            action_name,
            key_values,
        });
    }

    Ok(entries)
}

/// Build key-value pairs for a single rule's match criteria
fn build_key_values(mc: &MatchCriteria) -> Result<Vec<P4KeyValue>> {
    let mut kvs = Vec::new();

    if let Some(ref et) = mc.ethertype {
        let val = parse_ethertype(et)?;
        kvs.push(P4KeyValue {
            header_field: "hdr.ethernet.etherType".to_string(),
            value: format!("0x{:04x}", val),
            mask: None,
        });
    }

    if let Some(ref mac) = mc.dst_mac {
        kvs.push(P4KeyValue {
            header_field: "hdr.ethernet.dstAddr".to_string(),
            value: mac_to_p4(mac),
            mask: Some(mac_mask_to_p4(mac)),
        });
    }

    if let Some(ref mac) = mc.src_mac {
        kvs.push(P4KeyValue {
            header_field: "hdr.ethernet.srcAddr".to_string(),
            value: mac_to_p4(mac),
            mask: Some(mac_mask_to_p4(mac)),
        });
    }

    if let Some(vid) = mc.vlan_id {
        kvs.push(P4KeyValue { header_field: "hdr.vlan.vid".to_string(), value: vid.to_string(), mask: None });
    }
    if let Some(pcp) = mc.vlan_pcp {
        kvs.push(P4KeyValue { header_field: "hdr.vlan.pcp".to_string(), value: pcp.to_string(), mask: None });
    }

    // IPv4
    if let Some(ref ip) = mc.src_ip {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.srcAddr".to_string(), value: ip.clone(), mask: None });
    }
    if let Some(ref ip) = mc.dst_ip {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.dstAddr".to_string(), value: ip.clone(), mask: None });
    }
    if let Some(proto) = mc.ip_protocol {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.protocol".to_string(), value: proto.to_string(), mask: None });
    }
    if let Some(dscp) = mc.ip_dscp {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.dscp".to_string(), value: dscp.to_string(), mask: None });
    }
    if let Some(ecn) = mc.ip_ecn {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.ecn".to_string(), value: ecn.to_string(), mask: None });
    }
    if let Some(ttl) = mc.ip_ttl {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.ttl".to_string(), value: ttl.to_string(), mask: None });
    }

    // L4 ports
    if let Some(ref port) = mc.src_port {
        let (lo, hi) = port_match_range(port);
        kvs.push(P4KeyValue { header_field: "meta.l4_src_port".to_string(), value: format!("{}..{}", lo, hi), mask: None });
    }
    if let Some(ref port) = mc.dst_port {
        let (lo, hi) = port_match_range(port);
        kvs.push(P4KeyValue { header_field: "meta.l4_dst_port".to_string(), value: format!("{}..{}", lo, hi), mask: None });
    }

    // TCP flags
    if let Some(flags) = mc.tcp_flags {
        let mask = mc.tcp_flags_mask.unwrap_or(0xFF);
        kvs.push(P4KeyValue {
            header_field: "hdr.tcp.flags".to_string(),
            value: format!("0x{:02x}", flags),
            mask: Some(format!("0x{:02x}", mask)),
        });
    }

    // IPv6
    if let Some(ref ip) = mc.src_ipv6 {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.srcAddr".to_string(), value: ip.clone(), mask: None });
    }
    if let Some(ref ip) = mc.dst_ipv6 {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.dstAddr".to_string(), value: ip.clone(), mask: None });
    }
    if let Some(nh) = mc.ipv6_next_header {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.nextHdr".to_string(), value: nh.to_string(), mask: None });
    }
    if let Some(dscp) = mc.ipv6_dscp {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.dscp".to_string(), value: dscp.to_string(), mask: None });
    }
    if let Some(ecn) = mc.ipv6_ecn {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.ecn".to_string(), value: ecn.to_string(), mask: None });
    }
    if let Some(hl) = mc.ipv6_hop_limit {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.hopLimit".to_string(), value: hl.to_string(), mask: None });
    }
    if let Some(fl) = mc.ipv6_flow_label {
        kvs.push(P4KeyValue { header_field: "hdr.ipv6.flowLabel".to_string(), value: fl.to_string(), mask: None });
    }

    // Tunnels
    if let Some(vni) = mc.vxlan_vni {
        kvs.push(P4KeyValue { header_field: "hdr.vxlan.vni".to_string(), value: vni.to_string(), mask: None });
    }
    if let Some(teid) = mc.gtp_teid {
        kvs.push(P4KeyValue { header_field: "hdr.gtp.teid".to_string(), value: teid.to_string(), mask: None });
    }
    if let Some(vni) = mc.geneve_vni {
        kvs.push(P4KeyValue { header_field: "hdr.geneve.vni".to_string(), value: vni.to_string(), mask: None });
    }
    if let Some(proto) = mc.gre_protocol {
        kvs.push(P4KeyValue { header_field: "hdr.gre.protocol".to_string(), value: format!("0x{:04x}", proto), mask: None });
    }
    if let Some(key) = mc.gre_key {
        kvs.push(P4KeyValue { header_field: "hdr.gre.key".to_string(), value: key.to_string(), mask: None });
    }
    if let Some(label) = mc.mpls_label {
        kvs.push(P4KeyValue { header_field: "hdr.mpls.label".to_string(), value: label.to_string(), mask: None });
    }
    if let Some(tc) = mc.mpls_tc {
        kvs.push(P4KeyValue { header_field: "hdr.mpls.tc".to_string(), value: tc.to_string(), mask: None });
    }
    if let Some(bos) = mc.mpls_bos {
        kvs.push(P4KeyValue { header_field: "hdr.mpls.bos".to_string(), value: if bos { "1" } else { "0" }.to_string(), mask: None });
    }

    // ARP
    if let Some(op) = mc.arp_opcode {
        kvs.push(P4KeyValue { header_field: "hdr.arp.opcode".to_string(), value: op.to_string(), mask: None });
    }
    if let Some(ref spa) = mc.arp_spa {
        kvs.push(P4KeyValue { header_field: "hdr.arp.senderProtoAddr".to_string(), value: spa.clone(), mask: None });
    }
    if let Some(ref tpa) = mc.arp_tpa {
        kvs.push(P4KeyValue { header_field: "hdr.arp.targetProtoAddr".to_string(), value: tpa.clone(), mask: None });
    }

    // ICMP
    if let Some(t) = mc.icmp_type {
        kvs.push(P4KeyValue { header_field: "hdr.icmp.type_".to_string(), value: t.to_string(), mask: None });
    }
    if let Some(c) = mc.icmp_code {
        kvs.push(P4KeyValue { header_field: "hdr.icmp.code".to_string(), value: c.to_string(), mask: None });
    }
    if let Some(t) = mc.icmpv6_type {
        kvs.push(P4KeyValue { header_field: "hdr.icmpv6.type_".to_string(), value: t.to_string(), mask: None });
    }
    if let Some(c) = mc.icmpv6_code {
        kvs.push(P4KeyValue { header_field: "hdr.icmpv6.code".to_string(), value: c.to_string(), mask: None });
    }

    // IGMP/MLD
    if let Some(t) = mc.igmp_type {
        kvs.push(P4KeyValue { header_field: "hdr.igmp.type_".to_string(), value: t.to_string(), mask: None });
    }
    if let Some(t) = mc.mld_type {
        kvs.push(P4KeyValue { header_field: "hdr.mld.type_".to_string(), value: t.to_string(), mask: None });
    }

    // OAM/NSH
    if let Some(l) = mc.oam_level {
        kvs.push(P4KeyValue { header_field: "hdr.oam.level".to_string(), value: l.to_string(), mask: None });
    }
    if let Some(o) = mc.oam_opcode {
        kvs.push(P4KeyValue { header_field: "hdr.oam.opcode".to_string(), value: o.to_string(), mask: None });
    }
    if let Some(spi) = mc.nsh_spi {
        kvs.push(P4KeyValue { header_field: "hdr.nsh.spi".to_string(), value: spi.to_string(), mask: None });
    }
    if let Some(si) = mc.nsh_si {
        kvs.push(P4KeyValue { header_field: "hdr.nsh.si".to_string(), value: si.to_string(), mask: None });
    }
    if let Some(np) = mc.nsh_next_protocol {
        kvs.push(P4KeyValue { header_field: "hdr.nsh.nextProtocol".to_string(), value: np.to_string(), mask: None });
    }

    // QinQ
    if let Some(vid) = mc.outer_vlan_id {
        kvs.push(P4KeyValue { header_field: "hdr.outer_vlan.vid".to_string(), value: vid.to_string(), mask: None });
    }
    if let Some(pcp) = mc.outer_vlan_pcp {
        kvs.push(P4KeyValue { header_field: "hdr.outer_vlan.pcp".to_string(), value: pcp.to_string(), mask: None });
    }

    // Fragment fields
    if let Some(df) = mc.ip_dont_fragment {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.flags_df".to_string(), value: if df { "1" } else { "0" }.to_string(), mask: None });
    }
    if let Some(mf) = mc.ip_more_fragments {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.flags_mf".to_string(), value: if mf { "1" } else { "0" }.to_string(), mask: None });
    }
    if let Some(fo) = mc.ip_frag_offset {
        kvs.push(P4KeyValue { header_field: "hdr.ipv4.fragOffset".to_string(), value: fo.to_string(), mask: None });
    }

    Ok(kvs)
}

/// Build per-rule rewrite actions for P4
fn build_rewrite_actions(config: &FilterConfig) -> Vec<P4RewriteAction> {
    let mut actions = Vec::new();
    for rule in &config.pacgate.rules {
        if rule.is_stateful() { continue; }
        if let Some(ref rw) = rule.rewrite {
            if !rw.is_empty() {
                let ops = rewrite_to_p4_ops(rw);
                actions.push(P4RewriteAction {
                    action_name: format!("rewrite_{}", sanitize_name(&rule.name)),
                    operations: ops,
                });
            }
        }
    }
    actions
}

/// Convert RewriteAction to P4 action operation strings
fn rewrite_to_p4_ops(rw: &RewriteAction) -> Vec<String> {
    let mut ops = Vec::new();
    if let Some(ref mac) = rw.set_dst_mac {
        ops.push(format!("hdr.ethernet.dstAddr = {};", mac_to_p4(mac)));
    }
    if let Some(ref mac) = rw.set_src_mac {
        ops.push(format!("hdr.ethernet.srcAddr = {};", mac_to_p4(mac)));
    }
    if let Some(vid) = rw.set_vlan_id {
        ops.push(format!("hdr.vlan.vid = {};", vid));
    }
    if let Some(ttl) = rw.set_ttl {
        ops.push(format!("hdr.ipv4.ttl = {};", ttl));
    }
    if rw.dec_ttl == Some(true) {
        ops.push("hdr.ipv4.ttl = hdr.ipv4.ttl - 1;".to_string());
    }
    if let Some(ref ip) = rw.set_src_ip {
        ops.push(format!("hdr.ipv4.srcAddr = {};", ip));
    }
    if let Some(ref ip) = rw.set_dst_ip {
        ops.push(format!("hdr.ipv4.dstAddr = {};", ip));
    }
    if let Some(dscp) = rw.set_dscp {
        ops.push(format!("hdr.ipv4.dscp = {};", dscp));
    }
    if let Some(port) = rw.set_src_port {
        ops.push(format!("meta.l4_src_port = {};", port));
    }
    if let Some(port) = rw.set_dst_port {
        ops.push(format!("meta.l4_dst_port = {};", port));
    }
    if rw.dec_hop_limit == Some(true) {
        ops.push("hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;".to_string());
    }
    if let Some(hl) = rw.set_hop_limit {
        ops.push(format!("hdr.ipv6.hopLimit = {};", hl));
    }
    if let Some(ecn) = rw.set_ecn {
        ops.push(format!("hdr.ipv4.ecn = {};", ecn));
    }
    if let Some(pcp) = rw.set_vlan_pcp {
        ops.push(format!("hdr.vlan.pcp = {};", pcp));
    }
    if let Some(vid) = rw.set_outer_vlan_id {
        ops.push(format!("hdr.outer_vlan.vid = {};", vid));
    }
    ops
}

/// Convert port match to range
fn port_match_range(pm: &PortMatch) -> (u16, u16) {
    match pm {
        PortMatch::Exact(v) => (*v, *v),
        PortMatch::Range { range } => (range[0], range[1]),
    }
}

/// Sanitize a rule name for use as a P4 identifier
fn sanitize_name(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// Convert MAC string to P4 hex literal
fn mac_to_p4(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    let hex: String = parts.iter().map(|p| if *p == "*" { "00" } else { *p }).collect::<Vec<&str>>().join("");
    format!("0x{}", hex)
}

/// Convert MAC string to P4 mask hex literal
fn mac_mask_to_p4(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    let hex: String = parts.iter().map(|p| if *p == "*" { "00" } else { "ff" }).collect::<Vec<&str>>().join("");
    format!("0x{}", hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

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

    #[test]
    fn detect_ipv4_from_ethertype() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let protos = detect_protocols(&config);
        assert!(protos.has_ipv4);
        assert!(!protos.has_ipv6);
    }

    #[test]
    fn detect_tcp_from_port_match() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria { dst_port: Some(PortMatch::Exact(80)), ..Default::default() },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let protos = detect_protocols(&config);
        assert!(protos.has_tcp);
        assert!(protos.has_udp);
    }

    #[test]
    fn collect_keys_basic() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria {
                ethertype: Some("0x0800".to_string()),
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let keys = collect_table_keys(&config).unwrap();
        assert!(keys.iter().any(|k| k.header_field == "hdr.ethernet.etherType"));
        assert!(keys.iter().any(|k| k.header_field == "meta.l4_dst_port"));
    }

    #[test]
    fn build_entries_basic() {
        let rule = StatelessRule {
            name: "allow_http".to_string(), priority: 100,
            match_criteria: MatchCriteria {
                ethertype: Some("0x0800".to_string()),
                dst_port: Some(PortMatch::Exact(80)),
                ..Default::default()
            },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let entries = build_table_entries(&config).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action_name, "pass_action");
        assert_eq!(entries[0].priority, 100);
    }

    #[test]
    fn rewrite_to_ops() {
        let rw = RewriteAction {
            set_dst_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            set_ttl: Some(64),
            dec_ttl: None,
            ..Default::default()
        };
        let ops = rewrite_to_p4_ops(&rw);
        assert!(ops.iter().any(|o| o.contains("dstAddr")));
        assert!(ops.iter().any(|o| o.contains("ttl = 64")));
    }

    #[test]
    fn sanitize_rule_name() {
        assert_eq!(sanitize_name("allow-http_443"), "allow_http_443");
        assert_eq!(sanitize_name("block.all"), "block_all");
    }

    #[test]
    fn mac_conversion() {
        assert_eq!(mac_to_p4("aa:bb:cc:dd:ee:ff"), "0xaabbccddeeff");
        assert_eq!(mac_to_p4("aa:bb:cc:*:*:*"), "0xaabbcc000000");
        assert_eq!(mac_mask_to_p4("aa:bb:cc:*:*:*"), "0xffffff000000");
    }

    #[test]
    fn port_range_exact() {
        let (lo, hi) = port_match_range(&PortMatch::Exact(80));
        assert_eq!(lo, 80);
        assert_eq!(hi, 80);
    }

    #[test]
    fn port_range_range() {
        let (lo, hi) = port_match_range(&PortMatch::Range { range: [1024, 65535] });
        assert_eq!(lo, 1024);
        assert_eq!(hi, 65535);
    }

    #[test]
    fn p4_summary_basic() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let summary = generate_p4_summary(&config);
        assert_eq!(summary["rules_count"], 1);
        assert_eq!(summary["stateless_rules"], 1);
        assert_eq!(summary["protocols"]["ipv4"], true);
    }

    #[test]
    fn detect_tunnel_protocols() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria {
                vxlan_vni: Some(100),
                gtp_teid: Some(12345),
                geneve_vni: Some(5000),
                ..Default::default()
            },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let protos = detect_protocols(&config);
        assert!(protos.has_vxlan);
        assert!(protos.has_gtp);
        assert!(protos.has_geneve);
        assert!(protos.has_udp);
    }

    #[test]
    fn detect_arp_icmp() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria {
                arp_opcode: Some(1),
                icmp_type: Some(8),
                ..Default::default()
            },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let protos = detect_protocols(&config);
        assert!(protos.has_arp);
        assert!(protos.has_icmp);
    }

    #[test]
    fn stateful_rules_skipped_in_entries() {
        let rule = StatelessRule {
            name: "fsm_rule".to_string(), priority: 100,
            match_criteria: MatchCriteria::default(),
            action: None,
            rule_type: Some("stateful".to_string()),
            fsm: Some(crate::model::FsmDefinition {
                initial_state: "idle".to_string(),
                states: std::collections::HashMap::new(),
                variables: None,
            }),
            ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
        };
        let config = make_config(vec![rule]);
        let entries = build_table_entries(&config).unwrap();
        assert!(entries.is_empty(), "Stateful rules should be skipped");
    }
}
