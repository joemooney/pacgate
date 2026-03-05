use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, Ipv4Prefix, Ipv6Prefix, MacAddress, PortMatch, parse_ethertype};

/// Platform integration target for NIC wrappers
#[derive(Debug, Clone, PartialEq)]
pub enum PlatformTarget {
    Standalone,
    OpenNic,
    Corundum,
}

impl PlatformTarget {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "standalone" => Ok(PlatformTarget::Standalone),
            "opennic" => Ok(PlatformTarget::OpenNic),
            "corundum" => Ok(PlatformTarget::Corundum),
            _ => anyhow::bail!("Unknown platform target '{}': expected standalone, opennic, or corundum", s),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            PlatformTarget::Standalone => "standalone",
            PlatformTarget::OpenNic => "opennic",
            PlatformTarget::Corundum => "corundum",
        }
    }

    pub fn is_platform(&self) -> bool {
        !matches!(self, PlatformTarget::Standalone)
    }
}

/// Global protocol flags — ensures all rule modules in a design have consistent port lists
#[allow(dead_code)]
struct GlobalProtocolFlags {
    has_ipv6: bool,
    has_gtp: bool,
    has_mpls: bool,
    has_multicast: bool,
    has_dscp_ecn: bool,
    has_ipv6_tc: bool,
    has_tcp_flags: bool,
    has_icmp: bool,
    has_icmpv6: bool,
    has_arp: bool,
    has_ipv6_ext: bool,
    has_qinq: bool,
    has_ip_frag: bool,
    has_gre: bool,
    has_oam: bool,
    has_nsh: bool,
    has_conntrack_state: bool,
    has_geneve: bool,
    has_ip_ttl: bool,
    has_ptp: bool,
    has_flow_counters: bool,
    has_mirror: bool,
    has_redirect: bool,
}

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

    // L3: IPv6 source (CIDR prefix matching)
    if let Some(ref ip) = mc.src_ipv6 {
        let prefix = Ipv6Prefix::parse(ip)?;
        if prefix.prefix_len == 128 {
            conditions.push(format!("(src_ipv6 == {})", prefix.to_verilog_value()));
        } else {
            conditions.push(format!(
                "((src_ipv6 & {}) == ({} & {}))",
                prefix.to_verilog_mask(), prefix.to_verilog_value(), prefix.to_verilog_mask()
            ));
        }
    }

    // L3: IPv6 destination (CIDR prefix matching)
    if let Some(ref ip) = mc.dst_ipv6 {
        let prefix = Ipv6Prefix::parse(ip)?;
        if prefix.prefix_len == 128 {
            conditions.push(format!("(dst_ipv6 == {})", prefix.to_verilog_value()));
        } else {
            conditions.push(format!(
                "((dst_ipv6 & {}) == ({} & {}))",
                prefix.to_verilog_mask(), prefix.to_verilog_value(), prefix.to_verilog_mask()
            ));
        }
    }

    // L3: IPv6 next header
    if let Some(nh) = mc.ipv6_next_header {
        conditions.push(format!("(ipv6_next_header == 8'd{})", nh));
    }

    // VXLAN VNI
    if let Some(vni) = mc.vxlan_vni {
        conditions.push(format!("(vxlan_vni == 24'd{})", vni));
    }

    // GTP-U TEID
    if let Some(teid) = mc.gtp_teid {
        conditions.push(format!("(gtp_teid == 32'd{})", teid));
    }

    // MPLS fields
    if let Some(label) = mc.mpls_label {
        conditions.push(format!("(mpls_label == 20'd{})", label));
    }
    if let Some(tc) = mc.mpls_tc {
        conditions.push(format!("(mpls_tc == 3'd{})", tc));
    }
    if let Some(bos) = mc.mpls_bos {
        conditions.push(format!("(mpls_bos == 1'b{})", if bos { 1 } else { 0 }));
    }

    // Multicast fields
    if let Some(igmp) = mc.igmp_type {
        conditions.push(format!("(igmp_type == 8'd{})", igmp));
    }
    if let Some(mld) = mc.mld_type {
        conditions.push(format!("(mld_type == 8'd{})", mld));
    }

    // QoS fields (DSCP/ECN)
    if let Some(dscp) = mc.ip_dscp {
        conditions.push(format!("(ip_dscp == 6'd{})", dscp));
    }
    if let Some(ecn) = mc.ip_ecn {
        conditions.push(format!("(ip_ecn == 2'd{})", ecn));
    }

    // IPv6 Traffic Class
    if let Some(dscp) = mc.ipv6_dscp {
        conditions.push(format!("(ipv6_dscp == 6'd{})", dscp));
    }
    if let Some(ecn) = mc.ipv6_ecn {
        conditions.push(format!("(ipv6_ecn == 2'd{})", ecn));
    }

    // TCP flags (value & mask comparison)
    if let Some(flags) = mc.tcp_flags {
        let mask = mc.tcp_flags_mask.unwrap_or(0xFF);
        conditions.push(format!("((tcp_flags & 8'd{}) == 8'd{})", mask, flags & mask));
    }

    // ICMP type/code
    if let Some(t) = mc.icmp_type {
        conditions.push(format!("(icmp_type_field == 8'd{})", t));
    }
    if let Some(c) = mc.icmp_code {
        conditions.push(format!("(icmp_code == 8'd{})", c));
    }

    // ICMPv6 type/code
    if let Some(t) = mc.icmpv6_type {
        conditions.push(format!("(icmpv6_type == 8'd{})", t));
    }
    if let Some(c) = mc.icmpv6_code {
        conditions.push(format!("(icmpv6_code == 8'd{})", c));
    }

    // ARP fields
    if let Some(op) = mc.arp_opcode {
        conditions.push(format!("(arp_opcode == 16'd{})", op));
    }
    if let Some(ref spa) = mc.arp_spa {
        let prefix = Ipv4Prefix::parse(spa)?;
        conditions.push(format!("(arp_spa == {})", prefix.to_verilog_value()));
    }
    if let Some(ref tpa) = mc.arp_tpa {
        let prefix = Ipv4Prefix::parse(tpa)?;
        conditions.push(format!("(arp_tpa == {})", prefix.to_verilog_value()));
    }

    // IPv6 extension fields
    if let Some(hl) = mc.ipv6_hop_limit {
        conditions.push(format!("(ipv6_hop_limit == 8'd{})", hl));
    }
    if let Some(fl) = mc.ipv6_flow_label {
        conditions.push(format!("(ipv6_flow_label == 20'd{})", fl));
    }

    // QinQ (802.1ad) double VLAN fields
    if let Some(vid) = mc.outer_vlan_id {
        conditions.push(format!("(outer_vlan_id == 12'd{})", vid));
    }
    if let Some(pcp) = mc.outer_vlan_pcp {
        conditions.push(format!("(outer_vlan_pcp == 3'd{})", pcp));
    }

    // IPv4 fragmentation fields
    if let Some(df) = mc.ip_dont_fragment {
        conditions.push(format!("(ip_dont_fragment == 1'b{})", if df { 1 } else { 0 }));
    }
    if let Some(mf) = mc.ip_more_fragments {
        conditions.push(format!("(ip_more_fragments == 1'b{})", if mf { 1 } else { 0 }));
    }
    if let Some(offset) = mc.ip_frag_offset {
        conditions.push(format!("(ip_frag_offset == 13'd{})", offset));
    }

    // GRE tunnel
    if let Some(proto) = mc.gre_protocol {
        conditions.push(format!("(gre_protocol == 16'h{:04x})", proto));
    }
    if let Some(key) = mc.gre_key {
        conditions.push(format!("(gre_key == 32'd{})", key));
    }

    // OAM/CFM fields
    if let Some(level) = mc.oam_level {
        conditions.push(format!("(oam_valid && oam_level == 3'd{})", level));
    }
    if let Some(opcode) = mc.oam_opcode {
        conditions.push(format!("(oam_valid && oam_opcode == 8'd{})", opcode));
    }

    // NSH/SFC fields
    if let Some(spi) = mc.nsh_spi {
        conditions.push(format!("(nsh_valid && nsh_spi == 24'd{})", spi));
    }
    if let Some(si) = mc.nsh_si {
        conditions.push(format!("(nsh_valid && nsh_si == 8'd{})", si));
    }
    if let Some(np) = mc.nsh_next_protocol {
        conditions.push(format!("(nsh_valid && nsh_next_protocol == 8'd{})", np));
    }

    // Geneve tunnel
    if let Some(vni) = mc.geneve_vni {
        conditions.push(format!("(geneve_valid && geneve_vni == 24'd{})", vni));
    }

    // ip_ttl (already extracted by parser)
    if let Some(ttl) = mc.ip_ttl {
        conditions.push(format!("(ip_ttl == 8'd{})", ttl));
    }

    // PTP (IEEE 1588) fields
    if let Some(mt) = mc.ptp_message_type {
        conditions.push(format!("(ptp_valid && ptp_message_type == 4'd{})", mt));
    }
    if let Some(dom) = mc.ptp_domain {
        conditions.push(format!("(ptp_valid && ptp_domain == 8'd{})", dom));
    }
    if let Some(ver) = mc.ptp_version {
        conditions.push(format!("(ptp_valid && ptp_version == 4'd{})", ver));
    }

    // Connection tracking state
    if let Some(ref state) = mc.conntrack_state {
        match state.as_str() {
            "established" => conditions.push("(conntrack_established == 1'b1)".to_string()),
            "new" => conditions.push("(conntrack_established == 1'b0)".to_string()),
            _ => {} // validated elsewhere
        }
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

    // Per-rule generation is done after global protocol flags are computed (below)

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

    // Check if any rule uses IPv6
    let has_ipv6 = config.pacgate.rules.iter().any(|r| {
        if r.is_stateful() {
            if let Some(ref fsm) = r.fsm {
                return fsm.states.values().any(|s| {
                    s.transitions.iter().any(|t| t.match_criteria.uses_ipv6())
                });
            }
            false
        } else {
            r.match_criteria.uses_ipv6()
        }
    });

    // Check for protocol extension features
    let has_gtp = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_gtp());
    let has_mpls = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_mpls());
    let has_multicast = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_multicast());
    let has_dscp_ecn = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_dscp_ecn());
    let has_ipv6_tc = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_ipv6_tc());
    let has_tcp_flags = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_tcp_flags());
    let has_icmp = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_icmp());
    let has_icmpv6 = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_icmpv6());
    let has_arp = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_arp());
    let has_ipv6_ext = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_ipv6_ext());
    let has_qinq = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_qinq());
    let has_ip_frag = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_ip_frag());
    let has_gre = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_gre());
    let has_oam = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_oam());
    let has_nsh = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_nsh());
    let has_conntrack_state = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_conntrack_state());
    let has_geneve = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_geneve());
    let has_ip_ttl = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_ip_ttl());
    let has_ptp = config.pacgate.rules.iter().any(|r| r.match_criteria.uses_ptp());
    let has_flow_counters = config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false);
    let has_mirror = config.pacgate.rules.iter().any(|r| r.has_mirror());
    let has_redirect = config.pacgate.rules.iter().any(|r| r.has_redirect());

    // Global protocol flags — all rules in a design must have consistent port lists
    let global_protos = GlobalProtocolFlags {
        has_ipv6,
        has_gtp,
        has_mpls,
        has_multicast,
        has_dscp_ecn,
        has_ipv6_tc,
        has_tcp_flags,
        has_icmp,
        has_icmpv6,
        has_arp,
        has_ipv6_ext,
        has_qinq,
        has_ip_frag,
        has_gre,
        has_oam,
        has_nsh,
        has_conntrack_state,
        has_geneve,
        has_ip_ttl,
        has_ptp,
        has_flow_counters,
        has_mirror,
        has_redirect,
    };

    // Generate per-rule matchers (stateless: combinational, stateful: registered FSM)
    for (idx, rule) in rules.iter().enumerate() {
        if rule.is_stateful() {
            generate_fsm_rule(&tera, &rtl_dir, idx, rule, &byte_offsets, &global_protos)?;
        } else {
            generate_stateless_rule(&tera, &rtl_dir, idx, rule, &byte_offsets, &global_protos)?;
        }
    }

    // Check if any rule has rewrite actions
    let has_rewrite = rules.iter().any(|r| r.has_rewrite());

    // Calculate index bit width (shared with decision_logic)
    let idx_bits = if rules.is_empty() { 1 } else {
        ((rules.len() as f64).log2().ceil() as usize).max(1)
    };

    // Generate rewrite LUT if any rule has rewrite actions
    if has_rewrite {
        generate_rewrite_lut(&tera, &rtl_dir, &rules, idx_bits)?;
    }

    // Generate egress LUT if any rule has mirror or redirect port
    if has_mirror || has_redirect {
        generate_egress_lut(&tera, &rtl_dir, &rules, idx_bits)?;
    }

    // Generate RSS queue LUT if any rule has rss_queue override
    let has_rss_queue = rules.iter().any(|r| r.has_rss_queue());
    if has_rss_queue {
        generate_rss_queue_lut(&tera, &rtl_dir, &rules, idx_bits)?;
    }

    // Generate top-level
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_rules", &rules.len());
        ctx.insert("has_byte_capture", &has_byte_capture);
        ctx.insert("has_ipv6", &has_ipv6);
        ctx.insert("has_gtp", &has_gtp);
        ctx.insert("has_mpls", &has_mpls);
        ctx.insert("has_multicast", &has_multicast);
        ctx.insert("has_dscp_ecn", &has_dscp_ecn);
        ctx.insert("has_ipv6_tc", &has_ipv6_tc);
        ctx.insert("has_tcp_flags", &has_tcp_flags);
        ctx.insert("has_icmp", &has_icmp);
        ctx.insert("has_icmpv6", &has_icmpv6);
        ctx.insert("has_arp", &has_arp);
        ctx.insert("has_ipv6_ext", &has_ipv6_ext);
        ctx.insert("has_qinq", &has_qinq);
        ctx.insert("has_ip_frag", &has_ip_frag);
        ctx.insert("has_gre", &has_gre);
        ctx.insert("has_oam", &has_oam);
        ctx.insert("has_nsh", &has_nsh);
        ctx.insert("has_conntrack_state", &has_conntrack_state);
        ctx.insert("has_geneve", &has_geneve);
        ctx.insert("has_ip_ttl", &has_ip_ttl);
        ctx.insert("has_ptp", &has_ptp);
        ctx.insert("has_flow_counters", &has_flow_counters);
        ctx.insert("has_rewrite", &has_rewrite);
        ctx.insert("has_mirror", &has_mirror);
        ctx.insert("has_redirect", &has_redirect);
        ctx.insert("idx_bits", &idx_bits);

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

/// Generate multi-table pipeline Verilog.
/// Creates per-stage rule matchers and decision logic, plus a pipeline_top wrapper.
pub fn generate_pipeline(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let tables = config.pacgate.tables.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Pipeline generation requires tables"))?;

    // Compute global protocol flags across ALL stages
    let all_rules = config.all_rules();
    let global_protos = compute_global_protos_from_rules(&all_rules, config);

    // Collect all byte_match offsets across all stages
    let byte_offsets = collect_byte_match_offsets_from_rules(&all_rules);
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
    }

    // Track total rules for global index width
    let total_rules: usize = tables.iter().map(|s| s.rules.len()).sum();
    let total_idx_bits = if total_rules == 0 { 1 } else {
        ((total_rules as f64).log2().ceil() as usize).max(1)
    };

    // Generate per-stage rule matchers and decision logic
    let mut stage_infos: Vec<serde_json::Value> = Vec::new();
    let mut global_rule_offset = 0usize;

    for (stage_idx, stage) in tables.iter().enumerate() {
        let mut rules = stage.rules.clone();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        let stage_idx_bits = if rules.is_empty() { 1 } else {
            ((rules.len() as f64).log2().ceil() as usize).max(1)
        };

        // Generate per-rule matchers with stage-prefixed names
        for (rule_idx, rule) in rules.iter().enumerate() {
            let module_name = format!("rule_match_s{}_r{}", stage_idx, rule_idx);
            generate_stateless_rule_with_name(&tera, &rtl_dir, rule_idx, rule, &byte_offsets, &global_protos, &module_name)?;
        }

        // Generate per-stage decision logic
        {
            let mut ctx = tera::Context::new();
            ctx.insert("num_rules", &rules.len());
            let default_pass = stage.default_action == Action::Pass;
            ctx.insert("default_pass", &default_pass);
            ctx.insert("idx_bits", &stage_idx_bits);
            ctx.insert("module_name", &format!("decision_logic_s{}", stage_idx));

            let rule_info: Vec<_> = rules.iter().enumerate().map(|(idx, rule)| {
                let mut map = std::collections::HashMap::new();
                map.insert("index".to_string(), idx.to_string());
                map.insert("name".to_string(), rule.name.clone());
                let action_pass = (rule.action() == Action::Pass).to_string();
                map.insert("action_pass".to_string(), action_pass);
                map
            }).collect();
            ctx.insert("rules", &rule_info);

            let rendered = tera.render("decision_logic.v.tera", &ctx)?;
            // Replace module name in rendered output
            let rendered = rendered.replace("module decision_logic", &format!("module decision_logic_s{}", stage_idx));
            std::fs::write(rtl_dir.join(format!("decision_logic_s{}.v", stage_idx)), &rendered)?;
            log::info!("Generated decision_logic_s{}.v", stage_idx);
        }

        // Build stage info for pipeline_top template
        let rule_infos: Vec<serde_json::Value> = rules.iter().enumerate().map(|(idx, rule)| {
            serde_json::json!({
                "index": idx,
                "name": rule.name,
                "global_index": global_rule_offset + idx,
            })
        }).collect();

        stage_infos.push(serde_json::json!({
            "index": stage_idx,
            "name": stage.name,
            "num_rules": rules.len(),
            "idx_bits": stage_idx_bits,
            "rules": rule_infos,
        }));

        global_rule_offset += rules.len();
    }

    // Generate pipeline_top.v
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_stages", &tables.len());
        ctx.insert("stages", &stage_infos);
        ctx.insert("total_idx_bits", &total_idx_bits);
        ctx.insert("has_ipv6", &global_protos.has_ipv6);
        ctx.insert("has_gtp", &global_protos.has_gtp);
        ctx.insert("has_mpls", &global_protos.has_mpls);
        ctx.insert("has_multicast", &global_protos.has_multicast);
        ctx.insert("has_dscp_ecn", &global_protos.has_dscp_ecn);
        ctx.insert("has_ipv6_tc", &global_protos.has_ipv6_tc);
        ctx.insert("has_tcp_flags", &global_protos.has_tcp_flags);
        ctx.insert("has_icmp", &global_protos.has_icmp);
        ctx.insert("has_icmpv6", &global_protos.has_icmpv6);
        ctx.insert("has_arp", &global_protos.has_arp);
        ctx.insert("has_ipv6_ext", &global_protos.has_ipv6_ext);
        ctx.insert("has_qinq", &global_protos.has_qinq);
        ctx.insert("has_ip_frag", &global_protos.has_ip_frag);
        ctx.insert("has_gre", &global_protos.has_gre);
        ctx.insert("has_oam", &global_protos.has_oam);
        ctx.insert("has_nsh", &global_protos.has_nsh);
        ctx.insert("has_conntrack_state", &global_protos.has_conntrack_state);
        ctx.insert("has_geneve", &global_protos.has_geneve);
        ctx.insert("has_ip_ttl", &global_protos.has_ip_ttl);
        ctx.insert("has_ptp", &global_protos.has_ptp);
        ctx.insert("has_byte_capture", &has_byte_capture);

        let rendered = tera.render("pipeline_top.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("pipeline_top.v"), &rendered)?;
        log::info!("Generated pipeline_top.v ({} stages)", tables.len());
    }

    // Copy frame_parser.v (shared across all pipeline stages)
    {
        let src = Path::new("rtl").join("frame_parser.v");
        if src.exists() {
            let dst = rtl_dir.join("frame_parser.v");
            std::fs::copy(&src, &dst)
                .with_context(|| "Failed to copy frame_parser.v to output")?;
            log::info!("Copied frame_parser.v to {}", dst.display());
        }
    }

    Ok(())
}

/// Compute GlobalProtocolFlags from a list of rule references
fn compute_global_protos_from_rules(all_rules: &[&crate::model::StatelessRule], config: &FilterConfig) -> GlobalProtocolFlags {
    GlobalProtocolFlags {
        has_ipv6: all_rules.iter().any(|r| r.match_criteria.uses_ipv6()),
        has_gtp: all_rules.iter().any(|r| r.match_criteria.uses_gtp()),
        has_mpls: all_rules.iter().any(|r| r.match_criteria.uses_mpls()),
        has_multicast: all_rules.iter().any(|r| r.match_criteria.uses_multicast()),
        has_dscp_ecn: all_rules.iter().any(|r| r.match_criteria.uses_dscp_ecn()),
        has_ipv6_tc: all_rules.iter().any(|r| r.match_criteria.uses_ipv6_tc()),
        has_tcp_flags: all_rules.iter().any(|r| r.match_criteria.uses_tcp_flags()),
        has_icmp: all_rules.iter().any(|r| r.match_criteria.uses_icmp()),
        has_icmpv6: all_rules.iter().any(|r| r.match_criteria.uses_icmpv6()),
        has_arp: all_rules.iter().any(|r| r.match_criteria.uses_arp()),
        has_ipv6_ext: all_rules.iter().any(|r| r.match_criteria.uses_ipv6_ext()),
        has_qinq: all_rules.iter().any(|r| r.match_criteria.uses_qinq()),
        has_ip_frag: all_rules.iter().any(|r| r.match_criteria.uses_ip_frag()),
        has_gre: all_rules.iter().any(|r| r.match_criteria.uses_gre()),
        has_oam: all_rules.iter().any(|r| r.match_criteria.uses_oam()),
        has_nsh: all_rules.iter().any(|r| r.match_criteria.uses_nsh()),
        has_conntrack_state: all_rules.iter().any(|r| r.match_criteria.uses_conntrack_state()),
        has_geneve: all_rules.iter().any(|r| r.match_criteria.uses_geneve()),
        has_ip_ttl: all_rules.iter().any(|r| r.match_criteria.uses_ip_ttl()),
        has_ptp: all_rules.iter().any(|r| r.match_criteria.uses_ptp()),
        has_flow_counters: config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false),
        has_mirror: all_rules.iter().any(|r| r.has_mirror()),
        has_redirect: all_rules.iter().any(|r| r.has_redirect()),
    }
}

/// Collect byte_match offsets from a list of rule references
fn collect_byte_match_offsets_from_rules(all_rules: &[&crate::model::StatelessRule]) -> Vec<(u16, usize)> {
    let mut offsets: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for rule in all_rules {
        if let Some(ref bm) = rule.match_criteria.byte_match {
            for m in bm {
                let byte_len = (m.value.len() / 2).max(1);
                offsets.entry(m.offset as u16).or_insert(byte_len);
            }
        }
    }
    offsets.into_iter().collect()
}

/// Generate a stateless rule matcher with a custom module name
fn generate_stateless_rule_with_name(
    tera: &Tera,
    rtl_dir: &Path,
    rule_idx: usize,
    rule: &crate::model::StatelessRule,
    byte_offsets: &[(u16, usize)],
    global_protos: &GlobalProtocolFlags,
    module_name: &str,
) -> Result<()> {
    // Delegate to generate_stateless_rule, then rename the module
    generate_stateless_rule(tera, rtl_dir, rule_idx, rule, byte_offsets, global_protos)?;

    // Rename the generated file and module name
    let src_file = rtl_dir.join(format!("rule_match_{}.v", rule_idx));
    let dst_file = rtl_dir.join(format!("{}.v", module_name));

    if src_file.exists() {
        let content = std::fs::read_to_string(&src_file)?;
        let content = content.replace(
            &format!("module rule_match_{}", rule_idx),
            &format!("module {}", module_name),
        );
        std::fs::write(&dst_file, &content)?;
        if src_file != dst_file {
            std::fs::remove_file(&src_file)?;
        }
        log::info!("Generated {}.v", module_name);
    }

    Ok(())
}

/// Generate rewrite LUT: combinational ROM mapping rule_idx → rewrite parameters
fn generate_rewrite_lut(tera: &Tera, rtl_dir: &Path, rules: &[crate::model::StatelessRule], idx_bits: usize) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("idx_bits", &idx_bits);

    let rewrite_entries: Vec<std::collections::HashMap<String, serde_json::Value>> = rules.iter().enumerate()
        .filter(|(_, rule)| rule.has_rewrite())
        .map(|(idx, rule)| {
            let rw = rule.rewrite.as_ref().unwrap();
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), serde_json::json!(idx));

            let flags = rw.flags();
            map.insert("flags_bin".to_string(), serde_json::json!(format!("{:016b}", flags)));

            // MAC addresses
            if let Some(ref mac) = rw.set_dst_mac {
                map.insert("has_dst_mac".to_string(), serde_json::json!(true));
                let m = MacAddress::parse(mac).unwrap();
                map.insert("dst_mac".to_string(), serde_json::json!(m.to_verilog_value()));
            } else {
                map.insert("has_dst_mac".to_string(), serde_json::json!(false));
            }
            if let Some(ref mac) = rw.set_src_mac {
                map.insert("has_src_mac".to_string(), serde_json::json!(true));
                let m = MacAddress::parse(mac).unwrap();
                map.insert("src_mac".to_string(), serde_json::json!(m.to_verilog_value()));
            } else {
                map.insert("has_src_mac".to_string(), serde_json::json!(false));
            }

            // VLAN ID
            if let Some(vid) = rw.set_vlan_id {
                map.insert("has_vlan_id".to_string(), serde_json::json!(true));
                map.insert("vlan_id".to_string(), serde_json::json!(vid));
            } else {
                map.insert("has_vlan_id".to_string(), serde_json::json!(false));
            }

            // TTL
            if let Some(ttl) = rw.set_ttl {
                map.insert("has_ttl".to_string(), serde_json::json!(true));
                map.insert("ttl".to_string(), serde_json::json!(ttl));
            } else {
                map.insert("has_ttl".to_string(), serde_json::json!(false));
            }

            // IP addresses
            if let Some(ref ip) = rw.set_src_ip {
                map.insert("has_src_ip".to_string(), serde_json::json!(true));
                let prefix = Ipv4Prefix::parse(ip).unwrap();
                map.insert("src_ip".to_string(), serde_json::json!(prefix.to_verilog_value()));
            } else {
                map.insert("has_src_ip".to_string(), serde_json::json!(false));
            }
            if let Some(ref ip) = rw.set_dst_ip {
                map.insert("has_dst_ip".to_string(), serde_json::json!(true));
                let prefix = Ipv4Prefix::parse(ip).unwrap();
                map.insert("dst_ip".to_string(), serde_json::json!(prefix.to_verilog_value()));
            } else {
                map.insert("has_dst_ip".to_string(), serde_json::json!(false));
            }

            // DSCP
            if let Some(dscp) = rw.set_dscp {
                map.insert("has_dscp".to_string(), serde_json::json!(true));
                map.insert("dscp".to_string(), serde_json::json!(dscp));
            } else {
                map.insert("has_dscp".to_string(), serde_json::json!(false));
            }

            // L4 port rewrite
            if let Some(port) = rw.set_src_port {
                map.insert("has_src_port".to_string(), serde_json::json!(true));
                map.insert("src_port".to_string(), serde_json::json!(port));
            } else {
                map.insert("has_src_port".to_string(), serde_json::json!(false));
            }
            if let Some(port) = rw.set_dst_port {
                map.insert("has_dst_port".to_string(), serde_json::json!(true));
                map.insert("dst_port".to_string(), serde_json::json!(port));
            } else {
                map.insert("has_dst_port".to_string(), serde_json::json!(false));
            }

            // IPv6 hop limit rewrite
            if let Some(hl) = rw.set_hop_limit {
                map.insert("has_hop_limit".to_string(), serde_json::json!(true));
                map.insert("hop_limit".to_string(), serde_json::json!(hl));
            } else {
                map.insert("has_hop_limit".to_string(), serde_json::json!(false));
            }

            // ECN rewrite
            if let Some(ecn) = rw.set_ecn {
                map.insert("has_ecn".to_string(), serde_json::json!(true));
                map.insert("ecn".to_string(), serde_json::json!(ecn));
            } else {
                map.insert("has_ecn".to_string(), serde_json::json!(false));
            }

            // VLAN PCP rewrite
            if let Some(pcp) = rw.set_vlan_pcp {
                map.insert("has_vlan_pcp".to_string(), serde_json::json!(true));
                map.insert("vlan_pcp".to_string(), serde_json::json!(pcp));
            } else {
                map.insert("has_vlan_pcp".to_string(), serde_json::json!(false));
            }

            // Outer VLAN ID rewrite (QinQ)
            if let Some(vid) = rw.set_outer_vlan_id {
                map.insert("has_outer_vlan_id".to_string(), serde_json::json!(true));
                map.insert("outer_vlan_id".to_string(), serde_json::json!(vid));
            } else {
                map.insert("has_outer_vlan_id".to_string(), serde_json::json!(false));
            }

            map
        })
        .collect();

    ctx.insert("rewrite_entries", &rewrite_entries);
    let rendered = tera.render("rewrite_lut.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("rewrite_lut.v"), &rendered)?;
    log::info!("Generated rewrite_lut.v");
    Ok(())
}

/// Generate egress LUT: combinational ROM mapping rule_idx → mirror/redirect port parameters
fn generate_egress_lut(tera: &Tera, rtl_dir: &Path, rules: &[crate::model::StatelessRule], idx_bits: usize) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("idx_bits", &idx_bits);

    let egress_entries: Vec<std::collections::HashMap<String, serde_json::Value>> = rules.iter().enumerate()
        .filter(|(_, rule)| rule.has_mirror() || rule.has_redirect())
        .map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), serde_json::json!(idx));

            if let Some(port) = rule.mirror_port {
                map.insert("has_mirror_port".to_string(), serde_json::json!(true));
                map.insert("mirror_port".to_string(), serde_json::json!(port));
            } else {
                map.insert("has_mirror_port".to_string(), serde_json::json!(false));
            }

            if let Some(port) = rule.redirect_port {
                map.insert("has_redirect_port".to_string(), serde_json::json!(true));
                map.insert("redirect_port".to_string(), serde_json::json!(port));
            } else {
                map.insert("has_redirect_port".to_string(), serde_json::json!(false));
            }

            map
        })
        .collect();

    ctx.insert("egress_entries", &egress_entries);
    let rendered = tera.render("egress_lut.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("egress_lut.v"), &rendered)?;
    log::info!("Generated egress_lut.v");
    Ok(())
}

/// Generate RSS queue override LUT (combinational ROM mapping rule_idx to queue).
fn generate_rss_queue_lut(tera: &Tera, rtl_dir: &Path, rules: &[crate::model::StatelessRule], idx_bits: usize) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("idx_bits", &idx_bits);

    let rss_entries: Vec<std::collections::HashMap<String, serde_json::Value>> = rules.iter().enumerate()
        .filter(|(_, rule)| rule.has_rss_queue())
        .map(|(idx, rule)| {
            let mut map = std::collections::HashMap::new();
            map.insert("index".to_string(), serde_json::json!(idx));
            map.insert("rss_queue".to_string(), serde_json::json!(rule.rss_queue.unwrap()));
            map
        })
        .collect();

    ctx.insert("rss_entries", &rss_entries);
    let rendered = tera.render("rss_queue_lut.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("rss_queue_lut.v"), &rendered)?;
    log::info!("Generated rss_queue_lut.v");
    Ok(())
}

/// Generate dynamic flow table RTL (register-based, AXI-Lite writable).
/// Replaces per-rule static matchers with a single flow_table module.
pub fn generate_dynamic(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, num_entries: u16) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    // Sort rules by priority (highest first)
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    let default_pass = config.pacgate.defaults.action == Action::Pass;

    // Build initial entry data from YAML rules
    let initial_entries: Vec<std::collections::HashMap<String, serde_json::Value>> = rules.iter().enumerate().map(|(idx, rule)| {
        rule_to_flow_entry(idx, rule)
    }).collect();

    // Calculate index bit width
    let idx_bits = if num_entries <= 1 { 1 } else {
        ((num_entries as f64).log2().ceil() as usize).max(1)
    };

    // Render flow_table.v
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_entries", &num_entries);
        ctx.insert("num_initial_entries", &initial_entries.len());
        ctx.insert("default_pass", &default_pass);
        ctx.insert("initial_entries", &initial_entries);
        ctx.insert("idx_bits", &idx_bits);

        let rendered = tera.render("flow_table.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("flow_table.v"), &rendered)?;
        log::info!("Generated flow_table.v ({} entries, {} initial)", num_entries, initial_entries.len());
    }

    // Render dynamic top-level
    {
        let mut ctx = tera::Context::new();
        ctx.insert("num_entries", &num_entries);
        ctx.insert("idx_bits", &idx_bits);
        ctx.insert("default_pass", &default_pass);

        let rendered = tera.render("packet_filter_dynamic_top.v.tera", &ctx)?;
        std::fs::write(rtl_dir.join("packet_filter_top.v"), &rendered)?;
        log::info!("Generated packet_filter_top.v (dynamic mode)");
    }

    // Copy frame_parser.v (still needed)
    {
        let src = Path::new("rtl").join("frame_parser.v");
        if src.exists() {
            let dst = rtl_dir.join("frame_parser.v");
            std::fs::copy(&src, &dst)
                .with_context(|| "Failed to copy frame_parser.v to output")?;
            log::info!("Copied frame_parser.v to {}", dst.display());
        }
    }

    Ok(())
}

/// Convert a YAML rule to flow table entry data for template rendering.
/// All numeric values are pre-formatted as hex or decimal strings for direct template use.
fn rule_to_flow_entry(idx: usize, rule: &crate::model::StatelessRule) -> std::collections::HashMap<String, serde_json::Value> {
    let mc = &rule.match_criteria;
    let mut entry = std::collections::HashMap::new();

    entry.insert("index".to_string(), serde_json::json!(idx));
    entry.insert("name".to_string(), serde_json::json!(rule.name));
    entry.insert("priority".to_string(), serde_json::json!(rule.priority));
    entry.insert("action_pass".to_string(), serde_json::json!(rule.action() == Action::Pass));

    // Ethertype (hex strings)
    if let Some(ref et) = mc.ethertype {
        if let Ok(val) = parse_ethertype(et) {
            entry.insert("ethertype_val_hex".to_string(), serde_json::json!(format!("{:04x}", val)));
            entry.insert("ethertype_msk_hex".to_string(), serde_json::json!("ffff"));
        }
    }
    if !entry.contains_key("ethertype_val_hex") {
        entry.insert("ethertype_val_hex".to_string(), serde_json::json!("0000"));
        entry.insert("ethertype_msk_hex".to_string(), serde_json::json!("0000"));
    }

    // DST MAC (hex strings, 12 chars)
    if let Some(ref mac_str) = mc.dst_mac {
        if let Ok(mac) = MacAddress::parse(mac_str) {
            entry.insert("dst_mac_val".to_string(), serde_json::json!(format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.value[0], mac.value[1], mac.value[2],
                mac.value[3], mac.value[4], mac.value[5]
            )));
            entry.insert("dst_mac_msk".to_string(), serde_json::json!(format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.mask[0], mac.mask[1], mac.mask[2],
                mac.mask[3], mac.mask[4], mac.mask[5]
            )));
        }
    }
    if !entry.contains_key("dst_mac_val") {
        entry.insert("dst_mac_val".to_string(), serde_json::json!("000000000000"));
        entry.insert("dst_mac_msk".to_string(), serde_json::json!("000000000000"));
    }

    // SRC MAC (hex strings, 12 chars)
    if let Some(ref mac_str) = mc.src_mac {
        if let Ok(mac) = MacAddress::parse(mac_str) {
            entry.insert("src_mac_val".to_string(), serde_json::json!(format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.value[0], mac.value[1], mac.value[2],
                mac.value[3], mac.value[4], mac.value[5]
            )));
            entry.insert("src_mac_msk".to_string(), serde_json::json!(format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.mask[0], mac.mask[1], mac.mask[2],
                mac.mask[3], mac.mask[4], mac.mask[5]
            )));
        }
    }
    if !entry.contains_key("src_mac_val") {
        entry.insert("src_mac_val".to_string(), serde_json::json!("000000000000"));
        entry.insert("src_mac_msk".to_string(), serde_json::json!("000000000000"));
    }

    // VLAN ID (decimal values)
    entry.insert("vlan_id_val".to_string(), serde_json::json!(mc.vlan_id.unwrap_or(0)));
    entry.insert("vlan_id_msk_hex".to_string(), serde_json::json!(
        if mc.vlan_id.is_some() { "fff" } else { "000" }
    ));

    // IP protocol (decimal values)
    entry.insert("ip_protocol_val".to_string(), serde_json::json!(mc.ip_protocol.unwrap_or(0)));
    entry.insert("ip_protocol_msk_hex".to_string(), serde_json::json!(
        if mc.ip_protocol.is_some() { "ff" } else { "00" }
    ));

    // SRC IP (CIDR → hex value/mask)
    if let Some(ref ip) = mc.src_ip {
        if let Ok(prefix) = Ipv4Prefix::parse(ip) {
            let val = u32::from_be_bytes(prefix.addr);
            let msk = u32::from_be_bytes(prefix.mask);
            entry.insert("src_ip_val_hex".to_string(), serde_json::json!(format!("{:08x}", val)));
            entry.insert("src_ip_msk_hex".to_string(), serde_json::json!(format!("{:08x}", msk)));
        }
    }
    if !entry.contains_key("src_ip_val_hex") {
        entry.insert("src_ip_val_hex".to_string(), serde_json::json!("00000000"));
        entry.insert("src_ip_msk_hex".to_string(), serde_json::json!("00000000"));
    }

    // DST IP (CIDR → hex value/mask)
    if let Some(ref ip) = mc.dst_ip {
        if let Ok(prefix) = Ipv4Prefix::parse(ip) {
            let val = u32::from_be_bytes(prefix.addr);
            let msk = u32::from_be_bytes(prefix.mask);
            entry.insert("dst_ip_val_hex".to_string(), serde_json::json!(format!("{:08x}", val)));
            entry.insert("dst_ip_msk_hex".to_string(), serde_json::json!(format!("{:08x}", msk)));
        }
    }
    if !entry.contains_key("dst_ip_val_hex") {
        entry.insert("dst_ip_val_hex".to_string(), serde_json::json!("00000000"));
        entry.insert("dst_ip_msk_hex".to_string(), serde_json::json!("00000000"));
    }

    // SRC port (min/max decimal)
    match &mc.src_port {
        Some(crate::model::PortMatch::Exact(port)) => {
            entry.insert("src_port_min".to_string(), serde_json::json!(port));
            entry.insert("src_port_max".to_string(), serde_json::json!(port));
        }
        Some(crate::model::PortMatch::Range { range }) => {
            entry.insert("src_port_min".to_string(), serde_json::json!(range[0]));
            entry.insert("src_port_max".to_string(), serde_json::json!(range[1]));
        }
        None => {
            entry.insert("src_port_min".to_string(), serde_json::json!(0u16));
            entry.insert("src_port_max".to_string(), serde_json::json!(65535u16));
        }
    }

    // DST port (min/max decimal)
    match &mc.dst_port {
        Some(crate::model::PortMatch::Exact(port)) => {
            entry.insert("dst_port_min".to_string(), serde_json::json!(port));
            entry.insert("dst_port_max".to_string(), serde_json::json!(port));
        }
        Some(crate::model::PortMatch::Range { range }) => {
            entry.insert("dst_port_min".to_string(), serde_json::json!(range[0]));
            entry.insert("dst_port_max".to_string(), serde_json::json!(range[1]));
        }
        None => {
            entry.insert("dst_port_min".to_string(), serde_json::json!(0u16));
            entry.insert("dst_port_max".to_string(), serde_json::json!(65535u16));
        }
    }

    entry
}

/// Generate multi-port wrapper that instantiates N independent packet_filter_top instances.
pub fn generate_multiport(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, num_ports: u16) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let mut ctx = tera::Context::new();
    ctx.insert("num_ports", &num_ports);
    ctx.insert("num_rules", &config.pacgate.rules.len());

    let byte_offsets = collect_byte_match_offsets(config);
    let has_byte_capture = !byte_offsets.is_empty();
    ctx.insert("has_byte_capture", &has_byte_capture);

    let rendered = tera.render("packet_filter_multiport_top.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("packet_filter_multiport_top.v"), &rendered)?;
    log::info!("Generated packet_filter_multiport_top.v ({} ports)", num_ports);

    Ok(())
}

/// Generate or copy AXI-Stream RTL modules to the output directory.
/// When has_rewrite=true, renders the AXI top template with rewrite wiring.
/// Otherwise, copies the original hand-written modules.
pub fn copy_axi_rtl(output_dir: &Path, config: &FilterConfig, templates_dir: &Path, data_width: u16, rss_enabled: bool, rss_queues: u8) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    // Always copy adapter and FIFO (hand-written infrastructure)
    let copy_files = [
        "axi_stream_adapter.v",
        "store_forward_fifo.v",
    ];
    for filename in &copy_files {
        let src = Path::new("rtl").join(filename);
        let dst = rtl_dir.join(filename);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("Failed to copy {} to output", filename))?;
        log::info!("Copied {} to {}", filename, dst.display());
    }

    // Check if any rule has rewrite actions
    let has_rewrite = config.pacgate.rules.iter().any(|r| r.has_rewrite());
    let has_mirror = config.pacgate.rules.iter().any(|r| r.has_mirror());
    let has_redirect = config.pacgate.rules.iter().any(|r| r.has_redirect());

    if has_rewrite {
        // Copy packet_rewrite.v (hand-written rewrite engine)
        let src = Path::new("rtl").join("packet_rewrite.v");
        let dst = rtl_dir.join("packet_rewrite.v");
        std::fs::copy(&src, &dst)
            .with_context(|| "Failed to copy packet_rewrite.v to output")?;
        log::info!("Copied packet_rewrite.v to {}", dst.display());
    }

    // Generate parameterized width converters if data_width > 8
    if data_width > 8 {
        generate_width_converters(templates_dir, &rtl_dir, data_width)?;
    }

    // Render AXI top from template (supports both rewrite and non-rewrite modes)
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rules = &config.pacgate.rules;
    let idx_bits = if rules.is_empty() { 1 } else {
        ((rules.len() as f64).log2().ceil() as usize).max(1)
    };

    let has_flow_counters = config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false);

    let mut ctx = tera::Context::new();
    ctx.insert("has_rewrite", &has_rewrite);
    ctx.insert("has_mirror", &has_mirror);
    ctx.insert("has_redirect", &has_redirect);
    ctx.insert("has_flow_counters", &has_flow_counters);
    ctx.insert("idx_bits", &idx_bits);
    ctx.insert("num_rules", &rules.len());
    ctx.insert("data_width", &data_width);
    ctx.insert("data_width_bytes", &(data_width / 8));
    ctx.insert("tkeep_width", &(data_width / 8));
    ctx.insert("rss_enabled", &rss_enabled);
    ctx.insert("rss_queues", &rss_queues);
    let has_rss_queue_lut = config.pacgate.rules.iter().any(|r| r.has_rss_queue());
    ctx.insert("has_rss_queue_lut", &has_rss_queue_lut);

    // INT (In-band Network Telemetry) — disabled at this level
    // Use enable_int_in_axi_top() after copy_axi_rtl() to enable
    ctx.insert("int_enabled", &false);
    ctx.insert("int_switch_id", &0u16);
    ctx.insert("has_int_lut", &false);
    ctx.insert("has_ptp", &false);

    let rendered = tera.render("packet_filter_axi_top.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("packet_filter_axi_top.v"), &rendered)?;
    log::info!("Generated packet_filter_axi_top.v (has_rewrite={}, data_width={}, rss={})", has_rewrite, data_width, rss_enabled);

    Ok(())
}

/// Re-render AXI top with INT enabled. Call after copy_axi_rtl().
pub fn enable_int_in_axi_top(output_dir: &Path, config: &FilterConfig, templates_dir: &Path, data_width: u16, rss_enabled: bool, rss_queues: u8, int_switch_id: u16, has_ptp: bool) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rules = &config.pacgate.rules;
    let idx_bits = if rules.is_empty() { 1 } else {
        ((rules.len() as f64).log2().ceil() as usize).max(1)
    };
    let has_rewrite = rules.iter().any(|r| r.has_rewrite());
    let has_mirror = rules.iter().any(|r| r.has_mirror());
    let has_redirect = rules.iter().any(|r| r.has_redirect());
    let has_flow_counters = config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false);
    let has_rss_queue_lut = rules.iter().any(|r| r.has_rss_queue());
    let has_int_lut = rules.iter().any(|r| r.has_int_insert());

    let mut ctx = tera::Context::new();
    ctx.insert("has_rewrite", &has_rewrite);
    ctx.insert("has_mirror", &has_mirror);
    ctx.insert("has_redirect", &has_redirect);
    ctx.insert("has_flow_counters", &has_flow_counters);
    ctx.insert("idx_bits", &idx_bits);
    ctx.insert("num_rules", &rules.len());
    ctx.insert("data_width", &data_width);
    ctx.insert("data_width_bytes", &(data_width / 8));
    ctx.insert("tkeep_width", &(data_width / 8));
    ctx.insert("rss_enabled", &rss_enabled);
    ctx.insert("rss_queues", &rss_queues);
    ctx.insert("has_rss_queue_lut", &has_rss_queue_lut);
    ctx.insert("int_enabled", &true);
    ctx.insert("int_switch_id", &int_switch_id);
    ctx.insert("has_int_lut", &has_int_lut);
    ctx.insert("has_ptp", &has_ptp);

    let rendered = tera.render("packet_filter_axi_top.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("packet_filter_axi_top.v"), &rendered)?;
    log::info!("Re-generated packet_filter_axi_top.v with INT enabled (switch_id={})", int_switch_id);

    Ok(())
}

/// Generate parameterized width converter Verilog from templates.
pub fn generate_width_converters(templates_dir: &Path, rtl_dir: &Path, data_width: u16) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let mut ctx = tera::Context::new();
    ctx.insert("data_width", &data_width);
    ctx.insert("keep_width", &(data_width / 8));
    ctx.insert("data_width_minus_1", &(data_width - 1));
    ctx.insert("keep_width_minus_1", &(data_width / 8 - 1));
    // Bit width for byte index counter
    let byte_idx_bits = ((data_width / 8) as f64).log2().ceil() as u16;
    ctx.insert("byte_idx_bits", &byte_idx_bits);
    // Byte count including zero (need +1 bit for full count)
    ctx.insert("byte_count_bits", &(byte_idx_bits + 1));

    // Generate wide-to-8 converter
    let rendered = tera.render("axis_wide_to_8.v.tera", &ctx)?;
    let filename = format!("axis_{}_to_8.v", data_width);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {} (parameterized width converter)", filename);

    // Generate 8-to-wide converter
    let rendered = tera.render("axis_8_to_wide.v.tera", &ctx)?;
    let filename = format!("axis_8_to_{}.v", data_width);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {} (parameterized width converter)", filename);

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

/// Copy hand-written connection tracking RTL to the output directory.
pub fn copy_conntrack_rtl(output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let src = Path::new("rtl").join("conntrack_table.v");
    let dst = rtl_dir.join("conntrack_table.v");
    std::fs::copy(&src, &dst)
        .with_context(|| "Failed to copy conntrack_table.v to output")?;
    log::info!("Copied conntrack_table.v to {}", dst.display());

    Ok(())
}

/// Copy hand-written rate limiter RTL to the output directory.
pub fn copy_rate_limiter_rtl(output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let src = Path::new("rtl").join("rate_limiter.v");
    let dst = rtl_dir.join("rate_limiter.v");
    std::fs::copy(&src, &dst)
        .with_context(|| "Failed to copy rate_limiter.v to output")?;
    log::info!("Copied rate_limiter.v to {}", dst.display());

    Ok(())
}

/// Copy 512-bit width converter RTL to the output directory (for platform targets).
pub fn copy_width_converter_rtl(output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let width_files = [
        "axis_512_to_8.v",
        "axis_8_to_512.v",
    ];

    for filename in &width_files {
        let src = Path::new("rtl").join(filename);
        let dst = rtl_dir.join(filename);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("Failed to copy {} to output", filename))?;
        log::info!("Copied {} to {}", filename, dst.display());
    }

    Ok(())
}

/// Generate INT LUT from rules with int_insert enabled.
pub fn generate_int_lut(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let mut int_rules = Vec::new();
    for (idx, rule) in config.pacgate.rules.iter().enumerate() {
        if rule.has_int_insert() {
            let mut map = std::collections::HashMap::new();
            map.insert("idx".to_string(), serde_json::json!(idx));
            map.insert("name".to_string(), serde_json::json!(rule.name));
            int_rules.push(map);
        }
    }

    let mut ctx = tera::Context::new();
    ctx.insert("int_rules", &int_rules);

    let rendered = tera.render("int_lut.v.tera", &ctx)
        .context("Failed to render int_lut.v.tera")?;

    let path = rtl_dir.join("int_lut.v");
    std::fs::write(&path, rendered)?;
    log::info!("Generated {}", path.display());

    Ok(())
}

/// Generate OpenNIC platform wrapper from template.
pub fn generate_opennic_wrapper(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, rss_enabled: bool, rss_queues: u8) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rules = &config.pacgate.rules;
    let has_rewrite = rules.iter().any(|r| r.has_rewrite());
    let has_mirror = rules.iter().any(|r| r.has_mirror());
    let has_redirect = rules.iter().any(|r| r.has_redirect());
    let idx_bits = if rules.is_empty() { 1 } else {
        ((rules.len() as f64).log2().ceil() as usize).max(1)
    };
    let has_counters = true; // OpenNIC typically wants CSR access
    let has_flow_counters = config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false);

    let mut ctx = tera::Context::new();
    ctx.insert("has_rewrite", &has_rewrite);
    ctx.insert("has_mirror", &has_mirror);
    ctx.insert("has_redirect", &has_redirect);
    ctx.insert("has_counters", &has_counters);
    ctx.insert("has_flow_counters", &has_flow_counters);
    ctx.insert("rss_enabled", &rss_enabled);
    ctx.insert("rss_queues", &rss_queues);
    ctx.insert("idx_bits", &idx_bits);
    ctx.insert("num_rules", &rules.len());
    ctx.insert("int_enabled", &false);

    let rendered = tera.render("pacgate_opennic_250.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("pacgate_opennic_250.v"), &rendered)?;
    log::info!("Generated pacgate_opennic_250.v (OpenNIC wrapper)");

    Ok(())
}

/// Generate Corundum platform wrapper from template.
pub fn generate_corundum_wrapper(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, rss_enabled: bool, rss_queues: u8) -> Result<()> {
    let rtl_dir = output_dir.join("rtl");
    std::fs::create_dir_all(&rtl_dir)?;

    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let rules = &config.pacgate.rules;
    let has_rewrite = rules.iter().any(|r| r.has_rewrite());
    let has_mirror = rules.iter().any(|r| r.has_mirror());
    let has_redirect = rules.iter().any(|r| r.has_redirect());
    let idx_bits = if rules.is_empty() { 1 } else {
        ((rules.len() as f64).log2().ceil() as usize).max(1)
    };

    let has_flow_counters = config.pacgate.conntrack.as_ref().and_then(|c| c.enable_flow_counters).unwrap_or(false);

    let mut ctx = tera::Context::new();
    ctx.insert("has_rewrite", &has_rewrite);
    ctx.insert("has_mirror", &has_mirror);
    ctx.insert("has_redirect", &has_redirect);
    ctx.insert("has_flow_counters", &has_flow_counters);
    ctx.insert("rss_enabled", &rss_enabled);
    ctx.insert("rss_queues", &rss_queues);
    ctx.insert("idx_bits", &idx_bits);
    ctx.insert("num_rules", &rules.len());
    ctx.insert("int_enabled", &false);

    let rendered = tera.render("pacgate_corundum_app.v.tera", &ctx)?;
    std::fs::write(rtl_dir.join("pacgate_corundum_app.v"), &rendered)?;
    log::info!("Generated pacgate_corundum_app.v (Corundum wrapper)");

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
    byte_offsets: &[(u16, usize)], global_protos: &GlobalProtocolFlags,
) -> Result<()> {
    let mut ctx = tera::Context::new();
    ctx.insert("rule_index", &idx);
    ctx.insert("rule_name", &rule.name);
    ctx.insert("condition_expr", &build_condition_expr(&rule.match_criteria)?);
    ctx.insert("action_pass", &(rule.action() == Action::Pass));

    let has_byte_capture = !byte_offsets.is_empty();
    ctx.insert("has_byte_capture", &has_byte_capture);
    // Use global flags so all rules have consistent port lists
    ctx.insert("has_ipv6", &global_protos.has_ipv6);
    ctx.insert("has_gtp", &global_protos.has_gtp);
    ctx.insert("has_mpls", &global_protos.has_mpls);
    ctx.insert("has_multicast", &global_protos.has_multicast);
    ctx.insert("has_dscp_ecn", &global_protos.has_dscp_ecn);
    ctx.insert("has_ipv6_tc", &global_protos.has_ipv6_tc);
    ctx.insert("has_tcp_flags", &global_protos.has_tcp_flags);
    ctx.insert("has_icmp", &global_protos.has_icmp);
    ctx.insert("has_icmpv6", &global_protos.has_icmpv6);
    ctx.insert("has_arp", &global_protos.has_arp);
    ctx.insert("has_ipv6_ext", &global_protos.has_ipv6_ext);
    ctx.insert("has_qinq", &global_protos.has_qinq);
    ctx.insert("has_ip_frag", &global_protos.has_ip_frag);
    ctx.insert("has_gre", &global_protos.has_gre);
    ctx.insert("has_oam", &global_protos.has_oam);
    ctx.insert("has_nsh", &global_protos.has_nsh);
    ctx.insert("has_conntrack_state", &global_protos.has_conntrack_state);
    ctx.insert("has_geneve", &global_protos.has_geneve);
    ctx.insert("has_ip_ttl", &global_protos.has_ip_ttl);
    ctx.insert("has_ptp", &global_protos.has_ptp);
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
                        // Transition to a composite sibling targets its initial leaf state.
                        if let Some(target_state) = states.get(&trans.next_state) {
                            if target_state.substates.is_some() {
                                trans.next_state = resolve_initial_state(&trans.next_state, states);
                                continue;
                            }
                        }
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
    byte_offsets: &[(u16, usize)], global_protos: &GlobalProtocolFlags,
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

    // Use global flags so all rules have consistent port lists
    ctx.insert("has_ipv6", &global_protos.has_ipv6);
    ctx.insert("has_gtp", &global_protos.has_gtp);
    ctx.insert("has_mpls", &global_protos.has_mpls);
    ctx.insert("has_multicast", &global_protos.has_multicast);
    ctx.insert("has_dscp_ecn", &global_protos.has_dscp_ecn);
    ctx.insert("has_ipv6_tc", &global_protos.has_ipv6_tc);
    ctx.insert("has_tcp_flags", &global_protos.has_tcp_flags);
    ctx.insert("has_icmp", &global_protos.has_icmp);
    ctx.insert("has_icmpv6", &global_protos.has_icmpv6);
    ctx.insert("has_arp", &global_protos.has_arp);
    ctx.insert("has_ipv6_ext", &global_protos.has_ipv6_ext);
    ctx.insert("has_qinq", &global_protos.has_qinq);
    ctx.insert("has_ip_frag", &global_protos.has_ip_frag);
    ctx.insert("has_gre", &global_protos.has_gre);
    ctx.insert("has_oam", &global_protos.has_oam);
    ctx.insert("has_nsh", &global_protos.has_nsh);
    ctx.insert("has_conntrack_state", &global_protos.has_conntrack_state);
    ctx.insert("has_geneve", &global_protos.has_geneve);
    ctx.insert("has_ip_ttl", &global_protos.has_ip_ttl);
    ctx.insert("has_ptp", &global_protos.has_ptp);

    let rendered = tera.render("rule_fsm.v.tera", &ctx)
        .with_context(|| format!("Failed to render rule_fsm for rule {}", rule.name))?;
    let filename = format!("rule_match_{}.v", idx);
    std::fs::write(rtl_dir.join(&filename), &rendered)?;
    log::info!("Generated {} (FSM)", filename);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_target_parse_standalone() {
        let t = PlatformTarget::from_str("standalone").unwrap();
        assert_eq!(t, PlatformTarget::Standalone);
        assert!(!t.is_platform());
    }

    #[test]
    fn test_platform_target_parse_opennic() {
        let t = PlatformTarget::from_str("opennic").unwrap();
        assert_eq!(t, PlatformTarget::OpenNic);
        assert!(t.is_platform());
        assert_eq!(t.name(), "opennic");
    }

    #[test]
    fn test_platform_target_parse_corundum() {
        let t = PlatformTarget::from_str("corundum").unwrap();
        assert_eq!(t, PlatformTarget::Corundum);
        assert!(t.is_platform());
        assert_eq!(t.name(), "corundum");
    }

    #[test]
    fn test_platform_target_parse_invalid() {
        let result = PlatformTarget::from_str("xilinx");
        assert!(result.is_err());
    }

    #[test]
    fn test_platform_target_case_insensitive() {
        assert_eq!(PlatformTarget::from_str("OpenNIC").unwrap(), PlatformTarget::OpenNic);
        assert_eq!(PlatformTarget::from_str("CORUNDUM").unwrap(), PlatformTarget::Corundum);
    }

    #[test]
    fn test_platform_standalone_is_not_platform() {
        let t = PlatformTarget::Standalone;
        assert!(!t.is_platform());
        assert_eq!(t.name(), "standalone");
    }
}
