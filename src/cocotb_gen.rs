use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::{Action, FilterConfig, Ipv4Prefix, Ipv6Prefix, PortMatch, parse_ethertype};

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
        // IPv6 fields
        if let Some(ref ipv6) = rule.match_criteria.src_ipv6 {
            tc.insert("src_ipv6".to_string(), generate_matching_ipv6(ipv6));
        }
        if let Some(ref ipv6) = rule.match_criteria.dst_ipv6 {
            tc.insert("dst_ipv6".to_string(), generate_matching_ipv6(ipv6));
        }
        if let Some(nh) = rule.match_criteria.ipv6_next_header {
            tc.insert("ipv6_next_header".to_string(), nh.to_string());
        }
        tc.insert("has_ipv6".to_string(), rule.match_criteria.uses_ipv6().to_string());
        // GTP-U fields
        if let Some(teid) = rule.match_criteria.gtp_teid {
            tc.insert("gtp_teid".to_string(), teid.to_string());
            tc.insert("has_gtp".to_string(), "true".to_string());
        }
        // MPLS fields
        if let Some(label) = rule.match_criteria.mpls_label {
            tc.insert("mpls_label".to_string(), label.to_string());
            tc.insert("has_mpls".to_string(), "true".to_string());
        }
        if let Some(tc_val) = rule.match_criteria.mpls_tc {
            tc.insert("mpls_tc".to_string(), tc_val.to_string());
        }
        if let Some(bos) = rule.match_criteria.mpls_bos {
            tc.insert("mpls_bos".to_string(), if bos { "1" } else { "0" }.to_string());
        }
        // IGMP/MLD fields
        if let Some(igmp) = rule.match_criteria.igmp_type {
            tc.insert("igmp_type".to_string(), format!("0x{:02X}", igmp));
            tc.insert("has_igmp".to_string(), "true".to_string());
        }
        if let Some(mld) = rule.match_criteria.mld_type {
            tc.insert("mld_type".to_string(), format!("0x{:02X}", mld));
            tc.insert("has_mld".to_string(), "true".to_string());
        }
        // DSCP/ECN fields
        if let Some(dscp) = rule.match_criteria.ip_dscp {
            tc.insert("ip_dscp".to_string(), dscp.to_string());
            tc.insert("has_dscp_ecn".to_string(), "true".to_string());
        }
        if let Some(ecn) = rule.match_criteria.ip_ecn {
            tc.insert("ip_ecn".to_string(), ecn.to_string());
            tc.insert("has_dscp_ecn".to_string(), "true".to_string());
        }
        // IPv6 Traffic Class fields
        if let Some(dscp) = rule.match_criteria.ipv6_dscp {
            tc.insert("ipv6_dscp".to_string(), dscp.to_string());
            tc.insert("has_ipv6_tc".to_string(), "true".to_string());
        }
        if let Some(ecn) = rule.match_criteria.ipv6_ecn {
            tc.insert("ipv6_ecn".to_string(), ecn.to_string());
            tc.insert("has_ipv6_tc".to_string(), "true".to_string());
        }
        // TCP flags fields
        if let Some(flags) = rule.match_criteria.tcp_flags {
            tc.insert("tcp_flags".to_string(), format!("0x{:02X}", flags));
            tc.insert("has_tcp_flags".to_string(), "true".to_string());
            if let Some(mask) = rule.match_criteria.tcp_flags_mask {
                tc.insert("tcp_flags_mask".to_string(), format!("0x{:02X}", mask));
            }
        }
        // ICMP fields
        if let Some(t) = rule.match_criteria.icmp_type {
            tc.insert("icmp_type".to_string(), t.to_string());
            tc.insert("has_icmp".to_string(), "true".to_string());
        }
        if let Some(c) = rule.match_criteria.icmp_code {
            tc.insert("icmp_code".to_string(), c.to_string());
            tc.insert("has_icmp".to_string(), "true".to_string());
        }
        // ICMPv6 fields
        if let Some(t) = rule.match_criteria.icmpv6_type {
            tc.insert("icmpv6_type".to_string(), t.to_string());
            tc.insert("has_icmpv6".to_string(), "true".to_string());
        }
        if let Some(c) = rule.match_criteria.icmpv6_code {
            tc.insert("icmpv6_code".to_string(), c.to_string());
            tc.insert("has_icmpv6".to_string(), "true".to_string());
        }
        // ARP fields
        if let Some(op) = rule.match_criteria.arp_opcode {
            tc.insert("arp_opcode".to_string(), op.to_string());
            tc.insert("has_arp".to_string(), "true".to_string());
        }
        if let Some(ref spa) = rule.match_criteria.arp_spa {
            tc.insert("arp_spa".to_string(), spa.clone());
            tc.insert("has_arp".to_string(), "true".to_string());
        }
        if let Some(ref tpa) = rule.match_criteria.arp_tpa {
            tc.insert("arp_tpa".to_string(), tpa.clone());
            tc.insert("has_arp".to_string(), "true".to_string());
        }
        // IPv6 extension fields
        if let Some(hl) = rule.match_criteria.ipv6_hop_limit {
            tc.insert("ipv6_hop_limit".to_string(), hl.to_string());
            tc.insert("has_ipv6_ext".to_string(), "true".to_string());
        }
        if let Some(fl) = rule.match_criteria.ipv6_flow_label {
            tc.insert("ipv6_flow_label".to_string(), fl.to_string());
            tc.insert("has_ipv6_ext".to_string(), "true".to_string());
        }
        // QinQ fields
        if let Some(vid) = rule.match_criteria.outer_vlan_id {
            tc.insert("outer_vlan_id".to_string(), vid.to_string());
            tc.insert("has_qinq".to_string(), "true".to_string());
        }
        if let Some(pcp) = rule.match_criteria.outer_vlan_pcp {
            tc.insert("outer_vlan_pcp".to_string(), pcp.to_string());
            tc.insert("has_qinq".to_string(), "true".to_string());
        }
        // IP fragmentation fields
        if let Some(df) = rule.match_criteria.ip_dont_fragment {
            tc.insert("ip_dont_fragment".to_string(), if df { "1" } else { "0" }.to_string());
            tc.insert("has_ip_frag".to_string(), "true".to_string());
        }
        if let Some(mf) = rule.match_criteria.ip_more_fragments {
            tc.insert("ip_more_fragments".to_string(), if mf { "1" } else { "0" }.to_string());
            tc.insert("has_ip_frag".to_string(), "true".to_string());
        }
        if let Some(offset) = rule.match_criteria.ip_frag_offset {
            tc.insert("ip_frag_offset".to_string(), offset.to_string());
            tc.insert("has_ip_frag".to_string(), "true".to_string());
        }
        // GRE tunnel fields
        if let Some(proto) = rule.match_criteria.gre_protocol {
            tc.insert("gre_protocol".to_string(), format!("0x{:04X}", proto));
            tc.insert("has_gre".to_string(), "true".to_string());
        }
        if let Some(key) = rule.match_criteria.gre_key {
            tc.insert("gre_key".to_string(), key.to_string());
            tc.insert("has_gre".to_string(), "true".to_string());
        }
        // Connection tracking state
        if let Some(ref state) = rule.match_criteria.conntrack_state {
            tc.insert("conntrack_state".to_string(), state.clone());
            tc.insert("has_conntrack_state".to_string(), "true".to_string());
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

    // Generate boundary test cases for CIDR and port range rules
    let mut boundary_index = 0u32;
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        // CIDR boundary: test IP just outside the prefix
        if let Some(ref cidr) = rule.match_criteria.src_ip {
            if let Some(boundary_ip) = generate_boundary_ip_outside(cidr) {
                let ethertype = if let Some(ref et) = rule.match_criteria.ethertype {
                    format!("0x{:04X}", parse_ethertype(et).unwrap_or(0x0800))
                } else {
                    "0x0800".to_string()
                };
                let mut tc = std::collections::HashMap::new();
                tc.insert("name".to_string(), format!("test_boundary_cidr_{}", boundary_index));
                tc.insert("description".to_string(), format!("CIDR boundary: src_ip={} just outside {}", boundary_ip, cidr));
                tc.insert("ethertype".to_string(), ethertype);
                tc.insert("dst_mac".to_string(), "de:ad:be:ef:00:01".to_string());
                tc.insert("src_mac".to_string(), "02:00:00:00:00:01".to_string());
                tc.insert("expect_pass".to_string(), default_pass.to_string());
                tc.insert("has_vlan".to_string(), "false".to_string());
                tc.insert("vlan_id".to_string(), "0".to_string());
                tc.insert("vlan_pcp".to_string(), "0".to_string());
                tc.insert("has_l3".to_string(), "true".to_string());
                tc.insert("src_ip".to_string(), boundary_ip);
                tc.insert("dst_ip".to_string(), "10.0.0.2".to_string());
                tc.insert("ip_protocol".to_string(), rule.match_criteria.ip_protocol.unwrap_or(6).to_string());
                test_cases.push(tc);
                boundary_index += 1;
            }
        }
        // Port boundary: test port just below range
        if let Some(ref pm) = rule.match_criteria.dst_port {
            if let Some(boundary_port) = generate_boundary_port_outside(pm) {
                let ethertype = if let Some(ref et) = rule.match_criteria.ethertype {
                    format!("0x{:04X}", parse_ethertype(et).unwrap_or(0x0800))
                } else {
                    "0x0800".to_string()
                };
                let mut tc = std::collections::HashMap::new();
                tc.insert("name".to_string(), format!("test_boundary_port_{}", boundary_index));
                tc.insert("description".to_string(), format!("Port boundary: dst_port={} just outside rule range", boundary_port));
                tc.insert("ethertype".to_string(), ethertype);
                tc.insert("dst_mac".to_string(), "de:ad:be:ef:00:01".to_string());
                tc.insert("src_mac".to_string(), "02:00:00:00:00:01".to_string());
                tc.insert("expect_pass".to_string(), default_pass.to_string());
                tc.insert("has_vlan".to_string(), "false".to_string());
                tc.insert("vlan_id".to_string(), "0".to_string());
                tc.insert("vlan_pcp".to_string(), "0".to_string());
                tc.insert("has_l3".to_string(), "true".to_string());
                tc.insert("src_ip".to_string(), rule.match_criteria.src_ip.as_ref().map(|ip| generate_matching_ip(ip)).unwrap_or_else(|| "10.0.0.1".to_string()));
                tc.insert("dst_ip".to_string(), rule.match_criteria.dst_ip.as_ref().map(|ip| generate_matching_ip(ip)).unwrap_or_else(|| "10.0.0.2".to_string()));
                tc.insert("ip_protocol".to_string(), rule.match_criteria.ip_protocol.unwrap_or(6).to_string());
                tc.insert("dst_port".to_string(), boundary_port.to_string());
                tc.insert("src_port".to_string(), "12345".to_string());
                test_cases.push(tc);
                boundary_index += 1;
            }
        }
    }

    // Generate formally-derived negative test: guaranteed no-match frame
    {
        let used_ethertypes: std::collections::HashSet<u16> = rules.iter()
            .filter_map(|r| r.match_criteria.ethertype.as_ref())
            .filter_map(|et| parse_ethertype(et).ok())
            .collect();
        // Pick an unused ethertype for negative test
        let neg_ethertype = [0x88B5u16, 0x88B6, 0x9000, 0x6003, 0x22F0]
            .iter()
            .find(|et| !used_ethertypes.contains(et))
            .copied()
            .unwrap_or(0x88B5);
        let mut tc = std::collections::HashMap::new();
        tc.insert("name".to_string(), "test_negative_derived".to_string());
        tc.insert("description".to_string(), "Formally-derived negative: frame guaranteed to match no rule".to_string());
        tc.insert("ethertype".to_string(), format!("0x{:04X}", neg_ethertype));
        tc.insert("dst_mac".to_string(), "00:00:00:00:ff:ee".to_string());
        tc.insert("src_mac".to_string(), "00:00:00:00:ff:dd".to_string());
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
                PortMatch::Range { range } => { sr.insert("src_port_range".to_string(), format!("{}, {}", range[0], range[1])); }
            }
        }
        if let Some(ref pm) = rule.match_criteria.dst_port {
            match pm {
                PortMatch::Exact(p) => { sr.insert("dst_port".to_string(), p.to_string()); }
                PortMatch::Range { range } => { sr.insert("dst_port_range".to_string(), format!("{}, {}", range[0], range[1])); }
            }
        }
        // VXLAN scoreboard fields
        if let Some(vni) = rule.match_criteria.vxlan_vni {
            sr.insert("vxlan_vni".to_string(), vni.to_string());
        }
        // IPv6 scoreboard fields
        if let Some(ref ipv6) = rule.match_criteria.src_ipv6 {
            sr.insert("src_ipv6".to_string(), ipv6.clone());
        }
        if let Some(ref ipv6) = rule.match_criteria.dst_ipv6 {
            sr.insert("dst_ipv6".to_string(), ipv6.clone());
        }
        if let Some(nh) = rule.match_criteria.ipv6_next_header {
            sr.insert("ipv6_next_header".to_string(), nh.to_string());
        }
        // GTP-U scoreboard fields
        if let Some(teid) = rule.match_criteria.gtp_teid {
            sr.insert("gtp_teid".to_string(), teid.to_string());
        }
        // MPLS scoreboard fields
        if let Some(label) = rule.match_criteria.mpls_label {
            sr.insert("mpls_label".to_string(), label.to_string());
        }
        if let Some(tc_val) = rule.match_criteria.mpls_tc {
            sr.insert("mpls_tc".to_string(), tc_val.to_string());
        }
        if let Some(bos) = rule.match_criteria.mpls_bos {
            sr.insert("mpls_bos".to_string(), if bos { "true" } else { "false" }.to_string());
        }
        // IGMP/MLD scoreboard fields
        if let Some(igmp) = rule.match_criteria.igmp_type {
            sr.insert("igmp_type".to_string(), format!("0x{:02X}", igmp));
        }
        if let Some(mld) = rule.match_criteria.mld_type {
            sr.insert("mld_type".to_string(), format!("0x{:02X}", mld));
        }
        // DSCP/ECN scoreboard fields
        if let Some(dscp) = rule.match_criteria.ip_dscp {
            sr.insert("ip_dscp".to_string(), dscp.to_string());
        }
        if let Some(ecn) = rule.match_criteria.ip_ecn {
            sr.insert("ip_ecn".to_string(), ecn.to_string());
        }
        // IPv6 Traffic Class scoreboard fields
        if let Some(dscp) = rule.match_criteria.ipv6_dscp {
            sr.insert("ipv6_dscp".to_string(), dscp.to_string());
        }
        if let Some(ecn) = rule.match_criteria.ipv6_ecn {
            sr.insert("ipv6_ecn".to_string(), ecn.to_string());
        }
        // TCP flags scoreboard fields
        if let Some(flags) = rule.match_criteria.tcp_flags {
            sr.insert("tcp_flags".to_string(), format!("0x{:02X}", flags));
            if let Some(mask) = rule.match_criteria.tcp_flags_mask {
                sr.insert("tcp_flags_mask".to_string(), format!("0x{:02X}", mask));
            }
        }
        // ICMP scoreboard fields
        if let Some(t) = rule.match_criteria.icmp_type {
            sr.insert("icmp_type".to_string(), t.to_string());
        }
        if let Some(c) = rule.match_criteria.icmp_code {
            sr.insert("icmp_code".to_string(), c.to_string());
        }
        // ICMPv6 scoreboard fields
        if let Some(t) = rule.match_criteria.icmpv6_type {
            sr.insert("icmpv6_type".to_string(), t.to_string());
        }
        if let Some(c) = rule.match_criteria.icmpv6_code {
            sr.insert("icmpv6_code".to_string(), c.to_string());
        }
        // ARP scoreboard fields
        if let Some(op) = rule.match_criteria.arp_opcode {
            sr.insert("arp_opcode".to_string(), op.to_string());
        }
        if let Some(ref spa) = rule.match_criteria.arp_spa {
            sr.insert("arp_spa".to_string(), spa.clone());
        }
        if let Some(ref tpa) = rule.match_criteria.arp_tpa {
            sr.insert("arp_tpa".to_string(), tpa.clone());
        }
        // IPv6 extension scoreboard fields
        if let Some(hl) = rule.match_criteria.ipv6_hop_limit {
            sr.insert("ipv6_hop_limit".to_string(), hl.to_string());
        }
        if let Some(fl) = rule.match_criteria.ipv6_flow_label {
            sr.insert("ipv6_flow_label".to_string(), fl.to_string());
        }
        // GRE tunnel scoreboard fields
        if let Some(proto) = rule.match_criteria.gre_protocol {
            sr.insert("gre_protocol".to_string(), format!("0x{:04X}", proto));
        }
        if let Some(key) = rule.match_criteria.gre_key {
            sr.insert("gre_key".to_string(), key.to_string());
        }
        // Connection tracking state scoreboard field
        if let Some(ref state) = rule.match_criteria.conntrack_state {
            sr.insert("conntrack_state".to_string(), state.clone());
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
        ctx.insert("has_gtp_rules", &rules.iter().any(|r| r.match_criteria.gtp_teid.is_some()));
        ctx.insert("has_mpls_rules", &rules.iter().any(|r| r.match_criteria.mpls_label.is_some() || r.match_criteria.mpls_tc.is_some() || r.match_criteria.mpls_bos.is_some()));
        ctx.insert("has_igmp_rules", &rules.iter().any(|r| r.match_criteria.igmp_type.is_some()));
        ctx.insert("has_mld_rules", &rules.iter().any(|r| r.match_criteria.mld_type.is_some()));
        ctx.insert("has_ipv6_tc_rules", &rules.iter().any(|r| r.match_criteria.uses_ipv6_tc()));
        ctx.insert("has_tcp_flags_rules", &rules.iter().any(|r| r.match_criteria.uses_tcp_flags()));
        ctx.insert("has_icmp_rules", &rules.iter().any(|r| r.match_criteria.uses_icmp()));
        ctx.insert("has_icmpv6_rules", &rules.iter().any(|r| r.match_criteria.uses_icmpv6()));
        ctx.insert("has_arp_rules", &rules.iter().any(|r| r.match_criteria.uses_arp()));
        ctx.insert("has_ipv6_ext_rules", &rules.iter().any(|r| r.match_criteria.uses_ipv6_ext()));
        ctx.insert("has_qinq_rules", &rules.iter().any(|r| r.match_criteria.uses_qinq()));
        ctx.insert("has_ip_frag_rules", &rules.iter().any(|r| r.match_criteria.uses_ip_frag()));
        ctx.insert("has_gre_rules", &rules.iter().any(|r| r.match_criteria.uses_gre()));
        ctx.insert("has_conntrack_state_rules", &rules.iter().any(|r| r.match_criteria.uses_conntrack_state()));

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

/// Generate cocotb 2.0 runner script (run_sim.py) for main packet filter tests.
/// Uses cocotb_tools.runner API for programmatic, cross-platform simulation.
pub fn generate_runner(config: &FilterConfig, templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_dir = output_dir.join("tb");
    std::fs::create_dir_all(&tb_dir)?;

    let mut ctx = tera::Context::new();
    ctx.insert("module_name", "packet_filter_top");
    ctx.insert("test_module", "test_packet_filter");

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

    let rendered = tera.render("test_runner.py.tera", &ctx)?;
    std::fs::write(tb_dir.join("run_sim.py"), &rendered)?;
    log::info!("Generated tb/run_sim.py");

    let _ = config; // config reserved for future use (platform target filtering)
    Ok(())
}

/// Generate cocotb 2.0 runner script for AXI-Stream tests.
/// When `has_platform_target` is true, includes width converter sources.
pub fn generate_axi_runner(_config: &FilterConfig, templates_dir: &Path, output_dir: &Path, has_platform_target: bool) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_axi_dir = output_dir.join("tb-axi");
    std::fs::create_dir_all(&tb_axi_dir)?;

    let mut ctx = tera::Context::new();
    ctx.insert("module_name", "packet_filter_axi_top");
    ctx.insert("test_module", "test_axi_packet_filter");

    let rtl_gen_dir = output_dir.join("rtl");
    let mut verilog_files: Vec<String> = Vec::new();
    verilog_files.push("../../rtl/frame_parser.v".to_string());

    // Include width converters when platform target is active
    if has_platform_target {
        verilog_files.push("../rtl/axis_512_to_8.v".to_string());
        verilog_files.push("../rtl/axis_8_to_512.v".to_string());
    }

    verilog_files.push("../rtl/axi_stream_adapter.v".to_string());
    verilog_files.push("../rtl/store_forward_fifo.v".to_string());
    verilog_files.push("../rtl/packet_filter_axi_top.v".to_string());

    if rtl_gen_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&rtl_gen_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.ends_with(".v")
                    && name != "axi_stream_adapter.v"
                    && name != "store_forward_fifo.v"
                    && name != "packet_filter_axi_top.v"
                    && name != "axis_512_to_8.v"
                    && name != "axis_8_to_512.v"
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            verilog_files.push(format!("../rtl/{}", entry.file_name().to_string_lossy()));
        }
    }

    ctx.insert("verilog_files", &verilog_files);

    let rendered = tera.render("test_runner.py.tera", &ctx)?;
    std::fs::write(tb_axi_dir.join("run_sim.py"), &rendered)?;
    log::info!("Generated tb-axi/run_sim.py");

    Ok(())
}

/// Generate cocotb 2.0 runner script for conntrack tests.
pub fn generate_conntrack_runner(templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_ct_dir = output_dir.join("tb-conntrack");
    std::fs::create_dir_all(&tb_ct_dir)?;

    let ctx = tera::Context::new();
    let rendered = tera.render("test_conntrack_runner.py.tera", &ctx)?;
    std::fs::write(tb_ct_dir.join("run_sim.py"), &rendered)?;
    log::info!("Generated tb-conntrack/run_sim.py");

    Ok(())
}

/// Generate cocotb 2.0 runner script for rate limiter tests.
pub fn generate_rate_limiter_runner(templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_rl_dir = output_dir.join("tb-rate-limiter");
    std::fs::create_dir_all(&tb_rl_dir)?;

    let ctx = tera::Context::new();
    let rendered = tera.render("test_rate_limiter_runner.py.tera", &ctx)?;
    std::fs::write(tb_rl_dir.join("run_sim.py"), &rendered)?;
    log::info!("Generated tb-rate-limiter/run_sim.py");

    Ok(())
}

/// Generate cocotb 2.0 runner script for dynamic flow table tests.
pub fn generate_dynamic_runner(templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_dir = output_dir.join("tb");
    std::fs::create_dir_all(&tb_dir)?;

    let mut ctx = tera::Context::new();
    ctx.insert("module_name", "packet_filter_top");
    let verilog_files: Vec<String> = vec![
        "../rtl/frame_parser.v".to_string(),
        "../rtl/flow_table.v".to_string(),
        "../rtl/packet_filter_top.v".to_string(),
    ];
    ctx.insert("verilog_files", &verilog_files);

    let rendered = tera.render("test_flow_table_runner.py.tera", &ctx)?;
    std::fs::write(tb_dir.join("run_sim.py"), &rendered)?;
    log::info!("Generated tb/run_sim.py (dynamic mode)");

    Ok(())
}

/// Generate an IP address just outside a CIDR prefix (for boundary testing)
fn generate_boundary_ip_outside(cidr: &str) -> Option<String> {
    if let Ok(prefix) = Ipv4Prefix::parse(cidr) {
        if prefix.prefix_len == 0 || prefix.prefix_len > 30 {
            return None; // /0 matches everything, /31+ is too narrow for meaningful boundary
        }
        // Compute the broadcast address + 1 (first IP outside the prefix)
        let host_bits = 32 - prefix.prefix_len;
        let ip_u32 = u32::from_be_bytes(prefix.addr);
        let broadcast = ip_u32 | ((1u32 << host_bits) - 1);
        let outside = broadcast.wrapping_add(1);
        if outside == 0 { return None; } // wrapped around
        let bytes = outside.to_be_bytes();
        Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

/// Generate a port number just outside a PortMatch range (for boundary testing)
fn generate_boundary_port_outside(pm: &PortMatch) -> Option<u16> {
    match pm {
        PortMatch::Exact(p) => {
            if *p > 1 { Some(p - 1) } else { Some(p + 1) }
        }
        PortMatch::Range { range } => {
            if range[0] > 1 { Some(range[0] - 1) }
            else if range[1] < 65535 { Some(range[1] + 1) }
            else { None }
        }
    }
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

/// Generate an IPv6 address string that matches a CIDR prefix
fn generate_matching_ipv6(cidr: &str) -> String {
    if let Ok(prefix) = Ipv6Prefix::parse(cidr) {
        // Format as colon-separated hex string
        let a = &prefix.addr;
        format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
            a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15])
    } else {
        "2001:0db8:0000:0000:0000:0000:0000:0001".to_string()
    }
}

/// Generate connection tracking cocotb testbench files
pub fn generate_conntrack_tests(templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_ct_dir = output_dir.join("tb-conntrack");
    std::fs::create_dir_all(&tb_ct_dir)?;

    // Render conntrack test
    {
        let ctx = tera::Context::new();
        let rendered = tera.render("test_conntrack.py.tera", &ctx)?;
        std::fs::write(tb_ct_dir.join("test_conntrack.py"), &rendered)?;
        log::info!("Generated test_conntrack.py");
    }

    // Render conntrack Makefile
    {
        let ctx = tera::Context::new();
        let rendered = tera.render("test_conntrack_makefile.tera", &ctx)?;
        std::fs::write(tb_ct_dir.join("Makefile"), &rendered)?;
        log::info!("Generated tb-conntrack/Makefile");
    }

    Ok(())
}

/// Generate rate limiter cocotb testbench files
pub fn generate_rate_limiter_tests(templates_dir: &Path, output_dir: &Path) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_rl_dir = output_dir.join("tb-rate-limiter");
    std::fs::create_dir_all(&tb_rl_dir)?;

    // Render rate limiter test
    {
        let ctx = tera::Context::new();
        let rendered = tera.render("test_rate_limiter.py.tera", &ctx)?;
        std::fs::write(tb_rl_dir.join("test_rate_limiter.py"), &rendered)?;
        log::info!("Generated test_rate_limiter.py");
    }

    // Render rate limiter Makefile
    {
        let ctx = tera::Context::new();
        let rendered = tera.render("test_rate_limiter_makefile.tera", &ctx)?;
        std::fs::write(tb_rl_dir.join("Makefile"), &rendered)?;
        log::info!("Generated tb-rate-limiter/Makefile");
    }

    Ok(())
}

/// Generate cocotb tests for dynamic flow table mode.
/// Tests initial rules, AXI-Lite entry modification, add/disable, commit atomicity, priority.
pub fn generate_dynamic_tests(config: &FilterConfig, templates_dir: &Path, output_dir: &Path, num_entries: u16) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let tb_dir = output_dir.join("tb");
    std::fs::create_dir_all(&tb_dir)?;

    // Sort rules by priority (highest first) — same order as verilog_gen
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    let default_pass = config.pacgate.defaults.action == Action::Pass;

    // Build test case data for initial rules
    let mut test_cases: Vec<std::collections::HashMap<String, String>> = Vec::new();
    for rule in rules.iter().filter(|r| !r.is_stateful()) {
        let ethertype = if let Some(ref et) = rule.match_criteria.ethertype {
            format!("0x{:04X}", parse_ethertype(et).unwrap_or(0x0800))
        } else {
            "0x0800".to_string()
        };

        let dst_mac = if let Some(ref mac) = rule.match_criteria.dst_mac {
            generate_matching_mac(mac)
        } else {
            "02:00:00:00:00:01".to_string()
        };

        let src_mac = if let Some(ref mac) = rule.match_criteria.src_mac {
            generate_matching_mac(mac)
        } else {
            "02:00:00:00:00:02".to_string()
        };

        let expect_pass = (rule.action() == Action::Pass).to_string();

        let mut tc = std::collections::HashMap::new();
        tc.insert("name".to_string(), rule.name.clone());
        tc.insert("ethertype".to_string(), ethertype);
        tc.insert("dst_mac".to_string(), dst_mac);
        tc.insert("src_mac".to_string(), src_mac);
        tc.insert("expect_pass".to_string(), expect_pass);

        // L3/L4 fields
        if let Some(ref ip) = rule.match_criteria.src_ip {
            tc.insert("src_ip".to_string(), generate_matching_ip(ip));
            tc.insert("has_l3".to_string(), "true".to_string());
        }
        if let Some(ref ip) = rule.match_criteria.dst_ip {
            tc.insert("dst_ip".to_string(), generate_matching_ip(ip));
            tc.insert("has_l3".to_string(), "true".to_string());
        }
        if let Some(proto) = rule.match_criteria.ip_protocol {
            tc.insert("ip_protocol".to_string(), proto.to_string());
            tc.insert("has_l3".to_string(), "true".to_string());
        }
        if let Some(ref pm) = rule.match_criteria.src_port {
            tc.insert("src_port".to_string(), generate_matching_port(pm));
            tc.insert("has_l3".to_string(), "true".to_string());
        }
        if let Some(ref pm) = rule.match_criteria.dst_port {
            tc.insert("dst_port".to_string(), generate_matching_port(pm));
            tc.insert("has_l3".to_string(), "true".to_string());
        }
        if let Some(vid) = rule.match_criteria.vlan_id {
            tc.insert("vlan_id".to_string(), vid.to_string());
            tc.insert("has_vlan".to_string(), "true".to_string());
        }

        test_cases.push(tc);
    }

    // Render test_flow_table.py
    {
        let mut ctx = tera::Context::new();
        ctx.insert("test_cases", &test_cases);
        ctx.insert("num_entries", &num_entries);
        ctx.insert("default_pass", &default_pass);
        ctx.insert("num_rules", &rules.len());

        let rendered = tera.render("test_flow_table.py.tera", &ctx)?;
        std::fs::write(tb_dir.join("test_flow_table.py"), &rendered)?;
        log::info!("Generated test_flow_table.py");
    }

    // Render Makefile for flow table tests
    {
        let mut ctx = tera::Context::new();
        ctx.insert("module_name", "packet_filter_top");
        let verilog_files: Vec<String> = vec![
            "../rtl/frame_parser.v".to_string(),
            "../rtl/flow_table.v".to_string(),
            "../rtl/packet_filter_top.v".to_string(),
        ];
        ctx.insert("verilog_files", &verilog_files);
        let rendered = tera.render("test_makefile.tera", &ctx)?;
        // Update the test module name for dynamic mode
        let rendered = rendered.replace("test_packet_filter", "test_flow_table");
        std::fs::write(tb_dir.join("Makefile"), &rendered)?;
        log::info!("Generated tb/Makefile (dynamic mode)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_test_config() -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "allow_arp".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0806".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                        rewrite: None,
                    },
                ],
                conntrack: None,
            },
        }
    }

    #[test]
    fn runner_template_renders_verilog_sources() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module pft; endmodule").unwrap();
        std::fs::write(rtl_dir.join("rule_match_0.v"), "module rm0; endmodule").unwrap();

        generate_runner(&config, Path::new("templates"), tmp.path()).unwrap();

        let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
        assert!(runner_py.contains("frame_parser.v"), "runner should include frame_parser.v");
        assert!(runner_py.contains("packet_filter_top.v"), "runner should include generated RTL");
        assert!(runner_py.contains("rule_match_0.v"), "runner should include rule matchers");
    }

    #[test]
    fn runner_template_renders_correct_toplevel() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module pft; endmodule").unwrap();

        generate_runner(&config, Path::new("templates"), tmp.path()).unwrap();

        let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
        assert!(runner_py.contains("hdl_toplevel=\"packet_filter_top\""), "runner should have correct toplevel");
    }

    #[test]
    fn runner_imports_cocotb_tools_runner() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module pft; endmodule").unwrap();

        generate_runner(&config, Path::new("templates"), tmp.path()).unwrap();

        let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
        assert!(runner_py.contains("from cocotb_tools.runner import get_runner"), "runner should import cocotb_tools.runner");
    }

    #[test]
    fn runner_has_sim_override() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module pft; endmodule").unwrap();

        generate_runner(&config, Path::new("templates"), tmp.path()).unwrap();

        let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
        assert!(runner_py.contains("os.environ.get(\"SIM\", \"icarus\")"), "runner should support SIM env override");
    }
}
