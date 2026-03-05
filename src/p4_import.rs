// P4 Import: Parse P4_16 PSA programs into PacGate FilterConfig
//
// Targeted parser for PacGate-generated P4 programs and compatible simple PSA programs.
// State machine processes P4 source line-by-line to extract table structure, entries, actions.

use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::model::*;

// ============================================================
// Parsed intermediate representation
// ============================================================

#[derive(Debug, Default)]
pub struct ParsedP4 {
    pub detected_headers: Vec<String>,
    pub keys: Vec<ParsedKey>,
    pub default_pass: bool,
    pub entries: Vec<ParsedEntry>,
    pub rewrite_actions: HashMap<String, Vec<String>>,
    pub has_conntrack: bool,
    pub has_rate_limit: bool,
    pub has_rss: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedKey {
    pub header_field: String,
    pub match_kind: String,
}

#[derive(Debug, Clone)]
pub struct ParsedEntry {
    pub rule_name: String,
    pub priority: u32,
    pub action_name: String,
    pub key_values: Vec<String>,
}

// ============================================================
// Parser state machine
// ============================================================

#[derive(Debug, PartialEq)]
enum ParserState {
    TopLevel,
    HeaderDef(String),         // header name
    IngressControl,
    ActionBody(String, Vec<String>),  // action name, ops
    TableKeys,
    ConstEntries,
    ConstEntry(String, u32, Vec<String>), // rule_name, priority, values
    Skip(usize),               // brace depth
}

/// Main entry point: parse P4 source and produce FilterConfig + warnings
pub fn import_p4(source: &str) -> Result<(FilterConfig, Vec<String>)> {
    let parsed = parse_p4_source(source)?;
    let (config, mut warnings) = parsed_to_config(&parsed)?;
    warnings.extend(parsed.warnings.clone());
    Ok((config, warnings))
}

/// Parse P4 source into intermediate representation
pub fn parse_p4_source(source: &str) -> Result<ParsedP4> {
    let mut parsed = ParsedP4::default();
    let mut state = ParserState::TopLevel;
    let mut ctrl_depth: i32 = 0;     // relative brace depth inside Ingress control
    let mut action_entry_depth: i32 = 0; // ctrl_depth when we entered ActionBody
    let mut found_ingress_brace = false; // have we seen the opening { for Ingress?
    let mut pending_rule_name = String::new();
    let mut pending_priority: u32 = 100;
    let mut table_default_action = String::new();

    for (_line_no, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();

        // Count braces on this line
        let opens = raw_line.chars().filter(|&c| c == '{').count() as i32;
        let closes = raw_line.chars().filter(|&c| c == '}').count() as i32;

        match state {
            ParserState::TopLevel => {
                // Detect header definitions (skip them)
                if line.starts_with("header ") && line.contains("_t") {
                    if let Some(name) = extract_header_name(line) {
                        parsed.detected_headers.push(name);
                    }
                    // Don't need to track these — just note them
                }

                // Detect extern instances
                if line.contains("Register<bit<") {
                    parsed.has_conntrack = true;
                    parsed.warnings.push("Register extern detected — conntrack state is approximate".to_string());
                }
                if line.contains("Meter<bit<") {
                    parsed.has_rate_limit = true;
                    parsed.warnings.push("Meter extern detected — rate limiting parameters not imported".to_string());
                }
                if line.contains("ActionSelector(") {
                    parsed.has_rss = true;
                    parsed.warnings.push("ActionSelector extern detected — RSS configuration not imported".to_string());
                }

                // Enter ingress control
                if line.starts_with("control Ingress(") || line.starts_with("control Ingress ") {
                    state = ParserState::IngressControl;
                    ctrl_depth = 0;
                    found_ingress_brace = false;
                    // If opening brace is on this line
                    if opens > 0 {
                        ctrl_depth = opens - closes;
                        found_ingress_brace = true;
                    }
                    continue;
                }
            }

            ParserState::HeaderDef(_) => {
                // Unused — we handle headers in TopLevel now
            }

            ParserState::IngressControl => {
                // Track brace depth within the control block
                if !found_ingress_brace {
                    if opens > 0 {
                        found_ingress_brace = true;
                        ctrl_depth = opens - closes;
                    }
                    continue;
                }
                ctrl_depth += opens - closes;

                // Detect rewrite action definitions
                if line.starts_with("action ") && line.contains("(") {
                    if let Some(name) = extract_action_name(line) {
                        if name != "pass_action" && name != "drop_action" {
                            action_entry_depth = ctrl_depth;
                            state = ParserState::ActionBody(name, Vec::new());
                            continue;
                        }
                    }
                }

                // Detect table keys
                if line.contains("key = {") {
                    // Handle single-line key block: key = { field : kind; }
                    if line.contains("key = {") && line.ends_with("}") {
                        let inner = line.split("key = {").nth(1).unwrap_or("");
                        let inner = inner.trim_end_matches('}').trim();
                        for part in inner.split(';') {
                            if let Some(key) = parse_table_key_line(part.trim()) {
                                parsed.keys.push(key);
                            }
                        }
                        // Stay in IngressControl
                    } else {
                        state = ParserState::TableKeys;
                    }
                    continue;
                }

                // Detect const entries
                if line.contains("const entries = {") {
                    state = ParserState::ConstEntries;
                    continue;
                }

                // Detect default action
                if line.contains("default_action = ") {
                    table_default_action = line.to_string();
                }

                // Exit Ingress control when all braces closed
                if ctrl_depth <= 0 && found_ingress_brace {
                    state = ParserState::TopLevel;
                }
            }

            ParserState::ActionBody(ref name, ref mut ops) => {
                ctrl_depth += opens - closes;
                // End of action body
                if ctrl_depth < action_entry_depth {
                    let action_name = name.clone();
                    let operations = ops.clone();
                    parsed.rewrite_actions.insert(action_name, operations);
                    state = ParserState::IngressControl;
                    continue;
                }
                // Collect operation lines
                let trimmed = line.trim_end_matches(';').trim();
                if !trimmed.is_empty() && !trimmed.starts_with("//") && trimmed != "}" && trimmed != "{" {
                    ops.push(format!("{};", trimmed));
                }
            }

            ParserState::TableKeys => {
                ctrl_depth += opens - closes;
                // End of key block
                if line == "}" {
                    state = ParserState::IngressControl;
                    continue;
                }
                // Parse "field : kind;" lines
                if let Some(key) = parse_table_key_line(line) {
                    parsed.keys.push(key);
                }
            }

            ParserState::ConstEntries => {
                ctrl_depth += opens - closes;

                // Look for rule comment
                if line.starts_with("//") && line.contains("Rule:") {
                    let (name, priority) = parse_entry_comment(line);
                    pending_rule_name = name;
                    pending_priority = priority;
                    continue;
                }

                // Start of entry values
                if line.starts_with("(") {
                    // Check if single-line entry: (val) : action();
                    if let Some(entry) = try_parse_single_line_entry(line, &pending_rule_name, pending_priority) {
                        parsed.entries.push(entry);
                        continue;
                    }
                    state = ParserState::ConstEntry(
                        pending_rule_name.clone(),
                        pending_priority,
                        Vec::new(),
                    );
                    continue;
                }

                // End of const entries block
                if line == "}" {
                    state = ParserState::IngressControl;
                    continue;
                }
            }

            ParserState::ConstEntry(ref name, priority, ref mut vals) => {
                ctrl_depth += opens - closes;
                // Check for end of entry: ") : action();"
                if line.starts_with(")") && line.contains(":") {
                    let action_name = extract_entry_action(line);
                    parsed.entries.push(ParsedEntry {
                        rule_name: name.clone(),
                        priority,
                        action_name,
                        key_values: vals.clone(),
                    });
                    state = ParserState::ConstEntries;
                    continue;
                }
                // Accumulate key values
                let val = line.trim_end_matches(',').trim().to_string();
                if !val.is_empty() && !val.starts_with("//") {
                    vals.push(val);
                }
            }

            ParserState::Skip(_) => {
                // Not used
            }
        }
    }

    // Determine default action
    parsed.default_pass = table_default_action.contains("pass_action");

    Ok(parsed)
}

/// Extract header name from "header ethernet_t {" → "ethernet"
fn extract_header_name(line: &str) -> Option<String> {
    let s = line.strip_prefix("header ")?.trim();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    let name = s[..end].trim_end_matches("_t").to_string();
    Some(name)
}

// ============================================================
// IR → FilterConfig conversion
// ============================================================

fn parsed_to_config(parsed: &ParsedP4) -> Result<(FilterConfig, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut rules = Vec::new();

    for (idx, entry) in parsed.entries.iter().enumerate() {
        match entry_to_rule(entry, &parsed.keys, &parsed.rewrite_actions) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                warnings.push(format!("Skipped entry {}: {}", idx, e));
            }
        }
    }

    let default_action = if parsed.default_pass { Action::Pass } else { Action::Drop };

    let config = FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: default_action },
            rules,
            conntrack: None,
            tables: None,
        },
    };

    Ok((config, warnings))
}

fn entry_to_rule(
    entry: &ParsedEntry,
    keys: &[ParsedKey],
    rewrite_actions: &HashMap<String, Vec<String>>,
) -> Result<StatelessRule> {
    let mut mc = MatchCriteria::default();

    // Map each key value to the corresponding match field
    if entry.key_values.len() > keys.len() {
        bail!("Entry '{}' has {} values but only {} keys",
            entry.rule_name, entry.key_values.len(), keys.len());
    }

    for (i, val) in entry.key_values.iter().enumerate() {
        if i >= keys.len() { break; }
        let key = &keys[i];
        apply_key_value(&mut mc, &key.header_field, &key.match_kind, val)?;
    }

    // Determine action and rewrite
    let (action, rewrite) = if entry.action_name == "pass_action" {
        (Action::Pass, None)
    } else if entry.action_name == "drop_action" {
        (Action::Drop, None)
    } else {
        // Rewrite action implies pass
        let rw = rewrite_actions.get(&entry.action_name)
            .map(|ops| parse_rewrite_ops(ops))
            .transpose()?;
        (Action::Pass, rw)
    };

    Ok(StatelessRule {
        name: entry.rule_name.clone(),
        priority: entry.priority,
        match_criteria: mc,
        action: Some(action),
        rule_type: None,
        fsm: None,
        ports: None,
        rate_limit: None,
        rewrite,
        mirror_port: None,
        redirect_port: None,
        rss_queue: None,
        int_insert: None,
    })
}

// ============================================================
// Reverse field mapping: P4 field → PacGate MatchCriteria
// ============================================================

fn apply_key_value(mc: &mut MatchCriteria, field: &str, _kind: &str, raw_value: &str) -> Result<()> {
    let value = raw_value.trim();

    // Handle "don't care" wildcard — skip field
    if value == "_" || value == "0 &&& 0" || value == "0x000000000000 &&& 0x000000000000" {
        return Ok(());
    }

    match field {
        // Ethernet
        "hdr.ethernet.etherType" => {
            mc.ethertype = Some(parse_p4_ethertype(value)?);
        }
        "hdr.ethernet.dstAddr" => {
            mc.dst_mac = Some(p4_to_mac(value)?);
        }
        "hdr.ethernet.srcAddr" => {
            mc.src_mac = Some(p4_to_mac(value)?);
        }
        "hdr.vlan.vid" => {
            mc.vlan_id = Some(parse_p4_u16(value)?);
        }
        "hdr.vlan.pcp" => {
            mc.vlan_pcp = Some(parse_p4_u8(value)?);
        }

        // IPv4
        "hdr.ipv4.srcAddr" => {
            mc.src_ip = Some(parse_p4_lpm(value));
        }
        "hdr.ipv4.dstAddr" => {
            mc.dst_ip = Some(parse_p4_lpm(value));
        }
        "hdr.ipv4.protocol" => {
            mc.ip_protocol = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv4.dscp" => {
            mc.ip_dscp = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv4.ecn" => {
            mc.ip_ecn = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv4.ttl" => {
            mc.ip_ttl = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv4.flags_df" => {
            mc.ip_dont_fragment = Some(parse_p4_bool(value));
        }
        "hdr.ipv4.flags_mf" => {
            mc.ip_more_fragments = Some(parse_p4_bool(value));
        }
        "hdr.ipv4.fragOffset" => {
            mc.ip_frag_offset = Some(parse_p4_u16(value)?);
        }

        // L4 ports
        "meta.l4_src_port" => {
            mc.src_port = Some(parse_p4_port(value)?);
        }
        "meta.l4_dst_port" => {
            mc.dst_port = Some(parse_p4_port(value)?);
        }

        // TCP flags
        "hdr.tcp.flags" => {
            let (flags, mask) = parse_p4_ternary_u8(value)?;
            mc.tcp_flags = Some(flags);
            if mask != 0xFF {
                mc.tcp_flags_mask = Some(mask);
            }
        }

        // IPv6
        "hdr.ipv6.srcAddr" => {
            mc.src_ipv6 = Some(parse_p4_lpm(value));
        }
        "hdr.ipv6.dstAddr" => {
            mc.dst_ipv6 = Some(parse_p4_lpm(value));
        }
        "hdr.ipv6.nextHdr" => {
            mc.ipv6_next_header = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv6.dscp" => {
            mc.ipv6_dscp = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv6.ecn" => {
            mc.ipv6_ecn = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv6.hopLimit" => {
            mc.ipv6_hop_limit = Some(parse_p4_u8(value)?);
        }
        "hdr.ipv6.flowLabel" => {
            mc.ipv6_flow_label = Some(parse_p4_u32(value)?);
        }

        // Tunnels
        "hdr.vxlan.vni" => {
            mc.vxlan_vni = Some(parse_p4_u32(value)?);
        }
        "hdr.gtp.teid" => {
            mc.gtp_teid = Some(parse_p4_u32(value)?);
        }
        "hdr.geneve.vni" => {
            mc.geneve_vni = Some(parse_p4_u32(value)?);
        }
        "hdr.gre.protocol" => {
            mc.gre_protocol = Some(parse_p4_u16(value)?);
        }
        "hdr.gre.key" => {
            mc.gre_key = Some(parse_p4_u32(value)?);
        }
        "hdr.mpls.label" => {
            mc.mpls_label = Some(parse_p4_u32(value)?);
        }
        "hdr.mpls.tc" => {
            mc.mpls_tc = Some(parse_p4_u8(value)?);
        }
        "hdr.mpls.bos" => {
            mc.mpls_bos = Some(parse_p4_bool(value));
        }

        // ARP
        "hdr.arp.opcode" => {
            mc.arp_opcode = Some(parse_p4_u16(value)?);
        }
        "hdr.arp.senderProtoAddr" => {
            mc.arp_spa = Some(parse_p4_lpm(value));
        }
        "hdr.arp.targetProtoAddr" => {
            mc.arp_tpa = Some(parse_p4_lpm(value));
        }

        // ICMP
        "hdr.icmp.type_" => {
            mc.icmp_type = Some(parse_p4_u8(value)?);
        }
        "hdr.icmp.code" => {
            mc.icmp_code = Some(parse_p4_u8(value)?);
        }
        "hdr.icmpv6.type_" => {
            mc.icmpv6_type = Some(parse_p4_u8(value)?);
        }
        "hdr.icmpv6.code" => {
            mc.icmpv6_code = Some(parse_p4_u8(value)?);
        }

        // IGMP/MLD
        "hdr.igmp.type_" => {
            mc.igmp_type = Some(parse_p4_u8(value)?);
        }
        "hdr.mld.type_" => {
            mc.mld_type = Some(parse_p4_u8(value)?);
        }

        // OAM/NSH
        "hdr.oam.level" => {
            mc.oam_level = Some(parse_p4_u8(value)?);
        }
        "hdr.oam.opcode" => {
            mc.oam_opcode = Some(parse_p4_u8(value)?);
        }
        "hdr.nsh.spi" => {
            mc.nsh_spi = Some(parse_p4_u32(value)?);
        }
        "hdr.nsh.si" => {
            mc.nsh_si = Some(parse_p4_u8(value)?);
        }
        "hdr.nsh.nextProtocol" => {
            mc.nsh_next_protocol = Some(parse_p4_u8(value)?);
        }

        // PTP
        "hdr.ptp.messageType" => {
            mc.ptp_message_type = Some(parse_p4_u8(value)?);
        }
        "hdr.ptp.domainNumber" => {
            mc.ptp_domain = Some(parse_p4_u8(value)?);
        }
        "hdr.ptp.versionPTP" => {
            mc.ptp_version = Some(parse_p4_u8(value)?);
        }

        // QinQ
        "hdr.outer_vlan.vid" => {
            mc.outer_vlan_id = Some(parse_p4_u16(value)?);
        }
        "hdr.outer_vlan.pcp" => {
            mc.outer_vlan_pcp = Some(parse_p4_u8(value)?);
        }

        // Conntrack
        "meta.conntrack_state" => {
            mc.conntrack_state = Some(parse_p4_conntrack_state(value));
        }

        _ => {
            // Unknown field — skip silently (may be from newer version)
        }
    }

    Ok(())
}

// ============================================================
// Rewrite action parsing
// ============================================================

fn parse_rewrite_ops(operations: &[String]) -> Result<RewriteAction> {
    let mut rw = RewriteAction::default();

    for op in operations {
        let op = op.trim().trim_end_matches(';').trim();

        // MAC assignments: hdr.ethernet.dstAddr = 0xaabbccddeeff;
        if op.starts_with("hdr.ethernet.dstAddr = ") {
            let val = op.strip_prefix("hdr.ethernet.dstAddr = ").unwrap().trim();
            rw.set_dst_mac = Some(p4_hex_to_mac(val)?);
        } else if op.starts_with("hdr.ethernet.srcAddr = ") {
            let val = op.strip_prefix("hdr.ethernet.srcAddr = ").unwrap().trim();
            rw.set_src_mac = Some(p4_hex_to_mac(val)?);
        }
        // VLAN
        else if op.starts_with("hdr.vlan.vid = ") {
            let val = op.strip_prefix("hdr.vlan.vid = ").unwrap().trim();
            rw.set_vlan_id = Some(val.parse()?);
        } else if op.starts_with("hdr.vlan.pcp = ") {
            let val = op.strip_prefix("hdr.vlan.pcp = ").unwrap().trim();
            rw.set_vlan_pcp = Some(val.parse()?);
        } else if op.starts_with("hdr.outer_vlan.vid = ") {
            let val = op.strip_prefix("hdr.outer_vlan.vid = ").unwrap().trim();
            rw.set_outer_vlan_id = Some(val.parse()?);
        }
        // IPv4 TTL
        else if op == "hdr.ipv4.ttl = hdr.ipv4.ttl - 1" {
            rw.dec_ttl = Some(true);
        } else if op.starts_with("hdr.ipv4.ttl = ") {
            let val = op.strip_prefix("hdr.ipv4.ttl = ").unwrap().trim();
            rw.set_ttl = Some(val.parse()?);
        }
        // IPv4 addresses
        else if op.starts_with("hdr.ipv4.srcAddr = ") {
            let val = op.strip_prefix("hdr.ipv4.srcAddr = ").unwrap().trim();
            rw.set_src_ip = Some(val.to_string());
        } else if op.starts_with("hdr.ipv4.dstAddr = ") {
            let val = op.strip_prefix("hdr.ipv4.dstAddr = ").unwrap().trim();
            rw.set_dst_ip = Some(val.to_string());
        }
        // DSCP
        else if op.starts_with("hdr.ipv4.dscp = ") {
            let val = op.strip_prefix("hdr.ipv4.dscp = ").unwrap().trim();
            rw.set_dscp = Some(val.parse()?);
        }
        // ECN
        else if op.starts_with("hdr.ipv4.ecn = ") {
            let val = op.strip_prefix("hdr.ipv4.ecn = ").unwrap().trim();
            rw.set_ecn = Some(val.parse()?);
        }
        // L4 ports
        else if op.starts_with("meta.l4_src_port = ") {
            let val = op.strip_prefix("meta.l4_src_port = ").unwrap().trim();
            rw.set_src_port = Some(val.parse()?);
        } else if op.starts_with("meta.l4_dst_port = ") {
            let val = op.strip_prefix("meta.l4_dst_port = ").unwrap().trim();
            rw.set_dst_port = Some(val.parse()?);
        }
        // IPv6 hop limit
        else if op == "hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1" {
            rw.dec_hop_limit = Some(true);
        } else if op.starts_with("hdr.ipv6.hopLimit = ") {
            let val = op.strip_prefix("hdr.ipv6.hopLimit = ").unwrap().trim();
            rw.set_hop_limit = Some(val.parse()?);
        }
    }

    Ok(rw)
}

// ============================================================
// Value parsers
// ============================================================

/// Parse P4 hex ethertype "0x0800" → "0x0800" (pass through)
fn parse_p4_ethertype(value: &str) -> Result<String> {
    // Accept both "0x0800" and "2048" decimal
    if value.starts_with("0x") || value.starts_with("0X") {
        Ok(value.to_string())
    } else {
        let v: u16 = value.parse()?;
        Ok(format!("0x{:04x}", v))
    }
}

/// Parse P4 MAC ternary "0xaabbcc000000 &&& 0xffffff000000" → "aa:bb:cc:*:*:*"
fn p4_to_mac(value: &str) -> Result<String> {
    if value.contains("&&&") {
        let parts: Vec<&str> = value.split("&&&").collect();
        let val_hex = parts[0].trim().trim_start_matches("0x").trim_start_matches("0X");
        let mask_hex = parts[1].trim().trim_start_matches("0x").trim_start_matches("0X");

        if val_hex.len() < 12 || mask_hex.len() < 12 {
            bail!("Invalid MAC ternary: {}", value);
        }

        let mut octets = Vec::new();
        for i in 0..6 {
            let m = &mask_hex[i*2..i*2+2];
            let v = &val_hex[i*2..i*2+2];
            if m == "00" {
                octets.push("*".to_string());
            } else {
                octets.push(v.to_lowercase());
            }
        }
        Ok(octets.join(":"))
    } else {
        // Exact MAC: 0xaabbccddeeff → aa:bb:cc:dd:ee:ff
        let hex = value.trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() < 12 {
            bail!("Invalid MAC: {}", value);
        }
        let mut octets = Vec::new();
        for i in 0..6 {
            octets.push(hex[i*2..i*2+2].to_lowercase());
        }
        Ok(octets.join(":"))
    }
}

/// Convert P4 hex "0xaabbccddeeff" → "aa:bb:cc:dd:ee:ff"
fn p4_hex_to_mac(value: &str) -> Result<String> {
    let hex = value.trim_start_matches("0x").trim_start_matches("0X");
    if hex.len() < 12 {
        bail!("Invalid MAC hex: {}", value);
    }
    let mut octets = Vec::new();
    for i in 0..6 {
        octets.push(hex[i*2..i*2+2].to_lowercase());
    }
    Ok(octets.join(":"))
}

/// Parse P4 range "80..80" → Exact(80), "1024..65535" → Range([1024, 65535])
fn parse_p4_port(value: &str) -> Result<PortMatch> {
    if value.contains("..") {
        let parts: Vec<&str> = value.split("..").collect();
        let lo: u16 = parts[0].trim().parse()?;
        let hi: u16 = parts[1].trim().parse()?;
        if lo == hi {
            Ok(PortMatch::Exact(lo))
        } else {
            Ok(PortMatch::Range { range: [lo, hi] })
        }
    } else {
        let v: u16 = value.parse()?;
        Ok(PortMatch::Exact(v))
    }
}

/// Parse P4 ternary u8 "0x02 &&& 0x02" → (2, 2)
fn parse_p4_ternary_u8(value: &str) -> Result<(u8, u8)> {
    if value.contains("&&&") {
        let parts: Vec<&str> = value.split("&&&").collect();
        let val = parse_p4_u8(parts[0].trim())?;
        let mask = parse_p4_u8(parts[1].trim())?;
        Ok((val, mask))
    } else {
        let val = parse_p4_u8(value)?;
        Ok((val, 0xFF))
    }
}

/// Parse P4 LPM value (pass through as CIDR string)
fn parse_p4_lpm(value: &str) -> String {
    value.trim().to_string()
}

/// Parse decimal or hex u8
fn parse_p4_u8(value: &str) -> Result<u8> {
    let v = value.trim();
    if v.starts_with("0x") || v.starts_with("0X") {
        Ok(u8::from_str_radix(&v[2..], 16)?)
    } else {
        Ok(v.parse()?)
    }
}

/// Parse decimal or hex u16
fn parse_p4_u16(value: &str) -> Result<u16> {
    let v = value.trim();
    if v.starts_with("0x") || v.starts_with("0X") {
        Ok(u16::from_str_radix(&v[2..], 16)?)
    } else {
        Ok(v.parse()?)
    }
}

/// Parse decimal or hex u32
fn parse_p4_u32(value: &str) -> Result<u32> {
    let v = value.trim();
    if v.starts_with("0x") || v.starts_with("0X") {
        Ok(u32::from_str_radix(&v[2..], 16)?)
    } else {
        Ok(v.parse()?)
    }
}

/// Parse "1"/"0" → true/false
fn parse_p4_bool(value: &str) -> bool {
    value.trim() == "1"
}

/// Parse conntrack state: "0" → "new", "1" → "established"
fn parse_p4_conntrack_state(value: &str) -> String {
    match value.trim() {
        "0" => "new".to_string(),
        "1" => "established".to_string(),
        _ => "new".to_string(),
    }
}

// ============================================================
// Line parsing helpers
// ============================================================

/// Extract action name from "action rewrite_foo() {"
fn extract_action_name(line: &str) -> Option<String> {
    let line = line.trim();
    let s = line.strip_prefix("action ")?;
    let end = s.find('(')?;
    Some(s[..end].trim().to_string())
}

/// Parse table key line: "hdr.ipv4.srcAddr : lpm;" → ParsedKey
fn parse_table_key_line(line: &str) -> Option<ParsedKey> {
    let line = line.trim().trim_end_matches(';');
    if line.is_empty() || line.starts_with("//") || line == "}" {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() >= 2 {
        Some(ParsedKey {
            header_field: parts[0].trim().to_string(),
            match_kind: parts.last().unwrap().trim().to_string(),
        })
    } else {
        None
    }
}

/// Parse entry comment: "// Rule: allow_arp (priority 200)" → ("allow_arp", 200)
fn parse_entry_comment(line: &str) -> (String, u32) {
    let s = line.trim().trim_start_matches("//").trim();
    let s = s.strip_prefix("Rule:").unwrap_or(s).trim();

    if let Some(paren_start) = s.rfind("(priority ") {
        let name = s[..paren_start].trim().to_string();
        let prio_str = s[paren_start + 10..].trim_end_matches(')').trim();
        let priority: u32 = prio_str.parse().unwrap_or(100);
        (name, priority)
    } else {
        (s.to_string(), 100)
    }
}

/// Try to parse a single-line entry: "(0x0806) : pass_action();"
fn try_parse_single_line_entry(line: &str, name: &str, priority: u32) -> Option<ParsedEntry> {
    // Match pattern: (values) : action();
    let line = line.trim();
    if !line.contains(") :") && !line.contains("):") {
        return None;
    }

    let paren_end = line.find(") :")?;
    let values_str = &line[1..paren_end]; // skip opening "("
    let action_part = &line[paren_end + 3..]; // skip ") :"
    let action_name = extract_entry_action_from_str(action_part.trim());

    let key_values: Vec<String> = values_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Some(ParsedEntry {
        rule_name: name.to_string(),
        priority,
        action_name,
        key_values,
    })
}

/// Extract action name from ") : rewrite_foo();" line
fn extract_entry_action(line: &str) -> String {
    extract_entry_action_from_str(line)
}

fn extract_entry_action_from_str(s: &str) -> String {
    let s = s.trim().trim_start_matches(") :").trim_start_matches("):").trim();
    let s = s.trim_end_matches(';').trim();
    s.trim_end_matches("()").trim().to_string()
}

// ============================================================
// JSON summary
// ============================================================

pub fn import_p4_summary(source: &str) -> serde_json::Value {
    match import_p4(source) {
        Ok((config, warnings)) => {
            let rules = &config.pacgate.rules;
            let protocols: Vec<String> = detect_imported_protocols(rules);
            let has_rewrite = rules.iter().any(|r| r.has_rewrite());

            serde_json::json!({
                "status": "ok",
                "rules_imported": rules.len(),
                "default_action": format!("{:?}", config.pacgate.defaults.action).to_lowercase(),
                "detected_protocols": protocols,
                "has_rewrite": has_rewrite,
                "has_conntrack": false,
                "has_rate_limit": false,
                "warnings": warnings,
            })
        }
        Err(e) => {
            serde_json::json!({
                "status": "error",
                "error": e.to_string(),
            })
        }
    }
}

fn detect_imported_protocols(rules: &[StatelessRule]) -> Vec<String> {
    let mut protos = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for rule in rules {
        let mc = &rule.match_criteria;
        if mc.src_ip.is_some() || mc.dst_ip.is_some() || mc.ip_protocol.is_some()
            || mc.ip_dscp.is_some() || mc.ip_ecn.is_some() || mc.ip_ttl.is_some() {
            if seen.insert("ipv4") { protos.push("ipv4".to_string()); }
        }
        if mc.src_ipv6.is_some() || mc.dst_ipv6.is_some() || mc.ipv6_next_header.is_some() {
            if seen.insert("ipv6") { protos.push("ipv6".to_string()); }
        }
        if mc.tcp_flags.is_some() {
            if seen.insert("tcp") { protos.push("tcp".to_string()); }
        }
        if mc.src_port.is_some() || mc.dst_port.is_some() {
            if seen.insert("tcp") { protos.push("tcp".to_string()); }
            if seen.insert("udp") { protos.push("udp".to_string()); }
        }
        if mc.vxlan_vni.is_some() { if seen.insert("vxlan") { protos.push("vxlan".to_string()); } }
        if mc.gtp_teid.is_some() { if seen.insert("gtp") { protos.push("gtp".to_string()); } }
        if mc.geneve_vni.is_some() { if seen.insert("geneve") { protos.push("geneve".to_string()); } }
        if mc.gre_protocol.is_some() || mc.gre_key.is_some() { if seen.insert("gre") { protos.push("gre".to_string()); } }
        if mc.mpls_label.is_some() { if seen.insert("mpls") { protos.push("mpls".to_string()); } }
        if mc.arp_opcode.is_some() { if seen.insert("arp") { protos.push("arp".to_string()); } }
        if mc.icmp_type.is_some() { if seen.insert("icmp") { protos.push("icmp".to_string()); } }
        if mc.icmpv6_type.is_some() { if seen.insert("icmpv6") { protos.push("icmpv6".to_string()); } }
        if mc.igmp_type.is_some() { if seen.insert("igmp") { protos.push("igmp".to_string()); } }
        if mc.oam_level.is_some() { if seen.insert("oam") { protos.push("oam".to_string()); } }
        if mc.nsh_spi.is_some() { if seen.insert("nsh") { protos.push("nsh".to_string()); } }
        if mc.ptp_message_type.is_some() { if seen.insert("ptp") { protos.push("ptp".to_string()); } }
    }
    protos
}

// ============================================================
// Round-trip validation: compare two FilterConfigs for equivalence
// ============================================================

/// Compare two configs for semantic equivalence (returns list of differences)
pub fn configs_equivalent(a: &FilterConfig, b: &FilterConfig) -> Vec<String> {
    let mut diffs = Vec::new();

    // Compare default action
    if a.pacgate.defaults.action != b.pacgate.defaults.action {
        diffs.push(format!("Default action differs: {:?} vs {:?}",
            a.pacgate.defaults.action, b.pacgate.defaults.action));
    }

    // Compare stateless rules only
    let a_rules: Vec<_> = a.pacgate.rules.iter().filter(|r| !r.is_stateful()).collect();
    let b_rules: Vec<_> = b.pacgate.rules.iter().filter(|r| !r.is_stateful()).collect();

    if a_rules.len() != b_rules.len() {
        diffs.push(format!("Rule count differs: {} vs {} (stateless)",
            a_rules.len(), b_rules.len()));
        return diffs;
    }

    // Compare rules by name (sorted by priority)
    let mut a_sorted: Vec<_> = a_rules.clone();
    let mut b_sorted: Vec<_> = b_rules.clone();
    a_sorted.sort_by(|x, y| y.priority.cmp(&x.priority));
    b_sorted.sort_by(|x, y| y.priority.cmp(&x.priority));

    for (i, (ar, br)) in a_sorted.iter().zip(b_sorted.iter()).enumerate() {
        if ar.name != br.name {
            diffs.push(format!("Rule {} name differs: '{}' vs '{}'", i, ar.name, br.name));
        }
        if ar.priority != br.priority {
            diffs.push(format!("Rule '{}' priority differs: {} vs {}", ar.name, ar.priority, br.priority));
        }
        if ar.action != br.action {
            diffs.push(format!("Rule '{}' action differs: {:?} vs {:?}", ar.name, ar.action, br.action));
        }
        // Compare match criteria
        compare_match_criteria(&ar.match_criteria, &br.match_criteria, &ar.name, &mut diffs);
        // Compare rewrite
        if ar.rewrite != br.rewrite {
            diffs.push(format!("Rule '{}' rewrite differs", ar.name));
        }
    }

    diffs
}

fn compare_match_criteria(a: &MatchCriteria, b: &MatchCriteria, rule_name: &str, diffs: &mut Vec<String>) {
    macro_rules! cmp_field {
        ($field:ident) => {
            if a.$field != b.$field {
                diffs.push(format!("Rule '{}' field '{}' differs: {:?} vs {:?}",
                    rule_name, stringify!($field), a.$field, b.$field));
            }
        };
    }
    cmp_field!(ethertype);
    cmp_field!(dst_mac);
    cmp_field!(src_mac);
    cmp_field!(vlan_id);
    cmp_field!(vlan_pcp);
    cmp_field!(src_ip);
    cmp_field!(dst_ip);
    cmp_field!(ip_protocol);
    cmp_field!(src_port);
    cmp_field!(dst_port);
    cmp_field!(vxlan_vni);
    cmp_field!(src_ipv6);
    cmp_field!(dst_ipv6);
    cmp_field!(ipv6_next_header);
    cmp_field!(gtp_teid);
    cmp_field!(mpls_label);
    cmp_field!(mpls_tc);
    cmp_field!(mpls_bos);
    cmp_field!(igmp_type);
    cmp_field!(mld_type);
    cmp_field!(ip_dscp);
    cmp_field!(ip_ecn);
    cmp_field!(ipv6_dscp);
    cmp_field!(ipv6_ecn);
    cmp_field!(tcp_flags);
    cmp_field!(tcp_flags_mask);
    cmp_field!(icmp_type);
    cmp_field!(icmp_code);
    cmp_field!(icmpv6_type);
    cmp_field!(icmpv6_code);
    cmp_field!(arp_opcode);
    cmp_field!(arp_spa);
    cmp_field!(arp_tpa);
    cmp_field!(ipv6_hop_limit);
    cmp_field!(ipv6_flow_label);
    cmp_field!(outer_vlan_id);
    cmp_field!(outer_vlan_pcp);
    cmp_field!(ip_dont_fragment);
    cmp_field!(ip_more_fragments);
    cmp_field!(ip_frag_offset);
    cmp_field!(gre_protocol);
    cmp_field!(gre_key);
    cmp_field!(oam_level);
    cmp_field!(oam_opcode);
    cmp_field!(nsh_spi);
    cmp_field!(nsh_si);
    cmp_field!(nsh_next_protocol);
    cmp_field!(geneve_vni);
    cmp_field!(ip_ttl);
    cmp_field!(conntrack_state);
    cmp_field!(ptp_message_type);
    cmp_field!(ptp_domain);
    cmp_field!(ptp_version);
}

// ============================================================
// YAML serialization
// ============================================================

/// Serialize FilterConfig to clean YAML (omitting null fields)
pub fn config_to_yaml(config: &FilterConfig) -> Result<String> {
    // Convert to JSON Value first, then strip nulls, then to YAML
    let json_val = serde_json::to_value(config)?;
    let cleaned = strip_nulls(json_val);
    Ok(serde_yaml::to_string(&cleaned)?)
}

/// Recursively remove null values from JSON Value
fn strip_nulls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_nulls(v)))
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(strip_nulls).collect())
        }
        other => other,
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Value parser tests ----

    #[test]
    fn test_parse_p4_ethertype_hex() {
        assert_eq!(parse_p4_ethertype("0x0800").unwrap(), "0x0800");
        assert_eq!(parse_p4_ethertype("0x86DD").unwrap(), "0x86DD");
    }

    #[test]
    fn test_parse_p4_ethertype_decimal() {
        assert_eq!(parse_p4_ethertype("2048").unwrap(), "0x0800");
    }

    #[test]
    fn test_parse_p4_port_exact() {
        assert_eq!(parse_p4_port("80..80").unwrap(), PortMatch::Exact(80));
    }

    #[test]
    fn test_parse_p4_port_range() {
        assert_eq!(parse_p4_port("1024..65535").unwrap(), PortMatch::Range { range: [1024, 65535] });
    }

    #[test]
    fn test_parse_p4_ternary_tcp_flags() {
        let (val, mask) = parse_p4_ternary_u8("0x02 &&& 0x02").unwrap();
        assert_eq!(val, 0x02);
        assert_eq!(mask, 0x02);
    }

    #[test]
    fn test_p4_to_mac_exact() {
        assert_eq!(p4_to_mac("0xaabbccddeeff").unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_p4_to_mac_wildcard() {
        assert_eq!(
            p4_to_mac("0xaabbcc000000 &&& 0xffffff000000").unwrap(),
            "aa:bb:cc:*:*:*"
        );
    }

    #[test]
    fn test_p4_hex_to_mac() {
        assert_eq!(p4_hex_to_mac("0x001122334455").unwrap(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_parse_p4_bool() {
        assert!(parse_p4_bool("1"));
        assert!(!parse_p4_bool("0"));
    }

    #[test]
    fn test_parse_p4_conntrack_state() {
        assert_eq!(parse_p4_conntrack_state("0"), "new");
        assert_eq!(parse_p4_conntrack_state("1"), "established");
    }

    // ---- Line parsing tests ----

    #[test]
    fn test_parse_table_key_line() {
        let key = parse_table_key_line("            hdr.ipv4.srcAddr : lpm;").unwrap();
        assert_eq!(key.header_field, "hdr.ipv4.srcAddr");
        assert_eq!(key.match_kind, "lpm");
    }

    #[test]
    fn test_parse_table_key_line_range() {
        let key = parse_table_key_line("            meta.l4_dst_port : range;").unwrap();
        assert_eq!(key.header_field, "meta.l4_dst_port");
        assert_eq!(key.match_kind, "range");
    }

    #[test]
    fn test_parse_entry_comment() {
        let (name, prio) = parse_entry_comment("            // Rule: allow_arp (priority 200)");
        assert_eq!(name, "allow_arp");
        assert_eq!(prio, 200);
    }

    #[test]
    fn test_parse_entry_comment_spaces() {
        let (name, prio) = parse_entry_comment("// Rule: http_traffic (priority 100)");
        assert_eq!(name, "http_traffic");
        assert_eq!(prio, 100);
    }

    #[test]
    fn test_extract_action_name() {
        assert_eq!(extract_action_name("    action rewrite_foo() {"), Some("rewrite_foo".to_string()));
        assert_eq!(extract_action_name("    action pass_action() {"), Some("pass_action".to_string()));
    }

    // ---- apply_key_value tests ----

    #[test]
    fn test_apply_key_ethertype() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.ethernet.etherType", "exact", "0x0800").unwrap();
        assert_eq!(mc.ethertype, Some("0x0800".to_string()));
    }

    #[test]
    fn test_apply_key_src_ip() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.ipv4.srcAddr", "lpm", "10.0.0.0/8").unwrap();
        assert_eq!(mc.src_ip, Some("10.0.0.0/8".to_string()));
    }

    #[test]
    fn test_apply_key_dst_port() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "meta.l4_dst_port", "range", "80..80").unwrap();
        assert_eq!(mc.dst_port, Some(PortMatch::Exact(80)));
    }

    #[test]
    fn test_apply_key_port_range() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "meta.l4_dst_port", "range", "1024..65535").unwrap();
        assert_eq!(mc.dst_port, Some(PortMatch::Range { range: [1024, 65535] }));
    }

    #[test]
    fn test_apply_key_dont_care() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.ethernet.etherType", "exact", "_").unwrap();
        assert_eq!(mc.ethertype, None);
    }

    #[test]
    fn test_apply_key_vxlan_vni() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.vxlan.vni", "exact", "1000").unwrap();
        assert_eq!(mc.vxlan_vni, Some(1000));
    }

    #[test]
    fn test_apply_key_ptp() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.ptp.messageType", "exact", "0").unwrap();
        apply_key_value(&mut mc, "hdr.ptp.domainNumber", "exact", "0").unwrap();
        assert_eq!(mc.ptp_message_type, Some(0));
        assert_eq!(mc.ptp_domain, Some(0));
    }

    #[test]
    fn test_apply_key_oam() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.oam.level", "exact", "3").unwrap();
        apply_key_value(&mut mc, "hdr.oam.opcode", "exact", "1").unwrap();
        assert_eq!(mc.oam_level, Some(3));
        assert_eq!(mc.oam_opcode, Some(1));
    }

    #[test]
    fn test_apply_key_nsh() {
        let mut mc = MatchCriteria::default();
        apply_key_value(&mut mc, "hdr.nsh.spi", "exact", "100").unwrap();
        apply_key_value(&mut mc, "hdr.nsh.si", "exact", "254").unwrap();
        assert_eq!(mc.nsh_spi, Some(100));
        assert_eq!(mc.nsh_si, Some(254));
    }

    // ---- Rewrite parsing tests ----

    #[test]
    fn test_parse_rewrite_dst_mac() {
        let ops = vec!["hdr.ethernet.dstAddr = 0xaabbccddeeff;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_dst_mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn test_parse_rewrite_dec_ttl() {
        let ops = vec!["hdr.ipv4.ttl = hdr.ipv4.ttl - 1;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.dec_ttl, Some(true));
    }

    #[test]
    fn test_parse_rewrite_dscp() {
        let ops = vec!["hdr.ipv4.dscp = 46;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_dscp, Some(46));
    }

    #[test]
    fn test_parse_rewrite_port() {
        let ops = vec!["meta.l4_dst_port = 443;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_dst_port, Some(443));
    }

    #[test]
    fn test_parse_rewrite_hop_limit() {
        let ops = vec!["hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.dec_hop_limit, Some(true));
    }

    #[test]
    fn test_parse_rewrite_set_hop_limit() {
        let ops = vec!["hdr.ipv6.hopLimit = 64;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_hop_limit, Some(64));
    }

    #[test]
    fn test_parse_rewrite_ecn() {
        let ops = vec!["hdr.ipv4.ecn = 1;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_ecn, Some(1));
    }

    #[test]
    fn test_parse_rewrite_vlan_pcp() {
        let ops = vec!["hdr.vlan.pcp = 5;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_vlan_pcp, Some(5));
    }

    #[test]
    fn test_parse_rewrite_outer_vlan() {
        let ops = vec!["hdr.outer_vlan.vid = 200;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_outer_vlan_id, Some(200));
    }

    #[test]
    fn test_parse_rewrite_set_ttl() {
        let ops = vec!["hdr.ipv4.ttl = 64;".to_string()];
        let rw = parse_rewrite_ops(&ops).unwrap();
        assert_eq!(rw.set_ttl, Some(64));
    }

    // ---- Full import tests ----

    #[test]
    fn test_import_minimal_p4() {
        let source = r#"
#include <core.p4>
#include <psa.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct metadata_t {
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

struct headers_t {
    ethernet_t ethernet;
}

parser IngressParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    in psa_ingress_parser_input_metadata_t istd,
    in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta
) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control Ingress(
    inout headers_t hdr,
    inout metadata_t meta,
    in    psa_ingress_input_metadata_t  istd,
    inout psa_ingress_output_metadata_t ostd
) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }

    table filter_table {
        key = {
            hdr.ethernet.etherType : exact;
        }
        actions = { pass_action; drop_action; }
        default_action = drop_action();

        const entries = {
            // Rule: allow_arp (priority 200)
            (
                0x0806
            ) : pass_action();
        }
    }

    apply { filter_table.apply(); }
}

control IngressDeparser(packet_out pkt, out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta,
    inout headers_t hdr, in metadata_t meta,
    in psa_ingress_output_metadata_t istd) {
    apply { pkt.emit(hdr.ethernet); }
}
parser EgressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta,
    in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start { transition accept; }
}
control Egress(inout headers_t hdr, inout metadata_t meta,
    in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) {
    apply {}
}
control EgressDeparser(packet_out pkt, out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta, inout headers_t hdr, in metadata_t meta,
    in psa_egress_input_metadata_t istd, in psa_egress_output_metadata_t ostd) {
    apply { pkt.emit(hdr.ethernet); }
}
IngressPipeline(IngressParser(), Ingress(), IngressDeparser()) ip;
EgressPipeline(EgressParser(), Egress(), EgressDeparser()) ep;
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
"#;

        let (config, warnings) = import_p4(source).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].name, "allow_arp");
        assert_eq!(config.pacgate.rules[0].priority, 200);
        assert_eq!(config.pacgate.rules[0].match_criteria.ethertype, Some("0x0806".to_string()));
        assert_eq!(config.pacgate.rules[0].action, Some(Action::Pass));
        assert_eq!(config.pacgate.defaults.action, Action::Drop);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_import_l3l4_p4() {
        let source = r#"
#include <core.p4>
#include <psa.p4>
header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<6> dscp; bit<2> ecn; bit<16> totalLen;
    bit<16> identification; bit<1> flags_reserved; bit<1> flags_df; bit<1> flags_mf;
    bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum;
    bit<32> srcAddr; bit<32> dstAddr; }
struct metadata_t { bit<16> l4_src_port; bit<16> l4_dst_port; }
struct headers_t { ethernet_t ethernet; ipv4_t ipv4; }
parser IngressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_ingress_parser_input_metadata_t istd, in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta) { state start { transition accept; } }
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }

    table filter_table {
        key = {
            hdr.ethernet.etherType : exact;
            hdr.ipv4.srcAddr : lpm;
            meta.l4_dst_port : range;
        }
        actions = { pass_action; drop_action; }
        default_action = drop_action();

        const entries = {
            // Rule: allow_http (priority 100)
            (
                0x0800,
                10.0.0.0/8,
                80..80
            ) : pass_action();
            // Rule: allow_https (priority 90)
            (
                0x0800,
                10.0.0.0/8,
                443..443
            ) : pass_action();
        }
    }
    apply { filter_table.apply(); }
}
parser EgressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta,
    in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start { transition accept; } }
control Egress(inout headers_t hdr, inout metadata_t meta,
    in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) { apply {} }
control EgressDeparser(packet_out pkt, out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta, inout headers_t hdr, in metadata_t meta,
    in psa_egress_input_metadata_t istd, in psa_egress_output_metadata_t ostd) { apply {} }
control IngressDeparser(packet_out pkt, out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta,
    inout headers_t hdr, in metadata_t meta, in psa_ingress_output_metadata_t istd) { apply {} }
IngressPipeline(IngressParser(), Ingress(), IngressDeparser()) ip;
EgressPipeline(EgressParser(), Egress(), EgressDeparser()) ep;
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
"#;

        let (config, warnings) = import_p4(source).unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].name, "allow_http");
        assert_eq!(config.pacgate.rules[0].match_criteria.ethertype, Some("0x0800".to_string()));
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip, Some("10.0.0.0/8".to_string()));
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
        assert_eq!(config.pacgate.rules[1].name, "allow_https");
        assert_eq!(config.pacgate.rules[1].match_criteria.dst_port, Some(PortMatch::Exact(443)));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_import_with_rewrite() {
        let source = r#"
#include <core.p4>
#include <psa.p4>
header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<6> dscp; bit<2> ecn; bit<16> totalLen;
    bit<16> identification; bit<1> flags_reserved; bit<1> flags_df; bit<1> flags_mf;
    bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum;
    bit<32> srcAddr; bit<32> dstAddr; }
struct metadata_t { bit<16> l4_src_port; bit<16> l4_dst_port; }
struct headers_t { ethernet_t ethernet; ipv4_t ipv4; }
parser IngressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_ingress_parser_input_metadata_t istd, in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta) { state start { transition accept; } }
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    action rewrite_remark_ef() {
        hdr.ipv4.dscp = 46;
    }

    table filter_table {
        key = {
            hdr.ethernet.etherType : exact;
            hdr.ipv4.dscp : exact;
        }
        actions = { pass_action; drop_action; rewrite_remark_ef; }
        default_action = drop_action();

        const entries = {
            // Rule: remark_ef (priority 100)
            (
                0x0800,
                46
            ) : rewrite_remark_ef();
        }
    }
    apply { filter_table.apply(); }
}
parser EgressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta,
    in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start { transition accept; } }
control Egress(inout headers_t hdr, inout metadata_t meta,
    in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) { apply {} }
control EgressDeparser(packet_out pkt, out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta, inout headers_t hdr, in metadata_t meta,
    in psa_egress_input_metadata_t istd, in psa_egress_output_metadata_t ostd) { apply {} }
control IngressDeparser(packet_out pkt, out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta,
    inout headers_t hdr, in metadata_t meta, in psa_ingress_output_metadata_t istd) { apply {} }
IngressPipeline(IngressParser(), Ingress(), IngressDeparser()) ip;
EgressPipeline(EgressParser(), Egress(), EgressDeparser()) ep;
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
"#;

        let (config, warnings) = import_p4(source).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.name, "remark_ef");
        assert_eq!(rule.action, Some(Action::Pass)); // rewrite implies pass
        let rw = rule.rewrite.as_ref().unwrap();
        assert_eq!(rw.set_dscp, Some(46));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_import_extern_detection() {
        let source = r#"
#include <core.p4>
#include <psa.p4>
header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
struct metadata_t { bit<16> l4_src_port; bit<16> l4_dst_port; bit<2> conntrack_state; }
struct headers_t { ethernet_t ethernet; }
Register<bit<2>, bit<16>>(65536) conntrack_register;
Meter<bit<16>>(5, PSA_MeterType_t.PACKETS) rate_meter;
ActionSelector(HashAlgorithm.crc32, 128, 4) rss_selector;
parser IngressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_ingress_parser_input_metadata_t istd, in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta) { state start { transition accept; } }
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    table filter_table {
        key = { hdr.ethernet.etherType : exact; }
        actions = { pass_action; drop_action; }
        default_action = drop_action();
        const entries = {
            // Rule: allow_all (priority 100)
            (
                0x0800
            ) : pass_action();
        }
    }
    apply { filter_table.apply(); }
}
parser EgressParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
    in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta,
    in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start { transition accept; } }
control Egress(inout headers_t hdr, inout metadata_t meta,
    in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) { apply {} }
control EgressDeparser(packet_out pkt, out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta, inout headers_t hdr, in metadata_t meta,
    in psa_egress_input_metadata_t istd, in psa_egress_output_metadata_t ostd) { apply {} }
control IngressDeparser(packet_out pkt, out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta,
    inout headers_t hdr, in metadata_t meta, in psa_ingress_output_metadata_t istd) { apply {} }
IngressPipeline(IngressParser(), Ingress(), IngressDeparser()) ip;
EgressPipeline(EgressParser(), Egress(), EgressDeparser()) ep;
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
"#;

        let (config, warnings) = import_p4(source).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert!(warnings.iter().any(|w| w.contains("Register extern")));
        assert!(warnings.iter().any(|w| w.contains("Meter extern")));
        assert!(warnings.iter().any(|w| w.contains("ActionSelector extern")));
    }

    #[test]
    fn test_import_default_pass() {
        let source = r#"
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    table filter_table {
        key = { hdr.ethernet.etherType : exact; }
        actions = { pass_action; drop_action; }
        default_action = pass_action();
        const entries = {
            // Rule: block_bad (priority 100)
            (
                0x9999
            ) : drop_action();
        }
    }
    apply { filter_table.apply(); }
}
"#;

        let (config, _) = import_p4(source).unwrap();
        assert_eq!(config.pacgate.defaults.action, Action::Pass);
        assert_eq!(config.pacgate.rules[0].action, Some(Action::Drop));
    }

    #[test]
    fn test_json_summary_basic() {
        let source = r#"
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    table filter_table {
        key = { hdr.ethernet.etherType : exact; }
        actions = { pass_action; drop_action; }
        default_action = drop_action();
        const entries = {
            // Rule: allow_ipv4 (priority 100)
            (
                0x0800
            ) : pass_action();
        }
    }
    apply { filter_table.apply(); }
}
"#;

        let summary = import_p4_summary(source);
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rules_imported"], 1);
        assert_eq!(summary["default_action"], "drop");
    }

    #[test]
    fn test_json_summary_with_warnings() {
        let source = r#"
Register<bit<2>, bit<16>>(65536) conntrack_register;
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    table filter_table {
        key = { hdr.ethernet.etherType : exact; }
        actions = { pass_action; drop_action; }
        default_action = drop_action();
        const entries = {
            // Rule: test (priority 100)
            (
                0x0800
            ) : pass_action();
        }
    }
    apply { filter_table.apply(); }
}
"#;

        let summary = import_p4_summary(source);
        assert_eq!(summary["status"], "ok");
        let warnings = summary["warnings"].as_array().unwrap();
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_json_summary_empty() {
        let source = r#"
control Ingress(inout headers_t hdr, inout metadata_t meta,
    in psa_ingress_input_metadata_t istd, inout psa_ingress_output_metadata_t ostd) {
    action pass_action() { }
    action drop_action() { ingress_drop(ostd); }
    table filter_table {
        key = { hdr.ethernet.etherType : exact; }
        actions = { pass_action; drop_action; }
        default_action = drop_action();
        const entries = {
        }
    }
    apply { filter_table.apply(); }
}
"#;

        let summary = import_p4_summary(source);
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rules_imported"], 0);
    }

    #[test]
    fn test_configs_equivalent_same() {
        let rule = StatelessRule {
            name: "test".to_string(), priority: 100,
            match_criteria: MatchCriteria { ethertype: Some("0x0800".to_string()), ..Default::default() },
            action: Some(Action::Pass), rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None,
            rss_queue: None, int_insert: None,
        };
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![rule.clone()],
                conntrack: None,
                tables: None,
            },
        };
        let diffs = configs_equivalent(&config, &config);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_configs_equivalent_different_default() {
        let make = |action: Action| FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action },
                rules: vec![],
                conntrack: None,
                tables: None,
            },
        };
        let diffs = configs_equivalent(&make(Action::Pass), &make(Action::Drop));
        assert!(!diffs.is_empty());
        assert!(diffs[0].contains("Default action"));
    }
}
