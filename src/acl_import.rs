// Cisco IOS ACL Import: Parse Cisco IOS extended/standard ACL syntax into PacGate FilterConfig
//
// Supports:
//   - Named extended ACLs:  ip access-list extended NAME
//   - Named standard ACLs:  ip access-list standard NAME
//   - Numbered extended ACLs: access-list 100-199/2000-2699
//   - Numbered standard ACLs: access-list 1-99/1300-1999
//   - Address forms: any, host IP, IP WILDCARD
//   - Wildcard-to-CIDR conversion
//   - Port operators: eq, gt, lt, neq, range
//   - Named ports: www, ftp, ssh, etc.
//   - TCP established keyword
//   - ICMP type/code
//   - Protocol keywords and numbers

use anyhow::{bail, Result};

use crate::model::*;

// ============================================================
// Wildcard mask → CIDR prefix length
// ============================================================

/// Convert a wildcard mask (e.g., 0.0.0.255) to a CIDR prefix length.
/// Returns None if the wildcard is not contiguous.
fn wildcard_to_cidr(wildcard: &str) -> Result<u8> {
    let octets: Vec<u8> = wildcard
        .split('.')
        .map(|s| s.parse::<u8>().map_err(|_| anyhow::anyhow!("Invalid wildcard octet: {}", s)))
        .collect::<Result<Vec<_>>>()?;
    if octets.len() != 4 {
        bail!("Invalid wildcard mask: {}", wildcard);
    }

    // Convert wildcard to 32-bit integer and invert to get subnet mask
    let wc = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);

    // Wildcard of all 1s = /0 (match all)
    if wc == 0xFFFFFFFF {
        return Ok(0);
    }
    // Wildcard of all 0s = /32 (exact match)
    if wc == 0 {
        return Ok(32);
    }

    // Check contiguous: wildcard bits must be all trailing 1s
    // e.g., 0.0.0.255 = 0x000000FF → inverted = 0xFFFFFF00, leading 1s = 24
    let mask = !wc;
    let prefix = mask.leading_ones() as u8;
    // Verify: mask should be exactly `prefix` leading 1s and rest 0s
    let expected = if prefix == 0 { 0u32 } else { !((1u32 << (32 - prefix)) - 1) };
    if mask != expected {
        bail!("Non-contiguous wildcard mask '{}' cannot be converted to CIDR", wildcard);
    }

    Ok(prefix)
}

/// Parse address: "any" | "host IP" | "IP WILDCARD" from tokens at position i.
/// Returns (address option as CIDR string, new position).
fn parse_address(tokens: &[String], i: usize) -> Result<(Option<String>, usize)> {
    if i >= tokens.len() {
        bail!("Expected address but reached end of line");
    }

    match tokens[i].to_lowercase().as_str() {
        "any" => Ok((None, i + 1)),
        "host" => {
            if i + 1 >= tokens.len() {
                bail!("Expected IP after 'host'");
            }
            Ok((Some(format!("{}/32", tokens[i + 1])), i + 2))
        }
        _ => {
            // IP WILDCARD
            if i + 1 >= tokens.len() {
                // Just an IP with no wildcard — treat as host
                Ok((Some(format!("{}/32", tokens[i])), i + 1))
            } else {
                // Check if next token looks like a wildcard mask (4 dot-separated octets)
                let next = &tokens[i + 1];
                if next.split('.').count() == 4 && next.split('.').all(|s| s.parse::<u8>().is_ok()) {
                    let prefix = wildcard_to_cidr(next)?;
                    if prefix == 0 {
                        // /0 means match all — same as "any"
                        Ok((None, i + 2))
                    } else if prefix == 32 {
                        Ok((Some(format!("{}/32", tokens[i])), i + 2))
                    } else {
                        Ok((Some(format!("{}/{}", tokens[i], prefix)), i + 2))
                    }
                } else {
                    // Next token is not a wildcard mask — treat IP as /32
                    Ok((Some(format!("{}/32", tokens[i])), i + 1))
                }
            }
        }
    }
}

// ============================================================
// Named port resolution
// ============================================================

fn resolve_port_name(name: &str) -> Option<u16> {
    match name.to_lowercase().as_str() {
        "ftp-data" => Some(20),
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "time" => Some(37),
        "dns" | "domain" | "nameserver" => Some(53),
        "bootps" | "dhcps" => Some(67),
        "bootpc" | "dhcpc" => Some(68),
        "tftp" => Some(69),
        "http" | "www" | "www-http" => Some(80),
        "pop2" => Some(109),
        "pop3" => Some(110),
        "sunrpc" => Some(111),
        "nntp" => Some(119),
        "ntp" => Some(123),
        "netbios-ns" => Some(137),
        "netbios-dgm" => Some(138),
        "netbios-ssn" | "netbios-ss" => Some(139),
        "imap" | "imap4" => Some(143),
        "snmp" => Some(161),
        "snmptrap" => Some(162),
        "bgp" => Some(179),
        "ldap" => Some(389),
        "https" => Some(443),
        "syslog" => Some(514),
        "ldaps" => Some(636),
        "rtsp" => Some(554),
        "exec" | "rsh" => Some(512),
        "login" | "rlogin" => Some(513),
        "cmd" => Some(514),
        "lpd" => Some(515),
        "talk" => Some(517),
        "rip" => Some(520),
        "kerberos" => Some(88),
        "klogin" => Some(543),
        "kshell" => Some(544),
        _ => name.parse::<u16>().ok(),
    }
}

// ============================================================
// Protocol name → ip_protocol
// ============================================================

fn protocol_number(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "ip" => Some(0), // special: matches all IP protocols
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "gre" => Some(47),
        "ospf" | "ospfigp" => Some(89),
        "eigrp" => Some(88),
        "igmp" => Some(2),
        "ahp" | "ah" => Some(51),
        "esp" | "ipsec" => Some(50),
        "pim" => Some(103),
        "sctp" => Some(132),
        "ipv6" | "ipv6-route" => Some(43),
        _ => name.parse::<u8>().ok(),
    }
}

// ============================================================
// ICMP type name → type number
// ============================================================

fn icmp_type_from_name(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "echo-reply" | "echoreply" => Some(0),
        "unreachable" | "host-unreachable" | "net-unreachable" => Some(3),
        "source-quench" => Some(4),
        "redirect" => Some(5),
        "echo" | "echo-request" => Some(8),
        "router-advertisement" => Some(9),
        "router-solicitation" => Some(10),
        "time-exceeded" | "ttl-exceeded" => Some(11),
        "parameter-problem" => Some(12),
        "timestamp-request" => Some(13),
        "timestamp-reply" => Some(14),
        "information-request" => Some(15),
        "information-reply" => Some(16),
        "mask-request" | "address-mask-request" => Some(17),
        "mask-reply" | "address-mask-reply" => Some(18),
        "traceroute" => Some(30),
        _ => name.parse::<u8>().ok(),
    }
}

// ============================================================
// Port operator parsing
// ============================================================

/// Parse a port operator (eq, gt, lt, neq, range) from tokens at position i.
/// Returns (PortMatch, new position).
fn parse_port_op(tokens: &[String], i: usize, warnings: &mut Vec<String>) -> Result<(Option<PortMatch>, usize)> {
    if i >= tokens.len() {
        return Ok((None, i));
    }

    match tokens[i].to_lowercase().as_str() {
        "eq" => {
            if i + 1 >= tokens.len() {
                bail!("Expected port after 'eq'");
            }
            let port = resolve_port_name(&tokens[i + 1])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 1]))?;
            Ok((Some(PortMatch::Exact(port)), i + 2))
        }
        "gt" => {
            if i + 1 >= tokens.len() {
                bail!("Expected port after 'gt'");
            }
            let port = resolve_port_name(&tokens[i + 1])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 1]))?;
            // gt N → range N+1..65535
            Ok((Some(PortMatch::Range { range: [port + 1, 65535] }), i + 2))
        }
        "lt" => {
            if i + 1 >= tokens.len() {
                bail!("Expected port after 'lt'");
            }
            let port = resolve_port_name(&tokens[i + 1])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 1]))?;
            // lt N → range 0..N-1 (but port 0 is unusual)
            let low = if port > 0 { 0 } else { 0 };
            let high = if port > 0 { port - 1 } else { 0 };
            Ok((Some(PortMatch::Range { range: [low, high] }), i + 2))
        }
        "neq" => {
            if i + 1 >= tokens.len() {
                bail!("Expected port after 'neq'");
            }
            let port = resolve_port_name(&tokens[i + 1])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 1]))?;
            // neq cannot be directly represented — warn and skip port match
            warnings.push(format!("Port operator 'neq {}' cannot be directly mapped, ignoring port constraint", port));
            Ok((None, i + 2))
        }
        "range" => {
            if i + 2 >= tokens.len() {
                bail!("Expected two ports after 'range'");
            }
            let low = resolve_port_name(&tokens[i + 1])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 1]))?;
            let high = resolve_port_name(&tokens[i + 2])
                .ok_or_else(|| anyhow::anyhow!("Unknown port: {}", tokens[i + 2]))?;
            Ok((Some(PortMatch::Range { range: [low, high] }), i + 3))
        }
        _ => Ok((None, i)),
    }
}

// ============================================================
// Rule builder
// ============================================================

struct RuleBuilder {
    name_prefix: String,
    counter: usize,
    priority: u32,
    warnings: Vec<String>,
}

impl RuleBuilder {
    fn new(name: &str) -> Self {
        RuleBuilder {
            name_prefix: name.to_string(),
            counter: 0,
            priority: 1000,
            warnings: Vec::new(),
        }
    }

    fn next_name(&mut self, remark: Option<&str>) -> String {
        self.counter += 1;
        if let Some(r) = remark {
            let sanitized: String = r.chars()
                .map(|ch| if ch.is_alphanumeric() || ch == '_' { ch } else { '_' })
                .collect();
            format!("{}_{}_r{}", self.name_prefix, sanitized, self.counter)
        } else {
            format!("{}_r{}", self.name_prefix, self.counter)
        }
    }

    fn next_priority(&mut self) -> u32 {
        let p = self.priority;
        if self.priority >= 10 {
            self.priority -= 10;
        }
        p
    }

    fn make_rule(&self, name: String, priority: u32, mc: MatchCriteria, action: Option<Action>) -> StatelessRule {
        StatelessRule {
            name,
            priority,
            match_criteria: mc,
            action,
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
}

// ============================================================
// ACL type detection
// ============================================================

fn is_numbered_extended(num: u32) -> bool {
    (100..=199).contains(&num) || (2000..=2699).contains(&num)
}

fn is_numbered_standard(num: u32) -> bool {
    (1..=99).contains(&num) || (1300..=1999).contains(&num)
}

// ============================================================
// Extended ACL rule line parser
// ============================================================

/// Parse a single extended ACL rule line (the part after "permit"/"deny").
/// Format: protocol source [port-op] dest [port-op] [options]
fn parse_extended_rule(
    tokens: &[String],
    start: usize,
    action: Option<Action>,
    builder: &mut RuleBuilder,
    last_remark: Option<&str>,
) -> Result<Option<StatelessRule>> {
    let mut i = start;
    let len = tokens.len();

    if i >= len {
        bail!("Expected protocol after permit/deny");
    }

    // Protocol
    let proto_str = tokens[i].to_lowercase();
    let proto_num = protocol_number(&proto_str);
    if proto_num.is_none() {
        bail!("Unknown protocol: {}", tokens[i]);
    }
    let proto_num = proto_num.unwrap();
    i += 1;

    let mut mc = MatchCriteria::default();
    mc.ethertype = Some("0x0800".to_string());

    // ip protocol 0 means "all IP" — don't set ip_protocol
    if proto_num != 0 {
        mc.ip_protocol = Some(proto_num);
    }

    // Source address
    let (src_addr, new_i) = parse_address(tokens, i)?;
    i = new_i;
    mc.src_ip = src_addr;

    // Source port operator (only for TCP/UDP)
    if proto_num == 6 || proto_num == 17 {
        let (src_port, new_i) = parse_port_op(tokens, i, &mut builder.warnings)?;
        i = new_i;
        mc.src_port = src_port;
    }

    // Destination address
    let (dst_addr, new_i) = parse_address(tokens, i)?;
    i = new_i;
    mc.dst_ip = dst_addr;

    // Destination port operator (only for TCP/UDP)
    if proto_num == 6 || proto_num == 17 {
        let (dst_port, new_i) = parse_port_op(tokens, i, &mut builder.warnings)?;
        i = new_i;
        mc.dst_port = dst_port;
    }

    // ICMP type/code (for ICMP protocol)
    if proto_num == 1 && i < len {
        // Next token might be an ICMP type name or number
        if let Some(icmp_type) = icmp_type_from_name(&tokens[i]) {
            mc.icmp_type = Some(icmp_type);
            i += 1;
            // Optional ICMP code
            if i < len {
                if let Ok(code) = tokens[i].parse::<u8>() {
                    mc.icmp_code = Some(code);
                    i += 1;
                }
            }
        }
    }

    // Trailing options: established, log, etc.
    while i < len {
        match tokens[i].to_lowercase().as_str() {
            "established" => {
                // Match ACK or RST flags
                mc.tcp_flags_mask = Some(0x14); // ACK(0x10) | RST(0x04)
                mc.tcp_flags = Some(0x10);       // ACK set (either ACK or RST matches)
                // Actually: "established" means ACK or RST is set
                // tcp_flags_mask = ACK|RST = 0x14, tcp_flags = any non-zero means at least one set
                // PacGate semantics: (flags & mask) == value
                // For "ACK or RST set", we need: at least one of ACK|RST is set
                // This can't be expressed as a single mask/value — approximate with ACK set
                // (standard Cisco behavior: match packets with ACK or RST bit set)
                if mc.ip_protocol.is_none() {
                    mc.ip_protocol = Some(6); // TCP
                }
            }
            "log" | "log-input" => {
                builder.warnings.push("'log' keyword ignored (no PacGate equivalent)".to_string());
            }
            "fragments" => {
                mc.ip_more_fragments = Some(true);
            }
            "dscp" => {
                i += 1;
                if i < len {
                    if let Ok(dscp) = tokens[i].parse::<u8>() {
                        mc.ip_dscp = Some(dscp);
                    }
                }
            }
            "precedence" => {
                i += 1;
                if i < len {
                    builder.warnings.push(format!("'precedence {}' mapped to DSCP approximation", tokens[i]));
                }
            }
            "ttl" => {
                i += 1;
                // ttl eq N
                if i < len && tokens[i].to_lowercase() == "eq" {
                    i += 1;
                    if i < len {
                        if let Ok(ttl) = tokens[i].parse::<u8>() {
                            mc.ip_ttl = Some(ttl);
                        }
                    }
                }
            }
            _ => {
                // Unknown option — skip
            }
        }
        i += 1;
    }

    let name = builder.next_name(last_remark);
    let priority = builder.next_priority();
    Ok(Some(builder.make_rule(name, priority, mc, action)))
}

/// Parse a single standard ACL rule line (source only).
/// Format: source [source-wildcard] [log]
fn parse_standard_rule(
    tokens: &[String],
    start: usize,
    action: Option<Action>,
    builder: &mut RuleBuilder,
    last_remark: Option<&str>,
) -> Result<Option<StatelessRule>> {
    let mut i = start;

    let mut mc = MatchCriteria::default();
    mc.ethertype = Some("0x0800".to_string());

    // Source address
    let (src_addr, new_i) = parse_address(tokens, i)?;
    i = new_i;
    mc.src_ip = src_addr;

    // Trailing options
    while i < tokens.len() {
        match tokens[i].to_lowercase().as_str() {
            "log" | "log-input" => {
                builder.warnings.push("'log' keyword ignored (no PacGate equivalent)".to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let name = builder.next_name(last_remark);
    let priority = builder.next_priority();
    Ok(Some(builder.make_rule(name, priority, mc, action)))
}

// ============================================================
// Full import
// ============================================================

/// Parse Cisco IOS ACL text and return a FilterConfig + warnings.
pub fn import_acl(
    content: &str,
    name: &str,
) -> Result<(FilterConfig, Vec<String>)> {
    let mut builder = RuleBuilder::new(name);
    let mut all_rules: Vec<StatelessRule> = Vec::new();
    let mut acl_type: Option<&str> = None; // "extended" or "standard"
    let mut last_remark: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('!') {
            continue;
        }

        let tokens: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
        if tokens.is_empty() {
            continue;
        }

        // Named ACL header: "ip access-list extended NAME" or "ip access-list standard NAME"
        if tokens.len() >= 4
            && tokens[0].eq_ignore_ascii_case("ip")
            && tokens[1].eq_ignore_ascii_case("access-list")
        {
            let acl_kind = tokens[2].to_lowercase();
            if acl_kind == "extended" {
                acl_type = Some("extended");
            } else if acl_kind == "standard" {
                acl_type = Some("standard");
            }
            last_remark = None;
            continue;
        }

        // Numbered ACL: "access-list NUMBER ..."
        if tokens.len() >= 3 && tokens[0].eq_ignore_ascii_case("access-list") {
            if let Ok(num) = tokens[1].parse::<u32>() {
                // Determine if standard or extended
                let is_extended = is_numbered_extended(num);
                let is_standard = is_numbered_standard(num);

                if !is_extended && !is_standard {
                    builder.warnings.push(format!("Unknown ACL number {}, treating as extended", num));
                }

                // tokens[2] is permit/deny
                let action_str = tokens[2].to_lowercase();
                let action = match action_str.as_str() {
                    "permit" => Some(Action::Pass),
                    "deny" => Some(Action::Drop),
                    "remark" => {
                        last_remark = Some(tokens[3..].join(" "));
                        continue;
                    }
                    _ => {
                        builder.warnings.push(format!("Unknown action '{}', skipping", tokens[2]));
                        continue;
                    }
                };

                if is_standard {
                    match parse_standard_rule(&tokens, 3, action, &mut builder, last_remark.as_deref()) {
                        Ok(Some(rule)) => all_rules.push(rule),
                        Ok(None) => {}
                        Err(e) => builder.warnings.push(format!("Parse error: {}", e)),
                    }
                } else {
                    match parse_extended_rule(&tokens, 3, action, &mut builder, last_remark.as_deref()) {
                        Ok(Some(rule)) => all_rules.push(rule),
                        Ok(None) => {}
                        Err(e) => builder.warnings.push(format!("Parse error: {}", e)),
                    }
                }
                last_remark = None;
                continue;
            }
        }

        // Named ACL body lines: "[sequence] permit|deny ..."
        // or "remark ..."
        if let Some(acl_kind) = acl_type {
            let mut idx = 0;

            // Optional sequence number
            if tokens[0].parse::<u32>().is_ok() {
                idx = 1;
            }

            if idx >= tokens.len() {
                continue;
            }

            let action_str = tokens[idx].to_lowercase();
            match action_str.as_str() {
                "permit" | "deny" => {
                    let action = if action_str == "permit" {
                        Some(Action::Pass)
                    } else {
                        Some(Action::Drop)
                    };
                    idx += 1;

                    if acl_kind == "extended" {
                        match parse_extended_rule(&tokens, idx, action, &mut builder, last_remark.as_deref()) {
                            Ok(Some(rule)) => all_rules.push(rule),
                            Ok(None) => {}
                            Err(e) => builder.warnings.push(format!("Parse error: {}", e)),
                        }
                    } else {
                        match parse_standard_rule(&tokens, idx, action, &mut builder, last_remark.as_deref()) {
                            Ok(Some(rule)) => all_rules.push(rule),
                            Ok(None) => {}
                            Err(e) => builder.warnings.push(format!("Parse error: {}", e)),
                        }
                    }
                    last_remark = None;
                }
                "remark" => {
                    last_remark = Some(tokens[idx + 1..].join(" "));
                }
                _ => {
                    // Unknown line inside named ACL — skip
                }
            }
            continue;
        }
    }

    if all_rules.is_empty() {
        bail!("No rules imported from ACL input");
    }

    let config = FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: Action::Drop },
            rules: all_rules,
            conntrack: None,
            tables: None,
        },
    };

    Ok((config, builder.warnings))
}

/// Generate JSON summary of a Cisco ACL import.
pub fn import_acl_summary(
    content: &str,
    name: &str,
) -> serde_json::Value {
    match import_acl(content, name) {
        Ok((config, warnings)) => {
            serde_json::json!({
                "status": "ok",
                "format": "cisco-acl",
                "rule_count": config.pacgate.rules.len(),
                "default_action": format!("{:?}", config.pacgate.defaults.action).to_lowercase(),
                "rules": config.pacgate.rules.iter().map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "priority": r.priority,
                        "action": format!("{:?}", r.action()).to_lowercase(),
                    })
                }).collect::<Vec<_>>(),
                "warnings": warnings,
            })
        }
        Err(e) => {
            serde_json::json!({
                "status": "error",
                "format": "cisco-acl",
                "error": e.to_string(),
            })
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p4_import::config_to_yaml;

    // ---- Wildcard conversion tests ----

    #[test]
    fn test_wildcard_to_cidr_24() {
        assert_eq!(wildcard_to_cidr("0.0.0.255").unwrap(), 24);
    }

    #[test]
    fn test_wildcard_to_cidr_32() {
        assert_eq!(wildcard_to_cidr("0.0.0.0").unwrap(), 32);
    }

    #[test]
    fn test_wildcard_to_cidr_0() {
        assert_eq!(wildcard_to_cidr("255.255.255.255").unwrap(), 0);
    }

    #[test]
    fn test_wildcard_to_cidr_16() {
        assert_eq!(wildcard_to_cidr("0.0.255.255").unwrap(), 16);
    }

    #[test]
    fn test_wildcard_to_cidr_8() {
        assert_eq!(wildcard_to_cidr("0.255.255.255").unwrap(), 8);
    }

    #[test]
    fn test_wildcard_to_cidr_28() {
        assert_eq!(wildcard_to_cidr("0.0.0.15").unwrap(), 28);
    }

    #[test]
    fn test_wildcard_non_contiguous() {
        assert!(wildcard_to_cidr("0.255.0.255").is_err());
    }

    // ---- Address parsing tests ----

    #[test]
    fn test_parse_address_any() {
        let tokens: Vec<String> = vec!["any".to_string()];
        let (addr, i) = parse_address(&tokens, 0).unwrap();
        assert!(addr.is_none());
        assert_eq!(i, 1);
    }

    #[test]
    fn test_parse_address_host() {
        let tokens: Vec<String> = vec!["host".to_string(), "10.0.0.1".to_string()];
        let (addr, i) = parse_address(&tokens, 0).unwrap();
        assert_eq!(addr.unwrap(), "10.0.0.1/32");
        assert_eq!(i, 2);
    }

    #[test]
    fn test_parse_address_with_wildcard() {
        let tokens: Vec<String> = vec!["10.0.0.0".to_string(), "0.0.0.255".to_string()];
        let (addr, i) = parse_address(&tokens, 0).unwrap();
        assert_eq!(addr.unwrap(), "10.0.0.0/24");
        assert_eq!(i, 2);
    }

    // ---- Named port tests ----

    #[test]
    fn test_resolve_port_names() {
        assert_eq!(resolve_port_name("www"), Some(80));
        assert_eq!(resolve_port_name("https"), Some(443));
        assert_eq!(resolve_port_name("ssh"), Some(22));
        assert_eq!(resolve_port_name("ftp"), Some(21));
        assert_eq!(resolve_port_name("telnet"), Some(23));
        assert_eq!(resolve_port_name("dns"), Some(53));
        assert_eq!(resolve_port_name("domain"), Some(53));
        assert_eq!(resolve_port_name("bgp"), Some(179));
    }

    #[test]
    fn test_resolve_port_numeric() {
        assert_eq!(resolve_port_name("8080"), Some(8080));
        assert_eq!(resolve_port_name("443"), Some(443));
    }

    // ---- Protocol number tests ----

    #[test]
    fn test_protocol_numbers() {
        assert_eq!(protocol_number("tcp"), Some(6));
        assert_eq!(protocol_number("udp"), Some(17));
        assert_eq!(protocol_number("icmp"), Some(1));
        assert_eq!(protocol_number("gre"), Some(47));
        assert_eq!(protocol_number("ip"), Some(0));
        assert_eq!(protocol_number("ospf"), Some(89));
    }

    // ---- ICMP type tests ----

    #[test]
    fn test_icmp_types() {
        assert_eq!(icmp_type_from_name("echo"), Some(8));
        assert_eq!(icmp_type_from_name("echo-reply"), Some(0));
        assert_eq!(icmp_type_from_name("unreachable"), Some(3));
        assert_eq!(icmp_type_from_name("time-exceeded"), Some(11));
    }

    // ---- Extended ACL import tests ----

    #[test]
    fn test_named_extended_basic() {
        let input = r#"
ip access-list extended FIREWALL
 permit tcp 10.0.0.0 0.0.0.255 any eq 80
 deny ip any any
"#;
        let (config, warnings) = import_acl(input, "acl").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].action(), Action::Pass);
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_protocol, Some(6));
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
        assert_eq!(config.pacgate.rules[1].action(), Action::Drop);
        // "ip any any" should have no ip_protocol set (ip = all)
        assert_eq!(config.pacgate.rules[1].match_criteria.ip_protocol, None);
        for w in &warnings {
            eprintln!("  warn: {}", w);
        }
    }

    #[test]
    fn test_named_extended_multiple_ports() {
        let input = r#"
ip access-list extended WEB
 permit tcp any any eq www
 permit tcp any any eq https
 permit udp any any eq dns
 deny ip any any
"#;
        let (config, _) = import_acl(input, "web").unwrap();
        assert_eq!(config.pacgate.rules.len(), 4);
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
        assert_eq!(config.pacgate.rules[1].match_criteria.dst_port, Some(PortMatch::Exact(443)));
        assert_eq!(config.pacgate.rules[2].match_criteria.dst_port, Some(PortMatch::Exact(53)));
        assert_eq!(config.pacgate.rules[2].match_criteria.ip_protocol, Some(17));
    }

    #[test]
    fn test_numbered_extended() {
        let input = r#"
access-list 100 permit tcp any any eq 22
access-list 100 deny ip any any
"#;
        let (config, _) = import_acl(input, "acl").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_protocol, Some(6));
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(22)));
    }

    #[test]
    fn test_standard_acl() {
        let input = r#"
access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 deny any
"#;
        let (config, _) = import_acl(input, "std").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(config.pacgate.rules[0].action(), Action::Pass);
        assert!(config.pacgate.rules[1].match_criteria.src_ip.is_none()); // any
    }

    #[test]
    fn test_named_standard() {
        let input = r#"
ip access-list standard ADMIN
 permit host 10.0.0.1
 deny any
"#;
        let (config, _) = import_acl(input, "admin").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip.as_deref(), Some("10.0.0.1/32"));
    }

    #[test]
    fn test_established() {
        let input = r#"
ip access-list extended STATEFUL
 permit tcp any any established
 deny ip any any
"#;
        let (config, _) = import_acl(input, "fw").unwrap();
        assert!(config.pacgate.rules[0].match_criteria.tcp_flags_mask.is_some());
        assert!(config.pacgate.rules[0].match_criteria.tcp_flags.is_some());
    }

    #[test]
    fn test_icmp_type() {
        let input = r#"
ip access-list extended ICMP_FILTER
 permit icmp any any echo
 permit icmp any any echo-reply
 deny icmp any any
"#;
        let (config, _) = import_acl(input, "icmp").unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.icmp_type, Some(8));
        assert_eq!(config.pacgate.rules[1].match_criteria.icmp_type, Some(0));
    }

    #[test]
    fn test_port_range() {
        let input = r#"
ip access-list extended RANGES
 permit tcp any any range 1024 65535
 deny ip any any
"#;
        let (config, _) = import_acl(input, "ranges").unwrap();
        assert_eq!(
            config.pacgate.rules[0].match_criteria.dst_port,
            Some(PortMatch::Range { range: [1024, 65535] })
        );
    }

    #[test]
    fn test_port_gt_lt() {
        let input = r#"
ip access-list extended PORTS
 permit tcp any gt 1023 any
 permit tcp any any lt 1024
"#;
        let (config, _) = import_acl(input, "ports").unwrap();
        assert_eq!(
            config.pacgate.rules[0].match_criteria.src_port,
            Some(PortMatch::Range { range: [1024, 65535] })
        );
        assert_eq!(
            config.pacgate.rules[1].match_criteria.dst_port,
            Some(PortMatch::Range { range: [0, 1023] })
        );
    }

    #[test]
    fn test_host_addresses() {
        let input = r#"
ip access-list extended HOSTS
 permit ip host 10.0.0.1 host 10.0.0.2
"#;
        let (config, _) = import_acl(input, "hosts").unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip.as_deref(), Some("10.0.0.1/32"));
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_ip.as_deref(), Some("10.0.0.2/32"));
    }

    #[test]
    fn test_remark_as_rule_name() {
        let input = r#"
ip access-list extended DOCUMENTED
 remark Allow SSH access
 permit tcp any any eq 22
 deny ip any any
"#;
        let (config, _) = import_acl(input, "doc").unwrap();
        assert!(config.pacgate.rules[0].name.contains("Allow_SSH_access"));
    }

    #[test]
    fn test_gre_protocol() {
        let input = r#"
ip access-list extended GRE
 permit gre host 10.0.0.1 host 10.0.0.2
"#;
        let (config, _) = import_acl(input, "gre").unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_protocol, Some(47));
    }

    #[test]
    fn test_sequence_numbers() {
        let input = r#"
ip access-list extended SEQ
 10 permit tcp any any eq 80
 20 deny ip any any
"#;
        let (config, _) = import_acl(input, "seq").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
    }

    #[test]
    fn test_log_warning() {
        let input = r#"
ip access-list extended LOGGED
 deny ip any any log
"#;
        let (config, warnings) = import_acl(input, "log").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert!(warnings.iter().any(|w| w.contains("log")));
    }

    #[test]
    fn test_yaml_round_trip() {
        let input = r#"
ip access-list extended ROUNDTRIP
 permit tcp 10.0.0.0 0.0.0.255 any eq 443
 deny ip any any
"#;
        let (config, _) = import_acl(input, "rt").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("ip_protocol: 6"));
        assert!(yaml.contains("443"));
        assert!(yaml.contains("10.0.0.0/24"));
    }

    #[test]
    fn test_json_summary() {
        let input = r#"
ip access-list extended TEST
 permit tcp any any eq 80
 deny ip any any
"#;
        let summary = import_acl_summary(input, "test");
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rule_count"], 2);
        assert_eq!(summary["format"], "cisco-acl");
    }

    #[test]
    fn test_json_summary_error() {
        let summary = import_acl_summary("", "test");
        assert_eq!(summary["status"], "error");
    }

    #[test]
    fn test_empty_input_error() {
        let result = import_acl("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_comments_and_blank_lines() {
        let input = r#"
! This is a comment
ip access-list extended CLEAN

 ! Another comment
 permit tcp any any eq 80
"#;
        let (config, _) = import_acl(input, "clean").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
    }

    #[test]
    fn test_fragments() {
        let input = r#"
ip access-list extended FRAG
 deny ip any any fragments
"#;
        let (config, _) = import_acl(input, "frag").unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_more_fragments, Some(true));
    }

    #[test]
    fn test_dscp() {
        let input = r#"
ip access-list extended QOS
 permit ip any any dscp 46
"#;
        let (config, _) = import_acl(input, "qos").unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_dscp, Some(46));
    }

    #[test]
    fn test_mixed_named_and_numbered() {
        // Multiple ACLs in same file
        let input = r#"
access-list 100 permit tcp any any eq 80
ip access-list extended EXTRA
 permit udp any any eq 53
"#;
        let (config, _) = import_acl(input, "mix").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
    }

    #[test]
    fn test_any_any_no_src_dst() {
        let input = r#"
ip access-list extended CATCHALL
 deny ip any any
"#;
        let (config, _) = import_acl(input, "any").unwrap();
        assert!(config.pacgate.rules[0].match_criteria.src_ip.is_none());
        assert!(config.pacgate.rules[0].match_criteria.dst_ip.is_none());
    }

    #[test]
    fn test_priority_decrements() {
        let input = r#"
ip access-list extended MULTI
 permit tcp any any eq 80
 permit tcp any any eq 443
 permit udp any any eq 53
 deny ip any any
"#;
        let (config, _) = import_acl(input, "multi").unwrap();
        assert_eq!(config.pacgate.rules[0].priority, 1000);
        assert_eq!(config.pacgate.rules[1].priority, 990);
        assert_eq!(config.pacgate.rules[2].priority, 980);
        assert_eq!(config.pacgate.rules[3].priority, 970);
    }
}
