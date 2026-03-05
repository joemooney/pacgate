// iptables-save Import: Parse Linux iptables-save output into PacGate FilterConfig
//
// Converts iptables-save dump lines into YAML rules.
// Line-based parser → IptablesRule → StatelessRule(s) converter.

use anyhow::{bail, Result};

use crate::model::*;

// ============================================================
// Parsed intermediate representation
// ============================================================

#[derive(Debug, Default)]
struct IptablesRule {
    chain: String,
    protocol: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<String>,
    dst_port: Option<String>,
    src_ports_multi: Vec<String>,
    dst_ports_multi: Vec<String>,
    tcp_flags_mask: Option<String>,
    tcp_flags_set: Option<String>,
    icmp_type: Option<String>,
    mac_source: Option<String>,
    state: Vec<String>,
    in_interface: Option<String>,
    out_interface: Option<String>,
    target: String,
    target_opts: Vec<String>,
    comment: Option<String>,
    negations: Vec<String>,
}

// ============================================================
// Tokenizer
// ============================================================

/// Split an iptables rule line into tokens, respecting quoted strings.
fn tokenize_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if in_quote {
            if ch == quote_char {
                in_quote = false;
                // Push current token (without quotes)
                tokens.push(current.clone());
                current.clear();
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            // Start quote — if we have accumulated non-quoted text, push it first
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
            in_quote = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
        i += 1;
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

// ============================================================
// Rule parser
// ============================================================

/// Parse a tokenized `-A CHAIN ...` line into an IptablesRule.
fn parse_rule(tokens: &[String]) -> Result<IptablesRule> {
    let mut rule = IptablesRule::default();
    let len = tokens.len();
    let mut i = 0;

    // Must start with -A CHAIN
    if len < 2 || tokens[0] != "-A" {
        bail!("Expected rule starting with -A CHAIN");
    }
    rule.chain = tokens[1].clone();
    i = 2;

    // Track which flags are negated (preceded by !)
    let mut next_negated = false;

    while i < len {
        let tok = &tokens[i];

        if tok == "!" {
            next_negated = true;
            i += 1;
            continue;
        }

        match tok.as_str() {
            "-p" | "--protocol" => {
                i += 1;
                if i < len {
                    if next_negated {
                        rule.negations.push("protocol".to_string());
                        next_negated = false;
                    }
                    rule.protocol = Some(tokens[i].clone());
                }
            }
            "-s" | "--source" => {
                i += 1;
                if i < len {
                    if next_negated {
                        rule.negations.push("src_ip".to_string());
                        next_negated = false;
                    }
                    rule.src_ip = Some(tokens[i].clone());
                }
            }
            "-d" | "--destination" => {
                i += 1;
                if i < len {
                    if next_negated {
                        rule.negations.push("dst_ip".to_string());
                        next_negated = false;
                    }
                    rule.dst_ip = Some(tokens[i].clone());
                }
            }
            "--sport" | "--source-port" => {
                i += 1;
                if i < len {
                    rule.src_port = Some(tokens[i].clone());
                }
            }
            "--dport" | "--destination-port" => {
                i += 1;
                if i < len {
                    rule.dst_port = Some(tokens[i].clone());
                }
            }
            "-i" | "--in-interface" => {
                i += 1;
                if i < len {
                    rule.in_interface = Some(tokens[i].clone());
                }
            }
            "-o" | "--out-interface" => {
                i += 1;
                if i < len {
                    rule.out_interface = Some(tokens[i].clone());
                }
            }
            "--syn" => {
                // Shorthand for --tcp-flags SYN,RST,ACK,FIN SYN
                rule.tcp_flags_mask = Some("SYN,RST,ACK,FIN".to_string());
                rule.tcp_flags_set = Some("SYN".to_string());
            }
            "--tcp-flags" => {
                // --tcp-flags MASK SET
                if i + 2 < len {
                    i += 1;
                    rule.tcp_flags_mask = Some(tokens[i].clone());
                    i += 1;
                    rule.tcp_flags_set = Some(tokens[i].clone());
                }
            }
            "--icmp-type" => {
                i += 1;
                if i < len {
                    rule.icmp_type = Some(tokens[i].clone());
                }
            }
            "--mac-source" => {
                i += 1;
                if i < len {
                    rule.mac_source = Some(tokens[i].clone());
                }
            }
            "--dports" | "--destination-ports" => {
                i += 1;
                if i < len {
                    rule.dst_ports_multi = tokens[i].split(',').map(|s| s.to_string()).collect();
                }
            }
            "--sports" | "--source-ports" => {
                i += 1;
                if i < len {
                    rule.src_ports_multi = tokens[i].split(',').map(|s| s.to_string()).collect();
                }
            }
            "--state" | "--ctstate" => {
                i += 1;
                if i < len {
                    rule.state = tokens[i].split(',').map(|s| s.to_string()).collect();
                }
            }
            "--comment" => {
                i += 1;
                if i < len {
                    rule.comment = Some(tokens[i].clone());
                }
            }
            "--to-destination" | "--to-source" => {
                i += 1;
                if i < len {
                    // Track which option this is
                    rule.target_opts.push(tok.clone());
                    rule.target_opts.push(tokens[i].clone());
                }
            }
            "-m" => {
                // Match module — skip the module name itself, its options follow
                i += 1;
                // module name: tcp, udp, state, conntrack, multiport, mac, comment, etc.
            }
            "-j" | "--jump" => {
                i += 1;
                if i < len {
                    rule.target = tokens[i].clone();
                    // Remaining tokens are target options
                    i += 1;
                    while i < len {
                        // Catch --to-destination/--to-source inside -j processing
                        if tokens[i] == "--to-destination" || tokens[i] == "--to-source" {
                            rule.target_opts.push(tokens[i].clone());
                            i += 1;
                            if i < len {
                                rule.target_opts.push(tokens[i].clone());
                            }
                        } else {
                            rule.target_opts.push(tokens[i].clone());
                        }
                        i += 1;
                    }
                    // Early return — -j is always last
                    return Ok(rule);
                }
            }
            _ => {
                // Unknown flag — skip
            }
        }

        next_negated = false;
        i += 1;
    }

    Ok(rule)
}

// ============================================================
// ICMP type name lookup
// ============================================================

fn icmp_type_from_name(name: &str) -> Option<u8> {
    match name {
        "echo-reply" | "pong" => Some(0),
        "destination-unreachable" => Some(3),
        "redirect" => Some(5),
        "echo-request" | "ping" => Some(8),
        "time-exceeded" | "ttl-exceeded" => Some(11),
        "timestamp-request" => Some(13),
        "timestamp-reply" => Some(14),
        _ => name.parse::<u8>().ok(),
    }
}

// ============================================================
// TCP flag name → bit value
// ============================================================

fn tcp_flag_bit(name: &str) -> Option<u8> {
    match name.to_uppercase().as_str() {
        "FIN" => Some(0),
        "SYN" => Some(1),
        "RST" => Some(2),
        "PSH" => Some(3),
        "ACK" => Some(4),
        "URG" => Some(5),
        "ECE" => Some(6),
        "CWR" => Some(7),
        _ => None,
    }
}

/// Convert comma-separated flag names to a bitmask.
fn flags_to_mask(flags_str: &str) -> u8 {
    let mut mask = 0u8;
    for name in flags_str.split(',') {
        if let Some(bit) = tcp_flag_bit(name.trim()) {
            mask |= 1 << bit;
        }
    }
    mask
}

// ============================================================
// Protocol name → ip_protocol
// ============================================================

fn protocol_number(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "gre" => Some(47),
        "icmpv6" | "ipv6-icmp" => Some(58),
        "sctp" => Some(132),
        "esp" => Some(50),
        "ah" => Some(51),
        _ => name.parse::<u8>().ok(),
    }
}

// ============================================================
// Port string → PortMatch
// ============================================================

fn parse_port(s: &str) -> Result<PortMatch> {
    if let Some(colon_pos) = s.find(':') {
        let low: u16 = s[..colon_pos].parse()
            .map_err(|_| anyhow::anyhow!("Invalid port range low: {}", s))?;
        let high: u16 = s[colon_pos + 1..].parse()
            .map_err(|_| anyhow::anyhow!("Invalid port range high: {}", s))?;
        Ok(PortMatch::Range { range: [low, high] })
    } else {
        let port: u16 = s.parse()
            .map_err(|_| anyhow::anyhow!("Invalid port: {}", s))?;
        Ok(PortMatch::Exact(port))
    }
}

// ============================================================
// Parse DNAT/SNAT --to-destination/--to-source value
// ============================================================

/// Parse "IP:PORT" or "IP" from --to-destination / --to-source
fn parse_nat_target(s: &str) -> (Option<String>, Option<u16>) {
    if let Some(colon_pos) = s.rfind(':') {
        let ip = &s[..colon_pos];
        let port_str = &s[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (Some(ip.to_string()), Some(port))
        } else {
            (Some(s.to_string()), None)
        }
    } else {
        (Some(s.to_string()), None)
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

    fn next_name(&mut self, comment: Option<&str>) -> String {
        self.counter += 1;
        if let Some(c) = comment {
            // Sanitize comment for use as rule name
            let sanitized: String = c.chars()
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

    fn make_rule(&self, name: String, priority: u32, mc: MatchCriteria, action: Option<Action>, rewrite: Option<RewriteAction>) -> StatelessRule {
        StatelessRule {
            name,
            priority,
            match_criteria: mc,
            action,
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite,
            mirror_port: None,
            redirect_port: None,
            rss_queue: None,
            int_insert: None,
        }
    }
}

// ============================================================
// IptablesRule → StatelessRule(s) converter
// ============================================================

fn rule_to_stateless(
    rule: &IptablesRule,
    builder: &mut RuleBuilder,
) -> Result<Vec<StatelessRule>> {
    // Determine action
    let (action, rewrite) = match rule.target.to_uppercase().as_str() {
        "ACCEPT" => (Some(Action::Pass), None),
        "DROP" | "REJECT" => (Some(Action::Drop), None),
        "DNAT" => {
            // Parse --to-destination IP:PORT
            let mut rw = RewriteAction::default();
            for pair in rule.target_opts.chunks(2) {
                if pair.len() == 2 && pair[0] == "--to-destination" {
                    let (ip, port) = parse_nat_target(&pair[1]);
                    rw.set_dst_ip = ip;
                    rw.set_dst_port = port;
                }
            }
            (Some(Action::Pass), Some(rw))
        }
        "SNAT" => {
            let mut rw = RewriteAction::default();
            for pair in rule.target_opts.chunks(2) {
                if pair.len() == 2 && pair[0] == "--to-source" {
                    let (ip, port) = parse_nat_target(&pair[1]);
                    rw.set_src_ip = ip;
                    rw.set_src_port = port;
                }
            }
            (Some(Action::Pass), Some(rw))
        }
        "LOG" | "MARK" | "TCPMSS" | "MASQUERADE" | "RETURN" => {
            builder.warnings.push(format!(
                "Unsupported target '{}' in chain {}, skipping rule",
                rule.target, rule.chain
            ));
            return Ok(vec![]);
        }
        "" => {
            // No target — skip
            return Ok(vec![]);
        }
        other => {
            builder.warnings.push(format!(
                "Unknown target '{}' in chain {}, treating as ACCEPT",
                other, rule.chain
            ));
            (Some(Action::Pass), None)
        }
    };

    // Build base MatchCriteria
    let mut mc = MatchCriteria::default();

    // Protocol
    if let Some(ref proto) = rule.protocol {
        if let Some(num) = protocol_number(proto) {
            mc.ethertype = Some("0x0800".to_string());
            mc.ip_protocol = Some(num);
        }
    }

    // Source/destination IP
    if let Some(ref ip) = rule.src_ip {
        if !rule.negations.contains(&"src_ip".to_string()) {
            mc.ethertype = Some("0x0800".to_string());
            // Normalize: no /32 or /0 cleanup needed, CIDR is valid as-is
            mc.src_ip = Some(ip.clone());
        } else {
            builder.warnings.push(format!("Negated source IP '! {}' not directly supported", ip));
        }
    }
    if let Some(ref ip) = rule.dst_ip {
        if !rule.negations.contains(&"dst_ip".to_string()) {
            mc.ethertype = Some("0x0800".to_string());
            mc.dst_ip = Some(ip.clone());
        } else {
            builder.warnings.push(format!("Negated destination IP '! {}' not directly supported", ip));
        }
    }

    // Source MAC
    if let Some(ref mac) = rule.mac_source {
        mc.src_mac = Some(mac.clone());
    }

    // TCP flags
    if let (Some(ref mask_str), Some(ref set_str)) = (&rule.tcp_flags_mask, &rule.tcp_flags_set) {
        mc.tcp_flags_mask = Some(flags_to_mask(mask_str));
        mc.tcp_flags = Some(flags_to_mask(set_str));
        // Ensure protocol is TCP
        if mc.ip_protocol.is_none() {
            mc.ethertype = Some("0x0800".to_string());
            mc.ip_protocol = Some(6);
        }
    }

    // ICMP type
    if let Some(ref icmp) = rule.icmp_type {
        if let Some(type_num) = icmp_type_from_name(icmp) {
            mc.icmp_type = Some(type_num);
        } else {
            builder.warnings.push(format!("Unknown ICMP type '{}', skipping", icmp));
        }
    }

    // Conntrack state
    if !rule.state.is_empty() {
        // Map conntrack states: NEW→"new", ESTABLISHED/RELATED→"established"
        for st in &rule.state {
            match st.to_uppercase().as_str() {
                "NEW" => {
                    mc.conntrack_state = Some("new".to_string());
                }
                "ESTABLISHED" | "RELATED" => {
                    mc.conntrack_state = Some("established".to_string());
                }
                _ => {
                    builder.warnings.push(format!("Unsupported conntrack state '{}', skipping", st));
                }
            }
        }
    }

    // Interface warnings
    if let Some(ref iface) = rule.in_interface {
        builder.warnings.push(format!("Interface match '-i {}' not supported in FPGA, skipping", iface));
    }
    if let Some(ref iface) = rule.out_interface {
        builder.warnings.push(format!("Interface match '-o {}' not supported in FPGA, skipping", iface));
    }

    // Negated protocol
    if rule.negations.contains(&"protocol".to_string()) {
        builder.warnings.push("Negated protocol match not directly supported".to_string());
    }

    // Single port (--dport, --sport)
    if let Some(ref port_str) = rule.dst_port {
        mc.dst_port = Some(parse_port(port_str)?);
    }
    if let Some(ref port_str) = rule.src_port {
        mc.src_port = Some(parse_port(port_str)?);
    }

    // Multiport expansion: create one rule per port/range
    if !rule.dst_ports_multi.is_empty() || !rule.src_ports_multi.is_empty() {
        let mut rules = Vec::new();

        if !rule.dst_ports_multi.is_empty() {
            for port_str in &rule.dst_ports_multi {
                let mut mc_clone = mc.clone();
                mc_clone.dst_port = Some(parse_port(port_str)?);
                let name = builder.next_name(rule.comment.as_deref());
                let priority = builder.next_priority();
                rules.push(builder.make_rule(name, priority, mc_clone, action.clone(), rewrite.clone()));
            }
        }

        if !rule.src_ports_multi.is_empty() {
            for port_str in &rule.src_ports_multi {
                let mut mc_clone = mc.clone();
                mc_clone.src_port = Some(parse_port(port_str)?);
                let name = builder.next_name(rule.comment.as_deref());
                let priority = builder.next_priority();
                rules.push(builder.make_rule(name, priority, mc_clone, action.clone(), rewrite.clone()));
            }
        }

        return Ok(rules);
    }

    // Single rule
    let name = builder.next_name(rule.comment.as_deref());
    let priority = builder.next_priority();
    Ok(vec![builder.make_rule(name, priority, mc, action, rewrite)])
}

// ============================================================
// Full import
// ============================================================

/// Parse an iptables-save dump and return a FilterConfig + warnings.
/// `chain` selects which chain to import ("INPUT", "FORWARD", "OUTPUT", or "all").
pub fn import_iptables(
    content: &str,
    chain: &str,
    name: &str,
) -> Result<(FilterConfig, Vec<String>)> {
    let chain_upper = chain.to_uppercase();
    let import_all = chain_upper == "ALL";

    let mut default_action = Action::Drop; // fallback
    let mut builder = RuleBuilder::new(name);
    let mut all_rules: Vec<StatelessRule> = Vec::new();
    let mut current_table = String::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Table header: *filter, *nat, *mangle, etc.
        if let Some(table) = line.strip_prefix('*') {
            current_table = table.to_string();
            continue;
        }

        // COMMIT
        if line == "COMMIT" {
            continue;
        }

        // Chain default policy: :CHAIN POLICY [pkts:bytes]
        if line.starts_with(':') {
            let parts: Vec<&str> = line[1..].split_whitespace().collect();
            if parts.len() >= 2 {
                let chain_name = parts[0];
                let policy = parts[1];
                if import_all || chain_name.eq_ignore_ascii_case(&chain_upper) {
                    match policy {
                        "ACCEPT" => default_action = Action::Pass,
                        "DROP" => default_action = Action::Drop,
                        _ => {} // RETURN, etc.
                    }
                }
            }
            continue;
        }

        // Rule line: -A CHAIN ...
        if line.starts_with("-A ") {
            // Only import from *filter table (and *nat for DNAT/SNAT)
            if current_table != "filter" && current_table != "nat" {
                continue;
            }

            let tokens = tokenize_line(line);
            if tokens.len() < 2 {
                continue;
            }

            let rule_chain = &tokens[1];
            if !import_all && !rule_chain.eq_ignore_ascii_case(&chain_upper) {
                continue;
            }

            match parse_rule(&tokens) {
                Ok(ipt_rule) => {
                    match rule_to_stateless(&ipt_rule, &mut builder) {
                        Ok(rules) => all_rules.extend(rules),
                        Err(e) => builder.warnings.push(format!("Failed to convert rule: {}", e)),
                    }
                }
                Err(e) => {
                    builder.warnings.push(format!("Failed to parse rule: {}", e));
                }
            }
        }
    }

    if all_rules.is_empty() {
        bail!("No rules imported from chain '{}' (table: {})", chain, if current_table.is_empty() { "none" } else { &current_table });
    }

    let config = FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: default_action },
            rules: all_rules,
            conntrack: None,
            tables: None,
        },
    };

    Ok((config, builder.warnings))
}

/// Generate JSON summary of an iptables import.
pub fn import_iptables_summary(
    content: &str,
    chain: &str,
    name: &str,
) -> serde_json::Value {
    match import_iptables(content, chain, name) {
        Ok((config, warnings)) => {
            serde_json::json!({
                "status": "ok",
                "chain": chain,
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
                "chain": chain,
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

    // ---- Tokenizer tests ----

    #[test]
    fn test_tokenize_simple() {
        let tokens = tokenize_line("-A INPUT -p tcp --dport 22 -j ACCEPT");
        assert_eq!(tokens, vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]);
    }

    #[test]
    fn test_tokenize_quoted_comment() {
        let tokens = tokenize_line(r#"-A INPUT -m comment --comment "Allow SSH" -j ACCEPT"#);
        assert!(tokens.contains(&"Allow SSH".to_string()));
    }

    #[test]
    fn test_tokenize_negation() {
        let tokens = tokenize_line("-A INPUT ! -s 10.0.0.0/8 -j DROP");
        assert!(tokens.contains(&"!".to_string()));
        assert!(tokens.contains(&"-s".to_string()));
        assert!(tokens.contains(&"10.0.0.0/8".to_string()));
    }

    // ---- Parser tests ----

    #[test]
    fn test_parse_tcp_port() {
        let tokens = tokenize_line("-A INPUT -p tcp --dport 22 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.chain, "INPUT");
        assert_eq!(rule.protocol, Some("tcp".to_string()));
        assert_eq!(rule.dst_port, Some("22".to_string()));
        assert_eq!(rule.target, "ACCEPT");
    }

    #[test]
    fn test_parse_udp_port() {
        let tokens = tokenize_line("-A INPUT -p udp --dport 53 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.protocol, Some("udp".to_string()));
        assert_eq!(rule.dst_port, Some("53".to_string()));
    }

    #[test]
    fn test_parse_icmp_type() {
        let tokens = tokenize_line("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.protocol, Some("icmp".to_string()));
        assert_eq!(rule.icmp_type, Some("echo-request".to_string()));
    }

    #[test]
    fn test_parse_tcp_flags() {
        let tokens = tokenize_line("-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.tcp_flags_mask, Some("SYN,ACK".to_string()));
        assert_eq!(rule.tcp_flags_set, Some("SYN".to_string()));
    }

    #[test]
    fn test_parse_syn_shorthand() {
        let tokens = tokenize_line("-A INPUT -p tcp --syn -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.tcp_flags_mask, Some("SYN,RST,ACK,FIN".to_string()));
        assert_eq!(rule.tcp_flags_set, Some("SYN".to_string()));
    }

    #[test]
    fn test_parse_multiport() {
        let tokens = tokenize_line("-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.dst_ports_multi, vec!["80", "443", "8080"]);
    }

    #[test]
    fn test_parse_state() {
        let tokens = tokenize_line("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.state, vec!["ESTABLISHED", "RELATED"]);
    }

    #[test]
    fn test_parse_conntrack() {
        let tokens = tokenize_line("-A INPUT -m conntrack --ctstate NEW -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.state, vec!["NEW"]);
    }

    #[test]
    fn test_parse_mac_source() {
        let tokens = tokenize_line("-A INPUT -m mac --mac-source aa:bb:cc:dd:ee:ff -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.mac_source, Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn test_parse_comment() {
        let tokens = tokenize_line(r#"-A INPUT -m comment --comment "Allow DNS" -p udp --dport 53 -j ACCEPT"#);
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.comment, Some("Allow DNS".to_string()));
    }

    #[test]
    fn test_parse_port_range() {
        let tokens = tokenize_line("-A INPUT -p tcp --dport 1024:65535 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.dst_port, Some("1024:65535".to_string()));
    }

    #[test]
    fn test_parse_dnat() {
        let tokens = tokenize_line("-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080");
        let rule = parse_rule(&tokens).unwrap();
        assert_eq!(rule.target, "DNAT");
        assert!(rule.target_opts.contains(&"--to-destination".to_string()));
        assert!(rule.target_opts.contains(&"192.168.1.10:8080".to_string()));
    }

    // ---- Converter tests ----

    #[test]
    fn test_convert_accept_drop() {
        let tokens = tokenize_line("-A INPUT -p tcp --dport 22 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action(), Action::Pass);

        let tokens = tokenize_line("-A INPUT -p tcp --dport 23 -j DROP");
        let rule = parse_rule(&tokens).unwrap();
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results[0].action(), Action::Drop);
    }

    #[test]
    fn test_convert_cidr() {
        let tokens = tokenize_line("-A INPUT -s 10.0.0.0/8 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results[0].match_criteria.src_ip, Some("10.0.0.0/8".to_string()));
        assert_eq!(results[0].match_criteria.ethertype, Some("0x0800".to_string()));
    }

    #[test]
    fn test_convert_port_range() {
        let tokens = tokenize_line("-A INPUT -p tcp --dport 1024:65535 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results[0].match_criteria.dst_port, Some(PortMatch::Range { range: [1024, 65535] }));
    }

    #[test]
    fn test_convert_dnat_rewrite() {
        let tokens = tokenize_line("-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results.len(), 1);
        let rw = results[0].rewrite.as_ref().unwrap();
        assert_eq!(rw.set_dst_ip, Some("192.168.1.10".to_string()));
        assert_eq!(rw.set_dst_port, Some(8080));
    }

    #[test]
    fn test_convert_tcp_flags_syn() {
        let tokens = tokenize_line("-A INPUT -p tcp --syn -j DROP");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        // --syn = SYN,RST,ACK,FIN mask with SYN set
        // mask: SYN(0x02)|RST(0x04)|ACK(0x10)|FIN(0x01) = 0x17
        // set: SYN(0x02)
        assert_eq!(results[0].match_criteria.tcp_flags_mask, Some(0x17));
        assert_eq!(results[0].match_criteria.tcp_flags, Some(0x02));
    }

    #[test]
    fn test_convert_icmp_name() {
        let tokens = tokenize_line("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results[0].match_criteria.icmp_type, Some(8));
    }

    #[test]
    fn test_convert_multiport_expand() {
        let tokens = tokenize_line("-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
        assert_eq!(results[1].match_criteria.dst_port, Some(PortMatch::Exact(443)));
        assert_eq!(results[2].match_criteria.dst_port, Some(PortMatch::Exact(8080)));
    }

    #[test]
    fn test_convert_state_new() {
        let tokens = tokenize_line("-A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert_eq!(results[0].match_criteria.conntrack_state, Some("new".to_string()));
    }

    #[test]
    fn test_convert_state_established() {
        let tokens = tokenize_line("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        // RELATED maps to "established" since PacGate doesn't have a separate RELATED state
        assert_eq!(results[0].match_criteria.conntrack_state, Some("established".to_string()));
    }

    #[test]
    fn test_convert_snat_rewrite() {
        let tokens = tokenize_line("-A POSTROUTING -s 192.168.0.0/24 -j SNAT --to-source 203.0.113.1");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        let rw = results[0].rewrite.as_ref().unwrap();
        assert_eq!(rw.set_src_ip, Some("203.0.113.1".to_string()));
    }

    #[test]
    fn test_convert_log_skip() {
        let tokens = tokenize_line("-A INPUT -j LOG --log-prefix dropped:");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert!(results.is_empty());
        assert!(!builder.warnings.is_empty());
    }

    #[test]
    fn test_convert_interface_warning() {
        let tokens = tokenize_line("-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT");
        let rule = parse_rule(&tokens).unwrap();
        let mut builder = RuleBuilder::new("test");
        let _results = rule_to_stateless(&rule, &mut builder).unwrap();
        assert!(builder.warnings.iter().any(|w| w.contains("-i eth0")));
    }

    // ---- Full import tests ----

    #[test]
    fn test_import_simple_filter() {
        let input = r#"# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
"#;
        let (config, warnings) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.defaults.action, Action::Drop);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_import_multi_rule() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT
COMMIT
"#;
        let (config, _) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 4);
    }

    #[test]
    fn test_import_chain_policy_accept() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j DROP
COMMIT
"#;
        let (config, _) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.defaults.action, Action::Pass);
        assert_eq!(config.pacgate.rules[0].action(), Action::Drop);
    }

    #[test]
    fn test_import_multiport_expand() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
COMMIT
"#;
        let (config, _) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 3);
    }

    #[test]
    fn test_import_json_summary() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
"#;
        let summary = import_iptables_summary(input, "INPUT", "fw");
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rule_count"], 2);
        assert_eq!(summary["default_action"], "drop");
    }

    #[test]
    fn test_import_with_warnings() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let (config, warnings) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert!(warnings.iter().any(|w| w.contains("-i lo")));
    }

    #[test]
    fn test_import_forward_chain() {
        let input = r#"*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A FORWARD -p tcp --dport 80 -j ACCEPT
COMMIT
"#;
        let (config, _) = import_iptables(input, "FORWARD", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
    }

    #[test]
    fn test_import_all_chains() {
        let input = r#"*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A FORWARD -p tcp --dport 80 -j ACCEPT
-A OUTPUT -p tcp --dport 443 -j ACCEPT
COMMIT
"#;
        let (config, _) = import_iptables(input, "all", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 3);
    }

    #[test]
    fn test_import_skips_nat_log() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j LOG --log-prefix "dropped: "
COMMIT
"#;
        let (config, warnings) = import_iptables(input, "INPUT", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert!(warnings.iter().any(|w| w.contains("LOG")));
    }

    #[test]
    fn test_import_nat_dnat() {
        let input = r#"*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080
COMMIT
"#;
        let (config, _) = import_iptables(input, "PREROUTING", "fw").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let rw = config.pacgate.rules[0].rewrite.as_ref().unwrap();
        assert_eq!(rw.set_dst_ip, Some("192.168.1.10".to_string()));
        assert_eq!(rw.set_dst_port, Some(8080));
    }

    #[test]
    fn test_import_yaml_output() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let (config, _) = import_iptables(input, "INPUT", "fw").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("dst_port: 22"));
        assert!(yaml.contains("pass"));
        assert!(yaml.contains("drop"));
    }

    #[test]
    fn test_import_empty_error() {
        let result = import_iptables("", "INPUT", "fw");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_no_matching_chain_error() {
        let input = r#"*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let result = import_iptables(input, "FORWARD", "fw");
        assert!(result.is_err());
    }

    // ---- Helper tests ----

    #[test]
    fn test_icmp_type_lookup() {
        assert_eq!(icmp_type_from_name("echo-request"), Some(8));
        assert_eq!(icmp_type_from_name("echo-reply"), Some(0));
        assert_eq!(icmp_type_from_name("destination-unreachable"), Some(3));
        assert_eq!(icmp_type_from_name("11"), Some(11));
        assert_eq!(icmp_type_from_name("unknown-type"), None);
    }

    #[test]
    fn test_tcp_flags_to_mask() {
        assert_eq!(flags_to_mask("SYN"), 0x02);
        assert_eq!(flags_to_mask("SYN,ACK"), 0x12);
        assert_eq!(flags_to_mask("SYN,RST,ACK,FIN"), 0x17);
        assert_eq!(flags_to_mask("FIN,SYN,RST,PSH,ACK,URG"), 0x3F);
    }

    #[test]
    fn test_parse_port_exact() {
        assert_eq!(parse_port("80").unwrap(), PortMatch::Exact(80));
    }

    #[test]
    fn test_parse_port_range_helper() {
        assert_eq!(parse_port("1024:65535").unwrap(), PortMatch::Range { range: [1024, 65535] });
    }

    #[test]
    fn test_parse_nat_target_ip_port() {
        let (ip, port) = parse_nat_target("192.168.1.10:8080");
        assert_eq!(ip, Some("192.168.1.10".to_string()));
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_nat_target_ip_only() {
        let (ip, port) = parse_nat_target("203.0.113.1");
        assert_eq!(ip, Some("203.0.113.1".to_string()));
        assert_eq!(port, None);
    }

    #[test]
    fn test_protocol_number_lookup() {
        assert_eq!(protocol_number("tcp"), Some(6));
        assert_eq!(protocol_number("udp"), Some(17));
        assert_eq!(protocol_number("icmp"), Some(1));
        assert_eq!(protocol_number("gre"), Some(47));
        assert_eq!(protocol_number("47"), Some(47));
    }
}
