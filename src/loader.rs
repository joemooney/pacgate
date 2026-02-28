use std::path::Path;
use anyhow::{Context, Result};
use crate::model::FilterConfig;

pub fn load_rules(path: &Path) -> Result<FilterConfig> {
    let (config, warnings) = load_rules_with_warnings(path)?;
    for w in &warnings {
        eprintln!("Warning: {}", w);
    }
    Ok(config)
}

pub fn load_rules_with_warnings(path: &Path) -> Result<(FilterConfig, Vec<String>)> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rules file: {}", path.display()))?;

    load_rules_from_str_with_warnings(&contents)
}

pub fn load_rules_from_str(contents: &str) -> Result<FilterConfig> {
    let (config, warnings) = load_rules_from_str_with_warnings(contents)?;
    for w in &warnings {
        eprintln!("Warning: {}", w);
    }
    Ok(config)
}

pub fn load_rules_from_str_with_warnings(contents: &str) -> Result<(FilterConfig, Vec<String>)> {
    let config: FilterConfig = serde_yaml::from_str(contents)
        .with_context(|| "Failed to parse YAML")?;

    validate(&config)?;
    let warnings = check_rule_overlaps(&config.pacgate.rules);
    Ok((config, warnings))
}

fn validate_match_criteria(mc: &crate::model::MatchCriteria, rule_name: &str) -> Result<()> {
    if let Some(ref et) = mc.ethertype {
        crate::model::parse_ethertype(et)?;
    }
    if let Some(ref mac) = mc.dst_mac {
        crate::model::MacAddress::parse(mac)?;
    }
    if let Some(ref mac) = mc.src_mac {
        crate::model::MacAddress::parse(mac)?;
    }
    if let Some(pcp) = mc.vlan_pcp {
        if pcp > 7 {
            anyhow::bail!("VLAN PCP must be 0-7, got {} in rule '{}'", pcp, rule_name);
        }
    }
    // L3: Validate IP addresses
    if let Some(ref ip) = mc.src_ip {
        crate::model::Ipv4Prefix::parse(ip)
            .with_context(|| format!("Bad src_ip in rule '{}'", rule_name))?;
    }
    if let Some(ref ip) = mc.dst_ip {
        crate::model::Ipv4Prefix::parse(ip)
            .with_context(|| format!("Bad dst_ip in rule '{}'", rule_name))?;
    }
    // L4: Validate port ranges
    if let Some(ref pm) = mc.src_port {
        validate_port_match(pm, "src_port", rule_name)?;
    }
    if let Some(ref pm) = mc.dst_port {
        validate_port_match(pm, "dst_port", rule_name)?;
    }
    // VXLAN VNI (24-bit)
    if let Some(vni) = mc.vxlan_vni {
        if vni > 0xFFFFFF {
            anyhow::bail!("VXLAN VNI must be 0-16777215 (24-bit), got {} in rule '{}'", vni, rule_name);
        }
    }
    // L3: Validate IPv6 addresses
    if let Some(ref ip) = mc.src_ipv6 {
        crate::model::Ipv6Prefix::parse(ip)
            .with_context(|| format!("Bad src_ipv6 in rule '{}'", rule_name))?;
    }
    if let Some(ref ip) = mc.dst_ipv6 {
        crate::model::Ipv6Prefix::parse(ip)
            .with_context(|| format!("Bad dst_ipv6 in rule '{}'", rule_name))?;
    }
    // Byte-offset matching validation
    if let Some(ref byte_matches) = mc.byte_match {
        if byte_matches.len() > 4 {
            anyhow::bail!("Max 4 byte_match entries per rule, got {} in rule '{}'", byte_matches.len(), rule_name);
        }
        for bm in byte_matches {
            if bm.offset > 1500 {
                anyhow::bail!("byte_match offset must be <= 1500, got {} in rule '{}'", bm.offset, rule_name);
            }
            let value_bytes = crate::model::ByteMatch::parse_hex_value(&bm.value)
                .map_err(|e| anyhow::anyhow!("Bad byte_match value in rule '{}': {}", rule_name, e))?;
            if value_bytes.len() > 4 {
                anyhow::bail!("byte_match value must be <= 4 bytes, got {} in rule '{}'", value_bytes.len(), rule_name);
            }
            if let Some(ref mask) = bm.mask {
                let mask_bytes = crate::model::ByteMatch::parse_hex_value(mask)
                    .map_err(|e| anyhow::anyhow!("Bad byte_match mask in rule '{}': {}", rule_name, e))?;
                if mask_bytes.len() != value_bytes.len() {
                    anyhow::bail!("byte_match mask length ({}) must equal value length ({}) in rule '{}'",
                        mask_bytes.len(), value_bytes.len(), rule_name);
                }
            }
        }
    }

    // DSCP/ECN validation
    if let Some(dscp) = mc.ip_dscp {
        if dscp > 63 {
            anyhow::bail!("ip_dscp must be 0-63, got {} in rule '{}'", dscp, rule_name);
        }
    }
    if let Some(ecn) = mc.ip_ecn {
        if ecn > 3 {
            anyhow::bail!("ip_ecn must be 0-3, got {} in rule '{}'", ecn, rule_name);
        }
    }

    // IPv6 DSCP/ECN validation
    if let Some(dscp) = mc.ipv6_dscp {
        if dscp > 63 {
            anyhow::bail!("ipv6_dscp must be 0-63, got {} in rule '{}'", dscp, rule_name);
        }
    }
    if let Some(ecn) = mc.ipv6_ecn {
        if ecn > 3 {
            anyhow::bail!("ipv6_ecn must be 0-3, got {} in rule '{}'", ecn, rule_name);
        }
    }

    // TCP flags validation
    if mc.tcp_flags_mask.is_some() && mc.tcp_flags.is_none() {
        anyhow::bail!("tcp_flags_mask requires tcp_flags in rule '{}'", rule_name);
    }

    // ICMP validation: icmp_code requires icmp_type
    if mc.icmp_code.is_some() && mc.icmp_type.is_none() {
        anyhow::bail!("icmp_code requires icmp_type in rule '{}'", rule_name);
    }

    // ICMPv6 validation: icmpv6_code requires icmpv6_type
    if mc.icmpv6_code.is_some() && mc.icmpv6_type.is_none() {
        anyhow::bail!("icmpv6_code requires icmpv6_type in rule '{}'", rule_name);
    }

    // ARP validation
    if let Some(op) = mc.arp_opcode {
        if op != 1 && op != 2 {
            anyhow::bail!("arp_opcode must be 1 (request) or 2 (reply), got {} in rule '{}'", op, rule_name);
        }
    }
    if let Some(ref spa) = mc.arp_spa {
        crate::model::Ipv4Prefix::parse(spa)
            .map_err(|e| anyhow::anyhow!("Invalid arp_spa '{}' in rule '{}': {}", spa, rule_name, e))?;
    }
    if let Some(ref tpa) = mc.arp_tpa {
        crate::model::Ipv4Prefix::parse(tpa)
            .map_err(|e| anyhow::anyhow!("Invalid arp_tpa '{}' in rule '{}': {}", tpa, rule_name, e))?;
    }

    // IPv6 flow_label validation: 20-bit max (0-1048575)
    if let Some(fl) = mc.ipv6_flow_label {
        if fl > 0xFFFFF {
            anyhow::bail!("ipv6_flow_label must be 0-1048575 (20-bit), got {} in rule '{}'", fl, rule_name);
        }
    }

    Ok(())
}

fn validate_port_match(pm: &crate::model::PortMatch, field: &str, rule_name: &str) -> Result<()> {
    match pm {
        crate::model::PortMatch::Exact(_) => {} // u16 is always valid (0-65535)
        crate::model::PortMatch::Range { range } => {
            if range[0] > range[1] {
                anyhow::bail!(
                    "{} range start ({}) must be <= end ({}) in rule '{}'",
                    field, range[0], range[1], rule_name
                );
            }
        }
    }
    Ok(())
}

fn validate_rewrite(rw: &crate::model::RewriteAction, rule: &crate::model::StatelessRule, rule_name: &str) -> Result<()> {
    // Rewrite on stateful rules is not supported
    if rule.is_stateful() {
        anyhow::bail!("rewrite actions not supported on stateful rules (rule '{}')", rule_name);
    }

    // Validate MAC format
    if let Some(ref mac) = rw.set_dst_mac {
        crate::model::MacAddress::parse(mac)
            .map_err(|e| anyhow::anyhow!("Bad set_dst_mac '{}' in rule '{}': {}", mac, rule_name, e))?;
    }
    if let Some(ref mac) = rw.set_src_mac {
        crate::model::MacAddress::parse(mac)
            .map_err(|e| anyhow::anyhow!("Bad set_src_mac '{}' in rule '{}': {}", mac, rule_name, e))?;
    }

    // Validate VLAN ID range
    if let Some(vid) = rw.set_vlan_id {
        if vid > 4095 {
            anyhow::bail!("set_vlan_id must be 0-4095, got {} in rule '{}'", vid, rule_name);
        }
        // Require rule to match on VLAN (ethertype 0x8100 or vlan_id)
        let matches_vlan = rule.match_criteria.vlan_id.is_some()
            || rule.match_criteria.ethertype.as_deref() == Some("0x8100");
        if !matches_vlan {
            anyhow::bail!("set_vlan_id requires rule to match on vlan_id or ethertype 0x8100 in rule '{}'", rule_name);
        }
    }

    // set_ttl and dec_ttl are mutually exclusive
    if rw.set_ttl.is_some() && rw.dec_ttl == Some(true) {
        anyhow::bail!("set_ttl and dec_ttl are mutually exclusive in rule '{}'", rule_name);
    }

    // IP rewrites and TTL require ethertype 0x0800 match
    let needs_ipv4 = rw.set_src_ip.is_some() || rw.set_dst_ip.is_some()
        || rw.set_ttl.is_some() || rw.dec_ttl == Some(true);
    if needs_ipv4 {
        let has_ipv4_match = rule.match_criteria.ethertype.as_deref() == Some("0x0800");
        if !has_ipv4_match {
            anyhow::bail!("IP/TTL rewrite requires ethertype 0x0800 match in rule '{}'", rule_name);
        }
    }

    // Validate IP address format (dotted decimal, no CIDR)
    if let Some(ref ip) = rw.set_src_ip {
        if ip.contains('/') {
            anyhow::bail!("set_src_ip must be a host address (no CIDR), got '{}' in rule '{}'", ip, rule_name);
        }
        crate::model::Ipv4Prefix::parse(ip)
            .map_err(|e| anyhow::anyhow!("Bad set_src_ip '{}' in rule '{}': {}", ip, rule_name, e))?;
    }
    if let Some(ref ip) = rw.set_dst_ip {
        if ip.contains('/') {
            anyhow::bail!("set_dst_ip must be a host address (no CIDR), got '{}' in rule '{}'", ip, rule_name);
        }
        crate::model::Ipv4Prefix::parse(ip)
            .map_err(|e| anyhow::anyhow!("Bad set_dst_ip '{}' in rule '{}': {}", ip, rule_name, e))?;
    }

    // Validate set_dscp range and IPv4 prerequisite
    if let Some(dscp) = rw.set_dscp {
        if dscp > 63 {
            anyhow::bail!("set_dscp must be 0-63, got {} in rule '{}'", dscp, rule_name);
        }
        let has_ipv4_match = rule.match_criteria.ethertype.as_deref() == Some("0x0800");
        if !has_ipv4_match {
            anyhow::bail!("set_dscp requires ethertype 0x0800 match in rule '{}'", rule_name);
        }
    }

    Ok(())
}

fn validate(config: &FilterConfig) -> Result<()> {
    if config.pacgate.rules.is_empty() {
        anyhow::bail!("No rules defined");
    }

    for rule in &config.pacgate.rules {
        if rule.name.is_empty() {
            anyhow::bail!("Rule name cannot be empty");
        }

        if rule.is_stateful() {
            // Stateful rule validation
            let fsm = rule.fsm.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Stateful rule '{}' missing fsm definition", rule.name))?;

            if !fsm.states.contains_key(&fsm.initial_state) {
                anyhow::bail!("FSM initial_state '{}' not found in states for rule '{}'",
                    fsm.initial_state, rule.name);
            }

            // Validate HSM: check nesting depth, initial_substate, variables
            validate_fsm_hierarchy(&fsm.states, &rule.name, 0)?;

            // Validate variables
            if let Some(ref vars) = fsm.variables {
                for v in vars {
                    if v.width < 1 || v.width > 32 {
                        anyhow::bail!("FSM variable '{}' width must be 1-32, got {} in rule '{}'",
                            v.name, v.width, rule.name);
                    }
                    if !v.name.chars().all(|c| c.is_alphanumeric() || c == '_') || v.name.is_empty() {
                        anyhow::bail!("FSM variable name '{}' must be a valid identifier in rule '{}'",
                            v.name, rule.name);
                    }
                }
            }

            // Collect all state names (including flattened) for transition validation
            let all_state_names = collect_all_state_names(&fsm.states, "");

            for (state_name, state) in &fsm.states {
                validate_state_transitions(state, state_name, &all_state_names, &rule.name, &fsm.states)?;
            }
        } else {
            // Stateless rule validation
            validate_match_criteria(&rule.match_criteria, &rule.name)?;
        }

        // Validate rate_limit if specified
        if let Some(ref rl) = rule.rate_limit {
            if rl.pps == 0 {
                anyhow::bail!("rate_limit pps must be > 0 in rule '{}'", rule.name);
            }
            if rl.burst == 0 {
                anyhow::bail!("rate_limit burst must be > 0 in rule '{}'", rule.name);
            }
        }

        // Validate ports list if specified
        if let Some(ref ports) = rule.ports {
            if ports.is_empty() {
                anyhow::bail!("Empty ports list in rule '{}'", rule.name);
            }
        }

        // Validate rewrite actions if specified
        if let Some(ref rw) = rule.rewrite {
            validate_rewrite(rw, rule, &rule.name)?;
        }
    }

    // Check for duplicate priorities
    let mut priorities: Vec<u32> = config.pacgate.rules.iter().map(|r| r.priority).collect();
    priorities.sort();
    for w in priorities.windows(2) {
        if w[0] == w[1] {
            anyhow::bail!("Duplicate priority: {}", w[0]);
        }
    }

    // Validate conntrack config if present
    if let Some(ref ct) = config.pacgate.conntrack {
        if ct.table_size == 0 || (ct.table_size & (ct.table_size - 1)) != 0 {
            anyhow::bail!("conntrack table_size must be a power of 2, got {}", ct.table_size);
        }
        if ct.timeout_cycles == 0 {
            anyhow::bail!("conntrack timeout_cycles must be > 0");
        }
    }

    // Check for duplicate rule names
    let mut names: Vec<&str> = config.pacgate.rules.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    for w in names.windows(2) {
        if w[0] == w[1] {
            anyhow::bail!("Duplicate rule name: '{}'", w[0]);
        }
    }

    Ok(())
}

/// Validate HSM hierarchy depth and composite state requirements
fn validate_fsm_hierarchy(
    states: &std::collections::HashMap<String, crate::model::FsmState>,
    rule_name: &str,
    depth: usize,
) -> Result<()> {
    if depth > 4 {
        anyhow::bail!("HSM nesting depth exceeds 4 levels in rule '{}'", rule_name);
    }
    for (name, state) in states {
        if let Some(ref substates) = state.substates {
            if state.initial_substate.is_none() {
                anyhow::bail!("Composite state '{}' must have initial_substate in rule '{}'",
                    name, rule_name);
            }
            if let Some(ref init_sub) = state.initial_substate {
                if !substates.contains_key(init_sub) {
                    anyhow::bail!("initial_substate '{}' not found in composite state '{}' of rule '{}'",
                        init_sub, name, rule_name);
                }
            }
            validate_fsm_hierarchy(substates, rule_name, depth + 1)?;
        }
    }
    Ok(())
}

/// Collect all state names (flat + nested with dot notation)
fn collect_all_state_names(
    states: &std::collections::HashMap<String, crate::model::FsmState>,
    prefix: &str,
) -> Vec<String> {
    let mut names = Vec::new();
    for (name, state) in states {
        let full_name = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", prefix, name)
        };
        names.push(full_name.clone());
        if let Some(ref substates) = state.substates {
            names.extend(collect_all_state_names(substates, &full_name));
        }
    }
    names
}

/// Validate transitions for a state (recursive for substates)
fn validate_state_transitions(
    state: &crate::model::FsmState,
    state_name: &str,
    all_names: &[String],
    rule_name: &str,
    top_states: &std::collections::HashMap<String, crate::model::FsmState>,
) -> Result<()> {
    // Build sibling names if we're inside a composite
    let sibling_names: Vec<String> = if let Some(ref substates) = state.substates {
        substates.keys().cloned().collect()
    } else {
        Vec::new()
    };

    for transition in &state.transitions {
        // Allow transition to any known state (flat or hierarchical) or sibling name
        let target = &transition.next_state;
        let is_valid = all_names.contains(target)
            || top_states.contains_key(target)
            || sibling_names.contains(target);
        if !is_valid {
            anyhow::bail!("FSM transition from '{}' to unknown state '{}' in rule '{}'",
                state_name, transition.next_state, rule_name);
        }
        validate_match_criteria(&transition.match_criteria,
            &format!("{}(state {})", rule_name, state_name))?;
    }
    if let Some(ref substates) = state.substates {
        // Collect sibling names for substate validation
        let sub_sibling_names: Vec<String> = substates.keys().cloned().collect();
        for (sub_name, sub_state) in substates {
            let full_name = format!("{}.{}", state_name, sub_name);
            validate_state_transitions_with_siblings(
                sub_state, &full_name, all_names, rule_name, top_states, &sub_sibling_names,
            )?;
        }
    }
    Ok(())
}

/// Like validate_state_transitions but with sibling context
fn validate_state_transitions_with_siblings(
    state: &crate::model::FsmState,
    state_name: &str,
    all_names: &[String],
    rule_name: &str,
    top_states: &std::collections::HashMap<String, crate::model::FsmState>,
    sibling_names: &[String],
) -> Result<()> {
    for transition in &state.transitions {
        let target = &transition.next_state;
        let is_valid = all_names.contains(target)
            || top_states.contains_key(target)
            || sibling_names.contains(target);
        if !is_valid {
            anyhow::bail!("FSM transition from '{}' to unknown state '{}' in rule '{}'",
                state_name, transition.next_state, rule_name);
        }
        validate_match_criteria(&transition.match_criteria,
            &format!("{}(state {})", rule_name, state_name))?;
    }
    if let Some(ref substates) = state.substates {
        let sub_sibling_names: Vec<String> = substates.keys().cloned().collect();
        for (sub_name, sub_state) in substates {
            let full_name = format!("{}.{}", state_name, sub_name);
            validate_state_transitions_with_siblings(
                sub_state, &full_name, all_names, rule_name, top_states, &sub_sibling_names,
            )?;
        }
    }
    Ok(())
}

/// Analyze rules for overlaps and shadowing.
/// Returns a list of warning strings.
pub fn check_rule_overlaps(rules: &[crate::model::StatelessRule]) -> Vec<String> {
    let mut warnings = Vec::new();

    // Only analyze stateless rules
    let stateless: Vec<_> = rules.iter().filter(|r| !r.is_stateful()).collect();

    // Sort by priority descending (highest first)
    let mut sorted = stateless.clone();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Check each pair: does a higher-priority rule fully shadow a lower-priority one?
    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            let high = sorted[i];
            let low = sorted[j];

            if criteria_shadows(&high.match_criteria, &low.match_criteria) {
                warnings.push(format!(
                    "rule '{}' (priority {}) shadows '{}' (priority {}) — '{}' can never match",
                    high.name, high.priority, low.name, low.priority, low.name
                ));
            } else if criteria_overlaps(&high.match_criteria, &low.match_criteria) {
                let action_high = high.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or("N/A".to_string());
                let action_low = low.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or("N/A".to_string());
                if action_high != action_low {
                    warnings.push(format!(
                        "rules '{}' (priority {}, {}) and '{}' (priority {}, {}) overlap with different actions",
                        high.name, high.priority, action_high,
                        low.name, low.priority, action_low,
                    ));
                }
            }
        }
    }

    // Check for rules that match nothing (no criteria at all and action matches default)
    for rule in &stateless {
        let mc = &rule.match_criteria;
        if mc.dst_mac.is_none() && mc.src_mac.is_none() && mc.ethertype.is_none()
            && mc.vlan_id.is_none() && mc.vlan_pcp.is_none()
            && mc.src_ip.is_none() && mc.dst_ip.is_none() && mc.ip_protocol.is_none()
            && mc.src_port.is_none() && mc.dst_port.is_none()
            && mc.vxlan_vni.is_none()
            && mc.src_ipv6.is_none() && mc.dst_ipv6.is_none() && mc.ipv6_next_header.is_none()
            && !mc.uses_byte_match()
            && !mc.uses_gtp() && !mc.uses_mpls() && !mc.uses_multicast()
            && !mc.uses_dscp_ecn() && !mc.uses_ipv6_tc() && !mc.uses_tcp_flags() && !mc.uses_icmp()
        {
            warnings.push(format!(
                "rule '{}' (priority {}) has no match criteria — matches ALL packets",
                rule.name, rule.priority
            ));
        }
    }

    warnings
}

/// Check if CIDR prefix A fully contains CIDR prefix B.
/// e.g., 10.0.0.0/8 contains 10.1.0.0/16 (all of B's addresses are within A).
pub fn cidr_contains(a: &str, b: &str) -> bool {
    let (a_prefix, b_prefix) = match (crate::model::Ipv4Prefix::parse(a), crate::model::Ipv4Prefix::parse(b)) {
        (Ok(ap), Ok(bp)) => (ap, bp),
        _ => return a == b, // fallback to string comparison
    };
    // A contains B iff A's prefix is shorter/equal AND B's network address masked by A matches A's network
    if a_prefix.prefix_len > b_prefix.prefix_len {
        return false; // A is more specific than B
    }
    // Check that B's address ANDed with A's mask equals A's address ANDed with A's mask
    for i in 0..4 {
        if (b_prefix.addr[i] & a_prefix.mask[i]) != (a_prefix.addr[i] & a_prefix.mask[i]) {
            return false;
        }
    }
    true
}

/// Check if two CIDR prefixes share any common addresses.
pub fn cidr_overlaps(a: &str, b: &str) -> bool {
    let (a_prefix, b_prefix) = match (crate::model::Ipv4Prefix::parse(a), crate::model::Ipv4Prefix::parse(b)) {
        (Ok(ap), Ok(bp)) => (ap, bp),
        _ => return true, // assume overlap if can't parse
    };
    // Use the shorter prefix's mask — if both masked to the shorter match, they overlap
    let shorter_mask = if a_prefix.prefix_len <= b_prefix.prefix_len {
        a_prefix.mask
    } else {
        b_prefix.mask
    };
    for i in 0..4 {
        if (a_prefix.addr[i] & shorter_mask[i]) != (b_prefix.addr[i] & shorter_mask[i]) {
            return false;
        }
    }
    true
}

/// Check if port match A fully contains port match B.
pub fn port_contains(a: &crate::model::PortMatch, b: &crate::model::PortMatch) -> bool {
    let (a_lo, a_hi) = match a {
        crate::model::PortMatch::Exact(v) => (*v, *v),
        crate::model::PortMatch::Range { range } => (range[0], range[1]),
    };
    let (b_lo, b_hi) = match b {
        crate::model::PortMatch::Exact(v) => (*v, *v),
        crate::model::PortMatch::Range { range } => (range[0], range[1]),
    };
    a_lo <= b_lo && a_hi >= b_hi
}

/// Check if two port matches share any common port values.
pub fn port_ranges_overlap(a: &crate::model::PortMatch, b: &crate::model::PortMatch) -> bool {
    let (a_lo, a_hi) = match a {
        crate::model::PortMatch::Exact(v) => (*v, *v),
        crate::model::PortMatch::Range { range } => (range[0], range[1]),
    };
    let (b_lo, b_hi) = match b {
        crate::model::PortMatch::Exact(v) => (*v, *v),
        crate::model::PortMatch::Range { range } => (range[0], range[1]),
    };
    a_lo <= b_hi && b_lo <= a_hi
}

/// Check if rule A's criteria fully contain rule B's criteria (A shadows B).
pub fn criteria_shadows(a: &crate::model::MatchCriteria, b: &crate::model::MatchCriteria) -> bool {
    // A shadows B if every packet that matches B also matches A.
    // This happens when A's criteria are a superset (less restrictive) than B's.

    // If A has a constraint that B doesn't, A is more restrictive in that dimension
    // and thus doesn't shadow B.

    // Check each field: if A constrains a field, B must constrain it to the same value.
    if let Some(ref a_et) = a.ethertype {
        match &b.ethertype {
            Some(b_et) if a_et == b_et => {},
            Some(_) => return false,  // Different ethertypes — no shadow
            None => return false,     // A constrains ethertype but B doesn't — A is more restrictive
        }
    }
    // If A doesn't constrain ethertype, it matches all — fine for shadowing.

    if let Some(ref a_mac) = a.dst_mac {
        match &b.dst_mac {
            Some(b_mac) => {
                if !mac_pattern_contains(a_mac, b_mac) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref a_mac) = a.src_mac {
        match &b.src_mac {
            Some(b_mac) => {
                if !mac_pattern_contains(a_mac, b_mac) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(a_vid) = a.vlan_id {
        match b.vlan_id {
            Some(b_vid) if a_vid == b_vid => {},
            _ => return false,
        }
    }

    if let Some(a_pcp) = a.vlan_pcp {
        match b.vlan_pcp {
            Some(b_pcp) if a_pcp == b_pcp => {},
            _ => return false,
        }
    }

    // L3 shadow checks — uses CIDR containment
    if let Some(ref a_ip) = a.src_ip {
        match &b.src_ip {
            Some(b_ip) if cidr_contains(a_ip, b_ip) => {},
            _ => return false,
        }
    }
    if let Some(ref a_ip) = a.dst_ip {
        match &b.dst_ip {
            Some(b_ip) if cidr_contains(a_ip, b_ip) => {},
            _ => return false,
        }
    }
    if let Some(a_proto) = a.ip_protocol {
        match b.ip_protocol {
            Some(b_proto) if a_proto == b_proto => {},
            _ => return false,
        }
    }

    // L4 shadow checks — uses port containment
    if let Some(ref a_port) = a.src_port {
        match &b.src_port {
            Some(b_port) if port_contains(a_port, b_port) => {},
            _ => return false,
        }
    }
    if let Some(ref a_port) = a.dst_port {
        match &b.dst_port {
            Some(b_port) if port_contains(a_port, b_port) => {},
            _ => return false,
        }
    }

    // IPv6 shadow checks
    if let Some(ref a_ip) = a.src_ipv6 {
        match &b.src_ipv6 {
            Some(b_ip) if a_ip == b_ip => {},
            Some(_) => return false,
            None => return false,
        }
    }
    if let Some(ref a_ip) = a.dst_ipv6 {
        match &b.dst_ipv6 {
            Some(b_ip) if a_ip == b_ip => {},
            Some(_) => return false,
            None => return false,
        }
    }
    if let Some(a_nh) = a.ipv6_next_header {
        match b.ipv6_next_header {
            Some(b_nh) if a_nh == b_nh => {},
            _ => return false,
        }
    }

    // VXLAN shadow check
    if let Some(a_vni) = a.vxlan_vni {
        match b.vxlan_vni {
            Some(b_vni) if a_vni == b_vni => {},
            _ => return false,
        }
    }

    // GTP-U shadow check
    if let Some(a_teid) = a.gtp_teid {
        match b.gtp_teid {
            Some(b_teid) if a_teid == b_teid => {},
            _ => return false,
        }
    }

    // MPLS shadow checks
    if let Some(a_label) = a.mpls_label {
        match b.mpls_label {
            Some(b_label) if a_label == b_label => {},
            _ => return false,
        }
    }
    if let Some(a_tc) = a.mpls_tc {
        match b.mpls_tc {
            Some(b_tc) if a_tc == b_tc => {},
            _ => return false,
        }
    }
    if let Some(a_bos) = a.mpls_bos {
        match b.mpls_bos {
            Some(b_bos) if a_bos == b_bos => {},
            _ => return false,
        }
    }

    // IGMP/MLD shadow checks
    if let Some(a_igmp) = a.igmp_type {
        match b.igmp_type {
            Some(b_igmp) if a_igmp == b_igmp => {},
            _ => return false,
        }
    }
    if let Some(a_mld) = a.mld_type {
        match b.mld_type {
            Some(b_mld) if a_mld == b_mld => {},
            _ => return false,
        }
    }

    // DSCP/ECN shadow checks
    if let Some(a_dscp) = a.ip_dscp {
        match b.ip_dscp {
            Some(b_dscp) if a_dscp == b_dscp => {},
            _ => return false,
        }
    }
    if let Some(a_ecn) = a.ip_ecn {
        match b.ip_ecn {
            Some(b_ecn) if a_ecn == b_ecn => {},
            _ => return false,
        }
    }

    // IPv6 DSCP/ECN shadow checks
    if let Some(a_dscp) = a.ipv6_dscp {
        match b.ipv6_dscp {
            Some(b_dscp) if a_dscp == b_dscp => {},
            _ => return false,
        }
    }
    if let Some(a_ecn) = a.ipv6_ecn {
        match b.ipv6_ecn {
            Some(b_ecn) if a_ecn == b_ecn => {},
            _ => return false,
        }
    }

    // TCP flags shadow checks (mask-aware)
    if let Some(a_flags) = a.tcp_flags {
        match b.tcp_flags {
            Some(b_flags) => {
                let a_mask = a.tcp_flags_mask.unwrap_or(0xFF);
                let b_mask = b.tcp_flags_mask.unwrap_or(0xFF);
                // A shadows B if A's mask is a subset of B's mask and values agree on A's bits
                if a_mask != b_mask || (a_flags & a_mask) != (b_flags & b_mask) {
                    return false;
                }
            },
            _ => return false,
        }
    }

    // ICMP shadow checks
    if let Some(a_icmp) = a.icmp_type {
        match b.icmp_type {
            Some(b_icmp) if a_icmp == b_icmp => {},
            _ => return false,
        }
    }
    if let Some(a_code) = a.icmp_code {
        match b.icmp_code {
            Some(b_code) if a_code == b_code => {},
            _ => return false,
        }
    }

    // ICMPv6 shadow checks
    if let Some(a_icmpv6) = a.icmpv6_type {
        match b.icmpv6_type {
            Some(b_icmpv6) if a_icmpv6 == b_icmpv6 => {},
            _ => return false,
        }
    }
    if let Some(a_code) = a.icmpv6_code {
        match b.icmpv6_code {
            Some(b_code) if a_code == b_code => {},
            _ => return false,
        }
    }

    // ARP shadow checks
    if let Some(a_op) = a.arp_opcode {
        match b.arp_opcode {
            Some(b_op) if a_op == b_op => {},
            _ => return false,
        }
    }
    if let Some(ref a_spa) = a.arp_spa {
        match &b.arp_spa {
            Some(b_spa) if a_spa == b_spa => {},
            _ => return false,
        }
    }
    if let Some(ref a_tpa) = a.arp_tpa {
        match &b.arp_tpa {
            Some(b_tpa) if a_tpa == b_tpa => {},
            _ => return false,
        }
    }

    // IPv6 extension shadow checks
    if let Some(a_hl) = a.ipv6_hop_limit {
        match b.ipv6_hop_limit {
            Some(b_hl) if a_hl == b_hl => {},
            _ => return false,
        }
    }
    if let Some(a_fl) = a.ipv6_flow_label {
        match b.ipv6_flow_label {
            Some(b_fl) if a_fl == b_fl => {},
            _ => return false,
        }
    }

    true
}

/// Check if two criteria could match the same packet (overlap).
fn criteria_overlaps(a: &crate::model::MatchCriteria, b: &crate::model::MatchCriteria) -> bool {
    // Two rules overlap if there exists a packet matching both.
    // They DON'T overlap if any field constrains to disjoint values.

    if let (Some(a_et), Some(b_et)) = (&a.ethertype, &b.ethertype) {
        if a_et != b_et {
            return false; // Different ethertypes — no overlap
        }
    }

    if let (Some(a_mac), Some(b_mac)) = (&a.dst_mac, &b.dst_mac) {
        if !mac_patterns_overlap(a_mac, b_mac) {
            return false;
        }
    }

    if let (Some(a_mac), Some(b_mac)) = (&a.src_mac, &b.src_mac) {
        if !mac_patterns_overlap(a_mac, b_mac) {
            return false;
        }
    }

    if let (Some(a_vid), Some(b_vid)) = (a.vlan_id, b.vlan_id) {
        if a_vid != b_vid {
            return false;
        }
    }

    if let (Some(a_pcp), Some(b_pcp)) = (a.vlan_pcp, b.vlan_pcp) {
        if a_pcp != b_pcp {
            return false;
        }
    }

    // L3 overlap checks — uses CIDR overlap
    if let (Some(ref a_ip), Some(ref b_ip)) = (&a.src_ip, &b.src_ip) {
        if !cidr_overlaps(a_ip, b_ip) { return false; }
    }
    if let (Some(ref a_ip), Some(ref b_ip)) = (&a.dst_ip, &b.dst_ip) {
        if !cidr_overlaps(a_ip, b_ip) { return false; }
    }
    if let (Some(a_proto), Some(b_proto)) = (a.ip_protocol, b.ip_protocol) {
        if a_proto != b_proto { return false; }
    }

    // L4 overlap checks — uses port range overlap
    if let (Some(ref a_port), Some(ref b_port)) = (&a.src_port, &b.src_port) {
        if !port_ranges_overlap(a_port, b_port) { return false; }
    }
    if let (Some(ref a_port), Some(ref b_port)) = (&a.dst_port, &b.dst_port) {
        if !port_ranges_overlap(a_port, b_port) { return false; }
    }

    // IPv6 overlap checks
    if let (Some(ref a_ip), Some(ref b_ip)) = (&a.src_ipv6, &b.src_ipv6) {
        if a_ip != b_ip { return false; }
    }
    if let (Some(ref a_ip), Some(ref b_ip)) = (&a.dst_ipv6, &b.dst_ipv6) {
        if a_ip != b_ip { return false; }
    }
    if let (Some(a_nh), Some(b_nh)) = (a.ipv6_next_header, b.ipv6_next_header) {
        if a_nh != b_nh { return false; }
    }

    // VXLAN overlap check
    if let (Some(a_vni), Some(b_vni)) = (a.vxlan_vni, b.vxlan_vni) {
        if a_vni != b_vni { return false; }
    }

    // GTP-U overlap check
    if let (Some(a_teid), Some(b_teid)) = (a.gtp_teid, b.gtp_teid) {
        if a_teid != b_teid { return false; }
    }

    // MPLS overlap checks
    if let (Some(a_label), Some(b_label)) = (a.mpls_label, b.mpls_label) {
        if a_label != b_label { return false; }
    }
    if let (Some(a_tc), Some(b_tc)) = (a.mpls_tc, b.mpls_tc) {
        if a_tc != b_tc { return false; }
    }
    if let (Some(a_bos), Some(b_bos)) = (a.mpls_bos, b.mpls_bos) {
        if a_bos != b_bos { return false; }
    }

    // IGMP/MLD overlap checks
    if let (Some(a_igmp), Some(b_igmp)) = (a.igmp_type, b.igmp_type) {
        if a_igmp != b_igmp { return false; }
    }
    if let (Some(a_mld), Some(b_mld)) = (a.mld_type, b.mld_type) {
        if a_mld != b_mld { return false; }
    }

    // DSCP/ECN overlap checks
    if let (Some(a_dscp), Some(b_dscp)) = (a.ip_dscp, b.ip_dscp) {
        if a_dscp != b_dscp { return false; }
    }
    if let (Some(a_ecn), Some(b_ecn)) = (a.ip_ecn, b.ip_ecn) {
        if a_ecn != b_ecn { return false; }
    }

    // IPv6 DSCP/ECN overlap checks
    if let (Some(a_dscp), Some(b_dscp)) = (a.ipv6_dscp, b.ipv6_dscp) {
        if a_dscp != b_dscp { return false; }
    }
    if let (Some(a_ecn), Some(b_ecn)) = (a.ipv6_ecn, b.ipv6_ecn) {
        if a_ecn != b_ecn { return false; }
    }

    // TCP flags overlap checks (mask-aware)
    if let (Some(a_flags), Some(b_flags)) = (a.tcp_flags, b.tcp_flags) {
        let a_mask = a.tcp_flags_mask.unwrap_or(0xFF);
        let b_mask = b.tcp_flags_mask.unwrap_or(0xFF);
        let common_mask = a_mask & b_mask;
        if (a_flags & common_mask) != (b_flags & common_mask) { return false; }
    }

    // ICMP overlap checks
    if let (Some(a_icmp), Some(b_icmp)) = (a.icmp_type, b.icmp_type) {
        if a_icmp != b_icmp { return false; }
    }
    if let (Some(a_code), Some(b_code)) = (a.icmp_code, b.icmp_code) {
        if a_code != b_code { return false; }
    }

    // ICMPv6 overlap checks
    if let (Some(a_icmpv6), Some(b_icmpv6)) = (a.icmpv6_type, b.icmpv6_type) {
        if a_icmpv6 != b_icmpv6 { return false; }
    }
    if let (Some(a_code), Some(b_code)) = (a.icmpv6_code, b.icmpv6_code) {
        if a_code != b_code { return false; }
    }

    // ARP overlap checks
    if let (Some(a_op), Some(b_op)) = (a.arp_opcode, b.arp_opcode) {
        if a_op != b_op { return false; }
    }
    if let (Some(ref a_spa), Some(ref b_spa)) = (&a.arp_spa, &b.arp_spa) {
        if a_spa != b_spa { return false; }
    }
    if let (Some(ref a_tpa), Some(ref b_tpa)) = (&a.arp_tpa, &b.arp_tpa) {
        if a_tpa != b_tpa { return false; }
    }

    // IPv6 extension overlap checks
    if let (Some(a_hl), Some(b_hl)) = (a.ipv6_hop_limit, b.ipv6_hop_limit) {
        if a_hl != b_hl { return false; }
    }
    if let (Some(a_fl), Some(b_fl)) = (a.ipv6_flow_label, b.ipv6_flow_label) {
        if a_fl != b_fl { return false; }
    }

    true
}

/// Check if MAC pattern A fully contains pattern B (all matches of B are also matches of A).
fn mac_pattern_contains(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split(':').collect();
    let b_parts: Vec<&str> = b.split(':').collect();
    if a_parts.len() != 6 || b_parts.len() != 6 {
        return false;
    }
    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        if *ap == "*" {
            continue; // A is wildcard here — matches everything B could
        }
        if *bp == "*" {
            return false; // B is wildcard but A is specific — A is more restrictive
        }
        if ap != bp {
            return false; // Different specific values
        }
    }
    true
}

/// Check if two MAC patterns can match the same address.
fn mac_patterns_overlap(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split(':').collect();
    let b_parts: Vec<&str> = b.split(':').collect();
    if a_parts.len() != 6 || b_parts.len() != 6 {
        return true; // Can't tell — assume overlap
    }
    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        if *ap == "*" || *bp == "*" {
            continue; // Wildcard — always overlaps
        }
        if ap != bp {
            return false; // Different specific values — no overlap
        }
    }
    true
}

/// Validate constraints for --dynamic mode.
/// Called from main.rs before code generation.
pub fn validate_dynamic(config: &FilterConfig, conntrack: bool, dynamic_entries: u16) -> Result<()> {
    // Dynamic entries bounds
    if dynamic_entries < 1 || dynamic_entries > 256 {
        anyhow::bail!("--dynamic-entries must be 1-256, got {}", dynamic_entries);
    }

    // Incompatible with conntrack
    if conntrack || config.pacgate.conntrack.is_some() {
        anyhow::bail!("--dynamic is incompatible with --conntrack (connection tracking modifies decision flow)");
    }

    // Incompatible with stateful/FSM rules
    for rule in &config.pacgate.rules {
        if rule.is_stateful() {
            anyhow::bail!("--dynamic is incompatible with stateful/FSM rules (rule '{}' is stateful)", rule.name);
        }
    }

    // V1 scope: no IPv6, GTP, MPLS, IGMP/MLD, byte_match, VXLAN
    for rule in &config.pacgate.rules {
        let mc = &rule.match_criteria;
        if mc.uses_ipv6() {
            anyhow::bail!("--dynamic V1 does not support IPv6 fields (rule '{}' uses IPv6). IPv6 support planned for V2.", rule.name);
        }
        if mc.uses_gtp() {
            anyhow::bail!("--dynamic V1 does not support GTP-U fields (rule '{}' uses gtp_teid). GTP support planned for V2.", rule.name);
        }
        if mc.uses_mpls() {
            anyhow::bail!("--dynamic V1 does not support MPLS fields (rule '{}' uses MPLS). MPLS support planned for V2.", rule.name);
        }
        if mc.uses_multicast() {
            anyhow::bail!("--dynamic V1 does not support IGMP/MLD fields (rule '{}' uses multicast). Multicast support planned for V2.", rule.name);
        }
        if mc.uses_byte_match() {
            anyhow::bail!("--dynamic V1 does not support byte_match fields (rule '{}' uses byte_match). Byte-match support planned for V2.", rule.name);
        }
        if mc.vxlan_vni.is_some() {
            anyhow::bail!("--dynamic V1 does not support VXLAN VNI (rule '{}' uses vxlan_vni). VXLAN support planned for V2.", rule.name);
        }
        if mc.uses_ipv6_tc() {
            anyhow::bail!("--dynamic V1 does not support IPv6 TC fields (rule '{}' uses ipv6_dscp/ipv6_ecn). IPv6 TC support planned for V2.", rule.name);
        }
        if mc.uses_tcp_flags() {
            anyhow::bail!("--dynamic V1 does not support TCP flags (rule '{}' uses tcp_flags). TCP flags support planned for V2.", rule.name);
        }
        if mc.uses_icmp() {
            anyhow::bail!("--dynamic V1 does not support ICMP fields (rule '{}' uses icmp_type/icmp_code). ICMP support planned for V2.", rule.name);
        }
    }

    // More rules than entries is a warning, not error (excess rules won't be loaded)
    // The actual cap is handled in verilog_gen

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_yaml(rules: &str) -> String {
        format!(
            r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
{rules}
"#
        )
    }

    #[test]
    fn load_valid_single_rule() {
        let yaml = valid_yaml(
            "    - name: allow_arp\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
    }

    #[test]
    fn load_valid_file() {
        let config = load_rules(Path::new("rules/examples/allow_arp.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].name, "allow_arp");
    }

    #[test]
    fn load_enterprise_rules() {
        let config = load_rules(Path::new("rules/examples/enterprise.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 7);
    }

    #[test]
    fn load_stateful_rules() {
        let config = load_rules(Path::new("rules/examples/stateful_sequence.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert!(config.pacgate.rules.iter().any(|r| r.is_stateful()));
    }

    #[test]
    fn reject_empty_rules() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules: []
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("No rules defined"));
    }

    #[test]
    fn reject_duplicate_priorities() {
        let yaml = valid_yaml(
            "    - name: rule_a\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass\n    - name: rule_b\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Duplicate priority"));
    }

    #[test]
    fn reject_bad_mac() {
        let yaml = valid_yaml(
            "    - name: bad_mac\n      priority: 100\n      match:\n        dst_mac: \"zz:zz:zz:zz:zz:zz\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn reject_bad_ethertype() {
        let yaml = valid_yaml(
            "    - name: bad_et\n      priority: 100\n      match:\n        ethertype: \"not_hex\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn reject_vlan_pcp_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad_pcp\n      priority: 100\n      match:\n        vlan_pcp: 8\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("VLAN PCP must be 0-7"), "got: {}", err);
    }

    #[test]
    fn reject_fsm_missing_initial_state() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_fsm
      type: stateful
      priority: 50
      fsm:
        initial_state: nonexistent
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: idle
                action: pass
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("initial_state"));
    }

    #[test]
    fn reject_fsm_bad_transition_target() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_fsm
      type: stateful
      priority: 50
      fsm:
        initial_state: idle
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: nonexistent
                action: pass
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown state"));
    }

    #[test]
    fn reject_stateful_missing_fsm() {
        let yaml = valid_yaml(
            "    - name: no_fsm\n      type: stateful\n      priority: 50",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("missing fsm"));
    }

    #[test]
    fn reject_empty_rule_name() {
        let yaml = valid_yaml(
            "    - name: \"\"\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("name cannot be empty"));
    }

    #[test]
    fn accept_mac_wildcards() {
        let yaml = valid_yaml(
            "    - name: vendor\n      priority: 100\n      match:\n        src_mac: \"00:1a:2b:*:*:*\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.src_mac.as_deref(), Some("00:1a:2b:*:*:*"));
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(load_rules(Path::new("nonexistent.yaml")).is_err());
    }

    #[test]
    fn reject_duplicate_rule_names() {
        let yaml = valid_yaml(
            "    - name: same_name\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass\n    - name: same_name\n      priority: 200\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Duplicate rule name"));
    }

    #[test]
    fn detect_shadowed_rule() {
        // Rule A (priority 200) matches all ethertypes with no constraints.
        // Rule B (priority 100) matches ethertype 0x0800.
        // A shadows B because A matches all packets B would match.
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 200,
                match_criteria: MatchCriteria::default(), // no constraints
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None,
            },
            StatelessRule {
                name: "allow_ipv4".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("shadows")));
    }

    #[test]
    fn detect_overlap_different_actions() {
        // Two rules overlap on the same ethertype but have different actions.
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "pass_arp".to_string(),
                priority: 200,
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
            StatelessRule {
                name: "drop_arp".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("overlap") || w.contains("shadows")));
    }

    #[test]
    fn no_overlap_disjoint_rules() {
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "allow_arp".to_string(),
                priority: 200,
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
            StatelessRule {
                name: "allow_ipv4".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warn_catch_all_rule() {
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 10,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("matches ALL packets")));
    }

    #[test]
    fn mac_overlap_detection() {
        assert!(mac_patterns_overlap("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"));
        assert!(!mac_patterns_overlap("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"));
        assert!(mac_patterns_overlap("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_patterns_overlap("00:1a:2b:*:*:*", "00:1a:3c:*:*:*"));
    }

    // --- L3/L4 validation tests ---

    #[test]
    fn accept_ipv4_exact() {
        let yaml = valid_yaml(
            "    - name: web\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        dst_ip: \"192.168.1.1\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_ip.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn accept_ipv4_cidr() {
        let yaml = valid_yaml(
            "    - name: subnet\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        src_ip: \"10.0.0.0/8\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.src_ip.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn reject_bad_ipv4() {
        let yaml = valid_yaml(
            "    - name: bad_ip\n      priority: 100\n      match:\n        dst_ip: \"999.999.999.999\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn reject_bad_cidr_prefix() {
        let yaml = valid_yaml(
            "    - name: bad_cidr\n      priority: 100\n      match:\n        src_ip: \"10.0.0.0/33\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn accept_port_exact() {
        let yaml = valid_yaml(
            "    - name: ssh\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_protocol: 6\n        dst_port: 22\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert!(config.pacgate.rules[0].match_criteria.dst_port.is_some());
    }

    #[test]
    fn accept_port_range() {
        let yaml = valid_yaml(
            "    - name: high_ports\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_protocol: 6\n        dst_port:\n          range: [1024, 65535]\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert!(config.pacgate.rules[0].match_criteria.dst_port.is_some());
    }

    #[test]
    fn reject_port_range_inverted() {
        let yaml = valid_yaml(
            "    - name: bad_range\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        dst_port:\n          range: [8080, 80]\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("range start"), "got: {}", err);
    }

    #[test]
    fn accept_ip_protocol() {
        let yaml = valid_yaml(
            "    - name: tcp\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_protocol: 6\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.ip_protocol, Some(6));
    }

    #[test]
    fn accept_vxlan_vni() {
        let yaml = valid_yaml(
            "    - name: tenant\n      priority: 100\n      match:\n        vxlan_vni: 1000\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.vxlan_vni, Some(1000));
    }

    #[test]
    fn reject_vxlan_vni_too_large() {
        let yaml = valid_yaml(
            "    - name: bad_vni\n      priority: 100\n      match:\n        vxlan_vni: 16777216\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("VXLAN VNI must be"), "got: {}", err);
    }

    // --- Byte-match validation tests ---

    #[test]
    fn accept_byte_match() {
        let yaml = valid_yaml(
            "    - name: ipv4_ver\n      priority: 100\n      match:\n        byte_match:\n          - offset: 14\n            value: \"0x45\"\n            mask: \"0xf0\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert!(config.pacgate.rules[0].match_criteria.byte_match.is_some());
    }

    #[test]
    fn reject_byte_match_too_many() {
        let yaml = valid_yaml(
            "    - name: too_many\n      priority: 100\n      match:\n        byte_match:\n          - offset: 0\n            value: \"0x45\"\n          - offset: 1\n            value: \"0x45\"\n          - offset: 2\n            value: \"0x45\"\n          - offset: 3\n            value: \"0x45\"\n          - offset: 4\n            value: \"0x45\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Max 4 byte_match"), "got: {}", err);
    }

    #[test]
    fn reject_byte_match_offset_too_large() {
        let yaml = valid_yaml(
            "    - name: big_off\n      priority: 100\n      match:\n        byte_match:\n          - offset: 1501\n            value: \"0x45\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("offset must be <= 1500"), "got: {}", err);
    }

    #[test]
    fn reject_byte_match_mask_length_mismatch() {
        let yaml = valid_yaml(
            "    - name: bad_mask\n      priority: 100\n      match:\n        byte_match:\n          - offset: 14\n            value: \"0x4500\"\n            mask: \"0xf0\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("mask length"), "got: {}", err);
    }

    #[test]
    fn mac_contains_detection() {
        assert!(mac_pattern_contains("*:*:*:*:*:*", "ff:ff:ff:ff:ff:ff"));
        assert!(!mac_pattern_contains("ff:ff:ff:ff:ff:ff", "*:*:*:*:*:*"));
        assert!(mac_pattern_contains("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_pattern_contains("00:1a:2b:cc:dd:ee", "00:1a:2b:*:*:*"));
    }

    #[test]
    fn cidr_contains_subnet() {
        assert!(cidr_contains("10.0.0.0/8", "10.1.0.0/16"));
        assert!(cidr_contains("10.0.0.0/8", "10.255.255.255/32"));
        assert!(!cidr_contains("10.1.0.0/16", "10.0.0.0/8")); // narrower doesn't contain wider
        assert!(cidr_contains("0.0.0.0/0", "192.168.1.0/24")); // /0 contains everything
        assert!(cidr_contains("192.168.1.0/24", "192.168.1.100/32")); // /24 contains host
        assert!(!cidr_contains("192.168.1.0/24", "192.168.2.0/24")); // different subnets
    }

    #[test]
    fn cidr_overlaps_detection() {
        assert!(cidr_overlaps("10.0.0.0/8", "10.1.0.0/16")); // containment → overlap
        assert!(cidr_overlaps("10.1.0.0/16", "10.0.0.0/8")); // reverse containment
        assert!(!cidr_overlaps("10.0.0.0/8", "172.16.0.0/12")); // disjoint
        assert!(cidr_overlaps("192.168.0.0/16", "192.168.1.0/24")); // subset
        assert!(!cidr_overlaps("192.168.1.0/24", "192.168.2.0/24")); // adjacent but disjoint
    }

    #[test]
    fn port_contains_detection() {
        use crate::model::PortMatch;
        assert!(port_contains(&PortMatch::Range { range: [1, 1024] }, &PortMatch::Exact(80)));
        assert!(port_contains(&PortMatch::Range { range: [1, 1024] }, &PortMatch::Range { range: [80, 443] }));
        assert!(!port_contains(&PortMatch::Exact(80), &PortMatch::Range { range: [1, 1024] }));
        assert!(port_contains(&PortMatch::Exact(80), &PortMatch::Exact(80)));
    }

    #[test]
    fn port_ranges_overlap_detection() {
        use crate::model::PortMatch;
        assert!(port_ranges_overlap(&PortMatch::Range { range: [1, 100] }, &PortMatch::Range { range: [50, 200] }));
        assert!(!port_ranges_overlap(&PortMatch::Range { range: [1, 100] }, &PortMatch::Range { range: [101, 200] }));
        assert!(port_ranges_overlap(&PortMatch::Exact(80), &PortMatch::Range { range: [1, 1024] }));
        assert!(!port_ranges_overlap(&PortMatch::Exact(80), &PortMatch::Exact(443)));
    }

    // --- Dynamic mode validation ---

    fn make_simple_config() -> FilterConfig {
        serde_yaml::from_str(r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_http
      priority: 100
      match:
        ethertype: "0x0800"
        dst_port: 80
      action: pass
"#).unwrap()
    }

    #[test]
    fn dynamic_rejects_fsm_rules() {
        let config: FilterConfig = serde_yaml::from_str(r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: fsm_rule
      type: stateful
      priority: 100
      fsm:
        initial_state: idle
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: idle
                action: pass
"#).unwrap();
        let result = validate_dynamic(&config, false, 16);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("stateful"));
    }

    #[test]
    fn dynamic_rejects_conntrack() {
        let config = make_simple_config();
        let result = validate_dynamic(&config, true, 16);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conntrack"));
    }

    #[test]
    fn dynamic_rejects_ipv6() {
        let config: FilterConfig = serde_yaml::from_str(r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_rule
      priority: 100
      match:
        src_ipv6: "2001:db8::/32"
      action: pass
"#).unwrap();
        let result = validate_dynamic(&config, false, 16);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("IPv6"));
    }

    #[test]
    fn dynamic_rejects_entries_out_of_bounds() {
        let config = make_simple_config();
        assert!(validate_dynamic(&config, false, 0).is_err());
        assert!(validate_dynamic(&config, false, 257).is_err());
    }

    #[test]
    fn dynamic_accepts_valid_l2l3l4() {
        let config = make_simple_config();
        assert!(validate_dynamic(&config, false, 16).is_ok());
    }

    #[test]
    fn reject_dscp_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad_dscp\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_dscp: 64\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ip_dscp must be 0-63"));
    }

    #[test]
    fn reject_ecn_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad_ecn\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_ecn: 4\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ip_ecn must be 0-3"));
    }

    #[test]
    fn accept_valid_dscp_ecn() {
        let yaml = valid_yaml(
            "    - name: ef_rule\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_dscp: 46\n        ip_ecn: 1\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn accept_dscp_zero_ecn_zero() {
        let yaml = valid_yaml(
            "    - name: be_rule\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_dscp: 0\n        ip_ecn: 0\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_ipv6_dscp_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        ipv6_dscp: 64\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ipv6_dscp must be 0-63"));
    }

    #[test]
    fn reject_ipv6_ecn_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        ipv6_ecn: 4\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ipv6_ecn must be 0-3"));
    }

    #[test]
    fn reject_tcp_flags_mask_without_flags() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        tcp_flags_mask: 0x12\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tcp_flags_mask requires tcp_flags"));
    }

    #[test]
    fn reject_icmp_code_without_type() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        icmp_code: 0\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("icmp_code requires icmp_type"));
    }

    #[test]
    fn accept_valid_tcp_flags() {
        let yaml = valid_yaml(
            "    - name: syn\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_protocol: 6\n        tcp_flags: 2\n        tcp_flags_mask: 18\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn accept_valid_icmp_type_code() {
        let yaml = valid_yaml(
            "    - name: echo\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n        ip_protocol: 1\n        icmp_type: 8\n        icmp_code: 0\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_icmpv6_code_without_type() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        icmpv6_code: 0\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("icmpv6_code requires icmpv6_type"));
    }

    #[test]
    fn reject_arp_opcode_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n        arp_opcode: 3\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("arp_opcode must be 1 (request) or 2 (reply)"));
    }

    #[test]
    fn reject_ipv6_flow_label_too_large() {
        let yaml = valid_yaml(
            "    - name: bad\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        ipv6_flow_label: 1048576\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ipv6_flow_label must be 0-1048575"));
    }

    #[test]
    fn accept_valid_icmpv6() {
        let yaml = valid_yaml(
            "    - name: ndp_ns\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        ipv6_next_header: 58\n        icmpv6_type: 135\n        icmpv6_code: 0\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn accept_valid_arp() {
        let yaml = valid_yaml(
            "    - name: arp_req\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n        arp_opcode: 1\n        arp_spa: \"10.0.0.1\"\n        arp_tpa: \"10.0.0.2\"\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn accept_valid_ipv6_ext() {
        let yaml = valid_yaml(
            "    - name: ipv6_ext\n      priority: 100\n      match:\n        ethertype: \"0x86DD\"\n        ipv6_hop_limit: 64\n        ipv6_flow_label: 12345\n      action: pass",
        );
        let result = load_rules_from_str(&yaml);
        assert!(result.is_ok());
    }
}
