use anyhow::{Result, bail};
use crate::model::{FilterConfig, MatchCriteria, Action, PortMatch, Ipv4Prefix, Ipv6Prefix, MacAddress, ByteMatch, parse_ethertype};

/// Represents a simulated packet with all match-field values
#[derive(Debug, Clone, Default)]
pub struct SimPacket {
    pub ethertype: Option<u16>,
    pub dst_mac: Option<String>,
    pub src_mac: Option<String>,
    pub vlan_id: Option<u16>,
    pub vlan_pcp: Option<u8>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vxlan_vni: Option<u32>,
    pub src_ipv6: Option<String>,
    pub dst_ipv6: Option<String>,
    pub ipv6_next_header: Option<u8>,
    pub raw_bytes: Option<Vec<u8>>,
    pub gtp_teid: Option<u32>,
    pub mpls_label: Option<u32>,
    pub mpls_tc: Option<u8>,
    pub mpls_bos: Option<bool>,
    pub igmp_type: Option<u8>,
    pub mld_type: Option<u8>,
}

/// Result of simulating a packet against the rule set
#[derive(Debug, Clone)]
pub struct SimResult {
    pub rule_name: Option<String>,
    pub action: Action,
    pub is_default: bool,
    pub fields: Vec<FieldMatch>,
}

/// Per-field match breakdown
#[derive(Debug, Clone)]
pub struct FieldMatch {
    pub field: String,
    pub rule_value: String,
    pub packet_value: String,
    pub matches: bool,
}

/// Parse a packet specification string like "ethertype=0x0800,src_ip=10.0.0.1,dst_port=80"
pub fn parse_packet_spec(spec: &str) -> Result<SimPacket> {
    let mut pkt = SimPacket::default();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid field spec '{}': expected key=value", part))?;
        let key = key.trim();
        let value = value.trim();

        match key {
            "ethertype" => {
                pkt.ethertype = Some(parse_ethertype(value)?);
            }
            "dst_mac" => {
                MacAddress::parse(value)?; // validate
                pkt.dst_mac = Some(value.to_string());
            }
            "src_mac" => {
                MacAddress::parse(value)?; // validate
                pkt.src_mac = Some(value.to_string());
            }
            "vlan_id" => {
                pkt.vlan_id = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vlan_id '{}': {}", value, e))?);
            }
            "vlan_pcp" => {
                pkt.vlan_pcp = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vlan_pcp '{}': {}", value, e))?);
            }
            "src_ip" => {
                pkt.src_ip = Some(value.to_string());
            }
            "dst_ip" => {
                pkt.dst_ip = Some(value.to_string());
            }
            "ip_protocol" => {
                pkt.ip_protocol = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ip_protocol '{}': {}", value, e))?);
            }
            "src_port" => {
                pkt.src_port = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad src_port '{}': {}", value, e))?);
            }
            "dst_port" => {
                pkt.dst_port = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad dst_port '{}': {}", value, e))?);
            }
            "vxlan_vni" => {
                pkt.vxlan_vni = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vxlan_vni '{}': {}", value, e))?);
            }
            "src_ipv6" => {
                Ipv6Prefix::parse(value)?; // validate
                pkt.src_ipv6 = Some(value.to_string());
            }
            "dst_ipv6" => {
                Ipv6Prefix::parse(value)?; // validate
                pkt.dst_ipv6 = Some(value.to_string());
            }
            "ipv6_next_header" => {
                pkt.ipv6_next_header = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_next_header '{}': {}", value, e))?);
            }
            "raw_bytes" => {
                pkt.raw_bytes = Some(parse_hex_bytes(value)?);
            }
            "gtp_teid" => {
                pkt.gtp_teid = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad gtp_teid '{}': {}", value, e))?);
            }
            "mpls_label" => {
                pkt.mpls_label = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mpls_label '{}': {}", value, e))?);
            }
            "mpls_tc" => {
                pkt.mpls_tc = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mpls_tc '{}': {}", value, e))?);
            }
            "mpls_bos" => {
                pkt.mpls_bos = Some(value == "true" || value == "1");
            }
            "igmp_type" => {
                pkt.igmp_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad igmp_type '{}': {}", value, e))?);
            }
            "mld_type" => {
                pkt.mld_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mld_type '{}': {}", value, e))?);
            }
            _ => bail!("Unknown packet field '{}'", key),
        }
    }

    Ok(pkt)
}

/// Simulate a packet against the filter configuration, returning the match result
pub fn simulate(config: &FilterConfig, packet: &SimPacket) -> SimResult {
    // Sort rules by priority (highest first) — same order as hardware
    let mut rules = config.pacgate.rules.clone();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Evaluate each stateless rule in priority order (first match wins)
    for rule in &rules {
        if rule.is_stateful() {
            continue; // skip stateful rules in simulation
        }

        let (matches, fields) = match_criteria_against_packet(&rule.match_criteria, packet);
        if matches {
            return SimResult {
                rule_name: Some(rule.name.clone()),
                action: rule.action(),
                is_default: false,
                fields,
            };
        }
    }

    // No rule matched — return default action
    SimResult {
        rule_name: None,
        action: config.pacgate.defaults.action.clone(),
        is_default: true,
        fields: Vec::new(),
    }
}

/// Evaluate match criteria against a packet, returning (overall_match, per-field breakdown)
pub fn match_criteria_against_packet(mc: &MatchCriteria, pkt: &SimPacket) -> (bool, Vec<FieldMatch>) {
    let mut fields = Vec::new();
    let mut all_match = true;

    // Ethertype
    if let Some(ref et_str) = mc.ethertype {
        if let Ok(rule_et) = parse_ethertype(et_str) {
            let pkt_val = pkt.ethertype.map(|v| format!("0x{:04x}", v)).unwrap_or_else(|| "none".to_string());
            let matches = pkt.ethertype.map(|v| v == rule_et).unwrap_or(false);
            fields.push(FieldMatch {
                field: "ethertype".to_string(),
                rule_value: format!("0x{:04x}", rule_et),
                packet_value: pkt_val,
                matches,
            });
            if !matches { all_match = false; }
        }
    }

    // dst_mac
    if let Some(ref rule_mac) = mc.dst_mac {
        let pkt_val = pkt.dst_mac.as_deref().unwrap_or("none");
        let matches = pkt.dst_mac.as_ref().map(|p| mac_matches_pattern(rule_mac, p)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_mac".to_string(),
            rule_value: rule_mac.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_mac
    if let Some(ref rule_mac) = mc.src_mac {
        let pkt_val = pkt.src_mac.as_deref().unwrap_or("none");
        let matches = pkt.src_mac.as_ref().map(|p| mac_matches_pattern(rule_mac, p)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_mac".to_string(),
            rule_value: rule_mac.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // vlan_id
    if let Some(rule_vid) = mc.vlan_id {
        let pkt_val = pkt.vlan_id.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vlan_id.map(|v| v == rule_vid).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vlan_id".to_string(),
            rule_value: rule_vid.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // vlan_pcp
    if let Some(rule_pcp) = mc.vlan_pcp {
        let pkt_val = pkt.vlan_pcp.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vlan_pcp.map(|v| v == rule_pcp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vlan_pcp".to_string(),
            rule_value: rule_pcp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_ip (CIDR matching)
    if let Some(ref rule_ip) = mc.src_ip {
        let pkt_val = pkt.src_ip.as_deref().unwrap_or("none");
        let matches = pkt.src_ip.as_ref().map(|p| ipv4_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_ip".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_ip (CIDR matching)
    if let Some(ref rule_ip) = mc.dst_ip {
        let pkt_val = pkt.dst_ip.as_deref().unwrap_or("none");
        let matches = pkt.dst_ip.as_ref().map(|p| ipv4_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_ip".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_protocol
    if let Some(rule_proto) = mc.ip_protocol {
        let pkt_val = pkt.ip_protocol.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_protocol.map(|v| v == rule_proto).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_protocol".to_string(),
            rule_value: rule_proto.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_port
    if let Some(ref rule_pm) = mc.src_port {
        let pkt_val = pkt.src_port.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.src_port.map(|v| port_matches(v, rule_pm)).unwrap_or(false);
        let rule_str = match rule_pm {
            PortMatch::Exact(p) => p.to_string(),
            PortMatch::Range { range } => format!("{}-{}", range[0], range[1]),
        };
        fields.push(FieldMatch {
            field: "src_port".to_string(),
            rule_value: rule_str,
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_port
    if let Some(ref rule_pm) = mc.dst_port {
        let pkt_val = pkt.dst_port.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.dst_port.map(|v| port_matches(v, rule_pm)).unwrap_or(false);
        let rule_str = match rule_pm {
            PortMatch::Exact(p) => p.to_string(),
            PortMatch::Range { range } => format!("{}-{}", range[0], range[1]),
        };
        fields.push(FieldMatch {
            field: "dst_port".to_string(),
            rule_value: rule_str,
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // vxlan_vni
    if let Some(rule_vni) = mc.vxlan_vni {
        let pkt_val = pkt.vxlan_vni.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vxlan_vni.map(|v| v == rule_vni).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vxlan_vni".to_string(),
            rule_value: rule_vni.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_ipv6 (CIDR matching)
    if let Some(ref rule_ip) = mc.src_ipv6 {
        let pkt_val = pkt.src_ipv6.as_deref().unwrap_or("none");
        let matches = pkt.src_ipv6.as_ref().map(|p| ipv6_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_ipv6".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_ipv6 (CIDR matching)
    if let Some(ref rule_ip) = mc.dst_ipv6 {
        let pkt_val = pkt.dst_ipv6.as_deref().unwrap_or("none");
        let matches = pkt.dst_ipv6.as_ref().map(|p| ipv6_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_ipv6".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // ipv6_next_header
    if let Some(rule_nh) = mc.ipv6_next_header {
        let pkt_val = pkt.ipv6_next_header.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ipv6_next_header.map(|v| v == rule_nh).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_next_header".to_string(),
            rule_value: rule_nh.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // GTP TEID
    if let Some(teid) = mc.gtp_teid {
        let pkt_val = pkt.gtp_teid.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.gtp_teid.map(|v| v == teid).unwrap_or(false);
        fields.push(FieldMatch {
            field: "gtp_teid".to_string(),
            rule_value: teid.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS label
    if let Some(label) = mc.mpls_label {
        let pkt_val = pkt.mpls_label.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_label.map(|v| v == label).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_label".to_string(),
            rule_value: label.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS TC
    if let Some(tc) = mc.mpls_tc {
        let pkt_val = pkt.mpls_tc.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_tc.map(|v| v == tc).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_tc".to_string(),
            rule_value: tc.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS BOS
    if let Some(bos) = mc.mpls_bos {
        let pkt_val = pkt.mpls_bos.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_bos.map(|v| v == bos).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_bos".to_string(),
            rule_value: bos.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // IGMP type
    if let Some(igmp) = mc.igmp_type {
        let pkt_val = pkt.igmp_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.igmp_type.map(|v| v == igmp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "igmp_type".to_string(),
            rule_value: igmp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MLD type
    if let Some(mld) = mc.mld_type {
        let pkt_val = pkt.mld_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mld_type.map(|v| v == mld).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mld_type".to_string(),
            rule_value: mld.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // byte_match
    if let Some(ref byte_matches) = mc.byte_match {
        for bm in byte_matches {
            let (bm_matches, bm_field) = byte_match_against_packet(bm, pkt);
            fields.push(bm_field);
            if !bm_matches { all_match = false; }
        }
    }

    (all_match, fields)
}

/// Evaluate a single byte_match rule against the packet's raw_bytes
fn byte_match_against_packet(bm: &ByteMatch, pkt: &SimPacket) -> (bool, FieldMatch) {
    let offset = bm.offset as usize;
    let value_bytes = ByteMatch::parse_hex_value(&bm.value).unwrap_or_default();
    let mask_bytes = bm.mask.as_ref()
        .and_then(|m| ByteMatch::parse_hex_value(m).ok())
        .unwrap_or_else(|| vec![0xFF; value_bytes.len()]);

    let rule_str = format!("offset={} value={} mask={}", bm.offset, bm.value,
        bm.mask.as_deref().unwrap_or("0xff.."));

    match &pkt.raw_bytes {
        Some(raw) => {
            let mut all_ok = true;
            let mut pkt_hex = String::new();
            for (i, vb) in value_bytes.iter().enumerate() {
                let idx = offset + i;
                if idx >= raw.len() {
                    all_ok = false;
                    pkt_hex.push_str("??");
                } else {
                    let mb = if i < mask_bytes.len() { mask_bytes[i] } else { 0xFF };
                    if (raw[idx] & mb) != (vb & mb) {
                        all_ok = false;
                    }
                    pkt_hex.push_str(&format!("{:02x}", raw[idx]));
                }
            }
            (all_ok, FieldMatch {
                field: format!("byte_match[{}]", bm.offset),
                rule_value: rule_str,
                packet_value: format!("0x{}", pkt_hex),
                matches: all_ok,
            })
        }
        None => {
            (false, FieldMatch {
                field: format!("byte_match[{}]", bm.offset),
                rule_value: rule_str,
                packet_value: "no raw_bytes".to_string(),
                matches: false,
            })
        }
    }
}

/// Parse a hex string like "0x4500deadbeef" into bytes
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 {
        bail!("Hex string must have even number of digits: '{}'", s);
    }
    let mut bytes = Vec::new();
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i+2], 16)
            .map_err(|e| anyhow::anyhow!("Bad hex byte '{}': {}", &s[i..i+2], e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Check if an IPv4 address matches a CIDR prefix
fn ipv4_matches_cidr(addr_str: &str, cidr_str: &str) -> bool {
    let addr = match Ipv4Prefix::parse(addr_str) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let cidr = match Ipv4Prefix::parse(cidr_str) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Apply CIDR mask to both addresses and compare
    for i in 0..4 {
        if (addr.addr[i] & cidr.mask[i]) != (cidr.addr[i] & cidr.mask[i]) {
            return false;
        }
    }
    true
}

/// Check if an IPv6 address matches a CIDR prefix
fn ipv6_matches_cidr(addr_str: &str, cidr_str: &str) -> bool {
    let addr = match Ipv6Prefix::parse(addr_str) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let cidr = match Ipv6Prefix::parse(cidr_str) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Apply CIDR mask to both addresses and compare
    for i in 0..16 {
        if (addr.addr[i] & cidr.mask[i]) != (cidr.addr[i] & cidr.mask[i]) {
            return false;
        }
    }
    true
}

/// Check if a MAC address matches a pattern (with wildcards)
fn mac_matches_pattern(pattern: &str, addr: &str) -> bool {
    let p_parts: Vec<&str> = pattern.split(':').collect();
    let a_parts: Vec<&str> = addr.split(':').collect();
    if p_parts.len() != 6 || a_parts.len() != 6 {
        return false;
    }
    for (pp, ap) in p_parts.iter().zip(a_parts.iter()) {
        if *pp == "*" {
            continue;
        }
        if pp.to_lowercase() != ap.to_lowercase() {
            return false;
        }
    }
    true
}

/// Check if a port value matches a PortMatch (exact or range)
fn port_matches(port: u16, pm: &PortMatch) -> bool {
    match pm {
        PortMatch::Exact(p) => port == *p,
        PortMatch::Range { range } => port >= range[0] && port <= range[1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_config(rules: Vec<StatelessRule>, default: Action) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: default },
                rules,
                conntrack: None,
            },
        }
    }

    #[test]
    fn parse_packet_spec_basic() {
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.dst_port, Some(80));
        assert!(pkt.src_ip.is_none());
    }

    #[test]
    fn parse_packet_spec_all_fields() {
        let pkt = parse_packet_spec(
            "ethertype=0x0800,dst_mac=ff:ff:ff:ff:ff:ff,src_mac=00:11:22:33:44:55,\
             vlan_id=100,vlan_pcp=5,src_ip=10.0.0.1,dst_ip=192.168.1.1,\
             ip_protocol=6,src_port=12345,dst_port=80,vxlan_vni=1000"
        ).unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.dst_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(pkt.vlan_id, Some(100));
        assert_eq!(pkt.ip_protocol, Some(6));
        assert_eq!(pkt.vxlan_vni, Some(1000));
    }

    #[test]
    fn parse_packet_spec_unknown_field() {
        assert!(parse_packet_spec("unknown=123").is_err());
    }

    #[test]
    fn parse_packet_spec_bad_format() {
        assert!(parse_packet_spec("no_equals_sign").is_err());
    }

    #[test]
    fn simulate_matches_first_rule() {
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
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0806").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("allow_arp"));
        assert_eq!(result.action, Action::Pass);
        assert!(!result.is_default);
    }

    #[test]
    fn simulate_default_action() {
        let rules = vec![
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
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = simulate(&config, &pkt);
        assert!(result.rule_name.is_none());
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn simulate_priority_order() {
        let rules = vec![
            StatelessRule {
                name: "low_pri".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
            StatelessRule {
                name: "high_pri".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("high_pri"));
        assert_eq!(result.action, Action::Pass);
    }

    #[test]
    fn simulate_ip_cidr_match() {
        let rules = vec![
            StatelessRule {
                name: "subnet".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_ip: Some("10.0.0.0/8".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_ip=10.1.2.3").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_ip=192.168.1.1").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_port_range() {
        let rules = vec![
            StatelessRule {
                name: "high_ports".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    dst_port: Some(PortMatch::Range { range: [1024, 65535] }),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("dst_port=8080").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_mac_wildcard() {
        let rules = vec![
            StatelessRule {
                name: "vendor".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_mac: Some("00:1a:2b:*:*:*".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_mac=00:1a:2b:cc:dd:ee").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_mac=00:1a:3c:cc:dd:ee").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_multi_field() {
        let rules = vec![
            StatelessRule {
                name: "web_server".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ip_protocol: Some(6),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // All fields match
        let pkt1 = parse_packet_spec("ethertype=0x0800,ip_protocol=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        // Wrong port
        let pkt2 = parse_packet_spec("ethertype=0x0800,ip_protocol=6,dst_port=443").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);

        // Missing protocol
        let pkt3 = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt3).action, Action::Drop);
    }

    #[test]
    fn simulate_field_breakdown() {
        let rules = vec![
            StatelessRule {
                name: "test".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        let result = simulate(&config, &pkt);
        assert!(!result.is_default);
        assert!(result.fields.iter().all(|f| f.matches));
        assert_eq!(result.fields.len(), 2);
    }

    #[test]
    fn ipv4_cidr_matching() {
        assert!(ipv4_matches_cidr("10.1.2.3", "10.0.0.0/8"));
        assert!(ipv4_matches_cidr("10.0.0.1", "10.0.0.0/24"));
        assert!(!ipv4_matches_cidr("192.168.1.1", "10.0.0.0/8"));
        assert!(ipv4_matches_cidr("192.168.1.1", "192.168.1.1"));
        assert!(ipv4_matches_cidr("0.0.0.0", "0.0.0.0/0"));
        assert!(ipv4_matches_cidr("255.255.255.255", "0.0.0.0/0"));
    }

    #[test]
    fn mac_pattern_matching() {
        assert!(mac_matches_pattern("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"));
        assert!(mac_matches_pattern("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_matches_pattern("00:1a:2b:*:*:*", "00:1a:3c:cc:dd:ee"));
        assert!(mac_matches_pattern("*:*:*:*:*:*", "aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn port_matching() {
        assert!(port_matches(80, &PortMatch::Exact(80)));
        assert!(!port_matches(443, &PortMatch::Exact(80)));
        assert!(port_matches(8080, &PortMatch::Range { range: [1024, 65535] }));
        assert!(!port_matches(80, &PortMatch::Range { range: [1024, 65535] }));
        assert!(port_matches(1024, &PortMatch::Range { range: [1024, 65535] }));
    }

    #[test]
    fn simulate_empty_criteria_matches_all() {
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 100,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Pass);
        let pkt = parse_packet_spec("ethertype=0x9999").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("catch_all"));
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn simulate_vxlan_vni() {
        let rules = vec![
            StatelessRule {
                name: "tenant_100".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    vxlan_vni: Some(100),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("vxlan_vni=100").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("vxlan_vni=200").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_ipv6_cidr_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_ipv6_subnet".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_ipv6: Some("2001:db8::/32".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_ipv6=2001:db8::1").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_ipv6=2001:db9::1").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_ipv6_next_header() {
        let rules = vec![
            StatelessRule {
                name: "allow_icmpv6".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ipv6_next_header: Some(58),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("ipv6_next_header=58").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("ipv6_next_header=6").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn ipv6_cidr_matching() {
        assert!(ipv6_matches_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(ipv6_matches_cidr("2001:db8:abcd::1", "2001:db8::/32"));
        assert!(!ipv6_matches_cidr("2001:db9::1", "2001:db8::/32"));
        assert!(ipv6_matches_cidr("fe80::1", "fe80::/10"));
        assert!(ipv6_matches_cidr("::1", "::1/128"));
        assert!(ipv6_matches_cidr("::1", "::1"));
    }

    #[test]
    fn simulate_ipv6_all_fields() {
        let rules = vec![
            StatelessRule {
                name: "ipv6_web".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    src_ipv6: Some("2001:db8::/32".to_string()),
                    ipv6_next_header: Some(6), // TCP
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // All match
        let pkt1 = parse_packet_spec("src_ipv6=2001:db8::1,ipv6_next_header=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        // Wrong subnet
        let pkt2 = parse_packet_spec("src_ipv6=2001:db9::1,ipv6_next_header=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);

        // Wrong port
        let pkt3 = parse_packet_spec("src_ipv6=2001:db8::1,ipv6_next_header=6,dst_port=443").unwrap();
        assert_eq!(simulate(&config, &pkt3).action, Action::Drop);
    }

    #[test]
    fn parse_hex_bytes_basic() {
        let bytes = parse_hex_bytes("0x4500").unwrap();
        assert_eq!(bytes, vec![0x45, 0x00]);
    }

    #[test]
    fn parse_hex_bytes_no_prefix() {
        let bytes = parse_hex_bytes("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_hex_bytes_odd_digits_rejected() {
        assert!(parse_hex_bytes("0x456").is_err());
    }

    #[test]
    fn simulate_byte_match_matches() {
        let rules = vec![
            StatelessRule {
                name: "ip_version".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x45".to_string(), mask: None },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let mut pkt = SimPacket::default();
        pkt.raw_bytes = Some(vec![0x45, 0x00, 0x00, 0x28]);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);
    }

    #[test]
    fn simulate_byte_match_with_mask() {
        let rules = vec![
            StatelessRule {
                name: "ip_version_masked".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x40".to_string(), mask: Some("0xf0".to_string()) },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // 0x45 & 0xf0 = 0x40 == 0x40 & 0xf0 → match
        let mut pkt = SimPacket::default();
        pkt.raw_bytes = Some(vec![0x45, 0x00]);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // 0x60 & 0xf0 = 0x60 != 0x40 → no match
        let mut pkt2 = SimPacket::default();
        pkt2.raw_bytes = Some(vec![0x60, 0x00]);
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_byte_match_no_raw_bytes() {
        let rules = vec![
            StatelessRule {
                name: "byte_rule".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x45".to_string(), mask: None },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // No raw_bytes → no match → default action
        let pkt = SimPacket::default();
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn parse_raw_bytes_in_packet_spec() {
        let pkt = parse_packet_spec("raw_bytes=0x4500deadbeef").unwrap();
        assert_eq!(pkt.raw_bytes, Some(vec![0x45, 0x00, 0xde, 0xad, 0xbe, 0xef]));
    }

    // --- GTP/MPLS/multicast simulation ---

    #[test]
    fn parse_gtp_teid() {
        let pkt = parse_packet_spec("gtp_teid=1000").unwrap();
        assert_eq!(pkt.gtp_teid, Some(1000));
    }

    #[test]
    fn parse_mpls_fields() {
        let pkt = parse_packet_spec("mpls_label=200,mpls_tc=7,mpls_bos=true").unwrap();
        assert_eq!(pkt.mpls_label, Some(200));
        assert_eq!(pkt.mpls_tc, Some(7));
        assert_eq!(pkt.mpls_bos, Some(true));
    }

    #[test]
    fn parse_igmp_type() {
        let pkt = parse_packet_spec("igmp_type=17").unwrap();
        assert_eq!(pkt.igmp_type, Some(17));
    }

    #[test]
    fn parse_mld_type() {
        let pkt = parse_packet_spec("mld_type=130").unwrap();
        assert_eq!(pkt.mld_type, Some(130));
    }

    #[test]
    fn simulate_gtp_teid_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_tunnel".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    gtp_teid: Some(1000),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.gtp_teid = Some(1000);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong TEID → default drop
        pkt.gtp_teid = Some(9999);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_mpls_label_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_vpn".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    mpls_label: Some(200),
                    mpls_bos: Some(true),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.mpls_label = Some(200);
        pkt.mpls_bos = Some(true);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong label → drop
        pkt.mpls_label = Some(300);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_igmp_type_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_igmp".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    igmp_type: Some(17),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.igmp_type = Some(17);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong type → drop
        pkt.igmp_type = Some(22);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_mld_type_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_mld".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    mld_type: Some(130),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.mld_type = Some(130);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);
    }
}
