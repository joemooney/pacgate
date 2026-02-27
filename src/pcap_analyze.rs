//! PCAP Traffic Analysis + Automatic Rule Suggestion Engine
//!
//! Parses PCAP packets at L2/L3/L4, aggregates flows, analyzes traffic patterns,
//! and suggests PacGate YAML rules automatically.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::pcap::PcapPacket;

/// L2/L3/L4 fields extracted from a raw Ethernet frame
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub src_ipv6: Option<Ipv6Addr>,
    pub dst_ipv6: Option<Ipv6Addr>,
    pub ip_protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vxlan_vni: Option<u32>,
    pub frame_len: usize,
    pub timestamp: f64,
}

/// 5-tuple flow identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} -> {}:{} proto={}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
    }
}

/// Per-flow aggregated statistics
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: f64,
    pub last_seen: f64,
}

/// Overall traffic analysis summary
#[derive(Debug, Clone)]
pub struct TrafficAnalysis {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub flows: Vec<FlowStats>,
    pub protocol_distribution: HashMap<String, u64>,
    pub top_dst_ports: Vec<(u16, u64)>,
    pub top_src_ips: Vec<(String, u64)>,
    pub top_dst_ips: Vec<(String, u64)>,
    pub ethertype_distribution: HashMap<u16, u64>,
    pub duration_secs: f64,
}

/// Suggest mode for rule generation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SuggestMode {
    Whitelist,
    Blacklist,
    Auto,
}

impl SuggestMode {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "whitelist" | "allow" => Ok(SuggestMode::Whitelist),
            "blacklist" | "deny" => Ok(SuggestMode::Blacklist),
            "auto" => Ok(SuggestMode::Auto),
            _ => anyhow::bail!("Invalid suggest mode '{}': expected whitelist, blacklist, or auto", s),
        }
    }
}

/// A suggested PacGate rule
#[derive(Debug, Clone)]
pub struct SuggestedRule {
    pub name: String,
    pub priority: u32,
    pub action: String,
    pub ethertype: Option<String>,
    pub ip_protocol: Option<u8>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub rationale: String,
    pub confidence: f64,
}

/// Parse a raw Ethernet frame into structured fields (mirrors frame_parser.v logic)
pub fn parse_packet(pkt: &PcapPacket) -> ParsedPacket {
    let data = &pkt.data;
    let frame_len = data.len();
    let timestamp = pkt.ts_sec as f64 + pkt.ts_usec as f64 / 1_000_000.0;

    let mut result = ParsedPacket {
        dst_mac: [0u8; 6],
        src_mac: [0u8; 6],
        ethertype: 0,
        vlan_id: None,
        src_ip: None,
        dst_ip: None,
        src_ipv6: None,
        dst_ipv6: None,
        ip_protocol: None,
        src_port: None,
        dst_port: None,
        vxlan_vni: None,
        frame_len,
        timestamp,
    };

    if data.len() < 14 {
        return result;
    }

    // L2: Ethernet header
    result.dst_mac.copy_from_slice(&data[0..6]);
    result.src_mac.copy_from_slice(&data[6..12]);

    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Check for 802.1Q VLAN tag
    if ethertype == 0x8100 && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        result.vlan_id = Some(tci & 0x0FFF);
        offset += 2;
        ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
    }

    result.ethertype = ethertype;

    // L3: IPv4
    if ethertype == 0x0800 && data.len() >= offset + 20 {
        let ihl = (data[offset] & 0x0F) as usize * 4;
        result.ip_protocol = Some(data[offset + 9]);
        result.src_ip = Some(Ipv4Addr::new(
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ));
        result.dst_ip = Some(Ipv4Addr::new(
            data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19],
        ));

        let l4_offset = offset + ihl;

        // L4: TCP/UDP
        if let Some(proto) = result.ip_protocol {
            if (proto == 6 || proto == 17) && data.len() >= l4_offset + 4 {
                result.src_port = Some(u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]));
                result.dst_port = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));

                // VXLAN: UDP dst port 4789 + 8-byte VXLAN header
                if proto == 17 && result.dst_port == Some(4789) && data.len() >= l4_offset + 16 {
                    let vni_offset = l4_offset + 8; // UDP header (8) = start of VXLAN header
                    let vni = ((data[vni_offset + 4] as u32) << 16)
                        | ((data[vni_offset + 5] as u32) << 8)
                        | (data[vni_offset + 6] as u32);
                    result.vxlan_vni = Some(vni >> 8); // VNI is top 24 bits
                }
            }
        }
    }

    // L3: IPv6
    if ethertype == 0x86DD && data.len() >= offset + 40 {
        result.ip_protocol = Some(data[offset + 6]); // next_header
        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
        dst_bytes.copy_from_slice(&data[offset + 24..offset + 40]);
        result.src_ipv6 = Some(Ipv6Addr::from(src_bytes));
        result.dst_ipv6 = Some(Ipv6Addr::from(dst_bytes));

        let l4_offset = offset + 40;
        if let Some(proto) = result.ip_protocol {
            if (proto == 6 || proto == 17) && data.len() >= l4_offset + 4 {
                result.src_port = Some(u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]));
                result.dst_port = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));
            }
        }
    }

    result
}

/// Aggregate packets into flows by 5-tuple
pub fn extract_flows(packets: &[ParsedPacket]) -> Vec<FlowStats> {
    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();

    for pkt in packets {
        let src_ip = pkt.src_ip.map(|ip| ip.to_string())
            .or_else(|| pkt.src_ipv6.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let dst_ip = pkt.dst_ip.map(|ip| ip.to_string())
            .or_else(|| pkt.dst_ipv6.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "0.0.0.0".to_string());

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            protocol: pkt.ip_protocol.unwrap_or(0),
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
        };

        let entry = flows.entry(key.clone()).or_insert_with(|| FlowStats {
            key: key.clone(),
            packet_count: 0,
            byte_count: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
        });
        entry.packet_count += 1;
        entry.byte_count += pkt.frame_len as u64;
        if pkt.timestamp < entry.first_seen {
            entry.first_seen = pkt.timestamp;
        }
        if pkt.timestamp > entry.last_seen {
            entry.last_seen = pkt.timestamp;
        }
    }

    let mut result: Vec<FlowStats> = flows.into_values().collect();
    result.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    result
}

/// Analyze traffic patterns
pub fn analyze_traffic(packets: &[ParsedPacket]) -> TrafficAnalysis {
    let total_packets = packets.len() as u64;
    let total_bytes: u64 = packets.iter().map(|p| p.frame_len as u64).sum();

    // Protocol distribution
    let mut protocol_distribution: HashMap<String, u64> = HashMap::new();
    for pkt in packets {
        let proto_name = match pkt.ip_protocol {
            Some(1) => "ICMP".to_string(),
            Some(6) => "TCP".to_string(),
            Some(17) => "UDP".to_string(),
            Some(58) => "ICMPv6".to_string(),
            Some(p) => format!("proto_{}", p),
            None => match pkt.ethertype {
                0x0806 => "ARP".to_string(),
                0x86DD => "IPv6_other".to_string(),
                _ => format!("etype_0x{:04x}", pkt.ethertype),
            },
        };
        *protocol_distribution.entry(proto_name).or_default() += 1;
    }

    // EtherType distribution
    let mut ethertype_distribution: HashMap<u16, u64> = HashMap::new();
    for pkt in packets {
        *ethertype_distribution.entry(pkt.ethertype).or_default() += 1;
    }

    // Top destination ports
    let mut dst_port_counts: HashMap<u16, u64> = HashMap::new();
    for pkt in packets {
        if let Some(port) = pkt.dst_port {
            *dst_port_counts.entry(port).or_default() += 1;
        }
    }
    let mut top_dst_ports: Vec<(u16, u64)> = dst_port_counts.into_iter().collect();
    top_dst_ports.sort_by(|a, b| b.1.cmp(&a.1));
    top_dst_ports.truncate(20);

    // Top source IPs
    let mut src_ip_counts: HashMap<String, u64> = HashMap::new();
    for pkt in packets {
        if let Some(ip) = &pkt.src_ip {
            *src_ip_counts.entry(ip.to_string()).or_default() += 1;
        } else if let Some(ip) = &pkt.src_ipv6 {
            *src_ip_counts.entry(ip.to_string()).or_default() += 1;
        }
    }
    let mut top_src_ips: Vec<(String, u64)> = src_ip_counts.into_iter().collect();
    top_src_ips.sort_by(|a, b| b.1.cmp(&a.1));
    top_src_ips.truncate(20);

    // Top destination IPs
    let mut dst_ip_counts: HashMap<String, u64> = HashMap::new();
    for pkt in packets {
        if let Some(ip) = &pkt.dst_ip {
            *dst_ip_counts.entry(ip.to_string()).or_default() += 1;
        } else if let Some(ip) = &pkt.dst_ipv6 {
            *dst_ip_counts.entry(ip.to_string()).or_default() += 1;
        }
    }
    let mut top_dst_ips: Vec<(String, u64)> = dst_ip_counts.into_iter().collect();
    top_dst_ips.sort_by(|a, b| b.1.cmp(&a.1));
    top_dst_ips.truncate(20);

    let flows = extract_flows(packets);
    let duration_secs = if packets.len() > 1 {
        let first = packets.iter().map(|p| p.timestamp).fold(f64::INFINITY, f64::min);
        let last = packets.iter().map(|p| p.timestamp).fold(f64::NEG_INFINITY, f64::max);
        last - first
    } else {
        0.0
    };

    TrafficAnalysis {
        total_packets,
        total_bytes,
        flows,
        protocol_distribution,
        top_dst_ports,
        top_src_ips,
        top_dst_ips,
        ethertype_distribution,
        duration_secs,
    }
}

/// Suggest PacGate rules from traffic analysis
pub fn suggest_rules(analysis: &TrafficAnalysis, mode: SuggestMode, max_rules: usize) -> Vec<SuggestedRule> {
    let effective_mode = if mode == SuggestMode::Auto {
        if analysis.flows.len() > 100 {
            SuggestMode::Blacklist
        } else {
            SuggestMode::Whitelist
        }
    } else {
        mode
    };

    match effective_mode {
        SuggestMode::Whitelist => suggest_whitelist(analysis, max_rules),
        SuggestMode::Blacklist => suggest_blacklist(analysis, max_rules),
        SuggestMode::Auto => unreachable!(),
    }
}

fn suggest_whitelist(analysis: &TrafficAnalysis, max_rules: usize) -> Vec<SuggestedRule> {
    let mut rules = Vec::new();
    let mut priority = 200u32;

    // Group flows by (ethertype, protocol, dst_port)
    let mut groups: HashMap<(u16, u8, u16), Vec<&FlowStats>> = HashMap::new();
    for flow in &analysis.flows {
        // Determine ethertype from flow
        let ethertype = if flow.key.src_ip.contains(':') { 0x86DDu16 } else { 0x0800u16 };
        let key = (ethertype, flow.key.protocol, flow.key.dst_port);
        groups.entry(key).or_default().push(flow);
    }

    // Create a rule for each service group
    let mut sorted_groups: Vec<_> = groups.into_iter().collect();
    sorted_groups.sort_by(|a, b| {
        let a_pkts: u64 = a.1.iter().map(|f| f.packet_count).sum();
        let b_pkts: u64 = b.1.iter().map(|f| f.packet_count).sum();
        b_pkts.cmp(&a_pkts)
    });

    for ((ethertype, protocol, dst_port), flows) in sorted_groups.iter().take(max_rules) {
        let total_pkts: u64 = flows.iter().map(|f| f.packet_count).sum();
        let confidence = (total_pkts as f64 / analysis.total_packets as f64).min(1.0);

        let proto_name = match protocol {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            58 => "icmpv6",
            _ => "other",
        };

        let port_name = match dst_port {
            22 => "ssh",
            53 => "dns",
            80 => "http",
            443 => "https",
            _ if *dst_port > 0 => &format!("port_{}", dst_port),
            _ => proto_name,
        };
        let port_name = port_name.to_string();

        let name = format!("allow_{}_{}", proto_name, port_name);

        let mut rule = SuggestedRule {
            name,
            priority,
            action: "pass".to_string(),
            ethertype: Some(format!("0x{:04X}", ethertype)),
            ip_protocol: if *protocol > 0 { Some(*protocol) } else { None },
            src_ip: None,
            dst_ip: None,
            dst_port: if *dst_port > 0 { Some(*dst_port) } else { None },
            rationale: format!("{} packets across {} flows", total_pkts, flows.len()),
            confidence,
        };

        // If all flows come from same subnet, add src_ip CIDR
        if flows.len() == 1 {
            let ip = &flows[0].key.src_ip;
            if !ip.is_empty() && ip != "0.0.0.0" {
                rule.src_ip = Some(format!("{}/32", ip));
            }
        }

        rules.push(rule);
        priority = priority.saturating_sub(10);
    }

    // Always suggest ARP allow in whitelist mode
    let has_arp = analysis.ethertype_distribution.contains_key(&0x0806);
    if has_arp {
        rules.push(SuggestedRule {
            name: "allow_arp".to_string(),
            priority: 50,
            action: "pass".to_string(),
            ethertype: Some("0x0806".to_string()),
            ip_protocol: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            rationale: "ARP required for address resolution".to_string(),
            confidence: 1.0,
        });
    }

    rules
}

fn suggest_blacklist(analysis: &TrafficAnalysis, max_rules: usize) -> Vec<SuggestedRule> {
    let mut rules = Vec::new();
    let mut priority = 200u32;

    // Detect port scans: many dst_ports from single source
    let mut src_port_diversity: HashMap<String, std::collections::HashSet<u16>> = HashMap::new();
    for flow in &analysis.flows {
        if flow.key.dst_port > 0 {
            src_port_diversity
                .entry(flow.key.src_ip.clone())
                .or_default()
                .insert(flow.key.dst_port);
        }
    }

    for (src_ip, ports) in &src_port_diversity {
        if ports.len() > 10 && rules.len() < max_rules {
            rules.push(SuggestedRule {
                name: format!("block_scanner_{}", src_ip.replace(['.', ':'], "_")),
                priority,
                action: "drop".to_string(),
                ethertype: Some("0x0800".to_string()),
                ip_protocol: None,
                src_ip: Some(format!("{}/32", src_ip)),
                dst_ip: None,
                dst_port: None,
                rationale: format!("Possible port scan: {} unique dst ports from {}", ports.len(), src_ip),
                confidence: 0.7,
            });
            priority = priority.saturating_sub(10);
        }
    }

    // Detect flood: high packet rate from single source
    if analysis.duration_secs > 0.0 {
        let mut src_pps: HashMap<String, f64> = HashMap::new();
        for flow in &analysis.flows {
            *src_pps.entry(flow.key.src_ip.clone()).or_default() +=
                flow.packet_count as f64 / analysis.duration_secs;
        }
        for (src_ip, pps) in &src_pps {
            if *pps > 10000.0 && rules.len() < max_rules && src_ip != "0.0.0.0" {
                rules.push(SuggestedRule {
                    name: format!("block_flood_{}", src_ip.replace(['.', ':'], "_")),
                    priority,
                    action: "drop".to_string(),
                    ethertype: Some("0x0800".to_string()),
                    ip_protocol: None,
                    src_ip: Some(format!("{}/32", src_ip)),
                    dst_ip: None,
                    dst_port: None,
                    rationale: format!("Possible flood: {:.0} pps from {}", pps, src_ip),
                    confidence: 0.6,
                });
                priority = priority.saturating_sub(10);
            }
        }
    }

    rules
}

/// Convert suggested rules to valid PacGate YAML
pub fn suggestions_to_yaml(suggestions: &[SuggestedRule], default_action: &str) -> String {
    let mut yaml = String::new();
    yaml.push_str("# PacGate Rules — Auto-generated from PCAP analysis\n");
    yaml.push_str("# Review and adjust before deploying to hardware\n\n");
    yaml.push_str("pacgate:\n");
    yaml.push_str("  version: \"1.0\"\n");
    yaml.push_str("  defaults:\n");
    yaml.push_str(&format!("    action: {}\n", default_action));
    yaml.push_str("\n  rules:\n");

    for rule in suggestions {
        yaml.push_str(&format!("    # {} (confidence: {:.0}%)\n", rule.rationale, rule.confidence * 100.0));
        yaml.push_str(&format!("    - name: {}\n", rule.name));
        yaml.push_str("      type: stateless\n");
        yaml.push_str(&format!("      priority: {}\n", rule.priority));
        yaml.push_str("      match:\n");
        if let Some(ref et) = rule.ethertype {
            yaml.push_str(&format!("        ethertype: \"{}\"\n", et));
        }
        if let Some(proto) = rule.ip_protocol {
            yaml.push_str(&format!("        ip_protocol: {}\n", proto));
        }
        if let Some(ref ip) = rule.src_ip {
            yaml.push_str(&format!("        src_ip: \"{}\"\n", ip));
        }
        if let Some(ref ip) = rule.dst_ip {
            yaml.push_str(&format!("        dst_ip: \"{}\"\n", ip));
        }
        if let Some(port) = rule.dst_port {
            yaml.push_str(&format!("        dst_port: {}\n", port));
        }
        yaml.push_str(&format!("      action: {}\n\n", rule.action));
    }

    yaml
}

/// Print analysis summary to stdout
pub fn print_analysis(analysis: &TrafficAnalysis) {
    println!();
    println!("  PacGate PCAP Traffic Analysis");
    println!("  ════════════════════════════════════════════");
    println!("  Total packets: {}", analysis.total_packets);
    println!("  Total bytes:   {}", analysis.total_bytes);
    println!("  Duration:      {:.2}s", analysis.duration_secs);
    println!("  Unique flows:  {}", analysis.flows.len());
    println!();

    // EtherType distribution
    println!("  EtherType Distribution:");
    let mut etype_sorted: Vec<_> = analysis.ethertype_distribution.iter().collect();
    etype_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (etype, count) in etype_sorted.iter().take(10) {
        let name = match etype {
            0x0800 => "IPv4",
            0x0806 => "ARP",
            0x86DD => "IPv6",
            0x8100 => "802.1Q",
            _ => "",
        };
        let pct = **count as f64 / analysis.total_packets as f64 * 100.0;
        println!("    0x{:04X} {:6} {:>6} ({:.1}%)", etype, name, count, pct);
    }
    println!();

    // Protocol distribution
    println!("  Protocol Distribution:");
    let mut proto_sorted: Vec<_> = analysis.protocol_distribution.iter().collect();
    proto_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in proto_sorted.iter().take(10) {
        let pct = **count as f64 / analysis.total_packets as f64 * 100.0;
        println!("    {:10} {:>6} ({:.1}%)", proto, count, pct);
    }
    println!();

    // Top destination ports
    if !analysis.top_dst_ports.is_empty() {
        println!("  Top Destination Ports:");
        for (port, count) in analysis.top_dst_ports.iter().take(10) {
            let svc = match port {
                22 => "SSH", 53 => "DNS", 80 => "HTTP", 443 => "HTTPS",
                123 => "NTP", 4789 => "VXLAN", 8080 => "HTTP-ALT",
                _ => "",
            };
            println!("    {:>5} {:8} {:>6}", port, svc, count);
        }
        println!();
    }

    // Top flows
    println!("  Top Flows:");
    println!("    {:40} {:>8} {:>10}", "Flow", "Packets", "Bytes");
    println!("    {:40} {:>8} {:>10}", "────", "───────", "─────");
    for flow in analysis.flows.iter().take(10) {
        println!("    {:40} {:>8} {:>10}",
            flow.key.to_string(), flow.packet_count, flow.byte_count);
    }
    println!();
}

/// Convert analysis to JSON
pub fn analysis_to_json(analysis: &TrafficAnalysis, suggestions: &[SuggestedRule]) -> serde_json::Value {
    let flows_json: Vec<serde_json::Value> = analysis.flows.iter().take(50).map(|f| {
        serde_json::json!({
            "src_ip": f.key.src_ip,
            "dst_ip": f.key.dst_ip,
            "protocol": f.key.protocol,
            "src_port": f.key.src_port,
            "dst_port": f.key.dst_port,
            "packets": f.packet_count,
            "bytes": f.byte_count,
        })
    }).collect();

    let suggestions_json: Vec<serde_json::Value> = suggestions.iter().map(|s| {
        serde_json::json!({
            "name": s.name,
            "priority": s.priority,
            "action": s.action,
            "ethertype": s.ethertype,
            "ip_protocol": s.ip_protocol,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "dst_port": s.dst_port,
            "rationale": s.rationale,
            "confidence": s.confidence,
        })
    }).collect();

    let proto_dist: HashMap<String, u64> = analysis.protocol_distribution.clone();
    let etype_dist: Vec<serde_json::Value> = analysis.ethertype_distribution.iter().map(|(k, v)| {
        serde_json::json!({"ethertype": format!("0x{:04X}", k), "count": v})
    }).collect();

    serde_json::json!({
        "status": "ok",
        "total_packets": analysis.total_packets,
        "total_bytes": analysis.total_bytes,
        "duration_secs": analysis.duration_secs,
        "unique_flows": analysis.flows.len(),
        "protocol_distribution": proto_dist,
        "ethertype_distribution": etype_dist,
        "top_dst_ports": analysis.top_dst_ports.iter().take(20).map(|(p, c)| {
            serde_json::json!({"port": p, "count": c})
        }).collect::<Vec<_>>(),
        "top_flows": flows_json,
        "suggested_rules": suggestions_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::PcapPacket;

    /// Helper: build a minimal IPv4 TCP packet
    fn make_ipv4_tcp_packet(
        src_ip: [u8; 4], dst_ip: [u8; 4],
        src_port: u16, dst_port: u16,
        ts_sec: u32,
    ) -> PcapPacket {
        let mut data = Vec::new();
        // Ethernet header
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst mac
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src mac
        data.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4

        // IPv4 header (20 bytes)
        data.push(0x45); // version + IHL
        data.push(0x00); // DSCP + ECN
        data.extend_from_slice(&60u16.to_be_bytes()); // total length
        data.extend_from_slice(&[0, 0]); // identification
        data.extend_from_slice(&[0, 0]); // flags + fragment offset
        data.push(64); // TTL
        data.push(6); // protocol = TCP
        data.extend_from_slice(&[0, 0]); // checksum
        data.extend_from_slice(&src_ip);
        data.extend_from_slice(&dst_ip);

        // TCP header (first 4 bytes: ports)
        data.extend_from_slice(&src_port.to_be_bytes());
        data.extend_from_slice(&dst_port.to_be_bytes());
        // Pad to at least 54 bytes
        while data.len() < 60 {
            data.push(0);
        }

        PcapPacket { ts_sec, ts_usec: 0, data }
    }

    fn make_arp_packet(ts_sec: u32) -> PcapPacket {
        let mut data = vec![0xff; 6]; // dst mac broadcast
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src mac
        data.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
        data.extend_from_slice(&[0u8; 28]); // ARP payload
        while data.len() < 60 { data.push(0); }
        PcapPacket { ts_sec, ts_usec: 0, data }
    }

    #[test]
    fn parse_ipv4_tcp() {
        let pkt = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.src_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.dst_ip, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(parsed.ip_protocol, Some(6));
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.dst_port, Some(80));
    }

    #[test]
    fn parse_arp() {
        let pkt = make_arp_packet(0);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x0806);
        assert_eq!(parsed.dst_mac, [0xff; 6]);
        assert!(parsed.src_ip.is_none());
        assert!(parsed.ip_protocol.is_none());
    }

    #[test]
    fn parse_short_frame() {
        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data: vec![0; 10] };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0);
        assert_eq!(parsed.frame_len, 10);
    }

    #[test]
    fn parse_vlan_tagged() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        data.extend_from_slice(&[0x81, 0x00]); // 802.1Q
        data.extend_from_slice(&[0x00, 100]); // VLAN ID=100, PCP=0
        data.extend_from_slice(&[0x08, 0x00]); // actual ethertype = IPv4
        // Minimal IPv4 header
        data.push(0x45); data.push(0); data.extend_from_slice(&[0, 40]);
        data.extend_from_slice(&[0; 4]); // id, flags
        data.push(64); data.push(17); // TTL, UDP
        data.extend_from_slice(&[0, 0]); // checksum
        data.extend_from_slice(&[192, 168, 1, 1]); // src
        data.extend_from_slice(&[192, 168, 1, 2]); // dst
        // UDP ports
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(&53u16.to_be_bytes());
        while data.len() < 64 { data.push(0); }

        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.vlan_id, Some(100));
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.ip_protocol, Some(17));
        assert_eq!(parsed.src_port, Some(53));
    }

    #[test]
    fn extract_flows_groups_by_5tuple() {
        let packets: Vec<ParsedPacket> = (0..10).map(|_| {
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0))
        }).collect();
        let flows = extract_flows(&packets);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packet_count, 10);
    }

    #[test]
    fn extract_flows_separate_ports() {
        let mut packets = Vec::new();
        packets.push(parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0)));
        packets.push(parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443, 0)));
        let flows = extract_flows(&packets);
        assert_eq!(flows.len(), 2);
    }

    #[test]
    fn analyze_traffic_basic() {
        let packets: Vec<ParsedPacket> = vec![
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0)),
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 1)),
            parse_packet(&make_arp_packet(2)),
        ];
        let analysis = analyze_traffic(&packets);
        assert_eq!(analysis.total_packets, 3);
        assert!(analysis.protocol_distribution.contains_key("TCP"));
        assert!(analysis.protocol_distribution.contains_key("ARP"));
    }

    #[test]
    fn suggest_whitelist_rules() {
        let packets: Vec<ParsedPacket> = (0..20).map(|i| {
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, i))
        }).collect();
        let analysis = analyze_traffic(&packets);
        let suggestions = suggest_rules(&analysis, SuggestMode::Whitelist, 10);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().all(|s| s.action == "pass"));
    }

    #[test]
    fn suggest_blacklist_detects_scan() {
        // Create packets from single source to many ports
        let packets: Vec<ParsedPacket> = (0..20).map(|i| {
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 99], [10, 0, 0, 2], 12345, 1000 + i as u16, i))
        }).collect();
        let analysis = analyze_traffic(&packets);
        let suggestions = suggest_rules(&analysis, SuggestMode::Blacklist, 10);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.name.contains("scanner")));
    }

    #[test]
    fn suggest_auto_picks_mode() {
        // Few flows → whitelist
        let packets: Vec<ParsedPacket> = (0..5).map(|i| {
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, i))
        }).collect();
        let analysis = analyze_traffic(&packets);
        let suggestions = suggest_rules(&analysis, SuggestMode::Auto, 10);
        assert!(suggestions.iter().all(|s| s.action == "pass")); // whitelist mode
    }

    #[test]
    fn suggestions_to_yaml_valid() {
        let rules = vec![SuggestedRule {
            name: "allow_tcp_http".to_string(),
            priority: 200,
            action: "pass".to_string(),
            ethertype: Some("0x0800".to_string()),
            ip_protocol: Some(6),
            src_ip: None,
            dst_ip: None,
            dst_port: Some(80),
            rationale: "HTTP traffic".to_string(),
            confidence: 0.9,
        }];
        let yaml = suggestions_to_yaml(&rules, "drop");
        assert!(yaml.contains("pacgate:"));
        assert!(yaml.contains("allow_tcp_http"));
        assert!(yaml.contains("ip_protocol: 6"));
        assert!(yaml.contains("dst_port: 80"));
        assert!(yaml.contains("action: drop"));
    }

    #[test]
    fn suggest_mode_from_str() {
        assert_eq!(SuggestMode::from_str("whitelist").unwrap(), SuggestMode::Whitelist);
        assert_eq!(SuggestMode::from_str("blacklist").unwrap(), SuggestMode::Blacklist);
        assert_eq!(SuggestMode::from_str("auto").unwrap(), SuggestMode::Auto);
        assert!(SuggestMode::from_str("invalid").is_err());
    }

    #[test]
    fn analysis_to_json_has_fields() {
        let packets: Vec<ParsedPacket> = vec![
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0)),
        ];
        let analysis = analyze_traffic(&packets);
        let suggestions = suggest_rules(&analysis, SuggestMode::Whitelist, 10);
        let json = analysis_to_json(&analysis, &suggestions);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["total_packets"], 1);
        assert!(json["top_flows"].is_array());
        assert!(json["suggested_rules"].is_array());
    }

    #[test]
    fn parse_ipv6_tcp() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        data.extend_from_slice(&[0x86, 0xDD]); // ethertype IPv6
        // IPv6 header (40 bytes)
        data.push(0x60); data.extend_from_slice(&[0, 0, 0]); // version + TC + flow label
        data.extend_from_slice(&20u16.to_be_bytes()); // payload length
        data.push(6); // next header = TCP
        data.push(64); // hop limit
        // src addr: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst addr: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // TCP ports
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&8080u16.to_be_bytes());
        while data.len() < 80 { data.push(0); }

        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x86DD);
        assert_eq!(parsed.ip_protocol, Some(6));
        assert!(parsed.src_ipv6.is_some());
        assert!(parsed.dst_ipv6.is_some());
        assert_eq!(parsed.src_port, Some(443));
        assert_eq!(parsed.dst_port, Some(8080));
    }

    #[test]
    fn flow_key_display() {
        let key = FlowKey {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            protocol: 6,
            src_port: 12345,
            dst_port: 80,
        };
        let s = format!("{}", key);
        assert!(s.contains("10.0.0.1"));
        assert!(s.contains("10.0.0.2"));
    }

    #[test]
    fn whitelist_includes_arp() {
        let mut packets: Vec<ParsedPacket> = (0..5).map(|i| {
            parse_packet(&make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, i))
        }).collect();
        packets.push(parse_packet(&make_arp_packet(5)));
        let analysis = analyze_traffic(&packets);
        let suggestions = suggest_rules(&analysis, SuggestMode::Whitelist, 10);
        assert!(suggestions.iter().any(|s| s.name == "allow_arp"));
    }

    #[test]
    fn empty_packets_analysis() {
        let analysis = analyze_traffic(&[]);
        assert_eq!(analysis.total_packets, 0);
        assert_eq!(analysis.flows.len(), 0);
    }
}
