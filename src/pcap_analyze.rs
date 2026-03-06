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
    // L2 fields
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub vlan_pcp: Option<u8>,
    pub outer_vlan_id: Option<u16>,
    pub outer_vlan_pcp: Option<u8>,
    // L3 IPv4 fields
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub ip_protocol: Option<u8>,
    pub ip_dscp: Option<u8>,
    pub ip_ecn: Option<u8>,
    pub ip_ttl: Option<u8>,
    pub ip_dont_fragment: Option<bool>,
    pub ip_more_fragments: Option<bool>,
    pub ip_frag_offset: Option<u16>,
    // L3 IPv6 fields
    pub src_ipv6: Option<Ipv6Addr>,
    pub dst_ipv6: Option<Ipv6Addr>,
    pub ipv6_next_header: Option<u8>,
    pub ipv6_dscp: Option<u8>,
    pub ipv6_ecn: Option<u8>,
    pub ipv6_hop_limit: Option<u8>,
    pub ipv6_flow_label: Option<u32>,
    // L4 fields
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    // ICMP/ICMPv6
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmpv6_type: Option<u8>,
    pub icmpv6_code: Option<u8>,
    // Multicast
    pub igmp_type: Option<u8>,
    pub mld_type: Option<u8>,
    // ARP
    pub arp_opcode: Option<u16>,
    pub arp_spa: Option<Ipv4Addr>,
    pub arp_tpa: Option<Ipv4Addr>,
    // Tunnels
    pub vxlan_vni: Option<u32>,
    pub gtp_teid: Option<u32>,
    pub geneve_vni: Option<u32>,
    pub gre_protocol: Option<u16>,
    pub gre_key: Option<u32>,
    // MPLS
    pub mpls_label: Option<u32>,
    pub mpls_tc: Option<u8>,
    pub mpls_bos: Option<bool>,
    // OAM/CFM
    pub oam_level: Option<u8>,
    pub oam_opcode: Option<u8>,
    // NSH/SFC
    pub nsh_spi: Option<u32>,
    pub nsh_si: Option<u8>,
    pub nsh_next_protocol: Option<u8>,
    // PTP
    pub ptp_message_type: Option<u8>,
    pub ptp_domain: Option<u8>,
    pub ptp_version: Option<u8>,
    // Metadata
    pub frame_len: usize,
    pub timestamp: f64,
    pub ts_sec: u32,
    pub ts_usec: u32,
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

/// Parse a raw Ethernet frame into structured fields (mirrors frame_parser.v 23-state FSM)
pub fn parse_packet(pkt: &PcapPacket) -> ParsedPacket {
    let data = &pkt.data;
    let frame_len = data.len();
    let timestamp = pkt.ts_sec as f64 + pkt.ts_usec as f64 / 1_000_000.0;

    let mut result = ParsedPacket {
        dst_mac: [0u8; 6],
        src_mac: [0u8; 6],
        ethertype: 0,
        vlan_id: None,
        vlan_pcp: None,
        outer_vlan_id: None,
        outer_vlan_pcp: None,
        src_ip: None,
        dst_ip: None,
        ip_protocol: None,
        ip_dscp: None,
        ip_ecn: None,
        ip_ttl: None,
        ip_dont_fragment: None,
        ip_more_fragments: None,
        ip_frag_offset: None,
        src_ipv6: None,
        dst_ipv6: None,
        ipv6_next_header: None,
        ipv6_dscp: None,
        ipv6_ecn: None,
        ipv6_hop_limit: None,
        ipv6_flow_label: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        icmp_type: None,
        icmp_code: None,
        icmpv6_type: None,
        icmpv6_code: None,
        igmp_type: None,
        mld_type: None,
        arp_opcode: None,
        arp_spa: None,
        arp_tpa: None,
        vxlan_vni: None,
        gtp_teid: None,
        geneve_vni: None,
        gre_protocol: None,
        gre_key: None,
        mpls_label: None,
        mpls_tc: None,
        mpls_bos: None,
        oam_level: None,
        oam_opcode: None,
        nsh_spi: None,
        nsh_si: None,
        nsh_next_protocol: None,
        ptp_message_type: None,
        ptp_domain: None,
        ptp_version: None,
        frame_len,
        timestamp,
        ts_sec: pkt.ts_sec,
        ts_usec: pkt.ts_usec,
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

    // QinQ (802.1ad): outer VLAN tag (0x88A8 or 0x9100 legacy)
    if (ethertype == 0x88A8 || ethertype == 0x9100) && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        result.outer_vlan_id = Some(tci & 0x0FFF);
        result.outer_vlan_pcp = Some((tci >> 13) as u8);
        offset += 2;
        ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
    }

    // 802.1Q VLAN tag
    if ethertype == 0x8100 && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        result.vlan_id = Some(tci & 0x0FFF);
        result.vlan_pcp = Some((tci >> 13) as u8);
        offset += 2;
        ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
    }

    result.ethertype = ethertype;

    match ethertype {
        // IPv4
        0x0800 => {
            if data.len() >= offset + 20 {
                parse_ipv4(data, offset, &mut result);
            }
        }
        // IPv6
        0x86DD => {
            if data.len() >= offset + 40 {
                parse_ipv6(data, offset, &mut result);
            }
        }
        // ARP
        0x0806 => {
            parse_arp(data, offset, &mut result);
        }
        // MPLS unicast/multicast
        0x8847 | 0x8848 => {
            parse_mpls(data, offset, &mut result);
        }
        // OAM/CFM (IEEE 802.1ag)
        0x8902 => {
            parse_oam(data, offset, &mut result);
        }
        // NSH (RFC 8300)
        0x894F => {
            parse_nsh(data, offset, &mut result);
        }
        // PTP L2 (IEEE 1588)
        0x88F7 => {
            parse_ptp(data, offset, &mut result);
        }
        _ => {}
    }

    result
}

/// Parse IPv4 header and L4 protocols
fn parse_ipv4(data: &[u8], ip_offset: usize, result: &mut ParsedPacket) {
    let ihl = (data[ip_offset] & 0x0F) as usize * 4;
    let tos = data[ip_offset + 1];
    result.ip_dscp = Some((tos >> 2) & 0x3F);
    result.ip_ecn = Some(tos & 0x03);
    result.ip_ttl = Some(data[ip_offset + 8]);
    result.ip_protocol = Some(data[ip_offset + 9]);

    // Flags + Fragment Offset (bytes 6-7)
    let flags_frag = u16::from_be_bytes([data[ip_offset + 6], data[ip_offset + 7]]);
    result.ip_dont_fragment = Some((flags_frag >> 14) & 1 == 1);
    result.ip_more_fragments = Some((flags_frag >> 13) & 1 == 1);
    result.ip_frag_offset = Some(flags_frag & 0x1FFF);

    result.src_ip = Some(Ipv4Addr::new(
        data[ip_offset + 12], data[ip_offset + 13], data[ip_offset + 14], data[ip_offset + 15],
    ));
    result.dst_ip = Some(Ipv4Addr::new(
        data[ip_offset + 16], data[ip_offset + 17], data[ip_offset + 18], data[ip_offset + 19],
    ));

    let l4_offset = ip_offset + ihl;
    if let Some(proto) = result.ip_protocol {
        parse_l4(data, l4_offset, proto, result);
    }
}

/// Parse IPv6 header and L4 protocols
fn parse_ipv6(data: &[u8], ip_offset: usize, result: &mut ParsedPacket) {
    let next_header = data[ip_offset + 6];
    result.ip_protocol = Some(next_header);
    result.ipv6_next_header = Some(next_header);
    result.ipv6_hop_limit = Some(data[ip_offset + 7]);

    // Traffic Class: version(4) + TC(8) + flow_label(20) in first 4 bytes
    let vtf = u32::from_be_bytes([data[ip_offset], data[ip_offset + 1], data[ip_offset + 2], data[ip_offset + 3]]);
    let tc = ((vtf >> 20) & 0xFF) as u8;
    result.ipv6_dscp = Some((tc >> 2) & 0x3F);
    result.ipv6_ecn = Some(tc & 0x03);
    result.ipv6_flow_label = Some(vtf & 0x000F_FFFF);

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[ip_offset + 8..ip_offset + 24]);
    dst_bytes.copy_from_slice(&data[ip_offset + 24..ip_offset + 40]);
    result.src_ipv6 = Some(Ipv6Addr::from(src_bytes));
    result.dst_ipv6 = Some(Ipv6Addr::from(dst_bytes));

    let l4_offset = ip_offset + 40;
    parse_l4(data, l4_offset, next_header, result);
}

/// Parse L4 protocol: TCP, UDP (with tunnel dispatch), ICMP, IGMP, GRE, ICMPv6
fn parse_l4(data: &[u8], l4_offset: usize, proto: u8, result: &mut ParsedPacket) {
    match proto {
        // TCP
        6 => {
            if data.len() >= l4_offset + 14 {
                result.src_port = Some(u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]));
                result.dst_port = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));
                result.tcp_flags = Some(data[l4_offset + 13]);
            } else if data.len() >= l4_offset + 4 {
                result.src_port = Some(u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]));
                result.dst_port = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));
            }
        }
        // UDP
        17 => {
            if data.len() >= l4_offset + 4 {
                result.src_port = Some(u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]));
                result.dst_port = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));

                let udp_payload = l4_offset + 8;
                match result.dst_port {
                    // VXLAN: UDP dst port 4789
                    Some(4789) => {
                        if data.len() >= udp_payload + 8 {
                            let vni = ((data[udp_payload + 4] as u32) << 16)
                                | ((data[udp_payload + 5] as u32) << 8)
                                | (data[udp_payload + 6] as u32);
                            result.vxlan_vni = Some(vni >> 8);
                        }
                    }
                    // GTP-U: UDP dst port 2152
                    Some(2152) => {
                        if data.len() >= udp_payload + 8 {
                            let teid = u32::from_be_bytes([
                                data[udp_payload + 4], data[udp_payload + 5],
                                data[udp_payload + 6], data[udp_payload + 7],
                            ]);
                            result.gtp_teid = Some(teid);
                        }
                    }
                    // Geneve: UDP dst port 6081
                    Some(6081) => {
                        if data.len() >= udp_payload + 8 {
                            // Geneve VNI: bytes 4-6 of header (24-bit, byte 7 is reserved)
                            let vni = ((data[udp_payload + 4] as u32) << 16)
                                | ((data[udp_payload + 5] as u32) << 8)
                                | (data[udp_payload + 6] as u32);
                            result.geneve_vni = Some(vni);
                        }
                    }
                    // PTP L4: UDP dst port 319 or 320
                    Some(319) | Some(320) => {
                        parse_ptp(data, udp_payload, result);
                    }
                    _ => {}
                }
            }
        }
        // ICMP
        1 => {
            if data.len() >= l4_offset + 2 {
                result.icmp_type = Some(data[l4_offset]);
                result.icmp_code = Some(data[l4_offset + 1]);
            }
        }
        // IGMP
        2 => {
            if data.len() >= l4_offset + 1 {
                result.igmp_type = Some(data[l4_offset]);
            }
        }
        // GRE
        47 => {
            if data.len() >= l4_offset + 4 {
                result.gre_protocol = Some(u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]));
                // K flag is bit 5 of byte 0 (RFC 2784: C=7,R=6,K=5,S=4 in byte 0)
                let k_flag = (data[l4_offset] >> 5) & 1 == 1;
                if k_flag && data.len() >= l4_offset + 8 {
                    result.gre_key = Some(u32::from_be_bytes([
                        data[l4_offset + 4], data[l4_offset + 5],
                        data[l4_offset + 6], data[l4_offset + 7],
                    ]));
                }
            }
        }
        // ICMPv6
        58 => {
            if data.len() >= l4_offset + 2 {
                result.icmpv6_type = Some(data[l4_offset]);
                result.icmpv6_code = Some(data[l4_offset + 1]);
                // MLD types 130-132
                let t = data[l4_offset];
                if (130..=132).contains(&t) {
                    result.mld_type = Some(t);
                }
            }
        }
        _ => {}
    }
}

/// Parse ARP header
fn parse_arp(data: &[u8], arp_offset: usize, result: &mut ParsedPacket) {
    // ARP: opcode at bytes 6-7, SPA at bytes 14-17, TPA at bytes 24-27 (relative to arp_offset)
    if data.len() >= arp_offset + 28 {
        result.arp_opcode = Some(u16::from_be_bytes([data[arp_offset + 6], data[arp_offset + 7]]));
        result.arp_spa = Some(Ipv4Addr::new(
            data[arp_offset + 14], data[arp_offset + 15], data[arp_offset + 16], data[arp_offset + 17],
        ));
        result.arp_tpa = Some(Ipv4Addr::new(
            data[arp_offset + 24], data[arp_offset + 25], data[arp_offset + 26], data[arp_offset + 27],
        ));
    }
}

/// Parse MPLS label entry (4 bytes)
fn parse_mpls(data: &[u8], mpls_offset: usize, result: &mut ParsedPacket) {
    if data.len() >= mpls_offset + 4 {
        let entry = u32::from_be_bytes([
            data[mpls_offset], data[mpls_offset + 1],
            data[mpls_offset + 2], data[mpls_offset + 3],
        ]);
        result.mpls_label = Some(entry >> 12);
        result.mpls_tc = Some(((entry >> 9) & 0x07) as u8);
        result.mpls_bos = Some((entry >> 8) & 1 == 1);
    }
}

/// Parse OAM/CFM header (IEEE 802.1ag)
fn parse_oam(data: &[u8], oam_offset: usize, result: &mut ParsedPacket) {
    if data.len() >= oam_offset + 2 {
        result.oam_level = Some((data[oam_offset] >> 5) & 0x07);
        result.oam_opcode = Some(data[oam_offset + 1]);
    }
}

/// Parse NSH header (RFC 8300)
fn parse_nsh(data: &[u8], nsh_offset: usize, result: &mut ParsedPacket) {
    if data.len() >= nsh_offset + 8 {
        result.nsh_next_protocol = Some(data[nsh_offset + 2]);
        result.nsh_spi = Some(
            ((data[nsh_offset + 4] as u32) << 16)
                | ((data[nsh_offset + 5] as u32) << 8)
                | (data[nsh_offset + 6] as u32),
        );
        result.nsh_si = Some(data[nsh_offset + 7]);
    }
}

/// Parse PTP header (IEEE 1588) — used for both L2 (EtherType 0x88F7) and L4 (UDP 319/320)
fn parse_ptp(data: &[u8], ptp_offset: usize, result: &mut ParsedPacket) {
    if data.len() >= ptp_offset + 5 {
        result.ptp_message_type = Some(data[ptp_offset] & 0x0F);
        result.ptp_version = Some(data[ptp_offset + 1] & 0x0F);
        result.ptp_domain = Some(data[ptp_offset + 4]);
    }
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

    // ---- Phase 37: Full protocol parser tests ----

    /// Helper: build an Ethernet frame with given ethertype + payload
    fn make_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> PcapPacket {
        let mut data = Vec::new();
        data.extend_from_slice(&dst);
        data.extend_from_slice(&src);
        data.extend_from_slice(&ethertype.to_be_bytes());
        data.extend_from_slice(payload);
        while data.len() < 60 { data.push(0); }
        PcapPacket { ts_sec: 1000, ts_usec: 500000, data }
    }

    /// Helper: build an IPv4 frame with given protocol + L4 payload
    fn make_ipv4_frame(protocol: u8, tos: u8, ttl: u8, flags_frag: u16, l4_payload: &[u8]) -> PcapPacket {
        let mut ip = Vec::new();
        ip.push(0x45); // version + IHL
        ip.push(tos);
        ip.extend_from_slice(&40u16.to_be_bytes()); // total length
        ip.extend_from_slice(&[0, 0]); // identification
        ip.extend_from_slice(&flags_frag.to_be_bytes()); // flags + fragment offset
        ip.push(ttl);
        ip.push(protocol);
        ip.extend_from_slice(&[0, 0]); // checksum
        ip.extend_from_slice(&[10, 0, 0, 1]); // src
        ip.extend_from_slice(&[10, 0, 0, 2]); // dst
        ip.extend_from_slice(l4_payload);
        make_eth_frame([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x0800, &ip)
    }

    /// Helper: build an IPv6 frame with given next_header + L4 payload
    fn make_ipv6_frame(next_header: u8, tc: u8, hop_limit: u8, flow_label: u32, l4_payload: &[u8]) -> PcapPacket {
        let mut ip6 = Vec::new();
        // Version(4) + TC(8) + Flow Label(20) = 32 bits
        let vtf: u32 = (6u32 << 28) | ((tc as u32) << 20) | (flow_label & 0x000F_FFFF);
        ip6.extend_from_slice(&vtf.to_be_bytes());
        ip6.extend_from_slice(&(l4_payload.len() as u16).to_be_bytes()); // payload length
        ip6.push(next_header);
        ip6.push(hop_limit);
        // src: 2001:db8::1
        ip6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst: 2001:db8::2
        ip6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip6.extend_from_slice(l4_payload);
        make_eth_frame([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x86DD, &ip6)
    }

    #[test]
    fn parse_ipv4_dscp_ecn() {
        // TOS=0xB8 → DSCP=46 (EF), ECN=0
        let pkt = make_ipv4_frame(6, 0xB8, 64, 0, &[0; 20]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ip_dscp, Some(46));
        assert_eq!(parsed.ip_ecn, Some(0));
    }

    #[test]
    fn parse_ipv4_dscp_ecn_with_ecn_bits() {
        // TOS=0xB9 → DSCP=46, ECN=1 (ECT(1))
        let pkt = make_ipv4_frame(6, 0xB9, 64, 0, &[0; 20]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ip_dscp, Some(46));
        assert_eq!(parsed.ip_ecn, Some(1));
    }

    #[test]
    fn parse_ipv4_ttl() {
        let pkt = make_ipv4_frame(6, 0, 128, 0, &[0; 20]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ip_ttl, Some(128));
    }

    #[test]
    fn parse_ipv4_fragmentation() {
        // DF=1, MF=0, offset=0 → flags_frag = 0x4000
        let pkt = make_ipv4_frame(6, 0, 64, 0x4000, &[0; 20]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ip_dont_fragment, Some(true));
        assert_eq!(parsed.ip_more_fragments, Some(false));
        assert_eq!(parsed.ip_frag_offset, Some(0));
    }

    #[test]
    fn parse_ipv4_frag_mf_with_offset() {
        // DF=0, MF=1, offset=185 → flags_frag = 0x20B9
        let pkt = make_ipv4_frame(6, 0, 64, 0x20B9, &[0; 20]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ip_dont_fragment, Some(false));
        assert_eq!(parsed.ip_more_fragments, Some(true));
        assert_eq!(parsed.ip_frag_offset, Some(0x00B9));
    }

    #[test]
    fn parse_tcp_flags() {
        // TCP header: ports + seq(4) + ack(4) + data_offset(1) + flags(1) + ...
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        tcp.extend_from_slice(&80u16.to_be_bytes()); // dst port
        tcp.extend_from_slice(&[0; 4]); // seq
        tcp.extend_from_slice(&[0; 4]); // ack
        tcp.push(0x50); // data offset (5 words)
        tcp.push(0x02); // flags = SYN
        tcp.extend_from_slice(&[0; 6]); // window + checksum + urgent
        let pkt = make_ipv4_frame(6, 0, 64, 0, &tcp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.tcp_flags, Some(0x02));
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.dst_port, Some(80));
    }

    #[test]
    fn parse_tcp_flags_syn_ack() {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&443u16.to_be_bytes());
        tcp.extend_from_slice(&54321u16.to_be_bytes());
        tcp.extend_from_slice(&[0; 4]); // seq
        tcp.extend_from_slice(&[0; 4]); // ack
        tcp.push(0x50);
        tcp.push(0x12); // SYN+ACK
        tcp.extend_from_slice(&[0; 6]);
        let pkt = make_ipv4_frame(6, 0, 64, 0, &tcp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.tcp_flags, Some(0x12));
    }

    #[test]
    fn parse_icmp_type_code() {
        // ICMP: type=8 (echo request), code=0
        let icmp = vec![8, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv4_frame(1, 0, 64, 0, &icmp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.icmp_type, Some(8));
        assert_eq!(parsed.icmp_code, Some(0));
        assert!(parsed.src_port.is_none());
    }

    #[test]
    fn parse_igmp_type() {
        // IGMP: type=0x11 (membership query)
        let igmp = vec![0x11, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv4_frame(2, 0, 64, 0, &igmp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.igmp_type, Some(0x11));
    }

    #[test]
    fn parse_gre_protocol_key() {
        // GRE: C=0, K=1 (bit 5 of first byte) → flags=0x20, ver=0, protocol=0x0800, key=0xDEADBEEF
        let mut gre = Vec::new();
        gre.extend_from_slice(&[0x20, 0x00]); // flags: K=1
        gre.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol
        gre.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // key
        let pkt = make_ipv4_frame(47, 0, 64, 0, &gre);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.gre_protocol, Some(0x0800));
        assert_eq!(parsed.gre_key, Some(0xDEADBEEF));
    }

    #[test]
    fn parse_gre_no_key() {
        // GRE without K flag
        let mut gre = Vec::new();
        gre.extend_from_slice(&[0x00, 0x00]); // flags: no K
        gre.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol
        gre.extend_from_slice(&[0; 4]); // padding
        let pkt = make_ipv4_frame(47, 0, 64, 0, &gre);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.gre_protocol, Some(0x0800));
        assert!(parsed.gre_key.is_none());
    }

    #[test]
    fn parse_arp_fields() {
        let mut arp_payload = vec![0u8; 28];
        // opcode at bytes 6-7: 1 (request)
        arp_payload[6] = 0;
        arp_payload[7] = 1;
        // SPA at bytes 14-17: 192.168.1.10
        arp_payload[14] = 192; arp_payload[15] = 168; arp_payload[16] = 1; arp_payload[17] = 10;
        // TPA at bytes 24-27: 192.168.1.1
        arp_payload[24] = 192; arp_payload[25] = 168; arp_payload[26] = 1; arp_payload[27] = 1;

        let pkt = make_eth_frame([0xff; 6], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x0806, &arp_payload);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x0806);
        assert_eq!(parsed.arp_opcode, Some(1));
        assert_eq!(parsed.arp_spa, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(parsed.arp_tpa, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_ipv6_tc() {
        // TC = 0xB8 → DSCP=46, ECN=0; flow_label=0
        let l4 = vec![0; 20];
        let pkt = make_ipv6_frame(6, 0xB8, 64, 0, &l4);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ipv6_dscp, Some(46));
        assert_eq!(parsed.ipv6_ecn, Some(0));
    }

    #[test]
    fn parse_ipv6_hop_limit() {
        let l4 = vec![0; 20];
        let pkt = make_ipv6_frame(6, 0, 255, 0, &l4);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ipv6_hop_limit, Some(255));
    }

    #[test]
    fn parse_ipv6_flow_label() {
        let l4 = vec![0; 20];
        let pkt = make_ipv6_frame(6, 0, 64, 0xABCDE, &l4);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ipv6_flow_label, Some(0xABCDE));
    }

    #[test]
    fn parse_ipv6_next_header() {
        let l4 = vec![0; 20];
        let pkt = make_ipv6_frame(17, 0, 64, 0, &l4);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ipv6_next_header, Some(17));
        assert_eq!(parsed.ip_protocol, Some(17));
    }

    #[test]
    fn parse_icmpv6() {
        // ICMPv6: type=128 (echo request), code=0
        let icmpv6 = vec![128, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv6_frame(58, 0, 64, 0, &icmpv6);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.icmpv6_type, Some(128));
        assert_eq!(parsed.icmpv6_code, Some(0));
        assert!(parsed.mld_type.is_none()); // 128 is not MLD
    }

    #[test]
    fn parse_mld() {
        // MLD: ICMPv6 type=130 (Multicast Listener Query)
        let mld = vec![130, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv6_frame(58, 0, 64, 0, &mld);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.icmpv6_type, Some(130));
        assert_eq!(parsed.mld_type, Some(130));
    }

    #[test]
    fn parse_gtp_teid() {
        // UDP dst=2152 + GTP-U header (8 bytes): version/flags, type, length, TEID
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp.extend_from_slice(&2152u16.to_be_bytes()); // dst port
        udp.extend_from_slice(&[0, 20, 0, 0]); // UDP length + checksum
        // GTP header: version(3b)+PT+reserved+E+S+PN, type, length, TEID
        udp.push(0x30); // version=1, PT=1
        udp.push(0xFF); // message type
        udp.extend_from_slice(&[0, 0]); // length
        udp.extend_from_slice(&0x12345678u32.to_be_bytes()); // TEID
        let pkt = make_ipv4_frame(17, 0, 64, 0, &udp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.gtp_teid, Some(0x12345678));
    }

    #[test]
    fn parse_geneve_vni() {
        // UDP dst=6081 + Geneve header (8 bytes)
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp.extend_from_slice(&6081u16.to_be_bytes()); // dst port
        udp.extend_from_slice(&[0, 20, 0, 0]); // UDP length + checksum
        // Geneve header: ver+opt_len(1), flags(1), protocol(2), VNI[23:16](1), VNI[15:8](1), VNI[7:0](1), reserved(1)
        udp.push(0x00); // ver=0, opt_len=0
        udp.push(0x00); // O+C+reserved
        udp.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol type = transparent ethernet
        // VNI: 5000 = 0x001388 → bytes 4-6 contain VNI directly
        udp.push(0x00); // VNI[23:16]
        udp.push(0x13); // VNI[15:8]
        udp.push(0x88); // VNI[7:0]
        udp.push(0x00); // reserved
        let pkt = make_ipv4_frame(17, 0, 64, 0, &udp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.geneve_vni, Some(5000));
    }

    #[test]
    fn parse_ptp_l2() {
        // PTP over L2 (EtherType 0x88F7)
        let mut ptp_payload = vec![0u8; 34]; // min PTP message
        ptp_payload[0] = 0x00; // messageType=0 (Sync), transportSpecific=0
        ptp_payload[1] = 0x02; // versionPTP=2
        ptp_payload[4] = 5;   // domainNumber=5
        let pkt = make_eth_frame([0x01, 0x1b, 0x19, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x88F7, &ptp_payload);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x88F7);
        assert_eq!(parsed.ptp_message_type, Some(0));
        assert_eq!(parsed.ptp_version, Some(2));
        assert_eq!(parsed.ptp_domain, Some(5));
    }

    #[test]
    fn parse_ptp_l4() {
        // PTP over UDP port 319
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp.extend_from_slice(&319u16.to_be_bytes()); // dst port = PTP event
        udp.extend_from_slice(&[0, 50, 0, 0]); // UDP length + checksum
        // PTP header
        udp.push(0x0B); // messageType=11 (Announce)
        udp.push(0x02); // versionPTP=2
        udp.push(0); udp.push(0);
        udp.push(10); // domainNumber=10
        while udp.len() < 48 { udp.push(0); }
        let pkt = make_ipv4_frame(17, 0, 64, 0, &udp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ptp_message_type, Some(0x0B));
        assert_eq!(parsed.ptp_version, Some(2));
        assert_eq!(parsed.ptp_domain, Some(10));
    }

    #[test]
    fn parse_mpls_label() {
        // MPLS: label=1000, TC=5, BOS=1, TTL=64
        let label_entry: u32 = (1000 << 12) | (5 << 9) | (1 << 8) | 64;
        let pkt = make_eth_frame([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x8847, &label_entry.to_be_bytes());
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x8847);
        assert_eq!(parsed.mpls_label, Some(1000));
        assert_eq!(parsed.mpls_tc, Some(5));
        assert_eq!(parsed.mpls_bos, Some(true));
    }

    #[test]
    fn parse_oam_level_opcode() {
        // OAM/CFM: MD level=3 (bits [7:5] of byte 0), opcode=1 (CCM, byte 1)
        let mut oam = vec![0u8; 8];
        oam[0] = 3 << 5; // MD level 3
        oam[1] = 1;       // OpCode CCM
        let pkt = make_eth_frame([0x01, 0x80, 0xc2, 0x00, 0x00, 0x30], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x8902, &oam);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x8902);
        assert_eq!(parsed.oam_level, Some(3));
        assert_eq!(parsed.oam_opcode, Some(1));
    }

    #[test]
    fn parse_nsh_fields() {
        // NSH: next_protocol=1 (IPv4), SPI=100, SI=254
        let mut nsh = vec![0u8; 8];
        nsh[2] = 1; // next_protocol
        // SPI: 100 = 0x000064 → bytes 4-6
        nsh[4] = 0x00;
        nsh[5] = 0x00;
        nsh[6] = 0x64;
        nsh[7] = 254; // SI
        let pkt = make_eth_frame([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x894F, &nsh);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ethertype, 0x894F);
        assert_eq!(parsed.nsh_spi, Some(100));
        assert_eq!(parsed.nsh_si, Some(254));
        assert_eq!(parsed.nsh_next_protocol, Some(1));
    }

    #[test]
    fn parse_qinq() {
        // QinQ: outer 0x88A8 → outer_vlan_id=200 PCP=5, inner 0x8100 → vlan_id=100 PCP=3, then IPv4
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        data.extend_from_slice(&0x88A8u16.to_be_bytes()); // outer ethertype
        // Outer TCI: PCP=5 → (5<<13) | 200 = 0xA0C8
        data.extend_from_slice(&((5u16 << 13) | 200).to_be_bytes());
        data.extend_from_slice(&0x8100u16.to_be_bytes()); // inner ethertype
        // Inner TCI: PCP=3 → (3<<13) | 100 = 0x6064
        data.extend_from_slice(&((3u16 << 13) | 100).to_be_bytes());
        data.extend_from_slice(&0x0800u16.to_be_bytes()); // actual ethertype = IPv4
        // Minimal IPv4
        data.push(0x45); data.push(0); data.extend_from_slice(&[0, 40]);
        data.extend_from_slice(&[0; 4]);
        data.push(64); data.push(6); data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&[10, 0, 0, 1]); data.extend_from_slice(&[10, 0, 0, 2]);
        while data.len() < 72 { data.push(0); }

        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.outer_vlan_id, Some(200));
        assert_eq!(parsed.outer_vlan_pcp, Some(5));
        assert_eq!(parsed.vlan_id, Some(100));
        assert_eq!(parsed.vlan_pcp, Some(3));
        assert_eq!(parsed.ethertype, 0x0800);
    }

    #[test]
    fn parse_vlan_pcp() {
        // VLAN with PCP=7, VID=42
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        data.extend_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q
        // TCI: PCP=7 → (7<<13) | 42 = 0xE02A
        data.extend_from_slice(&((7u16 << 13) | 42).to_be_bytes());
        data.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        data.push(0x45); data.push(0); data.extend_from_slice(&[0, 40]);
        data.extend_from_slice(&[0; 4]);
        data.push(64); data.push(6); data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&[10, 0, 0, 1]); data.extend_from_slice(&[10, 0, 0, 2]);
        while data.len() < 64 { data.push(0); }

        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.vlan_id, Some(42));
        assert_eq!(parsed.vlan_pcp, Some(7));
    }

    #[test]
    fn parse_qinq_offsets() {
        // QinQ adds 4 bytes offset → verify IPv4 fields still parse correctly
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&0x88A8u16.to_be_bytes()); // outer
        data.extend_from_slice(&[0x00, 50]); // outer VID=50
        data.extend_from_slice(&0x8100u16.to_be_bytes()); // inner
        data.extend_from_slice(&[0x00, 10]); // inner VID=10
        data.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // IPv4 at offset 22 (14 + 4 + 4)
        data.push(0x45); data.push(0xB8); // TOS = 0xB8 → DSCP=46
        data.extend_from_slice(&[0, 40]); // total length
        data.extend_from_slice(&[0; 2]); // identification
        data.extend_from_slice(&0x4000u16.to_be_bytes()); // DF=1
        data.push(128); data.push(6); // TTL=128, TCP
        data.extend_from_slice(&[0, 0]); // checksum
        data.extend_from_slice(&[172, 16, 0, 1]); // src
        data.extend_from_slice(&[172, 16, 0, 2]); // dst
        // TCP
        data.extend_from_slice(&8080u16.to_be_bytes());
        data.extend_from_slice(&443u16.to_be_bytes());
        while data.len() < 76 { data.push(0); }

        let pkt = PcapPacket { ts_sec: 0, ts_usec: 0, data };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.outer_vlan_id, Some(50));
        assert_eq!(parsed.vlan_id, Some(10));
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.ip_dscp, Some(46));
        assert_eq!(parsed.ip_ttl, Some(128));
        assert_eq!(parsed.ip_dont_fragment, Some(true));
        assert_eq!(parsed.src_ip, Some(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(parsed.src_port, Some(8080));
        assert_eq!(parsed.dst_port, Some(443));
    }

    #[test]
    fn parse_udp_no_tunnel() {
        // UDP with random high port — no tunnel fields set
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp.extend_from_slice(&9999u16.to_be_bytes()); // dst port (not a tunnel port)
        udp.extend_from_slice(&[0, 8, 0, 0]); // length + checksum
        let pkt = make_ipv4_frame(17, 0, 64, 0, &udp);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.dst_port, Some(9999));
        assert!(parsed.vxlan_vni.is_none());
        assert!(parsed.gtp_teid.is_none());
        assert!(parsed.geneve_vni.is_none());
        assert!(parsed.ptp_message_type.is_none());
    }

    #[test]
    fn parse_timestamp_preserved() {
        let pkt = PcapPacket { ts_sec: 1709734800, ts_usec: 123456, data: vec![0; 64] };
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.ts_sec, 1709734800);
        assert_eq!(parsed.ts_usec, 123456);
    }
}
