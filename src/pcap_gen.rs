// pcap_gen.rs — Synthetic PCAP traffic generator
//
// Generates test traffic that exercises each rule in the filter configuration.
// Uses a simple PRNG for reproducible, seed-based packet generation.

use std::path::Path;
use anyhow::Result;

use crate::model::{FilterConfig, MatchCriteria};

/// Simple xorshift64 PRNG for reproducible generation
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }

    fn next_u16(&mut self) -> u16 {
        (self.next() & 0xFFFF) as u16
    }

    fn next_u32(&mut self) -> u32 {
        (self.next() & 0xFFFF_FFFF) as u32
    }

    fn next_range(&mut self, min: u32, max: u32) -> u32 {
        if min >= max { return min; }
        min + (self.next_u32() % (max - min + 1))
    }
}

/// Generate synthetic PCAP traffic from a filter configuration.
///
/// Creates packets that match each rule plus random background traffic.
/// Returns a JSON stats object.
pub fn generate_traffic(
    config: &FilterConfig,
    output: &Path,
    count: u32,
    seed: u64,
) -> Result<serde_json::Value> {
    let mut rng = Rng::new(seed);
    let rules: Vec<_> = config.pacgate.rules.iter().filter(|r| !r.is_stateful()).collect();

    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
    let mut rules_covered = std::collections::HashSet::new();

    for i in 0..count {
        let pkt = if !rules.is_empty() {
            // Round-robin through rules, then random background
            let rule_idx = (i as usize) % (rules.len() + 1);
            if rule_idx < rules.len() {
                rules_covered.insert(rules[rule_idx].name.clone());
                build_matching_packet(&rules[rule_idx].match_criteria, &mut rng)
            } else {
                build_random_packet(&mut rng)
            }
        } else {
            build_random_packet(&mut rng)
        };
        packets.push(pkt);
    }

    // Write PCAP file
    let total_bytes = write_pcap(output, &packets)?;

    Ok(serde_json::json!({
        "packets_generated": count,
        "rules_covered": rules_covered.len(),
        "rules_total": rules.len(),
        "bytes_written": total_bytes,
        "seed": seed,
        "output": output.to_string_lossy(),
    }))
}

/// Build a packet that matches the given criteria
fn build_matching_packet(mc: &MatchCriteria, rng: &mut Rng) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    // Determine ethertype
    let ethertype = mc.ethertype.as_ref()
        .and_then(|e| u16::from_str_radix(e.trim_start_matches("0x").trim_start_matches("0X"), 16).ok())
        .unwrap_or(0x0800);

    let has_vlan = mc.vlan_id.is_some() || mc.vlan_pcp.is_some();
    let has_outer_vlan = mc.outer_vlan_id.is_some() || mc.outer_vlan_pcp.is_some();

    // Destination MAC
    if let Some(ref mac) = mc.dst_mac {
        push_mac(&mut pkt, mac);
    } else {
        push_random_mac(&mut pkt, rng);
    }

    // Source MAC
    if let Some(ref mac) = mc.src_mac {
        push_mac(&mut pkt, mac);
    } else {
        push_random_mac(&mut pkt, rng);
    }

    // Outer VLAN (QinQ)
    if has_outer_vlan {
        pkt.extend_from_slice(&[0x88, 0xA8]); // 802.1ad
        let pcp = mc.outer_vlan_pcp.unwrap_or(0);
        let vid = mc.outer_vlan_id.unwrap_or(100);
        let tci = ((pcp as u16 & 0x7) << 13) | (vid & 0xFFF);
        pkt.extend_from_slice(&tci.to_be_bytes());
    }

    // VLAN tag
    if has_vlan || has_outer_vlan {
        pkt.extend_from_slice(&[0x81, 0x00]); // 802.1Q
        let pcp = mc.vlan_pcp.unwrap_or(0);
        let vid = mc.vlan_id.unwrap_or(1);
        let tci = ((pcp as u16 & 0x7) << 13) | (vid & 0xFFF);
        pkt.extend_from_slice(&tci.to_be_bytes());
    }

    // EtherType
    pkt.extend_from_slice(&ethertype.to_be_bytes());

    // Build L3+ based on ethertype
    match ethertype {
        0x0800 => build_ipv4_payload(&mut pkt, mc, rng),
        0x86DD => build_ipv6_payload(&mut pkt, mc, rng),
        0x0806 => build_arp_payload(&mut pkt, mc, rng),
        0x8902 => build_oam_payload(&mut pkt, mc, rng),
        0x894F => build_nsh_payload(&mut pkt, mc, rng),
        0x8847 | 0x8848 => build_mpls_payload(&mut pkt, mc, rng),
        0x88F7 => build_ptp_payload(&mut pkt, mc, rng),
        _ => {
            // Random payload
            for _ in 0..46 {
                pkt.push(rng.next_u8());
            }
        }
    }

    // Pad to minimum 64 bytes
    while pkt.len() < 64 {
        pkt.push(0);
    }

    pkt
}

fn build_ipv4_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let ip_protocol = mc.ip_protocol.unwrap_or(6); // TCP default

    // IPv4 header (20 bytes)
    let dscp = mc.ip_dscp.unwrap_or(0);
    let ecn = mc.ip_ecn.unwrap_or(0);
    let tos = ((dscp & 0x3F) << 2) | (ecn & 0x3);

    let ttl = mc.ip_ttl.unwrap_or(64);
    let total_len: u16 = 40; // 20 IP + 20 TCP/UDP payload estimate

    pkt.push(0x45); // version=4, IHL=5
    pkt.push(tos);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&(rng.next_u16()).to_be_bytes()); // ID
    // Flags + fragment offset
    let df = mc.ip_dont_fragment.unwrap_or(false);
    let mf = mc.ip_more_fragments.unwrap_or(false);
    let frag_off = mc.ip_frag_offset.unwrap_or(0);
    let flags_frag = ((df as u16) << 14) | ((mf as u16) << 13) | (frag_off & 0x1FFF);
    pkt.extend_from_slice(&flags_frag.to_be_bytes());
    pkt.push(ttl);
    pkt.push(ip_protocol);
    pkt.extend_from_slice(&[0, 0]); // checksum (0 for generated traffic)

    // Source IP
    if let Some(ref cidr) = mc.src_ip {
        push_ipv4_from_cidr(pkt, cidr, rng);
    } else {
        pkt.extend_from_slice(&[10, rng.next_u8(), rng.next_u8(), rng.next_u8()]);
    }

    // Dest IP
    if let Some(ref cidr) = mc.dst_ip {
        push_ipv4_from_cidr(pkt, cidr, rng);
    } else {
        pkt.extend_from_slice(&[10, rng.next_u8(), rng.next_u8(), rng.next_u8()]);
    }

    // L4 header
    match ip_protocol {
        6 => build_tcp_header(pkt, mc, rng),
        17 => build_udp_header(pkt, mc, rng),
        1 => build_icmp_header(pkt, mc, rng),
        47 => build_gre_header(pkt, mc, rng),
        _ => {
            // Generic L4 payload
            for _ in 0..20 {
                pkt.push(rng.next_u8());
            }
        }
    }
}

fn build_tcp_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let src_port = match mc.src_port {
        Some(crate::model::PortMatch::Exact(p)) => p,
        Some(crate::model::PortMatch::Range { range }) => range[0],
        None => rng.next_range(1024, 65535) as u16,
    };
    let dst_port = match mc.dst_port {
        Some(crate::model::PortMatch::Exact(p)) => p,
        Some(crate::model::PortMatch::Range { range }) => range[0],
        None => rng.next_range(1, 1024) as u16,
    };

    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&rng.next_u32().to_be_bytes()); // seq
    pkt.extend_from_slice(&rng.next_u32().to_be_bytes()); // ack
    pkt.push(0x50); // data offset = 5 (20 bytes)

    let flags = mc.tcp_flags.unwrap_or(0x02); // SYN default
    pkt.push(flags);
    pkt.extend_from_slice(&[0xFF, 0xFF]); // window
    pkt.extend_from_slice(&[0, 0]); // checksum
    pkt.extend_from_slice(&[0, 0]); // urgent
}

fn build_udp_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let src_port = match mc.src_port {
        Some(crate::model::PortMatch::Exact(p)) => p,
        Some(crate::model::PortMatch::Range { range }) => range[0],
        None => rng.next_range(1024, 65535) as u16,
    };
    let dst_port = match mc.dst_port {
        Some(crate::model::PortMatch::Exact(p)) => p,
        Some(crate::model::PortMatch::Range { range }) => range[0],
        None => rng.next_range(1, 1024) as u16,
    };

    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&20u16.to_be_bytes()); // length
    pkt.extend_from_slice(&[0, 0]); // checksum

    // Check for tunnel protocols
    if dst_port == 4789 {
        // VXLAN
        build_vxlan_header(pkt, mc, rng);
    } else if dst_port == 2152 {
        // GTP-U
        build_gtpu_header(pkt, mc, rng);
    } else if dst_port == 6081 {
        // Geneve
        build_geneve_header(pkt, mc, rng);
    } else if dst_port == 319 || dst_port == 320 {
        // PTP over UDP
        build_ptp_payload(pkt, mc, rng);
    } else {
        // Random UDP payload
        for _ in 0..12 {
            pkt.push(rng.next_u8());
        }
    }
}

fn build_icmp_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    pkt.push(mc.icmp_type.unwrap_or(8)); // echo request
    pkt.push(mc.icmp_code.unwrap_or(0));
    pkt.extend_from_slice(&[0, 0]); // checksum
    pkt.extend_from_slice(&rng.next_u32().to_be_bytes()); // rest of header
}

fn build_gre_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let has_key = mc.gre_key.is_some();
    let flags: u16 = if has_key { 0x2000 } else { 0 }; // K bit
    pkt.extend_from_slice(&flags.to_be_bytes());
    let proto = mc.gre_protocol.unwrap_or(0x0800);
    pkt.extend_from_slice(&proto.to_be_bytes());
    if let Some(key) = mc.gre_key {
        pkt.extend_from_slice(&key.to_be_bytes());
    }
    // Inner payload
    for _ in 0..20 {
        pkt.push(rng.next_u8());
    }
}

fn build_vxlan_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let vni = mc.vxlan_vni.unwrap_or(rng.next_range(1, 16777215));
    pkt.push(0x08); // flags (I bit set)
    pkt.extend_from_slice(&[0, 0, 0]); // reserved
    pkt.push(((vni >> 16) & 0xFF) as u8);
    pkt.push(((vni >> 8) & 0xFF) as u8);
    pkt.push((vni & 0xFF) as u8);
    pkt.push(0); // reserved
}

fn build_gtpu_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let teid = mc.gtp_teid.unwrap_or(rng.next_u32());
    pkt.push(0x30); // version=1, PT=1
    pkt.push(0xFF); // message type
    pkt.extend_from_slice(&8u16.to_be_bytes()); // length
    pkt.extend_from_slice(&teid.to_be_bytes());
}

fn build_geneve_header(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let vni = mc.geneve_vni.unwrap_or(rng.next_range(1, 16777215));
    pkt.push(0x00); // ver=0, opt_len=0
    pkt.push(0x00); // flags
    pkt.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol (Ethernet)
    pkt.push(((vni >> 16) & 0xFF) as u8);
    pkt.push(((vni >> 8) & 0xFF) as u8);
    pkt.push((vni & 0xFF) as u8);
    pkt.push(0); // reserved
}

fn build_ipv6_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let next_header = mc.ipv6_next_header.unwrap_or(6);
    let hop_limit = mc.ipv6_hop_limit.unwrap_or(64);
    let flow_label = mc.ipv6_flow_label.unwrap_or(0);
    let dscp = mc.ipv6_dscp.unwrap_or(0);
    let ecn = mc.ipv6_ecn.unwrap_or(0);
    let tc = ((dscp & 0x3F) << 2) | (ecn & 0x3);

    // Version(4) + TC(8) + Flow Label(20) = first 4 bytes
    let first_word: u32 = (6u32 << 28) | ((tc as u32) << 20) | (flow_label as u32 & 0xFFFFF);
    pkt.extend_from_slice(&first_word.to_be_bytes());
    pkt.extend_from_slice(&20u16.to_be_bytes()); // payload length
    pkt.push(next_header);
    pkt.push(hop_limit);

    // Source IPv6 (16 bytes)
    for _ in 0..16 {
        pkt.push(rng.next_u8());
    }
    // Dest IPv6 (16 bytes)
    for _ in 0..16 {
        pkt.push(rng.next_u8());
    }

    // L4 header
    match next_header {
        6 => build_tcp_header(pkt, mc, rng),
        17 => build_udp_header(pkt, mc, rng),
        58 => {
            // ICMPv6
            pkt.push(mc.icmpv6_type.unwrap_or(128)); // echo request
            pkt.push(mc.icmpv6_code.unwrap_or(0));
            pkt.extend_from_slice(&[0, 0]); // checksum
            pkt.extend_from_slice(&rng.next_u32().to_be_bytes());
        }
        _ => {
            for _ in 0..20 {
                pkt.push(rng.next_u8());
            }
        }
    }
}

fn build_arp_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE = Ethernet
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE = IPv4
    pkt.push(6); // HLEN
    pkt.push(4); // PLEN
    let opcode = mc.arp_opcode.unwrap_or(1);
    pkt.extend_from_slice(&(opcode as u16).to_be_bytes());
    // Sender hardware address (6 bytes)
    push_random_mac(pkt, rng);
    // Sender protocol address (4 bytes)
    if let Some(ref spa) = mc.arp_spa {
        push_ipv4_from_cidr(pkt, spa, rng);
    } else {
        pkt.extend_from_slice(&[10, 0, 0, 1]);
    }
    // Target hardware address (6 bytes)
    push_random_mac(pkt, rng);
    // Target protocol address (4 bytes)
    if let Some(ref tpa) = mc.arp_tpa {
        push_ipv4_from_cidr(pkt, tpa, rng);
    } else {
        pkt.extend_from_slice(&[10, 0, 0, 2]);
    }
}

fn build_oam_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let level = mc.oam_level.unwrap_or(0);
    let opcode = mc.oam_opcode.unwrap_or(1);
    pkt.push((level << 5) | (rng.next_u8() & 0x1F)); // MEL[7:5] + version[4:0]
    pkt.push(opcode);
    // Flags + first TLV offset
    pkt.push(0);
    pkt.push(70); // first TLV offset for CCM
    // Rest of OAM PDU
    for _ in 0..66 {
        pkt.push(rng.next_u8());
    }
}

fn build_nsh_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let spi = mc.nsh_spi.unwrap_or(rng.next_range(1, 0xFFFFFF));
    let si = mc.nsh_si.unwrap_or(255);
    let next_proto = mc.nsh_next_protocol.unwrap_or(1); // IPv4

    // NSH base header (8 bytes)
    pkt.push(0x00); // ver=0, O=0, U=0
    pkt.push(0x06); // MD Type=1, length=6 (24 bytes total)
    pkt.push(next_proto);
    // SPI (3 bytes) + SI (1 byte)
    pkt.push(((spi >> 16) & 0xFF) as u8);
    pkt.push(((spi >> 8) & 0xFF) as u8);
    pkt.push((spi & 0xFF) as u8);
    pkt.push(si);
    pkt.push(0); // padding

    // Inner payload
    for _ in 0..20 {
        pkt.push(rng.next_u8());
    }
}

fn build_mpls_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, rng: &mut Rng) {
    let label = mc.mpls_label.unwrap_or(rng.next_range(16, 1048575) as u32);
    let tc = mc.mpls_tc.unwrap_or(0);
    let bos = mc.mpls_bos.unwrap_or(true);

    // MPLS label entry (4 bytes)
    let entry: u32 = ((label & 0xFFFFF) << 12) | ((tc as u32 & 0x7) << 9) | ((bos as u32 & 0x1) << 8) | 64;
    pkt.extend_from_slice(&entry.to_be_bytes());

    // Inner IPv4 payload
    for _ in 0..20 {
        pkt.push(rng.next_u8());
    }
}

fn build_ptp_payload(pkt: &mut Vec<u8>, mc: &MatchCriteria, _rng: &mut Rng) {
    let msg_type = mc.ptp_message_type.unwrap_or(0); // Sync
    let version = mc.ptp_version.unwrap_or(2);
    let domain = mc.ptp_domain.unwrap_or(0);

    pkt.push(msg_type & 0x0F); // transportSpecific(4) + messageType(4)
    pkt.push(version & 0x0F);  // reserved(4) + versionPTP(4)
    pkt.extend_from_slice(&34u16.to_be_bytes()); // messageLength
    pkt.push(domain);
    // Rest of PTP header (29 bytes to reach 34 total)
    for _ in 0..29 {
        pkt.push(0);
    }
}

/// Build a random Ethernet frame
fn build_random_packet(rng: &mut Rng) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    // Random MACs
    push_random_mac(&mut pkt, rng);
    push_random_mac(&mut pkt, rng);

    // IPv4 ethertype
    pkt.extend_from_slice(&[0x08, 0x00]);

    // Simple IPv4 + TCP
    pkt.push(0x45);
    pkt.push(0); // TOS
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&rng.next_u16().to_be_bytes());
    pkt.extend_from_slice(&[0x40, 0x00]); // DF, no frag
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0, 0]); // checksum
    // Random IPs
    for _ in 0..8 {
        pkt.push(rng.next_u8());
    }
    // Random TCP header
    pkt.extend_from_slice(&rng.next_u16().to_be_bytes()); // src port
    pkt.extend_from_slice(&rng.next_u16().to_be_bytes()); // dst port
    pkt.extend_from_slice(&rng.next_u32().to_be_bytes()); // seq
    pkt.extend_from_slice(&rng.next_u32().to_be_bytes()); // ack
    pkt.push(0x50); // data offset
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&[0xFF, 0xFF, 0, 0, 0, 0]); // window, cksum, urgent

    // Pad to 64 bytes
    while pkt.len() < 64 {
        pkt.push(0);
    }
    pkt
}

/// Write packets as a PCAP file. Returns total bytes written.
fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> Result<u64> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;

    // PCAP global header (24 bytes)
    file.write_all(&0xA1B2C3D4u32.to_le_bytes())?; // magic
    file.write_all(&2u16.to_le_bytes())?; // version major
    file.write_all(&4u16.to_le_bytes())?; // version minor
    file.write_all(&0i32.to_le_bytes())?; // thiszone
    file.write_all(&0u32.to_le_bytes())?; // sigfigs
    file.write_all(&65535u32.to_le_bytes())?; // snaplen
    file.write_all(&1u32.to_le_bytes())?; // network (Ethernet)

    let mut total_bytes: u64 = 24;

    for (i, pkt) in packets.iter().enumerate() {
        let ts_sec = (i as u32) / 1000;
        let ts_usec = ((i as u32) % 1000) * 1000;
        let len = pkt.len() as u32;

        // Packet header (16 bytes)
        file.write_all(&ts_sec.to_le_bytes())?;
        file.write_all(&ts_usec.to_le_bytes())?;
        file.write_all(&len.to_le_bytes())?;  // incl_len
        file.write_all(&len.to_le_bytes())?;  // orig_len

        file.write_all(pkt)?;
        total_bytes += 16 + len as u64;
    }

    Ok(total_bytes)
}

// --- Helper functions ---

fn push_mac(pkt: &mut Vec<u8>, mac_str: &str) {
    let cleaned = mac_str.replace([':', '-'], "");
    let cleaned = cleaned.replace('*', "0");
    if cleaned.len() == 12 {
        for i in 0..6 {
            if let Ok(b) = u8::from_str_radix(&cleaned[i*2..i*2+2], 16) {
                pkt.push(b);
            } else {
                pkt.push(0);
            }
        }
        return;
    }
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
}

fn push_random_mac(pkt: &mut Vec<u8>, rng: &mut Rng) {
    pkt.push(0x02); // locally administered
    for _ in 0..5 {
        pkt.push(rng.next_u8());
    }
}

fn push_ipv4_from_cidr(pkt: &mut Vec<u8>, cidr: &str, rng: &mut Rng) {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip_str = parts[0];
    let octets: Vec<u8> = ip_str.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    if octets.len() == 4 {
        let prefix_len: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);
        let mask: u32 = if prefix_len >= 32 { 0xFFFFFFFF } else { !((1u32 << (32 - prefix_len)) - 1) };
        let base = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]) & mask;
        let host_bits = if prefix_len >= 32 { 0 } else { rng.next_u32() & !mask };
        let ip = base | host_bits;
        pkt.extend_from_slice(&ip.to_be_bytes());
    } else {
        pkt.extend_from_slice(&[10, 0, 0, rng.next_u8()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;

    #[test]
    fn rng_deterministic() {
        let mut r1 = Rng::new(42);
        let mut r2 = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(r1.next(), r2.next());
        }
    }

    #[test]
    fn rng_different_seeds() {
        let mut r1 = Rng::new(42);
        let mut r2 = Rng::new(99);
        assert_ne!(r1.next(), r2.next());
    }

    #[test]
    fn build_random_packet_min_size() {
        let mut rng = Rng::new(1);
        let pkt = build_random_packet(&mut rng);
        assert!(pkt.len() >= 64);
    }

    #[test]
    fn build_matching_ipv4_tcp() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            ip_protocol: Some(6),
            dst_port: Some(crate::model::PortMatch::Exact(80)),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        // Check ethertype at offset 12-13
        assert_eq!(pkt[12], 0x08);
        assert_eq!(pkt[13], 0x00);
        // Check IP protocol at offset 23
        assert_eq!(pkt[23], 6);
    }

    #[test]
    fn build_matching_arp() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x0806".to_string()),
            arp_opcode: Some(1),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        assert_eq!(pkt[12], 0x08);
        assert_eq!(pkt[13], 0x06);
    }

    #[test]
    fn generate_traffic_basic() {
        let config = FilterConfig {
            pacgate: crate::model::PacgateConfig {
                version: "1.0".to_string(),
                defaults: crate::model::Defaults { action: Action::Drop },
                rules: vec![
                    crate::model::StatelessRule {
                        name: "test_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ip_protocol: Some(6),
                            dst_port: Some(crate::model::PortMatch::Exact(80)),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None,
                        rewrite: None, mirror_port: None, redirect_port: None,
                        rss_queue: None, int_insert: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let dir = std::env::temp_dir().join("pacgate_pcapgen_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.pcap");
        let stats = generate_traffic(&config, &path, 10, 42).unwrap();
        assert_eq!(stats["packets_generated"], 10);
        assert_eq!(stats["rules_covered"], 1);
        assert!(std::fs::metadata(&path).unwrap().len() > 24); // > PCAP header
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pcap_file_valid_header() {
        let packets = vec![vec![0u8; 64], vec![0u8; 128]];
        let dir = std::env::temp_dir().join("pacgate_pcapgen_header");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.pcap");
        let bytes = write_pcap(&path, &packets).unwrap();
        assert_eq!(bytes, 24 + 16 + 64 + 16 + 128); // header + 2*(pkt_hdr + data)
        let data = std::fs::read(&path).unwrap();
        // Check magic number
        assert_eq!(&data[0..4], &0xA1B2C3D4u32.to_le_bytes());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn push_mac_parse() {
        let mut pkt = Vec::new();
        push_mac(&mut pkt, "AA:BB:CC:DD:EE:FF");
        assert_eq!(pkt, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn push_ipv4_from_cidr_exact() {
        let mut pkt = Vec::new();
        let mut rng = Rng::new(42);
        push_ipv4_from_cidr(&mut pkt, "10.0.0.1/32", &mut rng);
        assert_eq!(pkt, vec![10, 0, 0, 1]);
    }

    #[test]
    fn push_ipv4_from_cidr_subnet() {
        let mut pkt = Vec::new();
        let mut rng = Rng::new(42);
        push_ipv4_from_cidr(&mut pkt, "192.168.1.0/24", &mut rng);
        assert_eq!(pkt[0], 192);
        assert_eq!(pkt[1], 168);
        assert_eq!(pkt[2], 1);
        // Last octet is random within subnet
    }

    #[test]
    fn build_matching_ipv6() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x86DD".to_string()),
            ipv6_next_header: Some(6),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        assert_eq!(pkt[12], 0x86);
        assert_eq!(pkt[13], 0xDD);
    }

    #[test]
    fn build_matching_udp_vxlan() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x0800".to_string()),
            ip_protocol: Some(17),
            dst_port: Some(crate::model::PortMatch::Exact(4789)),
            vxlan_vni: Some(42000),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        assert_eq!(pkt[23], 17); // UDP protocol
    }

    #[test]
    fn build_matching_ptp() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x88F7".to_string()),
            ptp_message_type: Some(0),
            ptp_domain: Some(0),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        assert_eq!(pkt[12], 0x88);
        assert_eq!(pkt[13], 0xF7);
    }

    #[test]
    fn build_matching_oam() {
        let mut rng = Rng::new(1);
        let mc = MatchCriteria {
            ethertype: Some("0x8902".to_string()),
            oam_level: Some(3),
            oam_opcode: Some(1),
            ..Default::default()
        };
        let pkt = build_matching_packet(&mc, &mut rng);
        assert!(pkt.len() >= 64);
        assert_eq!(pkt[12], 0x89);
        assert_eq!(pkt[13], 0x02);
    }

    #[test]
    fn generate_traffic_reproducible() {
        let config = FilterConfig {
            pacgate: crate::model::PacgateConfig {
                version: "1.0".to_string(),
                defaults: crate::model::Defaults { action: Action::Drop },
                rules: vec![],
                conntrack: None,
                tables: None,
            },
        };
        let dir = std::env::temp_dir().join("pacgate_pcapgen_repro");
        std::fs::create_dir_all(&dir).unwrap();
        let path1 = dir.join("test1.pcap");
        let path2 = dir.join("test2.pcap");
        generate_traffic(&config, &path1, 5, 42).unwrap();
        generate_traffic(&config, &path2, 5, 42).unwrap();
        let data1 = std::fs::read(&path1).unwrap();
        let data2 = std::fs::read(&path2).unwrap();
        assert_eq!(data1, data2, "Same seed should produce identical output");
        std::fs::remove_dir_all(&dir).ok();
    }
}
