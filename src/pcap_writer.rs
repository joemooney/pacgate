use anyhow::Result;
use std::io::Write;
use std::path::Path;

/// PCAP global header (24 bytes)
struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

impl PcapGlobalHeader {
    fn new() -> Self {
        PcapGlobalHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1, // Ethernet
        }
    }

    fn write<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.magic_number.to_le_bytes())?;
        w.write_all(&self.version_major.to_le_bytes())?;
        w.write_all(&self.version_minor.to_le_bytes())?;
        w.write_all(&self.thiszone.to_le_bytes())?;
        w.write_all(&self.sigfigs.to_le_bytes())?;
        w.write_all(&self.snaplen.to_le_bytes())?;
        w.write_all(&self.network.to_le_bytes())?;
        Ok(())
    }
}

/// PCAP packet header (16 bytes)
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

impl PcapPacketHeader {
    fn write<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.ts_sec.to_le_bytes())?;
        w.write_all(&self.ts_usec.to_le_bytes())?;
        w.write_all(&self.incl_len.to_le_bytes())?;
        w.write_all(&self.orig_len.to_le_bytes())?;
        Ok(())
    }
}

/// A simulation result packet to write to PCAP
pub struct SimPacketRecord {
    /// Raw Ethernet frame bytes
    pub frame_data: Vec<u8>,
    /// Matched rule name (None = default action)
    pub rule_name: Option<String>,
    /// Action taken (pass or drop)
    pub action: String,
    /// Packet sequence number
    pub seq: u32,
    /// Original PCAP timestamp (seconds)
    pub ts_sec: u32,
    /// Original PCAP timestamp (microseconds)
    pub ts_usec: u32,
}

/// Write a PCAP file from simulation results
pub fn write_pcap(path: &Path, packets: &[SimPacketRecord]) -> Result<()> {
    let mut file = std::fs::File::create(path)?;

    // Write global header
    PcapGlobalHeader::new().write(&mut file)?;

    // Write each packet
    for (_i, pkt) in packets.iter().enumerate() {
        let pkt_header = PcapPacketHeader {
            ts_sec: pkt.ts_sec,
            ts_usec: pkt.ts_usec,
            incl_len: pkt.frame_data.len() as u32,
            orig_len: pkt.frame_data.len() as u32,
        };

        pkt_header.write(&mut file)?;
        file.write_all(&pkt.frame_data)?;
    }

    Ok(())
}

/// Build a minimal Ethernet frame from simulation packet fields
pub fn build_frame_from_sim(
    src_mac: &str,
    dst_mac: &str,
    ethertype: u16,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    ip_protocol: Option<u8>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Vec<u8> {
    let mut frame = Vec::new();

    // Ethernet header: dst MAC + src MAC + ethertype
    frame.extend_from_slice(&parse_mac(dst_mac));
    frame.extend_from_slice(&parse_mac(src_mac));
    frame.push((ethertype >> 8) as u8);
    frame.push((ethertype & 0xff) as u8);

    // If IPv4, build IP header
    if ethertype == 0x0800 {
        let src = src_ip.map(|s| parse_ipv4(s)).unwrap_or([10, 0, 0, 1]);
        let dst = dst_ip.map(|s| parse_ipv4(s)).unwrap_or([10, 0, 0, 2]);
        let proto = ip_protocol.unwrap_or(6);

        // Minimal IPv4 header (20 bytes)
        let total_len: u16 = 40; // IP + 20 bytes payload/L4
        frame.push(0x45); // version + IHL
        frame.push(0x00); // DSCP/ECN
        frame.push((total_len >> 8) as u8);
        frame.push((total_len & 0xff) as u8);
        frame.extend_from_slice(&[0x00, 0x00]); // identification
        frame.extend_from_slice(&[0x00, 0x00]); // flags + frag offset
        frame.push(64); // TTL
        frame.push(proto);
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);

        // L4 header (ports if TCP/UDP)
        if proto == 6 || proto == 17 {
            let sp = src_port.unwrap_or(12345);
            let dp = dst_port.unwrap_or(80);
            frame.push((sp >> 8) as u8);
            frame.push((sp & 0xff) as u8);
            frame.push((dp >> 8) as u8);
            frame.push((dp & 0xff) as u8);
            // Pad to minimum
            frame.extend_from_slice(&[0u8; 16]);
        } else {
            frame.extend_from_slice(&[0u8; 20]);
        }
    } else {
        // Non-IPv4: just pad
        frame.extend_from_slice(&[0u8; 46]);
    }

    frame
}

fn parse_mac(mac: &str) -> [u8; 6] {
    let mut result = [0u8; 6];
    for (i, part) in mac.split(':').enumerate() {
        if i < 6 {
            result[i] = u8::from_str_radix(part, 16).unwrap_or(0);
        }
    }
    result
}

fn parse_ipv4(addr: &str) -> [u8; 4] {
    let mut result = [0u8; 4];
    for (i, part) in addr.split('.').enumerate() {
        if i < 4 {
            result[i] = part.parse().unwrap_or(0);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_pcap_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.pcap");

        let packets = vec![
            SimPacketRecord {
                frame_data: vec![0xFF; 64],
                rule_name: Some("test_rule".to_string()),
                action: "pass".to_string(),
                seq: 0,
                ts_sec: 0,
                ts_usec: 0,
            },
        ];

        write_pcap(&path, &packets).unwrap();
        let data = std::fs::read(&path).unwrap();
        // Global header (24) + packet header (16) + data (64) = 104
        assert_eq!(data.len(), 104);
        // Check magic number
        assert_eq!(&data[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    }

    #[test]
    fn write_pcap_multiple_packets() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("multi.pcap");

        let packets = vec![
            SimPacketRecord { frame_data: vec![0; 60], rule_name: None, action: "drop".to_string(), seq: 0, ts_sec: 0, ts_usec: 0 },
            SimPacketRecord { frame_data: vec![0; 60], rule_name: Some("r1".to_string()), action: "pass".to_string(), seq: 1, ts_sec: 1, ts_usec: 0 },
        ];

        write_pcap(&path, &packets).unwrap();
        let data = std::fs::read(&path).unwrap();
        // 24 + 2 * (16 + 60) = 24 + 152 = 176
        assert_eq!(data.len(), 176);
    }

    #[test]
    fn build_frame_ipv4_tcp() {
        let frame = build_frame_from_sim(
            "02:00:00:00:00:01", "de:ad:be:ef:00:01",
            0x0800, Some("10.0.0.1"), Some("10.0.0.2"),
            Some(6), Some(12345), Some(80),
        );
        // 14 (eth) + 20 (ip) + 20 (tcp) = 54
        assert_eq!(frame.len(), 54);
        // Check ethertype
        assert_eq!(frame[12], 0x08);
        assert_eq!(frame[13], 0x00);
        // Check IP version
        assert_eq!(frame[14], 0x45);
    }

    #[test]
    fn build_frame_non_ipv4() {
        let frame = build_frame_from_sim(
            "02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff",
            0x0806, None, None, None, None, None,
        );
        assert_eq!(frame.len(), 60); // 14 + 46
    }
}
