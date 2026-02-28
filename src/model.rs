use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Drop,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MatchCriteria {
    pub dst_mac: Option<String>,
    pub src_mac: Option<String>,
    pub ethertype: Option<String>,
    pub vlan_id: Option<u16>,
    pub vlan_pcp: Option<u8>,
    // L3 fields (IPv4)
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_protocol: Option<u8>,
    // L4 fields (TCP/UDP)
    pub src_port: Option<PortMatch>,
    pub dst_port: Option<PortMatch>,
    // VXLAN tunnel
    pub vxlan_vni: Option<u32>,
    // L3 fields (IPv6)
    #[serde(default)]
    pub src_ipv6: Option<String>,
    #[serde(default)]
    pub dst_ipv6: Option<String>,
    #[serde(default)]
    pub ipv6_next_header: Option<u8>,
    // GTP tunnel (5G)
    #[serde(default)]
    pub gtp_teid: Option<u32>,
    // MPLS label stack
    #[serde(default)]
    pub mpls_label: Option<u32>,
    #[serde(default)]
    pub mpls_tc: Option<u8>,
    #[serde(default)]
    pub mpls_bos: Option<bool>,
    // Multicast
    #[serde(default)]
    pub igmp_type: Option<u8>,
    #[serde(default)]
    pub mld_type: Option<u8>,
    // QoS fields (IPv4 TOS byte: DSCP[7:2] + ECN[1:0])
    #[serde(default)]
    pub ip_dscp: Option<u8>,
    #[serde(default)]
    pub ip_ecn: Option<u8>,
    // IPv6 Traffic Class (TC byte: DSCP[7:2] + ECN[1:0])
    #[serde(default)]
    pub ipv6_dscp: Option<u8>,    // 0-63
    #[serde(default)]
    pub ipv6_ecn: Option<u8>,     // 0-3
    // TCP flags (value + mask pattern for flexible matching)
    #[serde(default)]
    pub tcp_flags: Option<u8>,     // TCP flags byte: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
    #[serde(default)]
    pub tcp_flags_mask: Option<u8>, // Which flag bits to check (default: 0xFF if tcp_flags set)
    // ICMP Type/Code (IPv4 protocol 1)
    #[serde(default)]
    pub icmp_type: Option<u8>,     // 0-255 (e.g., 8=echo request, 0=echo reply)
    #[serde(default)]
    pub icmp_code: Option<u8>,     // 0-255
    // ICMPv6 Type/Code (IPv6 next_header 58)
    #[serde(default)]
    pub icmpv6_type: Option<u8>,   // 0-255 (e.g., 128=echo request, 133-137=NDP)
    #[serde(default)]
    pub icmpv6_code: Option<u8>,   // 0-255
    // ARP fields (ethertype 0x0806)
    #[serde(default)]
    pub arp_opcode: Option<u16>,   // 1=request, 2=reply
    #[serde(default)]
    pub arp_spa: Option<String>,   // Sender Protocol Address (IPv4 dotted-quad)
    #[serde(default)]
    pub arp_tpa: Option<String>,   // Target Protocol Address (IPv4 dotted-quad)
    // IPv6 extension fields
    #[serde(default)]
    pub ipv6_hop_limit: Option<u8>,    // 0-255 (TTL equivalent)
    #[serde(default)]
    pub ipv6_flow_label: Option<u32>,  // 0-0xFFFFF (20-bit)
    // Byte-offset matching
    #[serde(default)]
    pub byte_match: Option<Vec<ByteMatch>>,
}

/// Byte-offset matching: match raw bytes at a specific offset in the packet
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ByteMatch {
    pub offset: u16,
    pub value: String,
    #[serde(default)]
    pub mask: Option<String>,
}

/// Port matching: exact value or range
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PortMatch {
    Exact(u16),
    Range { range: [u16; 2] },
}

/// Parsed IPv4 address with prefix length for CIDR matching
#[derive(Debug, Clone)]
pub struct Ipv4Prefix {
    pub addr: [u8; 4],
    pub prefix_len: u8,
    pub mask: [u8; 4],
}

impl Ipv4Prefix {
    /// Parse "10.0.0.0/8" or "192.168.1.1" (implies /32)
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (addr_str, prefix_len) = if let Some(idx) = s.find('/') {
            let plen: u8 = s[idx+1..].parse()
                .map_err(|e| anyhow::anyhow!("Bad prefix length in '{}': {}", s, e))?;
            if plen > 32 {
                anyhow::bail!("Prefix length must be 0-32, got {} in '{}'", plen, s);
            }
            (&s[..idx], plen)
        } else {
            (s, 32)
        };

        let parts: Vec<&str> = addr_str.split('.').collect();
        if parts.len() != 4 {
            anyhow::bail!("IPv4 address must have 4 octets: {}", s);
        }
        let mut addr = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            addr[i] = part.parse()
                .map_err(|e| anyhow::anyhow!("Bad IPv4 octet '{}': {}", part, e))?;
        }

        // Build mask from prefix length
        let mask_u32 = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
        let mask = mask_u32.to_be_bytes();

        Ok(Ipv4Prefix { addr, prefix_len, mask })
    }

    pub fn to_verilog_value(&self) -> String {
        format!("32'h{:02x}{:02x}{:02x}{:02x}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3])
    }

    pub fn to_verilog_mask(&self) -> String {
        format!("32'h{:02x}{:02x}{:02x}{:02x}",
            self.mask[0], self.mask[1], self.mask[2], self.mask[3])
    }
}

/// Parsed IPv6 address with prefix length for CIDR matching
#[derive(Debug, Clone)]
pub struct Ipv6Prefix {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub mask: [u8; 16],
}

impl Ipv6Prefix {
    /// Parse "2001:db8::1/32", "fe80::/10", "::1" (implies /128)
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (addr_str, prefix_len) = if let Some(idx) = s.find('/') {
            let plen: u8 = s[idx+1..].parse()
                .map_err(|e| anyhow::anyhow!("Bad prefix length in '{}': {}", s, e))?;
            if plen > 128 {
                anyhow::bail!("IPv6 prefix length must be 0-128, got {} in '{}'", plen, s);
            }
            (&s[..idx], plen)
        } else {
            (s, 128)
        };

        let addr = Self::parse_ipv6_addr(addr_str)
            .map_err(|e| anyhow::anyhow!("Bad IPv6 address '{}': {}", s, e))?;

        // Build mask from prefix length
        let mut mask = [0u8; 16];
        for i in 0..16 {
            let bit_pos = i * 8;
            if bit_pos + 8 <= prefix_len as usize {
                mask[i] = 0xff;
            } else if bit_pos < prefix_len as usize {
                let bits = prefix_len as usize - bit_pos;
                mask[i] = !0u8 << (8 - bits);
            }
        }

        Ok(Ipv6Prefix { addr, prefix_len, mask })
    }

    /// Parse an IPv6 address string into 16 bytes
    fn parse_ipv6_addr(s: &str) -> anyhow::Result<[u8; 16]> {
        // Handle :: expansion
        let parts: Vec<&str> = if s.contains("::") {
            let halves: Vec<&str> = s.splitn(2, "::").collect();
            let left: Vec<&str> = if halves[0].is_empty() {
                Vec::new()
            } else {
                halves[0].split(':').collect()
            };
            let right: Vec<&str> = if halves.len() > 1 && !halves[1].is_empty() {
                halves[1].split(':').collect()
            } else {
                Vec::new()
            };
            let missing = 8 - left.len() - right.len();
            let mut result = left;
            for _ in 0..missing {
                result.push("0");
            }
            result.extend(right);
            result
        } else {
            s.split(':').collect()
        };

        if parts.len() != 8 {
            anyhow::bail!("IPv6 address must have 8 groups (got {})", parts.len());
        }

        let mut addr = [0u8; 16];
        for (i, part) in parts.iter().enumerate() {
            let val = u16::from_str_radix(part, 16)
                .map_err(|e| anyhow::anyhow!("Bad IPv6 group '{}': {}", part, e))?;
            addr[i * 2] = (val >> 8) as u8;
            addr[i * 2 + 1] = val as u8;
        }

        Ok(addr)
    }

    pub fn to_verilog_value(&self) -> String {
        let hex: String = self.addr.iter().map(|b| format!("{:02x}", b)).collect();
        format!("128'h{}", hex)
    }

    pub fn to_verilog_mask(&self) -> String {
        let hex: String = self.mask.iter().map(|b| format!("{:02x}", b)).collect();
        format!("128'h{}", hex)
    }
}

impl MatchCriteria {
    /// Returns true if this criteria uses any L3/L4 fields
    pub fn uses_l3l4(&self) -> bool {
        self.src_ip.is_some() || self.dst_ip.is_some() || self.ip_protocol.is_some()
            || self.src_port.is_some() || self.dst_port.is_some()
            || self.vxlan_vni.is_some()
            || self.src_ipv6.is_some() || self.dst_ipv6.is_some() || self.ipv6_next_header.is_some()
    }

    /// Returns true if this criteria uses IPv6 fields
    pub fn uses_ipv6(&self) -> bool {
        self.src_ipv6.is_some() || self.dst_ipv6.is_some() || self.ipv6_next_header.is_some()
    }

    /// Returns true if this criteria uses byte_match
    pub fn uses_byte_match(&self) -> bool {
        self.byte_match.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
    }

    /// Returns true if this criteria uses GTP tunnel fields
    pub fn uses_gtp(&self) -> bool {
        self.gtp_teid.is_some()
    }

    /// Returns true if this criteria uses MPLS fields
    pub fn uses_mpls(&self) -> bool {
        self.mpls_label.is_some() || self.mpls_tc.is_some() || self.mpls_bos.is_some()
    }

    /// Returns true if this criteria uses multicast fields
    pub fn uses_multicast(&self) -> bool {
        self.igmp_type.is_some() || self.mld_type.is_some()
    }

    /// Returns true if this criteria uses DSCP/ECN QoS fields
    pub fn uses_dscp_ecn(&self) -> bool {
        self.ip_dscp.is_some() || self.ip_ecn.is_some()
    }

    /// Returns true if this criteria uses IPv6 Traffic Class fields
    pub fn uses_ipv6_tc(&self) -> bool {
        self.ipv6_dscp.is_some() || self.ipv6_ecn.is_some()
    }

    /// Returns true if this criteria uses TCP flags matching
    pub fn uses_tcp_flags(&self) -> bool {
        self.tcp_flags.is_some()
    }

    /// Returns true if this criteria uses ICMP type/code matching
    pub fn uses_icmp(&self) -> bool {
        self.icmp_type.is_some() || self.icmp_code.is_some()
    }

    /// Returns true if this criteria uses ICMPv6 type/code matching
    pub fn uses_icmpv6(&self) -> bool {
        self.icmpv6_type.is_some() || self.icmpv6_code.is_some()
    }

    /// Returns true if this criteria uses ARP fields
    pub fn uses_arp(&self) -> bool {
        self.arp_opcode.is_some() || self.arp_spa.is_some() || self.arp_tpa.is_some()
    }

    /// Returns true if this criteria uses IPv6 extension fields
    pub fn uses_ipv6_ext(&self) -> bool {
        self.ipv6_hop_limit.is_some() || self.ipv6_flow_label.is_some()
    }
}

// --- Stateful FSM types ---

/// Variable declaration for HSM
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FsmVariable {
    pub name: String,
    #[serde(default = "default_var_width")]
    pub width: u8,
    #[serde(default)]
    pub reset_value: u64,
}

fn default_var_width() -> u8 { 16 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FsmTransition {
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,
    pub next_state: String,
    pub action: Action,
    /// Guard expression referencing FSM variables (e.g. "pkt_count > 10")
    #[serde(default)]
    pub guard: Option<String>,
    /// Actions to execute on this transition (e.g. ["counter += 1"])
    #[serde(default)]
    pub on_transition: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FsmState {
    #[serde(default)]
    pub timeout_cycles: Option<u64>,
    pub transitions: Vec<FsmTransition>,
    /// Nested substates for hierarchical state machines
    #[serde(default)]
    pub substates: Option<std::collections::HashMap<String, FsmState>>,
    /// Initial substate when entering a composite state
    #[serde(default)]
    pub initial_substate: Option<String>,
    /// Actions to execute on state entry
    #[serde(default)]
    pub on_entry: Option<Vec<String>>,
    /// Actions to execute on state exit
    #[serde(default)]
    pub on_exit: Option<Vec<String>>,
    /// Enable history for this composite state
    #[serde(default)]
    pub history: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FsmDefinition {
    pub initial_state: String,
    pub states: std::collections::HashMap<String, FsmState>,
    /// FSM variables (registers)
    #[serde(default)]
    pub variables: Option<Vec<FsmVariable>>,
}

// --- Packet rewrite actions ---

/// In-place packet header rewrite actions applied after filtering
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct RewriteAction {
    /// Overwrite destination MAC address (48-bit, format xx:xx:xx:xx:xx:xx)
    #[serde(default)]
    pub set_dst_mac: Option<String>,
    /// Overwrite source MAC address (48-bit, format xx:xx:xx:xx:xx:xx)
    #[serde(default)]
    pub set_src_mac: Option<String>,
    /// Overwrite VLAN ID (12-bit, 0-4095) — requires VLAN-tagged frame
    #[serde(default)]
    pub set_vlan_id: Option<u16>,
    /// Set TTL to a fixed value (8-bit) — mutually exclusive with dec_ttl
    #[serde(default)]
    pub set_ttl: Option<u8>,
    /// Decrement TTL by 1 — mutually exclusive with set_ttl
    #[serde(default)]
    pub dec_ttl: Option<bool>,
    /// Overwrite source IPv4 address (dotted decimal, no CIDR)
    #[serde(default)]
    pub set_src_ip: Option<String>,
    /// Overwrite destination IPv4 address (dotted decimal, no CIDR)
    #[serde(default)]
    pub set_dst_ip: Option<String>,
    /// Overwrite DSCP value (6-bit, 0-63) — QoS remarking
    #[serde(default)]
    pub set_dscp: Option<u8>,
}

impl RewriteAction {
    /// Returns true if no rewrite operations are specified
    pub fn is_empty(&self) -> bool {
        self.set_dst_mac.is_none()
            && self.set_src_mac.is_none()
            && self.set_vlan_id.is_none()
            && self.set_ttl.is_none()
            && (self.dec_ttl.is_none() || self.dec_ttl == Some(false))
            && self.set_src_ip.is_none()
            && self.set_dst_ip.is_none()
            && self.set_dscp.is_none()
    }

    /// Returns the set of rewrite flags for Verilog generation
    /// [0]=set_dst_mac [1]=set_src_mac [2]=set_vlan_id
    /// [3]=set_ttl [4]=dec_ttl [5]=set_src_ip [6]=set_dst_ip [7]=set_dscp
    pub fn flags(&self) -> u8 {
        let mut f: u8 = 0;
        if self.set_dst_mac.is_some() { f |= 1 << 0; }
        if self.set_src_mac.is_some() { f |= 1 << 1; }
        if self.set_vlan_id.is_some() { f |= 1 << 2; }
        if self.set_ttl.is_some() { f |= 1 << 3; }
        if self.dec_ttl == Some(true) { f |= 1 << 4; }
        if self.set_src_ip.is_some() { f |= 1 << 5; }
        if self.set_dst_ip.is_some() { f |= 1 << 6; }
        if self.set_dscp.is_some() { f |= 1 << 7; }
        f
    }
}

// --- Rate limiting ---

/// Token-bucket rate limiter configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimit {
    /// Packets per second
    pub pps: u32,
    /// Maximum burst size (tokens)
    pub burst: u32,
}

// --- Rule types ---

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatelessRule {
    pub name: String,
    pub priority: u32,
    #[serde(default)]
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    #[serde(default)]
    pub fsm: Option<FsmDefinition>,
    /// Which ports this rule applies to (multi-port mode)
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// Per-rule rate limiting (token bucket)
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    /// Packet rewrite actions (applied to passed packets in AXI output path)
    #[serde(default)]
    pub rewrite: Option<RewriteAction>,
}

impl StatelessRule {
    pub fn is_stateful(&self) -> bool {
        self.rule_type.as_deref() == Some("stateful")
    }

    /// Get action (required for stateless, not for stateful)
    pub fn action(&self) -> Action {
        self.action.clone().unwrap_or(Action::Drop)
    }

    /// Returns true if this rule has any rewrite actions
    pub fn has_rewrite(&self) -> bool {
        self.rewrite.as_ref().map(|r| !r.is_empty()).unwrap_or(false)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Defaults {
    pub action: Action,
}

/// Connection tracking configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConntrackConfig {
    pub table_size: u32,
    pub timeout_cycles: u64,
    #[serde(default = "default_conntrack_fields")]
    pub fields: Vec<String>,
}

fn default_conntrack_fields() -> Vec<String> {
    vec![
        "src_ip".to_string(), "dst_ip".to_string(),
        "ip_protocol".to_string(), "src_port".to_string(), "dst_port".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacgateConfig {
    pub version: String,
    pub defaults: Defaults,
    pub rules: Vec<StatelessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conntrack: Option<ConntrackConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub pacgate: PacgateConfig,
}

/// Parsed MAC address with value and mask (for wildcard support)
#[derive(Debug, Clone)]
pub struct MacAddress {
    pub value: [u8; 6],
    pub mask: [u8; 6],
}

impl MacAddress {
    /// Parse a MAC string like "00:1a:2b:*:*:*" into value + mask
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            anyhow::bail!("MAC address must have 6 octets: {}", s);
        }
        let mut value = [0u8; 6];
        let mut mask = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if *part == "*" {
                value[i] = 0x00;
                mask[i] = 0x00;
            } else {
                value[i] = u8::from_str_radix(part, 16)
                    .map_err(|e| anyhow::anyhow!("Bad MAC octet '{}': {}", part, e))?;
                mask[i] = 0xFF;
            }
        }
        Ok(MacAddress { value, mask })
    }

    pub fn to_verilog_value(&self) -> String {
        format!(
            "48'h{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.value[0], self.value[1], self.value[2],
            self.value[3], self.value[4], self.value[5]
        )
    }

    pub fn to_verilog_mask(&self) -> String {
        format!(
            "48'h{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.mask[0], self.mask[1], self.mask[2],
            self.mask[3], self.mask[4], self.mask[5]
        )
    }
}

impl ByteMatch {
    /// Parse hex string like "0x45" or "0x4500" into bytes
    pub fn parse_hex_value(s: &str) -> anyhow::Result<Vec<u8>> {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        if s.len() % 2 != 0 {
            anyhow::bail!("Hex value must have even number of digits: {}", s);
        }
        let mut bytes = Vec::new();
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i+2], 16)
                .map_err(|e| anyhow::anyhow!("Bad hex byte in '{}': {}", s, e))?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Number of bytes in the value
    pub fn byte_len(&self) -> anyhow::Result<usize> {
        Ok(Self::parse_hex_value(&self.value)?.len())
    }

    /// Value as Verilog hex literal
    pub fn to_verilog_value(&self) -> anyhow::Result<String> {
        let bytes = Self::parse_hex_value(&self.value)?;
        let bits = bytes.len() * 8;
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(format!("{}'h{}", bits, hex))
    }

    /// Mask as Verilog hex literal (all-ones if no mask specified)
    pub fn to_verilog_mask(&self) -> anyhow::Result<String> {
        let value_bytes = Self::parse_hex_value(&self.value)?;
        let bits = value_bytes.len() * 8;
        if let Some(ref mask) = self.mask {
            let mask_bytes = Self::parse_hex_value(mask)?;
            let hex: String = mask_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            Ok(format!("{}'h{}", bits, hex))
        } else {
            let hex: String = value_bytes.iter().map(|_| "ff".to_string()).collect();
            Ok(format!("{}'h{}", bits, hex))
        }
    }
}

/// Parse ethertype string "0x0806" -> u16
pub fn parse_ethertype(s: &str) -> anyhow::Result<u16> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(s, 16).map_err(|e| anyhow::anyhow!("Bad ethertype '{}': {}", s, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- MacAddress parsing ---

    #[test]
    fn mac_exact_parse() {
        let mac = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.value, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.mask, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn mac_wildcard_parse() {
        let mac = MacAddress::parse("00:1a:2b:*:*:*").unwrap();
        assert_eq!(mac.value, [0x00, 0x1a, 0x2b, 0x00, 0x00, 0x00]);
        assert_eq!(mac.mask, [0xff, 0xff, 0xff, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn mac_all_wildcard() {
        let mac = MacAddress::parse("*:*:*:*:*:*").unwrap();
        assert_eq!(mac.value, [0; 6]);
        assert_eq!(mac.mask, [0; 6]);
    }

    #[test]
    fn mac_broadcast() {
        let mac = MacAddress::parse("ff:ff:ff:ff:ff:ff").unwrap();
        assert_eq!(mac.value, [0xff; 6]);
        assert_eq!(mac.mask, [0xff; 6]);
    }

    #[test]
    fn mac_too_few_octets() {
        assert!(MacAddress::parse("aa:bb:cc").is_err());
    }

    #[test]
    fn mac_too_many_octets() {
        assert!(MacAddress::parse("aa:bb:cc:dd:ee:ff:00").is_err());
    }

    #[test]
    fn mac_invalid_hex() {
        assert!(MacAddress::parse("gg:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn mac_verilog_value() {
        let mac = MacAddress::parse("00:1a:2b:cc:dd:ee").unwrap();
        assert_eq!(mac.to_verilog_value(), "48'h001a2bccddee");
    }

    #[test]
    fn mac_verilog_mask_with_wildcards() {
        let mac = MacAddress::parse("00:1a:2b:*:*:*").unwrap();
        assert_eq!(mac.to_verilog_mask(), "48'hffffff000000");
    }

    // --- EtherType parsing ---

    #[test]
    fn ethertype_arp() {
        assert_eq!(parse_ethertype("0x0806").unwrap(), 0x0806);
    }

    #[test]
    fn ethertype_ipv4() {
        assert_eq!(parse_ethertype("0x0800").unwrap(), 0x0800);
    }

    #[test]
    fn ethertype_uppercase() {
        assert_eq!(parse_ethertype("0X86DD").unwrap(), 0x86DD);
    }

    #[test]
    fn ethertype_invalid() {
        assert!(parse_ethertype("0xZZZZ").is_err());
    }

    #[test]
    fn ethertype_no_prefix() {
        assert_eq!(parse_ethertype("0806").unwrap(), 0x0806);
    }

    // --- Ipv4Prefix parsing ---

    #[test]
    fn ipv4_exact_host() {
        let p = Ipv4Prefix::parse("192.168.1.1").unwrap();
        assert_eq!(p.addr, [192, 168, 1, 1]);
        assert_eq!(p.prefix_len, 32);
        assert_eq!(p.mask, [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn ipv4_class_a_cidr() {
        let p = Ipv4Prefix::parse("10.0.0.0/8").unwrap();
        assert_eq!(p.addr, [10, 0, 0, 0]);
        assert_eq!(p.prefix_len, 8);
        assert_eq!(p.mask, [0xff, 0, 0, 0]);
    }

    #[test]
    fn ipv4_slash_24() {
        let p = Ipv4Prefix::parse("172.16.0.0/24").unwrap();
        assert_eq!(p.addr, [172, 16, 0, 0]);
        assert_eq!(p.prefix_len, 24);
        assert_eq!(p.mask, [0xff, 0xff, 0xff, 0]);
    }

    #[test]
    fn ipv4_slash_0() {
        let p = Ipv4Prefix::parse("0.0.0.0/0").unwrap();
        assert_eq!(p.prefix_len, 0);
        assert_eq!(p.mask, [0, 0, 0, 0]);
    }

    #[test]
    fn ipv4_reject_prefix_33() {
        assert!(Ipv4Prefix::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn ipv4_reject_5_octets() {
        assert!(Ipv4Prefix::parse("10.0.0.0.1").is_err());
    }

    #[test]
    fn ipv4_reject_bad_octet() {
        assert!(Ipv4Prefix::parse("256.0.0.0").is_err());
    }

    #[test]
    fn ipv4_verilog_value() {
        let p = Ipv4Prefix::parse("10.20.30.40").unwrap();
        assert_eq!(p.to_verilog_value(), "32'h0a141e28");
    }

    #[test]
    fn ipv4_verilog_mask_slash16() {
        let p = Ipv4Prefix::parse("10.0.0.0/16").unwrap();
        assert_eq!(p.to_verilog_mask(), "32'hffff0000");
    }

    // --- Ipv6Prefix parsing ---

    #[test]
    fn ipv6_full_address() {
        let p = Ipv6Prefix::parse("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(p.addr[0..2], [0x20, 0x01]);
        assert_eq!(p.addr[2..4], [0x0d, 0xb8]);
        assert_eq!(p.addr[14..16], [0x00, 0x01]);
        assert_eq!(p.prefix_len, 128);
    }

    #[test]
    fn ipv6_compressed() {
        let p = Ipv6Prefix::parse("2001:db8::1").unwrap();
        assert_eq!(p.addr[0..2], [0x20, 0x01]);
        assert_eq!(p.addr[2..4], [0x0d, 0xb8]);
        assert_eq!(p.addr[14..16], [0x00, 0x01]);
        assert_eq!(p.prefix_len, 128);
    }

    #[test]
    fn ipv6_cidr_slash32() {
        let p = Ipv6Prefix::parse("2001:db8::/32").unwrap();
        assert_eq!(p.prefix_len, 32);
        assert_eq!(p.mask[0..4], [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(p.mask[4..8], [0, 0, 0, 0]);
    }

    #[test]
    fn ipv6_link_local() {
        let p = Ipv6Prefix::parse("fe80::/10").unwrap();
        assert_eq!(p.addr[0], 0xfe);
        assert_eq!(p.addr[1], 0x80);
        assert_eq!(p.prefix_len, 10);
        assert_eq!(p.mask[0], 0xff);
        assert_eq!(p.mask[1], 0xc0); // top 2 bits of byte 1
    }

    #[test]
    fn ipv6_loopback() {
        let p = Ipv6Prefix::parse("::1").unwrap();
        assert_eq!(p.addr[15], 1);
        assert_eq!(p.prefix_len, 128);
    }

    #[test]
    fn ipv6_all_zeros() {
        let p = Ipv6Prefix::parse("::/0").unwrap();
        assert_eq!(p.addr, [0u8; 16]);
        assert_eq!(p.mask, [0u8; 16]);
    }

    #[test]
    fn ipv6_reject_prefix_129() {
        assert!(Ipv6Prefix::parse("::1/129").is_err());
    }

    #[test]
    fn ipv6_reject_bad_hex() {
        assert!(Ipv6Prefix::parse("gggg::1").is_err());
    }

    #[test]
    fn ipv6_verilog_value() {
        let p = Ipv6Prefix::parse("2001:db8::1").unwrap();
        let v = p.to_verilog_value();
        assert!(v.starts_with("128'h"));
        assert!(v.contains("20010db8"));
    }

    #[test]
    fn ipv6_verilog_mask_slash64() {
        let p = Ipv6Prefix::parse("2001:db8::/64").unwrap();
        let m = p.to_verilog_mask();
        assert!(m.starts_with("128'h"));
        assert!(m.contains("ffffffffffffffff0000000000000000"));
    }

    #[test]
    fn ipv6_slash48() {
        let p = Ipv6Prefix::parse("2001:db8:abcd::/48").unwrap();
        assert_eq!(p.prefix_len, 48);
        assert_eq!(p.mask[0..6], [0xff; 6]);
        assert_eq!(p.mask[6], 0x00);
    }

    // --- PortMatch deserialization ---

    #[test]
    fn port_exact_deserialize() {
        let yaml = "22";
        let pm: PortMatch = serde_yaml::from_str(yaml).unwrap();
        match pm {
            PortMatch::Exact(v) => assert_eq!(v, 22),
            _ => panic!("expected Exact"),
        }
    }

    #[test]
    fn port_range_deserialize() {
        let yaml = "range: [1024, 65535]";
        let pm: PortMatch = serde_yaml::from_str(yaml).unwrap();
        match pm {
            PortMatch::Range { range } => {
                assert_eq!(range[0], 1024);
                assert_eq!(range[1], 65535);
            }
            _ => panic!("expected Range"),
        }
    }

    // --- Action and StatelessRule ---

    #[test]
    fn action_default_is_drop() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: None,
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
        };
        assert_eq!(rule.action(), Action::Drop);
    }

    #[test]
    fn action_explicit_pass() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: Some(Action::Pass),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
        };
        assert_eq!(rule.action(), Action::Pass);
    }

    #[test]
    fn stateful_rule_detection() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: None,
            rule_type: Some("stateful".to_string()),
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
        };
        assert!(rule.is_stateful());
    }

    #[test]
    fn stateless_rule_detection() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: Some(Action::Pass),
            rule_type: Some("stateless".to_string()),
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
        };
        assert!(!rule.is_stateful());
    }

    // --- YAML deserialization ---

    #[test]
    fn deserialize_minimal_config() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp
      type: stateless
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].name, "allow_arp");
        assert_eq!(config.pacgate.rules[0].priority, 100);
        assert_eq!(config.pacgate.defaults.action, Action::Drop);
    }

    #[test]
    fn deserialize_multiple_rules() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: rule_a
      priority: 200
      match:
        ethertype: "0x0800"
      action: pass
    - name: rule_b
      priority: 100
      match:
        dst_mac: "ff:ff:ff:ff:ff:ff"
      action: drop
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert_eq!(config.pacgate.rules[0].name, "rule_a");
        assert_eq!(config.pacgate.rules[1].name, "rule_b");
    }

    #[test]
    fn deserialize_vlan_fields() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: vlan_rule
      priority: 100
      match:
        vlan_id: 100
        vlan_pcp: 5
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.match_criteria.vlan_id, Some(100));
        assert_eq!(rule.match_criteria.vlan_pcp, Some(5));
    }

    // --- ByteMatch parsing ---

    #[test]
    fn byte_match_parse_hex() {
        let bytes = ByteMatch::parse_hex_value("0x45").unwrap();
        assert_eq!(bytes, vec![0x45]);
    }

    #[test]
    fn byte_match_parse_multi_byte() {
        let bytes = ByteMatch::parse_hex_value("0x4500").unwrap();
        assert_eq!(bytes, vec![0x45, 0x00]);
    }

    #[test]
    fn byte_match_reject_odd_digits() {
        assert!(ByteMatch::parse_hex_value("0x456").is_err());
    }

    #[test]
    fn byte_match_verilog_value() {
        let bm = ByteMatch { offset: 14, value: "0x45".to_string(), mask: None };
        assert_eq!(bm.to_verilog_value().unwrap(), "8'h45");
    }

    #[test]
    fn byte_match_verilog_mask_default() {
        let bm = ByteMatch { offset: 14, value: "0x4500".to_string(), mask: None };
        assert_eq!(bm.to_verilog_mask().unwrap(), "16'hffff");
    }

    #[test]
    fn byte_match_verilog_mask_custom() {
        let bm = ByteMatch { offset: 14, value: "0x45".to_string(), mask: Some("0xf0".to_string()) };
        assert_eq!(bm.to_verilog_mask().unwrap(), "8'hf0");
    }

    #[test]
    fn byte_match_byte_len() {
        let bm = ByteMatch { offset: 0, value: "0x001122".to_string(), mask: None };
        assert_eq!(bm.byte_len().unwrap(), 3);
    }

    #[test]
    fn deserialize_stateful_fsm() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: seq_rule
      type: stateful
      priority: 50
      fsm:
        initial_state: idle
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: arp_seen
                action: pass
          arp_seen:
            timeout_cycles: 1000
            transitions:
              - match:
                  ethertype: "0x0800"
                next_state: idle
                action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert!(rule.is_stateful());
        let fsm = rule.fsm.as_ref().unwrap();
        assert_eq!(fsm.initial_state, "idle");
        assert_eq!(fsm.states.len(), 2);
        assert_eq!(fsm.states["arp_seen"].timeout_cycles, Some(1000));
    }

    // --- Protocol extension helpers ---

    #[test]
    fn uses_gtp_true() {
        let mc = MatchCriteria { gtp_teid: Some(1000), ..Default::default() };
        assert!(mc.uses_gtp());
    }

    #[test]
    fn uses_gtp_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_gtp());
    }

    #[test]
    fn uses_mpls_label() {
        let mc = MatchCriteria { mpls_label: Some(100), ..Default::default() };
        assert!(mc.uses_mpls());
    }

    #[test]
    fn uses_mpls_tc() {
        let mc = MatchCriteria { mpls_tc: Some(7), ..Default::default() };
        assert!(mc.uses_mpls());
    }

    #[test]
    fn uses_mpls_bos() {
        let mc = MatchCriteria { mpls_bos: Some(true), ..Default::default() };
        assert!(mc.uses_mpls());
    }

    #[test]
    fn uses_multicast_igmp() {
        let mc = MatchCriteria { igmp_type: Some(17), ..Default::default() };
        assert!(mc.uses_multicast());
    }

    #[test]
    fn uses_multicast_mld() {
        let mc = MatchCriteria { mld_type: Some(130), ..Default::default() };
        assert!(mc.uses_multicast());
    }

    #[test]
    fn uses_multicast_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_multicast());
    }

    // --- DSCP/ECN helpers ---

    #[test]
    fn uses_dscp_ecn_true_dscp() {
        let mc = MatchCriteria { ip_dscp: Some(46), ..Default::default() };
        assert!(mc.uses_dscp_ecn());
    }

    #[test]
    fn uses_dscp_ecn_true_ecn() {
        let mc = MatchCriteria { ip_ecn: Some(1), ..Default::default() };
        assert!(mc.uses_dscp_ecn());
    }

    #[test]
    fn uses_dscp_ecn_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_dscp_ecn());
    }

    #[test]
    fn dscp_boundary_max() {
        let mc = MatchCriteria { ip_dscp: Some(63), ..Default::default() };
        assert!(mc.uses_dscp_ecn());
        assert_eq!(mc.ip_dscp, Some(63));
    }

    #[test]
    fn ecn_boundary_max() {
        let mc = MatchCriteria { ip_ecn: Some(3), ..Default::default() };
        assert!(mc.uses_dscp_ecn());
        assert_eq!(mc.ip_ecn, Some(3));
    }

    #[test]
    fn deserialize_dscp_ecn_rule() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: dscp_test
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
        ip_ecn: 1
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.match_criteria.ip_dscp, Some(46));
        assert_eq!(rule.match_criteria.ip_ecn, Some(1));
    }

    // --- GTP/MPLS/multicast YAML deserialization ---

    #[test]
    fn deserialize_gtp_rule() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: gtp_test
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 17
        dst_port: 2152
        gtp_teid: 1000
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.match_criteria.gtp_teid, Some(1000));
        assert_eq!(rule.match_criteria.ip_protocol, Some(17));
        assert_eq!(rule.match_criteria.dst_port, Some(crate::model::PortMatch::Exact(2152)));
    }

    #[test]
    fn deserialize_mpls_rule() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: mpls_test
      priority: 100
      match:
        ethertype: "0x8847"
        mpls_label: 200
        mpls_tc: 5
        mpls_bos: true
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.match_criteria.mpls_label, Some(200));
        assert_eq!(rule.match_criteria.mpls_tc, Some(5));
        assert_eq!(rule.match_criteria.mpls_bos, Some(true));
    }

    #[test]
    fn deserialize_multicast_rule() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: pass
  rules:
    - name: igmp_test
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 2
        igmp_type: 22
      action: pass
    - name: mld_test
      priority: 90
      match:
        ethertype: "0x86DD"
        ipv6_next_header: 58
        mld_type: 131
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.igmp_type, Some(22));
        assert_eq!(config.pacgate.rules[1].match_criteria.mld_type, Some(131));
    }

    // --- RewriteAction tests ---

    #[test]
    fn rewrite_action_default_is_empty() {
        let rw = RewriteAction::default();
        assert!(rw.is_empty());
        assert_eq!(rw.flags(), 0);
    }

    #[test]
    fn rewrite_action_flags_set_dst_mac() {
        let rw = RewriteAction {
            set_dst_mac: Some("00:11:22:33:44:55".to_string()),
            ..Default::default()
        };
        assert!(!rw.is_empty());
        assert_eq!(rw.flags(), 0b0000001);
    }

    #[test]
    fn rewrite_action_flags_all() {
        let rw = RewriteAction {
            set_dst_mac: Some("00:11:22:33:44:55".to_string()),
            set_src_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            set_vlan_id: Some(100),
            set_ttl: Some(64),
            dec_ttl: None,
            set_src_ip: Some("10.0.0.1".to_string()),
            set_dst_ip: Some("192.168.1.1".to_string()),
            set_dscp: None,
        };
        assert!(!rw.is_empty());
        // flags: dst_mac=1, src_mac=2, vlan=4, set_ttl=8, src_ip=32, dst_ip=64
        assert_eq!(rw.flags(), 0b01101111);
    }

    #[test]
    fn rewrite_action_flags_set_dscp() {
        let rw = RewriteAction {
            set_dscp: Some(46),
            ..Default::default()
        };
        assert!(!rw.is_empty());
        assert_eq!(rw.flags(), 0b10000000);
    }

    #[test]
    fn rewrite_action_flags_dec_ttl() {
        let rw = RewriteAction {
            dec_ttl: Some(true),
            ..Default::default()
        };
        assert!(!rw.is_empty());
        assert_eq!(rw.flags(), 0b0010000);
    }

    #[test]
    fn rewrite_action_dec_ttl_false_is_empty() {
        let rw = RewriteAction {
            dec_ttl: Some(false),
            ..Default::default()
        };
        assert!(rw.is_empty());
        assert_eq!(rw.flags(), 0);
    }

    #[test]
    fn has_rewrite_true() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: Some(Action::Pass),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: Some(RewriteAction {
                set_dst_mac: Some("00:11:22:33:44:55".to_string()),
                ..Default::default()
            }),
        };
        assert!(rule.has_rewrite());
    }

    #[test]
    fn has_rewrite_false_none() {
        let rule = StatelessRule {
            name: "test".to_string(),
            priority: 100,
            match_criteria: MatchCriteria::default(),
            action: Some(Action::Pass),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
        };
        assert!(!rule.has_rewrite());
    }

    // --- IPv6 TC / TCP flags / ICMP helpers ---

    #[test]
    fn uses_ipv6_tc_true_dscp() {
        let mc = MatchCriteria { ipv6_dscp: Some(46), ..Default::default() };
        assert!(mc.uses_ipv6_tc());
    }

    #[test]
    fn uses_ipv6_tc_true_ecn() {
        let mc = MatchCriteria { ipv6_ecn: Some(1), ..Default::default() };
        assert!(mc.uses_ipv6_tc());
    }

    #[test]
    fn uses_ipv6_tc_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_ipv6_tc());
    }

    #[test]
    fn uses_tcp_flags_true() {
        let mc = MatchCriteria { tcp_flags: Some(0x02), ..Default::default() };
        assert!(mc.uses_tcp_flags());
    }

    #[test]
    fn uses_tcp_flags_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_tcp_flags());
    }

    #[test]
    fn uses_icmp_true_type() {
        let mc = MatchCriteria { icmp_type: Some(8), ..Default::default() };
        assert!(mc.uses_icmp());
    }

    #[test]
    fn uses_icmp_true_code() {
        let mc = MatchCriteria { icmp_code: Some(0), ..Default::default() };
        assert!(mc.uses_icmp());
    }

    #[test]
    fn uses_icmp_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_icmp());
    }

    #[test]
    fn deserialize_ipv6_tc_tcp_flags_icmp() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_dscp_test
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_dscp: 46
        ipv6_ecn: 2
      action: pass
    - name: tcp_flags_test
      priority: 90
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 2
        tcp_flags_mask: 18
      action: pass
    - name: icmp_test
      priority: 80
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 8
        icmp_code: 0
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 3);
        assert_eq!(config.pacgate.rules[0].match_criteria.ipv6_dscp, Some(46));
        assert_eq!(config.pacgate.rules[0].match_criteria.ipv6_ecn, Some(2));
        assert_eq!(config.pacgate.rules[1].match_criteria.tcp_flags, Some(2));
        assert_eq!(config.pacgate.rules[1].match_criteria.tcp_flags_mask, Some(18));
        assert_eq!(config.pacgate.rules[2].match_criteria.icmp_type, Some(8));
        assert_eq!(config.pacgate.rules[2].match_criteria.icmp_code, Some(0));
    }

    #[test]
    fn deserialize_rewrite_action() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_rule
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
        set_dst_mac: "00:11:22:33:44:55"
        dec_ttl: true
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &config.pacgate.rules[0];
        assert!(rule.has_rewrite());
        let rw = rule.rewrite.as_ref().unwrap();
        assert_eq!(rw.set_src_ip.as_deref(), Some("203.0.113.1"));
        assert_eq!(rw.set_dst_mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(rw.dec_ttl, Some(true));
        assert!(rw.set_src_mac.is_none());
        assert!(rw.set_vlan_id.is_none());
        assert!(rw.set_ttl.is_none());
        assert!(rw.set_dst_ip.is_none());
    }

    // --- ICMPv6/ARP/IPv6 ext helpers ---

    #[test]
    fn uses_icmpv6_true_type() {
        let mc = MatchCriteria { icmpv6_type: Some(128), ..Default::default() };
        assert!(mc.uses_icmpv6());
    }

    #[test]
    fn uses_icmpv6_true_code() {
        let mc = MatchCriteria { icmpv6_code: Some(0), ..Default::default() };
        assert!(mc.uses_icmpv6());
    }

    #[test]
    fn uses_icmpv6_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_icmpv6());
    }

    #[test]
    fn uses_arp_true_opcode() {
        let mc = MatchCriteria { arp_opcode: Some(1), ..Default::default() };
        assert!(mc.uses_arp());
    }

    #[test]
    fn uses_arp_true_spa() {
        let mc = MatchCriteria { arp_spa: Some("10.0.0.1".to_string()), ..Default::default() };
        assert!(mc.uses_arp());
    }

    #[test]
    fn uses_arp_true_tpa() {
        let mc = MatchCriteria { arp_tpa: Some("10.0.0.1".to_string()), ..Default::default() };
        assert!(mc.uses_arp());
    }

    #[test]
    fn uses_arp_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_arp());
    }

    #[test]
    fn uses_ipv6_ext_true_hop_limit() {
        let mc = MatchCriteria { ipv6_hop_limit: Some(64), ..Default::default() };
        assert!(mc.uses_ipv6_ext());
    }

    #[test]
    fn uses_ipv6_ext_true_flow_label() {
        let mc = MatchCriteria { ipv6_flow_label: Some(12345), ..Default::default() };
        assert!(mc.uses_ipv6_ext());
    }

    #[test]
    fn uses_ipv6_ext_false() {
        let mc = MatchCriteria::default();
        assert!(!mc.uses_ipv6_ext());
    }

    #[test]
    fn deserialize_icmpv6_arp_ipv6_ext() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: icmpv6_test
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_next_header: 58
        icmpv6_type: 128
        icmpv6_code: 0
      action: pass
    - name: arp_test
      priority: 90
      match:
        ethertype: "0x0806"
        arp_opcode: 1
        arp_spa: "10.0.0.1"
        arp_tpa: "10.0.0.2"
      action: pass
    - name: ipv6_ext_test
      priority: 80
      match:
        ethertype: "0x86DD"
        ipv6_hop_limit: 64
        ipv6_flow_label: 1048575
      action: pass
"#;
        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 3);
        assert_eq!(config.pacgate.rules[0].match_criteria.icmpv6_type, Some(128));
        assert_eq!(config.pacgate.rules[0].match_criteria.icmpv6_code, Some(0));
        assert_eq!(config.pacgate.rules[1].match_criteria.arp_opcode, Some(1));
        assert_eq!(config.pacgate.rules[1].match_criteria.arp_spa.as_deref(), Some("10.0.0.1"));
        assert_eq!(config.pacgate.rules[1].match_criteria.arp_tpa.as_deref(), Some("10.0.0.2"));
        assert_eq!(config.pacgate.rules[2].match_criteria.ipv6_hop_limit, Some(64));
        assert_eq!(config.pacgate.rules[2].match_criteria.ipv6_flow_label, Some(1048575));
    }

    #[test]
    fn arp_opcode_boundary() {
        let mc = MatchCriteria { arp_opcode: Some(2), ..Default::default() };
        assert!(mc.uses_arp());
    }

    #[test]
    fn ipv6_flow_label_max() {
        let mc = MatchCriteria { ipv6_flow_label: Some(0xFFFFF), ..Default::default() };
        assert!(mc.uses_ipv6_ext());
        assert_eq!(mc.ipv6_flow_label, Some(1048575));
    }
}
