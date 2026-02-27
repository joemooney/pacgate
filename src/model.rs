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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

impl MatchCriteria {
    /// Returns true if this criteria uses any L3/L4 fields
    pub fn uses_l3l4(&self) -> bool {
        self.src_ip.is_some() || self.dst_ip.is_some() || self.ip_protocol.is_some()
            || self.src_port.is_some() || self.dst_port.is_some()
            || self.vxlan_vni.is_some()
    }

    /// Returns true if this criteria uses byte_match
    pub fn uses_byte_match(&self) -> bool {
        self.byte_match.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
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
}

impl StatelessRule {
    pub fn is_stateful(&self) -> bool {
        self.rule_type.as_deref() == Some("stateful")
    }

    /// Get action (required for stateless, not for stateful)
    pub fn action(&self) -> Action {
        self.action.clone().unwrap_or(Action::Drop)
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
}
