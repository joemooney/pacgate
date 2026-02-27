use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Drop,
}

#[derive(Debug, Clone, Deserialize, Default)]
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
}

/// Port matching: exact value or range
#[derive(Debug, Clone, Deserialize)]
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
    }
}

// --- Stateful FSM types ---

#[derive(Debug, Clone, Deserialize)]
pub struct FsmTransition {
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,
    pub next_state: String,
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FsmState {
    #[serde(default)]
    pub timeout_cycles: Option<u64>,
    pub transitions: Vec<FsmTransition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FsmDefinition {
    pub initial_state: String,
    pub states: std::collections::HashMap<String, FsmState>,
}

// --- Rule types ---

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PacgateConfig {
    pub version: String,
    pub defaults: Defaults,
    pub rules: Vec<StatelessRule>,
}

#[derive(Debug, Clone, Deserialize)]
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
