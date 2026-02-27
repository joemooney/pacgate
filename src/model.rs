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
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatelessRule {
    pub name: String,
    pub priority: u32,
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,
    pub action: Action,
    #[serde(default)]
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlippyConfig {
    pub version: String,
    pub defaults: Defaults,
    pub rules: Vec<StatelessRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    pub flippy: FlippyConfig,
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
