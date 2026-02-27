use std::path::Path;
use anyhow::{Context, Result};
use crate::model::FilterConfig;

pub fn load_rules(path: &Path) -> Result<FilterConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rules file: {}", path.display()))?;

    let config: FilterConfig = serde_yaml::from_str(&contents)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;

    validate(&config)?;
    Ok(config)
}

fn validate(config: &FilterConfig) -> Result<()> {
    if config.flippy.rules.is_empty() {
        anyhow::bail!("No rules defined");
    }

    for rule in &config.flippy.rules {
        if rule.name.is_empty() {
            anyhow::bail!("Rule name cannot be empty");
        }
        // Validate ethertype format if present
        if let Some(ref et) = rule.match_criteria.ethertype {
            crate::model::parse_ethertype(et)?;
        }
        // Validate MAC format if present
        if let Some(ref mac) = rule.match_criteria.dst_mac {
            crate::model::MacAddress::parse(mac)?;
        }
        if let Some(ref mac) = rule.match_criteria.src_mac {
            crate::model::MacAddress::parse(mac)?;
        }
        // Validate VLAN PCP range
        if let Some(pcp) = rule.match_criteria.vlan_pcp {
            if pcp > 7 {
                anyhow::bail!("VLAN PCP must be 0-7, got {}", pcp);
            }
        }
    }

    // Check for duplicate priorities
    let mut priorities: Vec<u32> = config.flippy.rules.iter().map(|r| r.priority).collect();
    priorities.sort();
    for w in priorities.windows(2) {
        if w[0] == w[1] {
            anyhow::bail!("Duplicate priority: {}", w[0]);
        }
    }

    Ok(())
}
