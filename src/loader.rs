use std::path::Path;
use anyhow::{Context, Result};
use crate::model::FilterConfig;

pub fn load_rules(path: &Path) -> Result<FilterConfig> {
    let (config, warnings) = load_rules_with_warnings(path)?;
    for w in &warnings {
        eprintln!("Warning: {}", w);
    }
    Ok(config)
}

pub fn load_rules_with_warnings(path: &Path) -> Result<(FilterConfig, Vec<String>)> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rules file: {}", path.display()))?;

    load_rules_from_str_with_warnings(&contents)
}

pub fn load_rules_from_str(contents: &str) -> Result<FilterConfig> {
    let (config, warnings) = load_rules_from_str_with_warnings(contents)?;
    for w in &warnings {
        eprintln!("Warning: {}", w);
    }
    Ok(config)
}

pub fn load_rules_from_str_with_warnings(contents: &str) -> Result<(FilterConfig, Vec<String>)> {
    let config: FilterConfig = serde_yaml::from_str(contents)
        .with_context(|| "Failed to parse YAML")?;

    validate(&config)?;
    let warnings = check_rule_overlaps(&config.pacgate.rules);
    Ok((config, warnings))
}

fn validate(config: &FilterConfig) -> Result<()> {
    if config.pacgate.rules.is_empty() {
        anyhow::bail!("No rules defined");
    }

    for rule in &config.pacgate.rules {
        if rule.name.is_empty() {
            anyhow::bail!("Rule name cannot be empty");
        }

        if rule.is_stateful() {
            // Stateful rule validation
            let fsm = rule.fsm.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Stateful rule '{}' missing fsm definition", rule.name))?;

            if !fsm.states.contains_key(&fsm.initial_state) {
                anyhow::bail!("FSM initial_state '{}' not found in states for rule '{}'",
                    fsm.initial_state, rule.name);
            }

            for (state_name, state) in &fsm.states {
                for transition in &state.transitions {
                    if !fsm.states.contains_key(&transition.next_state) {
                        anyhow::bail!("FSM transition from '{}' to unknown state '{}' in rule '{}'",
                            state_name, transition.next_state, rule.name);
                    }
                    // Validate match criteria in transitions
                    if let Some(ref et) = transition.match_criteria.ethertype {
                        crate::model::parse_ethertype(et)?;
                    }
                }
            }
        } else {
            // Stateless rule validation
            if let Some(ref et) = rule.match_criteria.ethertype {
                crate::model::parse_ethertype(et)?;
            }
            if let Some(ref mac) = rule.match_criteria.dst_mac {
                crate::model::MacAddress::parse(mac)?;
            }
            if let Some(ref mac) = rule.match_criteria.src_mac {
                crate::model::MacAddress::parse(mac)?;
            }
            if let Some(pcp) = rule.match_criteria.vlan_pcp {
                if pcp > 7 {
                    anyhow::bail!("VLAN PCP must be 0-7, got {}", pcp);
                }
            }
        }
    }

    // Check for duplicate priorities
    let mut priorities: Vec<u32> = config.pacgate.rules.iter().map(|r| r.priority).collect();
    priorities.sort();
    for w in priorities.windows(2) {
        if w[0] == w[1] {
            anyhow::bail!("Duplicate priority: {}", w[0]);
        }
    }

    // Check for duplicate rule names
    let mut names: Vec<&str> = config.pacgate.rules.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    for w in names.windows(2) {
        if w[0] == w[1] {
            anyhow::bail!("Duplicate rule name: '{}'", w[0]);
        }
    }

    Ok(())
}

/// Analyze rules for overlaps and shadowing.
/// Returns a list of warning strings.
pub fn check_rule_overlaps(rules: &[crate::model::StatelessRule]) -> Vec<String> {
    let mut warnings = Vec::new();

    // Only analyze stateless rules
    let stateless: Vec<_> = rules.iter().filter(|r| !r.is_stateful()).collect();

    // Sort by priority descending (highest first)
    let mut sorted = stateless.clone();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Check each pair: does a higher-priority rule fully shadow a lower-priority one?
    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            let high = sorted[i];
            let low = sorted[j];

            if criteria_shadows(&high.match_criteria, &low.match_criteria) {
                warnings.push(format!(
                    "rule '{}' (priority {}) shadows '{}' (priority {}) — '{}' can never match",
                    high.name, high.priority, low.name, low.priority, low.name
                ));
            } else if criteria_overlaps(&high.match_criteria, &low.match_criteria) {
                let action_high = high.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or("N/A".to_string());
                let action_low = low.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or("N/A".to_string());
                if action_high != action_low {
                    warnings.push(format!(
                        "rules '{}' (priority {}, {}) and '{}' (priority {}, {}) overlap with different actions",
                        high.name, high.priority, action_high,
                        low.name, low.priority, action_low,
                    ));
                }
            }
        }
    }

    // Check for rules that match nothing (no criteria at all and action matches default)
    for rule in &stateless {
        let mc = &rule.match_criteria;
        if mc.dst_mac.is_none() && mc.src_mac.is_none() && mc.ethertype.is_none()
            && mc.vlan_id.is_none() && mc.vlan_pcp.is_none()
        {
            warnings.push(format!(
                "rule '{}' (priority {}) has no match criteria — matches ALL packets",
                rule.name, rule.priority
            ));
        }
    }

    warnings
}

/// Check if rule A's criteria fully contain rule B's criteria (A shadows B).
fn criteria_shadows(a: &crate::model::MatchCriteria, b: &crate::model::MatchCriteria) -> bool {
    // A shadows B if every packet that matches B also matches A.
    // This happens when A's criteria are a superset (less restrictive) than B's.

    // If A has a constraint that B doesn't, A is more restrictive in that dimension
    // and thus doesn't shadow B.

    // Check each field: if A constrains a field, B must constrain it to the same value.
    if let Some(ref a_et) = a.ethertype {
        match &b.ethertype {
            Some(b_et) if a_et == b_et => {},
            Some(_) => return false,  // Different ethertypes — no shadow
            None => return false,     // A constrains ethertype but B doesn't — A is more restrictive
        }
    }
    // If A doesn't constrain ethertype, it matches all — fine for shadowing.

    if let Some(ref a_mac) = a.dst_mac {
        match &b.dst_mac {
            Some(b_mac) => {
                if !mac_pattern_contains(a_mac, b_mac) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref a_mac) = a.src_mac {
        match &b.src_mac {
            Some(b_mac) => {
                if !mac_pattern_contains(a_mac, b_mac) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(a_vid) = a.vlan_id {
        match b.vlan_id {
            Some(b_vid) if a_vid == b_vid => {},
            _ => return false,
        }
    }

    if let Some(a_pcp) = a.vlan_pcp {
        match b.vlan_pcp {
            Some(b_pcp) if a_pcp == b_pcp => {},
            _ => return false,
        }
    }

    true
}

/// Check if two criteria could match the same packet (overlap).
fn criteria_overlaps(a: &crate::model::MatchCriteria, b: &crate::model::MatchCriteria) -> bool {
    // Two rules overlap if there exists a packet matching both.
    // They DON'T overlap if any field constrains to disjoint values.

    if let (Some(a_et), Some(b_et)) = (&a.ethertype, &b.ethertype) {
        if a_et != b_et {
            return false; // Different ethertypes — no overlap
        }
    }

    if let (Some(a_mac), Some(b_mac)) = (&a.dst_mac, &b.dst_mac) {
        if !mac_patterns_overlap(a_mac, b_mac) {
            return false;
        }
    }

    if let (Some(a_mac), Some(b_mac)) = (&a.src_mac, &b.src_mac) {
        if !mac_patterns_overlap(a_mac, b_mac) {
            return false;
        }
    }

    if let (Some(a_vid), Some(b_vid)) = (a.vlan_id, b.vlan_id) {
        if a_vid != b_vid {
            return false;
        }
    }

    if let (Some(a_pcp), Some(b_pcp)) = (a.vlan_pcp, b.vlan_pcp) {
        if a_pcp != b_pcp {
            return false;
        }
    }

    true
}

/// Check if MAC pattern A fully contains pattern B (all matches of B are also matches of A).
fn mac_pattern_contains(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split(':').collect();
    let b_parts: Vec<&str> = b.split(':').collect();
    if a_parts.len() != 6 || b_parts.len() != 6 {
        return false;
    }
    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        if *ap == "*" {
            continue; // A is wildcard here — matches everything B could
        }
        if *bp == "*" {
            return false; // B is wildcard but A is specific — A is more restrictive
        }
        if ap != bp {
            return false; // Different specific values
        }
    }
    true
}

/// Check if two MAC patterns can match the same address.
fn mac_patterns_overlap(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split(':').collect();
    let b_parts: Vec<&str> = b.split(':').collect();
    if a_parts.len() != 6 || b_parts.len() != 6 {
        return true; // Can't tell — assume overlap
    }
    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        if *ap == "*" || *bp == "*" {
            continue; // Wildcard — always overlaps
        }
        if ap != bp {
            return false; // Different specific values — no overlap
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_yaml(rules: &str) -> String {
        format!(
            r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
{rules}
"#
        )
    }

    #[test]
    fn load_valid_single_rule() {
        let yaml = valid_yaml(
            "    - name: allow_arp\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
    }

    #[test]
    fn load_valid_file() {
        let config = load_rules(Path::new("rules/examples/allow_arp.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].name, "allow_arp");
    }

    #[test]
    fn load_enterprise_rules() {
        let config = load_rules(Path::new("rules/examples/enterprise.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 7);
    }

    #[test]
    fn load_stateful_rules() {
        let config = load_rules(Path::new("rules/examples/stateful_sequence.yaml")).unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
        assert!(config.pacgate.rules.iter().any(|r| r.is_stateful()));
    }

    #[test]
    fn reject_empty_rules() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules: []
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("No rules defined"));
    }

    #[test]
    fn reject_duplicate_priorities() {
        let yaml = valid_yaml(
            "    - name: rule_a\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass\n    - name: rule_b\n      priority: 100\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Duplicate priority"));
    }

    #[test]
    fn reject_bad_mac() {
        let yaml = valid_yaml(
            "    - name: bad_mac\n      priority: 100\n      match:\n        dst_mac: \"zz:zz:zz:zz:zz:zz\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn reject_bad_ethertype() {
        let yaml = valid_yaml(
            "    - name: bad_et\n      priority: 100\n      match:\n        ethertype: \"not_hex\"\n      action: pass",
        );
        assert!(load_rules_from_str(&yaml).is_err());
    }

    #[test]
    fn reject_vlan_pcp_out_of_range() {
        let yaml = valid_yaml(
            "    - name: bad_pcp\n      priority: 100\n      match:\n        vlan_pcp: 8\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("VLAN PCP must be 0-7"));
    }

    #[test]
    fn reject_fsm_missing_initial_state() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_fsm
      type: stateful
      priority: 50
      fsm:
        initial_state: nonexistent
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: idle
                action: pass
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("initial_state"));
    }

    #[test]
    fn reject_fsm_bad_transition_target() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_fsm
      type: stateful
      priority: 50
      fsm:
        initial_state: idle
        states:
          idle:
            transitions:
              - match:
                  ethertype: "0x0806"
                next_state: nonexistent
                action: pass
"#;
        let err = load_rules_from_str(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown state"));
    }

    #[test]
    fn reject_stateful_missing_fsm() {
        let yaml = valid_yaml(
            "    - name: no_fsm\n      type: stateful\n      priority: 50",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("missing fsm"));
    }

    #[test]
    fn reject_empty_rule_name() {
        let yaml = valid_yaml(
            "    - name: \"\"\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("name cannot be empty"));
    }

    #[test]
    fn accept_mac_wildcards() {
        let yaml = valid_yaml(
            "    - name: vendor\n      priority: 100\n      match:\n        src_mac: \"00:1a:2b:*:*:*\"\n      action: pass",
        );
        let config = load_rules_from_str(&yaml).unwrap();
        assert_eq!(config.pacgate.rules[0].match_criteria.src_mac.as_deref(), Some("00:1a:2b:*:*:*"));
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(load_rules(Path::new("nonexistent.yaml")).is_err());
    }

    #[test]
    fn reject_duplicate_rule_names() {
        let yaml = valid_yaml(
            "    - name: same_name\n      priority: 100\n      match:\n        ethertype: \"0x0800\"\n      action: pass\n    - name: same_name\n      priority: 200\n      match:\n        ethertype: \"0x0806\"\n      action: pass",
        );
        let err = load_rules_from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Duplicate rule name"));
    }

    #[test]
    fn detect_shadowed_rule() {
        // Rule A (priority 200) matches all ethertypes with no constraints.
        // Rule B (priority 100) matches ethertype 0x0800.
        // A shadows B because A matches all packets B would match.
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 200,
                match_criteria: MatchCriteria::default(), // no constraints
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
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
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("shadows")));
    }

    #[test]
    fn detect_overlap_different_actions() {
        // Two rules overlap on the same ethertype but have different actions.
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "pass_arp".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
            },
            StatelessRule {
                name: "drop_arp".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("overlap") || w.contains("shadows")));
    }

    #[test]
    fn no_overlap_disjoint_rules() {
        use crate::model::{StatelessRule, MatchCriteria, Action};
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
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warn_catch_all_rule() {
        use crate::model::{StatelessRule, MatchCriteria, Action};
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 10,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
            },
        ];
        let warnings = check_rule_overlaps(&rules);
        assert!(warnings.iter().any(|w| w.contains("matches ALL packets")));
    }

    #[test]
    fn mac_overlap_detection() {
        assert!(mac_patterns_overlap("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"));
        assert!(!mac_patterns_overlap("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"));
        assert!(mac_patterns_overlap("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_patterns_overlap("00:1a:2b:*:*:*", "00:1a:3c:*:*:*"));
    }

    #[test]
    fn mac_contains_detection() {
        assert!(mac_pattern_contains("*:*:*:*:*:*", "ff:ff:ff:ff:ff:ff"));
        assert!(!mac_pattern_contains("ff:ff:ff:ff:ff:ff", "*:*:*:*:*:*"));
        assert!(mac_pattern_contains("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_pattern_contains("00:1a:2b:cc:dd:ee", "00:1a:2b:*:*:*"));
    }
}
