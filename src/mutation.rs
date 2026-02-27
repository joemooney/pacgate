//! Rule Mutation Engine for Mutation Testing
//!
//! Generates mutated rule sets to verify test quality — if a mutation
//! is not caught by existing tests, the test suite has a gap.

use crate::model::{Action, FilterConfig};

/// A single mutation applied to a rule set
#[derive(Debug, Clone, serde::Serialize)]
pub struct Mutation {
    pub name: String,
    pub description: String,
    pub mutant_index: usize,
}

/// Generate mutated variants of a rule set
pub fn generate_mutations(config: &FilterConfig) -> Vec<(Mutation, FilterConfig)> {
    let mut mutations = Vec::new();
    let mut index = 0;

    // Mutation 1: Flip action on each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            let mut mutated = config.clone();
            let flipped = match rule.action() {
                Action::Pass => Action::Drop,
                Action::Drop => Action::Pass,
            };
            mutated.pacgate.rules[i].action = Some(flipped);
            mutations.push((Mutation {
                name: format!("flip_action_{}", rule.name),
                description: format!("Flip action of rule '{}' from {:?} to opposite", rule.name, rule.action()),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 2: Remove each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        let mut mutated = config.clone();
        mutated.pacgate.rules.remove(i);
        mutations.push((Mutation {
            name: format!("remove_{}", rule.name),
            description: format!("Remove rule '{}'", rule.name),
            mutant_index: index,
        }, mutated));
        index += 1;
    }

    // Mutation 3: Swap priorities of adjacent rules
    if config.pacgate.rules.len() >= 2 {
        for i in 0..config.pacgate.rules.len() - 1 {
            let mut mutated = config.clone();
            let pri_a = mutated.pacgate.rules[i].priority;
            let pri_b = mutated.pacgate.rules[i + 1].priority;
            if pri_a != pri_b {
                mutated.pacgate.rules[i].priority = pri_b;
                mutated.pacgate.rules[i + 1].priority = pri_a;
                mutations.push((Mutation {
                    name: format!("swap_priority_{}_{}", mutated.pacgate.rules[i].name, mutated.pacgate.rules[i + 1].name),
                    description: format!("Swap priorities of '{}' ({}) and '{}' ({})",
                        mutated.pacgate.rules[i].name, pri_a,
                        mutated.pacgate.rules[i + 1].name, pri_b),
                    mutant_index: index,
                }, mutated));
                index += 1;
            }
        }
    }

    // Mutation 4: Flip default action
    {
        let mut mutated = config.clone();
        mutated.pacgate.defaults.action = match config.pacgate.defaults.action {
            Action::Pass => Action::Drop,
            Action::Drop => Action::Pass,
        };
        mutations.push((Mutation {
            name: "flip_default_action".to_string(),
            description: format!("Flip default action from {:?} to opposite", config.pacgate.defaults.action),
            mutant_index: index,
        }, mutated));
    }

    // Mutation 5: Remove a match field from each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ethertype.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ethertype = None;
            mutations.push((Mutation {
                name: format!("remove_ethertype_{}", rule.name),
                description: format!("Remove ethertype match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    mutations
}

/// Generate a JSON mutation report
pub fn generate_mutation_report(config: &FilterConfig) -> serde_json::Value {
    let mutations = generate_mutations(config);
    let mutation_info: Vec<serde_json::Value> = mutations.iter().map(|(m, _)| {
        serde_json::json!({
            "name": m.name,
            "description": m.description,
            "index": m.mutant_index,
        })
    }).collect();

    serde_json::json!({
        "status": "ok",
        "total_mutations": mutations.len(),
        "mutations": mutation_info,
        "instructions": "Each mutant should fail at least one test. Surviving mutants indicate test gaps.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_test_config() -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "allow_arp".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0806".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                    },
                    StatelessRule {
                        name: "allow_ipv4".to_string(),
                        priority: 90,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                    },
                ],
                conntrack: None,
            },
        }
    }

    #[test]
    fn generate_mutations_creates_variants() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        assert!(mutations.len() >= 4, "expected at least 4 mutations, got {}", mutations.len());
    }

    #[test]
    fn flip_action_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let flip = mutations.iter().find(|(m, _)| m.name.starts_with("flip_action_")).unwrap();
        let mutated = &flip.1;
        // At least one rule should have opposite action from original
        assert!(mutated.pacgate.rules.iter().any(|r| r.action() == Action::Drop));
    }

    #[test]
    fn remove_rule_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let remove = mutations.iter().find(|(m, _)| m.name.starts_with("remove_")).unwrap();
        assert_eq!(remove.1.pacgate.rules.len(), 1);
    }

    #[test]
    fn swap_priority_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let swap = mutations.iter().find(|(m, _)| m.name.starts_with("swap_priority_"));
        assert!(swap.is_some(), "should generate priority swap mutation");
    }

    #[test]
    fn flip_default_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let flip = mutations.iter().find(|(m, _)| m.name == "flip_default_action").unwrap();
        assert_eq!(flip.1.pacgate.defaults.action, Action::Pass);
    }

    #[test]
    fn mutation_report_json() {
        let config = make_test_config();
        let report = generate_mutation_report(&config);
        assert_eq!(report["status"], "ok");
        assert!(report["total_mutations"].as_u64().unwrap() > 0);
        assert!(report["mutations"].is_array());
    }

    #[test]
    fn remove_ethertype_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let rm_et = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ethertype_")).unwrap();
        let mutated_rule = &rm_et.1.pacgate.rules.iter()
            .find(|r| r.name == "allow_arp")
            .unwrap();
        assert!(mutated_rule.match_criteria.ethertype.is_none() ||
                rm_et.0.name.contains("allow_ipv4"));
    }
}
