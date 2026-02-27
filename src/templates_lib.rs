//! Rule Template Library
//!
//! Provides built-in rule templates that can be customized with variables
//! and applied to generate PacGate YAML rule sets.

use anyhow::{bail, Result};

/// A variable in a rule template
#[derive(Debug, Clone, serde::Serialize)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub default: String,
    pub var_type: String, // "string", "int", "cidr"
}

/// A rule template with metadata and YAML body
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleTemplate {
    pub name: String,
    pub description: String,
    pub category: String,
    pub variables: Vec<TemplateVariable>,
    pub yaml_body: String,
}

/// Return all built-in rule templates
pub fn builtin_templates() -> Vec<RuleTemplate> {
    vec![
        RuleTemplate {
            name: "allow_management".to_string(),
            description: "SSH/HTTPS access from a trusted management subnet".to_string(),
            category: "access-control".to_string(),
            variables: vec![
                TemplateVariable { name: "mgmt_subnet".to_string(), description: "Management subnet CIDR".to_string(), default: "10.0.0.0/8".to_string(), var_type: "cidr".to_string() },
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "500".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/allow_management.yaml").to_string(),
        },
        RuleTemplate {
            name: "block_bogons".to_string(),
            description: "Block RFC 1918 private/reserved address ranges".to_string(),
            category: "security".to_string(),
            variables: vec![
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "900".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/block_bogons.yaml").to_string(),
        },
        RuleTemplate {
            name: "rate_limit_dns".to_string(),
            description: "Token-bucket rate limiting for DNS traffic".to_string(),
            category: "rate-limiting".to_string(),
            variables: vec![
                TemplateVariable { name: "pps".to_string(), description: "Packets per second".to_string(), default: "1000".to_string(), var_type: "int".to_string() },
                TemplateVariable { name: "burst".to_string(), description: "Burst size (tokens)".to_string(), default: "64".to_string(), var_type: "int".to_string() },
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "400".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/rate_limit_dns.yaml").to_string(),
        },
        RuleTemplate {
            name: "allow_icmp".to_string(),
            description: "Permit ICMP and ICMPv6 diagnostics (ping, NDP)".to_string(),
            category: "diagnostics".to_string(),
            variables: vec![
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "300".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/allow_icmp.yaml").to_string(),
        },
        RuleTemplate {
            name: "vlan_isolation".to_string(),
            description: "VLAN-based traffic segmentation".to_string(),
            category: "segmentation".to_string(),
            variables: vec![
                TemplateVariable { name: "allowed_vlan".to_string(), description: "Allowed VLAN ID".to_string(), default: "100".to_string(), var_type: "int".to_string() },
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "600".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/vlan_isolation.yaml").to_string(),
        },
        RuleTemplate {
            name: "web_server".to_string(),
            description: "Standard HTTP/HTTPS web server rules".to_string(),
            category: "application".to_string(),
            variables: vec![
                TemplateVariable { name: "server_subnet".to_string(), description: "Server subnet CIDR".to_string(), default: "0.0.0.0/0".to_string(), var_type: "cidr".to_string() },
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "400".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/web_server.yaml").to_string(),
        },
        RuleTemplate {
            name: "iot_gateway".to_string(),
            description: "IoT sensor/actuator network isolation (MQTT, CoAP)".to_string(),
            category: "iot".to_string(),
            variables: vec![
                TemplateVariable { name: "iot_subnet".to_string(), description: "IoT device subnet CIDR".to_string(), default: "10.99.0.0/16".to_string(), var_type: "cidr".to_string() },
                TemplateVariable { name: "mqtt_port".to_string(), description: "MQTT broker port".to_string(), default: "1883".to_string(), var_type: "int".to_string() },
                TemplateVariable { name: "priority".to_string(), description: "Rule priority".to_string(), default: "500".to_string(), var_type: "int".to_string() },
            ],
            yaml_body: include_str!("../rules/templates/iot_gateway.yaml").to_string(),
        },
    ]
}

/// Find a template by name
pub fn find_template(name: &str) -> Option<RuleTemplate> {
    builtin_templates().into_iter().find(|t| t.name == name)
}

/// Apply variable substitutions to a template
pub fn apply_template(template: &RuleTemplate, vars: &[(String, String)]) -> Result<String> {
    let mut body = template.yaml_body.clone();

    // Build effective variable map: defaults + overrides
    let mut var_map: std::collections::HashMap<String, String> = template.variables.iter()
        .map(|v| (v.name.clone(), v.default.clone()))
        .collect();

    for (key, value) in vars {
        if !var_map.contains_key(key) {
            bail!("Unknown variable '{}' for template '{}'. Available: {}",
                key, template.name,
                template.variables.iter().map(|v| v.name.as_str()).collect::<Vec<_>>().join(", "));
        }
        var_map.insert(key.clone(), value.clone());
    }

    // Substitute all ${var} patterns
    for (key, value) in &var_map {
        body = body.replace(&format!("${{{}}}", key), value);
    }

    // Check for unresolved variables
    if body.contains("${") {
        bail!("Template has unresolved variables after substitution");
    }

    Ok(body)
}

/// Generate a complete PacGate YAML file from a template
pub fn apply_template_to_yaml(template: &RuleTemplate, vars: &[(String, String)], default_action: &str) -> Result<String> {
    let rules_body = apply_template(template, vars)?;
    // Strip comment lines from the rules body to create clean YAML
    let rules_lines: Vec<&str> = rules_body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();

    Ok(format!(
        "# Generated from PacGate template: {}\n# {}\n\npacgate:\n  version: \"1.0\"\n  defaults:\n    action: {}\n  rules:\n{}",
        template.name, template.description, default_action,
        rules_lines.iter()
            .map(|line| format!("    {}", line))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_templates_not_empty() {
        let templates = builtin_templates();
        assert_eq!(templates.len(), 7);
    }

    #[test]
    fn find_existing_template() {
        assert!(find_template("allow_management").is_some());
        assert!(find_template("block_bogons").is_some());
        assert!(find_template("web_server").is_some());
    }

    #[test]
    fn find_nonexistent_template() {
        assert!(find_template("nonexistent").is_none());
    }

    #[test]
    fn apply_template_defaults() {
        let t = find_template("allow_management").unwrap();
        let result = apply_template(&t, &[]).unwrap();
        assert!(result.contains("10.0.0.0/8"), "should use default subnet");
        assert!(result.contains("priority: 500"), "should use default priority");
    }

    #[test]
    fn apply_template_custom_vars() {
        let t = find_template("allow_management").unwrap();
        let vars = vec![
            ("mgmt_subnet".to_string(), "192.168.1.0/24".to_string()),
            ("priority".to_string(), "800".to_string()),
        ];
        let result = apply_template(&t, &vars).unwrap();
        assert!(result.contains("192.168.1.0/24"), "should use custom subnet");
        assert!(result.contains("priority: 800"), "should use custom priority");
        assert!(!result.contains("${"), "no unresolved variables");
    }

    #[test]
    fn apply_template_unknown_var() {
        let t = find_template("allow_management").unwrap();
        let vars = vec![("bogus".to_string(), "value".to_string())];
        assert!(apply_template(&t, &vars).is_err());
    }

    #[test]
    fn all_templates_have_defaults() {
        for t in builtin_templates() {
            let result = apply_template(&t, &[]);
            assert!(result.is_ok(), "template '{}' should apply with defaults: {:?}", t.name, result.err());
            let body = result.unwrap();
            assert!(!body.contains("${"), "template '{}' has unresolved vars with defaults", t.name);
        }
    }

    #[test]
    fn apply_template_to_yaml_format() {
        let t = find_template("allow_icmp").unwrap();
        let yaml = apply_template_to_yaml(&t, &[], "drop").unwrap();
        assert!(yaml.contains("pacgate:"));
        assert!(yaml.contains("action: drop"));
        assert!(yaml.contains("rules:"));
    }

    #[test]
    fn template_categories() {
        let templates = builtin_templates();
        let categories: Vec<&str> = templates.iter().map(|t| t.category.as_str()).collect();
        assert!(categories.contains(&"security"));
        assert!(categories.contains(&"access-control"));
        assert!(categories.contains(&"rate-limiting"));
    }

    #[test]
    fn rate_limit_dns_template() {
        let t = find_template("rate_limit_dns").unwrap();
        let vars = vec![
            ("pps".to_string(), "5000".to_string()),
            ("burst".to_string(), "128".to_string()),
        ];
        let result = apply_template(&t, &vars).unwrap();
        assert!(result.contains("pps: 5000"));
        assert!(result.contains("burst: 128"));
    }

    #[test]
    fn vlan_isolation_template() {
        let t = find_template("vlan_isolation").unwrap();
        let vars = vec![("allowed_vlan".to_string(), "200".to_string())];
        let result = apply_template(&t, &vars).unwrap();
        assert!(result.contains("allow_vlan_200"));
        assert!(result.contains("vlan_id: 200"));
    }

    #[test]
    fn iot_gateway_template() {
        let t = find_template("iot_gateway").unwrap();
        let vars = vec![("iot_subnet".to_string(), "172.20.0.0/16".to_string())];
        let result = apply_template(&t, &vars).unwrap();
        assert!(result.contains("172.20.0.0/16"));
        assert!(result.contains("dst_port: 1883")); // default MQTT port
    }
}
