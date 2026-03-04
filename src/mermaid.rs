use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

use crate::model::{
    Action, Defaults, FsmDefinition, FsmState, FsmTransition, FsmVariable,
    FilterConfig, MatchCriteria, PacgateConfig, StatelessRule,
};

/// Parse a Mermaid stateDiagram-v2 into FSM components
pub fn parse_mermaid(input: &str) -> Result<ParsedDiagram> {
    let mut states: HashMap<String, FsmState> = HashMap::new();
    let mut initial_state: Option<String> = None;
    let mut variables: Vec<FsmVariable> = Vec::new();
    let mut composite_stack: Vec<String> = Vec::new();

    // Regex patterns
    let re_transition = Regex::new(
        r"^\s*(\w[\w.]*)\s*-->\s*(\w[\w.]*)\s*(?::\s*(.+))?\s*$"
    ).unwrap();
    let re_initial = Regex::new(r"^\s*\[\*\]\s*-->\s*(\w+)").unwrap();
    let re_composite_start = Regex::new(r"^\s*state\s+(\w+)\s*\{").unwrap();
    let re_composite_end = Regex::new(r"^\s*\}\s*$").unwrap();
    let re_note = Regex::new(
        r"^\s*note\s+(?:right|left)\s+of\s+(\w+)\s*:\s*(.+)$"
    ).unwrap();
    let re_var = Regex::new(
        r"^\s*%%\s*var:\s*(\w+)\s*(?:\((\d+)\))?\s*(?:=\s*(\d+))?\s*$"
    ).unwrap();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("stateDiagram")
            || trimmed.starts_with("direction") || trimmed == "---" {
            continue;
        }

        // Variable declaration: %% var: name(width) = reset_value
        if let Some(caps) = re_var.captures(trimmed) {
            let name = caps[1].to_string();
            let width: u8 = caps.get(2).map(|m| m.as_str().parse().unwrap_or(16)).unwrap_or(16);
            let reset_value: u64 = caps.get(3).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);
            variables.push(FsmVariable { name, width, reset_value });
            continue;
        }

        // Initial state: [*] --> state_name
        if let Some(caps) = re_initial.captures(trimmed) {
            initial_state = Some(caps[1].to_string());
            continue;
        }

        // Composite state start: state Parent {
        if let Some(caps) = re_composite_start.captures(trimmed) {
            composite_stack.push(caps[1].to_string());
            continue;
        }

        // Composite state end: }
        if re_composite_end.is_match(trimmed) {
            composite_stack.pop();
            continue;
        }

        // Note for timeout: note right of state: timeout=5000cycles
        if let Some(caps) = re_note.captures(trimmed) {
            let state_name = qualify_name(&caps[1], &composite_stack);
            let note_text = caps[2].trim();
            if let Some(timeout_str) = note_text.strip_prefix("timeout=") {
                let timeout_str = timeout_str.trim_end_matches("cycles").trim();
                if let Ok(timeout) = timeout_str.parse::<u64>() {
                    let state = states.entry(state_name).or_insert_with(|| FsmState {
                        timeout_cycles: None,
                        transitions: Vec::new(),
                        substates: None,
                        initial_substate: None,
                        on_entry: None,
                        on_exit: None,
                        history: None,
                    });
                    state.timeout_cycles = Some(timeout);
                }
            }
            continue;
        }

        // Transition: StateA --> StateB: [match_fields]/action
        if let Some(caps) = re_transition.captures(trimmed) {
            let from = qualify_name(&caps[1], &composite_stack);
            let to = qualify_name(&caps[2], &composite_stack);
            let label = caps.get(3).map(|m| m.as_str().trim().to_string());

            let (mc, action, guard, on_transition) = if let Some(ref label_str) = label {
                parse_transition_label(label_str)?
            } else {
                (MatchCriteria::default(), Action::Pass, None, None)
            };

            let transition = FsmTransition {
                match_criteria: mc,
                next_state: to,
                action,
                guard,
                on_transition,
            };

            let state = states.entry(from).or_insert_with(|| FsmState {
                timeout_cycles: None,
                transitions: Vec::new(),
                substates: None,
                initial_substate: None,
                on_entry: None,
                on_exit: None,
                history: None,
            });
            state.transitions.push(transition);
            continue;
        }
    }

    let initial_state = initial_state
        .ok_or_else(|| anyhow::anyhow!("No initial state found ([*] --> state)"))?;

    // Ensure all referenced states exist
    let transition_targets: Vec<String> = states.values()
        .flat_map(|s| s.transitions.iter().map(|t| t.next_state.clone()))
        .collect();
    for target in &transition_targets {
        states.entry(target.clone()).or_insert_with(|| FsmState {
            timeout_cycles: None,
            transitions: Vec::new(),
            substates: None,
            initial_substate: None,
            on_entry: None,
            on_exit: None,
            history: None,
        });
    }

    Ok(ParsedDiagram {
        initial_state,
        states,
        variables,
    })
}

/// Qualify a state name with composite context
fn qualify_name(name: &str, stack: &[String]) -> String {
    if stack.is_empty() || name.contains('.') {
        name.to_string()
    } else {
        let mut prefix = stack.join(".");
        prefix.push('.');
        prefix.push_str(name);
        prefix
    }
}

/// Parse transition label: [field=value,...][guard: expr]/action{actions}
fn parse_transition_label(label: &str) -> Result<(MatchCriteria, Action, Option<String>, Option<Vec<String>>)> {
    let mut mc = MatchCriteria::default();
    let mut action = Action::Pass;
    let mut guard: Option<String> = None;
    let mut on_transition: Option<Vec<String>> = None;

    let mut remaining = label.trim();

    // Parse guard: [guard: expr]
    let re_guard = Regex::new(r"^\[guard:\s*([^\]]+)\]").unwrap();
    if let Some(caps) = re_guard.captures(remaining) {
        guard = Some(caps[1].trim().to_string());
        remaining = &remaining[caps[0].len()..].trim_start();
    }

    // Parse match criteria: [field=value,field=value]
    let re_match = Regex::new(r"^\[([^\]]+)\]").unwrap();
    if let Some(caps) = re_match.captures(remaining) {
        let fields_str = &caps[1];
        for field in fields_str.split(',') {
            let field = field.trim();
            if let Some(idx) = field.find('=') {
                let key = field[..idx].trim();
                let val = field[idx+1..].trim();
                match key {
                    "ethertype" => mc.ethertype = Some(val.to_string()),
                    "dst_mac" => mc.dst_mac = Some(val.to_string()),
                    "src_mac" => mc.src_mac = Some(val.to_string()),
                    "vlan_id" => mc.vlan_id = val.parse().ok(),
                    "vlan_pcp" => mc.vlan_pcp = val.parse().ok(),
                    "src_ip" => mc.src_ip = Some(val.to_string()),
                    "dst_ip" => mc.dst_ip = Some(val.to_string()),
                    "ip_protocol" => mc.ip_protocol = val.parse().ok(),
                    _ => {} // Ignore unknown fields
                }
            }
        }
        remaining = &remaining[caps[0].len()..].trim_start();
    }

    // Parse action: /pass or /drop
    if remaining.starts_with('/') {
        let action_str = remaining[1..].split('{').next().unwrap_or("").trim();
        match action_str {
            "pass" => action = Action::Pass,
            "drop" => action = Action::Drop,
            _ => {}
        }
        if let Some(idx) = remaining.find('{') {
            remaining = &remaining[idx..];
        } else {
            remaining = "";
        }
    }

    // Parse transition actions: {action1; action2}
    if remaining.starts_with('{') && remaining.ends_with('}') {
        let actions_str = &remaining[1..remaining.len()-1];
        let actions: Vec<String> = actions_str.split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !actions.is_empty() {
            on_transition = Some(actions);
        }
    }

    Ok((mc, action, guard, on_transition))
}

/// Result of parsing a Mermaid diagram
pub struct ParsedDiagram {
    pub initial_state: String,
    pub states: HashMap<String, FsmState>,
    pub variables: Vec<FsmVariable>,
}

/// Convert a parsed Mermaid diagram to a complete PacGate YAML config
pub fn to_yaml(diagram: ParsedDiagram, rule_name: &str, priority: u32) -> FilterConfig {
    let fsm = FsmDefinition {
        initial_state: diagram.initial_state,
        states: diagram.states,
        variables: if diagram.variables.is_empty() { None } else { Some(diagram.variables) },
    };

    FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: Action::Drop },
            rules: vec![StatelessRule {
                name: rule_name.to_string(),
                priority,
                match_criteria: MatchCriteria::default(),
                action: None,
                rule_type: Some("stateful".to_string()),
                fsm: Some(fsm),
                ports: None,
                rate_limit: None,
                rewrite: None,
                mirror_port: None,
                redirect_port: None,
            }],
            conntrack: None,
            tables: None,
        },
    }
}

/// Convert a PacGate YAML config to Mermaid stateDiagram-v2 text
pub fn from_yaml(config: &FilterConfig) -> String {
    let mut lines = Vec::new();
    lines.push("stateDiagram-v2".to_string());

    for rule in &config.pacgate.rules {
        if !rule.is_stateful() {
            continue;
        }
        let fsm = match &rule.fsm {
            Some(f) => f,
            None => continue,
        };

        lines.push(format!("    %% Rule: {} (priority {})", rule.name, rule.priority));

        // Variables
        if let Some(ref vars) = fsm.variables {
            for var in vars {
                lines.push(format!("    %% var: {}({}) = {}", var.name, var.width, var.reset_value));
            }
        }

        // Initial state
        lines.push(format!("    [*] --> {}", fsm.initial_state));

        // States and transitions
        let mut state_names: Vec<_> = fsm.states.keys().cloned().collect();
        state_names.sort();

        for sname in &state_names {
            let state = &fsm.states[sname];

            // Note for timeout
            if let Some(timeout) = state.timeout_cycles {
                lines.push(format!("    note right of {}: timeout={}cycles", sname, timeout));
            }

            // Substates
            if let Some(ref substates) = state.substates {
                lines.push(format!("    state {} {{", sname));
                if let Some(ref init_sub) = state.initial_substate {
                    lines.push(format!("        [*] --> {}", init_sub));
                }
                let mut sub_names: Vec<_> = substates.keys().cloned().collect();
                sub_names.sort();
                for sub_name in &sub_names {
                    let sub_state = &substates[sub_name];
                    if let Some(timeout) = sub_state.timeout_cycles {
                        lines.push(format!("        note right of {}: timeout={}cycles", sub_name, timeout));
                    }
                    for trans in &sub_state.transitions {
                        let label = format_transition_label(trans);
                        lines.push(format!("        {} --> {}: {}", sub_name, trans.next_state, label));
                    }
                }
                lines.push("    }".to_string());
            }

            // Transitions from this state
            for trans in &state.transitions {
                let label = format_transition_label(trans);
                lines.push(format!("    {} --> {}: {}", sname, trans.next_state, label));
            }
        }
    }

    lines.join("\n")
}

/// Format a transition into a Mermaid label string
fn format_transition_label(trans: &FsmTransition) -> String {
    let mut parts = Vec::new();

    // Guard
    if let Some(ref guard) = trans.guard {
        parts.push(format!("[guard: {}]", guard));
    }

    // Match criteria
    let mut fields = Vec::new();
    let mc = &trans.match_criteria;
    if let Some(ref et) = mc.ethertype { fields.push(format!("ethertype={}", et)); }
    if let Some(ref mac) = mc.dst_mac { fields.push(format!("dst_mac={}", mac)); }
    if let Some(ref mac) = mc.src_mac { fields.push(format!("src_mac={}", mac)); }
    if let Some(vid) = mc.vlan_id { fields.push(format!("vlan_id={}", vid)); }
    if let Some(ref ip) = mc.src_ip { fields.push(format!("src_ip={}", ip)); }
    if let Some(ref ip) = mc.dst_ip { fields.push(format!("dst_ip={}", ip)); }
    if let Some(proto) = mc.ip_protocol { fields.push(format!("ip_protocol={}", proto)); }
    if !fields.is_empty() {
        parts.push(format!("[{}]", fields.join(",")));
    }

    // Action
    let action_str = match trans.action {
        Action::Pass => "pass",
        Action::Drop => "drop",
    };
    parts.push(format!("/{}", action_str));

    // Transition actions
    if let Some(ref actions) = trans.on_transition {
        parts.push(format!("{{{}}}", actions.join("; ")));
    }

    parts.join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_diagram() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    idle --> active: [ethertype=0x0800]/pass
    active --> idle: [ethertype=0x0806]/drop
"#;
        let diagram = parse_mermaid(input).unwrap();
        assert_eq!(diagram.initial_state, "idle");
        assert_eq!(diagram.states.len(), 2);
        assert_eq!(diagram.states["idle"].transitions.len(), 1);
        assert_eq!(diagram.states["idle"].transitions[0].next_state, "active");
    }

    #[test]
    fn parse_with_timeout() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    idle --> waiting: [ethertype=0x0800]/pass
    note right of waiting: timeout=5000cycles
    waiting --> idle: [ethertype=0x0806]/drop
"#;
        let diagram = parse_mermaid(input).unwrap();
        assert_eq!(diagram.states["waiting"].timeout_cycles, Some(5000));
    }

    #[test]
    fn parse_with_guard() {
        let input = r#"
stateDiagram-v2
    %% var: counter(16) = 0
    [*] --> idle
    idle --> active: [guard: counter > 10][ethertype=0x0800]/pass
"#;
        let diagram = parse_mermaid(input).unwrap();
        assert_eq!(diagram.variables.len(), 1);
        assert_eq!(diagram.variables[0].name, "counter");
        assert_eq!(diagram.variables[0].width, 16);
        let trans = &diagram.states["idle"].transitions[0];
        assert_eq!(trans.guard.as_deref(), Some("counter > 10"));
    }

    #[test]
    fn parse_transition_actions() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    idle --> active: [ethertype=0x0800]/pass{counter += 1; flag = 1}
"#;
        let diagram = parse_mermaid(input).unwrap();
        let trans = &diagram.states["idle"].transitions[0];
        let actions = trans.on_transition.as_ref().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "counter += 1");
        assert_eq!(actions[1], "flag = 1");
    }

    #[test]
    fn parse_composite_states() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    state tracking {
        normal --> burst: [ethertype=0x0800]/pass
    }
    idle --> tracking.normal: [ethertype=0x0800]/pass
"#;
        let diagram = parse_mermaid(input).unwrap();
        assert!(diagram.states.contains_key("tracking.normal"));
        assert!(diagram.states.contains_key("tracking.burst"));
    }

    #[test]
    fn reject_no_initial_state() {
        let input = r#"
stateDiagram-v2
    idle --> active: [ethertype=0x0800]/pass
"#;
        assert!(parse_mermaid(input).is_err());
    }

    #[test]
    fn roundtrip_yaml_mermaid() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    idle --> seen: [ethertype=0x0806]/pass
    seen --> idle: [ethertype=0x0800]/drop
"#;
        let diagram = parse_mermaid(input).unwrap();
        let config = to_yaml(diagram, "test_rule", 100);
        let mermaid_out = from_yaml(&config);
        assert!(mermaid_out.contains("[*] --> idle"));
        assert!(mermaid_out.contains("ethertype=0x0806"));
        assert!(mermaid_out.contains("/pass"));
    }

    #[test]
    fn to_yaml_produces_valid_config() {
        let input = r#"
stateDiagram-v2
    [*] --> idle
    idle --> active: [ethertype=0x0800]/pass
    active --> idle: /drop
"#;
        let diagram = parse_mermaid(input).unwrap();
        let config = to_yaml(diagram, "my_rule", 200);
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].name, "my_rule");
        assert_eq!(config.pacgate.rules[0].priority, 200);
        assert!(config.pacgate.rules[0].is_stateful());
    }
}
