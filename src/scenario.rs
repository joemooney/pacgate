// trace:FR-SCENARIO | ai:claude
//! Scenario validation, regression testing, and topology simulation.
//!
//! Migrated from pacilab (Python) into pacgate as native Rust subcommands.
//! Calls `simulator::simulate()` directly instead of shelling out to the binary.

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::loader;
use crate::model::{self, Ipv4Prefix};
use crate::simulator;

// ── Regex for scenario ID ──────────────────────────────────────────────────

static SCENARIO_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.\-]+$").unwrap());

// ── Allowed key sets (mirrors Python's strict key checking) ────────────────

const ALLOWED_TOP_KEYS: &[&str] = &[
    "schema_version",
    "id",
    "name",
    "description",
    "default_rules_file",
    "stateful",
    "tags",
    "events",
    "topology",
];

const ALLOWED_EVENT_KEYS: &[&str] = &[
    "name",
    "packet",
    "expected_action",
    "delay_ms",
    "meta",
    "ingress_port",
    "expected_egress_port",
    "expected_switch_action",
    "inject_rmac_error",
];

const ALLOWED_TOPOLOGY_KEYS: &[&str] = &["kind", "ports"];
const ALLOWED_TOPOLOGY_PORT_KEYS: &[&str] = &["id", "name", "subnet", "mac"];

// ── Types ──────────────────────────────────────────────────────────────────

pub type PacketSpec = HashMap<String, serde_json::Value>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExpectedAction {
    Pass,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SwitchAction {
    Forward,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyPort {
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub subnet: String,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    #[serde(default = "default_topology_kind")]
    pub kind: String,
    pub ports: Vec<TopologyPort>,
}

fn default_topology_kind() -> String {
    "l3_switch_2port".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvent {
    pub name: String,
    pub packet: PacketSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_action: Option<ExpectedAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_egress_port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_switch_action: Option<SwitchAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_rmac_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_rules_file: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stateful: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub events: Vec<ScenarioEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology: Option<Topology>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStore {
    pub items: Vec<Scenario>,
}

// ── JSON key validation ────────────────────────────────────────────────────

fn validate_json_keys(raw: &serde_json::Value) -> Result<()> {
    let obj = raw
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("scenario must be an object"))?;

    // Check top-level keys
    for key in obj.keys() {
        if !ALLOWED_TOP_KEYS.contains(&key.as_str()) {
            bail!("unknown top-level key: '{}'", key);
        }
    }

    // Check event keys
    if let Some(events) = obj.get("events").and_then(|v| v.as_array()) {
        for (i, ev) in events.iter().enumerate() {
            if let Some(ev_obj) = ev.as_object() {
                for key in ev_obj.keys() {
                    if !ALLOWED_EVENT_KEYS.contains(&key.as_str()) {
                        bail!("events[{}] unknown key: '{}'", i, key);
                    }
                }
                // Check packet values are scalar
                if let Some(pkt) = ev_obj.get("packet").and_then(|v| v.as_object()) {
                    for (k, v) in pkt {
                        if !v.is_string() && !v.is_number() && !v.is_boolean() {
                            bail!(
                                "events[{}].packet['{}'] must be string/integer/number/boolean",
                                i,
                                k
                            );
                        }
                    }
                }
            }
        }
    }

    // Check topology keys
    if let Some(topo) = obj.get("topology").and_then(|v| v.as_object()) {
        for key in topo.keys() {
            if !ALLOWED_TOPOLOGY_KEYS.contains(&key.as_str()) {
                bail!("topology unknown key: '{}'", key);
            }
        }
        if let Some(ports) = topo.get("ports").and_then(|v| v.as_array()) {
            for (i, port) in ports.iter().enumerate() {
                if let Some(port_obj) = port.as_object() {
                    for key in port_obj.keys() {
                        if !ALLOWED_TOPOLOGY_PORT_KEYS.contains(&key.as_str()) {
                            bail!("topology.ports[{}] unknown key: '{}'", i, key);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Semantic validation ────────────────────────────────────────────────────

impl Scenario {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            bail!("id is required");
        }
        if !SCENARIO_ID_RE.is_match(&self.id) {
            bail!("id must match ^[A-Za-z0-9_.-]+$");
        }
        if self.name.trim().is_empty() {
            bail!("name is required");
        }
        if self.events.is_empty() {
            bail!("events must be a non-empty array");
        }
        if let Some(ref v) = self.schema_version {
            let vl = v.to_lowercase();
            if vl != "v1" && vl != "v2" {
                bail!("schema_version must be 'v1' or 'v2'");
            }
        }
        if let Some(ref drf) = self.default_rules_file {
            if drf.trim().is_empty() {
                bail!("default_rules_file cannot be empty when provided");
            }
        }

        // Validate tags uniqueness
        let mut seen_tags = std::collections::HashSet::new();
        for (i, tag) in self.tags.iter().enumerate() {
            if tag.trim().is_empty() {
                bail!("tags[{}] cannot be empty", i);
            }
            if !seen_tags.insert(tag.as_str()) {
                bail!("tags[{}] duplicates '{}'", i, tag);
            }
        }

        // Validate events
        for (i, ev) in self.events.iter().enumerate() {
            if ev.name.trim().is_empty() {
                bail!("events[{}].name is required", i);
            }
            if ev.packet.is_empty() {
                bail!("events[{}].packet must be a non-empty object", i);
            }
        }

        // Validate topology
        if let Some(ref topo) = self.topology {
            if topo.kind.trim().is_empty() {
                bail!("topology.kind cannot be empty");
            }
            if topo.ports.len() < 2 {
                bail!("topology.ports must be an array of at least 2 ports");
            }
            let mut seen_ids = std::collections::HashSet::new();
            for (i, port) in topo.ports.iter().enumerate() {
                if !seen_ids.insert(port.id) {
                    bail!("topology.ports[{}].id duplicates {}", i, port.id);
                }
                if port.subnet.trim().is_empty() {
                    bail!("topology.ports[{}].subnet is required", i);
                }
                if port.mac.trim().is_empty() {
                    bail!("topology.ports[{}].mac is required", i);
                }
            }
        }

        Ok(())
    }
}

// ── Loading ────────────────────────────────────────────────────────────────

pub fn load_scenario(path: &Path) -> Result<Scenario> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read scenario file: {}", path.display()))?;

    let raw: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse JSON: {}", path.display()))?;

    validate_json_keys(&raw)?;

    let scenario: Scenario = serde_json::from_value(raw)
        .with_context(|| format!("Failed to deserialize scenario: {}", path.display()))?;

    scenario.validate()?;
    Ok(scenario)
}

pub fn load_scenario_from_str(contents: &str) -> Result<Scenario> {
    let raw: serde_json::Value = serde_json::from_str(contents)
        .context("Failed to parse JSON")?;

    validate_json_keys(&raw)?;

    let scenario: Scenario =
        serde_json::from_value(raw).context("Failed to deserialize scenario")?;

    scenario.validate()?;
    Ok(scenario)
}

// ── Packet conversion ──────────────────────────────────────────────────────

pub fn packet_spec_to_sim_packet(packet: &PacketSpec) -> Result<simulator::SimPacket> {
    let mut parts = Vec::new();
    for (k, v) in packet {
        let val_str = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => bail!("packet field '{}' must be string/number/boolean", k),
        };
        if !val_str.is_empty() {
            parts.push(format!("{}={}", k.trim(), val_str.trim()));
        }
    }
    if parts.is_empty() {
        bail!("packet has no fields");
    }
    let spec = parts.join(",");
    simulator::parse_packet_spec(&spec)
}

// ── Batch validation ───────────────────────────────────────────────────────

pub fn validate_files(paths: &[std::path::PathBuf]) -> serde_json::Value {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    for p in paths {
        match load_scenario(p) {
            Ok(s) => {
                results.push(serde_json::json!({
                    "file": p.display().to_string(),
                    "id": s.id,
                    "events": s.events.len(),
                    "ok": true,
                }));
            }
            Err(e) => {
                errors.push(serde_json::json!({
                    "file": p.display().to_string(),
                    "ok": false,
                    "error": format!("{}", e),
                }));
            }
        }
    }

    serde_json::json!({
        "status": if errors.is_empty() { "ok" } else { "error" },
        "validated": results.len(),
        "failed": errors.len(),
        "results": results,
        "errors": errors,
    })
}

// ── Store operations ───────────────────────────────────────────────────────

pub fn load_store(path: &Path) -> Result<Vec<Scenario>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read store: {}", path.display()))?;
    let store: ScenarioStore = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse store: {}", path.display()))?;

    // Validate each item
    for (i, s) in store.items.iter().enumerate() {
        s.validate()
            .with_context(|| format!("store item {} ('{}') invalid", i, s.id))?;
    }
    Ok(store.items)
}

pub fn save_store(path: &Path, items: &[Scenario]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = ScenarioStore {
        items: items.to_vec(),
    };
    let json = serde_json::to_string_pretty(&store)?;
    std::fs::write(path, format!("{}\n", json))?;
    Ok(())
}

pub fn import_scenarios(
    in_dir: &Path,
    store_path: &Path,
    replace: bool,
) -> Result<serde_json::Value> {
    let mut files: Vec<_> = std::fs::read_dir(in_dir)
        .with_context(|| format!("Failed to read directory: {}", in_dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "json")
                && e.path().is_file()
        })
        .map(|e| e.path())
        .collect();
    files.sort();

    let mut imported = Vec::new();
    for f in &files {
        let s = load_scenario(f)
            .with_context(|| format!("Failed to load {}", f.display()))?;
        imported.push(s);
    }

    let merged = if replace {
        imported.clone()
    } else {
        let current = load_store(store_path)?;
        let mut by_id: HashMap<String, Scenario> =
            current.into_iter().map(|s| (s.id.clone(), s)).collect();
        for s in &imported {
            by_id.insert(s.id.clone(), s.clone());
        }
        let mut items: Vec<Scenario> = by_id.into_values().collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        items
    };

    save_store(store_path, &merged)?;

    Ok(serde_json::json!({
        "imported_files": files.len(),
        "stored_total": merged.len(),
        "mode": if replace { "replace" } else { "merge" },
    }))
}

pub fn export_scenarios(store_path: &Path, out_dir: &Path) -> Result<serde_json::Value> {
    let items = load_store(store_path)?;
    std::fs::create_dir_all(out_dir)?;
    for s in &items {
        let path = out_dir.join(format!("{}.json", s.id));
        let json = serde_json::to_string_pretty(s)?;
        std::fs::write(path, format!("{}\n", json))?;
    }
    Ok(serde_json::json!({
        "exported": items.len(),
        "out_dir": out_dir.display().to_string(),
    }))
}

// ── Regression runner ──────────────────────────────────────────────────────

pub fn run_regress(
    scenario: &Scenario,
    count: usize,
    json_output: bool,
) -> Result<serde_json::Value> {
    let rules_file = scenario
        .default_rules_file
        .as_deref()
        .unwrap_or("rules/examples/allow_arp.yaml");

    let config = loader::load_rules(Path::new(rules_file))
        .with_context(|| format!("Failed to load rules: {}", rules_file))?;

    let events = &scenario.events;
    let mut mismatches = 0;
    let mut results = Vec::new();

    // Set up stateful state if needed
    let mut rate_state = simulator::SimRateLimitState::new(&config);
    let conntrack_timeout = config
        .pacgate
        .conntrack
        .as_ref()
        .map(|c| c.timeout_cycles)
        .unwrap_or(30);
    let mut conntrack = simulator::SimConntrackTable::new(conntrack_timeout);

    let start = std::time::Instant::now();

    for i in 0..count {
        let ev = &events[i % events.len()];
        let sim_pkt = packet_spec_to_sim_packet(&ev.packet)
            .with_context(|| format!("Failed to parse packet for event '{}'", ev.name))?;

        let result = if scenario.stateful {
            simulator::simulate_stateful(
                &config,
                &sim_pkt,
                &mut rate_state,
                &mut conntrack,
                0.01,
                i as u64,
            )
        } else {
            simulator::simulate(&config, &sim_pkt)
        };

        let action_str = match result.action {
            model::Action::Pass => "pass",
            model::Action::Drop => "drop",
        };

        let expected = ev.expected_action.as_ref().map(|ea| match ea {
            ExpectedAction::Pass => "pass",
            ExpectedAction::Drop => "drop",
        });

        let ok = expected.map_or(true, |exp| exp == action_str);
        if !ok {
            mismatches += 1;
        }

        // Cap output at first 50 results
        if results.len() < 50 {
            results.push(serde_json::json!({
                "index": i,
                "event_name": ev.name,
                "expected_action": expected,
                "actual_action": action_str,
                "ok": ok,
            }));
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let pps = if elapsed > 0.0 {
        Some((count as f64 / elapsed * 100.0).round() / 100.0)
    } else {
        None
    };

    let output = serde_json::json!({
        "scenario_id": scenario.id,
        "count": count,
        "mismatches": mismatches,
        "elapsed_sec": (elapsed * 1000.0).round() / 1000.0,
        "packets_per_sec": pps,
        "results": results,
    });

    if !json_output {
        if mismatches == 0 {
            println!(
                "  PASS  {} — {} packets, {:.3}s ({:.0} pps), 0 mismatches",
                scenario.id,
                count,
                elapsed,
                pps.unwrap_or(0.0)
            );
        } else {
            println!(
                "  FAIL  {} — {} packets, {:.3}s, {} mismatches",
                scenario.id, count, elapsed, mismatches
            );
            for r in &results {
                if r["ok"] == false {
                    println!(
                        "    [{}] {} — expected {:?}, got {}",
                        r["index"], r["event_name"], r["expected_action"], r["actual_action"]
                    );
                }
            }
        }
    }

    if mismatches > 0 {
        // Return the output but signal error via exit code
        // The caller (main.rs) handles process::exit
    }

    Ok(output)
}

// ── Topology simulation ────────────────────────────────────────────────────

struct PortCfg {
    id: u32,
    #[allow(dead_code)]
    name: String,
    subnet: Ipv4Prefix,
    #[allow(dead_code)]
    mac: String,
}

fn lookup_egress(ports: &[PortCfg], ingress: u32, dst_ip: Option<&str>) -> Option<u32> {
    let dst = dst_ip?;
    for p in ports {
        if p.id == ingress {
            continue;
        }
        if p.subnet.contains(dst) {
            return Some(p.id);
        }
    }
    None
}

pub fn run_topology(scenario: &Scenario, json_output: bool) -> Result<serde_json::Value> {
    let topo = scenario
        .topology
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("scenario.topology is required"))?;

    let mut ports = Vec::new();
    for p in &topo.ports {
        let subnet = Ipv4Prefix::parse(&p.subnet)
            .with_context(|| format!("Bad subnet '{}' in port {}", p.subnet, p.id))?;
        ports.push(PortCfg {
            id: p.id,
            name: p.name.clone().unwrap_or_else(|| format!("port{}", p.id)),
            subnet,
            mac: p.mac.clone(),
        });
    }
    let by_id: HashMap<u32, usize> = ports.iter().enumerate().map(|(i, p)| (p.id, i)).collect();

    let rules_file = scenario
        .default_rules_file
        .as_deref()
        .unwrap_or("rules/examples/allow_arp.yaml");

    let config = loader::load_rules(Path::new(rules_file))
        .with_context(|| format!("Failed to load rules: {}", rules_file))?;

    // Set up stateful state if needed
    let mut rate_state = simulator::SimRateLimitState::new(&config);
    let conntrack_timeout = config
        .pacgate
        .conntrack
        .as_ref()
        .map(|c| c.timeout_cycles)
        .unwrap_or(30);
    let mut conntrack = simulator::SimConntrackTable::new(conntrack_timeout);

    let mut stats = serde_json::json!({
        "total_events": 0,
        "rmac_error_count": 0,
        "rmac_dropped": 0,
        "switch_forwarded": 0,
        "switch_dropped": 0,
        "switch_drop_reasons": {
            "rmac_error": 0,
            "ingress_subnet_mismatch": 0,
            "pacgate_drop": 0,
            "no_route": 0,
        },
    });

    let mut mismatches = 0;
    let mut results = Vec::new();

    for (i, ev) in scenario.events.iter().enumerate() {
        stats["total_events"] = serde_json::json!(stats["total_events"].as_u64().unwrap() + 1);

        let ingress = ev.ingress_port.unwrap_or(0);
        if !by_id.contains_key(&ingress) {
            bail!("events[{}].ingress_port {} not in topology", i, ingress);
        }

        let src_ip = ev
            .packet
            .get("src_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let dst_ip = ev
            .packet
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        let ingress_idx = by_id[&ingress];
        let ingress_cfg = &ports[ingress_idx];

        let mut pacgate_result: Option<serde_json::Value> = None;
        let mut switch_action = "drop";
        let mut egress: Option<u32> = None;
        let mut drop_reason = "";

        let inject_rmac = ev.inject_rmac_error.unwrap_or(false);

        if inject_rmac {
            inc_stat(&mut stats, "rmac_error_count");
            inc_stat(&mut stats, "rmac_dropped");
            inc_stat(&mut stats, "switch_dropped");
            inc_drop_reason(&mut stats, "rmac_error");
            drop_reason = "rmac_error";
        } else if src_ip
            .as_deref()
            .map_or(false, |ip| !ingress_cfg.subnet.contains(ip))
        {
            inc_stat(&mut stats, "rmac_dropped");
            inc_stat(&mut stats, "switch_dropped");
            inc_drop_reason(&mut stats, "ingress_subnet_mismatch");
            drop_reason = "ingress_subnet_mismatch";
        } else {
            let sim_pkt = packet_spec_to_sim_packet(&ev.packet)
                .with_context(|| format!("Failed to parse packet for event '{}'", ev.name))?;

            let result = if scenario.stateful {
                simulator::simulate_stateful(
                    &config,
                    &sim_pkt,
                    &mut rate_state,
                    &mut conntrack,
                    0.01,
                    i as u64,
                )
            } else {
                simulator::simulate(&config, &sim_pkt)
            };

            let action_str = match result.action {
                model::Action::Pass => "pass",
                model::Action::Drop => "drop",
            };

            pacgate_result = Some(serde_json::json!({
                "status": "ok",
                "action": action_str,
                "matched_rule": result.rule_name,
                "is_default": result.is_default,
            }));

            if action_str == "drop" {
                inc_stat(&mut stats, "switch_dropped");
                inc_drop_reason(&mut stats, "pacgate_drop");
                drop_reason = "pacgate_drop";
            } else {
                let eg = lookup_egress(&ports, ingress, dst_ip.as_deref());
                if eg.is_none() {
                    inc_stat(&mut stats, "switch_dropped");
                    inc_drop_reason(&mut stats, "no_route");
                    drop_reason = "no_route";
                } else {
                    switch_action = "forward";
                    egress = eg;
                    inc_stat(&mut stats, "switch_forwarded");
                }
            }
        }

        // Check expectations
        let expected_action = ev.expected_action.as_ref().map(|ea| match ea {
            ExpectedAction::Pass => "pass",
            ExpectedAction::Drop => "drop",
        });

        let expected_switch = ev.expected_switch_action.as_ref().map(|sa| match sa {
            SwitchAction::Forward => "forward",
            SwitchAction::Drop => "drop",
        });

        let action_ok = expected_action.map_or(true, |exp| {
            let actual = pacgate_result
                .as_ref()
                .and_then(|r| r["action"].as_str())
                .unwrap_or("drop");
            exp == actual
        });

        let switch_ok = expected_switch.map_or(true, |exp| exp == switch_action);

        let egress_ok = ev.expected_egress_port.map_or(true, |exp| {
            egress.map_or(false, |eg| eg == exp)
        });

        let event_ok = action_ok && switch_ok && egress_ok;
        if !event_ok {
            mismatches += 1;
        }

        results.push(serde_json::json!({
            "event_index": i,
            "event_name": ev.name,
            "ingress_port": ingress,
            "switch_action": switch_action,
            "egress_port": egress,
            "drop_reason": drop_reason,
            "pacgate": pacgate_result,
            "event_ok": event_ok,
        }));
    }

    let output = serde_json::json!({
        "scenario_id": scenario.id,
        "mismatch_count": mismatches,
        "stats": stats,
        "results": results,
    });

    if !json_output {
        let total = stats["total_events"].as_u64().unwrap_or(0);
        let fwd = stats["switch_forwarded"].as_u64().unwrap_or(0);
        let drp = stats["switch_dropped"].as_u64().unwrap_or(0);
        if mismatches == 0 {
            println!(
                "  PASS  {} — {} events, {} forwarded, {} dropped, 0 mismatches",
                scenario.id, total, fwd, drp
            );
        } else {
            println!(
                "  FAIL  {} — {} events, {} mismatches",
                scenario.id, total, mismatches
            );
            for r in &results {
                if r["event_ok"] == false {
                    println!(
                        "    [{}] {} — switch={}, egress={}, drop_reason={}",
                        r["event_index"],
                        r["event_name"],
                        r["switch_action"],
                        r["egress_port"],
                        r["drop_reason"]
                    );
                }
            }
        }
    }

    Ok(output)
}

// Helper to increment a stat counter in the JSON object
fn inc_stat(stats: &mut serde_json::Value, key: &str) {
    let val = stats[key].as_u64().unwrap_or(0) + 1;
    stats[key] = serde_json::json!(val);
}

fn inc_drop_reason(stats: &mut serde_json::Value, reason: &str) {
    let val = stats["switch_drop_reasons"][reason].as_u64().unwrap_or(0) + 1;
    stats["switch_drop_reasons"][reason] = serde_json::json!(val);
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_scenario_parse() {
        let json = include_str!("../docs/management/paclab/scenarios/allow_arp_regression_v1.json");
        let scenario = load_scenario_from_str(json).unwrap();
        assert_eq!(scenario.id, "allow_arp_regression_v1");
        assert_eq!(scenario.events.len(), 2);
        assert!(scenario.topology.is_none());
        assert_eq!(
            scenario.events[0].expected_action,
            Some(ExpectedAction::Pass)
        );
        assert_eq!(
            scenario.events[1].expected_action,
            Some(ExpectedAction::Drop)
        );
    }

    #[test]
    fn test_v2_scenario_parse() {
        let json =
            include_str!("../docs/management/paclab/scenarios/rmac2_l3_switch_baseline.json");
        let scenario = load_scenario_from_str(json).unwrap();
        assert_eq!(scenario.id, "rmac2_l3_switch_baseline");
        assert!(scenario.topology.is_some());
        let topo = scenario.topology.unwrap();
        assert_eq!(topo.ports.len(), 2);
        assert_eq!(topo.ports[0].subnet, "10.0.0.0/24");
        assert_eq!(topo.ports[1].subnet, "10.0.1.0/24");
        assert_eq!(scenario.events.len(), 3);
        assert_eq!(
            scenario.events[0].expected_switch_action,
            Some(SwitchAction::Forward)
        );
    }

    #[test]
    fn test_bad_id_rejected() {
        let json = r#"{"id": "bad id!", "name": "Test", "events": [{"name": "e", "packet": {"ethertype": "0x0800"}}]}"#;
        let err = load_scenario_from_str(json).unwrap_err();
        assert!(
            format!("{}", err).contains("id must match"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_empty_events_rejected() {
        let json = r#"{"id": "test", "name": "Test", "events": []}"#;
        let err = load_scenario_from_str(json).unwrap_err();
        assert!(
            format!("{}", err).contains("non-empty"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_unknown_key_rejected() {
        let json = r#"{"id": "test", "name": "Test", "bogus": true, "events": [{"name": "e", "packet": {"ethertype": "0x0800"}}]}"#;
        let err = load_scenario_from_str(json).unwrap_err();
        assert!(
            format!("{}", err).contains("unknown top-level key"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_packet_spec_to_sim_packet() {
        let mut pkt = PacketSpec::new();
        pkt.insert("ethertype".into(), serde_json::json!("0x0800"));
        pkt.insert("src_ip".into(), serde_json::json!("10.0.0.1"));
        pkt.insert("dst_port".into(), serde_json::json!(80));
        let sim = packet_spec_to_sim_packet(&pkt).unwrap();
        assert_eq!(sim.ethertype, Some(0x0800));
        assert_eq!(sim.src_ip, Some("10.0.0.1".to_string()));
        assert_eq!(sim.dst_port, Some(80));
    }

    #[test]
    fn test_ipv4_prefix_contains() {
        let prefix = Ipv4Prefix::parse("10.0.0.0/24").unwrap();
        assert!(prefix.contains("10.0.0.1"));
        assert!(prefix.contains("10.0.0.254"));
        assert!(!prefix.contains("10.0.1.1"));
        assert!(!prefix.contains("192.168.0.1"));

        let host = Ipv4Prefix::parse("10.0.0.1").unwrap();
        assert!(host.contains("10.0.0.1"));
        assert!(!host.contains("10.0.0.2"));

        let wide = Ipv4Prefix::parse("10.0.0.0/8").unwrap();
        assert!(wide.contains("10.255.255.255"));
        assert!(!wide.contains("11.0.0.1"));
    }

    #[test]
    fn test_store_roundtrip() {
        let scenario = Scenario {
            id: "test_store".into(),
            name: "Store Test".into(),
            schema_version: None,
            description: Some("A test".into()),
            default_rules_file: None,
            stateful: false,
            tags: vec!["test".into()],
            events: vec![ScenarioEvent {
                name: "ev1".into(),
                packet: {
                    let mut m = PacketSpec::new();
                    m.insert("ethertype".into(), serde_json::json!("0x0800"));
                    m
                },
                expected_action: Some(ExpectedAction::Pass),
                delay_ms: None,
                meta: None,
                ingress_port: None,
                expected_egress_port: None,
                expected_switch_action: None,
                inject_rmac_error: None,
            }],
            topology: None,
        };

        let json = serde_json::to_string_pretty(&scenario).unwrap();
        let parsed: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test_store");
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.tags, vec!["test"]);
    }

    #[test]
    fn test_duplicate_tag_rejected() {
        let json = r#"{"id": "test", "name": "Test", "tags": ["a", "a"], "events": [{"name": "e", "packet": {"ethertype": "0x0800"}}]}"#;
        let err = load_scenario_from_str(json).unwrap_err();
        assert!(
            format!("{}", err).contains("duplicates"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_topology_port_uniqueness() {
        let json = r#"{
            "id": "test", "name": "Test", "schema_version": "v2",
            "topology": {
                "kind": "l3_switch_2port",
                "ports": [
                    {"id": 0, "subnet": "10.0.0.0/24", "mac": "AA:BB:CC:DD:00:00"},
                    {"id": 0, "subnet": "10.0.1.0/24", "mac": "AA:BB:CC:DD:01:00"}
                ]
            },
            "events": [{"name": "e", "packet": {"ethertype": "0x0800"}}]
        }"#;
        let err = load_scenario_from_str(json).unwrap_err();
        assert!(
            format!("{}", err).contains("duplicates"),
            "got: {}",
            err
        );
    }
}
