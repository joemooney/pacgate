use std::process::Command;

fn pacgate_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pacgate"))
}

#[test]
fn compile_allow_arp() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify generated files exist
    assert!(tmp.path().join("rtl").exists(), "rtl/ directory missing");
    assert!(tmp.path().join("tb").exists(), "tb/ directory missing");
    assert!(tmp.path().join("rtl/packet_filter_top.v").exists(), "top-level Verilog missing");
    assert!(tmp.path().join("rtl/decision_logic.v").exists(), "decision logic missing");
    assert!(tmp.path().join("tb/test_packet_filter.py").exists(), "cocotb test missing");
    assert!(tmp.path().join("tb/Makefile").exists(), "Makefile missing");

    // Verify files are non-empty
    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("module packet_filter_top"), "top-level missing module declaration");
}

#[test]
fn compile_enterprise() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/enterprise.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Enterprise has 7 rules — should generate rule matchers
    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("rule_match_0"), "missing rule_match_0");
    assert!(top_v.contains("rule_match_6"), "missing rule_match_6 (7th rule)");
}

#[test]
fn compile_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["rules_count"], 1);
}

#[test]
fn validate_all_examples() {
    for example in &["allow_arp", "enterprise", "stateful_sequence", "blacklist", "datacenter"] {
        let path = format!("rules/examples/{}.yaml", example);
        let output = pacgate_bin()
            .args(["validate", &path])
            .output()
            .unwrap();
        assert!(output.status.success(), "validate failed for {}: {}", example, String::from_utf8_lossy(&output.stderr));
    }
}

#[test]
fn validate_json_output() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/enterprise.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "valid");
    assert_eq!(json["rules_count"], 7);
    assert!(json["rules"].is_array());
    assert!(json["warnings"].is_array());
}

#[test]
fn estimate_json_output() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/enterprise.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["total"]["luts"].as_u64().unwrap() > 0);
    assert!(json["total"]["ffs"].as_u64().unwrap() > 0);
    assert!(json["timing"]["total_cycles"].as_u64().unwrap() == 16);
}

#[test]
fn diff_detects_changes() {
    let output = pacgate_bin()
        .args(["diff", "rules/examples/allow_arp.yaml", "rules/examples/enterprise.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["added"].as_array().unwrap().len() > 0, "should detect added rules");
}

#[test]
fn diff_no_changes() {
    let output = pacgate_bin()
        .args(["diff", "rules/examples/allow_arp.yaml", "rules/examples/allow_arp.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No differences"), "same file should show no differences");
}

#[test]
fn stats_json_output() {
    let output = pacgate_bin()
        .args(["stats", "rules/examples/datacenter.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["total_rules"], 8);
    assert_eq!(json["stateless"], 8);
}

#[test]
fn graph_outputs_dot() {
    let output = pacgate_bin()
        .args(["graph", "rules/examples/blacklist.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("digraph pacgate"), "should output DOT format");
    assert!(stdout.contains("block_broadcast"), "should include rule names");
}

#[test]
fn init_creates_file() {
    let tmp = tempfile::tempdir().unwrap();
    let out_path = tmp.path().join("new_rules.yaml");
    let output = pacgate_bin()
        .args(["init", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(out_path.exists(), "init should create file");

    let contents = std::fs::read_to_string(&out_path).unwrap();
    assert!(contents.contains("pacgate:"), "should contain pacgate key");
}

#[test]
fn init_refuses_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let out_path = tmp.path().join("existing.yaml");
    std::fs::write(&out_path, "existing content").unwrap();

    let output = pacgate_bin()
        .args(["init", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "init should fail on existing file");
}

#[test]
fn validate_rejects_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let bad_yaml = tmp.path().join("bad.yaml");
    std::fs::write(&bad_yaml, "pacgate:\n  version: '1.0'\n  defaults:\n    action: drop\n  rules: []\n").unwrap();

    let output = pacgate_bin()
        .args(["validate", bad_yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "empty rules should fail validation");
}

#[test]
fn compile_stateful_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/stateful_sequence.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate FSM module
    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("rule_fsm") || top_v.contains("rule_match"), "should have rule modules");
}

// ── Phase 4 Integration Tests ──────────────────────────────────

#[test]
fn compile_with_axi_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/enterprise.yaml", "--axi", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --axi failed: {}", String::from_utf8_lossy(&output.stderr));

    // AXI RTL files should be copied to output
    assert!(tmp.path().join("rtl/axi_stream_adapter.v").exists(), "axi_stream_adapter.v missing");
    assert!(tmp.path().join("rtl/store_forward_fifo.v").exists(), "store_forward_fifo.v missing");
    assert!(tmp.path().join("rtl/packet_filter_axi_top.v").exists(), "packet_filter_axi_top.v missing");

    // AXI test bench should be generated
    assert!(tmp.path().join("tb-axi").exists(), "tb-axi/ directory missing");
    assert!(tmp.path().join("tb-axi/test_axi_packet_filter.py").exists(), "AXI test missing");
    assert!(tmp.path().join("tb-axi/Makefile").exists(), "AXI Makefile missing");

    // Verify AXI top module content
    let axi_top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_axi_top.v")).unwrap();
    assert!(axi_top.contains("module packet_filter_axi_top"), "AXI top module declaration missing");
    assert!(axi_top.contains("s_axis_tdata"), "AXI-Stream input missing");
    assert!(axi_top.contains("m_axis_tdata"), "AXI-Stream output missing");
}

#[test]
fn compile_axi_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--axi", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["axi_stream"], true);
}

#[test]
fn formal_generates_files() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["formal", "rules/examples/enterprise.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    // SVA assertions should exist
    assert!(tmp.path().join("formal/assertions.sv").exists(), "assertions.sv missing");
    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("module packet_filter_assertions"), "SVA module missing");
    assert!(sva.contains("property p_reset_decision_valid"), "reset property missing");
    assert!(sva.contains("property p_completeness"), "completeness property missing");
    assert!(sva.contains("property p_default_action"), "default action property missing");

    // SymbiYosys task file should exist
    assert!(tmp.path().join("formal/packet_filter.sby").exists(), "SBY file missing");
    let sby = std::fs::read_to_string(tmp.path().join("formal/packet_filter.sby")).unwrap();
    assert!(sby.contains("[tasks]"), "SBY tasks section missing");
    assert!(sby.contains("bmc"), "SBY BMC task missing");
    assert!(sby.contains("cover"), "SBY cover task missing");
}

#[test]
fn formal_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["formal", "rules/examples/allow_arp.yaml", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["generated"]["assertions"].as_str().unwrap().contains("assertions.sv"));
    assert!(json["generated"]["sby_task"].as_str().unwrap().contains("packet_filter.sby"));
}

#[test]
fn compile_generates_property_tests() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/enterprise.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    // Property test file should be generated alongside main test
    assert!(tmp.path().join("tb/test_properties.py").exists(), "property test file missing");
    let props = std::fs::read_to_string(tmp.path().join("tb/test_properties.py")).unwrap();
    assert!(props.contains("run_property_tests"), "property test runner missing");
    assert!(props.contains("RULES"), "rule definitions missing");
    assert!(props.contains("DEFAULT_ACTION"), "default action missing");
}
