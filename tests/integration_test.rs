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
    for example in &["allow_arp", "enterprise", "stateful_sequence", "blacklist", "datacenter",
                     "industrial_ot", "automotive_gateway", "5g_fronthaul", "campus_access",
                     "iot_gateway", "syn_flood_detect", "arp_spoof_detect",
                     "l3l4_firewall", "vxlan_datacenter"] {
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

#[test]
fn lint_json_output() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/enterprise.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["findings"].is_array());
    assert!(json["summary"]["total"].as_u64().unwrap() > 0, "enterprise should have findings");
    assert_eq!(json["total_rules"], 7);
}

#[test]
fn lint_clean_blacklist() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/blacklist.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    // Blacklist example has STP block, so no LINT004 warning
    let findings = json["findings"].as_array().unwrap();
    let lint_findings: Vec<_> = findings.iter().filter(|f| {
        f["code"].as_str().map(|c| c.starts_with("LINT")).unwrap_or(false)
    }).collect();
    assert!(lint_findings.is_empty(), "blacklist should have no lint findings (only overlap warnings if any)");
}

// ── L3/L4 Integration Tests ──────────────────────────────────

#[test]
fn compile_l3l4_firewall() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate rule matchers for all 8 rules
    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("rule_match_0"), "missing rule_match_0");
    assert!(top_v.contains("rule_match_7"), "missing rule_match_7 (8th rule)");

    // Check that L3/L4 signals are wired
    assert!(top_v.contains("src_ip"), "missing src_ip signal in top");
    assert!(top_v.contains("dst_ip"), "missing dst_ip signal in top");
    assert!(top_v.contains("ip_protocol"), "missing ip_protocol signal in top");
    assert!(top_v.contains("src_port"), "missing src_port signal in top");
    assert!(top_v.contains("dst_port"), "missing dst_port signal in top");

    // Check generated rule matcher has IP/port conditions
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("src_ip") || rule0.contains("dst_port"), "L3/L4 conditions missing from rule matcher");
}

#[test]
fn compile_l3l4_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["rules_count"], 8);
}

#[test]
fn compile_with_counters() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/enterprise.yaml", "--counters", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --counters failed: {}", String::from_utf8_lossy(&output.stderr));

    // Counter RTL files should be copied to output
    assert!(tmp.path().join("rtl/rule_counters.v").exists(), "rule_counters.v missing");
    assert!(tmp.path().join("rtl/axi_lite_csr.v").exists(), "axi_lite_csr.v missing");

    // Decision logic should have rule_idx output
    let decision_v = std::fs::read_to_string(tmp.path().join("rtl/decision_logic.v")).unwrap();
    assert!(decision_v.contains("decision_rule_idx"), "decision_rule_idx output missing");
    assert!(decision_v.contains("decision_default"), "decision_default output missing");
}

#[test]
fn compile_counters_json() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--counters", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["counters"], true);
}

#[test]
fn compile_vxlan_datacenter() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/vxlan_datacenter.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Check VXLAN VNI matching in generated rule
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("vxlan_vni"), "VXLAN VNI matching missing from rule");

    // Check top-level has VXLAN signals
    let top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top.contains("vxlan_vni"), "vxlan_vni signal missing from top");
}

#[test]
fn report_generates_html() {
    let tmp = tempfile::tempdir().unwrap();
    let report_path = tmp.path().join("report.html");
    let output = pacgate_bin()
        .args(["report", "rules/examples/l3l4_firewall.yaml", "-o", report_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "report failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(report_path.exists(), "HTML report missing");
    let html = std::fs::read_to_string(&report_path).unwrap();
    assert!(html.contains("PacGate Coverage Report"), "missing report title");
    assert!(html.contains("allow_ssh_mgmt"), "missing rule name in report");
    assert!(html.contains("src_ip"), "missing L3 field in report");
    assert!(html.contains("dst_port"), "missing L4 field in report");
}

#[test]
fn pcap_import() {
    let tmp = tempfile::tempdir().unwrap();

    // Create a minimal valid PCAP file with 2 Ethernet frames
    let mut pcap_data: Vec<u8> = Vec::new();
    // Global header
    pcap_data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    pcap_data.extend_from_slice(&2u16.to_le_bytes());           // version major
    pcap_data.extend_from_slice(&4u16.to_le_bytes());           // version minor
    pcap_data.extend_from_slice(&0i32.to_le_bytes());           // thiszone
    pcap_data.extend_from_slice(&0u32.to_le_bytes());           // sigfigs
    pcap_data.extend_from_slice(&65535u32.to_le_bytes());       // snaplen
    pcap_data.extend_from_slice(&1u32.to_le_bytes());           // link type (Ethernet)

    // Frame 1: ARP broadcast (60 bytes)
    let frame1 = [0xffu8; 60];
    pcap_data.extend_from_slice(&0u32.to_le_bytes());           // ts_sec
    pcap_data.extend_from_slice(&0u32.to_le_bytes());           // ts_usec
    pcap_data.extend_from_slice(&(frame1.len() as u32).to_le_bytes()); // incl_len
    pcap_data.extend_from_slice(&(frame1.len() as u32).to_le_bytes()); // orig_len
    pcap_data.extend_from_slice(&frame1);

    // Frame 2: 64-byte frame
    let frame2 = [0xaau8; 64];
    pcap_data.extend_from_slice(&1u32.to_le_bytes());
    pcap_data.extend_from_slice(&0u32.to_le_bytes());
    pcap_data.extend_from_slice(&(frame2.len() as u32).to_le_bytes());
    pcap_data.extend_from_slice(&(frame2.len() as u32).to_le_bytes());
    pcap_data.extend_from_slice(&frame2);

    let pcap_path = tmp.path().join("test.pcap");
    std::fs::write(&pcap_path, &pcap_data).unwrap();

    let out_dir = tmp.path().join("gen");
    let output = pacgate_bin()
        .args(["pcap", pcap_path.to_str().unwrap(), "-o", out_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "pcap failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["frame_count"], 2);

    // Stimulus file should exist
    assert!(out_dir.join("tb/pcap_stimulus.py").exists(), "stimulus file missing");
    let stimulus = std::fs::read_to_string(out_dir.join("tb/pcap_stimulus.py")).unwrap();
    assert!(stimulus.contains("PCAP_FRAMES"), "missing PCAP_FRAMES");
}

// ── Connection Tracking Integration Tests ──────────────────────────────────

#[test]
fn compile_with_conntrack() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--conntrack",
               "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --conntrack failed: {}", String::from_utf8_lossy(&output.stderr));

    // Conntrack RTL should be copied
    assert!(tmp.path().join("rtl/conntrack_table.v").exists(), "conntrack_table.v missing");
    let ct = std::fs::read_to_string(tmp.path().join("rtl/conntrack_table.v")).unwrap();
    assert!(ct.contains("module conntrack_table"), "conntrack module missing");
    assert!(ct.contains("table_valid"), "table_valid missing");
}

// ── Multi-Port Integration Tests ──────────────────────────────────

#[test]
fn compile_multiport() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--ports", "4",
               "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --ports 4 failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate multiport wrapper
    assert!(tmp.path().join("rtl/packet_filter_multiport_top.v").exists(),
        "packet_filter_multiport_top.v missing");

    let multiport = std::fs::read_to_string(
        tmp.path().join("rtl/packet_filter_multiport_top.v")
    ).unwrap();
    assert!(multiport.contains("module packet_filter_multiport_top"), "multiport module missing");
    assert!(multiport.contains("port0_pkt_data"), "port0 interface missing");
    assert!(multiport.contains("port3_pkt_data"), "port3 interface missing");
    assert!(multiport.contains("u_filter_port0"), "port0 instance missing");
    assert!(multiport.contains("u_filter_port3"), "port3 instance missing");
}

#[test]
fn compile_multiport_json() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--ports", "2",
               "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["ports"], 2);
}

// ── Mermaid Integration Tests ──────────────────────────────────

#[test]
fn from_mermaid_generates_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    let mermaid_path = tmp.path().join("test.md");
    std::fs::write(&mermaid_path, r#"
stateDiagram-v2
    [*] --> idle
    idle --> seen: [ethertype=0x0806]/pass
    note right of seen: timeout=1000cycles
    seen --> idle: [ethertype=0x0800]/drop
"#).unwrap();

    let out_path = tmp.path().join("rules.yaml");
    let output = pacgate_bin()
        .args(["from-mermaid", mermaid_path.to_str().unwrap(),
               "--name", "arp_detect", "--priority", "150",
               "-o", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "from-mermaid failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(out_path.exists(), "output YAML missing");

    let yaml = std::fs::read_to_string(&out_path).unwrap();
    assert!(yaml.contains("arp_detect"), "rule name missing");
    assert!(yaml.contains("stateful"), "should be stateful rule");
}

#[test]
fn to_mermaid_outputs_diagram() {
    let output = pacgate_bin()
        .args(["to-mermaid", "rules/examples/stateful_sequence.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "to-mermaid failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stateDiagram-v2"), "missing Mermaid header");
    assert!(stdout.contains("[*] -->"), "missing initial state arrow");
}

// ── HSM Integration Tests ──────────────────────────────────

#[test]
fn compile_hsm_conntrack() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/hsm_conntrack.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate FSM with variables and flattened states
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("var_pkt_count"), "var_pkt_count register missing from FSM");
    assert!(rule0.contains("S_TRACKING_NORMAL") || rule0.contains("S_TRACKING_BURST"),
        "flattened HSM states missing");
}


#[test]
fn compile_byte_match() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/byte_match.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate byte_capture module
    assert!(tmp.path().join("rtl/byte_capture.v").exists(), "byte_capture.v missing");
    let byte_cap = std::fs::read_to_string(tmp.path().join("rtl/byte_capture.v")).unwrap();
    assert!(byte_cap.contains("module byte_capture"), "byte_capture module missing");
    assert!(byte_cap.contains("byte_cap_14"), "byte_cap_14 register missing");
    assert!(byte_cap.contains("byte_cap_47"), "byte_cap_47 register missing");

    // Top-level should instantiate byte_capture
    let top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top.contains("byte_capture"), "byte_capture instantiation missing from top");
    assert!(top.contains("byte_cap_14"), "byte_cap_14 wiring missing from top");

    // Rule matcher should use byte_cap inputs
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("byte_cap_14"), "byte_cap_14 missing from rule matcher");
}

#[test]
fn validate_l3l4_firewall() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/l3l4_firewall.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "valid");
    assert_eq!(json["rules_count"], 8);
}
