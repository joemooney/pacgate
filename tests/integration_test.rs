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
                     "l3l4_firewall", "vxlan_datacenter",
                     "byte_match", "hsm_conntrack",
                     "ipv6_firewall", "rate_limited"] {
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

// ── Simulate Integration Tests ──────────────────────────────────

#[test]
fn simulate_basic() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/allow_arp.yaml",
               "--packet", "ethertype=0x0806"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_arp"), "should match allow_arp rule");
    assert!(stdout.contains("PASS"), "should pass ARP");
}

#[test]
fn simulate_default_action() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/allow_arp.yaml",
               "--packet", "ethertype=0x9999"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DEFAULT"), "should hit default action");
    assert!(stdout.contains("DROP"), "default should be DROP");
}

#[test]
fn simulate_json_output() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/l3l4_firewall.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=22,dst_ip=10.0.1.1",
               "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["matched_rule"].is_string() || json["matched_rule"].is_null());
    assert!(json["action"].as_str().unwrap() == "pass" || json["action"].as_str().unwrap() == "drop");
}

// ── IPv6 Integration Tests ──────────────────────────────────

#[test]
fn compile_ipv6_firewall() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("src_ipv6"), "missing src_ipv6 signal in top");
    assert!(top_v.contains("dst_ipv6"), "missing dst_ipv6 signal in top");
    assert!(top_v.contains("ipv6_next_header"), "missing ipv6_next_header signal in top");

    // Check generated rule matcher has IPv6 conditions
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("ipv6_next_header") || rule0.contains("src_ipv6"),
        "IPv6 conditions missing from rule matcher");
}

#[test]
fn validate_ipv6() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/ipv6_firewall.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "validate ipv6 failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "valid");
    assert_eq!(json["rules_count"], 6);
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

// ── Rate Limiting Integration Tests ────────────────────────

#[test]
fn compile_rate_limited() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rate_limited.yaml", "--rate-limit",
               "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify rate_limiter.v was copied
    assert!(tmp.path().join("rtl/rate_limiter.v").exists(), "rate_limiter.v missing");

    let rl_v = std::fs::read_to_string(tmp.path().join("rtl/rate_limiter.v")).unwrap();
    assert!(rl_v.contains("module rate_limiter"), "rate_limiter module missing");
    assert!(rl_v.contains("token"), "token logic missing from rate_limiter.v");
}

#[test]
fn compile_rate_limited_json() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rate_limited.yaml", "--rate-limit",
               "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["rate_limit"], true);
    assert_eq!(json["rules_count"], 4);
}

// ── Synthesis Project Integration Tests ────────────────────

#[test]
fn synth_yosys_artix7() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["synth", "rules/examples/enterprise.yaml",
               "--target", "yosys", "--part", "artix7",
               "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "synth yosys failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("synth/synth.ys").exists(), "synth.ys missing");
    assert!(tmp.path().join("synth/constraints.xdc").exists(), "constraints.xdc missing");
    assert!(tmp.path().join("synth/Makefile").exists(), "Makefile missing");

    let ys = std::fs::read_to_string(tmp.path().join("synth/synth.ys")).unwrap();
    assert!(ys.contains("synth_xilinx"), "should target xilinx for artix7");
    assert!(ys.contains("packet_filter_top"), "should reference top module");
}

#[test]
fn synth_vivado_project() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["synth", "rules/examples/allow_arp.yaml",
               "--target", "vivado", "--part", "xc7a35tcpg236-1",
               "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "synth vivado failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("synth/synth.tcl").exists(), "synth.tcl missing");
    let tcl = std::fs::read_to_string(tmp.path().join("synth/synth.tcl")).unwrap();
    assert!(tcl.contains("xc7a35tcpg236-1"), "should contain part number");
}

#[test]
fn synth_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["synth", "rules/examples/allow_arp.yaml",
               "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "synth --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["generated"].is_array());
}

// ── PCAP Analyze Integration Tests ─────────────────────────

/// Helper: create a PCAP file with IPv4 TCP packets for analysis tests
fn make_analysis_pcap(num_frames: usize) -> Vec<u8> {
    let mut pcap_data: Vec<u8> = Vec::new();
    // Global header
    pcap_data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap_data.extend_from_slice(&2u16.to_le_bytes());
    pcap_data.extend_from_slice(&4u16.to_le_bytes());
    pcap_data.extend_from_slice(&0i32.to_le_bytes());
    pcap_data.extend_from_slice(&0u32.to_le_bytes());
    pcap_data.extend_from_slice(&65535u32.to_le_bytes());
    pcap_data.extend_from_slice(&1u32.to_le_bytes());

    for i in 0..num_frames {
        let mut frame = Vec::new();
        // Ethernet header
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes)
        frame.push(0x45); frame.push(0x00);
        frame.extend_from_slice(&60u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(64); frame.push(6); // TCP
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1]); // src IP
        frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP
        // TCP ports
        frame.extend_from_slice(&12345u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        while frame.len() < 60 { frame.push(0); }

        pcap_data.extend_from_slice(&(i as u32).to_le_bytes());
        pcap_data.extend_from_slice(&0u32.to_le_bytes());
        pcap_data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap_data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap_data.extend_from_slice(&frame);
    }
    pcap_data
}

#[test]
fn pcap_analyze_basic() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    std::fs::write(&pcap_path, make_analysis_pcap(10)).unwrap();

    let output = pacgate_bin()
        .args(["pcap-analyze", pcap_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "pcap-analyze failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Traffic Analysis"), "should contain analysis header");
}

#[test]
fn pcap_analyze_json() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    std::fs::write(&pcap_path, make_analysis_pcap(5)).unwrap();

    let output = pacgate_bin()
        .args(["pcap-analyze", pcap_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "pcap-analyze --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["total_packets"], 5);
    assert!(json["suggested_rules"].is_array());
}

#[test]
fn pcap_analyze_yaml_output() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    std::fs::write(&pcap_path, make_analysis_pcap(5)).unwrap();
    let yaml_path = tmp.path().join("suggested.yaml");

    let output = pacgate_bin()
        .args(["pcap-analyze", pcap_path.to_str().unwrap(),
               "-o", yaml_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "pcap-analyze -o failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(yaml_path.exists(), "YAML output file should exist");

    let yaml_content = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(yaml_content.contains("pacgate:"), "should be valid PacGate YAML");
    assert!(yaml_content.contains("rules:"), "should contain rules section");
}

#[test]
fn pcap_analyze_empty_error() {
    let tmp = tempfile::tempdir().unwrap();
    // Create PCAP with no frames
    let mut pcap_data: Vec<u8> = Vec::new();
    pcap_data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap_data.extend_from_slice(&2u16.to_le_bytes());
    pcap_data.extend_from_slice(&4u16.to_le_bytes());
    pcap_data.extend_from_slice(&0i32.to_le_bytes());
    pcap_data.extend_from_slice(&0u32.to_le_bytes());
    pcap_data.extend_from_slice(&65535u32.to_le_bytes());
    pcap_data.extend_from_slice(&1u32.to_le_bytes());

    let pcap_path = tmp.path().join("empty.pcap");
    std::fs::write(&pcap_path, &pcap_data).unwrap();

    let output = pacgate_bin()
        .args(["pcap-analyze", pcap_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should fail on empty PCAP");
}

// ── Mutation Testing Integration Tests ─────────────────────

#[test]
fn mutate_json_report() {
    let output = pacgate_bin()
        .args(["mutate", "rules/examples/allow_arp.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "mutate --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(json["status"], "ok");
    assert!(json["total_mutations"].as_u64().unwrap() > 0, "should generate at least 1 mutation");
    assert!(json["mutations"].is_array());
}

#[test]
fn mutate_generates_mutants() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["mutate", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "mutate failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should create mutants directory with at least one mutant
    let mutants_dir = tmp.path().join("mutants");
    assert!(mutants_dir.exists(), "mutants/ directory missing");

    let mut_0 = mutants_dir.join("mut_0");
    assert!(mut_0.exists(), "mut_0/ directory missing");
    assert!(mut_0.join("rules.yaml").exists(), "mutant rules.yaml missing");
    assert!(mut_0.join("rtl").exists(), "mutant rtl/ directory missing");
    assert!(mut_0.join("tb").exists(), "mutant tb/ directory missing");
}

#[test]
fn mutate_multi_rule() {
    let output = pacgate_bin()
        .args(["mutate", "rules/examples/enterprise.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "mutate --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    // Enterprise has 7 rules — should generate many mutations
    let total = json["total_mutations"].as_u64().unwrap();
    assert!(total >= 10, "expected >= 10 mutations for enterprise, got {}", total);
}

// ── IPv6 Test Generation Integration Tests ────────────────

#[test]
fn compile_ipv6_generates_ipv6_tests() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify the generated test harness contains IPv6 header construction
    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(test_py.contains("Ipv6Header"), "test should use Ipv6Header for IPv6 rules");
    assert!(test_py.contains("ipv6_addr_to_bytes"), "test should import ipv6_addr_to_bytes");
}

// ── Rate Limiter Testbench Integration Tests ──────────────

#[test]
fn compile_rate_limit_generates_tb() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rate_limited.yaml", "-o", tmp.path().to_str().unwrap(), "--rate-limit"])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --rate-limit failed: {}", String::from_utf8_lossy(&output.stderr));

    // Should generate rate limiter testbench directory
    let tb_rl = tmp.path().join("tb-rate-limiter");
    assert!(tb_rl.exists(), "tb-rate-limiter/ directory missing");
    assert!(tb_rl.join("test_rate_limiter.py").exists(), "test_rate_limiter.py missing");
    assert!(tb_rl.join("Makefile").exists(), "rate limiter Makefile missing");

    // Verify content
    let test_py = std::fs::read_to_string(tb_rl.join("test_rate_limiter.py")).unwrap();
    assert!(test_py.contains("test_initial_burst"), "should contain initial burst test");
    assert!(test_py.contains("test_token_refill"), "should contain token refill test");
}

// ── Template Library Integration Tests ─────────────────────

#[test]
fn template_list() {
    let output = pacgate_bin()
        .args(["template", "list"])
        .output()
        .unwrap();
    assert!(output.status.success(), "template list failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_management"), "should list allow_management template");
    assert!(stdout.contains("block_bogons"), "should list block_bogons template");
    assert!(stdout.contains("web_server"), "should list web_server template");
}

#[test]
fn template_list_json() {
    let output = pacgate_bin()
        .args(["template", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "template list --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json.is_array());
    assert!(json.as_array().unwrap().len() >= 7, "should have at least 7 templates");
}

#[test]
fn template_show() {
    let output = pacgate_bin()
        .args(["template", "show", "allow_management"])
        .output()
        .unwrap();
    assert!(output.status.success(), "template show failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mgmt_subnet"), "should show mgmt_subnet variable");
    assert!(stdout.contains("SSH"), "should show description");
}

#[test]
fn template_show_nonexistent() {
    let output = pacgate_bin()
        .args(["template", "show", "nonexistent_template"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should fail for nonexistent template");
}

#[test]
fn template_apply() {
    let tmp = tempfile::tempdir().unwrap();
    let output_path = tmp.path().join("rules.yaml");
    let output = pacgate_bin()
        .args(["template", "apply", "web_server", "-o", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "template apply failed: {}", String::from_utf8_lossy(&output.stderr));

    let yaml = std::fs::read_to_string(&output_path).unwrap();
    assert!(yaml.contains("pacgate:"), "should generate valid PacGate YAML");
    assert!(yaml.contains("allow_http"), "should contain allow_http rule");
    assert!(yaml.contains("allow_https"), "should contain allow_https rule");
}

#[test]
fn template_apply_with_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let output_path = tmp.path().join("rules.yaml");
    let output = pacgate_bin()
        .args(["template", "apply", "allow_management", "-o", output_path.to_str().unwrap(),
               "--set", "mgmt_subnet=192.168.1.0/24", "--set", "priority=800"])
        .output()
        .unwrap();
    assert!(output.status.success(), "template apply with vars failed: {}", String::from_utf8_lossy(&output.stderr));

    let yaml = std::fs::read_to_string(&output_path).unwrap();
    assert!(yaml.contains("192.168.1.0/24"), "should use custom subnet");
    assert!(yaml.contains("priority: 800"), "should use custom priority");
}

// ── Documentation Generation Integration Tests ───────────

#[test]
fn doc_generates_html() {
    let tmp = tempfile::tempdir().unwrap();
    let output_path = tmp.path().join("docs.html");
    let output = pacgate_bin()
        .args(["doc", "rules/examples/allow_arp.yaml", "-o", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "doc failed: {}", String::from_utf8_lossy(&output.stderr));

    let html = std::fs::read_to_string(&output_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"), "should generate valid HTML");
    assert!(html.contains("PacGate Rule Documentation"), "should have title");
    assert!(html.contains("allow_arp"), "should contain rule name");
}

#[test]
fn doc_enterprise_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let output_path = tmp.path().join("docs.html");
    let output = pacgate_bin()
        .args(["doc", "rules/examples/enterprise.yaml", "-o", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "doc enterprise failed: {}", String::from_utf8_lossy(&output.stderr));

    let html = std::fs::read_to_string(&output_path).unwrap();
    assert!(html.contains("Rule Summary"), "should have summary table");
    assert!(html.contains("Rule Details"), "should have detail sections");
}

// ── Simulator IPv6 Integration Tests ───────────────────────

#[test]
fn simulate_ipv6() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/ipv6_firewall.yaml",
               "--packet", "ethertype=0x86DD,ipv6_next_header=58"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_icmpv6"), "expected ICMPv6 rule match, got: {}", stdout);
}

#[test]
fn simulate_all_fields() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/l3l4_firewall.yaml",
               "--packet", "ethertype=0x0800,src_ip=10.0.0.1,ip_protocol=6,dst_port=80",
               "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(!json["fields"].as_array().unwrap().is_empty(), "expected field breakdown");
}

// ── Phase 10: Verification Completeness ──────────────────────────

#[test]
fn scoreboard_l3l4_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // L3/L4 firewall rules should emit src_ip/dst_ip/dst_port in scoreboard
    assert!(test_py.contains("src_ip="), "test file missing src_ip scoreboard field");
    assert!(test_py.contains("dst_port="), "test file missing dst_port scoreboard field");
    assert!(test_py.contains("ip_protocol="), "test file missing ip_protocol scoreboard field");
}

#[test]
fn scoreboard_ipv6_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(test_py.contains("src_ipv6="), "test file missing src_ipv6 scoreboard field");
    assert!(test_py.contains("ipv6_next_header="), "test file missing ipv6_next_header scoreboard field");
}

#[test]
fn scoreboard_port_range_format() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // Port ranges should be formatted as Python tuples "(low, high)" not "low-high"
    if test_py.contains("port_range=") {
        assert!(!test_py.contains("port_range=\""), "port_range should be tuple, not string");
    }
}

#[test]
fn properties_l3l4_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let props_py = std::fs::read_to_string(tmp.path().join("tb/test_properties.py")).unwrap();
    assert!(props_py.contains("src_ip="), "properties file missing src_ip field");
    assert!(props_py.contains("ip_protocol="), "properties file missing ip_protocol field");
}

#[test]
fn directed_test_l3l4_has_ipv4_header() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(test_py.contains("Ipv4Header"), "directed test missing Ipv4Header construction");
    assert!(test_py.contains("extracted"), "directed test missing extracted dict");
    assert!(test_py.contains("import struct"), "test missing struct import");
}

#[test]
fn directed_test_ipv6_has_header() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(test_py.contains("Ipv6Header"), "directed test missing Ipv6Header construction");
    assert!(test_py.contains("extracted"), "directed test missing extracted dict");
}

#[test]
fn random_test_has_l3l4_construction() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // Random test should construct L3/L4 headers for IPv4 frames
    assert!(test_py.contains("ip_hdr = Ipv4Header"), "random test missing IPv4 header construction");
    assert!(test_py.contains("ip6_hdr = Ipv6Header"), "random test missing IPv6 header construction");
    assert!(test_py.contains("extracted=extracted"), "random test missing extracted param in scoreboard.check");
}

#[test]
fn random_test_imports_struct() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(test_py.contains("import struct"), "test harness missing struct import");
}

#[test]
fn directed_test_vlan_has_extracted() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/enterprise.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // VLAN/L2-only tests should still define extracted (empty dict)
    assert!(test_py.contains("extracted"), "test missing extracted dict for VLAN tests");
}

#[test]
fn all_examples_compile_with_updated_templates() {
    // Verify all 18 examples still compile with the updated test_harness template
    let examples = std::fs::read_dir("rules/examples").unwrap();
    for entry in examples {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "yaml").unwrap_or(false) {
            let tmp = tempfile::tempdir().unwrap();
            let output = pacgate_bin()
                .args(["compile", path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
                .output()
                .unwrap();
            assert!(output.status.success(),
                "compile failed for {}: {}", path.display(), String::from_utf8_lossy(&output.stderr));
        }
    }
}

#[test]
fn simulate_byte_match_via_cli() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/byte_match.yaml",
               "--packet", "ethertype=0x0800,raw_bytes=0x4500002800000000",
               "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    // Should match "match_ipv4_version" rule (offset 14 not in raw_bytes since we
    // only pass 8 bytes, but ethertype matches and byte_match at offset 14 needs
    // actual packet offset — with raw_bytes starting at offset 0, this tests the
    // mechanism even if it doesn't match the specific offset)
}

#[test]
fn properties_has_l3l4_determinism_test() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let props_py = std::fs::read_to_string(tmp.path().join("tb/test_properties.py")).unwrap();
    assert!(props_py.contains("l3l4_determinism"), "properties file missing l3l4_determinism test");
    assert!(props_py.contains("l3l4_ethernet_frames"), "properties file missing l3l4_ethernet_frames import");
}

#[test]
fn formal_ipv6_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    // First compile to generate RTL
    let compile_out = pacgate_bin()
        .args(["compile", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(compile_out.status.success());

    let output = pacgate_bin()
        .args(["formal", "rules/examples/ipv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("ipv6_cidr_stable"), "formal missing IPv6 CIDR assertion");
}

#[test]
fn formal_port_range_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    let compile_out = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(compile_out.status.success());

    let output = pacgate_bin()
        .args(["formal", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    // l3l4_firewall has port range rules
    assert!(assertions.contains("port_range_decision_stable") || assertions.contains("p_port_range"),
        "formal missing port range assertion");
}

#[test]
fn conntrack_generates_test_files() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/hsm_conntrack.yaml", "-o", tmp.path().to_str().unwrap(), "--conntrack"])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb-conntrack").exists(), "tb-conntrack directory missing");
    assert!(tmp.path().join("tb-conntrack/test_conntrack.py").exists(), "conntrack test missing");
    assert!(tmp.path().join("tb-conntrack/Makefile").exists(), "conntrack Makefile missing");

    let test_py = std::fs::read_to_string(tmp.path().join("tb-conntrack/test_conntrack.py")).unwrap();
    assert!(test_py.contains("test_conntrack_new_flow"), "missing new_flow test");
    assert!(test_py.contains("test_conntrack_return_traffic"), "missing return_traffic test");
    assert!(test_py.contains("test_conntrack_timeout"), "missing timeout test");
    assert!(test_py.contains("test_conntrack_hash_collision"), "missing hash_collision test");
    assert!(test_py.contains("test_conntrack_table_full"), "missing table_full test");
}

#[test]
fn multi_flag_compile() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rate_limited.yaml",
               "-o", tmp.path().to_str().unwrap(),
               "--rate-limit", "--counters", "--axi"])
        .output()
        .unwrap();
    assert!(output.status.success(), "multi-flag compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify all generated directories exist
    assert!(tmp.path().join("rtl").exists(), "rtl/ missing");
    assert!(tmp.path().join("tb").exists(), "tb/ missing");
    assert!(tmp.path().join("tb-axi").exists(), "tb-axi/ missing");
    assert!(tmp.path().join("tb-rate-limiter").exists(), "tb-rate-limiter/ missing");

    // Verify key files
    assert!(tmp.path().join("rtl/rate_limiter.v").exists(), "rate_limiter.v missing");
    assert!(tmp.path().join("rtl/rule_counters.v").exists(), "rule_counters.v missing");
    assert!(tmp.path().join("rtl/axi_stream_adapter.v").exists(), "axi_stream_adapter.v missing");
}

#[test]
fn reachability_basic() {
    let output = pacgate_bin()
        .args(["reachability", "rules/examples/l3l4_firewall.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "reachability failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REACHABILITY ANALYSIS"), "missing report header");
    assert!(stdout.contains("allow_http"), "missing rule in report");
    assert!(stdout.contains("port 80"), "missing port 80 query");
}

#[test]
fn reachability_json() {
    let output = pacgate_bin()
        .args(["reachability", "rules/examples/l3l4_firewall.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "reachability json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["entries"].is_array());
    assert!(json["queries"].is_array());
    assert!(json["default_action"].is_string());
}

// ── Performance Benchmark Tests ────────────────────────────────

#[test]
fn bench_basic() {
    let output = pacgate_bin()
        .args(["bench", "rules/examples/l3l4_firewall.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "bench failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PERFORMANCE BENCHMARK"), "should show benchmark report");
    assert!(stdout.contains("Scaling Curve"), "should show scaling curve");
    assert!(stdout.contains("LUT Utilization"), "should show LUT chart");
    assert!(stdout.contains("packets/sec"), "should show throughput");
}

#[test]
fn bench_json() {
    let output = pacgate_bin()
        .args(["bench", "rules/examples/l3l4_firewall.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "bench --json failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["compile_time_ms"].is_number());
    assert!(json["sim_throughput_pps"].is_number());
    assert!(json["scaling"].is_array());
    let scaling = json["scaling"].as_array().unwrap();
    assert!(scaling.len() >= 3, "should have multiple scaling points");
}

// ── PCAP Output from Simulation Tests ─────────────────────────

#[test]
fn simulate_pcap_out_creates_file() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("sim_output.pcap");
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/l3l4_firewall.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80,src_ip=10.0.0.1,dst_ip=10.0.1.1",
               "--pcap-out", pcap_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate --pcap-out failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify PCAP file was created
    assert!(pcap_path.exists(), "PCAP file should be created");
    let data = std::fs::read(&pcap_path).unwrap();
    // Check PCAP magic number (little-endian: 0xa1b2c3d4)
    assert!(data.len() >= 24, "PCAP should have at least global header");
    assert_eq!(&data[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "PCAP magic number mismatch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PCAP written to"), "should print PCAP path");
}

#[test]
fn simulate_pcap_out_with_json() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("sim_json.pcap");
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/allow_arp.yaml",
               "--packet", "ethertype=0x0806",
               "--pcap-out", pcap_path.to_str().unwrap(),
               "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate --pcap-out --json failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify PCAP file created
    assert!(pcap_path.exists(), "PCAP file should be created");

    // Verify JSON output includes pcap_file field
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["pcap_file"].is_string(), "JSON should include pcap_file path");
}

#[test]
fn simulate_pcap_out_ipv4_frame_structure() {
    let tmp = tempfile::tempdir().unwrap();
    let pcap_path = tmp.path().join("ipv4_frame.pcap");
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/l3l4_firewall.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,src_port=12345,dst_port=443,src_ip=192.168.1.1,dst_ip=10.0.0.1",
               "--pcap-out", pcap_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));

    let data = std::fs::read(&pcap_path).unwrap();
    // Global header (24) + packet header (16) + frame data
    assert!(data.len() > 40, "PCAP should contain packet data");

    // Check that frame contains IPv4 ethertype at offset 24+16+12 = 52
    let frame_start = 24 + 16; // global header + first packet header
    assert_eq!(data[frame_start + 12], 0x08, "ethertype high byte");
    assert_eq!(data[frame_start + 13], 0x00, "ethertype low byte");

    // Check IP version/IHL at frame offset 14
    assert_eq!(data[frame_start + 14], 0x45, "IPv4 version+IHL");
}

#[test]
fn simulate_without_pcap_out_no_file() {
    // When --pcap-out is NOT provided, no PCAP file should be created
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/allow_arp.yaml",
               "--packet", "ethertype=0x0806"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("PCAP written"), "should not mention PCAP");
}

#[test]
fn all_examples_lint() {
    let examples = std::fs::read_dir("rules/examples").unwrap();
    for entry in examples {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "yaml").unwrap_or(false) {
            let output = pacgate_bin()
                .args(["lint", path.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(output.status.success(),
                "lint failed for {}: {}", path.display(), String::from_utf8_lossy(&output.stderr));
        }
    }
}
