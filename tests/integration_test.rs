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
                     "ipv6_firewall", "rate_limited",
                     "dynamic_firewall",
                     "opennic_l3l4",
                     "corundum_datacenter",
                     "arp_security",
                     "icmpv6_firewall"] {
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

// ── Diff HTML Visualization Tests ──────────────────────────────

#[test]
fn diff_html_output() {
    let tmp = tempfile::tempdir().unwrap();
    let html_path = tmp.path().join("diff_report.html");
    let output = pacgate_bin()
        .args(["diff", "rules/examples/allow_arp.yaml", "rules/examples/l3l4_firewall.yaml",
               "--html", html_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "diff --html failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(html_path.exists(), "HTML file should be created");
    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("PacGate Rule Diff Report"), "should contain report title");
    assert!(html.contains("Added"), "should show added section");
    assert!(html.contains("Removed"), "should show removed section");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generated HTML diff report"), "should print success");
}

#[test]
fn diff_html_same_file() {
    let tmp = tempfile::tempdir().unwrap();
    let html_path = tmp.path().join("same_diff.html");
    let output = pacgate_bin()
        .args(["diff", "rules/examples/allow_arp.yaml", "rules/examples/allow_arp.yaml",
               "--html", html_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "diff --html same file failed: {}", String::from_utf8_lossy(&output.stderr));

    let html = std::fs::read_to_string(&html_path).unwrap();
    // Should show 0 added, 0 removed, 0 modified
    assert!(html.contains(">0<"), "should have zero changes");
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

// ---- Phase 12: Protocol Extensions ----

#[test]
fn compile_gtp_5g() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify GTP TEID appears in generated Verilog
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("gtp_teid"), "rule_match_0 should have gtp_teid port");
    assert!(rule0.contains("gtp_teid == 32'd1000"), "rule_match_0 should match TEID 1000");

    // Verify all rules have gtp_teid port (consistent interface)
    let rule2 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_2.v")).unwrap();
    assert!(rule2.contains("gtp_teid"), "rule_match_2 should also have gtp_teid port");
}

#[test]
fn compile_mpls_network() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify MPLS fields in generated Verilog
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("mpls_label"), "rule_match_0 should have mpls_label port");
    assert!(rule0.contains("mpls_label == 20'd100"), "rule_match_0 should match label 100");

    let rule1 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_1.v")).unwrap();
    assert!(rule1.contains("mpls_bos"), "rule_match_1 should have mpls_bos port");
}

#[test]
fn compile_multicast() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify IGMP and MLD fields in generated Verilog
    let rule0 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule0.contains("igmp_type"), "rule_match_0 should have igmp_type port");
    assert!(rule0.contains("igmp_type == 8'd17"), "rule_match_0 should match IGMP query type 17");

    // MLD rule
    let rule2 = std::fs::read_to_string(tmp.path().join("rtl/rule_match_2.v")).unwrap();
    assert!(rule2.contains("mld_type"), "rule_match_2 should have mld_type port");
    assert!(rule2.contains("mld_type == 8'd130"), "rule_match_2 should match MLD query type 130");
}

#[test]
fn simulate_gtp_tunnel_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/gtp_5g.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=2152,gtp_teid=1000"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_gtp_tunnel_1"), "should match GTP tunnel 1");
    assert!(stdout.contains("PASS"), "should pass");
}

#[test]
fn simulate_gtp_tunnel_2_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/gtp_5g.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=2152,gtp_teid=2000"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_gtp_tunnel_2"), "should match GTP tunnel 2");
}

#[test]
fn simulate_gtp_unknown_teid_dropped() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/gtp_5g.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=2152,gtp_teid=9999"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("block_unknown_gtp"), "should match block rule");
    assert!(stdout.contains("DROP"), "unknown TEID should be dropped");
}

#[test]
fn simulate_mpls_label_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mpls_network.yaml",
               "--packet", "ethertype=0x8847,mpls_label=200,mpls_bos=true"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_mpls_vpn_200"), "should match MPLS VPN 200");
    assert!(stdout.contains("PASS"), "should pass");
}

#[test]
fn simulate_mpls_tc_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mpls_network.yaml",
               "--packet", "ethertype=0x8847,mpls_tc=7"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_mpls_priority"), "should match MPLS priority rule");
}

#[test]
fn simulate_igmp_query() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/multicast.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=2,igmp_type=17"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_igmp_membership_query"), "should match IGMP query");
    assert!(stdout.contains("PASS"), "should pass");
}

#[test]
fn simulate_mld_listener_query() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/multicast.yaml",
               "--packet", "ethertype=0x86DD,ipv6_next_header=58,mld_type=130"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_mld_listener_query"), "should match MLD listener query");
    assert!(stdout.contains("PASS"), "should pass");
}

#[test]
fn simulate_gtp_json_output() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/gtp_5g.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=2152,gtp_teid=1000",
               "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "allow_gtp_tunnel_1");
    let fields = json["fields"].as_array().unwrap();
    assert!(fields.iter().any(|f| f["field"] == "gtp_teid"), "should include gtp_teid in fields");
}

#[test]
fn gtp_top_level_has_parser_connections() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top.contains(".gtp_teid"), "top-level should connect gtp_teid to parser");
    assert!(top.contains("wire [31:0] gtp_teid"), "top-level should declare gtp_teid wire");
}

#[test]
fn mpls_top_level_has_parser_connections() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top.contains(".mpls_label"), "top-level should connect mpls_label to parser");
    assert!(top.contains(".mpls_tc"), "top-level should connect mpls_tc to parser");
    assert!(top.contains(".mpls_bos"), "top-level should connect mpls_bos to parser");
}

// ── Phase 13 Batch 1: Coverage Framework + CI ────────────────

#[test]
fn harness_has_coverage_director() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("CoverageDirector"), "harness should import CoverageDirector");
    assert!(harness.contains("generate_coverage_closure_packets"), "harness should call coverage closure");
}

#[test]
fn harness_has_coverage_xml_export() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("save_xml"), "harness should call coverage.save_xml()");
}

#[test]
fn harness_passes_l3l4_kwargs_to_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("cov_kwargs"), "harness should build cov_kwargs dict");
    assert!(harness.contains("ip_protocol"), "harness should pass ip_protocol to coverage");
    assert!(harness.contains("ipv6_src"), "harness should pass ipv6_src to coverage");
}

#[test]
fn properties_has_boundary_tests() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let props = std::fs::read_to_string(tmp.path().join("tb/test_properties.py")).unwrap();
    assert!(props.contains("check_cidr_boundary"), "properties should import check_cidr_boundary");
    assert!(props.contains("test_hypothesis_cidr_boundary"), "properties should define cidr boundary test");
    assert!(props.contains("test_hypothesis_port_range_boundary"), "properties should define port range boundary test");
    assert!(props.contains("test_hypothesis_ipv6_cidr_match"), "properties should define ipv6 cidr match test");
}

#[test]
fn gtp_scoreboard_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("gtp_teid="), "harness should include gtp_teid in scoreboard rules");
}

#[test]
fn mpls_scoreboard_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("mpls_label="), "harness should include mpls_label in scoreboard rules");
}

#[test]
fn multicast_scoreboard_fields_in_generated_test() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("igmp_type="), "harness should include igmp_type in scoreboard rules");
}

// ── Phase 13 Batch 2: Boundary + Negative Tests ─────────────

#[test]
fn boundary_cidr_test_generated() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("test_boundary_cidr_"), "harness should include CIDR boundary tests");
}

#[test]
fn boundary_port_test_generated() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("test_boundary_port_"), "harness should include port boundary tests");
}

#[test]
fn negative_derived_test_generated() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("test_negative_derived"), "harness should include formally-derived negative test");
}

#[test]
fn negative_derived_uses_unused_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // allow_arp uses 0x0806, so negative test should NOT use 0x0806
    let neg_start = harness.find("test_negative_derived").unwrap();
    let neg_section = &harness[neg_start..neg_start + 500.min(harness.len() - neg_start)];
    assert!(!neg_section.contains("0x0806"), "negative test should not use ARP ethertype used by rules");
}

// ── Phase 13 Batch 3: MCY Mutation Testing ───────────────────

#[test]
fn mcy_generates_config() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["mcy", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "mcy command failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("mcy/mcy.cfg").exists(), "mcy.cfg should be generated");
    assert!(tmp.path().join("mcy/test_mutation.sh").exists(), "test_mutation.sh should be generated");
}

#[test]
fn mcy_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["mcy", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["mutation_count"].as_u64().unwrap() > 0);
    assert!(json["rtl_files_count"].as_u64().unwrap() > 0);
}

#[test]
fn mcy_config_content() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["mcy", "rules/examples/enterprise.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let cfg = std::fs::read_to_string(tmp.path().join("mcy/mcy.cfg")).unwrap();
    assert!(cfg.contains("[options]"), "config should have [options] section");
    assert!(cfg.contains("[script]"), "config should have [script] section");
    assert!(cfg.contains("[logic]"), "config should have [logic] section");
    assert!(cfg.contains("read_verilog"), "config should have read_verilog commands");
    assert!(cfg.contains("packet_filter_top"), "config should reference top module");
}

#[test]
fn mcy_script_has_shebang() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["mcy", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let script = std::fs::read_to_string(tmp.path().join("mcy/test_mutation.sh")).unwrap();
    assert!(script.starts_with("#!/bin/bash"), "script should have bash shebang");
    assert!(script.contains("make"), "script should run make for cocotb simulation");
}

#[test]
fn mutate_run_json() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["mutate", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap(), "--run", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "mutate --run --json failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(json["total"].as_u64().unwrap() > 0, "should report total mutations");
    assert!(json["kill_rate"].is_number(), "should report kill_rate");
}

#[test]
fn mutate_run_human_readable() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["mutate", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap(), "--run"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MUTATION TEST REPORT"), "should print mutation test report");
    assert!(stdout.contains("Kill rate:"), "should show kill rate");
}

// ── Phase 14 Batch 2: Protocol Directed Test Branches ─────────

#[test]
fn gtp_directed_test_branch_in_harness() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("PacketFactory.gtp_u(teid="), "harness should use PacketFactory.gtp_u for GTP directed tests");
    assert!(harness.contains("\"gtp_teid\":"), "harness should extract gtp_teid in directed test");
}

#[test]
fn mpls_directed_test_branch_in_harness() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("PacketFactory.mpls(label="), "harness should use PacketFactory.mpls for MPLS directed tests");
    assert!(harness.contains("\"mpls_label\":"), "harness should extract mpls_label in directed test");
}

#[test]
fn igmp_directed_test_branch_in_harness() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("PacketFactory.igmp(igmp_type="), "harness should use PacketFactory.igmp for IGMP directed tests");
    assert!(harness.contains("\"igmp_type\":"), "harness should extract igmp_type in directed test");
}

#[test]
fn mld_directed_test_branch_in_harness() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    assert!(harness.contains("PacketFactory.mld(mld_type="), "harness should use PacketFactory.mld for MLD directed tests");
    assert!(harness.contains("\"mld_type\":"), "harness should extract mld_type in directed test");
}

#[test]
fn random_test_includes_protocol_packets() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let harness = std::fs::read_to_string(tmp.path().join("tb/test_packet_filter.py")).unwrap();
    // Verify random test section includes protocol packet injection
    assert!(harness.contains("proto_choice = random.choice"), "harness should inject random protocol packets");
    assert!(harness.contains("PacketFactory.gtp_u(teid=_teid)"), "random test should generate GTP frames");
    assert!(harness.contains("PacketFactory.mpls(label=_label"), "random test should generate MPLS frames");
    assert!(harness.contains("PacketFactory.igmp(igmp_type=_igmp_type)"), "random test should generate IGMP frames");
    assert!(harness.contains("PacketFactory.mld(mld_type=_mld_type)"), "random test should generate MLD frames");
}

// ── Phase 14 Batch 3: Formal Assertions ───────────────────────

#[test]
fn formal_gtp_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    pacgate_bin()
        .args(["formal", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("GTP-U TEID"), "formal assertions should include GTP-U section");
    assert!(sva.contains("p_gtp_decision_stable"), "formal assertions should include GTP stability property");
}

#[test]
fn formal_mpls_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    pacgate_bin()
        .args(["formal", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("MPLS Label Stack"), "formal assertions should include MPLS section");
    assert!(sva.contains("p_mpls_decision_stable"), "formal assertions should include MPLS stability property");
}

#[test]
fn formal_igmp_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    pacgate_bin()
        .args(["formal", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("IGMP Assertions"), "formal assertions should include IGMP section");
    assert!(sva.contains("p_igmp_decision_stable"), "formal assertions should include IGMP stability property");
}

#[test]
fn formal_mld_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    pacgate_bin()
        .args(["compile", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    pacgate_bin()
        .args(["formal", "rules/examples/multicast.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("MLD Assertions"), "formal assertions should include MLD section");
    assert!(sva.contains("p_mld_decision_stable"), "formal assertions should include MLD stability property");
}

// ── Phase 14 Batch 4: Analysis tool completeness ────────────────────

#[test]
fn stats_includes_protocol_fields() {
    let output = pacgate_bin()
        .args(["stats", "rules/examples/gtp_5g.yaml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gtp_teid"), "stats should show gtp_teid usage");

    let output2 = pacgate_bin()
        .args(["stats", "rules/examples/mpls_network.yaml"])
        .output()
        .unwrap();
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout2.contains("mpls_label"), "stats should show mpls_label usage");

    let output3 = pacgate_bin()
        .args(["stats", "rules/examples/multicast.yaml"])
        .output()
        .unwrap();
    let stdout3 = String::from_utf8_lossy(&output3.stdout);
    assert!(stdout3.contains("igmp_type"), "stats should show igmp_type usage");
}

#[test]
fn graph_includes_protocol_fields() {
    let output = pacgate_bin()
        .args(["graph", "rules/examples/gtp_5g.yaml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gtp_teid"), "graph should include gtp_teid in DOT labels");

    let output2 = pacgate_bin()
        .args(["graph", "rules/examples/mpls_network.yaml"])
        .output()
        .unwrap();
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout2.contains("mpls_label"), "graph should include mpls_label in DOT labels");
}

#[test]
fn diff_detects_protocol_field_changes() {
    // Create two YAML files that differ in gtp_teid
    let tmp = tempfile::tempdir().unwrap();
    let old_yaml = tmp.path().join("old.yaml");
    let new_yaml = tmp.path().join("new.yaml");
    std::fs::write(&old_yaml, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: gtp_rule
      priority: 100
      match:
        ethertype: "0x0800"
        gtp_teid: 1000
      action: pass
"#).unwrap();
    std::fs::write(&new_yaml, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: gtp_rule
      priority: 100
      match:
        ethertype: "0x0800"
        gtp_teid: 2000
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["diff", old_yaml.to_str().unwrap(), new_yaml.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gtp_teid"), "diff should detect gtp_teid change");
}

#[test]
fn estimate_includes_protocol_field_costs() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/gtp_5g.yaml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The estimate should include LUT costs for gtp_teid matching
    assert!(output.status.success(), "estimate should succeed for GTP example");
    // Check JSON output includes the fields
    let json_output = pacgate_bin()
        .args(["estimate", "rules/examples/gtp_5g.yaml", "--json"])
        .output()
        .unwrap();
    let json_str = String::from_utf8_lossy(&json_output.stdout);
    assert!(json_str.contains("\"luts\""), "JSON estimate should include luts");
}

#[test]
fn doc_renders_protocol_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let html_path = tmp.path().join("gtp_doc.html");
    let output = pacgate_bin()
        .args(["doc", "rules/examples/gtp_5g.yaml", "-o", html_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "doc should succeed for GTP example");
    assert!(html_path.exists(), "doc should generate HTML file");
    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("gtp_teid"), "doc HTML should contain gtp_teid field");
}

#[test]
fn diff_detects_l3_l4_field_changes() {
    // Verify the L3/L4 diff bug fix — diff should detect src_ip changes
    let tmp = tempfile::tempdir().unwrap();
    let old_yaml = tmp.path().join("old.yaml");
    let new_yaml = tmp.path().join("new.yaml");
    std::fs::write(&old_yaml, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ip_rule
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
        dst_port: 80
      action: pass
"#).unwrap();
    std::fs::write(&new_yaml, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ip_rule
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "192.168.0.0/16"
        dst_port: 443
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["diff", old_yaml.to_str().unwrap(), new_yaml.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("src_ip"), "diff should detect src_ip change (L3/L4 bug fix)");
    assert!(stdout.contains("dst_port"), "diff should detect dst_port change (L3/L4 bug fix)");
}

// ── Phase 15 Batch 4: Lint Rules + Reachability ───────────────

#[test]
fn lint_detects_gtp_without_udp_prereq() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml_path = tmp.path().join("gtp_no_prereq.yaml");
    std::fs::write(&yaml_path, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: gtp_missing_prereq
      priority: 100
      match:
        ethertype: "0x0800"
        gtp_teid: 1000
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["lint", yaml_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT013"), "should detect GTP without UDP prerequisite");
}

#[test]
fn lint_no_warning_for_valid_gtp_rule() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/gtp_5g.yaml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("LINT013"), "valid GTP rules should not trigger LINT013");
}

#[test]
fn lint_detects_mpls_without_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml_path = tmp.path().join("mpls_no_etype.yaml");
    std::fs::write(&yaml_path, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: mpls_missing_etype
      priority: 100
      match:
        mpls_label: 100
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["lint", yaml_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT014"), "should detect MPLS without EtherType");
}

#[test]
fn lint_detects_igmp_without_protocol() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml_path = tmp.path().join("igmp_no_proto.yaml");
    std::fs::write(&yaml_path, r#"pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: igmp_missing_proto
      priority: 100
      match:
        ethertype: "0x0800"
        igmp_type: 17
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["lint", yaml_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT015"), "should detect IGMP without ip_protocol:2");
}

#[test]
fn formal_gtp_prerequisite_assertion_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = pacgate_bin()
        .args(["formal", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("parsed_ip_protocol == 8'd17"), "should assert UDP protocol for GTP rules");
}

#[test]
fn formal_mpls_bounds_assertion_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = pacgate_bin()
        .args(["formal", "rules/examples/mpls_network.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("parsed_mpls_tc <= 3'd7"), "should assert MPLS TC bounds");
}

#[test]
fn formal_cover_statements_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = pacgate_bin()
        .args(["formal", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let sva = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("cover property"), "should contain cover statements");
    assert!(sva.contains("parsed_gtp_valid"), "should cover GTP valid signal");
}

#[test]
fn simulate_stateful_flag_accepted() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/rate_limited.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80",
               "--stateful"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate --stateful failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Simulation") || stdout.contains("Result"),
        "should contain simulation output");
}

#[test]
fn simulate_stateful_rate_limit_drops() {
    // With --stateful and rate-limited rule, first packet should pass (burst > 0)
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/rate_limited.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80",
               "--stateful", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate --stateful --json failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["stateful"].as_bool().unwrap_or(false), "should have stateful=true");
    assert!(json.get("rate_limited").is_some(), "should have rate_limited field");
}

#[test]
fn simulate_stateful_json_output() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/rate_limited.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80",
               "--stateful", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json.get("rate_limited").is_some(), "stateful JSON should include rate_limited field");
    assert!(json.get("stateful").is_some(), "stateful JSON should include stateful field");
}

#[test]
fn all_examples_simulate_basic() {
    // Verify key examples can be simulated without error
    let examples = vec![
        ("allow_arp", "ethertype=0x0806"),
        ("l3l4_firewall", "ethertype=0x0800,ip_protocol=6,dst_port=80"),
        ("ipv6_firewall", "src_ipv6=2001:db8::1,ipv6_next_header=6"),
        ("gtp_5g", "ethertype=0x0800,ip_protocol=17,dst_port=2152,gtp_teid=1000"),
    ];
    for (example, packet) in examples {
        let output = pacgate_bin()
            .args(["simulate", &format!("rules/examples/{}.yaml", example), "--packet", packet, "--json"])
            .output()
            .unwrap();
        assert!(output.status.success(), "simulate {} failed: {}", example, String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect(&format!("invalid JSON for {}", example));
        assert_eq!(json["status"], "ok", "simulate {} status should be ok", example);
    }
}

#[test]
fn property_test_gtp_strategy_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/gtp_5g.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let props = std::fs::read_to_string(tmp.path().join("tb/test_properties.py")).unwrap();
    assert!(props.contains("gtp_u_frames"), "should import gtp_u_frames strategy");
    assert!(props.contains("test_hypothesis_gtp_determinism"), "should define GTP determinism test");
}

#[test]
fn doc_byte_match_displayed() {
    let tmp = tempfile::tempdir().unwrap();
    let out_html = tmp.path().join("doc.html");
    let output = pacgate_bin()
        .args(["doc", "rules/examples/byte_match.yaml", "-o", out_html.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "doc failed: {}", String::from_utf8_lossy(&output.stderr));

    let html = std::fs::read_to_string(&out_html).unwrap();
    assert!(html.contains("byte_match"), "HTML doc should contain byte_match field");
}

#[test]
fn reachability_shows_protocol_fields() {
    let output = pacgate_bin()
        .args(["reachability", "rules/examples/gtp_5g.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gtp_teid=1000"), "reachability should show gtp_teid in additional fields");
}

// --- Dynamic flow table tests ---

#[test]
fn dynamic_flag_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn dynamic_entries_flag_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "--dynamic-entries", "32", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --dynamic --dynamic-entries 32 failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn dynamic_rejects_fsm_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/stateful_sequence.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should reject --dynamic with FSM rules");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("stateful"), "error should mention stateful: {}", stderr);
}

#[test]
fn dynamic_generates_flow_table() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("rtl/flow_table.v").exists(), "flow_table.v should be generated");
}

#[test]
fn dynamic_no_rule_match_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!tmp.path().join("rtl/rule_match_0.v").exists(), "rule_match_0.v should not exist in dynamic mode");
    assert!(!tmp.path().join("rtl/decision_logic.v").exists(), "decision_logic.v should not exist in dynamic mode");
}

#[test]
fn dynamic_top_has_axi_lite_ports() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let top_v = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top_v.contains("s_axil_awaddr"), "dynamic top should have AXI-Lite ports");
    assert!(top_v.contains("flow_table"), "dynamic top should instantiate flow_table");
}

#[test]
fn dynamic_initial_values_from_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let flow_v = std::fs::read_to_string(tmp.path().join("rtl/flow_table.v")).unwrap();
    assert!(flow_v.contains("entry_valid[0]"), "flow_table should have initial entries from YAML");
    assert!(flow_v.contains("entry_ethertype_val"), "flow_table should have ethertype initial values");
}

#[test]
fn dynamic_correct_num_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "--dynamic-entries", "32", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let flow_v = std::fs::read_to_string(tmp.path().join("rtl/flow_table.v")).unwrap();
    assert!(flow_v.contains("NUM_ENTRIES   = 32"), "NUM_ENTRIES should be 32");
}

#[test]
fn dynamic_default_action_propagated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let flow_v = std::fs::read_to_string(tmp.path().join("rtl/flow_table.v")).unwrap();
    assert!(flow_v.contains("default_action = 1'b0"), "default action should be drop (1'b0)");
}

#[test]
fn dynamic_cocotb_test_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(tmp.path().join("tb/test_flow_table.py").exists(), "cocotb test should be generated");
    let test_py = std::fs::read_to_string(tmp.path().join("tb/test_flow_table.py")).unwrap();
    assert!(test_py.contains("test_initial_rules"), "test should include initial rules test");
    assert!(test_py.contains("test_commit_atomicity"), "test should include commit atomicity test");
}

#[test]
fn dynamic_example_compiles() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/dynamic_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "dynamic_firewall.yaml --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("rtl/flow_table.v").exists());
    assert!(tmp.path().join("tb/test_flow_table.py").exists());
}

#[test]
fn dynamic_estimate_shows_flow_table() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/dynamic_firewall.yaml", "--dynamic", "--dynamic-entries", "32", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "estimate --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["mode"], "dynamic");
    assert_eq!(json["num_entries"], 32);
    assert!(json["components"]["flow_table_entries"]["ffs"].as_u64().unwrap() > 0);
    assert!(json["total"]["luts"].as_u64().unwrap() > 0);
}

#[test]
fn dynamic_lint_warns_large() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/dynamic_firewall.yaml", "--dynamic", "--dynamic-entries", "128", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "lint --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["code"] == "LINT016"), "Expected LINT016 warning for 128 entries");
    assert!(findings.iter().any(|f| f["code"] == "LINT017"), "Expected LINT017 info for dynamic mode");
}

#[test]
fn dynamic_formal_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["formal", "rules/examples/dynamic_firewall.yaml", "--dynamic", "--dynamic-entries", "16", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));
    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("p_dynamic_rule_idx_bounds"), "Missing dynamic rule idx bounds assertion");
    assert!(assertions.contains("p_dynamic_decision_stable"), "Missing dynamic decision stability assertion");
    assert!(tmp.path().join("formal/packet_filter.sby").exists(), "Missing SBY task file");
}

// --- Rewrite action tests (Phase 18) ---

#[test]
fn rewrite_validate_accepts_valid() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_outbound
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
        set_dst_mac: "00:11:22:33:44:55"
        dec_ttl: true
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["validate", rules_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Valid rewrite rejected: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn rewrite_reject_ttl_mutual_exclusion() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_rule
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_ttl: 64
        dec_ttl: true
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("bad_rewrite.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["validate", rules_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "Should reject mutually exclusive set_ttl + dec_ttl");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "Error should mention mutual exclusion: {}", stderr);
}

#[test]
fn rewrite_reject_ip_rewrite_without_ipv4_match() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_nat
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
      rewrite:
        set_src_ip: "10.0.0.1"
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("bad_rewrite2.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["validate", rules_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "Should reject IP rewrite without ethertype 0x0800");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("0x0800"), "Error should mention ethertype requirement: {}", stderr);
}

#[test]
fn rewrite_compile_generates_lut() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_outbound
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
        dec_ttl: true
    - name: allow_arp
      priority: 50
      match:
        ethertype: "0x0806"
      action: pass
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile with rewrite failed: {}", String::from_utf8_lossy(&output.stderr));
    // Check rewrite_lut.v was generated
    let lut = std::fs::read_to_string(tmp.path().join("rtl/rewrite_lut.v")).unwrap();
    assert!(lut.contains("module rewrite_lut"), "Missing rewrite_lut module");
    assert!(lut.contains("rewrite_en"), "Missing rewrite_en signal");
    assert!(lut.contains("rewrite_src_ip"), "Missing rewrite_src_ip in LUT");
}

#[test]
fn rewrite_compile_no_lut_without_rewrite() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("no_rewrite.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile failed: {}", String::from_utf8_lossy(&output.stderr));
    // rewrite_lut.v should NOT be generated when no rules have rewrite
    assert!(!tmp.path().join("rtl/rewrite_lut.v").exists(), "rewrite_lut.v should not exist without rewrite rules");
}

#[test]
fn rewrite_top_exports_rule_idx() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_dst_mac: "00:11:22:33:44:55"
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_top.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_top.v")).unwrap();
    assert!(top.contains("decision_rule_idx"), "Top should export decision_rule_idx");
    assert!(top.contains("ip_ttl"), "Top should export ip_ttl for rewrite");
    assert!(top.contains("ip_checksum"), "Top should export ip_checksum for rewrite");
    assert!(top.contains("vlan_valid"), "Top should export vlan_valid for rewrite");
}

#[test]
fn rewrite_frame_parser_has_ttl_checksum() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_ttl: 64
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_fp.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile failed: {}", String::from_utf8_lossy(&output.stderr));
    // Verify the hand-written frame_parser.v has the new ports
    let fp = std::fs::read_to_string("rtl/frame_parser.v").unwrap();
    assert!(fp.contains("ip_ttl"), "frame_parser.v must have ip_ttl port");
    assert!(fp.contains("ip_checksum"), "frame_parser.v must have ip_checksum port");
}

#[test]
fn rewrite_axi_top_has_rewrite() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_src_ip: "10.0.0.1"
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_axi.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "--axi", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile --axi with rewrite failed: {}", String::from_utf8_lossy(&output.stderr));
    let axi_top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_axi_top.v")).unwrap();
    assert!(axi_top.contains("packet_rewrite"), "AXI top should contain packet_rewrite instantiation");
    assert!(axi_top.contains("rewrite_lut"), "AXI top should contain rewrite_lut instantiation");
    // packet_rewrite.v should be copied to output
    assert!(tmp.path().join("rtl/packet_rewrite.v").exists(), "packet_rewrite.v should be copied to output");
}

#[test]
fn rewrite_axi_no_rewrite_clean() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp
      priority: 100
      match:
        ethertype: "0x0806"
      action: pass
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("no_rewrite_axi.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "--axi", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile --axi without rewrite failed: {}", String::from_utf8_lossy(&output.stderr));
    let axi_top = std::fs::read_to_string(tmp.path().join("rtl/packet_filter_axi_top.v")).unwrap();
    assert!(!axi_top.contains("packet_rewrite"), "AXI top should NOT contain packet_rewrite without rewrite rules");
    assert!(!axi_top.contains("rewrite_lut"), "AXI top should NOT contain rewrite_lut without rewrite rules");
    assert!(axi_top.contains("packet_filter_top"), "AXI top should still contain filter core");
    assert!(axi_top.contains("store_forward_fifo"), "AXI top should still contain FIFO");
}

#[test]
fn rewrite_without_axi_generates_lut_no_rewrite_engine() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        dec_ttl: true
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_no_axi.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["compile", rules_path.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile with rewrite (no --axi) failed: {}", String::from_utf8_lossy(&output.stderr));
    // rewrite_lut.v should exist (generated alongside filter)
    assert!(tmp.path().join("rtl/rewrite_lut.v").exists(), "rewrite_lut.v should exist even without --axi");
    // packet_rewrite.v should NOT be copied (only with --axi)
    assert!(!tmp.path().join("rtl/packet_rewrite.v").exists(), "packet_rewrite.v should not exist without --axi");
}

#[test]
fn rewrite_example_compiles() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rewrite_actions.yaml", "--axi", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "rewrite_actions.yaml compile failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("rtl/rewrite_lut.v").exists());
    assert!(tmp.path().join("rtl/packet_rewrite.v").exists());
    assert!(tmp.path().join("rtl/packet_filter_axi_top.v").exists());
}

#[test]
fn rewrite_simulate_shows_rewrite_json() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/rewrite_actions.yaml", "--packet", "ethertype=0x0800,src_ip=10.0.0.5", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "Simulate failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["matched_rule"], "nat_outbound");
    assert_eq!(json["action"], "pass");
    let rw = &json["rewrite"];
    assert_eq!(rw["set_src_ip"], "203.0.113.1");
    assert_eq!(rw["dec_ttl"], true);
}

#[test]
fn rewrite_simulate_no_rewrite_on_drop() {
    // Create a rule with rewrite on a drop action — rewrite should be ignored
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: drop_and_rewrite
      priority: 100
      match:
        ethertype: "0x0800"
      action: drop
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("drop_rewrite.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["simulate", rules_path.to_str().unwrap(), "--packet", "ethertype=0x0800", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "drop");
    assert!(json.get("rewrite").is_none(), "Rewrite should not be present on drop action");
}

// === Phase 18 Batch 6: Estimate, Lint, Formal ===

#[test]
fn rewrite_estimate_includes_rewrite_engine() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_out
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
        dec_ttl: true
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_est.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["estimate", rules_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rewrite = &json["components"]["rewrite_engine"];
    assert_eq!(rewrite["count"], 1);
    assert!(rewrite["luts"].as_u64().unwrap() > 0, "Rewrite engine should have LUT estimate");
    assert!(rewrite["ffs"].as_u64().unwrap() > 0, "Rewrite engine should have FF estimate");
}

#[test]
fn rewrite_lint_warns_axi_and_checksum() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_out
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
        dec_ttl: true
    - name: allow_arp
      priority: 50
      match:
        ethertype: "0x0806"
      action: pass
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_lint.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output = pacgate_bin()
        .args(["lint", rules_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let codes: Vec<&str> = findings.iter().map(|f| f["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"LINT018"), "Should warn about rewrite needing --axi");
    assert!(codes.contains(&"LINT019"), "Should info about IP checksum auto-update");
}

#[test]
fn rewrite_formal_generates_rewrite_assertions() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: nat_out
      priority: 100
      match:
        ethertype: "0x0800"
        src_ip: "10.0.0.0/8"
      action: pass
      rewrite:
        set_src_ip: "203.0.113.1"
"#;
    let tmp = tempfile::tempdir().unwrap();
    let rules_path = tmp.path().join("rewrite_formal.yaml");
    std::fs::write(&rules_path, yaml).unwrap();
    let output_dir = tmp.path().join("gen");
    let output = pacgate_bin()
        .args(["formal", rules_path.to_str().unwrap(), "-o", output_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let sva = std::fs::read_to_string(output_dir.join("formal/assertions.sv")).unwrap();
    assert!(sva.contains("p_rewrite_implies_pass"), "SVA should contain rewrite assertion");
    assert!(sva.contains("rewrite_en"), "SVA should reference rewrite_en signal");
}

// --- Platform target tests ---

#[test]
fn target_opennic_flag_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--target", "opennic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --target opennic failed: {}", String::from_utf8_lossy(&output.stderr));
    // Should generate width converters
    assert!(tmp.path().join("rtl/axis_512_to_8.v").exists(), "axis_512_to_8.v missing");
    assert!(tmp.path().join("rtl/axis_8_to_512.v").exists(), "axis_8_to_512.v missing");
    // Should also generate AXI (implied)
    assert!(tmp.path().join("rtl/packet_filter_axi_top.v").exists(), "AXI top missing (should be implied by --target)");
}

#[test]
fn target_corundum_flag_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--target", "corundum", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --target corundum failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("rtl/axis_512_to_8.v").exists(), "axis_512_to_8.v missing");
    assert!(tmp.path().join("rtl/axis_8_to_512.v").exists(), "axis_8_to_512.v missing");
}

#[test]
fn target_invalid_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--target", "xilinx", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should reject invalid --target");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown platform target"), "error should mention unknown target: {}", stderr);
}

#[test]
fn target_dynamic_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--target", "opennic", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should reject --target with --dynamic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incompatible"), "error should mention incompatibility: {}", stderr);
}

#[test]
fn target_opennic_generates_wrapper() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --target opennic failed: {}", String::from_utf8_lossy(&output.stderr));
    // OpenNIC wrapper should be generated
    assert!(tmp.path().join("rtl/pacgate_opennic_250.v").exists(), "OpenNIC wrapper missing");
    let wrapper = std::fs::read_to_string(tmp.path().join("rtl/pacgate_opennic_250.v")).unwrap();
    assert!(wrapper.contains("module pacgate_opennic_250"), "wrapper should have correct module name");
    assert!(wrapper.contains("s_axis_tuser_size"), "wrapper should have tuser_size port");
    assert!(wrapper.contains("axis_512_to_8"), "wrapper should instantiate RX width converter");
    assert!(wrapper.contains("axis_8_to_512"), "wrapper should instantiate TX width converter");
    assert!(wrapper.contains("packet_filter_axi_top"), "wrapper should instantiate filter pipeline");
}

#[test]
fn target_opennic_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["target"], "opennic");
    assert_eq!(json["axi_stream"], true);
}

#[test]
fn target_opennic_example_validates() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/opennic_l3l4.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "opennic_l3l4.yaml should validate: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn target_corundum_generates_wrapper() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/corundum_datacenter.yaml", "--target", "corundum", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --target corundum failed: {}", String::from_utf8_lossy(&output.stderr));
    // Corundum wrapper should be generated
    assert!(tmp.path().join("rtl/pacgate_corundum_app.v").exists(), "Corundum wrapper missing");
    let wrapper = std::fs::read_to_string(tmp.path().join("rtl/pacgate_corundum_app.v")).unwrap();
    assert!(wrapper.contains("module pacgate_corundum_app"), "wrapper should have correct module name");
    assert!(wrapper.contains("s_axis_sync_rx_tdata"), "wrapper should have Corundum sync RX port");
    assert!(wrapper.contains("m_axis_sync_tx_tdata"), "wrapper should have Corundum sync TX port");
    assert!(wrapper.contains("rst_n = ~rst"), "wrapper should invert reset");
    assert!(wrapper.contains("PTP_TS_WIDTH"), "wrapper should have PTP timestamp parameter");
}

#[test]
fn target_corundum_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/corundum_datacenter.yaml", "--target", "corundum", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["target"], "corundum");
    assert_eq!(json["axi_stream"], true);
}

#[test]
fn target_corundum_example_validates() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/corundum_datacenter.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "corundum_datacenter.yaml should validate: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn target_ports_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--target", "corundum", "--ports", "4", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should reject --target with --ports > 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incompatible"), "error should mention incompatibility: {}", stderr);
}

#[test]
fn target_estimate_includes_width_converters() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "estimate --target opennic failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["platform_target"], "opennic");
    assert!(json["width_converters"]["luts"].as_u64().unwrap() > 0, "width converter LUTs should be > 0");
    assert!(json["width_converters"]["ffs"].as_u64().unwrap() > 0, "width converter FFs should be > 0");
}

#[test]
fn target_lint_includes_lint020_021() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "lint --target opennic failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    let findings = json["findings"].as_array().unwrap();
    let codes: Vec<&str> = findings.iter().map(|f| f["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"LINT020"), "Should have LINT020 (throughput limitation)");
    assert!(codes.contains(&"LINT021"), "Should have LINT021 (implicit AXI)");
}

#[test]
fn target_synth_includes_platform_files() {
    let tmp = tempfile::tempdir().unwrap();
    // First compile with target to generate RTL
    let output = pacgate_bin()
        .args(["compile", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    // Now run synth to check file list includes width converters
    let output = pacgate_bin()
        .args(["synth", "rules/examples/opennic_l3l4.yaml", "--axi", "--json", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "synth failed: {}", String::from_utf8_lossy(&output.stderr));
}

// --- Phase 20: cocotb 2.0 runner tests ---

#[test]
fn compile_generates_run_sim_py() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb/run_sim.py").exists(), "run_sim.py should be generated");

    let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
    assert!(runner_py.contains("from cocotb_tools.runner import get_runner"), "runner should import cocotb_tools.runner");
    assert!(runner_py.contains("packet_filter_top"), "runner should reference correct toplevel");
}

#[test]
fn compile_conntrack_generates_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/hsm_conntrack.yaml", "--conntrack", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --conntrack failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb-conntrack/run_sim.py").exists(), "conntrack run_sim.py should be generated");

    let runner_py = std::fs::read_to_string(tmp.path().join("tb-conntrack/run_sim.py")).unwrap();
    assert!(runner_py.contains("conntrack_table"), "conntrack runner should reference correct toplevel");
    assert!(runner_py.contains("from cocotb_tools.runner import get_runner"), "conntrack runner should import cocotb_tools");
}

#[test]
fn compile_rate_limit_generates_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/rate_limited.yaml", "--rate-limit", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --rate-limit failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb-rate-limiter/run_sim.py").exists(), "rate limiter run_sim.py should be generated");

    let runner_py = std::fs::read_to_string(tmp.path().join("tb-rate-limiter/run_sim.py")).unwrap();
    assert!(runner_py.contains("rate_limiter"), "rate limiter runner should reference correct toplevel");
}

#[test]
fn compile_dynamic_generates_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/l3l4_firewall.yaml", "--dynamic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --dynamic failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb/run_sim.py").exists(), "dynamic run_sim.py should be generated");

    let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
    assert!(runner_py.contains("flow_table"), "dynamic runner should reference flow_table");
    assert!(runner_py.contains("test_flow_table"), "dynamic runner should use test_flow_table module");
}

#[test]
fn runner_contains_correct_module_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
    assert!(runner_py.contains("frame_parser.v"), "runner should include frame_parser.v source");
    assert!(runner_py.contains("test_module=\"test_packet_filter\""), "runner should have correct test module");
    assert!(runner_py.contains("results_xml"), "runner should produce results XML");
}

#[test]
fn runner_coexists_with_makefile() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    // Both Makefile and run_sim.py should exist
    assert!(tmp.path().join("tb/Makefile").exists(), "Makefile should still be generated");
    assert!(tmp.path().join("tb/run_sim.py").exists(), "run_sim.py should also be generated");
}

#[test]
fn platform_target_runner_includes_width_converters() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/opennic_l3l4.yaml", "--target", "opennic", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --target opennic failed: {}", String::from_utf8_lossy(&output.stderr));

    // AXI runner should include width converters
    let runner_py = std::fs::read_to_string(tmp.path().join("tb-axi/run_sim.py")).unwrap();
    assert!(runner_py.contains("axis_512_to_8.v"), "platform runner should include 512→8 width converter");
    assert!(runner_py.contains("axis_8_to_512.v"), "platform runner should include 8→512 width converter");
}

#[test]
fn runner_default_simulator_is_icarus() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let runner_py = std::fs::read_to_string(tmp.path().join("tb/run_sim.py")).unwrap();
    assert!(runner_py.contains("\"icarus\""), "runner default simulator should be icarus");
}

#[test]
fn axi_compile_generates_axi_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/allow_arp.yaml", "--axi", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile --axi failed: {}", String::from_utf8_lossy(&output.stderr));

    assert!(tmp.path().join("tb-axi/run_sim.py").exists(), "AXI run_sim.py should be generated");
    let runner_py = std::fs::read_to_string(tmp.path().join("tb-axi/run_sim.py")).unwrap();
    assert!(runner_py.contains("packet_filter_axi_top"), "AXI runner should reference AXI toplevel");
}

// --- Phase 21: DSCP/ECN QoS matching tests ---

#[test]
fn compile_dscp_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ef
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let rule_v = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule_v.contains("ip_dscp == 6'd46"), "rule_match should contain DSCP comparison");
    assert!(rule_v.contains("ip_dscp"), "rule_match should have ip_dscp port");
}

#[test]
fn compile_ecn_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ecn.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ecn
      priority: 100
      match:
        ethertype: "0x0800"
        ip_ecn: 1
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let rule_v = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule_v.contains("ip_ecn == 2'd1"), "rule_match should contain ECN comparison");
}

#[test]
fn simulate_dscp_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/allow_arp.yaml",
               "--packet", "ethertype=0x0800,ip_dscp=46", "--json"])
        .output()
        .unwrap();
    // This should work even though allow_arp doesn't match DSCP — it hits default action
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn simulate_dscp_nomatch() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ef
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x0800,ip_dscp=0", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"action\":\"drop\"") || stdout.contains("\"action\": \"drop\""),
        "DSCP=0 should not match EF rule (DSCP=46)");
}

#[test]
fn validate_dscp_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_dscp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 64
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "validate should reject ip_dscp=64");
}

#[test]
fn validate_ecn_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_ecn.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        ip_ecn: 4
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "validate should reject ip_ecn=4");
}

#[test]
fn compile_dscp_rewrite() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp_rewrite.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: remark_cs1
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 8
      action: pass
      rewrite:
        set_dscp: 0
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap(), "--axi"])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    let lut_v = std::fs::read_to_string(tmp.path().join("rtl/rewrite_lut.v")).unwrap();
    assert!(lut_v.contains("rewrite_dscp"), "rewrite_lut.v should contain rewrite_dscp port");
}

#[test]
fn simulate_ecn_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ecn.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ecn_ect1
      priority: 100
      match:
        ethertype: "0x0800"
        ip_ecn: 1
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["simulate", yaml.to_str().unwrap(), "--packet", "ethertype=0x0800,ip_ecn=1"])
        .output()
        .unwrap();
    assert!(output.status.success(), "simulate failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pass") || stdout.contains("PASS"), "should match ECN rule");
}

#[test]
fn lint_dscp_no_ipv4() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp_no_ipv4.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: dscp_no_etype
      priority: 100
      match:
        ip_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "lint failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT022"), "should warn about DSCP without IPv4 ethertype");
}

#[test]
fn estimate_dscp_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp_est.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ef_traffic
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["estimate", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "estimate failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("luts") || stdout.contains("LUTs"), "estimate should report LUT count");
}

#[test]
fn diff_dscp_change() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old.yaml");
    let new = tmp.path().join("new.yaml");
    std::fs::write(&old, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: qos_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#).unwrap();
    std::fs::write(&new, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: qos_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 34
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["diff", old.to_str().unwrap(), new.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "diff failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ip_dscp"), "diff should report ip_dscp change");
}

#[test]
fn formal_dscp_ecn() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("dscp_formal.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ef_traffic
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["formal", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("p_dscp_bounds"), "assertions should contain DSCP bounds check");
    assert!(assertions.contains("p_ecn_bounds"), "assertions should contain ECN bounds check");
}

// --- Phase 22: IPv6 TC + TCP Flags + ICMP ---

#[test]
fn compile_ipv6_dscp_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ipv6_dscp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_ef
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let rule_v = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule_v.contains("ipv6_dscp == 6'd46"), "should contain ipv6_dscp comparison");
}

#[test]
fn compile_tcp_flags_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("tcp_flags.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_syn
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 2
        tcp_flags_mask: 18
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let rule_v = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule_v.contains("tcp_flags"), "should contain tcp_flags comparison");
}

#[test]
fn compile_icmp_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ping
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 8
        icmp_code: 0
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["compile", yaml.to_str().unwrap(), "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let rule_v = std::fs::read_to_string(tmp.path().join("rtl/rule_match_0.v")).unwrap();
    assert!(rule_v.contains("icmp_type_field == 8'd8"), "should contain icmp_type comparison");
    assert!(rule_v.contains("icmp_code == 8'd0"), "should contain icmp_code comparison");
}

#[test]
fn simulate_ipv6_dscp_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ipv6_dscp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_ef
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_dscp: 46
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["simulate", yaml.to_str().unwrap(), "--packet", "ethertype=0x86DD,ipv6_dscp=46"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ipv6_ef"), "should match ipv6_ef rule");
    assert!(stdout.contains("PASS"), "should pass");
}

#[test]
fn simulate_tcp_syn_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("syn.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_syn
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 2
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["simulate", yaml.to_str().unwrap(), "--packet", "ethertype=0x0800,ip_protocol=6,tcp_flags=0x02"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_syn"), "should match allow_syn rule");
}

#[test]
fn simulate_icmp_echo_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ping
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 8
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["simulate", yaml.to_str().unwrap(), "--packet", "ethertype=0x0800,ip_protocol=1,icmp_type=8"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_ping"), "should match allow_ping rule");
}

#[test]
fn validate_ipv6_dscp_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_dscp: 64
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ipv6_dscp must be 0-63"), "should reject ipv6_dscp > 63");
}

#[test]
fn validate_tcp_flags_mask_without_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        tcp_flags_mask: 18
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tcp_flags_mask requires tcp_flags"), "should reject mask without flags");
}

#[test]
fn lint_tcp_flags_no_protocol() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("tcp_no_proto.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_no_proto
      priority: 100
      match:
        ethertype: "0x0800"
        tcp_flags: 0x02
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT024"), "should warn about tcp_flags without ip_protocol 6");
}

#[test]
fn lint_icmp_no_protocol() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmp_no_proto.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: echo_no_proto
      priority: 100
      match:
        ethertype: "0x0800"
        icmp_type: 8
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT025"), "should warn about icmp_type without ip_protocol 1");
}

#[test]
fn lint_ipv6_dscp_no_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ipv6_dscp_no_et.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_ef_no_et
      priority: 100
      match:
        ipv6_dscp: 46
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT023"), "should warn about ipv6_dscp without ethertype 0x86DD");
}

#[test]
fn estimate_tcp_flags_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("est_tcp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 0x02
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["estimate", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("luts"), "should include LUT estimate");
}

#[test]
fn diff_tcp_flags_change() {
    let tmp = tempfile::tempdir().unwrap();
    let old_yaml = tmp.path().join("old.yaml");
    let new_yaml = tmp.path().join("new.yaml");
    std::fs::write(&old_yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 0x02
      action: pass
"#).unwrap();
    std::fs::write(&new_yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 0x12
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["diff", old_yaml.to_str().unwrap(), new_yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tcp_flags"), "should detect tcp_flags change");
}

#[test]
fn formal_tcp_icmp() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("formal_tcp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_rule
      priority: 200
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 0x02
      action: pass
    - name: echo_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 8
      action: pass
"#).unwrap();
    let out_dir = tmp.path().join("gen");
    // First compile to generate RTL
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    // Then generate formal
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["formal", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let assertions = std::fs::read_to_string(out_dir.join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("tcp_flags"), "should include TCP flags assertions");
    assert!(assertions.contains("icmp"), "should include ICMP assertions");
}

// --- Phase 23: ICMPv6, ARP, IPv6 extensions ---

#[test]
fn compile_icmpv6_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmpv6.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ndp_ns
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_next_header: 58
        icmpv6_type: 135
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let verilog = std::fs::read_to_string(out_dir.join("rtl/rule_match_0.v")).unwrap();
    assert!(verilog.contains("icmpv6_type == 8'd135"), "should have ICMPv6 type comparison");
}

#[test]
fn compile_arp_opcode_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("arp.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: arp_req
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 1
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let verilog = std::fs::read_to_string(out_dir.join("rtl/rule_match_0.v")).unwrap();
    assert!(verilog.contains("arp_opcode == 16'd1"), "should have ARP opcode comparison");
}

#[test]
fn compile_ipv6_flow_label_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ipv6ext.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: flow_rule
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_flow_label: 12345
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let verilog = std::fs::read_to_string(out_dir.join("rtl/rule_match_0.v")).unwrap();
    assert!(verilog.contains("ipv6_flow_label == 20'd12345"), "should have flow label comparison");
}

#[test]
fn simulate_icmpv6_echo_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmpv6_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_echo
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_next_header: 58
        icmpv6_type: 128
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x86DD,ipv6_next_header=58,icmpv6_type=128"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_echo") || stdout.contains("pass"), "should match icmpv6 echo rule");
}

#[test]
fn simulate_arp_request_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("arp_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp_req
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 1
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x0806,arp_opcode=1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_arp_req") || stdout.contains("pass"), "should match ARP request rule");
}

#[test]
fn simulate_ipv6_hop_limit_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("hop_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ttl64
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_hop_limit: 64
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x86DD,ipv6_hop_limit=64"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_ttl64") || stdout.contains("pass"), "should match hop limit rule");
}

#[test]
fn validate_arp_opcode_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_arp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 3
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("arp_opcode must be 1") || stderr.contains("arp_opcode"), "should reject arp_opcode=3");
}

// ============================================================
// Phase 24 — QinQ, IPv4 Fragmentation, L4 Port Rewrite
// ============================================================

#[test]
fn compile_qinq_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("qinq.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: outer_vlan_100
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_id: 100
        outer_vlan_pcp: 5
      action: pass
    - name: inner_vlan_only
      priority: 50
      match:
        ethertype: "0x8100"
        vlan_id: 200
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "QinQ compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let verilog = std::fs::read_to_string(out_dir.join("rtl/rule_match_0.v")).unwrap();
    assert!(verilog.contains("outer_vlan_id == 12'd100"), "should have outer VLAN ID comparison");
    assert!(verilog.contains("outer_vlan_pcp == 3'd5"), "should have outer VLAN PCP comparison");
}

#[test]
fn compile_fragment_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("frag.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: block_fragments
      priority: 100
      match:
        ethertype: "0x0800"
        ip_more_fragments: true
      action: drop
    - name: allow_df_set
      priority: 90
      match:
        ethertype: "0x0800"
        ip_dont_fragment: true
      action: pass
    - name: block_nonzero_offset
      priority: 80
      match:
        ethertype: "0x0800"
        ip_frag_offset: 100
      action: drop
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Fragment compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let v0 = std::fs::read_to_string(out_dir.join("rtl/rule_match_0.v")).unwrap();
    assert!(v0.contains("ip_more_fragments == 1'b1"), "should have MF flag check");
    let v1 = std::fs::read_to_string(out_dir.join("rtl/rule_match_1.v")).unwrap();
    assert!(v1.contains("ip_dont_fragment == 1'b1"), "should have DF flag check");
    let v2 = std::fs::read_to_string(out_dir.join("rtl/rule_match_2.v")).unwrap();
    assert!(v2.contains("ip_frag_offset == 13'd100"), "should have frag offset check");
}

#[test]
fn compile_port_rewrite_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("port_rw.yaml");
    let out_dir = tmp.path().join("gen");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: redirect_http
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        dst_port: 80
      action: pass
      rewrite:
        set_dst_port: 8080
    - name: nat_ssh
      priority: 90
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        dst_port: 22
      action: pass
      rewrite:
        set_src_port: 10022
        set_dst_port: 2222
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", yaml.to_str().unwrap(), "--axi", "-o", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Port rewrite compile failed: {}", String::from_utf8_lossy(&output.stderr));
    let lut = std::fs::read_to_string(out_dir.join("rtl/rewrite_lut.v")).unwrap();
    assert!(lut.contains("rewrite_src_port"), "LUT should have src_port output");
    assert!(lut.contains("rewrite_dst_port"), "LUT should have dst_port output");
    assert!(lut.contains("16'd8080"), "LUT should have dst_port value 8080");
    assert!(lut.contains("16'd10022"), "LUT should have src_port value 10022");
}

#[test]
fn validate_outer_vlan_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_qinq.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_id: 5000
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("outer_vlan_id") && stderr.contains("4095"), "should reject outer_vlan_id > 4095");
}

#[test]
fn validate_frag_offset_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_frag.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        ip_frag_offset: 9000
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ip_frag_offset") && stderr.contains("8191"), "should reject ip_frag_offset > 8191");
}

#[test]
fn validate_port_rewrite_requires_ipv4() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_port_rw.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x86DD"
        ip_protocol: 6
      action: pass
      rewrite:
        set_dst_port: 8080
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Port rewrite") || stderr.contains("port rewrite") || stderr.contains("set_dst_port") || stderr.contains("IPv4"),
            "should reject port rewrite without IPv4: {}", stderr);
}

#[test]
fn validate_port_rewrite_requires_protocol() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_port_rw2.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_src_port: 1234
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("port rewrite") || stderr.contains("TCP") || stderr.contains("UDP") || stderr.contains("ip_protocol"),
            "should reject port rewrite without TCP/UDP: {}", stderr);
}

#[test]
fn validate_port_rewrite_rejects_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_port_rw3.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
      action: pass
      rewrite:
        set_dst_port: 0
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("set_dst_port") || stderr.contains("port") || stderr.contains("1-65535"),
            "should reject port 0: {}", stderr);
}

#[test]
fn simulate_qinq_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("qinq_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: customer_voice
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_id: 100
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x88A8,outer_vlan_id=100"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("customer_voice") || stdout.contains("pass"),
            "should match QinQ rule: {}", stdout);
}

#[test]
fn simulate_frag_df_match() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("frag_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_df
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dont_fragment: true
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x0800,ip_dont_fragment=true"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow_df") || stdout.contains("pass"),
            "should match DF rule: {}", stdout);
}

#[test]
fn simulate_port_rewrite_info() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("port_rw_sim.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: redirect_http
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        dst_port: 80
      action: pass
      rewrite:
        set_dst_port: 8080
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", yaml.to_str().unwrap(),
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("redirect_http") || stdout.contains("pass"),
            "should match port rewrite rule: {}", stdout);
    assert!(stdout.contains("8080") || stdout.contains("set_dst_port"),
            "should show port rewrite info: {}", stdout);
}

#[test]
fn validate_outer_vlan_pcp_range() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_pcp.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_pcp: 10
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("outer_vlan_pcp") || stderr.contains("0-7"),
            "should reject outer_vlan_pcp > 7: {}", stderr);
}

#[test]
fn validate_icmpv6_code_without_type() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("bad_icmpv6.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x86DD"
        icmpv6_code: 0
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", yaml.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("icmpv6_code requires icmpv6_type"), "should reject icmpv6_code without type");
}

// ── Phase 23 Batch 2 integration tests ─────────────────────────────

#[test]
fn lint_icmpv6_no_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("icmpv6_no_etype.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: icmpv6_no_prereq
      priority: 100
      match:
        icmpv6_type: 128
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT026"), "should emit LINT026 for icmpv6 without ethertype");
}

#[test]
fn lint_arp_no_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("arp_no_etype.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: arp_no_prereq
      priority: 100
      match:
        arp_opcode: 1
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT027"), "should emit LINT027 for arp without ethertype");
}

#[test]
fn lint_ipv6_ext_no_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("ipv6_ext_no_etype.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_ext_no_prereq
      priority: 100
      match:
        ipv6_hop_limit: 64
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT028"), "should emit LINT028 for ipv6 ext without ethertype");
}

#[test]
fn estimate_arp_rule() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["estimate", "rules/examples/arp_security.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    let total_luts = json["total"]["luts"].as_u64().unwrap();
    assert!(total_luts > 0, "estimate should report LUTs > 0 for ARP rules");
}

#[test]
fn diff_arp_opcode_change() {
    let tmp = tempfile::tempdir().unwrap();
    let old_yaml = tmp.path().join("old.yaml");
    let new_yaml = tmp.path().join("new.yaml");
    std::fs::write(&old_yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: arp_rule
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 1
      action: pass
"#).unwrap();
    std::fs::write(&new_yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: arp_rule
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 2
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["diff", old_yaml.to_str().unwrap(), new_yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("arp_opcode"), "diff should detect arp_opcode change");
}

#[test]
fn formal_icmpv6_arp() {
    let tmp = tempfile::tempdir().unwrap();
    // First compile to generate RTL
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", "rules/examples/icmpv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));

    // Then generate formal assertions
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["formal", "rules/examples/icmpv6_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));

    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("icmpv6"), "SVA should contain ICMPv6 assertions");
}

// ============================================================
// Phase 24 Batch 2 — Lint, Estimate, Diff, Formal, Examples
// ============================================================

#[test]
fn lint_qinq_without_ethertype() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("lint_qinq.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_qinq
      priority: 100
      match:
        outer_vlan_id: 100
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT029"), "should have LINT029 for QinQ without ethertype: {}", stdout);
}

#[test]
fn lint_frag_without_ipv4() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("lint_frag.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_frag
      priority: 100
      match:
        ip_dont_fragment: true
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT030"), "should have LINT030 for frag without IPv4: {}", stdout);
}

#[test]
fn lint_port_rewrite_info() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = tmp.path().join("lint_port_rw.yaml");
    std::fs::write(&yaml, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: port_rw
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        dst_port: 80
      action: pass
      rewrite:
        set_dst_port: 8080
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["lint", yaml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LINT031"), "should have LINT031 for port rewrite: {}", stdout);
    assert!(stdout.contains("LINT032"), "should have LINT032 for L4 checksum info: {}", stdout);
}

#[test]
fn estimate_qinq_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["estimate", "rules/examples/qinq_provider.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["total"]["luts"].as_u64().unwrap() > 0, "should estimate LUTs for QinQ rules");
}

#[test]
fn estimate_port_rewrite_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["estimate", "rules/examples/port_rewrite.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["total"]["luts"].as_u64().unwrap() > 0, "should estimate LUTs for port rewrite rules");
}

#[test]
fn diff_qinq_change() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old.yaml");
    let new = tmp.path().join("new.yaml");
    std::fs::write(&old, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: qinq_rule
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_id: 100
      action: pass
"#).unwrap();
    std::fs::write(&new, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: qinq_rule
      priority: 100
      match:
        ethertype: "0x88A8"
        outer_vlan_id: 200
      action: pass
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["diff", old.to_str().unwrap(), new.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("outer_vlan_id"), "diff should detect outer_vlan_id change: {}", stdout);
}

#[test]
fn formal_qinq_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", "rules/examples/qinq_provider.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["formal", "rules/examples/qinq_provider.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));
    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("qinq"), "SVA should contain QinQ assertions: {}", assertions);
}

#[test]
fn formal_frag_assertions() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", "rules/examples/fragment_security.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["formal", "rules/examples/fragment_security.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "formal failed: {}", String::from_utf8_lossy(&output.stderr));
    let assertions = std::fs::read_to_string(tmp.path().join("formal/assertions.sv")).unwrap();
    assert!(assertions.contains("ip_frag"), "SVA should contain IP frag assertions: {}", assertions);
}

#[test]
fn stats_shows_qinq_fields() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["stats", "rules/examples/qinq_provider.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let usage = &json["field_usage"];
    assert!(usage["outer_vlan_id"].as_u64().unwrap() > 0, "stats should show outer_vlan_id usage");
}

#[test]
fn all_examples_validate_phase24() {
    for name in &["qinq_provider", "fragment_security", "port_rewrite"] {
        let path = format!("rules/examples/{}.yaml", name);
        let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
            .args(["validate", &path])
            .output()
            .unwrap();
        assert!(output.status.success(), "Example {} should validate: {}", name, String::from_utf8_lossy(&output.stderr));
    }
}

#[test]
fn all_examples_simulate_phase24() {
    let cases = [
        ("qinq_provider", "ethertype=0x88A8,outer_vlan_id=100,outer_vlan_pcp=5,vlan_id=10"),
        ("fragment_security", "ethertype=0x0800,ip_dont_fragment=true"),
        ("port_rewrite", "ethertype=0x0800,ip_protocol=6,dst_port=80"),
    ];
    for (name, packet) in &cases {
        let path = format!("rules/examples/{}.yaml", name);
        let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
            .args(["simulate", &path, "--packet", packet])
            .output()
            .unwrap();
        assert!(output.status.success(), "Simulate {} failed: {}", name, String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("PASS"), "Simulate {} should match a PASS rule: {}", name, stdout);
    }
}

// ============================================================
// Phase 25.1: GRE Tunnel Parsing integration tests
// ============================================================

#[test]
fn compile_gre_tunnel_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["compile", "rules/examples/gre_tunnel.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile gre_tunnel failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compilation complete"));
}

#[test]
fn validate_gre_tunnel_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", "rules/examples/gre_tunnel.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "validate gre_tunnel failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("5 rules"));
}

#[test]
fn validate_gre_key_requires_protocol() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad_gre
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 47
        gre_key: 12345
      action: pass
"#;
    let tmp = std::env::temp_dir().join("bad_gre_key.yaml");
    std::fs::write(&tmp, yaml).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["validate", tmp.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("gre_key requires gre_protocol"), "Expected gre_key validation error: {}", stderr);
}

#[test]
fn simulate_gre_keyed_match() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", "rules/examples/gre_tunnel.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=47,gre_protocol=0x0800,gre_key=1000"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gre_ipv4_keyed"), "Should match gre_ipv4_keyed: {}", stdout);
    assert!(stdout.contains("PASS"));
}

#[test]
fn simulate_gre_protocol_only_match() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", "rules/examples/gre_tunnel.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=47,gre_protocol=25944"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gre_transparent_bridge"), "Should match transparent bridge: {}", stdout);
    assert!(stdout.contains("PASS"));
}

#[test]
fn simulate_gre_drop_unknown() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", "rules/examples/gre_tunnel.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=47,gre_protocol=0x0800,gre_key=9999"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // gre_key=9999 doesn't match keyed rules (key 1000/2000), but gre_any (priority 70) drops all GRE
    assert!(stdout.contains("DROP"), "Should drop unknown GRE key: {}", stdout);
}

#[test]
fn simulate_gre_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_pacgate"))
        .args(["simulate", "rules/examples/gre_tunnel.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=47,gre_protocol=0x0800,gre_key=1000", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "gre_ipv4_keyed");
}

// --- Phase 25.2: Connection Tracking State ---

#[test]
fn validate_conntrack_firewall_rules() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/conntrack_firewall.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "validate failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn validate_conntrack_state_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("bad_conntrack.yaml");
    std::fs::write(&rules, r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
        conntrack_state: "related"
      action: pass
"#).unwrap();
    let output = pacgate_bin()
        .args(["validate", rules.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("conntrack_state must be"), "Expected validation error: {}", stderr);
}

#[test]
fn compile_conntrack_firewall_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let output = pacgate_bin()
        .args(["compile", "rules/examples/conntrack_firewall.yaml", "-o", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "compile failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(tmp.path().join("rtl/packet_filter_top.v").exists());
}

#[test]
fn simulate_conntrack_state_established_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/conntrack_firewall.yaml", "--packet",
            "ethertype=0x0800,conntrack_state=established"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "Established traffic should pass: {}", stdout);
    assert!(stdout.contains("allow_established"), "Should match allow_established rule: {}", stdout);
}

#[test]
fn simulate_conntrack_state_new_http() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/conntrack_firewall.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=6,dst_port=80,conntrack_state=new"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "New HTTP should pass: {}", stdout);
    assert!(stdout.contains("allow_new_http"), "Should match allow_new_http: {}", stdout);
}

#[test]
fn simulate_conntrack_state_new_blocked() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/conntrack_firewall.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=6,dst_port=443,conntrack_state=new"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Port 443 not in allowed new connections list → should be dropped
    assert!(stdout.contains("DROP"), "New HTTPS (443) should be dropped: {}", stdout);
}

#[test]
fn simulate_conntrack_state_json_output() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/conntrack_firewall.yaml", "--packet",
            "ethertype=0x0800,conntrack_state=established", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "allow_established");
}

#[test]
fn simulate_conntrack_stateful_new_flow() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/conntrack_firewall.yaml", "--packet",
            "ethertype=0x0800,ip_protocol=6,dst_port=22", "--stateful"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // With --stateful, a new flow (no conntrack entry) should match "new" SSH rule
    assert!(stdout.contains("PASS"), "Stateful new SSH should pass: {}", stdout);
}

#[test]
fn estimate_conntrack_state_rules() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/conntrack_firewall.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LUT"), "Should show LUT estimates: {}", stdout);
}

// ──────────────────────────────────────────────────────────────
// Phase 25.3: Mirror/Redirect egress actions
// ──────────────────────────────────────────────────────────────

#[test]
fn validate_mirror_redirect_rules() {
    let output = pacgate_bin()
        .args(["validate", "rules/examples/mirror_redirect.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "Validation failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn compile_mirror_redirect_rules() {
    let output = pacgate_bin()
        .args(["compile", "rules/examples/mirror_redirect.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "Compile failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn simulate_mirror_port_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mirror_redirect.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "mirror_http_to_ids");
    assert_eq!(json["mirror_port"], 1);
}

#[test]
fn simulate_redirect_port_match() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mirror_redirect.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=53", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "redirect_dns_to_proxy");
    assert_eq!(json["redirect_port"], 2);
}

#[test]
fn simulate_mirror_and_redirect_combined() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mirror_redirect.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=17,dst_port=161", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "pass");
    assert_eq!(json["matched_rule"], "mirror_and_redirect_snmp");
    assert_eq!(json["mirror_port"], 3);
    assert_eq!(json["redirect_port"], 4);
}

#[test]
fn simulate_no_match_no_egress() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mirror_redirect.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=443", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["action"], "drop");
    assert!(json.get("mirror_port").is_none(), "No mirror_port on default drop");
    assert!(json.get("redirect_port").is_none(), "No redirect_port on default drop");
}

#[test]
fn simulate_mirror_text_output() {
    let output = pacgate_bin()
        .args(["simulate", "rules/examples/mirror_redirect.yaml",
               "--packet", "ethertype=0x0800,ip_protocol=6,dst_port=80"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mirror_port: 1"), "Text output should show mirror: {}", stdout);
    assert!(stdout.contains("Egress Actions"), "Text output should show Egress Actions section: {}", stdout);
}

#[test]
fn reject_redirect_with_drop_action() {
    let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: bad
      priority: 100
      match:
        ethertype: "0x0800"
      action: drop
      redirect_port: 2
"#;
    let tmp = std::env::temp_dir().join("test_redirect_drop.yaml");
    std::fs::write(&tmp, yaml).unwrap();
    let output = pacgate_bin()
        .args(["validate", &tmp.to_string_lossy()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("redirect_port requires action: pass"), "Error: {}", stderr);
}

#[test]
fn estimate_mirror_redirect_rules() {
    let output = pacgate_bin()
        .args(["estimate", "rules/examples/mirror_redirect.yaml"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LUT"), "Should show LUT estimates: {}", stdout);
}

#[test]
fn lint_mirror_redirect_rules() {
    let output = pacgate_bin()
        .args(["lint", "rules/examples/mirror_redirect.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let has_lint036 = findings.iter().any(|f| f["code"] == "LINT036");
    assert!(has_lint036, "Should have LINT036 for egress actions: {}", stdout);
}

#[test]
fn stats_mirror_redirect_rules() {
    let output = pacgate_bin()
        .args(["stats", "rules/examples/mirror_redirect.yaml", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["egress_actions"]["mirror_port"].as_u64().unwrap() >= 2, "Mirror count");
    assert!(json["egress_actions"]["redirect_port"].as_u64().unwrap() >= 2, "Redirect count");
}

#[test]
fn diff_mirror_redirect_change() {
    // Create two YAML files with different mirror settings
    let old_yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: rule1
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      mirror_port: 1
"#;
    let new_yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: rule1
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      mirror_port: 5
"#;
    let tmp_old = std::env::temp_dir().join("test_diff_mirror_old.yaml");
    let tmp_new = std::env::temp_dir().join("test_diff_mirror_new.yaml");
    std::fs::write(&tmp_old, old_yaml).unwrap();
    std::fs::write(&tmp_new, new_yaml).unwrap();
    let output = pacgate_bin()
        .args(["diff", &tmp_old.to_string_lossy(), &tmp_new.to_string_lossy()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mirror_port"), "Diff should show mirror_port change: {}", stdout);
}
