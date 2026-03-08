// Rule Test Vectors: Batch testing of packet matching against expected outcomes
//
// Loads a YAML test vector file with packet specifications and expected results,
// runs each through the simulator, and reports pass/fail with detailed diagnostics.
//
// Test vector format:
//   test_vectors:
//     - name: "Web traffic passes"
//       packet: "ethertype=0x0800,ip_protocol=6,dst_port=80"
//       expect_action: pass
//       expect_rule: allow_web    # optional
//     - name: "SSH blocked"
//       packet: "ethertype=0x0800,ip_protocol=6,dst_port=22"
//       expect_action: drop

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::model::{Action, FilterConfig};
use crate::simulator;

// ============================================================
// Test vector model
// ============================================================

#[derive(Debug, Deserialize)]
pub struct TestVectorFile {
    pub test_vectors: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
pub struct TestVector {
    pub name: String,
    pub packet: String,
    pub expect_action: String,
    #[serde(default)]
    pub expect_rule: Option<String>,
}

// ============================================================
// Test result types
// ============================================================

#[derive(Debug, Clone)]
pub struct TestCaseResult {
    pub name: String,
    pub passed: bool,
    pub expected_action: Action,
    pub actual_action: Action,
    pub expected_rule: Option<String>,
    pub actual_rule: Option<String>,
    pub is_default: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug)]
pub struct TestRunResult {
    pub cases: Vec<TestCaseResult>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

// ============================================================
// Parse action string
// ============================================================

fn parse_action(s: &str) -> Result<Action> {
    match s.to_lowercase().as_str() {
        "pass" | "accept" | "allow" | "permit" => Ok(Action::Pass),
        "drop" | "deny" | "reject" | "block" => Ok(Action::Drop),
        _ => bail!("Unknown action '{}': expected pass/drop", s),
    }
}

// ============================================================
// Run test vectors
// ============================================================

/// Load test vectors from a YAML file.
pub fn load_test_vectors(path: &std::path::Path) -> Result<Vec<TestVector>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read test vector file: {}", path.display()))?;
    let file: TestVectorFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse test vector YAML: {}", path.display()))?;
    Ok(file.test_vectors)
}

/// Run all test vectors against a filter config.
pub fn run_test_vectors(config: &FilterConfig, vectors: &[TestVector]) -> Result<TestRunResult> {
    let mut cases = Vec::new();

    for tv in vectors {
        let expected_action = parse_action(&tv.expect_action)
            .with_context(|| format!("In test '{}': invalid expect_action", tv.name))?;

        let sim_pkt = simulator::parse_packet_spec(&tv.packet)
            .with_context(|| format!("In test '{}': invalid packet spec", tv.name))?;

        let result = simulator::simulate(config, &sim_pkt);

        let mut passed = true;
        let mut failure_reason = None;

        // Check action
        if result.action != expected_action {
            passed = false;
            failure_reason = Some(format!(
                "expected action '{}' but got '{}'",
                format_action(&expected_action),
                format_action(&result.action)
            ));
        }

        // Check rule name (if specified)
        if passed {
            if let Some(ref expected_rule) = tv.expect_rule {
                match &result.rule_name {
                    Some(actual_rule) if actual_rule == expected_rule => {}
                    Some(actual_rule) => {
                        passed = false;
                        failure_reason = Some(format!(
                            "expected rule '{}' but matched '{}'",
                            expected_rule, actual_rule
                        ));
                    }
                    None => {
                        passed = false;
                        failure_reason = Some(format!(
                            "expected rule '{}' but hit default action",
                            expected_rule
                        ));
                    }
                }
            }
        }

        cases.push(TestCaseResult {
            name: tv.name.clone(),
            passed,
            expected_action,
            actual_action: result.action,
            expected_rule: tv.expect_rule.clone(),
            actual_rule: result.rule_name.clone(),
            is_default: result.is_default,
            failure_reason,
        });
    }

    let total = cases.len();
    let passed = cases.iter().filter(|c| c.passed).count();
    let failed = total - passed;

    Ok(TestRunResult {
        cases,
        total,
        passed,
        failed,
    })
}

fn format_action(a: &Action) -> &'static str {
    match a {
        Action::Pass => "pass",
        Action::Drop => "drop",
    }
}

// ============================================================
// Text formatter
// ============================================================

pub fn format_text(result: &TestRunResult) -> String {
    let mut out = String::new();

    for case in &result.cases {
        if case.passed {
            out.push_str(&format!("  PASS  {}\n", case.name));
        } else {
            out.push_str(&format!("  FAIL  {}  — {}\n",
                case.name,
                case.failure_reason.as_deref().unwrap_or("unknown")
            ));
        }
    }

    out.push('\n');
    out.push_str(&format!("{}/{} tests passed", result.passed, result.total));
    if result.failed > 0 {
        out.push_str(&format!(", {} failed", result.failed));
    }
    out.push('\n');

    out
}

// ============================================================
// JSON formatter
// ============================================================

pub fn format_json(result: &TestRunResult) -> serde_json::Value {
    serde_json::json!({
        "status": if result.failed == 0 { "ok" } else { "fail" },
        "total": result.total,
        "passed": result.passed,
        "failed": result.failed,
        "cases": result.cases.iter().map(|c| {
            let mut obj = serde_json::json!({
                "name": c.name,
                "passed": c.passed,
                "expected_action": format_action(&c.expected_action),
                "actual_action": format_action(&c.actual_action),
            });
            if let Some(ref er) = c.expected_rule {
                obj["expected_rule"] = serde_json::json!(er);
            }
            if let Some(ref ar) = c.actual_rule {
                obj["actual_rule"] = serde_json::json!(ar);
            }
            if let Some(ref reason) = c.failure_reason {
                obj["failure_reason"] = serde_json::json!(reason);
            }
            obj
        }).collect::<Vec<_>>(),
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_config(rules: Vec<StatelessRule>, default: Action) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: default },
                rules,
                conntrack: None,
                tables: None,
            },
        }
    }

    fn make_rule(name: &str, priority: u32, action: Action, mc: MatchCriteria) -> StatelessRule {
        StatelessRule {
            name: name.to_string(),
            priority,
            match_criteria: mc,
            action: Some(action),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
            mirror_port: None,
            redirect_port: None,
            rss_queue: None,
            int_insert: None,
        }
    }

    fn web_config() -> FilterConfig {
        let mut mc_http = MatchCriteria::default();
        mc_http.ethertype = Some("0x0800".to_string());
        mc_http.ip_protocol = Some(6);
        mc_http.dst_port = Some(PortMatch::Exact(80));

        let mut mc_https = MatchCriteria::default();
        mc_https.ethertype = Some("0x0800".to_string());
        mc_https.ip_protocol = Some(6);
        mc_https.dst_port = Some(PortMatch::Exact(443));

        let mut mc_arp = MatchCriteria::default();
        mc_arp.ethertype = Some("0x0806".to_string());

        make_config(
            vec![
                make_rule("allow_http", 1000, Action::Pass, mc_http),
                make_rule("allow_https", 900, Action::Pass, mc_https),
                make_rule("allow_arp", 800, Action::Pass, mc_arp),
            ],
            Action::Drop,
        )
    }

    // ---- parse_action tests ----

    #[test]
    fn test_parse_action_pass() {
        assert!(matches!(parse_action("pass").unwrap(), Action::Pass));
        assert!(matches!(parse_action("PASS").unwrap(), Action::Pass));
        assert!(matches!(parse_action("accept").unwrap(), Action::Pass));
        assert!(matches!(parse_action("allow").unwrap(), Action::Pass));
        assert!(matches!(parse_action("permit").unwrap(), Action::Pass));
    }

    #[test]
    fn test_parse_action_drop() {
        assert!(matches!(parse_action("drop").unwrap(), Action::Drop));
        assert!(matches!(parse_action("DROP").unwrap(), Action::Drop));
        assert!(matches!(parse_action("deny").unwrap(), Action::Drop));
        assert!(matches!(parse_action("reject").unwrap(), Action::Drop));
        assert!(matches!(parse_action("block").unwrap(), Action::Drop));
    }

    #[test]
    fn test_parse_action_invalid() {
        assert!(parse_action("unknown").is_err());
    }

    // ---- run_test_vectors tests ----

    #[test]
    fn test_all_pass() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "HTTP passes".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: Some("allow_http".to_string()),
            },
            TestVector {
                name: "HTTPS passes".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=443".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: Some("allow_https".to_string()),
            },
            TestVector {
                name: "SSH blocked".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=22".to_string(),
                expect_action: "drop".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.passed, 3);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_action_mismatch() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Expect HTTP to be dropped (wrong)".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "drop".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.failed, 1);
        assert!(!result.cases[0].passed);
        assert!(result.cases[0].failure_reason.as_ref().unwrap().contains("expected action 'drop' but got 'pass'"));
    }

    #[test]
    fn test_rule_name_mismatch() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Wrong rule name".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: Some("wrong_rule".to_string()),
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.failed, 1);
        assert!(result.cases[0].failure_reason.as_ref().unwrap().contains("expected rule 'wrong_rule'"));
    }

    #[test]
    fn test_expect_rule_but_default() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Expect rule but hits default".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=22".to_string(),
                expect_action: "drop".to_string(),
                expect_rule: Some("block_ssh".to_string()),
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.failed, 1);
        assert!(result.cases[0].failure_reason.as_ref().unwrap().contains("default action"));
    }

    #[test]
    fn test_no_rule_check_action_only() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "ARP passes".to_string(),
                packet: "ethertype=0x0806".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.passed, 1);
    }

    #[test]
    fn test_default_drop() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Unknown traffic dropped".to_string(),
                packet: "ethertype=0x86DD".to_string(),
                expect_action: "drop".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.passed, 1);
        assert!(result.cases[0].is_default);
    }

    #[test]
    fn test_mixed_pass_fail() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "HTTP passes".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: None,
            },
            TestVector {
                name: "Wrong expectation".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "drop".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.passed, 1);
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_empty_vectors() {
        let config = web_config();
        let result = run_test_vectors(&config, &[]).unwrap();
        assert_eq!(result.total, 0);
        assert_eq!(result.passed, 0);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_invalid_packet_spec() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Bad spec".to_string(),
                packet: "invalid_field=123".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_action() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Bad action".to_string(),
                packet: "ethertype=0x0800".to_string(),
                expect_action: "forward".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors);
        assert!(result.is_err());
    }

    // ---- Format tests ----

    #[test]
    fn test_text_all_pass() {
        let result = TestRunResult {
            cases: vec![
                TestCaseResult {
                    name: "test1".to_string(),
                    passed: true,
                    expected_action: Action::Pass,
                    actual_action: Action::Pass,
                    expected_rule: None,
                    actual_rule: Some("r1".to_string()),
                    is_default: false,
                    failure_reason: None,
                },
            ],
            total: 1,
            passed: 1,
            failed: 0,
        };
        let text = format_text(&result);
        assert!(text.contains("PASS"));
        assert!(text.contains("1/1 tests passed"));
        assert!(!text.contains("FAIL"));
    }

    #[test]
    fn test_text_with_failure() {
        let result = TestRunResult {
            cases: vec![
                TestCaseResult {
                    name: "bad_test".to_string(),
                    passed: false,
                    expected_action: Action::Drop,
                    actual_action: Action::Pass,
                    expected_rule: None,
                    actual_rule: Some("r1".to_string()),
                    is_default: false,
                    failure_reason: Some("expected action 'drop' but got 'pass'".to_string()),
                },
            ],
            total: 1,
            passed: 0,
            failed: 1,
        };
        let text = format_text(&result);
        assert!(text.contains("FAIL"));
        assert!(text.contains("expected action"));
        assert!(text.contains("0/1 tests passed"));
        assert!(text.contains("1 failed"));
    }

    #[test]
    fn test_json_pass() {
        let result = TestRunResult {
            cases: vec![
                TestCaseResult {
                    name: "t1".to_string(),
                    passed: true,
                    expected_action: Action::Pass,
                    actual_action: Action::Pass,
                    expected_rule: Some("r1".to_string()),
                    actual_rule: Some("r1".to_string()),
                    is_default: false,
                    failure_reason: None,
                },
            ],
            total: 1,
            passed: 1,
            failed: 0,
        };
        let json = format_json(&result);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["total"], 1);
        assert_eq!(json["passed"], 1);
        assert_eq!(json["failed"], 0);
        assert_eq!(json["cases"][0]["passed"], true);
        assert_eq!(json["cases"][0]["expected_rule"], "r1");
    }

    #[test]
    fn test_json_fail() {
        let result = TestRunResult {
            cases: vec![
                TestCaseResult {
                    name: "bad".to_string(),
                    passed: false,
                    expected_action: Action::Drop,
                    actual_action: Action::Pass,
                    expected_rule: None,
                    actual_rule: None,
                    is_default: true,
                    failure_reason: Some("wrong".to_string()),
                },
            ],
            total: 1,
            passed: 0,
            failed: 1,
        };
        let json = format_json(&result);
        assert_eq!(json["status"], "fail");
        assert_eq!(json["failed"], 1);
        assert!(json["cases"][0]["failure_reason"].as_str().unwrap().contains("wrong"));
    }

    #[test]
    fn test_accept_alias() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Accept alias".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=80".to_string(),
                expect_action: "accept".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.passed, 1);
    }

    #[test]
    fn test_deny_alias() {
        let config = web_config();
        let vectors = vec![
            TestVector {
                name: "Deny alias".to_string(),
                packet: "ethertype=0x0800,ip_protocol=6,dst_port=22".to_string(),
                expect_action: "deny".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.passed, 1);
    }

    // ---- YAML parsing test ----

    #[test]
    fn test_parse_yaml() {
        let yaml = r#"
test_vectors:
  - name: "HTTP"
    packet: "ethertype=0x0800,ip_protocol=6,dst_port=80"
    expect_action: pass
    expect_rule: allow_http
  - name: "SSH blocked"
    packet: "ethertype=0x0800,ip_protocol=6,dst_port=22"
    expect_action: drop
"#;
        let file: TestVectorFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.test_vectors.len(), 2);
        assert_eq!(file.test_vectors[0].name, "HTTP");
        assert_eq!(file.test_vectors[0].expect_action, "pass");
        assert_eq!(file.test_vectors[0].expect_rule, Some("allow_http".to_string()));
        assert_eq!(file.test_vectors[1].expect_rule, None);
    }

    #[test]
    fn test_parse_yaml_minimal() {
        let yaml = r#"
test_vectors:
  - name: "test"
    packet: "ethertype=0x0800"
    expect_action: drop
"#;
        let file: TestVectorFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.test_vectors.len(), 1);
        assert!(file.test_vectors[0].expect_rule.is_none());
    }

    // ---- Pipeline test ----

    #[test]
    fn test_pipeline_config() {
        let mut mc = MatchCriteria::default();
        mc.ethertype = Some("0x0800".to_string());

        let stage = crate::model::PipelineStage {
            name: "classify".to_string(),
            rules: vec![
                make_rule("allow_ipv4", 100, Action::Pass, mc.clone()),
            ],
            default_action: Action::Drop,
            next_table: None,
        };

        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![],
                conntrack: None,
                tables: Some(vec![stage]),
            },
        };

        let vectors = vec![
            TestVector {
                name: "IPv4 passes pipeline".to_string(),
                packet: "ethertype=0x0800".to_string(),
                expect_action: "pass".to_string(),
                expect_rule: None,
            },
        ];
        let result = run_test_vectors(&config, &vectors).unwrap();
        assert_eq!(result.passed, 1);
    }
}
