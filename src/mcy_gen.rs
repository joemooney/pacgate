//! MCY (Mutation Cover with Yosys) Configuration Generator
//!
//! Generates MCY configuration files for Verilog-level mutation testing.
//! MCY uses Yosys to inject mutations into synthesized netlists and
//! verifies whether existing cocotb tests detect them.

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use tera::Tera;

use crate::model::FilterConfig;

/// Result of MCY configuration generation
#[derive(Debug, serde::Serialize)]
pub struct McyGenResult {
    pub config_path: PathBuf,
    pub script_path: PathBuf,
    pub mutation_count: usize,
    pub rtl_files: Vec<String>,
}

/// Generate MCY configuration file and test runner script
pub fn generate_mcy_config(
    _config: &FilterConfig,
    templates_dir: &Path,
    output_dir: &Path,
    rtl_dir: &Path,
    tb_dir: &Path,
) -> Result<McyGenResult> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let mcy_dir = output_dir.join("mcy");
    std::fs::create_dir_all(&mcy_dir)?;

    // Collect RTL files
    let mut rtl_files: Vec<String> = Vec::new();

    // Add hand-written frame parser
    let frame_parser = Path::new("rtl/frame_parser.v");
    if frame_parser.exists() {
        rtl_files.push(std::fs::canonicalize(frame_parser)
            .unwrap_or_else(|_| frame_parser.to_path_buf())
            .to_string_lossy().to_string());
    } else {
        rtl_files.push("../../rtl/frame_parser.v".to_string());
    }

    // Add generated RTL files
    if rtl_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(rtl_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "v").unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            rtl_files.push(std::fs::canonicalize(entry.path())
                .unwrap_or_else(|_| entry.path())
                .to_string_lossy().to_string());
        }
    }

    let mutation_count = 100; // Default number of mutations to enumerate

    // Render MCY config
    {
        let mut ctx = tera::Context::new();
        ctx.insert("mutation_count", &mutation_count);
        ctx.insert("rtl_files", &rtl_files);
        ctx.insert("top_module", "packet_filter_top");

        let rendered = tera.render("mcy.cfg.tera", &ctx)?;
        std::fs::write(mcy_dir.join("mcy.cfg"), &rendered)?;
        log::info!("Generated mcy/mcy.cfg");
    }

    // Render test mutation script
    {
        let mut ctx = tera::Context::new();
        let tb_path = std::fs::canonicalize(tb_dir)
            .unwrap_or_else(|_| tb_dir.to_path_buf());
        let rtl_path = std::fs::canonicalize(rtl_dir)
            .unwrap_or_else(|_| rtl_dir.to_path_buf());
        ctx.insert("tb_dir", &tb_path.to_string_lossy().to_string());
        ctx.insert("rtl_dir", &rtl_path.to_string_lossy().to_string());

        let rendered = tera.render("test_mutation.sh.tera", &ctx)?;
        let script_path = mcy_dir.join("test_mutation.sh");
        std::fs::write(&script_path, &rendered)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms)?;
        }

        log::info!("Generated mcy/test_mutation.sh");
    }

    Ok(McyGenResult {
        config_path: mcy_dir.join("mcy.cfg"),
        script_path: mcy_dir.join("test_mutation.sh"),
        mutation_count,
        rtl_files,
    })
}

/// Generate JSON report for MCY configuration
pub fn generate_mcy_report(result: &McyGenResult) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "config_path": result.config_path.to_string_lossy(),
        "script_path": result.script_path.to_string_lossy(),
        "mutation_count": result.mutation_count,
        "rtl_files_count": result.rtl_files.len(),
        "rtl_files": result.rtl_files,
        "instructions": "Run 'mcy mcy.cfg' in the gen/mcy/ directory to execute Verilog mutation testing."
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
                        rewrite: None,
                        mirror_port: None,
                        redirect_port: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        }
    }

    #[test]
    fn mcy_config_generation() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        let tb_dir = tmp.path().join("tb");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::create_dir_all(&tb_dir).unwrap();

        // Create a dummy RTL file
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module packet_filter_top; endmodule").unwrap();

        let result = generate_mcy_config(
            &config,
            Path::new("templates"),
            tmp.path(),
            &rtl_dir,
            &tb_dir,
        ).unwrap();

        assert!(result.config_path.exists(), "mcy.cfg should be generated");
        assert!(result.script_path.exists(), "test_mutation.sh should be generated");
        assert!(result.mutation_count > 0);
    }

    #[test]
    fn mcy_config_contains_rtl_files() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        let tb_dir = tmp.path().join("tb");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::create_dir_all(&tb_dir).unwrap();

        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module pft; endmodule").unwrap();
        std::fs::write(rtl_dir.join("rule_match_0.v"), "module rm0; endmodule").unwrap();

        let result = generate_mcy_config(
            &config,
            Path::new("templates"),
            tmp.path(),
            &rtl_dir,
            &tb_dir,
        ).unwrap();

        let cfg_content = std::fs::read_to_string(&result.config_path).unwrap();
        assert!(cfg_content.contains("packet_filter_top"), "config should reference top module");
        assert!(cfg_content.contains("read_verilog"), "config should have read_verilog commands");
    }

    #[test]
    fn mcy_script_is_executable() {
        let config = make_test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        let tb_dir = tmp.path().join("tb");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::create_dir_all(&tb_dir).unwrap();

        let result = generate_mcy_config(
            &config,
            Path::new("templates"),
            tmp.path(),
            &rtl_dir,
            &tb_dir,
        ).unwrap();

        let script_content = std::fs::read_to_string(&result.script_path).unwrap();
        assert!(script_content.starts_with("#!/bin/bash"), "script should have bash shebang");
        assert!(script_content.contains("make"), "script should run make");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&result.script_path).unwrap().permissions();
            assert!(perms.mode() & 0o111 != 0, "script should be executable");
        }
    }

    #[test]
    fn mcy_report_json() {
        let result = McyGenResult {
            config_path: PathBuf::from("gen/mcy/mcy.cfg"),
            script_path: PathBuf::from("gen/mcy/test_mutation.sh"),
            mutation_count: 100,
            rtl_files: vec!["rtl/a.v".to_string(), "rtl/b.v".to_string()],
        };
        let report = generate_mcy_report(&result);
        assert_eq!(report["status"], "ok");
        assert_eq!(report["mutation_count"], 100);
        assert_eq!(report["rtl_files_count"], 2);
    }
}
