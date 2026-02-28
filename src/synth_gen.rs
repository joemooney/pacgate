//! Synthesis Project File Generation for Yosys and Vivado
//!
//! Generates synthesis scripts, constraint files, and Makefiles
//! for FPGA synthesis targeting Xilinx 7-series, iCE40, and ECP5.

use std::path::Path;
use anyhow::{Context, Result};
use tera::Tera;

/// Target synthesis tool
#[derive(Debug, Clone)]
pub enum SynthTarget {
    Yosys { device: YosysDevice },
    Vivado { part: String },
}

/// Yosys-supported device families
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum YosysDevice {
    Artix7,
    Ice40,
    Ecp5,
}

impl YosysDevice {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "artix7" | "xc7" | "xilinx" => Ok(YosysDevice::Artix7),
            "ice40" | "lattice-ice40" => Ok(YosysDevice::Ice40),
            "ecp5" | "lattice-ecp5" => Ok(YosysDevice::Ecp5),
            _ => anyhow::bail!("Unknown Yosys device '{}': expected artix7, ice40, or ecp5", s),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            YosysDevice::Artix7 => "artix7",
            YosysDevice::Ice40 => "ice40",
            YosysDevice::Ecp5 => "ecp5",
        }
    }
}

/// Synthesis configuration
#[derive(Debug, Clone)]
pub struct SynthConfig {
    pub target: SynthTarget,
    pub clock_mhz: f64,
    pub top_module: String,
    pub rtl_files: Vec<String>,
    pub has_axi: bool,
    pub has_counters: bool,
    pub has_conntrack: bool,
    pub has_rate_limit: bool,
    pub ports: u16,
}

/// Synthesis results parsed from logs
#[derive(Debug, Clone, serde::Serialize)]
pub struct SynthResults {
    pub tool: String,
    pub part: String,
    pub luts: Option<u64>,
    pub ffs: Option<u64>,
    pub brams: Option<u64>,
    pub dsps: Option<u64>,
    pub fmax_mhz: Option<f64>,
    pub wns: Option<f64>,
    pub power_mw: Option<f64>,
}

/// Collect the list of RTL files for synthesis
pub fn collect_rtl_files(
    gen_dir: &Path,
    has_axi: bool,
    has_counters: bool,
    has_conntrack: bool,
    has_rate_limit: bool,
    _ports: u16,
) -> Vec<String> {
    collect_rtl_files_with_target(gen_dir, has_axi, has_counters, has_conntrack, has_rate_limit, _ports, "standalone")
}

pub fn collect_rtl_files_with_target(
    gen_dir: &Path,
    has_axi: bool,
    has_counters: bool,
    has_conntrack: bool,
    has_rate_limit: bool,
    _ports: u16,
    target: &str,
) -> Vec<String> {
    let mut files = Vec::new();

    // Hand-written RTL
    files.push("rtl/frame_parser.v".to_string());

    if has_axi {
        files.push("rtl/axi_stream_adapter.v".to_string());
        files.push("rtl/store_forward_fifo.v".to_string());
        files.push("rtl/packet_filter_axi_top.v".to_string());
    }

    if has_counters {
        files.push("rtl/rule_counters.v".to_string());
        files.push("rtl/axi_lite_csr.v".to_string());
    }

    if has_conntrack {
        files.push("rtl/conntrack_table.v".to_string());
    }

    if has_rate_limit {
        files.push("rtl/rate_limiter.v".to_string());
    }

    // Platform target: width converters
    let is_platform = target == "opennic" || target == "corundum";
    if is_platform {
        files.push("rtl/axis_512_to_8.v".to_string());
        files.push("rtl/axis_8_to_512.v".to_string());
    }

    // Generated RTL (includes platform wrappers since they are generated into gen/rtl/)
    let rtl_dir = gen_dir.join("rtl");
    if rtl_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&rtl_dir) {
            let mut gen_files: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.ends_with(".v")
                        && name != "axi_stream_adapter.v"
                        && name != "store_forward_fifo.v"
                        && name != "packet_filter_axi_top.v"
                        && name != "rule_counters.v"
                        && name != "axi_lite_csr.v"
                        && name != "conntrack_table.v"
                        && name != "rate_limiter.v"
                        && name != "axis_512_to_8.v"
                        && name != "axis_8_to_512.v"
                })
                .map(|e| format!("gen/rtl/{}", e.file_name().to_string_lossy()))
                .collect();
            gen_files.sort();
            files.extend(gen_files);
        }
    }

    files
}

/// Generate Yosys synthesis script
pub fn generate_yosys_script(
    config: &SynthConfig,
    templates_dir: &Path,
    output_dir: &Path,
) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let device = match &config.target {
        SynthTarget::Yosys { device } => device.name().to_string(),
        _ => "artix7".to_string(),
    };

    let mut ctx = tera::Context::new();
    ctx.insert("device", &device);
    ctx.insert("top_module", &config.top_module);
    ctx.insert("rtl_files", &config.rtl_files);
    ctx.insert("clock_mhz", &config.clock_mhz);

    let rendered = tera.render("synth_yosys.ys.tera", &ctx)?;

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(output_dir.join("synth.ys"), &rendered)?;
    log::info!("Generated synth.ys");

    Ok(())
}

/// Generate Vivado TCL project script
pub fn generate_vivado_tcl(
    config: &SynthConfig,
    templates_dir: &Path,
    output_dir: &Path,
) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let part = match &config.target {
        SynthTarget::Vivado { part } => part.clone(),
        _ => "xc7a35tcpg236-1".to_string(),
    };

    let mut ctx = tera::Context::new();
    ctx.insert("part", &part);
    ctx.insert("top_module", &config.top_module);
    ctx.insert("rtl_files", &config.rtl_files);
    ctx.insert("has_xdc", &true);

    let rendered = tera.render("synth_vivado.tcl.tera", &ctx)?;

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(output_dir.join("synth.tcl"), &rendered)?;
    log::info!("Generated synth.tcl");

    Ok(())
}

/// Generate XDC constraint file
pub fn generate_xdc_constraints(
    config: &SynthConfig,
    templates_dir: &Path,
    output_dir: &Path,
) -> Result<()> {
    let glob = format!("{}/**/*.tera", templates_dir.display());
    let tera = Tera::new(&glob)
        .with_context(|| format!("Failed to load templates from {}", templates_dir.display()))?;

    let part = match &config.target {
        SynthTarget::Vivado { part } => part.clone(),
        SynthTarget::Yosys { device } => format!("{:?}", device),
    };

    let clock_period_ns = 1000.0 / config.clock_mhz;

    let mut ctx = tera::Context::new();
    ctx.insert("part", &part);
    ctx.insert("clock_mhz", &config.clock_mhz);
    ctx.insert("clock_period_ns", &format!("{:.3}", clock_period_ns));
    ctx.insert("has_axi", &config.has_axi);

    let rendered = tera.render("synth_xdc.tera", &ctx)?;

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(output_dir.join("constraints.xdc"), &rendered)?;
    log::info!("Generated constraints.xdc");

    Ok(())
}

/// Generate Makefile with synthesis targets
pub fn generate_synth_makefile(
    config: &SynthConfig,
    output_dir: &Path,
) -> Result<()> {
    let mut makefile = String::new();
    makefile.push_str("# PacGate Synthesis Makefile\n");
    makefile.push_str("# Generated by pacgate — do not edit\n\n");

    makefile.push_str("TOP ?= ");
    makefile.push_str(&config.top_module);
    makefile.push('\n');

    makefile.push_str("RTL_FILES = ");
    makefile.push_str(&config.rtl_files.join(" \\\n    "));
    makefile.push_str("\n\n");

    // Yosys target
    makefile.push_str(".PHONY: yosys vivado clean\n\n");
    makefile.push_str("yosys: synth.ys $(RTL_FILES)\n");
    makefile.push_str("\tyosys synth.ys 2>&1 | tee yosys.log\n\n");

    // Vivado target
    makefile.push_str("vivado: synth.tcl $(RTL_FILES)\n");
    makefile.push_str("\tvivado -mode batch -source synth.tcl 2>&1 | tee vivado.log\n\n");

    // Clean
    makefile.push_str("clean:\n");
    makefile.push_str("\trm -rf vivado_project *.log *.json *.edif *.rpt\n");

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(output_dir.join("Makefile"), &makefile)?;
    log::info!("Generated synthesis Makefile");

    Ok(())
}

/// Parse Yosys synthesis log for resource utilization
pub fn parse_yosys_log(path: &Path) -> Result<SynthResults> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Yosys log: {}", path.display()))?;

    let mut results = SynthResults {
        tool: "yosys".to_string(),
        part: String::new(),
        luts: None,
        ffs: None,
        brams: None,
        dsps: None,
        fmax_mhz: None,
        wns: None,
        power_mw: None,
    };

    for line in content.lines() {
        let line = line.trim();
        // Yosys stat output format: "   Number of cells:  1234"
        if line.contains("Number of LUT") || line.contains("$lut") || line.contains("SB_LUT4") || line.contains("LUT") {
            if let Some(num) = extract_last_number(line) {
                results.luts = Some(num);
            }
        }
        if line.contains("Number of DFF") || line.contains("$dff") || line.contains("SB_DFF") {
            if let Some(num) = extract_last_number(line) {
                results.ffs = Some(num);
            }
        }
        if line.contains("BRAM") || line.contains("$mem") || line.contains("SB_RAM") {
            if let Some(num) = extract_last_number(line) {
                results.brams = Some(num);
            }
        }
        if line.contains("DSP") || line.contains("$mul") {
            if let Some(num) = extract_last_number(line) {
                results.dsps = Some(num);
            }
        }
    }

    Ok(results)
}

/// Parse Vivado utilization report
pub fn parse_vivado_utilization(path: &Path) -> Result<SynthResults> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Vivado report: {}", path.display()))?;

    let mut results = SynthResults {
        tool: "vivado".to_string(),
        part: String::new(),
        luts: None,
        ffs: None,
        brams: None,
        dsps: None,
        fmax_mhz: None,
        wns: None,
        power_mw: None,
    };

    for line in content.lines() {
        let line = line.trim();
        // Vivado utilization format: "| Slice LUTs | 1234 | ..."
        if line.contains("Slice LUTs") && !line.contains("*") {
            if let Some(num) = extract_table_number(line) {
                results.luts = Some(num);
            }
        }
        if line.contains("Slice Registers") || line.contains("Register as Flip Flop") {
            if let Some(num) = extract_table_number(line) {
                results.ffs = Some(num);
            }
        }
        if line.contains("Block RAM Tile") {
            if let Some(num) = extract_table_number(line) {
                results.brams = Some(num);
            }
        }
        if line.contains("DSPs") || line.contains("DSP48") {
            if let Some(num) = extract_table_number(line) {
                results.dsps = Some(num);
            }
        }
        // Timing: WNS (Worst Negative Slack)
        if line.contains("WNS") && line.contains("ns") {
            if let Some(val) = extract_float(line) {
                results.wns = Some(val);
            }
        }
    }

    Ok(results)
}

fn extract_last_number(line: &str) -> Option<u64> {
    line.split_whitespace()
        .rev()
        .find_map(|w| w.parse::<u64>().ok())
}

fn extract_table_number(line: &str) -> Option<u64> {
    // Vivado table format: "| name | value | available | util% |"
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() >= 3 {
        parts[2].trim().parse::<u64>().ok()
    } else {
        None
    }
}

fn extract_float(line: &str) -> Option<f64> {
    line.split_whitespace()
        .find_map(|w| w.parse::<f64>().ok())
}

/// Generate all synthesis project files
pub fn generate_synth_project(
    config: &SynthConfig,
    templates_dir: &Path,
    output_dir: &Path,
) -> Result<Vec<String>> {
    let synth_dir = output_dir.join("synth");
    std::fs::create_dir_all(&synth_dir)?;

    let mut generated = Vec::new();

    match &config.target {
        SynthTarget::Yosys { .. } => {
            generate_yosys_script(config, templates_dir, &synth_dir)?;
            generated.push("synth/synth.ys".to_string());
        }
        SynthTarget::Vivado { .. } => {
            generate_vivado_tcl(config, templates_dir, &synth_dir)?;
            generated.push("synth/synth.tcl".to_string());
        }
    }

    generate_xdc_constraints(config, templates_dir, &synth_dir)?;
    generated.push("synth/constraints.xdc".to_string());

    generate_synth_makefile(config, &synth_dir)?;
    generated.push("synth/Makefile".to_string());

    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yosys_device_from_str() {
        assert_eq!(YosysDevice::from_str("artix7").unwrap(), YosysDevice::Artix7);
        assert_eq!(YosysDevice::from_str("ice40").unwrap(), YosysDevice::Ice40);
        assert_eq!(YosysDevice::from_str("ecp5").unwrap(), YosysDevice::Ecp5);
        assert!(YosysDevice::from_str("invalid").is_err());
    }

    #[test]
    fn collect_rtl_files_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let rtl_dir = tmp.path().join("rtl");
        std::fs::create_dir_all(&rtl_dir).unwrap();
        std::fs::write(rtl_dir.join("packet_filter_top.v"), "module packet_filter_top;").unwrap();
        std::fs::write(rtl_dir.join("rule_match_0.v"), "module rule_match_0;").unwrap();

        let files = collect_rtl_files(tmp.path(), false, false, false, false, 1);
        assert!(files.contains(&"rtl/frame_parser.v".to_string()));
        assert!(files.iter().any(|f| f.contains("packet_filter_top.v")));
        assert!(files.iter().any(|f| f.contains("rule_match_0.v")));
    }

    #[test]
    fn collect_rtl_files_with_axi() {
        let tmp = tempfile::tempdir().unwrap();
        let files = collect_rtl_files(tmp.path(), true, true, true, true, 1);
        assert!(files.contains(&"rtl/axi_stream_adapter.v".to_string()));
        assert!(files.contains(&"rtl/rule_counters.v".to_string()));
        assert!(files.contains(&"rtl/conntrack_table.v".to_string()));
        assert!(files.contains(&"rtl/rate_limiter.v".to_string()));
    }

    #[test]
    fn generate_yosys_script_artix7() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Yosys { device: YosysDevice::Artix7 },
            clock_mhz: 125.0,
            top_module: "packet_filter_top".to_string(),
            rtl_files: vec!["rtl/frame_parser.v".to_string(), "gen/rtl/packet_filter_top.v".to_string()],
            has_axi: false,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_yosys_script(&config, Path::new("templates"), tmp.path()).unwrap();
        let script = std::fs::read_to_string(tmp.path().join("synth.ys")).unwrap();
        assert!(script.contains("synth_xilinx"), "should use synth_xilinx for artix7");
        assert!(script.contains("packet_filter_top"), "should reference top module");
        assert!(script.contains("frame_parser.v"), "should include RTL files");
    }

    #[test]
    fn generate_yosys_script_ice40() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Yosys { device: YosysDevice::Ice40 },
            clock_mhz: 48.0,
            top_module: "packet_filter_top".to_string(),
            rtl_files: vec!["rtl/frame_parser.v".to_string()],
            has_axi: false,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_yosys_script(&config, Path::new("templates"), tmp.path()).unwrap();
        let script = std::fs::read_to_string(tmp.path().join("synth.ys")).unwrap();
        assert!(script.contains("synth_ice40"), "should use synth_ice40");
    }

    #[test]
    fn generate_vivado_tcl_test() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Vivado { part: "xc7a35tcpg236-1".to_string() },
            clock_mhz: 125.0,
            top_module: "packet_filter_top".to_string(),
            rtl_files: vec!["rtl/frame_parser.v".to_string()],
            has_axi: false,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_vivado_tcl(&config, Path::new("templates"), tmp.path()).unwrap();
        let tcl = std::fs::read_to_string(tmp.path().join("synth.tcl")).unwrap();
        assert!(tcl.contains("xc7a35tcpg236-1"), "should contain part number");
        assert!(tcl.contains("create_project"), "should create Vivado project");
    }

    #[test]
    fn generate_xdc_test() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Vivado { part: "xc7a35tcpg236-1".to_string() },
            clock_mhz: 125.0,
            top_module: "packet_filter_top".to_string(),
            rtl_files: vec![],
            has_axi: false,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_xdc_constraints(&config, Path::new("templates"), tmp.path()).unwrap();
        let xdc = std::fs::read_to_string(tmp.path().join("constraints.xdc")).unwrap();
        assert!(xdc.contains("create_clock"), "should have clock constraint");
        assert!(xdc.contains("8.000"), "125 MHz = 8.000ns period");
    }

    #[test]
    fn generate_xdc_with_axi() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Vivado { part: "xc7a35tcpg236-1".to_string() },
            clock_mhz: 125.0,
            top_module: "packet_filter_axi_top".to_string(),
            rtl_files: vec![],
            has_axi: true,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_xdc_constraints(&config, Path::new("templates"), tmp.path()).unwrap();
        let xdc = std::fs::read_to_string(tmp.path().join("constraints.xdc")).unwrap();
        assert!(xdc.contains("s_axis_tdata"), "should have AXI constraints");
    }

    #[test]
    fn generate_makefile_test() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SynthConfig {
            target: SynthTarget::Yosys { device: YosysDevice::Artix7 },
            clock_mhz: 125.0,
            top_module: "packet_filter_top".to_string(),
            rtl_files: vec!["rtl/frame_parser.v".to_string()],
            has_axi: false,
            has_counters: false,
            has_conntrack: false,
            has_rate_limit: false,
            ports: 1,
        };

        generate_synth_makefile(&config, tmp.path()).unwrap();
        let makefile = std::fs::read_to_string(tmp.path().join("Makefile")).unwrap();
        assert!(makefile.contains("yosys:"), "should have yosys target");
        assert!(makefile.contains("vivado:"), "should have vivado target");
        assert!(makefile.contains("clean:"), "should have clean target");
    }

    #[test]
    fn parse_yosys_log_test() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("yosys.log");
        std::fs::write(&log_path, r#"
   Number of cells:    1234
     $lut              500
     SB_LUT4           500
     $dff              200
   Number of BRAM:     4
   Number of DSP:      0
"#).unwrap();

        let results = parse_yosys_log(&log_path).unwrap();
        assert_eq!(results.tool, "yosys");
        assert!(results.luts.is_some());
        assert!(results.ffs.is_some());
    }

    #[test]
    fn parse_vivado_utilization_test() {
        let tmp = tempfile::tempdir().unwrap();
        let rpt_path = tmp.path().join("utilization.rpt");
        std::fs::write(&rpt_path, r#"
+-------------------------+------+-------+-----------+-------+
| Site Type               | Used | Fixed | Available | Util% |
+-------------------------+------+-------+-----------+-------+
| Slice LUTs              | 450  |     0 |     20800 |  2.16 |
| Slice Registers         | 200  |     0 |     41600 |  0.48 |
| Block RAM Tile          |   2  |     0 |        50 |  4.00 |
| DSPs                    |   0  |     0 |        90 |  0.00 |
+-------------------------+------+-------+-----------+-------+
"#).unwrap();

        let results = parse_vivado_utilization(&rpt_path).unwrap();
        assert_eq!(results.tool, "vivado");
        assert_eq!(results.luts, Some(450));
        assert_eq!(results.ffs, Some(200));
        assert_eq!(results.brams, Some(2));
        assert_eq!(results.dsps, Some(0));
    }

    #[test]
    fn extract_last_number_works() {
        assert_eq!(extract_last_number("Number of cells: 1234"), Some(1234));
        assert_eq!(extract_last_number("no numbers here"), None);
    }

    #[test]
    fn synth_results_serialize() {
        let results = SynthResults {
            tool: "yosys".to_string(),
            part: "xc7a35t".to_string(),
            luts: Some(500),
            ffs: Some(200),
            brams: None,
            dsps: None,
            fmax_mhz: None,
            wns: None,
            power_mw: None,
        };
        let json = serde_json::to_value(&results).unwrap();
        assert_eq!(json["tool"], "yosys");
        assert_eq!(json["luts"], 500);
    }
}
