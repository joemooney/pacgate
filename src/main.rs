mod model;
mod loader;
mod verilog_gen;
mod cocotb_gen;

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "flippy", version, about = "FPGA Layer 2 Packet Filter Switch")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile YAML rules into Verilog RTL and cocotb test bench
    Compile {
        /// Path to the YAML rules file
        rules: PathBuf,

        /// Output directory for generated files
        #[arg(short, long, default_value = "gen")]
        output: PathBuf,

        /// Templates directory
        #[arg(short, long, default_value = "templates")]
        templates: PathBuf,
    },
    /// Validate YAML rules without generating output
    Validate {
        /// Path to the YAML rules file
        rules: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { rules, output, templates } => {
            log::info!("Compiling rules from {}", rules.display());
            let config = loader::load_rules(&rules)?;
            println!("Loaded {} rules from {}", config.flippy.rules.len(), rules.display());

            // Generate Verilog
            verilog_gen::generate(&config, &templates, &output)?;
            println!("Generated Verilog RTL in {}/rtl/", output.display());

            // Generate cocotb tests
            cocotb_gen::generate(&config, &templates, &output)?;
            println!("Generated cocotb tests in {}/tb/", output.display());

            println!("Compilation complete.");
        }
        Commands::Validate { rules } => {
            let config = loader::load_rules(&rules)?;
            println!("Valid: {} rules loaded from {}", config.flippy.rules.len(), rules.display());
        }
    }

    Ok(())
}
