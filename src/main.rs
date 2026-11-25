use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use gre_controller::config;

/// A declarative GRE tunnel controller for Linux.
#[derive(Debug, Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, global = true, value_name = "PATH", default_value = config::DEFAULT_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration without modifying the kernel or performing DNS lookups.
    Validate,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate => validate(&cli.config),
    }
}

fn validate(path: &Path) -> ExitCode {
    match config::load(path) {
        Ok(config) => {
            println!(
                "configuration is valid ({} tunnel(s))",
                config.tunnels.len()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
