use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use gre_controller::{config, logging, run};

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
    /// Reconcile the kernel with the configuration until stopped with SIGTERM or SIGINT.
    Run,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate => validate(&cli.config),
        Command::Run => run(&cli.config),
    }
}

fn run(path: &Path) -> ExitCode {
    logging::init();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!("cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run::run(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::FAILURE
        }
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
