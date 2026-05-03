// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

mod cli;
mod config;
mod logging;
mod runtime;

use clap::Parser as _;

use crate::cli::{Cli, Command, LogFormat, LogLevel};
use crate::config::print_summary;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Start(args) => {
            // Boot phase 4: initialise logging (BIN-015 step 4).
            logging::init(args.log_level, args.log_format);

            // Boot phase 3: parse and validate configuration (BIN-015 step 3).
            let loader = crate::config::load(&args.config).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(2);
            });

            let config_guard = loader.current();
            let worker_threads = config_guard.server.worker_threads;

            // Boot phase 7: start Tokio runtime (BIN-016..BIN-019).
            let (_rt, _rt_info) = runtime::start(worker_threads).unwrap_or_else(|e| {
                tracing::error!(error = %e, "Failed to start Tokio runtime");
                std::process::exit(1);
            });

            // Boot sequence continues in Sprint 46 tasks #459..#465, #537..#556, #569.
            // Placeholder: exits 0 until the full boot sequence is wired.
            std::process::exit(0);
        }
        Command::CheckConfig(args) => {
            // check-config uses pretty logging for interactive use.
            logging::init(LogLevel::Info, LogFormat::Pretty);

            match crate::config::load(&args.config) {
                Ok(loader) => {
                    let guard = loader.current();
                    print_summary(&guard);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        Command::Version => {
            print_version();
            std::process::exit(0);
        }
    }
}

fn print_version() {
    // Build-time metadata is embedded via vergen in build.rs (Sprint 46 task #555).
    // Until that task is complete, fall back to the Cargo package version.
    println!("heimdall {}", env!("CARGO_PKG_VERSION"));
}
