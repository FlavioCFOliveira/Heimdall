// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

mod cli;
mod logging;

use clap::Parser as _;

use crate::cli::{Cli, Command, LogFormat, LogLevel};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Start(args) => {
            logging::init(args.log_level, args.log_format);
            // Boot sequence implementation: Sprint 46 tasks #457..#465, #537..#556, #569.
            // Placeholder: exits 0 until the full boot sequence is wired.
            std::process::exit(0);
        }
        Command::CheckConfig(args) => {
            logging::init(LogLevel::Info, LogFormat::Pretty);
            let _ = args;
            // Deep validation implementation: Sprint 46 task #556.
            // Placeholder: exits 0 until the full check-config pipeline is wired.
            std::process::exit(0);
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
