// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

mod alloc;
mod cli;
mod config;
mod listeners;
mod logging;
mod privdrop;
mod redis_boot;
mod rlimit;
mod roles;
mod runtime;
mod signals;

use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser as _;
use heimdall_runtime::{Drain, state::RunningState};

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

            let config_arc = {
                let guard = loader.current();
                Arc::clone(&guard)
            };
            let worker_threads = config_arc.server.worker_threads;

            // Boot phase 7: start Tokio runtime (BIN-016..BIN-019).
            let (rt, _rt_info) = runtime::start(worker_threads).unwrap_or_else(|e| {
                tracing::error!(error = %e, "Failed to start Tokio runtime");
                std::process::exit(1);
            });

            // Build initial running state and drain primitive.
            let state = Arc::new(ArcSwap::new(Arc::new(RunningState::initial(config_arc))));
            let drain = Drain::new();
            let config_path = args.config.clone();

            // Boot phases 10..17: run the async supervision loop (BIN-015 steps 10..17).
            let exit_code = rt.block_on(async {
                // Boot phase 12: bind all configured transport listeners (BIN-022).
                let guard = state.load();
                let grace_secs = guard.config.server.drain_grace_secs;
                let bound = listeners::bind_all(&guard.config).await.unwrap_or_else(|e| {
                    tracing::error!(error = %e, "listener bind failed");
                    std::process::exit(1);
                });

                // Boot phase 9: connect Redis pool if persistence is configured (BIN-050).
                let _redis = redis_boot::connect(&guard.config.persistence).await;

                // Boot phase 13: apply OS resource limits (BIN-036..BIN-038, THREAT-068).
                rlimit::apply(&guard.config.rlimit);

                // Capture admin UDS path before privilege drop consumes the guard.
                let admin_uds = guard.config.admin.uds_path.clone();

                // Boot phase 14: drop privileges to heimdall user (BIN-041..BIN-043).
                if let Err(e) = privdrop::apply(&guard.config) {
                    tracing::error!(error = %e, "privilege drop failed");
                    std::process::exit(1);
                }

                signals::supervision_loop(drain, state, config_path, grace_secs, bound, admin_uds).await
            });

            std::process::exit(exit_code);
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
