// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

mod alloc;
mod build_info;
mod check_config;
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
use heimdall_runtime::{BuildInfo, Drain, state::RunningState};

use crate::cli::{CheckFormat, Cli, Command, LogFormat, LogLevel};

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

                // Build observability bind address; abort if non-loopback without mTLS (OPS-028).
                let obs_addr = guard.config.observability.metrics_addr;
                let obs_port = guard.config.observability.metrics_port;
                if !obs_addr.is_loopback()
                    && (guard.config.admin.tls_cert.is_none() || guard.config.admin.tls_key.is_none())
                {
                    tracing::error!(
                        addr = %obs_addr,
                        "observability bind address is non-loopback but mTLS is not configured; \
                         set [admin] tls_cert and tls_key or bind to 127.0.0.1"
                    );
                    std::process::exit(1);
                }
                let obs_bind_addr = std::net::SocketAddr::new(obs_addr, obs_port);

                // Boot phase 14: drop privileges to heimdall user (BIN-041..BIN-043).
                if let Err(e) = privdrop::apply(&guard.config) {
                    tracing::error!(error = %e, "privilege drop failed");
                    std::process::exit(1);
                }

                let info = BuildInfo {
                    version:    build_info::VERSION,
                    git_commit: build_info::GIT_COMMIT,
                    build_date: build_info::BUILD_DATE,
                    rustc:      build_info::RUSTC,
                    target:     build_info::TARGET,
                    profile:    build_info::PROFILE,
                    features:   build_info::FEATURES,
                };
                signals::supervision_loop(drain, state, config_path, grace_secs, bound, admin_uds, obs_bind_addr, info).await
            });

            std::process::exit(exit_code);
        }
        Command::CheckConfig(args) => {
            // check-config uses pretty logging unless JSON output is requested.
            if args.format == CheckFormat::Plain {
                logging::init(LogLevel::Warn, LogFormat::Pretty);
            }

            let loader = match crate::config::load(&args.config) {
                Ok(l) => l,
                Err(e) => {
                    match args.format {
                        CheckFormat::Json => println!(
                            r#"{{"ok":false,"checks":[{{"name":"toml_parse","ok":false,"message":"{}"}}]}}"#,
                            check_config::json_escape_str(&e.to_string()),
                        ),
                        CheckFormat::Plain => eprintln!("[FAIL] toml_parse: {e}"),
                    }
                    std::process::exit(2);
                }
            };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for check-config");

            let report = rt.block_on(async {
                let guard = loader.current();
                check_config::run(&**guard).await
            });

            match args.format {
                CheckFormat::Plain => report.print_plain(),
                CheckFormat::Json => report.print_json(),
            }

            std::process::exit(report.exit_code);
        }
        Command::Version => {
            print_version();
            std::process::exit(0);
        }
    }
}

fn print_version() {
    println!(
        "heimdall {} ({} {}) [{}] {}",
        build_info::VERSION,
        build_info::GIT_COMMIT,
        build_info::BUILD_DATE,
        build_info::PROFILE,
        build_info::RUSTC,
    );
}
