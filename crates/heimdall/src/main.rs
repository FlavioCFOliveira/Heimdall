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
use heimdall_runtime::{
    BuildInfo, Drain, QueryDispatcher, RedisStore, ZoneTransferHandler, state::RunningState,
};

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
                // Boot phase 11: assemble roles and build dispatcher (BIN-021).
                let guard = state.load();
                let grace_secs = guard.config.server.drain_grace_secs;

                let (dispatcher, xfr_handler, secondary_tasks, startup_notify_zones): (
                    Option<Arc<dyn QueryDispatcher + Send + Sync>>,
                    Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
                    Vec<roles::SecondaryZoneTask>,
                    Vec<heimdall_roles::auth::ZoneConfig>,
                ) = {
                    let data_dir = std::path::PathBuf::from("/var/lib/heimdall");
                    match roles::assemble(&guard.config, &data_dir) {
                        Ok(assembled) => {
                            let notify_zones = assembled.startup_notify_zones;
                            let xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>> =
                                assembled.auth.as_ref().map(|a| Arc::clone(a) as _);
                            let dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>> =
                                if let Some(auth_arc) = &assembled.auth {
                                    Some(Arc::clone(auth_arc) as _)
                                } else if let Some(rec) = assembled.recursive {
                                    Some(Arc::new(rec) as _)
                                } else if let Some(fwd) = assembled.forwarder {
                                    Some(Arc::new(fwd) as _)
                                } else {
                                    None
                                };
                            (dispatcher, xfr_handler, assembled.secondary_tasks, notify_zones)
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "role assembly failed");
                            std::process::exit(1);
                        }
                    }
                };

                // Boot phase 12: bind all configured transport listeners (BIN-022).
                let bound = listeners::bind_all(&guard.config, dispatcher, xfr_handler).await.unwrap_or_else(|e| {
                    tracing::error!(error = %e, "listener bind failed");
                    std::process::exit(1);
                });

                // Boot phase 9: connect Redis pool if persistence is configured (BIN-050).
                let redis_store: Option<Arc<RedisStore>> =
                    redis_boot::connect(&guard.config.persistence).await.map(Arc::new);

                // Emit startup NOTIFY to configured secondaries (RFC 1996 §3.7).
                // Each NOTIFY is sent in a detached task so the boot sequence
                // is not blocked by network latency or retries.
                for zone_cfg in startup_notify_zones {
                    tokio::spawn(async move {
                        // Extract the SOA serial from the in-memory zone file.
                        let serial = zone_cfg
                            .zone_file
                            .as_deref()
                            .and_then(|zf| {
                                use heimdall_core::rdata::RData;
                                use heimdall_core::record::Rtype;
                                zf.records.iter().find(|r| r.rtype == Rtype::Soa).and_then(
                                    |r| {
                                        if let RData::Soa { serial, .. } = &r.rdata {
                                            Some(*serial)
                                        } else {
                                            None
                                        }
                                    },
                                )
                            })
                            .unwrap_or(0);
                        for target in &zone_cfg.notify_secondaries {
                            if let Err(e) = heimdall_roles::auth::notify::send_notify(
                                &zone_cfg.apex,
                                serial,
                                *target,
                                zone_cfg.tsig_key.as_ref(),
                            )
                            .await
                            {
                                tracing::warn!(
                                    zone = %zone_cfg.apex,
                                    %target,
                                    error = %e,
                                    "startup NOTIFY failed"
                                );
                            }
                        }
                    });
                }

                // Spawn secondary refresh loops (RFC 1996 / RFC 1034 §3.7).
                // Each loop pulls zone data from the upstream primary and keeps
                // the in-memory zone file up to date.
                for task in secondary_tasks {
                    let zone_cfg = task.zone_config;
                    let notify_sig = task.notify_signal;
                    let auth_ref = Arc::clone(&task.auth_server);
                    let drain_ref = Arc::new(drain.clone());
                    let apex_wire =
                        zone_cfg.apex.as_wire_bytes().to_ascii_lowercase();
                    tokio::spawn(async move {
                        let on_update: Arc<
                            dyn Fn(Arc<heimdall_core::zone::ZoneFile>) + Send + Sync,
                        > = Arc::new(move |zf| {
                            auth_ref.update_zone_file(&apex_wire, zf);
                        });
                        if let Err(e) = heimdall_roles::auth::secondary::run_secondary_refresh_loop_with_notify(
                            zone_cfg,
                            drain_ref,
                            notify_sig,
                            on_update,
                        )
                        .await
                        {
                            tracing::warn!(error = %e, "secondary refresh loop exited with error");
                        }
                    });
                }

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
                signals::supervision_loop(drain, state, config_path, grace_secs, bound, admin_uds, obs_bind_addr, info, redis_store).await
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
        "heimdall {} ({} {}) {} [{}] features={} {}",
        build_info::VERSION,
        build_info::GIT_COMMIT,
        build_info::BUILD_DATE,
        build_info::TARGET,
        build_info::PROFILE,
        build_info::FEATURES,
        build_info::RUSTC,
    );
}
