// SPDX-License-Identifier: MIT

//! Signal handler installation and supervision loop (BIN-023-SIG..BIN-027-SIG).
//!
//! Installs handlers for SIGTERM, SIGINT, SIGHUP, SIGPIPE (ignored),
//! SIGUSR1, and SIGUSR2 (reserved / debug-logged).
//!
//! The supervision loop selects on SIGTERM/SIGINT and delegates reload to
//! `SighupReloader`. A second SIGTERM/SIGINT during drain forces fast shutdown.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use heimdall_runtime::{AdminRpcServer, BuildInfo, Drain, ObservabilityServer, RedisStore, SighupReloader, notify_extend_timeout_usec, notify_ready, notify_stopping, spawn_watchdog, state::RunningState};
use tracing::{debug, info, warn};

use crate::listeners::BoundListener;

/// Default grace timeout for the drain phase (BIN-048).
#[allow(dead_code)]
pub const DRAIN_GRACE_SECS: u64 = 30;

/// Run the supervision loop.
///
/// Spawns listener workers in the supervisor, installs the SIGHUP reload
/// handler, then waits for SIGTERM or SIGINT. On first signal, initiates
/// drain with `grace_secs`. A second signal forces immediate exit.
///
/// `admin_uds_path`: when `Some`, the admin-RPC UDS is bound and spawned
/// before the READY notification (BIN-052).
///
/// Returns the suggested process exit code (0 on clean shutdown, 1 on error).
#[allow(clippy::too_many_arguments)] // All parameters are required for this supervisor entry point.
pub async fn supervision_loop(
    drain: Drain,
    state: Arc<ArcSwap<RunningState>>,
    config_path: std::path::PathBuf,
    grace_secs: u64,
    listeners: Vec<BoundListener>,
    admin_uds_path: Option<std::path::PathBuf>,
    obs_bind_addr: std::net::SocketAddr,
    build_info: BuildInfo,
    redis_store: Option<Arc<RedisStore>>,
) -> i32 {
    let drain = Arc::new(drain);

    // Install SIGHUP reload handler (BIN-025-SIG, OPS-001..006).
    // On non-Unix platforms the SighupReloader is a no-op.
    let _reload_handle = {
        let reloader = SighupReloader::new(Arc::clone(&state), config_path);
        reloader.spawn()
    };

    // SIGPIPE is ignored by default in Tokio — Rust sets SA_RESETHAND=false for
    // SIGPIPE, so broken-pipe errors surface as io::Error returns (BIN-026-SIG).

    // Spawn listener workers (BIN-022). Listeners stop when drain.is_draining()
    // returns true, so no separate shutdown signal is needed.
    for listener in listeners {
        let label = listener.label();
        let drain_c = Arc::clone(&drain);
        tokio::spawn(async move {
            if let Err(e) = listener.run(drain_c).await {
                tracing::error!(transport = label, error = %e, "listener exited with error");
            }
        });
    }

    // Boot phase 13.5: bind admin-RPC UDS if configured (BIN-052, OPS-008).
    if let Some(uds_path) = admin_uds_path {
        let server = AdminRpcServer::new(&uds_path, Arc::clone(&state));
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!(error = %e, path = %uds_path.display(), "admin-RPC server exited");
            }
        });
    }

    // Bind HTTP observability endpoint (OPS-021..031, BIN-054).
    {
        let server = ObservabilityServer::new(obs_bind_addr, Arc::clone(&state), Arc::clone(&drain), build_info);
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!(error = %e, addr = %obs_bind_addr, "observability server exited");
            }
        });
    }

    // All sockets are bound; start the watchdog keepalive (OPS-045) and
    // signal readiness to systemd (OPS-032). Both are no-ops outside systemd.
    let _watchdog = spawn_watchdog();
    notify_ready();

    // Wait for SIGTERM or SIGINT (BIN-024, BIN-027-SIG).
    wait_for_shutdown_signal().await;
    info!(grace_secs, "Shutdown signal received — initiating drain");
    notify_stopping();
    // Ask systemd to extend its stop timeout to match our grace period (OPS-045).
    notify_extend_timeout_usec(grace_secs.saturating_mul(1_000_000));

    // Initiate drain and wait for in-flight work to complete (BIN-047..BIN-048).
    let grace = Duration::from_secs(grace_secs);
    let drain_result = tokio::select! {
        result = drain.drain_and_wait(grace) => result,
        () = wait_for_shutdown_signal() => {
            // Second signal during drain: fast shutdown (BIN-024).
            warn!("Second shutdown signal — forcing fast shutdown");
            return 0;
        }
    };

    // Drain Redis pool after listener drain completes (BIN-051, ENG-225).
    if let Some(store) = redis_store {
        let stats = store.drain(grace).await;
        info!(
            commands_in_flight_at_drain = stats.commands_in_flight_at_drain,
            commands_completed_during_drain = stats.commands_completed_during_drain,
            commands_force_cancelled = stats.commands_force_cancelled,
            "Redis pool drained"
        );
        if stats.commands_force_cancelled > 0 {
            warn!(
                commands_force_cancelled = stats.commands_force_cancelled,
                "Redis drain grace period elapsed with in-flight commands"
            );
        }
    }

    match drain_result {
        Ok(()) => {
            info!("Drain complete — clean shutdown");
            0
        }
        Err(e) => {
            let remaining = drain.in_flight();
            warn!(
                error = %e,
                in_flight_remaining = remaining,
                "Drain grace period elapsed — forcing shutdown with in-flight queries"
            );
            0
        }
    }
}

/// Block until SIGTERM or SIGINT is received.
///
/// Uses `tokio::signal` for async-safe delivery (BIN-023-SIG).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let sigterm_result = signal(SignalKind::terminate());
        let sigint_result  = signal(SignalKind::interrupt());

        match (sigterm_result, sigint_result) {
            (Ok(mut sigterm), Ok(mut sigint)) => {
                tokio::select! {
                    _ = sigterm.recv() => {
                        debug!("SIGTERM received");
                    }
                    _ = sigint.recv() => {
                        debug!("SIGINT received");
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                // Signal handler installation failed; fall back to Ctrl-C.
                warn!(error = %e, "failed to install Unix signal handler; falling back to Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
                debug!("Ctrl-C received (fallback)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms (Windows), only Ctrl-C is available.
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
        debug!("Ctrl-C received");
    }
}
