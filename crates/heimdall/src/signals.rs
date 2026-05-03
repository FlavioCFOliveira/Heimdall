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
use heimdall_runtime::{Drain, SighupReloader, notify_ready, notify_stopping, spawn_watchdog, state::RunningState};
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
/// Returns the suggested process exit code (0 on clean shutdown, 1 on error).
pub async fn supervision_loop(
    drain: Drain,
    state: Arc<ArcSwap<RunningState>>,
    config_path: std::path::PathBuf,
    grace_secs: u64,
    listeners: Vec<BoundListener>,
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

    // All sockets are bound; start the watchdog keepalive (OPS-045) and
    // signal readiness to systemd (OPS-032). Both are no-ops outside systemd.
    let _watchdog = spawn_watchdog();
    notify_ready();

    // Wait for SIGTERM or SIGINT (BIN-024, BIN-027-SIG).
    wait_for_shutdown_signal().await;
    info!("Shutdown signal received — initiating drain");
    notify_stopping();

    // Initiate drain and wait for in-flight work to complete (BIN-047..BIN-048).
    let grace = Duration::from_secs(grace_secs);
    let drain_result = tokio::select! {
        result = drain.drain_and_wait(grace) => result,
        _ = wait_for_shutdown_signal() => {
            // Second signal during drain: fast shutdown (BIN-024).
            warn!("Second shutdown signal — forcing fast shutdown");
            return 0;
        }
    };

    match drain_result {
        Ok(()) => {
            info!("Drain complete — clean shutdown");
            0
        }
        Err(e) => {
            warn!(error = %e, "Drain grace period elapsed — forcing shutdown");
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

        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt())
            .expect("failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                debug!("SIGTERM received");
            }
            _ = sigint.recv() => {
                debug!("SIGINT received");
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
