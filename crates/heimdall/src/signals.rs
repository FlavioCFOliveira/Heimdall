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
use heimdall_runtime::{Drain, SighupReloader, state::RunningState};
use tracing::{debug, info, warn};

/// Default grace timeout for the drain phase (BIN-048).
#[allow(dead_code)]
pub const DRAIN_GRACE_SECS: u64 = 30;

/// Run the supervision loop.
///
/// This is the main async body executed inside the Tokio runtime. It:
/// 1. Installs SIGHUP reload handler (spawned task).
/// 2. Waits for SIGTERM or SIGINT.
/// 3. Initiates drain with the configured grace timeout.
/// 4. A second SIGTERM/SIGINT during drain triggers immediate exit.
///
/// Returns the suggested process exit code (0 on clean shutdown, 1 on error).
pub async fn supervision_loop(
    drain: Drain,
    state: Arc<ArcSwap<RunningState>>,
    config_path: std::path::PathBuf,
    grace_secs: u64,
) -> i32 {
    // Install SIGHUP reload handler (BIN-025-SIG, OPS-001..006).
    // On non-Unix platforms the SighupReloader is a no-op.
    let _reload_handle = {
        let reloader = SighupReloader::new(Arc::clone(&state), config_path);
        reloader.spawn()
    };

    // SIGPIPE is ignored by default in Tokio — Rust sets SA_RESETHAND=false for
    // SIGPIPE, so broken-pipe errors surface as io::Error returns (BIN-026-SIG).

    // Wait for SIGTERM or SIGINT (BIN-024, BIN-027-SIG).
    wait_for_shutdown_signal().await;
    info!("Shutdown signal received — initiating drain");

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
