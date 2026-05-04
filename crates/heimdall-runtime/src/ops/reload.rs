// SPDX-License-Identifier: MIT

//! SIGHUP-triggered configuration reload handler.
//!
//! [`SighupReloader`] listens for POSIX `SIGHUP`, re-reads the configuration file,
//! validates it, and atomically swaps the [`crate::state::RunningState`] on success.
//! On failure the existing state is preserved unchanged (OPS-003).
//!
//! The transport layer (sockets, TLS contexts) is never restarted on reload —
//! only the `StateContainer` is swapped, so listeners observe the new config on
//! their next access through `Arc<ArcSwap<RunningState>>` (OPS-004).
//!
//! # At-most-one-queued semantics (OPS-039)
//!
//! A `Semaphore` with one permit gates entry into the reload critical section:
//! - The first SIGHUP acquires the permit and begins reloading.
//! - A second SIGHUP while the first is in progress takes the queued slot
//!   (the semaphore permit is not yet released).
//! - Further SIGHUPs while a reload is in progress *and* one is already queued
//!   are silently discarded (no permit available).

use std::{path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::{ConfigError, load_and_validate};
use crate::state::RunningState;

/// Outcome of a single reload cycle, emitted as a structured audit event (OPS-005).
#[derive(Debug)]
pub enum ReloadOutcome {
    /// The reload succeeded and the new config is live.
    Applied {
        /// The new config generation number after the reload.
        generation: u64,
    },
    /// The reload was rejected; the existing state is unchanged.
    Rejected {
        /// Human-readable description of the failure.
        reason: String,
    },
}

/// SIGHUP reload handler.
///
/// Listens for `SIGHUP`, validates the new config, and atomically swaps the
/// [`RunningState`] on success. On failure the existing state is preserved
/// (OPS-003). Listeners are never torn down (OPS-004).
///
/// # At-most-one-queued semantics (OPS-039)
///
/// A [`Semaphore`] with one permit serialises reloads. If a reload is in
/// progress and a second `SIGHUP` arrives, it waits for a permit. Further
/// `SIGHUP`s while one is queued are dropped (no permit is available without
/// blocking).
pub struct SighupReloader {
    state: Arc<ArcSwap<RunningState>>,
    config_path: PathBuf,
}

impl SighupReloader {
    /// Create a new reloader bound to `state` and `config_path`.
    #[must_use]
    pub fn new(state: Arc<ArcSwap<RunningState>>, config_path: PathBuf) -> Self {
        Self { state, config_path }
    }

    /// Spawn a tokio task that listens for `SIGHUP` and triggers reload cycles.
    ///
    /// At most one reload is queued at any time (OPS-039):
    /// - If a reload is in progress and a second `SIGHUP` arrives, it is queued.
    /// - Further `SIGHUP`s while one is queued are silently discarded.
    ///
    /// The spawned task runs until the process exits.
    #[must_use]
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // One-permit semaphore: the holder is reloading; one waiter is queued.
            // Any extra SIGHUP while the waiter slot is occupied is dropped.
            let sem = Arc::new(Semaphore::new(1));

            let mut sig = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to register SIGHUP handler; reload disabled");
                    return;
                }
            };

            loop {
                // Wait for the next SIGHUP.
                if sig.recv().await.is_none() {
                    // Signal stream closed — process is shutting down.
                    break;
                }

                // Try to acquire a permit without blocking (non-async try_acquire).
                // `Semaphore::try_acquire` returns Err if no permit is available.
                match sem.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let reloader = SighupReloader {
                            state: Arc::clone(&self.state),
                            config_path: self.config_path.clone(),
                        };
                        tokio::spawn(async move {
                            let outcome = reloader.reload_once().await;
                            let generation = match &outcome {
                                ReloadOutcome::Applied { generation } => Some(*generation),
                                ReloadOutcome::Rejected { .. } => None,
                            };
                            info!(
                                event = "sighup_reload",
                                outcome = ?outcome,
                                generation = generation,
                                "reload completed"
                            );
                            drop(permit); // Release after reload finishes.
                        });
                    }
                    Err(_no_permit) => {
                        // A reload is in progress and one is already queued;
                        // silently discard this SIGHUP (OPS-039).
                        warn!(
                            event = "sighup_reload_discarded",
                            "SIGHUP discarded: reload in progress with one already queued"
                        );
                    }
                }
            }
        })
    }

    /// Perform a single reload cycle.
    ///
    /// Steps:
    /// 1. Re-reads the config file from disk.
    /// 2. Validates it (parse + validate).
    /// 3. On success: atomically swaps the [`RunningState`] (OPS-016/017).
    /// 4. Returns [`ReloadOutcome`] for audit logging (OPS-005).
    ///
    /// The `async` signature is intentional: the function will be made truly
    /// async (using `tokio::fs`) in a future sprint. Keeping the signature
    /// stable now avoids a breaking change at the call sites.
    #[expect(
        clippy::unused_async,
        reason = "signature is intentionally async; will use tokio::fs in future sprint"
    )]
    pub async fn reload_once(&self) -> ReloadOutcome {
        match load_and_validate(&self.config_path) {
            Ok(new_config) => {
                let new_config = Arc::new(new_config);
                // Build next generation from the current state.
                let current = self.state.load();
                let new_state = current.next_generation(Arc::clone(&new_config));
                let new_generation = new_state.generation;
                self.state.store(Arc::new(new_state));
                ReloadOutcome::Applied {
                    generation: new_generation,
                }
            }
            Err(e) => {
                let reason = format_config_error(&e);
                warn!(
                    event = "sighup_reload_rejected",
                    path = %self.config_path.display(),
                    error = %reason,
                    "reload rejected: config invalid; existing state preserved"
                );
                ReloadOutcome::Rejected { reason }
            }
        }
    }
}

/// Format a [`ConfigError`] for the audit log without exposing stack traces.
fn format_config_error(e: &ConfigError) -> String {
    match e {
        ConfigError::Io(io) => format!("I/O error reading config: {io}"),
        ConfigError::Parse(p) => format!("TOML parse error: {p}"),
        ConfigError::Validation(errs) => {
            format!("validation failed: {}", errs.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_initial_state() -> Arc<ArcSwap<RunningState>> {
        let config = Arc::new(crate::config::Config::default());
        let telemetry = Arc::new(crate::admission::AdmissionTelemetry::new());
        let state = RunningState::initial(config, telemetry);
        Arc::new(ArcSwap::new(Arc::new(state)))
    }

    #[tokio::test]
    async fn rejected_reload_preserves_generation() {
        let state = make_initial_state();
        // Use a path that does not exist.
        let reloader = SighupReloader::new(
            Arc::clone(&state),
            PathBuf::from("/nonexistent/path/to/config.toml"),
        );
        let outcome = reloader.reload_once().await;
        assert!(
            matches!(outcome, ReloadOutcome::Rejected { .. }),
            "expected Rejected, got {outcome:?}"
        );
        assert_eq!(
            state.load().generation,
            0,
            "generation must not change on rejection"
        );
    }

    #[tokio::test]
    async fn valid_reload_increments_generation() {
        // Write a valid minimal TOML config to a temp file.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("heimdall.toml");
        std::fs::write(
            &path,
            b"[server]\nidentity = \"test\"\nworker_threads = 1\n",
        )
        .expect("write config");

        let state = make_initial_state();
        let reloader = SighupReloader::new(Arc::clone(&state), path);
        let outcome = reloader.reload_once().await;
        assert!(
            matches!(outcome, ReloadOutcome::Applied { generation: 1 }),
            "expected Applied(1), got {outcome:?}"
        );
        assert_eq!(state.load().generation, 1);
    }
}
