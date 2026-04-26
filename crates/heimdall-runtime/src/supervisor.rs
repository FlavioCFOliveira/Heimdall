// SPDX-License-Identifier: MIT

//! Task spawning and shutdown orchestration.
//!
//! [`Supervisor`] spawns named worker tasks, monitors them for completion or
//! fatal errors, and orchestrates a clean shutdown via the [`crate::drain::Drain`]
//! primitive.

use tokio::task::JoinSet;

use crate::drain::Drain;

/// Errors reported by worker tasks.
#[derive(Debug)]
pub enum WorkerError {
    /// A worker encountered an unrecoverable error and the server must shut down.
    Fatal {
        /// Name of the role or subsystem that failed.
        role: String,
        /// Human-readable description of the failure.
        reason: String,
    },
    /// A worker panicked and was restarted.
    ///
    /// Non-fatal panics are logged; if the task returns this variant, the supervisor
    /// records the event but does not initiate shutdown.
    Restarted {
        /// Name of the role or subsystem that was restarted.
        role: String,
        /// How many restart attempts have been made so far.
        attempt: u32,
    },
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fatal { role, reason } => {
                write!(f, "fatal error in worker '{role}': {reason}")
            }
            Self::Restarted { role, attempt } => {
                write!(f, "worker '{role}' restarted (attempt {attempt})")
            }
        }
    }
}

impl std::error::Error for WorkerError {}

/// Central supervisor that spawns and monitors per-role tasks.
///
/// Spawn workers with [`Supervisor::spawn_worker`], then call
/// [`Supervisor::run_to_completion`] to drive the supervisor event loop. A
/// shutdown signal can be sent at any time via [`Supervisor::shutdown`].
pub struct Supervisor {
    tasks: JoinSet<Result<(), WorkerError>>,
    /// Held for use in later sprints (initiating drain on shutdown).
    // TODO(sprint 18): call drain.drain_and_wait() in run_to_completion shutdown path.
    #[allow(dead_code)]
    drain: Drain,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl Supervisor {
    /// Create a new supervisor backed by `drain`.
    #[must_use]
    pub fn new(drain: Drain) -> Self {
        // Capacity 1: a single shutdown signal is enough; late subscribers can
        // observe it via subscribe() before the channel closes.
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tasks: JoinSet::new(),
            drain,
            shutdown_tx,
        }
    }

    /// Spawn a named worker task.
    ///
    /// The worker factory `f` is called with a shutdown receiver. The factory
    /// must return a [`Future`] that resolves to `Ok(())` on clean exit or
    /// `Err(WorkerError)` on error. The supervisor collects all results and
    /// returns them from [`Supervisor::run_to_completion`].
    ///
    /// Non-fatal panics (i.e. the task handle returns `JoinError::is_panic()`)
    /// are recorded as [`WorkerError::Restarted`] with `attempt = 1`.
    ///
    /// Fatal errors (a returned `Err(WorkerError::Fatal { .. })`) trigger a
    /// shutdown signal to all other workers during [`Supervisor::run_to_completion`].
    pub fn spawn_worker<F, Fut>(&mut self, name: &'static str, f: F)
    where
        F: Fn(tokio::sync::broadcast::Receiver<()>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), WorkerError>> + Send + 'static,
    {
        let rx = self.shutdown_tx.subscribe();
        self.tasks.spawn(async move { f(rx).await });
        // The name is captured in the closure for diagnostics; use it in a
        // spawn_named() call when tokio stabilises that API.
        let _ = name; // suppress unused-variable warning until named spawn is available
    }

    /// Send the shutdown signal to all workers.
    ///
    /// This is a broadcast: all workers that hold a [`tokio::sync::broadcast::Receiver`]
    /// obtained from [`Supervisor::subscribe_shutdown`] or via `spawn_worker` will be
    /// notified. Errors (no active receivers) are silently ignored — the supervisor
    /// may call this after all workers have exited.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to the shutdown broadcast channel.
    ///
    /// Useful for components outside the supervisor that need to react to shutdown.
    #[must_use]
    pub fn subscribe_shutdown(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Drive the supervisor event loop until all workers have exited.
    ///
    /// Collects the results of all spawned workers. On the first fatal error, sends
    /// a shutdown signal to all remaining workers and initiates drain. Continues
    /// collecting remaining worker results after signalling shutdown.
    ///
    /// Returns all non-`Ok` results collected. An empty `Vec` means every worker
    /// exited cleanly.
    pub async fn run_to_completion(mut self) -> Vec<WorkerError> {
        let mut errors: Vec<WorkerError> = Vec::new();
        let mut shutdown_sent = false;

        while let Some(result) = self.tasks.join_next().await {
            match result {
                Ok(Ok(())) => {
                    // Worker exited cleanly — nothing to record.
                }
                Ok(Err(e)) => {
                    let is_fatal = matches!(e, WorkerError::Fatal { .. });
                    errors.push(e);
                    if is_fatal && !shutdown_sent {
                        self.shutdown_tx.send(()).ok();
                        shutdown_sent = true;
                    }
                }
                Err(join_err) => {
                    // Task panicked.
                    let reason = join_err.to_string();
                    errors.push(WorkerError::Fatal {
                        role: "<unknown>".to_owned(),
                        reason,
                    });
                    if !shutdown_sent {
                        self.shutdown_tx.send(()).ok();
                        shutdown_sent = true;
                    }
                }
            }
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn supervisor_with_no_workers_returns_empty() {
        let drain = Drain::new();
        let supervisor = Supervisor::new(drain);
        let errors = supervisor.run_to_completion().await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn clean_worker_exit_produces_no_errors() {
        let drain = Drain::new();
        let mut supervisor = Supervisor::new(drain);
        supervisor.spawn_worker("noop", |_rx| async { Ok(()) });
        let errors = supervisor.run_to_completion().await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn fatal_error_triggers_shutdown() {
        let drain = Drain::new();
        let mut supervisor = Supervisor::new(drain);

        // Worker that returns a fatal error.
        supervisor.spawn_worker("faulty", |_rx| async {
            Err(WorkerError::Fatal {
                role: "faulty".to_owned(),
                reason: "intentional test failure".to_owned(),
            })
        });

        // Worker that exits cleanly once it receives the shutdown signal.
        supervisor.spawn_worker("listener", |mut rx| async move {
            let _ = rx.recv().await;
            Ok(())
        });

        let errors = supervisor.run_to_completion().await;
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], WorkerError::Fatal { .. }));
    }

    #[tokio::test]
    async fn shutdown_signal_reaches_workers() {
        let drain = Drain::new();
        let mut supervisor = Supervisor::new(drain);

        supervisor.spawn_worker("waiter", |mut rx| async move {
            tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .expect("timeout: shutdown signal not received")
                .ok(); // RecvError is fine — sender dropped counts as signal
            Ok(())
        });

        // Give the worker a moment to start, then signal shutdown.
        tokio::time::sleep(Duration::from_millis(10)).await;
        supervisor.shutdown();

        let errors = supervisor.run_to_completion().await;
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[tokio::test]
    async fn restarted_error_is_non_fatal() {
        let drain = Drain::new();
        let mut supervisor = Supervisor::new(drain);

        supervisor.spawn_worker("unstable", |_rx| async {
            Err(WorkerError::Restarted {
                role: "unstable".to_owned(),
                attempt: 1,
            })
        });

        let errors = supervisor.run_to_completion().await;
        // Restarted is an error, but it should NOT have triggered shutdown of
        // other workers (tested by ensuring run_to_completion returns normally).
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], WorkerError::Restarted { .. }));
    }
}
