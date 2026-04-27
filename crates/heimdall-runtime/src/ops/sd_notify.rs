// SPDX-License-Identifier: MIT

//! systemd `sd_notify` integration (OPS-032, OPS-045).
//!
//! Sends state-change notifications to the systemd supervisor via a Unix datagram
//! socket whose path is given by the `$NOTIFY_SOCKET` environment variable.
//!
//! All functions in this module are no-ops if `$NOTIFY_SOCKET` is not set,
//! making them safe to call in non-systemd environments (containers, development
//! machines, etc.).
//!
//! # Rationale for no external crate
//!
//! The `sd_notify` protocol is trivially simple: send a UTF-8 string over a Unix
//! datagram socket. Introducing an external crate for this small surface would
//! add unnecessary supply-chain risk. The implementation is self-contained here.
//!
//! # Abstract socket namespace
//!
//! systemd may set `$NOTIFY_SOCKET` to an abstract socket path prefixed with `@`.
//! This prefix is stripped before use because [`std::os::unix::net::UnixDatagram`]
//! does not natively handle the abstract namespace notation — the `@` is not part
//! of the actual socket name.

use std::time::Duration;

use tracing::warn;

// ── Core send primitive ──────────────────────────────────────────────────────

/// Send `payload` to the systemd supervisor.
///
/// No-ops silently if `$NOTIFY_SOCKET` is not set (non-systemd environments).
/// Errors are silently ignored: notification delivery is best-effort and must
/// not interfere with server operation.
pub fn notify(payload: &str) {
    let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    // Strip the abstract-socket `@` prefix (OPS-032).
    let socket_path = socket_path.trim_start_matches('@');

    match std::os::unix::net::UnixDatagram::unbound() {
        Ok(sock) => {
            // send_to errors are intentionally ignored: sd_notify is best-effort.
            let _ = sock.send_to(payload.as_bytes(), socket_path);
        }
        Err(e) => {
            warn!(event = "sd_notify_error", error = %e, "failed to create unbound datagram socket");
        }
    }
}

// ── Convenience helpers ───────────────────────────────────────────────────────

/// Notify systemd that the service is ready to accept requests (OPS-045).
///
/// Sends `READY=1`.
pub fn notify_ready() {
    notify("READY=1");
}

/// Notify systemd that the service is about to stop (OPS-045).
///
/// Sends `STOPPING=1`. Call this before initiating graceful shutdown so that
/// systemd does not restart the unit prematurely.
pub fn notify_stopping() {
    notify("STOPPING=1");
}

/// Send a watchdog keepalive to systemd (OPS-045).
///
/// Sends `WATCHDOG=1`. Must be called more frequently than the interval
/// configured in the unit file (`WatchdogSec=`); [`spawn_watchdog`] handles
/// this automatically.
pub fn notify_watchdog() {
    notify("WATCHDOG=1");
}

/// Update the human-readable status line shown by `systemctl status` (OPS-045).
///
/// Sends `STATUS=<msg>`.
pub fn notify_status(msg: &str) {
    notify(&format!("STATUS={msg}"));
}

// ── Watchdog keepalive task ───────────────────────────────────────────────────

/// Spawn a watchdog keepalive task (OPS-045).
///
/// Reads `WATCHDOG_USEC` from the environment. If set, spawns a tokio task that
/// sends `WATCHDOG=1` every `WATCHDOG_USEC / 2` microseconds, which is the
/// sd_notify-recommended interval.
///
/// Returns `None` if `WATCHDOG_USEC` is not set or cannot be parsed, making
/// this safe to call unconditionally in non-systemd environments.
#[must_use]
pub fn spawn_watchdog() -> Option<tokio::task::JoinHandle<()>> {
    let usec_str = std::env::var("WATCHDOG_USEC").ok()?;
    let usec: u64 = usec_str.trim().parse().ok()?;
    // Interval is half the configured watchdog period (sd_notify recommendation).
    let interval = Duration::from_micros(usec / 2);

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the first tick (fires immediately) to avoid a double-notify at start.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            notify_watchdog();
        }
    });

    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `notify_*` helpers do not panic.
    ///
    /// In a standard CI/development environment `$NOTIFY_SOCKET` is not set, so
    /// all helpers become no-ops. If a systemd socket happens to be set, the
    /// `send_to` will either succeed or silently fail — neither panics.
    #[test]
    fn notify_helpers_do_not_panic() {
        // These are safe to call regardless of whether NOTIFY_SOCKET is set.
        notify_ready();
        notify_stopping();
        notify_watchdog();
        notify_status("unit-test");
    }

    /// Verify that `spawn_watchdog` returns `None` when `$WATCHDOG_USEC` is absent.
    ///
    /// `$WATCHDOG_USEC` is never set in a normal development or CI environment.
    /// If it happens to be set (running under systemd with watchdog), `spawn_watchdog`
    /// returns `Some`, which is equally valid; we abort the task to avoid leaking it.
    #[tokio::test]
    async fn spawn_watchdog_none_without_watchdog_usec() {
        // Only assert None when the env var is truly absent.
        if std::env::var("WATCHDOG_USEC").is_err() {
            let handle = spawn_watchdog();
            assert!(
                handle.is_none(),
                "expected None when WATCHDOG_USEC is not set"
            );
        }
        // If WATCHDOG_USEC is set (running under systemd), skip the assertion.
    }
}
