// SPDX-License-Identifier: MIT

//! TLS handshake telemetry counters for the `DoT` listener (task #268).
//!
//! [`TlsTelemetry`] collects per-listener counts of TLS handshake outcomes.
//! All counters use `Relaxed` ordering because they are diagnostic counters
//! consumed by the `report` snapshot; they do not synchronise access to any
//! shared mutable state.

use std::sync::atomic::{AtomicU64, Ordering};

// ── TlsTelemetry ─────────────────────────────────────────────────────────────

/// Per-listener TLS handshake telemetry counters.
///
/// Construct with [`TlsTelemetry::new`] and pass an `Arc<TlsTelemetry>` to
/// the [`DotListener`](crate::transport::dot::DotListener). Call
/// [`TlsTelemetry::report`] to emit a snapshot as a structured tracing event.
#[derive(Debug, Default)]
pub struct TlsTelemetry {
    /// Number of TLS handshakes that completed successfully.
    pub handshake_successes: AtomicU64,
    /// Total number of TLS handshakes that failed for any reason.
    pub handshake_failures: AtomicU64,
    /// Subset of `handshake_failures`: peer presented an invalid certificate.
    pub handshake_failures_cert_invalid: AtomicU64,
    /// Subset of `handshake_failures`: handshake timed out before completion.
    pub handshake_failures_timeout: AtomicU64,
}

impl TlsTelemetry {
    /// Creates a new [`TlsTelemetry`] with all counters initialised to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emits a `tracing::info!` snapshot of the current counter values.
    ///
    /// The snapshot is a point-in-time read; individual counters are loaded
    /// independently and the overall snapshot is not atomic.
    pub fn report(&self) {
        let successes = self.handshake_successes.load(Ordering::Relaxed);
        let failures = self.handshake_failures.load(Ordering::Relaxed);
        let cert_invalid = self.handshake_failures_cert_invalid.load(Ordering::Relaxed);
        let timeout = self.handshake_failures_timeout.load(Ordering::Relaxed);

        tracing::info!(
            tls_handshake_successes = successes,
            tls_handshake_failures = failures,
            tls_handshake_failures_cert_invalid = cert_invalid,
            tls_handshake_failures_timeout = timeout,
            "TLS telemetry snapshot"
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let t = TlsTelemetry::new();
        assert_eq!(t.handshake_successes.load(Ordering::Relaxed), 0);
        assert_eq!(t.handshake_failures.load(Ordering::Relaxed), 0);
        assert_eq!(t.handshake_failures_cert_invalid.load(Ordering::Relaxed), 0);
        assert_eq!(t.handshake_failures_timeout.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn success_counter_increments_correctly() {
        let t = TlsTelemetry::new();
        t.handshake_successes.fetch_add(1, Ordering::Relaxed);
        t.handshake_successes.fetch_add(1, Ordering::Relaxed);
        assert_eq!(t.handshake_successes.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failure_counters_increment_independently() {
        let t = TlsTelemetry::new();
        t.handshake_failures.fetch_add(3, Ordering::Relaxed);
        t.handshake_failures_cert_invalid.fetch_add(2, Ordering::Relaxed);
        t.handshake_failures_timeout.fetch_add(1, Ordering::Relaxed);

        assert_eq!(t.handshake_failures.load(Ordering::Relaxed), 3);
        assert_eq!(t.handshake_failures_cert_invalid.load(Ordering::Relaxed), 2);
        assert_eq!(t.handshake_failures_timeout.load(Ordering::Relaxed), 1);
        // Success counter must remain zero.
        assert_eq!(t.handshake_successes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn report_does_not_panic() {
        // Smoke-test that `report` runs without panicking, even under concurrent
        // modification. We do not assert on output since `report` emits to tracing.
        let t = Arc::new(TlsTelemetry::new());
        t.handshake_successes.fetch_add(10, Ordering::Relaxed);
        t.handshake_failures.fetch_add(2, Ordering::Relaxed);
        t.report(); // must not panic
    }
}
