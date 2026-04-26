// SPDX-License-Identifier: MIT

//! Per-stage admission telemetry counters (THREAT-057, THREAT-077, task #257).
//!
//! All counters are `AtomicU64` and updated on the hot path with
//! [`Ordering::Relaxed`] (metric-counter semantic: we care about the total
//! count, not about ordering relative to other stores).  A `Relaxed` load in
//! `report()` is sufficient because the report is a best-effort snapshot.

use std::sync::atomic::{AtomicU64, Ordering};

// ── AdmissionTelemetry ────────────────────────────────────────────────────────

/// Counters for each stage of the admission pipeline (THREAT-057, THREAT-077).
///
/// All fields are `pub` so listener code can increment them directly without
/// going through an accessor, keeping the hot path to a single `fetch_add`.
#[derive(Debug, Default)]
pub struct AdmissionTelemetry {
    /// Requests that passed the ACL check.
    pub acl_allowed: AtomicU64,
    /// Requests denied by the ACL.
    pub acl_denied: AtomicU64,
    /// Requests denied by a connection / in-flight / global-pending limit.
    pub conn_limit_denied: AtomicU64,
    /// Requests denied because the server is under load and no valid cookie was
    /// present (THREAT-069).
    pub cookie_load_denied: AtomicU64,
    /// Requests dropped by RRL (budget exhausted, no slip).
    pub rrl_dropped: AtomicU64,
    /// Requests that received a TC slip response from RRL.
    pub rrl_slipped: AtomicU64,
    /// Requests denied by the per-client query rate limiter.
    pub query_rl_denied: AtomicU64,
    /// Requests that passed all pipeline stages and were admitted.
    pub total_allowed: AtomicU64,
    /// Number of times the under-load signal transitioned to or from load.
    pub under_load_transitions: AtomicU64,
}

impl AdmissionTelemetry {
    /// Create a new zeroed telemetry instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a `tracing::info!` event with a snapshot of all counters.
    ///
    /// Counters are read with `Relaxed` ordering — values are a best-effort
    /// snapshot, not a transactionally consistent view.
    pub fn report(&self) {
        tracing::info!(
            acl_allowed      = self.acl_allowed.load(Ordering::Relaxed),
            acl_denied       = self.acl_denied.load(Ordering::Relaxed),
            conn_limit_denied = self.conn_limit_denied.load(Ordering::Relaxed),
            cookie_load_denied = self.cookie_load_denied.load(Ordering::Relaxed),
            rrl_dropped      = self.rrl_dropped.load(Ordering::Relaxed),
            rrl_slipped      = self.rrl_slipped.load(Ordering::Relaxed),
            query_rl_denied  = self.query_rl_denied.load(Ordering::Relaxed),
            total_allowed    = self.total_allowed.load(Ordering::Relaxed),
            under_load_transitions = self.under_load_transitions.load(Ordering::Relaxed),
            "admission_pipeline_snapshot"
        );
    }

    // ── convenience increment helpers ─────────────────────────────────────────

    /// Increment `acl_allowed` by 1.
    #[inline]
    pub fn inc_acl_allowed(&self) {
        self.acl_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `acl_denied` by 1.
    #[inline]
    pub fn inc_acl_denied(&self) {
        self.acl_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `conn_limit_denied` by 1.
    #[inline]
    pub fn inc_conn_limit_denied(&self) {
        self.conn_limit_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `cookie_load_denied` by 1.
    #[inline]
    pub fn inc_cookie_load_denied(&self) {
        self.cookie_load_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `rrl_dropped` by 1.
    #[inline]
    pub fn inc_rrl_dropped(&self) {
        self.rrl_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `rrl_slipped` by 1.
    #[inline]
    pub fn inc_rrl_slipped(&self) {
        self.rrl_slipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `query_rl_denied` by 1.
    #[inline]
    pub fn inc_query_rl_denied(&self) {
        self.query_rl_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `total_allowed` by 1.
    #[inline]
    pub fn inc_total_allowed(&self) {
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `under_load_transitions` by 1.
    #[inline]
    pub fn inc_under_load_transitions(&self) {
        self.under_load_transitions.fetch_add(1, Ordering::Relaxed);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::AdmissionTelemetry;

    #[test]
    fn counters_start_at_zero() {
        let t = AdmissionTelemetry::new();
        assert_eq!(t.acl_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(t.acl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.conn_limit_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.cookie_load_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.rrl_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(t.rrl_slipped.load(Ordering::Relaxed), 0);
        assert_eq!(t.query_rl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.total_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(t.under_load_transitions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn increment_helpers() {
        let t = AdmissionTelemetry::new();
        t.inc_acl_allowed();
        t.inc_acl_denied();
        t.inc_conn_limit_denied();
        t.inc_cookie_load_denied();
        t.inc_rrl_dropped();
        t.inc_rrl_slipped();
        t.inc_query_rl_denied();
        t.inc_total_allowed();
        t.inc_under_load_transitions();
        assert_eq!(t.acl_allowed.load(Ordering::Relaxed), 1);
        assert_eq!(t.acl_denied.load(Ordering::Relaxed), 1);
        assert_eq!(t.conn_limit_denied.load(Ordering::Relaxed), 1);
        assert_eq!(t.cookie_load_denied.load(Ordering::Relaxed), 1);
        assert_eq!(t.rrl_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(t.rrl_slipped.load(Ordering::Relaxed), 1);
        assert_eq!(t.query_rl_denied.load(Ordering::Relaxed), 1);
        assert_eq!(t.total_allowed.load(Ordering::Relaxed), 1);
        assert_eq!(t.under_load_transitions.load(Ordering::Relaxed), 1);
    }
}
