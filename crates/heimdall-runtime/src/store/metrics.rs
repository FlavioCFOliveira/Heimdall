// SPDX-License-Identifier: MIT

//! Per-operation counters and latency stubs for the Redis persistence layer.
//!
//! Task #241 requires:
//! - Per-op counters: `cache_hit`, `cache_miss`, `zone_write_ok`,
//!   `zone_write_err`, `cache_write_ok`, `cache_write_err`,
//!   `journal_append_ok`, `journal_append_err`.
//! - Latency histograms: stubbed as `AtomicU64` total-duration accumulators.
//!   Full histogram support is deferred to the observability sprint.
//! - Connection pool utilisation gauge.
//! - Reconnect counter.
//!
//! All writes use `Relaxed` ordering: counters are informational metrics and
//! do not synchronise any shared state.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Shared, cheaply-cloneable store-operation metric counters.
///
/// Clone freely — all clones share the same underlying atomics via [`Arc`].
#[derive(Debug, Clone)]
pub struct StoreMetrics {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    // ── Cache reads ──────────────────────────────────────────────────────────
    cache_hit: AtomicU64,
    cache_miss: AtomicU64,

    // ── Cache writes ─────────────────────────────────────────────────────────
    cache_write_ok: AtomicU64,
    cache_write_err: AtomicU64,

    // ── Zone writes ──────────────────────────────────────────────────────────
    zone_write_ok: AtomicU64,
    zone_write_err: AtomicU64,

    // ── IXFR journal ─────────────────────────────────────────────────────────
    journal_append_ok: AtomicU64,
    journal_append_err: AtomicU64,

    // ── Connection pool ──────────────────────────────────────────────────────
    /// Current number of connections in-use (approximation; not precise under
    /// concurrent load due to relaxed ordering — use for dashboards only).
    pool_connections_in_use: AtomicU64,

    // ── Reconnection ─────────────────────────────────────────────────────────
    reconnect_attempts: AtomicU64,

    // ── Latency stubs (total nanoseconds accumulated, operation count) ────────
    //
    // Full histogram (percentile buckets) is deferred to the observability
    // sprint. Current stub lets callers accumulate totals and compute a
    // rough mean: mean_ns = total_ns / op_count.
    cache_read_total_ns: AtomicU64,
    cache_read_count: AtomicU64,
    zone_write_total_ns: AtomicU64,
    zone_write_count: AtomicU64,
}

impl StoreMetrics {
    /// Create a new zero-initialised metrics instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner::default()),
        }
    }

    // ── Cache read ────────────────────────────────────────────────────────────

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.inner.cache_hit.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "cache_hit");
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&self) {
        self.inner.cache_miss.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "cache_miss");
    }

    /// Accumulate a cache-read latency sample in nanoseconds.
    pub fn record_cache_read_latency_ns(&self, ns: u64) {
        self.inner
            .cache_read_total_ns
            .fetch_add(ns, Ordering::Relaxed);
        self.inner.cache_read_count.fetch_add(1, Ordering::Relaxed);
    }

    // ── Cache write ───────────────────────────────────────────────────────────

    /// Record a successful cache write.
    pub fn record_cache_write_ok(&self) {
        self.inner.cache_write_ok.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "cache_write_ok");
    }

    /// Record a failed cache write.
    pub fn record_cache_write_err(&self) {
        self.inner.cache_write_err.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(event = "cache_write_err");
    }

    // ── Zone write ────────────────────────────────────────────────────────────

    /// Record a successful zone write (HSET + RENAME).
    pub fn record_zone_write_ok(&self) {
        self.inner.zone_write_ok.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "zone_write_ok");
    }

    /// Record a failed zone write.
    pub fn record_zone_write_err(&self) {
        self.inner.zone_write_err.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(event = "zone_write_err");
    }

    /// Accumulate a zone-write latency sample in nanoseconds.
    pub fn record_zone_write_latency_ns(&self, ns: u64) {
        self.inner
            .zone_write_total_ns
            .fetch_add(ns, Ordering::Relaxed);
        self.inner.zone_write_count.fetch_add(1, Ordering::Relaxed);
    }

    // ── IXFR journal ──────────────────────────────────────────────────────────

    /// Record a successful journal append (ZADD).
    pub fn record_journal_append_ok(&self) {
        self.inner.journal_append_ok.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "journal_append_ok");
    }

    /// Record a failed journal append.
    pub fn record_journal_append_err(&self) {
        self.inner
            .journal_append_err
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(event = "journal_append_err");
    }

    // ── Connection pool ───────────────────────────────────────────────────────

    /// Set the current gauge of connections in use.
    ///
    /// Callers should snapshot the pool's `status().size` at the time of the
    /// read and pass it here. Ordering is Relaxed — this is a dashboard gauge,
    /// not a synchronisation primitive.
    pub fn set_pool_connections_in_use(&self, count: u64) {
        self.inner
            .pool_connections_in_use
            .store(count, Ordering::Relaxed);
    }

    // ── Reconnection ──────────────────────────────────────────────────────────

    /// Increment the reconnection-attempt counter and emit a structured event.
    pub fn record_reconnect_attempt(&self) {
        let n = self
            .inner
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        tracing::warn!(event = "redis_reconnect_attempt", attempt = n);
    }

    // ── Snapshot (for testing and /metrics exposition) ────────────────────────

    /// Snapshot of all current counter values.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            cache_hit: self.inner.cache_hit.load(Ordering::Relaxed),
            cache_miss: self.inner.cache_miss.load(Ordering::Relaxed),
            cache_write_ok: self.inner.cache_write_ok.load(Ordering::Relaxed),
            cache_write_err: self.inner.cache_write_err.load(Ordering::Relaxed),
            zone_write_ok: self.inner.zone_write_ok.load(Ordering::Relaxed),
            zone_write_err: self.inner.zone_write_err.load(Ordering::Relaxed),
            journal_append_ok: self.inner.journal_append_ok.load(Ordering::Relaxed),
            journal_append_err: self.inner.journal_append_err.load(Ordering::Relaxed),
            pool_connections_in_use: self.inner.pool_connections_in_use.load(Ordering::Relaxed),
            reconnect_attempts: self.inner.reconnect_attempts.load(Ordering::Relaxed),
            cache_read_total_ns: self.inner.cache_read_total_ns.load(Ordering::Relaxed),
            cache_read_count: self.inner.cache_read_count.load(Ordering::Relaxed),
            zone_write_total_ns: self.inner.zone_write_total_ns.load(Ordering::Relaxed),
            zone_write_count: self.inner.zone_write_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for StoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of all [`StoreMetrics`] counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Cache reads that found an unexpired entry.
    pub cache_hit: u64,
    /// Cache reads that found no entry or an expired entry.
    pub cache_miss: u64,
    /// Successful cache writes (`SET … EX`).
    pub cache_write_ok: u64,
    /// Failed cache writes.
    pub cache_write_err: u64,
    /// Successful zone writes (HSET staging + RENAME).
    pub zone_write_ok: u64,
    /// Failed zone writes.
    pub zone_write_err: u64,
    /// Successful IXFR journal appends.
    pub journal_append_ok: u64,
    /// Failed IXFR journal appends.
    pub journal_append_err: u64,
    /// Current in-use connection count (pool gauge).
    pub pool_connections_in_use: u64,
    /// Total Redis reconnection attempts since process start.
    pub reconnect_attempts: u64,
    /// Total nanoseconds accumulated across all cache-read operations.
    pub cache_read_total_ns: u64,
    /// Number of cache-read latency samples recorded.
    pub cache_read_count: u64,
    /// Total nanoseconds accumulated across all zone-write operations.
    pub zone_write_total_ns: u64,
    /// Number of zone-write latency samples recorded.
    pub zone_write_count: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_starts_at_zero() {
        let m = StoreMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.cache_hit, 0);
        assert_eq!(s.cache_miss, 0);
        assert_eq!(s.zone_write_ok, 0);
        assert_eq!(s.reconnect_attempts, 0);
    }

    #[test]
    fn record_cache_hit_increments() {
        let m = StoreMetrics::new();
        m.record_cache_hit();
        m.record_cache_hit();
        assert_eq!(m.snapshot().cache_hit, 2);
    }

    #[test]
    fn record_cache_miss_increments() {
        let m = StoreMetrics::new();
        m.record_cache_miss();
        assert_eq!(m.snapshot().cache_miss, 1);
    }

    #[test]
    fn record_zone_write_errors() {
        let m = StoreMetrics::new();
        m.record_zone_write_ok();
        m.record_zone_write_err();
        let s = m.snapshot();
        assert_eq!(s.zone_write_ok, 1);
        assert_eq!(s.zone_write_err, 1);
    }

    #[test]
    fn record_journal_append() {
        let m = StoreMetrics::new();
        m.record_journal_append_ok();
        m.record_journal_append_ok();
        m.record_journal_append_err();
        let s = m.snapshot();
        assert_eq!(s.journal_append_ok, 2);
        assert_eq!(s.journal_append_err, 1);
    }

    #[test]
    fn pool_gauge_stored_and_retrieved() {
        let m = StoreMetrics::new();
        m.set_pool_connections_in_use(42);
        assert_eq!(m.snapshot().pool_connections_in_use, 42);
    }

    #[test]
    fn reconnect_counter_increments() {
        let m = StoreMetrics::new();
        m.record_reconnect_attempt();
        m.record_reconnect_attempt();
        m.record_reconnect_attempt();
        assert_eq!(m.snapshot().reconnect_attempts, 3);
    }

    #[test]
    fn clone_shares_atomics() {
        let m1 = StoreMetrics::new();
        let m2 = m1.clone();
        m1.record_cache_hit();
        // Both views see the same value because they share the Arc<Inner>.
        assert_eq!(m2.snapshot().cache_hit, 1);
    }
}
