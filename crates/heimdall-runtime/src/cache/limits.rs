// SPDX-License-Identifier: MIT

//! TTL bounds and per-zone admission limits.
//!
//! [`TtlBounds`] encodes the operator-configurable TTL policy (CACHE-010).
//! [`ZoneAdmissionTracker`] enforces the per-zone admission limit (CACHE-013).

use std::time::{Duration, Instant};

// ── TtlBounds ─────────────────────────────────────────────────────────────────

/// Operator-configurable TTL bounds applied when admitting a cache entry.
///
/// All values are in seconds.
///
/// # Defaults
///
/// | Field                   | Default |
/// |-------------------------|---------|
/// | `max_ttl_secs`          | 86400   |
/// | `min_ttl_secs`          | 60      |
/// | `neg_cache_ttl_cap_secs`| 3600    |
/// | `serve_stale_secs`      | 300     |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlBounds {
    /// Maximum TTL in seconds.  Wire TTLs above this are clamped down.
    pub max_ttl_secs: u32,
    /// Minimum TTL in seconds.  Wire TTLs below this are raised (CACHE-010).
    pub min_ttl_secs: u32,
    /// Negative cache TTL cap in seconds (CACHE-009, RFC 2308 §5).
    pub neg_cache_ttl_cap_secs: u32,
    /// Serve-stale window in seconds beyond the primary TTL expiry (CACHE-011,
    /// RFC 8767).  Set to `0` to disable serve-stale globally.
    pub serve_stale_secs: u32,
}

impl Default for TtlBounds {
    fn default() -> Self {
        Self {
            max_ttl_secs: 86_400,
            min_ttl_secs: 60,
            neg_cache_ttl_cap_secs: 3_600,
            serve_stale_secs: 300,
        }
    }
}

impl TtlBounds {
    /// Clamps a positive (non-negative) TTL to `[min_ttl_secs, max_ttl_secs]`.
    #[must_use]
    pub fn clamp_positive(&self, ttl_secs: u32) -> u32 {
        ttl_secs.clamp(self.min_ttl_secs, self.max_ttl_secs)
    }

    /// Clamps a negative-cache TTL to `[min_ttl_secs, neg_cache_ttl_cap_secs]`.
    #[must_use]
    pub fn clamp_negative(&self, soa_minimum_secs: u32) -> u32 {
        soa_minimum_secs
            .min(self.neg_cache_ttl_cap_secs)
            .max(self.min_ttl_secs)
    }

    /// Computes the TTL deadline from `now` for the given `ttl_secs`.
    #[must_use]
    pub fn deadline_positive(&self, now: Instant, ttl_secs: u32) -> Instant {
        let clamped = self.clamp_positive(ttl_secs);
        now + Duration::from_secs(u64::from(clamped))
    }

    /// Computes the TTL deadline from `now` for a negative cache entry.
    #[must_use]
    pub fn deadline_negative(&self, now: Instant, soa_minimum_secs: u32) -> Instant {
        let clamped = self.clamp_negative(soa_minimum_secs);
        now + Duration::from_secs(u64::from(clamped))
    }

    /// Computes the serve-stale deadline given the primary TTL deadline.
    ///
    /// Returns `None` when `serve_stale_secs == 0` (serve-stale disabled).
    #[must_use]
    pub fn stale_deadline(&self, ttl_deadline: Instant) -> Option<Instant> {
        if self.serve_stale_secs == 0 {
            None
        } else {
            Some(ttl_deadline + Duration::from_secs(u64::from(self.serve_stale_secs)))
        }
    }
}

// ── ZoneAdmissionTracker ──────────────────────────────────────────────────────

/// Tracks the number of cache entries per zone apex within a single shard.
///
/// Enforces the per-zone admission limit: at most `limit` entries per zone
/// apex (CACHE-013, default 10% of shard capacity).
#[derive(Debug, Default)]
pub struct ZoneAdmissionTracker {
    /// `zone_apex` (wire-encoded FQDN) → current entry count in this shard.
    counts: std::collections::HashMap<Vec<u8>, usize>,
    /// Maximum entries allowed per zone apex.
    limit: usize,
}

impl ZoneAdmissionTracker {
    /// Creates a new tracker with the given per-zone limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            limit: limit.max(1),
        }
    }

    /// Returns `true` when the zone has remaining admission capacity.
    #[must_use]
    pub fn can_admit(&self, zone_apex: &[u8]) -> bool {
        let current = self.counts.get(zone_apex).copied().unwrap_or(0);
        current < self.limit
    }

    /// Records that one entry for `zone_apex` was admitted.
    pub fn record_admit(&mut self, zone_apex: &[u8]) {
        *self.counts.entry(zone_apex.to_vec()).or_insert(0) += 1;
    }

    /// Records that one entry for `zone_apex` was evicted.
    ///
    /// Saturating-subtracts so the count never underflows.
    pub fn record_evict(&mut self, zone_apex: &[u8]) {
        if let Some(count) = self.counts.get_mut(zone_apex) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(zone_apex);
            }
        }
    }

    /// Returns the current entry count for `zone_apex`.
    #[must_use]
    pub fn count(&self, zone_apex: &[u8]) -> usize {
        self.counts.get(zone_apex).copied().unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{TtlBounds, ZoneAdmissionTracker};

    #[test]
    fn clamp_positive_below_min() {
        let b = TtlBounds::default();
        assert_eq!(b.clamp_positive(0), 60);
        assert_eq!(b.clamp_positive(30), 60);
    }

    #[test]
    fn clamp_positive_above_max() {
        let b = TtlBounds::default();
        assert_eq!(b.clamp_positive(200_000), 86_400);
    }

    #[test]
    fn clamp_positive_within_range() {
        let b = TtlBounds::default();
        assert_eq!(b.clamp_positive(3_600), 3_600);
    }

    #[test]
    fn clamp_negative_caps_at_3600() {
        let b = TtlBounds::default();
        // SOA minimum 7200 → capped at 3600.
        assert_eq!(b.clamp_negative(7_200), 3_600);
    }

    #[test]
    fn clamp_negative_below_min() {
        let b = TtlBounds::default();
        assert_eq!(b.clamp_negative(10), 60);
    }

    #[test]
    fn stale_deadline_disabled_when_zero() {
        let b = TtlBounds {
            serve_stale_secs: 0,
            ..TtlBounds::default()
        };
        let now = std::time::Instant::now();
        assert!(b.stale_deadline(now).is_none());
    }

    #[test]
    fn stale_deadline_set_when_nonzero() {
        let b = TtlBounds::default();
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_secs(300);
        let stale = b.stale_deadline(deadline);
        assert!(stale.is_some());
        assert!(stale.unwrap() > deadline);
    }

    #[test]
    fn zone_tracker_admits_within_limit() {
        let mut t = ZoneAdmissionTracker::new(3);
        let zone = b"\x03foo\x00";
        assert!(t.can_admit(zone));
        t.record_admit(zone);
        t.record_admit(zone);
        t.record_admit(zone);
        assert!(!t.can_admit(zone)); // limit reached
    }

    #[test]
    fn zone_tracker_evict_restores_capacity() {
        let mut t = ZoneAdmissionTracker::new(1);
        let zone = b"\x03bar\x00";
        t.record_admit(zone);
        assert!(!t.can_admit(zone));
        t.record_evict(zone);
        assert!(t.can_admit(zone));
    }
}
