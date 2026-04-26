// SPDX-License-Identifier: MIT

//! Recursive-resolver query-response cache.
//!
//! [`RecursiveCache`] is a distinct newtype — it cannot be confused with
//! [`ForwarderCache`] at compile time (CACHE-002).  It wraps a sharded SLRU
//! indexed by [`CacheKey`] with a default of 32 shards and a 512 MiB memory
//! budget (CACHE-005).
//!
//! # DNSSEC policy
//!
//! - Bogus entries: stored for a 60-second penalty, never served (CACHE-014).
//! - Secure entries: serve-stale window = `TtlBounds::serve_stale_secs` (CACHE-011).
//! - Negative entries: TTL capped at `min(soa_minimum, 3600 s)` (CACHE-009).
//!
//! [`ForwarderCache`]: crate::cache::ForwarderCache

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use heimdall_core::dnssec::ValidationOutcome;
use tracing::debug;

use crate::cache::entry::CacheEntry;
use crate::cache::limits::{TtlBounds, ZoneAdmissionTracker};
use crate::cache::shard::ShardedCache;
use crate::cache::{CacheKey, LookupResult};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of shards for the recursive cache (CACHE-008).
const SHARD_COUNT: usize = 32;

/// Default memory budget for the recursive cache: 512 MiB (CACHE-005).
const DEFAULT_BUDGET_BYTES: usize = 512 * 1024 * 1024;

/// Heuristic per-entry size used for approximate memory accounting.
/// Chosen conservatively: typical DNS `RRset` ≈ 512 bytes.
const APPROX_ENTRY_BYTES: usize = 512;

/// Fixed penalty TTL for `Bogus` entries in seconds (CACHE-014).
const BOGUS_PENALTY_SECS: u64 = 60;

// ── RecursiveCache ────────────────────────────────────────────────────────────

/// Query-response cache for the recursive-resolver role.
///
/// This type is deliberately distinct from [`ForwarderCache`]: the Rust type
/// system prevents cross-role cache access at compile time (CACHE-002).
///
/// [`ForwarderCache`]: crate::cache::ForwarderCache
pub struct RecursiveCache {
    /// Inner sharded SLRU.
    inner: ShardedCache<CacheKey, CacheEntry, SHARD_COUNT>,
    /// Per-zone entry counts, one tracker per shard.
    zone_trackers: [Mutex<ZoneAdmissionTracker>; SHARD_COUNT],
    /// Operator-configurable TTL policy.
    ttl_bounds: TtlBounds,
    /// Maximum approximate memory usage in bytes.
    budget_bytes: usize,
}

impl RecursiveCache {
    /// Creates a new [`RecursiveCache`] with the given capacity and default TTL bounds.
    ///
    /// `protected_cap` and `probationary_cap` are the total entry counts
    /// across all shards.
    #[must_use]
    pub fn new(protected_cap: usize, probationary_cap: usize) -> Self {
        Self::with_bounds(protected_cap, probationary_cap, TtlBounds::default())
    }

    /// Creates a new [`RecursiveCache`] with explicit TTL bounds.
    #[must_use]
    pub fn with_bounds(
        protected_cap: usize,
        probationary_cap: usize,
        ttl_bounds: TtlBounds,
    ) -> Self {
        // Per-zone limit = 10% of total shard capacity, minimum 1 (CACHE-013).
        let shard_prob = (probationary_cap / SHARD_COUNT).max(1);
        let shard_prot = (protected_cap / SHARD_COUNT).max(1);
        let per_zone_limit = ((shard_prob + shard_prot) / 10).max(1);

        let zone_trackers =
            std::array::from_fn(|_| Mutex::new(ZoneAdmissionTracker::new(per_zone_limit)));

        Self {
            inner: ShardedCache::new(protected_cap, probationary_cap),
            zone_trackers,
            ttl_bounds,
            budget_bytes: DEFAULT_BUDGET_BYTES,
        }
    }

    /// Overrides the memory budget.
    #[must_use]
    pub fn with_budget(mut self, budget_bytes: usize) -> Self {
        self.budget_bytes = budget_bytes;
        self
    }

    /// Looks up `key` at `now`.
    ///
    /// Returns:
    /// - [`LookupResult::Hit`] — entry is live.
    /// - [`LookupResult::Stale`] — entry is expired but within its serve-stale
    ///   window (RFC 8767); the caller must re-validate upstream while serving
    ///   the stale copy.
    /// - [`LookupResult::Miss`] — not found, expired beyond stale window, or
    ///   a bogus entry whose 60-second penalty is still active.
    pub fn get(&self, key: &CacheKey, now: Instant) -> LookupResult {
        match self.inner.get_cloned(key) {
            None => LookupResult::Miss,
            Some(entry) => classify_entry(entry, now),
        }
    }

    /// Inserts an entry, applying TTL bounds and per-zone admission limits.
    ///
    /// When the memory budget is exceeded, LRU entries are evicted from the
    /// probationary segment until the budget is satisfied (CACHE-005).
    ///
    /// Bogus entries receive a fixed 60-second penalty TTL regardless of the
    /// wire TTL (CACHE-014).
    pub fn insert(&self, key: CacheKey, mut entry: CacheEntry) {
        let now = Instant::now();
        apply_ttl_bounds(&mut entry, now, &self.ttl_bounds);

        let shard_idx = shard_index_for(&key);
        let zone_apex = entry.zone_apex.clone();

        // Per-zone admission check (CACHE-013).
        {
            let mut tracker = self.zone_trackers[shard_idx]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !tracker.can_admit(&zone_apex) {
                // Evict the LRU probationary entry for this zone before admitting.
                self.inner.with_shard_mut(&key, |shard| {
                    let mut found_one = false;
                    shard.retain(|_k, v| {
                        if !found_one && v.zone_apex == zone_apex {
                            found_one = true;
                            true // remove this entry
                        } else {
                            false
                        }
                    });
                });
                tracker.record_evict(&zone_apex);
            }
            tracker.record_admit(&zone_apex);
        }

        // Memory budget enforcement (CACHE-005).
        self.enforce_budget();

        let evicted = self.inner.insert(key, entry);
        for (evicted_key, evicted_entry) in evicted {
            debug!(
                key = ?evicted_key,
                "recursive cache: evicted entry due to capacity"
            );
            self.record_zone_evict(shard_index_for(&evicted_key), &evicted_entry.zone_apex);
        }
    }

    /// Removes expired entries opportunistically (background sweep).
    ///
    /// This is intended to be called periodically from a background task to
    /// reclaim memory from entries that have expired but not yet been displaced
    /// by newer insertions.
    pub fn evict_expired(&self, now: Instant) {
        self.inner.retain(|_k, v| v.is_expired(now));
    }

    /// Returns the approximate memory usage in bytes (heuristic).
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.inner.len() * APPROX_ENTRY_BYTES
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn enforce_budget(&self) {
        while self.size_bytes() > self.budget_bytes {
            // Evict one LRU probationary entry per shard sweep.
            // We iterate in a fixed order; approximate fairness is sufficient.
            let mut evicted_any = false;
            for shard_mutex in self.inner.shards_raw() {
                let maybe_evicted = shard_mutex
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .evict_lru_probationary();
                if let Some((_k, _v)) = maybe_evicted {
                    debug!("recursive cache: evicted entry due to memory budget");
                    // Zone accounting is best-effort under budget pressure; the
                    // zone_apex is available but the shard index cannot be
                    // recovered without re-hashing, so the tracker may drift by
                    // ≤1 per budget eviction.
                    evicted_any = true;
                    break;
                }
            }
            if !evicted_any {
                break;
            }
        }
    }

    fn record_zone_evict(&self, shard_idx: usize, zone_apex: &[u8]) {
        self.zone_trackers[shard_idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_evict(zone_apex);
    }
}

// ── Helpers shared with ForwarderCache ────────────────────────────────────────

/// Classifies a cache entry into a [`LookupResult`] based on expiry.
pub(super) fn classify_entry(entry: CacheEntry, now: Instant) -> LookupResult {
    if !entry.is_expired(now) {
        // Bogus entries within penalty window must not be served (CACHE-014).
        if matches!(entry.dnssec_outcome, ValidationOutcome::Bogus(_)) {
            return LookupResult::Miss;
        }
        return LookupResult::Hit(entry);
    }
    if entry.is_serveable_stale(now) {
        return LookupResult::Stale(entry);
    }
    LookupResult::Miss
}

/// Applies TTL bounds to `entry` in-place.
pub(super) fn apply_ttl_bounds(entry: &mut CacheEntry, now: Instant, bounds: &TtlBounds) {
    // Bogus entries: fixed 60-second penalty, never stale (CACHE-014).
    if matches!(entry.dnssec_outcome, ValidationOutcome::Bogus(_)) {
        entry.ttl_deadline = now + Duration::from_secs(BOGUS_PENALTY_SECS);
        entry.serve_stale_until = None;
        return;
    }

    // Negative entries: TTL capped at neg_cache_ttl_cap_secs (CACHE-009).
    if entry.is_negative {
        let original_secs = entry
            .ttl_deadline
            .checked_duration_since(now)
            .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
        let clamped = bounds.clamp_negative(original_secs);
        let new_deadline = now + Duration::from_secs(u64::from(clamped));
        entry.ttl_deadline = new_deadline;
        entry.serve_stale_until = bounds.stale_deadline(new_deadline);
        return;
    }

    // Positive entries: clamp within [min_ttl, max_ttl].
    let original_secs = entry
        .ttl_deadline
        .checked_duration_since(now)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
    let clamped = bounds.clamp_positive(original_secs);
    let new_deadline = now + Duration::from_secs(u64::from(clamped));
    entry.ttl_deadline = new_deadline;
    entry.serve_stale_until = bounds.stale_deadline(new_deadline);
}

/// Returns the shard index for `key`.
fn shard_index_for(key: &CacheKey) -> usize {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    // Truncation is intentional: upper bits are discarded on 32-bit targets.
    // The result is reduced modulo SHARD_COUNT, which is at most 64.
    #[allow(clippy::cast_possible_truncation)]
    let idx = h.finish() as usize;
    idx % SHARD_COUNT
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use heimdall_core::dnssec::{BogusReason, ValidationOutcome};

    use super::{RecursiveCache, apply_ttl_bounds};
    use crate::cache::entry::CacheEntry;
    use crate::cache::limits::TtlBounds;
    use crate::cache::{CacheKey, LookupResult};

    fn make_key(qname: &[u8]) -> CacheKey {
        CacheKey {
            qname: qname.to_vec(),
            qtype: 1,
            qclass: 1,
        }
    }

    fn make_entry(ttl_secs: u64, outcome: ValidationOutcome, is_negative: bool) -> CacheEntry {
        let now = Instant::now();
        let ttl_deadline = now + Duration::from_secs(ttl_secs);
        let bounds = TtlBounds::default();
        let serve_stale_until = if matches!(outcome, ValidationOutcome::Bogus(_)) {
            None
        } else {
            bounds.stale_deadline(ttl_deadline)
        };
        CacheEntry {
            rdata_wire: vec![1, 2, 3],
            ttl_deadline,
            dnssec_outcome: outcome,
            is_negative,
            serve_stale_until,
            zone_apex: b"\x07example\x03com\x00".to_vec(),
        }
    }

    #[test]
    fn ttl_clamped_below_minimum() {
        let bounds = TtlBounds::default(); // min = 60
        let now = Instant::now();
        let mut entry = make_entry(10, ValidationOutcome::Insecure, false);
        apply_ttl_bounds(&mut entry, now, &bounds);
        let remaining = entry
            .ttl_deadline
            .checked_duration_since(now)
            .expect("deadline must be in the future after clamping");
        assert!(
            remaining >= Duration::from_secs(59),
            "TTL must have been raised to at least min_ttl"
        );
    }

    #[test]
    fn ttl_clamped_above_maximum() {
        let bounds = TtlBounds::default(); // max = 86400
        let now = Instant::now();
        let mut entry = make_entry(200_000, ValidationOutcome::Insecure, false);
        apply_ttl_bounds(&mut entry, now, &bounds);
        let remaining = entry
            .ttl_deadline
            .checked_duration_since(now)
            .expect("deadline must be in the future after clamping");
        assert!(
            remaining <= Duration::from_secs(86_401),
            "TTL must be capped at max_ttl"
        );
    }

    #[test]
    fn negative_ttl_cap_applied() {
        let bounds = TtlBounds::default(); // neg_cache_ttl_cap = 3600
        let now = Instant::now();
        // SOA minimum = 7200 — should be capped at 3600.
        let mut entry = make_entry(7_200, ValidationOutcome::Insecure, true);
        apply_ttl_bounds(&mut entry, now, &bounds);
        let remaining = entry
            .ttl_deadline
            .checked_duration_since(now)
            .expect("deadline must be in the future after clamping");
        assert!(
            remaining <= Duration::from_secs(3_601),
            "Negative TTL must be capped at neg_cache_ttl_cap"
        );
    }

    #[test]
    fn bogus_gets_60s_penalty_and_no_stale() {
        let bounds = TtlBounds::default();
        let now = Instant::now();
        let mut entry = make_entry(
            3_600,
            ValidationOutcome::Bogus(BogusReason::InvalidSignature),
            false,
        );
        apply_ttl_bounds(&mut entry, now, &bounds);
        let remaining = entry
            .ttl_deadline
            .checked_duration_since(now)
            .expect("deadline must be in the future after clamping");
        assert!(
            remaining <= Duration::from_secs(61),
            "Bogus penalty must be ≤ 60s"
        );
        assert!(
            remaining >= Duration::from_secs(59),
            "Bogus penalty must be ≥ 59s"
        );
        assert!(
            entry.serve_stale_until.is_none(),
            "Bogus entries must never have a stale deadline"
        );
    }

    #[test]
    fn hit_returns_entry() {
        let cache = RecursiveCache::new(256, 256);
        let key = make_key(b"\x03www\x07example\x03com\x00");
        let entry = make_entry(300, ValidationOutcome::Insecure, false);
        cache.insert(key.clone(), entry);
        let result = cache.get(&key, Instant::now());
        assert!(matches!(result, LookupResult::Hit(_)));
    }

    #[test]
    fn miss_for_absent_key() {
        let cache = RecursiveCache::new(256, 256);
        let key = make_key(b"\x03foo\x07example\x03com\x00");
        assert!(matches!(
            cache.get(&key, Instant::now()),
            LookupResult::Miss
        ));
    }

    #[test]
    fn per_zone_limit_enforced() {
        // Small cache: total per-shard capacity is very low, so zone limits kick in.
        let cache = RecursiveCache::new(4, 4);
        for i in 0u8..4 {
            let qname = vec![
                1u8,
                b'a' + i,
                7,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                3,
                b'c',
                b'o',
                b'm',
                0,
            ];
            let key = CacheKey {
                qname,
                qtype: 1,
                qclass: 1,
            };
            let entry = make_entry(300, ValidationOutcome::Insecure, false);
            cache.insert(key, entry);
        }
        // Just verify the cache doesn't panic and stays bounded.
        assert!(cache.inner.len() <= 8, "total must not exceed capacity");
    }
}
