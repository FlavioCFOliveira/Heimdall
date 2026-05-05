// SPDX-License-Identifier: MIT

//! Forwarder query-response cache.
//!
//! [`ForwarderCache`] is a distinct newtype — it cannot be confused with
//! [`RecursiveCache`] at compile time (CACHE-002).  It wraps a sharded SLRU
//! indexed by [`CacheKey`] with a default of 32 shards and a 256 MiB memory
//! budget (CACHE-005).
//!
//! All DNSSEC, TTL, and serve-stale policies are identical to those of
//! [`RecursiveCache`]; the operational distinction is the resolution trust
//! boundary (see `004-cache-policy.md §4`).
//!
//! [`RecursiveCache`]: crate::cache::RecursiveCache

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Mutex,
    time::Instant,
};

use tracing::debug;

use crate::cache::{
    CacheKey, LookupResult,
    entry::CacheEntry,
    limits::{TtlBounds, ZoneAdmissionTracker},
    recursive::{apply_ttl_bounds, classify_entry},
    shard::ShardedCache,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of shards for the forwarder cache (CACHE-008).
const SHARD_COUNT: usize = 32;

/// Default memory budget for the forwarder cache: 256 MiB (CACHE-005).
const DEFAULT_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Heuristic per-entry size for approximate memory accounting.
const APPROX_ENTRY_BYTES: usize = 512;

// ── ForwarderCache ────────────────────────────────────────────────────────────

/// Query-response cache for the forwarder role.
///
/// This type is deliberately distinct from [`RecursiveCache`]: the Rust type
/// system prevents cross-role cache access at compile time (CACHE-002).
///
/// [`RecursiveCache`]: crate::cache::RecursiveCache
pub struct ForwarderCache {
    /// Inner sharded SLRU.
    inner: ShardedCache<CacheKey, CacheEntry, SHARD_COUNT>,
    /// Per-zone entry counts, one tracker per shard.
    zone_trackers: [Mutex<ZoneAdmissionTracker>; SHARD_COUNT],
    /// Operator-configurable TTL policy.
    ttl_bounds: TtlBounds,
    /// Maximum approximate memory usage in bytes.
    budget_bytes: usize,
}

impl ForwarderCache {
    /// Creates a new [`ForwarderCache`] with the given capacity and default TTL bounds.
    #[must_use]
    pub fn new(protected_cap: usize, probationary_cap: usize) -> Self {
        Self::with_bounds(protected_cap, probationary_cap, TtlBounds::default())
    }

    /// Creates a new [`ForwarderCache`] with explicit TTL bounds.
    #[must_use]
    pub fn with_bounds(
        protected_cap: usize,
        probationary_cap: usize,
        ttl_bounds: TtlBounds,
    ) -> Self {
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
    /// See [`RecursiveCache::get`] for the full semantics of the returned
    /// [`LookupResult`].
    ///
    /// [`RecursiveCache::get`]: crate::cache::RecursiveCache::get
    pub fn get(&self, key: &CacheKey, now: Instant) -> LookupResult {
        match self.inner.get_cloned(key) {
            None => LookupResult::Miss,
            Some(entry) => classify_entry(entry, now),
        }
    }

    /// Inserts an entry, applying TTL bounds and per-zone admission limits.
    ///
    /// See [`RecursiveCache::insert`] for the full policy.
    ///
    /// [`RecursiveCache::insert`]: crate::cache::RecursiveCache::insert
    pub fn insert(&self, key: CacheKey, mut entry: CacheEntry) {
        let now = Instant::now();
        apply_ttl_bounds(&mut entry, now, &self.ttl_bounds);

        let shard_idx = shard_index_for(&key);
        let zone_apex = entry.zone_apex.clone();

        {
            let mut tracker = self.zone_trackers[shard_idx]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !tracker.can_admit(&zone_apex) {
                self.inner.with_shard_mut(&key, |shard| {
                    let mut found_one = false;
                    shard.retain(|_k, v| {
                        if !found_one && v.zone_apex == zone_apex {
                            found_one = true;
                            true
                        } else {
                            false
                        }
                    });
                });
                tracker.record_evict(&zone_apex);
            }
            tracker.record_admit(&zone_apex);
        }

        self.enforce_budget();

        let evicted = self.inner.insert(key, entry);
        for (evicted_key, evicted_entry) in evicted {
            debug!(
                key = ?evicted_key,
                "forwarder cache: evicted entry due to capacity"
            );
            self.record_zone_evict(shard_index_for(&evicted_key), &evicted_entry.zone_apex);
        }
    }

    /// Removes expired entries opportunistically (background sweep).
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
            let mut evicted_any = false;
            for shard_mutex in self.inner.shards_raw() {
                let maybe_evicted = shard_mutex
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .evict_lru_probationary();
                if maybe_evicted.is_some() {
                    debug!("forwarder cache: evicted entry due to memory budget");
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

// ── Helper ────────────────────────────────────────────────────────────────────

fn shard_index_for(key: &CacheKey) -> usize {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    // Truncation is intentional: upper bits are discarded on 32-bit targets.
    #[allow(clippy::cast_possible_truncation)]
    let idx = h.finish() as usize;
    idx % SHARD_COUNT
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use heimdall_core::dnssec::ValidationOutcome;

    use super::ForwarderCache;
    use crate::cache::{CacheKey, LookupResult, entry::CacheEntry};

    fn make_key(label: &[u8]) -> CacheKey {
        CacheKey {
            qname: label.to_vec(),
            qtype: 1,
            qclass: 1,
        }
    }

    fn make_entry(ttl_secs: u64) -> CacheEntry {
        let now = Instant::now();
        let ttl_deadline = now + Duration::from_secs(ttl_secs);
        CacheEntry {
            rdata_wire: vec![0xDE, 0xAD],
            ttl_deadline,
            dnssec_outcome: ValidationOutcome::Insecure,
            is_negative: false,
            serve_stale_until: Some(ttl_deadline + Duration::from_mins(5)),
            zone_apex: b"\x03fwd\x00".to_vec(),
        }
    }

    #[test]
    fn forwarder_hit() {
        let cache = ForwarderCache::new(256, 256);
        let key = make_key(b"\x03fwd\x00");
        cache.insert(key.clone(), make_entry(300));
        assert!(matches!(
            cache.get(&key, Instant::now()),
            LookupResult::Hit(_)
        ));
    }

    #[test]
    fn forwarder_miss_for_absent_key() {
        let cache = ForwarderCache::new(256, 256);
        let key = make_key(b"\x07missing\x00");
        assert!(matches!(
            cache.get(&key, Instant::now()),
            LookupResult::Miss
        ));
    }
}
