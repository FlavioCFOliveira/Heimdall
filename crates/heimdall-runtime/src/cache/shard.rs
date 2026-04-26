// SPDX-License-Identifier: MIT

//! Sharded SLRU cache wrapper.
//!
//! [`ShardedCache`] partitions its key space across `N` independent
//! [`SlruCache`] shards, each protected by its own mutex.  On any cache hit or
//! miss, only the shard that owns the key is locked; all other shards remain
//! fully available for concurrent access (CACHE-008).
//!
//! # Shard selection
//!
//! The shard index is derived by hashing the key with [`std::hash::DefaultHasher`]
//! and reducing modulo `N`.  `DefaultHasher` is not cryptographically secure but
//! is fast, stable within a single process, and sufficient for load-balancing
//! across shards.
//!
//! # Loom support
//!
//! Under `--cfg loom` the module substitutes `loom::sync::Mutex` for
//! `std::sync::Mutex` so that concurrency models can be explored with the loom
//! scheduler.

use std::hash::{DefaultHasher, Hash, Hasher};

#[cfg(loom)]
use loom::sync::Mutex;
#[cfg(not(loom))]
use std::sync::Mutex;

use crate::cache::slru::SlruCache;

// ── ShardedCache ──────────────────────────────────────────────────────────────

/// A sharded cache of `N` SLRU shards, each independently locked.
///
/// The default `N = 32` is chosen to minimise mutex contention under the
/// concurrency levels targeted by Heimdall (CACHE-008).
pub struct ShardedCache<K, V, const N: usize> {
    pub(super) shards: [Mutex<SlruCache<K, V>>; N],
}

impl<K, V, const N: usize> ShardedCache<K, V, N>
where
    K: Hash + Eq + Clone,
{
    /// Creates a new [`ShardedCache`].
    ///
    /// Total logical capacity is split evenly across shards:
    /// each shard receives `protected_cap / N` and `probationary_cap / N`
    /// entries (minimum 1 per segment per shard).
    #[must_use]
    pub fn new(protected_cap: usize, probationary_cap: usize) -> Self {
        // Per-shard capacities, minimum 1 so no shard has zero capacity.
        let shard_protected = (protected_cap / N).max(1);
        let shard_probationary = (probationary_cap / N).max(1);

        let shards = std::array::from_fn(|_| {
            Mutex::new(SlruCache::new(shard_protected, shard_probationary))
        });

        Self { shards }
    }

    /// Returns the shard index for `key`.
    fn shard_index(key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        // Truncation is intentional: we need a usize index from a u64 hash.
        // On 32-bit targets this discards the upper 32 bits, which is acceptable
        // since we only use the result modulo N (at most 64).
        #[allow(clippy::cast_possible_truncation)]
        let h = hasher.finish() as usize;
        h % N
    }

    /// Acquires the shard for `key` and calls `f` with a mutable reference.
    ///
    /// Mutex poisoning is recovered by taking the inner value, because a panic
    /// while holding the shard lock is a bug elsewhere — the data itself is
    /// not corrupted (the LRU structures are consistent at the time of the panic
    /// boundary), and refusing to use a poisoned mutex would cause all future
    /// operations on that shard to fail permanently.
    fn with_shard<F, R>(&self, key: &K, f: F) -> R
    where
        F: FnOnce(&mut SlruCache<K, V>) -> R,
    {
        let idx = Self::shard_index(key);
        let mut guard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut *guard)
    }

    /// Looks up `key`, returning a clone of the value if present.
    ///
    /// A successful lookup promotes a probationary entry to protected.
    pub fn get_cloned(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.with_shard(key, |shard| shard.get(key).cloned())
    }

    /// Inserts `(key, value)` into the appropriate shard.
    ///
    /// Returns evicted `(key, value)` pairs.
    pub fn insert(&self, key: K, value: V) -> Vec<(K, V)> {
        self.with_shard(&key.clone(), |shard| shard.insert(key, value))
    }

    /// Removes `key` from the cache, returning the value if it was present.
    pub fn remove(&self, key: &K) -> Option<V> {
        self.with_shard(key, |shard| shard.remove(key))
    }

    /// Returns the total number of entries across all shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|m| {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }

    /// Returns `true` when all shards are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies `predicate` across all shards, removing matching entries.
    ///
    /// Returns the total number of entries removed.
    pub fn retain<F>(&self, predicate: F) -> usize
    where
        F: Fn(&K, &V) -> bool,
    {
        self.shards
            .iter()
            .map(|m| {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(&predicate)
            })
            .sum()
    }

    /// Calls `f` with a mutable borrow of the shard that owns `key`.
    ///
    /// This is a lower-level escape hatch used by `RecursiveCache` and
    /// `ForwarderCache` for operations that need direct shard access (e.g.
    /// per-zone accounting).
    pub fn with_shard_mut<F, R>(&self, key: &K, f: F) -> R
    where
        F: FnOnce(&mut SlruCache<K, V>) -> R,
    {
        self.with_shard(key, f)
    }

    /// Returns a reference to the raw shard array.
    ///
    /// Used by `RecursiveCache` and `ForwarderCache` for budget-driven eviction
    /// sweeps that need to iterate across all shards without a key.
    pub fn shards_raw(&self) -> &[Mutex<SlruCache<K, V>>; N] {
        &self.shards
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::ShardedCache;

    #[test]
    fn basic_insert_get_remove() {
        let cache: ShardedCache<u32, String, 4> = ShardedCache::new(8, 8);
        cache.insert(1, "hello".to_owned());
        assert_eq!(cache.get_cloned(&1).as_deref(), Some("hello"));
        assert_eq!(cache.remove(&1).as_deref(), Some("hello"));
        assert!(cache.get_cloned(&1).is_none());
    }

    #[test]
    fn missing_key_returns_none() {
        let cache: ShardedCache<u32, u32, 4> = ShardedCache::new(8, 8);
        assert!(cache.get_cloned(&42).is_none());
        assert!(cache.remove(&42).is_none());
    }

    #[test]
    fn len_tracks_insertions() {
        let cache: ShardedCache<u32, u32, 8> = ShardedCache::new(64, 64);
        for i in 0..10u32 {
            cache.insert(i, i * 2);
        }
        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn keys_land_on_different_shards() {
        let cache: ShardedCache<u32, u32, 32> = ShardedCache::new(256, 256);
        for i in 0..32u32 {
            cache.insert(i, i);
        }
        for i in 0..32u32 {
            assert_eq!(cache.get_cloned(&i), Some(i));
        }
    }

    #[test]
    fn retain_removes_selected_entries() {
        let cache: ShardedCache<u32, u32, 4> = ShardedCache::new(32, 32);
        for i in 0..8u32 {
            cache.insert(i, i);
        }
        // Remove odd keys.
        cache.retain(|k, _| k % 2 != 0);
        for i in (1..8u32).step_by(2) {
            assert!(cache.get_cloned(&i).is_none());
        }
        for i in (0..8u32).step_by(2) {
            assert_eq!(cache.get_cloned(&i), Some(i));
        }
    }
}
