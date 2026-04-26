// SPDX-License-Identifier: MIT

//! Generic two-segment LRU (SLRU) cache implementation.
//!
//! The SLRU policy (Segmented Least-Recently-Used) divides capacity into two
//! segments:
//!
//! - **Probationary** — entries that have been seen exactly once live here.
//! - **Protected** — entries that have been accessed at least twice live here.
//!
//! Access pattern:
//! - A first insert goes to probationary.
//! - A subsequent `get` on a probationary entry promotes it to protected.
//! - Eviction pressure first targets the LRU tail of probationary; if protected
//!   overflows, its LRU tail is demoted back to the probationary tail.
//!
//! # Implementation note
//!
//! The LRU ordering is maintained with a `VecDeque<K>` whose **front** holds the
//! most-recently-used key and whose **back** holds the least-recently-used key.
//! `HashMap` provides O(1) lookup; `VecDeque` removal by value is O(n). For the
//! correctness-first goal of this sprint that trade-off is acceptable; a proper
//! intrusive doubly-linked list is deferred to the performance sprint.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

// ── SlruCache ─────────────────────────────────────────────────────────────────

/// A segmented LRU cache with a protected and a probationary segment.
///
/// # Type parameters
///
/// - `K` — key type; must be `Hash + Eq + Clone`.
/// - `V` — value type.
pub struct SlruCache<K, V> {
    /// Key → value for the protected segment.
    protected_map: HashMap<K, V>,
    /// LRU order for protected (front = MRU, back = LRU).
    protected_order: VecDeque<K>,
    /// Maximum number of entries in the protected segment.
    protected_cap: usize,

    /// Key → value for the probationary segment.
    probationary_map: HashMap<K, V>,
    /// LRU order for probationary (front = MRU, back = LRU).
    probationary_order: VecDeque<K>,
    /// Maximum number of entries in the probationary segment.
    probationary_cap: usize,
}

impl<K, V> SlruCache<K, V>
where
    K: Hash + Eq + Clone,
{
    /// Creates a new [`SlruCache`] with the given segment capacities.
    ///
    /// # Panics
    ///
    /// Panics if both `protected_cap` and `probationary_cap` are zero.
    #[must_use]
    pub fn new(protected_cap: usize, probationary_cap: usize) -> Self {
        assert!(
            protected_cap > 0 || probationary_cap > 0,
            "SlruCache: at least one segment must have non-zero capacity"
        );
        Self {
            protected_map: HashMap::new(),
            protected_order: VecDeque::new(),
            protected_cap,
            probationary_map: HashMap::new(),
            probationary_order: VecDeque::new(),
            probationary_cap,
        }
    }

    /// Returns the total number of entries across both segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.protected_map.len() + self.probationary_map.len()
    }

    /// Returns `true` when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the value for `k`, updating LRU position.
    ///
    /// If `k` is in probationary, it is promoted to protected (triggering
    /// eviction of the protected LRU tail back to probationary if the protected
    /// segment is full).
    ///
    /// Returns `None` when `k` is not present in either segment.
    pub fn get(&mut self, k: &K) -> Option<&V> {
        if self.probationary_map.contains_key(k) {
            // Promote from probationary → protected.
            // Invariant: key was just confirmed present; remove cannot return None.
            let v = self.probationary_map.remove(k)?;
            remove_from_order(&mut self.probationary_order, k);

            // If protected is at capacity, demote its LRU tail to probationary.
            if self.protected_cap > 0
                && self.protected_map.len() >= self.protected_cap
                && let Some(lru_key) = self.protected_order.pop_back()
            {
                // Invariant: every key in protected_order maps to an entry.
                if let Some(lru_val) = self.protected_map.remove(&lru_key) {
                    // Evict probationary LRU if probationary is also full.
                    if self.probationary_cap > 0
                        && self.probationary_map.len() >= self.probationary_cap
                        && let Some(prob_lru) = self.probationary_order.pop_back()
                    {
                        self.probationary_map.remove(&prob_lru);
                    }
                    self.probationary_map.insert(lru_key.clone(), lru_val);
                    self.probationary_order.push_front(lru_key);
                }
            }

            // Insert the promoted entry at the MRU position of protected.
            self.protected_map.insert(k.clone(), v);
            self.protected_order.push_front(k.clone());

            return self.protected_map.get(k);
        }

        if self.protected_map.contains_key(k) {
            // Already protected: refresh LRU position.
            remove_from_order(&mut self.protected_order, k);
            self.protected_order.push_front(k.clone());
            return self.protected_map.get(k);
        }

        None
    }

    /// Inserts `(k, v)` into the cache, placing it in the probationary segment.
    ///
    /// If `k` already exists in either segment, the existing entry is removed
    /// first and replaced (resetting its segment to probationary on re-insert).
    ///
    /// Returns a `Vec` of `(key, value)` pairs that were evicted to make room.
    /// In the common case (no overflow) this vector is empty.
    pub fn insert(&mut self, k: K, v: V) -> Vec<(K, V)> {
        let mut evicted = Vec::new();

        // Remove from whichever segment already holds this key.
        if self.protected_map.remove(&k).is_some() {
            remove_from_order(&mut self.protected_order, &k);
        } else if self.probationary_map.remove(&k).is_some() {
            remove_from_order(&mut self.probationary_order, &k);
        }

        // Evict probationary LRU if probationary is at capacity.
        if self.probationary_cap > 0
            && self.probationary_map.len() >= self.probationary_cap
            && let Some(lru_key) = self.probationary_order.pop_back()
            && let Some(lru_val) = self.probationary_map.remove(&lru_key)
        {
            evicted.push((lru_key, lru_val));
        }

        self.probationary_map.insert(k.clone(), v);
        self.probationary_order.push_front(k);

        evicted
    }

    /// Removes and returns the value associated with `k`, if present.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        if let Some(v) = self.protected_map.remove(k) {
            remove_from_order(&mut self.protected_order, k);
            return Some(v);
        }
        if let Some(v) = self.probationary_map.remove(k) {
            remove_from_order(&mut self.probationary_order, k);
            return Some(v);
        }
        None
    }

    /// Returns the number of entries in the probationary segment.
    #[cfg(test)]
    #[must_use]
    pub fn probationary_len(&self) -> usize {
        self.probationary_map.len()
    }

    /// Returns the number of entries in the protected segment.
    #[cfg(test)]
    #[must_use]
    pub fn protected_len(&self) -> usize {
        self.protected_map.len()
    }

    /// Iterates over all entries in both segments, calling `f` for each.
    ///
    /// Order is unspecified.  Used for background expiry sweeps.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for (k, v) in &self.protected_map {
            f(k, v);
        }
        for (k, v) in &self.probationary_map {
            f(k, v);
        }
    }

    /// Removes all entries for which `predicate(key, value)` returns `true`.
    ///
    /// Returns the number of entries removed.
    pub fn retain<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&K, &V) -> bool,
    {
        let mut removed = 0usize;

        let to_remove_protected: Vec<K> = self
            .protected_map
            .iter()
            .filter(|(k, v)| predicate(k, v))
            .map(|(k, _)| k.clone())
            .collect();

        for k in &to_remove_protected {
            self.protected_map.remove(k);
            remove_from_order(&mut self.protected_order, k);
            removed += 1;
        }

        let to_remove_prob: Vec<K> = self
            .probationary_map
            .iter()
            .filter(|(k, v)| predicate(k, v))
            .map(|(k, _)| k.clone())
            .collect();

        for k in &to_remove_prob {
            self.probationary_map.remove(k);
            remove_from_order(&mut self.probationary_order, k);
            removed += 1;
        }

        removed
    }

    /// Evicts the least-recently-used probationary entry.
    ///
    /// Returns `Some((key, value))` if an entry was evicted, `None` if the
    /// probationary segment was empty.
    pub fn evict_lru_probationary(&mut self) -> Option<(K, V)> {
        let lru_key = self.probationary_order.pop_back()?;
        // Invariant: every key in probationary_order has a corresponding entry
        // in probationary_map; the two structures are always kept in sync.
        let lru_val = self.probationary_map.remove(&lru_key)?;
        Some((lru_key, lru_val))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Removes the first occurrence of `k` from `order`.
///
/// O(n) — acceptable for the correctness sprint; revisit in the performance sprint.
fn remove_from_order<K: PartialEq>(order: &mut VecDeque<K>, k: &K) {
    if let Some(pos) = order.iter().position(|x| x == k) {
        order.remove(pos);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::SlruCache;

    #[test]
    fn insert_goes_to_probationary() {
        let mut cache: SlruCache<u32, &str> = SlruCache::new(4, 4);
        cache.insert(1, "a");
        assert_eq!(cache.probationary_len(), 1);
        assert_eq!(cache.protected_len(), 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn get_promotes_from_probationary_to_protected() {
        let mut cache: SlruCache<u32, &str> = SlruCache::new(4, 4);
        cache.insert(1, "a");
        assert_eq!(cache.probationary_len(), 1);
        // First get → promote.
        let v = cache.get(&1);
        assert_eq!(v, Some(&"a"));
        assert_eq!(cache.probationary_len(), 0);
        assert_eq!(cache.protected_len(), 1);
    }

    #[test]
    fn second_get_keeps_in_protected() {
        let mut cache: SlruCache<u32, &str> = SlruCache::new(4, 4);
        cache.insert(1, "a");
        cache.get(&1); // promote
        cache.get(&1); // still protected
        assert_eq!(cache.protected_len(), 1);
        assert_eq!(cache.probationary_len(), 0);
    }

    #[test]
    fn evicts_from_probationary_first() {
        // Probationary cap = 2, protected cap = 2.
        let mut cache: SlruCache<u32, &str> = SlruCache::new(2, 2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        // Insert 3rd → evicts LRU of probationary (key 1, the oldest).
        let evicted = cache.insert(3, "c");
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn protected_overflow_demotes_to_probationary() {
        // Protected cap = 2, probationary cap = 4.
        let mut cache: SlruCache<u32, &str> = SlruCache::new(2, 4);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        // Promote all three to protected.
        cache.get(&1);
        cache.get(&2);
        cache.get(&3); // protected now has 2 (cap), key 1 demoted to probationary
        assert_eq!(cache.protected_len(), 2);
        // Key 1 was demoted to probationary.
        assert_eq!(cache.probationary_len(), 1);
    }

    #[test]
    fn lru_eviction_order_probationary() {
        // Probationary cap = 3, protected cap = 0 (no promotions).
        let mut cache: SlruCache<u32, &str> = SlruCache::new(0, 3);
        cache.insert(1, "a"); // order: [1]
        cache.insert(2, "b"); // order: [2, 1]
        cache.insert(3, "c"); // order: [3, 2, 1]
        // Evict LRU = 1.
        let evicted = cache.insert(4, "d");
        assert_eq!(evicted[0].0, 1);
    }

    #[test]
    fn remove_works_in_both_segments() {
        let mut cache: SlruCache<u32, &str> = SlruCache::new(4, 4);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.get(&1); // promote 1 to protected
        assert_eq!(cache.remove(&1), Some("a")); // from protected
        assert_eq!(cache.remove(&2), Some("b")); // from probationary
        assert_eq!(cache.remove(&99), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn len_tracking_consistent() {
        let mut cache: SlruCache<u32, u32> = SlruCache::new(8, 8);
        for i in 0..10u32 {
            cache.insert(i, i * 10);
        }
        for i in (1..10u32).step_by(2) {
            cache.get(&i);
        }
        assert_eq!(
            cache.len(),
            cache.probationary_len() + cache.protected_len()
        );
    }

    #[test]
    fn insert_replaces_existing_key() {
        let mut cache: SlruCache<u32, &str> = SlruCache::new(4, 4);
        cache.insert(1, "first");
        cache.insert(1, "second");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&1), Some(&"second"));
    }

    #[test]
    fn retain_removes_matching_entries() {
        // Capacity large enough to hold all 6 entries without eviction.
        let mut cache: SlruCache<u32, u32> = SlruCache::new(8, 8);
        for i in 0..6u32 {
            cache.insert(i, i);
        }
        assert_eq!(cache.len(), 6);
        // retain removes entries where predicate is true.
        // Even keys: 0, 2, 4 → 3 entries removed.
        let removed = cache.retain(|k, _v| k % 2 == 0);
        assert_eq!(removed, 3);
        for k in [0u32, 2, 4] {
            assert_eq!(cache.get(&k), None, "even key {k} must have been removed");
        }
        for k in [1u32, 3, 5] {
            assert!(cache.get(&k).is_some(), "odd key {k} must remain");
        }
    }
}
