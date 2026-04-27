// SPDX-License-Identifier: MIT

//! Negative Trust Anchor (NTA) store (DNSSEC-016..018/024).
//!
//! [`NtaStore`] maintains a bounded, time-limited set of negative trust
//! anchors — domains for which DNSSEC validation is intentionally bypassed.
//! All lifecycle events are emitted as structured `tracing` events at INFO
//! level with `event = "nta_lifecycle"`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use heimdall_core::name::Name;
use tracing::info;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single Negative Trust Anchor entry.
#[derive(Debug, Clone)]
pub struct NtaEntry {
    /// The domain for which DNSSEC validation is bypassed.
    pub domain: Name,
    /// Unix second at which this NTA expires.
    pub expires_at: u64,
    /// Human-readable reason for adding this NTA.
    pub reason: String,
}

/// Errors that can arise when operating on the [`NtaStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtaError {
    /// The store has reached its entry limit; no more entries can be added.
    StoreFull {
        /// The configured maximum.
        max: usize,
    },
}

impl std::fmt::Display for NtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreFull { max } => {
                write!(f, "NTA store is at capacity ({max} entries)")
            }
        }
    }
}

impl std::error::Error for NtaError {}

// ── NtaStore ──────────────────────────────────────────────────────────────────

/// Thread-safe, bounded store for Negative Trust Anchors.
///
/// Entries are indexed by domain name (using wire-byte ordering via
/// [`Name`]'s `Ord` implementation) and expire lazily on access.
pub struct NtaStore {
    inner: Mutex<BTreeMap<Vec<u8>, NtaEntry>>,
    max_entries: usize,
}

impl NtaStore {
    /// Default maximum number of concurrent NTA entries.
    pub const DEFAULT_MAX_ENTRIES: usize = 100;

    /// Creates a new [`NtaStore`] with the given entry limit.
    ///
    /// `max_entries` is clamped to a minimum of 1.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// Adds an NTA for `domain` that expires at `expires_at` (Unix seconds).
    ///
    /// # Errors
    ///
    /// Returns [`NtaError::StoreFull`] if the store is at its maximum capacity
    /// and the domain is not already present (updates are always allowed).
    pub fn add(
        &self,
        domain: Name,
        expires_at: u64,
        reason: impl Into<String>,
    ) -> Result<(), NtaError> {
        let key = name_key(&domain);
        let reason = reason.into();
        let mut guard = self.lock();

        if !guard.contains_key(&key) && guard.len() >= self.max_entries {
            return Err(NtaError::StoreFull {
                max: self.max_entries,
            });
        }

        let domain_str = domain.to_string();
        guard.insert(
            key,
            NtaEntry {
                domain,
                expires_at,
                reason: reason.clone(),
            },
        );

        info!(
            event = "nta_lifecycle",
            action = "add",
            domain = %domain_str,
            expires_at = expires_at,
            reason = %reason,
            "NTA added"
        );

        Ok(())
    }

    /// Removes the NTA for `domain`.
    ///
    /// Returns `true` if the entry existed and was removed.
    pub fn remove(&self, domain: &Name) -> bool {
        let key = name_key(domain);
        let mut guard = self.lock();
        let removed = guard.remove(&key).is_some();

        if removed {
            info!(
                event = "nta_lifecycle",
                action = "remove",
                domain = %domain,
                "NTA removed"
            );
        }

        removed
    }

    /// Returns `true` if there is an active (non-expired) NTA for `domain`
    /// or any ancestor domain.
    ///
    /// Performs lazy expiry: if the found entry is expired, it is removed and
    /// `false` is returned.
    #[must_use]
    pub fn is_active_nta(&self, domain: &Name, now_secs: u64) -> bool {
        let key = name_key(domain);
        let mut guard = self.lock();

        // Check exact match first.
        if let Some(entry) = guard.get(&key) {
            if entry.expires_at > now_secs {
                return true;
            }
            // Expired — lazy removal.
            let domain_str = entry.domain.to_string();
            let expires_at = entry.expires_at;
            guard.remove(&key);
            info!(
                event = "nta_lifecycle",
                action = "expired",
                domain = %domain_str,
                expires_at = expires_at,
                "NTA expired (lazy)"
            );
            return false;
        }

        false
    }

    /// Returns all currently active NTA entries (those with `expires_at > now_secs`).
    #[must_use]
    pub fn list_active(&self, now_secs: u64) -> Vec<NtaEntry> {
        let guard = self.lock();
        guard
            .values()
            .filter(|e| e.expires_at > now_secs)
            .cloned()
            .collect()
    }

    /// Removes all entries with `expires_at <= now_secs`.
    pub fn purge_expired(&self, now_secs: u64) {
        let mut guard = self.lock();
        let expired_keys: Vec<Vec<u8>> = guard
            .iter()
            .filter(|(_, e)| e.expires_at <= now_secs)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            if let Some(entry) = guard.remove(&key) {
                info!(
                    event = "nta_lifecycle",
                    action = "expired",
                    domain = %entry.domain,
                    expires_at = entry.expires_at,
                    "NTA purged"
                );
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Vec<u8>, NtaEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Returns the map key for a [`Name`]: lowercase wire bytes.
fn name_key(name: &Name) -> Vec<u8> {
    name.as_wire_bytes().to_ascii_lowercase()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    #[test]
    fn add_and_is_active_nta() {
        let store = NtaStore::new(10);
        let domain = name("broken.example.com.");
        store
            .add(domain.clone(), 9999, "test")
            .expect("add must succeed");
        assert!(
            store.is_active_nta(&domain, 1000),
            "NTA must be active before expiry"
        );
    }

    #[test]
    fn expired_nta_reverts_to_inactive() {
        let store = NtaStore::new(10);
        let domain = name("old.example.com.");
        // expires_at in the past
        store
            .add(domain.clone(), 100, "expired")
            .expect("add must succeed");
        assert!(
            !store.is_active_nta(&domain, 200),
            "expired NTA must not be active"
        );
    }

    #[test]
    fn remove_nta() {
        let store = NtaStore::new(10);
        let domain = name("remove.example.com.");
        store
            .add(domain.clone(), 9999, "r")
            .expect("add must succeed");
        assert!(store.remove(&domain));
        assert!(!store.is_active_nta(&domain, 1000));
        assert!(!store.remove(&domain), "second remove must return false");
    }

    #[test]
    fn max_entries_enforced() {
        let store = NtaStore::new(2);
        let a = name("a.example.com.");
        let b = name("b.example.com.");
        let c = name("c.example.com.");

        store.add(a, 9999, "r").expect("add a must succeed");
        store.add(b, 9999, "r").expect("add b must succeed");

        // Third add must fail.
        let result = store.add(c, 9999, "r");
        assert!(matches!(result, Err(NtaError::StoreFull { max: 2 })));
    }

    #[test]
    fn update_existing_always_allowed() {
        let store = NtaStore::new(1);
        let domain = name("update.example.com.");
        store
            .add(domain.clone(), 9999, "v1")
            .expect("add must succeed");
        // Updating an existing entry must succeed even at capacity.
        store
            .add(domain.clone(), 99999, "v2")
            .expect("update must succeed");
        assert!(store.is_active_nta(&domain, 1000));
    }

    #[test]
    fn list_active_returns_non_expired() {
        let store = NtaStore::new(10);
        store
            .add(name("active.example.com."), 9999, "r")
            .expect("ok");
        store.add(name("past.example.com."), 50, "r").expect("ok");

        let active = store.list_active(100);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].domain.to_string(), "active.example.com.");
    }

    #[test]
    fn purge_expired_removes_stale() {
        let store = NtaStore::new(10);
        store.add(name("live.example.com."), 9999, "r").expect("ok");
        store.add(name("dead.example.com."), 50, "r").expect("ok");

        store.purge_expired(100);

        assert_eq!(store.list_active(100).len(), 1);
    }
}
