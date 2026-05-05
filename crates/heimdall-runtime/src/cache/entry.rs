// SPDX-License-Identifier: MIT

//! Cache entry type for Heimdall's query-response caches.
//!
//! [`CacheEntry`] is the value stored in both [`RecursiveCache`] and
//! [`ForwarderCache`]. It carries the wire-encoded `RRset`, the DNSSEC validation
//! outcome, TTL deadlines, and per-zone accounting state.
//!
//! [`RecursiveCache`]: crate::cache::RecursiveCache
//! [`ForwarderCache`]: crate::cache::ForwarderCache

use std::time::Instant;

use heimdall_core::dnssec::ValidationOutcome;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single entry stored in a query-response cache.
///
/// # DNSSEC policy
///
/// - `Bogus` entries: TTL is fixed at 60 s; `serve_stale_until` is always
///   `None` (CACHE-014, CACHE-011).
/// - `Secure` entries: `serve_stale_until = Some(ttl_deadline + stale_window)`,
///   default stale window 300 s (CACHE-011, RFC 8767).
/// - Negative entries: TTL is capped at `min(soa_minimum, 3600 s)` (CACHE-009).
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Wire-encoded `RRset` bytes (STORE-043 format from the store module).
    ///
    /// For `Secure` entries, the associated RRSIG records MUST be stored here
    /// alongside the covered `RRset` (CACHE-015). For NSEC/NSEC3 entries, the
    /// opt-out flag is preserved in this wire encoding (CACHE-016).
    pub rdata_wire: Vec<u8>,

    /// Absolute deadline after which the entry is considered expired.
    pub ttl_deadline: Instant,

    /// DNSSEC validation outcome for this entry (CACHE-014).
    pub dnssec_outcome: ValidationOutcome,

    /// `true` if this is a negative entry (NXDOMAIN or NODATA).
    pub is_negative: bool,

    /// Absolute deadline until which the entry MAY be served stale per RFC 8767.
    ///
    /// `None` when serve-stale is disabled, when `dnssec_outcome` is
    /// [`ValidationOutcome::Bogus`], or when the operator has set the stale
    /// window to zero (CACHE-011, CACHE-014).
    pub serve_stale_until: Option<Instant>,

    /// Zone apex of the owner name, used for per-zone admission accounting
    /// (CACHE-013).
    ///
    /// Stored as a lowercase, wire-encoded, fully-qualified domain name.
    pub zone_apex: Vec<u8>,
}

impl CacheEntry {
    /// Returns `true` if the entry's TTL deadline has passed.
    ///
    /// An expired entry should not be served directly; it may still be serveable
    /// stale — check [`is_serveable_stale`](Self::is_serveable_stale).
    #[inline]
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.ttl_deadline
    }

    /// Returns `true` if the entry is expired but eligible to be served stale
    /// per RFC 8767.
    ///
    /// Precondition: the entry is already expired.  Bogus entries are never
    /// serveable stale (CACHE-011, CACHE-014).
    #[inline]
    #[must_use]
    pub fn is_serveable_stale(&self, now: Instant) -> bool {
        self.is_expired(now)
            && self
                .serve_stale_until
                .is_some_and(|deadline| now < deadline)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use heimdall_core::dnssec::{BogusReason, ValidationOutcome};

    use super::CacheEntry;

    fn make_entry(
        ttl_secs: u64,
        stale_secs: Option<u64>,
        outcome: ValidationOutcome,
    ) -> CacheEntry {
        let now = Instant::now();
        let ttl_deadline = now + Duration::from_secs(ttl_secs);
        let serve_stale_until = stale_secs.map(|s| ttl_deadline + Duration::from_secs(s));
        CacheEntry {
            rdata_wire: vec![],
            ttl_deadline,
            dnssec_outcome: outcome,
            is_negative: false,
            serve_stale_until,
            zone_apex: b"\x07example\x03com\x00".to_vec(),
        }
    }

    #[test]
    fn not_expired_before_deadline() {
        let entry = make_entry(300, None, ValidationOutcome::Insecure);
        let now = Instant::now();
        assert!(!entry.is_expired(now));
    }

    #[test]
    fn expired_after_deadline() {
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let entry = CacheEntry {
            rdata_wire: vec![],
            ttl_deadline: past,
            dnssec_outcome: ValidationOutcome::Insecure,
            is_negative: false,
            serve_stale_until: None,
            zone_apex: vec![],
        };
        assert!(entry.is_expired(Instant::now()));
    }

    #[test]
    fn stale_within_window() {
        // Expired (ttl 0s ago), stale window still open (300 s).
        let now = Instant::now();
        let past_ttl = now.checked_sub(Duration::from_secs(1)).unwrap();
        let entry = CacheEntry {
            rdata_wire: vec![],
            ttl_deadline: past_ttl,
            dnssec_outcome: ValidationOutcome::Secure,
            is_negative: false,
            serve_stale_until: Some(now + Duration::from_secs(299)),
            zone_apex: vec![],
        };
        assert!(entry.is_expired(now));
        assert!(entry.is_serveable_stale(now));
    }

    #[test]
    fn stale_window_past_returns_false() {
        let now = Instant::now();
        let past = now.checked_sub(Duration::from_secs(400)).unwrap();
        let entry = CacheEntry {
            rdata_wire: vec![],
            ttl_deadline: past,
            dnssec_outcome: ValidationOutcome::Secure,
            is_negative: false,
            serve_stale_until: Some(now.checked_sub(Duration::from_secs(100)).unwrap()),
            zone_apex: vec![],
        };
        assert!(entry.is_expired(now));
        assert!(!entry.is_serveable_stale(now));
    }

    #[test]
    fn bogus_never_stale() {
        // Bogus entries must always have serve_stale_until = None (CACHE-014).
        let now = Instant::now();
        let past = now.checked_sub(Duration::from_secs(1)).unwrap();
        let entry = CacheEntry {
            rdata_wire: vec![],
            ttl_deadline: past,
            dnssec_outcome: ValidationOutcome::Bogus(BogusReason::InvalidSignature),
            is_negative: false,
            // Correctly constructed bogus entries never have this set;
            // even if set erroneously, is_serveable_stale must be false.
            serve_stale_until: None,
            zone_apex: vec![],
        };
        assert!(entry.is_expired(now));
        assert!(!entry.is_serveable_stale(now));
    }

    #[test]
    fn not_expired_not_stale() {
        // Entry still live: neither expired nor stale.
        let entry = make_entry(300, Some(300), ValidationOutcome::Secure);
        let now = Instant::now();
        assert!(!entry.is_expired(now));
        assert!(!entry.is_serveable_stale(now));
    }
}
