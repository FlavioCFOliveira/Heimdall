// SPDX-License-Identifier: MIT

//! Query-response caches for the recursive-resolver and forwarder roles.
//!
//! # Cache segregation (CACHE-001..CACHE-007)
//!
//! Two distinct cache types are provided:
//!
//! - [`RecursiveCache`] — for the recursive-resolver role; default 512 MiB budget.
//! - [`ForwarderCache`] — for the forwarder role; default 256 MiB budget.
//!
//! The types are structurally incompatible: passing a `ForwarderCache` where a
//! `RecursiveCache` is expected (or vice versa) is a compile-time error.  No
//! configuration option enables sharing entries between the two caches
//! (CACHE-003).
//!
//! # Data structure (CACHE-008)
//!
//! Each cache is a sharded segmented-LRU (SLRU):
//!
//! ```text
//! [ probationary segment | protected segment ]
//! ```
//!
//! - Entries land in probationary on first insertion.
//! - A subsequent cache hit on a probationary entry promotes it to protected.
//! - Eviction pressure targets the LRU tail of probationary first; overflow
//!   from protected demotes its LRU tail back to probationary.
//!
//! The shard count is 32 by default and can be varied via the `N` const
//! parameter on [`shard::ShardedCache`].
//!
//! # DNSSEC policy (CACHE-009..CACHE-016)
//!
//! - **Bogus** entries: cached for 60 s (penalty window); never served to
//!   clients; serve-stale never applies (CACHE-014, CACHE-011).
//! - **Secure** entries: `serve_stale_until = ttl_deadline + 300 s` (default);
//!   RRSIG records must be stored in `rdata_wire` (CACHE-015).
//! - **Negative** entries: TTL capped at `min(soa_minimum, 3600 s)` (CACHE-009,
//!   RFC 2308 §5).
//! - **NSEC/NSEC3** entries: same TTL/eviction policy; opt-out flag preserved
//!   in `rdata_wire` (CACHE-016).
//!
//! # Admission (CACHE-012..CACHE-013)
//!
//! [`admission::AdmissionGuard`] is the Sprint 20 extension point for
//! per-source repeat-miss suppression and DNS-Cookie weighting.  The current
//! default is [`admission::NoopAdmission`] (always admits).
//!
//! Per-zone admission tracking limits any single zone to 10% of shard
//! capacity by default (CACHE-013).

pub mod admission;
pub mod entry;
pub mod forwarder;
pub mod limits;
pub mod recursive;
pub mod shard;
pub mod slru;

pub use admission::{AdmissionGuard, NoopAdmission};
pub use entry::CacheEntry;
pub use forwarder::ForwarderCache;
pub use limits::TtlBounds;
pub use recursive::RecursiveCache;

// Re-export ValidationOutcome so callers of the cache module do not need to
// depend on heimdall-core directly.
pub use heimdall_core::dnssec::ValidationOutcome;

// ── CacheKey ──────────────────────────────────────────────────────────────────

/// Key for a cache lookup, scoped to a single cache instance (CACHE-004).
///
/// Stored as lowercase wire-encoded bytes to ensure case-insensitive matching
/// per RFC 1034 §3.1.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// Wire-encoded, lowercase owner name (FQDN).
    pub qname: Vec<u8>,
    /// Numeric QTYPE (e.g. 1 = A, 28 = AAAA, 5 = CNAME).
    pub qtype: u16,
    /// Numeric QCLASS (e.g. 1 = IN).
    pub qclass: u16,
}

// ── LookupResult ──────────────────────────────────────────────────────────────

/// The outcome of a cache lookup.
#[derive(Debug)]
pub enum LookupResult {
    /// The entry is present and its TTL has not expired.
    Hit(CacheEntry),
    /// The entry's TTL has expired but it is within its serve-stale window
    /// (RFC 8767).  The caller SHOULD serve this entry while re-validating
    /// upstream.
    Stale(CacheEntry),
    /// No usable entry was found (absent, fully expired, or a bogus entry
    /// within its 60-second penalty window).
    Miss,
}
