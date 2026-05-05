// SPDX-License-Identifier: MIT

//! Recursive cache client for the resolver role.
//!
//! [`RecursiveCacheClient`] wraps [`heimdall_runtime::cache::RecursiveCache`]
//! and provides a higher-level interface that operates on [`Name`] and [`Rtype`]
//! instead of raw wire-format cache keys.

use std::{sync::Arc, time::Instant};

use heimdall_core::{
    dnssec::ValidationOutcome, name::Name, parser::Message, record::Rtype, serialiser::Serialiser,
};
use heimdall_runtime::cache::{
    CacheKey, LookupResult, entry::CacheEntry, recursive::RecursiveCache,
};

// ── CachedResponse ────────────────────────────────────────────────────────────

/// A response retrieved from the recursive cache.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// The cached entry.
    pub entry: CacheEntry,
    /// `true` if the entry's TTL has expired but it is within its stale window.
    pub is_stale: bool,
}

// ── RecursiveCacheClient ──────────────────────────────────────────────────────

/// A higher-level wrapper around [`RecursiveCache`].
///
/// Converts between typed DNS names/types and the wire-format cache keys
/// expected by the underlying cache.
pub struct RecursiveCacheClient {
    cache: Arc<RecursiveCache>,
}

impl RecursiveCacheClient {
    /// Creates a new [`RecursiveCacheClient`] wrapping `cache`.
    #[must_use]
    pub fn new(cache: Arc<RecursiveCache>) -> Self {
        Self { cache }
    }

    /// Looks up a response for `(qname, qtype, qclass)` in the cache.
    ///
    /// The `do_bit` parameter is accepted for future DNSSEC filtering but
    /// does not currently affect cache keying (the cache stores the DNSSEC
    /// outcome in the entry; callers filter by that).
    ///
    /// Returns:
    /// - `Some(CachedResponse { is_stale: false })` on a cache hit.
    /// - `Some(CachedResponse { is_stale: true })` on a stale hit (expired but
    ///   within the RFC 8767 serve-stale window).
    /// - `None` on a miss.
    #[must_use]
    pub fn lookup(
        &self,
        qname: &Name,
        qtype: Rtype,
        qclass: u16,
        _do_bit: bool,
    ) -> Option<CachedResponse> {
        let key = make_key(qname, qtype, qclass);
        match self.cache.get(&key, Instant::now()) {
            LookupResult::Hit(entry) => Some(CachedResponse {
                entry,
                is_stale: false,
            }),
            LookupResult::Stale(entry) => Some(CachedResponse {
                entry,
                is_stale: true,
            }),
            LookupResult::Miss => None,
        }
    }

    /// Stores the relevant `RRset`s from `msg` in the cache.
    ///
    /// The answer section is serialised into `CacheEntry::rdata_wire` using
    /// the uncompressed form (compress=false) for canonical storage.
    ///
    /// `zone_apex` is used for per-zone admission accounting.
    // Eight arguments are required by the cache interface; grouping would
    // obscure the semantics without reducing actual complexity.
    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &self,
        qname: &Name,
        qtype: Rtype,
        qclass: u16,
        msg: &Message,
        outcome: ValidationOutcome,
        zone_apex: &Name,
        is_negative: bool,
    ) {
        let key = make_key(qname, qtype, qclass);

        // Serialise the answer section (uncompressed, canonical form).
        let rdata_wire = serialise_answers(msg);

        // TTL deadline: use the minimum TTL across answer records, defaulting
        // to 300 s if the answer section is empty (e.g. for NODATA responses).
        let min_ttl_secs = msg
            .answers
            .iter()
            .map(|r| u64::from(r.ttl))
            .min()
            .unwrap_or(300);

        let now = Instant::now();
        let ttl_deadline = now + std::time::Duration::from_secs(min_ttl_secs);

        // Stale window: 300 s beyond TTL for non-bogus entries (RFC 8767).
        let serve_stale_until = if matches!(outcome, ValidationOutcome::Bogus(_)) {
            None
        } else {
            Some(ttl_deadline + std::time::Duration::from_mins(5))
        };

        let entry = CacheEntry {
            rdata_wire,
            ttl_deadline,
            dnssec_outcome: outcome,
            is_negative,
            serve_stale_until,
            zone_apex: zone_apex.as_wire_bytes().to_ascii_lowercase(),
        };

        self.cache.insert(key, entry);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Builds the [`CacheKey`] for a `(qname, qtype, qclass)` triple.
///
/// The `qname` wire bytes are lowercased for case-insensitive comparison
/// per RFC 1034 §3.1.
fn make_key(qname: &Name, qtype: Rtype, qclass: u16) -> CacheKey {
    CacheKey {
        qname: qname.as_wire_bytes().to_ascii_lowercase(),
        qtype: qtype.as_u16(),
        qclass,
    }
}

/// Serialises the answer section of `msg` into uncompressed wire bytes.
///
/// Returns an empty `Vec<u8>` on serialisation failure (treat as a cache miss
/// to avoid caching corrupt data).
fn serialise_answers(msg: &Message) -> Vec<u8> {
    if msg.answers.is_empty() {
        return Vec::new();
    }

    // Build a minimal message containing only the answer section.
    let answer_msg = Message {
        header: msg.header.clone(),
        questions: Vec::new(),
        answers: msg.answers.clone(),
        authority: Vec::new(),
        additional: Vec::new(),
    };

    let mut ser = Serialiser::new(false); // uncompressed, canonical form
    if ser.write_message(&answer_msg).is_err() {
        return Vec::new();
    }
    ser.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        str::FromStr,
        time::{Duration, Instant},
    };

    use heimdall_core::{
        header::{Header, Qclass},
        rdata::RData,
        record::Record,
    };

    use super::*;

    fn make_cache() -> RecursiveCacheClient {
        let cache = Arc::new(RecursiveCache::new(512, 512));
        RecursiveCacheClient::new(cache)
    }

    fn root_name() -> Name {
        Name::root()
    }

    fn example_name() -> Name {
        Name::from_str("example.com.").expect("INVARIANT: valid test name")
    }

    fn make_msg_with_a() -> Message {
        let mut header = Header::default();
        header.set_qr(true);
        header.ancount = 1;
        Message {
            header,
            questions: vec![],
            answers: vec![Record {
                name: example_name(),
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn lookup_miss_on_empty_cache() {
        let client = make_cache();
        let result = client.lookup(&example_name(), Rtype::A, 1, false);
        assert!(result.is_none(), "empty cache must miss");
    }

    #[test]
    fn store_and_lookup_hit() {
        let client = make_cache();
        let qname = example_name();

        let msg = make_msg_with_a();
        client.store(
            &qname,
            Rtype::A,
            1,
            &msg,
            ValidationOutcome::Insecure,
            &root_name(),
            false,
        );

        let result = client.lookup(&qname, Rtype::A, 1, false);
        assert!(result.is_some(), "stored entry must produce a hit");
        let cached = result.expect("INVARIANT: just checked is_some");
        assert!(!cached.is_stale, "freshly stored entry must not be stale");
    }

    #[test]
    fn stale_entry_returned_with_is_stale_true() {
        // Insert a cache entry whose TTL has already expired but whose stale
        // window is still open.  We use `with_bounds(min_ttl_secs=0)` so the
        // runtime cache does not clamp the expired deadline to its minimum.
        use heimdall_runtime::cache::TtlBounds;
        let bounds = TtlBounds {
            min_ttl_secs: 0,
            ..TtlBounds::default()
        };
        let inner_cache = Arc::new(RecursiveCache::with_bounds(512, 512, bounds));
        let client = RecursiveCacheClient::new(Arc::clone(&inner_cache));

        let qname = example_name();
        let key = make_key(&qname, Rtype::A, 1);

        let now = Instant::now();
        // TTL already expired 10 s ago; stale window open for another ~5 min.
        let expired_ttl = now.checked_sub(Duration::from_secs(10)).unwrap();
        let stale_window = now + Duration::from_secs(290);

        let entry = CacheEntry {
            rdata_wire: vec![1, 2, 3],
            ttl_deadline: expired_ttl,
            dnssec_outcome: ValidationOutcome::Insecure,
            is_negative: false,
            serve_stale_until: Some(stale_window),
            zone_apex: b"\x00".to_vec(),
        };
        inner_cache.insert(key, entry);

        let result = client.lookup(&qname, Rtype::A, 1, false);
        assert!(result.is_some(), "stale entry must be returned");
        let cached = result.expect("INVARIANT: just checked");
        assert!(
            cached.is_stale,
            "expired entry within stale window must have is_stale=true"
        );
    }

    #[test]
    fn negative_entry_stored_and_retrieved() {
        let client = make_cache();
        let qname = Name::from_str("nxdomain.example.com.").expect("INVARIANT: valid test name");
        let msg = Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        client.store(
            &qname,
            Rtype::A,
            1,
            &msg,
            ValidationOutcome::Insecure,
            &example_name(),
            true,
        );

        let result = client.lookup(&qname, Rtype::A, 1, false);
        assert!(result.is_some(), "negative entry must be retrievable");
        let cached = result.expect("INVARIANT: just checked");
        assert!(cached.entry.is_negative);
    }
}
