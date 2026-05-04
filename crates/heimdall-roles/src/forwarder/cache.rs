// SPDX-License-Identifier: MIT

//! Forwarder cache client (Task #334 part 1).
//!
//! [`ForwarderCacheClient`] wraps [`heimdall_runtime::cache::ForwarderCache`]
//! and provides a higher-level interface that operates on [`Name`] and [`Rtype`]
//! instead of raw wire-format cache keys.
//!
//! The design mirrors [`crate::recursive::cache::RecursiveCacheClient`] but
//! wraps [`ForwarderCache`] (CACHE-002: the two cache types are kept separate
//! at compile time).

use std::sync::Arc;
use std::time::Instant;

use heimdall_core::dnssec::ValidationOutcome;
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::record::Rtype;
use heimdall_core::serialiser::Serialiser;
use heimdall_runtime::cache::entry::CacheEntry;
use heimdall_runtime::cache::forwarder::ForwarderCache;
use heimdall_runtime::cache::{CacheKey, LookupResult};

// ── CachedResponse ────────────────────────────────────────────────────────────

/// A response retrieved from the forwarder cache.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// The cached entry.
    pub entry: CacheEntry,
    /// `true` if the entry's TTL has expired but it is within its stale window.
    pub is_stale: bool,
}

// ── ForwarderCacheClient ──────────────────────────────────────────────────────

/// A higher-level wrapper around [`ForwarderCache`].
///
/// Converts between typed DNS names/types and the wire-format cache keys
/// expected by the underlying cache.
pub struct ForwarderCacheClient {
    cache: Arc<ForwarderCache>,
}

impl ForwarderCacheClient {
    /// Creates a new [`ForwarderCacheClient`] wrapping `cache`.
    #[must_use]
    pub fn new(cache: Arc<ForwarderCache>) -> Self {
        Self { cache }
    }

    /// Looks up a response for `(qname, qtype, qclass)` in the cache.
    ///
    /// `do_bit` is accepted for future DNSSEC filtering but does not currently
    /// affect cache keying.
    ///
    /// Returns:
    /// - `Some(CachedResponse { is_stale: false })` on a cache hit.
    /// - `Some(CachedResponse { is_stale: true })` on a stale-but-valid hit.
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
    /// the uncompressed form for canonical storage.
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
        let rdata_wire = serialise_answers(msg);

        let min_ttl_secs = msg
            .answers
            .iter()
            .map(|r| u64::from(r.ttl))
            .min()
            .unwrap_or(300);

        let now = Instant::now();
        let ttl_deadline = now + std::time::Duration::from_secs(min_ttl_secs);

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
/// Returns an empty `Vec<u8>` on serialisation failure (treated as a cache miss
/// to avoid caching corrupt data).
fn serialise_answers(msg: &Message) -> Vec<u8> {
    if msg.answers.is_empty() {
        return Vec::new();
    }

    // Reset QDCOUNT to 0: questions are stripped, and the wire must be
    // self-consistent so that Message::parse succeeds in build_cached_response.
    let mut cache_header = msg.header.clone();
    cache_header.qdcount = 0;

    let answer_msg = Message {
        header: cache_header,
        questions: Vec::new(),
        answers: msg.answers.clone(),
        authority: Vec::new(),
        additional: Vec::new(),
    };

    let mut ser = Serialiser::new(false);
    if ser.write_message(&answer_msg).is_err() {
        return Vec::new();
    }
    ser.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use heimdall_core::header::{Header, Qclass};
    use heimdall_core::rdata::RData;
    use heimdall_core::record::Record;

    use super::*;

    fn make_client() -> ForwarderCacheClient {
        ForwarderCacheClient::new(Arc::new(ForwarderCache::new(512, 512)))
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
        let client = make_client();
        assert!(client.lookup(&example_name(), Rtype::A, 1, false).is_none());
    }

    #[test]
    fn store_and_lookup_hit() {
        let client = make_client();
        let qname = example_name();
        let msg = make_msg_with_a();
        client.store(
            &qname,
            Rtype::A,
            1,
            &msg,
            ValidationOutcome::Insecure,
            &Name::root(),
            false,
        );
        let result = client.lookup(&qname, Rtype::A, 1, false);
        assert!(result.is_some(), "stored entry must produce a hit");
        assert!(!result.expect("INVARIANT: just checked").is_stale);
    }

    #[test]
    fn negative_entry_stored_and_retrieved() {
        let client = make_client();
        let qname = Name::from_str("nxdomain.example.com.").expect("INVARIANT: valid");
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
        assert!(result.is_some());
        assert!(result.expect("INVARIANT: just checked").entry.is_negative);
    }
}
