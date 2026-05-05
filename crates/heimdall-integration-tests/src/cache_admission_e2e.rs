// SPDX-License-Identifier: MIT

//! Cache admission integration tests (CACHE-012/013/015/016, task #603).
//!
//! # Cases
//!
//! - `cache_012_per_source_query_rate_limit` — (i) Anonymous-bucket budget is
//!   exhausted after `anon_rate * burst_window_secs` queries from the same IP.
//! - `cache_013_per_zone_cap_evicts_on_overflow` — (ii) Inserting a second entry
//!   for the same zone in the same shard evicts the first, keeping the per-shard
//!   count at the 10% limit (minimum 1).
//! - `cache_015_rrsig_stored_and_retrievable_on_secure_entry` — (iii) A Secure
//!   cache entry serialises RRSIG records alongside the covered `RRset`; they are
//!   visible in the deserialized `rdata_wire` on a subsequent DO=1 lookup.
//! - `cache_016_nsec_visible_to_aggressive_synthesis` — (iv) An NSEC record
//!   stored with `ValidationOutcome::Secure` at `(zone_apex, NSEC, IN)` is
//!   retrieved by `try_aggressive_synthesis` and produces a synthesised Nxdomain.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use heimdall_core::dnssec::{ValidationOutcome, encode_type_bitmap};
    use heimdall_core::header::{Header, Qclass};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;
    use heimdall_core::rdata::RData;
    use heimdall_core::record::{Record, Rtype};
    use heimdall_roles::recursive::{AggressiveResult, RecursiveCacheClient, try_aggressive_synthesis};
    use heimdall_runtime::admission::query_rl::{QueryRlConfig, QueryRlEngine, RlBucket, RlKey};
    use heimdall_runtime::cache::entry::CacheEntry;
    use heimdall_runtime::cache::recursive::RecursiveCache;
    use heimdall_runtime::cache::{CacheKey, LookupResult};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid test name")
    }

    fn make_cache_client() -> RecursiveCacheClient {
        RecursiveCacheClient::new(Arc::new(RecursiveCache::new(512, 512)))
    }

    /// Replicates the shard index computation from `RecursiveCache` / `ShardedCache`.
    ///
    /// `SHARD_COUNT` is 32 in the production code.  Duplicating it here is
    /// intentional: the test validates that the per-zone eviction logic fires,
    /// not the shard dispatch itself.
    fn shard_index_of(key: &CacheKey) -> usize {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        #[allow(clippy::cast_possible_truncation)]
        let idx = h.finish() as usize;
        idx % 32
    }

    /// Returns a minimal live `CacheEntry` for `zone_apex`.
    fn live_entry(zone_apex: Vec<u8>) -> CacheEntry {
        let now = Instant::now();
        CacheEntry {
            rdata_wire: vec![0u8; 4],
            ttl_deadline: now + Duration::from_secs(300),
            dnssec_outcome: ValidationOutcome::Insecure,
            is_negative: false,
            serve_stale_until: Some(now + Duration::from_secs(600)),
            zone_apex,
        }
    }

    /// Finds two distinct `CacheKey`s that map to the same shard index.
    ///
    /// The caller supplies the `zone_apex` bytes (used only for entry
    /// construction, not keying).  Because the zone_apex shares a zone, both
    /// keys count against the same per-zone admission limit in the shard they
    /// land on.
    ///
    /// With 32 shards and a pseudo-random hash, ~1/32 of candidates share a
    /// shard with the first key found.  Within 200 candidates the probability of
    /// failure is < 0.1%.
    fn find_two_same_shard_keys() -> (CacheKey, CacheKey) {
        let mut first: Option<(CacheKey, usize)> = None;

        for i in 0u32..200 {
            // Build a valid wire-encoded FQDN: \x01X\x07example\x03com\x00
            // where X is a synthetic label byte derived from i.
            let prefix = (i % 253 + 1) as u8;
            let qname: Vec<u8> = std::iter::once(1u8)
                .chain(std::iter::once(prefix))
                .chain(b"\x07example\x03com\x00".iter().copied())
                .collect();
            let key = CacheKey { qname, qtype: 1, qclass: 1 };
            let shard = shard_index_of(&key);

            match &first {
                None => {
                    first = Some((key, shard));
                }
                Some((first_key, first_shard)) if shard == *first_shard => {
                    return (first_key.clone(), key);
                }
                _ => {}
            }
        }

        // Fallback: try with qtype variation to ensure we find a collision.
        for qtype in 2u16..300 {
            let key = CacheKey {
                qname: b"\x07example\x03com\x00".to_vec(),
                qtype,
                qclass: 1,
            };
            let shard = shard_index_of(&key);
            let (first_key, first_shard) = first.as_ref().expect("set in first loop");
            if shard == *first_shard {
                return (first_key.clone(), key);
            }
        }

        panic!("could not find two CacheKeys with the same shard index in 500 attempts");
    }

    // ── (i) CACHE-012: per-source query rate-limiting ─────────────────────────

    /// (i) Anonymous-bucket query rate limit is enforced per source IP.
    ///
    /// Config: anon_rate=5, burst_window=1 s → budget = 5.
    /// Queries 1–5 from 192.0.2.1 are allowed; query 6 is denied.
    /// A different source IP (192.0.2.2) retains its own independent budget.
    #[test]
    fn cache_012_per_source_query_rate_limit() {
        let engine = QueryRlEngine::new(QueryRlConfig {
            anon_rate: 5,
            cookie_rate: 200,
            auth_rate: 500,
            burst_window_secs: 1,
        });

        let src1 = RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let src2 = RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        let now = Instant::now();

        // First 5 from src1 must be allowed (budget = 5 × 1 = 5).
        for n in 1..=5u32 {
            assert!(
                engine.check(&src1, RlBucket::Anonymous, now),
                "(i) query {n} from src1 must be allowed"
            );
        }

        // 6th from src1 must be denied.
        assert!(
            !engine.check(&src1, RlBucket::Anonymous, now),
            "(i) 6th query from src1 must be denied when budget is exhausted"
        );

        // src2 has an independent budget and must still be allowed.
        assert!(
            engine.check(&src2, RlBucket::Anonymous, now),
            "(i) src2 must have an independent budget and be allowed"
        );
    }

    // ── (ii) CACHE-013: per-zone 10% cap ──────────────────────────────────────

    /// (ii) A second entry for the same zone in the same shard evicts the first.
    ///
    /// `RecursiveCache::new(32, 32)` gives `per_zone_limit = max((1+1)/10, 1) = 1`
    /// per shard.  Inserting key2 (same shard as key1, same zone) must evict
    /// key1 so the per-shard zone count stays at 1.
    #[test]
    fn cache_013_per_zone_cap_evicts_on_overflow() {
        // per_zone_limit = max( (32/32 + 32/32) / 10, 1 ) = max(0, 1) = 1
        let cache = RecursiveCache::new(32, 32);

        let zone_apex = b"\x07example\x03com\x00".to_vec();
        let (key1, key2) = find_two_same_shard_keys();

        // Insert key1 — admitted (count 0 < limit 1).
        cache.insert(key1.clone(), live_entry(zone_apex.clone()));
        assert!(
            matches!(cache.get(&key1, Instant::now()), LookupResult::Hit(_)),
            "(ii) key1 must be present after first insert"
        );

        // Insert key2 (same shard, same zone) — triggers zone-cap eviction of key1.
        cache.insert(key2.clone(), live_entry(zone_apex.clone()));

        assert!(
            matches!(cache.get(&key1, Instant::now()), LookupResult::Miss),
            "(ii) key1 must be evicted when the per-zone limit is reached by key2"
        );
        assert!(
            matches!(cache.get(&key2, Instant::now()), LookupResult::Hit(_)),
            "(ii) key2 must be present after it displaced key1"
        );
    }

    // ── (iii) CACHE-015: RRSIG retrievable on Secure entries ─────────────────

    /// (iii) A Secure cache entry stores RRSIG alongside the covered RRset in
    /// `rdata_wire`; a DO=1 lookup returns both records in the wire bytes.
    #[test]
    fn cache_015_rrsig_stored_and_retrievable_on_secure_entry() {
        let client = make_cache_client();
        let qname = name("secure.example.com.");
        let zone = name("example.com.");

        // Build a message containing an A record AND its covering RRSIG.
        let a_record = Record {
            name: qname.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(198, 51, 100, 1)),
        };
        let rrsig_record = Record {
            name: qname.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: 1234,
                signer_name: zone.clone(),
                signature: vec![0xABu8; 64],
            },
        };
        let msg = Message {
            header: Header { ancount: 2, ..Header::default() },
            questions: vec![],
            answers: vec![a_record, rrsig_record],
            authority: vec![],
            additional: vec![],
        };

        client.store(&qname, Rtype::A, 1, &msg, ValidationOutcome::Secure, &zone, false);

        // DO=1 lookup.
        let cached = client
            .lookup(&qname, Rtype::A, 1, true)
            .expect("(iii) stored Secure entry must produce a hit");

        // The rdata_wire is a serialised message (see serialise_answers).
        // Parse it back and verify RRSIG is present.
        let wire_msg = Message::parse(&cached.entry.rdata_wire)
            .expect("(iii) rdata_wire must be valid DNS wire");
        let has_rrsig = wire_msg.answers.iter().any(|r| r.rtype == Rtype::Rrsig);

        assert!(
            has_rrsig,
            "(iii) CACHE-015: RRSIG must be present in rdata_wire for a Secure entry"
        );
        assert_eq!(
            cached.entry.dnssec_outcome,
            ValidationOutcome::Secure,
            "(iii) DNSSEC outcome must be Secure"
        );
    }

    // ── (iv) CACHE-016: NSEC/NSEC3 visible to aggressive synthesis ───────────

    /// (iv) An NSEC record stored with `ValidationOutcome::Secure` at
    /// `(zone_apex, Nsec, IN)` is fetched by `try_aggressive_synthesis` and
    /// produces a synthesised `Nxdomain` result.
    ///
    /// NSEC interval: `a.example.com. → c.example.com.`
    /// Queried name: `b.example.com.` (covered by the interval: a < b < c
    /// under left-to-right label ordering).
    #[test]
    fn cache_016_nsec_visible_to_aggressive_synthesis() {
        let client = make_cache_client();
        let apex = name("example.com.");

        // Build a message with an NSEC record covering a→c.
        let nsec = Record {
            name: name("a.example.com."),
            rtype: Rtype::Nsec,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec {
                next_domain: name("c.example.com."),
                type_bitmaps: encode_type_bitmap(&[Rtype::Nsec, Rtype::Soa]),
            },
        };
        let msg = Message {
            header: Header { ancount: 1, ..Header::default() },
            questions: vec![],
            answers: vec![nsec],
            authority: vec![],
            additional: vec![],
        };

        // Store at (apex, Nsec, IN) with Secure outcome (CACHE-016).
        client.store(&apex, Rtype::Nsec, 1, &msg, ValidationOutcome::Secure, &apex, false);

        // Try synthesis for b.example.com. (A query): must find the NSEC.
        let qname = name("b.example.com.");
        let result = try_aggressive_synthesis(&client, &qname, Rtype::A, &apex, Instant::now());

        assert!(
            matches!(result, AggressiveResult::Nxdomain { .. }),
            "(iv) CACHE-016: NSEC cached from a Secure response must produce Nxdomain synthesis"
        );
    }
}
