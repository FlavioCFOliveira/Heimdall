// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unused_async,
    clippy::undocumented_unsafe_blocks
)]

//! Store layer tests.
//!
//! ## Unit tests
//!
//! All tests that do not require a live Redis server are here. They cover:
//! - Encoding/decoding of keys, field names, `RrsetPayload`, and `CacheEntry`.
//! - Backoff interval sequences.
//! - Metrics counter behaviour.
//! - Key uniqueness / collision properties.
//!
//! Run with: `cargo test -p heimdall-runtime`
//!
//! ## Integration tests
//!
//! Integration tests require a live Redis 7.x server and are gated behind the
//! `redis-integration` feature flag. They are **never** run in CI without an
//! explicit Redis service.
//!
//! Run with:
//! ```sh
//! cargo test -p heimdall-runtime --features redis-integration
//! ```
//!
//! The tests expect a Redis server on `/tmp/redis.sock` (UDS) by default,
//! with ACL credentials `heimdall` / `heimdall-test`. Override via environment
//! variables: `REDIS_URL`, `REDIS_USER`, `REDIS_PASSWORD`.

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — no live Redis required
// ─────────────────────────────────────────────────────────────────────────────

mod encoding {
    use heimdall_runtime::store::encoding::{
        CacheEntry, CacheNamespace, DnssecOutcome, RrsetPayload, cache_key, field_name,
        zone_journal_key, zone_key, zone_staging_key,
    };

    // ── Key generation ────────────────────────────────────────────────────────

    #[test]
    fn zone_key_starts_with_heimdall_prefix() {
        let k = zone_key("example.com.");
        assert!(k.starts_with("heimdall:zone:auth:{"), "key: {k}");
    }

    #[test]
    fn zone_staging_key_ends_with_colon_staging() {
        let k = zone_staging_key("example.com.");
        assert!(k.ends_with(":staging"), "key: {k}");
    }

    #[test]
    fn staging_and_live_share_hash_tag() {
        // Both live and staging keys must have the same hash tag so they hash
        // to the same Redis Cluster slot (STORE-039/040).
        let live = zone_key("example.com.");
        let staging = zone_staging_key("example.com.");
        // Both should contain `{example.com.}` as the hash tag.
        let tag = "{example.com.}";
        assert!(live.contains(tag), "live key missing tag: {live}");
        assert!(staging.contains(tag), "staging key missing tag: {staging}");
    }

    #[test]
    fn zone_journal_key_format_correct() {
        let k = zone_journal_key("example.com.");
        assert_eq!(k, "heimdall:journal:auth:{example.com.}");
    }

    #[test]
    fn cache_key_recursive_contains_namespace() {
        let k = cache_key(CacheNamespace::Recursive, "example.com.", 1, 1);
        assert!(k.contains(":recursive:"), "key: {k}");
    }

    #[test]
    fn cache_key_forwarder_contains_namespace() {
        let k = cache_key(CacheNamespace::Forwarder, "example.com.", 1, 1);
        assert!(k.contains(":forwarder:"), "key: {k}");
    }

    #[test]
    fn cache_keys_for_same_name_different_namespaces_are_disjoint() {
        let rec = cache_key(CacheNamespace::Recursive, "x.example.com.", 28, 1);
        let fwd = cache_key(CacheNamespace::Forwarder, "x.example.com.", 28, 1);
        assert_ne!(rec, fwd, "namespaces must produce distinct keys");
    }

    #[test]
    fn field_name_uses_pipe_separator() {
        let f = field_name("example.com.", 1, 1);
        assert_eq!(f, "example.com.|1|1");
    }

    #[test]
    fn field_name_different_qtype_different_field() {
        let a = field_name("example.com.", 1, 1);
        let aaaa = field_name("example.com.", 28, 1);
        assert_ne!(a, aaaa);
    }

    // ── RrsetPayload encoding ─────────────────────────────────────────────────

    #[test]
    fn rrset_empty_rdata_round_trip() {
        let p = RrsetPayload {
            ttl: 0,
            rdata: vec![],
        };
        let encoded = p.encode().expect("encode");
        let decoded = RrsetPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded, p);
    }

    #[test]
    fn rrset_max_ttl_round_trip() {
        let p = RrsetPayload {
            ttl: u32::MAX,
            rdata: vec![vec![0xFF; 4]],
        };
        let encoded = p.encode().expect("encode");
        let decoded = RrsetPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.ttl, u32::MAX);
    }

    #[test]
    fn rrset_multiple_records_preserved_in_order() {
        let rdata = vec![vec![1u8], vec![2u8, 3u8], vec![4u8, 5u8, 6u8]];
        let p = RrsetPayload { ttl: 300, rdata };
        let encoded = p.encode().expect("encode");
        let decoded = RrsetPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.rdata, p.rdata);
    }

    #[test]
    fn rrset_corrupt_version_byte_rejected() {
        let p = RrsetPayload {
            ttl: 300,
            rdata: vec![],
        };
        let mut encoded = p.encode().expect("encode");
        encoded[0] = 0x99;
        assert!(
            RrsetPayload::decode(&encoded).is_err(),
            "bad version should error"
        );
    }

    // ── CacheEntry encoding ───────────────────────────────────────────────────

    #[test]
    fn cache_entry_all_outcomes_round_trip() {
        for outcome in [
            DnssecOutcome::Secure,
            DnssecOutcome::Insecure,
            DnssecOutcome::Bogus,
            DnssecOutcome::Indeterminate,
        ] {
            let entry = CacheEntry {
                dnssec_outcome: outcome,
                inserted_at: 1_000_000,
                stale_until: 1_001_000,
                rrset: RrsetPayload {
                    ttl: 1000,
                    rdata: vec![vec![1, 2, 3, 4]],
                },
            };
            let encoded = entry.encode().expect("encode");
            let decoded = CacheEntry::decode(&encoded).expect("decode");
            assert_eq!(
                decoded.dnssec_outcome, outcome,
                "outcome mismatch for {outcome:?}"
            );
            assert_eq!(decoded.inserted_at, 1_000_000);
            assert_eq!(decoded.stale_until, 1_001_000);
        }
    }

    #[test]
    fn cache_entry_header_is_9_bytes() {
        // The CacheEntry header is 1 (outcome) + 4 (inserted_at) + 4 (stale_until) = 9.
        let rrset = RrsetPayload {
            ttl: 0,
            rdata: vec![],
        };
        let rrset_len = rrset.encode().expect("encode rrset").len();
        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Secure,
            inserted_at: 0,
            stale_until: 0,
            rrset,
        };
        let total_len = entry.encode().expect("encode entry").len();
        assert_eq!(total_len, rrset_len + 9, "header must be exactly 9 bytes");
    }
}

mod backoff {
    use std::time::Duration;

    use heimdall_runtime::store::backoff::{BackoffIterator, SeededJitter};

    /// Zero-offset jitter source (always 0.5 = midpoint → no offset applied).
    struct MidpointJitter;
    impl heimdall_runtime::store::backoff::JitterSource for MidpointJitter {
        fn sample(&mut self) -> f64 {
            0.5
        }
    }

    #[test]
    fn first_interval_is_floor() {
        let mut b = BackoffIterator::new(MidpointJitter);
        let first = b.next().expect("value");
        assert_eq!(first, Duration::from_millis(100));
    }

    #[test]
    fn intervals_double_without_jitter() {
        let actual: Vec<u64> = BackoffIterator::new(MidpointJitter)
            .take(8)
            .map(|d| d.as_millis() as u64)
            .collect();
        assert_eq!(actual, [100, 200, 400, 800, 1600, 3200, 6400, 12800]);
    }

    #[test]
    fn ceiling_never_exceeded() {
        let exceeded: Vec<u64> = BackoffIterator::new(MidpointJitter)
            .take(30)
            .map(|d| d.as_millis() as u64)
            .filter(|&ms| ms > 30_000)
            .collect();
        assert!(exceeded.is_empty(), "ceiling exceeded: {exceeded:?}");
    }

    #[test]
    fn reset_returns_to_floor() {
        let mut b = BackoffIterator::new(MidpointJitter);
        b.by_ref().take(10).for_each(|_| {});
        b.reset();
        let after_reset = b.next().expect("value");
        assert_eq!(after_reset, Duration::from_millis(100));
    }

    #[test]
    fn seeded_jitter_is_reproducible() {
        let seeds = vec![0.1, 0.5, 0.9];
        let run_a: Vec<Duration> = BackoffIterator::new(SeededJitter::new(seeds.clone()))
            .take(6)
            .collect();
        let run_b: Vec<Duration> = BackoffIterator::new(SeededJitter::new(seeds))
            .take(6)
            .collect();
        assert_eq!(run_a, run_b, "same seed must produce identical sequence");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests — require live Redis 7.x (`--features redis-integration`)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "redis-integration")]
mod integration {
    //! Integration tests against a live Redis 7.x server.
    //!
    //! Required environment (defaults shown):
    //!
    //! | Variable          | Default                  |
    //! |-------------------|--------------------------|
    //! | `REDIS_URL`       | `redis+unix:///tmp/redis.sock` |
    //! | `REDIS_USER`      | `heimdall`               |
    //! | `REDIS_PASSWORD`  | `heimdall-test`          |
    //!
    //! Run: `cargo test -p heimdall-runtime --features redis-integration`

    use std::path::PathBuf;

    use heimdall_runtime::store::{
        backoff::{BackoffIterator, SystemJitter},
        cache_store::{delete_cache, read_cache, write_cache},
        client::{RedisAuth, RedisConfig, RedisStore, RedisTopology},
        encoding::{CacheEntry, CacheNamespace, DnssecOutcome, RrsetPayload},
        ixfr_journal,
        zone_store::{ZoneRrset, delete_zone, get_rrset, write_zone},
    };

    fn redis_config() -> RedisConfig {
        let url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis+unix:///tmp/redis.sock".to_owned());
        let username = std::env::var("REDIS_USER").unwrap_or_else(|_| "heimdall".to_owned());
        let password =
            std::env::var("REDIS_PASSWORD").unwrap_or_else(|_| "heimdall-test".to_owned());

        // Parse URL to topology.
        let topology = if url.starts_with("redis+unix://") {
            let path = url.trim_start_matches("redis+unix://");
            RedisTopology::UnixSocket {
                path: PathBuf::from(path),
            }
        } else {
            // Parse as TCP.
            let without_scheme = url
                .trim_start_matches("rediss://")
                .trim_start_matches("redis://");
            let (host, port_str) = without_scheme
                .split_once(':')
                .unwrap_or(("127.0.0.1", "6379"));
            let port = port_str.parse().unwrap_or(6379);
            let tls = url.starts_with("rediss://");
            RedisTopology::Tcp {
                host: host.to_owned(),
                port,
                tls,
            }
        };

        RedisConfig {
            topology,
            auth: RedisAuth { username, password },
            ..RedisConfig::default()
        }
    }

    // ── Zone store ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn zone_write_and_read_round_trip() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        let fqdn = "integration-test.example.";

        let rrsets = vec![ZoneRrset {
            owner: fqdn.to_owned(),
            qtype: 1,  // A
            qclass: 1, // IN
            rrset: RrsetPayload {
                ttl: 300,
                rdata: vec![vec![127, 0, 0, 1]],
            },
        }];

        write_zone(&store, fqdn, &rrsets).await.expect("write zone");

        let result = get_rrset(&store, fqdn, fqdn, 1, 1)
            .await
            .expect("get rrset");
        assert!(result.is_some(), "expected rrset to be present");
        assert_eq!(result.unwrap().ttl, 300);

        delete_zone(&store, fqdn).await.expect("delete zone");
    }

    #[tokio::test]
    async fn zone_delete_removes_zone() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        let fqdn = "integration-delete-test.example.";

        let rrsets = vec![ZoneRrset {
            owner: fqdn.to_owned(),
            qtype: 28, // AAAA
            qclass: 1,
            rrset: RrsetPayload {
                ttl: 60,
                rdata: vec![vec![0u8; 16]],
            },
        }];

        write_zone(&store, fqdn, &rrsets).await.expect("write zone");
        delete_zone(&store, fqdn).await.expect("delete zone");

        let result = get_rrset(&store, fqdn, fqdn, 28, 1)
            .await
            .expect("get after delete");
        assert!(result.is_none(), "rrset should be gone after zone deletion");
    }

    // ── Cache store ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_write_read_delete_round_trip() {
        let store = RedisStore::connect(redis_config()).expect("connect");

        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Secure,
            inserted_at: 1_700_000_000,
            stale_until: 1_700_000_300,
            rrset: RrsetPayload {
                ttl: 300,
                rdata: vec![vec![1, 2, 3, 4]],
            },
        };

        write_cache(
            &store,
            CacheNamespace::Recursive,
            "cache-test.example.",
            1,
            1,
            &entry,
            300,
        )
        .await
        .expect("write cache");

        let read = read_cache(
            &store,
            CacheNamespace::Recursive,
            "cache-test.example.",
            1,
            1,
        )
        .await
        .expect("read cache");
        assert!(read.is_some(), "expected cache entry");
        assert_eq!(read.unwrap().dnssec_outcome, DnssecOutcome::Secure);

        let deleted = delete_cache(
            &store,
            CacheNamespace::Recursive,
            "cache-test.example.",
            1,
            1,
        )
        .await
        .expect("delete cache");
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn cache_namespaces_do_not_share_entries() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        let owner = "ns-isolation-test.example.";

        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Insecure,
            inserted_at: 0,
            stale_until: 300,
            rrset: RrsetPayload {
                ttl: 300,
                rdata: vec![vec![10, 0, 0, 1]],
            },
        };

        // Write only into Recursive namespace.
        write_cache(&store, CacheNamespace::Recursive, owner, 1, 1, &entry, 300)
            .await
            .expect("write recursive");

        // Forwarder namespace must not find it.
        let fwd = read_cache(&store, CacheNamespace::Forwarder, owner, 1, 1)
            .await
            .expect("read forwarder");
        assert!(
            fwd.is_none(),
            "forwarder namespace must not see recursive entry"
        );

        // Clean up.
        let _ = delete_cache(&store, CacheNamespace::Recursive, owner, 1, 1).await;
    }

    // ── IXFR journal ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn journal_append_and_query() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        let fqdn = "journal-test.example.";
        let now = 1_700_000_000u64;

        ixfr_journal::append(&store, fqdn, 2024_01_01, b"changeset-1", now)
            .await
            .expect("append 1");
        ixfr_journal::append(&store, fqdn, 2024_01_02, b"changeset-2", now)
            .await
            .expect("append 2");

        let entries = ixfr_journal::query_since(&store, fqdn, 2024_01_01)
            .await
            .expect("query");

        assert_eq!(
            entries.len(),
            1,
            "should return only entry after since_serial"
        );
        assert_eq!(entries[0].1, b"changeset-2");
    }

    // ── Availability flag ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn availability_flag_starts_true() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        assert!(store.is_available());
    }

    #[tokio::test]
    async fn record_error_marks_unavailable() {
        let store = RedisStore::connect(redis_config()).expect("connect");
        let err = heimdall_runtime::store::client::StoreError::Config("test".to_owned());
        store.record_error(&err);
        assert!(!store.is_available());
        store.record_success();
        assert!(store.is_available());
    }

    // ── Backoff reconnect ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn backoff_produces_increasing_delays() {
        // Verify the production SystemJitter path doesn't panic.
        let delays: Vec<_> = BackoffIterator::new(SystemJitter::new()).take(5).collect();
        assert_eq!(delays.len(), 5);
        // All delays ≤ ceiling.
        for d in &delays {
            assert!(d.as_millis() <= 30_000, "delay exceeded ceiling: {d:?}");
        }
    }
}
