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
    clippy::undocumented_unsafe_blocks
)]

//! E2E: Redis persistence — auth zone HSET load + atomic RENAME swap;
//! cache namespace isolation; TCP + ACL credentials.
//! (Sprint 47 task #607, STORE-018..030, STORE-042..044)
//!
//! Requires Docker (testcontainers). Tests that need a container print
//! "SKIP: …" and return without failing when Docker is unavailable.
//!
//! Sub-cases:
//!
//! (i)   **Zone HSET shape** (`STORE-042/043`): `write_zone` stores Hash fields
//!       whose names follow `<owner>|<qtype>|<qclass>` and whose values carry
//!       the version-0x01 binary header with the big-endian TTL.
//!
//! (ii)  **Atomic RENAME swap** (`STORE-023`): after `write_zone` v2 the live key
//!       holds all-v2 data; the staging key is absent.
//!
//! (iii) **Cache namespace isolation** (`STORE-027/028`): an entry written to the
//!       `Recursive` namespace is invisible when read with the `Forwarder` namespace
//!       selector, and vice versa.
//!
//! (iv)  **TCP ACL credentials enforced** (`STORE-012`): Redis with `--requirepass`
//!       rejects an empty-credential connection; the correct username/password succeeds.

// ── Container helpers ─────────────────────────────────────────────────────────

fn redis_container_blocking() -> Option<(u16, impl Drop)> {
    use testcontainers::{GenericImage, core::WaitFor, runners::SyncRunner};

    match GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
    {
        Ok(c) => {
            let port = c.get_host_port_ipv4(6379u16).expect("Redis host port");
            Some((port, c))
        }
        Err(e) => {
            eprintln!("SKIP: could not start Redis container: {e}");
            None
        }
    }
}

fn redis_with_password_blocking(password: &str) -> Option<(u16, impl Drop)> {
    use testcontainers::{GenericImage, ImageExt as _, core::WaitFor, runners::SyncRunner};

    match GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_cmd(["redis-server", "--requirepass", password])
        .start()
    {
        Ok(c) => {
            let port = c.get_host_port_ipv4(6379u16).expect("Redis host port");
            Some((port, c))
        }
        Err(e) => {
            eprintln!("SKIP: could not start Redis container with password: {e}");
            None
        }
    }
}

// ── Store constructors ────────────────────────────────────────────────────────

fn tcp_store(port: u16) -> heimdall_runtime::RedisStore {
    heimdall_runtime::RedisStore::connect(heimdall_runtime::RedisConfig {
        topology: heimdall_runtime::RedisTopology::Tcp {
            host: "127.0.0.1".into(),
            port,
            tls: false,
        },
        auth: heimdall_runtime::RedisAuth {
            username: String::new(),
            password: String::new(),
        },
        pool_max_size: 4,
        pool_min_size: 1,
        pool_acquisition_timeout_ms: 2_000,
        hscan_count: 64,
    })
    .expect("RedisStore::connect (no auth)")
}

fn tcp_store_with_auth(port: u16, username: &str, password: &str) -> heimdall_runtime::RedisStore {
    heimdall_runtime::RedisStore::connect(heimdall_runtime::RedisConfig {
        topology: heimdall_runtime::RedisTopology::Tcp {
            host: "127.0.0.1".into(),
            port,
            tls: false,
        },
        auth: heimdall_runtime::RedisAuth {
            username: username.to_owned(),
            password: password.to_owned(),
        },
        pool_max_size: 4,
        pool_min_size: 1,
        pool_acquisition_timeout_ms: 1_000,
        hscan_count: 64,
    })
    .expect("RedisStore::connect (with auth)")
}

// ── (i) Zone HSET shape ───────────────────────────────────────────────────────

/// (i) `write_zone` produces Hash fields named `<owner>|<qtype>|<qclass>` whose
/// values carry the STORE-043 version byte (0x01) and big-endian TTL.
#[test]
fn zone_hset_carries_documented_field_shape() {
    use heimdall_runtime::store::{
        RrsetPayload, zone_key,
        zone_store::{ZoneRrset, write_zone},
    };

    let Some((port, _container)) = redis_container_blocking() else {
        return;
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let store = tcp_store(port);
        let fqdn = "hset-shape-test.";

        let rrsets = vec![
            ZoneRrset {
                owner: "hset-shape-test.".to_owned(),
                qtype: 1,  // A
                qclass: 1, // IN
                rrset: RrsetPayload {
                    ttl: 0x0102_0304,
                    rdata: vec![vec![192, 0, 2, 1]],
                },
            },
            ZoneRrset {
                owner: "hset-shape-test.".to_owned(),
                qtype: 28, // AAAA
                qclass: 1,
                rrset: RrsetPayload {
                    ttl: 300,
                    rdata: vec![vec![0u8; 16]],
                },
            },
        ];

        write_zone(&store, fqdn, &rrsets).await.expect("write_zone");

        // Read raw fields back from Redis to inspect binary layout.
        let live_key = zone_key(fqdn);
        let mut conn = store.connection().await.expect("connection");
        let fields: Vec<(String, Vec<u8>)> = redis::cmd("HGETALL")
            .arg(&live_key)
            .query_async(&mut conn)
            .await
            .expect("HGETALL");

        assert_eq!(
            fields.len(),
            2,
            "(i) HSET must have exactly 2 fields; got {}",
            fields.len()
        );

        let field_names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            field_names.contains(&"hset-shape-test.|1|1"),
            "(i) A record field name must be 'hset-shape-test.|1|1'; got {field_names:?}"
        );
        assert!(
            field_names.contains(&"hset-shape-test.|28|1"),
            "(i) AAAA record field name must be 'hset-shape-test.|28|1'; got {field_names:?}"
        );

        // Verify STORE-043 binary layout on the A-record value.
        let a_value = fields
            .iter()
            .find(|(k, _)| k == "hset-shape-test.|1|1")
            .map(|(_, v)| v)
            .expect("A record value must be present");

        assert_eq!(
            a_value[0], 0x01,
            "(i) version byte must be 0x01; got {:#04x}",
            a_value[0]
        );
        // Bytes 1..5: TTL big-endian 0x01020304.
        assert_eq!(
            &a_value[1..5],
            &[0x01, 0x02, 0x03, 0x04],
            "(i) TTL bytes must be big-endian 0x01020304; got {:?}",
            &a_value[1..5]
        );
    });
}

// ── (ii) Atomic RENAME swap ───────────────────────────────────────────────────

/// (ii) `write_zone` atomically promotes the staging key to the live key.
/// After the call: live key holds all-v2 data; staging key is absent.
#[test]
fn zone_rename_swap_live_key_reflects_v2_staging_key_absent() {
    use heimdall_runtime::store::{
        RrsetPayload, zone_staging_key,
        zone_store::{ZoneRrset, get_rrset, write_zone},
    };

    let Some((port, _container)) = redis_container_blocking() else {
        return;
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let store = tcp_store(port);
        let fqdn = "atomic-rename-test.";

        let make_rrsets = |ttl: u32| {
            vec![
                ZoneRrset {
                    owner: "atomic-rename-test.".to_owned(),
                    qtype: 1,
                    qclass: 1,
                    rrset: RrsetPayload {
                        ttl,
                        rdata: vec![vec![1, 1, 1, 1]],
                    },
                },
                ZoneRrset {
                    owner: "sub.atomic-rename-test.".to_owned(),
                    qtype: 1,
                    qclass: 1,
                    rrset: RrsetPayload {
                        ttl,
                        rdata: vec![vec![2, 2, 2, 2]],
                    },
                },
            ]
        };

        write_zone(&store, fqdn, &make_rrsets(100))
            .await
            .expect("write v1");

        // Confirm v1 is live.
        let v1 = get_rrset(&store, fqdn, "atomic-rename-test.", 1, 1)
            .await
            .expect("get v1")
            .expect("v1 must be present");
        assert_eq!(v1.ttl, 100, "(ii) v1 TTL must be 100; got {}", v1.ttl);

        // Write v2 — this uses staging → RENAME.
        write_zone(&store, fqdn, &make_rrsets(200))
            .await
            .expect("write v2");

        // Both apex and sub must reflect v2.
        let apex = get_rrset(&store, fqdn, "atomic-rename-test.", 1, 1)
            .await
            .expect("get apex v2")
            .expect("apex must be present");
        assert_eq!(
            apex.ttl, 200,
            "(ii) apex TTL must be 200 after v2; got {}",
            apex.ttl
        );

        let sub = get_rrset(&store, fqdn, "sub.atomic-rename-test.", 1, 1)
            .await
            .expect("get sub v2")
            .expect("sub must be present");
        assert_eq!(
            sub.ttl, 200,
            "(ii) sub TTL must be 200 after v2; got {}",
            sub.ttl
        );

        // Staging key must not exist after RENAME completes.
        let staging = zone_staging_key(fqdn);
        let mut conn = store.connection().await.expect("connection");
        let exists: i64 = redis::cmd("EXISTS")
            .arg(&staging)
            .query_async(&mut conn)
            .await
            .expect("EXISTS staging");
        assert_eq!(
            exists, 0,
            "(ii) staging key must be absent after RENAME; EXISTS returned {exists}"
        );
    });
}

// ── (iii) Cache namespace isolation ─────────────────────────────────────────

/// (iii) An entry written to `Recursive` is invisible from `Forwarder`, and
/// vice versa (`STORE-027/028`).
#[test]
fn cache_namespace_isolation_recursive_invisible_from_forwarder() {
    use heimdall_runtime::store::{
        CacheEntry, CacheNamespace, DnssecOutcome, RrsetPayload,
        cache_store::{read_cache, write_cache},
    };

    let Some((port, _container)) = redis_container_blocking() else {
        return;
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let store = tcp_store(port);
        let owner = "ns-isolation-test.com.";
        let qtype = 1u16;
        let qclass = 1u16;

        let rec_entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Secure,
            inserted_at: 1_700_000_000,
            stale_until: 1_700_000_060,
            rrset: RrsetPayload {
                ttl: 60,
                rdata: vec![vec![10, 0, 0, 1]],
            },
        };

        // Write to Recursive namespace.
        write_cache(
            &store,
            CacheNamespace::Recursive,
            owner,
            qtype,
            qclass,
            &rec_entry,
            60,
        )
        .await
        .expect("write recursive cache entry");

        // Must be readable from Recursive.
        let read_rec = read_cache(&store, CacheNamespace::Recursive, owner, qtype, qclass)
            .await
            .expect("read recursive")
            .expect("recursive entry must be present");
        assert_eq!(
            read_rec.rrset.ttl, 60,
            "(iii) Recursive entry TTL must be 60"
        );

        // Must NOT be readable from Forwarder.
        let read_fwd = read_cache(&store, CacheNamespace::Forwarder, owner, qtype, qclass)
            .await
            .expect("read forwarder (must not error)");
        assert!(
            read_fwd.is_none(),
            "(iii) Recursive entry must be invisible from Forwarder namespace; got {read_fwd:?}"
        );

        // Write a distinct entry to Forwarder namespace.
        let fwd_entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Insecure,
            inserted_at: 1_700_000_000,
            stale_until: 1_700_000_120,
            rrset: RrsetPayload {
                ttl: 120,
                rdata: vec![vec![10, 0, 0, 2]],
            },
        };
        write_cache(
            &store,
            CacheNamespace::Forwarder,
            owner,
            qtype,
            qclass,
            &fwd_entry,
            120,
        )
        .await
        .expect("write forwarder cache entry");

        // Forwarder write must not overwrite the Recursive entry.
        let read_rec_after = read_cache(&store, CacheNamespace::Recursive, owner, qtype, qclass)
            .await
            .expect("re-read recursive after forwarder write")
            .expect("recursive entry must still be present");
        assert_eq!(
            read_rec_after.rrset.ttl, 60,
            "(iii) Recursive TTL must remain 60 after Forwarder write; got {}",
            read_rec_after.rrset.ttl
        );

        // Forwarder entry must be independently readable.
        let read_fwd_after = read_cache(&store, CacheNamespace::Forwarder, owner, qtype, qclass)
            .await
            .expect("read forwarder after write")
            .expect("forwarder entry must be present");
        assert_eq!(
            read_fwd_after.rrset.ttl, 120,
            "(iii) Forwarder entry TTL must be 120; got {}",
            read_fwd_after.rrset.ttl
        );
    });
}

// ── (iv) TCP + ACL credentials enforced ─────────────────────────────────────

/// (iv) Redis with `--requirepass` rejects empty-credential connections and
/// accepts the correct `username/password` pair (`STORE-012`).
#[test]
fn tcp_acl_credentials_enforced_correct_pass_succeeds_wrong_fails() {
    const PASSWORD: &str = "acl-test-pass-607";

    let Some((port, _container)) = redis_with_password_blocking(PASSWORD) else {
        return;
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        // Empty credentials — pool creation is lazy, so test by issuing a command.
        let store_no_auth = tcp_store(port);
        let auth_failure = if let Ok(mut conn) = store_no_auth.connection().await {
            let ping: Result<String, redis::RedisError> =
                redis::cmd("PING").query_async(&mut conn).await;
            ping.is_err()
        } else {
            true
        };
        assert!(
            auth_failure,
            "(iv) empty-credential connection or PING must fail on AUTH-required Redis"
        );

        // Correct credentials.
        let store_with_auth = tcp_store_with_auth(port, "default", PASSWORD);
        let mut conn = store_with_auth
            .connection()
            .await
            .expect("(iv) correct-credential connection must succeed");
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .expect("(iv) PING with correct credentials must succeed");
        assert_eq!(pong, "PONG", "(iv) PING must return PONG; got {pong:?}");
    });
}
