// SPDX-License-Identifier: MIT

//! Integration tests for Sprint 30 — Recursive resolver core.
//!
//! These tests exercise the public API of the `recursive` and `dnssec_roles`
//! modules without using any real network sockets.  All upstream DNS queries
//! are intercepted by the `MockUpstream` helper.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_runtime::cache::entry::CacheEntry;
use heimdall_runtime::cache::recursive::RecursiveCache;
use heimdall_runtime::cache::{TtlBounds, ValidationOutcome};

use heimdall_roles::dnssec_roles::{NtaStore, TrustAnchorStore};
use heimdall_roles::recursive::{
    DelegationFollower, FollowResult, RecursiveCacheClient, RecursiveError, RecursiveServer,
    RootHints, ServerStateCache, UpstreamQuery, MAX_CNAME_HOPS, MAX_DELEGATION_DEPTH,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn name(s: &str) -> Name {
    Name::from_str(s).expect("INVARIANT: valid test name")
}

fn make_server(dir: &std::path::Path) -> RecursiveServer {
    let cache = Arc::new(RecursiveCache::new(512, 512));
    let trust_anchor =
        Arc::new(TrustAnchorStore::new(dir).expect("INVARIANT: trust anchor init"));
    let nta_store = Arc::new(NtaStore::new(100));
    let root_hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: root hints"));
    RecursiveServer::new(cache, trust_anchor, nta_store, root_hints)
}

fn make_query(qname: &Name, qtype: Qtype) -> Message {
    let mut header = Header::default();
    header.id = 1;
    header.set_rd(true);
    header.qdcount = 1;
    Message {
        header,
        questions: vec![Question {
            qname: qname.clone(),
            qtype,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn authoritative_a_answer(qname: &Name) -> Message {
    let mut header = Header::default();
    header.set_qr(true);
    header.set_aa(true);
    header.ancount = 1;
    Message {
        header,
        questions: vec![Question {
            qname: qname.clone(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![Record {
            name: qname.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        }],
        authority: vec![],
        additional: vec![],
    }
}

fn nxdomain_response(qname: &Name) -> Message {
    let mut header = Header::default();
    header.set_qr(true);
    header.set_aa(true);
    header.set_rcode(Rcode::NxDomain);
    Message {
        header,
        questions: vec![Question {
            qname: qname.clone(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn referral_message(delegation_zone: &Name, ns_name: &Name, ns_ip: Ipv4Addr) -> Message {
    let mut header = Header::default();
    header.set_qr(true);
    // AA=0 for referral
    Message {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![Record {
            name: delegation_zone.clone(),
            rtype: Rtype::Ns,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Ns(ns_name.clone()),
        }],
        additional: vec![Record {
            name: ns_name.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::A(ns_ip),
        }],
    }
}

// ── MockUpstream ──────────────────────────────────────────────────────────────

struct MockUpstream {
    responses: Arc<std::sync::Mutex<std::collections::VecDeque<Result<Message, std::io::Error>>>>,
    call_count: Arc<AtomicU32>,
}

impl MockUpstream {
    fn new(responses: Vec<Result<Message, std::io::Error>>) -> Arc<Self> {
        Arc::new(Self {
            responses: Arc::new(std::sync::Mutex::new(responses.into())),
            call_count: Arc::new(AtomicU32::new(0)),
        })
    }

    fn calls(&self) -> u32 {
        self.call_count.load(Ordering::Relaxed)
    }
}

impl UpstreamQuery for MockUpstream {
    fn query<'a>(
        &'a self,
        _server: IpAddr,
        _port: u16,
        _msg: &'a Message,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>> {
        let responses = Arc::clone(&self.responses);
        let counter = Arc::clone(&self.call_count);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            let mut guard =
                responses.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.pop_front().unwrap_or_else(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no more mock responses",
                ))
            })
        })
    }
}

// ── Test 1: dispatcher — cache hit short-circuits resolution ──────────────────

#[tokio::test]
async fn test_dispatcher_cache_hit_short_circuits_resolution() {
    let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
    let server = make_server(dir.path());

    let qname = name("cached.example.com.");
    let answer_msg = authoritative_a_answer(&qname);

    // Pre-populate the cache.
    server.cache_client().store(
        &qname,
        Rtype::A,
        1,
        &answer_msg,
        ValidationOutcome::Insecure,
        &Name::root(),
        false,
    );

    // Mock with no responses — if upstream is called, we'd get an error.
    let upstream = MockUpstream::new(vec![]);
    let query = make_query(&qname, Qtype::A);
    let response = server.handle(&query, upstream.clone()).await;

    assert_eq!(response.header.rcode(), Rcode::NoError, "cache hit must return NOERROR");
    assert_eq!(upstream.calls(), 0, "upstream must NOT be called on a cache hit");
}

// ── Test 2: dispatcher — bogus validation → SERVFAIL ─────────────────────────

#[tokio::test]
async fn test_dispatcher_bogus_validation_returns_servfail() {
    // We test the error mapping path directly by using RecursiveError.
    // The RecursiveServer returns SERVFAIL for BogusValidation errors.
    let err = RecursiveError::BogusValidation { reason: "InvalidSignature".into() };
    assert_eq!(err.to_rcode(), Rcode::ServFail);
    assert_eq!(
        err.to_ede_code(),
        Some(heimdall_core::edns::ede_code::DNSSEC_BOGUS)
    );
}

// ── Test 3: dispatcher — query timeout → SERVFAIL ─────────────────────────────

#[tokio::test]
async fn test_dispatcher_query_timeout_returns_servfail() {
    let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
    let server = make_server(dir.path());
    let qname = name("timeout.example.com.");

    // Return 40 timeouts — enough to exhaust all 13 root servers × 2.
    let responses: Vec<Result<Message, _>> = (0..40)
        .map(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))
        .collect();

    let upstream = MockUpstream::new(responses);
    let query = make_query(&qname, Qtype::A);
    let response = server.handle(&query, upstream).await;

    assert_eq!(
        response.header.rcode(),
        Rcode::ServFail,
        "all timeouts must yield SERVFAIL"
    );
}

// ── Test 4: follow — max delegation depth → ServFail ─────────────────────────

#[tokio::test]
async fn test_follow_max_delegation_depth_servfail() {
    let server_state = Arc::new(ServerStateCache::new());
    let root_hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: root hints"));
    let follower = DelegationFollower::new(server_state, root_hints);

    let qname = name("deep.example.com.");
    let ns_ip = Ipv4Addr::new(10, 0, 0, 1);
    let ns_name = name("ns.example.com.");
    let zone = name("example.com.");

    // MAX_DELEGATION_DEPTH + extra to ensure the cap fires.
    let responses: Vec<Result<Message, _>> =
        (0..=u32::from(MAX_DELEGATION_DEPTH) + 5)
            .map(|_| Ok(referral_message(&zone, &ns_name, ns_ip)))
            .collect();

    let upstream = MockUpstream::new(responses);
    let result = follower
        .resolve(&qname, Rtype::A, 1, upstream)
        .await;

    assert!(
        matches!(result, FollowResult::ServFail(RecursiveError::MaxDelegationsExceeded)),
        "must return MaxDelegationsExceeded, got: {result:?}"
    );
}

// ── Test 5: follow — CNAME hop cap → ServFail ─────────────────────────────────

#[tokio::test]
async fn test_follow_cname_hop_cap_servfail() {
    let server_state = Arc::new(ServerStateCache::new());
    let root_hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: root hints"));
    let follower = DelegationFollower::new(server_state, root_hints);

    let qname = name("alias0.example.com.");

    // Build MAX_CNAME_HOPS + 1 CNAME responses (each AA=1 to avoid delegation).
    let mut responses: Vec<Result<Message, _>> = Vec::new();
    for i in 0u8..=MAX_CNAME_HOPS {
        let from = Name::from_str(&format!("alias{i}.example.com."))
            .expect("INVARIANT: valid name");
        let to = Name::from_str(&format!("alias{}.example.com.", i + 1))
            .expect("INVARIANT: valid name");
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.ancount = 1;
        let msg = Message {
            header,
            questions: vec![Question {
                qname: from.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![Record {
                name: from,
                rtype: Rtype::Cname,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::Cname(to),
            }],
            authority: vec![],
            additional: vec![],
        };
        responses.push(Ok(msg));
    }
    responses.push(Err(std::io::Error::new(std::io::ErrorKind::Other, "cap hit")));

    let upstream = MockUpstream::new(responses);
    let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;

    assert!(
        matches!(result, FollowResult::ServFail(RecursiveError::MaxCnameHopsExceeded)),
        "must return MaxCnameHopsExceeded, got: {result:?}"
    );
}

// ── Test 6: follow — out-of-bailiwick glue discarded ─────────────────────────

#[tokio::test]
async fn test_follow_out_of_bailiwick_glue_discarded() {
    let server_state = Arc::new(ServerStateCache::new());
    let root_hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: root hints"));
    let follower = DelegationFollower::new(server_state, root_hints);

    let qname = name("www.example.com.");
    let delegation_zone = name("example.com.");
    let ns_name = name("ns.evil.com."); // Out-of-bailiwick

    let mut header = Header::default();
    header.set_qr(true);
    let referral = Message {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![Record {
            name: delegation_zone.clone(),
            rtype: Rtype::Ns,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Ns(ns_name.clone()),
        }],
        additional: vec![Record {
            // ns.evil.com. is NOT under example.com. → out-of-bailiwick.
            name: ns_name,
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        }],
    };

    let upstream = MockUpstream::new(vec![Ok(referral)]);
    let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;

    // Out-of-bailiwick glue discarded → no usable servers → ServFail.
    assert!(
        matches!(result, FollowResult::ServFail(_)),
        "out-of-bailiwick glue must be discarded: {result:?}"
    );
}

// ── Test 7: server_state — 0x20 non-conformant classification ────────────────

#[test]
fn test_server_state_ox20_non_conformant_classification() {
    let cache = ServerStateCache::new();
    let target = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let now = 1_000_000_u64;

    // 3 non-conformant out of 10 → threshold reached.
    for i in 0..10 {
        let conformant = i >= 3; // first 3 fail
        cache.record_response(target, conformant, now);
    }

    assert!(
        cache.should_disable_ox20(target),
        "server must be classified non-conformant after 3-of-10 failures"
    );
}

// ── Test 8: server_state — 0x20 reprobe interval ─────────────────────────────

#[test]
fn test_server_state_ox20_reprobe_interval() {
    let cache = ServerStateCache::new();
    let target = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5));
    let now = 1_000_000_u64;

    // Force non-conformance.
    for _ in 0..10 {
        cache.record_response(target, false, now);
    }

    // Should not reprobe before 1 hour.
    assert!(!cache.should_reprobe_ox20(target, now), "must not reprobe before 1 h");
    assert!(!cache.should_reprobe_ox20(target, now + 3_599), "must not reprobe at 3599 s");
    // Should reprobe at exactly 1 hour (3600 s).
    assert!(cache.should_reprobe_ox20(target, now + 3_600), "must reprobe after 1 h");

    // After advancing, the interval doubles to 2 h.
    cache.advance_reprobe_interval(target);
    assert!(
        !cache.should_reprobe_ox20(target, now + 3_600),
        "after doubling, must not reprobe at 1 h"
    );
    assert!(
        cache.should_reprobe_ox20(target, now + 7_200),
        "after doubling, must reprobe at 2 h"
    );
}

// ── Test 9: nta_store — expired NTA reverts to bogus ─────────────────────────

#[test]
fn test_nta_store_expired_nta_reverts_to_inactive() {
    let store = NtaStore::new(10);
    let domain = name("broken.example.com.");

    // Add with a past expiry.
    store.add(domain.clone(), 100, "test").expect("INVARIANT: add NTA");

    // At now=200, the NTA has expired → should be inactive.
    assert!(
        !store.is_active_nta(&domain, 200),
        "expired NTA must not be active"
    );
}

// ── Test 10: nta_store — bounded max entries enforced ────────────────────────

#[test]
fn test_nta_store_max_entries_enforced() {
    let store = NtaStore::new(2);

    store
        .add(name("a.example.com."), 9999, "r")
        .expect("INVARIANT: add a");
    store
        .add(name("b.example.com."), 9999, "r")
        .expect("INVARIANT: add b");

    let result = store.add(name("c.example.com."), 9999, "r");
    assert!(
        result.is_err(),
        "adding beyond max_entries must return an error"
    );
}

// ── Test 11: error — RecursiveError maps to correct RCODE + EDE ──────────────

#[test]
fn test_error_mapping_all_variants() {
    use heimdall_core::edns::ede_code;

    struct Case {
        err: RecursiveError,
        rcode: Rcode,
        ede: Option<u16>,
    }

    let cases = vec![
        Case {
            err: RecursiveError::AclDeny,
            rcode: Rcode::Refused,
            ede: None,
        },
        Case {
            err: RecursiveError::BogusValidation { reason: "x".into() },
            rcode: Rcode::ServFail,
            ede: Some(ede_code::DNSSEC_BOGUS),
        },
        Case {
            err: RecursiveError::QueryTimeout { elapsed_ms: 5000 },
            rcode: Rcode::ServFail,
            ede: Some(ede_code::NO_REACHABLE_AUTHORITY),
        },
        Case {
            err: RecursiveError::UpstreamRefused,
            rcode: Rcode::ServFail,
            ede: Some(ede_code::NOT_AUTHORITATIVE),
        },
        Case {
            err: RecursiveError::UpstreamServFail,
            rcode: Rcode::ServFail,
            ede: Some(2), // EDE 2
        },
        Case {
            err: RecursiveError::NxDomain,
            rcode: Rcode::NxDomain,
            ede: None,
        },
        Case {
            err: RecursiveError::NoData,
            rcode: Rcode::NoError,
            ede: None,
        },
        Case {
            err: RecursiveError::MaxDelegationsExceeded,
            rcode: Rcode::ServFail,
            ede: Some(ede_code::NO_REACHABLE_AUTHORITY),
        },
        Case {
            err: RecursiveError::MaxCnameHopsExceeded,
            rcode: Rcode::ServFail,
            ede: Some(ede_code::NO_REACHABLE_AUTHORITY),
        },
        Case {
            err: RecursiveError::TrustAnchorNotFound,
            rcode: Rcode::ServFail,
            ede: Some(ede_code::DNSKEY_MISSING),
        },
        Case {
            err: RecursiveError::CacheError("x".into()),
            rcode: Rcode::ServFail,
            ede: None,
        },
    ];

    for case in cases {
        assert_eq!(
            case.err.to_rcode(),
            case.rcode,
            "wrong RCODE for {:?}",
            case.err
        );
        assert_eq!(
            case.err.to_ede_code(),
            case.ede,
            "wrong EDE code for {:?}",
            case.err
        );
        assert!(!case.err.should_set_ad(), "errors must never set AD");
    }
}

// ── Test 12: timing — budget exhaustion ──────────────────────────────────────

#[test]
fn test_timing_budget_exhaustion() {
    use heimdall_roles::recursive::QueryBudget;

    // A budget with zero total time is immediately exhausted.
    let budget = QueryBudget {
        total_budget: Duration::ZERO,
        per_attempt_timeout: Duration::from_millis(100),
        start: Instant::now(),
        attempts: 0,
    };
    // Give the clock a moment.
    std::thread::sleep(Duration::from_millis(1));
    assert!(budget.is_exhausted(), "zero-duration budget must be exhausted");
}

// ── Test 13: cache_client — stale entry returned with is_stale=true ──────────

#[test]
fn test_cache_client_stale_entry() {
    // Use min_ttl_secs=0 so the cache does not clamp the already-expired
    // deadline to the default 60-second minimum — we need it to remain expired.
    let bounds = TtlBounds { min_ttl_secs: 0, ..TtlBounds::default() };
    let inner_cache = Arc::new(RecursiveCache::with_bounds(512, 512, bounds));
    let client = RecursiveCacheClient::new(Arc::clone(&inner_cache));

    let qname = name("stale.example.com.");
    let key = heimdall_runtime::cache::CacheKey {
        qname: qname.as_wire_bytes().to_ascii_lowercase(),
        qtype: 1,
        qclass: 1,
    };

    let now = Instant::now();
    inner_cache.insert(
        key,
        CacheEntry {
            rdata_wire: vec![1, 2, 3],
            ttl_deadline: now - Duration::from_secs(10),
            dnssec_outcome: ValidationOutcome::Insecure,
            is_negative: false,
            serve_stale_until: Some(now + Duration::from_secs(290)),
            zone_apex: b"\x00".to_vec(),
        },
    );

    let result = client.lookup(&qname, Rtype::A, 1, false);
    assert!(result.is_some(), "stale entry must be returned");
    assert!(result.unwrap().is_stale, "entry must be marked is_stale=true");
}
