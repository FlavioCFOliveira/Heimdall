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
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! Integration tests for the forwarder role (Sprint 32).
//!
//! Tests 1–13 per the sprint specification.

use std::{collections::HashSet, net::IpAddr, sync::Arc};

use heimdall_core::{
    header::{Header, Qclass, Qtype, Question},
    name::Name,
    parser::Message,
};
use heimdall_roles::{
    dnssec_roles::{NtaStore, TrustAnchorStore},
    forwarder::{
        ClientRegistry, ForwardDispatcher, ForwardRule, ForwarderPool, ForwarderRateLimiter,
        ForwarderServer, ForwarderValidator, MatchMode, RlKey, UpstreamConfig, UpstreamTransport,
    },
};
use heimdall_runtime::cache::forwarder::ForwarderCache;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn udp_upstream(host: &str) -> UpstreamConfig {
    UpstreamConfig {
        host: host.to_string(),
        port: 53,
        transport: UpstreamTransport::UdpTcp,
        sni: None,
        tls_verify: true,
    }
}

fn rule(zone: &str, mode: MatchMode) -> ForwardRule {
    ForwardRule {
        zone: zone.to_string(),
        match_mode: mode,
        upstreams: vec![udp_upstream("8.8.8.8")],
        fallback_recursive: false,
    }
}

fn query_for(name: &str) -> Message {
    let mut header = Header::default();
    header.set_rd(true);
    header.qdcount = 1;
    Message {
        header,
        questions: vec![Question {
            qname: Name::from_str_fqdn(name),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn make_trust_anchor() -> Arc<TrustAnchorStore> {
    let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
    let store = Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
    std::mem::forget(dir);
    store
}

fn make_server(rules: Vec<ForwardRule>, rate_limit: u32) -> ForwarderServer {
    let trust_anchor = make_trust_anchor();
    let nta_store = Arc::new(NtaStore::new(100));
    let cache = Arc::new(ForwarderCache::new(512, 512));
    let registry = Arc::new(ClientRegistry::build(&HashSet::new()));
    let pool = ForwarderPool::new(registry, vec![]);

    ForwarderServer::new(rules, pool, trust_anchor, nta_store, cache, rate_limit)
}

// ── Name helper (FQDN from string) ───────────────────────────────────────────

trait FromStrFqdn {
    fn from_str_fqdn(s: &str) -> Self;
}

impl FromStrFqdn for Name {
    fn from_str_fqdn(s: &str) -> Self {
        use std::str::FromStr;
        Name::from_str(s).expect("INVARIANT: test name must be valid FQDN")
    }
}

// ── Test 1: dispatcher — exact match ─────────────────────────────────────────

/// Test 1 — Dispatcher exact match.
///
/// A rule with `zone="example.com."` and `mode=Exact`:
/// - `"example.com."` must match.
/// - `"sub.example.com."` must NOT match.
#[test]
fn test_dispatcher_exact_match() {
    let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Exact)]);

    assert!(
        d.match_query("example.com.").is_some(),
        "exact zone must match"
    );
    assert!(
        d.match_query("sub.example.com.").is_none(),
        "subdomain must not match exact rule"
    );
}

// ── Test 2: dispatcher — suffix match ────────────────────────────────────────

/// Test 2 — Dispatcher suffix match.
///
/// A rule with `zone="example.com."` and `mode=Suffix`:
/// - `"example.com."` must match.
/// - `"sub.example.com."` must match.
/// - `"notexample.com."` must NOT match.
#[test]
fn test_dispatcher_suffix_match() {
    let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);

    assert!(
        d.match_query("example.com.").is_some(),
        "apex must match suffix rule"
    );
    assert!(
        d.match_query("sub.example.com.").is_some(),
        "subdomain must match suffix rule"
    );
    assert!(
        d.match_query("notexample.com.").is_none(),
        "non-suffix domain must not match"
    );
}

// ── Test 3: dispatcher — wildcard match ──────────────────────────────────────

/// Test 3 — Dispatcher wildcard match.
///
/// A rule with `zone="*.example.com."` and `mode=Wildcard`:
/// - `"sub.example.com."` must match.
/// - `"example.com."` (apex) must NOT match.
#[test]
fn test_dispatcher_wildcard_match() {
    let d = ForwardDispatcher::new(vec![rule("*.example.com.", MatchMode::Wildcard)]);

    assert!(
        d.match_query("sub.example.com.").is_some(),
        "subdomain must match wildcard rule"
    );
    assert!(
        d.match_query("example.com.").is_none(),
        "apex must not match wildcard rule"
    );
}

// ── Test 4: dispatcher — longest-zone wins ───────────────────────────────────

/// Test 4 — Dispatcher: longest-zone wins on tie.
///
/// Two suffix rules for `"com."` and `"example.com."`:
/// query `"a.example.com."` must pick the `"example.com."` rule.
#[test]
fn test_dispatcher_longest_zone_wins() {
    let d = ForwardDispatcher::new(vec![
        rule("com.", MatchMode::Suffix),
        rule("example.com.", MatchMode::Suffix),
    ]);

    let matched = d
        .match_query("a.example.com.")
        .expect("INVARIANT: must match a suffix rule");
    assert_eq!(
        matched.zone, "example.com.",
        "longer zone must win (most specific rule)"
    );
}

// ── Test 5: dispatcher — no match returns None ───────────────────────────────

/// Test 5 — Dispatcher: no matching rule returns `None`.
///
/// Query `"other.org."` against `"example.com."` rules returns `None`.
#[test]
fn test_dispatcher_no_match_returns_none() {
    let d = ForwardDispatcher::new(vec![
        rule("example.com.", MatchMode::Suffix),
        rule("*.example.com.", MatchMode::Wildcard),
    ]);

    assert!(
        d.match_query("other.org.").is_none(),
        "unrelated domain must not match"
    );
}

// ── Test 6: dispatcher — atomic reload ───────────────────────────────────────

/// Test 6 — Dispatcher: atomic reload takes effect.
///
/// After `reload()`, new rules are matched and old rules are not.
#[test]
fn test_dispatcher_atomic_reload() {
    let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);

    assert!(
        d.match_query("example.com.").is_some(),
        "original rule must match before reload"
    );
    assert!(
        d.match_query("other.org.").is_none(),
        "other.org must not match before reload"
    );

    d.reload(vec![rule("other.org.", MatchMode::Suffix)]);

    assert!(
        d.match_query("other.org.").is_some(),
        "new rule must match after reload"
    );
    assert!(
        d.match_query("example.com.").is_none(),
        "old rule must not match after reload"
    );
}

// ── Test 7: ratelimit — allows under limit ───────────────────────────────────

/// Test 7 — Rate limiter: 10 rps limit, 5 queries pass.
#[test]
fn test_ratelimit_allows_under_limit() {
    let rl = ForwarderRateLimiter::new(10);
    let key = RlKey::SourceIp(
        "192.168.1.1"
            .parse::<IpAddr>()
            .expect("INVARIANT: valid IP"),
    );

    for i in 0..5 {
        assert!(
            rl.check_and_consume(&key),
            "query {i} must be allowed at 10 rps"
        );
    }
}

// ── Test 8: ratelimit — blocks over limit ────────────────────────────────────

/// Test 8 — Rate limiter: 5 rps limit, 10 immediate queries → some blocked.
#[test]
fn test_ratelimit_blocks_over_limit() {
    let rl = ForwarderRateLimiter::new(5);
    let key = RlKey::SourceIp("10.0.0.1".parse::<IpAddr>().expect("INVARIANT: valid IP"));

    let allowed: usize = (0..10).filter(|_| rl.check_and_consume(&key)).count();

    assert!(
        allowed < 10,
        "some queries must be blocked at 5 rps with 10 immediate queries"
    );
    assert_eq!(
        allowed, 5,
        "exactly 5 of 10 immediate queries must pass (initial bucket)"
    );
}

// ── Test 9: forwarder_validator — upstream AD bit not trusted ─────────────────

/// Test 9 — `ForwarderValidator`: upstream AD bit is never trusted.
///
/// A response with `AD=1` but no RRSIG records must return `Insecure` (not
/// `Secure`), per DNSSEC-019.
#[test]
fn test_forwarder_validator_upstream_ad_not_trusted() {
    use heimdall_core::dnssec::ValidationOutcome;

    let trust_anchor = make_trust_anchor();
    let nta_store = Arc::new(NtaStore::new(100));
    let validator = ForwarderValidator::new(trust_anchor, nta_store);

    // Build a response with AD=1 but no RRSIG records (invalid DNSSEC data).
    let mut header = Header::default();
    header.set_qr(true);
    header.set_ad(true); // Upstream claims the response is secure.
    let msg = Message {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let zone = Name::from_str_fqdn("example.com.");
    let outcome = validator.validate(&msg, &zone, 1_000_000);

    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "upstream AD=1 without RRSIGs must validate as Insecure, not Secure (DNSSEC-019)"
    );
}

// ── Test 10: client_registry — only declared transports instantiated ──────────

/// Test 10 — `ClientRegistry`: only declared transports are instantiated.
///
/// Registry built with `UdpTcp` only; `DoT` client returns `None`.
#[test]
fn test_client_registry_only_declared_transports() {
    let mut transports = HashSet::new();
    transports.insert(UpstreamTransport::UdpTcp);

    let registry = ClientRegistry::build(&transports);

    assert!(
        registry.get_client(&UpstreamTransport::UdpTcp).is_some(),
        "declared UdpTcp transport must have a client"
    );
    assert!(
        registry.get_client(&UpstreamTransport::Dot).is_none(),
        "undeclared DoT transport must return None"
    );
    assert!(
        registry.get_client(&UpstreamTransport::DohH2).is_none(),
        "undeclared DohH2 transport must return None"
    );
    assert!(
        registry.get_client(&UpstreamTransport::DohH3).is_none(),
        "undeclared DohH3 transport must return None"
    );
    assert!(
        registry.get_client(&UpstreamTransport::Doq).is_none(),
        "undeclared DoQ transport must return None"
    );
}

// ── Test 11: pool — chain exhaustion returns error ────────────────────────────

/// Test 11 — `ForwarderPool`: chain exhaustion returns `AllTransportsFailed`.
///
/// All transports in the chain are stubs (return `Unsupported`); the pool
/// must return `AllTransportsFailed`.
#[tokio::test]
async fn test_pool_chain_exhaustion_returns_error() {
    use heimdall_roles::forwarder::ForwarderError;

    // Only DohH2 registered (stub → always Unsupported).
    let mut transports = HashSet::new();
    transports.insert(UpstreamTransport::DohH2);
    let registry = Arc::new(ClientRegistry::build(&transports));

    // Chain: DohH2 (stub fails) then UdpTcp (not registered → skip).
    let pool = ForwarderPool::new(
        registry,
        vec![UpstreamTransport::DohH2, UpstreamTransport::UdpTcp],
    );

    let upstream = UpstreamConfig {
        host: "127.0.0.1".to_string(),
        port: 53,
        transport: UpstreamTransport::DohH2,
        sni: None,
        tls_verify: true,
    };

    let msg = Message {
        header: Header::default(),
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let result = pool.query(&upstream, &msg).await;
    assert!(
        matches!(result, Err(ForwarderError::AllTransportsFailed)),
        "exhausted chain must return AllTransportsFailed; got: {result:?}"
    );
}

// ── Test 12: forwarder_server — no rule match returns None ────────────────────

/// Test 12 — `ForwarderServer`: no matching rule returns `None`.
///
/// Server with no rules; any query returns `None`.
#[tokio::test]
async fn test_forwarder_server_no_rule_match_returns_none() {
    let server = make_server(vec![], 100);
    let query = query_for("other.org.");
    let key = RlKey::SourceIp("127.0.0.1".parse::<IpAddr>().expect("INVARIANT: valid IP"));

    let result = server.handle(&query, &key).await;
    assert!(result.is_none(), "no matching rule must return None");
}

// ── Test 13: forwarder_server — rate-limited client returns REFUSED ───────────

/// Test 13 — `ForwarderServer`: rate-limited client returns REFUSED.
///
/// Rate limit = 1 rps; second query immediately returns REFUSED.
#[tokio::test]
async fn test_forwarder_server_rate_limited_returns_refused() {
    use heimdall_core::header::Rcode;

    // Rule that matches example.com. (with no actual upstreams — all will fail,
    // but the rate-limit check runs before upstream selection).
    let r = ForwardRule {
        zone: "example.com.".to_string(),
        match_mode: MatchMode::Suffix,
        upstreams: vec![], // No real upstreams → SERVFAIL on first query.
        fallback_recursive: false,
    };

    let server = make_server(vec![r], 1); // 1 query per second limit.
    let query = query_for("example.com.");
    let key = RlKey::SourceIp("10.0.0.2".parse::<IpAddr>().expect("INVARIANT: valid IP"));

    // First query: passes the rate limiter (consumes the initial token).
    // May return SERVFAIL (no upstreams) or None — but NOT REFUSED.
    let first = server.handle(&query, &key).await;
    if let Some(ref msg) = first {
        assert_ne!(
            msg.header.rcode(),
            Rcode::Refused,
            "first query must not be REFUSED"
        );
    }

    // Second query: rate-limited → must return REFUSED.
    let second = server
        .handle(&query, &key)
        .await
        .expect("INVARIANT: rate-limited query must return Some(REFUSED)");

    assert_eq!(
        second.header.rcode(),
        Rcode::Refused,
        "rate-limited second query must return REFUSED"
    );
}
