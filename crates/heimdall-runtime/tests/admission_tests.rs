// SPDX-License-Identifier: MIT

//! Integration tests for the Sprint 20 admission pipeline (THREAT-033..078).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use heimdall_runtime::admission::{
    AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CidrSet, CompiledAcl, EnumSet,
    LoadFactors, LoadSignal, Matcher, Operation, PipelineDecision, QnamePattern, QueryRlConfig,
    QueryRlEngine, RequestCtx, ResourceCounters, ResourceLimits, RlBucket, RlKey, Role, RrlConfig,
    RrlDecision, RrlEngine, Transport, new_acl_handle,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn src(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn base_ctx(role: Role, op: Operation) -> RequestCtx {
    RequestCtx {
        source_ip: src(10, 0, 0, 1),
        mtls_identity: None,
        tsig_identity: None,
        transport: Transport::Udp53,
        role,
        operation: op,
        qname: b"\x07example\x03com\x00".to_vec(),
        has_valid_cookie: false,
    }
}

fn unlimited_pipeline() -> AdmissionPipeline {
    AdmissionPipeline {
        acl: new_acl_handle(CompiledAcl::default()),
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(RrlConfig {
            rate_per_sec: 1_000_000,
            ..Default::default()
        })),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig {
            anon_rate: 1_000_000,
            cookie_rate: 1_000_000,
            auth_rate: 1_000_000,
            burst_window_secs: 10,
        })),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    }
}

// ── Full-pipeline integration tests ──────────────────────────────────────────

#[test]
fn full_pipeline_acl_deny_short_circuits() {
    let deny_all = AclRule {
        matchers: vec![],
        action: AclAction::Deny,
    };
    let p = AdmissionPipeline {
        acl: new_acl_handle(CompiledAcl::new(vec![deny_all])),
        ..unlimited_pipeline()
    };
    let ctx = base_ctx(Role::Authoritative, Operation::Query);
    assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
    // Resource counter must be untouched.
    assert_eq!(p.resource_counters.global_pending(), 0);
    assert_eq!(p.telemetry.acl_denied.load(Ordering::Relaxed), 1);
    assert_eq!(p.telemetry.conn_limit_denied.load(Ordering::Relaxed), 0);
}

#[test]
fn full_pipeline_under_load_no_cookie_denied_stage3() {
    let p = unlimited_pipeline();
    p.load_signal.update(LoadFactors {
        cpu_pct: 1.0,
        memory_pct: 1.0,
        pending_queries_pct: 1.0,
        rl_fires_rate: 1.0,
    });
    let ctx = base_ctx(Role::Authoritative, Operation::Query);
    assert_eq!(
        p.evaluate(&ctx, Instant::now()),
        PipelineDecision::DenyCookieUnderLoad
    );
    // Stage 2 slot must be released.
    assert_eq!(p.resource_counters.global_pending(), 0);
    assert_eq!(p.telemetry.cookie_load_denied.load(Ordering::Relaxed), 1);
}

#[test]
fn full_pipeline_over_rate_denied_stage4_budget_unaffected() {
    // RRL budget=1, slip=100 (no slip in this test).
    let p = AdmissionPipeline {
        rrl: Arc::new(RrlEngine::new(RrlConfig {
            rate_per_sec: 1,
            slip_ratio: 100,
            ..Default::default()
        })),
        ..unlimited_pipeline()
    };
    let now = Instant::now();
    let ctx = base_ctx(Role::Authoritative, Operation::Query);

    // First: allowed.
    let d = p.evaluate(&ctx, now);
    p.resource_counters.release_global(); // simulate query done
    assert_eq!(d, PipelineDecision::Allow);

    // Second: RRL fires.
    let d2 = p.evaluate(&ctx, now);
    assert_eq!(d2, PipelineDecision::DenyRrl(RrlDecision::Drop));
    // Global counter was released inside the pipeline.
    assert_eq!(p.resource_counters.global_pending(), 0);
    assert_eq!(p.telemetry.rrl_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(p.telemetry.total_allowed.load(Ordering::Relaxed), 1);
}

#[test]
fn dynamic_acl_reload_in_flight_uses_old_acl() {
    // Start with default ACL (authoritative=allow).
    let handle = new_acl_handle(CompiledAcl::default());
    let p = AdmissionPipeline {
        acl: handle.clone(),
        ..unlimited_pipeline()
    };
    let ctx = base_ctx(Role::Authoritative, Operation::Query);
    // Snapshot the old ACL (in-flight query holds this guard).
    let old_snap = handle.load();
    assert_eq!(old_snap.evaluate(&ctx), AclAction::Allow);

    // Hot-reload: deny all.
    let new_acl = Arc::new(CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Deny,
    }]));
    handle.store(new_acl);

    // Old snapshot still allows.
    assert_eq!(old_snap.evaluate(&ctx), AclAction::Allow);
    // Pipeline now uses new ACL.
    assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
}

#[test]
fn resource_counter_concurrent_acquire_release_invariant() {
    let counters = Arc::new(ResourceCounters::new());
    let limits = Arc::new(ResourceLimits {
        max_global_pending: 50,
        ..Default::default()
    });
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&counters);
        let l = Arc::clone(&limits);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                if c.try_acquire_global(&l) {
                    c.release_global();
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(counters.global_pending(), 0);
}

#[test]
fn default_deny_axfr_even_with_valid_source() {
    let p = unlimited_pipeline();
    let ctx = base_ctx(Role::Authoritative, Operation::Axfr);
    // Default ACL denies AXFR regardless of source.
    assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
}

#[test]
fn rrl_reflection_simulation() {
    // Simulate 1 000 queries from a spoofed source.
    // With rate=5 and slip=2: at most rate + ceil(excess / slip) responses
    // get through (allowed + slipped).
    let rate = 5u32;
    let slip = 2u8;
    let p = AdmissionPipeline {
        rrl: Arc::new(RrlEngine::new(RrlConfig {
            rate_per_sec: rate,
            slip_ratio: slip,
            window_secs: 1,
            ..Default::default()
        })),
        ..unlimited_pipeline()
    };
    let now = Instant::now();
    let ctx = base_ctx(Role::Authoritative, Operation::Query);

    let mut allowed = 0u32;
    let mut slipped = 0u32;
    let mut dropped = 0u32;

    for _ in 0..1_000 {
        match p.evaluate(&ctx, now) {
            PipelineDecision::Allow => {
                p.resource_counters.release_global();
                allowed += 1;
            }
            PipelineDecision::DenyRrl(RrlDecision::Slip) => slipped += 1,
            PipelineDecision::DenyRrl(RrlDecision::Drop) => dropped += 1,
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    // Exactly `rate` queries were allowed.
    assert_eq!(allowed, rate, "allowed={allowed} rate={rate}");
    // Slip fires every `slip_ratio`-th excess — exactly half the drops become
    // slips when slip_ratio=2 (excess=995, slips=497 or 498 depending on parity).
    let excess = 1_000 - allowed;
    assert_eq!(dropped + slipped, excess);
    let expected_slips = excess / u32::from(slip);
    // Allow ±1 for boundary.
    assert!(
        slipped.abs_diff(expected_slips) <= 1,
        "slipped={slipped} expected~{expected_slips}"
    );
}

#[test]
fn query_rl_anonymous_vs_cookie_vs_auth_buckets() {
    let p = AdmissionPipeline {
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig {
            anon_rate: 2,
            cookie_rate: 5,
            auth_rate: 10,
            burst_window_secs: 1,
        })),
        ..unlimited_pipeline()
    };
    let now = Instant::now();

    let key_anon = RlKey::SourceIp(src(1, 1, 1, 1));
    let key_cookie = RlKey::SourceIp(src(2, 2, 2, 2));
    let key_auth = RlKey::MtlsIdentity("CN=trusted".to_string());

    let rl = &p.query_rl;

    // Anonymous: 2.
    for _ in 0..2 {
        assert!(rl.check(&key_anon, RlBucket::Anonymous, now));
    }
    assert!(!rl.check(&key_anon, RlBucket::Anonymous, now));

    // Cookie: 5.
    for _ in 0..5 {
        assert!(rl.check(&key_cookie, RlBucket::ValidatedCookie, now));
    }
    assert!(!rl.check(&key_cookie, RlBucket::ValidatedCookie, now));

    // Auth: 10.
    for _ in 0..10 {
        assert!(rl.check(&key_auth, RlBucket::AuthenticatedIdentity, now));
    }
    assert!(!rl.check(&key_auth, RlBucket::AuthenticatedIdentity, now));
}

#[test]
fn cidr_acl_allows_only_permitted_range() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24);

    // Allow recursive only from 192.168.1.0/24.
    let allow_rule = AclRule {
        matchers: vec![
            Matcher::SourceCidr(cidr),
            Matcher::Role(heimdall_runtime::admission::EnumSet::<Role>::from_slice(&[
                Role::Recursive,
            ])),
        ],
        action: AclAction::Allow,
    };
    let p = AdmissionPipeline {
        acl: new_acl_handle(CompiledAcl::new(vec![allow_rule])),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig {
            anon_rate: 1_000_000,
            cookie_rate: 1_000_000,
            auth_rate: 1_000_000,
            burst_window_secs: 10,
        })),
        ..unlimited_pipeline()
    };

    // Permitted source.
    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.source_ip = src(192, 168, 1, 42);
    let d = p.evaluate(&ctx, Instant::now());
    p.resource_counters.release_global();
    assert_eq!(d, PipelineDecision::Allow);

    // Denied source (falls to default-deny recursive).
    ctx.source_ip = src(10, 0, 0, 1);
    assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
}

#[test]
fn rrl_window_reset_allows_again_after_expiry() {
    let p = AdmissionPipeline {
        rrl: Arc::new(RrlEngine::new(RrlConfig {
            rate_per_sec: 1,
            slip_ratio: 100,
            window_secs: 1,
            ..Default::default()
        })),
        ..unlimited_pipeline()
    };
    let t0 = Instant::now();
    let ctx = base_ctx(Role::Authoritative, Operation::Query);

    let d = p.evaluate(&ctx, t0);
    p.resource_counters.release_global();
    assert_eq!(d, PipelineDecision::Allow);

    assert_eq!(
        p.evaluate(&ctx, t0),
        PipelineDecision::DenyRrl(RrlDecision::Drop)
    );

    // 2 s later — window resets.
    let t1 = t0 + Duration::from_secs(2);
    let d2 = p.evaluate(&ctx, t1);
    p.resource_counters.release_global();
    assert_eq!(d2, PipelineDecision::Allow);
}

// ── ACL multi-axis matrix (THREAT-033..047, task #595) ────────────────────────

/// Helper: build a pipeline with a single ACL rule and unlimited throughput.
fn pipeline_with_acl(rules: Vec<AclRule>) -> AdmissionPipeline {
    AdmissionPipeline {
        acl: new_acl_handle(CompiledAcl::new(rules)),
        ..unlimited_pipeline()
    }
}

/// Helper: evaluate `ctx` and release the global counter on Allow.
fn eval(p: &AdmissionPipeline, ctx: &RequestCtx) -> PipelineDecision {
    let d = p.evaluate(ctx, Instant::now());
    if d == PipelineDecision::Allow {
        p.resource_counters.release_global();
    }
    d
}

// ── Axis 1: Source CIDR ───────────────────────────────────────────────────────

/// Source-CIDR allow rule: a Recursive request from 10/8 is admitted; one
/// from outside 10/8 falls through to the recursive default-deny.
#[test]
fn acl_axis_source_cidr_allow_in_range() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::SourceCidr(cidr)],
        action: AclAction::Allow,
    }]);

    // Use Recursive role so that no-rule-match → default-deny recursive.
    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.source_ip = src(10, 1, 2, 3);
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "10.1.2.3 is in 10/8 → Allow");

    ctx.source_ip = src(192, 168, 1, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "192.168.1.1 not in 10/8 → no rule match → recursive default-deny");
}

#[test]
fn acl_axis_source_cidr_deny_out_of_range() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);
    // Deny 10/8, all others fall through to default-deny recursive.
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::SourceCidr(cidr)],
        action: AclAction::Deny,
    }]);

    let mut ctx = base_ctx(Role::Authoritative, Operation::Query);
    ctx.source_ip = src(10, 0, 0, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "10.0.0.1 in 10/8 → Deny");

    ctx.source_ip = src(172, 16, 0, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "172.16.0.1 not denied → default-allow auth");
}

// ── Axis 2: mTLS identity ─────────────────────────────────────────────────────

#[test]
fn acl_axis_mtls_identity_allow_known_cert() {
    let ids = std::collections::HashSet::from(["CN=heimdall-peer".to_string()]);
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::MtlsIdentity(ids)],
        action: AclAction::Allow,
    }]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.mtls_identity = Some("CN=heimdall-peer".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "known mTLS identity → Allow");

    ctx.mtls_identity = Some("CN=untrusted".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "unknown mTLS identity → DenyAcl (recursive default-deny)");

    ctx.mtls_identity = None;
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "no mTLS identity → DenyAcl");
}

// ── Axis 3: TSIG identity ────────────────────────────────────────────────────

#[test]
fn acl_axis_tsig_identity_allow_known_key() {
    let ids = std::collections::HashSet::from(["tsig-key-a.".to_string()]);
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::TsigIdentity(ids)],
        action: AclAction::Allow,
    }]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.tsig_identity = Some("tsig-key-a.".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "known TSIG identity → Allow");

    ctx.tsig_identity = Some("tsig-key-b.".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "unknown TSIG key → DenyAcl");

    ctx.tsig_identity = None;
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "no TSIG key → DenyAcl");
}

// ── Axis 4: Transport ─────────────────────────────────────────────────────────

#[test]
fn acl_axis_transport_allow_only_tcp() {
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::Transport(
            EnumSet::<Transport>::from_slice(&[Transport::Tcp53]),
        )],
        action: AclAction::Allow,
    }]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.transport = Transport::Tcp53;
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "TCP/53 → Allow");

    ctx.transport = Transport::Udp53;
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "UDP/53 → DenyAcl (no rule match → recursive default-deny)");

    ctx.transport = Transport::DoT;
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "DoT → DenyAcl");
}

// ── Axis 5: Role ──────────────────────────────────────────────────────────────

#[test]
fn acl_axis_role_allow_only_authoritative() {
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::Role(
            EnumSet::<Role>::from_slice(&[Role::Authoritative]),
        )],
        action: AclAction::Allow,
    }]);

    let ctx_auth = base_ctx(Role::Authoritative, Operation::Query);
    assert_eq!(eval(&p, &ctx_auth), PipelineDecision::Allow, "Authoritative role → Allow");

    let ctx_rec = base_ctx(Role::Recursive, Operation::Query);
    assert_eq!(eval(&p, &ctx_rec), PipelineDecision::DenyAcl, "Recursive role → DenyAcl");

    let ctx_fwd = base_ctx(Role::Forwarder, Operation::Query);
    assert_eq!(eval(&p, &ctx_fwd), PipelineDecision::DenyAcl, "Forwarder role → DenyAcl");
}

// ── Axis 6: Operation ─────────────────────────────────────────────────────────

#[test]
fn acl_axis_operation_allow_only_query() {
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::Operation(
            EnumSet::<Operation>::from_slice(&[Operation::Query]),
        )],
        action: AclAction::Allow,
    }]);

    let ctx_query = base_ctx(Role::Authoritative, Operation::Query);
    assert_eq!(eval(&p, &ctx_query), PipelineDecision::Allow, "Query → Allow via rule");

    // AXFR hits the rule (operation matcher returns false) → no match → default-deny AXFR.
    let ctx_axfr = base_ctx(Role::Authoritative, Operation::Axfr);
    assert_eq!(eval(&p, &ctx_axfr), PipelineDecision::DenyAcl, "AXFR not in rule → default-deny AXFR");

    let ctx_notify = base_ctx(Role::Authoritative, Operation::Notify);
    assert_eq!(eval(&p, &ctx_notify), PipelineDecision::Allow, "Notify → no rule match → default-allow auth");
}

// ── Axis 7: QNAME pattern ─────────────────────────────────────────────────────

/// Exact QNAME pattern: only the exact name matches.
#[test]
fn acl_axis_qname_exact() {
    // "example.com." in wire encoding.
    let pattern_wire = b"\x07example\x03com\x00".to_vec();
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::QnamePattern(QnamePattern::Exact(pattern_wire))],
        action: AclAction::Deny,
    }]);

    let mut ctx = base_ctx(Role::Authoritative, Operation::Query);
    ctx.qname = b"\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "exact match → Deny");

    ctx.qname = b"\x03sub\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "sub.example.com. not exact match → Allow (auth default)");
}

/// Suffix QNAME pattern: the name itself and all sub-names match.
#[test]
fn acl_axis_qname_suffix() {
    let suffix_wire = b"\x07example\x03com\x00".to_vec();
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::QnamePattern(QnamePattern::Suffix(suffix_wire))],
        action: AclAction::Deny,
    }]);

    let mut ctx = base_ctx(Role::Authoritative, Operation::Query);

    // Exact name matches suffix.
    ctx.qname = b"\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "example.com. matches suffix → Deny");

    // Sub-name matches suffix.
    ctx.qname = b"\x03sub\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "sub.example.com. matches suffix → Deny");

    // Unrelated name does not match.
    ctx.qname = b"\x05other\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "other.com. no suffix match → Allow (auth default)");
}

/// Wildcard QNAME pattern: exactly one additional label prepended to suffix.
#[test]
fn acl_axis_qname_wildcard() {
    let suffix_wire = b"\x07example\x03com\x00".to_vec();
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::QnamePattern(QnamePattern::Wildcard(suffix_wire))],
        action: AclAction::Deny,
    }]);

    let mut ctx = base_ctx(Role::Authoritative, Operation::Query);

    // One label prepended → matches.
    ctx.qname = b"\x01a\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "a.example.com. matches wildcard → Deny");

    // The apex itself does not match (zero labels prepended).
    ctx.qname = b"\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "example.com. apex no wildcard match → Allow (auth default)");

    // Two labels prepended → does not match (wildcard is not a glob).
    ctx.qname = b"\x01a\x01b\x07example\x03com\x00".to_vec();
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "a.b.example.com. two labels no wildcard match → Allow");
}

// ── AND combination: all matchers must match ──────────────────────────────────

#[test]
fn acl_and_combination_all_matchers_must_match() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);

    let ids = std::collections::HashSet::from(["key-a.".to_string()]);

    // Rule fires only when source is 10/8 AND TSIG is "key-a.".
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![
            Matcher::SourceCidr(cidr),
            Matcher::TsigIdentity(ids),
        ],
        action: AclAction::Allow,
    }]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);

    // Both conditions satisfied → Allow.
    ctx.source_ip = src(10, 0, 0, 1);
    ctx.tsig_identity = Some("key-a.".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "both matchers satisfied → Allow");

    // Source matches but TSIG doesn't → no rule match → default-deny recursive.
    ctx.tsig_identity = Some("key-b.".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "TSIG mismatch → DenyAcl");

    // TSIG matches but source doesn't → no rule match → default-deny recursive.
    ctx.source_ip = src(172, 16, 0, 1);
    ctx.tsig_identity = Some("key-a.".to_string());
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "source mismatch → DenyAcl");
}

// ── First-match-wins across rules ─────────────────────────────────────────────

#[test]
fn acl_first_match_wins() {
    // Rule 1: allow 10/8. Rule 2: deny all (no matchers).
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);

    let p = pipeline_with_acl(vec![
        AclRule { matchers: vec![Matcher::SourceCidr(cidr)], action: AclAction::Allow },
        AclRule { matchers: vec![], action: AclAction::Deny },  // catch-all deny
    ]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);

    // Source in 10/8 → rule 1 matches first → Allow (even though rule 2 would deny).
    ctx.source_ip = src(10, 0, 0, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "rule 1 (allow 10/8) fires first → Allow");

    // Source not in 10/8 → rule 1 skipped → rule 2 fires (catch-all deny).
    ctx.source_ip = src(192, 168, 1, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "rule 2 (catch-all deny) fires → DenyAcl");
}

// ── Defaults ──────────────────────────────────────────────────────────────────

#[test]
fn acl_default_deny_axfr_no_matching_rule() {
    // Empty ACL — no rules at all.
    let p = pipeline_with_acl(vec![]);

    let ctx = base_ctx(Role::Authoritative, Operation::Axfr);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "AXFR with no rule → default-deny AXFR");
}

#[test]
fn acl_default_deny_ixfr_no_matching_rule() {
    let p = pipeline_with_acl(vec![]);

    let ctx = base_ctx(Role::Authoritative, Operation::Ixfr);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "IXFR with no rule → default-deny IXFR");
}

#[test]
fn acl_default_deny_recursive_no_matching_rule() {
    let p = pipeline_with_acl(vec![]);

    let ctx = base_ctx(Role::Recursive, Operation::Query);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "Recursive query with no rule → default-deny recursive");
}

#[test]
fn acl_default_deny_forwarder_no_matching_rule() {
    let p = pipeline_with_acl(vec![]);

    let ctx = base_ctx(Role::Forwarder, Operation::Query);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "Forwarder query with no rule → default-deny forwarder");
}

#[test]
fn acl_default_allow_authoritative_query_no_matching_rule() {
    let p = pipeline_with_acl(vec![]);

    let ctx = base_ctx(Role::Authoritative, Operation::Query);
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "Authoritative query with no rule → default-allow auth");
}

// ── Negation (THREAT-111) ─────────────────────────────────────────────────────

/// `Matcher::Not(SourceCidr)` matches every source NOT in the CIDR.
#[test]
fn acl_negation_not_source_cidr() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);

    // Deny any source that is NOT in 10/8 (i.e., deny outside-10/8 on an authoritative role).
    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![Matcher::Not(Box::new(Matcher::SourceCidr(cidr)))],
        action: AclAction::Deny,
    }]);

    let mut ctx = base_ctx(Role::Authoritative, Operation::Query);

    // Source in 10/8: Not(10/8) = false → rule does NOT match → default-allow auth.
    ctx.source_ip = src(10, 0, 0, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "10.0.0.1 in 10/8: Not matches false → auth default-allow");

    // Source outside 10/8: Not(10/8) = true → rule matches → Deny.
    ctx.source_ip = src(192, 168, 1, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "192.168.1.1 not in 10/8: Not matches true → Deny");
}

/// `Matcher::Not` applies individually to the matcher, not the whole rule.
/// A rule `[Not(Transport=UDP), SourceCidr=10/8]` with Allow still requires
/// both: source must be in 10/8 AND transport must NOT be UDP.
#[test]
fn acl_negation_individual_matcher_not_whole_rule() {
    let mut cidr = CidrSet::default();
    cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);

    let p = pipeline_with_acl(vec![AclRule {
        matchers: vec![
            Matcher::Not(Box::new(Matcher::Transport(
                EnumSet::<Transport>::from_slice(&[Transport::Udp53]),
            ))),
            Matcher::SourceCidr(cidr),
        ],
        action: AclAction::Allow,
    }]);

    let mut ctx = base_ctx(Role::Recursive, Operation::Query);
    ctx.source_ip = src(10, 0, 0, 1);

    // TCP from 10/8: Not(UDP)=true, SourceCidr(10/8)=true → Allow.
    ctx.transport = Transport::Tcp53;
    assert_eq!(eval(&p, &ctx), PipelineDecision::Allow, "TCP from 10/8: both matchers satisfied → Allow");

    // UDP from 10/8: Not(UDP)=false → rule does not match → default-deny recursive.
    ctx.transport = Transport::Udp53;
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "UDP from 10/8: Not(UDP) fails → DenyAcl");

    // TCP from outside 10/8: Not(UDP)=true but SourceCidr=false → no rule match → default-deny recursive.
    ctx.transport = Transport::Tcp53;
    ctx.source_ip = src(172, 16, 0, 1);
    assert_eq!(eval(&p, &ctx), PipelineDecision::DenyAcl, "TCP from non-10/8: CIDR fails → DenyAcl");
}
