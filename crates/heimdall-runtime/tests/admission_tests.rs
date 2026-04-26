// SPDX-License-Identifier: MIT

//! Integration tests for the Sprint 20 admission pipeline (THREAT-033..078).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use heimdall_runtime::admission::{
    AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CidrSet, CompiledAcl,
    LoadFactors, LoadSignal, Matcher, Operation, PipelineDecision, QueryRlConfig,
    QueryRlEngine, RequestCtx, ResourceCounters, ResourceLimits, RlBucket, RlKey, Role,
    RrlConfig, RrlDecision, RrlEngine, Transport, new_acl_handle,
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
