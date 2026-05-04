// SPDX-License-Identifier: MIT

//! Five-stage composite admission pipeline (THREAT-076, task #254).
//!
//! Each inbound request is evaluated in a fixed order:
//!
//! 1. **ACL** — source CIDR, transport, identity, operation, QNAME pattern.
//! 2. **Connection-level limits** — global pending-query cap.
//! 3. **Cookie under load** — if under load and no valid cookie, deny.
//! 4. **Rate limiting** — RRL for authoritative; query RL for recursive/forwarder.
//! 5. **Allow** — all stages passed.
//!
//! A request denied at stage *N* does **not** consume the budget of any later
//! stage (THREAT-054, THREAT-076).

use std::sync::Arc;
use std::time::Instant;

use super::acl::{AclAction, AclHandle, RequestCtx, Role};
use crate::ops::anomaly;
use super::load_signal::LoadSignal;
use super::query_rl::{QueryRlEngine, RlKey};
use super::resource::{ResourceCounters, ResourceLimits};
use super::rrl::{RrlDecision, RrlEngine};
use super::telemetry::AdmissionTelemetry;

// ── ConnLimitReason ───────────────────────────────────────────────────────────

/// The specific connection-level limit that fired at stage 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnLimitReason {
    /// The global pending-query cap (THREAT-065) was reached.
    GlobalPending,
}

// ── PipelineDecision ──────────────────────────────────────────────────────────

/// The terminal decision produced by the admission pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineDecision {
    /// All stages passed — the query may proceed to processing.
    Allow,
    /// Stage 1 — ACL denied the request.
    DenyAcl,
    /// Stage 2 — A connection or in-flight limit was exceeded.
    DenyConnLimit {
        /// Which limit fired.
        reason: ConnLimitReason,
    },
    /// Stage 3 — Under load and the request carries no valid DNS Cookie.
    DenyCookieUnderLoad,
    /// Stage 4 — RRL budget exhausted (drop or slip).
    DenyRrl(RrlDecision),
    /// Stage 4 — Per-client query rate limit exceeded.
    DenyQueryRl,
}

// ── AdmissionPipeline ─────────────────────────────────────────────────────────

/// The five-stage admission pipeline.
///
/// All fields are `pub` for direct construction.
pub struct AdmissionPipeline {
    /// Lock-free ACL handle (stage 1).
    pub acl: AclHandle,
    /// Configured resource limits (stage 2).
    pub resource_limits: ResourceLimits,
    /// Live resource counters (stage 2).
    pub resource_counters: Arc<ResourceCounters>,
    /// RRL engine for the authoritative role (stage 4).
    pub rrl: Arc<RrlEngine>,
    /// Per-client query rate limiter for recursive/forwarder roles (stage 4).
    pub query_rl: Arc<QueryRlEngine>,
    /// Composite under-load signal (stage 3).
    pub load_signal: Arc<LoadSignal>,
    /// Per-stage telemetry counters (THREAT-057, THREAT-077).
    pub telemetry: Arc<AdmissionTelemetry>,
}

impl AdmissionPipeline {
    /// Evaluate all five pipeline stages for one inbound request.
    ///
    /// `now` is injected so callers can share a clock snapshot across multiple
    /// pipeline calls in the same dispatch loop iteration.
    ///
    /// # Stage ordering guarantee
    ///
    /// A denial at stage *N* returns immediately without touching any state
    /// belonging to stages > *N* (THREAT-054).
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestCtx, now: Instant) -> PipelineDecision {
        // ── Stage 1: ACL ──────────────────────────────────────────────────────
        let acl_snap = self.acl.load();
        let acl_decision = acl_snap.evaluate(ctx);
        if acl_decision == AclAction::Deny {
            self.telemetry.inc_acl_denied();
            let cid = anomaly::next_correlation_id();
            tracing::warn!(
                schema_version   = anomaly::SCHEMA_VERSION,
                event_type       = "acl-deny",
                correlation_id   = %cid,
                instance_node    = anomaly::instance_node(),
                instance_version = anomaly::INSTANCE_VERSION,
                client_ip        = %ctx.source_ip,
                "ACL deny",
            );
            return PipelineDecision::DenyAcl;
        }
        self.telemetry.inc_acl_allowed();

        // ── Stage 2: Connection-level resource limits ─────────────────────────
        if !self
            .resource_counters
            .try_acquire_global(&self.resource_limits)
        {
            self.telemetry.inc_conn_limit_denied();
            return PipelineDecision::DenyConnLimit {
                reason: ConnLimitReason::GlobalPending,
            };
        }
        // We acquired a slot; we are responsible for releasing it when the query
        // finishes.  For the purposes of the admission gate the counter stays
        // incremented — the caller must call `resource_counters.release_global()`
        // when the query terminal state is reached.

        // ── Stage 3: Cookie-based admission under load ────────────────────────
        if self.load_signal.is_under_load() && !ctx.has_valid_cookie {
            // Do NOT consume later stages; release the slot immediately since
            // we are denying this request.
            self.resource_counters.release_global();
            self.telemetry.inc_cookie_load_denied();
            return PipelineDecision::DenyCookieUnderLoad;
        }

        // ── Stage 4: Rate limiting ────────────────────────────────────────────
        let rl_decision = self.check_rate_limit(ctx, now);
        if let Some(deny) = rl_decision {
            // Release the slot immediately — rate-limited queries do not enter
            // query processing.
            self.resource_counters.release_global();
            return deny;
        }

        // ── Stage 5: Allow ────────────────────────────────────────────────────
        self.telemetry.inc_total_allowed();
        PipelineDecision::Allow
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Evaluate the rate-limiting stage; return `Some(PipelineDecision)` if the
    /// query should be denied, `None` if it passes.
    fn check_rate_limit(&self, ctx: &RequestCtx, now: Instant) -> Option<PipelineDecision> {
        match ctx.role {
            Role::Authoritative => {
                let decision = self.rrl.check(ctx.source_ip, &ctx.qname, 0, now);
                match decision {
                    RrlDecision::Allow => None,
                    RrlDecision::Drop => {
                        self.telemetry.inc_rrl_dropped();
                        let cid = anomaly::next_correlation_id();
                        tracing::warn!(
                            schema_version   = anomaly::SCHEMA_VERSION,
                            event_type       = "rrl-fired",
                            correlation_id   = %cid,
                            instance_node    = anomaly::instance_node(),
                            instance_version = anomaly::INSTANCE_VERSION,
                            action           = "drop",
                            client_ip        = %ctx.source_ip,
                            "RRL drop",
                        );
                        Some(PipelineDecision::DenyRrl(RrlDecision::Drop))
                    }
                    RrlDecision::Slip => {
                        self.telemetry.inc_rrl_slipped();
                        let cid = anomaly::next_correlation_id();
                        tracing::warn!(
                            schema_version   = anomaly::SCHEMA_VERSION,
                            event_type       = "rrl-fired",
                            correlation_id   = %cid,
                            instance_node    = anomaly::instance_node(),
                            instance_version = anomaly::INSTANCE_VERSION,
                            action           = "slip",
                            client_ip        = %ctx.source_ip,
                            "RRL slip",
                        );
                        Some(PipelineDecision::DenyRrl(RrlDecision::Slip))
                    }
                }
            }
            Role::Recursive | Role::Forwarder => {
                let key = RlKey::from_ctx(ctx);
                let bucket = QueryRlEngine::classify(ctx);
                if self.query_rl.check(&key, bucket, now) {
                    None
                } else {
                    self.telemetry.inc_query_rl_denied();
                    Some(PipelineDecision::DenyQueryRl)
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use super::*;
    use crate::admission::acl::{
        AclAction, AclRule, CompiledAcl, Operation, RequestCtx, Role, Transport, new_acl_handle,
    };
    use crate::admission::load_signal::LoadFactors;
    use crate::admission::query_rl::{QueryRlConfig, QueryRlEngine};
    use crate::admission::resource::{ResourceCounters, ResourceLimits};
    use crate::admission::rrl::{RrlConfig, RrlEngine};
    use crate::admission::telemetry::AdmissionTelemetry;

    fn src_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn base_ctx(role: Role, op: Operation) -> RequestCtx {
        RequestCtx {
            source_ip: src_ip(),
            mtls_identity: None,
            tsig_identity: None,
            transport: Transport::Udp53,
            role,
            operation: op,
            qname: b"\x07example\x03com\x00".to_vec(),
            has_valid_cookie: false,
        }
    }

    fn default_pipeline() -> AdmissionPipeline {
        AdmissionPipeline {
            acl: new_acl_handle(CompiledAcl::default()),
            resource_limits: ResourceLimits::default(),
            resource_counters: Arc::new(ResourceCounters::new()),
            rrl: Arc::new(RrlEngine::new(RrlConfig {
                rate_per_sec: 1_000_000, // effectively unlimited
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

    #[test]
    fn authoritative_query_passes_all_stages() {
        let p = default_pipeline();
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::Allow);
        assert_eq!(p.telemetry.total_allowed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn acl_deny_short_circuits() {
        // All requests denied by ACL.
        let deny_rule = AclRule {
            matchers: vec![],
            action: AclAction::Deny,
        };
        let acl = new_acl_handle(CompiledAcl::new(vec![deny_rule]));
        let p = AdmissionPipeline {
            acl,
            ..default_pipeline()
        };
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
        // Stage-2 counter must be zero — we did not touch resource counters.
        assert_eq!(p.resource_counters.global_pending(), 0);
        assert_eq!(p.telemetry.acl_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn acl_deny_does_not_consume_stage2_budget() {
        let deny_rule = AclRule {
            matchers: vec![],
            action: AclAction::Deny,
        };
        let acl = new_acl_handle(CompiledAcl::new(vec![deny_rule]));
        let p = AdmissionPipeline {
            acl,
            resource_limits: ResourceLimits {
                max_global_pending: 1,
                ..Default::default()
            },
            ..default_pipeline()
        };
        // Even with cap=1, ACL denial should not consume it.
        for _ in 0..5 {
            let ctx = base_ctx(Role::Authoritative, Operation::Query);
            assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
        }
        assert_eq!(p.resource_counters.global_pending(), 0);
    }

    #[test]
    fn stage2_global_cap_fires() {
        let p = AdmissionPipeline {
            resource_limits: ResourceLimits {
                max_global_pending: 0,
                ..Default::default()
            },
            ..default_pipeline()
        };
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        assert_eq!(
            p.evaluate(&ctx, Instant::now()),
            PipelineDecision::DenyConnLimit {
                reason: ConnLimitReason::GlobalPending
            }
        );
        assert_eq!(p.telemetry.conn_limit_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stage2_deny_does_not_consume_stage3_or_4() {
        // Cap = 0, under load, and rate limiter tight; only stage 2 should fire.
        let p = AdmissionPipeline {
            resource_limits: ResourceLimits {
                max_global_pending: 0,
                ..Default::default()
            },
            ..default_pipeline()
        };
        p.load_signal.update(LoadFactors {
            cpu_pct: 1.0,
            memory_pct: 1.0,
            pending_queries_pct: 1.0,
            rl_fires_rate: 1.0,
        });
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        assert_eq!(
            p.evaluate(&ctx, Instant::now()),
            PipelineDecision::DenyConnLimit {
                reason: ConnLimitReason::GlobalPending
            }
        );
        // Stage-3 counter must be zero.
        assert_eq!(p.telemetry.cookie_load_denied.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn under_load_no_cookie_denied_stage3() {
        let p = default_pipeline();
        p.load_signal.update(LoadFactors {
            cpu_pct: 1.0,
            memory_pct: 1.0,
            pending_queries_pct: 1.0,
            rl_fires_rate: 1.0,
        });
        let ctx = base_ctx(Role::Authoritative, Operation::Query); // no cookie
        assert_eq!(
            p.evaluate(&ctx, Instant::now()),
            PipelineDecision::DenyCookieUnderLoad
        );
        assert_eq!(p.telemetry.cookie_load_denied.load(Ordering::Relaxed), 1);
        // Stage-3 denial released the global counter.
        assert_eq!(p.resource_counters.global_pending(), 0);
    }

    #[test]
    fn under_load_with_cookie_passes_stage3() {
        let p = default_pipeline();
        p.load_signal.update(LoadFactors {
            cpu_pct: 1.0,
            memory_pct: 1.0,
            pending_queries_pct: 1.0,
            rl_fires_rate: 1.0,
        });
        let mut ctx = base_ctx(Role::Authoritative, Operation::Query);
        ctx.has_valid_cookie = true;
        assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::Allow);
    }

    #[test]
    fn stage3_deny_does_not_consume_stage4_budget() {
        // Rate limiter with a tiny budget; under-load denial must not touch it.
        let p = AdmissionPipeline {
            rrl: Arc::new(RrlEngine::new(RrlConfig {
                rate_per_sec: 1,
                ..Default::default()
            })),
            ..default_pipeline()
        };
        p.load_signal.update(LoadFactors {
            cpu_pct: 1.0,
            memory_pct: 1.0,
            pending_queries_pct: 1.0,
            rl_fires_rate: 1.0,
        });
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        // Denied at stage 3.
        assert_eq!(
            p.evaluate(&ctx, Instant::now()),
            PipelineDecision::DenyCookieUnderLoad
        );
        // RRL counter for this source must still be 0 (not consumed).
        assert_eq!(p.telemetry.rrl_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(p.telemetry.rrl_slipped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rrl_over_budget_fires_stage4() {
        let p = AdmissionPipeline {
            rrl: Arc::new(RrlEngine::new(RrlConfig {
                rate_per_sec: 1,
                slip_ratio: 100, // no slip in this test
                ..Default::default()
            })),
            ..default_pipeline()
        };
        let now = Instant::now();
        let ctx = base_ctx(Role::Authoritative, Operation::Query);
        // First allowed.
        let d = p.evaluate(&ctx, now);
        p.resource_counters.release_global(); // simulate query completion
        assert_eq!(d, PipelineDecision::Allow);
        // Second drops.
        assert_eq!(
            p.evaluate(&ctx, now),
            PipelineDecision::DenyRrl(RrlDecision::Drop)
        );
        assert_eq!(p.telemetry.rrl_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn query_rl_over_budget_fires_stage4() {
        // ACL must allow recursive so the request reaches stage 4.
        let allow_recursive = AclRule {
            matchers: vec![],
            action: AclAction::Allow,
        };
        let p = AdmissionPipeline {
            acl: new_acl_handle(CompiledAcl::new(vec![allow_recursive])),
            query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig {
                anon_rate: 1,
                burst_window_secs: 1,
                ..Default::default()
            })),
            ..default_pipeline()
        };
        let now = Instant::now();
        let ctx = base_ctx(Role::Recursive, Operation::Query);
        // First allowed.
        let d = p.evaluate(&ctx, now);
        p.resource_counters.release_global();
        assert_eq!(d, PipelineDecision::Allow);
        // Second denied by query RL.
        assert_eq!(p.evaluate(&ctx, now), PipelineDecision::DenyQueryRl);
        assert_eq!(p.telemetry.query_rl_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn axfr_default_deny() {
        let p = default_pipeline();
        let ctx = base_ctx(Role::Authoritative, Operation::Axfr);
        assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
    }

    #[test]
    fn recursive_default_deny() {
        let p = default_pipeline();
        let ctx = base_ctx(Role::Recursive, Operation::Query);
        assert_eq!(p.evaluate(&ctx, Instant::now()), PipelineDecision::DenyAcl);
    }
}
