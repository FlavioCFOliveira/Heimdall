// SPDX-License-Identifier: MIT

//! Per-client query rate limiting (THREAT-051 through THREAT-053).
//!
//! Three bucket tiers apply different rate limits:
//!
//! - [`RlBucket::Anonymous`]  — no identity, no valid cookie (strictest).
//! - [`RlBucket::ValidatedCookie`] — DNS Cookie validated.
//! - [`RlBucket::AuthenticatedIdentity`] — mTLS or TSIG identity present
//!   (most permissive).
//!
//! The most-specific identity available drives bucket selection:
//! mTLS / TSIG > cookie > source IP (THREAT-052, THREAT-053).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::acl::RequestCtx;

// ── RlBucket ──────────────────────────────────────────────────────────────────

/// Rate-limit tier for a client (THREAT-052, THREAT-053).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlBucket {
    /// No cookie and no authenticated identity — strictest limits.
    Anonymous,
    /// Presents a validated DNS Cookie — intermediate limits.
    ValidatedCookie,
    /// Authenticated via mTLS certificate or TSIG key — most permissive.
    AuthenticatedIdentity,
}

// ── RlKey ─────────────────────────────────────────────────────────────────────

/// The lookup key that identifies a client for rate-limiting purposes.
///
/// The most-specific available identity is used (mTLS > TSIG > cookie/IP).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RlKey {
    /// Keyed on source IP address when no stronger identity is available.
    SourceIp(IpAddr),
    /// Keyed on TSIG key identity.
    TsigIdentity(String),
    /// Keyed on mTLS client-certificate identity (most specific).
    MtlsIdentity(String),
}

impl RlKey {
    /// Derive the most-specific key from a request context.
    #[must_use]
    pub fn from_ctx(ctx: &RequestCtx) -> Self {
        if let Some(id) = &ctx.mtls_identity {
            return RlKey::MtlsIdentity(id.clone());
        }
        if let Some(id) = &ctx.tsig_identity {
            return RlKey::TsigIdentity(id.clone());
        }
        RlKey::SourceIp(ctx.source_ip)
    }
}

// ── QueryRlConfig ─────────────────────────────────────────────────────────────

/// Configuration for the query rate limiter.
#[derive(Debug, Clone)]
pub struct QueryRlConfig {
    /// Maximum queries per second for anonymous clients (default: 50).
    pub anon_rate: u32,
    /// Maximum queries per second for cookie-validated clients (default: 200).
    pub cookie_rate: u32,
    /// Maximum queries per second for mTLS / TSIG authenticated clients
    /// (default: 500).
    pub auth_rate: u32,
    /// Burst window in seconds — queries are counted per window (default: 10).
    ///
    /// The effective per-window budget is `rate * burst_window_secs`.
    pub burst_window_secs: u32,
}

impl Default for QueryRlConfig {
    fn default() -> Self {
        Self {
            anon_rate: 50,
            cookie_rate: 200,
            auth_rate: 500,
            burst_window_secs: 10,
        }
    }
}

// ── internal bucket state ─────────────────────────────────────────────────────

struct BucketState {
    count: u32,
    window_start: Instant,
}

// ── QueryRlEngine ─────────────────────────────────────────────────────────────

/// Per-client query rate-limiting engine.
///
/// Thread-safe; wrap in `Arc` for sharing across tasks.
pub struct QueryRlEngine {
    config: QueryRlConfig,
    buckets: Arc<Mutex<HashMap<RlKey, BucketState>>>,
}

impl QueryRlEngine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub fn new(config: QueryRlConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Classify a request context into the appropriate rate-limit tier.
    ///
    /// mTLS / TSIG identity → [`RlBucket::AuthenticatedIdentity`].
    /// Valid DNS Cookie     → [`RlBucket::ValidatedCookie`].
    /// Everything else      → [`RlBucket::Anonymous`].
    #[must_use]
    pub fn classify(ctx: &RequestCtx) -> RlBucket {
        if ctx.mtls_identity.is_some() || ctx.tsig_identity.is_some() {
            return RlBucket::AuthenticatedIdentity;
        }
        if ctx.has_valid_cookie {
            return RlBucket::ValidatedCookie;
        }
        RlBucket::Anonymous
    }

    /// Check whether a query is within the rate limit.
    ///
    /// Returns `true` when the query is allowed, `false` when the budget is
    /// exhausted.
    ///
    /// `now` is injected for deterministic testing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned, which can only happen if a
    /// thread panics while holding the lock — an impossible condition since no
    /// panic path exists inside the critical section.
    #[must_use]
    pub fn check(&self, key: &RlKey, bucket: RlBucket, now: Instant) -> bool {
        let rate = match bucket {
            RlBucket::Anonymous => self.config.anon_rate,
            RlBucket::ValidatedCookie => self.config.cookie_rate,
            RlBucket::AuthenticatedIdentity => self.config.auth_rate,
        };
        let budget = rate.saturating_mul(self.config.burst_window_secs);
        let window = Duration::from_secs(u64::from(self.config.burst_window_secs));

        #[allow(clippy::expect_used)]
        // INVARIANT: the critical section contains no panic path; poisoning is impossible.
        let mut map = self
            .buckets
            .lock()
            .expect("INVARIANT: QueryRlEngine mutex is never poisoned");

        let state = map.entry(key.clone()).or_insert_with(|| BucketState {
            count: 0,
            window_start: now,
        });

        // Roll the window if expired.
        if now.duration_since(state.window_start) >= window {
            state.count = 0;
            state.window_start = now;
        }

        if state.count < budget {
            state.count += 1;
            true
        } else {
            false
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    use super::*;
    use crate::admission::acl::{Operation, RequestCtx, Role, Transport};

    fn base_ctx() -> RequestCtx {
        RequestCtx {
            source_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            mtls_identity: None,
            tsig_identity: None,
            transport: Transport::Udp53,
            role: Role::Recursive,
            operation: Operation::Query,
            qname: b"\x07example\x03com\x00".to_vec(),
            has_valid_cookie: false,
        }
    }

    fn engine_tight() -> QueryRlEngine {
        QueryRlEngine::new(QueryRlConfig {
            anon_rate: 2,
            cookie_rate: 5,
            auth_rate: 10,
            burst_window_secs: 1,
        })
    }

    #[test]
    fn anonymous_bucket_tight_limit() {
        let e = engine_tight();
        let ctx = base_ctx();
        let key = RlKey::from_ctx(&ctx);
        let now = Instant::now();
        // Budget = 2 * 1 = 2.
        assert!(e.check(&key, RlBucket::Anonymous, now));
        assert!(e.check(&key, RlBucket::Anonymous, now));
        assert!(!e.check(&key, RlBucket::Anonymous, now));
    }

    #[test]
    fn cookie_bucket_higher_rate() {
        let e = engine_tight();
        let mut ctx = base_ctx();
        ctx.has_valid_cookie = true;
        let key = RlKey::from_ctx(&ctx);
        let now = Instant::now();
        // Budget = 5 * 1 = 5.
        for _ in 0..5 {
            assert!(e.check(&key, RlBucket::ValidatedCookie, now));
        }
        assert!(!e.check(&key, RlBucket::ValidatedCookie, now));
    }

    #[test]
    fn auth_bucket_highest_rate() {
        let e = engine_tight();
        let mut ctx = base_ctx();
        ctx.tsig_identity = Some("key1".to_string());
        let key = RlKey::from_ctx(&ctx);
        let now = Instant::now();
        // Budget = 10 * 1 = 10.
        for _ in 0..10 {
            assert!(e.check(&key, RlBucket::AuthenticatedIdentity, now));
        }
        assert!(!e.check(&key, RlBucket::AuthenticatedIdentity, now));
    }

    #[test]
    fn classify_anonymous() {
        let ctx = base_ctx();
        assert_eq!(QueryRlEngine::classify(&ctx), RlBucket::Anonymous);
    }

    #[test]
    fn classify_cookie() {
        let mut ctx = base_ctx();
        ctx.has_valid_cookie = true;
        assert_eq!(QueryRlEngine::classify(&ctx), RlBucket::ValidatedCookie);
    }

    #[test]
    fn classify_tsig_beats_cookie() {
        let mut ctx = base_ctx();
        ctx.has_valid_cookie = true;
        ctx.tsig_identity = Some("key1".to_string());
        assert_eq!(
            QueryRlEngine::classify(&ctx),
            RlBucket::AuthenticatedIdentity
        );
    }

    #[test]
    fn classify_mtls_beats_all() {
        let mut ctx = base_ctx();
        ctx.has_valid_cookie = true;
        ctx.tsig_identity = Some("key1".to_string());
        ctx.mtls_identity = Some("CN=client".to_string());
        assert_eq!(
            QueryRlEngine::classify(&ctx),
            RlBucket::AuthenticatedIdentity
        );
    }

    #[test]
    fn window_reset_restores_budget() {
        let e = engine_tight();
        let ctx = base_ctx();
        let key = RlKey::from_ctx(&ctx);
        let t0 = Instant::now();
        // Exhaust anonymous budget (2).
        assert!(e.check(&key, RlBucket::Anonymous, t0));
        assert!(e.check(&key, RlBucket::Anonymous, t0));
        assert!(!e.check(&key, RlBucket::Anonymous, t0));
        // Advance past window.
        let t1 = t0 + Duration::from_secs(2);
        assert!(e.check(&key, RlBucket::Anonymous, t1));
    }

    #[test]
    fn rl_key_mtls_identity() {
        let mut ctx = base_ctx();
        ctx.mtls_identity = Some("CN=trusted".to_string());
        assert_eq!(
            RlKey::from_ctx(&ctx),
            RlKey::MtlsIdentity("CN=trusted".to_string())
        );
    }

    #[test]
    fn rl_key_source_ip_fallback() {
        let ctx = base_ctx();
        assert_eq!(
            RlKey::from_ctx(&ctx),
            RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }
}
