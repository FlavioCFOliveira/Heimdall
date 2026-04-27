// SPDX-License-Identifier: MIT

//! Per-client query rate limiter for the forwarder role (THREAT-051, Task #334 part 2).
//!
//! [`ForwarderRateLimiter`] enforces per-client query rate limiting keyed on
//! source IP, mTLS identity, TSIG identity, or DNS Cookie bucket.
//!
//! # Algorithm
//!
//! Token-bucket per client key: each bucket holds up to `rate_limit` tokens.
//! One token is consumed per query.  Tokens refill at `rate_limit` tokens per
//! second.  If the bucket is empty, the query is rejected.
//!
//! Stale buckets (no activity for > 60 s) are evicted by [`evict_stale`] to
//! bound memory growth.
//!
//! [`evict_stale`]: ForwarderRateLimiter::evict_stale

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use tracing::info;

// ── RlKey ─────────────────────────────────────────────────────────────────────

/// Rate-limiting key identifying a client (THREAT-051).
///
/// Each variant represents one identity dimension.  The server selects the
/// highest-fidelity key available for an incoming query (mTLS > TSIG > Cookie
/// > source IP).
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum RlKey {
    /// Source IP address (fallback key when no stronger identity is present).
    SourceIp(IpAddr),
    /// mTLS client certificate identity (SHA-256 fingerprint or SAN).
    MtlsIdentity(String),
    /// TSIG key identity.
    TsigIdentity(String),
    /// DNS Cookie client cookie (8-byte value, RFC 7873).
    Cookie([u8; 8]),
}

// ── TokenBucket ───────────────────────────────────────────────────────────────

/// A single token-bucket state for one client.
struct TokenBucket {
    /// Current token count (fractional to support sub-second refill).
    tokens: f64,
    /// Wall-clock time of the last refill.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Refills tokens based on elapsed time and attempts to consume one.
    ///
    /// Returns `true` if a token was consumed (query allowed).
    fn try_consume(&mut self, rate_limit: u32, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let capacity = f64::from(rate_limit);

        // Refill: add elapsed_seconds * rate tokens, capped at capacity.
        self.tokens = (self.tokens + elapsed * capacity).min(capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns `true` if the bucket has been idle for more than `idle_secs`.
    fn is_stale(&self, idle_secs: u64, now: Instant) -> bool {
        now.duration_since(self.last_refill).as_secs() > idle_secs
    }
}

// ── ForwarderRateLimiter ──────────────────────────────────────────────────────

/// Stale bucket eviction threshold: buckets idle for > 60 s are evicted.
const STALE_IDLE_SECS: u64 = 60;

/// Per-client token-bucket rate limiter for the forwarder role.
///
/// The `buckets` map is protected by a [`Mutex`] to allow concurrent access
/// from multiple async tasks.  Lock contention is minimised by the short
/// critical section (a single `HashMap` lookup + token arithmetic).
pub struct ForwarderRateLimiter {
    buckets: Mutex<HashMap<RlKey, TokenBucket>>,
    /// Queries per second limit per client.
    rate_limit: u32,
}

impl ForwarderRateLimiter {
    /// Creates a new [`ForwarderRateLimiter`] with `rate_limit` queries/s per client.
    #[must_use]
    pub fn new(rate_limit: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate_limit,
        }
    }

    /// Returns `true` if the query is within the rate limit and consumes a token.
    ///
    /// Returns `false` and emits a structured tracing event if the client is
    /// rate-limited.
    pub fn check_and_consume(&self, key: &RlKey) -> bool {
        let now = Instant::now();
        let rate_limit = self.rate_limit;

        let allowed = {
            let mut guard = self
                .buckets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let bucket = guard
                .entry(key.clone())
                .or_insert_with(|| TokenBucket::new(f64::from(rate_limit)));
            bucket.try_consume(rate_limit, now)
        };

        if !allowed {
            info!(key = ?key, "forwarder rate-limit fired");
        }
        allowed
    }

    /// Evicts token buckets that have been idle for more than 60 s.
    ///
    /// Call periodically (e.g. every minute) to bound memory growth.
    pub fn evict_stale(&self) {
        let now = Instant::now();
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, bucket| !bucket.is_stale(STALE_IDLE_SECS, now));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip_key() -> RlKey {
        RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    }

    #[test]
    fn allows_queries_under_limit() {
        // 10 rps limit; 5 immediate queries must all be allowed.
        let rl = ForwarderRateLimiter::new(10);
        let key = ip_key();
        for i in 0..5 {
            assert!(rl.check_and_consume(&key), "query {i} must be allowed");
        }
    }

    #[test]
    fn blocks_queries_over_limit() {
        // 5 rps limit; 10 immediate queries → some must be blocked.
        let rl = ForwarderRateLimiter::new(5);
        let key = ip_key();
        let allowed: usize = (0..10).filter(|_| rl.check_and_consume(&key)).count();
        assert!(allowed < 10, "some queries must be blocked at 5 rps");
        // Exactly 5 tokens at construction, all consumed.
        assert_eq!(allowed, 5, "exactly 5 of 10 immediate queries must pass");
    }

    #[test]
    fn different_keys_are_independent() {
        let rl = ForwarderRateLimiter::new(1);
        let key1 = RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let key2 = RlKey::SourceIp(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert!(rl.check_and_consume(&key1), "key1 first query must pass");
        assert!(rl.check_and_consume(&key2), "key2 first query must pass");
        assert!(
            !rl.check_and_consume(&key1),
            "key1 second query must be blocked"
        );
        assert!(
            !rl.check_and_consume(&key2),
            "key2 second query must be blocked"
        );
    }

    #[test]
    fn evict_stale_removes_old_buckets() {
        let rl = ForwarderRateLimiter::new(10);
        let key = ip_key();
        // Consume to create a bucket entry.
        rl.check_and_consume(&key);

        // Manually age the bucket beyond the idle threshold.
        {
            let mut guard = rl.buckets.lock().expect("INVARIANT: mutex not poisoned");
            if let Some(bucket) = guard.get_mut(&key) {
                // Backdate last_refill by more than STALE_IDLE_SECS.
                bucket.last_refill =
                    Instant::now() - std::time::Duration::from_secs(STALE_IDLE_SECS + 1);
            }
        }

        rl.evict_stale();

        {
            let guard = rl.buckets.lock().expect("INVARIANT: mutex not poisoned");
            assert!(!guard.contains_key(&key), "stale bucket must be evicted");
        }
    }

    #[test]
    fn cookie_key_variant_works() {
        let rl = ForwarderRateLimiter::new(3);
        let key = RlKey::Cookie([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        for i in 0..3 {
            assert!(rl.check_and_consume(&key), "cookie query {i} must pass");
        }
        assert!(
            !rl.check_and_consume(&key),
            "4th cookie query must be blocked"
        );
    }
}
