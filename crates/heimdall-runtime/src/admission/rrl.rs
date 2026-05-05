// SPDX-License-Identifier: MIT

//! Response Rate Limiting (RRL) per RFC 8906 (THREAT-048 through THREAT-050).
//!
//! RRL is keyed on `(source_prefix, qname_hash, qtype)` where the source prefix
//! is the client IP truncated to a configured prefix length.  Within each window,
//! a counter tracks how many responses have been sent.  Once the budget is
//! exhausted the engine drops excess queries, **except** at every `slip_ratio`-th
//! drop where it returns a truncated TC response to allow legitimate clients to
//! recover via TCP fallback (THREAT-049).
//!
//! ## Locking note
//!
//! A single `std::sync::Mutex<HashMap>` is used for correctness.  A comment at
//! the call-site documents the path to sharded or lock-free counters if
//! benchmarking identifies contention.

use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

// ── RrlConfig ─────────────────────────────────────────────────────────────────

/// Configuration parameters for the RRL engine.
#[derive(Debug, Clone)]
pub struct RrlConfig {
    /// Prefix length used to group IPv4 source addresses (default: 24).
    pub ipv4_prefix_len: u8,
    /// Prefix length used to group IPv6 source addresses (default: 56).
    pub ipv6_prefix_len: u8,
    /// Maximum responses per second per `(prefix, qname, qtype)` bucket
    /// (default: 10).
    pub rate_per_sec: u32,
    /// Slip ratio: send a TC response every `slip_ratio`-th suppressed response
    /// (default: 2).
    pub slip_ratio: u8,
    /// Window duration in seconds (default: 1).
    pub window_secs: u32,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            ipv4_prefix_len: 24,
            ipv6_prefix_len: 56,
            rate_per_sec: 10,
            slip_ratio: 2,
            window_secs: 1,
        }
    }
}

// ── RrlKey ────────────────────────────────────────────────────────────────────

/// Hash key for an RRL bucket: (truncated source prefix, qname hash, qtype).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RrlKey {
    /// 16-byte canonical form of the (possibly truncated) source prefix.
    source_prefix: [u8; 16],
    /// Hash of the lowercase wire-encoded QNAME.
    qname_hash: u64,
    /// QTYPE value.
    qtype: u16,
}

// ── RrlBucket ─────────────────────────────────────────────────────────────────

struct RrlBucket {
    /// Number of responses issued within the current window.
    count: u32,
    /// When the current window started.
    window_start: Instant,
    /// Incremented on every suppressed response; drives slip.
    slip_counter: u32,
}

// ── RrlDecision ───────────────────────────────────────────────────────────────

/// Decision returned by [`RrlEngine::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlDecision {
    /// Budget not exhausted — send the normal response.
    Allow,
    /// Budget exhausted — silently drop this query.
    Drop,
    /// Budget exhausted but slip ratio fires — send a TC truncated response.
    Slip,
}

// ── RrlEngine ─────────────────────────────────────────────────────────────────

/// Response Rate Limiting engine.
///
/// Thread-safe; clone the `Arc` to share across tasks.
///
/// # Performance note
///
/// Lock contention on the `Mutex<HashMap>` should be benchmarked in a dedicated
/// performance sprint.  If contention is measurable, replace with a sharded
/// array of `Mutex<HashMap>` (shard by `key.source_prefix[0]`) or a lock-free
/// counter map (`dashmap` with `#[deny(unsafe_code)]`-safe operations).
pub struct RrlEngine {
    config: RrlConfig,
    buckets: Arc<Mutex<HashMap<RrlKey, RrlBucket>>>,
}

impl RrlEngine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub fn new(config: RrlConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Evaluate the RRL policy for one inbound query.
    ///
    /// - If the source's budget is not exhausted, returns [`RrlDecision::Allow`].
    /// - If exhausted and the slip counter fires, returns [`RrlDecision::Slip`].
    /// - Otherwise returns [`RrlDecision::Drop`].
    ///
    /// `now` is injected so unit tests can control the clock.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned, which can only happen if a
    /// thread panics while holding the lock — an impossible condition since no
    /// panic path exists inside the critical section.
    #[must_use]
    pub fn check(&self, source: IpAddr, qname: &[u8], qtype: u16, now: Instant) -> RrlDecision {
        let key = self.make_key(source, qname, qtype);
        let window = Duration::from_secs(u64::from(self.config.window_secs));
        // Lock contention benchmarked in performance sprint; replace with
        // sharded counters if needed.
        #[allow(clippy::expect_used)]
        // INVARIANT: the critical section contains no panic path; poisoning is impossible.
        let mut map = self
            .buckets
            .lock()
            .expect("INVARIANT: RRL mutex is never poisoned");

        let bucket = map.entry(key).or_insert_with(|| RrlBucket {
            count: 0,
            window_start: now,
            slip_counter: 0,
        });

        // Roll the window if expired.
        if now.duration_since(bucket.window_start) >= window {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count < self.config.rate_per_sec {
            bucket.count += 1;
            RrlDecision::Allow
        } else {
            // Budget exhausted — determine whether to slip.
            bucket.slip_counter += 1;
            let slip_ratio = u32::from(self.config.slip_ratio.max(1));
            if bucket.slip_counter.is_multiple_of(slip_ratio) {
                RrlDecision::Slip
            } else {
                RrlDecision::Drop
            }
        }
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /// Truncate `source` to the configured prefix and encode as 16-byte canonical
    /// form (IPv4 addresses are stored in their 4-byte representation, left-padded
    /// to 16 bytes for a uniform key width).
    fn truncate_prefix(&self, source: IpAddr) -> [u8; 16] {
        match source {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = prefix_mask_v4(self.config.ipv4_prefix_len);
                let masked = bits & mask;
                let mut out = [0u8; 16];
                out[12..].copy_from_slice(&masked.to_be_bytes());
                out
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = prefix_mask_v6(self.config.ipv6_prefix_len);
                let masked = bits & mask;
                masked.to_be_bytes()
            }
        }
    }

    fn make_key(&self, source: IpAddr, qname: &[u8], qtype: u16) -> RrlKey {
        let source_prefix = self.truncate_prefix(source);
        let qname_hash = hash_qname(qname);
        RrlKey {
            source_prefix,
            qname_hash,
            qtype,
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a 32-bit big-endian mask for IPv4 with the top `prefix_len` bits set.
fn prefix_mask_v4(prefix_len: u8) -> u32 {
    let n = prefix_len.min(32);
    if n == 0 { 0 } else { u32::MAX << (32 - n) }
}

/// Build a 128-bit big-endian mask for IPv6 with the top `prefix_len` bits set.
fn prefix_mask_v6(prefix_len: u8) -> u128 {
    let n = prefix_len.min(128);
    if n == 0 { 0 } else { u128::MAX << (128 - n) }
}

/// Hash the wire-encoded QNAME with `DefaultHasher` for use as a bucket key.
fn hash_qname(qname: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    qname.hash(&mut h);
    h.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    use super::{RrlConfig, RrlDecision, RrlEngine};

    fn addr(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn engine(rate: u32, slip: u8) -> RrlEngine {
        RrlEngine::new(RrlConfig {
            rate_per_sec: rate,
            slip_ratio: slip,
            ..Default::default()
        })
    }

    #[test]
    fn under_budget_allowed() {
        let e = engine(10, 2);
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(
                e.check(addr(1, 2, 3, 4), b"\x07example\x03com\x00", 1, now),
                RrlDecision::Allow
            );
        }
    }

    #[test]
    fn over_budget_dropped() {
        let e = engine(2, 100); // slip_ratio 100 → never slip in this test
        let now = Instant::now();
        let src = addr(1, 2, 3, 4);
        let q = b"\x07example\x03com\x00";
        // First two allowed.
        assert_eq!(e.check(src, q, 1, now), RrlDecision::Allow);
        assert_eq!(e.check(src, q, 1, now), RrlDecision::Allow);
        // Third is over budget.
        assert_eq!(e.check(src, q, 1, now), RrlDecision::Drop);
    }

    #[test]
    fn slip_every_n() {
        // slip_ratio=2: every 2nd drop is a Slip.
        let e = engine(1, 2);
        let now = Instant::now();
        let src = addr(5, 6, 7, 8);
        let q = b"\x04test\x00";
        // Budget=1: first call allowed.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Allow);
        // Excess: slip_counter=1 → 1 % 2 != 0 → Drop.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Drop);
        // Excess: slip_counter=2 → 2 % 2 == 0 → Slip.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Slip);
        // Excess: slip_counter=3 → Drop.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Drop);
        // Excess: slip_counter=4 → Slip.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Slip);
    }

    #[test]
    fn window_reset_allows_again() {
        let e = engine(1, 100);
        let t0 = Instant::now();
        let src = addr(9, 9, 9, 9);
        let q = b"\x03foo\x00";
        // Exhaust budget.
        assert_eq!(e.check(src, q, 1, t0), RrlDecision::Allow);
        assert_eq!(e.check(src, q, 1, t0), RrlDecision::Drop);
        // Advance clock by 2 s — window expires.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(e.check(src, q, 1, t1), RrlDecision::Allow);
    }

    #[test]
    fn different_qtype_different_bucket() {
        let e = engine(1, 100);
        let now = Instant::now();
        let src = addr(1, 1, 1, 1);
        let q = b"\x07example\x03com\x00";
        // A records.
        assert_eq!(e.check(src, q, 1, now), RrlDecision::Allow);
        // AAAA records — different bucket.
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Allow);
        // Both exhausted now.
        assert_eq!(e.check(src, q, 1, now), RrlDecision::Drop);
        assert_eq!(e.check(src, q, 28, now), RrlDecision::Drop);
    }

    #[test]
    fn different_prefix_groups_independently() {
        let e = engine(1, 100); // /24 default
        let now = Instant::now();
        let q = b"\x07example\x03com\x00";
        // 10.0.0.1 and 10.0.1.1 are in different /24 prefixes.
        assert_eq!(e.check(addr(10, 0, 0, 1), q, 1, now), RrlDecision::Allow);
        assert_eq!(e.check(addr(10, 0, 1, 1), q, 1, now), RrlDecision::Allow);
    }
}
