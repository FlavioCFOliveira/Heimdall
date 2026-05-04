// SPDX-License-Identifier: MIT

//! Per-server state cache for upstream DNS servers.
//!
//! [`ServerStateCache`] tracks per-IP-address state: exponential moving
//! average latency, timeout counts, 0x20 case-randomisation conformance
//! (PROTO-028/087), and EDNS capability (PROTO-025/026).
//!
//! The cache is LRU-bounded using a `HashMap` + `VecDeque` without any
//! external LRU crate — the same pattern used in Sprint 19's SLRU cache.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default maximum number of server entries tracked.
const DEFAULT_MAX_ENTRIES: usize = 1024;

/// Sliding window size for 0x20 case-randomisation conformance checks (PROTO-087).
const OX20_WINDOW_SIZE: usize = 10;

/// Number of non-conformant responses out of the window required to mark a
/// server as non-conformant (PROTO-087: 3-of-10 threshold).
const OX20_NON_CONFORMANT_THRESHOLD: usize = 3;

/// Exponential moving average alpha (≈ 1/8).  New value contributes 12.5%.
const EMA_ALPHA_NUM: u64 = 1;
const EMA_ALPHA_DEN: u64 = 8;

/// Initial reprobe interval: 1 hour in seconds (PROTO-090).
const OX20_INITIAL_REPROBE_SECS: u64 = 3_600;

/// Maximum reprobe interval: 24 hours in seconds (PROTO-090).
const OX20_MAX_REPROBE_SECS: u64 = 86_400;

// ── ServerState ───────────────────────────────────────────────────────────────

/// Per-server health and behavioural state.
#[derive(Debug, Clone)]
pub struct ServerState {
    /// Exponential moving average latency in milliseconds.
    pub recent_latency_ms: u64,
    /// Total number of timeouts recorded for this server.
    pub timeout_count: u32,
    /// Approximate NXDOMAIN rate (0–100, integer percent).
    pub nxdomain_rate: u8,
    /// Approximate SERVFAIL rate (0–100, integer percent).
    pub servfail_rate: u8,
    /// `true` when the server does not support EDNS and we have fallen back.
    pub edns_disabled: bool,
    /// `true` when the server correctly preserves 0x20 case randomisation.
    pub ox20_conformant: bool,
    /// Sliding window of the last `OX20_WINDOW_SIZE` non-error responses.
    /// Each element is `true` if the server correctly reflected the case.
    pub ox20_window: VecDeque<bool>,
    /// Unix second at which 0x20 non-conformance was first detected.
    pub ox20_non_conformant_since: Option<u64>,
    /// Current re-probe interval for 0x20 (seconds), doubling each failure.
    pub reprobe_interval_secs: u64,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            recent_latency_ms: 100,
            timeout_count: 0,
            nxdomain_rate: 0,
            servfail_rate: 0,
            edns_disabled: false,
            ox20_conformant: true,
            ox20_window: VecDeque::with_capacity(OX20_WINDOW_SIZE),
            ox20_non_conformant_since: None,
            reprobe_interval_secs: OX20_INITIAL_REPROBE_SECS,
        }
    }
}

// ── ServerStateCache ──────────────────────────────────────────────────────────

/// Thread-safe LRU cache of per-upstream-server state.
///
/// Uses a `HashMap` + `VecDeque` for O(1) lookup and approximate LRU eviction
/// without an external crate.
pub struct ServerStateCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<IpAddr, ServerState>,
    /// Insertion-order queue used for LRU eviction.
    order: VecDeque<IpAddr>,
    max_entries: usize,
}

impl CacheInner {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_entries.min(256)),
            order: VecDeque::with_capacity(max_entries.min(256)),
            max_entries,
        }
    }

    /// Returns a mutable reference to the state for `ip`, inserting a default
    /// entry if not present.  Evicts the LRU entry when at capacity.
    fn get_or_insert(&mut self, ip: IpAddr) -> &mut ServerState {
        if !self.map.contains_key(&ip) {
            // Evict LRU entry if at capacity.
            while self.map.len() >= self.max_entries {
                if let Some(evict_ip) = self.order.pop_front() {
                    self.map.remove(&evict_ip);
                } else {
                    break;
                }
            }
            self.map.insert(ip, ServerState::default());
            self.order.push_back(ip);
        }
        // INVARIANT: we just inserted if absent; this unwrap cannot fail.
        // INVARIANT: the entry was just inserted above; this cannot be None.
        #[allow(clippy::expect_used)]
        self.map
            .get_mut(&ip)
            .expect("INVARIANT: entry just inserted above")
    }
}

impl ServerStateCache {
    /// Creates a new [`ServerStateCache`] with the default entry limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Creates a new [`ServerStateCache`] with the given entry limit.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner::new(max_entries.max(1))),
        }
    }

    /// Updates the EMA latency for `ip` with a new measurement.
    pub fn update_latency(&self, ip: IpAddr, ms: u64) {
        let mut guard = self.lock();
        let state = guard.get_or_insert(ip);
        // EMA: new = old × (1 - α) + sample × α, where α = 1/8.
        state.recent_latency_ms = state
            .recent_latency_ms
            .saturating_mul(EMA_ALPHA_DEN - EMA_ALPHA_NUM)
            .saturating_add(ms.saturating_mul(EMA_ALPHA_NUM))
            / EMA_ALPHA_DEN;
    }

    /// Records a query timeout for `ip`.
    pub fn record_timeout(&self, ip: IpAddr) {
        let mut guard = self.lock();
        let state = guard.get_or_insert(ip);
        state.timeout_count = state.timeout_count.saturating_add(1);
    }

    /// Records a non-error response for `ip`, updating the 0x20 sliding window.
    ///
    /// `is_case_preserving` is `true` when the server reflected the
    /// randomised QNAME case correctly (PROTO-087).
    ///
    /// After `OX20_WINDOW_SIZE` observations, if the number of non-conformant
    /// responses reaches `OX20_NON_CONFORMANT_THRESHOLD`, the server is marked
    /// as non-conformant and `ox20_non_conformant_since` is set.
    pub fn record_response(&self, ip: IpAddr, is_case_preserving: bool, now_secs: u64) {
        let mut guard = self.lock();
        let state = guard.get_or_insert(ip);

        // Slide the window.
        if state.ox20_window.len() >= OX20_WINDOW_SIZE {
            state.ox20_window.pop_front();
        }
        state.ox20_window.push_back(is_case_preserving);

        // Recompute conformance from the window (only once full or late-startup).
        if state.ox20_window.len() >= OX20_WINDOW_SIZE {
            let non_conformant_count = state.ox20_window.iter().filter(|&&ok| !ok).count();
            let was_conformant = state.ox20_conformant;
            state.ox20_conformant = non_conformant_count < OX20_NON_CONFORMANT_THRESHOLD;

            if was_conformant && !state.ox20_conformant {
                // Newly non-conformant: record the timestamp.
                state.ox20_non_conformant_since = Some(now_secs);
                state.reprobe_interval_secs = OX20_INITIAL_REPROBE_SECS;
            } else if !was_conformant && state.ox20_conformant {
                // Recovered: clear the timestamp.
                state.ox20_non_conformant_since = None;
            }
        }
    }

    /// Returns `true` if 0x20 case-randomisation should be skipped for `ip`.
    ///
    /// Randomisation is disabled when the server has been classified as
    /// non-conformant (PROTO-087).
    #[must_use]
    pub fn should_disable_ox20(&self, ip: IpAddr) -> bool {
        let guard = self.lock();
        guard.map.get(&ip).is_some_and(|s| !s.ox20_conformant)
    }

    /// Returns `true` when the re-probe interval has elapsed for a
    /// non-conformant server, meaning we should retry 0x20 (PROTO-090).
    #[must_use]
    pub fn should_reprobe_ox20(&self, ip: IpAddr, now_secs: u64) -> bool {
        let guard = self.lock();
        let Some(state) = guard.map.get(&ip) else {
            return false;
        };
        if state.ox20_conformant {
            return false;
        }
        let Some(since) = state.ox20_non_conformant_since else {
            return false;
        };
        now_secs.saturating_sub(since) >= state.reprobe_interval_secs
    }

    /// Advances the re-probe interval for `ip` by doubling it, up to 24 h.
    ///
    /// Call this when a re-probe attempt reveals the server is still
    /// non-conformant (PROTO-090).
    pub fn advance_reprobe_interval(&self, ip: IpAddr) {
        let mut guard = self.lock();
        let state = guard.get_or_insert(ip);
        state.reprobe_interval_secs = state
            .reprobe_interval_secs
            .saturating_mul(2)
            .min(OX20_MAX_REPROBE_SECS);
    }

    /// Returns `true` if `ip` has EDNS support enabled.
    #[must_use]
    pub fn is_edns_capable(&self, ip: IpAddr) -> bool {
        let guard = self.lock();
        // Unknown servers are assumed EDNS-capable by default.
        guard.map.get(&ip).is_none_or(|s| !s.edns_disabled)
    }

    /// Disables EDNS for `ip` (EDNS fallback flag).
    pub fn disable_edns(&self, ip: IpAddr) {
        let mut guard = self.lock();
        let state = guard.get_or_insert(ip);
        state.edns_disabled = true;
    }

    /// Selects the best candidate from `candidates`.
    ///
    /// Selection heuristic (lower score = better):
    /// - Timed-out servers are penalised heavily.
    /// - EDNS-disabled servers are penalised moderately.
    /// - Remaining penalty is proportional to EMA latency.
    ///
    /// Returns `None` only when `candidates` is empty.
    #[must_use]
    pub fn select_best(&self, candidates: &[IpAddr]) -> Option<IpAddr> {
        if candidates.is_empty() {
            return None;
        }
        let guard = self.lock();

        let best = candidates.iter().min_by_key(|&&ip| {
            let state = guard.map.get(&ip);
            let latency = state.map_or(100u64, |s| s.recent_latency_ms);
            let timeout_penalty = state.map_or(0u64, |s| u64::from(s.timeout_count) * 500);
            let edns_penalty = state.map_or(0u64, |s| if s.edns_disabled { 300 } else { 0 });
            latency
                .saturating_add(timeout_penalty)
                .saturating_add(edns_penalty)
        });

        best.copied()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for ServerStateCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, octet))
    }

    #[test]
    fn latency_ema_updates() {
        let cache = ServerStateCache::new();
        let target = ip(1);
        cache.update_latency(target, 200);
        let guard = cache.lock();
        let state = guard.map.get(&target).expect("state must exist");
        // EMA: (100 * 7 + 200 * 1) / 8 = 112
        assert!(state.recent_latency_ms > 100, "EMA must have increased");
    }

    #[test]
    fn timeout_count_increments() {
        let cache = ServerStateCache::new();
        let target = ip(2);
        cache.record_timeout(target);
        cache.record_timeout(target);
        let guard = cache.lock();
        let state = guard.map.get(&target).expect("state must exist");
        assert_eq!(state.timeout_count, 2);
    }

    #[test]
    fn ox20_non_conformant_classification() {
        let cache = ServerStateCache::new();
        let target = ip(3);
        let now = 1_000_000_u64;

        // Record 10 responses: 3 non-conformant, 7 conformant.
        // After 10 responses the window is full; 3 non-conformant = threshold.
        for i in 0..10 {
            let conformant = i >= 3; // first 3 are non-conformant
            cache.record_response(target, conformant, now);
        }

        assert!(
            cache.should_disable_ox20(target),
            "server should be marked non-conformant after 3-of-10 failures"
        );
    }

    #[test]
    fn ox20_conformant_below_threshold() {
        let cache = ServerStateCache::new();
        let target = ip(4);
        let now = 1_000_000_u64;

        // 2 non-conformant out of 10 → below threshold → still conformant.
        for i in 0..10 {
            let conformant = i >= 2;
            cache.record_response(target, conformant, now);
        }

        assert!(
            !cache.should_disable_ox20(target),
            "server must remain conformant with only 2-of-10 failures"
        );
    }

    #[test]
    fn ox20_reprobe_interval_initial_is_1h() {
        let cache = ServerStateCache::new();
        let target = ip(5);
        let now = 1_000_000_u64;

        // Force non-conformance.
        for _ in 0..10 {
            cache.record_response(target, false, now);
        }

        // Reprobe should not fire before 1 h has elapsed.
        assert!(
            !cache.should_reprobe_ox20(target, now),
            "reprobe must not fire immediately"
        );
        // Should fire after 1 h.
        assert!(
            cache.should_reprobe_ox20(target, now + OX20_INITIAL_REPROBE_SECS),
            "reprobe must fire after 1 h"
        );
    }

    #[test]
    fn ox20_reprobe_interval_doubles() {
        let cache = ServerStateCache::new();
        let target = ip(6);
        let now = 1_000_000_u64;

        // Force non-conformance.
        for _ in 0..10 {
            cache.record_response(target, false, now);
        }

        // Advance the interval once.
        cache.advance_reprobe_interval(target);

        {
            let guard = cache.lock();
            let state = guard.map.get(&target).expect("state must exist");
            assert_eq!(
                state.reprobe_interval_secs,
                OX20_INITIAL_REPROBE_SECS * 2,
                "interval must double"
            );
        }

        // Advance many times — must cap at 24 h.
        for _ in 0..20 {
            cache.advance_reprobe_interval(target);
        }
        {
            let guard = cache.lock();
            let state = guard.map.get(&target).expect("state must exist");
            assert_eq!(
                state.reprobe_interval_secs, OX20_MAX_REPROBE_SECS,
                "interval must cap at 24 h"
            );
        }
    }

    #[test]
    fn edns_capability_defaults_to_true() {
        let cache = ServerStateCache::new();
        let target = ip(7);
        assert!(
            cache.is_edns_capable(target),
            "unknown server must default to EDNS-capable"
        );
    }

    #[test]
    fn edns_disable_takes_effect() {
        let cache = ServerStateCache::new();
        let target = ip(8);
        cache.disable_edns(target);
        assert!(!cache.is_edns_capable(target));
    }

    #[test]
    fn select_best_returns_none_for_empty() {
        let cache = ServerStateCache::new();
        assert!(cache.select_best(&[]).is_none());
    }

    #[test]
    fn select_best_prefers_lower_latency() {
        let cache = ServerStateCache::new();
        let fast = ip(10);
        let slow = ip(11);

        cache.update_latency(fast, 10);
        cache.update_latency(slow, 500);

        assert_eq!(
            cache.select_best(&[slow, fast]),
            Some(fast),
            "should prefer faster server"
        );
    }

    #[test]
    fn lru_eviction_on_capacity() {
        let cache = ServerStateCache::with_capacity(3);
        let ips: Vec<IpAddr> = (0..5).map(|i| ip(i + 20)).collect();

        for &ip in &ips {
            cache.record_timeout(ip);
        }

        // After inserting 5 into a capacity-3 cache, the first 2 should be gone.
        let guard = cache.lock();
        assert!(
            guard.map.len() <= 3,
            "cache must not exceed capacity: len = {}",
            guard.map.len()
        );
    }

    // ── PROTO-088 ─────────────────────────────────────────────────────────────

    /// PROTO-088: a single non-conformant response from an otherwise-conformant
    /// server does NOT reclassify it as non-conformant.  The sliding window
    /// requires at least OX20_NON_CONFORMANT_THRESHOLD (3) failures out of
    /// OX20_WINDOW_SIZE (10) observations.
    #[test]
    fn proto088_single_bad_response_does_not_reclassify() {
        let cache = ServerStateCache::new();
        let target = ip(30);
        let now = 1_000_000_u64;

        // Fill the window with 10 conformant responses → server is conformant.
        for _ in 0..10 {
            cache.record_response(target, true, now);
        }
        assert!(
            !cache.should_disable_ox20(target),
            "server must be conformant after 10 conformant responses"
        );

        // One non-conformant response: window now has 1-of-10 failures.
        cache.record_response(target, false, now);
        assert!(
            !cache.should_disable_ox20(target),
            "PROTO-088: a single non-conformant response must not reclassify server as non-conformant"
        );
    }

    /// PROTO-088 (positive gate): verify that exactly threshold non-conformant
    /// responses in a full window DO trigger reclassification.
    #[test]
    fn proto088_threshold_bad_responses_do_reclassify() {
        let cache = ServerStateCache::new();
        let target = ip(31);
        let now = 1_000_000_u64;

        // Fill window: first OX20_NON_CONFORMANT_THRESHOLD are bad, rest conformant.
        for i in 0..10 {
            cache.record_response(target, i >= OX20_NON_CONFORMANT_THRESHOLD, now);
        }
        assert!(
            cache.should_disable_ox20(target),
            "server must be non-conformant once threshold is reached"
        );
    }

    // ── PROTO-091 ─────────────────────────────────────────────────────────────

    /// PROTO-091: when a server recovers from non-conformance (enough conformant
    /// responses push the window below threshold), the backoff state is cleared:
    /// `ox20_non_conformant_since` becomes `None` and `should_reprobe_ox20`
    /// returns `false`.
    #[test]
    fn proto091_backoff_state_cleared_on_recovery() {
        let cache = ServerStateCache::new();
        let target = ip(40);
        let now = 1_000_000_u64;

        // Force non-conformance: all 10 responses are non-conformant.
        for _ in 0..OX20_WINDOW_SIZE {
            cache.record_response(target, false, now);
        }
        assert!(
            cache.should_disable_ox20(target),
            "server must be non-conformant"
        );
        // Non-conformant-since timestamp must be set.
        {
            let guard = cache.lock();
            let state = guard.map.get(&target).expect("state exists");
            assert!(
                state.ox20_non_conformant_since.is_some(),
                "non_conformant_since must be set"
            );
        }

        // Now feed enough conformant responses to push failures below threshold.
        // After OX20_WINDOW_SIZE conformant responses all old bad ones slide out.
        for _ in 0..OX20_WINDOW_SIZE {
            cache.record_response(target, true, now);
        }

        assert!(
            !cache.should_disable_ox20(target),
            "PROTO-091: server must be conformant after sufficient good responses"
        );

        // Backoff state must be cleared.
        {
            let guard = cache.lock();
            let state = guard.map.get(&target).expect("state exists");
            assert!(
                state.ox20_non_conformant_since.is_none(),
                "PROTO-091: non_conformant_since must be cleared on recovery"
            );
        }

        // Reprobe must not fire on a conformant server.
        assert!(
            !cache.should_reprobe_ox20(target, now + OX20_MAX_REPROBE_SECS),
            "PROTO-091: should_reprobe_ox20 must return false for a conformant server"
        );
    }
}
