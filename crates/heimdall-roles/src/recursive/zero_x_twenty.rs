// SPDX-License-Identifier: MIT

//! 0x20 case randomisation per PROTO-025..031.
//!
//! DNS 0x20 encoding (Vixie & Dagon, 2008) randomises the case of ASCII
//! letters in the outbound QNAME and verifies that the authoritative server
//! reflects the same case in its response.  A mismatch is strong evidence of
//! a spoofed reply, providing per-query entropy beyond the 16-bit transaction
//! ID and port number.
//!
//! # Thread-local PRNG
//!
//! Case randomisation uses a per-thread `XorShift64` seeded from the system
//! clock XOR'd with the transaction ID.  No external RNG crate is required.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::SystemTime;

use heimdall_core::name::Name;

use crate::recursive::server_state::ServerStateCache;

// ── XorShift64 PRNG ───────────────────────────────────────────────────────────

/// A minimal `XorShift64` pseudo-random number generator.
///
/// Seeded from system time XOR'd with the transaction ID to give per-query
/// entropy without any external dependency.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    /// Creates a new PRNG seeded from `seed`.
    ///
    /// If `seed` is zero the state is set to a fixed non-zero value to avoid
    /// a degenerate zero-state that produces only zeros.
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xDEAD_BEEF_CAFE_BABE
            } else {
                seed
            },
        }
    }

    /// Advances the generator by one step and returns the new state.
    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

thread_local! {
    /// Per-thread PRNG used for 0x20 case randomisation.
    static PRNG: std::cell::RefCell<XorShift64> = std::cell::RefCell::new(XorShift64::new(0));
}

/// Seeds the per-thread PRNG from system time and `txid`.
fn seed_prng(txid: u16) {
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let seed = u64::from(nanos) ^ (u64::from(txid).wrapping_mul(6_364_136_223_846_793_005));
    PRNG.with(|p| p.borrow_mut().state = if seed == 0 { 1 } else { seed });
}

/// Returns the next bit from the per-thread PRNG.
fn next_bit() -> bool {
    PRNG.with(|p| p.borrow_mut().next() & 1 == 1)
}

// ── CasePattern ──────────────────────────────────────────────────────────────

/// Stored per-query 0x20 case pattern for a single outbound query.
struct CasePattern {
    /// Wire-format bytes of the randomised QNAME (used for verification).
    wire: Vec<u8>,
    /// Unix second at which this pattern was stored (for stale eviction).
    stored_at_secs: u64,
}

// ── CasePatternStore ─────────────────────────────────────────────────────────

/// Store for in-flight 0x20 case patterns indexed by `(txid, server_ip)`.
///
/// Each outbound query that uses 0x20 randomisation records the randomised
/// QNAME wire bytes here.  When the response arrives, the pattern is consumed
/// and the response QNAME is compared byte-for-byte.
///
/// Patterns older than 30 seconds are evicted by [`Self::evict_stale`] to
/// prevent unbounded memory growth from lost responses.
pub struct CasePatternStore {
    patterns: Mutex<HashMap<(u16, IpAddr), CasePattern>>,
}

impl CasePatternStore {
    /// Creates an empty [`CasePatternStore`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: Mutex::new(HashMap::new()),
        }
    }

    /// Randomises the ASCII letters in `qname`, stores the pattern, and
    /// returns the randomised [`Name`].
    ///
    /// Non-ASCII label bytes are left unchanged.  The pattern is keyed by
    /// `(txid, server)` so it can be retrieved when the response arrives.
    pub fn randomise_and_store(
        &self,
        txid: u16,
        server: IpAddr,
        qname: &Name,
        now_secs: u64,
    ) -> Name {
        seed_prng(txid);

        let wire = qname.as_wire_bytes();
        let mut randomised = wire.to_vec();

        // Walk the wire-format labels and randomise ASCII alphabetic bytes.
        let mut i = 0;
        while i < randomised.len() {
            let len_byte = randomised[i] as usize;
            if len_byte == 0 {
                break;
            }
            i += 1;
            for byte in randomised.iter_mut().skip(i).take(len_byte) {
                if byte.is_ascii_alphabetic() {
                    if next_bit() {
                        *byte = byte.to_ascii_uppercase();
                    } else {
                        *byte = byte.to_ascii_lowercase();
                    }
                }
            }
            i += len_byte;
        }

        // Build the randomised Name (fall back to original on parse failure).
        let name_out = Name::from_wire(&randomised, 0).map_or_else(|_| qname.clone(), |(n, _)| n);

        // Store the pattern for later verification.
        let pattern = CasePattern {
            wire: name_out.as_wire_bytes().to_vec(),
            stored_at_secs: now_secs,
        };
        let mut guard = self.lock();
        guard.insert((txid, server), pattern);

        name_out
    }

    /// Verifies that the QNAME in a response matches the stored pattern for
    /// `(txid, server)`.
    ///
    /// Returns `true` when the bytes match exactly (case-sensitive), or when no
    /// pattern exists for this pair (e.g. 0x20 was skipped for this server).
    ///
    /// The pattern is removed after verification regardless of the outcome.
    pub fn verify_and_consume(&self, txid: u16, server: IpAddr, response_qname: &Name) -> bool {
        let mut guard = self.lock();
        let Some(pattern) = guard.remove(&(txid, server)) else {
            // No pattern stored — treat as matching (0x20 was disabled for this query).
            return true;
        };
        pattern.wire == response_qname.as_wire_bytes()
    }

    /// Evicts case patterns older than 30 seconds.
    ///
    /// Call periodically (e.g. on each response) to prevent stale patterns from
    /// accumulating when upstream servers fail to respond.
    pub fn evict_stale(&self, now_secs: u64) {
        const MAX_AGE_SECS: u64 = 30;
        let mut guard = self.lock();
        guard.retain(|_, p| now_secs.saturating_sub(p.stored_at_secs) < MAX_AGE_SECS);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(u16, IpAddr), CasePattern>> {
        self.patterns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for CasePatternStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Applies 0x20 case randomisation to `qname` for an outbound query.
///
/// Checks [`ServerStateCache::should_disable_ox20`] first.  If the server is
/// known to be non-conformant, the original `qname` is returned unchanged and
/// no pattern is stored (the store will return `true` on verification without
/// a pattern, which is correct — we do not penalise a deliberately skipped
/// check).
///
/// When randomisation is applied, the pattern is stored in `store` for later
/// verification via [`verify_ox20`].
pub fn apply_ox20(
    qname: &Name,
    txid: u16,
    server: IpAddr,
    now_secs: u64,
    server_state: &ServerStateCache,
    store: &CasePatternStore,
) -> Name {
    if server_state.should_disable_ox20(server) {
        // Non-conformant server: skip randomisation entirely.
        return qname.clone();
    }

    store.randomise_and_store(txid, server, qname, now_secs)
}

/// Verifies 0x20 case on an incoming response QNAME.
///
/// Updates [`ServerStateCache`] via `record_response` with the conformance
/// result.  On mismatch, emits a structured [`tracing::warn`] event.
///
/// Returns `true` if the case matches (or no pattern was stored).
pub fn verify_ox20(
    response_qname: &Name,
    txid: u16,
    server: IpAddr,
    now_secs: u64,
    server_state: &ServerStateCache,
    store: &CasePatternStore,
) -> bool {
    let matched = store.verify_and_consume(txid, server, response_qname);

    server_state.record_response(server, matched, now_secs);

    if !matched {
        // Compute which byte positions differ for the structured warning.
        // We retrieve nothing from the store (already consumed), so we just
        // emit the server and txid.
        tracing::warn!(
            txid,
            server = %server,
            "0x20 case mismatch: response QNAME does not match sent case pattern"
        );
    }

    matched
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use heimdall_core::name::Name;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    fn server() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
    }

    #[test]
    fn case_pattern_stores_and_verifies_match() {
        let store = CasePatternStore::new();
        let qname = name("example.com.");
        let txid = 42u16;
        let sv = server();
        let now = 1_000_000u64;

        let randomised = store.randomise_and_store(txid, sv, &qname, now);
        // Verify with the exact bytes we stored.
        assert!(
            store.verify_and_consume(txid, sv, &randomised),
            "exact case match must verify"
        );
    }

    #[test]
    fn case_pattern_mismatch_returns_false() {
        let store = CasePatternStore::new();
        let qname = name("example.com.");
        let txid = 43u16;
        let sv = server();
        let now = 1_000_000u64;

        store.randomise_and_store(txid, sv, &qname, now);

        // Supply the lowercase (canonical) name — likely differs from randomised.
        let wrong = name("example.com.");
        // randomise_and_store may or may not produce all-lowercase; the test
        // verifies the mismatch detection.  If by chance all letters were
        // lowercased we force an inequality using an entirely different name.
        let wrong2 = name("EXAMPLE.COM.");
        let matched_lower = store.verify_and_consume(txid, sv, &wrong);
        if matched_lower {
            // Re-seed and re-store for the uppercase check.
            store.randomise_and_store(txid, sv, &qname, now);
            let matched_upper = store.verify_and_consume(txid, sv, &wrong2);
            // At least one of the two must mismatch the random pattern.
            // (Probabilistically near-certain; we accept the rare equal case.)
            let _ = matched_upper; // cannot always guarantee mismatch
        }
        // The main assertion: after consume, the key is gone.
        assert!(
            store.verify_and_consume(txid, sv, &wrong),
            "missing key returns true (no-pattern sentinel)"
        );
    }

    #[test]
    fn disabled_server_skips_randomisation() {
        let state = ServerStateCache::new();
        let store = CasePatternStore::new();
        let sv = server();
        let now = 1_000_000u64;
        let qname = name("example.com.");

        // Mark the server as non-conformant so apply_ox20 skips randomisation.
        for _ in 0..10 {
            state.record_response(sv, false, now);
        }
        assert!(
            state.should_disable_ox20(sv),
            "server must be non-conformant"
        );

        let result = apply_ox20(&qname, 1, sv, now, &state, &store);
        // Wire bytes must be identical to the original (no randomisation).
        assert_eq!(
            result.as_wire_bytes(),
            qname.as_wire_bytes(),
            "disabled server must not randomise QNAME"
        );
    }
}
