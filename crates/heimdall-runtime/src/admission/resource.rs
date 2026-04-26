// SPDX-License-Identifier: MIT

//! Connection and in-flight query resource counters (THREAT-062 through THREAT-068).
//!
//! [`ResourceLimits`] holds the configured caps.  [`ResourceCounters`] holds the
//! live atomic counters that the admission pipeline checks on every inbound
//! request.  Per-listener and per-connection counters are expected to be managed
//! externally by the listener code; this module owns the global pending-query
//! counter.

use std::sync::atomic::{AtomicU32, Ordering};

// ── ResourceLimits ────────────────────────────────────────────────────────────

/// Configured resource caps for the server.
///
/// Every cap is mandatory and has a conservative default (THREAT-061, THREAT-078).
/// There is no way to set a cap to 0 (effectively "unlimited") — the minimum
/// enforced value for any counter cap is 1.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum concurrent connections per `(transport, listener)` (THREAT-062).
    pub max_conn_per_listener: u32,
    /// Maximum in-flight queries per connection (THREAT-063).
    pub max_in_flight_per_conn: u32,
    /// Maximum in-flight queries per source address or identity (THREAT-064).
    pub max_in_flight_per_source: u32,
    /// Maximum global pending queries across all roles, transports, and sources
    /// (THREAT-065).
    pub max_global_pending: u32,
    /// Maximum parse buffer size in bytes per query (THREAT-067).
    pub max_parse_buffer_bytes: u32,
    /// Maximum response buffer size in bytes per query (THREAT-067).
    pub max_response_buffer_bytes: u32,
    /// Maximum decompression buffer size in bytes per query (THREAT-067).
    pub max_decompress_buffer_bytes: u32,
    /// Idle connection timeout in seconds (THREAT-068).
    pub idle_timeout_secs: u32,
    /// Stall timeout in seconds — TCP connections that stop making forward
    /// progress are disconnected (THREAT-068).
    pub stall_timeout_secs: u32,
    /// TLS / QUIC handshake completion timeout in seconds (THREAT-068).
    pub handshake_timeout_secs: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_conn_per_listener: 10_000,
            max_in_flight_per_conn: 100,
            max_in_flight_per_source: 200,
            max_global_pending: 100_000,
            max_parse_buffer_bytes: 65_535,
            max_response_buffer_bytes: 65_535,
            max_decompress_buffer_bytes: 65_535,
            idle_timeout_secs: 30,
            stall_timeout_secs: 10,
            handshake_timeout_secs: 5,
        }
    }
}

// ── ResourceCounters ──────────────────────────────────────────────────────────

/// Live atomic counters for global resource enforcement.
///
/// Per-listener and per-connection counters live alongside this in the listener
/// implementations; [`ResourceCounters`] owns only the server-wide global pending
/// counter (THREAT-065).
#[derive(Debug, Default)]
pub struct ResourceCounters {
    global_pending: AtomicU32,
}

impl ResourceCounters {
    /// Create a fresh counter set, all zeros.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to increment the global pending counter.
    ///
    /// Returns `true` when the counter was incremented (query admitted).
    /// Returns `false` when the counter already equals or exceeds the limit;
    /// the counter is **not** modified in the `false` case (THREAT-065).
    pub fn try_acquire_global(&self, limits: &ResourceLimits) -> bool {
        // Optimistic increment: read → compare → CAS.
        // The loop is expected to succeed on the first iteration under low
        // contention; under high contention it is bounded by the number of
        // competing threads (wait-free if compare_exchange succeeds first try).
        let cap = limits.max_global_pending;
        loop {
            let current = self.global_pending.load(Ordering::Relaxed);
            if current >= cap {
                return false;
            }
            if self
                .global_pending
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
            // Lost the CAS race — retry.
        }
    }

    /// Decrement the global pending counter.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when the counter would underflow below zero.
    pub fn release_global(&self) {
        let prev = self.global_pending.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            prev > 0,
            "INVARIANT: release_global called more times than try_acquire_global succeeded"
        );
    }

    /// Read the current global pending count.
    #[must_use]
    pub fn global_pending(&self) -> u32 {
        self.global_pending.load(Ordering::Relaxed)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{ResourceCounters, ResourceLimits};

    fn limits(cap: u32) -> ResourceLimits {
        ResourceLimits {
            max_global_pending: cap,
            ..Default::default()
        }
    }

    #[test]
    fn acquire_and_release() {
        let c = ResourceCounters::new();
        let lim = limits(5);
        assert!(c.try_acquire_global(&lim));
        assert_eq!(c.global_pending(), 1);
        c.release_global();
        assert_eq!(c.global_pending(), 0);
    }

    #[test]
    fn over_cap_rejected() {
        let c = ResourceCounters::new();
        let lim = limits(2);
        assert!(c.try_acquire_global(&lim));
        assert!(c.try_acquire_global(&lim));
        // At cap.
        assert!(!c.try_acquire_global(&lim));
        assert_eq!(c.global_pending(), 2);
    }

    #[test]
    fn release_restores_capacity() {
        let c = ResourceCounters::new();
        let lim = limits(1);
        assert!(c.try_acquire_global(&lim));
        assert!(!c.try_acquire_global(&lim));
        c.release_global();
        assert!(c.try_acquire_global(&lim));
    }

    #[test]
    fn concurrent_acquire_release() {
        use std::sync::Arc;
        let c = Arc::new(ResourceCounters::new());
        let lim = Arc::new(limits(100));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c2 = Arc::clone(&c);
            let l2 = Arc::clone(&lim);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    if c2.try_acquire_global(&l2) {
                        c2.release_global();
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All releases matched acquires, so counter must be 0.
        assert_eq!(c.global_pending(), 0);
    }
}
