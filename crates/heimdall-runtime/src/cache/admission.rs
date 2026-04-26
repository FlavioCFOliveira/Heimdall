// SPDX-License-Identifier: MIT

//! Cache admission guard trait and the no-op default implementation.
//!
//! [`AdmissionGuard`] is the extension point for Sprint 20's rate-limiting and
//! DNS-Cookie-based admission weighting (CACHE-012).  Until that sprint
//! integrates real admission control, every query is admitted via
//! [`NoopAdmission`].

use std::net::IpAddr;

// ── AdmissionGuard ────────────────────────────────────────────────────────────

/// Decides whether a cache-miss response may be admitted into the cache.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// shard-owning threads without additional synchronisation on the caller side.
///
/// # Sprint 20 integration point
///
/// The real implementation will enforce per-source repeat-miss suppression
/// (CACHE-012, THREAT-051..THREAT-053) and privilege responses from sources
/// that present a valid DNS Cookie (RFC 7873).
pub trait AdmissionGuard: Send + Sync {
    /// Returns `true` when the response for `(qname, qtype)` from `source_hint`
    /// is eligible for cache admission.
    ///
    /// # Parameters
    ///
    /// - `source_hint` — the IP address of the upstream that produced the
    ///   response, if known.  `None` means the source is not attributed (e.g.
    ///   synthesised responses).
    /// - `qname` — the wire-encoded owner name of the queried `RRset`.
    /// - `qtype` — the numeric QTYPE of the query.
    fn check_admit(&self, source_hint: Option<IpAddr>, qname: &[u8], qtype: u16) -> bool;
}

// ── NoopAdmission ─────────────────────────────────────────────────────────────

/// An [`AdmissionGuard`] that admits every response unconditionally.
///
/// Used during Sprint 19 while the real rate-limiting machinery is deferred to
/// Sprint 20.
pub struct NoopAdmission;

impl AdmissionGuard for NoopAdmission {
    fn check_admit(&self, _source_hint: Option<IpAddr>, _qname: &[u8], _qtype: u16) -> bool {
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{AdmissionGuard, NoopAdmission};

    #[test]
    fn noop_admits_everything() {
        let guard = NoopAdmission;
        assert!(guard.check_admit(None, b"\x03www\x07example\x03com\x00", 1));
        assert!(guard.check_admit(
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            b"\x03foo\x00",
            28,
        ));
    }
}
