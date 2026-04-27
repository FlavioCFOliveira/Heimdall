// SPDX-License-Identifier: MIT

//! Upstream resolver configuration types for the forwarder role.
//!
//! Defines the transport declaration, per-upstream configuration, and
//! forward-zone rule structure used throughout the forwarder module.

use std::collections::HashSet;

// ── UpstreamTransport ─────────────────────────────────────────────────────────

/// DNS transport protocol for an upstream resolver.
///
/// NET-013: transport must be declared explicitly per upstream — there is no
/// implicit default.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamTransport {
    /// Classic DNS over UDP with fallback to TCP (RFC 1035).
    UdpTcp,
    /// DNS-over-TLS (RFC 7858), port 853 by default.
    Dot,
    /// DNS-over-HTTPS using HTTP/2 (RFC 8484).
    DohH2,
    /// DNS-over-HTTPS using HTTP/3 (draft-ietf-doh-h3).
    DohH3,
    /// DNS-over-QUIC (RFC 9250).
    Doq,
}

// ── UpstreamConfig ────────────────────────────────────────────────────────────

/// Configuration for a single upstream resolver.
///
/// Each upstream is fully described by its address, port, transport, and
/// optional TLS parameters.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Hostname or IP address of the upstream resolver.
    pub host: String,
    /// UDP/TCP port for the upstream resolver.
    pub port: u16,
    /// Transport protocol to use for this upstream (NET-013).
    pub transport: UpstreamTransport,
    /// Optional TLS SNI override. When `None`, `host` is used as the SNI name.
    pub sni: Option<String>,
    /// Whether to verify the upstream's TLS certificate.
    ///
    /// Defaults to `true`. Set to `false` only in test environments — disabling
    /// certificate verification opens a man-in-the-middle attack vector.
    pub tls_verify: bool,
}

// ── MatchMode ─────────────────────────────────────────────────────────────────

/// Zone-pattern matching mode for a [`ForwardRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// The query name must equal the zone pattern exactly.
    Exact,
    /// The query name must equal or end with `.{zone}`.
    Suffix,
    /// The zone pattern begins with `*.`; the remainder is used for suffix
    /// matching.  The zone apex itself does not match.
    Wildcard,
}

// ── ForwardRule ───────────────────────────────────────────────────────────────

/// A forward-zone rule that maps a zone pattern to one or more upstream resolvers.
///
/// FWD-023: `fallback_recursive` is only valid when the recursive role is also
/// active in the same server instance.
#[derive(Debug, Clone)]
pub struct ForwardRule {
    /// Zone pattern (e.g. `"example.com."`, `"*.internal."`).
    pub zone: String,
    /// How to match `zone` against incoming query names.
    pub match_mode: MatchMode,
    /// Ordered list of upstream resolvers to try.
    pub upstreams: Vec<UpstreamConfig>,
    /// If `true`, fall back to the recursive resolver when all upstreams fail.
    ///
    /// FWD-023: only valid when the recursive role is active.
    pub fallback_recursive: bool,
}

// ── Structural gating (NET-014) ───────────────────────────────────────────────

/// Returns the set of transports actually referenced by at least one upstream
/// across all rules.
///
/// NET-014: the caller must only instantiate transport clients for transports
/// present in the returned set.  Transports absent from the set must not be
/// instantiated, even if their client type exists in the binary.
#[must_use]
pub fn instantiated_transports(rules: &[ForwardRule]) -> HashSet<UpstreamTransport> {
    rules
        .iter()
        .flat_map(|r| r.upstreams.iter())
        .map(|u| u.transport.clone())
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn udp_upstream(host: &str) -> UpstreamConfig {
        UpstreamConfig {
            host: host.to_string(),
            port: 53,
            transport: UpstreamTransport::UdpTcp,
            sni: None,
            tls_verify: true,
        }
    }

    fn dot_upstream(host: &str) -> UpstreamConfig {
        UpstreamConfig {
            host: host.to_string(),
            port: 853,
            transport: UpstreamTransport::Dot,
            sni: None,
            tls_verify: true,
        }
    }

    #[test]
    fn instantiated_transports_udp_only() {
        let rules = vec![ForwardRule {
            zone: "example.com.".to_string(),
            match_mode: MatchMode::Suffix,
            upstreams: vec![udp_upstream("8.8.8.8")],
            fallback_recursive: false,
        }];
        let transports = instantiated_transports(&rules);
        assert!(transports.contains(&UpstreamTransport::UdpTcp));
        assert!(!transports.contains(&UpstreamTransport::Dot));
        assert!(!transports.contains(&UpstreamTransport::DohH2));
    }

    #[test]
    fn instantiated_transports_mixed() {
        let rules = vec![ForwardRule {
            zone: "example.com.".to_string(),
            match_mode: MatchMode::Suffix,
            upstreams: vec![udp_upstream("8.8.8.8"), dot_upstream("1.1.1.1")],
            fallback_recursive: false,
        }];
        let transports = instantiated_transports(&rules);
        assert!(transports.contains(&UpstreamTransport::UdpTcp));
        assert!(transports.contains(&UpstreamTransport::Dot));
        assert!(!transports.contains(&UpstreamTransport::DohH2));
    }

    #[test]
    fn instantiated_transports_empty() {
        let transports = instantiated_transports(&[]);
        assert!(transports.is_empty());
    }
}
