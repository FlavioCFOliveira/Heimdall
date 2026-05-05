// SPDX-License-Identifier: MIT

//! Per-zone role configuration for the authoritative server.
//!
//! Each zone served by the authoritative role has an associated [`ZoneConfig`]
//! that determines whether this instance acts as primary, secondary, or both for
//! that zone, as well as the TSIG key and ACL for zone-transfer operations
//! (`PROTO-039`, `PROTO-044`, `PROTO-045`).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use heimdall_core::{Name, TsigAlgorithm, zone::ZoneFile};

// ── ZoneRole ──────────────────────────────────────────────────────────────────

/// The role this Heimdall instance plays for a given zone (`PROTO-039`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRole {
    /// This instance is the primary for the zone: it serves AXFR/IXFR to
    /// configured secondaries and emits NOTIFY on updates (`PROTO-040`).
    Primary,
    /// This instance is a secondary for the zone: it pulls AXFR/IXFR from a
    /// configured primary and accepts NOTIFY from that primary (`PROTO-041`).
    Secondary,
    /// This instance acts as both primary and secondary for the zone, within
    /// a single running instance, on the same zone apex (`PROTO-039`).
    Both,
}

// ── TsigConfig ────────────────────────────────────────────────────────────────

/// TSIG key material for zone-transfer authentication (`PROTO-044`).
///
/// Stored as `(key_name, algorithm, secret_bytes)`.
#[derive(Debug, Clone)]
pub struct TsigConfig {
    /// The TSIG key name as a DNS [`Name`].
    pub key_name: String,
    /// HMAC algorithm for this key.
    pub algorithm: TsigAlgorithm,
    /// Raw shared secret bytes.
    pub secret: Vec<u8>,
}

// ── ZoneConfig ────────────────────────────────────────────────────────────────

/// Per-zone configuration for the authoritative server role.
///
/// Carries the zone apex, role, TSIG material for zone-transfer authentication
/// (`PROTO-044`), and the explicit allow-list for AXFR (`THREAT-042`).
///
/// The `axfr_acl` is used as an *additional* layer alongside TSIG; it MUST NOT
/// be the sole authentication mechanism (`PROTO-045`).
#[derive(Debug, Clone)]
pub struct ZoneConfig {
    /// The zone apex (fully-qualified domain name).
    pub apex: Name,
    /// The role this instance plays for this zone.
    pub role: ZoneRole,
    /// For `Secondary` / `Both`: the upstream primary address to pull from.
    /// For `Primary`: unused (`None`).
    pub upstream_primary: Option<SocketAddr>,
    /// For `Primary` / `Both`: configured secondaries to NOTIFY on zone updates.
    pub notify_secondaries: Vec<SocketAddr>,
    /// Optional TSIG key for zone-transfer authentication (`PROTO-044`).
    ///
    /// Zone transfers MUST be authenticated; omitting this field will cause
    /// AXFR/IXFR requests to be refused with `REFUSED` (`PROTO-048`).
    pub tsig_key: Option<TsigConfig>,
    /// Explicit IP allow-list for AXFR/IXFR (`THREAT-042`, `PROTO-045`).
    ///
    /// Used in combination with TSIG, never as the sole gate.
    pub axfr_acl: Vec<IpAddr>,
    /// In-memory zone data loaded from a zone file at startup or SIGHUP.
    ///
    /// `None` when Redis is the authoritative source (deferred to STORE sprint).
    /// When `Some`, this zone file is used directly for query serving without a
    /// Redis round-trip (`ROLE-002`).
    pub zone_file: Option<Arc<ZoneFile>>,
}

impl ZoneConfig {
    /// Returns `true` if `ip` is allowed by the AXFR ACL, or if the ACL is
    /// empty (no IP restriction configured).
    ///
    /// This check MUST be used in addition to, not instead of, TSIG verification.
    #[must_use]
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.axfr_acl.is_empty() || self.axfr_acl.contains(&ip)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::*;

    fn test_apex() -> Name {
        Name::from_str("example.com.").expect("INVARIANT: valid test name")
    }

    fn make_primary_config() -> ZoneConfig {
        ZoneConfig {
            apex: test_apex(),
            role: ZoneRole::Primary,
            upstream_primary: None,
            notify_secondaries: vec!["192.0.2.10:53".parse().expect("INVARIANT: valid addr")],
            tsig_key: Some(TsigConfig {
                key_name: "xfr-key.".to_owned(),
                algorithm: TsigAlgorithm::HmacSha256,
                secret: b"supersecretkey32bytes-exactly!!".to_vec(),
            }),
            axfr_acl: vec!["192.0.2.10".parse().expect("INVARIANT: valid ip")],
            zone_file: None,
        }
    }

    #[test]
    fn primary_role_construction() {
        let cfg = make_primary_config();
        assert_eq!(cfg.role, ZoneRole::Primary);
        assert!(cfg.upstream_primary.is_none());
        assert_eq!(cfg.notify_secondaries.len(), 1);
        assert!(cfg.tsig_key.is_some());
        assert_eq!(cfg.axfr_acl.len(), 1);
    }

    #[test]
    fn secondary_role_construction() {
        let cfg = ZoneConfig {
            apex: test_apex(),
            role: ZoneRole::Secondary,
            upstream_primary: Some("198.51.100.1:53".parse().expect("INVARIANT: valid addr")),
            notify_secondaries: vec![],
            tsig_key: None,
            axfr_acl: vec![],
            zone_file: None,
        };
        assert_eq!(cfg.role, ZoneRole::Secondary);
        assert!(cfg.upstream_primary.is_some());
    }

    #[test]
    fn both_role_construction() {
        let cfg = ZoneConfig {
            apex: test_apex(),
            role: ZoneRole::Both,
            upstream_primary: Some("198.51.100.1:53".parse().expect("INVARIANT: valid addr")),
            notify_secondaries: vec!["192.0.2.20:53".parse().expect("INVARIANT: valid addr")],
            tsig_key: None,
            axfr_acl: vec![],
            zone_file: None,
        };
        assert_eq!(cfg.role, ZoneRole::Both);
    }

    #[test]
    fn ip_allowed_empty_acl_permits_all() {
        let cfg = ZoneConfig {
            apex: test_apex(),
            role: ZoneRole::Primary,
            upstream_primary: None,
            notify_secondaries: vec![],
            tsig_key: None,
            axfr_acl: vec![],
            zone_file: None,
        };
        let any: IpAddr = "1.2.3.4".parse().expect("INVARIANT: valid ip");
        assert!(cfg.ip_allowed(any));
    }

    #[test]
    fn ip_allowed_acl_enforced() {
        let allowed: IpAddr = "192.0.2.10".parse().expect("INVARIANT: valid ip");
        let denied: IpAddr = "198.51.100.99".parse().expect("INVARIANT: valid ip");
        let cfg = ZoneConfig {
            apex: test_apex(),
            role: ZoneRole::Primary,
            upstream_primary: None,
            notify_secondaries: vec![],
            tsig_key: None,
            axfr_acl: vec![allowed],
            zone_file: None,
        };
        assert!(cfg.ip_allowed(allowed));
        assert!(!cfg.ip_allowed(denied));
    }
}
