// SPDX-License-Identifier: MIT

//! RPZ trigger types and associated data structures (RPZ-011..015, RPZ-027, RPZ-029).
//!
//! A trigger defines the condition that causes a policy zone entry to fire.
//! Each [`RpzEntry`] pairs one trigger with one [`crate::rpz::action::RpzAction`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use heimdall_core::name::Name;

use crate::rpz::action::RpzAction;

// ── CidrRange ─────────────────────────────────────────────────────────────────

/// A CIDR network range for use in Client-IP, Response-IP, and NSIP triggers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRange {
    /// The base address of the network (masked to the network address).
    pub addr: IpAddr,
    /// The prefix length in bits.
    pub prefix_len: u8,
}

impl CidrRange {
    /// Returns `true` if `ip` falls within this CIDR range.
    ///
    /// For IPv4 vs IPv6 mismatches the result is always `false`.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(base), IpAddr::V4(candidate)) => {
                ipv4_in_range(base, candidate, self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(candidate)) => {
                ipv6_in_range(base, candidate, self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Tests whether `candidate` is within the IPv4 CIDR `base/prefix_len`.
fn ipv4_in_range(base: Ipv4Addr, candidate: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let shift = 32u32.saturating_sub(u32::from(prefix_len));
    let mask = !0u32 << shift;
    let base_bits = u32::from_be_bytes(base.octets()) & mask;
    let cand_bits = u32::from_be_bytes(candidate.octets()) & mask;
    base_bits == cand_bits
}

/// Tests whether `candidate` is within the IPv6 CIDR `base/prefix_len`.
fn ipv6_in_range(base: Ipv6Addr, candidate: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let shift = 128u32.saturating_sub(u32::from(prefix_len));
    let mask: u128 = !0u128 << shift;
    let base_bits = u128::from_be_bytes(base.octets()) & mask;
    let cand_bits = u128::from_be_bytes(candidate.octets()) & mask;
    base_bits == cand_bits
}

// ── RpzTrigger ────────────────────────────────────────────────────────────────

/// A single RPZ trigger condition (RPZ-011..015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpzTrigger {
    /// Exact QNAME match (RPZ-011).
    ///
    /// Fires when the queried name is case-insensitively equal to the stored name.
    QnameExact(Name),
    /// Wildcard QNAME match (RPZ-011, RPZ-029).
    ///
    /// Stores the suffix without the leading wildcard label.  A trigger
    /// `*.evil.com.` is stored as `evil.com.` and matches any strict subdomain
    /// of `evil.com.` (i.e. `evil.com.` itself does NOT match).
    QnameWildcard(Name),
    /// Response-IP CIDR match (RPZ-012).
    ///
    /// Fires when any IP address in the upstream response falls in the given range.
    ResponseIp(CidrRange),
    /// NSIP CIDR match (RPZ-013).
    ///
    /// Fires when any IP address of an encountered authoritative name server falls
    /// within the given range.
    Nsip(CidrRange),
    /// NSDNAME exact name match (RPZ-014).
    ///
    /// Fires when an encountered NS name is case-insensitively equal to the stored name.
    NsdnameExact(Name),
    /// NSDNAME suffix name match (RPZ-014).
    ///
    /// Fires when an encountered NS name is a subdomain of the stored suffix.
    NsdnameSuffix(Name),
    /// Client-IP CIDR match (RPZ-015).
    ///
    /// Fires when the client's source IP address falls within the given range.
    ClientIp(CidrRange),
}

impl RpzTrigger {
    /// Returns the intra-zone trigger precedence value used for tie-breaking when
    /// multiple triggers within one zone match the same query (RPZ-027).
    ///
    /// Lower values indicate higher priority.
    ///
    /// | Priority | Trigger type         |
    /// |----------|----------------------|
    /// | 0        | `ClientIp`           |
    /// | 1        | `QnameExact`         |
    /// | 2        | `QnameWildcard`      |
    /// | 3        | `ResponseIp`         |
    /// | 4        | `Nsip`               |
    /// | 5        | `NsdnameExact` / `NsdnameSuffix` |
    #[must_use]
    pub fn precedence(&self) -> u8 {
        match self {
            Self::ClientIp(_) => 0,
            Self::QnameExact(_) => 1,
            Self::QnameWildcard(_) => 2,
            Self::ResponseIp(_) => 3,
            Self::Nsip(_) => 4,
            Self::NsdnameExact(_) | Self::NsdnameSuffix(_) => 5,
        }
    }

    /// Returns a short string label for the trigger type, used in audit log events.
    #[must_use]
    pub fn type_label(&self) -> &'static str {
        match self {
            Self::ClientIp(_) => "client-ip",
            Self::QnameExact(_) => "qname-exact",
            Self::QnameWildcard(_) => "qname-wildcard",
            Self::ResponseIp(_) => "response-ip",
            Self::Nsip(_) => "nsip",
            Self::NsdnameExact(_) => "nsdname-exact",
            Self::NsdnameSuffix(_) => "nsdname-suffix",
        }
    }
}

// ── RpzEntry ──────────────────────────────────────────────────────────────────

/// One RPZ policy entry: a trigger paired with an action.
#[derive(Debug, Clone)]
pub struct RpzEntry {
    /// The condition that activates this entry.
    pub trigger: RpzTrigger,
    /// The action to take when the trigger fires.
    pub action: RpzAction,
    /// The entry's position within its policy zone (used for tie-breaking per RPZ-027).
    pub position: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cidr_v4_contains() {
        let range = CidrRange { addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), prefix_len: 16 };
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn cidr_v4_host_route() {
        let range = CidrRange { addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), prefix_len: 32 };
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5))));
    }

    #[test]
    fn cidr_v4_default_route() {
        let range = CidrRange { addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), prefix_len: 0 };
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn cidr_v6_contains() {
        let range = CidrRange {
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix_len: 32,
        };
        assert!(range.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6))));
        assert!(!range.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0))));
    }

    #[test]
    fn cidr_family_mismatch() {
        let range = CidrRange { addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), prefix_len: 16 };
        assert!(!range.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn trigger_precedence_ordering() {
        // Client-IP must be highest priority (lowest value).
        let client_ip = RpzTrigger::ClientIp(CidrRange {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_len: 32,
        });
        let qname_exact =
            RpzTrigger::QnameExact(heimdall_core::name::Name::parse_str("a.com.").unwrap());
        assert!(client_ip.precedence() < qname_exact.precedence());
    }
}
