// SPDX-License-Identifier: MIT

//! Glue-record handling per RFC 9471 (PROTO-050..054).
//!
//! Glue records are A/AAAA records in the Additional section of a referral
//! response that allow the resolver to contact the newly-delegated nameserver
//! without first resolving its address.  They are _hints_, not authoritative
//! data: only in-bailiwick glue is accepted; out-of-bailiwick glue is silently
//! discarded to prevent cache poisoning (PROTO-051).
//!
//! # Bailiwick definition
//!
//! A glue record is in-bailiwick for a child zone if its owner name is at or
//! below the child zone apex (i.e. `owner.is_in_bailiwick(child_zone)`).
//!
//! # Glue as hint only (PROTO-052)
//!
//! Addresses obtained from glue are used to bootstrap the next iterative query
//! but must be validated against authoritative data before being treated as
//! final answers (PROTO-053).

use std::net::IpAddr;

use heimdall_core::{name::Name, parser::Message, rdata::RData, record::Rtype};

// ── ValidatedNs ───────────────────────────────────────────────────────────────

/// A nameserver extracted from a referral, together with any in-bailiwick
/// glue addresses found in the referral's Additional section.
#[derive(Debug, Clone)]
pub struct ValidatedNs {
    /// The nameserver name (the RDATA of the NS record).
    pub name: Name,
    /// In-bailiwick glue addresses for this nameserver.
    ///
    /// Empty when the nameserver's address is out-of-bailiwick (requires a
    /// separate sub-resolution to obtain a usable address).
    pub addrs: Vec<IpAddr>,
    /// `true` when at least one address was obtained from in-bailiwick glue in
    /// the referral's Additional section.
    pub from_glue: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Extracts and validates glue records from a referral response.
///
/// # Bailiwick enforcement (PROTO-051)
///
/// Only A and AAAA records whose owner name is at or below `child_zone` are
/// accepted.  Records outside the bailiwick are discarded with a
/// [`tracing::debug`] event so that operators can diagnose delegation issues.
///
/// # Glue as hint only (PROTO-052)
///
/// Addresses returned here are bootstrap hints only.  Callers must treat them
/// as such and not assume they are authoritative.
///
/// # Returns
///
/// One [`ValidatedNs`] entry per NS record in `referral`'s authority section.
/// Each entry's `addrs` list contains only in-bailiwick glue IPs.  If no glue
/// is available for an NS, `addrs` is empty and `from_glue` is `false`.
#[must_use]
pub fn extract_glue(referral: &Message, child_zone: &Name) -> Vec<ValidatedNs> {
    // Collect NS targets from the authority section.
    let ns_names: Vec<Name> = referral
        .authority
        .iter()
        .filter(|r| r.rtype == Rtype::Ns)
        .filter_map(|r| {
            if let RData::Ns(target) = &r.rdata {
                Some(target.clone())
            } else {
                None
            }
        })
        .collect();

    if ns_names.is_empty() {
        return Vec::new();
    }

    // For each NS, collect in-bailiwick A/AAAA glue from the Additional section.
    ns_names
        .into_iter()
        .map(|ns_name| {
            let addrs: Vec<IpAddr> = referral
                .additional
                .iter()
                .filter(|r| {
                    // Must be A or AAAA.
                    if !matches!(r.rtype, Rtype::A | Rtype::Aaaa) {
                        return false;
                    }
                    // Must belong to this NS target.
                    if r.name != ns_name {
                        return false;
                    }
                    // Bailiwick check (PROTO-051).
                    if !is_in_bailiwick(&r.name, child_zone) {
                        tracing::debug!(
                            owner = %r.name,
                            child_zone = %child_zone,
                            ns = %ns_name,
                            "dropping out-of-bailiwick glue record"
                        );
                        return false;
                    }
                    true
                })
                .filter_map(|r| match &r.rdata {
                    RData::A(a) => Some(IpAddr::V4(*a)),
                    RData::Aaaa(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                })
                .collect();

            let from_glue = !addrs.is_empty();
            ValidatedNs {
                name: ns_name,
                addrs,
                from_glue,
            }
        })
        .collect()
}

/// Returns `true` if `owner` is in-bailiwick for `child_zone`.
///
/// "In-bailiwick" means `owner == child_zone` or `owner` has `child_zone` as a
/// suffix of its labels (i.e. `owner` is a subdomain of `child_zone`).
///
/// Comparison is case-insensitive per RFC 4343.
#[must_use]
pub fn is_in_bailiwick(owner: &Name, child_zone: &Name) -> bool {
    owner.is_in_bailiwick(child_zone)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use heimdall_core::{
        header::{Header, Qclass},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
    };

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    fn empty_msg() -> Message {
        Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn ns_record(zone: &Name, ns_target: &Name) -> Record {
        Record {
            name: zone.clone(),
            rtype: Rtype::Ns,
            rclass: Qclass::In,
            ttl: 172_800,
            rdata: RData::Ns(ns_target.clone()),
        }
    }

    fn a_record(owner: &Name, ip: Ipv4Addr) -> Record {
        Record {
            name: owner.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 172_800,
            rdata: RData::A(ip),
        }
    }

    // ── is_in_bailiwick tests ──────────────────────────────────────────────────

    #[test]
    fn in_bailiwick_subdomain() {
        assert!(is_in_bailiwick(
            &name("a.example.com."),
            &name("example.com.")
        ));
    }

    #[test]
    fn in_bailiwick_equal() {
        assert!(is_in_bailiwick(
            &name("example.com."),
            &name("example.com.")
        ));
    }

    #[test]
    fn not_in_bailiwick_different_tld() {
        assert!(!is_in_bailiwick(&name("evil.com."), &name("example.com.")));
    }

    #[test]
    fn not_in_bailiwick_sibling() {
        assert!(!is_in_bailiwick(
            &name("other.example.com."),
            &name("ns.example.com.")
        ));
    }

    // ── extract_glue tests ─────────────────────────────────────────────────────

    #[test]
    fn out_of_bailiwick_glue_discarded() {
        let child_zone = name("example.com.");
        let ns_name = name("ns.evil.com."); // out-of-bailiwick
        let mut msg = empty_msg();
        msg.authority.push(ns_record(&child_zone, &ns_name));
        msg.additional
            .push(a_record(&ns_name, Ipv4Addr::new(1, 2, 3, 4)));

        let result = extract_glue(&msg, &child_zone);
        assert_eq!(result.len(), 1, "one NS entry expected");
        assert!(
            result[0].addrs.is_empty(),
            "out-of-bailiwick glue must be discarded; addrs must be empty"
        );
        assert!(!result[0].from_glue);
    }

    #[test]
    fn in_bailiwick_glue_extracted() {
        let child_zone = name("example.com.");
        let ns_name = name("ns.example.com."); // in-bailiwick
        let expected_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut msg = empty_msg();
        msg.authority.push(ns_record(&child_zone, &ns_name));
        msg.additional.push(a_record(&ns_name, expected_ip));

        let result = extract_glue(&msg, &child_zone);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].addrs, vec![IpAddr::V4(expected_ip)]);
        assert!(result[0].from_glue);
    }

    #[test]
    fn no_authority_records_returns_empty() {
        let child_zone = name("example.com.");
        let msg = empty_msg();
        let result = extract_glue(&msg, &child_zone);
        assert!(result.is_empty());
    }

    #[test]
    fn multiple_ns_with_mixed_glue() {
        let child_zone = name("example.com.");
        let ns1 = name("ns1.example.com."); // in-bailiwick
        let ns2 = name("ns2.evil.org."); // out-of-bailiwick
        let ip1 = Ipv4Addr::new(10, 0, 0, 1);
        let ip2 = Ipv4Addr::new(192, 168, 1, 1);

        let mut msg = empty_msg();
        msg.authority.push(ns_record(&child_zone, &ns1));
        msg.authority.push(ns_record(&child_zone, &ns2));
        msg.additional.push(a_record(&ns1, ip1));
        msg.additional.push(a_record(&ns2, ip2));

        let result = extract_glue(&msg, &child_zone);
        assert_eq!(result.len(), 2);

        let ns1_entry = result
            .iter()
            .find(|e| e.name == ns1)
            .expect("ns1 must be present");
        assert_eq!(ns1_entry.addrs, vec![IpAddr::V4(ip1)]);
        assert!(ns1_entry.from_glue);

        let ns2_entry = result
            .iter()
            .find(|e| e.name == ns2)
            .expect("ns2 must be present");
        assert!(
            ns2_entry.addrs.is_empty(),
            "out-of-bailiwick ns2 glue must be discarded"
        );
        assert!(!ns2_entry.from_glue);
    }
}
