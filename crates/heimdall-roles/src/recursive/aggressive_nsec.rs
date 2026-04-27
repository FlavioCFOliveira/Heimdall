// SPDX-License-Identifier: MIT

//! Aggressive NSEC/NSEC3 synthesis per RFC 8198 (DNSSEC-025..030).
//!
//! Rather than issuing an upstream query for every name that falls within a
//! cached NSEC/NSEC3 interval, the resolver can synthesise a negative response
//! (NXDOMAIN or NODATA) directly from cached secure NSEC/NSEC3 records.  This
//! reduces upstream load and improves latency for non-existent names.
//!
//! # Security constraints
//!
//! - Synthesis is performed only from entries with
//!   [`ValidationOutcome::Secure`].  Insecure or bogus entries are ignored
//!   (DNSSEC-026).
//! - NSEC3 opt-out (flags bit 0): when set, unsigned delegations are possible
//!   within the zone; synthesis MUST NOT be applied for NS or DS queries
//!   because a delegation NS/DS may exist even without a matching NSEC3 owner
//!   hash (DNSSEC-028).

use std::time::Instant;

use heimdall_core::dnssec::ValidationOutcome;
use heimdall_core::dnssec::synthesis::{SynthesisResult, synthesise_negative};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};

use crate::recursive::cache::RecursiveCacheClient;

// ── AggressiveResult ──────────────────────────────────────────────────────────

/// The outcome of an aggressive NSEC/NSEC3 synthesis attempt.
#[derive(Debug)]
pub enum AggressiveResult {
    /// Synthesised NXDOMAIN; the caller may return this to the client without
    /// an upstream query.
    Nxdomain {
        /// The NSEC or NSEC3 records that prove non-existence.
        nsec_proof: Vec<Record>,
    },
    /// Synthesised NODATA; the queried type is provably absent.
    Nodata {
        /// The NSEC or NSEC3 records that prove the type is absent.
        nsec_proof: Vec<Record>,
    },
    /// Synthesis is not possible from current cache contents; an upstream
    /// query is required.
    Miss,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Attempts aggressive NSEC/NSEC3 synthesis from the recursive cache.
///
/// Searches the cache for NSEC and NSEC3 `RRsets` associated with `zone_apex`
/// and calls [`synthesise_negative`] on them.
///
/// # NSEC3 opt-out (DNSSEC-028)
///
/// If any NSEC3 record in the cached set carries the opt-out flag
/// (`flags & 0x01 != 0`), synthesis is suppressed for `Rtype::Ns` and
/// `Rtype::Ds` queries.  A delegation NS/DS may exist for an unsigned
/// delegation even when no NSEC3 owner hash covers it.
///
/// # Returns
///
/// - [`AggressiveResult::Nxdomain`] — the name provably does not exist.
/// - [`AggressiveResult::Nodata`] — the name exists but the type is absent.
/// - [`AggressiveResult::Miss`] — synthesis is not possible.
pub fn try_aggressive_synthesis(
    cache: &RecursiveCacheClient,
    qname: &Name,
    qtype: Rtype,
    zone_apex: &Name,
    now: Instant,
) -> AggressiveResult {
    let nsec_records = fetch_secure_records(cache, zone_apex, Rtype::Nsec, now);
    let nsec3_records = fetch_secure_records(cache, zone_apex, Rtype::Nsec3, now);

    // No usable records in cache → immediate miss.
    if nsec_records.is_empty() && nsec3_records.is_empty() {
        return AggressiveResult::Miss;
    }

    // DNSSEC-028: opt-out check.
    // If any NSEC3 record has opt-out bit set, do not synthesise for NS or DS.
    if matches!(qtype, Rtype::Ns | Rtype::Ds) && any_nsec3_opt_out(&nsec3_records) {
        tracing::debug!(
            qname = %qname,
            qtype = ?qtype,
            zone = %zone_apex,
            "aggressive synthesis skipped: NSEC3 opt-out bit set for NS/DS query"
        );
        return AggressiveResult::Miss;
    }

    match synthesise_negative(&nsec_records, &nsec3_records, qname, qtype, zone_apex) {
        SynthesisResult::Nxdomain { nsec_proof } => {
            use heimdall_core::dnssec::synthesis::NsecOrNsec3Proof;
            let records = match nsec_proof {
                NsecOrNsec3Proof::Nsec(v) | NsecOrNsec3Proof::Nsec3(v) => v,
            };
            AggressiveResult::Nxdomain {
                nsec_proof: records,
            }
        }
        SynthesisResult::Nodata { nsec_proof } => {
            use heimdall_core::dnssec::synthesis::NsecOrNsec3Proof;
            let records = match nsec_proof {
                NsecOrNsec3Proof::Nsec(v) | NsecOrNsec3Proof::Nsec3(v) => v,
            };
            AggressiveResult::Nodata {
                nsec_proof: records,
            }
        }
        SynthesisResult::Miss => AggressiveResult::Miss,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Fetches and deserialises NSEC or NSEC3 records from the cache.
///
/// Only entries with [`ValidationOutcome::Secure`] are considered (DNSSEC-026).
/// Malformed cached wire bytes are silently dropped.
fn fetch_secure_records(
    cache: &RecursiveCacheClient,
    zone_apex: &Name,
    rtype: Rtype,
    _now: Instant,
) -> Vec<Record> {
    let Some(cached) = cache.lookup(zone_apex, rtype, 1, true) else {
        return Vec::new();
    };

    // Only trust secure entries.
    if !matches!(cached.entry.dnssec_outcome, ValidationOutcome::Secure) {
        return Vec::new();
    }

    // The cache stores a serialised minimal Message (answer section only).
    // Parse it back to extract the individual records.
    parse_records_from_wire(&cached.entry.rdata_wire, rtype)
}

/// Parses records of `expected_rtype` from wire-format message bytes.
///
/// Returns an empty `Vec` on any parse failure (treated as a cache miss for
/// synthesis purposes, without propagating corruption upstream).
fn parse_records_from_wire(wire: &[u8], expected_rtype: Rtype) -> Vec<Record> {
    if wire.is_empty() {
        return Vec::new();
    }

    let Ok(msg) = Message::parse(wire) else {
        tracing::debug!(
            "aggressive synthesis: failed to parse cached wire bytes, treating as miss"
        );
        return Vec::new();
    };

    msg.answers
        .into_iter()
        .filter(|r| r.rtype == expected_rtype)
        .collect()
}

/// Returns `true` if any NSEC3 record in the set has the opt-out flag set
/// (`flags & 0x01 != 0`).
fn any_nsec3_opt_out(nsec3_records: &[Record]) -> bool {
    nsec3_records
        .iter()
        .any(|r| matches!(&r.rdata, RData::Nsec3 { flags, .. } if flags & 0x01 != 0))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use heimdall_core::header::Qclass;
    use heimdall_core::name::Name;
    use heimdall_core::record::{Record, Rtype};
    use heimdall_runtime::cache::recursive::RecursiveCache;

    use super::*;
    use crate::recursive::cache::RecursiveCacheClient;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    fn make_cache() -> RecursiveCacheClient {
        RecursiveCacheClient::new(Arc::new(RecursiveCache::new(512, 512)))
    }

    fn make_nsec3_record(zone_apex: &Name, opt_out: bool) -> Record {
        Record {
            name: zone_apex.clone(),
            rtype: Rtype::Nsec3,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec3 {
                hash_algorithm: 1,
                flags: if opt_out { 0x01 } else { 0x00 },
                iterations: 1,
                salt: vec![0xAB, 0xCD],
                next_hashed_owner: vec![0u8; 20],
                type_bitmaps: vec![],
            },
        }
    }

    #[test]
    fn returns_miss_when_no_nsec_in_cache() {
        let cache = make_cache();
        let qname = name("noexist.example.com.");
        let apex = name("example.com.");

        let result = try_aggressive_synthesis(&cache, &qname, Rtype::A, &apex, Instant::now());
        assert!(
            matches!(result, AggressiveResult::Miss),
            "empty cache must produce Miss"
        );
    }

    #[test]
    fn opt_out_nsec3_skips_synthesis_for_ns_qtype() {
        // We cannot easily inject a secure NSEC3 entry into the cache in a unit
        // test (the store path serialises a full Message).  Instead we test the
        // opt-out guard logic directly by calling any_nsec3_opt_out.
        let apex = name("example.com.");
        let record = make_nsec3_record(&apex, true /* opt_out */);

        assert!(any_nsec3_opt_out(&[record]), "opt-out bit must be detected");
    }

    #[test]
    fn no_opt_out_bit_not_detected() {
        let apex = name("example.com.");
        let record = make_nsec3_record(&apex, false /* opt_out */);
        assert!(!any_nsec3_opt_out(&[record]));
    }

    #[test]
    fn parse_records_from_empty_wire_returns_empty() {
        let result = parse_records_from_wire(&[], Rtype::Nsec);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_records_from_malformed_wire_returns_empty() {
        let garbage = vec![0xFF, 0xFE, 0xAB, 0x00, 0x01];
        let result = parse_records_from_wire(&garbage, Rtype::Nsec);
        assert!(result.is_empty());
    }
}
