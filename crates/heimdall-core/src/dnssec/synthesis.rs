// SPDX-License-Identifier: MIT

//! Aggressive NSEC/NSEC3 synthesis (RFC 8198).
//!
//! Attempts to derive NXDOMAIN or NODATA answers from cached NSEC/NSEC3 records
//! without sending an upstream query, reducing latency and upstream load.
//!
//! Implements DNSSEC-011 (aggressive synthesis).

use crate::{
    dnssec::nsec::{
        Nsec3ProofType, NsecProofType, nsec_proves_nxdomain, nsec3_proves_nxdomain, type_in_bitmap,
    },
    name::Name,
    rdata::RData,
    record::{Record, Rtype},
};

// ── Public types ───────────────────────────────────────────────────────────────

/// The result of an aggressive NSEC/NSEC3 synthesis attempt.
///
/// Implements DNSSEC-011.
#[derive(Debug, Clone)]
pub enum SynthesisResult {
    /// The query name provably does not exist (NXDOMAIN). No upstream needed.
    Nxdomain {
        /// The NSEC or NSEC3 records that prove non-existence.
        nsec_proof: NsecOrNsec3Proof,
    },
    /// The query name exists but the query type has no records (NODATA). No upstream needed.
    Nodata {
        /// The NSEC or NSEC3 records that prove the type is absent.
        nsec_proof: NsecOrNsec3Proof,
    },
    /// Cannot derive an answer from cache; an upstream query is required.
    Miss,
}

/// A collection of NSEC or NSEC3 records that form a proof.
#[derive(Debug, Clone)]
pub enum NsecOrNsec3Proof {
    /// Proof constructed from NSEC records.
    Nsec(Vec<Record>),
    /// Proof constructed from NSEC3 records.
    Nsec3(Vec<Record>),
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Attempts to synthesise a negative response from cached NSEC/NSEC3 records,
/// without sending an upstream query (RFC 8198).
///
/// Logic (NSEC tried first, NSEC3 if NSEC provides no proof):
/// 1. NSEC direct cover → `SynthesisResult::Nxdomain`.
/// 2. NSEC NODATA: `qname` exists (NSEC owner == qname) but `qtype` is absent from bitmap.
/// 3. NSEC3 direct cover → `SynthesisResult::Nxdomain`.
/// 4. NSEC3 NODATA: owner hash matches `qname` hash but `qtype` absent from bitmap.
/// 5. Otherwise → `SynthesisResult::Miss`.
///
/// Implements DNSSEC-011.
///
/// # Arguments
///
/// * `cached_nsec` — secure NSEC records from the cache covering the zone.
/// * `cached_nsec3` — secure NSEC3 records from the cache covering the zone.
/// * `qname` — the query name being resolved.
/// * `qtype` — the query type.
/// * `zone_apex` — the zone being searched.
#[must_use]
pub fn synthesise_negative(
    cached_nsec: &[Record],
    cached_nsec3: &[Record],
    qname: &Name,
    qtype: Rtype,
    zone_apex: &Name,
) -> SynthesisResult {
    // ── 1. NSEC NXDOMAIN ─────────────────────────────────────────────────────
    if let Some(proof_type) = nsec_proves_nxdomain(cached_nsec, qname) {
        // Collect the covering records for the proof.
        let covering = collect_nsec_covering(cached_nsec, qname);
        match proof_type {
            NsecProofType::DirectCover | NsecProofType::WildcardDenial => {
                return SynthesisResult::Nxdomain {
                    nsec_proof: NsecOrNsec3Proof::Nsec(covering),
                };
            }
        }
    }

    // ── 2. NSEC NODATA ────────────────────────────────────────────────────────
    for rec in cached_nsec {
        if rec.name != *qname {
            continue;
        }
        if let RData::Nsec { type_bitmaps, .. } = &rec.rdata
            && !type_in_bitmap(type_bitmaps, qtype)
        {
            return SynthesisResult::Nodata {
                nsec_proof: NsecOrNsec3Proof::Nsec(vec![rec.clone()]),
            };
        }
    }

    // ── 3. NSEC3 NXDOMAIN ────────────────────────────────────────────────────
    if let Some(proof_type) = nsec3_proves_nxdomain(cached_nsec3, qname, zone_apex) {
        let covering = collect_nsec3_covering(cached_nsec3, qname, zone_apex);
        match proof_type {
            Nsec3ProofType::DirectCover | Nsec3ProofType::ClosestEncloserProof { .. } => {
                return SynthesisResult::Nxdomain {
                    nsec_proof: NsecOrNsec3Proof::Nsec3(covering),
                };
            }
        }
    }

    // ── 4. NSEC3 NODATA ───────────────────────────────────────────────────────
    if let Some(rec) = nsec3_nodata_match(cached_nsec3, qname, qtype) {
        return SynthesisResult::Nodata {
            nsec_proof: NsecOrNsec3Proof::Nsec3(vec![rec]),
        };
    }

    // ── 5. Miss ───────────────────────────────────────────────────────────────
    SynthesisResult::Miss
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collects NSEC records that directly cover `qname`.
fn collect_nsec_covering(nsec_records: &[Record], qname: &Name) -> Vec<Record> {
    nsec_records
        .iter()
        .filter(|r| {
            let RData::Nsec { next_domain, .. } = &r.rdata else {
                return false;
            };
            let owner = &r.name;
            let is_covering = (owner < qname && qname < next_domain)
                || (next_domain <= owner && (owner < qname || qname < next_domain));
            is_covering || qname.is_in_bailiwick(owner)
        })
        .cloned()
        .collect()
}

/// Collects NSEC3 records that participate in the proof for `qname`.
fn collect_nsec3_covering(
    nsec3_records: &[Record],
    qname: &Name,
    _zone_apex: &Name,
) -> Vec<Record> {
    use crate::dnssec::nsec::{MAX_NSEC3_ITERATIONS, nsec3_hash};

    let params = nsec3_records.iter().find_map(|r| {
        if let RData::Nsec3 {
            hash_algorithm: 1,
            iterations,
            salt,
            ..
        } = &r.rdata
            && *iterations <= MAX_NSEC3_ITERATIONS
        {
            return Some((salt.clone(), *iterations));
        }
        None
    });

    let Some((salt, iterations)) = params else {
        return Vec::new();
    };

    let qname_hash = nsec3_hash(qname, &salt, iterations);

    nsec3_records
        .iter()
        .filter(|r| {
            let RData::Nsec3 {
                next_hashed_owner,
                iterations: it,
                salt: s,
                ..
            } = &r.rdata
            else {
                return false;
            };
            if *it > MAX_NSEC3_ITERATIONS {
                return false;
            }
            if s.as_slice() != salt.as_slice() {
                return false;
            }
            // Include any record whose interval might cover qname.
            if let Some(qh) = &qname_hash {
                let owner_hash = crate::dnssec::nsec::nsec3_owner_hash_pub(r);
                let next_arr: Option<[u8; 20]> = next_hashed_owner.as_slice().try_into().ok();
                if let (Some(oh), Some(nh)) = (owner_hash, next_arr) {
                    return hash_in_interval_pub(qh, &oh, &nh);
                }
            }
            false
        })
        .cloned()
        .collect()
}

/// Finds an NSEC3 record whose owner hash matches `qname` but `qtype` is absent.
fn nsec3_nodata_match(nsec3_records: &[Record], qname: &Name, qtype: Rtype) -> Option<Record> {
    use crate::dnssec::nsec::{MAX_NSEC3_ITERATIONS, nsec3_hash};

    let params = nsec3_records.iter().find_map(|r| {
        if let RData::Nsec3 {
            hash_algorithm: 1,
            iterations,
            salt,
            ..
        } = &r.rdata
            && *iterations <= MAX_NSEC3_ITERATIONS
        {
            return Some((salt.clone(), *iterations));
        }
        None
    });

    let (salt, iterations) = params?;
    let qname_hash = nsec3_hash(qname, &salt, iterations)?;

    for rec in nsec3_records {
        let RData::Nsec3 {
            type_bitmaps,
            iterations: it,
            salt: s,
            ..
        } = &rec.rdata
        else {
            continue;
        };
        if *it > MAX_NSEC3_ITERATIONS {
            continue;
        }
        if s.as_slice() != salt.as_slice() {
            continue;
        }

        let owner_hash = crate::dnssec::nsec::nsec3_owner_hash_pub(rec)?;
        if owner_hash == qname_hash && !type_in_bitmap(type_bitmaps, qtype) {
            return Some(rec.clone());
        }
    }
    None
}

/// Re-exported interval check for synthesis.rs use.
fn hash_in_interval_pub(hash: &[u8; 20], owner: &[u8; 20], next: &[u8; 20]) -> bool {
    if next > owner {
        hash > owner && hash < next
    } else {
        hash > owner || hash < next
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        dnssec::nsec::encode_type_bitmap,
        header::Qclass,
        name::Name,
        record::{Record, Rtype},
    };

    fn make_nsec_record(owner: &str, next: &str, types: &[Rtype]) -> Record {
        Record {
            name: Name::from_str(owner).unwrap(),
            rtype: Rtype::Nsec,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec {
                next_domain: Name::from_str(next).unwrap(),
                type_bitmaps: encode_type_bitmap(types),
            },
        }
    }

    #[test]
    fn miss_when_no_records() {
        let qname = Name::from_str("foo.example.com.").unwrap();
        let apex = Name::from_str("example.com.").unwrap();
        let result = synthesise_negative(&[], &[], &qname, Rtype::A, &apex);
        assert!(matches!(result, SynthesisResult::Miss));
    }

    #[test]
    fn nsec_nxdomain_via_direct_cover() {
        // a.example. → c.example. covers b.example.
        let nsec = make_nsec_record("a.example.", "c.example.", &[Rtype::A]);
        let qname = Name::from_str("b.example.").unwrap();
        let apex = Name::from_str("example.").unwrap();
        let result = synthesise_negative(&[nsec], &[], &qname, Rtype::A, &apex);
        assert!(matches!(result, SynthesisResult::Nxdomain { .. }));
    }

    #[test]
    fn nsec_nodata_when_type_absent_from_bitmap() {
        // qname exists (NSEC owner == qname) but AAAA is not in the bitmap.
        let nsec = make_nsec_record("foo.example.", "z.example.", &[Rtype::A, Rtype::Mx]);
        let qname = Name::from_str("foo.example.").unwrap();
        let apex = Name::from_str("example.").unwrap();
        let result = synthesise_negative(&[nsec], &[], &qname, Rtype::Aaaa, &apex);
        assert!(matches!(result, SynthesisResult::Nodata { .. }));
    }

    #[test]
    fn nsec_miss_when_type_present_in_bitmap() {
        // A is in the bitmap → cannot prove NODATA for A.
        let nsec = make_nsec_record("foo.example.", "z.example.", &[Rtype::A]);
        let qname = Name::from_str("foo.example.").unwrap();
        let apex = Name::from_str("example.").unwrap();
        let result = synthesise_negative(&[nsec], &[], &qname, Rtype::A, &apex);
        assert!(matches!(result, SynthesisResult::Miss));
    }
}
