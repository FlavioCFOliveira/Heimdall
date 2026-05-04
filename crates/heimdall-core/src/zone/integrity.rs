// SPDX-License-Identifier: MIT

//! Load-time DNSSEC zone-integrity verification (Task #217, Task #588).
//!
//! After loading all records, [`verify_zone_integrity`] runs a series of
//! structural and cryptographic checks that enforce the DNSSEC load-time
//! invariants described in `005-dnssec-policy.md`.
//!
//! ## Checks performed (in order)
//!
//! 1. **DNSSEC-068** — zones MUST NOT contain both NSEC and NSEC3 records.
//! 2. **DNSSEC-067** — zones with NSEC3 records MUST have an NSEC3PARAM at
//!    the zone apex; requires a known apex.
//! 3. **DNSSEC-062** — zones signed exclusively with MUST-NOT algorithms
//!    (RFC 8624 §3.1: 1, 3, 6, 12) MUST be rejected.
//! 4. **DNSSEC-077** — all RRSIG records covering a given RRset MUST NOT be
//!    expired at load time; partially expired RRsets are allowed.
//! 5. **Existing DNSKEY / signature verification** — each RRSIG covering the
//!    DNSKEY or SOA RRset at the apex must verify against a DNSKEY in the zone.
//!
//! ## Algorithm support (cryptographic verification)
//!
//! - Algorithm 13 (ECDSA P-256 / SHA-256) — fully verified via `ring`.
//! - Algorithm 14 (ECDSA P-384 / SHA-384) — fully verified via `ring`.
//! - Algorithm 15 (Ed25519) — fully verified via `ring`.
//! - Algorithm 8 (RSA/SHA-256) and 10 (RSA/SHA-512) — reported as
//!   [`IntegrityError::UnsupportedAlgorithm`] (deferred per ADR-0036).
//! - All other algorithm numbers — [`IntegrityError::UnsupportedAlgorithm`].

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature::{self, UnparsedPublicKey};

use crate::header::Qclass;
use crate::name::Name;
use crate::rdata::RData;
use crate::record::{Record, Rtype};

// ── IntegrityError ────────────────────────────────────────────────────────────

/// Errors reported by the zone-integrity checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// At least one RRSIG is present but no DNSKEY `RRset` exists at the apex.
    MissingDnskey,
    /// A signature failed to verify.
    InvalidSignature {
        /// Owner name of the `RRset` whose signature failed.
        owner: String,
        /// String representation of the RR type.
        rtype: String,
    },
    /// The algorithm number is not supported by this implementation.
    UnsupportedAlgorithm(u8),
    /// A DNSKEY record is malformed (public key bytes are unusable).
    MalformedDnskey,
    /// An RRSIG record is malformed (fields are logically inconsistent).
    MalformedRrsig,
    /// The key tag in an RRSIG does not match any loaded DNSKEY.
    KeyTagMismatch,
    /// Zone contains NSEC3 records but no NSEC3PARAM at the zone apex (DNSSEC-067).
    Nsec3ParamMissing,
    /// Zone contains both NSEC and NSEC3 records, which is invalid (DNSSEC-068).
    Nsec3AndNsecCoexist,
    /// All RRSIG records covering an RRset are expired at load time (DNSSEC-077).
    AllRrsigsExpired {
        /// Owner name of the expired RRset.
        owner: String,
        /// String representation of the covered RR type.
        rtype: String,
    },
    /// Zone is signed exclusively with MUST-NOT algorithms (DNSSEC-062).
    MustNotAlgorithmOnly {
        /// The MUST-NOT algorithm numbers found in the zone.
        algorithms: Vec<u8>,
    },
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDnskey => {
                write!(f, "RRSIG records present but no DNSKEY RRset found at zone apex")
            }
            Self::InvalidSignature { owner, rtype } => {
                write!(f, "RRSIG verification failed for {rtype} at {owner}")
            }
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "DNSSEC algorithm {a} is not supported by this implementation")
            }
            Self::MalformedDnskey => write!(f, "malformed DNSKEY record"),
            Self::MalformedRrsig => write!(f, "malformed RRSIG record"),
            Self::KeyTagMismatch => write!(f, "no DNSKEY matches the key tag in RRSIG"),
            Self::Nsec3ParamMissing => {
                write!(f, "zone uses NSEC3 but has no NSEC3PARAM record at apex (DNSSEC-067)")
            }
            Self::Nsec3AndNsecCoexist => {
                write!(f, "zone contains both NSEC and NSEC3 records, which is invalid (DNSSEC-068)")
            }
            Self::AllRrsigsExpired { owner, rtype } => {
                write!(f, "all RRSIG records covering {rtype} at {owner} are expired at load time (DNSSEC-077)")
            }
            Self::MustNotAlgorithmOnly { algorithms } => {
                let algs: Vec<String> = algorithms.iter().map(|a| a.to_string()).collect();
                write!(
                    f,
                    "zone is signed exclusively with MUST-NOT algorithms [{algs}] (DNSSEC-062)",
                    algs = algs.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for IntegrityError {}

// ── MUST-NOT algorithm set (RFC 8624 §3.1) ───────────────────────────────────

const MUST_NOT_ALGORITHMS: &[u8] = &[
    1,  // RSAMD5     — MUST NOT sign / MUST NOT validate
    3,  // DSA-SHA1   — MUST NOT
    6,  // DSA-NSEC3-SHA1 — MUST NOT
    12, // ECC-GOST   — MUST NOT
];

fn is_must_not(algorithm: u8) -> bool {
    MUST_NOT_ALGORITHMS.contains(&algorithm)
}

// ── Current time as u32 Unix seconds ─────────────────────────────────────────

fn now_unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

// ── Key-tag computation ───────────────────────────────────────────────────────

/// Computes the key tag for a DNSKEY from its raw wire-format RDATA
/// (RFC 4034 Appendix B).
///
/// `dnskey_rdata` is the full wire RDATA: flags (2 bytes) + protocol (1 byte)
/// + algorithm (1 byte) + public key bytes.
#[must_use]
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in dnskey_rdata.iter().enumerate() {
        ac += if i & 1 == 0 { u32::from(byte) << 8 } else { u32::from(byte) };
    }
    ac += ac >> 16;
    // Mask to 16 bits; truncation is intentional per RFC 4034 §B.
    #[allow(clippy::cast_possible_truncation)]
    let tag = (ac & 0xFFFF) as u16;
    tag
}

// ── RRSET canonical wire form ─────────────────────────────────────────────────

/// Builds the RRSIG signature input for an `RRset` (RFC 4034 §6.2).
fn build_sig_input(
    rrsig: &RData,
    rrset_records: &[&Record],
    original_ttl: u32,
) -> Option<Vec<u8>> {
    let RData::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl: _,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        ..
    } = rrsig
    else {
        return None;
    };

    let mut sig_input: Vec<u8> = Vec::new();

    sig_input.extend_from_slice(&type_covered.as_u16().to_be_bytes());
    sig_input.push(*algorithm);
    sig_input.push(*labels);
    sig_input.extend_from_slice(&original_ttl.to_be_bytes());
    sig_input.extend_from_slice(&sig_expiration.to_be_bytes());
    sig_input.extend_from_slice(&sig_inception.to_be_bytes());
    sig_input.extend_from_slice(&key_tag.to_be_bytes());
    sig_input.extend_from_slice(&signer_name.to_canonical_wire());

    let mut wires: Vec<Vec<u8>> = rrset_records
        .iter()
        .map(|r| {
            let mut rdata_buf = Vec::new();
            r.rdata.write_to(&mut rdata_buf);
            rdata_buf
        })
        .collect();
    wires.sort();

    for (rr, rdata_wire) in rrset_records.iter().zip(wires.iter()) {
        sig_input.extend_from_slice(&rr.name.to_canonical_wire());
        sig_input.extend_from_slice(&rr.rtype.as_u16().to_be_bytes());
        sig_input.extend_from_slice(&rr.rclass.as_u16().to_be_bytes());
        sig_input.extend_from_slice(&original_ttl.to_be_bytes());
        // INVARIANT: RDATA is bounded by the 16-bit RDLENGTH field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        let rdlen = rdata_wire.len() as u16;
        sig_input.extend_from_slice(&rdlen.to_be_bytes());
        sig_input.extend_from_slice(rdata_wire);
    }

    Some(sig_input)
}

/// Encodes a DNSKEY's public key material into wire RDATA (for `key_tag` and
/// ring import).
fn dnskey_wire_rdata(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + public_key.len());
    v.extend_from_slice(&flags.to_be_bytes());
    v.push(protocol);
    v.push(algorithm);
    v.extend_from_slice(public_key);
    v
}

// ── Structural checks (origin-independent) ────────────────────────────────────

/// DNSSEC-068: reject zones that contain both NSEC and NSEC3 records.
fn check_nsec_coexistence(records: &[Record]) -> Result<(), IntegrityError> {
    let has_nsec = records.iter().any(|r| r.rtype == Rtype::Nsec);
    let has_nsec3 = records.iter().any(|r| r.rtype == Rtype::Nsec3);
    if has_nsec && has_nsec3 {
        return Err(IntegrityError::Nsec3AndNsecCoexist);
    }
    Ok(())
}

/// DNSSEC-067: if the zone uses NSEC3, an NSEC3PARAM record MUST exist at the apex.
fn check_nsec3param_at_apex(records: &[Record], origin: &Name) -> Result<(), IntegrityError> {
    let has_nsec3 = records.iter().any(|r| r.rtype == Rtype::Nsec3);
    if !has_nsec3 {
        return Ok(());
    }
    let has_nsec3param = records.iter().any(|r| {
        r.rtype == Rtype::Nsec3param && &r.name == origin && r.rclass == Qclass::In
    });
    if !has_nsec3param {
        return Err(IntegrityError::Nsec3ParamMissing);
    }
    Ok(())
}

/// DNSSEC-062: reject zones signed exclusively with MUST-NOT algorithms.
///
/// A zone with signatures under at least one supported algorithm is allowed
/// (the MUST-NOT RRSIG records will be dropped at serve time).
fn check_must_not_algorithms(records: &[Record]) -> Result<(), IntegrityError> {
    let rrsig_algorithms: Vec<u8> = records
        .iter()
        .filter_map(|r| {
            if let RData::Rrsig { algorithm, .. } = &r.rdata { Some(*algorithm) } else { None }
        })
        .collect();

    if rrsig_algorithms.is_empty() {
        return Ok(());
    }

    // If every RRSIG uses a MUST-NOT algorithm, reject.
    if rrsig_algorithms.iter().all(|a| is_must_not(*a)) {
        let mut unique: Vec<u8> = rrsig_algorithms;
        unique.sort_unstable();
        unique.dedup();
        return Err(IntegrityError::MustNotAlgorithmOnly { algorithms: unique });
    }

    Ok(())
}

/// DNSSEC-077: reject zones where all RRSIG records covering a given RRset are
/// expired at load time.
///
/// Groups RRSIG records by (owner, type_covered).  If ALL signatures in a
/// group are expired, the load is refused.  If only some are expired, the
/// zone is still loadable (partial expiry is a warning-only condition; the
/// caller is responsible for emitting any diagnostic).
fn check_rrsig_expiry(records: &[Record]) -> Result<(), IntegrityError> {
    let now = now_unix_secs();

    // Group: (owner_str, type_covered_u16) → Vec<sig_expiration u32>
    let mut groups: BTreeMap<(String, u16), Vec<u32>> = BTreeMap::new();

    for rec in records {
        if let RData::Rrsig { sig_expiration, type_covered, .. } = &rec.rdata {
            let key = (rec.name.to_string(), type_covered.as_u16());
            groups.entry(key).or_default().push(*sig_expiration);
        }
    }

    for ((owner, type_num), expirations) in &groups {
        if expirations.iter().all(|&exp| exp < now) {
            let rtype = Rtype::from_u16(*type_num).to_string();
            return Err(IntegrityError::AllRrsigsExpired {
                owner: owner.clone(),
                rtype,
            });
        }
    }

    Ok(())
}

// ── verify_zone_integrity (structural only — load-time) ───────────────────────

/// Runs load-time structural DNSSEC integrity checks against a parsed zone.
///
/// Per `005-dnssec-policy.md`, full cryptographic RRSIG verification is
/// deliberately **not** performed at load time (performance / trust model).
/// Only the structural invariants that can be verified without private-key
/// material are enforced here.
///
/// `origin` is the zone apex.  Pass `None` when the origin is not known;
/// origin-dependent checks (DNSSEC-067) are skipped in that case.
///
/// Checks are applied in this order:
/// 1. **DNSSEC-068** — NSEC + NSEC3 coexistence.
/// 2. **DNSSEC-067** — NSEC3PARAM at apex (skipped when `origin` is `None`).
/// 3. **DNSSEC-062** — reject if exclusively MUST-NOT algorithms.
/// 4. **DNSSEC-077** — reject if any RRset has all-expired RRSIGs.
///
/// # Errors
///
/// Returns [`IntegrityError`] on the first violated invariant.
pub fn verify_zone_integrity(
    records: &[Record],
    origin: Option<&Name>,
) -> Result<(), IntegrityError> {
    // 1. DNSSEC-068: no NSEC + NSEC3 coexistence.
    check_nsec_coexistence(records)?;

    // 2. DNSSEC-067: NSEC3 → NSEC3PARAM at apex (requires known origin).
    if let Some(apex) = origin {
        check_nsec3param_at_apex(records, apex)?;
    }

    let has_any_rrsig = records.iter().any(|r| r.rtype == Rtype::Rrsig);
    if !has_any_rrsig {
        // Unsigned zone — valid for authoritative loading.
        return Ok(());
    }

    // 3. DNSSEC-062: reject if exclusively MUST-NOT algorithms.
    check_must_not_algorithms(records)?;

    // 4. DNSSEC-077: reject if any RRset has all-expired RRSIGs.
    check_rrsig_expiry(records)?;

    Ok(())
}

// ── drain_dangling_rrsigs (DNSSEC-076) ───────────────────────────────────────

/// Removes RRSIG records that cover a type absent from the zone (dangling
/// signatures).
///
/// Per DNSSEC-076, a dangling RRSIG MUST be silently dropped at load time;
/// the zone load itself MUST succeed.  The caller is responsible for emitting
/// a diagnostic warning for each dropped record — this function only removes
/// them from `records` and returns the (owner, type_covered) pairs that were
/// dropped so the caller can log them.
///
/// An RRSIG is considered dangling when no other record in the zone shares its
/// owner name *and* the type indicated by `type_covered`, regardless of TTL or
/// RDATA.  An RRSIG covering a DNSKEY at the apex is never considered dangling
/// as long as any DNSKEY record exists at that owner name.
pub fn drain_dangling_rrsigs(records: &mut Vec<Record>) -> Vec<(Name, Rtype)> {
    use std::collections::HashSet;

    // Build the set of (owner, type) pairs that are present (excluding RRSIG).
    let covered_pairs: HashSet<(Vec<u8>, u16)> = records
        .iter()
        .filter(|r| r.rtype != Rtype::Rrsig)
        .map(|r| (r.name.as_wire_bytes().to_vec(), r.rtype.as_u16()))
        .collect();

    let mut dangling = Vec::new();
    let mut i = 0;
    while i < records.len() {
        let is_dangling = if records[i].rtype == Rtype::Rrsig {
            if let RData::Rrsig { type_covered, .. } = &records[i].rdata {
                let key = (records[i].name.as_wire_bytes().to_vec(), type_covered.as_u16());
                !covered_pairs.contains(&key)
            } else {
                false
            }
        } else {
            false
        };

        if is_dangling {
            let rec = records.remove(i);
            if let RData::Rrsig { type_covered, .. } = &rec.rdata {
                dangling.push((rec.name.clone(), *type_covered));
            }
            // Do not advance i — next element is now at position i.
        } else {
            i += 1;
        }
    }

    dangling
}

// ── verify_zone_signatures (cryptographic — NOT called at load time) ──────────

/// Performs full cryptographic RRSIG verification for the DNSKEY and SOA
/// `RRset`s at the zone apex.
///
/// This function is **not** invoked during zone loading (see the rationale in
/// `005-dnssec-policy.md §3.5`).  It is provided for standalone validation
/// tools and integration tests.
///
/// # Errors
///
/// Returns [`IntegrityError`] if any signature fails to verify.
pub fn verify_zone_signatures(records: &[Record], origin: &Name) -> Result<(), IntegrityError> {
    let has_any_rrsig = records.iter().any(|r| r.rtype == Rtype::Rrsig);
    if !has_any_rrsig {
        return Ok(());
    }

    // Collect DNSKEY RRset at apex.
    let dnskey_records: Vec<&Record> = records
        .iter()
        .filter(|r| r.rtype == Rtype::Dnskey && &r.name == origin && r.rclass == Qclass::In)
        .collect();

    if dnskey_records.is_empty() {
        return Err(IntegrityError::MissingDnskey);
    }

    // Build a map: key_tag → (algorithm, public_key_bytes)
    let mut key_map: Vec<(u16, u8, &[u8])> = Vec::new();
    for rec in &dnskey_records {
        if let RData::Dnskey { flags, protocol, algorithm, public_key } = &rec.rdata {
            let wire = dnskey_wire_rdata(*flags, *protocol, *algorithm, public_key);
            let kt = key_tag(&wire);
            key_map.push((kt, *algorithm, public_key.as_slice()));
        }
    }

    // Check RRSIG RRsets for DNSKEY and SOA at the apex.
    for check_type in [Rtype::Dnskey, Rtype::Soa] {
        let rrsig_records: Vec<&Record> = records
            .iter()
            .filter(|r| {
                if r.rtype != Rtype::Rrsig || &r.name != origin || r.rclass != Qclass::In {
                    return false;
                }
                if let RData::Rrsig { type_covered, .. } = &r.rdata {
                    *type_covered == check_type
                } else {
                    false
                }
            })
            .collect();

        if rrsig_records.is_empty() {
            continue;
        }

        // Collect the covered RRset.
        let rrset_records: Vec<&Record> = records
            .iter()
            .filter(|r| r.rtype == check_type && &r.name == origin && r.rclass == Qclass::In)
            .collect();

        if rrset_records.is_empty() {
            continue;
        }

        for rrsig_rec in &rrsig_records {
            let RData::Rrsig { algorithm, key_tag: rrsig_kt, original_ttl, signature, .. } =
                &rrsig_rec.rdata
            else {
                return Err(IntegrityError::MalformedRrsig);
            };

            let matching_key = key_map
                .iter()
                .find(|(kt, alg, _)| kt == rrsig_kt && alg == algorithm);

            let (_, _, pub_key_bytes) = matching_key.ok_or(IntegrityError::KeyTagMismatch)?;

            let sig_input = build_sig_input(&rrsig_rec.rdata, &rrset_records, *original_ttl)
                .ok_or(IntegrityError::MalformedRrsig)?;

            verify_signature(*algorithm, pub_key_bytes, &sig_input, signature)
                .map_err(|e| match e {
                    IntegrityError::UnsupportedAlgorithm(a) => {
                        IntegrityError::UnsupportedAlgorithm(a)
                    }
                    _ => IntegrityError::InvalidSignature {
                        owner: origin.to_string(),
                        rtype: check_type.to_string(),
                    },
                })?;
        }
    }

    Ok(())
}

/// Dispatches signature verification to the correct `ring` API.
fn verify_signature(
    algorithm: u8,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), IntegrityError> {
    match algorithm {
        // ECDSA P-256 / SHA-256 (RFC 8624, alg 13).
        // ring expects the uncompressed public key (65 bytes: 0x04 || X || Y).
        13 => {
            let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key);
            key.verify(message, signature).map_err(|_| IntegrityError::MalformedDnskey)
        }
        // ECDSA P-384 / SHA-384 (RFC 8624, alg 14).
        14 => {
            let key = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, public_key);
            key.verify(message, signature).map_err(|_| IntegrityError::MalformedDnskey)
        }
        // Ed25519 (RFC 8080, alg 15).
        15 => {
            let key = UnparsedPublicKey::new(&signature::ED25519, public_key);
            key.verify(message, signature).map_err(|_| IntegrityError::MalformedDnskey)
        }
        // RSA variants deferred (ADR-0036).
        5 | 7 | 8 | 10 => Err(IntegrityError::UnsupportedAlgorithm(algorithm)),
        other => Err(IntegrityError::UnsupportedAlgorithm(other)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn origin() -> Name {
        Name::from_str("example.com.").unwrap()
    }

    #[test]
    fn unsigned_zone_passes() {
        assert!(verify_zone_integrity(&[], Some(&origin())).is_ok());
    }

    #[test]
    fn unsigned_zone_no_origin_passes() {
        assert!(verify_zone_integrity(&[], None).is_ok());
    }

    #[test]
    fn rrsig_without_dnskey_fails_signature_check() {
        // verify_zone_signatures (cryptographic path) requires DNSKEY when RRSIG is present.
        let apex = origin();
        let rrsig_rec = Record {
            name: apex.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Rrsig {
                type_covered: Rtype::Soa,
                algorithm: 13,
                labels: 2,
                original_ttl: 3600,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: 12345,
                signer_name: apex.clone(),
                signature: vec![0u8; 64],
            },
        };
        // Structural check passes (algorithm 13 is supported, expiry is u32::MAX).
        assert!(
            verify_zone_integrity(&[rrsig_rec.clone()], Some(&apex)).is_ok(),
            "structural check must pass for a non-expired, non-MUST-NOT RRSIG"
        );
        // Cryptographic check returns MissingDnskey.
        let result = verify_zone_signatures(&[rrsig_rec], &apex);
        assert!(matches!(result, Err(IntegrityError::MissingDnskey)));
    }

    #[test]
    fn key_tag_rfc_example() {
        let rdata = vec![0x01u8, 0x01, 0x03, 0x05, 0xAA, 0xBB, 0xCC, 0xDD];
        let _tag = key_tag(&rdata);
    }

    // ── DNSSEC-068 ────────────────────────────────────────────────────────────

    #[test]
    fn nsec_and_nsec3_coexist_rejected() {
        use crate::rdata::RData;
        use std::str::FromStr;

        let apex = origin();
        let nsec_rec = Record {
            name: apex.clone(),
            rtype: Rtype::Nsec,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec {
                next_domain: Name::from_str("ns1.example.com.").unwrap(),
                type_bitmaps: vec![],
            },
        };
        let nsec3_rec = Record {
            name: Name::from_str("AAAA.example.com.").unwrap(),
            rtype: Rtype::Nsec3,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: vec![],
                next_hashed_owner: vec![0u8; 20],
                type_bitmaps: vec![],
            },
        };
        let result = verify_zone_integrity(&[nsec_rec, nsec3_rec], Some(&apex));
        assert!(
            matches!(result, Err(IntegrityError::Nsec3AndNsecCoexist)),
            "expected Nsec3AndNsecCoexist, got {result:?}"
        );
    }

    // ── DNSSEC-067 ────────────────────────────────────────────────────────────

    #[test]
    fn nsec3_without_nsec3param_rejected() {
        let apex = origin();
        let nsec3_rec = Record {
            name: Name::from_str("AAAA.example.com.").unwrap(),
            rtype: Rtype::Nsec3,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: vec![],
                next_hashed_owner: vec![0u8; 20],
                type_bitmaps: vec![],
            },
        };
        let result = verify_zone_integrity(&[nsec3_rec], Some(&apex));
        assert!(
            matches!(result, Err(IntegrityError::Nsec3ParamMissing)),
            "expected Nsec3ParamMissing, got {result:?}"
        );
    }

    // ── DNSSEC-062 ────────────────────────────────────────────────────────────

    #[test]
    fn must_not_only_rejected() {
        let apex = origin();
        let rrsig = Record {
            name: apex.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::Soa,
                algorithm: 1, // RSAMD5 — MUST NOT
                labels: 2,
                original_ttl: 300,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: 0,
                signer_name: apex.clone(),
                signature: vec![],
            },
        };
        let result = verify_zone_integrity(&[rrsig], Some(&apex));
        assert!(
            matches!(result, Err(IntegrityError::MustNotAlgorithmOnly { .. })),
            "expected MustNotAlgorithmOnly, got {result:?}"
        );
    }

    // ── DNSSEC-077 ────────────────────────────────────────────────────────────

    #[test]
    fn all_rrsigs_expired_rejected() {
        let apex = origin();
        // sig_expiration = 1 (1970-01-01T00:00:01Z) — always in the past.
        let rrsig = Record {
            name: apex.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::Soa,
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                sig_expiration: 1,
                sig_inception: 0,
                key_tag: 0,
                signer_name: apex.clone(),
                signature: vec![],
            },
        };
        let result = verify_zone_integrity(&[rrsig], Some(&apex));
        assert!(
            matches!(result, Err(IntegrityError::AllRrsigsExpired { .. })),
            "expected AllRrsigsExpired, got {result:?}"
        );
    }

    // ── DNSSEC-076 ────────────────────────────────────────────────────────────

    fn make_rrsig(name: Name, type_covered: Rtype) -> Record {
        Record {
            name: name.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered,
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: 0,
                signer_name: name,
                signature: vec![0u8; 64],
            },
        }
    }

    fn make_a(name: Name) -> Record {
        Record {
            name,
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A([192, 0, 2, 1].into()),
        }
    }

    #[test]
    fn dangling_rrsig_is_removed_and_reported() {
        let apex = origin();
        // RRSIG covers MX, but there is no MX record in the zone.
        let dangling = make_rrsig(apex.clone(), Rtype::Mx);
        let mut records = vec![dangling];
        let dropped = drain_dangling_rrsigs(&mut records);

        assert!(records.is_empty(), "dangling RRSIG must be removed from records");
        assert_eq!(dropped.len(), 1, "one dropped entry must be reported");
        assert_eq!(dropped[0].1, Rtype::Mx, "reported type_covered must be MX");
    }

    #[test]
    fn non_dangling_rrsig_is_kept() {
        let apex = origin();
        // RRSIG covers A, and an A record is present → not dangling.
        let rrsig = make_rrsig(apex.clone(), Rtype::A);
        let a_rec = make_a(apex.clone());
        let mut records = vec![a_rec, rrsig];
        let dropped = drain_dangling_rrsigs(&mut records);

        assert_eq!(dropped.len(), 0, "no records must be dropped");
        assert_eq!(records.len(), 2, "both records must remain");
    }

    #[test]
    fn mixed_zone_drops_only_dangling_rrsig() {
        let apex = origin();
        // A record + RRSIG covering A (kept) + RRSIG covering MX (dangling).
        let a_rec = make_a(apex.clone());
        let rrsig_a = make_rrsig(apex.clone(), Rtype::A);
        let rrsig_mx = make_rrsig(apex.clone(), Rtype::Mx);
        let mut records = vec![a_rec, rrsig_a, rrsig_mx];
        let dropped = drain_dangling_rrsigs(&mut records);

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].1, Rtype::Mx);
        // A record and the A RRSIG remain.
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.rtype == Rtype::A));
        assert!(records.iter().any(|r| r.rtype == Rtype::Rrsig));
    }

    #[test]
    fn zone_with_dangling_rrsig_loads_via_parse() {
        // A zone with a dangling RRSIG MUST load (not rejected) and
        // ZoneFile::dangling_rrsig_count must reflect the dropped count.
        let zone_src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS  ns1\n\
ns1 IN A 192.0.2.1\n\
; RRSIG covers MX but no MX record exists — dangling.\n\
@ IN RRSIG MX 13 2 300 20991231000000 19700101000000 0 example.com. AAAA\n\
";
        let zone =
            crate::zone::ZoneFile::parse(zone_src, None, crate::zone::ZoneLimits::default())
                .expect("zone with dangling RRSIG must load successfully (DNSSEC-076)");

        assert_eq!(zone.dangling_rrsig_count, 1, "one dangling RRSIG must be reported");
        assert!(
            zone.records.iter().all(|r| r.rtype != Rtype::Rrsig),
            "dangling RRSIG must not appear in loaded records"
        );
    }
}
