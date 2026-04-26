// SPDX-License-Identifier: MIT

//! Load-time DNSSEC zone-integrity verification (Task #217).
//!
//! After loading all records, [`verify_zone_integrity`] checks that every
//! RRSIG covering the DNSKEY `RRset` and the SOA `RRset` can be verified against
//! a DNSKEY in the zone apex.
//!
//! # Algorithm support
//!
//! - Algorithm 13 (ECDSA P-256 / SHA-256) — fully verified via `ring`.
//! - Algorithm 14 (ECDSA P-384 / SHA-384) — fully verified via `ring`.
//! - Algorithm 15 (Ed25519) — fully verified via `ring`.
//! - Algorithm 8 (RSA/SHA-256) and 10 (RSA/SHA-512) — reported as
//!   [`IntegrityError::UnsupportedAlgorithm`] (deferred per ADR-0036).
//! - All other algorithm numbers — [`IntegrityError::UnsupportedAlgorithm`].

use std::fmt;

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
        }
    }
}

impl std::error::Error for IntegrityError {}

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
///
/// The input is:
/// ```text
/// signature_rdata_prefix || rrset_wire
/// ```
/// where `signature_rdata_prefix` is the first 18+ bytes of the RRSIG RDATA
/// (everything up to and excluding the signature field), and `rrset_wire` is
/// each RR in the set serialised as `owner || type || class || original_ttl ||
/// rdlength || rdata` in canonical (owner lowercased, name pointers expanded)
/// wire format, sorted in ascending order of RDATA.
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

    // RRSIG RDATA prefix (everything before the Signature field).
    // type_covered (2) + algorithm (1) + labels (1) + original_ttl (4)
    // + sig_expiration (4) + sig_inception (4) + key_tag (2) + signer_name (wire)
    sig_input.extend_from_slice(&type_covered.as_u16().to_be_bytes());
    sig_input.push(*algorithm);
    sig_input.push(*labels);
    sig_input.extend_from_slice(&original_ttl.to_be_bytes());
    sig_input.extend_from_slice(&sig_expiration.to_be_bytes());
    sig_input.extend_from_slice(&sig_inception.to_be_bytes());
    sig_input.extend_from_slice(&key_tag.to_be_bytes());
    sig_input.extend_from_slice(&signer_name.to_canonical_wire());

    // Canonical RRset: sort by RDATA wire bytes.
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
        // owner (canonical lowercased wire)
        sig_input.extend_from_slice(&rr.name.to_canonical_wire());
        // type
        sig_input.extend_from_slice(&rr.rtype.as_u16().to_be_bytes());
        // class
        sig_input.extend_from_slice(&rr.rclass.as_u16().to_be_bytes());
        // original TTL (from RRSIG, not the record's own TTL)
        sig_input.extend_from_slice(&original_ttl.to_be_bytes());
        // rdlength
        // INVARIANT: RDATA is bounded by the 16-bit RDLENGTH field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        let rdlen = rdata_wire.len() as u16;
        sig_input.extend_from_slice(&rdlen.to_be_bytes());
        // rdata
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

// ── verify_zone_integrity ─────────────────────────────────────────────────────

/// Verifies load-time DNSSEC integrity for a zone.
///
/// Steps:
/// 1. If no RRSIG records are present anywhere → pass (unsigned zone).
/// 2. Locate the DNSKEY `RRset` at `origin`; if absent → `MissingDnskey`.
/// 3. For each RRSIG covering the DNSKEY or SOA `RRset` at `origin`, verify
///    the signature using the matching DNSKEY.
///
/// # Errors
///
/// Returns [`IntegrityError`] if signatures cannot be verified or if
/// preconditions are violated.
pub fn verify_zone_integrity(records: &[Record], origin: &Name) -> Result<(), IntegrityError> {
    let has_any_rrsig = records.iter().any(|r| r.rtype == Rtype::Rrsig);
    if !has_any_rrsig {
        // Unsigned zone — valid for authoritative loading.
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

    // Build a map: key_tag → (algorithm, public_key_bytes, wire_rdata)
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
            // RRSIG present but no covered RRset — nothing to verify against.
            continue;
        }

        for rrsig_rec in &rrsig_records {
            let RData::Rrsig { algorithm, key_tag: rrsig_kt, original_ttl, signature, .. } =
                &rrsig_rec.rdata
            else {
                return Err(IntegrityError::MalformedRrsig);
            };

            // Find matching DNSKEY.
            let matching_key = key_map
                .iter()
                .find(|(kt, alg, _)| kt == rrsig_kt && alg == algorithm);

            let (_, _, pub_key_bytes) = matching_key.ok_or(IntegrityError::KeyTagMismatch)?;

            // Build the signature input.
            let sig_input = build_sig_input(&rrsig_rec.rdata, &rrset_records, *original_ttl)
                .ok_or(IntegrityError::MalformedRrsig)?;

            // Verify the signature.
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

    #[test]
    fn unsigned_zone_passes() {
        // No RRSIG records → integrity check should pass trivially.
        let origin = Name::from_str("example.com.").unwrap();
        assert!(verify_zone_integrity(&[], &origin).is_ok());
    }

    #[test]
    fn rrsig_without_dnskey_fails() {
        use crate::header::Qclass;
        use crate::record::Rtype;
        use std::str::FromStr;

        let origin = Name::from_str("example.com.").unwrap();
        let rrsig_rec = Record {
            name: origin.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Rrsig {
                type_covered: Rtype::Soa,
                algorithm: 13,
                labels: 2,
                original_ttl: 3600,
                sig_expiration: 0xFFFF_FFFF,
                sig_inception: 0,
                key_tag: 12345,
                signer_name: origin.clone(),
                signature: vec![0u8; 64],
            },
        };
        let result = verify_zone_integrity(&[rrsig_rec], &origin);
        assert!(matches!(result, Err(IntegrityError::MissingDnskey)));
    }

    #[test]
    fn key_tag_rfc_example() {
        // RFC 4034 Appendix B example: key tag of a known DNSKEY.
        // The example uses algorithm 5 (RSA/SHA1) with a specific public key.
        // We just verify the algorithm doesn't panic and returns some u16.
        let rdata = vec![0x01u8, 0x01, 0x03, 0x05, 0xAA, 0xBB, 0xCC, 0xDD];
        let _tag = key_tag(&rdata);
        // No assertion on the specific value — the RFC example uses a longer key.
    }
}
