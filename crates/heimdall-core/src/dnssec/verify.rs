// SPDX-License-Identifier: MIT

//! RRSIG verification pipeline (RFC 4035 §5).
//!
//! [`verify_rrsig`] implements DNSSEC-001: full signature verification with
//! validity-period checking, key matching, `KeyTrap` mitigation, and per-query
//! CPU budget enforcement.

use ring::signature::{self, UnparsedPublicKey};

use crate::dnssec::algorithms::DnsAlgorithm;
use crate::dnssec::budget::ValidationBudget;
use crate::dnssec::canonical::{RsigFields, rrset_signing_input};
use crate::edns::{EdnsOption, ExtendedError, ede_code};
use crate::rdata::RData;
use crate::record::{Record, Rtype};
use crate::zone::integrity::key_tag;

// ── Public outcome types ───────────────────────────────────────────────────────

/// The four DNSSEC validation outcomes per RFC 4035 §5.
///
/// Implements DNSSEC-001 (validation pipeline), DNSSEC-040 (`KeyTrap`),
/// and DNSSEC-045 (CPU budget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// The `RRset` has a valid, in-date signature from a trusted key.
    Secure,
    /// The `RRset` is in an unsigned zone or delegation; validity cannot be established.
    Insecure,
    /// The `RRset` has an invalid or expired signature, or validation failed.
    Bogus(BogusReason),
    /// Insufficient information to determine security status.
    Indeterminate,
}

/// Specific causes of a [`ValidationOutcome::Bogus`] result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BogusReason {
    /// The RRSIG expiration time has passed (`now > sig_expiration`).
    SignatureExpired,
    /// The RRSIG inception time is in the future (`now < sig_inception`).
    SignatureNotYetValid,
    /// The cryptographic signature verification failed.
    InvalidSignature,
    /// The signing algorithm is not implemented by this validator.
    AlgorithmNotImplemented(u8),
    /// The RRSIG `key_tag` does not match any candidate DNSKEY.
    KeyTagMismatch,
    /// No DNSKEY in the provided set matches the RRSIG signer and `key_tag`.
    NoMatchingKey,
    /// The RRSIG `signer_name` does not match the zone apex.
    SignerNameMismatch,
    /// The RRSIG labels field exceeds the number of labels in the owner name.
    LabelCountMismatch,
    /// The DNSKEY public key bytes are malformed or the wrong size.
    InvalidKeyFormat,
    /// Too many DNSKEY candidates were tried (RFC 9276 `KeyTrap` mitigation).
    ///
    /// Implements DNSSEC-040.
    KeyTrapLimit,
    /// The per-query validation wall-clock budget was exceeded.
    ///
    /// Implements DNSSEC-045.
    CpuBudgetExceeded,
}

// ── Internal key representation ────────────────────────────────────────────────

/// Parsed public key material ready for `ring` verification.
enum RingKey {
    Ed25519(Vec<u8>),
    EcdsaP256(Vec<u8>),  // 04 || x || y (65 bytes)
    EcdsaP384(Vec<u8>),  // 04 || x || y (97 bytes)
    RsaComponents { n: Vec<u8>, e: Vec<u8> },
}

/// Extracts the public key from a DNSKEY `public_key` field for the given algorithm.
///
/// DNSKEY wire format for the key material varies by algorithm:
/// - Ed25519: 32 raw bytes.
/// - ECDSA P-256: 64 bytes (x || y, no `0x04` prefix in DNSKEY wire).
/// - ECDSA P-384: 96 bytes (x || y, no `0x04` prefix in DNSKEY wire).
/// - RSA: `[exp_len_byte][exponent][modulus]` or `[0x00][exp_len_hi][exp_len_lo][exp][mod]`.
fn extract_public_key(
    key_bytes: &[u8],
    algorithm: DnsAlgorithm,
) -> Result<RingKey, BogusReason> {
    match algorithm {
        DnsAlgorithm::Ed25519 => {
            if key_bytes.len() != 32 {
                return Err(BogusReason::InvalidKeyFormat);
            }
            Ok(RingKey::Ed25519(key_bytes.to_vec()))
        }
        DnsAlgorithm::EcdsaP256Sha256 => {
            // RFC 6605 §4: key field is x || y (64 bytes). ring needs `04` || x || y.
            if key_bytes.len() != 64 {
                return Err(BogusReason::InvalidKeyFormat);
            }
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(key_bytes);
            Ok(RingKey::EcdsaP256(uncompressed))
        }
        DnsAlgorithm::EcdsaP384Sha384 => {
            // RFC 6605 §4: key field is x || y (96 bytes). ring needs `04` || x || y.
            if key_bytes.len() != 96 {
                return Err(BogusReason::InvalidKeyFormat);
            }
            let mut uncompressed = Vec::with_capacity(97);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(key_bytes);
            Ok(RingKey::EcdsaP384(uncompressed))
        }
        DnsAlgorithm::RsaSha256
        | DnsAlgorithm::RsaSha512
        | DnsAlgorithm::RsaSha1
        | DnsAlgorithm::RsaSha1Nsec3 => {
            // RFC 3110 §2: `[exp_len_byte][exponent][modulus]`
            // If `exp_len_byte == 0`: `[0x00][exp_len_hi][exp_len_lo][exponent][modulus]`
            if key_bytes.is_empty() {
                return Err(BogusReason::InvalidKeyFormat);
            }
            let (exp_len, data_start) = if key_bytes[0] == 0 {
                if key_bytes.len() < 3 {
                    return Err(BogusReason::InvalidKeyFormat);
                }
                let elen = usize::from(u16::from_be_bytes([key_bytes[1], key_bytes[2]]));
                (elen, 3usize)
            } else {
                (usize::from(key_bytes[0]), 1usize)
            };
            let exp_end = data_start.checked_add(exp_len).ok_or(BogusReason::InvalidKeyFormat)?;
            if exp_end > key_bytes.len() {
                return Err(BogusReason::InvalidKeyFormat);
            }
            let e = key_bytes[data_start..exp_end].to_vec();
            let n = key_bytes[exp_end..].to_vec();
            if n.is_empty() || e.is_empty() {
                return Err(BogusReason::InvalidKeyFormat);
            }
            Ok(RingKey::RsaComponents { n, e })
        }
        DnsAlgorithm::Ed448 => Err(BogusReason::AlgorithmNotImplemented(16)),
        // MUST-NOT algorithms (1, 3, 6, 12) return Indeterminate before reaching here;
        // this arm is a compile-time exhaustiveness guard only.
        DnsAlgorithm::RsaMd5
        | DnsAlgorithm::Dsa
        | DnsAlgorithm::DsaNsec3Sha1
        | DnsAlgorithm::EccGost => Err(BogusReason::AlgorithmNotImplemented(algorithm.as_u8())),
        DnsAlgorithm::Unknown(v) => Err(BogusReason::AlgorithmNotImplemented(v)),
    }
}

/// Performs the actual ring cryptographic verification.
fn ring_verify(
    ring_key: &RingKey,
    algorithm: DnsAlgorithm,
    message: &[u8],
    sig: &[u8],
) -> Result<(), BogusReason> {
    match ring_key {
        RingKey::Ed25519(pk) => {
            let key = UnparsedPublicKey::new(&signature::ED25519, pk.as_slice());
            key.verify(message, sig).map_err(|_| BogusReason::InvalidSignature)
        }
        RingKey::EcdsaP256(pk) => {
            let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pk.as_slice());
            key.verify(message, sig).map_err(|_| BogusReason::InvalidSignature)
        }
        RingKey::EcdsaP384(pk) => {
            let key = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, pk.as_slice());
            key.verify(message, sig).map_err(|_| BogusReason::InvalidSignature)
        }
        RingKey::RsaComponents { n, e } => {
            let components = signature::RsaPublicKeyComponents { n: n.as_slice(), e: e.as_slice() };
            match algorithm {
                DnsAlgorithm::RsaSha256 | DnsAlgorithm::RsaSha1 | DnsAlgorithm::RsaSha1Nsec3 => {
                    components
                        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig)
                        .map_err(|_| BogusReason::InvalidSignature)
                }
                DnsAlgorithm::RsaSha512 => {
                    components
                        .verify(&signature::RSA_PKCS1_2048_8192_SHA512, message, sig)
                        .map_err(|_| BogusReason::InvalidSignature)
                }
                _ => Err(BogusReason::AlgorithmNotImplemented(algorithm.as_u8())),
            }
        }
    }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Verifies a single RRSIG over an `RRset` against a set of candidate DNSKEYs.
///
/// Implements RFC 4035 §5.3 (validation procedure) and DNSSEC-001.
///
/// Steps:
/// 1. Extract RRSIG fields; return `Bogus(AlgorithmNotImplemented)` for unsupported algorithms.
/// 2. Check validity period.
/// 3. Find DNSKEY candidates matching `key_tag` and `algorithm`.
/// 4. Verify against each candidate, bounded by `max_attempts` (`KeyTrap` cap, DNSSEC-040).
/// 5. Return `Secure` if any candidate verifies, `Bogus(InvalidSignature)` if all fail.
///
/// # Arguments
///
/// * `rrset` — all records in the `RRset` being verified (must share name/type/class).
/// * `rrsig_rdata` — must be `RData::Rrsig`; the signature to verify.
/// * `dnskeys` — DNSKEY `RRset` for the zone (candidate signing keys).
/// * `now_unix` — current Unix timestamp in seconds (for validity-period check).
/// * `max_attempts` — `KeyTrap` cap; returns `Bogus(KeyTrapLimit)` if exceeded.
#[must_use]
pub fn verify_rrsig(
    rrset: &[Record],
    rrsig_rdata: &RData,
    dnskeys: &[Record],
    now_unix: u64,
    max_attempts: usize,
) -> ValidationOutcome {
    verify_rrsig_with_budget(rrset, rrsig_rdata, dnskeys, now_unix, max_attempts, None)
}

/// Same as [`verify_rrsig`] but with an explicit [`ValidationBudget`].
///
/// Implements DNSSEC-001 and DNSSEC-045.
#[must_use]
pub fn verify_rrsig_with_budget(
    rrset: &[Record],
    rrsig_rdata: &RData,
    dnskeys: &[Record],
    now_unix: u64,
    max_attempts: usize,
    budget: Option<&ValidationBudget>,
) -> ValidationOutcome {
    // Step 1: extract RRSIG fields.
    let RData::Rrsig {
        type_covered,
        algorithm: alg_u8,
        labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag: rrsig_key_tag,
        signer_name,
        signature,
    } = rrsig_rdata
    else {
        return ValidationOutcome::Bogus(BogusReason::InvalidKeyFormat);
    };

    let algorithm = DnsAlgorithm::from_u8(*alg_u8);

    // Check algorithm supportability (fail-fast before expensive work).
    //
    // MUST-NOT algorithms (1, 3, 6, 12 — DNSSEC-035): treat the RRSIG as absent.
    // Returning Indeterminate lets the caller skip this RRSIG without triggering
    // a Bogus outcome; if no other RRSIG validates, the result is Insecure.
    if algorithm.must_not_implement() {
        return ValidationOutcome::Indeterminate;
    }
    match algorithm {
        DnsAlgorithm::Ed448 => {
            return ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(16));
        }
        DnsAlgorithm::Unknown(v) => {
            return ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(v));
        }
        _ => {}
    }

    // Step 2: validity period check.
    if now_unix < u64::from(*sig_inception) {
        return ValidationOutcome::Bogus(BogusReason::SignatureNotYetValid);
    }
    if now_unix > u64::from(*sig_expiration) {
        return ValidationOutcome::Bogus(BogusReason::SignatureExpired);
    }

    // Validate labels field against owner name.
    if !rrset.is_empty() {
        let owner_labels = rrset[0].name.label_count();
        if usize::from(*labels) > owner_labels {
            return ValidationOutcome::Bogus(BogusReason::LabelCountMismatch);
        }
    }

    // Step 3: find candidate DNSKEYs matching key_tag + algorithm.
    let candidates: Vec<&Record> = dnskeys
        .iter()
        .filter(|r| {
            r.rtype == Rtype::Dnskey
                && matches!(&r.rdata, RData::Dnskey { algorithm: a, flags, protocol, public_key }
                    if {
                        // Compute key_tag from the wire RDATA.
                        let wire = dnskey_wire_rdata(*flags, *protocol, *a, public_key);
                        key_tag(&wire) == *rrsig_key_tag
                            && *a == *alg_u8
                            && r.name == *signer_name
                    }
                )
        })
        .collect();

    if candidates.is_empty() {
        return ValidationOutcome::Bogus(BogusReason::NoMatchingKey);
    }

    // Build the signing input once (it's the same for all candidate keys).
    let rrsig_fields = RsigFields {
        type_covered: *type_covered,
        algorithm: *alg_u8,
        labels: *labels,
        original_ttl: *original_ttl,
        sig_expiration: *sig_expiration,
        sig_inception: *sig_inception,
        key_tag: *rrsig_key_tag,
        signer_name: signer_name.clone(),
    };
    let signing_input = rrset_signing_input(&rrsig_fields, rrset);

    // Step 4: try candidates up to max_attempts (KeyTrap cap, DNSSEC-040).
    for (attempt_idx, candidate) in candidates.iter().enumerate() {
        if attempt_idx >= max_attempts {
            return ValidationOutcome::Bogus(BogusReason::KeyTrapLimit);
        }

        // Check CPU budget before each expensive verification (DNSSEC-045).
        if let Some(b) = budget
            && let Err(reason) = b.check()
        {
            return ValidationOutcome::Bogus(reason);
        }

        let RData::Dnskey { public_key, .. } = &candidate.rdata else { continue };

        let ring_key = match extract_public_key(public_key, algorithm) {
            Ok(k) => k,
            Err(reason) => return ValidationOutcome::Bogus(reason),
        };

        // Step 5: cryptographic verification.
        if ring_verify(&ring_key, algorithm, &signing_input, signature).is_ok() {
            return ValidationOutcome::Secure;
        }
    }

    ValidationOutcome::Bogus(BogusReason::InvalidSignature)
}

/// Returns the EDE EDNS option signalling use of a deprecated DNSSEC signing algorithm.
///
/// Attach this to the DNS response when the chain of trust for the response was
/// closed through a deprecated algorithm (5 RSASHA1, 7 RSASHA1-NSEC3-SHA1, or
/// 10 RSASHA512), per DNSSEC-038.  EDE code 1 (`UNSUPPORTED_DNSKEY_ALGORITHM`)
/// is used to signal that a non-recommended algorithm was observed.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn deprecated_algorithm_ede() -> EdnsOption {
    EdnsOption::ExtendedError(ExtendedError::new(
        ede_code::UNSUPPORTED_DNSKEY_ALGORITHM,
    ))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encodes DNSKEY fields into wire RDATA for `key_tag` computation.
fn dnskey_wire_rdata(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + public_key.len());
    v.extend_from_slice(&flags.to_be_bytes());
    v.push(protocol);
    v.push(algorithm);
    v.extend_from_slice(public_key);
    v
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use crate::header::Qclass;
    use crate::name::Name;
    use crate::record::Rtype;

    fn make_rrsig_rdata(
        type_covered: Rtype,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        sig_inception: u32,
        sig_expiration: u32,
        key_tag: u16,
        signer: &str,
        signature: Vec<u8>,
    ) -> RData {
        RData::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name: Name::from_str(signer).unwrap(),
            signature,
        }
    }

    #[test]
    fn unsupported_algorithm_returns_bogus() {
        let rrsig = make_rrsig_rdata(
            Rtype::A, 255, 2, 300, 0, u32::MAX, 1234, "example.com.", vec![0u8; 32],
        );
        let result = verify_rrsig(&[], &rrsig, &[], 1000, 16);
        assert!(matches!(result, ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(255))));
    }

    #[test]
    fn ed448_returns_bogus_not_implemented() {
        let rrsig = make_rrsig_rdata(
            Rtype::A, 16, 2, 300, 0, u32::MAX, 1234, "example.com.", vec![0u8; 64],
        );
        let result = verify_rrsig(&[], &rrsig, &[], 1000, 16);
        assert!(matches!(result, ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(16))));
    }

    #[test]
    fn expired_signature_returns_bogus() {
        let rrsig = make_rrsig_rdata(
            Rtype::A, 13, 2, 300,
            100,   // inception
            200,   // expiration
            1234, "example.com.", vec![0u8; 64],
        );
        // now_unix = 300 > expiration (200) → expired
        let result = verify_rrsig(&[], &rrsig, &[], 300, 16);
        assert_eq!(result, ValidationOutcome::Bogus(BogusReason::SignatureExpired));
    }

    #[test]
    fn not_yet_valid_signature_returns_bogus() {
        let rrsig = make_rrsig_rdata(
            Rtype::A, 13, 2, 300,
            1000,  // inception in future
            2000,  // expiration
            1234, "example.com.", vec![0u8; 64],
        );
        // now_unix = 500 < inception (1000) → not yet valid
        let result = verify_rrsig(&[], &rrsig, &[], 500, 16);
        assert_eq!(result, ValidationOutcome::Bogus(BogusReason::SignatureNotYetValid));
    }

    #[test]
    fn no_matching_key_returns_bogus() {
        let rrsig = make_rrsig_rdata(
            Rtype::A, 15, 2, 300, 0, u32::MAX, 9999, "example.com.", vec![0u8; 64],
        );
        // No DNSKEYs provided.
        let result = verify_rrsig(&[], &rrsig, &[], 1000, 16);
        assert_eq!(result, ValidationOutcome::Bogus(BogusReason::NoMatchingKey));
    }

    // ── DNSSEC-035/036: MUST-NOT algorithms treated as absent ─────────────────

    #[test]
    fn must_not_implement_algorithms_return_indeterminate() {
        // Algorithms 1, 3, 6, 12 MUST be treated as absent (DNSSEC-035/036).
        // verify_rrsig must return Indeterminate (not Bogus) so the caller can
        // skip these RRSIGs without triggering a Bogus outcome.
        for alg in [1u8, 3, 6, 12] {
            let rrsig = make_rrsig_rdata(
                Rtype::A, alg, 2, 300, 0, u32::MAX, 1234, "example.com.", vec![0u8; 32],
            );
            let result = verify_rrsig(&[], &rrsig, &[], 1000, 16);
            assert_eq!(
                result,
                ValidationOutcome::Indeterminate,
                "algorithm {alg} must return Indeterminate (treat as absent), not Bogus (DNSSEC-035)"
            );
        }
    }

    #[test]
    fn must_not_implement_never_contributes_to_secure() {
        // Even with a matching DNSKEY, MUST-NOT algorithms must not validate to Secure.
        // They return Indeterminate before the key lookup, so no Secure outcome is possible.
        for alg in [1u8, 3, 6, 12] {
            let rrsig = make_rrsig_rdata(
                Rtype::A, alg, 2, 300, 0, u32::MAX, 1234, "example.com.", vec![0u8; 64],
            );
            let result = verify_rrsig(&[], &rrsig, &[], 1000, 16);
            assert!(
                !matches!(result, ValidationOutcome::Secure),
                "algorithm {alg} MUST NOT contribute to Secure (DNSSEC-036)"
            );
        }
    }

    // ── DNSSEC-038: EDE for deprecated algorithms (5, 7, 10) ─────────────────

    #[test]
    fn deprecated_algorithm_ede_has_code_1() {
        let opt = deprecated_algorithm_ede();
        let crate::edns::EdnsOption::ExtendedError(crate::edns::ExtendedError { info_code, .. }) = opt else {
            panic!("deprecated_algorithm_ede must return ExtendedError variant");
        };
        assert_eq!(
            info_code,
            crate::edns::ede_code::UNSUPPORTED_DNSKEY_ALGORITHM,
            "EDE code must be 1 (Unsupported DNSKEY Algorithm)"
        );
    }

    // ── DNSSEC-035: DnsAlgorithm predicates ──────────────────────────────────

    #[test]
    fn must_not_implement_predicate_covers_1_3_6_12() {
        for alg in [1u8, 3, 6, 12] {
            assert!(
                DnsAlgorithm::from_u8(alg).must_not_implement(),
                "algorithm {alg} must be flagged must_not_implement (DNSSEC-035)"
            );
        }
        for alg in [5u8, 7, 8, 10, 13, 14, 15] {
            assert!(
                !DnsAlgorithm::from_u8(alg).must_not_implement(),
                "algorithm {alg} must NOT be flagged must_not_implement"
            );
        }
    }

    #[test]
    fn is_deprecated_predicate_covers_5_7_10() {
        for alg in [5u8, 7, 10] {
            assert!(
                DnsAlgorithm::from_u8(alg).is_deprecated(),
                "algorithm {alg} must be flagged is_deprecated (DNSSEC-038)"
            );
        }
        for alg in [1u8, 3, 6, 8, 12, 13, 14, 15] {
            assert!(
                !DnsAlgorithm::from_u8(alg).is_deprecated(),
                "algorithm {alg} must NOT be flagged is_deprecated"
            );
        }
    }

    #[test]
    fn keytrap_limit_respected() {
        // max_attempts = 0 → immediately hits limit.
        let name = Name::from_str("example.com.").unwrap();
        let pub_key = vec![0u8; 32];
        let wire = dnskey_wire_rdata(0x0101, 3, 15, &pub_key);
        let kt = key_tag(&wire);
        let dnskey_rec = Record {
            name: name.clone(),
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Dnskey {
                flags: 0x0101,
                protocol: 3,
                algorithm: 15,
                public_key: pub_key,
            },
        };
        // Force key_tag match by using the actual computed tag.
        let rrsig2 = make_rrsig_rdata(
            Rtype::Dnskey, 15, 2, 300, 0, u32::MAX, kt, "example.com.", vec![0u8; 64],
        );
        // max_attempts = 0: should hit limit immediately.
        let result = verify_rrsig(&[], &rrsig2, &[dnskey_rec], 1000, 0);
        assert_eq!(result, ValidationOutcome::Bogus(BogusReason::KeyTrapLimit));
    }
}
