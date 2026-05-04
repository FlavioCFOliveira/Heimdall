// SPDX-License-Identifier: MIT

//! DNSSEC algorithm and digest type support tables (RFC 8624 §3).
//!
//! Implements DNSSEC-002 (algorithm enumeration), DNSSEC-003 (RFC 8624 policy),
//! DNSSEC-004 (DS digest computation and matching), and DNSSEC-048..054
//! (DS digest acceptance policy: SHA-256/SHA-384 preferred, SHA-1 fallback
//! with EDE, GOST and unknown types rejected).

use ring::digest;

use crate::dnssec::canonical::canonical_name_wire;
use crate::edns::{EdnsOption, ExtendedError, ede_code};
use crate::name::Name;
use crate::rdata::RData;

// ── DnsAlgorithm ──────────────────────────────────────────────────────────────

/// DNSSEC signing algorithm numbers from the IANA DNSSEC Algorithm Numbers registry.
///
/// RFC 8624 §3.1 specifies the implementation requirements for each algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsAlgorithm {
    /// RSAMD5 (RFC 2535 / RFC 3110).  MUST NOT implement (RFC 8624 §3.1, DNSSEC-035).
    ///
    /// RRSIGs with this algorithm MUST be treated as absent.
    RsaMd5 = 1,
    /// DSA/SHA-1 (RFC 2536).  MUST NOT implement (RFC 8624 §3.1, DNSSEC-035).
    ///
    /// RRSIGs with this algorithm MUST be treated as absent.
    Dsa = 3,
    /// DSA-NSEC3-SHA1 (RFC 5155).  MUST NOT implement (RFC 8624 §3.1, DNSSEC-035).
    ///
    /// RRSIGs with this algorithm MUST be treated as absent.
    DsaNsec3Sha1 = 6,
    /// ECC-GOST (RFC 5933).  MUST NOT implement (RFC 8624 §3.1, DNSSEC-035).
    ///
    /// RRSIGs with this algorithm MUST be treated as absent.
    EccGost = 12,
    /// RSA/SHA-1 (RFC 3110).  MAY validate; MUST NOT sign (RFC 8624 §3.1, DNSSEC-034).
    RsaSha1 = 5,
    /// RSA/SHA-1 with NSEC3 (RFC 5155).  MAY validate; MUST NOT sign (RFC 8624 §3.1, DNSSEC-034).
    RsaSha1Nsec3 = 7,
    /// RSA/SHA-256 (RFC 5702).  MUST validate (RFC 8624 §3.1, DNSSEC-032).
    RsaSha256 = 8,
    /// RSA/SHA-512 (RFC 5702).  MAY validate (RFC 8624 §3.1, DNSSEC-034).
    RsaSha512 = 10,
    /// ECDSA P-256 / SHA-256 (RFC 6605).  MUST validate, RECOMMENDED for signing (RFC 8624 §3.1).
    EcdsaP256Sha256 = 13,
    /// ECDSA P-384 / SHA-384 (RFC 6605).  SHOULD validate (RFC 8624 §3.1).
    EcdsaP384Sha384 = 14,
    /// Ed25519 (RFC 8080).  MUST validate, RECOMMENDED for signing (RFC 8624 §3.1).
    Ed25519 = 15,
    /// Ed448 (RFC 8080).  Deferred — ring does not support Ed448.
    Ed448 = 16,
    /// An algorithm number not listed in this enum.
    Unknown(u8),
}

impl DnsAlgorithm {
    /// Converts a raw algorithm number to a [`DnsAlgorithm`].
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::RsaMd5,
            3 => Self::Dsa,
            5 => Self::RsaSha1,
            6 => Self::DsaNsec3Sha1,
            7 => Self::RsaSha1Nsec3,
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            12 => Self::EccGost,
            13 => Self::EcdsaP256Sha256,
            14 => Self::EcdsaP384Sha384,
            15 => Self::Ed25519,
            16 => Self::Ed448,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw algorithm number.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::RsaMd5 => 1,
            Self::Dsa => 3,
            Self::RsaSha1 => 5,
            Self::DsaNsec3Sha1 => 6,
            Self::RsaSha1Nsec3 => 7,
            Self::RsaSha256 => 8,
            Self::RsaSha512 => 10,
            Self::EccGost => 12,
            Self::EcdsaP256Sha256 => 13,
            Self::EcdsaP384Sha384 => 14,
            Self::Ed25519 => 15,
            Self::Ed448 => 16,
            Self::Unknown(v) => v,
        }
    }

    /// Returns `true` if RFC 8624 §3.1 forbids implementing this algorithm.
    ///
    /// MUST NOT implement: 1 (RSAMD5), 3 (DSA), 6 (DSA-NSEC3-SHA1), 12 (ECC-GOST).
    ///
    /// RRSIGs using these algorithms MUST be treated as absent by the validation
    /// pipeline rather than triggering Bogus (DNSSEC-035, DNSSEC-036).
    #[must_use]
    pub fn must_not_implement(self) -> bool {
        matches!(self, Self::RsaMd5 | Self::Dsa | Self::DsaNsec3Sha1 | Self::EccGost)
    }

    /// Returns `true` if this algorithm is deprecated per RFC 8624 §3.1.
    ///
    /// Deprecated (MAY validate, MUST NOT sign): 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1),
    /// 10 (RSASHA512).  When a chain is closed via a deprecated algorithm, the
    /// response MUST carry EDE code 1 (Unsupported DNSKEY Algorithm) and a
    /// structured log event MUST be emitted (DNSSEC-038, DNSSEC-039).
    #[must_use]
    pub fn is_deprecated(self) -> bool {
        matches!(self, Self::RsaSha1 | Self::RsaSha1Nsec3 | Self::RsaSha512)
    }

    /// Returns `true` if RFC 8624 §3.1 requires this algorithm to be validated (DNSSEC-032).
    ///
    /// MUST validate: 8 (RSASHA256), 13 (ECDSAP256SHA256).
    #[must_use]
    pub fn must_validate(self) -> bool {
        matches!(self, Self::RsaSha256 | Self::EcdsaP256Sha256)
    }

    /// Returns `true` if RFC 8624 §3.1 recommends this algorithm be validated (DNSSEC-033).
    ///
    /// SHOULD validate: 14 (ECDSAP384SHA384), 15 (Ed25519), 16 (Ed448).
    #[must_use]
    pub fn should_validate(self) -> bool {
        matches!(self, Self::EcdsaP384Sha384 | Self::Ed25519 | Self::Ed448)
    }

    /// Returns `true` if RFC 8624 §3.1 permits but does not require validation (DNSSEC-034).
    ///
    /// MAY validate: 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1), 10 (RSASHA512).
    #[must_use]
    pub fn may_validate(self) -> bool {
        matches!(self, Self::RsaSha1 | Self::RsaSha1Nsec3 | Self::RsaSha512)
    }

    /// Returns `true` if RFC 8624 §3.1 prohibits using this algorithm for signing.
    ///
    /// MUST NOT sign: 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1).
    #[must_use]
    pub fn must_not_sign(self) -> bool {
        matches!(self, Self::RsaSha1 | Self::RsaSha1Nsec3)
    }

    /// Returns `true` if RFC 8624 §3.1 recommends this algorithm for signing.
    ///
    /// Recommended for signing: 13 (ECDSAP256SHA256), 15 (Ed25519).
    #[must_use]
    pub fn recommended_for_signing(self) -> bool {
        matches!(self, Self::EcdsaP256Sha256 | Self::Ed25519)
    }
}

// ── DigestType ────────────────────────────────────────────────────────────────

/// DNSSEC DS record digest type identifiers (IANA DS RR Type Digest Algorithm Numbers).
///
/// RFC 8624 §3.3 specifies implementation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DigestType {
    /// SHA-1 (RFC 4034 §5.1.4).  NOT RECOMMENDED per RFC 8624 §3.3.
    Sha1 = 1,
    /// SHA-256 (RFC 4509).  MUST implement per RFC 8624 §3.3.
    Sha256 = 2,
    /// SHA-384 (RFC 6605).  MAY implement per RFC 8624 §3.3.
    Sha384 = 4,
    /// An unrecognised digest type number.
    Unknown(u8),
}

impl DigestType {
    /// Converts a raw digest type number to a [`DigestType`].
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Sha1,
            2 => Self::Sha256,
            4 => Self::Sha384,
            other => Self::Unknown(other),
        }
    }

    /// Computes the DS digest over `owner_wire || dnskey_rdata` using this digest type.
    ///
    /// Implements RFC 4034 §5.1.4 (DS digest computation).
    ///
    /// Returns `None` for [`DigestType::Unknown`] or unsupported variants.
    #[must_use]
    pub fn compute(&self, owner_wire: &[u8], dnskey_rdata: &[u8]) -> Option<Vec<u8>> {
        let mut data = Vec::with_capacity(owner_wire.len() + dnskey_rdata.len());
        data.extend_from_slice(owner_wire);
        data.extend_from_slice(dnskey_rdata);

        let algo = match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
            Self::Unknown(_) => return None,
        };

        Some(digest::digest(algo, &data).as_ref().to_vec())
    }
}

// ── DS matching ───────────────────────────────────────────────────────────────

/// Returns `true` if `dnskey` matches the `ds` record.
///
/// Implements RFC 4034 §5.2 (DS RR processing):
/// computes the DS digest over `canonical_name_wire(owner) || dnskey_rdata_wire`
/// and compares byte-by-byte to the digest field in the DS record.
///
/// Implements DNSSEC-004.
#[must_use]
pub fn dnskey_matches_ds(owner: &Name, dnskey: &RData, ds: &RData) -> bool {
    let RData::Dnskey { flags, protocol, algorithm, public_key } = dnskey else {
        return false;
    };
    let RData::Ds { key_tag: ds_key_tag, algorithm: ds_alg, digest_type, digest } = ds else {
        return false;
    };

    // Algorithm must match.
    if *algorithm != *ds_alg {
        return false;
    }

    // Build DNSKEY wire RDATA.
    let mut dnskey_rdata = Vec::with_capacity(4 + public_key.len());
    dnskey_rdata.extend_from_slice(&flags.to_be_bytes());
    dnskey_rdata.push(*protocol);
    dnskey_rdata.push(*algorithm);
    dnskey_rdata.extend_from_slice(public_key);

    // key_tag must match.
    let computed_tag = crate::zone::integrity::key_tag(&dnskey_rdata);
    if computed_tag != *ds_key_tag {
        return false;
    }

    let owner_wire = canonical_name_wire(owner);
    let dt = DigestType::from_u8(*digest_type);

    match dt.compute(&owner_wire, &dnskey_rdata) {
        Some(computed) => computed == *digest,
        None => false,
    }
}

// ── DS digest acceptance policy (DNSSEC-048..054) ────────────────────────────

/// Outcome of the DS digest acceptance policy for a delegation point.
///
/// Callers MUST use only the DS records returned by [`select_ds_records`] when
/// validating a DNSKEY at the delegation point.
///
/// Implements DNSSEC-048..054 (RFC 8624 §3.2 DS digest acceptance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsAcceptance<'a> {
    /// At least one DS record with a non-deprecated digest type (SHA-256 or
    /// SHA-384) is present.  Only these records may contribute to the chain of
    /// trust; SHA-1 records MUST be ignored even if they are also present.
    ///
    /// Implements DNSSEC-049, DNSSEC-050.
    Modern(Vec<&'a RData>),

    /// No non-deprecated DS record is present; SHA-1 (type 1) is the only
    /// available digest type at this delegation.
    ///
    /// The chain of trust MAY be closed through these records, but the caller
    /// MUST attach EDE code 2 (`UNSUPPORTED_DS_DIGEST_TYPE`) to the client
    /// response to signal the deprecated fallback (DNSSEC-051).
    Sha1Fallback(Vec<&'a RData>),

    /// No DS record with a supported digest type is present (all are GOST,
    /// unknown, or the set is empty).  The chain of trust cannot be closed;
    /// the delegation MUST be treated as Bogus (DNSSEC-052, DNSSEC-053).
    NoSupported,
}

impl DsAcceptance<'_> {
    /// Returns an EDE option to attach to the response when the fallback path
    /// was taken (SHA-1 only), or `None` for the `Modern` and `NoSupported`
    /// variants.
    ///
    /// Implements DNSSEC-051 (EDE signalling for deprecated SHA-1 DS).
    #[must_use]
    pub fn fallback_ede(&self) -> Option<EdnsOption> {
        if matches!(self, Self::Sha1Fallback(_)) {
            Some(EdnsOption::ExtendedError(ExtendedError::new(
                ede_code::UNSUPPORTED_DS_DIGEST_TYPE,
            )))
        } else {
            None
        }
    }
}

/// Applies the DS digest acceptance policy to a set of DS records at one
/// delegation point and returns the eligible subset together with the
/// appropriate handling signal.
///
/// Policy (RFC 8624 §3.2, DNSSEC-049..053):
///
/// 1. DS type 3 (GOST) — MUST NOT contribute; skip unconditionally.
/// 2. DS type `Unknown` — unsupported; skip unconditionally.
/// 3. DS type 2 (SHA-256) or type 4 (SHA-384) — preferred; collect.
/// 4. DS type 1 (SHA-1) — deprecated; collect only if no type-2/4 is present.
///
/// If the delegation provides at least one type-2 or type-4 DS, returns
/// [`DsAcceptance::Modern`].  If only type-1 DS records are available, returns
/// [`DsAcceptance::Sha1Fallback`] (caller must add EDE).  If no supported type
/// is present, returns [`DsAcceptance::NoSupported`].
#[must_use]
pub fn select_ds_records(ds_records: &[RData]) -> DsAcceptance<'_> {
    let mut modern: Vec<&RData> = Vec::new();
    let mut sha1: Vec<&RData> = Vec::new();

    for rdata in ds_records {
        let RData::Ds { digest_type, .. } = rdata else { continue };
        match DigestType::from_u8(*digest_type) {
            DigestType::Sha256 | DigestType::Sha384 => modern.push(rdata),
            DigestType::Sha1 => sha1.push(rdata),
            // GOST (3) and Unknown: MUST NOT contribute (DNSSEC-052, DNSSEC-053).
            DigestType::Unknown(_) => {}
        }
    }

    if !modern.is_empty() {
        DsAcceptance::Modern(modern)
    } else if !sha1.is_empty() {
        DsAcceptance::Sha1Fallback(sha1)
    } else {
        DsAcceptance::NoSupported
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_roundtrip() {
        for (v, expected) in [
            (1u8, DnsAlgorithm::RsaMd5),
            (3, DnsAlgorithm::Dsa),
            (5, DnsAlgorithm::RsaSha1),
            (6, DnsAlgorithm::DsaNsec3Sha1),
            (7, DnsAlgorithm::RsaSha1Nsec3),
            (8, DnsAlgorithm::RsaSha256),
            (10, DnsAlgorithm::RsaSha512),
            (12, DnsAlgorithm::EccGost),
            (13, DnsAlgorithm::EcdsaP256Sha256),
            (14, DnsAlgorithm::EcdsaP384Sha384),
            (15, DnsAlgorithm::Ed25519),
            (16, DnsAlgorithm::Ed448),
            (99, DnsAlgorithm::Unknown(99)),
        ] {
            let alg = DnsAlgorithm::from_u8(v);
            assert_eq!(alg, expected);
            assert_eq!(alg.as_u8(), v);
        }
    }

    #[test]
    fn rfc8624_must_validate() {
        // DNSSEC-032: MUST validate = alg 8, 13.
        assert!(DnsAlgorithm::RsaSha256.must_validate());
        assert!(DnsAlgorithm::EcdsaP256Sha256.must_validate());
        assert!(!DnsAlgorithm::Ed25519.must_validate());
        assert!(!DnsAlgorithm::RsaSha1.must_validate());
        assert!(!DnsAlgorithm::Ed448.must_validate());
        assert!(!DnsAlgorithm::RsaSha512.must_validate());
    }

    #[test]
    fn rfc8624_should_validate() {
        // DNSSEC-033: SHOULD validate = alg 14, 15, 16.
        assert!(DnsAlgorithm::EcdsaP384Sha384.should_validate());
        assert!(DnsAlgorithm::Ed25519.should_validate());
        assert!(DnsAlgorithm::Ed448.should_validate());
        assert!(!DnsAlgorithm::RsaSha512.should_validate());
        assert!(!DnsAlgorithm::RsaSha256.should_validate());
    }

    #[test]
    fn rfc8624_may_validate() {
        // DNSSEC-034: MAY validate = alg 5, 7, 10.
        assert!(DnsAlgorithm::RsaSha1.may_validate());
        assert!(DnsAlgorithm::RsaSha1Nsec3.may_validate());
        assert!(DnsAlgorithm::RsaSha512.may_validate());
        assert!(!DnsAlgorithm::RsaSha256.may_validate());
        assert!(!DnsAlgorithm::Ed25519.may_validate());
    }

    #[test]
    fn rfc8624_must_not_sign() {
        assert!(DnsAlgorithm::RsaSha1.must_not_sign());
        assert!(DnsAlgorithm::RsaSha1Nsec3.must_not_sign());
        assert!(!DnsAlgorithm::Ed25519.must_not_sign());
    }

    #[test]
    fn rfc8624_recommended_for_signing() {
        assert!(DnsAlgorithm::EcdsaP256Sha256.recommended_for_signing());
        assert!(DnsAlgorithm::Ed25519.recommended_for_signing());
        assert!(!DnsAlgorithm::RsaSha256.recommended_for_signing());
    }

    #[test]
    fn digest_type_roundtrip() {
        assert_eq!(DigestType::from_u8(1), DigestType::Sha1);
        assert_eq!(DigestType::from_u8(2), DigestType::Sha256);
        assert_eq!(DigestType::from_u8(4), DigestType::Sha384);
        assert_eq!(DigestType::from_u8(99), DigestType::Unknown(99));
    }

    #[test]
    fn digest_sha256_known_vector() {
        // Simple sanity: SHA-256 of empty produces a 32-byte digest.
        let result = DigestType::Sha256.compute(b"", b"");
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn digest_sha384_known_length() {
        let result = DigestType::Sha384.compute(b"hello", b"world");
        assert_eq!(result.unwrap().len(), 48);
    }

    #[test]
    fn digest_unknown_returns_none() {
        let result = DigestType::Unknown(99).compute(b"data", b"more");
        assert!(result.is_none());
    }

    #[test]
    fn dnskey_matches_ds_false_for_wrong_types() {
        use std::str::FromStr;
        let owner = Name::from_str("example.com.").unwrap();
        // Passing wrong RData types returns false rather than panicking.
        let not_dnskey = RData::A("192.0.2.1".parse().unwrap());
        let not_ds = RData::A("192.0.2.2".parse().unwrap());
        assert!(!dnskey_matches_ds(&owner, &not_dnskey, &not_ds));
    }

    // ── DS digest acceptance matrix (DNSSEC-049..054) ─────────────────────────
    //
    // Six cells:
    // (a) DS-2 alone       → Modern (SHA-256 selected)
    // (b) DS-4 alone       → Modern (SHA-384 selected)
    // (c) DS-1 alone       → Sha1Fallback + EDE code 2
    // (d) DS-1 + DS-2      → Modern (SHA-256 wins; SHA-1 NOT used)
    // (e) DS-3 alone       → NoSupported (GOST rejected per DNSSEC-052)
    // (f) DS-3 + DS-2      → Modern (DS-3 contributes nothing, DS-2 wins)

    fn make_ds(digest_type: u8) -> RData {
        RData::Ds {
            key_tag: 1234,
            algorithm: 13,
            digest_type,
            digest: vec![0xAB; 32],
        }
    }

    #[test]
    fn ds_matrix_a_sha256_alone_is_modern() {
        let set = [make_ds(2)];
        let result = select_ds_records(&set);
        assert!(matches!(result, DsAcceptance::Modern(_)), "DS-2 alone → Modern (DNSSEC-049)");
        assert!(result.fallback_ede().is_none(), "Modern path must not emit EDE");
    }

    #[test]
    fn ds_matrix_b_sha384_alone_is_modern() {
        let set = [make_ds(4)];
        let result = select_ds_records(&set);
        assert!(matches!(result, DsAcceptance::Modern(_)), "DS-4 alone → Modern (DNSSEC-050)");
        assert!(result.fallback_ede().is_none(), "Modern path must not emit EDE");
    }

    #[test]
    fn ds_matrix_c_sha1_alone_is_fallback_with_ede() {
        let set = [make_ds(1)];
        let result = select_ds_records(&set);
        assert!(
            matches!(result, DsAcceptance::Sha1Fallback(_)),
            "DS-1 alone → Sha1Fallback (DNSSEC-051)"
        );
        let ede = result.fallback_ede();
        assert!(ede.is_some(), "SHA-1 fallback must produce EDE");
        if let Some(crate::edns::EdnsOption::ExtendedError(e)) = ede {
            assert_eq!(
                e.info_code,
                crate::edns::ede_code::UNSUPPORTED_DS_DIGEST_TYPE,
                "EDE code must be 2 (Unsupported DS Digest Type)"
            );
        } else {
            panic!("EDE option must be ExtendedError variant");
        }
    }

    #[test]
    fn ds_matrix_d_sha1_and_sha256_modern_wins() {
        let set = [make_ds(1), make_ds(2)];
        let result = select_ds_records(&set);
        assert!(
            matches!(result, DsAcceptance::Modern(_)),
            "DS-1 + DS-2: Modern wins; SHA-1 NOT used (DNSSEC-051)"
        );
        if let DsAcceptance::Modern(selected) = &result {
            for rdata in selected {
                if let RData::Ds { digest_type, .. } = rdata {
                    assert_ne!(*digest_type, 1u8, "SHA-1 must NOT be selected when SHA-256 is present");
                }
            }
        }
    }

    #[test]
    fn ds_matrix_e_gost_alone_no_supported() {
        let set = [make_ds(3)]; // GOST — MUST NOT contribute (DNSSEC-052)
        let result = select_ds_records(&set);
        assert!(
            matches!(result, DsAcceptance::NoSupported),
            "DS-3 (GOST) alone → NoSupported (DNSSEC-052)"
        );
    }

    #[test]
    fn ds_matrix_f_gost_and_sha256_modern_wins() {
        let set = [make_ds(3), make_ds(2)];
        let result = select_ds_records(&set);
        assert!(
            matches!(result, DsAcceptance::Modern(_)),
            "DS-3 + DS-2: Modern wins; GOST contributes nothing (DNSSEC-052/053)"
        );
        if let DsAcceptance::Modern(selected) = &result {
            for rdata in selected {
                if let RData::Ds { digest_type, .. } = rdata {
                    assert_ne!(*digest_type, 3u8, "GOST (type 3) must NOT be selected");
                }
            }
        }
    }

    #[test]
    fn ds_empty_set_no_supported() {
        let result = select_ds_records(&[]);
        assert!(matches!(result, DsAcceptance::NoSupported), "empty DS set → NoSupported");
    }

    #[test]
    fn ds_unknown_type_no_supported() {
        let set = [make_ds(99)]; // Unknown → MUST NOT contribute (DNSSEC-053)
        let result = select_ds_records(&set);
        assert!(
            matches!(result, DsAcceptance::NoSupported),
            "Unknown digest type → NoSupported (DNSSEC-053)"
        );
    }
}
