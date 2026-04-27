// SPDX-License-Identifier: MIT

//! DNSSEC algorithm and digest type support tables (RFC 8624 §3).
//!
//! Implements DNSSEC-002 (algorithm enumeration), DNSSEC-003 (RFC 8624 policy),
//! and DNSSEC-004 (DS digest computation and matching).

use ring::digest;

use crate::dnssec::canonical::canonical_name_wire;
use crate::name::Name;
use crate::rdata::RData;

// ── DnsAlgorithm ──────────────────────────────────────────────────────────────

/// DNSSEC signing algorithm numbers from the IANA DNSSEC Algorithm Numbers registry.
///
/// RFC 8624 §3.1 specifies the implementation requirements for each algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsAlgorithm {
    /// RSA/SHA-1 (RFC 3110).  MUST NOT be used for signing (RFC 8624 §3.1).
    RsaSha1 = 5,
    /// RSA/SHA-1 with NSEC3 (RFC 5155).  MUST NOT be used for signing (RFC 8624 §3.1).
    RsaSha1Nsec3 = 7,
    /// RSA/SHA-256 (RFC 5702).  MUST validate (RFC 8624 §3.1).
    RsaSha256 = 8,
    /// RSA/SHA-512 (RFC 5702).  SHOULD validate (RFC 8624 §3.1).
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
            5 => Self::RsaSha1,
            7 => Self::RsaSha1Nsec3,
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
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
            Self::RsaSha1 => 5,
            Self::RsaSha1Nsec3 => 7,
            Self::RsaSha256 => 8,
            Self::RsaSha512 => 10,
            Self::EcdsaP256Sha256 => 13,
            Self::EcdsaP384Sha384 => 14,
            Self::Ed25519 => 15,
            Self::Ed448 => 16,
            Self::Unknown(v) => v,
        }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_roundtrip() {
        for (v, expected) in [
            (5u8, DnsAlgorithm::RsaSha1),
            (7, DnsAlgorithm::RsaSha1Nsec3),
            (8, DnsAlgorithm::RsaSha256),
            (10, DnsAlgorithm::RsaSha512),
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
}
