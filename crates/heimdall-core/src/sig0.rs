// SPDX-License-Identifier: MIT

//! SIG(0) transaction authentication (RFC 2931).
//!
//! SIG(0) uses the SIG record (RTYPE 24) with key tag 0 to authenticate
//! individual DNS messages using asymmetric cryptography.  This module
//! provides verification only; signing (which requires private key management)
//! is deferred to the runtime layer.
//!
//! Supported algorithms (RFC 8624 §3.1):
//! - ECDSAP256SHA256 (13)
//! - ECDSAP384SHA384 (14)
//! - Ed25519 (15)
//! - RSASHA256 (8)  — public API acceptance; decoding out of Sprint 14 scope.
//! - RSASHA512 (10) — public API acceptance; decoding out of Sprint 14 scope.
//!
//! Deprecated algorithms (MD5, SHA1) are rejected.

use std::fmt;

use crate::rdata::RData;

// ── Sig0Error ─────────────────────────────────────────────────────────────────

/// Errors that can arise during SIG(0) verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sig0Error {
    /// The algorithm identified in the SIG record is not supported.
    UnsupportedAlgorithm,
    /// The signature bytes are not valid for the supplied public key.
    InvalidSignature,
    /// The public key RDATA cannot be decoded.
    MalformedPublicKey,
    /// The SIG record RDATA is malformed.
    MalformedSignature,
}

impl fmt::Display for Sig0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm => {
                write!(f, "SIG(0) algorithm is not supported")
            }
            Self::InvalidSignature => write!(f, "SIG(0) signature verification failed"),
            Self::MalformedPublicKey => write!(f, "SIG(0) public key RDATA is malformed"),
            Self::MalformedSignature => write!(f, "SIG(0) signature RDATA is malformed"),
        }
    }
}

impl std::error::Error for Sig0Error {}

// ── Sig0Algorithm ─────────────────────────────────────────────────────────────

/// Asymmetric signature algorithms supported for SIG(0) verification.
///
/// Numbers follow IANA's "DNS Security Algorithm Numbers" registry
/// (RFC 8624, RFC 8032).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig0Algorithm {
    /// RSA with SHA-256 — algorithm number 8.
    RsaSha256 = 8,
    /// RSA with SHA-512 — algorithm number 10.
    RsaSha512 = 10,
    /// ECDSA over P-256 with SHA-256 — algorithm number 13.
    EcdsaP256Sha256 = 13,
    /// ECDSA over P-384 with SHA-384 — algorithm number 14.
    EcdsaP384Sha384 = 14,
    /// Ed25519 — algorithm number 15.
    Ed25519 = 15,
}

impl Sig0Algorithm {
    /// Converts a raw algorithm number to a [`Sig0Algorithm`].
    ///
    /// Returns `None` for unsupported or deprecated algorithms (including RSAMD5
    /// and RSASHA1).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// Returns the IANA algorithm number for this algorithm.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ── Sig0Verifier ──────────────────────────────────────────────────────────────

/// Verifies SIG(0) signatures over DNS messages (RFC 2931).
///
/// SIG(0) signing is not implemented here; private key management is deferred
/// to the runtime layer.
pub struct Sig0Verifier;

impl Sig0Verifier {
    /// Verifies a SIG(0) record over a DNS message.
    ///
    /// `msg_wire` is the full wire representation of the message, including the
    /// SIG(0) record in the additional section.  The signed data is the message
    /// without the SIG(0) record (RFC 2931 §2.4).
    ///
    /// `sig_record` must be an [`RData::Rrsig`] variant containing the SIG
    /// record.  `public_key_rdata` is the raw RDATA of the corresponding
    /// KEY/DNSKEY record.  `algorithm` is the algorithm to use for verification
    /// and must match the algorithm field in `sig_record`.
    ///
    /// # Errors
    ///
    /// - [`Sig0Error::UnsupportedAlgorithm`] — the algorithm is not supported.
    /// - [`Sig0Error::MalformedSignature`] — the SIG RDATA cannot be decoded.
    /// - [`Sig0Error::MalformedPublicKey`] — the KEY RDATA cannot be decoded.
    /// - [`Sig0Error::InvalidSignature`] — the signature does not verify.
    pub fn verify(
        msg_wire: &[u8],
        sig_record: &RData,
        public_key_rdata: &[u8],
        algorithm: Sig0Algorithm,
    ) -> Result<(), Sig0Error> {
        // Extract the signature bytes from the RRSIG/SIG record.
        let signature = extract_signature(sig_record)?;

        // Build the signed data: the message without the SIG(0) record.
        // RFC 2931 §2.4: the signed data is formed from the message with the
        // SIG(0) RR removed from the additional section and arcount decremented.
        let signed_data = strip_sig0_from_wire(msg_wire);

        match algorithm {
            Sig0Algorithm::EcdsaP256Sha256 => verify_ecdsa(
                &signed_data,
                signature,
                public_key_rdata,
                &ring::signature::ECDSA_P256_SHA256_FIXED,
            ),
            Sig0Algorithm::EcdsaP384Sha384 => verify_ecdsa(
                &signed_data,
                signature,
                public_key_rdata,
                &ring::signature::ECDSA_P384_SHA384_FIXED,
            ),
            Sig0Algorithm::Ed25519 => verify_ed25519(&signed_data, signature, public_key_rdata),
            Sig0Algorithm::RsaSha256 | Sig0Algorithm::RsaSha512 => {
                // RSA verification via ring requires a DER-encoded SubjectPublicKeyInfo,
                // which differs from the raw modulus + exponent encoding used in DNS KEY
                // records (RFC 3110).  Full RSA decoding is deferred to post-Sprint 14;
                // return UnsupportedAlgorithm to signal this to the caller.
                Err(Sig0Error::UnsupportedAlgorithm)
            }
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extracts the raw signature bytes from an [`RData::Rrsig`] variant.
fn extract_signature(sig_record: &RData) -> Result<&[u8], Sig0Error> {
    match sig_record {
        RData::Rrsig { signature, .. } => Ok(signature),
        _ => Err(Sig0Error::MalformedSignature),
    }
}

/// Verifies an ECDSA signature using the supplied ring algorithm descriptor.
fn verify_ecdsa(
    message: &[u8],
    signature: &[u8],
    public_key_rdata: &[u8],
    algorithm: &'static ring::signature::EcdsaVerificationAlgorithm,
) -> Result<(), Sig0Error> {
    let public_key = ring::signature::UnparsedPublicKey::new(algorithm, public_key_rdata);
    public_key.verify(message, signature).map_err(|_| Sig0Error::InvalidSignature)
}

/// Verifies an Ed25519 signature.
fn verify_ed25519(
    message: &[u8],
    signature: &[u8],
    public_key_rdata: &[u8],
) -> Result<(), Sig0Error> {
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_rdata);
    public_key.verify(message, signature).map_err(|_| Sig0Error::InvalidSignature)
}

/// Strips the SIG(0) record from the additional section of a DNS message wire
/// buffer and decrements arcount.  Returns the original buffer unchanged if the
/// SIG(0) record cannot be located.
fn strip_sig0_from_wire(msg_wire: &[u8]) -> Vec<u8> {
    if msg_wire.len() < 12 {
        return msg_wire.to_vec();
    }
    let arcount = u16::from_be_bytes([msg_wire[10], msg_wire[11]]);
    if arcount == 0 {
        return msg_wire.to_vec();
    }

    match find_sig0_rr_offset(msg_wire) {
        Some(sig0_start) => {
            let mut out = msg_wire[..sig0_start].to_vec();
            let new_arcount = arcount.saturating_sub(1);
            if out.len() >= 12 {
                out[10] = (new_arcount >> 8) as u8;
                out[11] = (new_arcount & 0xFF) as u8;
            }
            out
        }
        None => msg_wire.to_vec(),
    }
}

/// Finds the wire offset of the first SIG record (TYPE 24) in the additional
/// section.  Returns `None` if none is found or if parsing fails.
fn find_sig0_rr_offset(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);

    let mut off = 12usize;

    for _ in 0..qdcount {
        off = skip_name(buf, off)?;
        off = off.checked_add(4)?; // QTYPE + QCLASS
        if off > buf.len() {
            return None;
        }
    }

    let non_ar = u32::from(ancount) + u32::from(nscount);
    for _ in 0..non_ar {
        off = skip_rr(buf, off)?;
    }

    for _ in 0..arcount {
        let rr_start = off;
        off = skip_name(buf, off)?;
        if off + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        if rtype == 24 {
            return Some(rr_start);
        }
        off = off.checked_add(8)?; // TYPE + CLASS + TTL
        let rdlen = usize::from(u16::from_be_bytes([buf[off], buf[off + 1]]));
        off = off.checked_add(2)?.checked_add(rdlen)?;
        if off > buf.len() {
            return None;
        }
    }

    None
}

/// Skips a DNS name (following compression pointers) and returns the new offset.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    let mut follows = 0usize;
    loop {
        let len_byte = *buf.get(off)?;
        off += 1;
        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer — two bytes total, then the name ends here.
            off = off.checked_add(1)?;
            follows += 1;
            if follows > 128 || off > buf.len() {
                return None;
            }
            return Some(off);
        }
        if len_byte == 0 {
            return Some(off);
        }
        off = off.checked_add(usize::from(len_byte))?;
        if off > buf.len() {
            return None;
        }
    }
}

/// Skips a single DNS resource record and returns the offset after it.
fn skip_rr(buf: &[u8], off: usize) -> Option<usize> {
    let off = skip_name(buf, off)?;
    if off + 10 > buf.len() {
        return None;
    }
    // TYPE(2) + CLASS(2) + TTL(4) = 8 bytes, then RDLENGTH(2).
    let rdlen = usize::from(u16::from_be_bytes([buf[off + 8], buf[off + 9]]));
    let next = off.checked_add(10)?.checked_add(rdlen)?;
    if next > buf.len() {
        return None;
    }
    Some(next)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig0_algorithm_from_u8() {
        assert_eq!(Sig0Algorithm::from_u8(8), Some(Sig0Algorithm::RsaSha256));
        assert_eq!(Sig0Algorithm::from_u8(10), Some(Sig0Algorithm::RsaSha512));
        assert_eq!(Sig0Algorithm::from_u8(13), Some(Sig0Algorithm::EcdsaP256Sha256));
        assert_eq!(Sig0Algorithm::from_u8(14), Some(Sig0Algorithm::EcdsaP384Sha384));
        assert_eq!(Sig0Algorithm::from_u8(15), Some(Sig0Algorithm::Ed25519));
        // Deprecated algorithms must return None.
        assert_eq!(Sig0Algorithm::from_u8(1), None); // RSAMD5
        assert_eq!(Sig0Algorithm::from_u8(5), None); // RSASHA1
        assert_eq!(Sig0Algorithm::from_u8(0), None);
    }

    #[test]
    fn sig0_algorithm_as_u8() {
        assert_eq!(Sig0Algorithm::EcdsaP256Sha256.as_u8(), 13);
        assert_eq!(Sig0Algorithm::Ed25519.as_u8(), 15);
    }

    #[test]
    fn sig0_error_display() {
        assert!(Sig0Error::UnsupportedAlgorithm.to_string().contains("not supported"));
        assert!(Sig0Error::InvalidSignature.to_string().contains("failed"));
        assert!(Sig0Error::MalformedPublicKey.to_string().contains("malformed"));
        assert!(Sig0Error::MalformedSignature.to_string().contains("malformed"));
    }

    #[test]
    fn verify_wrong_rdata_variant() {
        use std::net::Ipv4Addr;
        let sig_record = RData::A(Ipv4Addr::new(1, 2, 3, 4));
        let err = Sig0Verifier::verify(&[], &sig_record, &[], Sig0Algorithm::Ed25519).unwrap_err();
        assert_eq!(err, Sig0Error::MalformedSignature);
    }

    #[test]
    fn verify_ed25519_invalid_key_material() {
        use crate::record::Rtype;
        let sig_record = RData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 15,
            labels: 0,
            original_ttl: 0,
            sig_expiration: 0,
            sig_inception: 0,
            key_tag: 0,
            signer_name: crate::name::Name::root(),
            signature: vec![0u8; 64], // invalid Ed25519 signature
        };
        let result =
            Sig0Verifier::verify(&[0u8; 12], &sig_record, &[0u8; 32], Sig0Algorithm::Ed25519);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rsa_unsupported() {
        use crate::record::Rtype;
        let sig_record = RData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 8,
            labels: 0,
            original_ttl: 0,
            sig_expiration: 0,
            sig_inception: 0,
            key_tag: 0,
            signer_name: crate::name::Name::root(),
            signature: vec![0u8; 64],
        };
        let err =
            Sig0Verifier::verify(&[0u8; 12], &sig_record, &[0u8; 64], Sig0Algorithm::RsaSha256)
                .unwrap_err();
        assert_eq!(err, Sig0Error::UnsupportedAlgorithm);
    }
}
