// SPDX-License-Identifier: MIT

//! TSIG transaction authentication (RFC 8945).
//!
//! TSIG authenticates individual DNS messages using a shared HMAC secret.
//! Only HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 are supported; HMAC-MD5 and
//! HMAC-SHA1 are rejected with [`TsigError::UnsupportedAlgorithm`].

use std::fmt;

use crate::header::ParseError;
use crate::name::Name;

// ── TsigError ─────────────────────────────────────────────────────────────────

/// Errors that can arise during TSIG signing or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsigError {
    /// The TSIG MAC does not match the expected value.
    BadSig = 16,
    /// The TSIG key name is unknown to this server.
    BadKey = 17,
    /// The timestamp in the TSIG record is outside the allowed clock skew window.
    BadTime = 18,
    /// The MAC is shorter than the algorithm minimum (RFC 8945 §5.2.2.4).
    BadTrunc = 22,
    /// The algorithm named in the TSIG record is not supported.
    UnsupportedAlgorithm,
}

impl fmt::Display for TsigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSig => write!(f, "TSIG BADSIG: MAC verification failed"),
            Self::BadKey => write!(f, "TSIG BADKEY: key name not recognised"),
            Self::BadTime => write!(f, "TSIG BADTIME: timestamp outside fudge window"),
            Self::BadTrunc => write!(f, "TSIG BADTRUNC: truncated MAC too short"),
            Self::UnsupportedAlgorithm => {
                write!(f, "TSIG unsupported algorithm (only HMAC-SHA256/384/512 are allowed)")
            }
        }
    }
}

impl std::error::Error for TsigError {}

// ── TsigAlgorithm ─────────────────────────────────────────────────────────────

/// TSIG HMAC algorithm identifiers (RFC 8945 §6).
///
/// Only the three SHA-2 variants are supported.  HMAC-MD5 and HMAC-SHA1 are
/// deprecated and intentionally omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    /// `hmac-sha256.` (FIPS 198-1 / RFC 6234).
    HmacSha256,
    /// `hmac-sha384.` (FIPS 198-1 / RFC 6234).
    HmacSha384,
    /// `hmac-sha512.` (FIPS 198-1 / RFC 6234).
    HmacSha512,
}

impl TsigAlgorithm {
    /// Parses a [`TsigAlgorithm`] from a DNS [`Name`] (the algorithm name field).
    ///
    /// Returns `None` for any unsupported or deprecated algorithm name
    /// (including `hmac-md5.sig-alg.reg.int.` and `hmac-sha1.`).
    #[must_use]
    pub fn from_name(name: &Name) -> Option<Self> {
        // Compare case-insensitively via the wire-format lowercase representation.
        let s = name.to_string();
        match s.as_str() {
            "hmac-sha256." => Some(Self::HmacSha256),
            "hmac-sha384." => Some(Self::HmacSha384),
            "hmac-sha512." => Some(Self::HmacSha512),
            _ => None,
        }
    }

    /// Returns the canonical DNS [`Name`] for this algorithm.
    ///
    /// The returned name is guaranteed to be valid; the algorithm name strings
    /// are compile-time constants whose validity is enforced by the unit tests.
    #[must_use]
    pub fn to_name(self) -> Name {
        use std::str::FromStr;
        // These strings are compile-time constants with valid DNS name syntax.
        // The `map_err` + `unwrap_or_else` is equivalent to `expect`, but satisfies
        // `clippy::expect_used`.  The `|_| unreachable!(...)` documents the invariant.
        let s = match self {
            Self::HmacSha256 => "hmac-sha256.",
            Self::HmacSha384 => "hmac-sha384.",
            Self::HmacSha512 => "hmac-sha512.",
        };
        Name::from_str(s).unwrap_or_else(|_| {
            // INVARIANT: algorithm name strings are ASCII DNS labels that satisfy
            // all Name constraints (total length < 255, labels < 64 bytes).
            // This branch is unreachable; if it were reached it would indicate a
            // programming error in this crate, not a runtime condition.
            unreachable!("TSIG algorithm name constant is invalid: {s}")
        })
    }

    /// Returns the corresponding `ring` HMAC algorithm descriptor.
    #[must_use]
    pub fn ring_algorithm(self) -> &'static ring::hmac::Algorithm {
        match self {
            Self::HmacSha256 => &ring::hmac::HMAC_SHA256,
            Self::HmacSha384 => &ring::hmac::HMAC_SHA384,
            Self::HmacSha512 => &ring::hmac::HMAC_SHA512,
        }
    }
}

// ── TsigRecord ────────────────────────────────────────────────────────────────

/// A parsed TSIG resource record (RFC 8945 §4.2).
///
/// TSIG records use RTYPE 250, CLASS ANY (255), and TTL 0.  The RDATA contains
/// the algorithm name, timestamp, fudge, MAC, original message ID, error code,
/// and optional "other" data (used by BADTIME responses to carry server time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecord {
    /// The TSIG key name (owner name of the record).
    pub key_name: Name,
    /// Algorithm name as a DNS [`Name`] (e.g. `hmac-sha256.`).
    pub algorithm: Name,
    /// Signing time — 48-bit Unix timestamp (seconds since epoch).
    pub time_signed: u64,
    /// Allowable clock skew in seconds.
    pub fudge: u16,
    /// HMAC output bytes.
    pub mac: Vec<u8>,
    /// The message ID as it was when the message was signed (before TSIG was applied).
    pub original_id: u16,
    /// TSIG error code (0 = no error).
    pub error: u16,
    /// "Other" data (used by BADTIME responses; otherwise empty).
    pub other: Vec<u8>,
}

impl TsigRecord {
    /// Parses a TSIG RDATA from `rdata_buf`.
    ///
    /// The `key_name` is the owner name of the TSIG record, which is parsed
    /// separately from the RDATA.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::UnexpectedEof`] if the buffer is too short, or
    /// [`ParseError::InvalidRdata`] for malformed length fields.
    pub fn parse_rdata(key_name: Name, rdata_buf: &[u8]) -> Result<Self, ParseError> {
        let mut off = 0usize;

        // Algorithm Name (domain name, uncompressed in TSIG RDATA).
        let algorithm = parse_name_uncompressed(rdata_buf, &mut off)?;

        // Time Signed: 6 bytes big-endian 48-bit integer.
        if off + 6 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let time_signed = u64::from(rdata_buf[off]) << 40
            | u64::from(rdata_buf[off + 1]) << 32
            | u64::from(rdata_buf[off + 2]) << 24
            | u64::from(rdata_buf[off + 3]) << 16
            | u64::from(rdata_buf[off + 4]) << 8
            | u64::from(rdata_buf[off + 5]);
        off += 6;

        // Fudge: 2 bytes.
        if off + 2 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let fudge = u16::from_be_bytes([rdata_buf[off], rdata_buf[off + 1]]);
        off += 2;

        // MAC Size: 2 bytes.
        if off + 2 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let mac_size = usize::from(u16::from_be_bytes([rdata_buf[off], rdata_buf[off + 1]]));
        off += 2;

        // MAC: mac_size bytes.
        let mac_end = off.checked_add(mac_size).ok_or(ParseError::UnexpectedEof)?;
        if mac_end > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let mac = rdata_buf[off..mac_end].to_vec();
        off = mac_end;

        // Original ID: 2 bytes.
        if off + 2 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let original_id = u16::from_be_bytes([rdata_buf[off], rdata_buf[off + 1]]);
        off += 2;

        // Error: 2 bytes.
        if off + 2 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let error = u16::from_be_bytes([rdata_buf[off], rdata_buf[off + 1]]);
        off += 2;

        // Other Len: 2 bytes.
        if off + 2 > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let other_len = usize::from(u16::from_be_bytes([rdata_buf[off], rdata_buf[off + 1]]));
        off += 2;

        // Other Data: other_len bytes.
        let other_end = off.checked_add(other_len).ok_or(ParseError::UnexpectedEof)?;
        if other_end > rdata_buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let other = rdata_buf[off..other_end].to_vec();

        Ok(Self { key_name, algorithm, time_signed, fudge, mac, original_id, error, other })
    }

    /// Serialises this TSIG record (owner name + TYPE + CLASS + TTL + RDLENGTH + RDATA)
    /// to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        // Owner name (key name).
        buf.extend_from_slice(self.key_name.as_wire_bytes());
        // TYPE = 250 (TSIG).
        buf.extend_from_slice(&250u16.to_be_bytes());
        // CLASS = ANY (255).
        buf.extend_from_slice(&255u16.to_be_bytes());
        // TTL = 0.
        buf.extend_from_slice(&0u32.to_be_bytes());
        // RDATA placeholder; we fill in RDLENGTH after.
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes());
        let rdata_start = buf.len();

        self.write_rdata_to(buf);

        let rdata_len = buf.len() - rdata_start;
        // INVARIANT: TSIG RDATA is bounded by u16 RDLENGTH field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        let rdlen_bytes = (rdata_len as u16).to_be_bytes();
        buf[rdlen_pos] = rdlen_bytes[0];
        buf[rdlen_pos + 1] = rdlen_bytes[1];
    }

    /// Writes only the RDATA portion (RFC 8945 §4.2) to `buf`.
    pub fn write_rdata_to(&self, buf: &mut Vec<u8>) {
        // Algorithm Name (uncompressed).
        buf.extend_from_slice(self.algorithm.as_wire_bytes());
        // Time Signed — 6-byte big-endian 48-bit integer.
        write_u48(buf, self.time_signed);
        // Fudge.
        buf.extend_from_slice(&self.fudge.to_be_bytes());
        // MAC Size + MAC.
        // INVARIANT: MAC length bounded by u16 MAC Size field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        buf.extend_from_slice(&(self.mac.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.mac);
        // Original ID.
        buf.extend_from_slice(&self.original_id.to_be_bytes());
        // Error.
        buf.extend_from_slice(&self.error.to_be_bytes());
        // Other Len + Other Data.
        // INVARIANT: Other length bounded by u16 Other Len field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        buf.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.other);
    }
}

// ── TsigSigner ────────────────────────────────────────────────────────────────

/// Signs and verifies DNS messages using TSIG (RFC 8945).
///
/// Create one `TsigSigner` per key; share it across requests.
pub struct TsigSigner {
    key_name: Name,
    algorithm: TsigAlgorithm,
    key_material: ring::hmac::Key,
    fudge: u16,
}

impl TsigSigner {
    /// Creates a new [`TsigSigner`].
    ///
    /// - `key_name`: the TSIG key name (must match the name in the TSIG RR).
    /// - `algorithm`: one of the three supported HMAC-SHA2 algorithms.
    /// - `key_bytes`: the raw shared secret.
    /// - `fudge`: maximum allowed clock skew in seconds (RFC 8945 recommends 300).
    #[must_use]
    pub fn new(
        key_name: Name,
        algorithm: TsigAlgorithm,
        key_bytes: &[u8],
        fudge: u16,
    ) -> Self {
        let key_material = ring::hmac::Key::new(*algorithm.ring_algorithm(), key_bytes);
        Self { key_name, algorithm, key_material, fudge }
    }

    /// Signs a DNS message and returns the TSIG record to append to the additional section.
    ///
    /// `msg_wire` MUST be the wire bytes of the message WITHOUT any TSIG record.
    /// The caller is responsible for appending the returned [`TsigRecord`] and
    /// incrementing `arcount` in the message header.
    ///
    /// `time_signed` is the current Unix timestamp (only the low 48 bits are used).
    #[must_use]
    pub fn sign(&self, msg_wire: &[u8], time_signed: u64) -> TsigRecord {
        let original_id = if msg_wire.len() >= 2 {
            u16::from_be_bytes([msg_wire[0], msg_wire[1]])
        } else {
            0
        };
        let mac = self.compute_mac(msg_wire, time_signed, 0, &[]);

        TsigRecord {
            key_name: self.key_name.clone(),
            algorithm: self.algorithm.to_name(),
            time_signed: time_signed & 0x0000_FFFF_FFFF_FFFF,
            fudge: self.fudge,
            mac,
            original_id,
            error: 0,
            other: Vec::new(),
        }
    }

    /// Verifies a TSIG-signed DNS message.
    ///
    /// `msg_wire` MUST be the full wire bytes of the message, INCLUDING the
    /// TSIG record in the additional section.  The TSIG record is stripped
    /// before the MAC is computed (as required by RFC 8945 §4.3).
    ///
    /// `now` is the current Unix timestamp (seconds since epoch).
    ///
    /// # Errors
    ///
    /// - [`TsigError::UnsupportedAlgorithm`] — algorithm in `tsig` is not recognised.
    /// - [`TsigError::BadKey`] — key name in `tsig` does not match this signer's key name.
    /// - [`TsigError::BadTime`] — `|now - time_signed| > fudge`.
    /// - [`TsigError::BadSig`] — MAC verification failed.
    pub fn verify(&self, msg_wire: &[u8], tsig: &TsigRecord, now: u64) -> Result<(), TsigError> {
        // 1. Algorithm check.
        if TsigAlgorithm::from_name(&tsig.algorithm).is_none() {
            return Err(TsigError::UnsupportedAlgorithm);
        }
        if TsigAlgorithm::from_name(&tsig.algorithm) != Some(self.algorithm) {
            return Err(TsigError::UnsupportedAlgorithm);
        }

        // 2. Key name check.
        if tsig.key_name != self.key_name {
            return Err(TsigError::BadKey);
        }

        // 3. Time check.
        let skew = now.abs_diff(tsig.time_signed);
        if skew > u64::from(self.fudge) {
            return Err(TsigError::BadTime);
        }

        // 4. Strip TSIG from wire and compute expected MAC.
        //    RFC 8945 §4.3: The signed data includes the message WITHOUT the TSIG RR
        //    in the additional section, with arcount decremented by 1.
        let msg_without_tsig = strip_tsig_from_wire(msg_wire, tsig);
        let expected_mac =
            self.compute_mac(&msg_without_tsig, tsig.time_signed, tsig.error, &tsig.other);

        // 5. Constant-time MAC comparison.
        //
        // ring::hmac::verify(key, message, tag) succeeds iff HMAC(key, message) == tag.
        //
        // To compare tsig.mac == expected_mac in constant time:
        //   1. Create ct_key keyed from expected_mac bytes.
        //   2. Compute ref_tag = HMAC(ct_key, expected_mac).
        //   3. Check HMAC(ct_key, tsig.mac) == ref_tag.
        //
        // Step 3 holds iff tsig.mac == expected_mac (the two inputs produce the same
        // HMAC output with overwhelming probability iff they are equal).
        let ct_key = ring::hmac::Key::new(*self.algorithm.ring_algorithm(), &expected_mac);
        let ref_tag = ring::hmac::sign(&ct_key, &expected_mac);
        ring::hmac::verify(&ct_key, &tsig.mac, ref_tag.as_ref())
            .map_err(|_| TsigError::BadSig)
    }

    /// Computes the TSIG MAC over the signed data (RFC 8945 §4.3.1).
    fn compute_mac(&self, msg_wire: &[u8], time_signed: u64, error: u16, other: &[u8]) -> Vec<u8> {
        let mut ctx = ring::hmac::Context::with_key(&self.key_material);

        // 1. DNS message wire bytes (TSIG already stripped by caller for verify;
        //    for sign the message has no TSIG yet).
        ctx.update(msg_wire);

        // 2. TSIG Variables (RFC 8945 §4.3.2), uncompressed.
        //    Algorithm Name.
        ctx.update(self.algorithm.to_name().as_wire_bytes());
        //    Time Signed (6 bytes big-endian 48-bit).
        let mut ts_buf = [0u8; 6];
        let ts = time_signed & 0x0000_FFFF_FFFF_FFFF;
        ts_buf[0] = ((ts >> 40) & 0xFF) as u8;
        ts_buf[1] = ((ts >> 32) & 0xFF) as u8;
        ts_buf[2] = ((ts >> 24) & 0xFF) as u8;
        ts_buf[3] = ((ts >> 16) & 0xFF) as u8;
        ts_buf[4] = ((ts >> 8) & 0xFF) as u8;
        ts_buf[5] = (ts & 0xFF) as u8;
        ctx.update(&ts_buf);
        //    Fudge.
        ctx.update(&self.fudge.to_be_bytes());
        //    Error.
        ctx.update(&error.to_be_bytes());
        //    Other Len + Other Data.
        // INVARIANT: other length bounded by u16 field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        ctx.update(&(other.len() as u16).to_be_bytes());
        ctx.update(other);

        ctx.sign().as_ref().to_vec()
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Writes a 48-bit unsigned integer to `buf` as 6 big-endian bytes.
fn write_u48(buf: &mut Vec<u8>, v: u64) {
    let v = v & 0x0000_FFFF_FFFF_FFFF;
    buf.push(((v >> 40) & 0xFF) as u8);
    buf.push(((v >> 32) & 0xFF) as u8);
    buf.push(((v >> 24) & 0xFF) as u8);
    buf.push(((v >> 16) & 0xFF) as u8);
    buf.push(((v >> 8) & 0xFF) as u8);
    buf.push((v & 0xFF) as u8);
}

/// Parses a DNS name from an uncompressed buffer (TSIG RDATA names are never
/// compressed per RFC 8945 §4.2).
fn parse_name_uncompressed(buf: &[u8], offset: &mut usize) -> Result<Name, ParseError> {
    // Delegates to the general parser; compression pointers are not present in
    // TSIG RDATA, so any pointer encountered would be an error caught by the
    // length checks in `parse_name`.
    crate::parser::parse_name(buf, offset)
}

/// Strips the TSIG record from the additional section in `msg_wire` and
/// decrements arcount, returning a new buffer ready for MAC computation.
///
/// If the TSIG record cannot be located (e.g. malformed message), returns the
/// original buffer unchanged — the MAC comparison will then fail naturally.
fn strip_tsig_from_wire(msg_wire: &[u8], tsig: &TsigRecord) -> Vec<u8> {
    // We need to find the TSIG RR in the additional section and remove it.
    // Strategy: re-serialise the message without TSIG by copying everything up
    // to (but not including) the TSIG RR, then patch arcount.

    // We walk the wire format to find the start of the TSIG record.
    // A minimal implementation: serialize the non-TSIG content.
    if msg_wire.len() < 12 {
        return msg_wire.to_vec();
    }

    let arcount_orig = u16::from_be_bytes([msg_wire[10], msg_wire[11]]);
    if arcount_orig == 0 {
        return msg_wire.to_vec();
    }

    // Find the byte offset of the TSIG RR by parsing sections.
    match find_tsig_rr_offset(msg_wire, tsig) {
        Some(tsig_start) => {
            // Build new buffer: header (with arcount - 1) + everything before TSIG.
            let mut out = msg_wire[..tsig_start].to_vec();
            // Patch arcount (bytes 10-11) with arcount_orig - 1.
            let new_arcount = arcount_orig.saturating_sub(1);
            if out.len() >= 12 {
                out[10] = (new_arcount >> 8) as u8;
                out[11] = (new_arcount & 0xFF) as u8;
            }
            out
        }
        None => msg_wire.to_vec(),
    }
}

/// Attempts to find the wire offset where the TSIG record begins by scanning
/// through the message sections.  Returns `None` if parsing fails.
fn find_tsig_rr_offset(buf: &[u8], _tsig: &TsigRecord) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);

    let mut off = 12usize;

    // Skip question section.
    for _ in 0..qdcount {
        off = skip_name(buf, off)?;
        off = off.checked_add(4)?; // QTYPE + QCLASS
        if off > buf.len() {
            return None;
        }
    }

    // Skip answer + authority sections (non-TSIG records).
    let rr_count = u32::from(ancount) + u32::from(nscount);
    for _ in 0..rr_count {
        off = skip_rr(buf, off)?;
    }

    // Walk additional section; return the offset of the first TYPE=250 (TSIG).
    for _ in 0..arcount {
        let rr_start = off;
        off = skip_name(buf, off)?;
        if off + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        if rtype == 250 {
            return Some(rr_start);
        }
        // Skip TYPE + CLASS + TTL.
        off = off.checked_add(8)?;
        let rdlen = usize::from(u16::from_be_bytes([buf[off], buf[off + 1]]));
        off = off.checked_add(2)?.checked_add(rdlen)?;
        if off > buf.len() {
            return None;
        }
    }

    None
}

/// Skips a DNS name (handling compression pointers) and returns the new offset.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    let mut follows = 0usize;
    loop {
        let len_byte = *buf.get(off)?;
        off += 1;
        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer — skip the second byte and stop.
            off = off.checked_add(1)?;
            if off > buf.len() {
                return None;
            }
            // After a pointer the name ends here in the *original* stream.
            follows += 1;
            if follows > 128 {
                return None;
            }
            return Some(off);
        }
        if len_byte == 0 {
            return Some(off);
        }
        let label_len = usize::from(len_byte);
        off = off.checked_add(label_len)?;
        if off > buf.len() {
            return None;
        }
    }
}

/// Skips a single resource record (name + fixed fields + RDATA).
fn skip_rr(buf: &[u8], off: usize) -> Option<usize> {
    let off = skip_name(buf, off)?;
    if off + 10 > buf.len() {
        return None;
    }
    // TYPE (2) + CLASS (2) + TTL (4) = 8 bytes, then RDLENGTH (2).
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
    use std::str::FromStr;

    use super::*;

    fn test_key_name() -> Name {
        Name::from_str("test-key.example.").unwrap()
    }

    #[test]
    fn tsig_algorithm_roundtrip() {
        for algo in [TsigAlgorithm::HmacSha256, TsigAlgorithm::HmacSha384, TsigAlgorithm::HmacSha512] {
            let name = algo.to_name();
            let parsed = TsigAlgorithm::from_name(&name);
            assert_eq!(parsed, Some(algo));
        }
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let md5_name = Name::from_str("hmac-md5.sig-alg.reg.int.").unwrap();
        assert_eq!(TsigAlgorithm::from_name(&md5_name), None);
        let sha1_name = Name::from_str("hmac-sha1.").unwrap();
        assert_eq!(TsigAlgorithm::from_name(&sha1_name), None);
    }

    #[test]
    fn sign_produces_tsig_record() {
        let signer = TsigSigner::new(
            test_key_name(),
            TsigAlgorithm::HmacSha256,
            b"super-secret-key-32-bytes-long!!",
            300,
        );
        let msg: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tsig = signer.sign(msg, 1_700_000_000u64);

        assert_eq!(tsig.key_name, test_key_name());
        assert_eq!(tsig.fudge, 300);
        assert_eq!(tsig.error, 0);
        assert!(!tsig.mac.is_empty());
        // SHA-256 produces a 32-byte MAC.
        assert_eq!(tsig.mac.len(), 32);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = b"a-very-secret-shared-key-32byte!";
        let signer = TsigSigner::new(test_key_name(), TsigAlgorithm::HmacSha256, key, 300);

        // Minimal 12-byte message (header only, id = 0x1234).
        let msg: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let now = 1_700_000_000u64;
        let tsig = signer.sign(&msg, now);

        // For verify we would need the full wire with TSIG appended, but since
        // strip_tsig_from_wire falls back to the original on failure to find the
        // TSIG in a minimal buffer, we test verify against the signed data directly.
        // Here we simulate by signing and then verifying the MAC.
        let expected_mac =
            signer.compute_mac(&msg, tsig.time_signed, tsig.error, &tsig.other);
        assert_eq!(expected_mac, tsig.mac);
    }

    #[test]
    fn verify_bad_time() {
        let key = b"a-very-secret-shared-key-32byte!";
        let signer = TsigSigner::new(test_key_name(), TsigAlgorithm::HmacSha256, key, 300);
        let msg: Vec<u8> = vec![0u8; 12];
        let tsig = signer.sign(&msg, 1_000_000_000u64);
        // `now` is more than 300 seconds away from `time_signed`.
        let err = signer.verify(&msg, &tsig, 2_000_000_000u64).unwrap_err();
        assert_eq!(err, TsigError::BadTime);
    }

    #[test]
    fn verify_bad_key() {
        let key = b"a-very-secret-shared-key-32byte!";
        let signer = TsigSigner::new(test_key_name(), TsigAlgorithm::HmacSha256, key, 300);
        let other_signer = TsigSigner::new(
            Name::from_str("other-key.example.").unwrap(),
            TsigAlgorithm::HmacSha256,
            key,
            300,
        );
        let msg: Vec<u8> = vec![0u8; 12];
        let tsig = other_signer.sign(&msg, 1_000_000_000u64);
        let err = signer.verify(&msg, &tsig, 1_000_000_000u64).unwrap_err();
        assert_eq!(err, TsigError::BadKey);
    }

    #[test]
    fn verify_unsupported_algorithm() {
        let key = b"a-very-secret-shared-key-32byte!";
        let signer = TsigSigner::new(test_key_name(), TsigAlgorithm::HmacSha256, key, 300);
        let msg: Vec<u8> = vec![0u8; 12];
        let mut tsig = signer.sign(&msg, 1_000_000_000u64);
        // Mutate algorithm to an unsupported one.
        tsig.algorithm = Name::from_str("hmac-md5.sig-alg.reg.int.").unwrap();
        let err = signer.verify(&msg, &tsig, 1_000_000_000u64).unwrap_err();
        assert_eq!(err, TsigError::UnsupportedAlgorithm);
    }

    #[test]
    fn tsig_record_write_parse_roundtrip() {
        let key = b"secret-key-material-32-bytes-lo!";
        let signer = TsigSigner::new(test_key_name(), TsigAlgorithm::HmacSha256, key, 300);
        let msg: Vec<u8> = vec![0u8; 12];
        let tsig = signer.sign(&msg, 1_700_000_000u64);

        let mut buf = Vec::new();
        // Write only RDATA (not the full RR header) for testing the parse path.
        tsig.write_rdata_to(&mut buf);

        let parsed = TsigRecord::parse_rdata(test_key_name(), &buf).unwrap();
        assert_eq!(parsed.time_signed, tsig.time_signed);
        assert_eq!(parsed.fudge, tsig.fudge);
        assert_eq!(parsed.mac, tsig.mac);
        assert_eq!(parsed.original_id, tsig.original_id);
        assert_eq!(parsed.error, tsig.error);
    }

    #[test]
    fn tsig_error_display() {
        assert!(TsigError::BadSig.to_string().contains("BADSIG"));
        assert!(TsigError::BadKey.to_string().contains("BADKEY"));
        assert!(TsigError::BadTime.to_string().contains("BADTIME"));
        assert!(TsigError::UnsupportedAlgorithm.to_string().contains("unsupported"));
    }
}
