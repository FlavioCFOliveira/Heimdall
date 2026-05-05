// SPDX-License-Identifier: MIT

//! EDNS(0) framework (RFC 6891), DNS Cookies (RFC 7873 / RFC 9018),
//! padding (RFC 7830 / RFC 8467), Extended DNS Errors (RFC 8914),
//! NSID (RFC 5001), and edns-tcp-keepalive (RFC 7828).

use crate::header::ParseError;

// ── Extended DNS Error info-codes (RFC 8914 §5.2) ────────────────────────────

/// Standard EDE info-code constants (RFC 8914 §5.2).
pub mod ede_code {
    /// Other — catch-all for errors not listed below.
    pub const OTHER: u16 = 0;
    /// Unsupported DNSKEY Algorithm.
    pub const UNSUPPORTED_DNSKEY_ALGORITHM: u16 = 1;
    /// Unsupported DS Digest Type.
    pub const UNSUPPORTED_DS_DIGEST_TYPE: u16 = 2;
    /// Stale Answer.
    pub const STALE_ANSWER: u16 = 3;
    /// Forged Answer.
    pub const FORGED_ANSWER: u16 = 4;
    /// DNSSEC Indeterminate.
    pub const DNSSEC_INDETERMINATE: u16 = 5;
    /// DNSSEC Bogus.
    pub const DNSSEC_BOGUS: u16 = 6;
    /// Signature Expired.
    pub const SIGNATURE_EXPIRED: u16 = 7;
    /// Signature Not Yet Valid.
    pub const SIGNATURE_NOT_YET_VALID: u16 = 8;
    /// DNSKEY Missing.
    pub const DNSKEY_MISSING: u16 = 9;
    /// RRSIGs Missing.
    pub const RRSIGS_MISSING: u16 = 10;
    /// No Zone Key Bit Set.
    pub const NO_ZONE_KEY_BIT_SET: u16 = 11;
    /// NSEC Missing.
    pub const NSEC_MISSING: u16 = 12;
    /// Cached Error.
    pub const CACHED_ERROR: u16 = 13;
    /// Not Ready.
    pub const NOT_READY: u16 = 14;
    /// Blocked.
    pub const BLOCKED: u16 = 15;
    /// Censored.
    pub const CENSORED: u16 = 16;
    /// Filtered.
    pub const FILTERED: u16 = 17;
    /// Prohibited.
    pub const PROHIBITED: u16 = 18;
    /// Stale NXDOMAIN Answer.
    pub const STALE_NXDOMAIN_ANSWER: u16 = 19;
    /// Not Authoritative.
    pub const NOT_AUTHORITATIVE: u16 = 20;
    /// Not Supported.
    pub const NOT_SUPPORTED: u16 = 21;
    /// No Reachable Authority.
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    /// Network Error.
    pub const NETWORK_ERROR: u16 = 23;
    /// Invalid Data.
    pub const INVALID_DATA: u16 = 24;
    /// Signature Expired Before Valid.
    pub const SIGNATURE_EXPIRED_BEFORE_VALID: u16 = 25;
    /// Too Early.
    pub const TOO_EARLY: u16 = 26;
    /// Unsupported NSEC3 Iterations Value.
    pub const UNSUPPORTED_NSEC3_ITERATIONS_VALUE: u16 = 27;
    /// Unable to Conform to Policy.
    pub const UNABLE_TO_CONFORM_TO_POLICY: u16 = 28;
    /// Synthesized.
    pub const SYNTHESIZED: u16 = 29;
    /// Invalid Query Type.
    pub const INVALID_QUERY_TYPE: u16 = 30;
}

// ── ExtendedError (RFC 8914) ──────────────────────────────────────────────────

/// An Extended DNS Error (EDE) option value (RFC 8914 §5).
///
/// The `info_code` identifies the error; `extra_text` is an optional
/// human-readable UTF-8 string for diagnostic purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedError {
    /// EDE info code (see [`ede_code`]).
    pub info_code: u16,
    /// Optional human-readable extra text (UTF-8, may contain non-ASCII).
    pub extra_text: Option<String>,
}

impl ExtendedError {
    /// Creates an [`ExtendedError`] with only an info code and no extra text.
    #[must_use]
    pub fn new(info_code: u16) -> Self {
        Self {
            info_code,
            extra_text: None,
        }
    }

    /// Creates an [`ExtendedError`] with an info code and extra text.
    #[must_use]
    pub fn with_text(info_code: u16, text: impl Into<String>) -> Self {
        Self {
            info_code,
            extra_text: Some(text.into()),
        }
    }

    /// Wire length of this EDE option value (2 bytes `info_code` + optional text).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        2 + self.extra_text.as_ref().map_or(0, String::len)
    }

    /// Writes this EDE option value (not the TLV wrapper) to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.info_code.to_be_bytes());
        if let Some(text) = &self.extra_text {
            buf.extend_from_slice(text.as_bytes());
        }
    }

    /// Parses an EDE option value from `data` (the option payload, after the TLV header).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidRdata`] if the payload is too short or the
    /// extra text is not valid UTF-8.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 2 {
            return Err(ParseError::InvalidRdata {
                rtype: 41,
                reason: "EDE option too short",
            });
        }
        let info_code = u16::from_be_bytes([data[0], data[1]]);
        let extra_text = if data.len() > 2 {
            let s = std::str::from_utf8(&data[2..]).map_err(|_| ParseError::InvalidRdata {
                rtype: 41,
                reason: "EDE extra text is not valid UTF-8",
            })?;
            Some(s.to_owned())
        } else {
            None
        };
        Ok(Self {
            info_code,
            extra_text,
        })
    }
}

// ── EdnsCookie (RFC 7873) ─────────────────────────────────────────────────────

/// The value of an EDNS Cookie option (RFC 7873 §4).
///
/// A DNS Cookie consists of a mandatory 8-byte client cookie and an optional
/// server cookie (8–32 bytes) present when the client has a previously received
/// server cookie or when the server is sending a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsCookie {
    /// 8-byte client cookie (random, generated by the client per RFC 7873 §5.1).
    pub client: [u8; 8],
    /// Server cookie (8–32 bytes), present in responses and in repeat queries.
    pub server: Option<Vec<u8>>,
}

impl EdnsCookie {
    /// Wire length of the full cookie option value.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        8 + self.server.as_ref().map_or(0, Vec::len)
    }

    /// Writes the cookie option value (not the TLV wrapper) to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client);
        if let Some(server) = &self.server {
            buf.extend_from_slice(server);
        }
    }

    /// Parses a cookie option value from `data`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidRdata`] if the data is shorter than 8 bytes or
    /// the server cookie length is outside the valid range (8–32 bytes).
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::InvalidRdata {
                rtype: 41,
                reason: "Cookie option too short (client cookie must be 8 bytes)",
            });
        }
        let client: [u8; 8] = data[..8].try_into().map_err(|_| ParseError::InvalidRdata {
            rtype: 41,
            reason: "Cookie client section truncated",
        })?;
        let server = if data.len() > 8 {
            let server_data = &data[8..];
            let server_len = server_data.len();
            if !(8..=32).contains(&server_len) {
                return Err(ParseError::InvalidRdata {
                    rtype: 41,
                    reason: "Cookie server section must be 8-32 bytes",
                });
            }
            Some(server_data.to_vec())
        } else {
            None
        };
        Ok(Self { client, server })
    }
}

// ── EdnsOption ────────────────────────────────────────────────────────────────

/// A single EDNS(0) option (one TLV entry from the OPT RDATA, RFC 6891 §6.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdnsOption {
    /// LLQ — Long-Lived Queries (RFC 8764), raw bytes.  Code 1.
    Llq(Vec<u8>),
    /// NSID — Name Server Identifier (RFC 5001).  Code 3.
    Nsid(Vec<u8>),
    /// DAU — DNSSEC Algorithm Understood (RFC 6975).  Code 5.
    Dau(Vec<u8>),
    /// DHU — DS Hash Understood (RFC 6975).  Code 6.
    Dhu(Vec<u8>),
    /// N3U — NSEC3 Hash Understood (RFC 6975).  Code 7.
    N3u(Vec<u8>),
    /// Client Subnet — ECS (RFC 7871), raw bytes.  Code 8.
    ClientSubnet(Vec<u8>),
    /// Expire — RFC 7314, raw bytes.  Code 9.
    Expire(Vec<u8>),
    /// Cookie — RFC 7873.  Code 10.
    Cookie(EdnsCookie),
    /// TCP Keepalive — RFC 7828.  Code 11.  `None` = no timeout advertised.
    TcpKeepalive(Option<u16>),
    /// Padding — RFC 7830.  Code 12.  Contains the number of padding bytes.
    Padding(u16),
    /// Chain — RFC 7901, raw bytes.  Code 13.
    Chain(Vec<u8>),
    /// Key Tag — RFC 8145.  Code 14.
    KeyTag(Vec<u16>),
    /// Extended Error — RFC 8914.  Code 15.
    ExtendedError(ExtendedError),
    /// An option whose code is not recognised by this implementation.
    Unknown {
        /// The raw option code.
        code: u16,
        /// The raw option data bytes.
        data: Vec<u8>,
    },
}

impl EdnsOption {
    /// Returns the option code for this option.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::Llq(_) => 1,
            Self::Nsid(_) => 3,
            Self::Dau(_) => 5,
            Self::Dhu(_) => 6,
            Self::N3u(_) => 7,
            Self::ClientSubnet(_) => 8,
            Self::Expire(_) => 9,
            Self::Cookie(_) => 10,
            Self::TcpKeepalive(_) => 11,
            Self::Padding(_) => 12,
            Self::Chain(_) => 13,
            Self::KeyTag(_) => 14,
            Self::ExtendedError(_) => 15,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Returns the wire length of the option value (excluding the 4-byte TLV header).
    #[must_use]
    pub fn value_wire_len(&self) -> usize {
        match self {
            Self::Llq(d)
            | Self::Nsid(d)
            | Self::Dau(d)
            | Self::Dhu(d)
            | Self::N3u(d)
            | Self::ClientSubnet(d)
            | Self::Expire(d)
            | Self::Chain(d)
            | Self::Unknown { data: d, .. } => d.len(),
            Self::Cookie(c) => c.wire_len(),
            Self::TcpKeepalive(None) => 0,
            Self::TcpKeepalive(Some(_)) => 2,
            Self::Padding(n) => usize::from(*n),
            Self::KeyTag(tags) => tags.len() * 2,
            Self::ExtendedError(e) => e.wire_len(),
        }
    }

    /// Writes this option (including the 4-byte TLV header) to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.code().to_be_bytes());
        // INVARIANT: option value length ≤ 65535 (bounded by u16 option-length field).
        #[allow(clippy::cast_possible_truncation)]
        buf.extend_from_slice(&(self.value_wire_len() as u16).to_be_bytes());
        self.write_value_to(buf);
    }

    /// Writes only the option value bytes (no TLV header) to `buf`.
    fn write_value_to(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Llq(d)
            | Self::Nsid(d)
            | Self::Dau(d)
            | Self::Dhu(d)
            | Self::N3u(d)
            | Self::ClientSubnet(d)
            | Self::Expire(d)
            | Self::Chain(d)
            | Self::Unknown { data: d, .. } => buf.extend_from_slice(d),
            Self::Cookie(c) => c.write_to(buf),
            Self::TcpKeepalive(None) => {}
            Self::TcpKeepalive(Some(t)) => buf.extend_from_slice(&t.to_be_bytes()),
            Self::Padding(n) => buf.extend(std::iter::repeat_n(0u8, usize::from(*n))),
            Self::KeyTag(tags) => {
                for &tag in tags {
                    buf.extend_from_slice(&tag.to_be_bytes());
                }
            }
            Self::ExtendedError(e) => e.write_to(buf),
        }
    }

    /// Parses a single EDNS option from `buf` starting at `offset`.
    ///
    /// Returns the parsed option and the new offset after the option.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::UnexpectedEof`] if the buffer is truncated, or
    /// a type-specific [`ParseError::InvalidRdata`] for malformed option values.
    pub fn parse(buf: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        // Need at least 4 bytes for code + length.
        let hdr_end = offset.checked_add(4).ok_or(ParseError::UnexpectedEof)?;
        if hdr_end > buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let code = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let opt_len = usize::from(u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]));
        let data_start = hdr_end;
        let data_end = data_start
            .checked_add(opt_len)
            .ok_or(ParseError::UnexpectedEof)?;
        if data_end > buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let data = &buf[data_start..data_end];

        let opt = match code {
            1 => Self::Llq(data.to_vec()),
            3 => Self::Nsid(data.to_vec()),
            5 => Self::Dau(data.to_vec()),
            6 => Self::Dhu(data.to_vec()),
            7 => Self::N3u(data.to_vec()),
            8 => Self::ClientSubnet(data.to_vec()),
            9 => Self::Expire(data.to_vec()),
            10 => Self::Cookie(EdnsCookie::parse(data)?),
            11 => {
                let timeout = if data.is_empty() {
                    None
                } else if data.len() == 2 {
                    Some(u16::from_be_bytes([data[0], data[1]]))
                } else {
                    return Err(ParseError::InvalidRdata {
                        rtype: 41,
                        reason: "TcpKeepalive option must be 0 or 2 bytes",
                    });
                };
                Self::TcpKeepalive(timeout)
            }
            12 => {
                // Padding: the count of padding bytes IS the data length.
                // Cast is safe: opt_len comes from a u16 above.
                #[allow(clippy::cast_possible_truncation)]
                Self::Padding(opt_len as u16)
            }
            13 => Self::Chain(data.to_vec()),
            14 => {
                if !data.len().is_multiple_of(2) {
                    return Err(ParseError::InvalidRdata {
                        rtype: 41,
                        reason: "KeyTag option length must be even",
                    });
                }
                let tags = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                    .collect();
                Self::KeyTag(tags)
            }
            15 => Self::ExtendedError(ExtendedError::parse(data)?),
            _ => Self::Unknown {
                code,
                data: data.to_vec(),
            },
        };

        Ok((opt, data_end))
    }
}

// ── OptRr ─────────────────────────────────────────────────────────────────────

/// Decoded OPT pseudo-RR payload (RFC 6891).
///
/// In the DNS wire format the OPT record repurposes the CLASS field for the
/// UDP payload size and the TTL field for EDNS version, extended RCODE, and
/// the DO bit.  This struct holds the decoded values alongside the parsed
/// option list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRr {
    /// Sender's UDP payload size (from the CLASS field of the OPT record).
    pub udp_payload_size: u16,
    /// High 8 bits of the extended RCODE (from TTL bits 31–24).
    pub extended_rcode: u8,
    /// EDNS version (from TTL bits 23–16; MUST be 0, RFC 6891 §6.1.3).
    pub version: u8,
    /// DO (DNSSEC OK) bit — TTL bit 15 (RFC 4035 §3.2.1).
    pub dnssec_ok: bool,
    /// Reserved Z bits (TTL bits 14–0, MUST be zero per RFC 6840 §5.7).
    pub z: u16,
    /// Decoded EDNS option list.
    pub options: Vec<EdnsOption>,
}

impl OptRr {
    /// Returns the negotiated UDP payload size, clamped to [512, 4096].
    ///
    /// Sizes below 512 are treated as 512 (the minimum per RFC 1035); sizes
    /// above 4096 are capped at 4096 as a conservative operational limit.
    #[must_use]
    pub fn negotiated_udp_size(&self) -> u16 {
        self.udp_payload_size.clamp(512, 4096)
    }

    /// Parses the OPT RDATA (the options TLV stream) together with the
    /// pre-extracted EDNS header fields from the OPT record's CLASS and TTL.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidRdata`] with RCODE 1 (`FormErr`) if the EDNS
    /// version is not 0, or a [`ParseError::UnexpectedEof`] / type-specific error
    /// for truncated / malformed option TLVs.
    pub fn parse_rdata(
        rdata: &[u8],
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        z: u16,
    ) -> Result<Self, ParseError> {
        // RFC 6891 §6.1.3: a responder MUST set RCODE to FORMERR if it
        // receives an OPT record with a version it does not support.
        if version != 0 {
            return Err(ParseError::InvalidRdata {
                rtype: 41,
                reason: "unsupported EDNS version (must be 0)",
            });
        }

        let mut options = Vec::new();
        let mut pos = 0usize;
        while pos < rdata.len() {
            let (opt, next_pos) = EdnsOption::parse(rdata, pos)?;
            options.push(opt);
            pos = next_pos;
        }

        Ok(Self {
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            z,
            options,
        })
    }

    /// Serialises the OPT RDATA (the options TLV stream only — does NOT write
    /// CLASS or TTL; those are handled by the record layer).
    pub fn write_rdata_to(&self, buf: &mut Vec<u8>) {
        for opt in &self.options {
            opt.write_to(buf);
        }
    }
}

// ── Full extended RCODE assembly ──────────────────────────────────────────────

/// Assembles the full 12-bit extended RCODE from the OPT `extended_rcode` byte
/// and the header RCODE nibble (RFC 6891 §6.1.3).
///
/// The DNS header carries only 4 bits of RCODE.  EDNS extends this to 12 bits
/// by placing the upper 8 bits in the OPT record TTL's high byte.  The full
/// code is reconstructed as `(extended_rcode << 4) | (header_rcode & 0x0F)`.
///
/// # Example
///
/// ```rust
/// use heimdall_core::edns::full_rcode;
/// // Extended RCODE 1 (upper 8 bits = 0) with header rcode 1 (FORMERR).
/// assert_eq!(full_rcode(0, 1), 1);
/// // Extended RCODE 4096 uses upper bits to extend the range.
/// assert_eq!(full_rcode(1, 0), 16);
/// ```
#[must_use]
pub fn full_rcode(extended_rcode: u8, header_rcode: u8) -> u16 {
    (u16::from(extended_rcode) << 4) | u16::from(header_rcode & 0x0F)
}

// ── DNS Cookie helpers (RFC 7873 / RFC 9018) ──────────────────────────────────

/// Derives an 8-byte server cookie using HMAC-SHA256 truncated to 8 bytes.
///
/// The derivation follows the spirit of RFC 9018 §4.2 (algorithm-agnostic
/// server cookie construction) using HMAC-SHA256 for simplicity and security.
///
/// Inputs mixed into the HMAC:
/// - `client_cookie` — the 8-byte client cookie from the query.
/// - `client_ip` — the client IP address bytes (4 for IPv4, 16 for IPv6).
/// - `server_secret` — the operator-configured secret (must be ≥ 16 bytes for
///   adequate security; shorter secrets are accepted but not recommended).
///
/// The output is the first 8 bytes of the HMAC-SHA256 tag.
#[must_use]
pub fn derive_server_cookie(
    client_cookie: &[u8; 8],
    client_ip: &[u8], // 4 bytes for IPv4, 16 bytes for IPv6
    server_secret: &[u8],
) -> [u8; 8] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, server_secret);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(client_cookie);
    ctx.update(client_ip);
    let tag = ctx.sign();
    let mut out = [0u8; 8];
    out.copy_from_slice(&tag.as_ref()[..8]);
    out
}

/// Verifies a server cookie received from a client against the expected value.
///
/// Returns `true` if `received` matches the server cookie that would have been
/// sent to a client with the given `client_cookie` and `client_ip`.
///
/// Note: a byte-by-byte comparison is used here because the server cookie is
/// not a MAC over data that the attacker can influence; constant-time comparison
/// would not provide a meaningful security benefit in this context.
#[must_use]
pub fn verify_server_cookie(
    received: &[u8],
    client_cookie: &[u8; 8],
    client_ip: &[u8],
    server_secret: &[u8],
) -> bool {
    let expected = derive_server_cookie(client_cookie, client_ip, server_secret);
    received == expected
}

// ── Padding helpers (RFC 7830 / RFC 8467) ────────────────────────────────────

/// Returns the number of padding bytes required to reach the next multiple of
/// `block_size`, per RFC 8467 §4.1.
///
/// Returns 0 if `current_wire_len` is already on a block boundary.
///
/// Padding is only applicable on encrypted transports (`DoT`, `DoH`, `DoQ`).  This
/// function is transport-agnostic; the transport layer is responsible for
/// deciding when to call it and for actually appending the padding option.
///
/// # Example
///
/// ```rust
/// use heimdall_core::edns::padding_len;
/// // RFC 8467 default block size.
/// assert_eq!(padding_len(100, 128), 28);
/// // Already aligned.
/// assert_eq!(padding_len(128, 128), 0);
/// ```
#[must_use]
pub fn padding_len(current_wire_len: usize, block_size: usize) -> usize {
    if block_size == 0 {
        return 0;
    }
    let rem = current_wire_len % block_size;
    if rem == 0 { 0 } else { block_size - rem }
}

// ── NSID helper (RFC 5001) ────────────────────────────────────────────────────

/// Constructs an NSID [`EdnsOption`] from a human-readable server identifier.
///
/// The identifier string is encoded as raw bytes (UTF-8 octets, no length
/// prefix).  Receivers treat the NSID value as an opaque octet string.
///
/// # Example
///
/// ```rust
/// use heimdall_core::edns::{nsid_option, EdnsOption};
/// let opt = nsid_option("ns1.example.com");
/// assert_eq!(opt, EdnsOption::Nsid(b"ns1.example.com".to_vec()));
/// ```
#[must_use]
pub fn nsid_option(id: &str) -> EdnsOption {
    EdnsOption::Nsid(id.as_bytes().to_vec())
}

// ── TCP keepalive helper (RFC 7828) ───────────────────────────────────────────

/// Builds a TCP keepalive [`EdnsOption`] advertising a server idle timeout.
///
/// The `seconds` value is converted to units of 100 milliseconds (as required
/// by RFC 7828 §3):  `timeout_100ms = seconds * 10`.
///
/// Uses `saturating_mul` to avoid overflow on large values (the maximum
/// representable timeout is 6553.5 seconds, which saturates at 65535 units).
///
/// # Example
///
/// ```rust
/// use heimdall_core::edns::{tcp_keepalive_option, EdnsOption};
/// // 30 seconds = 300 units of 100 ms.
/// assert_eq!(tcp_keepalive_option(30), EdnsOption::TcpKeepalive(Some(300)));
/// ```
#[must_use]
pub fn tcp_keepalive_option(seconds: u16) -> EdnsOption {
    EdnsOption::TcpKeepalive(Some(seconds.saturating_mul(10)))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EdnsOption TLV roundtrip ──────────────────────────────────────────────

    fn roundtrip(opt: &EdnsOption) -> EdnsOption {
        let mut buf = Vec::new();
        opt.write_to(&mut buf);
        let (parsed, consumed) = EdnsOption::parse(&buf, 0).unwrap();
        assert_eq!(consumed, buf.len(), "parsed should consume all bytes");
        parsed
    }

    #[test]
    fn nsid_roundtrip() {
        let opt = EdnsOption::Nsid(b"ns1.example.com".to_vec());
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn tcp_keepalive_with_timeout_roundtrip() {
        let opt = EdnsOption::TcpKeepalive(Some(300));
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn tcp_keepalive_no_timeout_roundtrip() {
        let opt = EdnsOption::TcpKeepalive(None);
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn padding_roundtrip() {
        let opt = EdnsOption::Padding(32);
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn key_tag_roundtrip() {
        let opt = EdnsOption::KeyTag(vec![1024, 2048, 4096]);
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn extended_error_roundtrip() {
        let opt = EdnsOption::ExtendedError(ExtendedError::with_text(
            ede_code::DNSSEC_BOGUS,
            "signature check failed",
        ));
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn extended_error_no_text_roundtrip() {
        let opt = EdnsOption::ExtendedError(ExtendedError::new(ede_code::STALE_ANSWER));
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn cookie_client_only_roundtrip() {
        let opt = EdnsOption::Cookie(EdnsCookie {
            client: [1, 2, 3, 4, 5, 6, 7, 8],
            server: None,
        });
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn cookie_with_server_roundtrip() {
        let server = vec![0xAA; 8];
        let opt = EdnsOption::Cookie(EdnsCookie {
            client: [1, 2, 3, 4, 5, 6, 7, 8],
            server: Some(server),
        });
        assert_eq!(roundtrip(&opt), opt);
    }

    #[test]
    fn unknown_option_roundtrip() {
        let opt = EdnsOption::Unknown {
            code: 9999,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(roundtrip(&opt), opt);
    }

    // ── OptRr parse / serialise ───────────────────────────────────────────────

    #[test]
    fn opt_rr_empty_rdata() {
        let rr = OptRr::parse_rdata(&[], 1232, 0, 0, true, 0).unwrap();
        assert_eq!(rr.udp_payload_size, 1232);
        assert!(rr.dnssec_ok);
        assert!(rr.options.is_empty());
    }

    #[test]
    fn opt_rr_with_nsid_roundtrip() {
        let rr = OptRr {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![EdnsOption::Nsid(b"server-a".to_vec())],
        };
        let mut buf = Vec::new();
        rr.write_rdata_to(&mut buf);
        let parsed = OptRr::parse_rdata(&buf, 4096, 0, 0, false, 0).unwrap();
        assert_eq!(parsed, rr);
    }

    #[test]
    fn opt_rr_rejects_nonzero_version() {
        let err = OptRr::parse_rdata(&[], 512, 0, 1, false, 0).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRdata { rtype: 41, .. }));
    }

    #[test]
    fn negotiated_udp_size_clamp() {
        let low = OptRr {
            udp_payload_size: 100,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        };
        assert_eq!(low.negotiated_udp_size(), 512);

        let high = OptRr {
            udp_payload_size: 65535,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        };
        assert_eq!(high.negotiated_udp_size(), 4096);

        let mid = OptRr {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        };
        assert_eq!(mid.negotiated_udp_size(), 1232);
    }

    // ── full_rcode ────────────────────────────────────────────────────────────

    #[test]
    fn full_rcode_basic() {
        assert_eq!(full_rcode(0, 0), 0);
        assert_eq!(full_rcode(0, 1), 1);
        assert_eq!(full_rcode(1, 0), 16);
        assert_eq!(full_rcode(1, 1), 17);
        assert_eq!(full_rcode(255, 15), 0x0FFF);
    }

    // ── DNS Cookie ────────────────────────────────────────────────────────────

    #[test]
    fn derive_and_verify_server_cookie() {
        let client_cookie: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let client_ip = [192u8, 168, 1, 1];
        let secret = b"my-server-secret-key";

        let cookie = derive_server_cookie(&client_cookie, &client_ip, secret);
        assert_eq!(cookie.len(), 8);
        assert!(verify_server_cookie(
            &cookie,
            &client_cookie,
            &client_ip,
            secret
        ));
        // Wrong IP must fail.
        assert!(!verify_server_cookie(
            &cookie,
            &client_cookie,
            &[10, 0, 0, 1],
            secret
        ));
    }

    // ── Padding ───────────────────────────────────────────────────────────────

    #[test]
    fn padding_len_basic() {
        assert_eq!(padding_len(0, 128), 0);
        assert_eq!(padding_len(128, 128), 0);
        assert_eq!(padding_len(100, 128), 28);
        assert_eq!(padding_len(1, 128), 127);
        assert_eq!(padding_len(468, 128), 128 - (468 % 128));
    }

    // ── NSID helper ───────────────────────────────────────────────────────────

    #[test]
    fn nsid_option_helper() {
        let opt = nsid_option("ns1.example.com");
        assert_eq!(opt, EdnsOption::Nsid(b"ns1.example.com".to_vec()));
    }

    // ── TCP keepalive helper ──────────────────────────────────────────────────

    #[test]
    fn tcp_keepalive_option_helper() {
        assert_eq!(
            tcp_keepalive_option(30),
            EdnsOption::TcpKeepalive(Some(300))
        );
        assert_eq!(tcp_keepalive_option(0), EdnsOption::TcpKeepalive(Some(0)));
        // Saturation: 65535 * 10 overflows u16, saturates.
        assert_eq!(
            tcp_keepalive_option(6554),
            EdnsOption::TcpKeepalive(Some(65535))
        );
    }

    // ── ExtendedError constructors ────────────────────────────────────────────

    #[test]
    fn extended_error_constructors() {
        let e = ExtendedError::new(ede_code::DNSSEC_BOGUS);
        assert_eq!(e.info_code, 6);
        assert_eq!(e.extra_text, None);

        let e2 = ExtendedError::with_text(ede_code::STALE_ANSWER, "cached");
        assert_eq!(e2.info_code, 3);
        assert_eq!(e2.extra_text.as_deref(), Some("cached"));
    }

    // ── Cookie parse error paths ──────────────────────────────────────────────

    #[test]
    fn cookie_too_short() {
        let err = EdnsCookie::parse(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRdata { rtype: 41, .. }));
    }

    #[test]
    fn cookie_server_bad_length() {
        // Client (8 bytes) + server (7 bytes — invalid, must be 8-32).
        let data: Vec<u8> = vec![0; 8 + 7];
        let err = EdnsCookie::parse(&data).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRdata { rtype: 41, .. }));
    }

    #[test]
    fn tcp_keepalive_bad_length() {
        // Option code 11, length 3 — invalid (must be 0 or 2).
        let buf: &[u8] = &[0x00, 11, 0x00, 3, 0x01, 0x02, 0x03];
        let err = EdnsOption::parse(buf, 0).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRdata { rtype: 41, .. }));
    }

    #[test]
    fn key_tag_odd_length() {
        // Option code 14, length 3 — invalid (must be even).
        let buf: &[u8] = &[0x00, 14, 0x00, 3, 0x01, 0x02, 0x03];
        let err = EdnsOption::parse(buf, 0).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRdata { rtype: 41, .. }));
    }
}
