// SPDX-License-Identifier: MIT

//! DNS message header (RFC 1035 §4.1.1), question section (RFC 1035 §4.1.2),
//! and associated type enumerations.

use std::fmt;

use crate::name::{Name, NameError};

// ── ParseError ────────────────────────────────────────────────────────────────

/// Errors that can arise while parsing a DNS message or its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer ended unexpectedly before the parse was complete.
    UnexpectedEof,
    /// A DNS name within the message is malformed.
    InvalidName(NameError),
    /// A compression pointer refers to an offset that is out of range.
    InvalidPointer,
    /// Name decompression encountered a pointer loop (RFC 1035 §4.1.4).
    PointerLoop,
    /// The resource record data is malformed.
    InvalidRdata {
        /// The numeric RTYPE value of the malformed record.
        rtype: u16,
        /// A static description of why the RDATA is invalid.
        reason: &'static str,
    },
    /// The 12-byte DNS header is malformed.
    InvalidHeader,
    /// A question section entry is malformed.
    InvalidQuestion,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of DNS message buffer"),
            Self::InvalidName(e) => write!(f, "invalid DNS name: {e}"),
            Self::InvalidPointer => write!(f, "DNS compression pointer out of range"),
            Self::PointerLoop => write!(f, "DNS name compression pointer loop detected"),
            Self::InvalidRdata { rtype, reason } => {
                write!(f, "invalid RDATA for type {rtype}: {reason}")
            }
            Self::InvalidHeader => write!(f, "malformed DNS message header"),
            Self::InvalidQuestion => write!(f, "malformed DNS question section"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NameError> for ParseError {
    fn from(e: NameError) -> Self {
        Self::InvalidName(e)
    }
}

// ── Opcode ────────────────────────────────────────────────────────────────────

/// DNS OPCODE field (bits 14–11 of the flags word, RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Opcode {
    /// Standard query (RFC 1035).
    Query,
    /// Inverse query, obsolete (RFC 3425).
    IQuery,
    /// Server status request (RFC 1035).
    Status,
    /// DNS NOTIFY (RFC 1996).
    Notify,
    /// Dynamic update (RFC 2136).
    Update,
    /// DNS Stateful Operations (RFC 8490).
    Dso,
    /// An opcode value not listed above.
    Unknown(u8),
}

impl Opcode {
    /// Converts a 4-bit value to an [`Opcode`].
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::Dso,
            other => Self::Unknown(other),
        }
    }

    /// Returns the 4-bit wire value for this opcode.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Dso => 6,
            Self::Unknown(v) => v & 0x0F,
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query => write!(f, "QUERY"),
            Self::IQuery => write!(f, "IQUERY"),
            Self::Status => write!(f, "STATUS"),
            Self::Notify => write!(f, "NOTIFY"),
            Self::Update => write!(f, "UPDATE"),
            Self::Dso => write!(f, "DSO"),
            Self::Unknown(v) => write!(f, "OPCODE({v})"),
        }
    }
}

// ── Rcode ─────────────────────────────────────────────────────────────────────

/// DNS response code (bits 3–0 of the flags word, RFC 1035 §4.1.1).
///
/// Extended response codes via EDNS OPT RR use the upper 8 bits; those are
/// handled separately in the OPT RDATA parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rcode {
    /// No error condition (RFC 1035).
    NoError,
    /// Format error — the name server could not interpret the query (RFC 1035).
    FormErr,
    /// Server failure (RFC 1035).
    ServFail,
    /// Non-existent domain (RFC 1035).
    NxDomain,
    /// Not implemented (RFC 1035).
    NotImp,
    /// Refused (RFC 1035).
    Refused,
    /// Name that should not exist does exist (RFC 2136).
    YxDomain,
    /// RR set that should not exist does exist (RFC 2136).
    YxRrset,
    /// RR set that should exist does not (RFC 2136).
    NxRrset,
    /// Server is not authoritative for the zone / not authorized (RFC 2136).
    NotAuth,
    /// Name not contained in zone (RFC 2136).
    NotZone,
    /// An rcode value not listed above (e.g. extended EDNS rcodes).
    Unknown(u8),
}

impl Rcode {
    /// Converts a 4-bit value to an [`Rcode`].
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Unknown(other),
        }
    }

    /// Returns the 4-bit wire value for this rcode.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::YxRrset => 7,
            Self::NxRrset => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::Unknown(v) => v & 0x0F,
        }
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NOERROR"),
            Self::FormErr => write!(f, "FORMERR"),
            Self::ServFail => write!(f, "SERVFAIL"),
            Self::NxDomain => write!(f, "NXDOMAIN"),
            Self::NotImp => write!(f, "NOTIMP"),
            Self::Refused => write!(f, "REFUSED"),
            Self::YxDomain => write!(f, "YXDOMAIN"),
            Self::YxRrset => write!(f, "YXRRSET"),
            Self::NxRrset => write!(f, "NXRRSET"),
            Self::NotAuth => write!(f, "NOTAUTH"),
            Self::NotZone => write!(f, "NOTZONE"),
            Self::Unknown(v) => write!(f, "RCODE({v})"),
        }
    }
}

// ── Header ────────────────────────────────────────────────────────────────────

/// The 12-byte DNS message header (RFC 1035 §4.1.1).
///
/// Bit layout of the flags word:
///
/// ```text
///  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// Message identifier.
    pub id: u16,
    /// Raw flags word; use the accessor methods for individual bits.
    pub flags: u16,
    /// Question count.
    pub qdcount: u16,
    /// Answer RR count.
    pub ancount: u16,
    /// Authority RR count.
    pub nscount: u16,
    /// Additional RR count.
    pub arcount: u16,
}

impl Header {
    /// Wire size of a DNS header in bytes.
    pub const WIRE_LEN: usize = 12;

    /// QR bit — `true` = response, `false` = query (RFC 1035 §4.1.1, bit 15).
    #[must_use]
    pub fn qr(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Sets the QR bit.
    pub fn set_qr(&mut self, v: bool) {
        if v {
            self.flags |= 0x8000;
        } else {
            self.flags &= !0x8000;
        }
    }

    /// OPCODE field (bits 14–11, RFC 1035 §4.1.1).
    #[must_use]
    pub fn opcode(&self) -> Opcode {
        Opcode::from_u8(((self.flags >> 11) & 0x0F) as u8)
    }

    /// Sets the OPCODE field.
    pub fn set_opcode(&mut self, op: Opcode) {
        self.flags = (self.flags & !(0x0F << 11)) | (u16::from(op.as_u8()) << 11);
    }

    /// AA (Authoritative Answer) bit, bit 10 (RFC 1035 §4.1.1).
    #[must_use]
    pub fn aa(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// Sets the AA bit.
    pub fn set_aa(&mut self, v: bool) {
        if v {
            self.flags |= 0x0400;
        } else {
            self.flags &= !0x0400;
        }
    }

    /// TC (Truncation) bit, bit 9 (RFC 1035 §4.1.1).
    #[must_use]
    pub fn tc(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// Sets the TC bit.
    pub fn set_tc(&mut self, v: bool) {
        if v {
            self.flags |= 0x0200;
        } else {
            self.flags &= !0x0200;
        }
    }

    /// RD (Recursion Desired) bit, bit 8 (RFC 1035 §4.1.1).
    #[must_use]
    pub fn rd(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Sets the RD bit.
    pub fn set_rd(&mut self, v: bool) {
        if v {
            self.flags |= 0x0100;
        } else {
            self.flags &= !0x0100;
        }
    }

    /// RA (Recursion Available) bit, bit 7 (RFC 1035 §4.1.1).
    #[must_use]
    pub fn ra(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Sets the RA bit.
    pub fn set_ra(&mut self, v: bool) {
        if v {
            self.flags |= 0x0080;
        } else {
            self.flags &= !0x0080;
        }
    }

    /// Z (Reserved) bit, bit 6.  MUST be zero per RFC 1035; repurposed as AD
    /// in some DNSSEC drafts — use [`Header::ad`] for the Authentic Data bit.
    #[must_use]
    pub fn z(&self) -> bool {
        self.flags & 0x0040 != 0
    }

    /// Sets the Z bit.
    pub fn set_z(&mut self, v: bool) {
        if v {
            self.flags |= 0x0040;
        } else {
            self.flags &= !0x0040;
        }
    }

    /// AD (Authentic Data) bit, bit 5 (RFC 4035 §3.2.3).
    #[must_use]
    pub fn ad(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Sets the AD bit.
    pub fn set_ad(&mut self, v: bool) {
        if v {
            self.flags |= 0x0020;
        } else {
            self.flags &= !0x0020;
        }
    }

    /// CD (Checking Disabled) bit, bit 4 (RFC 4035 §3.2.2).
    #[must_use]
    pub fn cd(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Sets the CD bit.
    pub fn set_cd(&mut self, v: bool) {
        if v {
            self.flags |= 0x0010;
        } else {
            self.flags &= !0x0010;
        }
    }

    /// RCODE field (bits 3–0, RFC 1035 §4.1.1).
    ///
    /// Extended rcodes (EDNS, 12-bit) are handled separately via the OPT RR.
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        Rcode::from_u8((self.flags & 0x000F) as u8)
    }

    /// Sets the RCODE field.
    pub fn set_rcode(&mut self, rc: Rcode) {
        self.flags = (self.flags & !0x000F) | u16::from(rc.as_u8());
    }

    /// Parses a [`Header`] from the first 12 bytes of `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidHeader`] if `buf` is shorter than 12 bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(ParseError::InvalidHeader);
        }
        Ok(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    /// Appends the 12-byte wire representation of this header to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
    }
}

// ── Qtype ─────────────────────────────────────────────────────────────────────

/// DNS QTYPE field — a superset of RTYPE that also includes meta-types and
/// query-only types (RFC 1035 §3.2.3, RFC 2535, RFC 3596, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Qtype {
    /// Host address (RFC 1035).
    A,
    /// Authoritative name server (RFC 1035).
    Ns,
    /// Canonical name (RFC 1035).
    Cname,
    /// Start of authority (RFC 1035).
    Soa,
    /// Domain name pointer (RFC 1035).
    Ptr,
    /// Host information (RFC 1035).
    Hinfo,
    /// Mail exchange (RFC 1035).
    Mx,
    /// Text record (RFC 1035).
    Txt,
    /// Responsible person (RFC 1183).
    Rp,
    /// AFS DB (RFC 1183).
    Afsdb,
    /// Signature (obsolete, RFC 2535).
    Sig,
    /// Public key (obsolete, RFC 2535).
    Key,
    /// IPv6 address (RFC 3596).
    Aaaa,
    /// Location (RFC 1876).
    Loc,
    /// Service locator (RFC 2782).
    Srv,
    /// Naming authority pointer (RFC 2915).
    Naptr,
    /// Certificate (RFC 4398).
    Cert,
    /// Delegation name (RFC 6672).
    Dname,
    /// OPT pseudo-RR (RFC 6891).
    Opt,
    /// Address prefix list (RFC 3123).
    Apl,
    /// Delegation signer (RFC 4034).
    Ds,
    /// SSH fingerprint (RFC 4255).
    Sshfp,
    /// `IPsec` key (RFC 4025).
    Ipseckey,
    /// DNSSEC signature (RFC 4034).
    Rrsig,
    /// Next secure (RFC 4034).
    Nsec,
    /// DNS key (RFC 4034).
    Dnskey,
    /// DHCP identifier (RFC 4701).
    Dhcid,
    /// Next secure v3 (RFC 5155).
    Nsec3,
    /// NSEC3 parameters (RFC 5155).
    Nsec3param,
    /// TLS association (RFC 6698).
    Tlsa,
    /// S/MIME cert association (RFC 8162).
    Smimea,
    /// Host identity protocol (RFC 8005).
    Hip,
    /// Child delegation signer (RFC 7344).
    Cds,
    /// Child DNSKEY (RFC 7344).
    Cdnskey,
    /// `OpenPGP` key (RFC 7929).
    Openpgpkey,
    /// Child-to-parent synchronisation (RFC 7477).
    Csync,
    /// Zone message digest (RFC 8976).
    Zonemd,
    /// Service binding (RFC 9460).
    Svcb,
    /// HTTPS binding (RFC 9460).
    Https,
    /// Uniform resource identifier (RFC 7553).
    Uri,
    /// Certification authority authorisation (RFC 8659).
    Caa,
    /// Incremental zone transfer (RFC 5936).
    Ixfr,
    /// Full zone transfer (RFC 5936).
    Axfr,
    /// Any / wildcard (RFC 1035).
    Any,
    /// An unknown / unrecognised type value.
    Unknown(u16),
}

impl Qtype {
    /// Converts a raw `u16` wire value to a [`Qtype`].
    #[must_use]
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            13 => Self::Hinfo,
            15 => Self::Mx,
            16 => Self::Txt,
            17 => Self::Rp,
            18 => Self::Afsdb,
            24 => Self::Sig,
            25 => Self::Key,
            28 => Self::Aaaa,
            29 => Self::Loc,
            33 => Self::Srv,
            35 => Self::Naptr,
            37 => Self::Cert,
            39 => Self::Dname,
            41 => Self::Opt,
            42 => Self::Apl,
            43 => Self::Ds,
            44 => Self::Sshfp,
            45 => Self::Ipseckey,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            49 => Self::Dhcid,
            50 => Self::Nsec3,
            51 => Self::Nsec3param,
            52 => Self::Tlsa,
            53 => Self::Smimea,
            55 => Self::Hip,
            59 => Self::Cds,
            60 => Self::Cdnskey,
            61 => Self::Openpgpkey,
            62 => Self::Csync,
            63 => Self::Zonemd,
            64 => Self::Svcb,
            65 => Self::Https,
            251 => Self::Ixfr,
            252 => Self::Axfr,
            255 => Self::Any,
            256 => Self::Uri,
            257 => Self::Caa,
            other => Self::Unknown(other),
        }
    }

    /// Returns the `u16` wire value of this [`Qtype`].
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Hinfo => 13,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Rp => 17,
            Self::Afsdb => 18,
            Self::Sig => 24,
            Self::Key => 25,
            Self::Aaaa => 28,
            Self::Loc => 29,
            Self::Srv => 33,
            Self::Naptr => 35,
            Self::Cert => 37,
            Self::Dname => 39,
            Self::Opt => 41,
            Self::Apl => 42,
            Self::Ds => 43,
            Self::Sshfp => 44,
            Self::Ipseckey => 45,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Dhcid => 49,
            Self::Nsec3 => 50,
            Self::Nsec3param => 51,
            Self::Tlsa => 52,
            Self::Smimea => 53,
            Self::Hip => 55,
            Self::Cds => 59,
            Self::Cdnskey => 60,
            Self::Openpgpkey => 61,
            Self::Csync => 62,
            Self::Zonemd => 63,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Ixfr => 251,
            Self::Axfr => 252,
            Self::Any => 255,
            Self::Uri => 256,
            Self::Caa => 257,
            Self::Unknown(v) => v,
        }
    }
}

impl From<u16> for Qtype {
    fn from(v: u16) -> Self {
        Self::from_u16(v)
    }
}

impl From<Qtype> for u16 {
    fn from(q: Qtype) -> Self {
        q.as_u16()
    }
}

impl fmt::Display for Qtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Ns => write!(f, "NS"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Hinfo => write!(f, "HINFO"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Rp => write!(f, "RP"),
            Self::Afsdb => write!(f, "AFSDB"),
            Self::Sig => write!(f, "SIG"),
            Self::Key => write!(f, "KEY"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Loc => write!(f, "LOC"),
            Self::Srv => write!(f, "SRV"),
            Self::Naptr => write!(f, "NAPTR"),
            Self::Cert => write!(f, "CERT"),
            Self::Dname => write!(f, "DNAME"),
            Self::Opt => write!(f, "OPT"),
            Self::Apl => write!(f, "APL"),
            Self::Ds => write!(f, "DS"),
            Self::Sshfp => write!(f, "SSHFP"),
            Self::Ipseckey => write!(f, "IPSECKEY"),
            Self::Rrsig => write!(f, "RRSIG"),
            Self::Nsec => write!(f, "NSEC"),
            Self::Dnskey => write!(f, "DNSKEY"),
            Self::Dhcid => write!(f, "DHCID"),
            Self::Nsec3 => write!(f, "NSEC3"),
            Self::Nsec3param => write!(f, "NSEC3PARAM"),
            Self::Tlsa => write!(f, "TLSA"),
            Self::Smimea => write!(f, "SMIMEA"),
            Self::Hip => write!(f, "HIP"),
            Self::Cds => write!(f, "CDS"),
            Self::Cdnskey => write!(f, "CDNSKEY"),
            Self::Openpgpkey => write!(f, "OPENPGPKEY"),
            Self::Csync => write!(f, "CSYNC"),
            Self::Zonemd => write!(f, "ZONEMD"),
            Self::Svcb => write!(f, "SVCB"),
            Self::Https => write!(f, "HTTPS"),
            Self::Ixfr => write!(f, "IXFR"),
            Self::Axfr => write!(f, "AXFR"),
            Self::Any => write!(f, "ANY"),
            Self::Uri => write!(f, "URI"),
            Self::Caa => write!(f, "CAA"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

// ── Qclass ────────────────────────────────────────────────────────────────────

/// DNS QCLASS / CLASS field (RFC 1035 §3.2.4–3.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Qclass {
    /// Internet class (RFC 1035).
    In,
    /// CSNET class, obsolete (RFC 1035).
    Cs,
    /// Chaos class (RFC 1035).
    Ch,
    /// Hesiod class (RFC 1035).
    Hs,
    /// NONE — used in RFC 2136 dynamic updates.
    None,
    /// ANY / wildcard class (RFC 1035).
    Any,
    /// An unknown class value.
    Unknown(u16),
}

impl Qclass {
    /// Converts a raw `u16` wire value to a [`Qclass`].
    #[must_use]
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::In,
            2 => Self::Cs,
            3 => Self::Ch,
            4 => Self::Hs,
            254 => Self::None,
            255 => Self::Any,
            other => Self::Unknown(other),
        }
    }

    /// Returns the `u16` wire value of this [`Qclass`].
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::In => 1,
            Self::Cs => 2,
            Self::Ch => 3,
            Self::Hs => 4,
            Self::None => 254,
            Self::Any => 255,
            Self::Unknown(v) => v,
        }
    }
}

impl From<u16> for Qclass {
    fn from(v: u16) -> Self {
        Self::from_u16(v)
    }
}

impl From<Qclass> for u16 {
    fn from(c: Qclass) -> Self {
        c.as_u16()
    }
}

impl fmt::Display for Qclass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Cs => write!(f, "CS"),
            Self::Ch => write!(f, "CH"),
            Self::Hs => write!(f, "HS"),
            Self::None => write!(f, "NONE"),
            Self::Any => write!(f, "ANY"),
            Self::Unknown(v) => write!(f, "CLASS{v}"),
        }
    }
}

// ── Question ──────────────────────────────────────────────────────────────────

/// A DNS question section entry (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The domain name being queried.
    pub qname: Name,
    /// The resource record type being requested.
    pub qtype: Qtype,
    /// The class of resource record being requested.
    pub qclass: Qclass,
}

impl Question {
    /// Parses a [`Question`] from `buf` starting at `*offset`.
    ///
    /// On success `*offset` is advanced past the consumed bytes.  Name
    /// decompression is handled by the caller via the `parse_name` function
    /// in the parser module; here we call that helper with `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on truncation or malformed data.
    pub fn parse(buf: &[u8], offset: &mut usize) -> Result<Self, ParseError> {
        let name = crate::parser::parse_name(buf, offset)?;
        let qtype_raw = read_u16(buf, offset).ok_or(ParseError::InvalidQuestion)?;
        let qclass_raw = read_u16(buf, offset).ok_or(ParseError::InvalidQuestion)?;
        Ok(Self {
            qname: name,
            qtype: Qtype::from_u16(qtype_raw),
            qclass: Qclass::from_u16(qclass_raw),
        })
    }

    /// Appends the wire representation of this question to `buf`.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.qname.as_wire_bytes());
        buf.extend_from_slice(&self.qtype.as_u16().to_be_bytes());
        buf.extend_from_slice(&self.qclass.as_u16().to_be_bytes());
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Reads a big-endian `u16` from `buf` at `*offset` and advances `*offset` by 2.
pub(crate) fn read_u16(buf: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    if end > buf.len() {
        return None;
    }
    let v = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
    *offset = end;
    Some(v)
}

/// Reads a big-endian `u32` from `buf` at `*offset` and advances `*offset` by 4.
pub(crate) fn read_u32(buf: &[u8], offset: &mut usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    let v = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]);
    *offset = end;
    Some(v)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut h = Header {
            id: 0x1234,
            qdcount: 1,
            ..Header::default()
        };
        h.set_qr(true);
        h.set_opcode(Opcode::Query);
        h.set_rd(true);
        h.set_rcode(Rcode::NoError);

        let mut buf = Vec::new();
        h.write_to(&mut buf);
        assert_eq!(buf.len(), 12);

        let h2 = Header::parse(&buf).unwrap();
        assert_eq!(h, h2);
        assert!(h2.qr());
        assert_eq!(h2.opcode(), Opcode::Query);
        assert!(h2.rd());
        assert_eq!(h2.rcode(), Rcode::NoError);
    }

    #[test]
    fn header_too_short() {
        let buf = [0u8; 11];
        assert!(matches!(
            Header::parse(&buf),
            Err(ParseError::InvalidHeader)
        ));
    }

    #[test]
    fn opcode_roundtrip() {
        for (op, expected) in [
            (Opcode::Query, 0u8),
            (Opcode::IQuery, 1),
            (Opcode::Status, 2),
            (Opcode::Notify, 4),
            (Opcode::Update, 5),
            (Opcode::Dso, 6),
            (Opcode::Unknown(15), 15),
        ] {
            assert_eq!(op.as_u8(), expected);
            assert_eq!(Opcode::from_u8(expected), op);
        }
    }

    #[test]
    fn rcode_roundtrip() {
        for (rc, expected) in [
            (Rcode::NoError, 0u8),
            (Rcode::FormErr, 1),
            (Rcode::ServFail, 2),
            (Rcode::NxDomain, 3),
            (Rcode::Refused, 5),
            (Rcode::NotZone, 10),
        ] {
            assert_eq!(rc.as_u8(), expected);
            assert_eq!(Rcode::from_u8(expected), rc);
        }
    }

    #[test]
    fn qtype_from_into_u16() {
        assert_eq!(Qtype::from_u16(1), Qtype::A);
        assert_eq!(Qtype::A.as_u16(), 1);
        assert_eq!(Qtype::from_u16(255), Qtype::Any);
        assert_eq!(Qtype::from_u16(9999), Qtype::Unknown(9999));
    }

    #[test]
    fn qclass_from_into_u16() {
        assert_eq!(Qclass::from_u16(1), Qclass::In);
        assert_eq!(Qclass::In.as_u16(), 1);
        assert_eq!(Qclass::from_u16(255), Qclass::Any);
    }
}
