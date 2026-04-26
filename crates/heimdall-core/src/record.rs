// SPDX-License-Identifier: MIT

//! DNS resource record types: [`Rtype`], [`Record`], and [`RRset`].

use std::fmt;

use crate::header::{ParseError, Qclass};
use crate::name::Name;
use crate::rdata::RData;

// ── Rtype ─────────────────────────────────────────────────────────────────────

/// DNS resource record type values (RFC 1035 and subsequent RFCs).
///
/// Variants not explicitly listed are captured by [`Rtype::Unknown`] for
/// forward compatibility per RFC 3597.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rtype {
    /// Host address (RFC 1035).
    A,
    /// Authoritative name server (RFC 1035).
    Ns,
    /// Canonical name for an alias (RFC 1035).
    Cname,
    /// Start of zone authority (RFC 1035).
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
    /// AFS database location (RFC 1183).
    Afsdb,
    /// Security signature (obsolete, RFC 2535).
    Sig,
    /// Security key (obsolete, RFC 2535).
    Key,
    /// IPv6 address (RFC 3596).
    Aaaa,
    /// Geographic location (RFC 1876).
    Loc,
    /// Service locator (RFC 2782).
    Srv,
    /// Naming authority pointer (RFC 2915).
    Naptr,
    /// Certificate record (RFC 4398).
    Cert,
    /// Delegation name (RFC 6672).
    Dname,
    /// OPT pseudo-resource record (RFC 6891).
    Opt,
    /// Address prefix list (RFC 3123).
    Apl,
    /// Delegation signer (RFC 4034).
    Ds,
    /// SSH public key fingerprint (RFC 4255).
    Sshfp,
    /// `IPsec` keying material (RFC 4025).
    Ipseckey,
    /// DNSSEC signature (RFC 4034).
    Rrsig,
    /// Next secure record (RFC 4034).
    Nsec,
    /// DNS public key (RFC 4034).
    Dnskey,
    /// DHCP identifier (RFC 4701).
    Dhcid,
    /// NSEC version 3 (RFC 5155).
    Nsec3,
    /// NSEC3 zone parameters (RFC 5155).
    Nsec3param,
    /// TLS authentication (RFC 6698).
    Tlsa,
    /// S/MIME cert association (RFC 8162).
    Smimea,
    /// Host identity protocol (RFC 8005).
    Hip,
    /// Child delegation signer (RFC 7344).
    Cds,
    /// Child DNSKEY (RFC 7344).
    Cdnskey,
    /// `OpenPGP` public key (RFC 7929).
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
    /// Transaction authentication (RFC 8945).
    Tsig,
    /// An unknown or unrecognised resource record type.
    Unknown(u16),
}

impl Rtype {
    /// Converts a raw `u16` wire value to an [`Rtype`].
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
            256 => Self::Uri,
            250 => Self::Tsig,
            257 => Self::Caa,
            other => Self::Unknown(other),
        }
    }

    /// Returns the `u16` wire value for this [`Rtype`].
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
            Self::Uri => 256,
            Self::Tsig => 250,
            Self::Caa => 257,
            Self::Unknown(v) => v,
        }
    }
}

impl From<u16> for Rtype {
    fn from(v: u16) -> Self {
        Self::from_u16(v)
    }
}

impl From<Rtype> for u16 {
    fn from(r: Rtype) -> Self {
        r.as_u16()
    }
}

impl fmt::Display for Rtype {
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
            Self::Uri => write!(f, "URI"),
            Self::Tsig => write!(f, "TSIG"),
            Self::Caa => write!(f, "CAA"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

// ── Record ────────────────────────────────────────────────────────────────────

/// A single DNS resource record (RFC 1035 §3.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Owner name of the resource record.
    pub name: Name,
    /// Resource record type.
    pub rtype: Rtype,
    /// Resource record class.  For OPT records this encodes the UDP payload size.
    pub rclass: Qclass,
    /// Time to live in seconds.  For OPT records the TTL field encodes EDNS data.
    pub ttl: u32,
    /// The resource record data payload.
    pub rdata: RData,
}

impl Record {
    /// Parses a single resource record from `buf` starting at `*offset`.
    ///
    /// On success `*offset` is advanced past all consumed bytes.  Name
    /// decompression is performed using the full `buf` slice.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on truncation, pointer loops, or malformed RDATA.
    pub fn parse(buf: &[u8], offset: &mut usize) -> Result<Self, ParseError> {
        let name = crate::parser::parse_name(buf, offset)?;
        let rtype_raw =
            crate::header::read_u16(buf, offset).ok_or(ParseError::UnexpectedEof)?;
        let rclass_raw =
            crate::header::read_u16(buf, offset).ok_or(ParseError::UnexpectedEof)?;
        let ttl =
            crate::header::read_u32(buf, offset).ok_or(ParseError::UnexpectedEof)?;
        let rdlength = usize::from(
            crate::header::read_u16(buf, offset).ok_or(ParseError::UnexpectedEof)?
        );

        let rtype = Rtype::from_u16(rtype_raw);
        let rclass = Qclass::from_u16(rclass_raw);

        // Special-case OPT: parse EDNS fields from the class/ttl wire fields.
        let rdata = if rtype == Rtype::Opt {
            parse_opt_record(rclass_raw, ttl, buf, *offset, rdlength)?
        } else {
            RData::parse(rtype, buf, *offset, rdlength)?
        };

        *offset = offset
            .checked_add(rdlength)
            .ok_or(ParseError::UnexpectedEof)?;
        if *offset > buf.len() {
            return Err(ParseError::UnexpectedEof);
        }

        Ok(Self { name, rtype, rclass, ttl, rdata })
    }

    /// Appends the wire representation of this record to `buf`.
    ///
    /// RDATA is written without name compression (canonical form, RFC 4034 §6.2).
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.name.as_wire_bytes());
        buf.extend_from_slice(&self.rtype.as_u16().to_be_bytes());

        if let RData::Opt(opt_rr) = &self.rdata {
            // OPT record: class encodes UDP payload size, TTL encodes EDNS fields.
            buf.extend_from_slice(&opt_rr.udp_payload_size.to_be_bytes());
            let do_bit: u8 = if opt_rr.dnssec_ok { 0x80 } else { 0 };
            // TTL layout: [extended_rcode][version][DO bit | Z high][Z low]
            buf.push(opt_rr.extended_rcode);
            buf.push(opt_rr.version);
            // Preserve z bits (bits 14-0 of the 16-bit Z field); DO is bit 15.
            let z_high = do_bit | ((opt_rr.z >> 8) as u8 & 0x7F);
            let z_low = (opt_rr.z & 0xFF) as u8;
            buf.push(z_high);
            buf.push(z_low);
            // Write RDLENGTH + options TLV stream.
            let rdata_start = buf.len();
            buf.extend_from_slice(&0u16.to_be_bytes()); // placeholder
            opt_rr.write_rdata_to(buf);
            let rdata_len = buf.len() - rdata_start - 2;
            // INVARIANT: OPT RDATA bounded by 16-bit RDLENGTH field (≤ 65535 bytes).
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (rdata_len as u16).to_be_bytes();
            buf[rdata_start] = len_bytes[0];
            buf[rdata_start + 1] = len_bytes[1];
        } else {
            buf.extend_from_slice(&self.rclass.as_u16().to_be_bytes());
            buf.extend_from_slice(&self.ttl.to_be_bytes());
            // Write RDATA with a length prefix.
            let rdata_start = buf.len();
            buf.extend_from_slice(&0u16.to_be_bytes()); // placeholder
            self.rdata.write_to(buf);
            let rdata_len = buf.len() - rdata_start - 2;
            // INVARIANT: RDATA cannot exceed 65535 bytes (16-bit RDLENGTH field in DNS wire format).
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (rdata_len as u16).to_be_bytes();
            buf[rdata_start] = len_bytes[0];
            buf[rdata_start + 1] = len_bytes[1];
        }
    }
}

/// Parses an OPT pseudo-RR (RFC 6891 §6.1).
///
/// For OPT records the class field encodes the UDP payload size and the TTL
/// field encodes the extended RCODE, EDNS version, DO bit, and Z bits.
fn parse_opt_record(
    class_raw: u16,
    ttl_raw: u32,
    buf: &[u8],
    rdata_offset: usize,
    rdlength: usize,
) -> Result<RData, ParseError> {
    let udp_payload_size = class_raw;
    // Shift + mask guarantees values fit in u8; truncation is intentional.
    #[allow(clippy::cast_possible_truncation)]
    let extended_rcode = ((ttl_raw >> 24) & 0xFF) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let version = ((ttl_raw >> 16) & 0xFF) as u8;
    // Bit 15 of the lower 16 bits of TTL is the DO bit.
    let dnssec_ok = (ttl_raw >> 15) & 1 == 1;
    // Remaining 15 bits are the Z field.
    #[allow(clippy::cast_possible_truncation)]
    let z = (ttl_raw & 0x7FFF) as u16;

    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(ParseError::UnexpectedEof)?;
    if rdata_end > buf.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let rdata = &buf[rdata_offset..rdata_end];

    let opt_rr = crate::edns::OptRr::parse_rdata(rdata, udp_payload_size, extended_rcode, version, dnssec_ok, z)?;
    Ok(RData::Opt(opt_rr))
}

// ── RRset ─────────────────────────────────────────────────────────────────────

/// A set of resource records sharing the same owner name, class, and type
/// (RFC 2181 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RRset {
    /// Owner name.
    pub name: Name,
    /// Resource record type.
    pub rtype: Rtype,
    /// Resource record class.
    pub rclass: Qclass,
    /// Time to live (shared across the set).
    pub ttl: u32,
    /// The RDATA payloads of each record in the set.
    pub records: Vec<RData>,
}

impl RRset {
    /// Creates a new, empty [`RRset`].
    #[must_use]
    pub fn new(name: Name, rtype: Rtype, rclass: Qclass, ttl: u32) -> Self {
        Self { name, rtype, rclass, ttl, records: Vec::new() }
    }

    /// Appends an RDATA payload to this `RRset`.
    pub fn add(&mut self, rdata: RData) {
        self.records.push(rdata);
    }

    /// Returns an iterator over the RDATA payloads in this `RRset`.
    pub fn iter(&self) -> impl Iterator<Item = &RData> {
        self.records.iter()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn rtype_from_into() {
        assert_eq!(Rtype::from_u16(1), Rtype::A);
        assert_eq!(Rtype::A.as_u16(), 1);
        assert_eq!(Rtype::from_u16(9999), Rtype::Unknown(9999));
        assert_eq!(Rtype::Unknown(9999).as_u16(), 9999);
    }

    #[test]
    fn record_a_roundtrip() {
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record {
            name: name.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut buf = Vec::new();
        rec.write_to(&mut buf);

        let mut offset = 0;
        let parsed = Record::parse(&buf, &mut offset).unwrap();
        assert_eq!(offset, buf.len());
        assert_eq!(parsed, rec);
    }

    #[test]
    fn rrset_add_and_iter() {
        let name = Name::from_str("example.com.").unwrap();
        let mut rrset = RRset::new(name, Rtype::A, Qclass::In, 300);
        rrset.add(RData::A(Ipv4Addr::new(1, 2, 3, 4)));
        rrset.add(RData::A(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(rrset.records.len(), 2);
        let addrs: Vec<_> = rrset.iter().collect();
        assert_eq!(addrs.len(), 2);
    }
}
