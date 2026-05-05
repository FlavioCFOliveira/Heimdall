// SPDX-License-Identifier: MIT

//! DNS resource record data types (RDATA) as defined across various RFCs.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{edns::OptRr, header::ParseError, name::Name, record::Rtype};

// ── RData ─────────────────────────────────────────────────────────────────────

/// The data payload of a DNS resource record.
///
/// Each variant corresponds to a specific RTYPE.  Types not explicitly listed
/// are represented by [`RData::Unknown`] for forward compatibility.
///
/// Parsing and serialisation follow the wire-format specifications in RFC 1035
/// and the respective type-specific RFCs.
///
/// # Size note
///
/// Variants containing [`Name`] fields (such as [`RData::Soa`] and
/// [`RData::Rrsig`]) are large because [`Name`] stores 255 bytes inline to
/// avoid heap allocation.  Callers that store `RData` in collections should
/// profile allocation behaviour; boxing is left to the call site where needed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // Name is 255 bytes inline; boxing at call site if needed.
pub enum RData {
    /// IPv4 host address — 4 wire bytes (RFC 1035 §3.4.1).
    A(Ipv4Addr),
    /// IPv6 host address — 16 wire bytes (RFC 3596 §2.2).
    Aaaa(Ipv6Addr),
    /// Authoritative name server (RFC 1035 §3.3.11).
    Ns(Name),
    /// Canonical name alias (RFC 1035 §3.3.1).
    Cname(Name),
    /// Delegation name redirect (RFC 6672 §2.3).
    Dname(Name),
    /// Mail exchanger with preference value (RFC 1035 §3.3.9).
    Mx {
        /// Lower values indicate higher preference.
        preference: u16,
        /// Domain name of the mail server.
        exchange: Name,
    },
    /// Domain name pointer for reverse lookups (RFC 1035 §3.3.12).
    Ptr(Name),
    /// Start of authority record (RFC 1035 §3.3.13).
    Soa {
        /// Primary name server.
        mname: Name,
        /// Mailbox of the zone administrator.
        rname: Name,
        /// Zone serial number.
        serial: u32,
        /// Seconds before zone refresh.
        refresh: u32,
        /// Seconds before retry after failure.
        retry: u32,
        /// Seconds after which the zone is no longer authoritative.
        expire: u32,
        /// Minimum TTL for negative caching (RFC 2308).
        minimum: u32,
    },
    /// One or more character-strings (RFC 1035 §3.3.14).
    Txt(Vec<Vec<u8>>),
    /// Service location record (RFC 2782).
    Srv {
        /// Service priority (lower = more preferred).
        priority: u16,
        /// Relative weight for load balancing among equal-priority servers.
        weight: u16,
        /// TCP/UDP port of the service.
        port: u16,
        /// Domain name of the host providing the service.
        target: Name,
    },
    /// Certification authority authorisation (RFC 8659).
    Caa {
        /// Flags byte (bit 0 = Issuer Critical).
        flags: u8,
        /// Property tag (ASCII, ≤ 15 bytes).
        tag: Vec<u8>,
        /// Property value.
        value: Vec<u8>,
    },
    /// DNS public key record (RFC 4034 §2).
    Dnskey {
        /// Key flags (e.g. bit 8 = Zone Key, bit 0 = SEP).
        flags: u16,
        /// Protocol — MUST be 3 (RFC 4034 §2.1.2).
        protocol: u8,
        /// Public key cryptographic algorithm number (RFC 8624).
        algorithm: u8,
        /// DER-encoded public key material.
        public_key: Vec<u8>,
    },
    /// Delegation signer record (RFC 4034 §5).
    Ds {
        /// Key tag of the referenced DNSKEY.
        key_tag: u16,
        /// Algorithm number matching the referenced DNSKEY.
        algorithm: u8,
        /// Digest type algorithm identifier.
        digest_type: u8,
        /// Cryptographic digest of the referenced DNSKEY.
        digest: Vec<u8>,
    },
    /// DNSSEC signature record (RFC 4034 §3).
    Rrsig {
        /// The RR type covered by this signature.
        type_covered: Rtype,
        /// Algorithm number.
        algorithm: u8,
        /// Number of labels in the original RRSIG owner name.
        labels: u8,
        /// Original TTL of the covered `RRset`.
        original_ttl: u32,
        /// Signature expiration time (seconds since epoch).
        sig_expiration: u32,
        /// Signature inception time (seconds since epoch).
        sig_inception: u32,
        /// Key tag of the signing DNSKEY.
        key_tag: u16,
        /// Domain name of the signing zone.
        signer_name: Name,
        /// Cryptographic signature bytes.
        signature: Vec<u8>,
    },
    /// Next secure record (RFC 4034 §4).
    Nsec {
        /// Owner name of the next RR in canonical order.
        next_domain: Name,
        /// Type bitmap encoding the present types at `next_domain`.
        type_bitmaps: Vec<u8>,
    },
    /// NSEC3 record (RFC 5155 §3).
    Nsec3 {
        /// Hash algorithm identifier.
        hash_algorithm: u8,
        /// NSEC3 flags byte.
        flags: u8,
        /// Number of additional hash iterations.
        iterations: u16,
        /// Salt value.
        salt: Vec<u8>,
        /// Hashed owner name of the next RR.
        next_hashed_owner: Vec<u8>,
        /// Type bitmap.
        type_bitmaps: Vec<u8>,
    },
    /// NSEC3PARAM record (RFC 5155 §4).
    Nsec3param {
        /// Hash algorithm identifier.
        hash_algorithm: u8,
        /// Flags byte.
        flags: u8,
        /// Iteration count.
        iterations: u16,
        /// Salt value.
        salt: Vec<u8>,
    },
    /// Child delegation signer (RFC 7344 §3).
    Cds {
        /// Key tag of the referenced DNSKEY.
        key_tag: u16,
        /// Algorithm number.
        algorithm: u8,
        /// Digest type.
        digest_type: u8,
        /// Digest bytes.
        digest: Vec<u8>,
    },
    /// Child DNSKEY (RFC 7344 §3).
    Cdnskey {
        /// Key flags.
        flags: u16,
        /// Protocol (MUST be 3).
        protocol: u8,
        /// Algorithm number.
        algorithm: u8,
        /// Public key material.
        public_key: Vec<u8>,
    },
    /// Child-to-parent synchronisation record (RFC 7477 §2).
    Csync {
        /// SOA serial number.
        soa_serial: u32,
        /// CSYNC flags.
        flags: u16,
        /// Type bitmap of RR types to synchronise.
        type_bitmaps: Vec<u8>,
    },
    /// TLS certificate association (RFC 6698 §2).
    Tlsa {
        /// Certificate usage identifier.
        cert_usage: u8,
        /// Selector identifier.
        selector: u8,
        /// Matching type identifier.
        matching_type: u8,
        /// Certificate association data.
        cert_association_data: Vec<u8>,
    },
    /// SSH public key fingerprint (RFC 4255 §3).
    Sshfp {
        /// Public key algorithm identifier.
        algorithm: u8,
        /// Fingerprint type identifier.
        fp_type: u8,
        /// Fingerprint bytes.
        fingerprint: Vec<u8>,
    },
    /// Service binding record (RFC 9460).  Parameters are stored as raw bytes
    /// pending full SVCB parameter parsing (out of Sprint 13 scope).
    Svcb {
        /// Service priority (0 = alias mode).
        priority: u16,
        /// Target name.
        target: Name,
        /// Raw `SvcParams` bytes.
        params: Vec<u8>,
    },
    /// HTTPS-specific service binding (RFC 9460).  Same wire format as SVCB.
    Https {
        /// Service priority (0 = alias mode).
        priority: u16,
        /// Target name.
        target: Name,
        /// Raw `SvcParams` bytes.
        params: Vec<u8>,
    },
    /// OPT pseudo-RR carrying EDNS(0) options (RFC 6891).
    ///
    /// The [`OptRr`] value contains the decoded EDNS fields extracted from the
    /// wire-format CLASS and TTL fields of the OPT record, together with the
    /// fully-decoded options list.
    Opt(OptRr),
    /// Unknown or unimplemented RDATA type — raw bytes preserved (RFC 3597).
    Unknown {
        /// The numeric RTYPE value.
        rtype: u16,
        /// Raw RDATA bytes.
        data: Vec<u8>,
    },
}

impl RData {
    /// Parses RDATA from the wire given the record type, the full message
    /// buffer (for name decompression), and the RDATA slice.
    ///
    /// `buf` is the entire DNS message (required for name decompression).
    /// `rdata` is the slice `buf[rdata_start..rdata_start+rdlength]`.
    /// `rdata_offset` is the absolute offset of `rdata` within `buf` (used
    /// so that name pointers within RDATA resolve correctly).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on truncation, pointer loops, or malformed data.
    pub fn parse(
        rtype: Rtype,
        buf: &[u8],
        rdata_offset: usize,
        rdlength: usize,
    ) -> Result<Self, ParseError> {
        let rdata_end = rdata_offset
            .checked_add(rdlength)
            .ok_or(ParseError::UnexpectedEof)?;
        if rdata_end > buf.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let rdata = &buf[rdata_offset..rdata_end];

        match rtype {
            Rtype::A => parse_a(rdata),
            Rtype::Aaaa => parse_aaaa(rdata),
            Rtype::Ns => parse_name_rdata(buf, rdata_offset, rdlength, RData::Ns),
            Rtype::Cname => parse_name_rdata(buf, rdata_offset, rdlength, RData::Cname),
            Rtype::Dname => parse_name_rdata(buf, rdata_offset, rdlength, RData::Dname),
            Rtype::Ptr => parse_name_rdata(buf, rdata_offset, rdlength, RData::Ptr),
            Rtype::Mx => parse_mx(buf, rdata_offset, rdlength),
            Rtype::Soa => parse_soa(buf, rdata_offset, rdlength),
            Rtype::Txt => parse_txt(rdata),
            Rtype::Srv => parse_srv(buf, rdata_offset, rdlength),
            Rtype::Caa => parse_caa(rdata),
            Rtype::Dnskey => parse_dnskey(rdata),
            Rtype::Ds => parse_ds(rdata),
            Rtype::Rrsig => parse_rrsig(buf, rdata_offset, rdlength),
            Rtype::Nsec => parse_nsec(buf, rdata_offset, rdlength),
            Rtype::Nsec3 => parse_nsec3(rdata),
            Rtype::Nsec3param => parse_nsec3param(rdata),
            Rtype::Cds => parse_cds(rdata),
            Rtype::Cdnskey => parse_cdnskey(rdata),
            Rtype::Csync => parse_csync(rdata),
            Rtype::Tlsa => parse_tlsa(rdata),
            Rtype::Sshfp => parse_sshfp(rdata),
            Rtype::Svcb => parse_svcb(buf, rdata_offset, rdlength, false),
            Rtype::Https => parse_svcb(buf, rdata_offset, rdlength, true),
            // OPT is parsed at the Record level (class/ttl encode EDNS fields);
            // if somehow called here fall through to Unknown.
            Rtype::Opt
            // TSIG is parsed at the Record level; fall through to Unknown here.
            | Rtype::Tsig
            // Types with no dedicated parser implementation are forwarded to Unknown.
            | Rtype::Hinfo
            | Rtype::Rp
            | Rtype::Afsdb
            | Rtype::Sig
            | Rtype::Key
            | Rtype::Loc
            | Rtype::Naptr
            | Rtype::Cert
            | Rtype::Apl
            | Rtype::Ipseckey
            | Rtype::Dhcid
            | Rtype::Smimea
            | Rtype::Hip
            | Rtype::Openpgpkey
            | Rtype::Zonemd
            | Rtype::Uri
            | Rtype::Unknown(_) => Ok(RData::Unknown {
                rtype: rtype.as_u16(),
                data: rdata.to_vec(),
            }),
        }
    }

    /// Appends the wire-format RDATA bytes to `buf`.
    ///
    /// Does not write RDLENGTH — the caller is responsible for prefixing it.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            Self::A(addr) => buf.extend_from_slice(&addr.octets()),
            Self::Aaaa(addr) => buf.extend_from_slice(&addr.octets()),
            Self::Ns(n) | Self::Cname(n) | Self::Dname(n) | Self::Ptr(n) => {
                buf.extend_from_slice(n.as_wire_bytes());
            }
            Self::Mx {
                preference,
                exchange,
            } => {
                buf.extend_from_slice(&preference.to_be_bytes());
                buf.extend_from_slice(exchange.as_wire_bytes());
            }
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                buf.extend_from_slice(mname.as_wire_bytes());
                buf.extend_from_slice(rname.as_wire_bytes());
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
                buf.extend_from_slice(&minimum.to_be_bytes());
            }
            Self::Txt(strings) => {
                for s in strings {
                    // INVARIANT: individual TXT character-strings are bounded to ≤ 255 bytes
                    // by the DNS wire format (single length byte).  Strings that were parsed
                    // from wire or constructed within this crate already satisfy this.
                    #[allow(clippy::cast_possible_truncation)]
                    buf.push(s.len() as u8);
                    buf.extend_from_slice(s);
                }
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                buf.extend_from_slice(&priority.to_be_bytes());
                buf.extend_from_slice(&weight.to_be_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(target.as_wire_bytes());
            }
            Self::Caa { flags, tag, value } => {
                buf.push(*flags);
                // INVARIANT: CAA tag ≤ 15 bytes per RFC 8659 §4; fits in u8.
                #[allow(clippy::cast_possible_truncation)]
                buf.push(tag.len() as u8);
                buf.extend_from_slice(tag);
                buf.extend_from_slice(value);
            }
            Self::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            }
            | Self::Cdnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                buf.extend_from_slice(&flags.to_be_bytes());
                buf.push(*protocol);
                buf.push(*algorithm);
                buf.extend_from_slice(public_key);
            }
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | Self::Cds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                buf.extend_from_slice(&key_tag.to_be_bytes());
                buf.push(*algorithm);
                buf.push(*digest_type);
                buf.extend_from_slice(digest);
            }
            Self::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                sig_expiration,
                sig_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                buf.extend_from_slice(&type_covered.as_u16().to_be_bytes());
                buf.push(*algorithm);
                buf.push(*labels);
                buf.extend_from_slice(&original_ttl.to_be_bytes());
                buf.extend_from_slice(&sig_expiration.to_be_bytes());
                buf.extend_from_slice(&sig_inception.to_be_bytes());
                buf.extend_from_slice(&key_tag.to_be_bytes());
                buf.extend_from_slice(signer_name.as_wire_bytes());
                buf.extend_from_slice(signature);
            }
            Self::Nsec {
                next_domain,
                type_bitmaps,
            } => {
                buf.extend_from_slice(next_domain.as_wire_bytes());
                buf.extend_from_slice(type_bitmaps);
            }
            Self::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmaps,
            } => {
                buf.push(*hash_algorithm);
                buf.push(*flags);
                buf.extend_from_slice(&iterations.to_be_bytes());
                // INVARIANT: salt and next_hashed_owner lengths are bounded by single-byte
                // length prefix in the wire format (≤ 255 bytes each).
                #[allow(clippy::cast_possible_truncation)]
                buf.push(salt.len() as u8);
                buf.extend_from_slice(salt);
                #[allow(clippy::cast_possible_truncation)]
                buf.push(next_hashed_owner.len() as u8);
                buf.extend_from_slice(next_hashed_owner);
                buf.extend_from_slice(type_bitmaps);
            }
            Self::Nsec3param {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => {
                buf.push(*hash_algorithm);
                buf.push(*flags);
                buf.extend_from_slice(&iterations.to_be_bytes());
                // INVARIANT: salt bounded by single-byte length prefix (≤ 255 bytes).
                #[allow(clippy::cast_possible_truncation)]
                buf.push(salt.len() as u8);
                buf.extend_from_slice(salt);
            }
            Self::Csync {
                soa_serial,
                flags,
                type_bitmaps,
            } => {
                buf.extend_from_slice(&soa_serial.to_be_bytes());
                buf.extend_from_slice(&flags.to_be_bytes());
                buf.extend_from_slice(type_bitmaps);
            }
            Self::Tlsa {
                cert_usage,
                selector,
                matching_type,
                cert_association_data,
            } => {
                buf.push(*cert_usage);
                buf.push(*selector);
                buf.push(*matching_type);
                buf.extend_from_slice(cert_association_data);
            }
            Self::Sshfp {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                buf.push(*algorithm);
                buf.push(*fp_type);
                buf.extend_from_slice(fingerprint);
            }
            Self::Svcb {
                priority,
                target,
                params,
            }
            | Self::Https {
                priority,
                target,
                params,
            } => {
                buf.extend_from_slice(&priority.to_be_bytes());
                buf.extend_from_slice(target.as_wire_bytes());
                buf.extend_from_slice(params);
            }
            Self::Opt(opt_rr) => {
                // OPT is handled specially by the record serialiser (class/ttl
                // encode payload size, extended rcode, version, DO bit, and Z).
                // This path only writes the RDATA (options TLV stream).
                opt_rr.write_rdata_to(buf);
            }
            Self::Unknown { data, .. } => {
                buf.extend_from_slice(data);
            }
        }
    }
}

// ── Individual parsers ────────────────────────────────────────────────────────

fn parse_a(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() != 4 {
        return Err(ParseError::InvalidRdata {
            rtype: 1,
            reason: "A record must be 4 bytes",
        });
    }
    Ok(RData::A(Ipv4Addr::new(
        rdata[0], rdata[1], rdata[2], rdata[3],
    )))
}

fn parse_aaaa(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() != 16 {
        return Err(ParseError::InvalidRdata {
            rtype: 28,
            reason: "AAAA record must be 16 bytes",
        });
    }
    let arr: [u8; 16] = rdata.try_into().map_err(|_| ParseError::InvalidRdata {
        rtype: 28,
        reason: "AAAA record must be 16 bytes",
    })?;
    Ok(RData::Aaaa(Ipv6Addr::from(arr)))
}

fn parse_name_rdata(
    buf: &[u8],
    rdata_offset: usize,
    _rdlength: usize,
    ctor: fn(Name) -> RData,
) -> Result<RData, ParseError> {
    let mut off = rdata_offset;
    let name = crate::parser::parse_name(buf, &mut off)?;
    Ok(ctor(name))
}

fn parse_mx(buf: &[u8], rdata_offset: usize, rdlength: usize) -> Result<RData, ParseError> {
    if rdlength < 2 {
        return Err(ParseError::InvalidRdata {
            rtype: 15,
            reason: "MX too short",
        });
    }
    let mut off = rdata_offset;
    let preference = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let exchange = crate::parser::parse_name(buf, &mut off)?;
    Ok(RData::Mx {
        preference,
        exchange,
    })
}

fn parse_soa(buf: &[u8], rdata_offset: usize, rdlength: usize) -> Result<RData, ParseError> {
    if rdlength < 22 {
        return Err(ParseError::InvalidRdata {
            rtype: 6,
            reason: "SOA too short",
        });
    }
    let mut off = rdata_offset;
    let mname = crate::parser::parse_name(buf, &mut off)?;
    let rname = crate::parser::parse_name(buf, &mut off)?;
    let serial = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let refresh = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let retry = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let expire = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let minimum = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    Ok(RData::Soa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

fn parse_txt(rdata: &[u8]) -> Result<RData, ParseError> {
    let mut strings = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        let len = usize::from(rdata[pos]);
        pos += 1;
        let end = pos.checked_add(len).ok_or(ParseError::UnexpectedEof)?;
        if end > rdata.len() {
            return Err(ParseError::InvalidRdata {
                rtype: 16,
                reason: "TXT string truncated",
            });
        }
        strings.push(rdata[pos..end].to_vec());
        pos = end;
    }
    Ok(RData::Txt(strings))
}

fn parse_srv(buf: &[u8], rdata_offset: usize, rdlength: usize) -> Result<RData, ParseError> {
    if rdlength < 6 {
        return Err(ParseError::InvalidRdata {
            rtype: 33,
            reason: "SRV too short",
        });
    }
    let mut off = rdata_offset;
    let priority = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let weight = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let port = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let target = crate::parser::parse_name(buf, &mut off)?;
    Ok(RData::Srv {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_caa(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 2 {
        return Err(ParseError::InvalidRdata {
            rtype: 257,
            reason: "CAA too short",
        });
    }
    let flags = rdata[0];
    let tag_len = usize::from(rdata[1]);
    if tag_len == 0 {
        return Err(ParseError::InvalidRdata {
            rtype: 257,
            reason: "CAA tag must not be empty",
        });
    }
    let tag_end = 2usize
        .checked_add(tag_len)
        .ok_or(ParseError::UnexpectedEof)?;
    if tag_end > rdata.len() {
        return Err(ParseError::InvalidRdata {
            rtype: 257,
            reason: "CAA tag truncated",
        });
    }
    let tag = rdata[2..tag_end].to_vec();
    let value = rdata[tag_end..].to_vec();
    Ok(RData::Caa { flags, tag, value })
}

fn parse_dnskey(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 4 {
        return Err(ParseError::InvalidRdata {
            rtype: 48,
            reason: "DNSKEY too short",
        });
    }
    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    let protocol = rdata[2];
    let algorithm = rdata[3];
    let public_key = rdata[4..].to_vec();
    Ok(RData::Dnskey {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn parse_ds(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 4 {
        return Err(ParseError::InvalidRdata {
            rtype: 43,
            reason: "DS too short",
        });
    }
    let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let digest_type = rdata[3];
    let digest = rdata[4..].to_vec();
    Ok(RData::Ds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

fn parse_rrsig(buf: &[u8], rdata_offset: usize, rdlength: usize) -> Result<RData, ParseError> {
    if rdlength < 18 {
        return Err(ParseError::InvalidRdata {
            rtype: 46,
            reason: "RRSIG too short",
        });
    }
    let mut off = rdata_offset;
    let type_covered_raw =
        crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let type_covered = Rtype::from_u16(type_covered_raw);
    let algorithm = buf.get(off).copied().ok_or(ParseError::UnexpectedEof)?;
    off += 1;
    let labels = buf.get(off).copied().ok_or(ParseError::UnexpectedEof)?;
    off += 1;
    let original_ttl = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let sig_expiration = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let sig_inception = crate::header::read_u32(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let key_tag = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let signer_name = crate::parser::parse_name(buf, &mut off)?;
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(ParseError::UnexpectedEof)?;
    let signature = buf
        .get(off..rdata_end)
        .ok_or(ParseError::UnexpectedEof)?
        .to_vec();
    Ok(RData::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        signature,
    })
}

fn parse_nsec(buf: &[u8], rdata_offset: usize, rdlength: usize) -> Result<RData, ParseError> {
    let mut off = rdata_offset;
    let next_domain = crate::parser::parse_name(buf, &mut off)?;
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(ParseError::UnexpectedEof)?;
    let type_bitmaps = buf
        .get(off..rdata_end)
        .ok_or(ParseError::UnexpectedEof)?
        .to_vec();
    Ok(RData::Nsec {
        next_domain,
        type_bitmaps,
    })
}

fn parse_nsec3(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 5 {
        return Err(ParseError::InvalidRdata {
            rtype: 50,
            reason: "NSEC3 too short",
        });
    }
    let hash_algorithm = rdata[0];
    let flags = rdata[1];
    let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
    let salt_len = usize::from(rdata[4]);
    let mut pos = 5usize;
    let salt_end = pos.checked_add(salt_len).ok_or(ParseError::UnexpectedEof)?;
    if salt_end > rdata.len() {
        return Err(ParseError::InvalidRdata {
            rtype: 50,
            reason: "NSEC3 salt truncated",
        });
    }
    let salt = rdata[pos..salt_end].to_vec();
    pos = salt_end;
    let hash_len = usize::from(*rdata.get(pos).ok_or(ParseError::UnexpectedEof)?);
    pos += 1;
    let hash_end = pos.checked_add(hash_len).ok_or(ParseError::UnexpectedEof)?;
    if hash_end > rdata.len() {
        return Err(ParseError::InvalidRdata {
            rtype: 50,
            reason: "NSEC3 next hashed owner truncated",
        });
    }
    let next_hashed_owner = rdata[pos..hash_end].to_vec();
    let type_bitmaps = rdata[hash_end..].to_vec();
    Ok(RData::Nsec3 {
        hash_algorithm,
        flags,
        iterations,
        salt,
        next_hashed_owner,
        type_bitmaps,
    })
}

fn parse_nsec3param(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 5 {
        return Err(ParseError::InvalidRdata {
            rtype: 51,
            reason: "NSEC3PARAM too short",
        });
    }
    let hash_algorithm = rdata[0];
    let flags = rdata[1];
    let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
    let salt_len = usize::from(rdata[4]);
    let salt_end = 5usize
        .checked_add(salt_len)
        .ok_or(ParseError::UnexpectedEof)?;
    if salt_end > rdata.len() {
        return Err(ParseError::InvalidRdata {
            rtype: 51,
            reason: "NSEC3PARAM salt truncated",
        });
    }
    let salt = rdata[5..salt_end].to_vec();
    Ok(RData::Nsec3param {
        hash_algorithm,
        flags,
        iterations,
        salt,
    })
}

fn parse_cds(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 4 {
        return Err(ParseError::InvalidRdata {
            rtype: 59,
            reason: "CDS too short",
        });
    }
    let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let digest_type = rdata[3];
    let digest = rdata[4..].to_vec();
    Ok(RData::Cds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

fn parse_cdnskey(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 4 {
        return Err(ParseError::InvalidRdata {
            rtype: 60,
            reason: "CDNSKEY too short",
        });
    }
    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    let protocol = rdata[2];
    let algorithm = rdata[3];
    let public_key = rdata[4..].to_vec();
    Ok(RData::Cdnskey {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn parse_csync(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 6 {
        return Err(ParseError::InvalidRdata {
            rtype: 62,
            reason: "CSYNC too short",
        });
    }
    let soa_serial = u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]);
    let flags = u16::from_be_bytes([rdata[4], rdata[5]]);
    let type_bitmaps = rdata[6..].to_vec();
    Ok(RData::Csync {
        soa_serial,
        flags,
        type_bitmaps,
    })
}

fn parse_tlsa(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 3 {
        return Err(ParseError::InvalidRdata {
            rtype: 52,
            reason: "TLSA too short",
        });
    }
    let cert_usage = rdata[0];
    let selector = rdata[1];
    let matching_type = rdata[2];
    let cert_association_data = rdata[3..].to_vec();
    Ok(RData::Tlsa {
        cert_usage,
        selector,
        matching_type,
        cert_association_data,
    })
}

fn parse_sshfp(rdata: &[u8]) -> Result<RData, ParseError> {
    if rdata.len() < 2 {
        return Err(ParseError::InvalidRdata {
            rtype: 44,
            reason: "SSHFP too short",
        });
    }
    let algorithm = rdata[0];
    let fp_type = rdata[1];
    let fingerprint = rdata[2..].to_vec();
    Ok(RData::Sshfp {
        algorithm,
        fp_type,
        fingerprint,
    })
}

fn parse_svcb(
    buf: &[u8],
    rdata_offset: usize,
    rdlength: usize,
    is_https: bool,
) -> Result<RData, ParseError> {
    let rtype_num: u16 = if is_https { 65 } else { 64 };
    if rdlength < 2 {
        return Err(ParseError::InvalidRdata {
            rtype: rtype_num,
            reason: "SVCB/HTTPS too short",
        });
    }
    let mut off = rdata_offset;
    let priority = crate::header::read_u16(buf, &mut off).ok_or(ParseError::UnexpectedEof)?;
    let target = crate::parser::parse_name(buf, &mut off)?;
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(ParseError::UnexpectedEof)?;
    let params = buf
        .get(off..rdata_end)
        .ok_or(ParseError::UnexpectedEof)?
        .to_vec();
    if is_https {
        Ok(RData::Https {
            priority,
            target,
            params,
        })
    } else {
        Ok(RData::Svcb {
            priority,
            target,
            params,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn a_roundtrip() {
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        let rdata = RData::A(addr);
        let mut buf = Vec::new();
        rdata.write_to(&mut buf);
        assert_eq!(buf, [192, 0, 2, 1]);
        let parsed = RData::parse(Rtype::A, &buf, 0, 4).unwrap();
        assert_eq!(parsed, rdata);
    }

    #[test]
    fn aaaa_roundtrip() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let rdata = RData::Aaaa(addr);
        let mut buf = Vec::new();
        rdata.write_to(&mut buf);
        assert_eq!(buf.len(), 16);
        let parsed = RData::parse(Rtype::Aaaa, &buf, 0, 16).unwrap();
        assert_eq!(parsed, rdata);
    }

    #[test]
    fn txt_roundtrip() {
        let rdata = RData::Txt(vec![b"hello".to_vec(), b"world".to_vec()]);
        let mut buf = Vec::new();
        rdata.write_to(&mut buf);
        // [5, h, e, l, l, o, 5, w, o, r, l, d]
        let parsed = RData::parse(Rtype::Txt, &buf, 0, buf.len()).unwrap();
        assert_eq!(parsed, rdata);
    }

    #[test]
    fn soa_roundtrip() {
        let rdata = RData::Soa {
            mname: Name::from_str("ns1.example.com.").unwrap(),
            rname: Name::from_str("admin.example.com.").unwrap(),
            serial: 20_240_101,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        };
        let mut buf = Vec::new();
        rdata.write_to(&mut buf);
        let len = buf.len();
        let parsed = RData::parse(Rtype::Soa, &buf, 0, len).unwrap();
        assert_eq!(parsed, rdata);
    }

    #[test]
    fn a_wrong_length() {
        let buf = [1u8, 2, 3]; // only 3 bytes
        assert!(matches!(
            RData::parse(Rtype::A, &buf, 0, 3),
            Err(ParseError::InvalidRdata { rtype: 1, .. })
        ));
    }
}
