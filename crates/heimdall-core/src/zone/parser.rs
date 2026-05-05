// SPDX-License-Identifier: MIT

//! Zone-file directive and resource-record parser (Task #214, #215, #216).
//!
//! The zone parser drives the tokenizer and calls directive handlers or
//! RDATA parsers as appropriate.  It produces a flat [`Vec<Record>`] from the
//! zone-file source text.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    header::Qclass,
    name::Name,
    rdata::RData,
    record::{Record, Rtype},
    zone::{
        ZoneError,
        directives::{
            expect_word, handle_generate, handle_include, handle_origin, handle_ttl,
            parse_absolute_name,
        },
        limits::{LimitKind, ZoneLimits},
        tokenizer::{Token, Tokenizer, resolve_word_escapes},
    },
};

// ── ZoneParser ────────────────────────────────────────────────────────────────

/// Stateful zone-file parser.
///
/// Drives the [`Tokenizer`] and accumulates [`Record`]s while enforcing
/// [`ZoneLimits`].
pub(crate) struct ZoneParser<'src> {
    tok: Tokenizer<'src>,
    pub(crate) origin: Option<Name>,
    default_ttl: Option<u32>,
    last_owner: Option<Name>,
    last_ttl: Option<u32>,
    limits: ZoneLimits,
    rr_count: usize,
    rrsig_count: usize,
    ns_count: usize,
    include_stack: Vec<PathBuf>,
}

impl<'src> ZoneParser<'src> {
    /// Creates a top-level parser.
    pub(crate) fn new(
        src: &'src str,
        origin: Option<Name>,
        limits: ZoneLimits,
        include_stack: Vec<PathBuf>,
    ) -> Self {
        Self {
            tok: Tokenizer::new(src),
            origin,
            default_ttl: None,
            last_owner: None,
            last_ttl: None,
            limits,
            rr_count: 0,
            rrsig_count: 0,
            ns_count: 0,
            include_stack,
        }
    }

    /// Creates an inner parser for `$INCLUDE` processing, inheriting counters
    /// and stack.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_inner(
        src: &'src str,
        origin: Option<Name>,
        default_ttl: Option<u32>,
        last_owner: Option<Name>,
        limits: ZoneLimits,
        include_stack: Vec<PathBuf>,
        rr_count: usize,
        rrsig_count: usize,
        ns_count: usize,
    ) -> Self {
        Self {
            tok: Tokenizer::new(src),
            origin,
            default_ttl,
            last_owner,
            last_ttl: None,
            limits,
            rr_count,
            rrsig_count,
            ns_count,
            include_stack,
        }
    }

    /// Returns a reference to the current effective origin, if any.
    pub(crate) fn origin(&self) -> Option<&Name> {
        self.origin.as_ref()
    }

    /// Returns the current total RR counter.
    pub(crate) fn rr_count(&self) -> usize {
        self.rr_count
    }

    /// Returns the current RRSIG counter.
    pub(crate) fn rrsig_count(&self) -> usize {
        self.rrsig_count
    }

    /// Returns the current NS counter.
    pub(crate) fn ns_count(&self) -> usize {
        self.ns_count
    }

    /// Parses all entries in the zone file and returns the collected records.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] on any syntax or semantic error.
    pub(crate) fn parse_all(&mut self) -> Result<Vec<Record>, ZoneError> {
        let mut records: Vec<Record> = Vec::new();
        loop {
            match self.tok.peek_token()? {
                Token::Eof => break,
                Token::Newline => {
                    self.tok.next_token()?;
                    continue;
                }
                _ => {}
            }
            self.parse_entry(&mut records)?;
        }
        Ok(records)
    }

    // ── Entry dispatch ────────────────────────────────────────────────────────

    fn parse_entry(&mut self, records: &mut Vec<Record>) -> Result<(), ZoneError> {
        let line = self.tok.line();
        let first = self.tok.next_token()?;

        // RFC 1035 §5.1: if the first token on a line was preceded by
        // horizontal whitespace, the owner field is absent and the last owner
        // is reused ("blank owner" carry-over).
        let blank_owner = self.tok.is_blank_owner_line();

        match first {
            Token::Newline | Token::Eof => return Ok(()),

            // Blank-owner line: the first token is NOT the owner — push it
            // back via a synthetic path by reusing `last_owner` and letting
            // `parse_rr` consume `first` as the TTL/class/type field.
            Token::Word(w) if blank_owner => {
                let owner = self
                    .last_owner
                    .clone()
                    .ok_or(ZoneError::MissingOwner { line })?;
                // The word `w` is the first field after the (implicit) owner.
                // Feed it to `parse_rr` by putting it back into the tokenizer's
                // peek slot so `parse_rr` sees it as the next token.
                self.tok.put_back(Token::Word(w));
                let rec = self.parse_rr(owner, line, records)?;
                self.push_record(rec, records)?;
            }

            Token::Word(w) if w.starts_with('$') => {
                let directive = w.to_ascii_uppercase();
                match directive.as_str() {
                    "$ORIGIN" => {
                        handle_origin(&mut self.tok, &mut self.origin)?;
                    }
                    "$TTL" => {
                        handle_ttl(&mut self.tok, &mut self.default_ttl)?;
                    }
                    "$INCLUDE" => {
                        let saved_origin = self.origin.clone();
                        let saved_ttl = self.default_ttl;
                        let saved_owner = self.last_owner.clone();
                        handle_include(
                            &mut self.tok,
                            saved_origin,
                            saved_ttl,
                            saved_owner,
                            &mut self.include_stack,
                            &self.limits,
                            records,
                            &mut self.rr_count,
                            &mut self.rrsig_count,
                            &mut self.ns_count,
                        )?;
                    }
                    "$GENERATE" => {
                        handle_generate(
                            &mut self.tok,
                            self.origin.as_ref(),
                            self.default_ttl,
                            self.last_owner.as_ref(),
                            &self.limits,
                            records,
                            &mut self.rr_count,
                        )?;
                    }
                    _ => {
                        return Err(ZoneError::UnknownDirective { line, directive });
                    }
                }
            }
            Token::Word(w) => {
                // The word is an owner name.  It may be '@', an absolute name,
                // or a relative name.
                let owner = if w == "@" {
                    self.origin
                        .clone()
                        .ok_or(ZoneError::MissingOrigin { line })?
                } else {
                    parse_absolute_name(w, self.origin.clone(), line)?
                };
                self.last_owner = Some(owner.clone());
                let rec = self.parse_rr(owner, line, records)?;
                self.push_record(rec, records)?;
            }
            Token::QuotedString(_) => {
                return Err(ZoneError::Tokenize {
                    line,
                    msg: "unexpected quoted string at start of line",
                });
            }
        }
        Ok(())
    }

    /// Parses the TTL, class, and type fields of a resource record, then the
    /// RDATA.  The `owner` has already been resolved by the caller.
    ///
    /// RFC 1035 §5.1 allows TTL and class in either order.
    fn parse_rr(
        &mut self,
        owner: Name,
        line: usize,
        _records: &mut Vec<Record>,
    ) -> Result<Record, ZoneError> {
        // After the owner, we may have: [TTL] [CLASS] TYPE RDATA
        // or: [CLASS] [TTL] TYPE RDATA (RFC 1035 allows either order).
        let mut ttl: Option<u32> = None;
        let mut class: Option<Qclass> = None;

        // Read at most 2 optional fields before the mandatory type.
        for _ in 0..2 {
            match self.tok.peek_token()? {
                Token::Word(w) => {
                    if let (Some(t), true) = (try_parse_ttl(w), ttl.is_none()) {
                        ttl = Some(t);
                        self.tok.next_token()?;
                        continue;
                    }
                    if let (Some(c), true) = (try_parse_class(w), class.is_none()) {
                        class = Some(c);
                        self.tok.next_token()?;
                        continue;
                    }
                    // Not TTL, not class — must be the type.
                    break;
                }
                _ => break,
            }
        }

        // Effective TTL: explicit > last seen > default > error.
        let effective_ttl =
            ttl.or(self.last_ttl)
                .or(self.default_ttl)
                .ok_or(ZoneError::ParseRdata {
                    line,
                    rtype: "RR".into(),
                    reason: "no TTL specified and no $TTL default is in effect".into(),
                })?;

        if ttl.is_some() {
            self.last_ttl = ttl;
        }

        let effective_class = class.unwrap_or(Qclass::In);

        // Mandatory: record type.
        let rtype_str = match self.tok.next_token()? {
            Token::Word(w) => w.to_ascii_uppercase(),
            other => {
                return Err(ZoneError::ParseRdata {
                    line,
                    rtype: "RR".into(),
                    reason: format!("expected record type, got {other:?}"),
                });
            }
        };

        let rtype = parse_rtype_str(&rtype_str, line)?;

        // Parse RDATA.
        let rdata = self.parse_rdata(rtype, line)?;

        // Consume any trailing comment / end-of-line.
        consume_to_newline_or_eof(&mut self.tok)?;

        Ok(Record {
            name: owner,
            rtype,
            rclass: effective_class,
            ttl: effective_ttl,
            rdata,
        })
    }

    /// Pushes a record onto the output vector and enforces limits.
    fn push_record(&mut self, rec: Record, records: &mut Vec<Record>) -> Result<(), ZoneError> {
        // Per-type limit tracking.
        match rec.rtype {
            Rtype::Rrsig => {
                self.rrsig_count += 1;
                if self.rrsig_count > self.limits.max_rrsig_records {
                    return Err(ZoneError::ZoneSizeLimit(LimitKind::RrsigCount));
                }
            }
            Rtype::Ns => {
                self.ns_count += 1;
                if self.ns_count > self.limits.max_ns_records {
                    return Err(ZoneError::ZoneSizeLimit(LimitKind::NsCount));
                }
            }
            _ => {}
        }
        self.rr_count += 1;
        if self.rr_count > self.limits.max_records {
            return Err(ZoneError::ZoneSizeLimit(LimitKind::RecordCount));
        }
        records.push(rec);
        Ok(())
    }

    // ── RDATA dispatch ────────────────────────────────────────────────────────

    fn parse_rdata(&mut self, rtype: Rtype, line: usize) -> Result<RData, ZoneError> {
        match rtype {
            Rtype::A => self.parse_rdata_a(line),
            Rtype::Aaaa => self.parse_rdata_aaaa(line),
            Rtype::Ns => self.parse_rdata_name(line).map(RData::Ns),
            Rtype::Cname => self.parse_rdata_name(line).map(RData::Cname),
            Rtype::Dname => self.parse_rdata_name(line).map(RData::Dname),
            Rtype::Ptr => self.parse_rdata_name(line).map(RData::Ptr),
            Rtype::Mx => self.parse_rdata_mx(line),
            Rtype::Soa => self.parse_rdata_soa(line),
            Rtype::Txt => self.parse_rdata_txt(line),
            Rtype::Srv => self.parse_rdata_srv(line),
            Rtype::Caa => self.parse_rdata_caa(line),
            Rtype::Dnskey => self.parse_rdata_dnskey(line),
            Rtype::Ds => self.parse_rdata_ds(line),
            Rtype::Rrsig => self.parse_rdata_rrsig(line),
            Rtype::Nsec => self.parse_rdata_nsec(line),
            Rtype::Nsec3 => self.parse_rdata_nsec3(line),
            Rtype::Nsec3param => self.parse_rdata_nsec3param(line),
            Rtype::Cds => self.parse_rdata_cds(line),
            Rtype::Cdnskey => self.parse_rdata_cdnskey(line),
            Rtype::Csync => self.parse_rdata_csync(line),
            Rtype::Tlsa => self.parse_rdata_tlsa(line),
            Rtype::Sshfp => self.parse_rdata_sshfp(line),
            Rtype::Https => self.parse_rdata_svcb_https(line, true),
            Rtype::Svcb => self.parse_rdata_svcb_https(line, false),
            Rtype::Unknown(_) => self.parse_rdata_unknown(rtype, line),
            _ => {
                // Remaining types not listed in spec → unknown generic form.
                self.parse_rdata_unknown(rtype, line)
            }
        }
    }

    // ── Individual RDATA parsers ──────────────────────────────────────────────

    fn parse_rdata_a(&mut self, line: usize) -> Result<RData, ZoneError> {
        let w = self.next_word(line, "A")?;
        Ipv4Addr::from_str(w)
            .map(RData::A)
            .map_err(|e| ZoneError::ParseRdata {
                line,
                rtype: "A".into(),
                reason: e.to_string(),
            })
    }

    fn parse_rdata_aaaa(&mut self, line: usize) -> Result<RData, ZoneError> {
        let w = self.next_word(line, "AAAA")?;
        Ipv6Addr::from_str(w)
            .map(RData::Aaaa)
            .map_err(|e| ZoneError::ParseRdata {
                line,
                rtype: "AAAA".into(),
                reason: e.to_string(),
            })
    }

    fn parse_rdata_name(&mut self, line: usize) -> Result<Name, ZoneError> {
        let origin = self.origin.clone();
        let w = self.next_word(line, "NAME")?;
        let w = w.to_string();
        parse_absolute_name(&w, origin, line)
    }

    fn parse_rdata_mx(&mut self, line: usize) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let pref_str = self.next_word(line, "MX preference")?;
        let preference: u16 = pref_str.parse().map_err(|_| ZoneError::ParseRdata {
            line,
            rtype: "MX".into(),
            reason: format!("invalid preference '{pref_str}'"),
        })?;
        let exch_str = self.next_word(line, "MX exchange")?;
        let exch_str = exch_str.to_string();
        let exchange = parse_absolute_name(&exch_str, origin, line)?;
        Ok(RData::Mx {
            preference,
            exchange,
        })
    }

    fn parse_rdata_soa(&mut self, line: usize) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let mname_str = self.next_word(line, "SOA mname")?;
        let mname_str = mname_str.to_string();
        let mname = parse_absolute_name(&mname_str, origin.clone(), line)?;
        let rname_str = self.next_word(line, "SOA rname")?;
        let rname_str = rname_str.to_string();
        let rname = parse_absolute_name(&rname_str, origin, line)?;
        let serial = self.next_u32(line, "SOA serial")?;
        let refresh = self.next_u32(line, "SOA refresh")?;
        let retry = self.next_u32(line, "SOA retry")?;
        let expire = self.next_u32(line, "SOA expire")?;
        let minimum = self.next_u32(line, "SOA minimum")?;
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

    fn parse_rdata_txt(&mut self, line: usize) -> Result<RData, ZoneError> {
        let mut strings: Vec<Vec<u8>> = Vec::new();
        loop {
            match self.tok.peek_token()? {
                Token::Newline | Token::Eof => break,
                Token::QuotedString(s) => {
                    self.tok.next_token()?;
                    // TXT strings are limited to 255 bytes in wire format.
                    if s.len() > 255 {
                        return Err(ZoneError::ParseRdata {
                            line,
                            rtype: "TXT".into(),
                            reason: "TXT string segment exceeds 255 bytes".into(),
                        });
                    }
                    strings.push(s.into_bytes());
                }
                Token::Word(w) => {
                    // Unquoted TXT string.
                    let bytes = resolve_word_escapes(w).ok_or_else(|| ZoneError::ParseRdata {
                        line,
                        rtype: "TXT".into(),
                        reason: "invalid escape in TXT".into(),
                    })?;
                    self.tok.next_token()?;
                    if bytes.len() > 255 {
                        return Err(ZoneError::ParseRdata {
                            line,
                            rtype: "TXT".into(),
                            reason: "TXT string segment exceeds 255 bytes".into(),
                        });
                    }
                    strings.push(bytes);
                }
            }
        }
        if strings.is_empty() {
            return Err(ZoneError::ParseRdata {
                line,
                rtype: "TXT".into(),
                reason: "TXT record must have at least one string".into(),
            });
        }
        Ok(RData::Txt(strings))
    }

    fn parse_rdata_srv(&mut self, line: usize) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let priority = self.next_u16(line, "SRV priority")?;
        let weight = self.next_u16(line, "SRV weight")?;
        let port = self.next_u16(line, "SRV port")?;
        let target_str = self.next_word(line, "SRV target")?;
        let target_str = target_str.to_string();
        let target = parse_absolute_name(&target_str, origin, line)?;
        Ok(RData::Srv {
            priority,
            weight,
            port,
            target,
        })
    }

    fn parse_rdata_caa(&mut self, line: usize) -> Result<RData, ZoneError> {
        let flags = self.next_u8(line, "CAA flags")?;
        let tag_str = self.next_word(line, "CAA tag")?;
        if tag_str.is_empty() || tag_str.len() > 15 {
            return Err(ZoneError::ParseRdata {
                line,
                rtype: "CAA".into(),
                reason: "CAA tag must be 1–15 ASCII characters".into(),
            });
        }
        let tag = tag_str.as_bytes().to_vec();
        // Value: quoted or unquoted.
        let value = match self.tok.next_token()? {
            Token::QuotedString(s) => s.into_bytes(),
            Token::Word(w) => w.as_bytes().to_vec(),
            other => {
                return Err(ZoneError::ParseRdata {
                    line,
                    rtype: "CAA".into(),
                    reason: format!("expected CAA value, got {other:?}"),
                });
            }
        };
        Ok(RData::Caa { flags, tag, value })
    }

    fn parse_rdata_dnskey(&mut self, line: usize) -> Result<RData, ZoneError> {
        let flags = self.next_u16(line, "DNSKEY flags")?;
        let protocol = self.next_u8(line, "DNSKEY protocol")?;
        if protocol != 3 {
            return Err(ZoneError::ParseRdata {
                line,
                rtype: "DNSKEY".into(),
                reason: format!("DNSKEY protocol must be 3, got {protocol}"),
            });
        }
        let algorithm = self.next_u8(line, "DNSKEY algorithm")?;
        let public_key = self.collect_base64_tokens(line, "DNSKEY")?;
        Ok(RData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    fn parse_rdata_ds(&mut self, line: usize) -> Result<RData, ZoneError> {
        let key_tag = self.next_u16(line, "DS key_tag")?;
        let algorithm = self.next_u8(line, "DS algorithm")?;
        let digest_type = self.next_u8(line, "DS digest_type")?;
        let digest = self.collect_hex_tokens(line, "DS")?;
        Ok(RData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn parse_rdata_rrsig(&mut self, line: usize) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let type_str = self.next_word(line, "RRSIG type_covered")?;
        let type_covered = parse_rtype_str(&type_str.to_ascii_uppercase(), line)?;
        let algorithm = self.next_u8(line, "RRSIG algorithm")?;
        let labels = self.next_u8(line, "RRSIG labels")?;
        let original_ttl = self.next_u32(line, "RRSIG original_ttl")?;
        let sig_expiration = self.next_timestamp(line, "RRSIG sig_expiration")?;
        let sig_inception = self.next_timestamp(line, "RRSIG sig_inception")?;
        let key_tag = self.next_u16(line, "RRSIG key_tag")?;
        let signer_str = self.next_word(line, "RRSIG signer_name")?;
        let signer_str = signer_str.to_string();
        let signer_name = parse_absolute_name(&signer_str, origin, line)?;
        let signature = self.collect_base64_tokens(line, "RRSIG")?;
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

    fn parse_rdata_nsec(&mut self, line: usize) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let next_str = self.next_word(line, "NSEC next_domain")?;
        let next_str = next_str.to_string();
        let next_domain = parse_absolute_name(&next_str, origin, line)?;
        let type_bitmaps = self.parse_type_bitmap(line)?;
        Ok(RData::Nsec {
            next_domain,
            type_bitmaps,
        })
    }

    fn parse_rdata_nsec3(&mut self, line: usize) -> Result<RData, ZoneError> {
        let hash_algorithm = self.next_u8(line, "NSEC3 hash_algorithm")?;
        let flags = self.next_u8(line, "NSEC3 flags")?;
        let iterations = self.next_u16(line, "NSEC3 iterations")?;
        let salt_str = self.next_word(line, "NSEC3 salt")?;
        let salt = if salt_str == "-" {
            vec![]
        } else {
            decode_hex(salt_str, line, "NSEC3 salt")?
        };
        let next_str = self.next_word(line, "NSEC3 next_hashed_owner")?;
        let next_hashed_owner = decode_base32hex(next_str, line, "NSEC3")?;
        let type_bitmaps = self.parse_type_bitmap(line)?;
        Ok(RData::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmaps,
        })
    }

    fn parse_rdata_nsec3param(&mut self, line: usize) -> Result<RData, ZoneError> {
        let hash_algorithm = self.next_u8(line, "NSEC3PARAM hash_algorithm")?;
        let flags = self.next_u8(line, "NSEC3PARAM flags")?;
        let iterations = self.next_u16(line, "NSEC3PARAM iterations")?;
        let salt_str = self.next_word(line, "NSEC3PARAM salt")?;
        let salt = if salt_str == "-" {
            vec![]
        } else {
            decode_hex(salt_str, line, "NSEC3PARAM salt")?
        };
        Ok(RData::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        })
    }

    fn parse_rdata_cds(&mut self, line: usize) -> Result<RData, ZoneError> {
        let key_tag = self.next_u16(line, "CDS key_tag")?;
        let algorithm = self.next_u8(line, "CDS algorithm")?;
        let digest_type = self.next_u8(line, "CDS digest_type")?;
        let digest = self.collect_hex_tokens(line, "CDS")?;
        Ok(RData::Cds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn parse_rdata_cdnskey(&mut self, line: usize) -> Result<RData, ZoneError> {
        let flags = self.next_u16(line, "CDNSKEY flags")?;
        let protocol = self.next_u8(line, "CDNSKEY protocol")?;
        let algorithm = self.next_u8(line, "CDNSKEY algorithm")?;
        let public_key = self.collect_base64_tokens(line, "CDNSKEY")?;
        Ok(RData::Cdnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    fn parse_rdata_csync(&mut self, line: usize) -> Result<RData, ZoneError> {
        let soa_serial = self.next_u32(line, "CSYNC soa_serial")?;
        let flags = self.next_u16(line, "CSYNC flags")?;
        let type_bitmaps = self.parse_type_bitmap(line)?;
        Ok(RData::Csync {
            soa_serial,
            flags,
            type_bitmaps,
        })
    }

    fn parse_rdata_tlsa(&mut self, line: usize) -> Result<RData, ZoneError> {
        let cert_usage = self.next_u8(line, "TLSA cert_usage")?;
        let selector = self.next_u8(line, "TLSA selector")?;
        let matching_type = self.next_u8(line, "TLSA matching_type")?;
        let cert_association_data = self.collect_hex_tokens(line, "TLSA")?;
        Ok(RData::Tlsa {
            cert_usage,
            selector,
            matching_type,
            cert_association_data,
        })
    }

    fn parse_rdata_sshfp(&mut self, line: usize) -> Result<RData, ZoneError> {
        let algorithm = self.next_u8(line, "SSHFP algorithm")?;
        let fp_type = self.next_u8(line, "SSHFP fp_type")?;
        let fingerprint = self.collect_hex_tokens(line, "SSHFP")?;
        Ok(RData::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        })
    }

    fn parse_rdata_svcb_https(&mut self, line: usize, is_https: bool) -> Result<RData, ZoneError> {
        let origin = self.origin.clone();
        let rtype_name = if is_https { "HTTPS" } else { "SVCB" };
        let priority = self.next_u16(line, rtype_name)?;
        let target_str = self.next_word(line, rtype_name)?;
        let target_str = target_str.to_string();
        let target = parse_absolute_name(&target_str, origin, line)?;
        // Collect all remaining tokens on the line as raw param bytes.
        let mut params_str = String::new();
        loop {
            match self.tok.peek_token()? {
                Token::Newline | Token::Eof => break,
                Token::Word(w) => {
                    if !params_str.is_empty() {
                        params_str.push(' ');
                    }
                    params_str.push_str(w);
                    self.tok.next_token()?;
                }
                Token::QuotedString(s) => {
                    if !params_str.is_empty() {
                        params_str.push(' ');
                    }
                    params_str.push_str(&s);
                    self.tok.next_token()?;
                }
            }
        }
        let params = params_str.into_bytes();
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

    /// Parses `\# <length> <hex>` or falls through to an error.
    fn parse_rdata_unknown(&mut self, rtype: Rtype, line: usize) -> Result<RData, ZoneError> {
        match self.tok.peek_token()? {
            Token::Word(r"\#") => {
                self.tok.next_token()?; // consume '\#'
                let len_str = self.next_word(line, "Unknown length")?;
                let len: usize = len_str.parse().map_err(|_| ZoneError::ParseRdata {
                    line,
                    rtype: rtype.to_string(),
                    reason: format!("invalid unknown-type length '{len_str}'"),
                })?;
                let data = self.collect_hex_tokens(line, "Unknown")?;
                if data.len() != len {
                    return Err(ZoneError::ParseRdata {
                        line,
                        rtype: rtype.to_string(),
                        reason: format!(
                            "unknown-type declared length {len} but got {} hex bytes",
                            data.len()
                        ),
                    });
                }
                Ok(RData::Unknown {
                    rtype: rtype.as_u16(),
                    data,
                })
            }
            _ => Err(ZoneError::UnknownType {
                line,
                rtype: rtype.to_string(),
            }),
        }
    }

    // ── Type bitmap parser ────────────────────────────────────────────────────

    /// Parses a sequence of RR type names into an RFC 4034 §4.1.2 type bitmap.
    fn parse_type_bitmap(&mut self, line: usize) -> Result<Vec<u8>, ZoneError> {
        let mut types: Vec<u16> = Vec::new();
        // Consume Word tokens; any non-Word token (Newline, Eof, QuotedString) ends the bitmap.
        while let Token::Word(w) = self.tok.peek_token()? {
            let rtype_upper = w.to_ascii_uppercase();
            let rtype = parse_rtype_str(&rtype_upper, line)?;
            types.push(rtype.as_u16());
            self.tok.next_token()?;
        }
        Ok(encode_type_bitmap(&types))
    }

    // ── Token-consuming helpers ───────────────────────────────────────────────

    /// Returns the next token as a `&str`, ensuring it is a [`Token::Word`].
    fn next_word<'a>(&'a mut self, line: usize, ctx: &'static str) -> Result<&'a str, ZoneError> {
        // We borrow the tokenizer for a single next_token call.  Since the
        // Tokenizer stores a `&'src str`, words are slices of that source.
        // We can't return them with 'src lifetime directly here because of
        // borrow rules, so we return with 'a (shorter lifetime).
        expect_word(&mut self.tok, line, ctx)
    }

    fn next_u8(&mut self, line: usize, ctx: &'static str) -> Result<u8, ZoneError> {
        let w = expect_word(&mut self.tok, line, ctx)?;
        w.parse::<u8>().map_err(|_| ZoneError::ParseRdata {
            line,
            rtype: ctx.into(),
            reason: format!("expected u8, got '{w}'"),
        })
    }

    fn next_u16(&mut self, line: usize, ctx: &'static str) -> Result<u16, ZoneError> {
        let w = expect_word(&mut self.tok, line, ctx)?;
        w.parse::<u16>().map_err(|_| ZoneError::ParseRdata {
            line,
            rtype: ctx.into(),
            reason: format!("expected u16, got '{w}'"),
        })
    }

    fn next_u32(&mut self, line: usize, ctx: &'static str) -> Result<u32, ZoneError> {
        let w = expect_word(&mut self.tok, line, ctx)?;
        w.parse::<u32>().map_err(|_| ZoneError::ParseRdata {
            line,
            rtype: ctx.into(),
            reason: format!("expected u32, got '{w}'"),
        })
    }

    /// Parses a RRSIG timestamp.  Either `YYYYMMDDHHmmss` (14 digits) or a
    /// plain decimal u32.
    fn next_timestamp(&mut self, line: usize, ctx: &'static str) -> Result<u32, ZoneError> {
        let w = expect_word(&mut self.tok, line, ctx)?;
        if w.len() == 14 && w.chars().all(|c| c.is_ascii_digit()) {
            parse_rrsig_timestamp(w, line)
        } else {
            w.parse::<u32>().map_err(|_| ZoneError::ParseRdata {
                line,
                rtype: ctx.into(),
                reason: format!("expected timestamp (YYYYMMDDHHmmss or u32), got '{w}'"),
            })
        }
    }

    /// Collects all remaining word tokens on the current logical line,
    /// concatenates them, and decodes as base64.
    fn collect_base64_tokens(
        &mut self,
        line: usize,
        ctx: &'static str,
    ) -> Result<Vec<u8>, ZoneError> {
        let mut combined = String::new();
        loop {
            match self.tok.peek_token()? {
                Token::Newline | Token::Eof => break,
                Token::Word(w) => {
                    combined.push_str(w);
                    self.tok.next_token()?;
                }
                Token::QuotedString(s) => {
                    combined.push_str(&s);
                    self.tok.next_token()?;
                }
            }
        }
        decode_base64(&combined, line, ctx)
    }

    /// Collects all remaining word tokens on the current logical line,
    /// concatenates them, and decodes as hex.
    fn collect_hex_tokens(&mut self, line: usize, ctx: &'static str) -> Result<Vec<u8>, ZoneError> {
        let mut combined = String::new();
        // Consume Word tokens; any non-Word token ends the hex stream.
        while let Token::Word(w) = self.tok.peek_token()? {
            combined.push_str(w);
            self.tok.next_token()?;
        }
        decode_hex(&combined, line, ctx)
    }
}

// ── Public helper for $GENERATE RDATA parsing ─────────────────────────────────

/// Parses RDATA from a plain string (used by `$GENERATE`).
///
/// `rdata_str` is the fully-expanded RDATA text.
pub(crate) fn parse_rdata_from_str(
    rtype: Rtype,
    rdata_str: &str,
    origin: Option<Name>,
    line: usize,
) -> Result<RData, ZoneError> {
    // Build a temporary tokenizer over the rdata string and parse it.
    let mut tok = Tokenizer::new(rdata_str);
    match rtype {
        Rtype::A => {
            let w = expect_word(&mut tok, line, "A")?;
            Ipv4Addr::from_str(w)
                .map(RData::A)
                .map_err(|e| ZoneError::ParseRdata {
                    line,
                    rtype: "A".into(),
                    reason: e.to_string(),
                })
        }
        Rtype::Aaaa => {
            let w = expect_word(&mut tok, line, "AAAA")?;
            Ipv6Addr::from_str(w)
                .map(RData::Aaaa)
                .map_err(|e| ZoneError::ParseRdata {
                    line,
                    rtype: "AAAA".into(),
                    reason: e.to_string(),
                })
        }
        Rtype::Ptr | Rtype::Cname | Rtype::Ns => {
            let w = expect_word(&mut tok, line, "NAME")?;
            let name = parse_absolute_name(w, origin, line)?;
            // The outer arm pattern guarantees rtype is Ptr, Cname, or Ns.
            #[allow(clippy::wildcard_in_or_patterns)]
            Ok(match rtype {
                Rtype::Ptr => RData::Ptr(name),
                Rtype::Cname => RData::Cname(name),
                _ => RData::Ns(name),
            })
        }
        _ => Err(ZoneError::UnknownType {
            line,
            rtype: rtype.to_string(),
        }),
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Consumes all tokens up to and including the next [`Token::Newline`] or EOF.
fn consume_to_newline_or_eof(tok: &mut Tokenizer<'_>) -> Result<(), ZoneError> {
    loop {
        match tok.peek_token()? {
            Token::Newline => {
                tok.next_token()?;
                return Ok(());
            }
            Token::Eof => return Ok(()),
            _ => {
                tok.next_token()?;
            }
        }
    }
}

/// Tries to parse a string as a TTL (decimal u32).  Returns `None` if not
/// a valid integer (so the caller can treat it as a class or type instead).
fn try_parse_ttl(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

/// Tries to parse a string as a DNS class keyword.
fn try_parse_class(s: &str) -> Option<Qclass> {
    match s.to_ascii_uppercase().as_str() {
        "IN" => Some(Qclass::In),
        "CH" => Some(Qclass::Ch),
        "HS" => Some(Qclass::Hs),
        "CS" => Some(Qclass::Cs),
        "ANY" => Some(Qclass::Any),
        _ => None,
    }
}

/// Parses a record type name string into an [`Rtype`].
///
/// Accepts `TYPEnnn` for numeric types (RFC 3597).
pub(crate) fn parse_rtype_str(s: &str, line: usize) -> Result<Rtype, ZoneError> {
    match s {
        "A" => Ok(Rtype::A),
        "NS" => Ok(Rtype::Ns),
        "CNAME" => Ok(Rtype::Cname),
        "SOA" => Ok(Rtype::Soa),
        "PTR" => Ok(Rtype::Ptr),
        "HINFO" => Ok(Rtype::Hinfo),
        "MX" => Ok(Rtype::Mx),
        "TXT" => Ok(Rtype::Txt),
        "RP" => Ok(Rtype::Rp),
        "AFSDB" => Ok(Rtype::Afsdb),
        "SIG" => Ok(Rtype::Sig),
        "KEY" => Ok(Rtype::Key),
        "AAAA" => Ok(Rtype::Aaaa),
        "LOC" => Ok(Rtype::Loc),
        "SRV" => Ok(Rtype::Srv),
        "NAPTR" => Ok(Rtype::Naptr),
        "CERT" => Ok(Rtype::Cert),
        "DNAME" => Ok(Rtype::Dname),
        "OPT" => Ok(Rtype::Opt),
        "APL" => Ok(Rtype::Apl),
        "DS" => Ok(Rtype::Ds),
        "SSHFP" => Ok(Rtype::Sshfp),
        "IPSECKEY" => Ok(Rtype::Ipseckey),
        "RRSIG" => Ok(Rtype::Rrsig),
        "NSEC" => Ok(Rtype::Nsec),
        "DNSKEY" => Ok(Rtype::Dnskey),
        "DHCID" => Ok(Rtype::Dhcid),
        "NSEC3" => Ok(Rtype::Nsec3),
        "NSEC3PARAM" => Ok(Rtype::Nsec3param),
        "TLSA" => Ok(Rtype::Tlsa),
        "SMIMEA" => Ok(Rtype::Smimea),
        "HIP" => Ok(Rtype::Hip),
        "CDS" => Ok(Rtype::Cds),
        "CDNSKEY" => Ok(Rtype::Cdnskey),
        "OPENPGPKEY" => Ok(Rtype::Openpgpkey),
        "CSYNC" => Ok(Rtype::Csync),
        "ZONEMD" => Ok(Rtype::Zonemd),
        "SVCB" => Ok(Rtype::Svcb),
        "HTTPS" => Ok(Rtype::Https),
        "URI" => Ok(Rtype::Uri),
        "CAA" => Ok(Rtype::Caa),
        "TSIG" => Ok(Rtype::Tsig),
        other => {
            if let Some(stripped) = other.strip_prefix("TYPE") {
                stripped
                    .parse::<u16>()
                    .map(Rtype::Unknown)
                    .map_err(|_| ZoneError::UnknownType {
                        line,
                        rtype: other.to_string(),
                    })
            } else {
                Err(ZoneError::UnknownType {
                    line,
                    rtype: other.to_string(),
                })
            }
        }
    }
}

// ── Codec helpers ─────────────────────────────────────────────────────────────

/// Decodes a base64 string (standard alphabet, with optional whitespace).
///
/// No external dependency — implemented inline.
pub(crate) fn decode_base64(s: &str, line: usize, ctx: &str) -> Result<Vec<u8>, ZoneError> {
    const TABLE: [u8; 128] = {
        let mut t = [0xFF_u8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = 52 + d;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes: Vec<u8> = s.bytes().filter(|&b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() {
        return Ok(vec![]);
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        // Collect a 4-byte group (padding with '=').
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1]
        } else {
            b'='
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2]
        } else {
            b'='
        };
        let b3 = if i + 3 < bytes.len() {
            bytes[i + 3]
        } else {
            b'='
        };

        if b0 == b'=' {
            break; // done
        }

        let v0 = decode_b64_char(b0, &TABLE, line, ctx)?;
        let v1 = decode_b64_char(b1, &TABLE, line, ctx)?;
        out.push((v0 << 2) | (v1 >> 4));

        if b2 != b'=' {
            let v2 = decode_b64_char(b2, &TABLE, line, ctx)?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));

            if b3 != b'=' {
                let v3 = decode_b64_char(b3, &TABLE, line, ctx)?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
        i += 4;
    }
    Ok(out)
}

fn decode_b64_char(b: u8, table: &[u8; 128], line: usize, ctx: &str) -> Result<u8, ZoneError> {
    if b as usize >= 128 || table[b as usize] == 0xFF {
        Err(ZoneError::ParseRdata {
            line,
            rtype: ctx.to_string(),
            reason: format!("invalid base64 character '{}'", b as char),
        })
    } else {
        Ok(table[b as usize])
    }
}

/// Decodes a hex string (case-insensitive, no separators).
pub(crate) fn decode_hex(s: &str, line: usize, ctx: &str) -> Result<Vec<u8>, ZoneError> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    if !s.len().is_multiple_of(2) {
        return Err(ZoneError::ParseRdata {
            line,
            rtype: ctx.to_string(),
            reason: format!("hex string has odd length ({} chars)", s.len()),
        });
    }
    let bytes_result: Result<Vec<u8>, _> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
        .collect();
    bytes_result.map_err(|_| ZoneError::ParseRdata {
        line,
        rtype: ctx.to_string(),
        reason: format!("invalid hex character in '{s}'"),
    })
}

/// Decodes a base32hex string (RFC 4648 §7, uppercase or lowercase).
///
/// Used for NSEC3 next-hashed-owner names.
pub(crate) fn decode_base32hex(s: &str, line: usize, ctx: &str) -> Result<Vec<u8>, ZoneError> {
    const ALPHA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let upper = s.to_ascii_uppercase();
    let bytes = upper.as_bytes();

    // Strip padding.
    let trimmed: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'=').collect();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits = 0u32;

    for &b in &trimmed {
        let v = ALPHA
            .iter()
            .position(|&a| a == b)
            .ok_or_else(|| ZoneError::ParseRdata {
                line,
                rtype: ctx.to_string(),
                reason: format!("invalid base32hex character '{}'", b as char),
            })? as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            // INVARIANT: shift ≤ 56, buf is u64; truncation to u8 is safe.
            #[allow(clippy::cast_possible_truncation)]
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// Encodes a list of RR type numbers into an RFC 4034 §4.1.2 type bitmap.
pub(crate) fn encode_type_bitmap(types: &[u16]) -> Vec<u8> {
    if types.is_empty() {
        return vec![];
    }

    // Group types by window (high byte of the type number).
    let mut windows: std::collections::BTreeMap<u8, Vec<u8>> = std::collections::BTreeMap::new();
    for &t in types {
        // Window number is the high byte.
        #[allow(clippy::cast_possible_truncation)]
        let window = (t >> 8) as u8;
        // Bit position is the low byte.
        #[allow(clippy::cast_possible_truncation)]
        let bit = (t & 0xFF) as u8;
        let entry = windows.entry(window).or_default();
        // Ensure the bitmap vector is large enough.
        let byte_idx = usize::from(bit) / 8;
        while entry.len() <= byte_idx {
            entry.push(0u8);
        }
        entry[byte_idx] |= 0x80 >> (bit % 8);
    }

    let mut out = Vec::new();
    for (window, bitmap) in &windows {
        out.push(*window);
        // INVARIANT: bitmap.len() ≤ 32 bytes (256 bits / 8); truncation is safe.
        #[allow(clippy::cast_possible_truncation)]
        out.push(bitmap.len() as u8);
        out.extend_from_slice(bitmap);
    }
    out
}

/// Parses a 14-digit RRSIG timestamp (`YYYYMMDDHHmmss`) into a Unix timestamp
/// (seconds since 1970-01-01 00:00:00 UTC).
///
/// Only handles dates in the range [1970, 2106].  Uses a simplified Gregorian
/// calculation without leap-second correction (standard for DNSSEC).
fn parse_rrsig_timestamp(s: &str, line: usize) -> Result<u32, ZoneError> {
    // Month-to-cumulative-day lookup (non-leap year).  Must appear before statements.
    const MONTH_DAYS: [i64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let err = || ZoneError::ParseRdata {
        line,
        rtype: "RRSIG".into(),
        reason: format!("invalid timestamp '{s}'"),
    };
    if s.len() != 14 {
        return Err(err());
    }
    let year: u32 = s[0..4].parse().map_err(|_| err())?;
    let month: u32 = s[4..6].parse().map_err(|_| err())?;
    let day: u32 = s[6..8].parse().map_err(|_| err())?;
    let hour: u32 = s[8..10].parse().map_err(|_| err())?;
    let min: u32 = s[10..12].parse().map_err(|_| err())?;
    let sec: u32 = s[12..14].parse().map_err(|_| err())?;

    if month == 0 || month > 12 || day == 0 || day > 31 {
        return Err(err());
    }

    // Days from epoch to start of year.
    let y = i64::from(year);
    let days_from_epoch = (y - 1970) * 365
        + (y - 1969) / 4   // leap years
        - (y - 1901) / 100 // century exclusions
        + (y - 1601) / 400; // 400-year inclusions

    // Days from start of year to start of month.
    let mut yday: i64 = 0;
    for m in 1..month {
        yday += MONTH_DAYS[m as usize];
        // Leap-day in February.
        if m == 2 {
            let leap =
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
            if leap {
                yday += 1;
            }
        }
    }
    let total_days = days_from_epoch + yday + (i64::from(day) - 1);
    let total_secs =
        total_days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);

    if total_secs < 0 || total_secs > i64::from(u32::MAX) {
        return Err(err());
    }
    // INVARIANT: 0 ≤ total_secs ≤ u32::MAX; truncation is safe.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(total_secs as u32)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::zone::{ZoneFile, ZoneLimits};

    fn parse_zone(src: &str) -> Vec<Record> {
        ZoneFile::parse(src, None, ZoneLimits::default())
            .unwrap()
            .records
    }

    // ── SOA ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_soa() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 300\n\
";
        let records = parse_zone(src);
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.rtype, Rtype::Soa);
        assert_eq!(rec.name, Name::from_str("example.com.").unwrap());
        if let RData::Soa { serial, .. } = &rec.rdata {
            assert_eq!(*serial, 2_024_010_101);
        } else {
            panic!("expected SOA");
        }
    }

    // ── A ────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_a_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
ns1 IN A 192.0.2.1\n\
";
        let records = parse_zone(src);
        assert_eq!(records.len(), 1);
        assert!(matches!(&records[0].rdata, RData::A(addr) if addr.octets() == [192, 0, 2, 1]));
    }

    // ── AAAA ─────────────────────────────────────────────────────────────────

    #[test]
    fn parse_aaaa_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
host IN AAAA 2001:db8::1\n\
";
        let records = parse_zone(src);
        assert_eq!(records.len(), 1);
        assert!(matches!(&records[0].rdata, RData::Aaaa(_)));
    }

    // ── MX ───────────────────────────────────────────────────────────────────

    #[test]
    fn parse_mx_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN MX 10 mail.example.com.\n\
";
        let records = parse_zone(src);
        if let RData::Mx { preference, .. } = &records[0].rdata {
            assert_eq!(*preference, 10);
        } else {
            panic!("expected MX");
        }
    }

    // ── TXT ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_txt_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN TXT \"v=spf1 include:example.com ~all\"\n\
";
        let records = parse_zone(src);
        if let RData::Txt(strings) = &records[0].rdata {
            assert_eq!(strings.len(), 1);
            assert!(strings[0].starts_with(b"v=spf1"));
        } else {
            panic!("expected TXT");
        }
    }

    // ── SRV ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_srv_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
_http._tcp IN SRV 10 20 80 www.example.com.\n\
";
        let records = parse_zone(src);
        if let RData::Srv {
            priority,
            weight,
            port,
            ..
        } = &records[0].rdata
        {
            assert_eq!((*priority, *weight, *port), (10, 20, 80));
        } else {
            panic!("expected SRV");
        }
    }

    // ── CAA ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_caa_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN CAA 0 issue \"letsencrypt.org\"\n\
";
        let records = parse_zone(src);
        if let RData::Caa { flags, tag, value } = &records[0].rdata {
            assert_eq!(*flags, 0);
            assert_eq!(tag, b"issue");
            assert_eq!(value, b"letsencrypt.org");
        } else {
            panic!("expected CAA");
        }
    }

    // ── NS ───────────────────────────────────────────────────────────────────

    #[test]
    fn parse_ns_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN NS ns1.example.com.\n\
";
        let records = parse_zone(src);
        assert!(matches!(&records[0].rdata, RData::Ns(_)));
    }

    // ── CNAME ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_cname_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
www IN CNAME host.example.com.\n\
";
        let records = parse_zone(src);
        assert!(matches!(&records[0].rdata, RData::Cname(_)));
    }

    // ── PTR ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_ptr_record() {
        let src = "\
$ORIGIN 2.0.192.in-addr.arpa.\n\
$TTL 300\n\
1 IN PTR ns1.example.com.\n\
";
        let records = parse_zone(src);
        assert!(matches!(&records[0].rdata, RData::Ptr(_)));
    }

    // ── DNSSEC types ─────────────────────────────────────────────────────────

    #[test]
    fn parse_dnskey_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d\n\
";
        let records = parse_zone(src);
        if let RData::Dnskey {
            flags,
            protocol,
            algorithm,
            ..
        } = &records[0].rdata
        {
            assert_eq!((*flags, *protocol, *algorithm), (257, 3, 13));
        } else {
            panic!("expected DNSKEY");
        }
    }

    #[test]
    fn parse_ds_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN DS 12345 13 2 AABBCCDD\n\
";
        let records = parse_zone(src);
        if let RData::Ds {
            key_tag,
            algorithm,
            digest_type,
            ..
        } = &records[0].rdata
        {
            assert_eq!((*key_tag, *algorithm, *digest_type), (12345, 13, 2));
        } else {
            panic!("expected DS");
        }
    }

    #[test]
    fn parse_tlsa_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
_443._tcp IN TLSA 3 1 1 AABBCCDD\n\
";
        let records = parse_zone(src);
        if let RData::Tlsa {
            cert_usage,
            selector,
            matching_type,
            ..
        } = &records[0].rdata
        {
            assert_eq!((*cert_usage, *selector, *matching_type), (3, 1, 1));
        } else {
            panic!("expected TLSA");
        }
    }

    #[test]
    fn parse_sshfp_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
host IN SSHFP 4 2 AABBCC\n\
";
        let records = parse_zone(src);
        assert!(matches!(&records[0].rdata, RData::Sshfp { .. }));
    }

    #[test]
    fn parse_nsec_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN NSEC next.example.com. A NS SOA RRSIG DNSKEY NSEC\n\
";
        let records = parse_zone(src);
        assert!(matches!(&records[0].rdata, RData::Nsec { .. }));
    }

    #[test]
    fn parse_nsec3param_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN NSEC3PARAM 1 0 10 -\n\
";
        let records = parse_zone(src);
        if let RData::Nsec3param {
            hash_algorithm,
            iterations,
            salt,
            ..
        } = &records[0].rdata
        {
            assert_eq!(*hash_algorithm, 1);
            assert_eq!(*iterations, 10);
            assert!(salt.is_empty());
        } else {
            panic!("expected NSEC3PARAM");
        }
    }

    #[test]
    fn parse_csync_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN CSYNC 2024010101 3 A NS AAAA\n\
";
        let records = parse_zone(src);
        if let RData::Csync {
            soa_serial, flags, ..
        } = &records[0].rdata
        {
            assert_eq!(*soa_serial, 2_024_010_101);
            assert_eq!(*flags, 3);
        } else {
            panic!("expected CSYNC");
        }
    }

    // ── Multiline (parentheses) ───────────────────────────────────────────────

    #[test]
    fn parse_multiline_soa() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster (\n\
    2024010101 ; serial\n\
    3600       ; refresh\n\
    900        ; retry\n\
    604800     ; expire\n\
    300        ; minimum\n\
)\n\
";
        let records = parse_zone(src);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rtype, Rtype::Soa);
    }

    // ── Last-owner carry-over ─────────────────────────────────────────────────

    #[test]
    fn blank_owner_uses_last() {
        // The second line intentionally starts with spaces: RFC 1035 §5.1 says
        // that a line beginning with whitespace reuses the previous owner.
        // We cannot use a `\` continuation here because Rust would strip the
        // leading spaces — build the string with explicit `\n` instead.
        let src = "$ORIGIN example.com.\n$TTL 300\nns1 IN A 192.0.2.1\n    IN A 192.0.2.2\n";
        let records = parse_zone(src);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, records[1].name);
    }

    // ── TTL carry-over ───────────────────────────────────────────────────────

    #[test]
    fn explicit_ttl_carries_over() {
        // Same blank-owner consideration: preserve leading spaces explicitly.
        let src = "$ORIGIN example.com.\n$TTL 300\nns1 600 IN A 192.0.2.1\n    IN A 192.0.2.2\n";
        let records = parse_zone(src);
        // Both should have TTL 600 (explicit TTL carries).
        assert_eq!(records[0].ttl, 600);
        assert_eq!(records[1].ttl, 600);
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    #[test]
    fn comments_ignored() {
        let src = "\
; This is a comment\n\
$ORIGIN example.com. ; inline comment\n\
$TTL 300\n\
@ IN A 192.0.2.1 ; another comment\n\
";
        let records = parse_zone(src);
        assert_eq!(records.len(), 1);
    }

    // ── @ as origin ──────────────────────────────────────────────────────────

    #[test]
    fn at_sign_resolves_to_origin() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN A 192.0.2.1\n\
";
        let records = parse_zone(src);
        assert_eq!(records[0].name, Name::from_str("example.com.").unwrap());
    }

    // ── Relative names ───────────────────────────────────────────────────────

    #[test]
    fn relative_name_appended_to_origin() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
sub IN A 192.0.2.1\n\
";
        let records = parse_zone(src);
        assert_eq!(records[0].name.to_string(), "sub.example.com.");
    }

    // ── Byte encoding ─────────────────────────────────────────────────────────

    #[test]
    fn base64_decode() {
        let decoded = decode_base64("SGVsbG8=", 1, "test").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn hex_decode() {
        let decoded = decode_hex("DEADBEEF", 1, "test").unwrap();
        assert_eq!(decoded, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn base32hex_decode() {
        // "A" in base32hex = 0b00000; "A" → 0x00
        let decoded = decode_base32hex("0", 1, "test").unwrap();
        // '0' in base32hex = 0 (first value)
        assert_eq!(decoded, []);
        // Two chars "00" = 0b00000_00000 → 0x00
        let decoded2 = decode_base32hex("00", 1, "test").unwrap();
        assert_eq!(decoded2, [0x00]);
    }

    // ── Type bitmap ───────────────────────────────────────────────────────────

    #[test]
    fn type_bitmap_a_ns() {
        // A=1, NS=2; window 0, bitmap byte 0 = 0b0110_0000 = 0x60
        let bitmap = encode_type_bitmap(&[1, 2]);
        assert_eq!(bitmap, [0x00, 0x01, 0x60]);
    }

    // ── Size limits ───────────────────────────────────────────────────────────

    #[test]
    fn zone_size_limit_enforced() {
        let limits = ZoneLimits {
            max_zone_size_bytes: 10,
            ..Default::default()
        };
        let src = "this is more than ten bytes of zone source";
        let result = ZoneFile::parse(src, None, limits);
        assert!(matches!(
            result,
            Err(crate::zone::ZoneError::ZoneSizeLimit(
                crate::zone::LimitKind::ZoneSizeBytes
            ))
        ));
    }

    #[test]
    fn record_count_limit_enforced() {
        let limits = ZoneLimits {
            max_records: 2,
            ..Default::default()
        };
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
a IN A 192.0.2.1\n\
b IN A 192.0.2.2\n\
c IN A 192.0.2.3\n\
";
        let result = ZoneFile::parse(src, None, limits);
        assert!(matches!(
            result,
            Err(crate::zone::ZoneError::ZoneSizeLimit(
                crate::zone::LimitKind::RecordCount
            ))
        ));
    }

    // ── Wire serialisation roundtrip ──────────────────────────────────────────

    #[test]
    fn parse_and_serialise_a_roundtrip() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
ns1 IN A 192.0.2.1\n\
";
        let zone = ZoneFile::parse(src, None, ZoneLimits::default()).unwrap();
        assert_eq!(zone.records.len(), 1);

        // Serialise to wire.
        let rec = &zone.records[0];
        let mut wire = Vec::new();
        rec.write_to(&mut wire);

        // Parse back from wire.
        let mut offset = 0;
        let parsed = Record::parse(&wire, &mut offset).unwrap();
        assert_eq!(offset, wire.len());
        assert_eq!(parsed, *rec);
    }

    // ── HTTPS / SVCB ──────────────────────────────────────────────────────────

    #[test]
    fn parse_https_record() {
        let src = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN HTTPS 1 . alpn=h2\n\
";
        let records = parse_zone(src);
        assert!(matches!(
            &records[0].rdata,
            RData::Https { priority: 1, .. }
        ));
    }

    // ── RRSIG timestamp parsing ───────────────────────────────────────────────

    #[test]
    fn rrsig_timestamp_epoch() {
        // 1970-01-01 00:00:00 → 0
        let ts = parse_rrsig_timestamp("19700101000000", 1).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn rrsig_timestamp_known_date() {
        // 2024-01-01 00:00:00
        // Days from epoch: 54 years × 365 + 14 leap years = 19723
        // 2024 is a leap year.  Days to 2024-01-01 = 19723.
        let ts = parse_rrsig_timestamp("20240101000000", 1).unwrap();
        // Verify it's reasonable (roughly 54 years of seconds).
        assert!(ts > 1_700_000_000, "expected > 2023-11-14 timestamp");
    }
}
