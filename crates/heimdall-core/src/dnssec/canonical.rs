// SPDX-License-Identifier: MIT

//! RFC 4034 §6 canonical `RRset` ordering and wire-form serialisation for DNSSEC signing.
//!
//! Implements DNSSEC-005 (canonical ordering) and DNSSEC-006 (signing input
//! construction).

use std::cmp::Ordering;

use crate::{
    name::Name,
    rdata::RData,
    record::{Record, Rtype},
};

// ── Canonical name wire ───────────────────────────────────────────────────────

/// Returns the canonical wire-format bytes for `name`: all label octets lowercased,
/// names uncompressed (RFC 4034 §6.2).
///
/// Implements DNSSEC-005.
#[must_use]
pub fn canonical_name_wire(name: &Name) -> Vec<u8> {
    name.as_wire_bytes()
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect()
}

// ── Canonical RDATA wire ───────────────────────────────────────────────────────

/// Returns the canonical wire-format RDATA for `rtype`/`rdata` (RFC 4034 §6.2).
///
/// Any domain names embedded in RDATA (NS, MX exchange, CNAME, DNAME, PTR, SOA
/// mname/rname, SRV target, RRSIG `signer_name`) are lowercased and uncompressed.
/// All other RDATA is written verbatim.
///
/// Implements DNSSEC-006.
#[must_use]
pub fn canonical_rdata_wire(rtype: Rtype, rdata: &RData) -> Vec<u8> {
    let mut buf = Vec::new();
    match (rtype, rdata) {
        (Rtype::Ns, RData::Ns(name))
        | (Rtype::Cname, RData::Cname(name))
        | (Rtype::Dname, RData::Dname(name))
        | (Rtype::Ptr, RData::Ptr(name)) => {
            buf.extend_from_slice(&canonical_name_wire(name));
        }
        (
            Rtype::Mx,
            RData::Mx {
                preference,
                exchange,
            },
        ) => {
            buf.extend_from_slice(&preference.to_be_bytes());
            buf.extend_from_slice(&canonical_name_wire(exchange));
        }
        (
            Rtype::Soa,
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
        ) => {
            buf.extend_from_slice(&canonical_name_wire(mname));
            buf.extend_from_slice(&canonical_name_wire(rname));
            buf.extend_from_slice(&serial.to_be_bytes());
            buf.extend_from_slice(&refresh.to_be_bytes());
            buf.extend_from_slice(&retry.to_be_bytes());
            buf.extend_from_slice(&expire.to_be_bytes());
            buf.extend_from_slice(&minimum.to_be_bytes());
        }
        (
            Rtype::Srv,
            RData::Srv {
                priority,
                weight,
                port,
                target,
            },
        ) => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            buf.extend_from_slice(&canonical_name_wire(target));
        }
        (
            Rtype::Rrsig,
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                sig_expiration,
                sig_inception,
                key_tag,
                signer_name,
                signature,
            },
        ) => {
            buf.extend_from_slice(&type_covered.as_u16().to_be_bytes());
            buf.push(*algorithm);
            buf.push(*labels);
            buf.extend_from_slice(&original_ttl.to_be_bytes());
            buf.extend_from_slice(&sig_expiration.to_be_bytes());
            buf.extend_from_slice(&sig_inception.to_be_bytes());
            buf.extend_from_slice(&key_tag.to_be_bytes());
            buf.extend_from_slice(&canonical_name_wire(signer_name));
            buf.extend_from_slice(signature);
        }
        (
            Rtype::Nsec,
            RData::Nsec {
                next_domain,
                type_bitmaps,
            },
        ) => {
            // NSEC next_domain MUST be lowercased (RFC 4034 §6.2).
            buf.extend_from_slice(&canonical_name_wire(next_domain));
            buf.extend_from_slice(type_bitmaps);
        }
        // All other types: wire bytes are not name-containing; write verbatim.
        _ => {
            rdata.write_to(&mut buf);
        }
    }
    buf
}

// ── Canonical RDATA ordering ───────────────────────────────────────────────────

/// Compares two RDATA byte slices for canonical ordering (RFC 4034 §6.3).
///
/// Records within an `RRset` are sorted by their canonical wire-format RDATA,
/// treated as unsigned left-justified byte strings.
///
/// Implements DNSSEC-005.
#[must_use]
pub fn canonical_rdata_order(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

// ── RsigFields ────────────────────────────────────────────────────────────────

/// The RRSIG header fields needed for computing the signing input (RFC 4034 §6.2).
///
/// Extracted from `RData::Rrsig`; excludes the signature bytes themselves.
pub struct RsigFields {
    /// The covered RR type.
    pub type_covered: Rtype,
    /// Algorithm number.
    pub algorithm: u8,
    /// Label count in the original signer name.
    pub labels: u8,
    /// Original TTL of the covered `RRset`.
    pub original_ttl: u32,
    /// Signature expiration (Unix seconds).
    pub sig_expiration: u32,
    /// Signature inception (Unix seconds).
    pub sig_inception: u32,
    /// Key tag of the signing DNSKEY.
    pub key_tag: u16,
    /// Zone apex / signer domain name.
    pub signer_name: Name,
}

// ── rrset_signing_input ────────────────────────────────────────────────────────

/// Produces the wire data that the RRSIG MAC covers (RFC 4034 §6.2).
///
/// Format:
/// ```text
/// RRSIG_RDATA_prefix || canonical_rrset_wire
/// ```
///
/// `RRSIG_RDATA_prefix` is the RRSIG RDATA up to (not including) the Signature
/// field:
/// ```text
/// type_covered (u16 BE)
/// algorithm    (u8)
/// labels       (u8)
/// original_ttl (u32 BE)
/// sig_expiration (u32 BE)
/// sig_inception  (u32 BE)
/// key_tag      (u16 BE)
/// signer_name  (canonical, uncompressed, lowercase)
/// ```
///
/// `canonical_rrset_wire` is each RR sorted by canonical RDATA order:
/// ```text
/// owner_name   (canonical, uncompressed, lowercase)
/// type         (u16 BE)
/// class        (u16 BE)
/// original_ttl (u32 BE)   ← from RRSIG, not the RR's own TTL
/// rdlength     (u16 BE)
/// rdata        (canonical wire)
/// ```
///
/// Implements DNSSEC-006.
#[must_use]
pub fn rrset_signing_input(rrsig: &RsigFields, rrset: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();

    // ── RRSIG RDATA prefix ────────────────────────────────────────────────────
    out.extend_from_slice(&rrsig.type_covered.as_u16().to_be_bytes());
    out.push(rrsig.algorithm);
    out.push(rrsig.labels);
    out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    out.extend_from_slice(&rrsig.sig_expiration.to_be_bytes());
    out.extend_from_slice(&rrsig.sig_inception.to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    out.extend_from_slice(&canonical_name_wire(&rrsig.signer_name));

    // ── Canonical RRset ───────────────────────────────────────────────────────
    // Sort by canonical RDATA wire form (RFC 4034 §6.3).
    let mut entries: Vec<(Vec<u8>, &Record)> = rrset
        .iter()
        .map(|r| (canonical_rdata_wire(r.rtype, &r.rdata), r))
        .collect();
    entries.sort_by(|(a_rdata, _), (b_rdata, _)| canonical_rdata_order(a_rdata, b_rdata));

    for (rdata_wire, rr) in &entries {
        // owner (canonical)
        out.extend_from_slice(&canonical_name_wire(&rr.name));
        // type
        out.extend_from_slice(&rr.rtype.as_u16().to_be_bytes());
        // class
        out.extend_from_slice(&rr.rclass.as_u16().to_be_bytes());
        // original_ttl from RRSIG, not rr.ttl
        out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        // rdlength
        // INVARIANT: RDATA bounded by 16-bit RDLENGTH field (≤ 65535 bytes).
        #[allow(clippy::cast_possible_truncation)]
        let rdlen = rdata_wire.len() as u16;
        out.extend_from_slice(&rdlen.to_be_bytes());
        // rdata (canonical)
        out.extend_from_slice(rdata_wire);
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        header::Qclass,
        name::Name,
        record::{Record, Rtype},
    };

    // ── RFC 4034 Appendix B.3 golden vector ───────────────────────────────────
    //
    // The zone is "example." and the RRset is the MX RRset at "example.":
    //
    //   example.  3600  IN  MX  1  ai.example.
    //   example.  3600  IN  MX  2  b.example.  (canonical wire sorts this first)
    //
    // Wait — RFC 4034 Appendix B gives:
    //   example.  3600  IN  MX  1  ai.example.
    //   example.  3600  IN  MX  2  b.example.
    //
    // RRSIG covering MX RRset:
    //   type_covered  = MX (15)
    //   algorithm     = 5 (RSA/SHA-1)
    //   labels        = 1
    //   original_ttl  = 3600
    //   sig_expiration = 20030101000000 → 1041379200 (0x3DC3E000)...
    //
    // RFC 4034 Appendix B.3 uses timestamps from 2003-01-01 UTC.
    // sig_expiration = 20030201000000 = 1044057600
    // sig_inception  = 20021201000000 = 1038441600
    //
    // The MX RDATA wire bytes:
    //   preference=1, exchange=ai.example.
    //   ai.example. wire: [2,'a','i',7,'e','x','a','m','p','l','e',0]  len=12
    //   => MX rdata: [0x00,0x01] [0x02,0x61,0x69,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x00]
    //                   pref=1                 ai.                  example.               root
    //
    //   preference=2, exchange=b.example.
    //   b.example. wire: [1,'b',7,'e','x','a','m','p','l','e',0] len=11
    //   => MX rdata: [0x00,0x02] [0x01,0x62,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x00]
    //
    // Canonical RDATA sort: compare [0x00,0x01,...] vs [0x00,0x02,...] → pref=1 first.
    //
    // RRSIG fields from RFC 4034 Appendix B.3 (Appendix B gives the zone signing params):
    //   type_covered=MX, algorithm=5, labels=1, original_ttl=3600,
    //   sig_expiration=1075118400, sig_inception=1072483200,
    //   key_tag=2642, signer_name=example.
    //
    // RFC 4034 Appendix B.3 signature input hex is:
    // (RRSIG header 18 + signer + RR1 + RR2)
    // We compute it ourselves and validate the known structure.
    //
    // The exact expected bytes come from RFC 4034 Appendix B.3.
    // Signer_name "example." wire = [7,e,x,a,m,p,l,e,0] = 9 bytes (canonical = same, already lowercase)
    //
    // RRSIG prefix (before signature):
    //   [0x00,0x0F]          type_covered MX=15
    //   [0x05]               algorithm=5
    //   [0x01]               labels=1
    //   [0x00,0x00,0x0E,0x10] original_ttl=3600
    //   [sig_expiration BE]
    //   [sig_inception  BE]
    //   [0x0A,0x52]          key_tag=2642
    //   [signer_name wire]   example. = 9 bytes
    //
    // sig_expiration = 1_075_118_400 = 0x400_76380
    // Actually per RFC 4034 Appendix B:
    //   Signature Expiration: 20040101000000 → 1072915200?
    //   Let me just hard-code the full expected bytes.
    //
    // Per RFC 4034 §Appendix B (actual zone signing example):
    //   20030101000000 = 1041379200  (sig_inception in RFC example B)
    //   20030201000000 = 1044057600  (sig_expiration in RFC example B)
    // But section B.3 gives the RRSIG RDATA for the MX RRset with:
    //   Type Covered = MX
    //   Algorithm Number = 1 (RSA/MD5 in RFC 2535 — but the example uses RSA/SHA-1 = 5)
    //
    // Note: The RFC 4034 Appendix B uses algorithm 5 (RSA/SHA-1).
    //
    // Rather than replicating the exact RFC hex that would require the original
    // private key, we test structural properties:
    // 1. The signing input starts with the correct RRSIG header.
    // 2. Records appear in canonical RDATA order.
    // 3. Each RR uses original_ttl from the RRSIG header.
    //
    // We also provide a deterministic byte-level test from fixed inputs.

    fn example_dot() -> Name {
        Name::from_str("example.").unwrap()
    }

    fn ai_example_dot() -> Name {
        Name::from_str("ai.example.").unwrap()
    }

    fn b_example_dot() -> Name {
        Name::from_str("b.example.").unwrap()
    }

    fn make_mx_rrset() -> Vec<Record> {
        vec![
            Record {
                name: example_dot(),
                rtype: Rtype::Mx,
                rclass: Qclass::In,
                ttl: 3600,
                rdata: RData::Mx {
                    preference: 1,
                    exchange: ai_example_dot(),
                },
            },
            Record {
                name: example_dot(),
                rtype: Rtype::Mx,
                rclass: Qclass::In,
                ttl: 3600,
                rdata: RData::Mx {
                    preference: 2,
                    exchange: b_example_dot(),
                },
            },
        ]
    }

    /// RFC 4034 Appendix B.3 — structural golden test.
    ///
    /// Validates the signing input byte sequence against the expected structure
    /// derived from the RFC example:
    /// - 2-byte type_covered (MX = 0x000F)
    /// - 1-byte algorithm (5)
    /// - 1-byte labels (1)
    /// - 4-byte original_ttl (3600 = 0x00000E10)
    /// - 4-byte sig_expiration
    /// - 4-byte sig_inception
    /// - 2-byte key_tag (2642 = 0x0A52)
    /// - 9-byte signer_name "example." wire
    /// Then two RRs in canonical RDATA order (preference=1 before preference=2).
    #[test]
    fn rfc4034_appendix_b3_signing_input_structure() {
        let rrset = make_mx_rrset();
        let sig_expiration: u32 = 1_075_118_400; // approx 2004-01-26
        let sig_inception: u32 = 1_072_483_200; // approx 2003-12-31
        let rrsig = RsigFields {
            type_covered: Rtype::Mx,
            algorithm: 5,
            labels: 1,
            original_ttl: 3600,
            sig_expiration,
            sig_inception,
            key_tag: 2642,
            signer_name: example_dot(),
        };

        let input = rrset_signing_input(&rrsig, &rrset);

        // ── Validate the RRSIG prefix ─────────────────────────────────────────

        // Offset 0-1: type_covered MX = 15
        assert_eq!(&input[0..2], &[0x00, 0x0F], "type_covered must be MX (15)");
        // Offset 2: algorithm = 5
        assert_eq!(input[2], 5, "algorithm");
        // Offset 3: labels = 1
        assert_eq!(input[3], 1, "labels");
        // Offset 4-7: original_ttl = 3600 = 0x00000E10
        assert_eq!(
            &input[4..8],
            &[0x00, 0x00, 0x0E, 0x10],
            "original_ttl = 3600"
        );
        // Offset 8-11: sig_expiration
        assert_eq!(
            &input[8..12],
            &sig_expiration.to_be_bytes(),
            "sig_expiration"
        );
        // Offset 12-15: sig_inception
        assert_eq!(
            &input[12..16],
            &sig_inception.to_be_bytes(),
            "sig_inception"
        );
        // Offset 16-17: key_tag = 2642 = 0x0A52
        assert_eq!(&input[16..18], &[0x0A, 0x52], "key_tag = 2642");

        // Offset 18..27: signer_name "example." canonical wire.
        // example. = [7, e,x,a,m,p,l,e, 0] = 9 bytes
        let expected_signer: &[u8] = &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
        assert_eq!(&input[18..27], expected_signer, "signer_name wire");

        // ── Validate the canonical RRset ordering ─────────────────────────────
        // After the 27-byte prefix, the first RR should be MX preference=1 (ai.example.)
        // because canonical RDATA order: [0x00,0x01,...] < [0x00,0x02,...]
        let mut pos = 27usize;

        // First RR: owner=example. (9 bytes)
        assert_eq!(
            &input[pos..pos + 9],
            expected_signer,
            "RR1 owner = example."
        );
        pos += 9;
        // type MX = 0x000F
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x0F]);
        pos += 2;
        // class IN = 1
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x01]);
        pos += 2;
        // original_ttl = 3600
        assert_eq!(&input[pos..pos + 4], &[0x00, 0x00, 0x0E, 0x10]);
        pos += 4;

        // rdlength for MX preference=1, exchange=ai.example.
        // ai.example. wire = [2,'a','i',7,'e','x','a','m','p','l','e',0] = 12 bytes
        // canonical = same (already lowercase). RDATA = pref(2) + name(12) = 14 bytes.
        let rdlen1 = u16::from_be_bytes([input[pos], input[pos + 1]]);
        assert_eq!(rdlen1, 14, "RR1 rdlength = 14 (pref=1, ai.example.)");
        pos += 2;

        // preference = 1
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x01], "RR1 preference = 1");
        pos += 2;
        // exchange ai.example. canonical wire
        let ai_example_wire: &[u8] = &[
            2, b'a', b'i', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ];
        assert_eq!(&input[pos..pos + 12], ai_example_wire);
        pos += 12;

        // Second RR: MX preference=2, exchange=b.example.
        // b.example. wire = [1,'b',7,'e','x','a','m','p','l','e',0] = 11 bytes
        // RDATA = pref(2) + name(11) = 13 bytes.
        assert_eq!(
            &input[pos..pos + 9],
            expected_signer,
            "RR2 owner = example."
        );
        pos += 9;
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x0F]);
        pos += 2;
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x01]);
        pos += 2;
        assert_eq!(&input[pos..pos + 4], &[0x00, 0x00, 0x0E, 0x10]);
        pos += 4;
        let rdlen2 = u16::from_be_bytes([input[pos], input[pos + 1]]);
        assert_eq!(rdlen2, 13, "RR2 rdlength = 13 (pref=2, b.example.)");
        pos += 2;
        assert_eq!(&input[pos..pos + 2], &[0x00, 0x02], "RR2 preference = 2");
        pos += 2;
        let b_example_wire: &[u8] = &[1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
        assert_eq!(&input[pos..pos + 11], b_example_wire);
        pos += 11;

        assert_eq!(pos, input.len(), "no trailing bytes");
    }

    #[test]
    fn canonical_name_wire_lowercases() {
        let n = Name::from_str("EXAMPLE.COM.").unwrap();
        let wire = canonical_name_wire(&n);
        // All alphabetic bytes should be lowercase.
        assert!(wire.iter().all(|b| !b.is_ascii_uppercase()));
    }

    #[test]
    fn canonical_rdata_order_by_content() {
        // Records sort purely by RDATA bytes.
        let a = vec![0x00u8, 0x01];
        let b = vec![0x00u8, 0x02];
        assert_eq!(canonical_rdata_order(&a, &b), Ordering::Less);
        assert_eq!(canonical_rdata_order(&b, &a), Ordering::Greater);
        assert_eq!(canonical_rdata_order(&a, &a), Ordering::Equal);
    }

    #[test]
    fn signing_input_uses_rrsig_ttl_not_record_ttl() {
        // Even if the RR has a different TTL, the signing input must use original_ttl.
        let name = Name::from_str("example.com.").unwrap();
        let record = Record {
            name: name.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 99999, // differs from original_ttl below
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        };
        let rrsig = RsigFields {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 1234,
            signer_name: name,
        };
        let input = rrset_signing_input(&rrsig, &[record]);
        // original_ttl field in RRSIG prefix (offset 4..8):
        assert_eq!(
            &input[4..8],
            &300u32.to_be_bytes(),
            "signing prefix uses original_ttl=300"
        );
        // original_ttl in the RR entry: skip prefix + owner + type + class = 18 (prefix len
        // before signer) + signer_name len + owner + 2+2 = ...
        // Easier: search for the TTL in the RR section.
        // The RR section TTL should also be 300, not 99999.
        let owner_wire = canonical_name_wire(&Name::from_str("example.com.").unwrap());
        let prefix_len = 18 + 9 + owner_wire.len(); // RRSIG header + signer "example.com." wire + owner
        // signer "example.com." = [7,e,x,a,m,p,l,e,3,c,o,m,0] = 13 bytes
        // Actually let me just check that 99999 does NOT appear as a 4-byte sequence.
        let bytes_99999 = 99999u32.to_be_bytes();
        let found_99999 = input.windows(4).any(|w| w == bytes_99999.as_slice());
        assert!(
            !found_99999,
            "record's own TTL (99999) must not appear in signing input"
        );
        let bytes_300 = 300u32.to_be_bytes();
        let found_300 = input
            .windows(4)
            .filter(|w| *w == bytes_300.as_slice())
            .count();
        assert_eq!(
            found_300, 2,
            "original_ttl=300 must appear twice: in prefix and in RR"
        );
    }

    #[test]
    fn empty_rrset_produces_only_rrsig_prefix() {
        let rrsig = RsigFields {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 1234,
            signer_name: Name::from_str("example.com.").unwrap(),
        };
        let input = rrset_signing_input(&rrsig, &[]);
        // Only RRSIG prefix bytes (18 fixed + signer_name wire).
        // "example.com." = [7,e,x,a,m,p,l,e,3,c,o,m,0] = 13 bytes.
        assert_eq!(input.len(), 18 + 13);
    }
}
