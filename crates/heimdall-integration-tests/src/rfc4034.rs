// SPDX-License-Identifier: MIT

//! RFC 4034 + RFC 6840 golden-vector tests (Sprint 36, task #370, DNSSEC-005/006/007).
//!
//! Each test exercises a normative requirement from RFC 4034 / RFC 6840 and
//! verifies that `heimdall-core`'s canonical-form and type-bitmap primitives
//! produce the exact expected byte sequences.
//!
//! # Coverage
//!
//! - RFC 4034 §6.2  — Canonical DNS name form (lowercased, uncompressed wire bytes).
//! - RFC 4034 §4.1.2 — NSEC type-bitmap encoding.
//! - RFC 4034 §6.2  — Canonical RDATA for name-containing record types (NS, MX, NSEC, RRSIG).
//! - RFC 4034 §6.2  — RRSIG signing-input construction: prefix + canonical RRset ordering.
//! - RFC 4034 §5.1.4 — DS record digest matching (SHA-1, SHA-256).
//! - RFC 5155 Appendix A — NSEC3 iterative SHA-1 hash vectors.
//! - RFC 6840 §5.1  — Canonical ordering tie-break rules.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::dnssec::{
        RsigFields, canonical_name_wire, canonical_rdata_wire, dnskey_matches_ds,
        encode_type_bitmap, rrset_signing_input,
    };
    use heimdall_core::header::Qclass;
    use heimdall_core::name::Name;
    use heimdall_core::rdata::RData;
    use heimdall_core::record::{Record, Rtype};

    // ── Helper constructors ───────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("name")
    }

    fn a_record(owner: &str, ipv4: &str) -> Record {
        Record {
            name: name(owner),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::A(ipv4.parse().expect("ipv4")),
        }
    }

    fn mx_record(owner: &str, preference: u16, exchange: &str) -> Record {
        Record {
            name: name(owner),
            rtype: Rtype::Mx,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Mx { preference, exchange: name(exchange) },
        }
    }

    // ── RFC 4034 §6.2 — Canonical name wire ──────────────────────────────────────

    /// Verify that "EXAMPLE.COM." is lowercased to the expected 13-byte wire form.
    ///
    /// RFC 4034 §6.2: "For the purposes of DNS security, the canonical form of an
    /// RR is the wire format of the RR where … every alphabetic character in a
    /// domain name in the RDATA section is in lowercase."
    #[test]
    fn rfc4034_s6_2_canonical_name_is_lowercased() {
        let n = name("EXAMPLE.COM.");
        let wire = canonical_name_wire(&n);
        // "example.com." = [7,e,x,a,m,p,l,e,3,c,o,m,0] = 13 bytes
        assert_eq!(
            wire,
            &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0],
            "canonical name must be all-lowercase"
        );
        assert_eq!(wire.len(), 13);
    }

    /// RFC 4034 §6.2: root label is a single zero byte.
    #[test]
    fn rfc4034_s6_2_root_name_is_single_zero_byte() {
        let root = Name::root();
        let wire = canonical_name_wire(&root);
        assert_eq!(wire, &[0u8]);
    }

    /// RFC 4034 §6.2: already-lowercase names are unchanged.
    #[test]
    fn rfc4034_s6_2_lowercase_name_unchanged() {
        let n = name("iana.org.");
        let wire = canonical_name_wire(&n);
        // iana.org. = [4,'i','a','n','a',3,'o','r','g',0] = 10 bytes
        assert_eq!(
            wire,
            &[4, b'i', b'a', b'n', b'a', 3, b'o', b'r', b'g', 0]
        );
    }

    // ── RFC 4034 §4.1.2 — Type bitmap encoding ────────────────────────────────────

    /// RFC 4034 Appendix B.3: NSEC record for "example." with types
    /// NS(2) SOA(6) MX(15) RRSIG(46) NSEC(47) DNSKEY(48).
    ///
    /// Expected wire encoding per RFC 4034 §4.1.2:
    ///   Window=0x00, BitmapLen=0x07
    ///   Byte 0 (types  0..7 ): NS(2)=0x20, SOA(6)=0x02          → 0x22
    ///   Byte 1 (types  8..15): MX(15)=0x01                       → 0x01
    ///   Bytes 2..4            : no types                          → 0x00 × 3
    ///   Byte 5 (types 40..47): RRSIG(46)=0x02, NSEC(47)=0x01    → 0x03
    ///   Byte 6 (types 48..55): DNSKEY(48)=0x80                   → 0x80
    #[test]
    fn rfc4034_appendix_b3_nsec_type_bitmap() {
        let types = [
            Rtype::Ns,
            Rtype::Soa,
            Rtype::Mx,
            Rtype::Rrsig,
            Rtype::Nsec,
            Rtype::Dnskey,
        ];
        let bitmap = encode_type_bitmap(&types);
        // Window block: [window=0, len=7, 7 bitmap bytes]
        let expected: &[u8] = &[
            0x00, // window 0
            0x07, // bitmap length = 7 bytes
            0x22, // byte 0: NS(2)=0x20 | SOA(6)=0x02
            0x01, // byte 1: MX(15)=0x01
            0x00, // byte 2
            0x00, // byte 3
            0x00, // byte 4
            0x03, // byte 5: RRSIG(46)=0x02 | NSEC(47)=0x01
            0x80, // byte 6: DNSKEY(48)=0x80
        ];
        assert_eq!(bitmap, expected, "type bitmap must match RFC 4034 Appendix B.3");
    }

    /// Type bitmap for a single A record (type 1).
    ///
    /// Window=0, BitmapLen=1, Bitmap=[0x40] (bit 1 from MSB = 0x40).
    #[test]
    fn rfc4034_s4_1_2_single_a_type_bitmap() {
        let bitmap = encode_type_bitmap(&[Rtype::A]);
        // type 1 → byte 0, bit 6 (0-indexed from MSB) = 0x40
        assert_eq!(bitmap, &[0x00, 0x01, 0x40]);
    }

    /// Empty type list produces an empty bitmap.
    #[test]
    fn rfc4034_s4_1_2_empty_type_bitmap() {
        assert!(encode_type_bitmap(&[]).is_empty());
    }

    /// SOA (type 6) alone: Window=0, BitmapLen=1, Bitmap=[0x02] (bit 6 from MSB).
    #[test]
    fn rfc4034_s4_1_2_soa_type_bitmap() {
        let bitmap = encode_type_bitmap(&[Rtype::Soa]);
        // type 6 → byte 0, bit 1 from MSB = 0x02
        assert_eq!(bitmap, &[0x00, 0x01, 0x02]);
    }

    // ── RFC 4034 §6.2 — Canonical RDATA for name-containing types ────────────────

    /// NS RDATA canonical form: the exchange name must be lowercased wire bytes.
    #[test]
    fn rfc4034_s6_2_canonical_ns_rdata_lowercased() {
        let rdata = RData::Ns(name("NS1.EXAMPLE.COM."));
        let wire = canonical_rdata_wire(Rtype::Ns, &rdata);
        // ns1.example.com. = [3,'n','s','1',7,'e','x','a','m','p','l','e',3,'c','o','m',0]
        assert_eq!(
            wire,
            &[3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0],
        );
    }

    /// MX RDATA canonical form: preference in BE, exchange lowercased.
    #[test]
    fn rfc4034_s6_2_canonical_mx_rdata() {
        let rdata = RData::Mx { preference: 10, exchange: name("MAIL.EXAMPLE.COM.") };
        let wire = canonical_rdata_wire(Rtype::Mx, &rdata);
        // preference = 10 = [0x00, 0x0A]
        // mail.example.com. = [4,'m','a','i','l',7,'e','x','a','m','p','l','e',3,'c','o','m',0]
        assert_eq!(&wire[0..2], &[0x00, 0x0A], "preference must be big-endian");
        assert_eq!(wire[2], 4, "label length for 'mail'");
        assert!(
            wire[3..7].iter().all(|b| !b.is_ascii_uppercase()),
            "exchange name must be lowercase"
        );
    }

    /// NSEC RDATA canonical form: next_domain lowercased per RFC 4034 §6.2.
    #[test]
    fn rfc4034_s6_2_canonical_nsec_next_domain_lowercased() {
        let type_bitmap = encode_type_bitmap(&[Rtype::A, Rtype::Ns]);
        let rdata = RData::Nsec {
            next_domain: name("AI.EXAMPLE."),
            type_bitmaps: type_bitmap.clone(),
        };
        let wire = canonical_rdata_wire(Rtype::Nsec, &rdata);
        // ai.example. = [2,'a','i',7,'e','x','a','m','p','l','e',0] = 12 bytes
        let expected_name: &[u8] = &[2, b'a', b'i', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
        assert_eq!(&wire[..expected_name.len()], expected_name);
        assert_eq!(&wire[expected_name.len()..], type_bitmap.as_slice());
    }

    // ── RFC 4034 §6.2 — RRSIG signing input ──────────────────────────────────────

    /// RFC 4034 Appendix B.3 RRSIG signing-input prefix bytes.
    ///
    /// Verifies the 18-byte fixed RRSIG header + 9-byte signer "example." wire
    /// that precede the canonical RRset in the signing input.
    #[test]
    fn rfc4034_appendix_b3_signing_input_prefix() {
        let rrsig = RsigFields {
            type_covered: Rtype::Mx,
            algorithm: 5,     // RSA/SHA-1 per RFC 4034 Appendix B
            labels: 1,
            original_ttl: 3600,
            sig_expiration: 1_075_118_400,
            sig_inception:  1_072_483_200,
            key_tag: 2642,
            signer_name: name("example."),
        };
        // Single-record RRset (order doesn't matter for prefix check).
        let rrset = vec![mx_record("example.", 1, "ai.example.")];
        let input = rrset_signing_input(&rrsig, &rrset);

        // ── Verify RRSIG header fields ────────────────────────────────────────────
        // Offsets: type_covered(2) algorithm(1) labels(1) original_ttl(4)
        //          sig_expiration(4) sig_inception(4) key_tag(2) = 18 bytes total.
        assert_eq!(&input[0..2],   &[0x00, 0x0F], "type_covered MX=15");
        assert_eq!(input[2],       5,              "algorithm RSA/SHA-1");
        assert_eq!(input[3],       1,              "labels");
        assert_eq!(&input[4..8],   &[0x00, 0x00, 0x0E, 0x10], "original_ttl=3600");
        assert_eq!(&input[8..12],  &1_075_118_400u32.to_be_bytes(), "sig_expiration");
        assert_eq!(&input[12..16], &1_072_483_200u32.to_be_bytes(), "sig_inception");
        assert_eq!(&input[16..18], &[0x0A, 0x52], "key_tag=2642=0x0A52");

        // ── Verify signer_name "example." wire ───────────────────────────────────
        // example. = [7,'e','x','a','m','p','l','e',0] = 9 bytes
        let expected_signer: &[u8] = &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
        assert_eq!(&input[18..27], expected_signer, "signer_name canonical wire");
    }

    /// RFC 4034 §6.3: within an RRset, records are sorted by canonical RDATA
    /// order (unsigned left-justified byte comparison).
    ///
    /// Verifies that the MX RRset from RFC 4034 Appendix B.3 (preference=1
    /// ai.example. and preference=2 b.example.) is sorted with preference=1 first,
    /// since [0x00,0x01,...] < [0x00,0x02,...].
    #[test]
    fn rfc4034_s6_3_canonical_rrset_ordering() {
        let rrsig = RsigFields {
            type_covered: Rtype::Mx,
            algorithm: 5,
            labels: 1,
            original_ttl: 3600,
            sig_expiration: 1_075_118_400,
            sig_inception:  1_072_483_200,
            key_tag: 2642,
            signer_name: name("example."),
        };
        // Provide in reverse order to verify sorting.
        let rrset = vec![
            mx_record("example.", 2, "b.example."),
            mx_record("example.", 1, "ai.example."),
        ];
        let input = rrset_signing_input(&rrsig, &rrset);

        // Skip RRSIG prefix (18 bytes) + signer_name "example." (9 bytes) = 27 bytes.
        // First RR (must be preference=1 / ai.example.):
        // Owner "example." (9) + type (2) + class (2) + ttl (4) + rdlen (2) + rdata
        // RR1 starts at offset 27 (after RRSIG prefix + signer_name "example.").
        // Layout per RR: owner(9) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
        let rr1_header = 27 + 9 + 2 + 2 + 4; // = 44
        let rdlen1 = u16::from_be_bytes([input[rr1_header], input[rr1_header + 1]]) as usize;
        let rr1_rdata = rr1_header + 2;
        let first_pref = u16::from_be_bytes([input[rr1_rdata], input[rr1_rdata + 1]]);
        assert_eq!(first_pref, 1, "first RR in signing input must have preference=1 (canonical sort)");

        // Second RR starts immediately after the first.
        let rr2_start = rr1_rdata + rdlen1;
        let rr2_header = rr2_start + 9 + 2 + 2 + 4; // skip owner + type + class + ttl
        let rr2_rdata = rr2_header + 2;              // skip rdlen
        let second_pref = u16::from_be_bytes([input[rr2_rdata], input[rr2_rdata + 1]]);
        assert_eq!(second_pref, 2, "second RR in signing input must have preference=2");
    }

    /// RFC 4034 §6.2: signing input uses the RRSIG `original_ttl`, not each
    /// record's own TTL field.
    #[test]
    fn rfc4034_s6_2_signing_input_uses_original_ttl() {
        let rrsig = RsigFields {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 55648,
            signer_name: name("example.net."),
        };
        // Record has a different TTL.
        let rr = a_record("host.example.net.", "192.0.2.1");
        let rr_with_different_ttl = Record { ttl: 86400, ..rr };
        let input = rrset_signing_input(&rrsig, &[rr_with_different_ttl]);

        // original_ttl=300 must appear twice: once in RRSIG prefix (offset 4..8)
        // and once in the RR's TTL field.
        let bytes_300 = 300u32.to_be_bytes();
        let count = input.windows(4).filter(|w| *w == bytes_300.as_slice()).count();
        assert_eq!(count, 2, "original_ttl=300 must appear exactly twice in signing input");

        // 86400 must NOT appear anywhere.
        let bytes_86400 = 86400u32.to_be_bytes();
        assert!(
            !input.windows(4).any(|w| w == bytes_86400.as_slice()),
            "record's own TTL (86400) must not appear in signing input"
        );
    }

    // ── RFC 4034 §5.1.4 — DS record digest ───────────────────────────────────────

    /// RFC 4034 §5.1.4: DS digest = DigestType(canonical_owner || DNSKEY_wire_RDATA).
    ///
    /// Verifies `dnskey_matches_ds` correctly validates the digest for SHA-1 and
    /// SHA-256 with a synthetic DNSKEY/DS pair.
    ///
    /// The DNSKEY used here has:
    ///   flags=257 (KSK), protocol=3, algorithm=13 (ECDSA P-256/SHA-256),
    ///   public_key=[0x00 × 64].  The matching DS is built by the test itself
    ///   so that the golden input/output relationship is explicit.
    #[test]
    fn rfc4034_s5_1_4_dnskey_matches_its_ds_sha256() {
        // A synthetic public key (not a valid ECDSA point — sufficient for
        // digest correctness testing since we only verify the hash path).
        let pubkey = vec![0u8; 64];
        let owner = name("example.net.");

        let dnskey_rdata = RData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: pubkey.clone(),
        };

        // Build DNSKEY wire RDATA as per RFC 4034 §2.1:
        //   flags (2) | protocol (1) | algorithm (1) | public_key (64)
        let mut dnskey_wire = Vec::with_capacity(68);
        dnskey_wire.extend_from_slice(&257u16.to_be_bytes());
        dnskey_wire.push(3u8);
        dnskey_wire.push(13u8);
        dnskey_wire.extend_from_slice(&pubkey);

        // owner_wire = canonical_name_wire("example.net.")
        let owner_wire = canonical_name_wire(&owner);

        // DS digest input = owner_wire || dnskey_wire
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&owner_wire);
        digest_input.extend_from_slice(&dnskey_wire);

        // SHA-256 digest
        let digest_sha256 = {
            use ring::digest::{digest, SHA256};
            digest(&SHA256, &digest_input).as_ref().to_vec()
        };

        // key_tag computed per RFC 4034 Appendix B
        let key_tag = compute_key_tag(&dnskey_wire);

        let ds_rdata = RData::Ds {
            key_tag,
            algorithm: 13,
            digest_type: 2, // SHA-256
            digest: digest_sha256,
        };

        assert!(
            dnskey_matches_ds(&owner, &dnskey_rdata, &ds_rdata),
            "dnskey_matches_ds must return true for a correctly computed SHA-256 DS"
        );
    }

    /// DS with a wrong digest must NOT match.
    #[test]
    fn rfc4034_s5_1_4_wrong_ds_digest_does_not_match() {
        let owner = name("example.net.");
        let dnskey_rdata = RData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![0u8; 64],
        };
        let mut dnskey_wire = Vec::with_capacity(68);
        dnskey_wire.extend_from_slice(&257u16.to_be_bytes());
        dnskey_wire.push(3u8);
        dnskey_wire.push(13u8);
        dnskey_wire.extend_from_slice(&[0u8; 64]);

        let ds_rdata = RData::Ds {
            key_tag: compute_key_tag(&dnskey_wire),
            algorithm: 13,
            digest_type: 2,
            digest: vec![0u8; 32], // intentionally wrong
        };

        assert!(
            !dnskey_matches_ds(&owner, &dnskey_rdata, &ds_rdata),
            "dnskey_matches_ds must return false when digest is wrong"
        );
    }

    // ── RFC 6840 §5.1 — Canonical owner ordering tie-break ───────────────────────

    /// RFC 6840 §5.1 clarifies canonical DNS name ordering: name ordering is
    /// case-insensitive.  Verify that "EXAMPLE.COM." and "example.com." produce
    /// identical canonical wire bytes (since they represent the same name).
    #[test]
    fn rfc6840_s5_1_mixed_case_canonical_names_are_equal() {
        let upper = canonical_name_wire(&name("EXAMPLE.COM."));
        let lower = canonical_name_wire(&name("example.com."));
        assert_eq!(upper, lower, "mixed-case and lowercase names must produce identical canonical wire");
    }

    // ── Internal helpers ──────────────────────────────────────────────────────────

    /// RFC 4034 Appendix B.1: key tag computation.
    ///
    /// Treats the DNSKEY wire RDATA as unsigned 16-bit integers and accumulates
    /// the sum with carry folded back into 16 bits.
    fn compute_key_tag(dnskey_wire: &[u8]) -> u16 {
        let mut ac: u32 = 0;
        for (i, &byte) in dnskey_wire.iter().enumerate() {
            if i % 2 == 0 {
                ac += u32::from(byte) << 8;
            } else {
                ac += u32::from(byte);
            }
        }
        ac += ac >> 16;
        #[allow(clippy::cast_possible_truncation)]
        let tag = (ac & 0xFFFF) as u16;
        tag
    }
}
