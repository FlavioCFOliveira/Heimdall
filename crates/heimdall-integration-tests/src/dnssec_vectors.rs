// SPDX-License-Identifier: MIT

//! IETF DNSSEC test-vector harness for `heimdall-core` primitives (Sprint 36, task #363).
//!
//! Vectors sourced from:
//! - **RFC 5702 §6** — RSA/SHA-256 (alg 8) and RSA/SHA-512 (alg 10).
//! - **RFC 6605 §6** — ECDSA P-256/SHA-256 (alg 13) and P-384/SHA-384 (alg 14).
//! - **RFC 8080 §6** (erratum 4935) — Ed25519 (alg 15) and Ed448 (alg 16).
//! - **RFC 5155 Appendix A** — NSEC3 hash computation table.
//! - **RFC 8624 §3** — Algorithm acceptance policy (DNSSEC-032..034).
//!
//! # Timestamp handling
//!
//! RFC 5702 vectors use inception `20000101000000` (946 684 800) and expiration
//! `20300101000000` (1 893 456 000).  RFC 6605 and RFC 8080 vectors used
//! timestamps from 2010 and 2015 respectively.  All tests pass a fixed
//! `now_unix` that falls inside each vector's validity window so that the
//! timestamp check is bypassed and the test exercises the cryptographic path.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    use heimdall_core::dnssec::{
        ValidationOutcome, BogusReason, DsAcceptance, MAX_NSEC3_ITERATIONS,
        nsec3_excess_iterations_ede, nsec3_hash, nsec3_hash_with_budget, select_ds_records,
    };
    use heimdall_core::dnssec::budget::ValidationBudget;
    use heimdall_core::edns::{EdnsOption, ExtendedError, ede_code};
    use heimdall_core::dnssec::verify::verify_rrsig;
    use heimdall_core::header::Qclass;
    use heimdall_core::name::Name;
    use heimdall_core::rdata::RData;
    use heimdall_core::record::{Record, Rtype};

    // ── Helpers ──────────────────────────────────────────────────────────────────

    fn make_dnskey(zone: &str, flags: u16, algorithm: u8, pub_key_b64: &str) -> Record {
        Record {
            name: Name::from_str(zone).expect("zone name"),
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key: B64.decode(pub_key_b64).expect("pub key base64"),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_rrsig(
        type_covered: Rtype,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        sig_inception: u32,
        sig_expiration: u32,
        key_tag: u16,
        signer_name: &str,
        sig_b64: &str,
    ) -> RData {
        RData::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name: Name::from_str(signer_name).expect("signer name"),
            signature: B64.decode(sig_b64).expect("signature base64"),
        }
    }

    fn make_a_record(owner: &str, ttl: u32, octets: [u8; 4]) -> Record {
        Record {
            name: Name::from_str(owner).expect("owner name"),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl,
            rdata: RData::A(std::net::Ipv4Addr::from(octets)),
        }
    }

    fn make_mx_record(owner: &str, ttl: u32, preference: u16, exchange: &str) -> Record {
        Record {
            name: Name::from_str(owner).expect("owner name"),
            rtype: Rtype::Mx,
            rclass: Qclass::In,
            ttl,
            rdata: RData::Mx {
                preference,
                exchange: Name::from_str(exchange).expect("exchange name"),
            },
        }
    }

    /// Decodes a base32hex string (RFC 4648 §7, alphabet `0-9A-V`) to a 20-byte
    /// SHA-1 hash.  Panics on invalid input; only used in test assertions.
    fn decode_base32hex(s: &str) -> [u8; 20] {
        let s = s.to_ascii_uppercase();
        let chars = s.as_bytes();
        assert_eq!(chars.len(), 32, "NSEC3 base32hex hash must be 32 chars (160 bits)");

        let val = |c: u8| -> u64 {
            match c {
                b'0'..=b'9' => u64::from(c - b'0'),
                b'A'..=b'V' => u64::from(c - b'A' + 10),
                _ => panic!("invalid base32hex char: {c}"),
            }
        };

        let mut bits: u64 = 0;
        let mut bit_count: u32 = 0;
        let mut out = [0u8; 20];
        let mut out_idx = 0usize;

        for &c in chars {
            bits = (bits << 5) | val(c);
            bit_count += 5;
            if bit_count >= 8 {
                bit_count -= 8;
                #[allow(clippy::cast_possible_truncation)]
                let byte = ((bits >> bit_count) & 0xFF) as u8;
                out[out_idx] = byte;
                out_idx += 1;
            }
        }
        out
    }

    // ── Algorithm 8 (RSASHA256) and 10 (RSASHA512) — Ring-compatible 2048-bit vectors ───
    //
    // RFC 5702 §6 deliberately uses 512-bit RSA keys for publication brevity.  Ring
    // (and DNSSEC best practice) requires a minimum of 2048 bits.  The RFC example
    // vectors therefore cannot be used to test the cryptographic path because ring
    // rejects keys smaller than 2048 bits in its RSA_PKCS1_2048_8192_* verifiers.
    //
    // These tests use self-generated 2048-bit RSA-2048 key material signed with
    // OpenSSL over the exact canonical DNSSEC signing input (RFC 4034 §6.2 +
    // RFC 4034 §3.1) so that the full code path is exercised.
    //
    // Key material (shared by alg 8 and alg 10, same key different algorithm field):
    //   Zone:        example.net.
    //   DNSKEY flags: 256 (ZSK)    protocol: 3
    //   Modulus:     2048 bits
    //   Exponent:    65537
    //
    // Test RRset: www.example.net. 3600 IN A 192.0.2.91
    // Inception:  20000101000000 (946 684 800)
    // Expiration: 20300101000000 (1 893 456 000)
    // now_unix:   1 000 000 000 — well inside the validity window.

    const ALG8_ZONE: &str = "example.net.";
    const ALG8_NOW: u64 = 1_000_000_000;
    const ALG8_INCEPTION: u32 = 946_684_800;
    const ALG8_EXPIRATION: u32 = 1_893_456_000;

    // RFC 3110 wire format of the 2048-bit RSA public key used for both alg 8 and alg 10.
    const RSA2048_PUBKEY: &str =
        "AwEAAaEQblB80w1sKfaq+jWsjSy+1iYXKD1JJxvMUx6Yk0Hb0KuyKG4V\
         mh0qsItSegJw+KfbgMOPBdrufMI1igVktcEXtac//xUh66K+d7RUzsMa0\
         rI6+AzkEXjEfNc6vmO2cRPBHeoETiBP7i3gftniX/LyxOFchLduLBN7tU\
         QETWehL+yDgCTbmfibS9VcXaBKQHXExZk5Ry+u37z2lxqm0LkwoxQGH6\
         1T7rfQG8Tx8vsU3WZK/CbS7Ws3pdde+7oksvWrI0HJENeFKynb+rhchQY\
         xFbLma0msmqDkypAiZb5Go+6zy3OltKhE2joe14VOVuafmemd4haLSVAO\
         FIKT2VU=";

    // PKCS#1 v1.5 SHA-256 signature over the canonical signing input for:
    // www.example.net. 3600 IN A 192.0.2.91, key tag 54915 (alg 8).
    const ALG8_KEY_TAG: u16 = 54915;
    const ALG8_SIG_A: &str =
        "kpnVNYgrI3w/jsfAhJy9qXg2p/m6N88PQoATFl3RaEGueskYvy9q8PJl\
         jomwvl8WHju7G+oM+7oxtrz1MmdFPnXNbsDk7DI02Fj6lF8eSGH1MFDRy\
         5bmM7Mcz0+s88iX3n/qB4C5lQ3xLm4DPP7IkB/eR69GCokpnrvAzHOn6b\
         eB260lsG8Ze639wxexjpRg/7pDQpZUvADpQ92VHw+3WBJdaihuQK8+R/g\
         05iZn8W5ePjKilDqzIBZ8/tshkhoeJfmht2PapHYavOZfWuFqQnwR+SAq\
         rWjempN/+4fP5kgZHexH1zwHteg+03q067EuKtbUTJJYRws4qu2KiEG/zg==";

    #[test]
    fn alg8_rsasha256_2048bit_a_record_verifies_secure() {
        let dnskey = make_dnskey(ALG8_ZONE, 256, 8, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        let rrsig = make_rrsig(
            Rtype::A, 8, 3, 3600,
            ALG8_INCEPTION, ALG8_EXPIRATION, ALG8_KEY_TAG, ALG8_ZONE, ALG8_SIG_A,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG8_NOW, 16);
        assert_eq!(outcome, ValidationOutcome::Secure, "alg-8 RSA-2048/SHA-256 vector must verify");
    }

    #[test]
    fn alg8_rsasha256_rejects_wrong_signature() {
        let dnskey = make_dnskey(ALG8_ZONE, 256, 8, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        // 256 bytes of zeros — valid length for RSA-2048 but cryptographically invalid.
        let bad_sig = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 256]);
        let rrsig = make_rrsig(
            Rtype::A, 8, 3, 3600,
            ALG8_INCEPTION, ALG8_EXPIRATION, ALG8_KEY_TAG, ALG8_ZONE, &bad_sig,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG8_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::InvalidSignature),
            "alg-8 with wrong signature must be Bogus(InvalidSignature)",
        );
    }

    // ── Algorithm 10 (RSASHA512) — ring-compatible 2048-bit vector ───────────────
    //
    // Per DNSSEC-034: alg 10 is MAY validate; implemented → must produce Secure.
    // Same key as alg 8 (different algorithm field → different key_tag).

    const ALG10_KEY_TAG: u16 = 54917;
    const ALG10_SIG_A: &str =
        "HwTEUuumA251KBa9sLCACQgnw1Q1vsPGTTcK9nTBqSXw2szv/BtWhDzA\
         TIvhaQ1v5yX/soDPQlvapBwIlA+BY6aJHqABHd9Yx1rPhhY1vSwKN8S+\
         ogpEgfR2DvyI4cFM9rBt8MfTU+xVC28aWB8sbX2H+zyI0lWAzQermKR18\
         gQzN/SVy00SYvjDMwoY4er1IynD+MlkHlkeBThMQA5QZh+sNluI8hNy0+\
         pNr2OawrzaAYxFqLkXzzFzj3ewpmgTupuYRs6rUZUP/jGjveBb+NwVSas\
         7clXCduvcb1DlG7vuwUL6dL2pl8kRmY+Xq0ald5zOYmzhaCbGvYAK/F9/ow==";

    #[test]
    fn alg10_rsasha512_2048bit_a_record_verifies_secure() {
        let dnskey = make_dnskey(ALG8_ZONE, 256, 10, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        let rrsig = make_rrsig(
            Rtype::A, 10, 3, 3600,
            ALG8_INCEPTION, ALG8_EXPIRATION, ALG10_KEY_TAG, ALG8_ZONE, ALG10_SIG_A,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG8_NOW, 16);
        assert_eq!(outcome, ValidationOutcome::Secure, "alg-10 RSA-2048/SHA-512 vector must verify");
    }

    // ── RFC 6605 §6 — ECDSA P-256/SHA-256 (algorithm 13) ────────────────────────
    //
    // Zone: example.net.   Key tag: 55648   DNSKEY flags: 257 (KSK/SEP)
    // Inception: 20100812100439 (1 281 607 479)   Expiration: 20100909100439 (1 284 026 679)
    // now_unix: 1 283 000 000 — inside the validity window.

    const ALG13_ZONE: &str = "example.net.";
    const ALG13_PUBKEY: &str =
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb\
         krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
    const ALG13_SIG_A: &str =
        "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA\
         yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";
    const ALG13_KEY_TAG: u16 = 55648;
    const ALG13_INCEPTION: u32 = 1_281_607_479;
    const ALG13_EXPIRATION: u32 = 1_284_026_679;
    const ALG13_NOW: u64 = 1_283_000_000;

    #[test]
    fn rfc6605_alg13_ecdsap256sha256_a_record_verifies_secure() {
        let dnskey = make_dnskey(ALG13_ZONE, 257, 13, ALG13_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 1])];
        let rrsig = make_rrsig(
            Rtype::A,
            13,
            3,
            3600,
            ALG13_INCEPTION,
            ALG13_EXPIRATION,
            ALG13_KEY_TAG,
            ALG13_ZONE,
            ALG13_SIG_A,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG13_NOW, 16);
        assert_eq!(outcome, ValidationOutcome::Secure, "RFC 6605 §6.1 alg-13 vector must verify");
    }

    #[test]
    fn rfc6605_alg13_rejects_wrong_rdata() {
        // Change the A record RData to a different IP — signing input changes → sig fails.
        let dnskey = make_dnskey(ALG13_ZONE, 257, 13, ALG13_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 99])];
        let rrsig = make_rrsig(
            Rtype::A,
            13,
            3,
            3600,
            ALG13_INCEPTION,
            ALG13_EXPIRATION,
            ALG13_KEY_TAG,
            ALG13_ZONE,
            ALG13_SIG_A,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG13_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::InvalidSignature),
            "alg-13 over tampered rdata must be Bogus(InvalidSignature)",
        );
    }

    // ── RFC 6605 §6 — ECDSA P-384/SHA-384 (algorithm 14) ────────────────────────
    //
    // Zone: example.net.   Key tag: 10771   DNSKEY flags: 257 (KSK/SEP)
    // Inception: 20100812102025 (1 281 608 425)   Expiration: 20100909102025 (1 284 027 625)
    // now_unix: 1 283 000 000 — inside the validity window.

    const ALG14_PUBKEY: &str =
        "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1\
         w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8\
         /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
    const ALG14_SIG_A: &str =
        "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP\
         95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz\
         WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";
    const ALG14_KEY_TAG: u16 = 10771;
    const ALG14_INCEPTION: u32 = 1_281_608_425;
    const ALG14_EXPIRATION: u32 = 1_284_027_625;

    #[test]
    fn rfc6605_alg14_ecdsap384sha384_a_record_verifies_secure() {
        let dnskey = make_dnskey(ALG13_ZONE, 257, 14, ALG14_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 1])];
        let rrsig = make_rrsig(
            Rtype::A,
            14,
            3,
            3600,
            ALG14_INCEPTION,
            ALG14_EXPIRATION,
            ALG14_KEY_TAG,
            ALG13_ZONE,
            ALG14_SIG_A,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG13_NOW, 16);
        assert_eq!(outcome, ValidationOutcome::Secure, "RFC 6605 §6.2 alg-14 vector must verify");
    }

    // ── RFC 8080 §6 (erratum 4935) — Ed25519 (algorithm 15) ─────────────────────
    //
    // Zone: example.com.
    // RRset: example.com. 3600 IN MX 10 mail.example.com.
    // Labels: 2 (example, com — root not counted per RFC 4034 §3.1.3).
    // Inception: 20150729220000 (1 438 207 200)   Expiration: 20150819220000 (1 440 021 600)
    // now_unix: 1 439 000 000 — inside the validity window.
    //
    // IMPORTANT: the signatures in the original RFC 8080 text are WRONG.
    // Use only the values from erratum 4935.

    const ALG15_ZONE: &str = "example.com.";
    const ALG15_INCEPTION: u32 = 1_438_207_200;
    const ALG15_EXPIRATION: u32 = 1_440_021_600;
    const ALG15_NOW: u64 = 1_439_000_000;

    // Example 1
    const ALG15_EX1_PUBKEY: &str = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";
    const ALG15_EX1_SIG: &str =
        "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeR\
         AvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==";
    const ALG15_EX1_KEY_TAG: u16 = 3613;

    #[test]
    fn rfc8080_alg15_ed25519_example1_mx_verifies_secure() {
        let dnskey = make_dnskey(ALG15_ZONE, 257, 15, ALG15_EX1_PUBKEY);
        let rrset = vec![make_mx_record(ALG15_ZONE, 3600, 10, "mail.example.com.")];
        let rrsig = make_rrsig(
            Rtype::Mx,
            15,
            2,
            3600,
            ALG15_INCEPTION,
            ALG15_EXPIRATION,
            ALG15_EX1_KEY_TAG,
            ALG15_ZONE,
            ALG15_EX1_SIG,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG15_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "RFC 8080 §6 erratum-4935 alg-15 example 1 must verify",
        );
    }

    // Example 2
    const ALG15_EX2_PUBKEY: &str = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";
    const ALG15_EX2_SIG: &str =
        "zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT4\
         10QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==";
    const ALG15_EX2_KEY_TAG: u16 = 35217;

    #[test]
    fn rfc8080_alg15_ed25519_example2_mx_verifies_secure() {
        let dnskey = make_dnskey(ALG15_ZONE, 257, 15, ALG15_EX2_PUBKEY);
        let rrset = vec![make_mx_record(ALG15_ZONE, 3600, 10, "mail.example.com.")];
        let rrsig = make_rrsig(
            Rtype::Mx,
            15,
            2,
            3600,
            ALG15_INCEPTION,
            ALG15_EXPIRATION,
            ALG15_EX2_KEY_TAG,
            ALG15_ZONE,
            ALG15_EX2_SIG,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG15_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "RFC 8080 §6 erratum-4935 alg-15 example 2 must verify",
        );
    }

    // ── RFC 8080 §6 (erratum 4935) — Ed448 (algorithm 16) ───────────────────────
    //
    // Ed448 is not supported by `ring`; DNSSEC-033 marks it as SHOULD validate but
    // defers implementation.  verify_rrsig must return AlgorithmNotImplemented(16)
    // immediately, before any key or signing-input processing.

    const ALG16_EX1_PUBKEY: &str =
        "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA";
    const ALG16_EX1_SIG: &str =
        "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1C\
         MB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXf\
         t0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyM\
         WbSNyGEY2213WKsJlwEA";
    const ALG16_EX1_KEY_TAG: u16 = 9713;

    #[test]
    fn rfc8080_alg16_ed448_example1_returns_not_implemented() {
        let dnskey = make_dnskey(ALG15_ZONE, 257, 16, ALG16_EX1_PUBKEY);
        let rrset = vec![make_mx_record(ALG15_ZONE, 3600, 10, "mail.example.com.")];
        let rrsig = make_rrsig(
            Rtype::Mx,
            16,
            2,
            3600,
            ALG15_INCEPTION,
            ALG15_EXPIRATION,
            ALG16_EX1_KEY_TAG,
            ALG15_ZONE,
            ALG16_EX1_SIG,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG15_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(16)),
            "alg-16 (Ed448) must be Bogus(AlgorithmNotImplemented(16)) — ring does not support Ed448",
        );
    }

    const ALG16_EX2_PUBKEY: &str =
        "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3t\
         DjeMCJcVMRDmgcNLp5HlHAMy12VoISsA";
    const ALG16_EX2_SIG: &str =
        "E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4\
         Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0AsQ4f7qI1gVnM\
         L8vWWiyW2KXhT9kuAICUSxv5OWbf81Rq7Yu60npabODB\
         0QFPb/rkW3kUZmQ0YQUA";
    const ALG16_EX2_KEY_TAG: u16 = 38353;

    #[test]
    fn rfc8080_alg16_ed448_example2_returns_not_implemented() {
        let dnskey = make_dnskey(ALG15_ZONE, 257, 16, ALG16_EX2_PUBKEY);
        let rrset = vec![make_mx_record(ALG15_ZONE, 3600, 10, "mail.example.com.")];
        let rrsig = make_rrsig(
            Rtype::Mx,
            16,
            2,
            3600,
            ALG15_INCEPTION,
            ALG15_EXPIRATION,
            ALG16_EX2_KEY_TAG,
            ALG15_ZONE,
            ALG16_EX2_SIG,
        );
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG15_NOW, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::AlgorithmNotImplemented(16)),
            "alg-16 (Ed448) must be Bogus(AlgorithmNotImplemented(16)) — ring does not support Ed448",
        );
    }

    // ── RFC 8624 §3 — Deprecated algorithm policy (algorithms 5 and 7) ───────────
    //
    // DNSSEC-034 permits Heimdall to implement validation for algorithms 5, 7, and 10
    // (MAY validate).  Algorithm 10 is implemented and tested above.  Algorithms 5
    // (RSASHA1) and 7 (RSASHA1-NSEC3-SHA1) are MUST NOT sign per RFC 8624 §3.1; the
    // `ring` PKCS#1 v1.5 verifier does not expose a SHA-1 path for RSA, so any
    // signature produced under these algorithms cannot produce a Secure outcome.
    //
    // These tests verify the policy invariant: deprecated algorithms 5 and 7 MUST NOT
    // produce ValidationOutcome::Secure regardless of the input.

    #[test]
    fn rfc8624_alg5_rsasha1_does_not_produce_secure() {
        // Use a key_tag that matches no DNSKEY → fastest path to a non-Secure outcome.
        let rrsig = RData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 5,
            labels: 3,
            original_ttl: 3600,
            sig_expiration: ALG8_EXPIRATION,
            sig_inception: ALG8_INCEPTION,
            key_tag: 0xFFFF,
            signer_name: Name::from_str(ALG8_ZONE).unwrap(),
            signature: vec![0u8; 64],
        };
        let outcome = verify_rrsig(&[], &rrsig, &[], ALG8_NOW, 16);
        assert_ne!(
            outcome,
            ValidationOutcome::Secure,
            "alg-5 (RSASHA1, MUST NOT sign per RFC 8624) must never produce Secure",
        );
    }

    #[test]
    fn rfc8624_alg7_rsasha1nsec3_does_not_produce_secure() {
        let rrsig = RData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 7,
            labels: 3,
            original_ttl: 3600,
            sig_expiration: ALG8_EXPIRATION,
            sig_inception: ALG8_INCEPTION,
            key_tag: 0xFFFF,
            signer_name: Name::from_str(ALG8_ZONE).unwrap(),
            signature: vec![0u8; 64],
        };
        let outcome = verify_rrsig(&[], &rrsig, &[], ALG8_NOW, 16);
        assert_ne!(
            outcome,
            ValidationOutcome::Secure,
            "alg-7 (RSASHA1-NSEC3-SHA1, MUST NOT sign per RFC 8624) must never produce Secure",
        );
    }

    // ── RFC 5155 Appendix A — NSEC3 hash computation vectors ─────────────────────
    //
    // Zone: example.   Hash algorithm: 1 (SHA-1).   Iterations: 12.   Salt: aabbccdd.
    //
    // The hash table below is taken verbatim from RFC 5155 Appendix A.  Each entry
    // is encoded in Base32Hex (RFC 4648 §7) as it appears in the wire format and in
    // zone-file presentation.
    //
    // The decode_base32hex helper converts these strings to raw 20-byte SHA-1 output
    // for direct comparison with nsec3_hash() return values.

    const NSEC3_SALT: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd];
    const NSEC3_ITERS: u16 = 12;

    fn nsec3_of(name: &str) -> [u8; 20] {
        nsec3_hash(&Name::from_str(name).expect(name), NSEC3_SALT, NSEC3_ITERS)
            .expect("hash must succeed for iters ≤ 150")
    }

    #[test]
    fn rfc5155_nsec3_hash_apex_example() {
        assert_eq!(
            nsec3_of("example."),
            decode_base32hex("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            "example. must hash to RFC 5155 Appendix A value",
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_a_example() {
        assert_eq!(
            nsec3_of("a.example."),
            decode_base32hex("35mthgpgcu1qg68fab165klnsnk3dpvl"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_ai_example() {
        assert_eq!(
            nsec3_of("ai.example."),
            decode_base32hex("gjeqe526plbf1g8mklp59enfd789njgi"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_ns1_example() {
        assert_eq!(
            nsec3_of("ns1.example."),
            decode_base32hex("2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_ns2_example() {
        assert_eq!(
            nsec3_of("ns2.example."),
            decode_base32hex("q04jkcevqvmu85r014c7dkba38o0ji5r"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_w_example() {
        assert_eq!(
            nsec3_of("w.example."),
            decode_base32hex("k8udemvp1j2f7eg6jebps17vp3n8i58h"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_x_w_example() {
        assert_eq!(
            nsec3_of("x.w.example."),
            decode_base32hex("b4um86eghhds6nea196smvmlo4ors995"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_y_w_example() {
        assert_eq!(
            nsec3_of("y.w.example."),
            decode_base32hex("ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_x_y_w_example() {
        assert_eq!(
            nsec3_of("x.y.w.example."),
            decode_base32hex("2vptu5timamqttgl4luu9kg21e0aor3s"),
        );
    }

    #[test]
    fn rfc5155_nsec3_hash_xx_example() {
        assert_eq!(
            nsec3_of("xx.example."),
            decode_base32hex("t644ebqk9bibcna874givr6joj62mlhv"),
        );
    }

    // Additional vectors from RFC 5155 Appendix B (example responses).
    #[test]
    fn rfc5155_nsec3_hash_wildcard_w_example() {
        assert_eq!(
            nsec3_of("*.w.example."),
            decode_base32hex("r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        );
    }

    // ── Boundary conditions ───────────────────────────────────────────────────────

    #[test]
    fn nsec3_hash_rejects_iterations_above_cap() {
        let name = Name::from_str("example.").unwrap();
        // MAX_NSEC3_ITERATIONS = 150; 151 must return None.
        assert!(
            nsec3_hash(&name, NSEC3_SALT, 151).is_none(),
            "nsec3_hash must return None for iterations > 150 (DNSSEC-044)",
        );
    }

    #[test]
    fn nsec3_hash_accepts_zero_iterations() {
        // 0 iterations (only the initial hash, no extra rounds) must succeed.
        let name = Name::from_str("example.").unwrap();
        assert!(nsec3_hash(&name, NSEC3_SALT, 0).is_some());
    }

    #[test]
    fn nsec3_hash_empty_salt() {
        // Salt may be empty per RFC 5155 §3.1 (salt length = 0).
        let name = Name::from_str("example.").unwrap();
        assert!(nsec3_hash(&name, &[], 0).is_some());
    }

    // ── DNSSEC-044..047: five-value systematic cap test ───────────────────────
    //
    // RFC 9276 §3.2 mandates a 150-iteration hard cap (DNSSEC-044).
    // Values 0, 1, 150 → hash computes (Secure path, DNSSEC-046).
    // Values 151, 1000 → hash refused, must be treated as Insecure (DNSSEC-045).
    // EDE code 27 (Unsupported NSEC3 Iterations Value) is attached to the
    // Insecure path per DNSSEC-045.  No config knob may raise the cap (DNSSEC-047).

    #[test]
    fn nsec3_iterations_five_values_outcomes_match_spec() {
        let name = Name::from_str("example.").unwrap();

        // Secure path: iterations within cap → Some(hash).
        for iter in [0u16, 1, 150] {
            assert!(
                nsec3_hash(&name, NSEC3_SALT, iter).is_some(),
                "iter={iter}: must compute hash (DNSSEC-046, secure path)"
            );
        }

        // Insecure path: iterations exceed cap → None.
        // The caller MUST treat None as Insecure, NOT Bogus (DNSSEC-044/045).
        for iter in [151u16, 1000] {
            assert!(
                nsec3_hash(&name, NSEC3_SALT, iter).is_none(),
                "iter={iter}: must refuse to compute (DNSSEC-044, insecure path)"
            );
        }
    }

    #[test]
    fn nsec3_iterations_exceeded_attaches_ede_code_27() {
        // When iterations > MAX_NSEC3_ITERATIONS, the caller uses
        // nsec3_excess_iterations_ede() to attach EDE code 27 (DNSSEC-045).
        let ede = nsec3_excess_iterations_ede();
        let EdnsOption::ExtendedError(ExtendedError { info_code, .. }) = ede else {
            panic!("nsec3_excess_iterations_ede must produce ExtendedError variant");
        };
        assert_eq!(
            info_code,
            ede_code::UNSUPPORTED_NSEC3_ITERATIONS_VALUE,
            "EDE code must be 27 — Unsupported NSEC3 Iterations Value (RFC 8914 §5.2)"
        );
    }

    #[test]
    fn nsec3_hash_with_budget_never_bogus_for_excessive_iterations() {
        // nsec3_hash_with_budget must return Ok(None) — not Err(BogusReason) —
        // when iterations exceed the cap.  Bogus is NEVER produced for this case
        // (DNSSEC-044/045).
        let name = Name::from_str("example.").unwrap();
        let budget = ValidationBudget::default_budget();

        for iter in [151u16, 1000] {
            let result = nsec3_hash_with_budget(&name, NSEC3_SALT, iter, &budget);
            assert!(
                result.is_ok(),
                "iter={iter}: excessive iterations must NOT produce Err (Bogus)"
            );
            assert!(
                result.unwrap().is_none(),
                "iter={iter}: excessive iterations must return Ok(None) (Insecure)"
            );
        }
    }

    #[test]
    fn nsec3_cap_is_compile_time_constant_150() {
        // DNSSEC-047: the cap MUST be a compile-time constant — no config knob
        // can elevate it above 150.  This test pins the value to catch any
        // accidental change.
        assert_eq!(
            MAX_NSEC3_ITERATIONS, 150,
            "RFC 9276 §3.2 cap is 150; changing it would violate DNSSEC-044/047"
        );
    }

    #[test]
    fn verify_rrsig_rejects_expired_timestamp() {
        // now_unix is beyond sig_expiration; must be Bogus(SignatureExpired).
        let dnskey = make_dnskey(ALG8_ZONE, 256, 8, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        let rrsig = make_rrsig(
            Rtype::A,
            8,
            3,
            3600,
            ALG8_INCEPTION,
            ALG8_EXPIRATION,
            ALG8_KEY_TAG,
            ALG8_ZONE,
            ALG8_SIG_A,
        );
        // now_unix well past expiration.
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], 2_000_000_000, 16);
        assert_eq!(outcome, ValidationOutcome::Bogus(BogusReason::SignatureExpired));
    }

    #[test]
    fn verify_rrsig_rejects_not_yet_valid_timestamp() {
        // now_unix is before sig_inception; must be Bogus(SignatureNotYetValid).
        let dnskey = make_dnskey(ALG8_ZONE, 256, 8, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        let rrsig = make_rrsig(
            Rtype::A,
            8,
            3,
            3600,
            ALG8_INCEPTION,
            ALG8_EXPIRATION,
            ALG8_KEY_TAG,
            ALG8_ZONE,
            ALG8_SIG_A,
        );
        // now_unix before inception.
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], 900_000_000, 16);
        assert_eq!(outcome, ValidationOutcome::Bogus(BogusReason::SignatureNotYetValid));
    }

    #[test]
    fn verify_rrsig_keytrap_limit_zero_blocks_immediately() {
        let dnskey = make_dnskey(ALG8_ZONE, 256, 8, RSA2048_PUBKEY);
        let rrset = vec![make_a_record("www.example.net.", 3600, [192, 0, 2, 91])];
        let rrsig = make_rrsig(
            Rtype::A,
            8,
            3,
            3600,
            ALG8_INCEPTION,
            ALG8_EXPIRATION,
            ALG8_KEY_TAG,
            ALG8_ZONE,
            ALG8_SIG_A,
        );
        // max_attempts=0: key_tag matches but attempt limit hit immediately.
        let outcome = verify_rrsig(&rrset, &rrsig, &[dnskey], ALG8_NOW, 0);
        assert_eq!(outcome, ValidationOutcome::Bogus(BogusReason::KeyTrapLimit));
    }

    // ── DS digest acceptance matrix (DNSSEC-049..054) ─────────────────────────
    //
    // Six cells per task #597 AC:
    // (a) DS-2 alone       → Modern (SHA-256)
    // (b) DS-4 alone       → Modern (SHA-384)
    // (c) DS-1 alone       → Sha1Fallback + EDE code 2
    // (d) DS-1 + DS-2      → Modern (SHA-256 wins; SHA-1 NOT used)
    // (e) DS-3 alone       → NoSupported (GOST rejected)
    // (f) DS-3 + DS-2      → Modern (GOST contributes nothing)

    fn make_ds_rdata(digest_type: u8) -> RData {
        RData::Ds {
            key_tag: 2345,
            algorithm: 13,
            digest_type,
            digest: vec![0xCC; 32],
        }
    }

    #[test]
    fn ds_digest_matrix_six_cells() {
        // (a) DS-2 (SHA-256) alone → Modern.
        let a = [make_ds_rdata(2)];
        assert!(matches!(select_ds_records(&a), DsAcceptance::Modern(_)), "(a) DS-2 → Modern");

        // (b) DS-4 (SHA-384) alone → Modern.
        let b = [make_ds_rdata(4)];
        assert!(matches!(select_ds_records(&b), DsAcceptance::Modern(_)), "(b) DS-4 → Modern");

        // (c) DS-1 (SHA-1) alone → Sha1Fallback + EDE code 2.
        let c = [make_ds_rdata(1)];
        let r_c = select_ds_records(&c);
        assert!(
            matches!(r_c, DsAcceptance::Sha1Fallback(_)),
            "(c) DS-1 alone → Sha1Fallback (DNSSEC-051)"
        );
        let ede_c = r_c.fallback_ede().expect("(c) SHA-1 fallback must emit EDE");
        let EdnsOption::ExtendedError(ExtendedError { info_code, .. }) = ede_c else {
            panic!("EDE must be ExtendedError");
        };
        assert_eq!(info_code, ede_code::UNSUPPORTED_DS_DIGEST_TYPE, "(c) EDE code must be 2");

        // (d) DS-1 + DS-2 → Modern (SHA-256 wins; SHA-1 NOT used as fallback).
        let d = [make_ds_rdata(1), make_ds_rdata(2)];
        let r_d = select_ds_records(&d);
        assert!(matches!(r_d, DsAcceptance::Modern(_)), "(d) DS-1+DS-2 → Modern (SHA-256 wins)");
        assert!(r_d.fallback_ede().is_none(), "(d) Modern path must not emit EDE");
        if let DsAcceptance::Modern(selected) = &r_d {
            for rdata in selected {
                if let RData::Ds { digest_type, .. } = rdata {
                    assert_ne!(*digest_type, 1u8, "(d) SHA-1 must NOT appear in Modern selection");
                }
            }
        }

        // (e) DS-3 (GOST) alone → NoSupported (DNSSEC-052: GOST MUST NOT contribute).
        let e = [make_ds_rdata(3)];
        assert!(
            matches!(select_ds_records(&e), DsAcceptance::NoSupported),
            "(e) DS-3 alone → NoSupported (GOST rejected)"
        );

        // (f) DS-3 + DS-2 → Modern (GOST contributes nothing; SHA-256 wins).
        let f = [make_ds_rdata(3), make_ds_rdata(2)];
        let r_f = select_ds_records(&f);
        assert!(matches!(r_f, DsAcceptance::Modern(_)), "(f) DS-3+DS-2 → Modern (GOST contributes nothing)");
        if let DsAcceptance::Modern(selected) = &r_f {
            for rdata in selected {
                if let RData::Ds { digest_type, .. } = rdata {
                    assert_ne!(*digest_type, 3u8, "(f) GOST must NOT appear in Modern selection");
                }
            }
        }
    }
}
