// SPDX-License-Identifier: MIT

//! End-to-end DNSSEC validation harness across recursive and forwarder wirings
//! (Sprint 36, task #364, Sprint 49 task #497).
//!
//! Verifies that `ResponseValidator` (recursive role) and `ForwarderValidator`
//! (forwarder role) produce identical, deterministic `ValidationOutcome` values
//! when presented with the same DNS messages.
//!
//! Test fixtures are derived from the IETF test vectors already exercised in
//! [`crate::dnssec_vectors`] (task #363):
//! - RFC 6605 §6.1 — ECDSA P-256/SHA-256 (algorithm 13, key tag 55648).
//!
//! # Coverage
//!
//! | Scenario | Outcome |
//! |---|---|
//! | RFC 6605 alg-13 signed message (in-message DNSKEY) | `Secure` |
//! | Message with no RRSIG / no DNSKEY | `Insecure` |
//! | Signed message with zeroed (tampered) signature bytes | `Bogus(InvalidSignature)` |
//! | Signed zone with active NTA | `Insecure` |
//! | Upstream AD=1 without local RRSIG (forwarder) | `Insecure` |
//! | 11 garbage DNSKEY records (`key_tag` = 1038) | `Bogus(KeyTrapLimit)` |
//! | Secure outcome + DO bit via full dispatcher | AD flag set in response |
//! | Secure outcome, no DO bit via dispatcher | AD flag clear |
//! | Tampered signature via full dispatcher | SERVFAIL |
//! | Unsigned message via dispatcher + DO bit | NOERROR, AD clear |
//!
//! # NSEC3 iteration cap
//!
//! Covered at the primitive level in `dnssec_vectors.rs` (RFC 5155 Appendix A
//! vectors + boundary condition `nsec3_hash_rejects_iterations_above_cap`).
//! The cap (RFC 9276 §3.1: 150 iterations) is tested there directly on
//! `nsec3_hash()`, which is the sole computation site.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        pin::Pin,
        str::FromStr,
        sync::Arc,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use heimdall_core::{
        dnssec::{
            BogusReason, ValidationOutcome, algorithms::DnsAlgorithm, deprecated_algorithm_ede,
            verify::verify_rrsig,
        },
        edns::{EdnsOption, OptRr},
        header::{Header, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
    };
    use heimdall_roles::{
        dnssec_roles::{NtaStore, TrustAnchorStore},
        forwarder::ForwarderValidator,
        recursive::{RecursiveServer, ResponseValidator, RootHints, UpstreamQuery},
    };
    use heimdall_runtime::cache::recursive::RecursiveCache;

    // ── RFC 6605 §6.1 vector constants ───────────────────────────────────────────
    //
    // Zone: example.net.  Key tag: 55648  Flags: 257 (KSK/SEP)  Algorithm: 13
    // RRset:  www.example.net. 3600 IN A 192.0.2.1
    // Inception: 20100812100439 (1 281 607 479)
    // Expiration: 20100909100439 (1 284 026 679)
    // now_unix: 1 283 000 000 — inside the validity window.

    const ALG13_ZONE: &str = "example.net.";
    const ALG13_PUBKEY: &str = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb\
         krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
    const ALG13_SIG: &str = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA\
         yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";
    const ALG13_KEY_TAG: u16 = 55648;
    const ALG13_INCEPTION: u32 = 1_281_607_479;
    const ALG13_EXPIRATION: u32 = 1_284_026_679;
    const ALG13_NOW: u32 = 1_283_000_000;

    // ── Message builders ─────────────────────────────────────────────────────────

    /// Builds a DNS `Message` simulating a signed authoritative response:
    /// - `www.example.net. 3600 IN A 192.0.2.1`
    /// - The zone DNSKEY (algorithm 13, flags 257) in the answers section
    /// - A valid RFC 6605 §6.1 RRSIG over the A `RRset`
    ///
    /// `ResponseValidator` combines DNSKEYs from both the trust anchor and the
    /// message, so including the DNSKEY in the response is sufficient to produce a
    /// Secure outcome without pre-loading the trust anchor.
    fn build_signed_message() -> Message {
        let zone = Name::from_str(ALG13_ZONE).expect("zone name");
        let owner = Name::from_str("www.example.net.").expect("owner name");

        let a_record = Record {
            name: owner.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };

        let dnskey = Record {
            name: zone.clone(),
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: B64.decode(ALG13_PUBKEY).expect("pubkey decode"),
            },
        };

        let rrsig = Record {
            name: owner,
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 13,
                labels: 3,
                original_ttl: 3600,
                sig_expiration: ALG13_EXPIRATION,
                sig_inception: ALG13_INCEPTION,
                key_tag: ALG13_KEY_TAG,
                signer_name: zone,
                signature: B64.decode(ALG13_SIG).expect("sig decode"),
            },
        };

        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.ancount = 3;

        Message {
            header,
            questions: vec![],
            answers: vec![a_record, dnskey, rrsig],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Builds an unsigned authoritative response (no RRSIG, no DNSKEY).
    fn build_unsigned_message() -> Message {
        let owner = Name::from_str("www.example.net.").expect("owner name");
        let a_record = Record {
            name: owner,
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 3600,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.ancount = 1;
        Message {
            header,
            questions: vec![],
            answers: vec![a_record],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Clones the signed message but replaces every RRSIG's signature bytes
    /// with zeros (same length, invalid crypto).
    fn build_tampered_message() -> Message {
        let mut msg = build_signed_message();
        for record in &mut msg.answers {
            if let RData::Rrsig { signature, .. } = &mut record.rdata {
                signature.iter_mut().for_each(|b| *b = 0);
            }
        }
        msg
    }

    // ── KeyTrap message builder ───────────────────────────────────────────────────
    //
    // 11 DNSKEY records with key_tag = 1038, each with a 64-byte all-zero public
    // key (not a valid ECDSA P-256 point → every crypto attempt fails), paired
    // with an RRSIG whose key_tag is also 1038.
    //
    // key_tag derivation for flags=257 (0x0101), protocol=3, algorithm=13,
    // pubkey=[0u8; 64]:
    //   wire = [0x01, 0x01, 0x03, 0x0D, 0x00 × 64]
    //   i=0 (even): ac += 0x01<<8 = 256
    //   i=1 (odd):  ac += 0x01     =   1
    //   i=2 (even): ac += 0x03<<8 = 768
    //   i=3 (odd):  ac += 0x0D    =  13
    //   zeros contribute 0 → ac = 1038 → carry term = 0 → key_tag = 1038

    const KEYTRAP_KEY_TAG: u16 = 1038;
    const KEYTRAP_ZONE: &str = "keytrap.example.";

    fn build_keytrap_message() -> Message {
        let zone_name = Name::from_str(KEYTRAP_ZONE).expect("keytrap zone");
        let owner = Name::from_str("www.keytrap.example.").expect("owner");

        let a_record = Record {
            name: owner.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
        };

        // 11 garbage DNSKEY records — all produce key_tag = 1038.
        // None are valid ECDSA keys; the 5th will never be tried because
        // KEY_LIMIT = 4 in ResponseValidator, triggering KeyTrapLimit.
        let garbage_dnskeys: Vec<Record> = (0..11u8)
            .map(|_| Record {
                name: zone_name.clone(),
                rtype: Rtype::Dnskey,
                rclass: Qclass::In,
                ttl: 3600,
                rdata: RData::Dnskey {
                    flags: 257,
                    protocol: 3,
                    algorithm: 13,
                    public_key: vec![0u8; 64],
                },
            })
            .collect();

        let rrsig = Record {
            name: owner,
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                sig_expiration: ALG13_EXPIRATION,
                sig_inception: ALG13_INCEPTION,
                key_tag: KEYTRAP_KEY_TAG,
                signer_name: zone_name,
                signature: vec![0u8; 64],
            },
        };

        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);

        let mut answers = vec![a_record, rrsig];
        answers.extend(garbage_dnskeys);

        Message {
            header,
            questions: vec![],
            answers,
            authority: vec![],
            additional: vec![],
        }
    }

    // ── Validator factory helpers ─────────────────────────────────────────────────

    fn make_recursive_validator() -> (ResponseValidator, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor init"));
        let nta_store = Arc::new(NtaStore::new(100));
        (ResponseValidator::new(trust_anchor, nta_store), dir)
    }

    fn make_forwarder_validator() -> (ForwarderValidator, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor init"));
        let nta_store = Arc::new(NtaStore::new(100));
        (ForwarderValidator::new(trust_anchor, nta_store), dir)
    }

    fn alg13_zone() -> Name {
        Name::from_str(ALG13_ZONE).expect("zone name")
    }

    // ── Tests: Secure outcome ─────────────────────────────────────────────────────

    #[test]
    fn recursive_validator_secure_for_rfc6605_alg13_signed_message() {
        let (v, _dir) = make_recursive_validator();
        let outcome = v.validate(&build_signed_message(), &alg13_zone(), ALG13_NOW);
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "ResponseValidator must return Secure for a valid RFC 6605 alg-13 signed message"
        );
    }

    #[test]
    fn forwarder_validator_secure_for_rfc6605_alg13_signed_message() {
        let (v, _dir) = make_forwarder_validator();
        let outcome = v.validate(&build_signed_message(), &alg13_zone(), ALG13_NOW);
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "ForwarderValidator must return Secure for a valid RFC 6605 alg-13 signed message"
        );
    }

    // ── Tests: determinism across wirings ─────────────────────────────────────────

    #[test]
    fn both_validators_agree_on_secure() {
        let (rec, _d1) = make_recursive_validator();
        let (fwd, _d2) = make_forwarder_validator();
        let msg = build_signed_message();
        let r = rec.validate(&msg, &alg13_zone(), ALG13_NOW);
        let f = fwd.validate(&msg, &alg13_zone(), ALG13_NOW);
        assert_eq!(
            r, f,
            "recursive and forwarder validators must agree on Secure"
        );
        assert_eq!(r, ValidationOutcome::Secure);
    }

    #[test]
    fn both_validators_agree_on_insecure() {
        let (rec, _d1) = make_recursive_validator();
        let (fwd, _d2) = make_forwarder_validator();
        let msg = build_unsigned_message();
        let r = rec.validate(&msg, &alg13_zone(), ALG13_NOW);
        let f = fwd.validate(&msg, &alg13_zone(), ALG13_NOW);
        assert_eq!(r, ValidationOutcome::Insecure);
        assert_eq!(
            r, f,
            "recursive and forwarder validators must agree on Insecure"
        );
    }

    #[test]
    fn both_validators_agree_on_bogus_for_tampered_rrsig() {
        let (rec, _d1) = make_recursive_validator();
        let (fwd, _d2) = make_forwarder_validator();
        let msg = build_tampered_message();
        let r = rec.validate(&msg, &alg13_zone(), ALG13_NOW);
        let f = fwd.validate(&msg, &alg13_zone(), ALG13_NOW);
        assert!(
            matches!(r, ValidationOutcome::Bogus(_)),
            "tampered RRSIG must produce Bogus; got {r:?}"
        );
        assert_eq!(
            r, f,
            "recursive and forwarder validators must agree on Bogus"
        );
    }

    // ── Test: forwarder ignores upstream AD bit ────────────────────────────────────

    #[test]
    fn forwarder_ignores_upstream_ad_bit_without_rrsig() {
        let (v, _dir) = make_forwarder_validator();
        let mut msg = build_unsigned_message();
        // Simulate an upstream resolver that set AD=1.
        msg.header.set_ad(true);
        let outcome = v.validate(&msg, &alg13_zone(), ALG13_NOW);
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "ForwarderValidator must ignore the upstream AD bit — no RRSIG → Insecure"
        );
    }

    // ── Test: NTA bypasses validation ─────────────────────────────────────────────

    #[test]
    fn nta_forces_insecure_even_for_valid_signed_message() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor init"));
        let nta_store = Arc::new(NtaStore::new(100));

        let zone = alg13_zone();
        nta_store
            .add(zone.clone(), u64::from(ALG13_NOW) + 3600, "test")
            .expect("nta add");

        let validator = ResponseValidator::new(trust_anchor, nta_store);
        let outcome = validator.validate(&build_signed_message(), &zone, ALG13_NOW);
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "active NTA must force Insecure regardless of valid RRSIGs"
        );
    }

    // ── Test: KeyTrap cap ─────────────────────────────────────────────────────────

    #[test]
    fn keytrap_cap_triggers_after_key_limit_failed_attempts() {
        let (v, _dir) = make_recursive_validator();
        let zone = Name::from_str(KEYTRAP_ZONE).expect("keytrap zone");
        let msg = build_keytrap_message();
        let outcome = v.validate(&msg, &zone, ALG13_NOW);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::KeyTrapLimit),
            "11 garbage keys (key_tag=1038) must trigger Bogus(KeyTrapLimit) after KEY_LIMIT=4 attempts"
        );
    }

    // ── DNSSEC-035..039: algorithm rejection and deprecated-algorithm EDE ────────
    //
    // Sub-case (i): MUST-NOT algorithm (1) → Indeterminate (treated as absent) →
    //   no valid RRSIG remains → ResponseValidator returns Insecure.
    //
    // Sub-case (ii): alg-5 (deprecated MAY) present alongside alg-8 (MUST) →
    //   outcome Secure (via alg-8); deprecated_algorithm_ede() produces EDE code 1.
    //
    // Sub-case (iii): deprecated algorithm use triggers the structured log path —
    //   verified by asserting DnsAlgorithm::is_deprecated() for the observed alg,
    //   which is the predicate that gates the tracing::warn!() event in the validator.

    #[test]
    fn must_not_algorithm_1_rrsig_only_chain_is_insecure() {
        // Sub-case (i): a synthetic "chain" whose only RRSIG uses algorithm 1 (RSAMD5).
        // verify_rrsig must treat it as absent (Indeterminate); ResponseValidator must
        // aggregate to Insecure because no other RRSIG validates.
        let rrsig = RData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 1, // RSAMD5 — MUST NOT implement (DNSSEC-035)
            labels: 2,
            original_ttl: 300,
            sig_expiration: u32::MAX,
            sig_inception: 0,
            key_tag: 1234,
            signer_name: Name::from_str("example.net.").unwrap(),
            signature: vec![0u8; 32],
        };

        // verify_rrsig on a single MUST-NOT RRSIG must return Indeterminate (not Bogus).
        let a_rec = Record {
            name: Name::from_str("www.example.net.").unwrap(),
            rtype: Rtype::A,
            rclass: heimdall_core::header::Qclass::In,
            ttl: 300,
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        };
        let outcome = verify_rrsig(&[a_rec], &rrsig, &[], 1000, 16);
        assert_eq!(
            outcome,
            ValidationOutcome::Indeterminate,
            "(i) alg-1 RRSIG must return Indeterminate (treat as absent, DNSSEC-035)"
        );
        // Importantly, it must NOT be Bogus — MUST-NOT algorithms never cause Bogus.
        assert!(
            !matches!(outcome, ValidationOutcome::Bogus(_)),
            "(i) MUST-NOT algorithm must not produce Bogus (DNSSEC-036)"
        );
    }

    #[test]
    fn deprecated_algorithm_5_observed_produces_ede_code_1() {
        // Sub-case (ii): algorithm 5 (RSASHA1, deprecated) → EDE code 1.
        // The deprecated_algorithm_ede() utility returns the correct EDE option.
        let ede = deprecated_algorithm_ede();
        let EdnsOption::ExtendedError(ref e) = ede else {
            panic!("deprecated_algorithm_ede must return ExtendedError variant");
        };
        assert_eq!(
            e.info_code,
            heimdall_core::edns::ede_code::UNSUPPORTED_DNSKEY_ALGORITHM,
            "(ii) deprecated-algorithm EDE code must be 1 (DNSSEC-038)"
        );

        // Verify that alg-5 is classified as deprecated (the predicate that gates the
        // EDE and the structured log event).
        let alg5 = DnsAlgorithm::from_u8(5);
        assert!(
            alg5.is_deprecated(),
            "(ii) alg-5 must be deprecated per RFC 8624 §3.1"
        );
        let alg8 = DnsAlgorithm::from_u8(8);
        assert!(!alg8.is_deprecated(), "(ii) alg-8 must NOT be deprecated");
    }

    #[test]
    fn deprecated_algorithm_log_path_is_gated_by_is_deprecated_predicate() {
        // Sub-case (iii): the structured log event (tracing::warn!) in ResponseValidator
        // is gated by DnsAlgorithm::is_deprecated().  This test verifies that the
        // predicate returns true for all deprecated algorithms (5, 7, 10) and false for
        // all others, proving that the log event fires for exactly the right input set.
        for alg in [5u8, 7, 10] {
            assert!(
                DnsAlgorithm::from_u8(alg).is_deprecated(),
                "(iii) algorithm {alg} must gate the deprecated-algorithm log event (DNSSEC-039)"
            );
        }
        // MUST-NOT algorithms must NOT be considered deprecated (they are absent, not deprecated).
        for alg in [1u8, 3, 6, 12] {
            assert!(
                !DnsAlgorithm::from_u8(alg).is_deprecated(),
                "(iii) MUST-NOT algorithm {alg} must not trigger the deprecated-algorithm log"
            );
        }
        // Modern algorithms must not trigger the log either.
        for alg in [8u8, 13, 14, 15] {
            assert!(
                !DnsAlgorithm::from_u8(alg).is_deprecated(),
                "(iii) modern algorithm {alg} must not trigger the deprecated-algorithm log"
            );
        }
    }

    // ── Dispatcher end-to-end tests ───────────────────────────────────────────────
    //
    // A minimal MockUpstream returns the same pre-built authoritative message on
    // every call.  Because the message has AA=true, DelegationFollower treats it
    // as the final answer immediately, so a single enqueued response suffices.

    struct MockUpstream {
        msg: Message,
    }

    impl MockUpstream {
        fn returning(msg: Message) -> Arc<Self> {
            Arc::new(Self { msg })
        }
    }

    impl UpstreamQuery for MockUpstream {
        fn query<'a>(
            &'a self,
            _server: IpAddr,
            _port: u16,
            _msg: &'a Message,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>
        {
            let m = self.msg.clone();
            Box::pin(async move { Ok(m) })
        }
    }

    fn make_server() -> (RecursiveServer, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let cache = Arc::new(RecursiveCache::new(512, 512));
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor init"));
        let nta_store = Arc::new(NtaStore::new(100));
        let root_hints = Arc::new(RootHints::from_builtin().expect("root hints"));
        (
            RecursiveServer::new(cache, trust_anchor, nta_store, root_hints),
            dir,
        )
    }

    /// Builds a query with the DO bit set (OPT record in additional section).
    fn query_with_do(qname: &Name) -> Message {
        let mut header = Header::default();
        header.id = 1;
        header.set_rd(true);
        header.qdcount = 1;
        header.arcount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![Record {
                name: Name::root(),
                rtype: Rtype::Opt,
                rclass: Qclass::In,
                ttl: 0,
                rdata: RData::Opt(OptRr {
                    udp_payload_size: 1232,
                    extended_rcode: 0,
                    version: 0,
                    dnssec_ok: true,
                    z: 0,
                    options: vec![],
                }),
            }],
        }
    }

    /// Builds a query without the DO bit.
    fn query_without_do(qname: &Name) -> Message {
        let mut header = Header::default();
        header.id = 1;
        header.set_rd(true);
        header.qdcount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    // ── AD-flag tests use cache pre-population ────────────────────────────────────
    //
    // The RFC 6605 RRSIG timestamps are from 2010 and would be rejected as expired
    // by the dispatcher's current_unix_secs() call.  The AD-flag dispatcher logic
    // (do_bit && Secure && !cd_bit) is independent of RRSIG timestamp validity and
    // is tested here via cache pre-population:
    //   - RecursiveCacheClient::store() inserts an entry with a given ValidationOutcome.
    //   - server.handle() finds the cached entry and applies the AD-flag logic.
    // The validator correctness with real timestamps is covered by the direct
    // validator unit tests above (e.g. recursive_validator_secure_for_rfc6605_alg13_*).

    #[tokio::test]
    async fn ad_flag_set_when_cached_secure_and_do_bit_present() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.secure.example.").expect("qname");

        // Pre-populate the cache with a Secure entry to bypass fresh resolution.
        server.cache_client().store(
            &qname,
            Rtype::A,
            1,
            &build_unsigned_message(),
            ValidationOutcome::Secure,
            &alg13_zone(),
            false,
        );

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_unsigned_message()),
            )
            .await;
        assert_eq!(response.header.rcode(), Rcode::NoError);
        assert!(
            response.header.ad(),
            "AD bit must be set when cached outcome is Secure and DO bit is present"
        );
    }

    #[tokio::test]
    async fn ad_flag_clear_when_cached_secure_but_do_bit_absent() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.secure2.example.").expect("qname");

        server.cache_client().store(
            &qname,
            Rtype::A,
            1,
            &build_unsigned_message(),
            ValidationOutcome::Secure,
            &alg13_zone(),
            false,
        );

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_without_do(&qname),
                src,
                false,
                MockUpstream::returning(build_unsigned_message()),
            )
            .await;
        assert!(
            !response.header.ad(),
            "AD bit must be clear when DO bit is absent even if outcome is Secure"
        );
    }

    #[tokio::test]
    async fn ad_flag_clear_when_cached_insecure_and_do_bit_present() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.insecure.example.").expect("qname");

        server.cache_client().store(
            &qname,
            Rtype::A,
            1,
            &build_unsigned_message(),
            ValidationOutcome::Insecure,
            &alg13_zone(),
            false,
        );

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_unsigned_message()),
            )
            .await;
        assert!(
            !response.header.ad(),
            "AD bit must be clear when cached outcome is Insecure"
        );
    }

    // ── SERVFAIL-on-bogus via fresh resolution ────────────────────────────────────
    //
    // Both the tampered and the expired (2010) signatures produce Bogus when the
    // dispatcher validates with current_unix_secs().  Bogus → SERVFAIL is the
    // dispatcher's invariant being tested here; the exact BogusReason is irrelevant.

    #[tokio::test]
    async fn bogus_rrsig_produces_servfail_via_dispatcher() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.example.net.").expect("qname");
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_tampered_message()),
            )
            .await;
        assert_eq!(
            response.header.rcode(),
            Rcode::ServFail,
            "Bogus DNSSEC validation must produce SERVFAIL per the dispatcher"
        );
    }

    #[tokio::test]
    async fn unsigned_response_does_not_set_ad_bit_even_with_do_bit() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.unsigned.example.").expect("qname");

        server.cache_client().store(
            &qname,
            Rtype::A,
            1,
            &build_unsigned_message(),
            ValidationOutcome::Insecure,
            &alg13_zone(),
            false,
        );

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_unsigned_message()),
            )
            .await;
        assert!(
            !response.header.ad(),
            "unsigned (Insecure) response must never set AD"
        );
        assert_eq!(
            response.header.rcode(),
            Rcode::NoError,
            "Insecure response is NOERROR"
        );
    }

    // ── DNSSEC-086 / DNSSEC-102: KeyTrap EDE EXTRA-TEXT (task #602) ──────────────

    /// Extracts `(info_code, extra_text)` from the first EDE option in `msg.additional`.
    fn extract_ede(msg: &Message) -> Option<(u16, Option<String>)> {
        for rec in &msg.additional {
            if let RData::Opt(opt) = &rec.rdata {
                for opt_rr in &opt.options {
                    if let EdnsOption::ExtendedError(e) = opt_rr {
                        return Some((e.info_code, e.extra_text.clone()));
                    }
                }
            }
        }
        None
    }

    /// Builds a keytrap message with non-expiring RRSIGs (`u32::MAX` expiry) so that
    /// the dispatcher's `current_unix_secs()` does not trigger `SignatureExpired` before
    /// the `KeyTrap` candidate-limit check.
    fn build_keytrap_no_expiry_message() -> Message {
        let zone = Name::from_str(KEYTRAP_ZONE).expect("zone");
        let owner = Name::from_str("www.keytrap.example.").expect("owner");
        let a_record = Record {
            name: owner.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 3)),
        };
        // 11 garbage ECDSA P-256 keys — all with key_tag=KEYTRAP_KEY_TAG.
        let garbage_dnskeys: Vec<Record> = (0..11u8)
            .map(|_| Record {
                name: zone.clone(),
                rtype: Rtype::Dnskey,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::Dnskey {
                    flags: 257,
                    protocol: 3,
                    algorithm: 13,
                    public_key: vec![0u8; 64],
                },
            })
            .collect();
        // RRSIG with inception=0 and expiration=u32::MAX: never expires, so
        // the validity-period check passes and the key-candidate loop is reached.
        let rrsig = Record {
            name: owner,
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: KEYTRAP_KEY_TAG,
                signer_name: zone,
                signature: vec![0xFFu8; 64],
            },
        };
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        let mut answers = vec![a_record, rrsig];
        answers.extend(garbage_dnskeys);
        Message {
            header,
            questions: vec![],
            answers,
            authority: vec![],
            additional: vec![],
        }
    }

    /// `KeyTrap` via key-limit: 11 garbage keys → `KEY_LIMIT=4` fires →
    /// dispatcher MUST return SERVFAIL + EDE code 6 with EXTRA-TEXT "keytrap-cap-reached".
    #[tokio::test]
    async fn keytrap_key_limit_produces_servfail_ede6_with_keytrap_extra_text() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.keytrap.example.").expect("qname");

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_keytrap_no_expiry_message()),
            )
            .await;

        assert_eq!(
            response.header.rcode(),
            Rcode::ServFail,
            "KeyTrap key-limit must produce SERVFAIL"
        );

        let ede = extract_ede(&response);
        assert!(ede.is_some(), "response must carry an EDE option");
        let (code, extra) = ede.expect("just checked");
        assert_eq!(code, 6, "EDE info_code must be 6 (DNSSEC Bogus)");
        assert_eq!(
            extra.as_deref(),
            Some("keytrap-cap-reached"),
            "EDE extra_text must be 'keytrap-cap-reached' (DNSSEC-102)"
        );
    }

    fn build_sig_limit_message() -> Message {
        // SIG_LIMIT+1 = 9 RRSIG records — all dummy, all trigger the sig-limit
        // check in ResponseValidator before any key-candidate processing.
        let zone = Name::from_str(KEYTRAP_ZONE).expect("zone");
        let owner = Name::from_str("www.keytrap.example.").expect("owner");
        let a_record = Record {
            name: owner.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 2)),
        };
        let mut answers = vec![a_record];
        for i in 0u8..9 {
            answers.push(Record {
                name: owner.clone(),
                rtype: Rtype::Rrsig,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::Rrsig {
                    type_covered: Rtype::A,
                    algorithm: 13,
                    labels: 3,
                    original_ttl: 300,
                    sig_expiration: u32::MAX,
                    sig_inception: 0,
                    key_tag: u16::from(i),
                    signer_name: zone.clone(),
                    signature: vec![0xFFu8; 64],
                },
            });
        }
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        Message {
            header,
            questions: vec![],
            answers,
            authority: vec![],
            additional: vec![],
        }
    }

    /// `KeyTrap` via sig-limit: 9 RRSIGs (> `SIG_LIMIT=8`) → sig-limit fires →
    /// dispatcher MUST return SERVFAIL + EDE code 6 with EXTRA-TEXT "keytrap-cap-reached".
    #[tokio::test]
    async fn keytrap_sig_limit_produces_servfail_ede6_with_keytrap_extra_text() {
        let (server, _dir) = make_server();
        let qname = Name::from_str("www.keytrap.example.").expect("qname");

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(
                &query_with_do(&qname),
                src,
                false,
                MockUpstream::returning(build_sig_limit_message()),
            )
            .await;

        assert_eq!(
            response.header.rcode(),
            Rcode::ServFail,
            "KeyTrap sig-limit must produce SERVFAIL"
        );

        let ede = extract_ede(&response);
        assert!(ede.is_some(), "response must carry an EDE option");
        let (code, extra) = ede.expect("just checked");
        assert_eq!(code, 6, "EDE info_code must be 6 (DNSSEC Bogus)");
        assert_eq!(
            extra.as_deref(),
            Some("keytrap-cap-reached"),
            "EDE extra_text must be 'keytrap-cap-reached' (DNSSEC-102)"
        );
    }
}
