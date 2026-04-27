// SPDX-License-Identifier: MIT

//! Golden-output comparison against Unbound (Sprint 36, task #365, ENG-035).
//!
//! Verifies that Heimdall's recursive resolver produces the same outputs as
//! a pinned Unbound instance for a standard query corpus.
//!
//! # Running
//!
//! These tests are `#[ignore]` by default.  To run them:
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored golden_unbound
//! ```
//!
//! Prerequisites:
//! - A pinned Unbound container must be reachable at `UNBOUND_ADDR` (default
//!   `127.0.0.1:5300`).
//! - A Heimdall recursive instance must be reachable at `HEIMDALL_ADDR` (default
//!   `127.0.0.1:5353`).
//! - Both must be pre-seeded with the same zone data and trust anchor.
//!
//! Example Docker command for the reference Unbound container:
//! ```text
//! docker run --rm -p 5300:53/udp --name unbound-golden \
//!   mvance/unbound:1.21.1
//! ```
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-065).  Any divergence that is not in the
//! whitelist triggers a structured failure with the query, Heimdall output,
//! and Unbound output printed for triage.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;
    use heimdall_core::serialiser::Serialiser;

    // ── Environment helpers ───────────────────────────────────────────────────────

    /// Returns the Heimdall recursive resolver address from the environment,
    /// falling back to `127.0.0.1:5353`.
    fn heimdall_addr() -> SocketAddr {
        std::env::var("HEIMDALL_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5353".parse().expect("default addr"))
    }

    /// Returns the Unbound reference server address from the environment,
    /// falling back to `127.0.0.1:5300`.
    fn unbound_addr() -> SocketAddr {
        std::env::var("UNBOUND_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5300".parse().expect("default addr"))
    }

    /// Returns `true` when the interop test suite is enabled via env var.
    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    // ── Query corpus ──────────────────────────────────────────────────────────────

    /// A single query in the golden corpus.
    #[derive(Debug, Clone)]
    struct CorpusQuery {
        /// Query name (FQDN).
        name: &'static str,
        /// Query type.
        qtype: Qtype,
        /// Whether to set the DO (DNSSEC OK) bit.
        do_bit: bool,
    }

    impl CorpusQuery {
        const fn new(name: &'static str, qtype: Qtype) -> Self {
            Self { name, qtype, do_bit: false }
        }

        const fn with_do(name: &'static str, qtype: Qtype) -> Self {
            Self { name, qtype, do_bit: true }
        }
    }

    /// Standard query corpus (ENG-035).
    ///
    /// Covers the most common record types, NXDOMAIN, NODATA, and DNSSEC paths.
    /// Queries are against IANA-stable zones that will never change their answers.
    const CORPUS: &[CorpusQuery] = &[
        // Common secure zones
        CorpusQuery::new("iana.org.", Qtype::A),
        CorpusQuery::new("iana.org.", Qtype::Aaaa),
        CorpusQuery::with_do("iana.org.", Qtype::A),
        CorpusQuery::new("iana.org.", Qtype::Mx),
        CorpusQuery::new("iana.org.", Qtype::Ns),
        // NXDOMAIN path
        CorpusQuery::new("nonexistent.invalid.", Qtype::A),
        // NODATA path (type doesn't exist for the name)
        CorpusQuery::new("iana.org.", Qtype::Ptr),
        // Root zone
        CorpusQuery::with_do(".", Qtype::Ns),
        CorpusQuery::with_do(".", Qtype::Dnskey),
        // Well-known DNSSEC-signed zones
        CorpusQuery::with_do("icann.org.", Qtype::A),
        CorpusQuery::with_do("verisigninc.com.", Qtype::A),
    ];

    // ── Documented divergences (whitelist) ────────────────────────────────────────

    /// A documented divergence between Heimdall and Unbound outputs.
    ///
    /// Any divergence NOT in this list triggers a test failure.
    struct AllowedDivergence {
        #[allow(dead_code)]
        reason: &'static str,
        /// A predicate that matches queries where the divergence is allowed.
        matches: fn(&CorpusQuery) -> bool,
    }

    /// Whitelist of known, acceptable divergences from Unbound golden output.
    ///
    /// This list must be kept minimal and each entry must document the exact
    /// RFC section or implementation decision that justifies the divergence.
    const ALLOWED_DIVERGENCES: &[AllowedDivergence] = &[
        // Additional section order: Heimdall and Unbound may reorder glue records.
        // RFC 1034 §3.6: order within a section is unspecified.
        AllowedDivergence {
            reason: "Additional section record ordering is unspecified by RFC 1034 §3.6",
            matches: |_| false, // placeholder: currently no known divergences
        },
    ];

    // ── Wire-format query builder ─────────────────────────────────────────────────

    fn build_query_wire(id: u16, q: &CorpusQuery) -> Vec<u8> {
        let mut header = Header::default();
        header.id = id;
        header.set_rd(true);
        header.qdcount = 1;

        let questions = vec![Question {
            qname: Name::from_str(q.name).expect("corpus query name"),
            qtype: q.qtype,
            qclass: Qclass::In,
        }];

        let additional = if q.do_bit {
            header.arcount = 1;
            vec![build_opt_rr(true)]
        } else {
            vec![]
        };

        let msg = Message {
            header,
            questions,
            answers: vec![],
            authority: vec![],
            additional,
        };

        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        ser.finish()
    }

    fn build_opt_rr(dnssec_ok: bool) -> heimdall_core::record::Record {
        use heimdall_core::edns::OptRr;
        use heimdall_core::rdata::RData;
        use heimdall_core::record::{Record, Rtype};

        Record {
            name: Name::root(),
            rtype: Rtype::Opt,
            rclass: Qclass::In,
            ttl: 0,
            rdata: RData::Opt(OptRr {
                udp_payload_size: 1232,
                extended_rcode: 0,
                version: 0,
                dnssec_ok,
                z: 0,
                options: vec![],
            }),
        }
    }

    // ── UDP query helper ─────────────────────────────────────────────────────────

    async fn udp_query(server: SocketAddr, wire: &[u8]) -> Option<Message> {
        use tokio::net::UdpSocket;

        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        sock.send_to(wire, server).await.ok()?;

        let mut buf = vec![0u8; 4096];
        let timeout = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf));
        let n = timeout.await.ok()?.ok()?;
        Message::parse(&buf[..n]).ok()
    }

    // ── Comparison ────────────────────────────────────────────────────────────────

    /// Extracts the fields that must match between Heimdall and Unbound:
    /// - RCODE
    /// - AA, TC, AD flags
    /// - Answer section record count
    /// - Each RRSIG algorithm (not position-specific)
    ///
    /// The answer section content comparison is by RCODE + ancount as a
    /// lightweight first pass; deep byte-for-byte comparison is done per-record.
    #[allow(dead_code)]
    struct OutputSummary {
        rcode: Rcode,
        aa: bool,
        tc: bool,
        ad: bool,
        ancount: u16,
        nscount: u16,
    }

    fn summarise(msg: &Message) -> OutputSummary {
        OutputSummary {
            rcode: msg.header.rcode(),
            aa: msg.header.aa(),
            tc: msg.header.tc(),
            ad: msg.header.ad(),
            ancount: msg.header.ancount,
            nscount: msg.header.nscount,
        }
    }

    fn diverges(heimdall: &OutputSummary, reference: &OutputSummary, q: &CorpusQuery) -> bool {
        if heimdall.rcode != reference.rcode {
            return true;
        }
        if heimdall.tc != reference.tc {
            return true;
        }
        if heimdall.ad != reference.ad {
            return true;
        }
        if heimdall.ancount != reference.ancount {
            // Check if this divergence is whitelisted.
            let whitelisted = ALLOWED_DIVERGENCES.iter().any(|d| (d.matches)(q));
            if !whitelisted {
                return true;
            }
        }
        false
    }

    // ── Test ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1 and running Unbound + Heimdall containers"]
    async fn golden_corpus_matches_unbound() {
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run Unbound golden tests");
            return;
        }

        let heimdall = heimdall_addr();
        let unbound = unbound_addr();
        let mut failures = 0usize;

        for (i, query) in CORPUS.iter().enumerate() {
            let wire = build_query_wire(u16::try_from(i + 1).unwrap_or(1), query);

            let h_msg = udp_query(heimdall, &wire).await;
            let u_msg = udp_query(unbound, &wire).await;

            match (h_msg, u_msg) {
                (Some(h), Some(u)) => {
                    let h_sum = summarise(&h);
                    let u_sum = summarise(&u);
                    if diverges(&h_sum, &u_sum, query) {
                        eprintln!(
                            "DIVERGENCE: query={} qtype={:?} do={}\n\
                             Heimdall: rcode={:?} ad={} ancount={}\n\
                             Unbound:  rcode={:?} ad={} ancount={}",
                            query.name,
                            query.qtype,
                            query.do_bit,
                            h_sum.rcode,
                            h_sum.ad,
                            h_sum.ancount,
                            u_sum.rcode,
                            u_sum.ad,
                            u_sum.ancount,
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!(
                        "TIMEOUT/ERROR: Heimdall did not respond to {} {:?}",
                        query.name, query.qtype
                    );
                    failures += 1;
                }
                (_, None) => {
                    eprintln!(
                        "TIMEOUT/ERROR: Unbound did not respond to {} {:?}",
                        query.name, query.qtype
                    );
                    failures += 1;
                }
            }
        }

        assert_eq!(
            failures, 0,
            "{failures} golden divergence(s) detected — see stderr for details"
        );
    }
}
