// SPDX-License-Identifier: MIT

//! Golden-output comparison against Knot DNS (Sprint 36, task #367, ENG-035).
//!
//! Extends the golden comparison to Knot, which acts as both an authoritative
//! server and a resolver.  Knot is a third reference that catches divergences
//! Unbound and NSD do not.
//!
//! # Running
//!
//! These tests are `#[ignore]` by default.  To run them:
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored golden_knot
//! ```
//!
//! Prerequisites:
//! - A pinned Knot Resolver container (for recursive comparison) at
//!   `KNOT_RESOLVER_ADDR` (default `127.0.0.1:5302`).
//! - A pinned Knot DNS container (for authoritative comparison) at
//!   `KNOT_AUTH_ADDR` (default `127.0.0.1:5303`).
//! - A Heimdall recursive instance at `HEIMDALL_ADDR` (default `127.0.0.1:5353`).
//! - A Heimdall authoritative instance at `HEIMDALL_AUTH_ADDR`
//!   (default `127.0.0.1:5354`).
//!
//! Example Docker commands:
//! ```text
//! # Knot Resolver 5.7.4 (recursive)
//! docker run --rm -p 5302:53/udp --name knot-resolver cznic/knot-resolver:5.7.4
//!
//! # Knot DNS 3.3.7 (authoritative)
//! docker run --rm -p 5303:53/udp -v $(pwd)/testdata/zones:/storage \
//!   --name knot-auth cznic/knot:3.3.7
//! ```
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-067).

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use heimdall_core::header::{Header, Qclass, Qtype, Question};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;
    use heimdall_core::serialiser::Serialiser;

    fn heimdall_addr() -> SocketAddr {
        std::env::var("HEIMDALL_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5353".parse().expect("default addr"))
    }

    fn heimdall_auth_addr() -> SocketAddr {
        std::env::var("HEIMDALL_AUTH_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5354".parse().expect("default addr"))
    }

    fn knot_resolver_addr() -> SocketAddr {
        std::env::var("KNOT_RESOLVER_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5302".parse().expect("default addr"))
    }

    fn knot_auth_addr() -> SocketAddr {
        std::env::var("KNOT_AUTH_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5303".parse().expect("default addr"))
    }

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    // ── Corpora ───────────────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct Query {
        name: &'static str,
        qtype: Qtype,
        rd: bool,
        do_bit: bool,
    }

    impl Query {
        const fn recursive(name: &'static str, qtype: Qtype) -> Self {
            Self { name, qtype, rd: true, do_bit: false }
        }
        const fn recursive_do(name: &'static str, qtype: Qtype) -> Self {
            Self { name, qtype, rd: true, do_bit: true }
        }
        const fn auth(name: &'static str, qtype: Qtype) -> Self {
            Self { name, qtype, rd: false, do_bit: false }
        }
    }

    const RECURSIVE_CORPUS: &[Query] = &[
        Query::recursive("iana.org.", Qtype::A),
        Query::recursive("iana.org.", Qtype::Mx),
        Query::recursive_do("iana.org.", Qtype::A),
        Query::recursive("nonexistent.invalid.", Qtype::A),
        Query::recursive_do("icann.org.", Qtype::A),
    ];

    const AUTH_CORPUS: &[Query] = &[
        Query::auth("example.test.", Qtype::Soa),
        Query::auth("example.test.", Qtype::Ns),
        Query::auth("www.example.test.", Qtype::A),
        Query::auth("nxd.example.test.", Qtype::A),
    ];

    fn build_wire(id: u16, q: &Query) -> Vec<u8> {
        let mut header = Header::default();
        header.id = id;
        header.set_rd(q.rd);
        header.qdcount = 1;

        let additional = if q.do_bit {
            header.arcount = 1;
            vec![build_opt_rr()]
        } else {
            vec![]
        };

        let msg = Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(q.name).expect("query name"),
                qtype: q.qtype,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional,
        };

        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        ser.finish()
    }

    fn build_opt_rr() -> heimdall_core::record::Record {
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
                dnssec_ok: true,
                z: 0,
                options: vec![],
            }),
        }
    }

    async fn udp_query(server: SocketAddr, wire: &[u8]) -> Option<Message> {
        use tokio::net::UdpSocket;

        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        sock.send_to(wire, server).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            sock.recv(&mut buf),
        )
        .await
        .ok()?
        .ok()?;
        Message::parse(&buf[..n]).ok()
    }

    async fn run_corpus(
        corpus: &[Query],
        heimdall: SocketAddr,
        reference: SocketAddr,
        ref_name: &str,
    ) -> usize {
        let mut failures = 0usize;

        for (i, q) in corpus.iter().enumerate() {
            let wire = build_wire(u16::try_from(i + 1).unwrap_or(1), q);
            let h_msg = udp_query(heimdall, &wire).await;
            let r_msg = udp_query(reference, &wire).await;

            match (h_msg, r_msg) {
                (Some(h), Some(r)) => {
                    let diverges = h.header.rcode() != r.header.rcode()
                        || h.header.tc() != r.header.tc()
                        || h.header.ad() != r.header.ad()
                        || h.header.ancount != r.header.ancount;

                    if diverges {
                        eprintln!(
                            "DIVERGENCE vs {ref_name}: {} {:?} do={}\n\
                             Heimdall: rcode={:?} ad={} ancount={}\n\
                             {ref_name}: rcode={:?} ad={} ancount={}",
                            q.name,
                            q.qtype,
                            q.do_bit,
                            h.header.rcode(),
                            h.header.ad(),
                            h.header.ancount,
                            r.header.rcode(),
                            r.header.ad(),
                            r.header.ancount,
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!(
                        "TIMEOUT: Heimdall did not respond to {} {:?}",
                        q.name, q.qtype
                    );
                    failures += 1;
                }
                (_, None) => {
                    eprintln!(
                        "TIMEOUT: {ref_name} did not respond to {} {:?}",
                        q.name, q.qtype
                    );
                    failures += 1;
                }
            }
        }

        failures
    }

    #[tokio::test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1 and running Knot Resolver + Heimdall containers"]
    async fn golden_recursive_corpus_matches_knot_resolver() {
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run Knot golden tests");
            return;
        }

        let failures = run_corpus(
            RECURSIVE_CORPUS,
            heimdall_addr(),
            knot_resolver_addr(),
            "Knot-Resolver",
        )
        .await;

        assert_eq!(
            failures, 0,
            "{failures} Knot-Resolver golden divergence(s) detected — see stderr"
        );
    }

    #[tokio::test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1 and running Knot DNS + Heimdall auth containers"]
    async fn golden_auth_corpus_matches_knot_dns() {
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run Knot DNS golden tests");
            return;
        }

        let failures = run_corpus(
            AUTH_CORPUS,
            heimdall_auth_addr(),
            knot_auth_addr(),
            "Knot-DNS",
        )
        .await;

        assert_eq!(
            failures, 0,
            "{failures} Knot-DNS golden divergence(s) detected — see stderr"
        );
    }
}
