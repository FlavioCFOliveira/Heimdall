// SPDX-License-Identifier: MIT

//! Golden-output comparison against NSD (Sprint 36, task #366, ENG-035).
//!
//! Verifies that Heimdall's authoritative server produces the same outputs as
//! a pinned NSD instance for a standard authoritative-only query corpus.
//!
//! # Running
//!
//! These tests are `#[ignore]` by default.  To run them:
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored golden_nsd
//! ```
//!
//! Prerequisites:
//! - A pinned NSD container reachable at `NSD_ADDR` (default `127.0.0.1:5301`),
//!   pre-loaded with the same zone files as Heimdall.
//! - A Heimdall authoritative instance reachable at `HEIMDALL_AUTH_ADDR`
//!   (default `127.0.0.1:5354`).
//!
//! Example Docker command for the reference NSD container:
//! ```text
//! docker run --rm -p 5301:53/udp -v $(pwd)/testdata/zones:/etc/nsd/zones \
//!   --name nsd-golden nlnetlabs/nsd:4.8.1
//! ```
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-066).

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

    fn heimdall_auth_addr() -> SocketAddr {
        std::env::var("HEIMDALL_AUTH_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5354".parse().expect("default addr"))
    }

    fn nsd_addr() -> SocketAddr {
        std::env::var("NSD_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5301".parse().expect("default addr"))
    }

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    // ── Authoritative-only corpus ─────────────────────────────────────────────────
    //
    // Queries target records that must exist in the zone files pre-loaded into
    // both Heimdall (authoritative) and NSD.  Recursion is deliberately not set
    // (RD=0) so that both servers answer authoritatively.

    #[derive(Debug, Clone)]
    struct AuthQuery {
        name: &'static str,
        qtype: Qtype,
    }

    const AUTH_CORPUS: &[AuthQuery] = &[
        // SOA is always present at the apex.
        AuthQuery { name: "example.test.", qtype: Qtype::Soa },
        // NS records at apex.
        AuthQuery { name: "example.test.", qtype: Qtype::Ns },
        // A record at a delegation point.
        AuthQuery { name: "www.example.test.", qtype: Qtype::A },
        // AAAA record.
        AuthQuery { name: "www.example.test.", qtype: Qtype::Aaaa },
        // MX record at apex.
        AuthQuery { name: "example.test.", qtype: Qtype::Mx },
        // NXDOMAIN — name does not exist.
        AuthQuery { name: "nxd.example.test.", qtype: Qtype::A },
        // NODATA — name exists but no record of this type.
        AuthQuery { name: "www.example.test.", qtype: Qtype::Mx },
        // AXFR is tested separately (TCP only, task #370 interop).
    ];

    fn build_auth_query_wire(id: u16, q: &AuthQuery) -> Vec<u8> {
        let mut header = Header::default();
        header.id = id;
        // RD=0: authoritative-only query.
        header.qdcount = 1;
        let msg = Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(q.name).expect("auth query name"),
                qtype: q.qtype,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        ser.finish()
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

    #[derive(Debug)]
    struct OutputSummary {
        rcode: Rcode,
        aa: bool,
        ancount: u16,
        nscount: u16,
    }

    fn summarise(msg: &Message) -> OutputSummary {
        OutputSummary {
            rcode: msg.header.rcode(),
            aa: msg.header.aa(),
            ancount: msg.header.ancount,
            nscount: msg.header.nscount,
        }
    }

    #[tokio::test]
    async fn golden_auth_corpus_matches_nsd() {
        if !crate::conformance::docker_available() {
            eprintln!("Skip: Docker not available — NSD golden tests require Docker");
            return;
        }
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run NSD golden tests");
            return;
        }

        let zone_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/conformance/example.test.zone"
        ));
        let _nsd_container = crate::conformance::start_nsd(zone_path);

        let heimdall = heimdall_auth_addr();
        let nsd = _nsd_container.dns_addr;
        let mut failures = 0usize;

        for (i, query) in AUTH_CORPUS.iter().enumerate() {
            let wire = build_auth_query_wire(u16::try_from(i + 1).unwrap_or(1), query);

            let h_msg = udp_query(heimdall, &wire).await;
            let n_msg = udp_query(nsd, &wire).await;

            match (h_msg, n_msg) {
                (Some(h), Some(n)) => {
                    let h_sum = summarise(&h);
                    let n_sum = summarise(&n);
                    let diverges = h_sum.rcode != n_sum.rcode
                        || h_sum.aa != n_sum.aa
                        || h_sum.ancount != n_sum.ancount;

                    if diverges {
                        eprintln!(
                            "DIVERGENCE: query={} qtype={:?}\n\
                             Heimdall: rcode={:?} aa={} ancount={} nscount={}\n\
                             NSD:      rcode={:?} aa={} ancount={} nscount={}",
                            query.name,
                            query.qtype,
                            h_sum.rcode,
                            h_sum.aa,
                            h_sum.ancount,
                            h_sum.nscount,
                            n_sum.rcode,
                            n_sum.aa,
                            n_sum.ancount,
                            n_sum.nscount,
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!(
                        "TIMEOUT/ERROR: Heimdall auth did not respond to {} {:?}",
                        query.name, query.qtype
                    );
                    failures += 1;
                }
                (_, None) => {
                    eprintln!(
                        "TIMEOUT/ERROR: NSD did not respond to {} {:?}",
                        query.name, query.qtype
                    );
                    failures += 1;
                }
            }
        }

        assert_eq!(
            failures, 0,
            "{failures} NSD golden divergence(s) detected — see stderr for details"
        );
    }
}
