// SPDX-License-Identifier: MIT

//! Golden-output comparison against `PowerDNS` (Sprint 49 task #564).
//!
//! Verifies that Heimdall's authoritative and recursive servers produce the
//! same outputs as `PowerDNS` Authoritative (pdns-auth-49) and `PowerDNS`
//! Recursor (pdns-recursor-50) for the standard query corpus.
//!
//! # Running
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- golden_powerdns
//! ```
//!
//! Prerequisites (auto-started via the conformance harness when Docker is
//! available):
//! - `PowerDNS` Authoritative at `PDNS_AUTH_ADDR` (default `127.0.0.1:5306`)
//! - `PowerDNS` Recursor at `PDNS_RECURSOR_ADDR` (default `127.0.0.1:5307`)
//! - Heimdall authoritative at `HEIMDALL_AUTH_ADDR` (default `127.0.0.1:5354`)
//! - Heimdall recursive at `HEIMDALL_ADDR` (default `127.0.0.1:5353`)
//!
//! # CI
//!
//! Wired into Tier 3 nightly (task #501).  Failure on aligned cases blocks
//! Tier 4 release per the conformance-gate job in ci-tier3.yml.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, time::Duration};

    use heimdall_core::{
        header::{Header, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
        serialiser::Serialiser,
    };

    fn heimdall_auth_addr() -> SocketAddr {
        std::env::var("HEIMDALL_AUTH_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5354".parse().expect("default"))
    }

    fn heimdall_addr() -> SocketAddr {
        std::env::var("HEIMDALL_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5353".parse().expect("default"))
    }

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    // ── Authoritative corpus (same as golden_nsd) ─────────────────────────────

    #[derive(Debug, Clone)]
    struct AuthQuery {
        name: &'static str,
        qtype: Qtype,
    }

    const AUTH_CORPUS: &[AuthQuery] = &[
        AuthQuery {
            name: "example.test.",
            qtype: Qtype::Soa,
        },
        AuthQuery {
            name: "example.test.",
            qtype: Qtype::Ns,
        },
        AuthQuery {
            name: "www.example.test.",
            qtype: Qtype::A,
        },
        AuthQuery {
            name: "www.example.test.",
            qtype: Qtype::Aaaa,
        },
        AuthQuery {
            name: "example.test.",
            qtype: Qtype::Mx,
        },
        AuthQuery {
            name: "nxd.example.test.",
            qtype: Qtype::A,
        },
        AuthQuery {
            name: "www.example.test.",
            qtype: Qtype::Mx,
        },
    ];

    fn build_query_wire(id: u16, name: &str, qtype: Qtype, rd: bool) -> Vec<u8> {
        let mut header = Header::default();
        header.id = id;
        header.set_rd(rd);
        header.qdcount = 1;
        let msg = Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(name).expect("name"),
                qtype,
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
        let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        Message::parse(&buf[..n]).ok()
    }

    #[derive(Debug)]
    struct Summary {
        rcode: Rcode,
        aa: bool,
        ancount: u16,
    }

    fn summarise(msg: &Message) -> Summary {
        Summary {
            rcode: msg.header.rcode(),
            aa: msg.header.aa(),
            ancount: msg.header.ancount,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn golden_auth_corpus_matches_powerdns_auth() {
        if !crate::conformance::docker_available() {
            eprintln!("Skip: Docker not available — PowerDNS golden tests require Docker");
            return;
        }
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run PowerDNS golden tests");
            return;
        }

        let zone_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/conformance/example.test.zone"
        ));
        let _pdns_auth = crate::conformance::start_powerdns_auth(zone_path);

        let heimdall = heimdall_auth_addr();
        let pdns = _pdns_auth.dns_addr;
        let mut failures = 0usize;

        for (i, query) in AUTH_CORPUS.iter().enumerate() {
            let wire = build_query_wire(
                u16::try_from(i + 1).unwrap_or(1),
                query.name,
                query.qtype,
                false,
            );
            let h_msg = udp_query(heimdall, &wire).await;
            let p_msg = udp_query(pdns, &wire).await;
            match (h_msg, p_msg) {
                (Some(h), Some(p)) => {
                    let h_s = summarise(&h);
                    let p_s = summarise(&p);
                    if h_s.rcode != p_s.rcode || h_s.aa != p_s.aa || h_s.ancount != p_s.ancount {
                        eprintln!(
                            "DIVERGENCE: {} {:?}  Heimdall={:?}/{}/{} PowerDNS={:?}/{}/{}",
                            query.name,
                            query.qtype,
                            h_s.rcode,
                            h_s.aa,
                            h_s.ancount,
                            p_s.rcode,
                            p_s.aa,
                            p_s.ancount,
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!("TIMEOUT: Heimdall did not respond");
                    failures += 1;
                }
                (_, None) => {
                    eprintln!("TIMEOUT: PowerDNS auth did not respond");
                    failures += 1;
                }
            }
        }

        assert_eq!(
            failures, 0,
            "{failures} PowerDNS auth divergence(s) — see stderr"
        );
    }

    #[tokio::test]
    async fn golden_recursive_corpus_matches_powerdns_recursor() {
        if !crate::conformance::docker_available() {
            eprintln!("Skip: Docker not available — PowerDNS recursor golden tests require Docker");
            return;
        }
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run PowerDNS recursor golden tests");
            return;
        }

        let _pdns_rec = crate::conformance::start_powerdns_recursor();

        let heimdall = heimdall_addr();
        let pdns = _pdns_rec.dns_addr;
        let mut failures = 0usize;

        // A small corpus of stable internet zones for recursive comparison.
        let corpus = [
            ("iana.org.", Qtype::Ns),
            ("iana.org.", Qtype::A),
            ("nonexistent.invalid.", Qtype::A), // NXDOMAIN
        ];

        for (i, (name, qtype)) in corpus.iter().enumerate() {
            let wire = build_query_wire(u16::try_from(i + 1).unwrap_or(1), name, *qtype, true);
            let h_msg = udp_query(heimdall, &wire).await;
            let p_msg = udp_query(pdns, &wire).await;
            match (h_msg, p_msg) {
                (Some(h), Some(p)) => {
                    if h.header.rcode() != p.header.rcode() {
                        eprintln!(
                            "DIVERGENCE: {} {:?}  Heimdall={:?} PowerDNS={:?}",
                            name,
                            qtype,
                            h.header.rcode(),
                            p.header.rcode()
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!("TIMEOUT: Heimdall did not respond");
                    failures += 1;
                }
                (_, None) => {
                    eprintln!("TIMEOUT: PowerDNS recursor did not respond");
                    failures += 1;
                }
            }
        }

        assert_eq!(
            failures, 0,
            "{failures} PowerDNS recursor divergence(s) — see stderr"
        );
    }
}
