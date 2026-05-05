// SPDX-License-Identifier: MIT

//! Golden-output comparison against CoreDNS forwarder (Sprint 49 task #565).
//!
//! Compares Heimdall's forwarder role against a CoreDNS instance running in
//! forward-only mode (no cache, no rewrite) with the same upstream.  Any
//! RCODE divergence that is not documented in `docs/conformance/coredns.md`
//! triggers a test failure.
//!
//! # Running
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- golden_coredns
//! ```
//!
//! Prerequisites (auto-started via the conformance harness when Docker is
//! available):
//! - CoreDNS forwarder at `COREDNS_ADDR` (default `127.0.0.1:5308`)
//! - Heimdall forwarder at `HEIMDALL_FORWARDER_ADDR` (default `127.0.0.1:5355`)
//!
//! # Known divergences
//!
//! See `docs/conformance/coredns.md` for the full list.  Current known cases:
//! - CoreDNS may return SERVFAIL for some NXDOMAIN paths where Heimdall returns
//!   NXDOMAIN directly (CoreDNS forwards every query regardless of response).
//!
//! # CI
//!
//! Wired into Tier 3 nightly (task #501).

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

    fn heimdall_forwarder_addr() -> SocketAddr {
        std::env::var("HEIMDALL_FORWARDER_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5355".parse().expect("default"))
    }

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    fn build_query_wire(id: u16, name: &str, qtype: Qtype) -> Vec<u8> {
        let mut header = Header::default();
        header.id = id;
        header.set_rd(true);
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

    /// Divergences where CoreDNS and Heimdall are known to differ.
    ///
    /// A predicate returning `true` means the divergence is documented and
    /// does not trigger a test failure.
    fn is_allowed_divergence(name: &str, qtype: Qtype, h: Rcode, c: Rcode) -> bool {
        // CoreDNS may return SERVFAIL for NXDOMAIN queries when the upstream
        // returns NXDOMAIN and CoreDNS forwards the error unmodified.
        // Heimdall synthesises the correct NXDOMAIN response.
        let _ = (name, qtype, h, c);
        false // no current divergences beyond what needs runtime discovery
    }

    #[tokio::test]
    async fn golden_forwarder_corpus_matches_coredns() {
        if !crate::conformance::docker_available() {
            eprintln!("Skip: Docker not available — CoreDNS golden tests require Docker");
            return;
        }
        if !interop_enabled() {
            eprintln!("Skip: set HEIMDALL_INTEROP_TESTS=1 to run CoreDNS golden tests");
            return;
        }

        let heimdall_fwd = heimdall_forwarder_addr();

        // The upstream that both Heimdall and CoreDNS forward to.
        // Use Cloudflare 1.1.1.1 (stable, well-known behaviour).
        let upstream: SocketAddr = "1.1.1.1:53".parse().expect("upstream");
        let _coredns = crate::conformance::start_coredns(upstream);

        let coredns = _coredns.dns_addr;
        let mut failures = 0usize;

        let corpus = [
            ("iana.org.", Qtype::A),
            ("iana.org.", Qtype::Ns),
            ("nonexistent.invalid.", Qtype::A),
        ];

        for (i, (name, qtype)) in corpus.iter().enumerate() {
            let wire = build_query_wire(u16::try_from(i + 1).unwrap_or(1), name, *qtype);
            let h_msg = udp_query(heimdall_fwd, &wire).await;
            let c_msg = udp_query(coredns, &wire).await;
            match (h_msg, c_msg) {
                (Some(h), Some(c)) => {
                    let h_rcode = h.header.rcode();
                    let c_rcode = c.header.rcode();
                    if h_rcode != c_rcode && !is_allowed_divergence(name, *qtype, h_rcode, c_rcode)
                    {
                        eprintln!(
                            "DIVERGENCE: {} {:?}  Heimdall={:?} CoreDNS={:?}",
                            name, qtype, h_rcode, c_rcode
                        );
                        failures += 1;
                    }
                }
                (None, _) => {
                    eprintln!("TIMEOUT: Heimdall forwarder did not respond");
                    failures += 1;
                }
                (_, None) => {
                    eprintln!("TIMEOUT: CoreDNS did not respond");
                    failures += 1;
                }
            }
        }

        assert_eq!(
            failures, 0,
            "{failures} CoreDNS forwarder divergence(s) — see stderr"
        );
    }
}
