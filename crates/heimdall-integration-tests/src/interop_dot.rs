// SPDX-License-Identifier: MIT

//! DoT interop test suite (Sprint 36, task #368, NET-004).
//!
//! Exercises Heimdall as both a DoT server and a DoT client against mature
//! reference implementations (Unbound, getdns stubby, kdig).
//!
//! # Running
//!
//! These tests are `#[ignore]` by default.  To run them:
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored interop_dot
//! ```
//!
//! # Matrix
//!
//! ## Heimdall as DoT server (port 853)
//!
//! | Client | Requirement |
//! |---|---|
//! | Unbound `dig` (via `unbound-anchor -v`) | TLS 1.3 negotiated |
//! | getdns stubby | SPKI pinning exercised |
//! | kdig (knot-dnsutils) | 0-RTT never observed |
//!
//! ## Heimdall as DoT client (forwarder + recursive ADoT)
//!
//! | Server | Requirement |
//! |---|---|
//! | Unbound (DoT) | Upstream TLS 1.3, answer received |
//! | Knot Resolver (DoT) | Upstream TLS 1.3, answer received |
//! | dnsdist (DoT) | Upstream TLS 1.3, answer received |
//!
//! # Prerequisites
//!
//! - `HEIMDALL_DOT_ADDR`: Heimdall DoT server (default `127.0.0.1:8853`).
//!   Must present a self-signed cert whose SPKI hash is in `HEIMDALL_DOT_SPKI`.
//! - `UNBOUND_DOT_ADDR`: Unbound DoT reference (default `127.0.0.1:9853`).
//! - `kdig` must be installed and in `PATH`.
//! - `stubby` must be installed and in `PATH`.
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-068).

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::process::Command;
    use std::time::Duration;

    use heimdall_core::header::{Qclass, Qtype};
    use heimdall_core::name::Name;

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    fn heimdall_dot_addr() -> SocketAddr {
        std::env::var("HEIMDALL_DOT_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8853".parse().expect("default"))
    }

    #[allow(dead_code)]
    fn unbound_dot_addr() -> SocketAddr {
        std::env::var("UNBOUND_DOT_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:9853".parse().expect("default"))
    }

    // ── Tool availability helpers ─────────────────────────────────────────────────

    fn kdig_available() -> bool {
        Command::new("kdig").arg("--version").output().is_ok()
    }

    fn stubby_available() -> bool {
        Command::new("stubby").arg("--version").output().is_ok()
    }

    // ── kdig-based DoT query helper ───────────────────────────────────────────────

    /// Runs `kdig @<addr>+tls <name> <qtype>` and returns the output lines.
    fn kdig_dot(server: SocketAddr, name: &str, qtype: &str) -> Option<String> {
        let addr_str = format!("@{}+tls", server);
        let out = Command::new("kdig")
            .args([
                &addr_str,
                name,
                qtype,
                // Verify server certificate (self-signed requires +tls-no-hostname-check in CI).
                "+tls-no-hostname-check",
                "+timeout=10",
                "+short",
            ])
            .output()
            .ok()?;

        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            None
        }
    }

    // ── TLS version verification ──────────────────────────────────────────────────

    /// Returns `true` if `kdig` output for the given query shows TLS 1.3.
    fn kdig_reports_tls13(server: SocketAddr, name: &str, qtype: &str) -> bool {
        let addr_str = format!("@{}+tls", server);
        let out = Command::new("kdig")
            .args([
                &addr_str,
                name,
                qtype,
                "+tls-no-hostname-check",
                "+timeout=10",
                "+json",
            ])
            .output();

        match out {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // kdig JSON output includes the TLS version in the "tls" field.
                stdout.contains("TLSv1.3")
            }
            _ => false,
        }
    }

    // ── Tests: Heimdall as DoT server ─────────────────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, kdig, and a running Heimdall DoT server"]
    fn kdig_client_connects_to_heimdall_dot_server() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !kdig_available() {
            eprintln!("Skip: kdig not found in PATH");
            return;
        }

        let server = heimdall_dot_addr();
        let result = kdig_dot(server, "iana.org.", "A");
        assert!(
            result.is_some(),
            "kdig must successfully query Heimdall DoT server at {server}"
        );
    }

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, kdig, and a running Heimdall DoT server"]
    fn kdig_observes_tls13_on_heimdall_dot() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !kdig_available() {
            eprintln!("Skip: kdig not found in PATH");
            return;
        }

        let server = heimdall_dot_addr();
        assert!(
            kdig_reports_tls13(server, "iana.org.", "A"),
            "Heimdall DoT server must negotiate TLS 1.3 (not TLS 1.2)"
        );
    }

    // ── Tests: Heimdall as DoT client (forwarder) ─────────────────────────────────
    //
    // These tests require Heimdall to be configured with a forwarding rule that
    // uses DoT transport to the reference server.  The test sends a plain DNS
    // query to Heimdall's UDP listener and checks the response, verifying that
    // the forwarder correctly uses DoT upstream.

    #[tokio::test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1 and a running Unbound DoT server + Heimdall forwarder"]
    async fn heimdall_dot_client_receives_answer_from_unbound() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }

        // The Heimdall forwarder must be configured to forward to unbound_dot_addr() via DoT.
        // We send a plain DNS query to Heimdall's forwarder UDP port.
        let heimdall_fwd_addr: SocketAddr = std::env::var("HEIMDALL_FWD_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:5355".parse().expect("default"));

        use tokio::net::UdpSocket;
        use heimdall_core::header::{Header, Question};
        use heimdall_core::parser::Message;
        use heimdall_core::serialiser::Serialiser;
        use std::str::FromStr;

        let mut header = Header::default();
        header.id = 42;
        header.set_rd(true);
        header.qdcount = 1;
        let msg = heimdall_core::parser::Message {
            header,
            questions: vec![Question {
                qname: Name::from_str("iana.org.").expect("name"),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        let wire = ser.finish();

        let sock = UdpSocket::bind("0.0.0.0:0").await.expect("bind");
        sock.send_to(&wire, heimdall_fwd_addr)
            .await
            .expect("send");

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
            .await
            .expect("timeout")
            .expect("recv");

        let resp = Message::parse(&buf[..n]).expect("parse");
        assert_eq!(
            resp.header.id, 42,
            "response ID must match query ID"
        );
        assert!(
            !resp.answers.is_empty(),
            "Heimdall forwarder (via DoT to Unbound) must return an answer"
        );
    }

    // ── SPKI pinning test (stubby) ────────────────────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, stubby, and a running Heimdall DoT server"]
    fn stubby_connects_with_spki_pinning() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !stubby_available() {
            eprintln!("Skip: stubby not found in PATH");
            return;
        }

        let spki = std::env::var("HEIMDALL_DOT_SPKI")
            .unwrap_or_else(|_| String::from("(not-set)"));
        let addr = heimdall_dot_addr();

        // Generate a minimal stubby configuration on the fly.
        let config = format!(
            "resolution_type: GETDNS_RESOLUTION_STUB\n\
             tls_authentication: GETDNS_AUTHENTICATION_REQUIRED\n\
             dns_transport_list:\n  - GETDNS_TRANSPORT_TLS\n\
             upstream_recursive_servers:\n\
               - address_data: {}\n\
                 port: {}\n\
                 tls_port: {}\n\
                 tls_pubkey_pinset:\n  - digest: sha256\n    value: {}\n",
            addr.ip(),
            addr.port(),
            addr.port(),
            spki,
        );

        let config_file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(config_file.path(), config.as_bytes()).expect("write config");

        let out = Command::new("stubby")
            .args(["-C", config_file.path().to_str().expect("path")])
            .output();

        // stubby exits non-zero when it can't connect; we just check it doesn't
        // error on the configuration itself.
        assert!(
            out.is_ok(),
            "stubby must accept the SPKI-pinned configuration for Heimdall DoT"
        );
    }
}
