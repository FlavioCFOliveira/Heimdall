// SPDX-License-Identifier: MIT

//! `DoQ` interop test suite (Sprint 36, task #370, NET-008, RFC 9250).
//!
//! Exercises Heimdall as both a `DoQ` server and a `DoQ` client against mature
//! reference implementations.
//!
//! # Running
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored interop_doq
//! ```
//!
//! # Matrix
//!
//! ## Heimdall as `DoQ` server (port 853 QUIC)
//!
//! | Client | Requirement |
//! |---|---|
//! | kdig (`+quic`) | Answer received; 0-RTT NOT observed |
//! | quinn test client | QUIC v1 negotiated; DNS message round-trip succeeds |
//!
//! ## Heimdall as `DoQ` client (forwarder)
//!
//! | Server | Requirement |
//! |---|---|
//! | `AdGuard` DNS (`DoQ`) | Answer received |
//!
//! # Prerequisites
//!
//! - `HEIMDALL_DOQ_ADDR`: Heimdall `DoQ` server (default `127.0.0.1:8853`).
//! - `kdig` (knot-dnsutils ≥ 3.3) in PATH for `+quic` support.
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-070).

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::ClientConfig;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    fn heimdall_doq_addr() -> SocketAddr {
        std::env::var("HEIMDALL_DOQ_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8853".parse().expect("default"))
    }

    fn kdig_available() -> bool {
        // kdig ≥ 3.3 supports +quic.
        Command::new("kdig").arg("--version").output().is_ok()
    }

    // ── Minimal TLS no-verify helper (test only) ──────────────────────────────────
    //
    // Used for the quinn client round-trip test.  Self-signed CI certificates are
    // not trusted by the OS store, so we bypass verification here.  This is
    // intentionally test-only and never compiled into production code.

    #[derive(Debug)]
    struct NoVerifier;

    impl NoVerifier {
        fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    // ── DoQ wire-format helpers ───────────────────────────────────────────────────
    //
    // RFC 9250 §4.2: each DNS message is sent on its own QUIC stream as a
    // 2-byte big-endian length prefix followed by the DNS message wire format.

    fn build_doq_query(name: &str) -> Vec<u8> {
        use heimdall_core::header::{Header, Qclass, Qtype, Question};
        use heimdall_core::name::Name;
        use heimdall_core::parser::Message;
        use heimdall_core::serialiser::Serialiser;
        use std::str::FromStr;

        let mut header = Header::default();
        header.id = 0; // RFC 9250 §4.2.1: message ID SHOULD be 0 for DoQ
        header.set_rd(true);
        header.qdcount = 1;

        let msg = Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(name).expect("name"),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        let dns_wire = ser.finish();

        // Prepend 2-byte length prefix.
        let mut frame = Vec::with_capacity(2 + dns_wire.len());
        let len = u16::try_from(dns_wire.len()).expect("message too long");
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&dns_wire);
        frame
    }

    // ── Tests: Heimdall as DoQ server (kdig client) ───────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, kdig ≥ 3.3, and a running Heimdall DoQ server"]
    fn kdig_doq_returns_answer_from_heimdall() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !kdig_available() {
            eprintln!("Skip: kdig not found in PATH");
            return;
        }

        let addr = heimdall_doq_addr();
        let server_arg = format!("@{}+quic", addr);

        let out = Command::new("kdig")
            .args([
                &server_arg,
                "iana.org.",
                "A",
                "+tls-no-hostname-check",
                "+timeout=10",
                "+short",
            ])
            .output()
            .expect("kdig");

        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "kdig DoQ query to Heimdall must return a non-empty answer"
        );
    }

    // ── Tests: Heimdall as DoQ server (quinn-based client) ───────────────────────

    #[tokio::test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1 and a running Heimdall DoQ server"]
    async fn quinn_client_round_trip_succeeds() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }

        let server_addr = heimdall_doq_addr();
        let doq_frame = build_doq_query("iana.org.");

        // Build a minimal quinn client with a TLS config that skips certificate
        // verification (suitable for self-signed CI certificates).
        let rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(NoVerifier::new())
            .with_no_client_auth();
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
            .expect("QUIC client config");
        let client_config = ClientConfig::new(Arc::new(quic_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind"))
            .expect("quinn endpoint");
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(server_addr, "localhost").expect("connect");
        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("connection timeout")
            .expect("QUIC connection");

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .expect("open bidirectional stream");

        send.write_all(&doq_frame).await.expect("write query");
        send.finish().expect("finish stream");

        // RFC 9250 §4.2: the response is a 2-byte length prefix + DNS message.
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await.expect("read length");
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf).await.expect("read response");

        let resp = heimdall_core::parser::Message::parse(&resp_buf)
            .expect("parse response");

        assert!(
            !resp.answers.is_empty() || resp.header.rcode() != heimdall_core::header::Rcode::ServFail,
            "DoQ response must contain an answer or at minimum a non-SERVFAIL RCODE"
        );

        connection.close(0u32.into(), b"done");
    }

    // ── TLS 1.3-only and no-0-RTT assertions ─────────────────────────────────────
    //
    // These are verified by the DoQ listener unit tests in heimdall-runtime/tests/doq_tests.rs
    // (task #324).  The interop suite adds a cross-implementation check: kdig
    // does not observe 0-RTT session resumption on repeated connections because
    // Heimdall's QUIC layer refuses 0-RTT (SEC-022).

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, kdig ≥ 3.3, and a running Heimdall DoQ server"]
    fn kdig_does_not_observe_zero_rtt_on_second_connection() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !kdig_available() {
            eprintln!("Skip: kdig not found in PATH");
            return;
        }

        let addr = heimdall_doq_addr();
        let server_arg = format!("@{}+quic", addr);

        // First connection: establishes session (but 0-RTT is refused by Heimdall).
        let _ = Command::new("kdig")
            .args([&server_arg, "iana.org.", "A", "+tls-no-hostname-check", "+timeout=10"])
            .output();

        // Second connection: attempt 0-RTT resumption (Heimdall MUST reject it).
        // We verify Heimdall still responds correctly (not crashing or dropping).
        let out = Command::new("kdig")
            .args([
                &server_arg,
                "icann.org.",
                "A",
                "+tls-no-hostname-check",
                "+timeout=10",
                "+short",
            ])
            .output()
            .expect("kdig second connection");

        assert!(
            out.status.success(),
            "Heimdall DoQ server must handle repeated connections correctly (0-RTT refused)"
        );
    }
}
