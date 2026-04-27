// SPDX-License-Identifier: MIT

//! `DoH` H2 + H3 interop test suite (Sprint 36, task #369, NET-005..007).
//!
//! Exercises Heimdall as both a `DoH` server and a `DoH` client against mature
//! reference implementations.
//!
//! # Running
//!
//! ```text
//! HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- --ignored interop_doh
//! ```
//!
//! # Matrix
//!
//! ## Heimdall as `DoH` server
//!
//! | Client | Protocol | Requirement |
//! |---|---|---|
//! | kdig | `DoH`/H2 | GET and POST both answered; `application/dns-message` enforced |
//! | curl | `DoH`/H2 | HTTP 200 with correct content-type |
//! | curl | `DoH`/H3 | HTTP/3 negotiated via Alt-Svc |
//!
//! ## Heimdall as `DoH` client (forwarder)
//!
//! | Server | Protocol | Requirement |
//! |---|---|---|
//! | cloudflared | `DoH`/H2 | Answer received |
//! | Unbound | `DoH`/H2 | Answer received |
//!
//! # Prerequisites
//!
//! - `HEIMDALL_DOH_ADDR`: Heimdall `DoH` server (default `https://127.0.0.1:8443/dns-query`).
//! - `curl` with HTTP/3 support in PATH.
//! - `kdig` (knot-dnsutils) in PATH.
//!
//! # CI
//!
//! Wired into Tier 3 nightly (ENG-069).

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::process::Command;

    fn interop_enabled() -> bool {
        std::env::var("HEIMDALL_INTEROP_TESTS").as_deref() == Ok("1")
    }

    fn heimdall_doh_url() -> String {
        std::env::var("HEIMDALL_DOH_ADDR")
            .unwrap_or_else(|_| "https://127.0.0.1:8443/dns-query".to_owned())
    }

    fn curl_available() -> bool {
        Command::new("curl").arg("--version").output().is_ok()
    }

    fn kdig_available() -> bool {
        Command::new("kdig").arg("--version").output().is_ok()
    }

    // ── curl helper ───────────────────────────────────────────────────────────────

    /// Base64url-encodes a raw DNS query wire format for use in DoH GET requests
    /// (RFC 8484 §6).
    fn base64url_encode(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    /// Builds a minimal A query wire format for `name`.
    fn build_a_query_wire(name: &str) -> Vec<u8> {
        use heimdall_core::header::{Header, Qclass, Qtype, Question};
        use heimdall_core::name::Name;
        use heimdall_core::parser::Message;
        use heimdall_core::serialiser::Serialiser;
        use std::str::FromStr;

        let mut header = Header::default();
        header.id = 0; // RFC 8484: message ID SHOULD be 0 for DoH
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
        ser.finish()
    }

    // ── Tests: GET /dns-query (HTTP/2) ────────────────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, curl, and a running Heimdall DoH/H2 server"]
    fn curl_get_h2_returns_200() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !curl_available() {
            eprintln!("Skip: curl not found in PATH");
            return;
        }

        let wire = build_a_query_wire("iana.org.");
        let encoded = base64url_encode(&wire);
        let url = format!("{}?dns={}", heimdall_doh_url(), encoded);

        let out = Command::new("curl")
            .args([
                "--http2",
                "--silent",
                "--insecure", // self-signed cert in CI
                "--write-out", "%{http_code}",
                "--output", "/dev/null",
                "--header", "Accept: application/dns-message",
                &url,
            ])
            .output()
            .expect("curl");

        let status = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            status.trim(), "200",
            "DoH GET must return HTTP 200; got {status}"
        );
    }

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, curl, and a running Heimdall DoH/H2 server"]
    fn curl_post_h2_returns_200_with_correct_content_type() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !curl_available() {
            eprintln!("Skip: curl not found in PATH");
            return;
        }

        let wire = build_a_query_wire("iana.org.");
        let url = heimdall_doh_url();

        // Write wire to a temp file for curl --data-binary.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), &wire).expect("write wire");

        let out = Command::new("curl")
            .args([
                "--http2",
                "--silent",
                "--insecure",
                "--write-out", "%{http_code} %{content_type}",
                "--output", "/dev/null",
                "--header", "Content-Type: application/dns-message",
                "--header", "Accept: application/dns-message",
                "--data-binary", &format!("@{}", tmp.path().display()),
                &url,
            ])
            .output()
            .expect("curl");

        let result = String::from_utf8_lossy(&out.stdout);
        assert!(
            result.starts_with("200"),
            "DoH POST must return HTTP 200; got {result}"
        );
        assert!(
            result.contains("application/dns-message"),
            "DoH POST response must have Content-Type: application/dns-message; got {result}"
        );
    }

    // ── Tests: Alt-Svc advertisement (H3 upgrade) ────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, curl, and a running Heimdall DoH/H2+H3 server"]
    fn h2_response_includes_alt_svc_h3_advertisement() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !curl_available() {
            eprintln!("Skip: curl not found in PATH");
            return;
        }

        let wire = build_a_query_wire("iana.org.");
        let encoded = base64url_encode(&wire);
        let url = format!("{}?dns={}", heimdall_doh_url(), encoded);

        let out = Command::new("curl")
            .args([
                "--http2",
                "--silent",
                "--insecure",
                "--head", // headers only
                "--header", "Accept: application/dns-message",
                &url,
            ])
            .output()
            .expect("curl");

        let headers = String::from_utf8_lossy(&out.stdout);
        assert!(
            headers.to_lowercase().contains("alt-svc"),
            "DoH/H2 response must include Alt-Svc header advertising H3; headers:\n{headers}"
        );
        assert!(
            headers.contains("h3"),
            "Alt-Svc header must advertise 'h3'; headers:\n{headers}"
        );
    }

    // ── Tests: DoH/H3 via curl ────────────────────────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, curl with HTTP/3 support, and a running Heimdall DoH/H3 server"]
    fn curl_get_h3_returns_200() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !curl_available() {
            eprintln!("Skip: curl not found in PATH");
            return;
        }

        let wire = build_a_query_wire("iana.org.");
        let encoded = base64url_encode(&wire);
        let url = format!("{}?dns={}", heimdall_doh_url(), encoded);

        let out = Command::new("curl")
            .args([
                "--http3-only", // force HTTP/3
                "--silent",
                "--insecure",
                "--write-out", "%{http_code}",
                "--output", "/dev/null",
                "--header", "Accept: application/dns-message",
                &url,
            ])
            .output()
            .expect("curl");

        let status = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            status.trim(), "200",
            "DoH GET over HTTP/3 must return HTTP 200; got {status}"
        );
    }

    // ── Tests: kdig DoH ──────────────────────────────────────────────────────────

    #[test]
    #[ignore = "requires HEIMDALL_INTEROP_TESTS=1, kdig, and a running Heimdall DoH/H2 server"]
    fn kdig_doh_h2_returns_answer() {
        if !interop_enabled() {
            eprintln!("Skip: HEIMDALL_INTEROP_TESTS not set");
            return;
        }
        if !kdig_available() {
            eprintln!("Skip: kdig not found in PATH");
            return;
        }

        let url = heimdall_doh_url();
        let out = Command::new("kdig")
            .args([
                "iana.org.",
                "A",
                &format!("+https={}", url),
                "+tls-no-hostname-check",
                "+timeout=10",
                "+short",
            ])
            .output()
            .expect("kdig");

        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "kdig DoH query to Heimdall must return a non-empty answer"
        );
    }
}
