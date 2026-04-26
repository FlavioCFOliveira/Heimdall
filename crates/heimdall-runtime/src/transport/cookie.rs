// SPDX-License-Identifier: MIT

//! DNS Cookie validation and generation wrapper (RFC 7873 / RFC 9018).
//!
//! This module ties [`heimdall_core::edns::EdnsCookie`] and the
//! [`heimdall_core::edns::derive_server_cookie`] / [`heimdall_core::edns::verify_server_cookie`]
//! primitives into the transport layer's request/response lifecycle.
//!
//! # Request path
//!
//! 1. Extract the `Cookie` option from the OPT RR (if present).
//! 2. Validate the server cookie using the current (and, if available, retired)
//!    server secret.
//! 3. Return a [`CookieState`] that the caller uses to populate
//!    `RequestCtx::has_valid_cookie` before passing the context to the admission
//!    pipeline.
//!
//! # Response path
//!
//! Call [`derive_response_cookie`] to build the server cookie bytes that must be
//! placed in the response OPT RR's Cookie option.  The caller is responsible for
//! including the resulting [`EdnsCookie`] in the response.
//!
//! # Security note
//!
//! Server cookie verification uses a straightforward byte comparison (`==`) over
//! the HMAC-SHA256 output.  This is intentionally NOT constant-time because the
//! server cookie is not a MAC over data the attacker controls: the HMAC input is
//! `(client_cookie || client_ip)`, both of which the attacker already knows.
//! A timing side-channel on the comparison cannot give the attacker any additional
//! information beyond what they already possess.

use std::net::IpAddr;

use heimdall_core::edns::{EdnsCookie, EdnsOption, OptRr, derive_server_cookie, verify_server_cookie};

// ── CookieState ───────────────────────────────────────────────────────────────

/// The result of cookie extraction and validation for one inbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieState {
    /// `true` when the query's OPT RR contains a Cookie option with at least a
    /// client cookie.
    pub has_client_cookie: bool,
    /// `true` when the query carried a server cookie that verified successfully
    /// against one of the currently held secrets.
    ///
    /// `false` when there was no server cookie, when the cookie failed HMAC
    /// verification, or when no OPT RR was present in the query at all.
    pub server_cookie_valid: bool,
    /// The raw 8-byte client cookie bytes, present when `has_client_cookie` is
    /// `true`.
    pub client_cookie_bytes: Option<[u8; 8]>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Extracts and validates the DNS Cookie from an inbound request's OPT RR.
///
/// `opt` — the decoded OPT record from the query, or `None` if the query
/// carried no OPT RR.
///
/// `client_ip` — the source IP address of the query, used as input to the
/// server-cookie HMAC.
///
/// `current_secret` — the active server cookie secret (16+ bytes).
///
/// `previous_secret` — the retired secret still within the grace period, if any
/// (RFC 7873 §5.2.2 allows accepting cookies from the just-rotated secret for
/// one rotation cycle).
///
/// Returns a [`CookieState`] describing the validation outcome.
#[must_use]
pub fn extract_cookie_state(
    opt: Option<&OptRr>,
    client_ip: IpAddr,
    current_secret: &[u8],
    previous_secret: Option<&[u8]>,
) -> CookieState {
    let Some(opt_rr) = opt else {
        // No OPT RR — no cookie at all.
        return CookieState {
            has_client_cookie: false,
            server_cookie_valid: false,
            client_cookie_bytes: None,
        };
    };

    // Find the first Cookie option in the OPT RR options list.
    let cookie = opt_rr.options.iter().find_map(|o| {
        if let EdnsOption::Cookie(c) = o { Some(c) } else { None }
    });

    let Some(cookie) = cookie else {
        return CookieState {
            has_client_cookie: false,
            server_cookie_valid: false,
            client_cookie_bytes: None,
        };
    };

    let client_ip_bytes: Vec<u8> = match client_ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    // A server cookie is present only when the client has previously received
    // one from us (RFC 7873 §5.2).
    let server_cookie_valid = match &cookie.server {
        None => false,
        Some(server_bytes) => {
            // Verify against the current secret first.
            if verify_server_cookie(
                server_bytes,
                &cookie.client,
                &client_ip_bytes,
                current_secret,
            ) {
                true
            } else if let Some(prev) = previous_secret {
                // Fall back to the previous secret (one-rotation-cycle grace period,
                // PROTO-055).
                verify_server_cookie(server_bytes, &cookie.client, &client_ip_bytes, prev)
            } else {
                false
            }
        }
    };

    CookieState {
        has_client_cookie: true,
        server_cookie_valid,
        client_cookie_bytes: Some(cookie.client),
    }
}

/// Derives the server cookie bytes to include in a DNS response.
///
/// Returns an [`EdnsCookie`] that carries both the client cookie (echoed back)
/// and the freshly derived server cookie, ready to be placed in the response OPT
/// RR as an [`EdnsOption::Cookie`].
///
/// `client_cookie` — the 8-byte client cookie from the inbound query.
///
/// `client_ip` — the source IP of the query.
///
/// `server_secret` — the current active server secret.
#[must_use]
pub fn derive_response_cookie(
    client_cookie: &[u8; 8],
    client_ip: IpAddr,
    server_secret: &[u8],
) -> EdnsCookie {
    let ip_bytes: Vec<u8> = match client_ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let server_cookie = derive_server_cookie(client_cookie, &ip_bytes, server_secret);
    EdnsCookie { client: *client_cookie, server: Some(server_cookie.to_vec()) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use heimdall_core::edns::{EdnsCookie, EdnsOption, OptRr, derive_server_cookie};

    use super::*;

    const SECRET: &[u8] = b"test-secret-key-16";
    const CLIENT_COOKIE: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    fn opt_with_cookie(cookie: EdnsCookie) -> OptRr {
        OptRr {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![EdnsOption::Cookie(cookie)],
        }
    }

    fn opt_no_cookie() -> OptRr {
        OptRr {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        }
    }

    // ── No OPT RR ────────────────────────────────────────────────────────────

    #[test]
    fn no_opt_rr_returns_no_cookie() {
        let state = extract_cookie_state(None, CLIENT_IP, SECRET, None);
        assert!(!state.has_client_cookie);
        assert!(!state.server_cookie_valid);
        assert!(state.client_cookie_bytes.is_none());
    }

    // ── OPT RR without Cookie option ─────────────────────────────────────────

    #[test]
    fn opt_without_cookie_option_returns_no_cookie() {
        let opt = opt_no_cookie();
        let state = extract_cookie_state(Some(&opt), CLIENT_IP, SECRET, None);
        assert!(!state.has_client_cookie);
        assert!(!state.server_cookie_valid);
        assert!(state.client_cookie_bytes.is_none());
    }

    // ── Client cookie only (no server cookie in query) ────────────────────────

    #[test]
    fn client_cookie_only_no_server_cookie() {
        let cookie = EdnsCookie { client: CLIENT_COOKIE, server: None };
        let opt = opt_with_cookie(cookie);
        let state = extract_cookie_state(Some(&opt), CLIENT_IP, SECRET, None);
        assert!(state.has_client_cookie);
        assert!(!state.server_cookie_valid);
        assert_eq!(state.client_cookie_bytes, Some(CLIENT_COOKIE));
    }

    // ── Invalid server cookie ─────────────────────────────────────────────────

    #[test]
    fn invalid_server_cookie_returns_false() {
        let bad_server_cookie = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
        let cookie = EdnsCookie { client: CLIENT_COOKIE, server: Some(bad_server_cookie) };
        let opt = opt_with_cookie(cookie);
        let state = extract_cookie_state(Some(&opt), CLIENT_IP, SECRET, None);
        assert!(state.has_client_cookie);
        assert!(!state.server_cookie_valid);
    }

    // ── Valid server cookie (current secret) ──────────────────────────────────

    #[test]
    fn valid_server_cookie_current_secret() {
        let ip_bytes = [10u8, 0, 0, 1];
        let server_cookie = derive_server_cookie(&CLIENT_COOKIE, &ip_bytes, SECRET);
        let cookie =
            EdnsCookie { client: CLIENT_COOKIE, server: Some(server_cookie.to_vec()) };
        let opt = opt_with_cookie(cookie);
        let state = extract_cookie_state(Some(&opt), CLIENT_IP, SECRET, None);
        assert!(state.has_client_cookie);
        assert!(state.server_cookie_valid);
        assert_eq!(state.client_cookie_bytes, Some(CLIENT_COOKIE));
    }

    // ── Valid server cookie (previous secret) ─────────────────────────────────

    #[test]
    fn valid_server_cookie_previous_secret() {
        let prev_secret = b"old-secret-key-16!";
        let ip_bytes = [10u8, 0, 0, 1];
        // Generate a cookie using the previous (retired) secret.
        let server_cookie = derive_server_cookie(&CLIENT_COOKIE, &ip_bytes, prev_secret);
        let cookie =
            EdnsCookie { client: CLIENT_COOKIE, server: Some(server_cookie.to_vec()) };
        let opt = opt_with_cookie(cookie);
        // Current secret is different; cookie must still validate via prev_secret.
        let state = extract_cookie_state(Some(&opt), CLIENT_IP, SECRET, Some(prev_secret));
        assert!(state.has_client_cookie);
        assert!(state.server_cookie_valid);
    }

    // ── Cookie valid for one IP, rejected for another ─────────────────────────

    #[test]
    fn server_cookie_wrong_ip_fails() {
        let ip_bytes = [10u8, 0, 0, 1];
        let server_cookie = derive_server_cookie(&CLIENT_COOKIE, &ip_bytes, SECRET);
        let cookie =
            EdnsCookie { client: CLIENT_COOKIE, server: Some(server_cookie.to_vec()) };
        let opt = opt_with_cookie(cookie);
        // Present the cookie from a different IP address.
        let wrong_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let state = extract_cookie_state(Some(&opt), wrong_ip, SECRET, None);
        assert!(state.has_client_cookie);
        assert!(!state.server_cookie_valid);
    }

    // ── IPv6 client address ───────────────────────────────────────────────────

    #[test]
    fn valid_server_cookie_ipv6() {
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ip_bytes = match ipv6 {
            IpAddr::V6(v6) => v6.octets().to_vec(),
            _ => unreachable!(),
        };
        let server_cookie = derive_server_cookie(&CLIENT_COOKIE, &ip_bytes, SECRET);
        let cookie =
            EdnsCookie { client: CLIENT_COOKIE, server: Some(server_cookie.to_vec()) };
        let opt = opt_with_cookie(cookie);
        let state = extract_cookie_state(Some(&opt), ipv6, SECRET, None);
        assert!(state.has_client_cookie);
        assert!(state.server_cookie_valid);
    }

    // ── derive_response_cookie ────────────────────────────────────────────────

    #[test]
    fn derive_response_cookie_roundtrip() {
        let result = derive_response_cookie(&CLIENT_COOKIE, CLIENT_IP, SECRET);
        assert_eq!(result.client, CLIENT_COOKIE);
        // The server cookie must be 8 bytes.
        let sc = result.server.expect("server cookie present");
        assert_eq!(sc.len(), 8);
        // Must verify successfully.
        let ip_bytes = [10u8, 0, 0, 1];
        assert!(verify_server_cookie(&sc, &CLIENT_COOKIE, &ip_bytes, SECRET));
    }
}
