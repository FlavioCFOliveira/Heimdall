// SPDX-License-Identifier: MIT

//! DNS transport listeners: UDP/53, TCP/53, and DoT/853 (Sprint 21–22).
//!
//! This module implements the transport listeners for the Heimdall DNS server
//! as specified by NET-003, NET-004, NET-011, PROTO-008, PROTO-014, SEC-001..016,
//! SEC-060..068, and the TCP behaviour sections of `006-protocol-conformance.md`.
//!
//! ## Module overview
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`backpressure`] | [`BackpressureAction`], `udp_backpressure`, `tcp_backpressure` |
//! | [`cookie`] | [`CookieState`], `extract_cookie_state`, `derive_response_cookie` |
//! | [`udp`] | [`UdpListener`] — UDP/53 listener loop |
//! | [`tcp`] | [`TcpListener`] — TCP/53 listener with RFC 7766 framing |
//! | [`tls`] | [`TlsServerConfig`], [`MtlsIdentitySource`], [`build_tls_server_config`], [`extract_mtls_identity`] |
//! | [`dot`] | [`DotListener`] — DoT/853 listener with TLS 1.3 and RFC 7766 framing |
//! | [`tls_telemetry`] | [`TlsTelemetry`] — TLS handshake counters |
//!
//! ## `io_uring` note
//!
//! The current UDP receive loop uses `recv_from` on a standard tokio
//! `UdpSocket`.  A future sprint will replace this with `io_uring` multishot
//! receive (`IORING_OP_RECVMSG_MULTI` / `IORING_OP_RECV_MULTISHOT`) for
//! zero-copy, syscall-batched ingestion on Linux ≥ 5.19.

pub mod backpressure;
pub mod cookie;
pub mod dot;
pub mod tcp;
pub mod tls;
pub mod tls_telemetry;
pub mod udp;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use backpressure::{BackpressureAction, tcp_backpressure, udp_backpressure};
pub use cookie::{CookieState, derive_response_cookie, extract_cookie_state};
pub use dot::DotListener;
pub use tcp::TcpListener;
pub use tls::{MtlsIdentitySource, TlsServerConfig, build_tls_server_config, extract_mtls_identity};
pub use tls_telemetry::TlsTelemetry;
pub use udp::UdpListener;

// ── ListenerConfig ────────────────────────────────────────────────────────────

/// Configuration shared between the UDP and TCP classic-DNS listeners.
///
/// All timeouts are expressed in seconds and converted to [`std::time::Duration`]
/// inside the listener code.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// The socket address on which the listeners bind.
    pub bind_addr: std::net::SocketAddr,
    /// Maximum UDP payload size the server will emit (bytes).
    ///
    /// Per RFC 8085 §3.2, the safe default is **1232 bytes**, which avoids IP
    /// fragmentation in almost all real-world paths (PROTO-008).  The effective
    /// payload for any given query is `min(client_advertised, max_udp_payload)`.
    pub max_udp_payload: u16,
    /// 16-byte secret used for HMAC-SHA256 server cookie derivation (PROTO-010,
    /// PROTO-055).
    pub server_cookie_secret: [u8; 16],
    /// Idle timeout advertised via `edns-tcp-keepalive` option in responses
    /// (PROTO-073, RFC 7828).  Default: **30 seconds**.
    pub tcp_keepalive_secs: u32,
    /// Maximum time a TCP connection may remain idle before the server closes it
    /// (THREAT-068).  Default: **30 seconds**.
    pub tcp_idle_timeout_secs: u32,
    /// Maximum time a TCP connection may stall (partial read or write with no
    /// forward progress) before the server closes it (THREAT-068).  Default:
    /// **10 seconds**.
    pub tcp_stall_timeout_secs: u32,
    /// Timeout for the first message on a newly accepted TCP connection.
    /// Analogous to a handshake timeout: if no well-formed 2-byte length prefix
    /// is received within this window the connection is aborted (THREAT-068).
    /// Default: **5 seconds**.
    pub tcp_handshake_timeout_secs: u32,
    /// Maximum number of queries that may be pipelined on a single TCP connection
    /// before the server closes it after the current query completes (THREAT-063).
    /// Default: **16**.
    pub tcp_max_pipelining: u32,
}

/// Default bind address: `[::]` (all interfaces) on port 53.
const DEFAULT_BIND_ADDR: std::net::SocketAddr = std::net::SocketAddr::V6(
    std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 53, 0, 0),
);

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR,
            max_udp_payload: 1232,
            server_cookie_secret: [0u8; 16],
            tcp_keepalive_secs: 30,
            tcp_idle_timeout_secs: 30,
            tcp_stall_timeout_secs: 10,
            tcp_handshake_timeout_secs: 5,
            tcp_max_pipelining: 16,
        }
    }
}

// ── TransportError ────────────────────────────────────────────────────────────

/// Errors that can be returned by the transport listener `run` loops.
///
/// Individual per-packet or per-connection errors are handled internally and
/// do not surface here; [`TransportError`] signals that the listener loop
/// itself has exited unrecoverably.
#[derive(Debug)]
pub enum TransportError {
    /// The underlying socket could not be bound.
    Bind(std::io::Error),
    /// A fatal I/O error occurred on the listening socket.
    Io(std::io::Error),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(e) => write!(f, "failed to bind transport socket: {e}"),
            Self::Io(e) => write!(f, "transport I/O error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(e) | Self::Io(e) => Some(e),
        }
    }
}

// ── process_query (stub) ──────────────────────────────────────────────────────

/// Stub query processor — returns REFUSED (RCODE 5) for all queries.
///
/// This stub is replaced by real role dispatch (authoritative / recursive /
/// forwarder) in dedicated later sprints.  It exists here so that the transport
/// listeners have a concrete call site that exercises the end-to-end
/// encode/decode path in tests.
///
/// The response:
/// - Copies the query ID.
/// - Sets QR=1, OPCODE=QUERY, RCODE=REFUSED.
/// - Echoes the question section unchanged.
/// - Carries no answer, authority, or additional records.
///
/// The OPT RR (server cookie, EDNS buf-size) is attached by the caller after
/// this function returns.
#[must_use]
pub fn process_query(msg: &heimdall_core::parser::Message) -> heimdall_core::serialiser::Serialiser {
    use heimdall_core::header::{Header, Rcode};
    use heimdall_core::parser::Message;
    use heimdall_core::serialiser::Serialiser;

    // Build response flags: QR=1, opcode echoed, RCODE=REFUSED.
    // Bit layout: QR(15)|OPCODE(14:11)|AA|TC|RD|RA|Z|AD|CD|RCODE(3:0)
    let query_opcode_bits = msg.header.flags & 0x7800; // bits 14:11
    let flags = 0x8000u16           // QR = 1
        | query_opcode_bits
        | u16::from(Rcode::Refused.as_u8()); // RCODE = 5

    let hdr = Header {
        id: msg.header.id,
        flags,
        qdcount: msg.header.qdcount,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let response = Message {
        header: hdr,
        questions: msg.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let mut ser = Serialiser::new(true);
    // INVARIANT: a well-formed REFUSED response with no additional records
    // cannot exceed 65535 bytes or produce offset-overflow errors.
    let _ = ser.write_message(&response);
    ser
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;

    use super::*;

    fn make_query() -> Message {
        let mut hdr = Header::default();
        hdr.id = 0xABCD;
        hdr.qdcount = 1;
        Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str("example.com.").unwrap(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn process_query_stub_returns_refused() {
        let query = make_query();
        let ser = process_query(&query);
        let wire = ser.finish();
        let resp = Message::parse(&wire).expect("valid DNS response");
        assert_eq!(resp.header.id, 0xABCD);
        assert!(resp.header.qr());
        assert_eq!(resp.header.flags & 0x000F, u16::from(Rcode::Refused.as_u8()));
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.answers.len(), 0);
    }

    #[test]
    fn listener_config_defaults_are_sane() {
        let cfg = ListenerConfig::default();
        assert_eq!(cfg.max_udp_payload, 1232);
        assert_eq!(cfg.tcp_keepalive_secs, 30);
        assert_eq!(cfg.tcp_idle_timeout_secs, 30);
        assert_eq!(cfg.tcp_stall_timeout_secs, 10);
        assert_eq!(cfg.tcp_handshake_timeout_secs, 5);
        assert_eq!(cfg.tcp_max_pipelining, 16);
    }
}
