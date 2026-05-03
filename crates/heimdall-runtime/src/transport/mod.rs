// SPDX-License-Identifier: MIT

//! DNS transport listeners: UDP/53, TCP/53, DoT/853, DoH/H2, DoQ/853, and
//! DoH/H3 (Sprints 21–25).
//!
//! This module implements the transport listeners for the Heimdall DNS server
//! as specified by NET-003..007, NET-011, NET-025..028, PROTO-008, PROTO-014,
//! SEC-001..016, SEC-036..046, SEC-060..068, SEC-077, and the TCP behaviour
//! sections of `006-protocol-conformance.md`.
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
//! | [`doh2`] | [`Doh2Listener`], [`Doh2HardeningConfig`], [`Doh2Telemetry`] — DoH/H2 listener |
//! | [`tls_telemetry`] | [`TlsTelemetry`] — TLS handshake counters |
//! | [`quic`] | [`DoqListener`], [`QuicHardeningConfig`], [`QuicTelemetry`], [`StrikeRegister`], [`NewTokenTekManager`], [`build_quinn_endpoint`] — DoQ/QUIC listener (Sprint 24) |
//! | [`doh3`] | [`Doh3Listener`], [`Doh3HardeningConfig`], [`Doh3Telemetry`], [`build_quinn_endpoint_h3`] — DoH/H3 listener (Sprint 25) |
//!
//! ## `io_uring` note
//!
//! The current UDP receive loop uses `recv_from` on a standard tokio
//! `UdpSocket`.  A future sprint will replace this with `io_uring` multishot
//! receive (`IORING_OP_RECVMSG_MULTI` / `IORING_OP_RECV_MULTISHOT`) for
//! zero-copy, syscall-batched ingestion on Linux ≥ 5.19.

pub mod backpressure;
pub mod cookie;
pub mod doh2;
pub mod doh3;
pub mod dot;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod tls_telemetry;
pub mod udp;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use backpressure::{BackpressureAction, tcp_backpressure, udp_backpressure};
pub use cookie::{CookieState, derive_response_cookie, extract_cookie_state};
pub use doh2::{Doh2HardeningConfig, Doh2Listener, Doh2Telemetry};
pub use doh3::{Doh3HardeningConfig, Doh3Listener, Doh3Telemetry, build_quinn_endpoint_h3};
pub use dot::DotListener;
pub use quic::{
    DoqListener, NewTokenTekManager, QuicHardeningConfig, QuicTelemetry, StrikeRegister,
    build_quinn_endpoint,
};
pub use tcp::TcpListener;
pub use tls::{
    MtlsIdentitySource, TlsServerConfig, build_tls_server_config, extract_mtls_identity,
};
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

// ── QueryDispatcher ───────────────────────────────────────────────────────────

/// Role dispatcher: routes a parsed DNS query to the appropriate server role.
///
/// Each enabled role (`AuthServer`, `RecursiveServer`, `ForwarderServer`)
/// implements this trait.  The transport listener holds an
/// `Option<Arc<dyn QueryDispatcher + Send + Sync>>` and calls
/// [`QueryDispatcher::dispatch`] for every admitted query.
pub trait QueryDispatcher: Send + Sync {
    /// Process `msg` from `src` and return the serialised DNS response wire bytes.
    fn dispatch(&self, msg: &heimdall_core::parser::Message, src: std::net::IpAddr) -> Vec<u8>;
}

// ── process_query ─────────────────────────────────────────────────────────────

/// Route an admitted DNS query to `dispatcher`, falling back to REFUSED when
/// no dispatcher is configured.
///
/// The response wire bytes are returned without an OPT RR — the calling
/// transport layer attaches EDNS options (server cookie, UDP payload size,
/// `edns-tcp-keepalive`) after this function returns.
#[must_use]
pub fn process_query(
    msg: &heimdall_core::parser::Message,
    src_ip: std::net::IpAddr,
    dispatcher: Option<&(dyn QueryDispatcher + Send + Sync)>,
) -> Vec<u8> {
    if let Some(d) = dispatcher {
        return d.dispatch(msg, src_ip);
    }

    // No dispatcher configured — return REFUSED.
    use heimdall_core::header::{Header, Rcode};
    use heimdall_core::parser::Message;
    use heimdall_core::serialiser::Serialiser;

    // Build response flags: QR=1, opcode echoed, RCODE=REFUSED.
    let query_opcode_bits = msg.header.flags & 0x7800;
    let flags = 0x8000u16 | query_opcode_bits | u16::from(Rcode::Refused.as_u8());

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
    ser.finish()
}

// ── ZoneTransferHandler ───────────────────────────────────────────────────────

/// Zone transfer handler: builds the pre-framed TCP wire messages for AXFR/IXFR.
///
/// Implemented by the authoritative server role.  The TCP (and DoT/XoT) transport
/// layers call [`ZoneTransferHandler::build_xfr_frames`] when they detect an AXFR
/// or IXFR opcode, then write the returned frames directly to the client socket.
///
/// The handler performs ACL checks, TSIG authentication, and zone data serialisation
/// entirely synchronously, so the transport layer is never blocked by async I/O.
pub trait ZoneTransferHandler: Send + Sync {
    /// Processes an AXFR or IXFR request and returns the pre-framed wire messages
    /// to write to the TCP stream (each entry includes the 2-byte length prefix).
    ///
    /// `raw` is the original received wire bytes for the query (used for TSIG
    /// verification — the MAC must be verified over the bytes as received, not
    /// over a re-serialized representation).
    ///
    /// Returns `Some(frames)` on success, `None` when the request must be refused
    /// (TSIG failure, ACL denial, or no matching zone).
    fn build_xfr_frames(
        &self,
        msg: &heimdall_core::parser::Message,
        raw: &[u8],
        src: std::net::IpAddr,
    ) -> Option<Vec<Vec<u8>>>;
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
        let wire = process_query(&query, "127.0.0.1".parse().unwrap(), None);
        let resp = Message::parse(&wire).expect("valid DNS response");
        assert_eq!(resp.header.id, 0xABCD);
        assert!(resp.header.qr());
        assert_eq!(
            resp.header.flags & 0x000F,
            u16::from(Rcode::Refused.as_u8())
        );
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
