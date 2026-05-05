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
    /// The DNS server role served by this listener.
    ///
    /// Injected into [`crate::admission::RequestCtx::role`] for every inbound
    /// request so the admission pipeline applies the correct ACL defaults and
    /// rate-limiting path (RRL for authoritative; query RL for recursive /
    /// forwarder).
    pub server_role: crate::admission::Role,
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
    /// Value for the `Alt-Svc` response header on DoH/H2 listeners (NET-007).
    ///
    /// `None` means no `Alt-Svc` header is emitted. Typically set to
    /// `"h3=\":443\""` to advertise a co-located DoH/H3 endpoint.
    pub alt_svc: Option<String>,
}

/// Default bind address: `[::]` (all interfaces) on port 53.
const DEFAULT_BIND_ADDR: std::net::SocketAddr = std::net::SocketAddr::V6(
    std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 53, 0, 0),
);

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR,
            server_role: crate::admission::Role::Authoritative,
            max_udp_payload: 1232,
            server_cookie_secret: [0u8; 16],
            tcp_keepalive_secs: 30,
            tcp_idle_timeout_secs: 30,
            tcp_stall_timeout_secs: 10,
            tcp_handshake_timeout_secs: 5,
            tcp_max_pipelining: 16,
            alt_svc: None,
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
    ///
    /// `is_udp` is `true` when the query arrived over UDP, `false` for TCP (and
    /// other stream transports).  Dispatchers that implement RPZ `TcpOnly` use
    /// this flag to return TC=1 on UDP while passing through on TCP.
    fn dispatch(
        &self,
        msg: &heimdall_core::parser::Message,
        src: std::net::IpAddr,
        is_udp: bool,
    ) -> Vec<u8>;
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
    is_udp: bool,
) -> Vec<u8> {
    use heimdall_core::{
        header::{Header, Rcode},
        parser::Message,
        serialiser::Serialiser,
    };

    if let Some(d) = dispatcher {
        return d.dispatch(msg, src_ip, is_udp);
    }

    // No dispatcher configured — return REFUSED.

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

// ── extract_query_opt ─────────────────────────────────────────────────────────

/// Returns the OPT pseudo-RR from the additional section of a parsed message,
/// if present.
#[must_use]
pub fn extract_query_opt(
    msg: &heimdall_core::parser::Message,
) -> Option<&heimdall_core::edns::OptRr> {
    msg.additional.iter().find_map(|r| {
        if let heimdall_core::rdata::RData::Opt(opt) = &r.rdata {
            Some(opt)
        } else {
            None
        }
    })
}

// ── apply_edns_padding ────────────────────────────────────────────────────────

/// Applies RFC 8467 EDNS padding (468-byte block size) to `response_wire`.
///
/// Adds an OPT RR containing a `Padding` option (RFC 7830, option code 12) that
/// brings the serialised wire length to the next multiple of 468 bytes.
///
/// Must only be called on encrypted transports (`DoT`, DoH/2, DoH/3, `DoQ`).  UDP
/// responses must never be padded.
///
/// # Algorithm (two-pass)
///
/// 1. Parse `response_wire`; strip any existing OPT RR.
/// 2. Build an OPT RR with no `Padding` option; serialise → `wire_no_pad`.
/// 3. `p = padding_len(wire_no_pad.len() + 4, 468)` — the +4 pre-accounts for
///    the Padding option TLV header (2-byte code + 2-byte length).
/// 4. Replace the OPT with one carrying `Padding(p)`; serialise → final wire.
///
/// Returns `response_wire` unchanged if parsing fails.
#[must_use]
pub fn apply_edns_padding(
    response_wire: &[u8],
    query_opt: Option<&heimdall_core::edns::OptRr>,
    max_udp_payload: u16,
) -> Vec<u8> {
    use heimdall_core::{
        edns::{EdnsOption, OptRr, padding_len},
        header::Qclass,
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
        serialiser::Serialiser,
    };

    let Ok(mut msg) = Message::parse(response_wire) else {
        return response_wire.to_vec();
    };

    // Extract any EDE from the dispatcher's OPT before stripping it, so we can
    // propagate it in the transport's authoritative OPT (e.g. EDE-20 from step-4).
    let dispatcher_ede: Option<EdnsOption> = msg.additional.iter().find_map(|r| {
        if let RData::Opt(opt) = &r.rdata {
            opt.options
                .iter()
                .find(|o| matches!(o, EdnsOption::ExtendedError(_)))
                .cloned()
        } else {
            None
        }
    });

    // Remove any existing OPT RR so we control the one we add.
    msg.additional
        .retain(|r| !matches!(&r.rdata, RData::Opt(_)));

    let mut base_options: Vec<EdnsOption> = Vec::new();
    if let Some(ede) = dispatcher_ede {
        base_options.push(ede);
    }

    let base_opt = OptRr {
        udp_payload_size: max_udp_payload,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: query_opt.is_some_and(|o| o.dnssec_ok),
        z: query_opt.map_or(0, |o| o.z),
        options: base_options,
    };

    // First pass: serialise without padding to measure the wire length.
    msg.additional.push(Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(base_opt.clone()),
    });
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.header.arcount = msg.additional.len() as u16;
    }

    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    let wire_no_pad = ser.finish();

    // p = bytes of Padding data needed so that (wire_no_pad + 4 + p) % 468 == 0.
    // The +4 accounts for the Padding option TLV header written in the wire.
    #[allow(clippy::cast_possible_truncation)]
    let p = padding_len(wire_no_pad.len() + 4, 468) as u16;

    // Second pass: replace OPT with padded version (EDE first, Padding last).
    msg.additional.pop();
    let mut final_options = base_opt.options.clone();
    final_options.push(EdnsOption::Padding(p));
    msg.additional.push(Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(OptRr {
            options: final_options,
            ..base_opt
        }),
    });

    let mut ser2 = Serialiser::new(true);
    let _ = ser2.write_message(&msg);
    ser2.finish()
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

    use heimdall_core::{
        header::{Header, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
    };

    use super::*;

    fn make_query() -> Message {
        let hdr = Header {
            id: 0xABCD,
            qdcount: 1,
            ..Header::default()
        };
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
        let wire = process_query(&query, "127.0.0.1".parse().unwrap(), None, true);
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
        use crate::admission::Role;
        let cfg = ListenerConfig::default();
        assert_eq!(cfg.server_role, Role::Authoritative);
        assert_eq!(cfg.max_udp_payload, 1232);
        assert_eq!(cfg.tcp_keepalive_secs, 30);
        assert_eq!(cfg.tcp_idle_timeout_secs, 30);
        assert_eq!(cfg.tcp_stall_timeout_secs, 10);
        assert_eq!(cfg.tcp_handshake_timeout_secs, 5);
        assert_eq!(cfg.tcp_max_pipelining, 16);
    }
}
