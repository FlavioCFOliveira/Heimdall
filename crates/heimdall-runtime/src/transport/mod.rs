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
pub mod reuseport;
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
pub use reuseport::bind_reuseport_udp;
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
///
/// ## Async-trait shape (rmp #675)
///
/// `dispatch` returns a `Pin<Box<dyn Future + Send + '_>>` rather than using
/// the unstable `async fn` in dyn-traits or the `async-trait` macro.  The
/// hand-written shape mirrors the [`UpstreamClient`] trait in `heimdall-roles`
/// (`crates/heimdall-roles/src/forwarder/client.rs`) and keeps the one-per-call
/// heap allocation explicit and grep-visible.  It supersedes a synchronous
/// trait method that bridged to the async role handlers via blocking primitives,
/// which both pinned the worker thread for the duration of an upstream query
/// and required a multi-threaded Tokio runtime (single-thread runtimes would
/// panic).
pub trait QueryDispatcher: Send + Sync {
    /// Process `msg` from `src` and return the serialised DNS response wire bytes.
    ///
    /// `is_udp` is `true` when the query arrived over UDP, `false` for TCP (and
    /// other stream transports).  Dispatchers that implement RPZ `TcpOnly` use
    /// this flag to return TC=1 on UDP while passing through on TCP.
    fn dispatch<'a>(
        &'a self,
        msg: &'a heimdall_core::parser::Message,
        src: std::net::IpAddr,
        is_udp: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>;

    /// Returns `true` if this dispatcher is explicitly authoritative for a zone
    /// whose apex matches `name` (case-insensitive, exact match — not suffix).
    ///
    /// Used by [`process_query`] to honour the ENV-065 precedence rule for the
    /// synthetic `health.heimdall.internal.` zone: an operator-defined zone
    /// with the same apex wins over the built-in synthetic response.
    ///
    /// The default implementation returns `false`, which is the right answer
    /// for dispatchers that hold no zone data (recursive, forwarder).  The
    /// authoritative dispatcher overrides this method.
    fn owns_zone_apex(&self, _name: &heimdall_core::name::Name) -> bool {
        false
    }
}

// ── Synthetic health-zone (ENV-065) ───────────────────────────────────────────

/// Wire bytes of the synthetic health-zone apex (`health.heimdall.internal.`),
/// stored in already-lower-case form so byte-level comparisons can short-circuit
/// without an allocation.
///
/// Layout (RFC 1035 §3.1): `0x06 "health" 0x08 "heimdall" 0x08 "internal" 0x00`.
const SYNTHETIC_HEALTH_APEX_WIRE: &[u8] = b"\x06health\x08heimdall\x08internal\x00";

/// TTL of the synthetic A record (seconds).  60 s matches what `ENV-065`
/// documents as the published TTL for the synthetic health response.
const SYNTHETIC_HEALTH_TTL: u32 = 60;

/// Returns `true` if `msg` is the canonical ENV-065 probe query:
/// `QNAME=health.heimdall.internal.`, `QTYPE=A`, `QCLASS=IN`.
///
/// The comparison is case-insensitive on the QNAME wire bytes (RFC 1035 §3.1)
/// and exact on the type and class — `QTYPE=ANY`, `QTYPE=AAAA`, and
/// `QCLASS=CH` deliberately do **not** trigger the synthetic short-circuit.
fn is_synthetic_health_query(msg: &heimdall_core::parser::Message) -> bool {
    use heimdall_core::header::{Qclass, Qtype};

    let Some(q) = msg.questions.first() else {
        return false;
    };
    if q.qtype != Qtype::A || q.qclass != Qclass::In {
        return false;
    }
    let wire = q.qname.as_wire_bytes();
    wire.len() == SYNTHETIC_HEALTH_APEX_WIRE.len()
        && wire
            .iter()
            .zip(SYNTHETIC_HEALTH_APEX_WIRE.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Returns `true` if the dispatcher (when present) is authoritative for an
/// operator-defined zone whose apex is exactly `health.heimdall.internal.`.
///
/// Per ENV-065, an explicit operator zone with this apex **wins** over the
/// built-in synthetic response.  When no dispatcher exists this returns
/// `false` and the synthetic zone is allowed to answer.
fn operator_owns_health_zone(dispatcher: Option<&(dyn QueryDispatcher + Send + Sync)>) -> bool {
    use std::str::FromStr;
    let Some(d) = dispatcher else { return false };

    // The Name we hand to `owns_zone_apex` must be a valid parse of the apex.
    // Constructing it once per call is acceptable — the synthetic path runs
    // only when the qname already matched the ENV-065 probe contract, so this
    // is a cold path relative to the dispatcher hot path.
    match heimdall_core::name::Name::from_str("health.heimdall.internal.") {
        Ok(name) => d.owns_zone_apex(&name),
        // INVARIANT: this literal is a well-formed DNS name; parsing cannot
        // fail.  If it ever did, the safe action is "no operator zone", which
        // lets the synthetic response fire.
        Err(_) => false,
    }
}

/// Builds the synthetic response for the ENV-065 health probe.
///
/// Response shape (per ENV-065 amendment):
/// - Header: `ID` echoed, `QR=1`, opcode `Query`, `AA=1`, `RA=0`,
///   `RCODE=NOERROR`, `QDCOUNT=1`, `ANCOUNT=1`.
/// - Question: copied from the query.
/// - Answer: one A record at the apex (`health.heimdall.internal.`) with
///   TTL=60 and RDATA `127.0.0.1`.
///
/// The response is intentionally tiny (≤ 55 bytes on the wire) and contains
/// no OPT RR; the calling transport layer adds EDNS options after this
/// function returns, exactly as for any dispatcher-built response.
fn build_synthetic_health_response(msg: &heimdall_core::parser::Message) -> Vec<u8> {
    use std::net::Ipv4Addr;

    use heimdall_core::{
        header::{Header, Opcode, Qclass, Rcode},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
        serialiser::Serialiser,
    };

    // Owner name of the A record is the QNAME from the query so the wire
    // response preserves the exact casing the client sent (preserves 0x20
    // randomisation, RFC 4343 §4).  Fall back to a freshly-parsed apex only
    // if the query somehow lacks a question — the caller already ruled this
    // out via `is_synthetic_health_query`, so this branch is defensive.
    let owner = msg.questions.first().map_or_else(
        || {
            // SAFETY: literal is a well-formed DNS name.  If parsing ever
            // returned an error we would lose the synthetic response on this
            // packet, which is the safe failure mode.
            Name::from_wire(SYNTHETIC_HEALTH_APEX_WIRE, 0)
                .map_or_else(|_| Name::root(), |(n, _)| n)
        },
        |q| q.qname.clone(),
    );

    let mut header = Header {
        id: msg.header.id,
        qdcount: msg.header.qdcount,
        ancount: 1,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_opcode(Opcode::Query);
    header.set_aa(true);
    header.set_rcode(Rcode::NoError);

    let answer = Record {
        name: owner,
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: SYNTHETIC_HEALTH_TTL,
        rdata: RData::A(Ipv4Addr::LOCALHOST),
    };

    let response = Message {
        header,
        questions: msg.questions.clone(),
        answers: vec![answer],
        authority: vec![],
        additional: vec![],
    };

    let mut ser = Serialiser::new(true);
    // INVARIANT: a 12-byte header + one question + one A answer cannot exceed
    // 65535 bytes or trigger offset overflow.
    let _ = ser.write_message(&response);
    ser.finish()
}

// ── process_query ─────────────────────────────────────────────────────────────

/// Route an admitted DNS query to `dispatcher`, falling back to REFUSED when
/// no dispatcher is configured.
///
/// The response wire bytes are returned without an OPT RR — the calling
/// transport layer attaches EDNS options (server cookie, UDP payload size,
/// `edns-tcp-keepalive`) after this function returns.
///
/// ## ENV-065 synthetic health zone
///
/// Before invoking the dispatcher, this function short-circuits queries that
/// match the canonical health probe (`QNAME=health.heimdall.internal.`,
/// `QTYPE=A`, `QCLASS=IN`).  The synthetic response is fired only when **no**
/// operator-defined zone with apex `health.heimdall.internal.` is loaded;
/// otherwise the dispatcher runs as normal so the operator's data wins.  This
/// makes the `heimdall-probe` HEALTHCHECK liveness contract deterministic
/// across all roles (authoritative, recursive, forwarder, multi-role).
pub async fn process_query(
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

    // ENV-065 synthetic health-zone short-circuit.  Runs before the dispatcher
    // so that recursive and forwarder roles — whose normal path would attempt
    // upstream resolution and time the probe out — answer locally.
    if is_synthetic_health_query(msg) && !operator_owns_health_zone(dispatcher) {
        return build_synthetic_health_response(msg);
    }

    if let Some(d) = dispatcher {
        return d.dispatch(msg, src_ip, is_udp).await;
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

    #[tokio::test]
    async fn process_query_stub_returns_refused() {
        let query = make_query();
        let wire = process_query(&query, "127.0.0.1".parse().unwrap(), None, true).await;
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

    // ── ENV-065 synthetic-zone tests ──────────────────────────────────────────

    /// Convenience builder for an ENV-065 probe-shaped query.
    fn make_health_query(qtype: Qtype, qclass: Qclass, qname: &str) -> Message {
        let hdr = Header {
            id: 0x1234,
            qdcount: 1,
            ..Header::default()
        };
        Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str(qname).unwrap(),
                qtype,
                qclass,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn is_synthetic_health_query_matches_canonical_probe() {
        let q = make_health_query(Qtype::A, Qclass::In, "health.heimdall.internal.");
        assert!(super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_is_case_insensitive() {
        // RFC 1035 §2.3.3 + RFC 4343: DNS comparisons are case-insensitive on ASCII.
        let q = make_health_query(Qtype::A, Qclass::In, "Health.HEIMDALL.Internal.");
        assert!(super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_aaaa() {
        let q = make_health_query(Qtype::Aaaa, Qclass::In, "health.heimdall.internal.");
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_any() {
        let q = make_health_query(Qtype::Any, Qclass::In, "health.heimdall.internal.");
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_chaos_class() {
        let q = make_health_query(Qtype::A, Qclass::Ch, "health.heimdall.internal.");
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_subdomain() {
        let q = make_health_query(Qtype::A, Qclass::In, "x.health.heimdall.internal.");
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_parent_apex() {
        let q = make_health_query(Qtype::A, Qclass::In, "heimdall.internal.");
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[test]
    fn is_synthetic_health_query_rejects_empty_question() {
        let mut q = make_health_query(Qtype::A, Qclass::In, "health.heimdall.internal.");
        q.questions.clear();
        q.header.qdcount = 0;
        assert!(!super::is_synthetic_health_query(&q));
    }

    #[tokio::test]
    async fn process_query_synthesises_health_response_without_dispatcher() {
        let query = make_health_query(Qtype::A, Qclass::In, "health.heimdall.internal.");
        let wire = process_query(&query, "127.0.0.1".parse().unwrap(), None, true).await;

        let resp = Message::parse(&wire).expect("valid DNS response");
        assert_eq!(resp.header.id, 0x1234);
        assert!(resp.header.qr(), "QR must be 1");
        assert!(resp.header.aa(), "AA must be 1 for the synthetic zone");
        assert!(!resp.header.ra(), "RA must be 0 (we are not recursing)");
        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert_eq!(resp.header.qdcount, 1);
        assert_eq!(resp.header.ancount, 1);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.answers.len(), 1);

        // Answer record: A 127.0.0.1, TTL 60, owner echoed from query.
        let answer = &resp.answers[0];
        assert_eq!(answer.rtype, heimdall_core::record::Rtype::A);
        assert_eq!(answer.rclass, Qclass::In);
        assert_eq!(answer.ttl, 60);
        match &answer.rdata {
            heimdall_core::rdata::RData::A(ip) => {
                assert_eq!(*ip, std::net::Ipv4Addr::LOCALHOST);
            }
            other => panic!("expected RData::A, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_query_synthesises_health_response_with_recursive_dispatcher() {
        // Dispatcher that doesn't own any zones (default `owns_zone_apex` ==
        // false) — like a pure recursive resolver.  The synthetic zone must
        // still fire before the dispatcher gets a chance to forward upstream.
        struct RecursiveLike;
        impl QueryDispatcher for RecursiveLike {
            fn dispatch<'a>(
                &'a self,
                msg: &'a Message,
                _src: std::net::IpAddr,
                _is_udp: bool,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>
            {
                // If we ever get here, the synthetic short-circuit failed.
                Box::pin(async move {
                    panic!(
                        "RecursiveLike::dispatch called for {:?} — \
                         synthetic short-circuit failed",
                        msg.questions
                    );
                })
            }
        }

        let dispatcher = RecursiveLike;
        let query = make_health_query(Qtype::A, Qclass::In, "health.heimdall.internal.");
        let wire = process_query(
            &query,
            "127.0.0.1".parse().unwrap(),
            Some(&dispatcher),
            true,
        )
        .await;

        let resp = Message::parse(&wire).expect("valid DNS response");
        assert!(resp.header.aa(), "AA must be 1 for the synthetic zone");
        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn process_query_yields_to_operator_zone() {
        // Dispatcher that *does* claim ownership of `health.heimdall.internal.`
        // — emulates an operator who has loaded that zone explicitly.  The
        // synthetic short-circuit must step aside.
        struct OperatorOwnsHealth;
        impl QueryDispatcher for OperatorOwnsHealth {
            fn dispatch<'a>(
                &'a self,
                msg: &'a Message,
                _src: std::net::IpAddr,
                _is_udp: bool,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>
            {
                // Sentinel response: RCODE=NXDOMAIN.  Distinguishable from the
                // synthetic NOERROR+answer response.
                Box::pin(async move {
                    let mut hdr = Header {
                        id: msg.header.id,
                        qdcount: msg.header.qdcount,
                        ..Header::default()
                    };
                    hdr.set_qr(true);
                    hdr.set_rcode(Rcode::NxDomain);
                    let r = Message {
                        header: hdr,
                        questions: msg.questions.clone(),
                        answers: vec![],
                        authority: vec![],
                        additional: vec![],
                    };
                    let mut ser = heimdall_core::Serialiser::new(true);
                    let _ = ser.write_message(&r);
                    ser.finish()
                })
            }

            fn owns_zone_apex(&self, name: &Name) -> bool {
                // Match only the exact apex (case-insensitive).
                *name == Name::from_str("health.heimdall.internal.").unwrap()
            }
        }

        let dispatcher = OperatorOwnsHealth;
        let query = make_health_query(Qtype::A, Qclass::In, "health.heimdall.internal.");
        let wire = process_query(
            &query,
            "127.0.0.1".parse().unwrap(),
            Some(&dispatcher),
            true,
        )
        .await;

        let resp = Message::parse(&wire).expect("valid DNS response");
        assert_eq!(
            resp.header.rcode(),
            Rcode::NxDomain,
            "operator dispatcher must win — NXDOMAIN is the sentinel from the \
             operator stub, NOERROR would mean the synthetic short-circuit fired"
        );
        assert_eq!(resp.answers.len(), 0);
    }

    #[tokio::test]
    async fn process_query_non_health_query_still_dispatched() {
        // Confirms the synthetic check does not change behaviour for the
        // generic query path: any unrelated qname must still reach the dispatcher.
        struct EchoStub;
        impl QueryDispatcher for EchoStub {
            fn dispatch<'a>(
                &'a self,
                msg: &'a Message,
                _src: std::net::IpAddr,
                _is_udp: bool,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>
            {
                Box::pin(async move {
                    let mut hdr = Header {
                        id: msg.header.id,
                        qdcount: msg.header.qdcount,
                        ..Header::default()
                    };
                    hdr.set_qr(true);
                    hdr.set_rcode(Rcode::ServFail); // sentinel
                    let r = Message {
                        header: hdr,
                        questions: msg.questions.clone(),
                        answers: vec![],
                        authority: vec![],
                        additional: vec![],
                    };
                    let mut ser = heimdall_core::Serialiser::new(true);
                    let _ = ser.write_message(&r);
                    ser.finish()
                })
            }
        }

        let dispatcher = EchoStub;
        let query = make_query(); // example.com. A IN
        let wire = process_query(
            &query,
            "127.0.0.1".parse().unwrap(),
            Some(&dispatcher),
            true,
        )
        .await;
        let resp = Message::parse(&wire).expect("valid DNS response");
        assert_eq!(
            resp.header.rcode(),
            Rcode::ServFail,
            "dispatcher must be invoked for non-health queries"
        );
    }
}
