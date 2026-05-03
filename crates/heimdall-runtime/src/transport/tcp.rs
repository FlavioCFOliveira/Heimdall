// SPDX-License-Identifier: MIT

//! TCP/53 classic DNS listener (NET-003, PROTO-014, THREAT-068/072).
//!
//! # Design overview
//!
//! The TCP listener accepts connections in a loop and spawns one tokio task per
//! connection to handle RFC 7766 2-byte-length-prefixed pipelining.
//!
//! ## RFC 7766 framing
//!
//! Each DNS message over TCP is preceded by a 2-byte network-order length prefix
//! (RFC 7766 §8).  The per-connection handler reads the 2-byte prefix, then reads
//! exactly that many bytes as the message payload, processes it, and writes back
//! a 2-byte-prefixed response.  A length prefix of zero is treated as a framing
//! error and closes the connection.
//!
//! ## Pipelining (THREAT-063)
//!
//! Queries are processed sequentially within a connection (in-order pipelining).
//! The `tcp_max_pipelining` limit bounds how many queries a single connection may
//! service before the server closes it after the current query finishes.
//!
//! ## Timeouts (THREAT-068)
//!
//! - **Handshake / first message**: if no complete 2-byte prefix + body arrives
//!   within `tcp_handshake_timeout_secs`, the connection is aborted.
//! - **Idle**: between queries, if `tcp_idle_timeout_secs` elapses without any
//!   bytes arriving, the connection is closed with FIN.
//! - **Stall**: if a read stalls mid-message for longer than
//!   `tcp_stall_timeout_secs`, the connection is closed with FIN.
//!
//! ## edns-tcp-keepalive (PROTO-014, PROTO-073)
//!
//! When the client's OPT RR carries a `TcpKeepalive` option, the response
//! includes a `TcpKeepalive` option advertising the server's idle timeout
//! (30 seconds by default, PROTO-073).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use heimdall_core::edns::{EdnsOption, OptRr, tcp_keepalive_option};
use heimdall_core::header::Rcode;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::Record;
use heimdall_core::serialiser::Serialiser;

use crate::admission::resource::ResourceCounters;
use crate::admission::{AdmissionPipeline, Operation, RequestCtx, Role, Transport};
use crate::drain::Drain;

use super::backpressure::{BackpressureAction, tcp_backpressure};
use super::cookie::{derive_response_cookie, extract_cookie_state};
use super::{ListenerConfig, QueryDispatcher, TransportError, process_query};

// ── TcpListener ───────────────────────────────────────────────────────────────

/// TCP/53 listener for classic DNS (NET-003).
pub struct TcpListener {
    listener: Arc<TokioTcpListener>,
    config: ListenerConfig,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
}

impl TcpListener {
    /// Creates a new [`TcpListener`] from an already-bound `TcpListener`.
    #[must_use]
    pub fn new(
        listener: Arc<TokioTcpListener>,
        config: ListenerConfig,
        pipeline: Arc<AdmissionPipeline>,
        resource_counters: Arc<ResourceCounters>,
    ) -> Self {
        Self {
            listener,
            config,
            pipeline,
            resource_counters,
            dispatcher: None,
        }
    }

    /// Attach a [`QueryDispatcher`] to this listener.
    #[must_use]
    pub fn with_dispatcher(
        mut self,
        dispatcher: Arc<dyn QueryDispatcher + Send + Sync>,
    ) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Runs the TCP accept loop until `drain` signals shutdown.
    ///
    /// Each accepted connection is handled in its own spawned tokio task.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] on a fatal accept error.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let listener = Arc::clone(&self.listener);
        let config = Arc::new(self.config);
        let pipeline = Arc::clone(&self.pipeline);
        let resource_counters = Arc::clone(&self.resource_counters);
        let dispatcher = self.dispatcher.clone();

        loop {
            if drain.is_draining() {
                break;
            }

            let (stream, addr) = listener.accept().await.map_err(TransportError::Io)?;

            let config_clone = Arc::clone(&config);
            let pipeline_clone = Arc::clone(&pipeline);
            let resource_counters_clone = Arc::clone(&resource_counters);
            let drain_clone = Arc::clone(&drain);
            let dispatcher_clone = dispatcher.clone();

            tokio::spawn(async move {
                handle_connection(
                    stream,
                    addr.ip(),
                    config_clone,
                    pipeline_clone,
                    resource_counters_clone,
                    drain_clone,
                    dispatcher_clone,
                )
                .await;
            });
        }

        Ok(())
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

/// Handles a single TCP connection according to RFC 7766 pipelining semantics.
async fn handle_connection(
    mut stream: TcpStream,
    client_ip: std::net::IpAddr,
    config: Arc<ListenerConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    drain: Arc<Drain>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) {
    let handshake_timeout = Duration::from_secs(u64::from(config.tcp_handshake_timeout_secs));
    let idle_timeout = Duration::from_secs(u64::from(config.tcp_idle_timeout_secs));
    let stall_timeout = Duration::from_secs(u64::from(config.tcp_stall_timeout_secs));

    let mut pipeline_count: u32 = 0;
    let mut first_message = true;

    loop {
        // ── Drain guard check ─────────────────────────────────────────────────
        if drain.is_draining() {
            break;
        }

        // ── Choose timeout ────────────────────────────────────────────────────
        let read_timeout = if first_message {
            handshake_timeout
        } else {
            idle_timeout
        };

        // ── Read 2-byte length prefix (RFC 7766) ──────────────────────────────
        let mut len_buf = [0u8; 2];
        let read_len = tokio::time::timeout(read_timeout, stream.read_exact(&mut len_buf)).await;

        match read_len {
            Err(_elapsed) => {
                // Timeout reading the length prefix — close cleanly.
                break;
            }
            Ok(Err(_io_err)) => {
                // I/O error (FIN/RST from client, or other) — close.
                break;
            }
            Ok(Ok(_)) => {}
        }

        first_message = false;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        // A zero-length message is a framing error — close the connection.
        if msg_len == 0 {
            break;
        }

        // ── Read message body ─────────────────────────────────────────────────
        let mut body = vec![0u8; msg_len];
        let read_body = tokio::time::timeout(stall_timeout, stream.read_exact(&mut body)).await;
        match read_body {
            Err(_elapsed) => break,
            Ok(Err(_io_err)) => break,
            Ok(Ok(_)) => {}
        }

        // ── Parse ─────────────────────────────────────────────────────────────
        // Respond FORMERR on TCP (RFC 1035): we have the message ID and
        // can craft a valid error response.  On TCP amplification is not
        // a concern because the connection is already established.
        let Ok(msg) = Message::parse(&body) else {
            let formerr = build_error_response_wire(
                0, /* ID unknown on total parse fail */
                Rcode::FormErr,
            );
            let _ = write_framed(&mut stream, &formerr).await;
            break;
        };

        // ── Cookie extraction (PROTO-010) ─────────────────────────────────────
        let opt_rr = extract_opt_rr_from_msg(&msg);
        let cookie_state =
            extract_cookie_state(opt_rr, client_ip, &config.server_cookie_secret, None);

        let qname_bytes = msg
            .questions
            .first()
            .map(|q| q.qname.as_wire_bytes().to_vec())
            .unwrap_or_default();

        // ── RequestCtx ────────────────────────────────────────────────────────
        let ctx = RequestCtx {
            source_ip: client_ip,
            mtls_identity: None,
            tsig_identity: None,
            transport: Transport::Tcp53,
            role: Role::Authoritative,
            operation: Operation::Query,
            qname: qname_bytes,
            has_valid_cookie: cookie_state.server_cookie_valid,
        };

        // ── Global budget (THREAT-065/072) ────────────────────────────────────
        // Acquire one in-flight slot for this query.  If the global cap is
        // reached, drop the connection with FIN immediately.
        if !resource_counters.try_acquire_global(&pipeline.resource_limits) {
            let refused = build_error_response_wire(msg.header.id, Rcode::Refused);
            let _ = write_framed(&mut stream, &refused).await;
            break;
        }

        // ── Admission pipeline ────────────────────────────────────────────────
        let decision = pipeline.evaluate(&ctx, Instant::now());
        if decision != crate::admission::PipelineDecision::Allow {
            resource_counters.release_global();
            let action = tcp_backpressure(&decision);
            match action {
                BackpressureAction::TcpFinClose => {
                    // Send REFUSED then close.
                    let refused = build_error_response_wire(msg.header.id, Rcode::Refused);
                    let _ = write_framed(&mut stream, &refused).await;
                    break;
                }
                BackpressureAction::TcpRstClose => {
                    // Unclean close — just drop the stream.
                    break;
                }
                // These variants are unreachable for TCP, but exhaustiveness.
                BackpressureAction::UdpSilentDrop | BackpressureAction::TcTruncated => {
                    break;
                }
            }
        }

        // Pipeline allowed the query; global slot is held until response is sent.

        // ── Process query ─────────────────────────────────────────────────────
        let response_wire = process_query(&msg, client_ip, dispatcher.as_deref());

        let Ok(mut response_msg) = Message::parse(&response_wire) else {
            resource_counters.release_global();
            break;
        };

        // ── Attach OPT RR (PROTO-008, PROTO-010, PROTO-014) ──────────────────
        let opt_rec = build_tcp_response_opt(
            &config,
            opt_rr,
            cookie_state.client_cookie_bytes.as_ref(),
            client_ip,
        );
        response_msg.additional.push(opt_rec);
        // INVARIANT: additional section has at most 1 OPT record; len() fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        {
            response_msg.header.arcount = response_msg.additional.len() as u16;
        }

        // Serialise — TCP has no payload limit (PROTO-116).
        let mut ser = Serialiser::new(true);
        let _ = ser.write_message(&response_msg);
        let final_wire = ser.finish();

        // ── Write response (2-byte length prefix + body) ──────────────────────
        let write_result =
            tokio::time::timeout(stall_timeout, write_framed(&mut stream, &final_wire)).await;

        // Release the in-flight slot now that the response is written (or
        // the write failed), regardless of the write outcome.
        resource_counters.release_global();

        match write_result {
            Err(_elapsed) => break,
            Ok(Err(_io_err)) => break,
            Ok(Ok(())) => {}
        }

        // ── Pipelining limit (THREAT-063) ─────────────────────────────────────
        pipeline_count += 1;
        if pipeline_count >= config.tcp_max_pipelining {
            // Close the connection gracefully after `max_pipelining` queries.
            break;
        }
    }

    // Tokio closes the TcpStream (FIN) when it is dropped.
}

// ── Helper: write RFC 7766 framed message ─────────────────────────────────────

/// Writes a 2-byte big-endian length prefix followed by `payload` to `stream`.
async fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    // INVARIANT: DNS messages are bounded by the 16-bit length prefix per RFC 7766.
    // The caller must ensure payload.len() <= 65535.
    #[allow(clippy::cast_possible_truncation)]
    let len = payload.len() as u16;
    let prefix = len.to_be_bytes();
    stream.write_all(&prefix).await?;
    stream.write_all(payload).await?;
    Ok(())
}

// ── Helper: extract OPT RR from message ──────────────────────────────────────

fn extract_opt_rr_from_msg(msg: &Message) -> Option<&OptRr> {
    msg.additional.iter().find_map(|r| {
        if let RData::Opt(opt) = &r.rdata {
            Some(opt)
        } else {
            None
        }
    })
}

// ── Helper: build TCP response OPT RR ────────────────────────────────────────

fn build_tcp_response_opt(
    config: &ListenerConfig,
    query_opt: Option<&OptRr>,
    client_cookie: Option<&[u8; 8]>,
    client_ip: std::net::IpAddr,
) -> Record {
    use heimdall_core::name::Name;

    let mut options: Vec<EdnsOption> = Vec::new();

    // Attach server cookie when the client sent a client cookie.
    if let Some(cc) = client_cookie {
        let echo = derive_response_cookie(cc, client_ip, &config.server_cookie_secret);
        options.push(EdnsOption::Cookie(echo));
    }

    // edns-tcp-keepalive (PROTO-014, PROTO-073): include when the client sent
    // TcpKeepalive option.
    if let Some(opt) = query_opt {
        let client_wants_keepalive = opt
            .options
            .iter()
            .any(|o| matches!(o, EdnsOption::TcpKeepalive(_)));
        if client_wants_keepalive {
            // Clamp to the maximum representable value for tcp_keepalive_option (u16).
            // INVARIANT: after min(), value is ≤ u16::MAX; cast is safe.
            #[allow(clippy::cast_possible_truncation)]
            let keepalive_secs = config.tcp_keepalive_secs.min(u32::from(u16::MAX / 10)) as u16;
            options.push(tcp_keepalive_option(keepalive_secs));
        }

        // Pass through unknown options (strip ECS, Cookie already handled).
        for o in &opt.options {
            match o {
                EdnsOption::Cookie(_)
                | EdnsOption::ClientSubnet(_)
                | EdnsOption::TcpKeepalive(_) => {}
                other => options.push(other.clone()),
            }
        }
    }

    let opt_rr = OptRr {
        // On TCP the UDP payload size field is meaningless, but RFC 6891
        // says the server SHOULD set it to the local interface MTU or a
        // well-known value.  We use our configured max_udp_payload.
        udp_payload_size: config.max_udp_payload,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: query_opt.is_some_and(|o| o.dnssec_ok),
        z: query_opt.map_or(0, |o| o.z),
        options,
    };

    Record {
        name: Name::root(),
        rtype: heimdall_core::record::Rtype::Opt,
        rclass: heimdall_core::header::Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(opt_rr),
    }
}

// ── Helper: build error response ──────────────────────────────────────────────

/// Builds a minimal error response (no question, no OPT) for use on TCP when
/// the message ID is available.
fn build_error_response_wire(id: u16, rcode: Rcode) -> Vec<u8> {
    use heimdall_core::header::Header;
    use heimdall_core::parser::Message;

    let hdr = Header {
        id,
        flags: 0x8000u16 | u16::from(rcode.as_u8()), // QR=1 | RCODE
        ..Header::default()
    };

    let msg = Message {
        header: hdr,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(false);
    let _ = ser.write_message(&msg);
    ser.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::edns::{EdnsOption, OptRr};
    use heimdall_core::header::{Header, Qclass, Qtype, Question};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;
    use heimdall_core::rdata::RData;

    use super::*;

    // ── RFC 7766 framing ──────────────────────────────────────────────────────

    #[test]
    fn two_byte_length_prefix_parses_correctly() {
        // Build a minimal DNS query in wire format.
        let mut hdr = Header::default();
        hdr.id = 0xABCD;
        hdr.qdcount = 1;
        let msg = Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str("example.com.").unwrap(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let mut ser = Serialiser::new(true);
        let _ = ser.write_message(&msg);
        let wire = ser.finish();

        // Simulate the 2-byte framing.
        let len = wire.len() as u16;
        let mut framed = Vec::with_capacity(2 + wire.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&wire);

        // Parse: first 2 bytes = length.
        let prefix = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(prefix, wire.len());
        let body = &framed[2..2 + prefix];
        let parsed = Message::parse(body).expect("valid message from framed body");
        assert_eq!(parsed.header.id, 0xABCD);
    }

    // ── edns-tcp-keepalive in response ────────────────────────────────────────

    #[test]
    fn keepalive_option_attached_when_client_requests_it() {
        use std::net::{IpAddr, Ipv4Addr};

        let config = ListenerConfig {
            tcp_keepalive_secs: 30,
            ..ListenerConfig::default()
        };
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Build an OPT RR that includes TcpKeepalive (client requests keepalive).
        let query_opt = OptRr {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![EdnsOption::TcpKeepalive(None)],
        };

        let opt_rec = build_tcp_response_opt(&config, Some(&query_opt), None, client_ip);

        let RData::Opt(resp_opt) = &opt_rec.rdata else {
            panic!("expected OPT record");
        };

        let has_keepalive = resp_opt
            .options
            .iter()
            .any(|o| matches!(o, EdnsOption::TcpKeepalive(Some(_))));
        assert!(has_keepalive, "response should carry TcpKeepalive option");
    }

    #[test]
    fn keepalive_option_absent_when_client_does_not_request_it() {
        use std::net::{IpAddr, Ipv4Addr};

        let config = ListenerConfig::default();
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let query_opt = OptRr {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![], // no TcpKeepalive option
        };

        let opt_rec = build_tcp_response_opt(&config, Some(&query_opt), None, client_ip);

        let RData::Opt(resp_opt) = &opt_rec.rdata else {
            panic!("expected OPT record");
        };

        let has_keepalive = resp_opt
            .options
            .iter()
            .any(|o| matches!(o, EdnsOption::TcpKeepalive(_)));
        assert!(
            !has_keepalive,
            "response should not carry TcpKeepalive when client did not request it"
        );
    }

    // ── build_error_response_wire ─────────────────────────────────────────────

    #[test]
    fn error_response_has_correct_rcode() {
        let wire = build_error_response_wire(0x1234, Rcode::FormErr);
        let parsed = Message::parse(&wire).expect("valid error response");
        assert_eq!(parsed.header.id, 0x1234);
        assert!(parsed.header.qr());
        assert_eq!(
            parsed.header.flags & 0x000F,
            u16::from(Rcode::FormErr.as_u8())
        );
    }
}
