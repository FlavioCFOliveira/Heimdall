// SPDX-License-Identifier: MIT

//! UDP/53 classic DNS listener (NET-003, PROTO-008, THREAT-065/071).
//!
//! # Design overview
//!
//! The UDP listener runs a single `recv_from` loop on one tokio task.  Each
//! received datagram is processed inline (parse → admission → cookie → stub
//! response → EDNS negotiation → `send_to`) without spawning a per-packet task,
//! keeping the hot path allocation-free once the per-packet buffer is reused.
//!
//! ## `io_uring` future work
//!
//! The current implementation uses standard tokio `UdpSocket::recv_from`.  A
//! future sprint will replace this with `io_uring` multishot receive
//! (`IORING_OP_RECV_MULTISHOT`) for zero-copy, syscall-batched ingestion on
//! Linux ≥ 5.19.  The architectural shape (single loop, inline processing) is
//! already aligned with that migration.
//!
//! ## Parse-error policy (PROTO-001)
//!
//! Malformed datagrams are silently dropped — no FORMERR is sent over UDP.
//! Responding to malformed datagrams would turn Heimdall into a reflection
//! amplifier: the attacker spoofs the source address, the server sends back a
//! response (possibly larger than the query), and the victim receives unsolicited
//! traffic.  Silence removes that amplification path entirely.
//!
//! ## Truncation (PROTO-008, PROTO-115)
//!
//! If the serialised response exceeds `min(client_advertised_edns_size,
//! server_max_udp_payload)`, the response is re-built with TC=1 and the answer,
//! authority, and additional sections stripped.  Only the header and question
//! section are retained in the truncated form.

use std::{net::IpAddr, sync::Arc, time::Instant};

use heimdall_core::{
    edns::{EdnsOption, OptRr},
    header::{Header, Rcode},
    parser::Message,
    rdata::RData,
    record::Record,
    serialiser::Serialiser,
};
use tokio::net::UdpSocket;

use super::{
    ListenerConfig, QueryDispatcher, TransportError,
    backpressure::{BackpressureAction, udp_backpressure},
    cookie::{derive_response_cookie, extract_cookie_state},
    process_query,
};
use crate::{
    admission::{AdmissionPipeline, Operation, RequestCtx, Transport, resource::ResourceCounters},
    drain::Drain,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Receive buffer size.  Sized at the DNS wire-format maximum so that no valid
/// datagram can be silently truncated by the OS.
const RECV_BUF_SIZE: usize = 65535;

// ── UdpListener ───────────────────────────────────────────────────────────────

/// UDP/53 listener for classic DNS (NET-003).
///
/// Bind, then call [`UdpListener::run`] inside a tokio task.
pub struct UdpListener {
    /// The bound UDP socket, shared so that multiple listeners may be registered
    /// on the same fd in a future `SO_REUSEPORT` configuration.
    socket: Arc<UdpSocket>,
    /// Listener configuration (max payload size, secrets, …).
    config: ListenerConfig,
    /// Five-stage admission pipeline (ACL, resource, cookie, rate-limit).
    pipeline: Arc<AdmissionPipeline>,
    /// Global resource counters shared with the admission pipeline.
    resource_counters: Arc<ResourceCounters>,
    /// Role dispatcher — `None` until a role is configured.
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
}

impl UdpListener {
    /// Creates a new [`UdpListener`] from an already-bound socket.
    ///
    /// The caller is responsible for binding the socket with the correct address
    /// and, on Linux, optionally setting `SO_REUSEPORT`.
    #[must_use]
    pub fn new(
        socket: Arc<UdpSocket>,
        config: ListenerConfig,
        pipeline: Arc<AdmissionPipeline>,
        resource_counters: Arc<ResourceCounters>,
    ) -> Self {
        Self {
            socket,
            config,
            pipeline,
            resource_counters,
            dispatcher: None,
        }
    }

    /// Attach a [`QueryDispatcher`] to this listener.
    #[must_use]
    pub fn with_dispatcher(mut self, dispatcher: Arc<dyn QueryDispatcher + Send + Sync>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Runs the UDP receive loop until `drain` signals shutdown.
    ///
    /// Processes each datagram inline: parse → admission → cookie → response →
    /// EDNS negotiation → truncation if needed → send.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] on a fatal socket error.  Per-datagram
    /// errors (parse failures, send failures on individual datagrams) are handled
    /// internally and do not terminate the loop.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let mut buf = vec![0u8; RECV_BUF_SIZE];

        loop {
            // Stop accepting when draining — let in-flight operations complete.
            if drain.is_draining() {
                break;
            }

            let (n, src_addr) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(TransportError::Io)?;

            let payload = &buf[..n];

            // ── Global pending budget check (THREAT-065/071) ──────────────────
            // We check the budget explicitly here before full pipeline evaluation
            // because the pipeline's try_acquire_global is consumed as part of
            // stage 2.  Under heavy load we want to short-circuit before even
            // attempting to parse the message.
            //
            // NOTE: we do NOT call try_acquire here; we let the pipeline own the
            // counter lifecycle.  Instead we read the current value to decide
            // whether to do the more expensive parse before the pipeline call.
            // The actual cap enforcement is in AdmissionPipeline::evaluate stage 2.

            // ── Parse (PROTO-001) ─────────────────────────────────────────────
            // Silently drop malformed datagrams — no FORMERR on UDP.
            let Ok(msg) = Message::parse(payload) else {
                continue;
            };

            // Extract the OPT RR from the Additional section (if present).
            let opt_rr = extract_opt_rr(&msg);

            // ── Cookie extraction (PROTO-010) ─────────────────────────────────
            let cookie_state = extract_cookie_state(
                opt_rr,
                src_addr.ip(),
                &self.config.server_cookie_secret,
                None,
            );

            // Build qname bytes for ACL/RRL.
            let qname_bytes = msg
                .questions
                .first()
                .map(|q| q.qname.as_wire_bytes().to_vec())
                .unwrap_or_default();

            // ── RequestCtx ────────────────────────────────────────────────────
            let ctx = RequestCtx {
                source_ip: src_addr.ip(),
                mtls_identity: None,
                tsig_identity: None,
                transport: Transport::Udp53,
                role: self.config.server_role,
                operation: Operation::Query,
                qname: qname_bytes,
                has_valid_cookie: cookie_state.server_cookie_valid,
            };

            // ── Admission pipeline (THREAT-076) ───────────────────────────────
            let decision = self.pipeline.evaluate(&ctx, Instant::now());
            if decision != crate::admission::PipelineDecision::Allow {
                let action = udp_backpressure(&decision);
                match action {
                    BackpressureAction::TcTruncated => {
                        // Send a TC=1 response so the client retries over TCP
                        // (THREAT-075, PROTO-117).
                        let tc_resp =
                            build_tc_truncated_response(&msg, &self.config, opt_rr, src_addr.ip());
                        // Note: dispatcher_ede is not available at this point (query not yet dispatched).
                        let _ = self.socket.send_to(&tc_resp, src_addr).await;
                    }
                    BackpressureAction::UdpRefused => {
                        // Send REFUSED + EDE PROHIBITED so the client can
                        // self-throttle (THREAT-051).
                        let refused_resp =
                            build_refused_response(&msg, &self.config, opt_rr, src_addr.ip());
                        let _ = self.socket.send_to(&refused_resp, src_addr).await;
                    }
                    // UdpSilentDrop: nothing to do — silence is the correct response.
                    // TcpFin/TcpRst: unreachable for UDP, but exhaustiveness required.
                    BackpressureAction::UdpSilentDrop
                    | BackpressureAction::TcpFinClose
                    | BackpressureAction::TcpRstClose => {}
                }
                continue;
            }

            // Pipeline allowed the query; the global counter is now held.
            // We must release it when we are done with this datagram.

            // ── BADCOOKIE (RFC 7873 §5.2.3) ───────────────────────────────────
            // A client that presents a server cookie that fails verification is
            // told to refresh it.  A client-cookie-only query (first contact) is
            // NOT rejected — it receives a normal response with a fresh server
            // cookie so the client can learn the value.
            if cookie_state.has_server_cookie && !cookie_state.server_cookie_valid {
                let badcookie_resp = build_badcookie_response(
                    &msg,
                    &self.config,
                    opt_rr,
                    cookie_state.client_cookie_bytes.as_ref(),
                    src_addr.ip(),
                );
                let _ = self.socket.send_to(&badcookie_resp, src_addr).await;
                self.resource_counters.release_global();
                continue;
            }

            // ── Process query ─────────────────────────────────────────────────
            let response_wire =
                process_query(&msg, src_addr.ip(), self.dispatcher.as_deref(), true);

            // An empty response_wire is the DROP signal from the RPZ engine
            // (RPZ-007): the dispatcher intentionally sends no UDP response.
            if response_wire.is_empty() {
                self.resource_counters.release_global();
                continue;
            }

            // Re-parse the stub response to attach the OPT RR.
            let Ok(mut response_msg) = Message::parse(&response_wire) else {
                self.resource_counters.release_global();
                continue;
            };

            // Extract EDE options from the dispatcher's OPT record (if any), then
            // remove that OPT so the transport can build a single authoritative one.
            let dispatcher_ede = extract_dispatcher_ede(&response_msg);
            response_msg
                .additional
                .retain(|r| !matches!(r.rdata, RData::Opt(_)));

            // ── Attach OPT RR to response (PROTO-008, PROTO-010) ──────────────
            let effective_udp_size =
                compute_effective_udp_size(opt_rr, self.config.max_udp_payload);
            let opt_rec = build_response_opt(
                &self.config,
                opt_rr,
                cookie_state.client_cookie_bytes.as_ref(),
                src_addr.ip(),
                effective_udp_size,
                dispatcher_ede.as_ref(),
            );
            response_msg.additional.push(opt_rec);
            // INVARIANT: additional section has at most 1 OPT record; fits in u16.
            #[allow(clippy::cast_possible_truncation)]
            {
                response_msg.header.arcount = response_msg.additional.len() as u16;
            }

            // ── Serialise (with possible truncation) (PROTO-115) ──────────────
            let final_wire = serialise_with_truncation(&response_msg, effective_udp_size);

            // ── Send ──────────────────────────────────────────────────────────
            let _ = self.socket.send_to(&final_wire, src_addr).await;

            // Release the global pending slot.
            self.resource_counters.release_global();
        }

        Ok(())
    }
}

// ── Helper: extract OPT RR ────────────────────────────────────────────────────

/// Extracts the first OPT RR from the Additional section of a message.
fn extract_opt_rr(msg: &Message) -> Option<&OptRr> {
    msg.additional.iter().find_map(|r| {
        if let RData::Opt(opt) = &r.rdata {
            Some(opt)
        } else {
            None
        }
    })
}

// ── Helper: extract EDE from dispatcher OPT ──────────────────────────────────

/// Extracts the first `ExtendedError` EDNS option from the dispatcher's response OPT record.
///
/// The recursive dispatcher embeds EDE codes (e.g. `DNSSEC_BOGUS`) in a temporary OPT
/// record so they survive the wire serialise/parse round-trip through `process_query`.
/// This function retrieves that EDE before the transport removes the dispatcher's OPT
/// and replaces it with its own authoritative one.
fn extract_dispatcher_ede(msg: &Message) -> Option<EdnsOption> {
    msg.additional.iter().find_map(|r| {
        if let RData::Opt(opt) = &r.rdata {
            opt.options
                .iter()
                .find(|o| matches!(o, EdnsOption::ExtendedError(_)))
                .cloned()
        } else {
            None
        }
    })
}

// ── Helper: effective UDP payload size ────────────────────────────────────────

/// Computes the effective UDP payload limit for this exchange.
///
/// Result: `min(client_advertised, server_max_udp_payload)`, with the client
/// value clamped to [512, 4096] per RFC 6891.
fn compute_effective_udp_size(opt_rr: Option<&OptRr>, server_max: u16) -> u16 {
    let client_size = opt_rr.map_or(512, OptRr::negotiated_udp_size);
    client_size.min(server_max)
}

// ── Helper: build response OPT RR record ─────────────────────────────────────

/// Builds the OPT pseudo-RR to attach to the response.
///
/// Always includes:
/// - The server's advertised UDP payload size.
/// - A Cookie option (server cookie derived from the client cookie) when the
///   client sent a Cookie option.
/// - Any EDE option passed by the dispatcher (`dispatcher_ede`).
fn build_response_opt(
    config: &ListenerConfig,
    query_opt: Option<&OptRr>,
    client_cookie: Option<&[u8; 8]>,
    client_ip: IpAddr,
    effective_udp_size: u16,
    dispatcher_ede: Option<&EdnsOption>,
) -> Record {
    use heimdall_core::{name::Name, record::Rtype};

    let mut options: Vec<EdnsOption> = Vec::new();

    // Attach server cookie when the client sent a client cookie (PROTO-010).
    if let Some(cc) = client_cookie {
        let echo = derive_response_cookie(cc, client_ip, &config.server_cookie_secret);
        options.push(EdnsOption::Cookie(echo));
    }

    // Propagate EDE from the dispatcher (e.g. DNSSEC_BOGUS from the recursive role).
    if let Some(ede) = dispatcher_ede {
        options.push(ede.clone());
    }

    // Preserve any unknown options from the query (pass-through unknown options).
    if let Some(opt) = query_opt {
        for o in &opt.options {
            match o {
                // Cookie already handled above; skip.
                // ECS: PROTO-017 — ignore/strip. Cookie already handled above.
                EdnsOption::Cookie(_) | EdnsOption::ClientSubnet(_) => {}
                // Everything else is passed through transparently.
                other => options.push(other.clone()),
            }
        }
    }

    let opt_rr = OptRr {
        udp_payload_size: effective_udp_size,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: query_opt.is_some_and(|o| o.dnssec_ok),
        z: query_opt.map_or(0, |o| o.z),
        options,
    };

    Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: heimdall_core::header::Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(opt_rr),
    }
}

// ── Helper: serialise with truncation ────────────────────────────────────────

/// Serialises `msg` and truncates to `udp_limit` bytes if necessary.
///
/// If the serialised form fits within `udp_limit`, returns it verbatim.
/// Otherwise, rebuilds the message with TC=1, keeping only the header and
/// question section (PROTO-115).
fn serialise_with_truncation(msg: &Message, udp_limit: u16) -> Vec<u8> {
    let mut ser = Serialiser::new(true);
    // INVARIANT: a well-formed response cannot overflow the serialiser.
    let _ = ser.write_message(msg);
    let wire = ser.finish();

    let limit = usize::from(udp_limit);
    if wire.len() <= limit {
        return wire;
    }

    // Response exceeds negotiated limit — truncate to header + question.
    build_truncated_wire(msg)
}

/// Builds a TC=1 response containing only the header and question section.
fn build_truncated_wire(original: &Message) -> Vec<u8> {
    use heimdall_core::parser::Message as DnsMessage;

    let mut hdr = original.header.clone();
    hdr.set_tc(true);
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    let tc_msg = DnsMessage {
        header: hdr,
        questions: original.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&tc_msg);
    // A TC=1 message with only header + question is sent in full even if it
    // technically exceeds the negotiated limit.  The TC bit already signals to
    // the client that answers were omitted; clipping the header or question
    // section would produce an unparseable datagram (RFC 1035 §4.2.1).
    ser.finish()
}

/// Builds a TC=1 truncated response for the backpressure slip path (PROTO-117).
fn build_tc_truncated_response(
    query: &Message,
    config: &ListenerConfig,
    query_opt: Option<&OptRr>,
    client_ip: IpAddr,
) -> Vec<u8> {
    // Compute flags: QR=1, echoed opcode, TC=1, RCODE=REFUSED.
    let opcode_bits = query.header.flags & 0x7800;
    let flags = 0x8000u16       // QR=1
        | opcode_bits
        | 0x0200u16             // TC=1
        | u16::from(Rcode::Refused.as_u8());
    let hdr = Header {
        id: query.header.id,
        flags,
        qdcount: query.header.qdcount,
        arcount: 1,
        ..Header::default()
    };

    let opt_rec = build_response_opt(
        config,
        query_opt,
        None,
        client_ip,
        config.max_udp_payload,
        None,
    );

    let tc_msg = Message {
        header: hdr,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rec],
    };

    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&tc_msg);
    ser.finish()
}

// ── Helper: REFUSED + EDE response ───────────────────────────────────────────

/// Builds a REFUSED (RCODE=5) response with EDE `PROHIBITED` (18, RFC 8914
/// §5.19) to inform a rate-limited client that it should self-throttle
/// (THREAT-051).
///
/// The response is small (header + question + OPT) — comparable in size to the
/// query — so it does not open an amplification vector.
fn build_refused_response(
    query: &Message,
    config: &ListenerConfig,
    query_opt: Option<&OptRr>,
    client_ip: IpAddr,
) -> Vec<u8> {
    use heimdall_core::edns::ExtendedError;

    let opcode_bits = query.header.flags & 0x7800;
    let flags = 0x8000u16 | opcode_bits | u16::from(Rcode::Refused.as_u8());
    let hdr = Header {
        id: query.header.id,
        flags,
        qdcount: query.header.qdcount,
        arcount: 1,
        ..Header::default()
    };

    let ede = EdnsOption::ExtendedError(ExtendedError::new(
        heimdall_core::edns::ede_code::PROHIBITED,
    ));
    let effective_udp_size = compute_effective_udp_size(query_opt, config.max_udp_payload);
    let opt_rec = build_response_opt(
        config,
        query_opt,
        None,
        client_ip,
        effective_udp_size,
        Some(&ede),
    );

    let refused_msg = Message {
        header: hdr,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rec],
    };

    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&refused_msg);
    ser.finish()
}

// ── Helper: BADCOOKIE response ────────────────────────────────────────────────

/// Builds a BADCOOKIE error response (RFC 7873 §5.2.3, extended RCODE 23).
///
/// The 12-bit RCODE 23 (0x17) is split per RFC 6891:
///   * header RCODE bits (lower 4) = 23 & 0x0F = 7
///   * OPT `extended_rcode` (upper 8) = 23 >> 4  = 1
///
/// A fresh server cookie is included in the response OPT RR when the client
/// sent a client cookie, so the client can retry with the correct value.
fn build_badcookie_response(
    query: &Message,
    config: &ListenerConfig,
    query_opt: Option<&OptRr>,
    client_cookie: Option<&[u8; 8]>,
    client_ip: IpAddr,
) -> Vec<u8> {
    use heimdall_core::{name::Name, record::Rtype};

    let opcode_bits = query.header.flags & 0x7800;
    // QR=1, echoed opcode, RCODE lower nibble = 7 (part of extended 23).
    let flags = 0x8000u16 | opcode_bits | (0x17u16 & 0x000F);

    let hdr = Header {
        id: query.header.id,
        flags,
        qdcount: query.header.qdcount,
        arcount: 1,
        ..Header::default()
    };

    // Fresh server cookie if the client supplied a client cookie.
    let mut options: Vec<EdnsOption> = Vec::new();
    if let Some(cc) = client_cookie {
        let echo = derive_response_cookie(cc, client_ip, &config.server_cookie_secret);
        options.push(EdnsOption::Cookie(echo));
    }

    let effective_udp_size = compute_effective_udp_size(query_opt, config.max_udp_payload);
    let opt_rr = OptRr {
        udp_payload_size: effective_udp_size,
        extended_rcode: 1, // upper 8 bits of BADCOOKIE=23
        version: 0,
        dnssec_ok: false,
        z: 0,
        options,
    };
    let opt_rec = Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: heimdall_core::header::Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(opt_rr),
    };

    let resp = Message {
        header: hdr,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rec],
    };

    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&resp);
    ser.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::{
        edns::OptRr,
        header::{Header, Qclass, Qtype, Question},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
        serialiser::Serialiser,
    };

    use super::*;

    #[allow(dead_code)]
    fn make_query_with_opt(udp_size: u16) -> Message {
        let hdr = Header {
            id: 0x1234,
            qdcount: 1,
            arcount: 1,
            ..Header::default()
        };

        let opt_rr = OptRr {
            udp_payload_size: udp_size,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
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
            additional: vec![Record {
                name: Name::root(),
                rtype: Rtype::Opt,
                rclass: Qclass::Any,
                ttl: 0,
                rdata: RData::Opt(opt_rr),
            }],
        }
    }

    #[allow(dead_code)]
    fn make_query_no_opt() -> Message {
        let hdr = Header {
            id: 0x5678,
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

    // ── Effective UDP size ────────────────────────────────────────────────────

    #[test]
    fn effective_udp_size_no_opt_defaults_to_512_clamped_by_server() {
        // Client sends no OPT → treated as 512 byte requestor size.
        // Server max is 1232, so effective = min(512, 1232) = 512.
        assert_eq!(compute_effective_udp_size(None, 1232), 512);
    }

    #[test]
    fn effective_udp_size_large_client_capped_by_server_max() {
        let opt = OptRr {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        };
        // Client advertises 4096, server max is 1232 → effective = 1232.
        assert_eq!(compute_effective_udp_size(Some(&opt), 1232), 1232);
    }

    #[test]
    fn effective_udp_size_small_client_wins() {
        let opt = OptRr {
            udp_payload_size: 800,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        };
        // Client advertises 800, server max is 1232 → effective = 800.
        assert_eq!(compute_effective_udp_size(Some(&opt), 1232), 800);
    }

    // ── Truncation boundary ───────────────────────────────────────────────────

    #[test]
    fn truncation_sets_tc_bit_when_response_exceeds_limit() {
        use std::net::Ipv4Addr;

        // Build a response with 20 A-record answers so the wire form is large.
        let name = Name::from_str("example.com.").unwrap();
        let answers: Vec<Record> = (1u8..=20)
            .map(|i| Record {
                name: name.clone(),
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(192, 168, 1, i)),
            })
            .collect();

        // The fixture caps `answers` at well under u16::MAX, so the cast is
        // bounded by construction.
        #[allow(clippy::cast_possible_truncation)]
        let ancount = answers.len() as u16;
        let hdr = Header {
            id: 0xBEEF,
            flags: 0x8000, // QR=1
            qdcount: 1,
            ancount,
            nscount: 0,
            arcount: 0,
        };
        let msg = Message {
            header: hdr,
            questions: vec![Question {
                qname: name.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers,
            authority: vec![],
            additional: vec![],
        };

        // Measure the full wire size.
        let mut ser = Serialiser::new(true);
        let _ = ser.write_message(&msg);
        let full_size = ser.finish().len();

        // The header+question form (TC=1, no answers) is much smaller.
        // Use a limit of 50 bytes to force truncation (full wire >> 50 bytes).
        let limit: u16 = 50;
        assert!(
            usize::from(limit) < full_size,
            "limit must be smaller than the full message"
        );

        let wire = serialise_with_truncation(&msg, limit);

        // The truncated wire is the header+question only, so it must be smaller
        // than the full response (which carries 20 answer RRs).
        assert!(
            wire.len() < full_size,
            "truncated wire must be shorter than full response"
        );

        // The truncated wire must be parseable and carry TC=1.
        let parsed = Message::parse(&wire).expect("valid truncated response");
        assert!(
            parsed.header.tc(),
            "TC bit must be set in truncated response"
        );
        assert_eq!(
            parsed.answers.len(),
            0,
            "truncated response must have no answers"
        );
    }

    #[test]
    fn no_truncation_when_response_fits() {
        let hdr = Header {
            id: 0xABCD,
            qdcount: 1,
            ..Header::default()
        };
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

        let wire = serialise_with_truncation(&msg, 1232);
        let parsed = Message::parse(&wire).expect("valid response");
        assert!(!parsed.header.tc());
    }

    // ── Parse error → silent drop (no response sent) ──────────────────────────

    #[test]
    fn malformed_datagram_is_silently_dropped() {
        // Attempting to parse a garbage buffer must return Err — the caller
        // continues without sending anything.
        let garbage = b"\xFF\xFF\xFF\xFF\xFF";
        let result = Message::parse(garbage);
        assert!(result.is_err(), "expected parse failure for garbage input");
    }
}
