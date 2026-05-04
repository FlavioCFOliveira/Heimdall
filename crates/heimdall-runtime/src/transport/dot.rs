// SPDX-License-Identifier: MIT

//! DNS-over-TLS (`DoT`) listener on port 853 (NET-004, SEC-001..016, THREAT-068).
//!
//! # Design overview
//!
//! The `DoT` listener mirrors the [`TcpListener`](super::tcp::TcpListener)
//! accept loop but wraps each accepted stream with a TLS handshake before
//! handing it to the per-connection handler.
//!
//! ## TLS handshake (SEC-001, SEC-005, THREAT-068)
//!
//! Each accepted [`TcpStream`] is passed to `TlsAcceptor::accept`, which
//! performs the TLS 1.3 handshake asynchronously. A `tokio::time::timeout`
//! wraps the handshake to enforce the `tls_handshake_timeout_secs` limit
//! (THREAT-068). Handshake failures are logged at `WARN` level; no DNS
//! response is sent on failure (SEC-002 / fail-closed principle).
//!
//! ## mTLS identity (SEC-012..016, SEC-067)
//!
//! If the [`TlsServerConfig`] has `mtls_trust_anchor` set, the post-handshake
//! peer certificate is extracted and passed to
//! [`extract_mtls_identity`]. The resulting
//! identity string is attached to [`RequestCtx::mtls_identity`] for ACL
//! evaluation.
//!
//! ## RFC 7766 framing and query processing
//!
//! After the handshake, the per-connection handler re-uses the same 2-byte
//! length-prefix framing and `process_query` stub as the classic TCP listener.
//! AXFR/IXFR operations on this listener (`XoT`, task #267) go through the same
//! ACL gate with `Operation::Axfr`/`Operation::Ixfr`; the stub returns REFUSED
//! for all queries at this sprint.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use heimdall_core::header::Rcode;
use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;

use crate::admission::resource::ResourceCounters;
use crate::admission::{AdmissionPipeline, Operation, RequestCtx, Role, Transport};
use crate::drain::Drain;

use super::backpressure::{BackpressureAction, tcp_backpressure};
use super::tls::{TlsServerConfig, extract_mtls_identity};
use super::tls_telemetry::TlsTelemetry;
use super::{ListenerConfig, QueryDispatcher, TransportError, apply_edns_padding, extract_query_opt, process_query};

// ── DotListener ───────────────────────────────────────────────────────────────

/// DNS-over-TLS (`DoT`) listener on port 853 (NET-004, SEC-001..016).
pub struct DotListener {
    listener: TokioTcpListener,
    tls_acceptor: TlsAcceptor,
    config: ListenerConfig,
    tls_config: TlsServerConfig,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<TlsTelemetry>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
}

impl DotListener {
    /// Creates a new [`DotListener`] from an already-bound `TcpListener` and a
    /// pre-built [`TlsAcceptor`].
    ///
    /// Use [`TlsAcceptor::from`] with an `Arc<rustls::ServerConfig>` produced
    /// by [`build_tls_server_config`](super::tls::build_tls_server_config).
    #[must_use]
    pub fn new(
        listener: TokioTcpListener,
        tls_acceptor: TlsAcceptor,
        config: ListenerConfig,
        tls_config: TlsServerConfig,
        pipeline: Arc<AdmissionPipeline>,
        resource_counters: Arc<ResourceCounters>,
        telemetry: Arc<TlsTelemetry>,
    ) -> Self {
        Self {
            listener,
            tls_acceptor,
            config,
            tls_config,
            pipeline,
            resource_counters,
            telemetry,
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

    /// Runs the `DoT` accept loop until `drain` signals shutdown.
    ///
    /// Each accepted connection is wrapped in a TLS handshake and handled in
    /// its own spawned tokio task.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] on a fatal accept error on the listening
    /// socket.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let config = Arc::new(self.config);
        let tls_config = Arc::new(self.tls_config);
        let pipeline = Arc::clone(&self.pipeline);
        let resource_counters = Arc::clone(&self.resource_counters);
        let telemetry = Arc::clone(&self.telemetry);
        let acceptor = self.tls_acceptor;
        let dispatcher = self.dispatcher.clone();

        loop {
            if drain.is_draining() {
                break;
            }

            let (stream, addr) = self.listener.accept().await.map_err(TransportError::Io)?;

            let config_clone = Arc::clone(&config);
            let tls_config_clone = Arc::clone(&tls_config);
            let pipeline_clone = Arc::clone(&pipeline);
            let resource_counters_clone = Arc::clone(&resource_counters);
            let telemetry_clone = Arc::clone(&telemetry);
            let drain_clone = Arc::clone(&drain);
            let acceptor_clone = acceptor.clone();
            let dispatcher_clone = dispatcher.clone();

            tokio::spawn(async move {
                handle_dot_connection(
                    stream,
                    addr.ip(),
                    acceptor_clone,
                    config_clone,
                    tls_config_clone,
                    pipeline_clone,
                    resource_counters_clone,
                    telemetry_clone,
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

/// Handles a single `DoT` connection: TLS handshake, then RFC 7766 framing.
#[allow(clippy::too_many_arguments)]
async fn handle_dot_connection(
    stream: TcpStream,
    client_ip: std::net::IpAddr,
    acceptor: TlsAcceptor,
    config: Arc<ListenerConfig>,
    tls_config: Arc<TlsServerConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<TlsTelemetry>,
    drain: Arc<Drain>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) {
    // ── TLS handshake with timeout (THREAT-068) ───────────────────────────────
    let handshake_dur = Duration::from_secs(u64::from(config.tcp_handshake_timeout_secs));

    let tls_result = tokio::time::timeout(handshake_dur, acceptor.accept(stream)).await;

    let mut tls_stream = match tls_result {
        Err(_elapsed) => {
            // Handshake timed out (THREAT-068): increment failure counters,
            // log a warning, do not send any DNS response (fail-closed, SEC-002).
            telemetry
                .handshake_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            telemetry
                .handshake_failures_timeout
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                peer = %client_ip,
                "DoT TLS handshake timed out"
            );
            return;
        }
        Ok(Err(e)) => {
            // Handshake failed (bad cert, protocol error, etc.).
            telemetry
                .handshake_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Classify: certificate-related errors increment the cert_invalid counter.
            let is_cert_err = is_certificate_error(&e);
            if is_cert_err {
                telemetry
                    .handshake_failures_cert_invalid
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            tracing::warn!(
                peer = %client_ip,
                error = %e,
                "DoT TLS handshake failed"
            );
            return;
        }
        Ok(Ok(stream)) => {
            telemetry
                .handshake_successes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            stream
        }
    };

    // ── mTLS identity extraction (SEC-012..016, SEC-067) ─────────────────────
    let mtls_identity = extract_peer_mtls_identity(&tls_stream, &tls_config);

    // ── RFC 7766 per-message loop (mirrors tcp.rs) ────────────────────────────
    let stall_timeout = Duration::from_secs(u64::from(config.tcp_stall_timeout_secs));
    let idle_timeout = Duration::from_secs(u64::from(config.tcp_idle_timeout_secs));

    let mut pipeline_count: u32 = 0;
    let mut first_message = true;

    loop {
        if drain.is_draining() {
            break;
        }

        let read_timeout = if first_message {
            handshake_dur
        } else {
            idle_timeout
        };

        // ── Read 2-byte length prefix (RFC 7766) ──────────────────────────────
        let mut len_buf = [0u8; 2];
        let read_len =
            tokio::time::timeout(read_timeout, tls_stream.read_exact(&mut len_buf)).await;

        match read_len {
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }

        first_message = false;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len == 0 {
            // Framing error — close the connection.
            break;
        }

        // ── Read message body ─────────────────────────────────────────────────
        let mut body = vec![0u8; msg_len];
        match tokio::time::timeout(stall_timeout, tls_stream.read_exact(&mut body)).await {
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }

        // ── Parse ─────────────────────────────────────────────────────────────
        let Ok(msg) = Message::parse(&body) else {
            let formerr = build_error_response_wire(0, Rcode::FormErr);
            let _ = write_framed(&mut tls_stream, &formerr).await;
            break;
        };

        let qname_bytes = msg
            .questions
            .first()
            .map(|q| q.qname.as_wire_bytes().to_vec())
            .unwrap_or_default();

        // ── RequestCtx ────────────────────────────────────────────────────────
        let ctx = RequestCtx {
            source_ip: client_ip,
            mtls_identity: mtls_identity.clone(),
            tsig_identity: None,
            transport: Transport::DoT,
            role: Role::Authoritative,
            operation: Operation::Query,
            qname: qname_bytes,
            has_valid_cookie: false, // DoT does not use DNS Cookies (RFC 7858)
        };

        // ── Global budget (THREAT-065/072) ────────────────────────────────────
        if !resource_counters.try_acquire_global(&pipeline.resource_limits) {
            let refused = build_error_response_wire(msg.header.id, Rcode::Refused);
            let _ = write_framed(&mut tls_stream, &refused).await;
            break;
        }

        // ── Admission pipeline ────────────────────────────────────────────────
        let decision = pipeline.evaluate(&ctx, std::time::Instant::now());
        if decision != crate::admission::PipelineDecision::Allow {
            resource_counters.release_global();
            let action = tcp_backpressure(&decision);
            match action {
                BackpressureAction::TcpFinClose => {
                    let refused = build_error_response_wire(msg.header.id, Rcode::Refused);
                    let _ = write_framed(&mut tls_stream, &refused).await;
                    break;
                }
                BackpressureAction::TcpRstClose
                | BackpressureAction::UdpSilentDrop
                | BackpressureAction::TcTruncated
                | BackpressureAction::UdpRefused => {
                    break;
                }
            }
        }

        // ── Process query ─────────────────────────────────────────────────────
        let response_wire = process_query(&msg, client_ip, dispatcher.as_deref(), false);

        // ── Attach OPT RR with RFC 8467 EDNS padding ──────────────────────────
        let query_opt = extract_query_opt(&msg);
        let final_wire = apply_edns_padding(&response_wire, query_opt, config.max_udp_payload);

        // ── Write response ────────────────────────────────────────────────────
        let write_result =
            tokio::time::timeout(stall_timeout, write_framed(&mut tls_stream, &final_wire)).await;

        resource_counters.release_global();

        match write_result {
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(())) => {}
        }

        // ── Pipelining limit (THREAT-063) ─────────────────────────────────────
        pipeline_count += 1;
        if pipeline_count >= config.tcp_max_pipelining {
            break;
        }
    }
    // TlsStream is dropped here; tokio-rustls closes the TLS connection cleanly.
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Writes a 2-byte big-endian length prefix followed by `payload` to `stream`.
async fn write_framed(stream: &mut TlsStream<TcpStream>, payload: &[u8]) -> std::io::Result<()> {
    // INVARIANT: DNS messages are bounded by the 16-bit length prefix per RFC 7766.
    #[allow(clippy::cast_possible_truncation)]
    let len = payload.len() as u16;
    let prefix = len.to_be_bytes();
    stream.write_all(&prefix).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// Builds a minimal error response for use when a message ID is available.
fn build_error_response_wire(id: u16, rcode: Rcode) -> Vec<u8> {
    use heimdall_core::header::Header;

    let hdr = Header {
        id,
        flags: 0x8000u16 | u16::from(rcode.as_u8()),
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

/// Extracts the mTLS identity from the post-handshake peer certificate, if
/// mTLS is enabled and a peer certificate was presented.
fn extract_peer_mtls_identity(
    tls_stream: &TlsStream<TcpStream>,
    tls_config: &TlsServerConfig,
) -> Option<String> {
    // mTLS is only attempted when a trust anchor is configured (SEC-013).
    tls_config.mtls_trust_anchor.as_ref()?;

    let conn = tls_stream.get_ref().1;
    // `peer_certificates()` returns the client's certificate chain, if any.
    // Index 0 is the end-entity certificate (the leaf).
    let leaf = conn.peer_certificates()?.first()?.clone();

    extract_mtls_identity(&leaf, tls_config.mtls_identity_source)
}

/// Returns `true` if the I/O error from a handshake failure is related to
/// certificate validation (heuristic: TLS alerts 42 = `bad_certificate`,
/// 43 = `unsupported_certificate`, 44 = `certificate_revoked`,
/// 45 = `certificate_expired`, 46 = `certificate_unknown`, 47 = `illegal_parameter`).
///
/// tokio-rustls surfaces handshake errors as `std::io::Error` wrapping a
/// `rustls::Error`.  We use the formatted string as a heuristic because
/// `io::Error::get_ref()` can downcast to the source only when the type is
/// known at compile time.
fn is_certificate_error(e: &std::io::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("certificate")
        || msg.contains("bad_certificate")
        || msg.contains("unknown_ca")
        || msg.contains("access_denied")
}
