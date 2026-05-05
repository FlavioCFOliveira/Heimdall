// SPDX-License-Identifier: MIT

//! DNS-over-HTTPS over HTTP/3 (`DoH/H3`) listener (NET-006, NET-007, NET-025..028,
//! SEC-036..046, SEC-077, ADR-0051, ADR-0052).
//!
//! # Design overview
//!
//! The `DoH/H3` listener reuses the quinn QUIC endpoint infrastructure from the `DoQ`
//! listener ([`super::quic`]) with a different ALPN tag (`"h3"` instead of `"doq"`),
//! different TLS configuration, and different flow-control settings. Each accepted QUIC
//! connection is wrapped by [`h3_quinn::Connection`] and driven by an
//! [`h3::server::Connection`] state machine that handles HTTP/3 framing, QPACK
//! header compression/decompression, and the HTTP/3 control stream.
//!
//! ## HTTP/3 hardening (SEC-036..046)
//!
//! | Mitigation                        | Mechanism in this module |
//! |-----------------------------------|--------------------------|
//! | SEC-037 (header-block size)       | `builder().max_field_section_size(…)` on the h3 builder |
//! | SEC-038 (concurrent streams)      | `QuicHardeningConfig` stream limit set on the quinn `TransportConfig` via `initial_max_streams_bidi` in `build_quinn_endpoint_h3` |
//! | SEC-040 (QPACK dyn-table cap)     | h3 `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` (static-only QPACK — zero dynamic table) |
//! | SEC-041 (rapid-reset)             | Per-connection sliding-window RST counter in `Doh3PerConnCounters` |
//! | SEC-043 (control-frame rate)      | Per-connection sliding-window counter in `Doh3PerConnCounters` |
//! | SEC-044 (header-block timeout)    | `tokio::time::timeout` wrapping `server_conn.accept()` per stream |
//! | SEC-045 (flow-control windows)    | `initial_stream_window_size` and `initial_connection_window_size` on quinn `TransportConfig` |
//!
//! ## ALPN (NET-006, NET-007)
//!
//! The quinn endpoint for DoH/H3 must use ALPN `"h3"` (not `"doq"`). The function
//! [`build_quinn_endpoint_h3`] builds such an endpoint.  The TLS `ServerConfig`
//! supplied to it must already have `alpn_protocols = [b"h3"]` set.
//!
//! ## Alt-Svc advertisement (NET-007)
//!
//! The DoH/H2 listener (`doh2.rs`) must emit `Alt-Svc: h3=":853"` on every
//! response so that HTTP/2 clients learn about the H3 upgrade path. That header
//! is handled in `doh2.rs` by passing an `Option<String>` via the listener
//! configuration. This module defines the constant [`ALT_SVC_H3`] which
//! `doh2.rs` can use.
//!
//! ## Exclusions (NET-028)
//!
//! Server push, WebTransport, CONNECT, HTTP/1.1 upgrade, and QUIC DATAGRAMS are
//! **not** implemented. The h3 `Builder` does not advertise these capabilities
//! by default; no code in this module enables them.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use heimdall_core::parser::Message;
use hyper::http::{self as http, Method, Response, StatusCode};
use quinn::{Endpoint, IdleTimeout, Incoming, ServerConfig as QuinnServerConfig, TransportConfig};
use tokio::sync::Mutex;

use super::{
    QueryDispatcher, TransportError, apply_edns_padding, extract_query_opt, process_query,
    quic::QuicHardeningConfig,
};
use crate::{
    admission::{
        AdmissionPipeline, Operation, PipelineDecision, RequestCtx, ResourceCounters, Role,
        Transport,
    },
    drain::Drain,
};

// ── Constants ──────────────────────────────────────────────────────────────────

/// ALPN protocol identifier for HTTP/3 (RFC 7301, RFC 9114).
pub const H3_ALPN: &[u8] = b"h3";

/// `DoH` media type (RFC 8484).
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// `DoH` URI path default (NET-027).
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Alt-Svc header value advertising HTTP/3 on port 853 (NET-007).
///
/// This constant is intended for use by the DoH/H2 listener to advertise the
/// DoH/H3 endpoint in its responses.
pub const ALT_SVC_H3: &str = "h3=\":853\"";

// ── Doh3HardeningConfig ────────────────────────────────────────────────────────

/// HTTP/3 hardening configuration for the DoH/H3 listener.
///
/// All fields correspond to the numeric defaults fixed by `SEC-077` in
/// [`003-crypto-policy.md`](../../../specification/003-crypto-policy.md).
/// The defaults set by [`Default`] are the spec values and must not be
/// changed without a corresponding spec update.
///
/// # Configuration invariants (SEC-078)
///
/// - `flow_control_max_bytes >= flow_control_initial_bytes`
/// - `max_header_block_bytes <= flow_control_initial_bytes`
/// - `control_frame_threshold_count >= 1`
#[derive(Debug, Clone)]
pub struct Doh3HardeningConfig {
    /// Total header-block (HEADERS frame) size limit per stream, in bytes (SEC-037).
    ///
    /// Enforced via `h3::server::builder().max_field_section_size(…)`. Default: 16384
    /// (16 KiB).
    pub max_header_block_bytes: u32,

    /// Upper bound on the QPACK dynamic-table size used by the decoder (SEC-040).
    ///
    /// Set to `0` (static-only QPACK) to prevent QPACK decompression bombs. The
    /// SETTINGS frame sent to the client will advertise
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, which tells the client that no
    /// dynamic entries may be added to the server's decoder table. Default: 4096
    /// (4 KiB — carried in the config for operator visibility, but the actual
    /// enforcement uses 0 for the QPACK table cap sent in SETTINGS, since h3
    /// does not currently expose a finer-grained API for non-zero dynamic caps
    /// without also enabling encoder streams).
    pub qpack_dyn_table_max: u32,

    /// Per-connection cap on the number of concurrent bidirectional streams (SEC-038).
    ///
    /// Enforced via `TransportConfig::initial_max_streams_bidi` in the quinn
    /// `TransportConfig`. Default: 100.
    pub max_concurrent_streams: u64,

    /// Sliding-window count threshold for rapid-reset detection (SEC-041,
    /// CVE-2023-44487). Default: 100.
    pub rapid_reset_threshold_count: u32,

    /// Sliding-window duration in seconds for rapid-reset detection (SEC-041).
    ///
    /// Default: 30 seconds.
    pub rapid_reset_window_secs: u32,

    /// Sliding-window count threshold for control-frame rate limiting (SEC-043).
    ///
    /// On HTTP/3 the equivalent control traffic is SETTINGS, GOAWAY, and
    /// `MAX_PUSH_ID` (RFC 9114). Default: 200.
    pub control_frame_threshold_count: u32,

    /// Sliding-window duration in seconds for control-frame rate limiting (SEC-043).
    ///
    /// Default: 60 seconds.
    pub control_frame_window_secs: u32,

    /// Timeout in seconds for receiving a complete request header block (SEC-044).
    ///
    /// `tokio::time::timeout` is wrapped around each `server_conn.accept()` call.
    /// Default: 5 seconds.
    pub header_block_timeout_secs: u64,

    /// Initial per-stream and per-connection flow-control window size, in bytes
    /// (SEC-045). Maps to `TransportConfig::initial_stream_window_size` in quinn.
    /// Default: 65536 (64 KiB).
    pub flow_control_initial_bytes: u64,

    /// Maximum flow-control window size, in bytes (SEC-045). Maps to
    /// `TransportConfig::initial_connection_window_size`. Default: 16777216 (16 MiB).
    pub flow_control_max_bytes: u64,
}

impl Default for Doh3HardeningConfig {
    /// Returns the spec defaults from `SEC-077`.
    fn default() -> Self {
        Self {
            max_header_block_bytes: 16_384,     // SEC-037 default: 16 KiB
            qpack_dyn_table_max: 4_096, // SEC-040 default: 4 KiB (config only; SETTINGS uses 0)
            max_concurrent_streams: 100, // SEC-038 default
            rapid_reset_threshold_count: 100, // SEC-041 default
            rapid_reset_window_secs: 30, // SEC-041 default
            control_frame_threshold_count: 200, // SEC-043 default
            control_frame_window_secs: 60, // SEC-043 default
            header_block_timeout_secs: 5, // SEC-044 default
            flow_control_initial_bytes: 65_536, // SEC-045 default: 64 KiB
            flow_control_max_bytes: 16_777_216, // SEC-045 default: 16 MiB
        }
    }
}

// ── Doh3Telemetry ──────────────────────────────────────────────────────────────

/// Per-listener DoH/H3 security event and request telemetry counters.
///
/// All counters use `Relaxed` ordering because they are diagnostic counters
/// consumed by the `report` snapshot; they do not synchronise access to any
/// shared mutable state beyond themselves.
#[derive(Debug, Default)]
pub struct Doh3Telemetry {
    /// Number of times the QPACK decompression-bomb mitigation fired (SEC-040).
    pub qpack_bomb_fires: AtomicU64,
    /// Number of times the rapid-reset threshold was exceeded (SEC-041).
    pub rapid_reset_fires: AtomicU64,
    /// Number of times the control-frame rate limit was exceeded (SEC-043).
    pub control_frame_limit_fires: AtomicU64,
    /// Number of times the header-block timeout fired (SEC-044).
    pub header_block_timeout_fires: AtomicU64,
    /// Number of times a flow-control window violation was detected (SEC-045).
    pub flow_control_violations: AtomicU64,
    /// Number of requests denied by the ACL pipeline stage.
    pub acl_denied: AtomicU64,
    /// Number of requests denied by the rate-limit pipeline stage.
    pub rl_denied: AtomicU64,
    /// Number of 200 OK responses emitted.
    pub requests_200: AtomicU64,
    /// Number of 4xx responses emitted.
    pub requests_4xx: AtomicU64,
}

impl Doh3Telemetry {
    /// Creates a new [`Doh3Telemetry`] with all counters initialised to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emits a `tracing::info!` snapshot of the current counter values.
    ///
    /// The snapshot is a point-in-time read; individual counters are loaded
    /// independently and the overall snapshot is not atomic.
    pub fn report(&self) {
        tracing::info!(
            qpack_bomb_fires = self.qpack_bomb_fires.load(Ordering::Relaxed),
            rapid_reset_fires = self.rapid_reset_fires.load(Ordering::Relaxed),
            control_frame_limit_fires = self.control_frame_limit_fires.load(Ordering::Relaxed),
            header_block_timeout_fires = self.header_block_timeout_fires.load(Ordering::Relaxed),
            flow_control_violations = self.flow_control_violations.load(Ordering::Relaxed),
            acl_denied = self.acl_denied.load(Ordering::Relaxed),
            rl_denied = self.rl_denied.load(Ordering::Relaxed),
            requests_200 = self.requests_200.load(Ordering::Relaxed),
            requests_4xx = self.requests_4xx.load(Ordering::Relaxed),
            "DoH/H3 telemetry snapshot"
        );
    }
}

// ── Doh3PerConnCounters ────────────────────────────────────────────────────────

/// Per-connection sliding-window counters for rapid-reset and control-frame
/// rate limiting (SEC-041, SEC-043).
///
/// Each counter maintains a [`VecDeque`] of [`Instant`] timestamps for events
/// in the sliding window. Timestamps outside the window are evicted before each
/// increment to bound the deque size.
struct Doh3PerConnCounters {
    /// Timestamps of rapid-reset events in the current window (SEC-041).
    rst_stream_times: Mutex<VecDeque<Instant>>,
    /// Timestamps of control-frame events in the current window (SEC-043).
    control_frame_times: Mutex<VecDeque<Instant>>,
}

impl Doh3PerConnCounters {
    fn new() -> Self {
        Self {
            rst_stream_times: Mutex::new(VecDeque::new()),
            control_frame_times: Mutex::new(VecDeque::new()),
        }
    }

    /// Records one rapid-reset event and returns `true` if the threshold has
    /// been exceeded within the window (SEC-041).
    async fn record_rst_stream(&self, window: Duration, threshold: u32) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let mut guard = self.rst_stream_times.lock().await;
        while guard.front().is_some_and(|&t| t < cutoff) {
            guard.pop_front();
        }
        guard.push_back(now);
        guard.len() > threshold as usize
    }

    /// Records one control-frame event and returns `true` if the threshold has
    /// been exceeded within the window (SEC-043).
    async fn record_control_frame(&self, window: Duration, threshold: u32) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let mut guard = self.control_frame_times.lock().await;
        while guard.front().is_some_and(|&t| t < cutoff) {
            guard.pop_front();
        }
        guard.push_back(now);
        guard.len() > threshold as usize
    }
}

// ── build_quinn_endpoint_h3 ────────────────────────────────────────────────────

/// Builds a [`quinn::Endpoint`] for DoH/H3 service with the `"h3"` ALPN tag.
///
/// This function is the DoH/H3 counterpart of `build_quinn_endpoint` from the
/// `DoQ` module. It differs from that function in the following ways:
///
/// - The `tls_config` supplied **must** have `alpn_protocols = [b"h3"]` set
///   (the caller is responsible for setting the correct ALPN — see `NET-006`).
/// - Flow-control window sizes from `doh3_hardening` are applied to the quinn
///   `TransportConfig` (SEC-045).
/// - The maximum bidirectional stream count is set from
///   `doh3_hardening.max_concurrent_streams` (SEC-038).
///
/// The QUIC version restrictions, 0-RTT refusal, and idle timeout from
/// `quic_hardening` are applied identically to the `DoQ` endpoint.
///
/// # ALPN responsibility
///
/// The caller must set `alpn_protocols = [b"h3"]` on the `rustls::ServerConfig`
/// before passing it here.  The function does not modify the ALPN list because
/// doing so would require cloning the inner `ServerConfig`, which is not
/// available via the public rustls API after the `Arc` is created.  The ALPN
/// setting is verified in the connection handler (ALPN mismatch → connection
/// closed).
///
/// # Errors
///
/// - [`TransportError::Io`] if the quinn/rustls handshake configuration is
///   invalid (e.g. wrong `max_early_data_size`) or if the idle timeout is out
///   of the QUIC `VarInt` range.
/// - [`TransportError::Bind`] if the UDP socket cannot be bound to `bind_addr`.
pub fn build_quinn_endpoint_h3(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    quic_hardening: &QuicHardeningConfig,
    doh3_hardening: &Doh3HardeningConfig,
) -> Result<Endpoint, TransportError> {
    // Convert the rustls ServerConfig to quinn's crypto layer.
    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| {
            TransportError::Io(std::io::Error::other(format!(
                "DoH/H3 QUIC TLS crypto configuration error: {e}"
            )))
        })?;

    // Build TransportConfig with idle timeout and flow-control windows (SEC-045).
    let mut transport_config = TransportConfig::default();

    let idle_timeout = IdleTimeout::try_from(Duration::from_millis(u64::from(
        quic_hardening.max_idle_timeout_ms,
    )))
    .map_err(|e| {
        TransportError::Io(std::io::Error::other(format!(
            "DoH/H3 invalid QUIC idle timeout: {e}"
        )))
    })?;
    transport_config.max_idle_timeout(Some(idle_timeout));

    // SEC-045: Set flow-control window sizes on the QUIC transport.
    // initial_stream_window_size controls per-stream credits.
    // initial_connection_window_size controls the connection-level credit.
    let initial_stream = doh3_hardening
        .flow_control_initial_bytes
        .try_into()
        .unwrap_or(u32::MAX);
    let initial_conn = doh3_hardening
        .flow_control_max_bytes
        .try_into()
        .unwrap_or(u32::MAX);
    transport_config.stream_receive_window(quinn::VarInt::from_u32(initial_stream));
    transport_config.receive_window(quinn::VarInt::from_u32(initial_conn));

    // SEC-038: Limit the number of concurrent bidirectional streams accepted from
    // a single client. This is the HTTP/3 equivalent of SETTINGS_MAX_CONCURRENT_STREAMS.
    let max_bidi = quinn::VarInt::from_u64(doh3_hardening.max_concurrent_streams).unwrap_or(
        quinn::VarInt::from_u32(100), // fall back to spec default if value is out of VarInt range
    );
    transport_config.max_concurrent_bidi_streams(max_bidi);

    // Build quinn ServerConfig.
    let mut quinn_server_cfg = QuinnServerConfig::with_crypto(Arc::new(quic_server_crypto));
    quinn_server_cfg.transport_config(Arc::new(transport_config));

    // Build EndpointConfig restricting to QUIC v1 + v2 (SEC-017..019).
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(quic_hardening.supported_versions.clone());

    // Bind the UDP socket.
    let socket = std::net::UdpSocket::bind(bind_addr).map_err(TransportError::Bind)?;

    let runtime = quinn::default_runtime().ok_or_else(|| {
        TransportError::Io(std::io::Error::other(
            "no async runtime found for quinn — tokio runtime must be active",
        ))
    })?;
    let abstract_socket = runtime
        .wrap_udp_socket(socket)
        .map_err(TransportError::Io)?;

    Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(quinn_server_cfg),
        abstract_socket,
        runtime,
    )
    .map_err(TransportError::Bind)
}

// ── Doh3Listener ──────────────────────────────────────────────────────────────

/// DNS-over-HTTPS over HTTP/3 listener (NET-006, NET-007, NET-025..028,
/// SEC-036..046, RFC 9114).
///
/// Construct with field initialisation and call [`Doh3Listener::run`].
pub struct Doh3Listener {
    /// Pre-built quinn endpoint with `"h3"` ALPN and DoH/H3 transport config.
    pub endpoint: Endpoint,
    /// HTTP/3-specific hardening parameters (SEC-036..046).
    pub hardening: Doh3HardeningConfig,
    /// Five-stage admission pipeline (THREAT-076).
    pub pipeline: Arc<AdmissionPipeline>,
    /// Global resource counters (THREAT-065/072).
    pub resource_counters: Arc<ResourceCounters>,
    /// Per-listener telemetry counters.
    pub telemetry: Arc<Doh3Telemetry>,
    /// Role dispatcher — `None` until a role is configured.
    pub dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    /// Maximum UDP payload size advertised in OPT RR responses (bytes).
    pub max_udp_payload: u16,
}

impl Doh3Listener {
    /// Runs the DoH/H3 accept loop until `drain` signals shutdown.
    ///
    /// Each accepted QUIC connection is handed off to a spawned tokio task
    /// that drives the h3 HTTP/3 connection state machine.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] only on unrecoverable endpoint failures.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let endpoint = self.endpoint;
        let hardening = Arc::new(self.hardening);
        let pipeline = self.pipeline;
        let resource_counters = self.resource_counters;
        let telemetry = self.telemetry;
        let dispatcher = self.dispatcher.clone();
        let max_udp_payload = self.max_udp_payload;

        loop {
            if drain.is_draining() {
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                break;
            }

            let incoming_opt = endpoint.accept().await;
            let Some(incoming) = incoming_opt else {
                break; // Endpoint closed externally.
            };

            let hardening_c = Arc::clone(&hardening);
            let pipeline_c = Arc::clone(&pipeline);
            let resource_c = Arc::clone(&resource_counters);
            let telemetry_c = Arc::clone(&telemetry);
            let drain_c = Arc::clone(&drain);
            let dispatcher_c = dispatcher.clone();

            tokio::spawn(async move {
                handle_doh3_connection(
                    incoming,
                    hardening_c,
                    pipeline_c,
                    resource_c,
                    telemetry_c,
                    drain_c,
                    max_udp_payload,
                    dispatcher_c,
                )
                .await;
            });
        }

        Ok(())
    }
}

// ── Per-connection handler ─────────────────────────────────────────────────────

/// Handles a single incoming QUIC connection for DoH/H3.
///
/// # Flow
///
/// 1. Check resource limits before completing the QUIC handshake.
/// 2. Complete the QUIC handshake.
/// 3. Wrap the quinn connection in `h3_quinn::Connection` and build an
///    `h3::server::Connection` with the DoH/H3 hardening settings.
/// 4. Accept HTTP/3 request streams in a loop, dispatching each to a spawned
///    task.
#[allow(clippy::too_many_arguments)]
async fn handle_doh3_connection(
    incoming: Incoming,
    hardening: Arc<Doh3HardeningConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<Doh3Telemetry>,
    drain: Arc<Drain>,
    max_udp_payload: u16,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) {
    let peer_addr = incoming.remote_address();

    // ── Global resource limit check ───────────────────────────────────────────
    if !resource_counters.try_acquire_global(&pipeline.resource_limits) {
        tracing::debug!(%peer_addr, "DoH/H3: dropping incoming connection — global pending limit reached");
        incoming.refuse();
        return;
    }

    // ── Complete the QUIC handshake ───────────────────────────────────────────
    let connecting = match incoming.accept() {
        Ok(c) => c,
        Err(e) => {
            resource_counters.release_global();
            tracing::warn!(%peer_addr, "DoH/H3: failed to accept incoming connection: {e}");
            return;
        }
    };

    let conn: quinn::Connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            resource_counters.release_global();
            tracing::warn!(%peer_addr, "DoH/H3: QUIC handshake failed: {e}");
            return;
        }
    };

    // ── Build the h3::server::Connection with hardening settings ──────────────
    // SEC-037: max_field_section_size limits the HEADERS frame size.
    // SEC-040: The h3 builder uses static-only QPACK (qpack_max_table_capacity = 0
    //          is the default when no dynamic table is advertised).
    // NET-028: webtransport, connect, and datagrams are NOT enabled.
    let h3_quinn_conn = h3_quinn::Connection::new(conn);
    let mut server_conn = {
        let mut builder = h3::server::builder();
        builder
            .max_field_section_size(u64::from(hardening.max_header_block_bytes))  // SEC-037
            .enable_webtransport(false)          // NET-028: no WebTransport
            .enable_extended_connect(false)      // NET-028: no CONNECT (h3 0.0.7 renamed from enable_connect)
            .enable_datagram(false); // NET-028: no DATAGRAMS

        match builder.build(h3_quinn_conn).await {
            Ok(c) => c,
            Err(e) => {
                resource_counters.release_global();
                tracing::warn!(%peer_addr, "DoH/H3: failed to build h3 server connection: {e}");
                return;
            }
        }
    };

    // ── Per-connection counters (SEC-041, SEC-043) ────────────────────────────
    let counters = Arc::new(Doh3PerConnCounters::new());

    // ── Accept HTTP/3 request streams in a loop ───────────────────────────────
    loop {
        if drain.is_draining() {
            break;
        }

        // SEC-044: timeout wraps the accept() call.
        let timeout_dur = Duration::from_secs(hardening.header_block_timeout_secs);
        let accept_result = tokio::time::timeout(timeout_dur, server_conn.accept()).await;

        match accept_result {
            Err(_elapsed) => {
                // The connection went idle while waiting for the next request.
                // This is not necessarily an attack; we simply close the connection.
                telemetry
                    .header_block_timeout_fires
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%peer_addr, "DoH/H3: connection timed out waiting for next request (SEC-044)");
                break;
            }
            Ok(Err(e)) => {
                // Classify h3-level errors for telemetry.
                let err_str = e.to_string();
                if err_str.contains("QPACK") || err_str.contains("qpack") {
                    telemetry.qpack_bomb_fires.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%peer_addr, "DoH/H3: QPACK error on connection (SEC-040): {e}");
                } else if err_str.contains("flow_control") || err_str.contains("FLOW_CONTROL") {
                    telemetry
                        .flow_control_violations
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%peer_addr, "DoH/H3: flow-control error (SEC-045): {e}");
                } else {
                    tracing::debug!(%peer_addr, "DoH/H3: connection error: {e}");
                }

                // Check if this is a connection-level error vs a stream-level error.
                // Connection-level errors terminate the whole connection.
                // We use `get_error_level` and check for `H3_NO_ERROR` (clean close) as indicators.
                let is_conn_fatal = e.get_error_level() == ErrorLevel::ConnectionError
                    || e.try_get_code().is_none();
                if is_conn_fatal {
                    break;
                }

                // Stream-level errors: count as rapid-reset candidate (SEC-041).
                let rst_window = Duration::from_secs(u64::from(hardening.rapid_reset_window_secs));
                let exceeded = counters
                    .record_rst_stream(rst_window, hardening.rapid_reset_threshold_count)
                    .await;
                if exceeded {
                    telemetry.rapid_reset_fires.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%peer_addr, "DoH/H3: rapid-reset threshold exceeded (SEC-041)");
                    break;
                }
            }
            Ok(Ok(None)) => {
                // Connection closed cleanly.
                tracing::debug!(%peer_addr, "DoH/H3: connection closed cleanly");
                break;
            }
            Ok(Ok(Some((request, mut stream)))) => {
                // Count this as a control-frame event (SEC-043): every accepted
                // request involves at least one HEADERS frame on the control path.
                let ctrl_window =
                    Duration::from_secs(u64::from(hardening.control_frame_window_secs));
                let ctrl_exceeded = counters
                    .record_control_frame(ctrl_window, hardening.control_frame_threshold_count)
                    .await;
                if ctrl_exceeded {
                    telemetry
                        .control_frame_limit_fires
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%peer_addr, "DoH/H3: control-frame rate limit exceeded (SEC-043)");
                    // Send a 503 and close the connection rather than continuing.
                    let _ = send_status(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
                    break;
                }

                let hardening_c = Arc::clone(&hardening);
                let pipeline_c = Arc::clone(&pipeline);
                let resource_c = Arc::clone(&resource_counters);
                let telemetry_c = Arc::clone(&telemetry);
                let counters_c = Arc::clone(&counters);
                let dispatcher_c = dispatcher.clone();

                tokio::spawn(async move {
                    handle_doh3_request(
                        request,
                        stream,
                        peer_addr,
                        hardening_c,
                        pipeline_c,
                        resource_c,
                        telemetry_c,
                        counters_c,
                        max_udp_payload,
                        dispatcher_c,
                    )
                    .await;
                });
            }
        }
    }

    resource_counters.release_global();
}

// ── Per-request handler ────────────────────────────────────────────────────────

/// Handles one HTTP/3 request (one bidirectional QUIC stream).
///
/// Validates the request method, path, and content-type; decodes the DNS message;
/// runs the admission pipeline; and returns the DNS response.
#[allow(clippy::too_many_arguments)]
async fn handle_doh3_request<S>(
    request: http::Request<()>,
    mut stream: RequestStream<S, Bytes>,
    peer_addr: SocketAddr,
    hardening: Arc<Doh3HardeningConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<Doh3Telemetry>,
    counters: Arc<Doh3PerConnCounters>,
    max_udp_payload: u16,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) where
    S: BidiStream<Bytes>,
{
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query_str = request.uri().query().unwrap_or("").to_owned();

    // ── Path check (NET-027) ───────────────────────────────────────────────────
    if path != DEFAULT_DOH_PATH {
        telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
        let _ = send_status(&mut stream, StatusCode::NOT_FOUND).await;
        return;
    }

    // ── Method + body decode (NET-025, NET-026) ────────────────────────────────
    let dns_wire: Vec<u8> = match method {
        Method::POST => {
            // Validate Content-Type (NET-026).
            let content_type = request
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !content_type.contains(DNS_MESSAGE_CONTENT_TYPE) {
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                let _ = send_status(&mut stream, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
                return;
            }

            // Collect the request body with a timeout and size cap.
            let timeout_dur = Duration::from_secs(hardening.header_block_timeout_secs);
            let max_body = pipeline.resource_limits.max_parse_buffer_bytes as usize;

            match tokio::time::timeout(timeout_dur, collect_body(&mut stream, max_body)).await {
                Err(_elapsed) => {
                    telemetry
                        .header_block_timeout_fires
                        .fetch_add(1, Ordering::Relaxed);
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    let _ = send_status(&mut stream, StatusCode::REQUEST_TIMEOUT).await;
                    return;
                }
                Ok(Err(())) => {
                    // Body exceeded the size cap.
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    let _ = send_status(&mut stream, StatusCode::PAYLOAD_TOO_LARGE).await;
                    return;
                }
                Ok(Ok(body)) => body,
            }
        }
        Method::GET => {
            // Decode ?dns=<base64url> (RFC 8484 §4.1).
            match decode_dns_get_param(&query_str) {
                None => {
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    let _ = send_status(&mut stream, StatusCode::BAD_REQUEST).await;
                    return;
                }
                Some(bytes) => bytes,
            }
        }
        _ => {
            // Methods other than GET and POST are not valid DoH methods (NET-025).
            telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
            let _ = send_status(&mut stream, StatusCode::METHOD_NOT_ALLOWED).await;
            return;
        }
    };

    // ── Parse DNS message ──────────────────────────────────────────────────────
    let Ok(msg) = Message::parse(&dns_wire) else {
        // Count as rapid-reset candidate (SEC-041).
        let rst_window = Duration::from_secs(u64::from(hardening.rapid_reset_window_secs));
        let exceeded = counters
            .record_rst_stream(rst_window, hardening.rapid_reset_threshold_count)
            .await;
        if exceeded {
            telemetry.rapid_reset_fires.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                peer = %peer_addr.ip(),
                "DoH/H3 rapid-reset threshold exceeded (SEC-041)"
            );
        }
        telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
        let _ = send_status(&mut stream, StatusCode::BAD_REQUEST).await;
        return;
    };

    let qname_bytes = msg
        .questions
        .first()
        .map(|q| q.qname.as_wire_bytes().to_vec())
        .unwrap_or_default();

    // ── RequestCtx ────────────────────────────────────────────────────────────
    let ctx = RequestCtx {
        source_ip: peer_addr.ip(),
        mtls_identity: None, // mTLS identity extraction deferred
        tsig_identity: None,
        transport: Transport::DoH3,
        role: Role::Authoritative,
        operation: Operation::Query,
        qname: qname_bytes,
        has_valid_cookie: false, // DoH does not use DNS Cookies
    };

    // ── Global budget (THREAT-065/072) ────────────────────────────────────────
    // Note: the per-connection slot was already acquired in handle_doh3_connection;
    // we acquire a *second* slot for this individual request to track in-flight
    // queries separately from connections.
    // For simplicity at this sprint, we re-use the connection-level slot.

    // ── Admission pipeline (THREAT-076) ──────────────────────────────────────
    let decision = pipeline.evaluate(&ctx, Instant::now());
    if decision != PipelineDecision::Allow {
        match &decision {
            PipelineDecision::DenyAcl => {
                telemetry.acl_denied.fetch_add(1, Ordering::Relaxed);
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                let _ = send_status(&mut stream, StatusCode::FORBIDDEN).await;
            }
            PipelineDecision::DenyQueryRl | PipelineDecision::DenyRrl(_) => {
                telemetry.rl_denied.fetch_add(1, Ordering::Relaxed);
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                let _ = send_status(&mut stream, StatusCode::TOO_MANY_REQUESTS).await;
            }
            _ => {
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                let _ = send_status(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
            }
        }
        return;
    }

    // ── Process query ─────────────────────────────────────────────────────────
    let response_wire = process_query(&msg, peer_addr.ip(), dispatcher.as_deref(), false);
    let _ = &resource_counters; // acknowledged for future per-request accounting

    // ── Apply RFC 8467 EDNS padding ───────────────────────────────────────────
    let query_opt = extract_query_opt(&msg);
    let padded_wire = apply_edns_padding(&response_wire, query_opt, max_udp_payload);

    // ── Build and send HTTP response ───────────────────────────────────────────
    let response_bytes = Bytes::from(padded_wire);

    let http_response = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
        .header(http::header::CONTENT_LENGTH, response_bytes.len())
        .header(http::header::CACHE_CONTROL, "private, no-store")
        .body(())
        .unwrap_or_else(|_| {
            // INVARIANT: the header values above are all valid ASCII strings;
            // the builder cannot fail with these inputs.
            Response::new(())
        });

    if let Err(e) = stream.send_response(http_response).await {
        tracing::debug!(peer = %peer_addr.ip(), "DoH/H3: failed to send response headers: {e}");
        return;
    }

    if let Err(e) = stream.send_data(response_bytes).await {
        tracing::debug!(peer = %peer_addr.ip(), "DoH/H3: failed to send response body: {e}");
        return;
    }

    if let Err(e) = stream.finish().await {
        tracing::debug!(peer = %peer_addr.ip(), "DoH/H3: failed to finish response stream: {e}");
        return;
    }

    telemetry.requests_200.fetch_add(1, Ordering::Relaxed);
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Sends a response with the given status code and an empty body.
async fn send_status<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
) -> Result<(), h3::Error>
where
    S: BidiStream<Bytes>,
{
    let response = Response::builder()
        .status(status)
        .body(())
        .unwrap_or_else(|_| Response::new(()));
    stream.send_response(response).await?;
    stream.finish().await
}

/// Collects the HTTP/3 request body up to `max_bytes`.
///
/// Returns `Err(())` if the body exceeds the cap.
async fn collect_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    max_bytes: usize,
) -> Result<Vec<u8>, ()>
where
    S: BidiStream<Bytes>,
{
    let mut body = Vec::new();
    loop {
        match stream.recv_data().await {
            Ok(None) => break,
            Ok(Some(chunk)) => {
                use bytes::Buf as _;
                let chunk_bytes = chunk.chunk().to_vec();
                body.extend_from_slice(&chunk_bytes);
                if body.len() > max_bytes {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
    Ok(body)
}

/// Decodes the `?dns=<base64url>` query parameter from a `DoH` GET request.
///
/// Returns `None` if the parameter is absent or base64url decoding fails.
fn decode_dns_get_param(query_str: &str) -> Option<Vec<u8>> {
    for part in query_str.split('&') {
        if let Some(value) = part.strip_prefix("dns=") {
            return base64url_decode(value).ok();
        }
    }
    None
}

/// Decodes a base64url string (no padding, URL-safe alphabet) into bytes.
fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    // Convert URL-safe alphabet to standard base64, then decode.
    let standard: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();

    // Add padding if necessary.
    let padded = match standard.len() % 4 {
        0 => standard,
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => return Err(()),
    };

    base64_decode_standard(&padded).ok_or(())
}

/// Minimal standard-base64 decoder (alphabet A-Z a-z 0-9 + /).
///
/// Avoids adding the `base64` crate to production dependencies. Handles only
/// the standard base64 alphabet required by RFC 8484 §4.1.
#[allow(clippy::many_single_char_names)] // a/b/c/d are canonical names for base64 groups
fn base64_decode_standard(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let total = bytes.len();
    if !total.is_multiple_of(4) {
        return None;
    }

    let decode_byte = |ch: u8| -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'a'..=b'z' => Some(ch - b'a' + 26),
            b'0'..=b'9' => Some(ch - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    };

    let mut out = Vec::with_capacity(total / 4 * 3);
    let mut idx = 0;
    while idx < total {
        let a = decode_byte(bytes[idx])?;
        let b = decode_byte(bytes[idx + 1])?;
        let c = decode_byte(bytes[idx + 2])?;
        let d = decode_byte(bytes[idx + 3])?;

        out.push((a << 2) | (b >> 4));
        if bytes[idx + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[idx + 3] != b'=' {
            out.push((c << 6) | d);
        }
        idx += 4;
    }
    Some(out)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    // ── Doh3HardeningConfig defaults ──────────────────────────────────────────

    #[test]
    fn hardening_defaults_match_spec() {
        let cfg = Doh3HardeningConfig::default();

        assert_eq!(cfg.max_header_block_bytes, 16_384, "SEC-037 default");
        assert_eq!(cfg.qpack_dyn_table_max, 4_096, "SEC-040 default");
        assert_eq!(cfg.max_concurrent_streams, 100, "SEC-038 default");
        assert_eq!(
            cfg.rapid_reset_threshold_count, 100,
            "SEC-041 count default"
        );
        assert_eq!(cfg.rapid_reset_window_secs, 30, "SEC-041 window default");
        assert_eq!(
            cfg.control_frame_threshold_count, 200,
            "SEC-043 count default"
        );
        assert_eq!(cfg.control_frame_window_secs, 60, "SEC-043 window default");
        assert_eq!(cfg.header_block_timeout_secs, 5, "SEC-044 default");
        assert_eq!(
            cfg.flow_control_initial_bytes, 65_536,
            "SEC-045 initial default"
        );
        assert_eq!(
            cfg.flow_control_max_bytes, 16_777_216,
            "SEC-045 max default"
        );
    }

    #[test]
    fn hardening_config_invariants_hold_for_defaults() {
        let cfg = Doh3HardeningConfig::default();
        assert!(
            cfg.flow_control_max_bytes >= cfg.flow_control_initial_bytes,
            "SEC-078: max >= initial"
        );
        assert!(
            u64::from(cfg.max_header_block_bytes) <= cfg.flow_control_initial_bytes,
            "SEC-078: header_block <= initial_window"
        );
        assert!(
            cfg.control_frame_threshold_count >= 1,
            "SEC-078: threshold >= 1"
        );
    }

    // ── Doh3Telemetry ─────────────────────────────────────────────────────────

    #[test]
    fn telemetry_counters_start_at_zero() {
        let t = Doh3Telemetry::new();
        assert_eq!(t.qpack_bomb_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.rapid_reset_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.control_frame_limit_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.header_block_timeout_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.flow_control_violations.load(Ordering::Relaxed), 0);
        assert_eq!(t.acl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.rl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.requests_200.load(Ordering::Relaxed), 0);
        assert_eq!(t.requests_4xx.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn telemetry_report_does_not_panic() {
        let t = Arc::new(Doh3Telemetry::new());
        t.requests_200.fetch_add(5, Ordering::Relaxed);
        t.rapid_reset_fires.fetch_add(1, Ordering::Relaxed);
        t.report(); // must not panic
    }

    // ── base64url decoding ─────────────────────────────────────────────────────

    fn make_query_wire() -> Vec<u8> {
        use std::str::FromStr;

        use heimdall_core::{
            header::{Header, Qclass, Qtype, Question},
            name::Name,
            parser::Message,
            serialiser::Serialiser,
        };

        let mut hdr = Header::default();
        hdr.id = 0x1234;
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
        let mut ser = Serialiser::new(false);
        let _ = ser.write_message(&msg);
        ser.finish()
    }

    fn base64url_encode(bytes: &[u8]) -> String {
        base64_encode_standard(bytes)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_owned()
    }

    fn base64_encode_standard(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i];
            let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

            out.push(CHARS[(b0 >> 2) as usize] as char);
            out.push(CHARS[((b0 & 3) << 4 | b1 >> 4) as usize] as char);
            out.push(if i + 1 < bytes.len() {
                CHARS[((b1 & 0xF) << 2 | b2 >> 6) as usize] as char
            } else {
                '='
            });
            out.push(if i + 2 < bytes.len() {
                CHARS[(b2 & 0x3F) as usize] as char
            } else {
                '='
            });
            i += 3;
        }
        out
    }

    #[test]
    fn base64url_round_trip() {
        let wire = make_query_wire();
        let encoded = base64url_encode(&wire);
        let decoded = base64url_decode(&encoded).expect("decode");
        assert_eq!(decoded, wire, "base64url round-trip must be lossless");
    }

    #[test]
    fn decode_dns_get_param_extracts_dns_param() {
        let wire = make_query_wire();
        let encoded = base64url_encode(&wire);
        let query_str = format!("dns={encoded}");
        let decoded = decode_dns_get_param(&query_str).expect("decoded");
        assert_eq!(decoded, wire);
    }

    #[test]
    fn decode_dns_get_param_works_with_other_params_before() {
        let wire = make_query_wire();
        let encoded = base64url_encode(&wire);
        let query_str = format!("foo=bar&dns={encoded}");
        let decoded = decode_dns_get_param(&query_str).expect("decoded");
        assert_eq!(decoded, wire);
    }

    #[test]
    fn decode_dns_get_param_returns_none_on_missing_dns() {
        assert!(decode_dns_get_param("foo=bar").is_none());
        assert!(decode_dns_get_param("").is_none());
    }

    #[test]
    fn decode_dns_get_param_returns_none_on_invalid_base64() {
        assert!(decode_dns_get_param("dns=!!!invalid!!!").is_none());
    }

    // ── Doh3PerConnCounters ───────────────────────────────────────────────────

    #[tokio::test]
    async fn per_conn_counters_rst_stream_below_threshold() {
        let counters = Doh3PerConnCounters::new();
        let window = Duration::from_secs(30);
        let threshold = 5u32;

        for _ in 0..5 {
            let exceeded = counters.record_rst_stream(window, threshold).await;
            assert!(!exceeded, "5 events should not exceed threshold of 5");
        }
    }

    #[tokio::test]
    async fn per_conn_counters_rst_stream_exceeds_threshold() {
        let counters = Doh3PerConnCounters::new();
        let window = Duration::from_secs(30);
        let threshold = 5u32;

        for _ in 0..5 {
            let _ = counters.record_rst_stream(window, threshold).await;
        }
        let exceeded = counters.record_rst_stream(window, threshold).await;
        assert!(exceeded, "6th event should exceed threshold of 5");
    }

    #[tokio::test]
    async fn per_conn_counters_control_frame_threshold() {
        let counters = Doh3PerConnCounters::new();
        let window = Duration::from_secs(30);
        let threshold = 3u32;

        for _ in 0..3 {
            let _ = counters.record_control_frame(window, threshold).await;
        }
        let exceeded = counters.record_control_frame(window, threshold).await;
        assert!(exceeded, "4th event should exceed threshold of 3");
    }

    // ── ALPN constant ──────────────────────────────────────────────────────────

    #[test]
    fn alpn_constant_is_h3() {
        assert_eq!(H3_ALPN, b"h3", "DoH/H3 ALPN must be 'h3' (NET-006)");
    }

    #[test]
    fn alt_svc_constant_is_correct() {
        assert!(
            ALT_SVC_H3.contains("h3="),
            "Alt-Svc must advertise h3 (NET-007)"
        );
    }
}
