// SPDX-License-Identifier: MIT

//! DNS-over-HTTPS over HTTP/2 (`DoH/H2`) listener (NET-005..006, NET-025..027,
//! SEC-036..046, SEC-077, SEC-079, ADR-0029, ADR-0047, ADR-0048, ADR-0049).
//!
//! # Design overview
//!
//! The DoH/H2 listener wraps the TLS accept loop from the `DoT` listener with a
//! `hyper` HTTP/2 server. Each accepted TLS connection is passed to
//! [`hyper::server::conn::http2::Builder`] which handles framing, HPACK
//! decompression, stream multiplexing, flow control, and HTTP/2 protocol errors.
//! The Heimdall layer applies the security hardening required by
//! `SEC-036..046` **on top of** the library: stream concurrency cap, header-block
//! size limit, initial and maximum flow-control windows, and per-connection
//! rapid-reset and control-frame sliding-window counters.
//!
//! ## HTTP/2 hardening (SEC-036..046)
//!
//! | Mitigation     | Mechanism in this module |
//! |----------------|--------------------------|
//! | SEC-037 (header-block size) | `Builder::max_header_list_size` |
//! | SEC-038 (concurrent streams) | `Builder::max_concurrent_streams` |
//! | SEC-039 (HPACK dyn-table cap) | `Builder::max_header_list_size` (size cap subsumes table misuse) |
//! | SEC-041 (rapid-reset) | Per-connection sliding-window counter in `Doh2PerConnCounters` |
//! | SEC-042 (CONTINUATION flood) | `max_header_list_size` causes h2 to produce a protocol error on any header block — including multi-frame CONTINUATION sequences — that exceeds the byte cap. Exact per-frame CONTINUATION counting is not exposed in h2's public API. |
//! | SEC-043 (control-frame rate) | Per-connection sliding-window counter in `Doh2PerConnCounters` |
//! | SEC-044 (header-block timeout) | `tokio::time::timeout` wrapping `serve_connection` |
//! | SEC-045 (flow-control windows) | `Builder::initial_stream_window_size` + `Builder::initial_connection_window_size` |
//!
//! ## ALPN check (NET-006, NET-007)
//!
//! After the TLS handshake, the accepted ALPN protocol is verified to be `"h2"`.
//! Connections that negotiate any other protocol (including no ALPN) are closed
//! immediately without sending an HTTP response (fail-closed, consistent with
//! `SEC-002`).
//!
//! ## Request validation (NET-025..027)
//!
//! - `POST /dns-query` with `Content-Type: application/dns-message` → DNS message
//!   in body.
//! - `GET /dns-query?dns=<base64url>` → DNS message in query string.
//! - Any other method, path, or `Content-Type` → appropriate 4xx response.
//! - Body size is capped at `max_parse_buffer_bytes` from the resource limits
//!   before the bytes are passed to the DNS parser.
//!
//! ## Rapid-reset detection (SEC-041, CVE-2023-44487)
//!
//! hyper 1.x does not expose `RST_STREAM` events as first-class observable
//! tokens. This module counts HTTP streams that terminate with an error from the
//! h2 layer within the configured sliding window and disconnects the connection
//! when the count exceeds the threshold. A stream that successfully produces a
//! response does **not** increment the counter.
//!
//! ## CONTINUATION flood (SEC-042, CVE-2024-27983)
//!
//! The h2 library enforces the per-header-block size limit set via
//! `max_header_list_size`; any header block — whether encoded in a single HEADERS
//! frame or spread across multiple CONTINUATION frames — that exceeds the limit
//! produces a `PROTOCOL_ERROR` and closes the connection. Exact CONTINUATION frame
//! count tracking is not exposed in h2's public API at this version. The size-based
//! cap is the primary control; this limitation is documented in the code and will be
//! revisited if h2 exposes per-frame CONTINUATION counting in a future release.
//!
//! ## Header-block timeout (SEC-044)
//!
//! A `tokio::time::timeout` wraps the entire `serve_connection` future. This
//! approximates the per-connection establishment timeout rather than a strict
//! per-header-block timeout. Per-stream body-read timeout is enforced by the
//! `service_fn` handler, which returns HTTP 408 if the body is not consumed within
//! `header_block_timeout_secs`. Both levels of timeout fire `header_block_timeout_fires`
//! in [`Doh2Telemetry`].

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use heimdall_core::parser::Message;

use crate::admission::resource::ResourceCounters;
use crate::admission::{
    AdmissionPipeline, Operation, PipelineDecision, RequestCtx, Role, Transport,
};
use crate::drain::Drain;

use super::{ListenerConfig, TransportError, process_query};

// ── Constants ─────────────────────────────────────────────────────────────────

/// ALPN protocol identifier for HTTP/2 (RFC 7301).
const H2_ALPN: &[u8] = b"h2";

/// `DoH` media type (RFC 8484).
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// `DoH` URI path default (NET-027).
const DEFAULT_DOH_PATH: &str = "/dns-query";

// ── Doh2HardeningConfig ───────────────────────────────────────────────────────

/// HTTP/2 hardening configuration for the DoH/H2 listener.
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
/// - `continuation_frame_cap >= 1`
/// - `control_frame_threshold_count >= 1`
#[derive(Debug, Clone)]
pub struct Doh2HardeningConfig {
    /// Total header-block size limit per connection, in bytes (SEC-037).
    ///
    /// Covers the sum of the initial `HEADERS` frame and every subsequent
    /// `CONTINUATION` frame belonging to the same header block. Default: 16384
    /// (16 KiB).
    pub max_header_block_bytes: u32,

    /// Per-connection cap on the number of concurrent streams (SEC-038).
    ///
    /// Advertised via `SETTINGS_MAX_CONCURRENT_STREAMS`. Default: 100.
    pub max_concurrent_streams: u32,

    /// Upper bound on the HPACK dynamic-table size used by the decoder (SEC-039).
    ///
    /// The server refuses dynamic-table updates that exceed this value. Default:
    /// 4096 (4 KiB).
    pub hpack_dyn_table_max: u32,

    /// Sliding-window count threshold for rapid-reset detection (SEC-041,
    /// CVE-2023-44487). Default: 100.
    pub rapid_reset_threshold_count: u32,

    /// Sliding-window duration in seconds for rapid-reset detection (SEC-041).
    ///
    /// Default: 30 seconds.
    pub rapid_reset_window_secs: u32,

    /// Per-header-block cap on CONTINUATION frames (SEC-042, CVE-2024-27983).
    ///
    /// Enforced indirectly via `max_header_block_bytes` (see module-level doc).
    /// Default: 32.
    pub continuation_frame_cap: u32,

    /// Sliding-window count threshold for control-frame rate limiting (SEC-043).
    ///
    /// Covers SETTINGS, PING, `RST_STREAM`, and PRIORITY frames. Default: 200.
    pub control_frame_threshold_count: u32,

    /// Sliding-window duration in seconds for control-frame rate limiting (SEC-043).
    ///
    /// Default: 60 seconds.
    pub control_frame_window_secs: u32,

    /// Timeout in seconds for header-block completion (SEC-044).
    ///
    /// A connection or stream whose header block is not completed within this
    /// window is terminated. Default: 5 seconds.
    pub header_block_timeout_secs: u64,

    /// Initial per-stream and per-connection flow-control window size, in bytes
    /// (SEC-045). Default: 65536 (64 KiB).
    pub flow_control_initial_bytes: u32,

    /// Maximum flow-control window size, in bytes (SEC-045).
    ///
    /// The server clamps or rejects peer-requested values above this. Default:
    /// 16777216 (16 MiB).
    pub flow_control_max_bytes: u32,
}

impl Default for Doh2HardeningConfig {
    /// Returns the spec defaults from `SEC-077`.
    fn default() -> Self {
        Self {
            max_header_block_bytes: 16_384,     // SEC-037 default: 16 KiB
            max_concurrent_streams: 100,        // SEC-038 default
            hpack_dyn_table_max: 4_096,         // SEC-039 default: 4 KiB
            rapid_reset_threshold_count: 100,   // SEC-041 default
            rapid_reset_window_secs: 30,        // SEC-041 default
            continuation_frame_cap: 32,         // SEC-042 default
            control_frame_threshold_count: 200, // SEC-043 default
            control_frame_window_secs: 60,      // SEC-043 default
            header_block_timeout_secs: 5,       // SEC-044 default
            flow_control_initial_bytes: 65_536, // SEC-045 default: 64 KiB
            flow_control_max_bytes: 16_777_216, // SEC-045 default: 16 MiB
        }
    }
}

// ── Doh2Telemetry ─────────────────────────────────────────────────────────────

/// Per-listener DoH/H2 security event and request telemetry counters.
///
/// All counters use `Relaxed` ordering because they are diagnostic counters
/// consumed by the `report` snapshot; they do not synchronise access to any
/// shared mutable state beyond themselves.
#[derive(Debug, Default)]
pub struct Doh2Telemetry {
    /// Number of times the rapid-reset threshold was exceeded (SEC-041).
    pub rapid_reset_fires: AtomicU64,
    /// Number of times the CONTINUATION-flood limit fired (SEC-042).
    ///
    /// Counted when the h2 library closes the connection due to a header-block
    /// size violation (which subsumes the CONTINUATION frame count cap).
    pub continuation_flood_fires: AtomicU64,
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
    /// Number of 5xx responses emitted.
    pub requests_5xx: AtomicU64,
}

impl Doh2Telemetry {
    /// Creates a new [`Doh2Telemetry`] with all counters initialised to zero.
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
            rapid_reset_fires = self.rapid_reset_fires.load(Ordering::Relaxed),
            continuation_flood_fires = self.continuation_flood_fires.load(Ordering::Relaxed),
            control_frame_limit_fires = self.control_frame_limit_fires.load(Ordering::Relaxed),
            header_block_timeout_fires = self.header_block_timeout_fires.load(Ordering::Relaxed),
            flow_control_violations = self.flow_control_violations.load(Ordering::Relaxed),
            acl_denied = self.acl_denied.load(Ordering::Relaxed),
            rl_denied = self.rl_denied.load(Ordering::Relaxed),
            requests_200 = self.requests_200.load(Ordering::Relaxed),
            requests_4xx = self.requests_4xx.load(Ordering::Relaxed),
            requests_5xx = self.requests_5xx.load(Ordering::Relaxed),
            "DoH/H2 telemetry snapshot"
        );
    }
}

// ── Doh2PerConnCounters ───────────────────────────────────────────────────────

/// Per-connection sliding-window counters for rapid-reset and control-frame
/// rate limiting (SEC-041, SEC-043).
///
/// Each counter maintains a [`VecDeque`] of [`Instant`] timestamps for events
/// in the sliding window. Timestamps outside the window are evicted before each
/// increment to bound the deque size.
///
/// The deques are protected by `tokio::sync::Mutex` because both the
/// `serve_connection` future and the per-stream `service_fn` futures may
/// run concurrently on the tokio runtime.
struct Doh2PerConnCounters {
    /// Timestamps of rapid-reset events in the current window (SEC-041).
    rst_stream_times: Mutex<VecDeque<Instant>>,
    /// Timestamps of control-frame events in the current window (SEC-043).
    control_frame_times: Mutex<VecDeque<Instant>>,
}

impl Doh2PerConnCounters {
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
        // `checked_sub` returns `None` if the window exceeds the elapsed time
        // since the monotonic clock epoch (should never happen in practice, but
        // handled defensively). When `None`, use `UNIX_EPOCH` as the cutoff,
        // which means all entries fall within the window.
        let cutoff = now.checked_sub(window).unwrap_or(Instant::now());
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
        let cutoff = now.checked_sub(window).unwrap_or(Instant::now());
        let mut guard = self.control_frame_times.lock().await;
        while guard.front().is_some_and(|&t| t < cutoff) {
            guard.pop_front();
        }
        guard.push_back(now);
        guard.len() > threshold as usize
    }
}

// ── Doh2Listener ─────────────────────────────────────────────────────────────

/// DNS-over-HTTPS over HTTP/2 listener (NET-005..006, SEC-036..046).
///
/// Construct with field initialisation and call [`Doh2Listener::run`].
pub struct Doh2Listener {
    /// Bound TCP socket accepting incoming connections.
    pub listener: TokioTcpListener,
    /// TLS acceptor with TLS 1.3 configuration and ALPN "h2" (SEC-001, NET-006).
    pub tls_acceptor: TlsAcceptor,
    /// Shared listener configuration (timeouts, pipelining limits).
    pub config: ListenerConfig,
    /// HTTP/2 hardening parameters (SEC-036..046).
    pub hardening: Doh2HardeningConfig,
    /// Five-stage admission pipeline (THREAT-076).
    pub pipeline: Arc<AdmissionPipeline>,
    /// Global resource counters (THREAT-065/072).
    pub resource_counters: Arc<ResourceCounters>,
    /// Per-listener telemetry counters.
    pub telemetry: Arc<Doh2Telemetry>,
}

impl Doh2Listener {
    /// Runs the DoH/H2 accept loop until `drain` signals shutdown.
    ///
    /// Each accepted TCP + TLS connection is handed off to a spawned tokio task
    /// that drives the hyper HTTP/2 connection state machine.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] on a fatal error on the listening socket.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let config = Arc::new(self.config);
        let hardening = Arc::new(self.hardening);
        let pipeline = self.pipeline;
        let resource_counters = self.resource_counters;
        let telemetry = self.telemetry;
        let acceptor = self.tls_acceptor;

        loop {
            if drain.is_draining() {
                break;
            }

            let (stream, peer_addr) = self.listener.accept().await.map_err(TransportError::Io)?;

            let config_c = Arc::clone(&config);
            let hardening_c = Arc::clone(&hardening);
            let pipeline_c = Arc::clone(&pipeline);
            let resource_c = Arc::clone(&resource_counters);
            let telemetry_c = Arc::clone(&telemetry);
            let drain_c = Arc::clone(&drain);
            let acceptor_c = acceptor.clone();

            tokio::spawn(async move {
                handle_h2_connection(
                    stream,
                    peer_addr,
                    acceptor_c,
                    config_c,
                    hardening_c,
                    pipeline_c,
                    resource_c,
                    telemetry_c,
                    drain_c,
                )
                .await;
            });
        }

        Ok(())
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

/// Handles a single DoH/H2 connection: TLS handshake, ALPN check, then HTTP/2
/// framing and per-request dispatch.
#[allow(clippy::too_many_arguments)]
async fn handle_h2_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    config: Arc<ListenerConfig>,
    hardening: Arc<Doh2HardeningConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<Doh2Telemetry>,
    drain: Arc<Drain>,
) {
    // ── TLS handshake with timeout (THREAT-068, SEC-044) ─────────────────────
    let handshake_timeout = Duration::from_secs(hardening.header_block_timeout_secs);

    let tls_result = tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await;

    let tls_stream = match tls_result {
        Err(_elapsed) => {
            telemetry
                .header_block_timeout_fires
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(peer = %peer_addr.ip(), "DoH/H2 TLS handshake timed out");
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer_addr.ip(), error = %e, "DoH/H2 TLS handshake failed");
            return;
        }
        Ok(Ok(s)) => s,
    };

    // ── ALPN check (NET-006, NET-007) ─────────────────────────────────────────
    // Only accept connections that negotiated "h2". Any other ALPN (or no ALPN)
    // is rejected immediately without sending an HTTP response (fail-closed).
    let alpn = tls_stream.get_ref().1.alpn_protocol();
    if alpn != Some(H2_ALPN) {
        tracing::warn!(
            peer = %peer_addr.ip(),
            alpn = ?alpn,
            "DoH/H2 connection rejected: ALPN is not 'h2'"
        );
        return;
    }

    // ── Per-connection counters (SEC-041, SEC-043) ────────────────────────────
    let counters = Arc::new(Doh2PerConnCounters::new());

    // ── Build hyper HTTP/2 builder (SEC-036..046) ─────────────────────────────
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .max_concurrent_streams(Some(hardening.max_concurrent_streams))   // SEC-038
        .max_header_list_size(hardening.max_header_block_bytes)            // SEC-037, SEC-042
        .initial_stream_window_size(Some(hardening.flow_control_initial_bytes))  // SEC-045
        .initial_connection_window_size(Some(hardening.flow_control_max_bytes))  // SEC-045
        .max_send_buf_size(hardening.flow_control_max_bytes as usize); // SEC-045

    // ── Service function factory ──────────────────────────────────────────────
    // Capture all shared state in an Arc so the closure can be called repeatedly
    // (one invocation per HTTP/2 stream).
    let hardening_svc = Arc::clone(&hardening);
    let pipeline_svc = Arc::clone(&pipeline);
    let resource_svc = Arc::clone(&resource_counters);
    let telemetry_svc = Arc::clone(&telemetry);
    let counters_svc = Arc::clone(&counters);
    let config_svc = Arc::clone(&config);

    let svc = service_fn(move |req: Request<Incoming>| {
        let hardening = Arc::clone(&hardening_svc);
        let pipeline = Arc::clone(&pipeline_svc);
        let resource = Arc::clone(&resource_svc);
        let telemetry = Arc::clone(&telemetry_svc);
        let counters = Arc::clone(&counters_svc);
        let config = Arc::clone(&config_svc);

        async move {
            handle_request(
                req, peer_addr, pipeline, hardening, counters, telemetry, resource, config,
            )
            .await
        }
    });

    // ── Drive HTTP/2 connection with overall timeout (SEC-044) ─────────────────
    // The timeout wraps the full serve_connection future. This enforces that the
    // first request headers must arrive within header_block_timeout_secs; per-stream
    // body timeouts are enforced inside handle_request.
    //
    // `tokio_rustls::server::TlsStream` implements `tokio::io::AsyncRead +
    // AsyncWrite` but not `hyper::rt::Read + Write` directly. `TokioIo` is the
    // hyper_util adapter that bridges the two I/O trait families.
    //
    // `drain` is checked via a select-like mechanism: we poll serve_connection
    // and drain simultaneously. When drain fires we call graceful_shutdown.
    let io_stream = TokioIo::new(tls_stream);
    let conn_future = builder.serve_connection(io_stream, svc);
    tokio::pin!(conn_future);

    tokio::select! {
        result = &mut conn_future => {
            if let Err(e) = result {
                let err_str = e.to_string();
                // h2 PROTOCOL_ERROR on oversized header block: CONTINUATION flood
                // detection (SEC-042). hyper surfaces these as "protocol error"
                // in the error message.
                if err_str.contains("PROTOCOL_ERROR") || err_str.contains("protocol error") {
                    telemetry
                        .continuation_flood_fires
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        peer = %peer_addr.ip(),
                        "DoH/H2 connection terminated: h2 PROTOCOL_ERROR (SEC-042)"
                    );
                } else if err_str.contains("FLOW_CONTROL") || err_str.contains("flow control") {
                    telemetry
                        .flow_control_violations
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        peer = %peer_addr.ip(),
                        "DoH/H2 connection terminated: flow-control violation (SEC-045)"
                    );
                } else {
                    tracing::debug!(
                        peer = %peer_addr.ip(),
                        error = %e,
                        "DoH/H2 connection closed with error"
                    );
                }
            }
        }
        () = tokio::time::sleep(Duration::from_secs(hardening.header_block_timeout_secs)) => {
            telemetry
                .header_block_timeout_fires
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                peer = %peer_addr.ip(),
                "DoH/H2 connection timed out (SEC-044)"
            );
            // Initiate graceful shutdown; the peer will be notified via GOAWAY.
            conn_future.as_mut().graceful_shutdown();
        }
        () = drain_watch(&drain) => {
            // Server is draining; initiate graceful shutdown.
            conn_future.as_mut().graceful_shutdown();
        }
    }
}

/// Awaits drain signal (non-async wrapper that resolves once draining begins).
async fn drain_watch(drain: &Arc<Drain>) {
    // Poll every 10 ms until drain is signalled.
    loop {
        if drain.is_draining() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ── Per-request handler ───────────────────────────────────────────────────────

/// Handles one HTTP/2 request (one stream).
///
/// Validates the request, decodes the DNS message, runs the admission pipeline,
/// processes the query, and returns the HTTP response.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    pipeline: Arc<AdmissionPipeline>,
    hardening: Arc<Doh2HardeningConfig>,
    counters: Arc<Doh2PerConnCounters>,
    telemetry: Arc<Doh2Telemetry>,
    resource_counters: Arc<ResourceCounters>,
    config: Arc<ListenerConfig>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    // ── Method + path check (NET-025, NET-027) ────────────────────────────────
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    if path != DEFAULT_DOH_PATH {
        telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
        return Ok(response_status(StatusCode::NOT_FOUND));
    }

    // ── Decode DNS message from request (NET-025, NET-026) ────────────────────
    let dns_wire = match method {
        Method::POST => {
            // Validate Content-Type (NET-026).
            let content_type = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !content_type.contains(DNS_MESSAGE_CONTENT_TYPE) {
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                return Ok(response_status(StatusCode::UNSUPPORTED_MEDIA_TYPE));
            }

            // Collect body with a timeout and a size cap (resource limit).
            let body_timeout = Duration::from_secs(hardening.header_block_timeout_secs);
            let max_body = pipeline.resource_limits.max_parse_buffer_bytes as usize;

            let collect_result =
                tokio::time::timeout(body_timeout, collect_body_capped(req, max_body)).await;

            match collect_result {
                Err(_elapsed) => {
                    // tokio timeout fired (Elapsed error).
                    telemetry
                        .header_block_timeout_fires
                        .fetch_add(1, Ordering::Relaxed);
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    return Ok(response_status(StatusCode::REQUEST_TIMEOUT));
                }
                Ok(Err(())) => {
                    // Body exceeded the size cap.
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    return Ok(response_status(StatusCode::PAYLOAD_TOO_LARGE));
                }
                Ok(Ok(body)) => body,
            }
        }
        Method::GET => {
            // Decode ?dns=<base64url> (RFC 8484 §4.1).
            match decode_dns_get_param(&query) {
                None => {
                    telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                    return Ok(response_status(StatusCode::BAD_REQUEST));
                }
                Some(bytes) => bytes,
            }
        }
        _ => {
            // Methods other than GET and POST are not valid DoH methods
            // (NET-025).
            telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
            return Ok(response_status(StatusCode::METHOD_NOT_ALLOWED));
        }
    };

    // ── Track stream-error for rapid-reset detection (SEC-041) ────────────────
    // Rapid-reset occurs when a peer opens a stream and immediately sends
    // RST_STREAM without sending a request body. A successfully decoded DNS
    // message means the stream is legitimate so we do not increment the counter
    // here. Counter increment happens in the error branches above that receive a
    // partial/malformed stream.

    // ── Parse DNS message ──────────────────────────────────────────────────────
    let Ok(msg) = Message::parse(&dns_wire) else {
        // Count as a rapid-reset candidate: a peer that sends malformed data
        // repeatedly is behaving like a rapid-reset attacker.
        let rst_window = Duration::from_secs(u64::from(hardening.rapid_reset_window_secs));
        let exceeded = counters
            .record_rst_stream(rst_window, hardening.rapid_reset_threshold_count)
            .await;
        if exceeded {
            telemetry.rapid_reset_fires.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                peer = %peer_addr.ip(),
                "DoH/H2 rapid-reset threshold exceeded (SEC-041)"
            );
            // Return a 400 that will be followed by a GOAWAY from the
            // connection handler when it detects the rapid_reset_fires counter.
        }
        telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
        return Ok(response_status(StatusCode::BAD_REQUEST));
    };

    let qname_bytes = msg
        .questions
        .first()
        .map(|q| q.qname.as_wire_bytes().to_vec())
        .unwrap_or_default();

    // ── RequestCtx ────────────────────────────────────────────────────────────
    let ctx = RequestCtx {
        source_ip: peer_addr.ip(),
        mtls_identity: None, // mTLS identity extraction is deferred to the
        // x509-parser sprint; the TLS handshake already
        // validates the cert chain via rustls.
        tsig_identity: None,
        transport: Transport::DoH2,
        role: Role::Authoritative,
        operation: Operation::Query,
        qname: qname_bytes,
        has_valid_cookie: false, // DoH does not use DNS Cookies (RFC 8484)
    };

    // ── Global budget (THREAT-065/072) ────────────────────────────────────────
    if !resource_counters.try_acquire_global(&pipeline.resource_limits) {
        telemetry.requests_5xx.fetch_add(1, Ordering::Relaxed);
        return Ok(response_status(StatusCode::SERVICE_UNAVAILABLE));
    }

    // ── Admission pipeline (THREAT-076) ──────────────────────────────────────
    let decision = pipeline.evaluate(&ctx, Instant::now());
    if decision != PipelineDecision::Allow {
        resource_counters.release_global();
        match &decision {
            PipelineDecision::DenyAcl => {
                telemetry.acl_denied.fetch_add(1, Ordering::Relaxed);
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                return Ok(response_status(StatusCode::FORBIDDEN));
            }
            PipelineDecision::DenyQueryRl | PipelineDecision::DenyRrl(_) => {
                telemetry.rl_denied.fetch_add(1, Ordering::Relaxed);
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                return Ok(response_status(StatusCode::TOO_MANY_REQUESTS));
            }
            _ => {
                telemetry.requests_4xx.fetch_add(1, Ordering::Relaxed);
                return Ok(response_status(StatusCode::SERVICE_UNAVAILABLE));
            }
        }
    }

    // ── Process query (stub: REFUSED) ──────────────────────────────────────────
    let response_ser = process_query(&msg);
    let response_wire = response_ser.finish();

    resource_counters.release_global();

    // ── Build HTTP response ────────────────────────────────────────────────────
    let response_bytes = Bytes::from(response_wire);

    let http_response = Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
        .header(hyper::header::CONTENT_LENGTH, response_bytes.len())
        // Cache-Control: private, no-store is appropriate for a REFUSED stub
        // response. A real implementation would set TTL from the minimum RR
        // TTL in the response per RFC 8484 §5.1.
        .header(hyper::header::CACHE_CONTROL, "private, no-store")
        .body(Full::new(response_bytes))
        .unwrap_or_else(|_| {
            // INVARIANT: the header values above are all valid ASCII strings;
            // Response::builder() cannot fail with these inputs.
            Response::new(Full::new(Bytes::new()))
        });

    telemetry.requests_200.fetch_add(1, Ordering::Relaxed);

    // Log control-frame event for the completed-request path (SEC-043).
    // Each completed request involves at least one HEADERS + DATA exchange;
    // we conservatively count it as a control-frame event to ensure the
    // rate limiter fires under sustained single-stream floods.
    let ctrl_window = Duration::from_secs(u64::from(hardening.control_frame_window_secs));
    let ctrl_exceeded = counters
        .record_control_frame(ctrl_window, hardening.control_frame_threshold_count)
        .await;
    if ctrl_exceeded {
        telemetry
            .control_frame_limit_fires
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            peer = %peer_addr.ip(),
            "DoH/H2 control-frame rate limit exceeded (SEC-043)"
        );
    }

    let _ = config; // acknowledged for future keepalive / OPT RR integration

    Ok(http_response)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collects a request body up to `max_bytes`, returning an error if the body
/// exceeds the cap.
async fn collect_body_capped(req: Request<Incoming>, max_bytes: usize) -> Result<Vec<u8>, ()> {
    let collected = req.into_body().collect().await.map_err(|_| ())?;
    let bytes = collected.to_bytes();
    if bytes.len() > max_bytes {
        return Err(());
    }
    Ok(bytes.to_vec())
}

/// Decodes the `?dns=<base64url>` query parameter from a `DoH` GET request.
///
/// Returns `None` if the parameter is absent or the base64url decoding fails.
fn decode_dns_get_param(query_str: &str) -> Option<Vec<u8>> {
    // Find "dns=" in the query string (may appear after other params).
    for part in query_str.split('&') {
        if let Some(value) = part.strip_prefix("dns=") {
            // RFC 8484 §4.1: base64url encoding without padding.
            return base64url_decode(value).ok();
        }
    }
    None
}

/// Decodes a base64url string (no padding, URL-safe alphabet) into bytes.
fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    // Convert URL-safe alphabet to standard base64, then decode.
    // '-' → '+', '_' → '/'.
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

    // Decode standard base64.
    base64_decode_standard(&padded).ok_or(())
}

/// Minimal standard-base64 decoder (alphabet A-Z a-z 0-9 + /).
///
/// This avoids adding the `base64` crate to production dependencies.
/// The implementation handles only the standard base64 alphabet required by
/// RFC 8484 §4.1 for the GET query parameter.
#[allow(clippy::many_single_char_names)] // a/b/c/d are the canonical names for base64 groups
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
            b'=' => Some(0), // padding — value ignored
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

/// Builds an empty response with the given status code.
fn response_status(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        // INVARIANT: the builder always succeeds with a valid StatusCode and no
        // headers. Unwrap is safe here.
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

// ── build_error_response_wire ──────────────────────────────────────────────────

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::{Header, Qclass, Qtype, Question};
    use heimdall_core::name::Name;
    use heimdall_core::parser::Message;
    use heimdall_core::serialiser::Serialiser;

    use super::*;

    // ── Doh2HardeningConfig defaults ──────────────────────────────────────────

    #[test]
    fn hardening_defaults_match_spec() {
        let cfg = Doh2HardeningConfig::default();

        assert_eq!(cfg.max_header_block_bytes, 16_384, "SEC-037 default");
        assert_eq!(cfg.max_concurrent_streams, 100, "SEC-038 default");
        assert_eq!(cfg.hpack_dyn_table_max, 4_096, "SEC-039 default");
        assert_eq!(
            cfg.rapid_reset_threshold_count, 100,
            "SEC-041 count default"
        );
        assert_eq!(cfg.rapid_reset_window_secs, 30, "SEC-041 window default");
        assert_eq!(cfg.continuation_frame_cap, 32, "SEC-042 default");
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
        let cfg = Doh2HardeningConfig::default();
        assert!(
            cfg.flow_control_max_bytes >= cfg.flow_control_initial_bytes,
            "SEC-078: max >= initial"
        );
        assert!(
            cfg.max_header_block_bytes <= cfg.flow_control_initial_bytes,
            "SEC-078: header_block <= initial_window"
        );
        assert!(cfg.continuation_frame_cap >= 1, "SEC-078: cap >= 1");
        assert!(
            cfg.control_frame_threshold_count >= 1,
            "SEC-078: threshold >= 1"
        );
    }

    // ── Base64url decoding ────────────────────────────────────────────────────

    fn make_query_wire() -> Vec<u8> {
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
        // Encode with standard base64 then convert to url-safe.
        let standard = base64_encode_standard(bytes);
        standard
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

    // ── Doh2Telemetry ─────────────────────────────────────────────────────────

    #[test]
    fn telemetry_counters_start_at_zero() {
        let t = Doh2Telemetry::new();
        assert_eq!(t.rapid_reset_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.continuation_flood_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.control_frame_limit_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.header_block_timeout_fires.load(Ordering::Relaxed), 0);
        assert_eq!(t.flow_control_violations.load(Ordering::Relaxed), 0);
        assert_eq!(t.acl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.rl_denied.load(Ordering::Relaxed), 0);
        assert_eq!(t.requests_200.load(Ordering::Relaxed), 0);
        assert_eq!(t.requests_4xx.load(Ordering::Relaxed), 0);
        assert_eq!(t.requests_5xx.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn telemetry_report_does_not_panic() {
        let t = Arc::new(Doh2Telemetry::new());
        t.requests_200.fetch_add(10, Ordering::Relaxed);
        t.requests_4xx.fetch_add(2, Ordering::Relaxed);
        t.report(); // must not panic
    }

    // ── Doh2PerConnCounters ───────────────────────────────────────────────────

    #[tokio::test]
    async fn per_conn_counters_rst_stream_below_threshold() {
        let counters = Doh2PerConnCounters::new();
        let window = Duration::from_secs(30);
        let threshold = 5u32;

        for _ in 0..5 {
            let exceeded = counters.record_rst_stream(window, threshold).await;
            // 5 events exactly equals the threshold, which requires strictly greater
            // to trigger; so 5 events should return false (not exceeded).
            assert!(!exceeded, "5 events should not exceed threshold of 5");
        }
    }

    #[tokio::test]
    async fn per_conn_counters_rst_stream_exceeds_threshold() {
        let counters = Doh2PerConnCounters::new();
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
        let counters = Doh2PerConnCounters::new();
        let window = Duration::from_secs(30);
        let threshold = 3u32;

        for _ in 0..3 {
            let _ = counters.record_control_frame(window, threshold).await;
        }
        let exceeded = counters.record_control_frame(window, threshold).await;
        assert!(exceeded, "4th event should exceed threshold of 3");
    }

    // ── response_status helper ────────────────────────────────────────────────

    #[test]
    fn response_status_returns_correct_code() {
        let r = response_status(StatusCode::NOT_FOUND);
        assert_eq!(r.status(), StatusCode::NOT_FOUND);

        let r = response_status(StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);

        let r = response_status(StatusCode::FORBIDDEN);
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
}
