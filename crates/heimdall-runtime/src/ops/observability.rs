// SPDX-License-Identifier: MIT

//! HTTP observability server.
//!
//! Serves four endpoints on a configurable TCP address (default `127.0.0.1:9000`):
//!
//! | Path       | Method | Description                           |
//! |------------|--------|---------------------------------------|
//! | `/healthz` | GET    | Always 200 if the process is alive    |
//! | `/readyz`  | GET    | 200 READY / 503 NOT READY             |
//! | `/metrics` | GET    | `OpenMetrics` plain-text exposition     |
//! | `/version` | GET    | JSON build-info object                |
//!
//! # Security (OPS-028)
//!
//! Non-loopback clients are rejected with 403 for all endpoints except `/healthz`
//! (which must always respond per OPS-023). Full mTLS enforcement is deferred to
//! the integration sprint.
//!
//! # Rate limiting (OPS-044)
//!
//! A per-IP window of 10 req/s is enforced via a `Mutex<HashMap<IpAddr, Window>>`.
//! Loopback addresses are exempt. Clients that exceed the limit receive 429.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use arc_swap::ArcSwap;
use crate::drain::Drain;
use crate::state::RunningState;

// ── Rate-limit window ────────────────────────────────────────────────────────

/// Sliding-window state for one IP address (OPS-044).
struct Window {
    /// Number of requests recorded in the current second.
    count: u32,
    /// The second in which this window started.
    second: u64,
}

impl Window {
    /// Record a request. Returns `true` if the request is allowed (within limit).
    fn allow(&mut self, limit: u32) -> bool {
        let now_sec = epoch_secs();
        if now_sec != self.second {
            // New second: reset window.
            self.second = now_sec;
            self.count = 0;
        }
        if self.count >= limit {
            false
        } else {
            self.count += 1;
            true
        }
    }
}

/// Returns the current Unix timestamp in whole seconds.
fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Per-IP rate limiter, 10 req/s (OPS-044).
struct RateLimiter {
    windows: Mutex<HashMap<IpAddr, Window>>,
    limit: u32,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// Check whether `ip` is allowed to proceed.
    async fn allow(&self, ip: IpAddr) -> bool {
        let mut map = self.windows.lock().await;
        let window = map.entry(ip).or_insert(Window {
            count: 0,
            second: epoch_secs(),
        });
        window.allow(self.limit)
    }
}

// ── BuildInfo ────────────────────────────────────────────────────────────────

/// Build-time metadata returned by the `/version` endpoint (OPS-026, OPS-029..031).
///
/// Populated by the binary's `build.rs` and passed into [`ObservabilityServer`]
/// so that the library crate does not need its own build script (ADR-0063).
#[derive(Clone, Debug)]
pub struct BuildInfo {
    /// Cargo package version (e.g. `"1.1.0"`).
    pub version: &'static str,
    /// Short git commit SHA at build time, or `"unknown"`.
    pub git_commit: &'static str,
    /// RFC 3339 UTC build timestamp.
    pub build_date: &'static str,
    /// `rustc --version` string.
    pub rustc: &'static str,
    /// Target triple (e.g. `"aarch64-apple-darwin"`).
    pub target: &'static str,
    /// Build profile: `"debug"` or `"release"`.
    pub profile: &'static str,
    /// Comma-separated enabled Cargo features, or `"none"`.
    pub features: &'static str,
}

// ── ObservabilityServer ──────────────────────────────────────────────────────

/// HTTP observability server.
///
/// Provides `/healthz`, `/readyz`, `/metrics`, and `/version` endpoints.
/// Bind address defaults to `127.0.0.1:9090`.
pub struct ObservabilityServer {
    /// TCP address to listen on.
    bind_addr: SocketAddr,
    /// Live server state (used for `/metrics`).
    state: Arc<ArcSwap<RunningState>>,
    /// Drain handle — used by `/readyz` to return 503 during drain (OPS-024).
    drain: Arc<Drain>,
    /// Compile-time build metadata served by `/version` (OPS-026).
    build_info: BuildInfo,
}

impl ObservabilityServer {
    /// Create a new server bound to `bind_addr`.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        state: Arc<ArcSwap<RunningState>>,
        drain: Arc<Drain>,
        build_info: BuildInfo,
    ) -> Self {
        Self { bind_addr, state, drain, build_info }
    }

    /// Start the HTTP server loop.
    ///
    /// Accepts connections indefinitely. Each connection is handled by an
    /// independent tokio task. The function only returns on fatal errors.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the TCP listener cannot be bound.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!(
            event = "observability_listening",
            addr = %self.bind_addr,
            "observability HTTP server listening"
        );

        let rate_limiter = Arc::new(RateLimiter::new(10));
        let state = Arc::clone(&self.state);
        let drain = Arc::clone(&self.drain);
        let build_info = self.build_info.clone();

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(event = "observability_accept_error", error = %e);
                    continue;
                }
            };

            let state = Arc::clone(&state);
            let drain = Arc::clone(&drain);
            let rate_limiter = Arc::clone(&rate_limiter);
            let build_info = build_info.clone();

            tokio::spawn(async move {
                let peer_ip = peer_addr.ip();
                let io = TokioIo::new(stream);

                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    let drain = Arc::clone(&drain);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let build_info = build_info.clone();
                    async move { handle_request(req, peer_ip, state.as_ref(), drain.as_ref(), &rate_limiter, &build_info).await }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    warn!(event = "observability_conn_error", error = %e);
                }
            });
        }
    }
}

// ── Request handler ──────────────────────────────────────────────────────────

/// Handle a single HTTP request.
///
/// Enforces rate limiting (OPS-044) and non-loopback rejection (OPS-028) before
/// dispatching to the appropriate endpoint handler.
async fn handle_request(
    req: Request<Incoming>,
    peer_ip: IpAddr,
    state: &ArcSwap<RunningState>,
    drain: &Drain,
    rate_limiter: &RateLimiter,
    build_info: &BuildInfo,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();

    // /healthz must always respond (OPS-023), bypassing all guards.
    if path == "/healthz" {
        return Ok(text_response(StatusCode::OK, "OK"));
    }

    // Rate-limit (OPS-044): exempt loopback.
    if !peer_ip.is_loopback() {
        if !rate_limiter.allow(peer_ip).await {
            return Ok(text_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
        // Non-loopback clients: reject with 403 (OPS-028).
        // Full mTLS enforcement is deferred to the integration sprint.
        return Ok(text_response(
            StatusCode::FORBIDDEN,
            "non-loopback access denied; mTLS required (deferred to integration sprint)",
        ));
    }

    // Rate-limit loopback as well.
    if !rate_limiter.allow(peer_ip).await {
        return Ok(text_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        ));
    }

    match path.as_str() {
        "/readyz" => Ok(handle_readyz(drain)),
        "/metrics" => Ok(handle_metrics(state)),
        "/version" => Ok(handle_version(build_info)),
        _ => Ok(text_response(StatusCode::NOT_FOUND, "not found")),
    }
}

/// `/readyz` — 200 while the server is running; 503 once drain has started (OPS-024).
fn handle_readyz(drain: &Drain) -> Response<Full<Bytes>> {
    if drain.is_draining() {
        text_response(StatusCode::SERVICE_UNAVAILABLE, "NOT READY")
    } else {
        text_response(StatusCode::OK, "READY")
    }
}

/// `/metrics` — `OpenMetrics` plain-text exposition (OPS-025).
fn handle_metrics(state: &ArcSwap<RunningState>) -> Response<Full<Bytes>> {
    use std::sync::atomic::Ordering;

    let snap = state.load();
    let generation = snap.generation;
    let t = &snap.admission_telemetry;

    let acl_denied      = t.acl_denied.load(Ordering::Relaxed);
    let rrl_slipped     = t.rrl_slipped.load(Ordering::Relaxed);
    let rrl_dropped     = t.rrl_dropped.load(Ordering::Relaxed);
    let query_rl_denied = t.query_rl_denied.load(Ordering::Relaxed);
    let total_allowed   = t.total_allowed.load(Ordering::Relaxed);

    let body = format!(
        "# HELP heimdall_up Whether Heimdall is running\n\
         # TYPE heimdall_up gauge\n\
         heimdall_up 1\n\
         # HELP heimdall_reload_generation Current config generation\n\
         # TYPE heimdall_reload_generation counter\n\
         heimdall_reload_generation {generation}\n\
         # HELP heimdall_acl_denied_total Requests denied by the admission ACL\n\
         # TYPE heimdall_acl_denied_total counter\n\
         heimdall_acl_denied_total {acl_denied}\n\
         # HELP heimdall_rrl_truncated_total Requests that received a TC=1 slip from RRL\n\
         # TYPE heimdall_rrl_truncated_total counter\n\
         heimdall_rrl_truncated_total {rrl_slipped}\n\
         # HELP heimdall_rrl_dropped_total Requests dropped by RRL (no TC slip)\n\
         # TYPE heimdall_rrl_dropped_total counter\n\
         heimdall_rrl_dropped_total {rrl_dropped}\n\
         # HELP heimdall_query_rl_refused_total Requests refused by per-client query rate limiter\n\
         # TYPE heimdall_query_rl_refused_total counter\n\
         heimdall_query_rl_refused_total {query_rl_denied}\n\
         # HELP heimdall_admitted_total Requests admitted through all pipeline stages\n\
         # TYPE heimdall_admitted_total counter\n\
         heimdall_admitted_total {total_allowed}\n\
         # EOF\n"
    );
    #[expect(
        clippy::expect_used,
        reason = "builder with static known-valid header; infallible"
    )]
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Full::new(Bytes::from(body)))
        .expect("INVARIANT: response builder with known-valid headers never fails")
}

/// `/version` — JSON build-info object (OPS-026).
fn handle_version(info: &BuildInfo) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"version":"{v}","git_commit":"{gc}","build_date":"{bd}","rustc":"{rc}","target":"{tgt}","profile":"{prof}","features":"{feat}"}}"#,
        v    = info.version,
        gc   = info.git_commit,
        bd   = info.build_date,
        rc   = info.rustc,
        tgt  = info.target,
        prof = info.profile,
        feat = info.features,
    );
    #[expect(
        clippy::expect_used,
        reason = "builder with static known-valid header; infallible"
    )]
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("INVARIANT: response builder with known-valid headers never fails")
}

/// Build a plain-text response.
fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    #[expect(
        clippy::expect_used,
        reason = "builder with static known-valid header and status; infallible"
    )]
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("INVARIANT: response builder with known-valid static values never fails")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_window_resets_on_new_second() {
        // Unit test: Window::allow at the limit returns false.
        let mut w = Window {
            count: 10,
            second: epoch_secs(),
        };
        assert!(!w.allow(10), "at limit should be denied");
        // Simulate time passage by forcing a different second.
        w.second = epoch_secs().wrapping_sub(1);
        assert!(w.allow(10), "new second should reset window");
    }
}
