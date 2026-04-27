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

use crate::state::StateContainer;

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

// ── ObservabilityServer ──────────────────────────────────────────────────────

/// HTTP observability server.
///
/// Provides `/healthz`, `/readyz`, `/metrics`, and `/version` endpoints.
/// Bind address defaults to `127.0.0.1:9000`.
pub struct ObservabilityServer {
    /// TCP address to listen on.
    bind_addr: SocketAddr,
    /// Live server state (used for `/readyz` and `/metrics`).
    state: Arc<StateContainer>,
}

impl ObservabilityServer {
    /// Create a new server bound to `bind_addr`.
    #[must_use]
    pub fn new(bind_addr: SocketAddr, state: Arc<StateContainer>) -> Self {
        Self { bind_addr, state }
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

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(event = "observability_accept_error", error = %e);
                    continue;
                }
            };

            let state = Arc::clone(&state);
            let rate_limiter = Arc::clone(&rate_limiter);

            tokio::spawn(async move {
                let peer_ip = peer_addr.ip();
                let io = TokioIo::new(stream);

                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    async move { handle_request(req, peer_ip, &state, &rate_limiter).await }
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
    state: &StateContainer,
    rate_limiter: &RateLimiter,
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
        "/readyz" => Ok(handle_readyz(state)),
        "/metrics" => Ok(handle_metrics(state)),
        "/version" => Ok(handle_version()),
        _ => Ok(text_response(StatusCode::NOT_FOUND, "not found")),
    }
}

/// `/readyz` — 200 if `generation > 0`, 503 otherwise (OPS-024).
fn handle_readyz(state: &StateContainer) -> Response<Full<Bytes>> {
    let generation = state.load().generation;
    if generation > 0 {
        text_response(StatusCode::OK, "READY")
    } else {
        text_response(StatusCode::SERVICE_UNAVAILABLE, "NOT READY")
    }
}

/// `/metrics` — `OpenMetrics` plain-text exposition (OPS-025).
fn handle_metrics(state: &StateContainer) -> Response<Full<Bytes>> {
    let generation = state.load().generation;
    let body = format!(
        "# HELP heimdall_up Whether Heimdall is running\n\
         # TYPE heimdall_up gauge\n\
         heimdall_up 1\n\
         # HELP heimdall_reload_generation Current config generation\n\
         # TYPE heimdall_reload_generation counter\n\
         heimdall_reload_generation {generation}\n\
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
fn handle_version() -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"version":"{version}","git_sha":"unknown","build_timestamp":"unknown","msrv":"1.85"}}"#,
        version = env!("CARGO_PKG_VERSION"),
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
