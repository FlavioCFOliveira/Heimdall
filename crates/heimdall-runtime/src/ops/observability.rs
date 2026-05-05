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

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{error, info, warn};

use crate::{drain::Drain, state::RunningState};

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
    /// Performance tier identifier (e.g. `"PERF-x86_64"`, `"PERF-aarch64"`).
    pub tier: &'static str,
    /// Minimum Supported Rust Version (e.g. `"1.82"`).
    pub msrv: &'static str,
}

// ── RuntimeInfo ──────────────────────────────────────────────────────────────

/// Runtime security metadata included in the `/version` response.
///
/// Populated once at [`ObservabilityServer`] creation time and served
/// statically — the UID/GID and root-fs-writable check do not change during
/// the lifetime of the process.
#[derive(Clone, Debug)]
pub struct RuntimeInfo {
    /// Effective UID of the running process (`u32::MAX` if unavailable).
    pub uid: u32,
    /// Effective GID of the running process (`u32::MAX` if unavailable).
    pub gid: u32,
    /// Whether the root filesystem (`/`) is writable by the current process.
    pub root_fs_writable: bool,
}

impl RuntimeInfo {
    /// Probe the running process's UID/GID and root-fs writeability.
    ///
    /// On Linux the UID/GID are read from `/proc/self/status`; on other
    /// platforms they are reported as `u32::MAX` (unknown). The root-fs
    /// writeability check attempts to create a temporary file at `/._hd_probe`
    /// and immediately removes it on success.
    #[must_use]
    pub fn probe() -> Self {
        let (uid, gid) = Self::read_uid_gid();
        let root_fs_writable = Self::check_root_writable();
        Self {
            uid,
            gid,
            root_fs_writable,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_uid_gid() -> (u32, u32) {
        let status = match std::fs::read_to_string("/proc/self/status") {
            Ok(s) => s,
            Err(_) => return (u32::MAX, u32::MAX),
        };
        let uid = parse_proc_status_field(&status, "Uid:");
        let gid = parse_proc_status_field(&status, "Gid:");
        (uid, gid)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_uid_gid() -> (u32, u32) {
        (u32::MAX, u32::MAX)
    }

    fn check_root_writable() -> bool {
        const PROBE_PATH: &str = "/_hd_probe";
        if std::fs::write(PROBE_PATH, b"").is_ok() {
            let _ = std::fs::remove_file(PROBE_PATH);
            true
        } else {
            false
        }
    }
}

/// Parse the effective (first) ID from a `/proc/self/status` field line.
///
/// The `Uid:` and `Gid:` lines in `/proc/self/status` contain four
/// tab-separated values: real, effective, saved-set, and filesystem IDs.
/// We return the effective ID (second column).
#[cfg(target_os = "linux")]
fn parse_proc_status_field(status: &str, field: &str) -> u32 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // Values are separated by tabs; take the second token (effective ID).
            let mut parts = rest.split_whitespace();
            parts.next(); // real ID
            if let Some(eff) = parts.next() {
                if let Ok(n) = eff.parse::<u32>() {
                    return n;
                }
            }
        }
    }
    u32::MAX
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
    /// Runtime security metadata served by `/version` (UID, GID, root-fs writable).
    runtime_info: RuntimeInfo,
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
        let runtime_info = RuntimeInfo::probe();
        Self {
            bind_addr,
            state,
            drain,
            build_info,
            runtime_info,
        }
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
        let runtime_info = self.runtime_info.clone();

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
            let runtime_info = runtime_info.clone();

            tokio::spawn(async move {
                let peer_ip = peer_addr.ip();
                let io = TokioIo::new(stream);

                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    let drain = Arc::clone(&drain);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let build_info = build_info.clone();
                    let runtime_info = runtime_info.clone();
                    async move {
                        handle_request(
                            req,
                            peer_ip,
                            state.as_ref(),
                            drain.as_ref(),
                            &rate_limiter,
                            &build_info,
                            &runtime_info,
                        )
                        .await
                    }
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
    runtime_info: &RuntimeInfo,
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
        "/version" => Ok(handle_version(build_info, runtime_info)),
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

    let acl_denied = t.acl_denied.load(Ordering::Relaxed);
    let rrl_slipped = t.rrl_slipped.load(Ordering::Relaxed);
    let rrl_dropped = t.rrl_dropped.load(Ordering::Relaxed);
    let query_rl_denied = t.query_rl_denied.load(Ordering::Relaxed);
    let total_allowed = t.total_allowed.load(Ordering::Relaxed);
    let xfr_tsig_rejected = t.xfr_tsig_rejected_total.load(Ordering::Relaxed);
    let queries_auth = t.queries_auth_total.load(Ordering::Relaxed);
    let queries_recursive = t.queries_recursive_total.load(Ordering::Relaxed);
    let cache_hits_recursive = t.cache_hits_recursive_total.load(Ordering::Relaxed);
    let cache_misses_recursive = t.cache_misses_recursive_total.load(Ordering::Relaxed);
    let cache_hits_forwarder = t.cache_hits_forwarder_total.load(Ordering::Relaxed);
    let cache_misses_forwarder = t.cache_misses_forwarder_total.load(Ordering::Relaxed);
    let dnssec_bogus = t.dnssec_bogus_total.load(Ordering::Relaxed);
    let drain_initiated = t.drain_initiated_total.load(Ordering::Relaxed);

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
         # HELP heimdall_xfr_tsig_rejected_total Zone-transfer requests rejected due to TSIG failure\n\
         # TYPE heimdall_xfr_tsig_rejected_total counter\n\
         heimdall_xfr_tsig_rejected_total {xfr_tsig_rejected}\n\
         # HELP heimdall_queries_total Queries dispatched by role\n\
         # TYPE heimdall_queries_total counter\n\
         heimdall_queries_total{{role=\"authoritative\"}} {queries_auth}\n\
         heimdall_queries_total{{role=\"recursive\"}} {queries_recursive}\n\
         # HELP heimdall_cache_hits_total Cache hits served without an upstream query\n\
         # TYPE heimdall_cache_hits_total counter\n\
         heimdall_cache_hits_total{{role=\"recursive\"}} {cache_hits_recursive}\n\
         heimdall_cache_hits_total{{role=\"forwarder\"}} {cache_hits_forwarder}\n\
         # HELP heimdall_cache_misses_total Cache misses that required an upstream query\n\
         # TYPE heimdall_cache_misses_total counter\n\
         heimdall_cache_misses_total{{role=\"recursive\"}} {cache_misses_recursive}\n\
         heimdall_cache_misses_total{{role=\"forwarder\"}} {cache_misses_forwarder}\n\
         # HELP heimdall_dnssec_bogus_total Queries that failed DNSSEC validation with a BOGUS result\n\
         # TYPE heimdall_dnssec_bogus_total counter\n\
         heimdall_dnssec_bogus_total {dnssec_bogus}\n\
         # HELP heimdall_drain_initiated_total Number of times the drain command has been issued\n\
         # TYPE heimdall_drain_initiated_total counter\n\
         heimdall_drain_initiated_total {drain_initiated}\n\
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

/// `/version` — JSON build-info + runtime object (OPS-026).
fn handle_version(info: &BuildInfo, runtime: &RuntimeInfo) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"version":"{v}","git_commit":"{gc}","build_date":"{bd}","rustc":"{rc}","target":"{tgt}","profile":"{prof}","features":"{feat}","tier":"{tier}","msrv":"{msrv}","runtime":{{"uid":{uid},"gid":{gid},"root_fs_writable":{rfw}}}}}"#,
        v = info.version,
        gc = info.git_commit,
        bd = info.build_date,
        rc = info.rustc,
        tgt = info.target,
        prof = info.profile,
        feat = info.features,
        tier = info.tier,
        msrv = info.msrv,
        uid = runtime.uid,
        gid = runtime.gid,
        rfw = runtime.root_fs_writable,
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
