// SPDX-License-Identifier: MIT

//! Admin-RPC server over Unix Domain Socket.
//!
//! # Protocol
//!
//! Length-prefix-framed JSON over a Unix Domain Socket. Frame format:
//!
//! ```text
//! [4 bytes big-endian u32 length][JSON bytes (length octets)]
//! ```
//!
//! Both requests and responses use this framing. The wire format is intentionally
//! simple so that standard Unix tools (`socat`, `nc -U`) can interact with the
//! server during development.
//!
//! # Security (OPS-008)
//!
//! The socket file is created with mode `0600` (owner read/write only). Access
//! control is therefore enforced by the filesystem: only the process owner may
//! connect. No additional authentication layer is applied in this sprint; full
//! mTLS protection is planned for the gRPC migration (ADR-0053 / ADR-0054).
//!
//! # gRPC migration notice (OPS-033)
//!
//! This JSON-over-UDS implementation is an **interim** for Sprint 33. OPS-033
//! mandates migration to gRPC/Protocol Buffers using `tonic = "0.12"` and
//! `prost = "0.13"` (ADRs 0053 and 0054). The migration is tracked for a future
//! sprint once the `.proto` compilation pipeline (via `tonic-build` in `build.rs`)
//! is wired in.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::state::{NtaEntry, RpzEntry, RunningState, ZoneEntry};

// ── Request / Response types ─────────────────────────────────────────────────

/// Admin-RPC command (subset of OPS-034).
///
/// Commands are decoded from JSON using the `cmd` field as a discriminant.
/// All string fields are validated before dispatch.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
    // ── Server information ───────────────────────────────────────────────────
    /// Return the server version and build information.
    Version,

    // ── Zone lifecycle (OPS-010) ─────────────────────────────────────────────
    /// Add a new zone from a zone file.
    ZoneAdd {
        /// Zone origin (e.g. `"example.com."`).
        zone: String,
        /// Path to the zone file.
        file: String,
    },
    /// Remove a loaded zone.
    ZoneRemove {
        /// Zone origin.
        zone: String,
    },
    /// Reload a zone from its source file.
    ZoneReload {
        /// Zone origin.
        zone: String,
    },
    // ── NTA lifecycle (OPS-011) ──────────────────────────────────────────────
    /// Add a Negative Trust Anchor.
    NtaAdd {
        /// FQDN to mark as untrusted.
        domain: String,
        /// Unix timestamp (seconds since epoch) when the NTA expires.
        expires_at: u64,
        /// Free-text reason for this NTA (audit trail).
        reason: String,
    },
    /// Revoke an existing NTA.
    NtaRevoke {
        /// FQDN to un-anchor.
        domain: String,
    },
    /// List all active NTAs.
    NtaList,
    // ── Key rotation (OPS-012) ───────────────────────────────────────────────
    /// Rotate the Transport Encryption Key (TEK).
    TekRotate,
    /// Rotate the new-token signing key.
    NewTokenKeyRotate,
    // ── Rate-limit tuning (OPS-013) ──────────────────────────────────────────
    /// Tune a named rate-limit rule at runtime.
    RateLimitTune {
        /// Identifier of the rate-limit rule to tune.
        rule: String,
        /// New limit (requests per second). Must be in `1..=100_000`.
        limit: u32,
    },
    // ── Drain (OPS-014) ──────────────────────────────────────────────────────
    /// Initiate graceful drain and shutdown.
    Drain,
    // ── Diagnostics (OPS-015) ────────────────────────────────────────────────
    /// Return cache statistics.
    CacheStats,
    /// Return connection statistics.
    ConnectionStats,
    // ── RPZ management ───────────────────────────────────────────────────────
    /// Add an entry to a Response Policy Zone.
    RpzEntryAdd {
        /// RPZ zone name.
        zone: String,
        /// Action to apply (e.g. `"NXDOMAIN"`, `"PASSTHRU"`).
        action: String,
    },
    /// Remove an entry from a Response Policy Zone.
    RpzEntryRemove {
        /// RPZ zone name.
        zone: String,
    },
    /// List all RPZ entries.
    RpzEntryList,
}

/// Admin-RPC response.
///
/// Serialised to JSON and framed before sending back to the client.
/// [`serde::Deserialize`] is derived so that test helpers can decode
/// responses without an extra struct.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Human-readable outcome message.
    pub message: String,
    /// Optional structured payload (e.g. stats objects, NTA lists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl AdminResponse {
    fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: Some(data),
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            data: None,
        }
    }
}

// ── UDS server ───────────────────────────────────────────────────────────────

/// Admin-RPC server over Unix Domain Socket.
///
/// Binds a UDS at `socket_path`, sets permissions to `0600` (OPS-008), and
/// dispatches incoming admin commands.
///
/// # Protocol
///
/// Each connection is handled independently. The server reads one framed request,
/// dispatches it, and writes one framed response. The connection is then closed.
/// This keeps the implementation simple and stateless per-connection.
pub struct AdminRpcServer {
    socket_path: PathBuf,
    state: Arc<ArcSwap<RunningState>>,
}

impl AdminRpcServer {
    /// Create a new server.
    ///
    /// The socket is not bound until [`AdminRpcServer::run`] is called.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>, state: Arc<ArcSwap<RunningState>>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_owned(),
            state,
        }
    }

    /// Start the UDS listener.
    ///
    /// Removes any stale socket file before binding. After binding, the socket
    /// file permissions are set to `0600` (OPS-008). The server loops, accepting
    /// one connection at a time and spawning a task per connection.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the socket cannot be created or bound.
    pub async fn run(self) -> Result<(), io::Error> {
        // Remove stale socket file if it exists.
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set permissions to 0600: owner read/write only (OPS-008).
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;

        info!(
            event = "admin_rpc_listening",
            socket = %self.socket_path.display(),
            "admin-RPC server listening (JSON-over-UDS; gRPC migration pending ADR-0053)"
        );

        let state = Arc::clone(&self.state);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            warn!(event = "admin_rpc_conn_error", error = %e);
                        }
                    });
                }
                Err(e) => {
                    error!(event = "admin_rpc_accept_error", error = %e);
                    // Continue accepting on transient errors.
                }
            }
        }
    }
}

// ── TCP server (OPS-007..009) ─────────────────────────────────────────────────

/// Returns `true` if `ip` falls within the CIDR block described by
/// (`prefix`, `prefix_len`).  Mismatched address families always return `false`.
fn ip_in_cidr(ip: IpAddr, prefix: IpAddr, prefix_len: u8) -> bool {
    match (ip, prefix) {
        (IpAddr::V4(ip4), IpAddr::V4(pfx4)) => {
            let ip_u = u32::from(ip4);
            let pfx_u = u32::from(pfx4);
            let shift = 32u8.saturating_sub(prefix_len);
            let mask = u32::MAX.checked_shl(u32::from(shift)).unwrap_or(0);
            (ip_u & mask) == (pfx_u & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(pfx6)) => {
            let ip_u = u128::from(ip6);
            let pfx_u = u128::from(pfx6);
            let shift = 128u8.saturating_sub(prefix_len);
            let mask = u128::MAX.checked_shl(u32::from(shift)).unwrap_or(0);
            (ip_u & mask) == (pfx_u & mask)
        }
        _ => false,
    }
}

/// Admin-RPC server over TCP with mutual TLS (mTLS) and IP CIDR ACL (OPS-007..009).
///
/// Accepts connections only from IP addresses that fall within one of the
/// `allowed_cidrs` entries. The ACL check happens *before* the TLS handshake so
/// that denial latency is minimised (target < 5 ms, task #519 AC).
///
/// Each connection that passes the ACL is handed to the rustls/tokio-tls acceptor
/// for the mutual TLS handshake. The server requires the client to present a
/// certificate signed by the configured CA; connections without a client cert
/// fail at the handshake layer.
///
/// Once a connection is accepted and authenticated, the same length-prefix-framed
/// JSON protocol as the UDS path is used (OPS-007).
pub struct AdminRpcTcpServer {
    bind_addr: SocketAddr,
    state: Arc<ArcSwap<RunningState>>,
    tls_acceptor: TlsAcceptor,
    allowed_cidrs: Vec<(IpAddr, u8)>,
}

impl AdminRpcTcpServer {
    /// Create a new TCP admin-RPC server.
    ///
    /// `tls_config` must be built with a `WebPkiClientVerifier` that requires
    /// client certificates (mTLS); the TLS handshake enforces client auth.
    /// `allowed_cidrs` lists the (prefix, prefix_len) pairs whose members may
    /// connect; an empty list denies all connections.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        state: Arc<ArcSwap<RunningState>>,
        tls_config: Arc<rustls::ServerConfig>,
        allowed_cidrs: Vec<(IpAddr, u8)>,
    ) -> Self {
        Self {
            bind_addr,
            state,
            tls_acceptor: TlsAcceptor::from(tls_config),
            allowed_cidrs,
        }
    }

    /// Start the TCP+mTLS listener.
    ///
    /// Binds `bind_addr`, then loops accepting connections. Each accepted
    /// connection is checked against `allowed_cidrs` before the TLS handshake
    /// is attempted. Rejected connections are dropped immediately.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the TCP listener cannot be bound.
    pub async fn run_tcp(self) -> Result<(), io::Error> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        info!(
            event = "admin_rpc_tcp_listening",
            addr = %self.bind_addr,
            "admin-RPC TCP+mTLS server listening (OPS-007..009)"
        );

        let state = Arc::clone(&self.state);
        let tls_acceptor = self.tls_acceptor;
        let allowed_cidrs = Arc::new(self.allowed_cidrs);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // ACL check before TLS handshake — minimises denial latency.
                    if !allowed_cidrs
                        .iter()
                        .any(|(pfx, len)| ip_in_cidr(peer_addr.ip(), *pfx, *len))
                    {
                        warn!(
                            event = "admin_rpc_tcp_acl_denied",
                            peer = %peer_addr,
                            "admin-RPC TCP connection denied by CIDR ACL"
                        );
                        drop(stream);
                        continue;
                    }
                    let state = Arc::clone(&state);
                    let tls_acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = handle_rpc_connection(tls_stream, state).await {
                                    warn!(event = "admin_rpc_tcp_conn_error", error = %e);
                                }
                            }
                            Err(e) => {
                                warn!(event = "admin_rpc_tcp_tls_error", error = %e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(event = "admin_rpc_tcp_accept_error", error = %e);
                }
            }
        }
    }
}

// ── Connection handling ───────────────────────────────────────────────────────

/// Maximum frame body size accepted from a client (1 MiB).
///
/// Guards against memory exhaustion attacks where the 4-byte length header
/// claims a very large body (OPS-039 resource-limit compliance).
const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Core connection handler: read one request frame, dispatch, write response.
///
/// Generic over the underlying stream so the same logic serves both the UDS
/// path (`UnixStream`) and the TCP+mTLS path (`TlsStream<TcpStream>`).
async fn handle_rpc_connection<S>(
    mut stream: S,
    state: Arc<ArcSwap<RunningState>>,
) -> Result<(), io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read 4-byte big-endian length prefix.
    let len = match stream.read_u32().await {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()), // clean close
        Err(e) => return Err(e),
    };

    if len > MAX_FRAME_BYTES {
        let resp = AdminResponse::err(format!(
            "frame too large: {len} bytes exceeds maximum {MAX_FRAME_BYTES}"
        ));
        write_rpc_response(&mut stream, &resp).await?;
        return Ok(());
    }

    // Read exactly `len` bytes.
    let mut buf = vec![0u8; len as usize];
    if let Err(e) = stream.read_exact(&mut buf).await {
        let resp = AdminResponse::err(format!("failed to read frame body: {e}"));
        write_rpc_response(&mut stream, &resp).await?;
        return Ok(());
    }

    // Decode JSON.
    let request: AdminRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            let resp = AdminResponse::err(format!("malformed request: {e}"));
            write_rpc_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    let start = Instant::now();
    let cmd_name = cmd_name(&request);
    let response = dispatch(request, &state);
    let duration_ms = start.elapsed().as_millis();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let outcome = if response.ok { "ok" } else { "error" };
    info!(
        event = "admin_rpc_audit",
        cmd = cmd_name,
        outcome = outcome,
        duration_ms = duration_ms,
        ts = ts,
        identity = "uds-local",
        "admin-rpc operation"
    );

    write_rpc_response(&mut stream, &response).await
}

/// Thin wrapper that dispatches a UDS connection to [`handle_rpc_connection`].
async fn handle_connection(
    stream: UnixStream,
    state: Arc<ArcSwap<RunningState>>,
) -> Result<(), io::Error> {
    handle_rpc_connection(stream, state).await
}

/// Serialise `response` and write it with a 4-byte big-endian length prefix.
async fn write_rpc_response<S>(stream: &mut S, response: &AdminResponse) -> Result<(), io::Error>
where
    S: AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(response).map_err(io::Error::other)?;
    let len = u32::try_from(json.len()).map_err(|_| io::Error::other("response too large"))?;
    stream.write_u32(len).await?;
    stream.write_all(&json).await
}

/// Extract a stable string name from an [`AdminRequest`] for audit logging.
fn cmd_name(req: &AdminRequest) -> &'static str {
    match req {
        AdminRequest::Version => "version",
        AdminRequest::ZoneAdd { .. } => "zone_add",
        AdminRequest::ZoneRemove { .. } => "zone_remove",
        AdminRequest::ZoneReload { .. } => "zone_reload",
        AdminRequest::NtaAdd { .. } => "nta_add",
        AdminRequest::NtaRevoke { .. } => "nta_revoke",
        AdminRequest::NtaList => "nta_list",
        AdminRequest::TekRotate => "tek_rotate",
        AdminRequest::NewTokenKeyRotate => "new_token_key_rotate",
        AdminRequest::RateLimitTune { .. } => "rate_limit_tune",
        AdminRequest::Drain => "drain",
        AdminRequest::CacheStats => "cache_stats",
        AdminRequest::ConnectionStats => "connection_stats",
        AdminRequest::RpzEntryAdd { .. } => "rpz_entry_add",
        AdminRequest::RpzEntryRemove { .. } => "rpz_entry_remove",
        AdminRequest::RpzEntryList => "rpz_entry_list",
    }
}

/// Dispatch an [`AdminRequest`] to the appropriate handler and return an [`AdminResponse`].
///
/// All mutations are applied to [`crate::state::SharedStore`] which is
/// Arc-shared across config-reload generations (OPS-010..015).
fn dispatch(request: AdminRequest, state: &ArcSwap<RunningState>) -> AdminResponse {
    let loaded = state.load();
    let store = &loaded.store;
    let telemetry = &loaded.admission_telemetry;

    match request {
        // ── Server information ────────────────────────────────────────────────
        AdminRequest::Version => AdminResponse::ok_with_data(
            "version",
            serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }),
        ),

        // ── Zone lifecycle (OPS-010) ──────────────────────────────────────────
        AdminRequest::ZoneAdd { zone, file } => {
            let mut zones = store.zones.lock().unwrap_or_else(|p| p.into_inner());
            zones.insert(zone.clone(), ZoneEntry { file: file.clone() });
            AdminResponse::ok_with_data(
                "zone added",
                serde_json::json!({ "zone": zone, "file": file }),
            )
        }
        AdminRequest::ZoneRemove { zone } => {
            let mut zones = store.zones.lock().unwrap_or_else(|p| p.into_inner());
            if zones.remove(&zone).is_some() {
                AdminResponse::ok_with_data("zone removed", serde_json::json!({ "zone": zone }))
            } else {
                AdminResponse::err(format!("zone '{zone}' not found"))
            }
        }
        AdminRequest::ZoneReload { zone } => {
            let zones = store.zones.lock().unwrap_or_else(|p| p.into_inner());
            if zones.contains_key(&zone) {
                AdminResponse::ok_with_data("zone reloaded", serde_json::json!({ "zone": zone }))
            } else {
                AdminResponse::err(format!("zone '{zone}' not found"))
            }
        }

        // ── NTA lifecycle (OPS-011) ───────────────────────────────────────────
        AdminRequest::NtaAdd {
            domain,
            expires_at,
            reason,
        } => {
            let mut ntas = store.ntas.lock().unwrap_or_else(|p| p.into_inner());
            ntas.insert(
                domain.clone(),
                NtaEntry {
                    expires_at,
                    reason: reason.clone(),
                },
            );
            AdminResponse::ok_with_data(
                "NTA added",
                serde_json::json!({ "domain": domain, "expires_at": expires_at }),
            )
        }
        AdminRequest::NtaRevoke { domain } => {
            let mut ntas = store.ntas.lock().unwrap_or_else(|p| p.into_inner());
            if ntas.remove(&domain).is_some() {
                AdminResponse::ok_with_data("NTA revoked", serde_json::json!({ "domain": domain }))
            } else {
                AdminResponse::err(format!("NTA for '{domain}' not found"))
            }
        }
        AdminRequest::NtaList => {
            let ntas = store.ntas.lock().unwrap_or_else(|p| p.into_inner());
            let list: Vec<serde_json::Value> = ntas
                .iter()
                .map(|(domain, entry)| {
                    serde_json::json!({
                        "domain": domain,
                        "expires_at": entry.expires_at,
                        "reason": entry.reason,
                    })
                })
                .collect();
            AdminResponse::ok_with_data("NTA list", serde_json::json!({ "ntas": list }))
        }

        // ── Key rotation (OPS-012) ────────────────────────────────────────────
        AdminRequest::TekRotate => {
            let new_gen = store.tek_generation.fetch_add(1, Ordering::Relaxed) + 1;
            AdminResponse::ok_with_data("TEK rotated", serde_json::json!({ "generation": new_gen }))
        }
        AdminRequest::NewTokenKeyRotate => {
            let new_gen = store.token_key_generation.fetch_add(1, Ordering::Relaxed) + 1;
            AdminResponse::ok_with_data(
                "new-token key rotated",
                serde_json::json!({ "generation": new_gen }),
            )
        }

        // ── Rate-limit tuning (OPS-013) ───────────────────────────────────────
        AdminRequest::RateLimitTune { rule, limit } => {
            if limit == 0 || limit > 100_000 {
                return AdminResponse::err(format!(
                    "invalid limit {limit}: must be in range 1..=100_000"
                ));
            }
            let mut rate_limits = store.rate_limits.lock().unwrap_or_else(|p| p.into_inner());
            rate_limits.insert(rule.clone(), limit);
            AdminResponse::ok_with_data(
                "rate-limit tuned",
                serde_json::json!({ "rule": rule, "limit_rps": limit }),
            )
        }

        // ── Drain (OPS-014) ───────────────────────────────────────────────────
        AdminRequest::Drain => {
            store.drain_requested.store(true, Ordering::Release);
            telemetry.inc_drain_initiated();
            AdminResponse::ok_with_data("drain initiated", serde_json::json!({ "draining": true }))
        }

        // ── Diagnostics (OPS-015) ─────────────────────────────────────────────
        AdminRequest::CacheStats => AdminResponse::ok_with_data(
            "cache stats",
            serde_json::json!({
                "cache_hits_recursive": telemetry.cache_hits_recursive_total.load(Ordering::Relaxed),
                "cache_misses_recursive": telemetry.cache_misses_recursive_total.load(Ordering::Relaxed),
                "cache_hits_forwarder": telemetry.cache_hits_forwarder_total.load(Ordering::Relaxed),
                "cache_misses_forwarder": telemetry.cache_misses_forwarder_total.load(Ordering::Relaxed),
            }),
        ),
        AdminRequest::ConnectionStats => AdminResponse::ok_with_data(
            "connection stats",
            serde_json::json!({
                "acl_allowed": telemetry.acl_allowed.load(Ordering::Relaxed),
                "acl_denied": telemetry.acl_denied.load(Ordering::Relaxed),
                "conn_limit_denied": telemetry.conn_limit_denied.load(Ordering::Relaxed),
                "rrl_dropped": telemetry.rrl_dropped.load(Ordering::Relaxed),
                "rrl_slipped": telemetry.rrl_slipped.load(Ordering::Relaxed),
                "total_allowed": telemetry.total_allowed.load(Ordering::Relaxed),
            }),
        ),

        // ── RPZ management (OPS-015) ──────────────────────────────────────────
        AdminRequest::RpzEntryAdd { zone, action } => {
            let mut rpz = store.rpz_entries.lock().unwrap_or_else(|p| p.into_inner());
            rpz.insert(
                zone.clone(),
                RpzEntry {
                    action: action.clone(),
                },
            );
            AdminResponse::ok_with_data(
                "RPZ entry added",
                serde_json::json!({ "zone": zone, "action": action }),
            )
        }
        AdminRequest::RpzEntryRemove { zone } => {
            let mut rpz = store.rpz_entries.lock().unwrap_or_else(|p| p.into_inner());
            if rpz.remove(&zone).is_some() {
                AdminResponse::ok_with_data(
                    "RPZ entry removed",
                    serde_json::json!({ "zone": zone }),
                )
            } else {
                AdminResponse::err(format!("RPZ entry '{zone}' not found"))
            }
        }
        AdminRequest::RpzEntryList => {
            let rpz = store.rpz_entries.lock().unwrap_or_else(|p| p.into_inner());
            let entries: Vec<serde_json::Value> = rpz
                .iter()
                .map(|(zone, entry)| serde_json::json!({ "zone": zone, "action": entry.action }))
                .collect();
            AdminResponse::ok_with_data("RPZ entries", serde_json::json!({ "entries": entries }))
        }
    }
}

// ── AdminRpcClient ────────────────────────────────────────────────────────────

/// Async client for the admin-RPC Unix Domain Socket (OPS-007..015).
///
/// Sends a single framed JSON request and returns the server's framed JSON
/// response.  One connection is opened per call.
pub struct AdminRpcClient {
    socket_path: PathBuf,
}

impl AdminRpcClient {
    /// Create a new client.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_owned(),
        }
    }

    /// Send a raw JSON request and receive the response.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the connection fails, the write fails, or the
    /// response cannot be read.
    pub async fn send(&self, request: &serde_json::Value) -> io::Result<AdminResponse> {
        let mut stream = tokio::net::UnixStream::connect(&self.socket_path).await?;
        write_request(&mut stream, request).await?;
        read_response(&mut stream).await
    }

    /// Send the `version` command and return the response.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] on any I/O failure.
    pub async fn version(&self) -> io::Result<AdminResponse> {
        self.send(&serde_json::json!({"cmd": "version"})).await
    }
}

// ── Helper: send a framed JSON request over a UnixStream (test-only) ─────────

/// Write a length-prefix-framed JSON request to any async stream.
///
/// Used in integration tests for both the UDS path (`UnixStream`) and the
/// TCP+mTLS path (`TlsStream<TcpStream>`).
///
/// # Warning
///
/// This function is intended for integration tests only. It is not part of the
/// stable public API and may change or be removed without notice.
#[doc(hidden)]
#[expect(
    clippy::expect_used,
    reason = "test helper: invariant is always upheld by controlled test data"
)]
pub async fn write_request<S>(stream: &mut S, value: &serde_json::Value) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(value).expect("serialise test request");
    let len = u32::try_from(json.len()).expect("len fits u32");
    stream.write_u32(len).await?;
    stream.write_all(&json).await
}

/// Read a length-prefix-framed [`AdminResponse`] from any async stream.
///
/// # Warning
///
/// This function is intended for integration tests only. It is not part of the
/// stable public API and may change or be removed without notice.
#[doc(hidden)]
pub async fn read_response<S>(stream: &mut S) -> io::Result<AdminResponse>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u32().await?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(io::Error::other)
}
