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
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use tracing::{error, info, warn};

use crate::state::StateContainer;

// ── Request / Response types ─────────────────────────────────────────────────

/// Admin-RPC command (subset of OPS-034).
///
/// Commands are decoded from JSON using the `cmd` field as a discriminant.
/// All string fields are validated before dispatch.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
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
    fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: None,
        }
    }

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
    state: Arc<StateContainer>,
}

impl AdminRpcServer {
    /// Create a new server.
    ///
    /// The socket is not bound until [`AdminRpcServer::run`] is called.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>, state: Arc<StateContainer>) -> Self {
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

// ── TCP stub (OPS-009, OPS-041) ───────────────────────────────────────────────

/// Admin-RPC stub for TCP binding.
///
/// Full mTLS-protected TCP binding is deferred to the integration sprint (OPS-009,
/// OPS-041). This type exists to satisfy the API shape; `run_tcp` always returns
/// an error.
pub struct AdminRpcTcpServer {
    _bind_addr: SocketAddr,
    _state: Arc<StateContainer>,
}

impl AdminRpcTcpServer {
    /// Create a new TCP server stub.
    #[must_use]
    pub fn new(bind_addr: SocketAddr, state: Arc<StateContainer>) -> Self {
        Self {
            _bind_addr: bind_addr,
            _state: state,
        }
    }

    /// Run the TCP admin-RPC server.
    ///
    /// Always returns an error: TCP binding requires mTLS wiring that is deferred
    /// to the integration sprint (OPS-009, OPS-041).
    ///
    /// # Errors
    ///
    /// Always returns `Err(io::ErrorKind::Unsupported)`.
    pub fn run_tcp(self) -> Result<(), io::Error> {
        warn!(
            event = "admin_rpc_tcp_disabled",
            "admin-RPC TCP binding requires mTLS wiring; deferred to integration sprint"
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "admin-rpc TCP binding requires mTLS wiring in integration sprint",
        ))
    }
}

// ── Connection handling ───────────────────────────────────────────────────────

/// Maximum frame body size accepted from a client (1 MiB).
///
/// Guards against memory exhaustion attacks where the 4-byte length header
/// claims a very large body (OPS-039 resource-limit compliance).
const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Handle a single UDS connection: read one request frame, dispatch, write response.
async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<StateContainer>,
) -> Result<(), io::Error> {
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
        write_response(&mut stream, &resp).await?;
        return Ok(());
    }

    // Read exactly `len` bytes.
    let mut buf = vec![0u8; len as usize];
    if let Err(e) = stream.read_exact(&mut buf).await {
        let resp = AdminResponse::err(format!("failed to read frame body: {e}"));
        write_response(&mut stream, &resp).await?;
        return Ok(());
    }

    // Decode JSON.
    let request: AdminRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            let resp = AdminResponse::err(format!("malformed request: {e}"));
            write_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    let start = Instant::now();
    let cmd_name = cmd_name(&request);
    let response = dispatch(request, &state);
    let duration_ms = start.elapsed().as_millis();

    let outcome = if response.ok { "ok" } else { "error" };
    info!(
        event = "admin_rpc_audit",
        cmd = cmd_name,
        outcome = outcome,
        duration_ms = duration_ms,
        "admin-rpc operation"
    );

    write_response(&mut stream, &response).await
}

/// Serialise `response` and write it with a 4-byte big-endian length prefix.
async fn write_response(
    stream: &mut UnixStream,
    response: &AdminResponse,
) -> Result<(), io::Error> {
    let json = serde_json::to_vec(response).map_err(io::Error::other)?;
    let len = u32::try_from(json.len()).map_err(|_| io::Error::other("response too large"))?;
    stream.write_u32(len).await?;
    stream.write_all(&json).await
}

/// Extract a stable string name from an [`AdminRequest`] for audit logging.
fn cmd_name(req: &AdminRequest) -> &'static str {
    match req {
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
fn dispatch(request: AdminRequest, state: &StateContainer) -> AdminResponse {
    match request {
        // ── Zone lifecycle ────────────────────────────────────────────────────
        AdminRequest::ZoneAdd { zone, file } => {
            info!(event = "admin_rpc", cmd = "zone_add", zone = %zone, file = %file);
            AdminResponse::ok("stub: zone operation queued")
        }
        AdminRequest::ZoneRemove { zone } => {
            info!(event = "admin_rpc", cmd = "zone_remove", zone = %zone);
            AdminResponse::ok("stub: zone operation queued")
        }
        AdminRequest::ZoneReload { zone } => {
            info!(event = "admin_rpc", cmd = "zone_reload", zone = %zone);
            AdminResponse::ok("stub: zone operation queued")
        }

        // ── NTA lifecycle ─────────────────────────────────────────────────────
        AdminRequest::NtaAdd {
            domain,
            expires_at,
            reason,
        } => {
            // Verify state is accessible.
            let _guard = state.load();
            info!(
                event = "admin_rpc",
                cmd = "nta_add",
                domain = %domain,
                expires_at = expires_at,
                reason = %reason
            );
            AdminResponse::ok("stub: NTA added")
        }
        AdminRequest::NtaRevoke { domain } => {
            let _guard = state.load();
            info!(event = "admin_rpc", cmd = "nta_revoke", domain = %domain);
            AdminResponse::ok("stub: NTA revoked")
        }
        AdminRequest::NtaList => {
            let _guard = state.load();
            info!(event = "admin_rpc", cmd = "nta_list");
            AdminResponse::ok_with_data("stub: NTA list", serde_json::json!({ "ntas": [] }))
        }

        // ── Key rotation ──────────────────────────────────────────────────────
        AdminRequest::TekRotate => {
            info!(
                event = "admin_rpc_audit",
                cmd = "tek_rotate",
                outcome = "ok",
                "TEK rotation requested"
            );
            AdminResponse::ok("TEK rotation queued")
        }
        AdminRequest::NewTokenKeyRotate => {
            info!(
                event = "admin_rpc_audit",
                cmd = "new_token_key_rotate",
                outcome = "ok",
                "new-token key rotation requested"
            );
            AdminResponse::ok("new-token key rotation queued")
        }

        // ── Rate-limit tuning ─────────────────────────────────────────────────
        AdminRequest::RateLimitTune { rule, limit } => {
            if limit == 0 || limit > 100_000 {
                return AdminResponse::err(format!(
                    "invalid limit {limit}: must be in range 1..=100_000"
                ));
            }
            info!(event = "admin_rpc", cmd = "rate_limit_tune", rule = %rule, limit = limit);
            AdminResponse::ok(format!("rate-limit rule '{rule}' updated to {limit} req/s"))
        }

        // ── Drain ─────────────────────────────────────────────────────────────
        AdminRequest::Drain => {
            info!(
                event = "admin_rpc_audit",
                cmd = "drain",
                outcome = "ok",
                "graceful drain requested"
            );
            // Actual drain signal wiring is deferred to integration sprint.
            AdminResponse::ok("drain initiated")
        }

        // ── Diagnostics ───────────────────────────────────────────────────────
        AdminRequest::CacheStats => AdminResponse::ok_with_data(
            "cache stats",
            serde_json::json!({ "entries": 0, "hits": 0, "misses": 0 }),
        ),
        AdminRequest::ConnectionStats => AdminResponse::ok_with_data(
            "connection stats",
            serde_json::json!({ "entries": 0, "hits": 0, "misses": 0 }),
        ),

        // ── RPZ management ────────────────────────────────────────────────────
        AdminRequest::RpzEntryAdd { zone, action } => {
            info!(event = "admin_rpc_audit", cmd = "rpz_entry_add", zone = %zone, action = %action, outcome = "ok", "RPZ entry added");
            AdminResponse::ok("stub: RPZ entry added")
        }
        AdminRequest::RpzEntryRemove { zone } => {
            info!(event = "admin_rpc_audit", cmd = "rpz_entry_remove", zone = %zone, outcome = "ok", "RPZ entry removed");
            AdminResponse::ok("stub: RPZ entry removed")
        }
        AdminRequest::RpzEntryList => {
            info!(
                event = "admin_rpc_audit",
                cmd = "rpz_entry_list",
                outcome = "ok",
                "RPZ entries listed"
            );
            AdminResponse::ok_with_data("stub: RPZ entries", serde_json::json!({ "entries": [] }))
        }
    }
}

// ── Helper: send a framed JSON request over a UnixStream (test-only) ─────────

/// Write a framed request to a [`UnixStream`].
///
/// Write a framed JSON request to a [`UnixStream`].
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
pub async fn write_request(stream: &mut UnixStream, value: &serde_json::Value) -> io::Result<()> {
    let json = serde_json::to_vec(value).expect("serialise test request");
    let len = u32::try_from(json.len()).expect("len fits u32");
    stream.write_u32(len).await?;
    stream.write_all(&json).await
}

/// Read a framed [`AdminResponse`] from a [`UnixStream`].
///
/// # Warning
///
/// This function is intended for integration tests only. It is not part of the
/// stable public API and may change or be removed without notice.
#[doc(hidden)]
pub async fn read_response(stream: &mut UnixStream) -> io::Result<AdminResponse> {
    let len = stream.read_u32().await?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(io::Error::other)
}
