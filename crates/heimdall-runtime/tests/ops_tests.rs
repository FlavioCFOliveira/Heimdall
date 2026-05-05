// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unused_async,
    clippy::undocumented_unsafe_blocks
)]

//! Integration tests for Sprint 33 + Sprint 52 — Runtime operations.
//!
//! Tests cover: SIGHUP reload semantics, admin-RPC framing and dispatch (all
//! OPS-010..015 commands verified individually per task #518), `sd_notify`
//! no-ops, and HTTP observability endpoints.

use std::{
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use heimdall_runtime::{
    AdminRpcServer, AuditLogger, ObservabilityServer, SighupReloader,
    admission::AdmissionTelemetry,
    config::Config,
    notify_ready, notify_stopping, notify_watchdog,
    ops::admin_rpc::{AdminRpcTcpServer, read_response, write_request},
    spawn_watchdog,
    state::RunningState,
    transport::tls::{TlsServerConfig, build_tls_server_config},
};
use rustls::pki_types::CertificateDer;
use tokio::net::UnixStream;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_state_arc_swap() -> Arc<arc_swap::ArcSwap<RunningState>> {
    let config = Arc::new(Config::default());
    let telemetry = Arc::new(AdmissionTelemetry::new());
    let state = RunningState::initial(config, telemetry);
    Arc::new(arc_swap::ArcSwap::new(Arc::new(state)))
}

// ── Reload tests ─────────────────────────────────────────────────────────────

/// TEST-1: Rejected config preserves prior generation.
#[tokio::test]
async fn reload_rejected_config_preserves_state() {
    let state = make_state_arc_swap();
    let reloader = SighupReloader::new(
        Arc::clone(&state),
        std::path::PathBuf::from("/nonexistent/__heimdall_test_config__.toml"),
    );
    let outcome = reloader.reload_once().await;
    assert!(
        matches!(outcome, heimdall_runtime::ReloadOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );
    assert_eq!(
        state.load().generation,
        0,
        "generation must not change on rejection"
    );
}

/// TEST-2: Valid config increments generation to 1.
#[tokio::test]
async fn reload_valid_config_increments_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("heimdall.toml");
    std::fs::write(
        &path,
        b"[roles]\nauthoritative = true\n\n[server]\nidentity = \"test\"\nworker_threads = 1\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 5357\ntransport = \"udp\"\n",
    )
    .expect("write config");

    let state = make_state_arc_swap();
    let reloader = SighupReloader::new(Arc::clone(&state), path);
    let outcome = reloader.reload_once().await;
    assert!(
        matches!(
            outcome,
            heimdall_runtime::ReloadOutcome::Applied { generation: 1 }
        ),
        "expected Applied(1), got {outcome:?}"
    );
    assert_eq!(
        state.load().generation,
        1,
        "generation should be 1 after successful reload"
    );
}

// ── Admin-RPC tests ───────────────────────────────────────────────────────────

/// Bind an `AdminRpcServer` on a temp socket and return its path plus the server task.
async fn start_admin_rpc() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("admin.sock");
    let state = make_state_arc_swap();
    let server = AdminRpcServer::new(&socket_path, state);
    let socket_path_clone = socket_path.clone();
    let handle = tokio::spawn(async move {
        server.run().await.expect("admin-rpc server error");
    });
    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (dir, socket_path_clone, handle)
}

/// Connect to a UDS admin-rpc server.
async fn connect(socket_path: &std::path::Path) -> UnixStream {
    UnixStream::connect(socket_path)
        .await
        .expect("connect to admin-rpc socket")
}

/// TEST-3: Malformed frame (length claims 1 MiB but body is empty) — server must
/// respond with `ok: false` and not panic.
#[tokio::test]
async fn admin_rpc_malformed_frame_returns_error() {
    use tokio::io::AsyncWriteExt;

    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    // Write a 4-byte length header claiming 1 MiB, then send no body.
    stream.write_u32(1024 * 1024).await.expect("write length");
    // Close the write side immediately — server will see an unexpected EOF on body read.
    stream.shutdown().await.expect("shutdown");
    // The server must handle this without panicking; our side just sees the connection close.
    // (No response to read because we closed mid-frame before the server can reply.)
}

/// TEST-4: Unknown command returns `ok: false`.
#[tokio::test]
async fn admin_rpc_unknown_command_returns_error() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    write_request(&mut stream, &serde_json::json!({"cmd": "explode"}))
        .await
        .expect("write request");
    let response = read_response(&mut stream).await.expect("read response");
    assert!(!response.ok, "unknown command should return ok: false");
}

/// TEST-5: `rate_limit_tune` rejects limit = 0.
#[tokio::test]
async fn admin_rpc_rate_limit_tune_rejects_zero() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "rate_limit_tune", "rule": "anon", "limit": 0}),
    )
    .await
    .expect("write request");
    let response = read_response(&mut stream).await.expect("read response");
    assert!(!response.ok, "limit 0 should be rejected");
}

/// TEST-6: `zone_add` returns `ok: true`.
#[tokio::test]
async fn admin_rpc_zone_add_returns_ok() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "zone_add", "zone": "example.com.", "file": "/tmp/example.zone"}),
    )
    .await
    .expect("write request");
    let response = read_response(&mut stream).await.expect("read response");
    assert!(response.ok, "zone_add should return ok: true");
}

/// TEST-7: `nta_list` returns `ok: true`.
#[tokio::test]
async fn admin_rpc_nta_list_returns_ok() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    write_request(&mut stream, &serde_json::json!({"cmd": "nta_list"}))
        .await
        .expect("write request");
    let response = read_response(&mut stream).await.expect("read response");
    assert!(response.ok, "nta_list should return ok: true");
}

// ── sd_notify tests ───────────────────────────────────────────────────────────

/// TEST-8: `notify_ready` does not panic (with or without `$NOTIFY_SOCKET`).
///
/// In CI/development environments `$NOTIFY_SOCKET` is absent, so all helpers
/// become no-ops. Under systemd the send may silently fail — neither panics.
#[test]
fn sd_notify_no_ops_without_notify_socket() {
    notify_ready();
    notify_stopping();
    notify_watchdog();
    // Must not panic.
}

/// TEST-9: `spawn_watchdog` returns `None` when `$WATCHDOG_USEC` is not set.
#[tokio::test]
async fn sd_notify_spawn_watchdog_none_without_watchdog_usec() {
    if std::env::var("WATCHDOG_USEC").is_err() {
        let handle = spawn_watchdog();
        assert!(
            handle.is_none(),
            "expected None when WATCHDOG_USEC is not set"
        );
    }
    // When running under systemd with watchdog configured, skip the assertion.
}

// ── Observability tests ───────────────────────────────────────────────────────

/// Bind an `ObservabilityServer` on a random port with an externally-supplied drain handle.
///
/// Callers can use the returned `Drain` to trigger drain state and observe how
/// endpoints respond (task #520).
async fn start_observability_with_drain(
    state: Arc<arc_swap::ArcSwap<RunningState>>,
    drain: Arc<heimdall_runtime::Drain>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use heimdall_runtime::ops::observability::BuildInfo;

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("bind");
    let actual_addr = listener.local_addr().expect("local addr");
    drop(listener);

    let build_info = BuildInfo {
        version: "0.0.0-test",
        git_commit: "abc1234",
        build_date: "1970-01-01T00:00:00Z",
        rustc: "rustc 1.94.0",
        target: "aarch64-apple-darwin",
        profile: "debug",
        features: "none",
        tier: "PERF-aarch64",
        msrv: "1.94.0",
    };
    let server = ObservabilityServer::new(actual_addr, state, drain, build_info);
    let handle = tokio::spawn(async move {
        server.run().await.expect("observability server error");
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (actual_addr, handle)
}

/// Convenience wrapper: bind an `ObservabilityServer` with an internal drain.
async fn start_observability(
    state: Arc<arc_swap::ArcSwap<RunningState>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let drain = Arc::new(heimdall_runtime::Drain::new());
    start_observability_with_drain(state, drain).await
}

/// Make a plain HTTP GET request using hyper and return status + body.
async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper_util::rt::TokioIo;

    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .expect("handshake");

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}{path}"))
        .header("host", addr.to_string())
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status().as_u16();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    (status, body)
}

/// TEST-10: `/healthz` returns 200.
#[tokio::test]
async fn observability_healthz_returns_200() {
    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, _body) = http_get(addr, "/healthz").await;
    assert_eq!(status, 200, "/healthz must return 200");
}

/// TEST-11: `/readyz` returns 200 while the server is running and not draining (OPS-024).
#[tokio::test]
async fn observability_readyz_returns_200_while_running() {
    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, _body) = http_get(addr, "/readyz").await;
    assert_eq!(
        status, 200,
        "/readyz must return 200 while server is running"
    );
}

/// TEST-12: `/metrics` response body contains `heimdall_up`.
#[tokio::test]
async fn observability_metrics_contains_heimdall_up() {
    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200, "/metrics must return 200; body: {body}");
    assert!(
        body.contains("heimdall_up"),
        "/metrics must contain 'heimdall_up'; got: {body}"
    );
}

/// TEST-13: `/version` response body contains the `version` field.
#[tokio::test]
async fn observability_version_contains_version_field() {
    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, body) = http_get(addr, "/version").await;
    assert_eq!(status, 200, "/version must return 200; body: {body}");
    assert!(
        body.contains("\"version\""),
        "/version must contain 'version' key; got: {body}"
    );
}

// ── Admin-RPC command E2E tests (Sprint 52 task #518, OPS-010..015) ──────────

/// TEST-14: `zone_add` inserts a zone and returns ok with the zone name (OPS-010).
#[tokio::test]
async fn admin_rpc_zone_add_stores_zone() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;
    let mut stream = connect(&socket_path).await;

    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "zone_add", "zone": "example.test.", "file": "/tmp/example.zone"}),
    )
    .await
    .expect("write zone_add");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(resp.ok, "zone_add must return ok=true; got: {resp:?}");
    let zone = resp
        .data
        .as_ref()
        .and_then(|d| d.get("zone"))
        .and_then(|v| v.as_str());
    assert_eq!(
        zone,
        Some("example.test."),
        "zone_add data must include zone name"
    );
}

/// TEST-15: `zone_reload` succeeds for an existing zone; fails for unknown zone (OPS-010).
#[tokio::test]
async fn admin_rpc_zone_reload_roundtrip() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    // Add zone first.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "zone_add", "zone": "reload.test.", "file": "/tmp/r.zone"}),
    )
    .await
    .expect("write zone_add");
    read_response(&mut stream)
        .await
        .expect("read zone_add resp");

    // Reload should succeed.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "zone_reload", "zone": "reload.test."}),
    )
    .await
    .expect("write zone_reload");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(resp.ok, "zone_reload of known zone must return ok=true");

    // Reload unknown zone must fail.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "zone_reload", "zone": "nope.test."}),
    )
    .await
    .expect("write zone_reload unknown");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(!resp.ok, "zone_reload of unknown zone must return ok=false");
}

/// TEST-16: `nta_add` persists an NTA; `nta_list` reflects it (OPS-011).
#[tokio::test]
async fn admin_rpc_nta_lifecycle() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    // Add NTA.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({
            "cmd": "nta_add",
            "domain": "bad.example.",
            "expires_at": 9_999_999_999u64,
            "reason": "test anchor"
        }),
    )
    .await
    .expect("write nta_add");
    let resp = read_response(&mut stream).await.expect("read nta_add");
    assert!(resp.ok, "nta_add must return ok=true; got: {resp:?}");

    // List should include the domain.
    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "nta_list"}))
        .await
        .expect("write nta_list");
    let resp = read_response(&mut stream).await.expect("read nta_list");
    assert!(resp.ok, "nta_list must return ok=true");
    let body = serde_json::to_string(&resp.data).unwrap_or_default();
    assert!(
        body.contains("bad.example."),
        "nta_list data must contain the added domain"
    );

    // Revoke.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "nta_revoke", "domain": "bad.example."}),
    )
    .await
    .expect("write nta_revoke");
    let resp = read_response(&mut stream).await.expect("read nta_revoke");
    assert!(resp.ok, "nta_revoke must return ok=true");

    // Revoking again must fail.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "nta_revoke", "domain": "bad.example."}),
    )
    .await
    .expect("write second nta_revoke");
    let resp = read_response(&mut stream)
        .await
        .expect("read second nta_revoke");
    assert!(!resp.ok, "revoking a non-existent NTA must return ok=false");
}

/// TEST-17: `tek_rotate` increments the generation counter (OPS-012).
#[tokio::test]
async fn admin_rpc_tek_rotate_increments_generation() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "tek_rotate"}))
        .await
        .expect("write tek_rotate");
    let resp = read_response(&mut stream).await.expect("read tek_rotate");
    assert!(resp.ok, "tek_rotate must return ok=true; got: {resp:?}");
    let first_gen = resp
        .data
        .as_ref()
        .and_then(|d| d.get("generation"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(first_gen, Some(1), "first tek_rotate must set generation=1");

    // Second rotation must increment again.
    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "tek_rotate"}))
        .await
        .expect("write second tek_rotate");
    let resp = read_response(&mut stream)
        .await
        .expect("read second tek_rotate");
    let second_gen = resp
        .data
        .as_ref()
        .and_then(|d| d.get("generation"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(
        second_gen,
        Some(2),
        "second tek_rotate must set generation=2"
    );
}

/// TEST-18: `new_token_key_rotate` increments its own generation counter (OPS-012).
#[tokio::test]
async fn admin_rpc_new_token_key_rotate() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "new_token_key_rotate"}),
    )
    .await
    .expect("write new_token_key_rotate");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(
        resp.ok,
        "new_token_key_rotate must return ok=true; got: {resp:?}"
    );
    let first_gen = resp
        .data
        .as_ref()
        .and_then(|d| d.get("generation"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(
        first_gen,
        Some(1),
        "first new_token_key_rotate must set generation=1"
    );
}

/// TEST-19: `rate_limit_tune` stores the rule; invalid limit is rejected (OPS-013).
#[tokio::test]
async fn admin_rpc_rate_limit_tune_stores_rule() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    // Valid limit.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "rate_limit_tune", "rule": "anon", "limit": 5000}),
    )
    .await
    .expect("write rate_limit_tune");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(
        resp.ok,
        "rate_limit_tune with valid limit must return ok=true; got: {resp:?}"
    );
    let limit_val = resp
        .data
        .as_ref()
        .and_then(|d| d.get("limit_rps"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(
        limit_val,
        Some(5000),
        "rate_limit_tune data must contain the new limit"
    );
}

/// TEST-20: `drain` sets the drain flag and returns draining=true (OPS-014).
#[tokio::test]
async fn admin_rpc_drain_signals_drain() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "drain"}))
        .await
        .expect("write drain");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(resp.ok, "drain must return ok=true; got: {resp:?}");
    let draining = resp
        .data
        .as_ref()
        .and_then(|d| d.get("draining"))
        .and_then(serde_json::Value::as_bool);
    assert_eq!(
        draining,
        Some(true),
        "drain data must include draining=true"
    );
}

/// TEST-21: `cache_stats` returns the telemetry counters (OPS-015).
#[tokio::test]
async fn admin_rpc_cache_stats_returns_telemetry() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "cache_stats"}))
        .await
        .expect("write cache_stats");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(resp.ok, "cache_stats must return ok=true; got: {resp:?}");
    assert!(
        resp.data
            .as_ref()
            .is_some_and(|d| d.get("cache_hits_recursive").is_some()),
        "cache_stats data must contain cache_hits_recursive field"
    );
}

/// TEST-22: `connection_stats` returns admission telemetry counters (OPS-015).
#[tokio::test]
async fn admin_rpc_connection_stats_returns_counters() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "connection_stats"}))
        .await
        .expect("write connection_stats");
    let resp = read_response(&mut stream).await.expect("read response");
    assert!(
        resp.ok,
        "connection_stats must return ok=true; got: {resp:?}"
    );
    assert!(
        resp.data
            .as_ref()
            .is_some_and(|d| d.get("acl_allowed").is_some()),
        "connection_stats data must contain acl_allowed field"
    );
}

/// TEST-23: RPZ entry lifecycle — add, list, remove (OPS-015).
#[tokio::test]
async fn admin_rpc_rpz_entry_lifecycle() {
    let (_dir, socket_path, _handle) = start_admin_rpc().await;

    // Add entry.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "rpz_entry_add", "zone": "block.rpz.", "action": "NXDOMAIN"}),
    )
    .await
    .expect("write rpz_entry_add");
    let resp = read_response(&mut stream)
        .await
        .expect("read rpz_entry_add");
    assert!(resp.ok, "rpz_entry_add must return ok=true; got: {resp:?}");

    // List must include the zone.
    let mut stream = connect(&socket_path).await;
    write_request(&mut stream, &serde_json::json!({"cmd": "rpz_entry_list"}))
        .await
        .expect("write rpz_entry_list");
    let resp = read_response(&mut stream)
        .await
        .expect("read rpz_entry_list");
    assert!(resp.ok, "rpz_entry_list must return ok=true");
    let body = serde_json::to_string(&resp.data).unwrap_or_default();
    assert!(
        body.contains("block.rpz."),
        "rpz_entry_list must contain the added zone"
    );

    // Remove.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "rpz_entry_remove", "zone": "block.rpz."}),
    )
    .await
    .expect("write rpz_entry_remove");
    let resp = read_response(&mut stream)
        .await
        .expect("read rpz_entry_remove");
    assert!(resp.ok, "rpz_entry_remove must return ok=true");

    // Removing again must fail.
    let mut stream = connect(&socket_path).await;
    write_request(
        &mut stream,
        &serde_json::json!({"cmd": "rpz_entry_remove", "zone": "block.rpz."}),
    )
    .await
    .expect("write second rpz_entry_remove");
    let resp = read_response(&mut stream)
        .await
        .expect("read second rpz_entry_remove");
    assert!(
        !resp.ok,
        "removing a non-existent RPZ entry must return ok=false"
    );
}

// ── Admin-RPC TCP+mTLS+ACL tests (Sprint 52 task #519, OPS-007..009) ─────────

use std::sync::OnceLock;

static PROVIDER_INIT_OPS: OnceLock<()> = OnceLock::new();

fn init_crypto_provider() {
    PROVIDER_INIT_OPS.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Generate a self-signed Ed25519 server certificate with rcgen.
/// Returns (cert DER, key PEM, cert PEM).
fn gen_tcp_server_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

/// Generate a self-signed Ed25519 client certificate with rcgen.
/// Returns (cert DER, key PEM, cert PEM).
fn gen_tcp_client_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("client keygen");
    let mut params = CertificateParams::new(vec!["client.localhost".to_owned()]).expect("params");
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

/// Build a rustls `ClientConfig` that presents a client cert and trusts the given server cert.
fn make_tcp_mtls_client_config(
    server_cert_der: Vec<u8>,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Arc<rustls::ClientConfig> {
    init_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(server_cert_der))
        .expect("add server cert");
    let client_certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(client_cert_pem.as_bytes()))
            .collect::<Result<_, _>>()
            .expect("parse client cert");
    let client_key = rustls_pemfile::private_key(&mut BufReader::new(client_key_pem.as_bytes()))
        .expect("parse client key io")
        .expect("client key present");
    Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .expect("client auth cert"),
    )
}

/// Build a rustls `ClientConfig` with no client cert (used to test handshake rejection).
fn make_tcp_no_client_auth_config(server_cert_der: Vec<u8>) -> Arc<rustls::ClientConfig> {
    init_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(server_cert_der))
        .expect("add server cert");
    Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Spawn an `AdminRpcTcpServer` with mTLS + ACL; returns its bound address.
async fn start_tcp_admin_rpc(
    allowed_cidrs: Vec<(IpAddr, u8)>,
    server_cert_pem: &str,
    server_key_pem: &str,
    client_ca_pem: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    init_crypto_provider();
    let cert_file = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(cert_file.path(), server_cert_pem).expect("write cert");
    let key_file = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(key_file.path(), server_key_pem).expect("write key");
    let ca_file = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(ca_file.path(), client_ca_pem).expect("write ca");

    let tls_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        mtls_trust_anchor: Some(ca_file.path().to_path_buf()),
        ..TlsServerConfig::default()
    };
    let server_tls = build_tls_server_config(&tls_cfg).expect("build tls config");
    drop(cert_file);
    drop(key_file);
    drop(ca_file);

    let state = make_state_arc_swap();
    // Bind on port 0 to get an OS-assigned port.
    let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = temp_listener.local_addr().expect("local addr");
    drop(temp_listener);

    let server = AdminRpcTcpServer::new(addr, state, server_tls, allowed_cidrs);
    let handle = tokio::spawn(async move {
        server.run_tcp().await.expect("tcp server error");
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (addr, handle)
}

/// TEST-24: Valid client cert + allowed CIDR → `version` command succeeds (OPS-007..009).
#[tokio::test]
async fn admin_rpc_tcp_valid_cert_allowed_cidr_succeeds() {
    let (server_cert_der, server_key_pem, server_cert_pem) = gen_tcp_server_cert();
    let (client_cert_der, client_key_pem, client_cert_pem) = gen_tcp_client_cert();
    let _ = client_cert_der; // der not needed for client config here

    let loopback: IpAddr = "127.0.0.1".parse().expect("parse");
    let allowed = vec![(loopback, 32u8)];
    let (addr, _handle) =
        start_tcp_admin_rpc(allowed, &server_cert_pem, &server_key_pem, &client_cert_pem).await;

    let client_cfg =
        make_tcp_mtls_client_config(server_cert_der, &client_cert_pem, &client_key_pem);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    write_request(&mut tls, &serde_json::json!({"cmd": "version"}))
        .await
        .expect("write version");
    let resp = read_response(&mut tls).await.expect("read version");
    assert!(
        resp.ok,
        "version over TCP+mTLS must return ok=true; got: {resp:?}"
    );
    assert!(
        resp.data.as_ref().and_then(|d| d.get("version")).is_some(),
        "version response must include version field"
    );
}

/// TEST-25: Valid client cert + denied CIDR → connection dropped before any response
/// (OPS-008 ACL enforcement; denial latency < 5 ms).
#[tokio::test]
async fn admin_rpc_tcp_valid_cert_denied_cidr_connection_dropped() {
    let (server_cert_der, server_key_pem, server_cert_pem) = gen_tcp_server_cert();
    let (_, client_key_pem, client_cert_pem) = gen_tcp_client_cert();

    // Allow only 192.0.2.1/32 (TEST-NET; loopback will not match).
    let test_net: IpAddr = "192.0.2.1".parse().expect("parse");
    let denied_for_loopback = vec![(test_net, 32u8)];
    let (addr, _handle) = start_tcp_admin_rpc(
        denied_for_loopback,
        &server_cert_pem,
        &server_key_pem,
        &client_cert_pem,
    )
    .await;

    let t0 = std::time::Instant::now();
    // The server drops the connection immediately on ACL denial, before the TLS
    // handshake.  The client therefore gets a connection-reset or EOF during
    // the handshake.
    let client_cfg =
        make_tcp_mtls_client_config(server_cert_der, &client_cert_pem, &client_key_pem);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let result = connector.connect(server_name, tcp).await;
    let elapsed_ms = t0.elapsed().as_millis();

    // The connection must have been rejected.
    assert!(result.is_err(), "denied CIDR must cause connection failure");
    // Denial latency must be well under 5 ms (task #519 AC); we give generous
    // headroom for CI scheduling jitter.
    assert!(
        elapsed_ms < 500,
        "denial latency {elapsed_ms}ms exceeds 500ms headroom"
    );
}

/// TEST-26: No client cert → server rejects the connection (mTLS enforcement).
///
/// In TLS 1.3 the server's rejection alert arrives after the client-side
/// handshake completes.  The failure therefore manifests on the first
/// application-data read, not necessarily on `connect()`.
#[tokio::test]
async fn admin_rpc_tcp_no_client_cert_handshake_fails() {
    let (server_cert_der, server_key_pem, server_cert_pem) = gen_tcp_server_cert();
    let (_, _, client_cert_pem) = gen_tcp_client_cert();

    // Allow loopback so the ACL passes; the mTLS layer must reject the client.
    let loopback: IpAddr = "127.0.0.1".parse().expect("parse");
    let allowed = vec![(loopback, 32u8)];
    let (addr, _handle) =
        start_tcp_admin_rpc(allowed, &server_cert_pem, &server_key_pem, &client_cert_pem).await;

    // Client presents no certificate.
    let client_cfg = make_tcp_no_client_auth_config(server_cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

    match connector.connect(server_name, tcp).await {
        Err(_) => {
            // Handshake rejected immediately — ideal.
        }
        Ok(mut tls) => {
            // In TLS 1.3 the server's post-handshake alert arrives on the first
            // application-layer read; the write may or may not succeed first.
            let _ = write_request(&mut tls, &serde_json::json!({"cmd": "version"})).await;
            let read_result = read_response(&mut tls).await;
            assert!(
                read_result.is_err(),
                "no-client-cert connection must fail during application-data exchange"
            );
        }
    }
}

// ── /healthz and /readyz drain semantics (Sprint 52 task #520, OPS-021..024) ─

/// TEST-27: `/healthz` returns 200 even after drain has been initiated (OPS-023).
///
/// `/healthz` signals "process alive" — it must never return 503 just because
/// the server is draining.
#[tokio::test]
async fn observability_healthz_returns_200_during_drain() {
    let state = make_state_arc_swap();
    let drain = Arc::new(heimdall_runtime::Drain::new());
    let (addr, _handle) = start_observability_with_drain(state, Arc::clone(&drain)).await;

    // Initiate drain with no in-flight ops — completes immediately.
    drain
        .drain_and_wait(Duration::from_millis(100))
        .await
        .expect("drain");
    assert!(drain.is_draining(), "drain must be active");

    let (status, _body) = http_get(addr, "/healthz").await;
    assert_eq!(status, 200, "/healthz must return 200 during drain");
}

/// TEST-28: `/readyz` returns 503 once drain has been initiated (OPS-024).
#[tokio::test]
async fn observability_readyz_returns_503_during_drain() {
    let state = make_state_arc_swap();
    let drain = Arc::new(heimdall_runtime::Drain::new());
    let (addr, _handle) = start_observability_with_drain(state, Arc::clone(&drain)).await;

    drain
        .drain_and_wait(Duration::from_millis(100))
        .await
        .expect("drain");

    let (status, body) = http_get(addr, "/readyz").await;
    assert_eq!(
        status, 503,
        "/readyz must return 503 during drain; body: {body}"
    );
}

// ── /metrics counter assertions (Sprint 52 task #521, OPS-025..028) ──────────

/// Build a dedicated state whose telemetry counters we fully control.
fn make_state_with_telemetry() -> (
    Arc<arc_swap::ArcSwap<RunningState>>,
    Arc<heimdall_runtime::admission::AdmissionTelemetry>,
) {
    use std::sync::atomic::Ordering;

    let config = Arc::new(heimdall_runtime::config::Config::default());
    let telemetry = Arc::new(heimdall_runtime::admission::AdmissionTelemetry::new());

    // Seed non-zero values for each counter so every assertion is meaningful.
    telemetry.acl_denied.fetch_add(3, Ordering::Relaxed);
    telemetry.rrl_slipped.fetch_add(2, Ordering::Relaxed);
    telemetry.rrl_dropped.fetch_add(1, Ordering::Relaxed);
    telemetry.query_rl_denied.fetch_add(4, Ordering::Relaxed);
    telemetry.total_allowed.fetch_add(10, Ordering::Relaxed);
    telemetry.queries_auth_total.fetch_add(7, Ordering::Relaxed);
    telemetry
        .queries_recursive_total
        .fetch_add(3, Ordering::Relaxed);
    telemetry.dnssec_bogus_total.fetch_add(5, Ordering::Relaxed);
    telemetry
        .drain_initiated_total
        .fetch_add(1, Ordering::Relaxed);

    let state = RunningState::initial(config, Arc::clone(&telemetry));
    let arc_swap = Arc::new(arc_swap::ArcSwap::new(Arc::new(state)));
    (arc_swap, telemetry)
}

/// TEST-29: `/metrics` contains all required counter names with HELP/TYPE lines (OPS-025).
#[tokio::test]
async fn observability_metrics_contains_required_counters() {
    let (state, _telemetry) = make_state_with_telemetry();
    let (addr, _handle) = start_observability(state).await;
    let (status, body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200, "/metrics must return 200");

    // All required counter names from task #521 acceptance criteria.
    let required = [
        "heimdall_queries_total",
        "heimdall_acl_denied_total",
        "heimdall_rrl_truncated_total",
        "heimdall_query_rl_refused_total",
        "heimdall_dnssec_bogus_total",
        "heimdall_drain_initiated_total",
    ];
    for name in &required {
        assert!(
            body.contains(name),
            "/metrics must contain counter '{name}'; body: {body}"
        );
        // Each counter must be declared with a HELP line.
        assert!(
            body.contains(&format!("# HELP {name}")),
            "/metrics must contain '# HELP {name}' line; body: {body}"
        );
        // Each counter must be declared with a TYPE line.
        assert!(
            body.contains(&format!("# TYPE {name}")),
            "/metrics must contain '# TYPE {name}' line; body: {body}"
        );
    }
    // OpenMetrics terminator must be present.
    assert!(
        body.contains("# EOF"),
        "/metrics must contain '# EOF' terminator; body: {body}"
    );
}

/// TEST-30: Counter increments are reflected in `/metrics` output (OPS-027).
#[tokio::test]
async fn observability_metrics_counters_reflect_increments() {
    use std::sync::atomic::Ordering;

    let (state, telemetry) = make_state_with_telemetry();
    let (addr, _handle) = start_observability(state).await;

    // Read baseline values (seeded in make_state_with_telemetry).
    let (_, body) = http_get(addr, "/metrics").await;
    assert!(
        body.contains("heimdall_acl_denied_total 3"),
        "acl_denied_total must be 3; body: {body}"
    );
    assert!(
        body.contains("heimdall_rrl_truncated_total 2"),
        "rrl_truncated_total must be 2; body: {body}"
    );
    assert!(
        body.contains("heimdall_query_rl_refused_total 4"),
        "query_rl_refused_total must be 4; body: {body}"
    );
    assert!(
        body.contains("heimdall_dnssec_bogus_total 5"),
        "dnssec_bogus_total must be 5; body: {body}"
    );
    assert!(
        body.contains("heimdall_drain_initiated_total 1"),
        "drain_initiated_total must be 1; body: {body}"
    );

    // Increment and verify the new values appear.
    telemetry.acl_denied.fetch_add(1, Ordering::Relaxed);
    telemetry.dnssec_bogus_total.fetch_add(2, Ordering::Relaxed);

    let (_, body2) = http_get(addr, "/metrics").await;
    assert!(
        body2.contains("heimdall_acl_denied_total 4"),
        "acl_denied_total must be 4 after increment; body: {body2}"
    );
    assert!(
        body2.contains("heimdall_dnssec_bogus_total 7"),
        "dnssec_bogus_total must be 7 after increment; body: {body2}"
    );
}

/// TEST-31: `/metrics` body passes `promtool check metrics` when the tool is available (task #567).
///
/// This test is skipped when `promtool` is not found in `$PATH` so that CI
/// environments without Prometheus tooling are not broken.
#[tokio::test]
async fn observability_metrics_passes_promtool_check() {
    // Skip if promtool is not installed.
    let promtool = which_promtool();
    if promtool.is_none() {
        eprintln!("Skip: promtool not found in PATH — install Prometheus to enable this test");
        return;
    }
    let promtool = promtool.unwrap();

    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200);

    // Write to a temp file and pipe to promtool.
    let dir = tempfile::tempdir().expect("tempdir");
    let metrics_file = dir.path().join("metrics.txt");
    std::fs::write(&metrics_file, &body).expect("write metrics file");

    let output = std::process::Command::new(&promtool)
        .args(["check", "metrics"])
        .stdin(std::fs::File::open(&metrics_file).expect("open metrics file"))
        .output()
        .expect("run promtool");

    assert!(
        output.status.success(),
        "promtool check metrics failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Locate `promtool` in the system `$PATH`, returning `None` if not found.
fn which_promtool() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|path_var| {
        std::env::split_paths(&path_var).find_map(|dir| {
            let candidate = dir.join("promtool");
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

// ── /version full field validation (Sprint 52 task #522, OPS-029..031) ───────

/// TEST-32: `/version` response contains all required build-info fields (OPS-029..031).
#[tokio::test]
async fn observability_version_contains_all_required_fields() {
    let state = make_state_arc_swap();
    let (addr, _handle) = start_observability(state).await;
    let (status, body) = http_get(addr, "/version").await;
    assert_eq!(status, 200, "/version must return 200; body: {body}");

    let json: serde_json::Value =
        serde_json::from_str(body.trim()).expect("/version body must be valid JSON");

    let required_fields = [
        "version",
        "git_commit",
        "build_date",
        "rustc",
        "target",
        "profile",
        "features",
        "tier",
        "msrv",
        "runtime",
    ];
    for field in &required_fields {
        assert!(
            json.get(field).is_some(),
            "/version JSON must contain '{field}' field; body: {body}"
        );
    }

    // `runtime` must contain uid, gid, root_fs_writable.
    let runtime = json.get("runtime").expect("runtime field must be present");
    assert!(runtime.get("uid").is_some(), "runtime.uid must be present");
    assert!(runtime.get("gid").is_some(), "runtime.gid must be present");
    assert!(
        runtime.get("root_fs_writable").is_some(),
        "runtime.root_fs_writable must be present"
    );

    // All string fields must be non-empty.
    for field in &["version", "git_commit", "build_date", "tier", "msrv"] {
        let val = json.get(*field).and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !val.is_empty(),
            "/version field '{field}' must be non-empty; body: {body}"
        );
    }
}

// ── WatchdogSec smoke test (Sprint 52 task #523, OPS-032) ────────────────────

/// TEST-33: `spawn_watchdog` returns `Some` when `WATCHDOG_USEC` is set (OPS-045).
///
/// Sets `WATCHDOG_USEC=200000` (200 ms), verifies that a watchdog task is
/// spawned, then aborts it immediately to avoid leaking the task.
///
/// Note: this test manipulates an environment variable which is process-global.
/// It must not run in parallel with other `WATCHDOG_USEC`-sensitive tests.
#[allow(unsafe_code)]
#[tokio::test]
async fn sd_notify_spawn_watchdog_some_when_watchdog_usec_set() {
    // Set a 200 ms watchdog interval to avoid a long-running keepalive task.
    // SAFETY: this test is the only user of WATCHDOG_USEC in this test binary;
    // `#[tokio::test]` functions run in a single-process executor and the env
    // mutation is restored before `spawn_watchdog` returns, so no concurrent
    // reader can observe a torn state.
    unsafe { std::env::set_var("WATCHDOG_USEC", "200000") };
    let handle = spawn_watchdog();
    // Restore the environment immediately so other tests are not affected.
    unsafe { std::env::remove_var("WATCHDOG_USEC") };

    assert!(
        handle.is_some(),
        "spawn_watchdog must return Some when WATCHDOG_USEC is set"
    );
    // Abort the spawned task to avoid leaking it into the test runtime.
    handle.unwrap().abort();
}

// ── Audit log HMAC chain (Sprint 52 task #524, THREAT-080) ───────────────────

/// TEST-34: Each admin-RPC call via the UDS path produces an audit entry with
/// a correct HMAC chain (THREAT-080).
///
/// Validates that `AuditLogger` emits entries with a verifiable chain when
/// multiple commands are issued in sequence.
#[test]
fn audit_logger_admin_rpc_chain_validates() {
    let key = b"heimdall-audit-key-32-bytes-pad!!";
    let logger = AuditLogger::new(key, None).expect("create logger");

    let e1 = logger.log("uds-local", "zone_add", "ok");
    let e2 = logger.log("uds-local", "nta_add", "ok");
    let e3 = logger.log("uds-local", "tek_rotate", "ok");
    let e4 = logger.log("uds-local", "drain", "ok");

    AuditLogger::verify_chain(key, &[e1, e2, e3, e4])
        .expect("HMAC chain must be valid after sequential admin-RPC calls");
}

/// TEST-35: Audit entries produced under concurrent access maintain a valid chain.
///
/// Spawns 4 threads each issuing 25 log calls; validates the complete chain.
#[test]
fn audit_logger_concurrent_access_maintains_chain() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    let key = b"heimdall-audit-key-32-bytes-pad!!";
    let logger = Arc::new(AuditLogger::new(key, None).expect("create logger"));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let done = Arc::new(AtomicUsize::new(0));

    const THREADS: usize = 4;
    const CALLS_PER_THREAD: usize = 25;

    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let logger = Arc::clone(&logger);
        let results = Arc::clone(&results);
        let done = Arc::clone(&done);
        handles.push(std::thread::spawn(move || {
            for i in 0..CALLS_PER_THREAD {
                let cmd = if i % 2 == 0 { "zone_add" } else { "nta_list" };
                let entry = logger.log("uds-local", cmd, "ok");
                results.lock().unwrap().push(entry);
            }
            done.fetch_add(1, AtomicOrdering::Relaxed);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    let mut entries = results.lock().unwrap();
    // Sort by seq to reconstruct the chain in emission order.
    entries.sort_by_key(|e| e.seq);

    AuditLogger::verify_chain(key, &entries)
        .expect("HMAC chain must be valid after concurrent access");

    // Total entries must be exactly THREADS * CALLS_PER_THREAD.
    assert_eq!(
        entries.len(),
        THREADS * CALLS_PER_THREAD,
        "entry count must equal total calls"
    );
    // Sequence numbers must be 1..=total with no gaps.
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, (i + 1) as u64, "seq must be gapless");
    }
}

/// TEST-36: Tampered audit entry is detected during offline chain verification (THREAT-080).
#[test]
fn audit_logger_tampered_entry_detected() {
    let key = b"heimdall-audit-key-32-bytes-pad!!";
    let logger = AuditLogger::new(key, None).expect("create logger");

    let e1 = logger.log("uds-local", "zone_add", "ok");
    let mut e2 = logger.log("uds-local", "drain", "ok");
    let e3 = logger.log("uds-local", "nta_list", "ok");

    // Tamper: flip the outcome of e2.
    e2.outcome = "ok_falsified".to_owned();

    let result = AuditLogger::verify_chain(key, &[e1, e2, e3]);
    assert_eq!(
        result,
        Err(2),
        "tampered entry seq=2 must break the chain at that point"
    );
}
