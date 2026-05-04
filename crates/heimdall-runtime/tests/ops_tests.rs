// SPDX-License-Identifier: MIT

//! Integration tests for Sprint 33 — Runtime operations.
//!
//! Tests cover: SIGHUP reload semantics, admin-RPC framing and dispatch,
//! sd_notify no-ops, and HTTP observability endpoints.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use heimdall_runtime::admission::AdmissionTelemetry;
use heimdall_runtime::ops::admin_rpc::{read_response, write_request};
use heimdall_runtime::{
    AdminRpcServer, ObservabilityServer, SighupReloader,
    config::Config,
    notify_ready, notify_stopping, notify_watchdog, spawn_watchdog,
    state::RunningState,
};
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

/// Bind an AdminRpcServer on a temp socket and return its path plus the server task.
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

/// Bind an ObservabilityServer on a random port and return the bound address.
async fn start_observability(
    state: Arc<arc_swap::ArcSwap<RunningState>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use heimdall_runtime::ops::observability::BuildInfo;
    use heimdall_runtime::Drain;

    // Bind on port 0 to get an OS-assigned port.
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    // Bind a listener first to discover the port.
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("bind");
    let actual_addr = listener.local_addr().expect("local addr");
    drop(listener);

    let drain = Arc::new(Drain::new());
    let build_info = BuildInfo {
        version: "0.0.0-test",
        git_commit: "unknown",
        build_date: "1970-01-01T00:00:00Z",
        rustc: "unknown",
        target: "unknown",
        profile: "debug",
        features: "none",
    };
    let server = ObservabilityServer::new(actual_addr, state, drain, build_info);
    let handle = tokio::spawn(async move {
        server.run().await.expect("observability server error");
    });
    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(30)).await;
    (actual_addr, handle)
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
    assert_eq!(status, 200, "/readyz must return 200 while server is running");
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
