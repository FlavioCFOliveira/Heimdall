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
// Integration tests for heimdall-runtime skeleton.
// These tests exercise the public API surface end-to-end without the
// concurrency state-space exploration of the loom tests.

use std::{sync::Arc, time::Duration};

// ── Config round-trip ─────────────────────────────────────────────────────────

#[test]
fn config_roundtrip() {
    let toml = r#"
[roles]
authoritative = true

[server]
identity = "test-node"
worker_threads = 2

[[listeners]]
address = "127.0.0.1"
port = 5353
transport = "udp"

[cache]
capacity = 10000
min_ttl_secs = 60
max_ttl_secs = 3600
"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("heimdall.toml");
    std::fs::write(&path, toml).expect("write config");

    let loader = heimdall_runtime::ConfigLoader::load(&path).expect("load config");
    let config = loader.current();

    assert_eq!(config.server.identity, "test-node");
    assert_eq!(config.server.worker_threads, 2);
    assert_eq!(config.cache.capacity, 10_000);
    assert_eq!(config.cache.min_ttl_secs, 60);
    assert_eq!(config.cache.max_ttl_secs, 3_600);
    assert_eq!(config.listeners.len(), 1);
}

#[test]
fn config_reload_replaces_current() {
    let toml_v1 = r#"
[roles]
authoritative = true

[server]
identity = "v1"
worker_threads = 1

[[listeners]]
address = "127.0.0.1"
port = 5354
transport = "udp"
"#;
    let toml_v2 = r#"
[roles]
authoritative = true

[server]
identity = "v2"
worker_threads = 4

[[listeners]]
address = "127.0.0.1"
port = 5355
transport = "udp"
"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("heimdall.toml");
    std::fs::write(&path, toml_v1).expect("write v1");

    let loader = heimdall_runtime::ConfigLoader::load(&path).expect("load v1");
    assert_eq!(loader.current().server.identity, "v1");

    std::fs::write(&path, toml_v2).expect("write v2");
    loader.reload().expect("reload v2");
    assert_eq!(loader.current().server.identity, "v2");
}

#[test]
fn config_reload_leaves_current_unchanged_on_parse_error() {
    let toml_valid = r#"
[roles]
authoritative = true

[server]
identity = "original"
worker_threads = 1

[[listeners]]
address = "127.0.0.1"
port = 5356
transport = "udp"
"#;
    let toml_invalid = "this is not valid toml ][[[";

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("heimdall.toml");
    std::fs::write(&path, toml_valid).expect("write valid");

    let loader = heimdall_runtime::ConfigLoader::load(&path).expect("load valid");
    assert_eq!(loader.current().server.identity, "original");

    std::fs::write(&path, toml_invalid).expect("write invalid");
    let result = loader.reload();
    assert!(result.is_err(), "reload of invalid TOML should fail");

    // Current config must be unchanged.
    assert_eq!(
        loader.current().server.identity,
        "original",
        "config must not change on failed reload"
    );
}

// ── State generation ──────────────────────────────────────────────────────────

#[test]
fn state_swap_increments_generation() {
    use heimdall_runtime::{Config, RunningState, StateContainer, admission::AdmissionTelemetry};

    let config = Arc::new(Config::default());
    let telemetry = Arc::new(AdmissionTelemetry::new());
    let initial = RunningState::initial(config.clone(), telemetry);
    let container = StateContainer::new(initial);

    let gen0 = container.load().generation;
    assert_eq!(gen0, 0);

    let new_state = container.load().next_generation(config);
    container.swap(new_state);

    let gen1 = container.load().generation;
    assert_eq!(gen1, gen0 + 1);
}

#[test]
fn state_multiple_swaps_monotonic() {
    use heimdall_runtime::{Config, RunningState, StateContainer, admission::AdmissionTelemetry};

    let config = Arc::new(Config::default());
    let telemetry = Arc::new(AdmissionTelemetry::new());
    let container = StateContainer::new(RunningState::initial(config.clone(), telemetry));

    for expected_gen in 1_u64..=5 {
        let next = container.load().next_generation(config.clone());
        container.swap(next);
        assert_eq!(container.load().generation, expected_gen);
    }
}

// ── Drain ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn drain_rejects_after_signal() {
    use heimdall_runtime::Drain;

    let drain = Drain::new();

    // Acquire two guards before signalling drain.
    let guard = drain.acquire().expect("acquire before drain");
    let guard2 = drain.acquire().expect("acquire2 before drain");

    // Release both guards first, then drain.
    drop(guard);
    drop(guard2);

    drain
        .drain_and_wait(Duration::from_millis(100))
        .await
        .expect("drain should succeed with no in-flight");

    // After drain, all subsequent acquires must be rejected.
    assert!(
        drain.acquire().is_none(),
        "acquire must return None after drain"
    );
}

#[tokio::test]
async fn drain_completes_when_last_guard_drops() {
    use heimdall_runtime::Drain;

    let drain = Drain::new();
    let guard = drain.acquire().expect("acquire");

    let drain2 = drain.clone();
    let handle = tokio::spawn(async move {
        drain2
            .drain_and_wait(Duration::from_millis(500))
            .await
            .expect("drain should succeed");
    });

    // Let the drain task start waiting.
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(guard);

    handle.await.expect("drain task panicked");
    assert!(drain.is_draining());
}

#[tokio::test]
async fn drain_timeout_when_guard_held() {
    use heimdall_runtime::{Drain, DrainError};

    let drain = Drain::new();
    let _guard = drain.acquire().expect("acquire");

    let result = drain.drain_and_wait(Duration::from_millis(20)).await;
    assert_eq!(result, Err(DrainError::Timeout));
}

// ── Runtime boot ──────────────────────────────────────────────────────────────

#[test]
fn build_runtime_two_threads() {
    use heimdall_runtime::{RuntimeFlavour, runtime::build_runtime};

    let (rt, info) = build_runtime(2).expect("build_runtime");
    assert_eq!(info.worker_threads, 2);
    // Without the io-uring feature, always Epoll.
    #[cfg(not(feature = "io-uring"))]
    assert_eq!(info.flavour, RuntimeFlavour::Epoll);
    let _ = info; // suppress warning when feature is active

    // Verify the runtime is functional.
    rt.block_on(async {
        assert_eq!(
            tokio::spawn(async { 42_u32 }).await.expect("spawn failed"),
            42
        );
    });
}
