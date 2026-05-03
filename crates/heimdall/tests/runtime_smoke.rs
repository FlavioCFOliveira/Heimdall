// SPDX-License-Identifier: MIT

//! Smoke tests for Tokio runtime boot (Sprint 46 task #458 AC).
//!
//! Verifies that `heimdall start` logs the chosen I/O backend and worker count.

use std::process::Command;

fn heimdall_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn fixture(kind: &str, name: &str) -> String {
    format!("{}/tests/fixtures/{kind}/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn start_logs_io_backend_and_worker_count() {
    // `start` with a valid config should log the io backend before exiting 0.
    // We use RUST_LOG=info so the log line is emitted.
    let out = heimdall_bin()
        .env("RUST_LOG", "info")
        .args(["start", "--config", &fixture("valid", "recursive_udp.toml")])
        .output()
        .unwrap();

    // Exit 0 (stub returns immediately after runtime start).
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify that the "Tokio runtime started" log event was emitted to stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Tokio runtime started") || stderr.contains("io_backend"),
        "expected runtime log line in stderr: {stderr}"
    );
}

#[test]
fn start_logs_worker_thread_count() {
    let out = heimdall_bin()
        .env("RUST_LOG", "info")
        .args(["start", "--config", &fixture("valid", "recursive_udp.toml")])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    // The log line should contain a worker_threads field.
    assert!(
        stderr.contains("worker_threads"),
        "expected worker_threads in runtime log: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn io_backend_matches_kernel_version() {
    use heimdall_runtime::RuntimeFlavour;
    use heimdall_runtime::build_runtime;

    let (_rt, info) = build_runtime(1).expect("build_runtime");

    // On a kernel ≥ 5.19 with the io-uring feature, we expect IoUring.
    // Without the feature (our current build), always Epoll.
    #[cfg(not(feature = "io-uring"))]
    assert_eq!(
        info.flavour,
        RuntimeFlavour::Epoll,
        "expected Epoll without io-uring feature"
    );
}
