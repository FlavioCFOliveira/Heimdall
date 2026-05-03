// SPDX-License-Identifier: MIT

//! Snapshot tests for config loading — 6 valid + 6 invalid configs.
//!
//! Sprint 46 task #457 acceptance criteria.

use std::process::Command;

fn heimdall_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn check_config(path: &str) -> std::process::Output {
    heimdall_bin()
        .args(["check-config", "--config", path])
        .output()
        .unwrap()
}

fn fixture(kind: &str, name: &str) -> String {
    // Paths are relative to the workspace root during `cargo test`.
    format!(
        "{}/tests/fixtures/{kind}/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

// ── Valid configurations ──────────────────────────────────────────────────────

#[test]
fn valid_minimal() {
    let out = check_config(&fixture("valid", "minimal.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Configuration loaded successfully."), "{stdout}");
}

#[test]
fn valid_recursive_udp() {
    let out = check_config(&fixture("valid", "recursive_udp.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("recursive=true"), "{stdout}");
}

#[test]
fn valid_authoritative_tcp() {
    let out = check_config(&fixture("valid", "authoritative_tcp.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("authoritative=true"), "{stdout}");
}

#[test]
fn valid_forwarder_dot() {
    let out = check_config(&fixture("valid", "forwarder_dot.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("forwarder=true"), "{stdout}");
}

#[test]
fn valid_multi_role_multi_listener() {
    let out = check_config(&fixture("valid", "multi_role_multi_listener.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Listeners (2)"), "{stdout}");
}

#[test]
fn valid_with_observability() {
    let out = check_config(&fixture("valid", "with_observability.toml"));
    assert!(out.status.success(), "expected exit 0: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Metrics port: 9090"), "{stdout}");
}

// ── Invalid configurations ────────────────────────────────────────────────────

#[test]
fn invalid_missing_listener_with_role() {
    let out = check_config(&fixture("invalid", "missing_listener_with_role.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no listeners"),
        "expected helpful message: {stderr}"
    );
}

#[test]
fn invalid_ttl_order() {
    let out = check_config(&fixture("invalid", "ttl_order.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("min_ttl_secs"),
        "expected min_ttl_secs message: {stderr}"
    );
}

#[test]
fn invalid_port_conflict() {
    let out = check_config(&fixture("invalid", "port_conflict.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("conflict") || stderr.contains("admin"),
        "expected port conflict message: {stderr}"
    );
}

#[test]
fn invalid_udp_buffer_too_small() {
    let out = check_config(&fixture("invalid", "udp_buffer_too_small.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("udp_recv_buffer") || stderr.contains("4096"),
        "expected buffer-size message: {stderr}"
    );
}

#[test]
fn invalid_bad_transport() {
    let out = check_config(&fixture("invalid", "bad_transport.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("parse error") || stderr.contains("transport"),
        "expected parse error: {stderr}"
    );
}

#[test]
fn invalid_not_toml() {
    let out = check_config(&fixture("invalid", "not_toml.toml"));
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("parse error") || stderr.contains("error"),
        "expected parse error: {stderr}"
    );
}

// ── Example file ─────────────────────────────────────────────────────────────

#[test]
fn example_config_exits_0() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let example = format!("{manifest_dir}/../../contrib/heimdall.toml.example");
    let out = check_config(&example);
    assert!(
        out.status.success(),
        "expected exit 0 for contrib/heimdall.toml.example, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
