// SPDX-License-Identifier: MIT

//! Integration tests for `heimdall check-config` deep validation (Sprint 46 task #556 AC).
//!
//! Runs the binary as a subprocess and asserts exit codes and output.

use std::process::Command;

fn heimdall_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn fixture(kind: &str, name: &str) -> String {
    format!("{}/tests/fixtures/{kind}/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn check_config(config: &str) -> std::process::Output {
    heimdall_bin()
        .args(["check-config", "--config", config])
        .output()
        .expect("failed to run heimdall check-config")
}

fn check_config_json(config: &str) -> std::process::Output {
    heimdall_bin()
        .args(["check-config", "--config", config, "--format", "json"])
        .output()
        .expect("failed to run heimdall check-config --format json")
}

trait OutputExt {
    fn stdout_str(&self) -> String;
    fn stderr_str(&self) -> String;
}

impl OutputExt for std::process::Output {
    fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }
    fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

// ── check 1: TOML parse ──────────────────────────────────────────────────────

#[test]
fn valid_minimal_config_exits_zero() {
    let out = check_config(&fixture("valid", "minimal.toml"));
    assert_eq!(
        out.status.code(),
        Some(0),
        "minimal.toml should exit 0; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
}

#[test]
fn bad_toml_exits_two() {
    let out = check_config(&fixture("invalid", "not_toml.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "bad TOML should exit 2; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
}

#[test]
fn bad_toml_json_format_contains_toml_parse_error() {
    let out = check_config_json(&fixture("invalid", "not_toml.toml"));
    assert_eq!(out.status.code(), Some(2), "bad TOML should exit 2");
    let stdout = out.stdout_str();
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("output must be JSON");
    assert!(!json["ok"].as_bool().unwrap_or(true), "ok must be false");
    let checks = json["checks"].as_array().unwrap();
    let parse_check = checks
        .iter()
        .find(|c| c["name"].as_str() == Some("toml_parse"))
        .expect("must have toml_parse check");
    assert!(!parse_check["ok"].as_bool().unwrap_or(true));
}

// ── check 2: zone files ──────────────────────────────────────────────────────

#[test]
fn missing_zone_file_exits_two() {
    let out = check_config(&fixture("invalid", "bad_zone_path.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing zone file should exit 2; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    let stdout = out.stdout_str();
    assert!(
        stdout.contains("FAIL") || stdout.contains("cannot read"),
        "output should indicate zone check failure; got: {stdout:?}"
    );
}

// ── check 3 + 4: TLS material + bind dry-run ─────────────────────────────────

#[test]
fn bad_tls_cert_exits_two() {
    let out = check_config(&fixture("invalid", "bad_tls_cert.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "bad TLS cert should exit 2; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    let stdout = out.stdout_str();
    assert!(
        stdout.contains("FAIL") || stdout.contains("TLS"),
        "output should indicate TLS check failure; got: {stdout:?}"
    );
}

// ── check 5: port already bound ──────────────────────────────────────────────

#[test]
fn port_already_bound_exits_three() {
    // Bind a socket ourselves to occupy a port, then run check-config against
    // a config that uses the same port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    let config_content = format!(
        "[[listeners]]\naddress = \"127.0.0.1\"\nport = {port}\ntransport = \"tcp\"\n"
    );
    let config_path = std::env::temp_dir().join(format!(
        "heimdall_cc_test_{}.toml",
        std::process::id()
    ));
    std::fs::write(&config_path, &config_content).unwrap();

    let out = check_config(config_path.to_str().unwrap());

    drop(listener); // release before asserting
    let _ = std::fs::remove_file(&config_path);

    assert_eq!(
        out.status.code(),
        Some(3),
        "port in use should exit 3; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
}

// ── check 5: unreachable Redis ───────────────────────────────────────────────

#[test]
fn unreachable_redis_exits_three() {
    let config = "[persistence]\nhost = \"127.0.0.1\"\nport = 1\n";
    let config_path = std::env::temp_dir().join(format!(
        "heimdall_cc_redis_test_{}.toml",
        std::process::id()
    ));
    std::fs::write(&config_path, config).unwrap();

    let out = check_config(config_path.to_str().unwrap());
    let _ = std::fs::remove_file(&config_path);

    assert_eq!(
        out.status.code(),
        Some(3),
        "unreachable Redis should exit 3; stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    let stdout = out.stdout_str();
    let stderr = out.stderr_str();
    assert!(
        stdout.contains("127.0.0.1") || stderr.contains("127.0.0.1") || stdout.contains("redis"),
        "output should mention the Redis address; stdout={stdout:?} stderr={stderr:?}"
    );
}

// ── JSON format: valid config produces ok=true ───────────────────────────────

#[test]
fn valid_config_json_output_ok_true() {
    let out = check_config_json(&fixture("valid", "minimal.toml"));
    assert_eq!(out.status.code(), Some(0), "should exit 0");
    let json: serde_json::Value =
        serde_json::from_str(out.stdout_str().trim()).expect("output must be valid JSON");
    assert!(
        json["ok"].as_bool().unwrap_or(false),
        "ok must be true for valid config; json={json}"
    );
}
