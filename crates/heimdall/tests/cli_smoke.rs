// SPDX-License-Identifier: MIT

//! CLI smoke tests (Sprint 46 task #456 + Sprint 47 task #579 acceptance criteria).
//!
//! Covers: log format selection (JSON vs pretty), RUST_LOG + --log-level
//! interaction per BIN-013, exit codes per BIN-006, and `version` subcommand
//! contract per BIN-004.

use std::process::Command;

fn heimdall_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

#[test]
fn version_exits_0() {
    let status = heimdall_bin().arg("--version").status().unwrap();
    assert!(status.success());
}

#[test]
fn help_exits_0() {
    let status = heimdall_bin().arg("--help").status().unwrap();
    assert!(status.success());
}

#[test]
fn start_help_exits_0() {
    let status = heimdall_bin().args(["start", "--help"]).status().unwrap();
    assert!(status.success());
}

#[test]
fn check_config_help_exits_0() {
    let status = heimdall_bin()
        .args(["check-config", "--help"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn start_defaults_to_json_log_format() {
    // When --log-format is not specified, default is json (BIN-002).
    let output = heimdall_bin()
        .args(["start", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("json"),
        "expected 'json' in --log-format help: {stdout}"
    );
}

#[test]
fn rust_log_env_var_accepted() {
    // RUST_LOG is accepted and does not cause a non-zero exit on --help (BIN-013).
    let status = heimdall_bin()
        .env("RUST_LOG", "debug")
        .args(["start", "--help"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn heimdall_config_env_var_reflected_in_help() {
    // HEIMDALL_CONFIG shows in start --help env output (BIN-012).
    let output = heimdall_bin()
        .env("HEIMDALL_CONFIG", "/tmp/test.toml")
        .args(["start", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HEIMDALL_CONFIG"),
        "expected HEIMDALL_CONFIG mention in help: {stdout}"
    );
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    let status = heimdall_bin()
        .arg("unknown-subcommand")
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "expected non-zero exit for unknown subcommand"
    );
}

// ── version subcommand (BIN-004) ─────────────────────────────────────────────

#[test]
fn version_subcommand_exits_zero() {
    let out = heimdall_bin().arg("version").output().unwrap();
    assert!(
        out.status.success(),
        "heimdall version should exit 0; stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_subcommand_outputs_to_stdout() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "heimdall version must write to stdout"
    );
    // Verify nothing leaks to stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.trim().is_empty(),
        "heimdall version must not write to stderr; got: {stderr:?}"
    );
}

#[test]
fn version_subcommand_contains_semver() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Expect at least one dot-separated numeric version token (e.g. "1.1.0").
    let has_semver = stdout
        .split_whitespace()
        .any(|tok| tok.split('.').count() >= 2 && tok.split('.').all(|p| {
            p.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
        }));
    assert!(
        has_semver,
        "heimdall version output must contain a semantic version; got: {stdout:?}"
    );
}

#[test]
fn version_subcommand_contains_build_date() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // RFC 3339 timestamps contain 'T' and either 'Z' or '+'.
    let has_date = stdout.contains('T') && (stdout.contains('Z') || stdout.contains('+'));
    assert!(
        has_date,
        "heimdall version output must contain an RFC 3339 build date; got: {stdout:?}"
    );
}

#[test]
fn version_subcommand_contains_features() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The output is JSON (BIN-005, Sprint 52 task #522): the field must be
    // present as a JSON key.
    assert!(
        stdout.contains("\"features\""),
        "heimdall version output must contain a `features` field; got: {stdout:?}"
    );
}

#[test]
fn version_subcommand_emits_valid_json() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Must be parseable as JSON with at least the canonical `version` field.
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("heimdall version output must be valid JSON");
    assert!(
        json.get("version").and_then(|v| v.as_str()).is_some(),
        "heimdall version JSON must contain a `version` string field; got: {stdout:?}"
    );
}

#[test]
fn version_subcommand_no_panic_output() {
    let out = heimdall_bin().arg("version").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panic") && !stderr.contains("SIGSEGV"),
        "heimdall version must not panic; stderr={stderr:?}"
    );
}
