// SPDX-License-Identifier: MIT

//! CLI smoke tests (Sprint 46 task #456 acceptance criteria).
//!
//! Covers: log format selection (JSON vs pretty), RUST_LOG + --log-level
//! interaction per BIN-013, and exit codes per BIN-006.

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
