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
        "[roles]\nrecursive = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = {port}\ntransport = \"tcp\"\n"
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
    let config = "[roles]\nrecursive = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 59155\ntransport = \"udp\"\n\n[persistence]\nhost = \"127.0.0.1\"\nport = 1\n";
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
    // Uses minimal_json.toml (port 59154) instead of minimal.toml (port 59153) so
    // this test can run in parallel with valid_minimal_config_exits_zero without a
    // UDP bind conflict.
    let out = check_config_json(&fixture("valid", "minimal_json.toml"));
    assert_eq!(out.status.code(), Some(0), "should exit 0");
    let json: serde_json::Value =
        serde_json::from_str(out.stdout_str().trim()).expect("output must be valid JSON");
    assert!(
        json["ok"].as_bool().unwrap_or(false),
        "ok must be true for valid config; json={json}"
    );
}

// ── ROLE-026: all-roles-disabled rejected at load ────────────────────────────

/// ROLE-026: a config with no [roles] section (all roles absent) must exit 2.
#[test]
fn no_roles_section_exits_two() {
    let out = check_config(&fixture("invalid", "no_roles.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "no-roles config should exit 2 (ROLE-026); stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    // ROLE-026 validation errors are reported via stderr (plain format).
    let output = out.stdout_str() + &out.stderr_str();
    assert!(
        output.contains("FAIL") || output.contains("role") || output.contains("ROLE-026"),
        "output should indicate role validation failure; got: stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
}

/// ROLE-026: a config with all three roles explicitly set to false must exit 2.
#[test]
fn all_roles_false_exits_two() {
    let out = check_config(&fixture("invalid", "all_roles_false.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "all-roles-false config should exit 2 (ROLE-026); stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    let output = out.stdout_str() + &out.stderr_str();
    assert!(
        output.contains("FAIL") || output.contains("role") || output.contains("ROLE-026"),
        "output should indicate role validation failure; got: stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
}

// ── ROLE-021: unknown key rejected ───────────────────────────────────────────

/// ROLE-021: a config containing an unknown top-level key must be rejected with
/// exit code 2 (parse error). The error message must identify the offending key.
#[test]
fn unknown_key_exits_two() {
    let out = check_config(&fixture("invalid", "unknown_key.toml"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown-key config should exit 2 (ROLE-021); stdout={:?} stderr={:?}",
        out.stdout_str(),
        out.stderr_str()
    );
    let output = out.stdout_str() + &out.stderr_str();
    assert!(
        output.contains("completely_unknown_top_level_key")
            || output.contains("unknown field")
            || output.contains("FAIL"),
        "output should identify the offending key; got: {output:?}"
    );
}

/// ROLE-026: inline all-roles-disabled configs (all 8 absent/false combinations)
/// must all be rejected with exit code 2.
#[test]
fn role026_eight_all_disabled_combinations_exit_two() {
    // In TOML, "absent" and "= false" produce the same parsed state.
    // The 8 combinations are the 2^3 cross-product of {absent, false} for each role.
    // We test them all inline.
    let combinations: &[&str] = &[
        // 1. All three absent (no [roles] section).
        "[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 2. auth=false, rec absent, fwd absent.
        "[roles]\nauthoritative=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 3. auth absent, rec=false, fwd absent.
        "[roles]\nrecursive=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 4. auth absent, rec absent, fwd=false.
        "[roles]\nforwarder=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 5. auth=false, rec=false, fwd absent.
        "[roles]\nauthoritative=false\nrecursive=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 6. auth=false, rec absent, fwd=false.
        "[roles]\nauthoritative=false\nforwarder=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 7. auth absent, rec=false, fwd=false.
        "[roles]\nrecursive=false\nforwarder=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
        // 8. auth=false, rec=false, fwd=false (all explicit false).
        "[roles]\nauthoritative=false\nrecursive=false\nforwarder=false\n[[listeners]]\naddress=\"127.0.0.1\"\nport=5353\ntransport=\"udp\"\n",
    ];

    for (i, toml) in combinations.iter().enumerate() {
        let config_path = std::env::temp_dir().join(format!(
            "heimdall_role026_combo{}_{}.toml",
            i,
            std::process::id()
        ));
        std::fs::write(&config_path, toml).unwrap();
        let out = check_config(config_path.to_str().unwrap());
        let _ = std::fs::remove_file(&config_path);

        assert_eq!(
            out.status.code(),
            Some(2),
            "ROLE-026 combination {i} must exit 2; toml={toml:?} stdout={:?} stderr={:?}",
            out.stdout_str(),
            out.stderr_str()
        );
    }
}
