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
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! Fail-closed integration tests (Sprint 48 task #561).
//!
//! Verifies three exit-code / diagnostic invariants mandated by BIN-006 and BIN-008:
//!
//! 1. **Bad TOML** — `start` with a syntactically invalid config file exits 2
//!    and emits a structured tracing event with `target=heimdall::config` to
//!    stderr.
//!
//! 2. **Unreachable Redis** — `start` with a valid config pointing at a Redis
//!    server that is not running exits 1 and logs `reason=redis-unreachable`.
//!
//! 3. **Usage error** — passing an unrecognised positional argument to
//!    `check-config` exits 64 (`EX_USAGE` per BIN-006).

use std::{
    io::Write as _,
    process::Stdio,
    time::{Duration, Instant},
};

fn heimdall_bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().unwrap().port()
}

// ── Test 1: bad TOML → exit 2, stderr contains target=heimdall::config ────────

#[test]
fn bad_toml_exits_two_with_config_target() {
    let mut cfg = tempfile::NamedTempFile::new().expect("tempfile");
    cfg.write_all(b"this is not valid toml =[[[")
        .expect("write config");
    cfg.flush().expect("flush");
    let path = cfg.path().to_str().unwrap().to_owned();

    // `start` initialises JSON logging before config load; the error is emitted
    // as a structured JSON event to stderr.
    let out = heimdall_bin()
        .args(["start", "--config", &path])
        .output()
        .expect("spawn heimdall");

    assert_eq!(
        out.status.code(),
        Some(2),
        "bad TOML must exit 2 (EX_CONFIG); stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("heimdall::config"),
        "stderr must contain target=heimdall::config; got: {stderr:?}"
    );
}

// ── Test 2: unreachable Redis → exit 1, stderr contains reason=redis-unreachable

#[test]
fn unreachable_redis_exits_one_with_reason() {
    let dns_port = free_port();
    let obs_port = free_port();
    // Port 1 on loopback: connection refused immediately (no process listens there).
    let config = format!(
        "[roles]\nauthoritative = true\n\n\
         [[listeners]]\naddress = \"127.0.0.1\"\nport = {dns_port}\ntransport = \"udp\"\n\n\
         [observability]\nmetrics_port = {obs_port}\n\n\
         [persistence]\nhost = \"127.0.0.1\"\nport = 1\nusername = \"\"\npassword = \"\"\n\
         pool_acquisition_timeout_ms = 200\n"
    );

    let mut cfg = tempfile::NamedTempFile::new().expect("tempfile");
    cfg.write_all(config.as_bytes()).expect("write config");
    cfg.flush().expect("flush");
    let path = cfg.path().to_str().unwrap().to_owned();

    let stderr_file = cfg.path().with_extension("stderr");
    let stderr_fd = std::fs::File::create(&stderr_file).expect("stderr capture file");

    let mut child = heimdall_bin()
        .args(["start", "--config", &path])
        .stdout(Stdio::null())
        .stderr(stderr_fd)
        .spawn()
        .expect("spawn heimdall");

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let stderr = std::fs::read_to_string(&stderr_file).unwrap_or_default();
            let _ = std::fs::remove_file(&stderr_file);
            assert_eq!(
                status.code(),
                Some(1),
                "unreachable Redis must exit 1 (EX_STARTUP); stderr={stderr:?}"
            );
            assert!(
                stderr.contains("redis-unreachable"),
                "stderr must contain reason=redis-unreachable; got: {stderr:?}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&stderr_file);
            panic!("daemon did not exit within 8 s when Redis is unreachable");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ── Test 3: usage error (unrecognised positional arg) → exit 64 (EX_USAGE) ────

#[test]
fn usage_error_exits_64() {
    // `check-config` accepts no positional arguments; passing one triggers a
    // clap usage error which must exit 64 per BIN-006.
    let out = heimdall_bin()
        .args(["check-config", "/unexpected/positional/arg"])
        .output()
        .expect("spawn heimdall");

    assert_eq!(
        out.status.code(),
        Some(64),
        "clap usage error must exit 64 (EX_USAGE per BIN-006); stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
