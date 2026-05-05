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
#![allow(unsafe_code)]

//! Graceful Redis pool drain on shutdown tests (Sprint 46 task #569 AC).
//!
//! Requires Docker (via testcontainers). If the Docker socket is unavailable
//! the test prints SKIP and returns without failing.
//!
//! Test: start Heimdall with a live Redis; send SIGTERM; verify:
//! - Process exits 0
//! - `StoreDrainStats` (accessed via the library API, not subprocess) shows
//!   `commands_force_cancelled` = 0

use std::{io::Write as _, os::unix::process::CommandExt as _, process::Stdio, time::Duration};

fn heimdall_bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn spawn_daemon(toml: &str) -> (std::process::Child, tempfile::NamedTempFile) {
    let mut cfg_file = tempfile::NamedTempFile::new().expect("tempfile");
    cfg_file.write_all(toml.as_bytes()).expect("write config");
    cfg_file.flush().expect("flush");

    let path = cfg_file.path().to_str().unwrap().to_owned();
    let mut cmd = heimdall_bin();
    cmd.args(["start", "--config", &path])
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn heimdall");
    (child, cfg_file)
}

fn sigterm(child: &std::process::Child) {
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

/// Verifies that `heimdall start` with a live Redis exits 0 on SIGTERM,
/// demonstrating graceful Redis pool drain with no force-cancelled commands.
#[test]
fn graceful_drain_exits_zero_with_live_redis() {
    use testcontainers::{GenericImage, core::WaitFor, runners::SyncRunner};

    let redis = match GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: could not start Redis container: {e}");
            return;
        }
    };

    let port: u16 = redis.get_host_port_ipv4(6379u16).expect("Redis host port");

    let config = format!(
        r#"
[persistence]
host = "127.0.0.1"
port = {port}
username = ""
password = ""
"#
    );

    let (mut child, _cfg) = spawn_daemon(&config);

    // Wait for the server to be fully up.
    std::thread::sleep(Duration::from_millis(1500));

    if let Some(status) = child.try_wait().expect("try_wait") {
        panic!("daemon exited prematurely with {status:?}");
    }

    // Send SIGTERM to initiate graceful shutdown.
    sigterm(&child);

    let start = std::time::Instant::now();
    let status = child.wait().expect("wait");

    assert!(
        start.elapsed() < Duration::from_secs(10),
        "expected shutdown within 10 seconds, took {:?}",
        start.elapsed()
    );
    assert!(status.success(), "expected exit 0, got {status:?}");
}

/// Verifies the `StoreDrainStats` API directly (unit-level): initiating drain on
/// an idle pool produces `commands_in_flight_at_drain=0` and
/// `commands_force_cancelled=0`.
#[test]
fn redis_store_drain_stats_idle_pool() {
    use testcontainers::{GenericImage, core::WaitFor, runners::SyncRunner};

    let redis = match GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: could not start Redis container: {e}");
            return;
        }
    };

    let port: u16 = redis.get_host_port_ipv4(6379u16).expect("Redis host port");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let stats = rt.block_on(async {
        let config = heimdall_runtime::RedisConfig {
            topology: heimdall_runtime::RedisTopology::Tcp {
                host: "127.0.0.1".into(),
                port,
                tls: false,
            },
            auth: heimdall_runtime::RedisAuth {
                username: String::new(),
                password: String::new(),
            },
            pool_max_size: 2,
            pool_min_size: 1,
            pool_acquisition_timeout_ms: 1_000,
            hscan_count: 1,
        };

        let store = heimdall_runtime::RedisStore::connect(config).expect("RedisStore::connect");

        // PING to confirm liveness.
        let mut conn = store.connection().await.expect("connection");
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .expect("PING");
        drop(conn); // return connection before draining

        store.drain(std::time::Duration::from_secs(5)).await
    });

    assert_eq!(
        stats.commands_in_flight_at_drain, 0,
        "idle pool should have 0 in-flight at drain"
    );
    assert_eq!(
        stats.commands_force_cancelled, 0,
        "idle pool should have 0 force-cancelled"
    );
}

extern crate libc;
