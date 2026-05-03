// SPDX-License-Identifier: MIT
#![allow(unsafe_code)]

//! Integration tests for Redis pool bootstrap at boot (BIN-050, STORE-005..016).
//!
//! Scenarios:
//!
//! 1. `unreachable_redis_exits_one` — configures a TCP address that is not
//!    listening (127.0.0.1 port 1).  Heimdall must exit with code 1 within 4 s.
//!
//! 2. `valid_redis_boot_exits_zero` — spins up Redis 7-alpine via testcontainers,
//!    configures Heimdall against it, verifies the daemon stays alive after 1.5 s
//!    (Redis probe succeeded), then terminates it cleanly and asserts exit 0.
//!
//! 3. `stale_namespace_exits_one` — spins up Redis, writes an incompatible schema
//!    marker (`heimdall:schema_version = "99"`), then verifies Heimdall exits 1.
//!
//! Tests 2 and 3 require Docker.  If the container fails to start, the test
//! prints a SKIP notice and returns without failing.

use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::process::Stdio;
use std::time::{Duration, Instant};

fn heimdall_bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
}

fn spawn_with_config(toml: &str) -> (std::process::Child, tempfile::NamedTempFile) {
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

// ── Test 1: unreachable Redis ─────────────────────────────────────────────────

#[test]
fn unreachable_redis_exits_one() {
    // Port 1 on loopback: connection always refused immediately.
    let config = r#"
[persistence]
host = "127.0.0.1"
port = 1
username = ""
password = ""
pool_acquisition_timeout_ms = 200
"#;
    let (mut child, _cfg) = spawn_with_config(config);

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert_eq!(status.code(), Some(1), "expected exit 1, got {status:?}");
            return;
        }
        if Instant::now() >= deadline {
            sigterm(&child);
            let _ = child.wait();
            panic!("daemon did not exit within 4 s when Redis is unreachable");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ── Tests 2 & 3: require Docker ───────────────────────────────────────────────

#[test]
fn valid_redis_boot_exits_zero() {
    use testcontainers::{core::WaitFor, runners::SyncRunner, GenericImage};

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

    let port: u16 = redis
        .get_host_port_ipv4(6379u16)
        .expect("Redis host port");

    let config = format!(
        r#"
[persistence]
host = "127.0.0.1"
port = {port}
username = ""
password = ""
"#
    );

    let (mut child, _cfg) = spawn_with_config(&config);

    // 1.5 s — enough for pool creation + PING + schema write to complete.
    std::thread::sleep(Duration::from_millis(1500));

    if let Some(status) = child.try_wait().expect("try_wait") {
        panic!("daemon exited prematurely with {status:?} — Redis probe failed");
    }

    sigterm(&child);
    let status = child.wait().expect("wait");
    assert!(status.success(), "expected exit 0, got {status:?}");
}

#[test]
fn stale_namespace_exits_one() {
    use testcontainers::{core::WaitFor, runners::SyncRunner, GenericImage};

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

    let port: u16 = redis
        .get_host_port_ipv4(6379u16)
        .expect("Redis host port");

    // Seed an incompatible schema marker before starting Heimdall.
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let client = redis_crate::Client::open(format!("redis://127.0.0.1:{port}/"))
                .expect("redis client");
            let mut conn = client
                .get_async_connection()
                .await
                .expect("redis connection");
            redis_crate::cmd("SET")
                .arg("heimdall:schema_version")
                .arg("99")
                .query_async::<()>(&mut conn)
                .await
                .expect("SET schema version");
        });
    }

    let config = format!(
        r#"
[persistence]
host = "127.0.0.1"
port = {port}
username = ""
password = ""
pool_acquisition_timeout_ms = 500
"#
    );

    let (mut child, _cfg) = spawn_with_config(&config);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert_eq!(status.code(), Some(1), "expected exit 1, got {status:?}");
            return;
        }
        if Instant::now() >= deadline {
            sigterm(&child);
            let _ = child.wait();
            panic!("daemon did not exit within 5 s with stale namespace");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

extern crate libc;
extern crate redis as redis_crate;
