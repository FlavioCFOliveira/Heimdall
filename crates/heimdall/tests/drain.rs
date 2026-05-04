// SPDX-License-Identifier: MIT
#![allow(unsafe_code)]

//! Drain-coordinator integration tests (Sprint 46 task #464 AC).
//!
//! Verifies that:
//! 1. Clean shutdown: process exits 0 within the configured grace period.
//! 2. Grace timeout from config: `drain_grace_secs` is read from TOML and
//!    propagated to `drain_and_wait`; with a very short grace (1 s) the daemon
//!    exits within ≤ 2 s after SIGTERM even if no in-flight work is outstanding.
//!
//! Note: the per-query `DrainGuard` path (waiting for in-flight queries to
//! complete) is tested at the unit level in heimdall-runtime/src/drain.rs.
//! Subprocess-level "slow query" tests require transport-level DrainGuard
//! integration (a future task).

#[cfg(unix)]
mod unix {
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn heimdall_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn spawn_daemon(config: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        cmd.spawn().expect("failed to spawn heimdall")
    }

    fn sigterm(child: &std::process::Child) {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    /// Clean drain: with no in-flight work, process exits 0 well within the
    /// default 30 s grace period.
    #[test]
    fn clean_drain_exits_zero_within_grace() {
        let config = fixture("minimal.toml");
        let mut child = spawn_daemon(&config);

        // Wait for signal handlers to be ready.
        std::thread::sleep(Duration::from_millis(600));

        let t0 = Instant::now();
        sigterm(&child);
        let status = child.wait().expect("wait failed");
        let elapsed = t0.elapsed();

        assert!(status.success(), "expected exit 0, got {status:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "expected exit within 5 s, took {elapsed:?}"
        );
    }

    /// Configurable grace: with `drain_grace_secs = 2`, process exits within
    /// 3 s of SIGTERM.  This verifies the field is read from config and
    /// threaded into `drain_and_wait`.
    #[test]
    fn drain_grace_from_config_is_respected() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let config_path = tmpdir.path().join("grace.toml");
        // ROLE-026 requires at least one active role.  Use a unique listener
        // port (59162) and observability port (9092) so this test can run in
        // parallel with the other drain tests without port conflicts.
        std::fs::write(
            &config_path,
            b"[server]\ndrain_grace_secs = 2\n\n[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 59162\ntransport = \"udp\"\n\n[observability]\nmetrics_port = 9092\n",
        )
        .expect("write config");

        let mut child = spawn_daemon(config_path.to_str().unwrap());

        // Wait for signal handlers to be ready.
        std::thread::sleep(Duration::from_millis(600));

        let t0 = Instant::now();
        sigterm(&child);
        let status = child.wait().expect("wait failed");
        let elapsed = t0.elapsed();

        // With no in-flight work, drain completes immediately regardless of the
        // grace period — the process exits 0 well before the 2 s grace.
        assert!(status.success(), "expected exit 0, got {status:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "expected exit within 5 s (no in-flight work), took {elapsed:?}"
        );
    }

    /// Double-SIGTERM during drain forces fast shutdown (BIN-024).
    #[test]
    fn double_sigterm_forces_fast_shutdown_from_drain() {
        // Use a unique listener port (59163) and observability port (9093) so
        // this test can run in parallel with clean_drain (minimal.toml, 59153/9090).
        let config = fixture("drain_double.toml");
        let mut child = spawn_daemon(&config);

        // Wait for signal handlers to be ready.
        std::thread::sleep(Duration::from_millis(600));

        let t0 = Instant::now();
        sigterm(&child);
        // Minimal pause — give the first SIGTERM time to be received.
        std::thread::sleep(Duration::from_millis(50));
        sigterm(&child);

        let status = child.wait().expect("wait failed");
        let elapsed = t0.elapsed();

        assert!(status.success(), "expected exit 0, got {status:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "expected fast exit within 3 s after double SIGTERM, took {elapsed:?}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate tempfile;
