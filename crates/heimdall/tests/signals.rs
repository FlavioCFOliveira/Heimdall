// SPDX-License-Identifier: MIT

//! Unix signal handling tests (Sprint 46 task #459 AC).
//!
//! Spawns heimdall as a subprocess in its own process group (to avoid inheriting
//! the test runner's signal disposition), sends signals, and verifies behaviour.
//! Unix-only (`#[cfg(unix)]`).
//!
//! `libc::kill` and `CommandExt::process_group` require unsafe / platform APIs;
//! these are the only practical alternatives for POSIX signal delivery in tests.
#![allow(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn heimdall_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(kind: &str, name: &str) -> String {
        format!("{}/tests/fixtures/{kind}/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Spawn `heimdall start` in its own process group so that it does not
    /// inherit the test runner's signal dispositions (e.g. SIG_IGN on SIGINT).
    fn spawn_daemon(config: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config])
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // Place the daemon in its own process group so it doesn't inherit
        // the test runner's SIGINT disposition.
        unsafe {
            cmd.pre_exec(|| {
                // setpgid(0, 0) creates a new process group for this process.
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        cmd.spawn().expect("failed to spawn heimdall")
    }

    /// Wait for the daemon to be ready (signal handlers installed).
    fn wait_for_ready() {
        std::thread::sleep(Duration::from_millis(600));
    }

    #[test]
    fn sigterm_exits_zero_within_drain_timeout() {
        let config = fixture("valid", "minimal.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        // Send SIGTERM.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }

        let start = Instant::now();
        let status = child.wait().expect("wait failed");

        // Must exit within 5 seconds (well under the 30-second drain timeout).
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 seconds after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }

    #[test]
    fn sigint_exits_zero_within_drain_timeout() {
        let config = fixture("valid", "minimal.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        // Send SIGINT — the daemon runs in its own process group so this only
        // affects the daemon, not the test runner.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGINT);
        }

        let start = Instant::now();
        let status = child.wait().expect("wait failed");

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 seconds after SIGINT"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGINT, got {status:?}"
        );
    }

    #[test]
    fn double_sigterm_forces_fast_shutdown() {
        let config = fixture("valid", "minimal.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        // Send SIGTERM twice: first triggers drain, second triggers fast-shutdown.
        let pid = child.id() as libc::pid_t;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        // Give the daemon a moment to enter the drain select!.
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }

        let start = Instant::now();
        let status = child.wait().expect("wait failed");

        // Fast shutdown must complete within 3 seconds.
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "expected fast shutdown within 3 seconds after double SIGTERM, elapsed: {:?}",
            start.elapsed()
        );
        assert!(
            status.success(),
            "expected exit 0 after double SIGTERM, got {status:?}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
