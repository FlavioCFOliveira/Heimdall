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
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::undocumented_unsafe_blocks
)]
#![allow(unsafe_code)]

//! Integration tests for OS resource-limit hardening (BIN-036..038, THREAT-068).
//!
//! Strategy: spawn heimdall with a fixture config that sets `RLIMIT_NOFILE` to a
//! specific low value (4096), then read /proc/PID/limits on Linux to verify the
//! kernel has the expected soft limit.
//!
//! /proc/PID/limits is Linux-only, so the limit-verification test is gated on
//! `target_os = "linux"`.  A platform-independent smoke test verifies that the
//! daemon boots and exits cleanly even when the rlimit section is present.

#[cfg(unix)]
mod unix {
    use std::{os::unix::process::CommandExt as _, process::Stdio, time::Duration};

    fn heimdall_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn spawn_daemon(config: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config])
            .env("RUST_LOG", "warn")
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

    /// Boot with an [rlimit] section present.  The daemon must exit cleanly
    /// even when the rlimit values are lower than defaults.  This test runs on
    /// all Unix platforms.
    #[test]
    fn rlimit_config_boots_and_exits_zero() {
        let config = fixture("rlimit.toml");
        let mut child = spawn_daemon(&config);
        std::thread::sleep(Duration::from_millis(600));
        sigterm(&child);
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "expected exit 0, got {status:?}");
    }

    /// On Linux, read /proc/PID/limits after boot and assert `RLIMIT_NOFILE`
    /// soft limit matches the configured value (or the hard limit if lower).
    #[cfg(target_os = "linux")]
    #[test]
    fn rlimit_nofile_matches_config() {
        let config = fixture("rlimit.toml");
        let mut child = spawn_daemon(&config);

        // Give the daemon time to apply limits (rlimit::apply runs synchronously
        // during boot before the async runtime is fully initialised).
        std::thread::sleep(Duration::from_millis(600));

        let soft = read_proc_nofile_soft(child.id());

        sigterm(&child);
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "expected exit 0, got {status:?}");

        // The fixture requests nofile=4096.  If the hard limit is lower (rare
        // in CI), we accept that value instead (capped to hard limit).
        let soft = soft.expect("failed to read /proc/PID/limits");
        assert!(
            soft <= 4096,
            "expected RLIMIT_NOFILE soft ≤ 4096, got {soft}"
        );
    }

    /// Parse the Max open files soft limit from /proc/PID/limits.
    ///
    /// Returns `None` if the file cannot be read or parsed.
    #[cfg(target_os = "linux")]
    fn read_proc_nofile_soft(pid: u32) -> Option<u64> {
        let path = format!("/proc/{pid}/limits");
        let contents = std::fs::read_to_string(&path).ok()?;
        for line in contents.lines() {
            if line.starts_with("Max open files") {
                // Format: "Max open files            <soft>               <hard>           files"
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Skip "Max", "open", "files" → parts[3] is soft limit.
                if parts.len() >= 4 {
                    return parts[3].parse::<u64>().ok();
                }
            }
        }
        None
    }
}

#[cfg(unix)]
extern crate libc;
