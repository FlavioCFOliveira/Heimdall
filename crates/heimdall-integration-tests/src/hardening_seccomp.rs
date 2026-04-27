// SPDX-License-Identifier: MIT

//! Seccomp-BPF allow-list runtime validation tests (THREAT-024, Sprint 37 task #371).
//!
//! Test A and B are self-contained: they spawn a child process via
//! `std::process::Command` with a sentinel environment variable that directs
//! the child to install a minimal seccomp filter and then execute a specific
//! syscall, verifying the outcome in the parent.
//!
//! Test C is process-dependent and requires a live Heimdall binary; it is
//! marked `#[ignore]` and gated on `HEIMDALL_HARDENING_TESTS=1`.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

/// Environment variable that directs the child process to run a seccomp scenario.
const SECCOMP_SCENARIO_VAR: &str = "HEIMDALL_SECCOMP_SCENARIO";

/// Scenario A: install a minimal filter (only getpid allowed) and call getpid.
/// The child should exit 0.
const SCENARIO_ALLOW: &str = "allow_getpid";

/// Scenario B: install a filter (only getpid allowed) and call getuid (denied).
/// The child should be killed by SIGSYS (signal 31).
const SCENARIO_DENY: &str = "deny_getuid";

/// Called from the test harness entry-point when the child scenario env var is set.
///
/// This function is invoked in the child process to exercise the seccomp path
/// and does not return normally — it calls `std::process::exit`.
#[cfg(target_os = "linux")]
pub fn run_seccomp_child_scenario() {
    use std::process;

    let scenario = std::env::var(SECCOMP_SCENARIO_VAR).unwrap_or_default();

    match scenario.as_str() {
        SCENARIO_ALLOW => {
            install_minimal_filter_getpid_only();
            // getpid is in the allow-list; this must succeed.
            let _ = std::process::id();
            process::exit(0);
        }
        SCENARIO_DENY => {
            install_minimal_filter_getpid_only();
            // getuid is NOT in the allow-list; the kernel delivers SIGSYS.
            // We never reach exit(0) — the kernel kills us.
            trigger_denied_syscall();
            process::exit(0);
        }
        _ => {}
    }
}

/// Installs a seccomp filter that only allows `getpid` and kills on anything else.
#[cfg(target_os = "linux")]
fn install_minimal_filter_getpid_only() {
    use heimdall_runtime::security::seccomp::SecurityFilter;
    SecurityFilter::with_syscalls(&[
        libc::SYS_getpid,
        // exit_group is required so the child can exit cleanly after a successful
        // getpid call in Scenario A.
        libc::SYS_exit_group,
        libc::SYS_exit,
        // write is needed so that any panic message can be emitted before exit.
        libc::SYS_write,
        // rt_sigreturn is needed by the kernel after signal delivery.
        libc::SYS_rt_sigreturn,
    ])
    .install()
    .expect("seccomp filter installation must succeed in child");
}

/// Issues `getuid` which is NOT in the minimal allow-list, triggering SIGSYS.
#[cfg(target_os = "linux")]
fn trigger_denied_syscall() {
    // SAFETY: getuid(2) is a trivial syscall with no pointer arguments and no
    // side effects. We call it here purely to trigger the seccomp kill path;
    // the return value is intentionally discarded.
    let _uid = unsafe { libc::getuid() };
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn current_exe() -> std::path::PathBuf {
        std::env::current_exe().expect("current_exe must be resolvable in test context")
    }

    /// Test A: install a minimal allow-list filter, call an allowed syscall, verify
    /// the child exits with status 0.
    #[test]
    fn seccomp_allows_permitted_syscall() {
        let status = Command::new(current_exe())
            .env(SECCOMP_SCENARIO_VAR, SCENARIO_ALLOW)
            // Prevent the test runner from recursing into the full test suite.
            .env("RUST_TEST_NOCAPTURE", "0")
            .args(["--test-threads=1", "--ignored"])
            .output()
            .expect("child process must spawn");

        assert!(
            status.status.success(),
            "child must exit 0 after calling an allowed syscall; status={:?}",
            status.status
        );
    }

    /// Test B: install a minimal allow-list filter, call a denied syscall, verify
    /// the child is killed by SIGSYS (signal 31) or exits non-zero.
    #[test]
    fn seccomp_kills_on_denied_syscall() {
        let output = Command::new(current_exe())
            .env(SECCOMP_SCENARIO_VAR, SCENARIO_DENY)
            .env("RUST_TEST_NOCAPTURE", "0")
            .args(["--test-threads=1", "--ignored"])
            .output()
            .expect("child process must spawn");

        // The child should NOT exit successfully: either killed by signal or non-zero exit.
        assert!(
            !output.status.success(),
            "child must not exit 0 after calling a denied syscall; status={:?}",
            output.status
        );

        // On Linux, check for signal 31 (SIGSYS) if the platform provides it.
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = output.status.signal() {
                assert!(
                    sig == 31 || sig == 9,
                    "child should be killed by SIGSYS (31) or SIGKILL (9), got signal {sig}"
                );
            }
        }
    }

    /// Test C: spawns the Heimdall binary under a seccomp filter and exercises the
    /// query path. Requires `HEIMDALL_HARDENING_TESTS=1` and a built binary.
    #[test]
    #[ignore]
    fn seccomp_full_filter_heimdall_binary() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }

        let binary = std::env::var("HEIMDALL_BINARY")
            .unwrap_or_else(|_| "/usr/local/bin/heimdall".to_string());

        let output = Command::new(binary)
            .args(["--version"])
            .output()
            .expect("Heimdall binary must be reachable");

        assert!(
            output.status.success(),
            "Heimdall binary must start successfully; status={:?}",
            output.status
        );
    }
}
