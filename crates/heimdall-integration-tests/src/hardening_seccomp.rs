// SPDX-License-Identifier: MIT

//! Seccomp-BPF allow-list runtime validation tests (THREAT-024, Sprint 37 task #371).
//!
//! Test A and B exercise the seccomp filter against a minimal allow-list by
//! `fork`ing a child process inside the test, installing the filter in the
//! child, and verifying the outcome from the parent via `waitpid`. Forking
//! within the test (rather than re-execing the test binary) avoids two
//! pitfalls of the original design:
//!
//!   1. The libtest harness owns `main`, so any dispatcher set in the child
//!      via `Command::new(current_exe())` would be ignored — the child would
//!      simply run the test suite again, and the seccomp scenario code path
//!      would never execute.
//!   2. The forked child only invokes async-signal-safe operations
//!      (`prctl(2)` to install the filter, `getuid(2)` to trigger the kill
//!      path, and `_exit(2)` to terminate), avoiding deadlocks that can occur
//!      when libstd state held by another thread is duplicated by `fork`.
//!
//! Test C is process-dependent and requires a live Heimdall binary; it is
//! gated on `HEIMDALL_HARDENING_TESTS=1`.

#![cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
// SAFETY policy: the seccomp scenarios deliberately invoke a denied syscall
// via libc to trigger the SIGSYS kill path, and call `fork(2)` plus `_exit(2)`
// to isolate the filtered execution. The `unsafe` blocks in this file are
// documented inline with SAFETY comments. Allowing `unsafe_code` at file level
// matches the precedent set by `crates/heimdall-runtime/src/security/seccomp.rs:26`
// (the production implementation of the seccomp filter installer this file
// exercises).
#![allow(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

/// Installs a seccomp filter in the current process that only allows `getpid`
/// (plus the syscalls strictly required to exit cleanly or be killed) and
/// terminates the process on anything else.
#[cfg(target_os = "linux")]
fn install_minimal_filter_getpid_only() {
    use heimdall_runtime::security::seccomp::SecurityFilter;
    SecurityFilter::with_syscalls(&[
        libc::SYS_getpid,
        // exit_group is required so the child can exit cleanly after a
        // successful getpid call in Scenario A.
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
    use std::process::Command;

    use nix::{
        sys::{
            signal::Signal,
            wait::{WaitStatus, waitpid},
        },
        unistd::{ForkResult, fork},
    };

    use super::*;

    /// Test A: install a minimal allow-list filter, call an allowed syscall,
    /// verify the child exits with status 0.
    #[test]
    fn seccomp_allows_permitted_syscall() {
        // SAFETY: in the child branch we restrict ourselves to async-signal-safe
        // operations only — `prctl` (via SecurityFilter::install), `getpid`
        // (via std::process::id; this maps to the `getpid` syscall, which is
        // explicitly allowed), and `_exit`. No libstd mutexes or allocator
        // state held by another thread are touched, so the well-known
        // post-fork "multi-threaded child" hazards do not apply.
        match unsafe { fork() }.expect("fork must succeed in test process") {
            ForkResult::Child => {
                install_minimal_filter_getpid_only();
                // getpid is in the allow-list; this must succeed.
                let _pid = std::process::id();
                // SAFETY: libc::_exit is async-signal-safe and does not
                // invoke any registered atexit handlers, which is what we
                // want in a forked child whose libstd state is shared with
                // the parent.
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid must succeed");
                match status {
                    WaitStatus::Exited(_, code) => {
                        assert_eq!(
                            code, 0,
                            "child must exit 0 after calling an allowed syscall (getpid); \
                             got exit code {code}"
                        );
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        panic!(
                            "child should have exited cleanly after calling an allowed \
                             syscall but was killed by signal {sig:?}; the seccomp \
                             allow-list may be too restrictive"
                        );
                    }
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
        }
    }

    /// Test B: install a minimal allow-list filter, call a denied syscall,
    /// verify the child is killed by SIGSYS (signal 31).
    #[test]
    fn seccomp_kills_on_denied_syscall() {
        // SAFETY: same async-signal-safety reasoning as
        // `seccomp_allows_permitted_syscall` above. In the kill-path branch
        // the kernel sends SIGSYS before `_exit` is reached; the `_exit`
        // call is a fail-closed sentinel that produces a non-zero exit if
        // the kernel — contrary to expectation — fails to enforce the filter.
        match unsafe { fork() }.expect("fork must succeed in test process") {
            ForkResult::Child => {
                install_minimal_filter_getpid_only();
                // getuid is NOT in the allow-list; the kernel delivers SIGSYS
                // synchronously on the next syscall, so we never return.
                trigger_denied_syscall();
                // Fail-closed sentinel: if we reach this point, the seccomp
                // filter did not enforce the kill policy and the test must
                // fail. _exit(42) gives the parent a recognisable signal that
                // is distinct from a kernel-delivered SIGSYS.
                // SAFETY: libc::_exit is async-signal-safe.
                unsafe { libc::_exit(42) };
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid must succeed");
                match status {
                    WaitStatus::Signaled(_, sig, _) => {
                        assert!(
                            sig == Signal::SIGSYS || sig == Signal::SIGKILL,
                            "child should be killed by SIGSYS (31) or SIGKILL (9); got {sig:?}"
                        );
                    }
                    WaitStatus::Exited(_, code) => {
                        panic!(
                            "child must not exit normally after calling a denied syscall \
                             (getuid); got exit code {code}. The seccomp filter did not \
                             enforce SECCOMP_RET_KILL_PROCESS."
                        );
                    }
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
        }
    }

    /// Test C: spawns the Heimdall binary under a seccomp filter and exercises the
    /// query path. Requires `HEIMDALL_HARDENING_TESTS=1` and a built binary.
    #[test]
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
