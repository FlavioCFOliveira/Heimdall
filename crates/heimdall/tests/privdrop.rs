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

//! Privilege-drop integration tests (Sprint 46 task #462 AC).
//!
//! Non-root path: verifies that heimdall starts cleanly when not running as root
//! and exits with code 0 on SIGTERM (`privdrop::apply` is a no-op / warning-only).
//!
//! The privileged-port warning path (port < 1024 when non-root) is only reachable
//! after a successful bind, which requires root or OS capabilities on most systems.
//! That path is verified by code inspection; this test covers the observable
//! subprocess behaviour.

#[cfg(unix)]
mod unix {
    use std::{os::unix::process::CommandExt as _, process::Stdio, time::Duration};

    fn heimdall_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Non-root: daemon starts cleanly with no privileged listeners and exits 0
    /// on SIGTERM, demonstrating that `privdrop::apply` is a safe no-op.
    #[test]
    fn non_root_privdrop_noop_clean_exit() {
        // minimal.toml — no listeners, no roles. privdrop::apply has nothing to
        // warn about and returns Ok(()) immediately.
        let config = fixture("minimal.toml");

        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", &config])
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let mut child = cmd.spawn().expect("failed to spawn heimdall");

        // Wait for the Tokio runtime and signal handlers to be ready.
        std::thread::sleep(Duration::from_millis(600));

        // Send SIGTERM directly to the daemon's PID (not the process group).
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }

        let status = child.wait().expect("wait failed");
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
