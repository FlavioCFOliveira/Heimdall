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

//! Admin-RPC UDS boot tests (Sprint 46 task #553 AC).
//!
//! Spawns `heimdall start` with an `[admin] uds_path` config, waits for the
//! server to be ready, connects via `AdminRpcClient`, sends `version`, and
//! verifies the response. Also verifies that daemon startup without a
//! `[admin]` section does not create any UDS.
//!
//! Unix-only (`#[cfg(unix)]`).
#![allow(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::{
        os::unix::process::CommandExt as _, path::PathBuf, process::Command, time::Duration,
    };

    fn heimdall_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(kind: &str, name: &str) -> String {
        format!(
            "{}/tests/fixtures/{kind}/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    fn spawn_daemon(config: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config])
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        cmd.spawn().expect("failed to spawn heimdall")
    }

    fn wait_for_ready() {
        std::thread::sleep(Duration::from_secs(2));
    }

    /// Verifies that `heimdall start` with `[admin] uds_path` binds the socket
    /// and responds to a `version` RPC with the package version.
    #[test]
    fn admin_rpc_version_responds_with_package_version() {
        let socket_path = {
            let mut p = std::env::temp_dir();
            p.push(format!("heimdall_test_admin_{}.sock", std::process::id()));
            p
        };

        // Write a temporary config referencing the socket.
        // ROLE-026 requires at least one active role; use authoritative on a
        // test port that won't conflict with other integration tests.
        // Use a dedicated observability port (9091) so this test can run in
        // parallel with no_admin_config_does_not_create_socket (which uses
        // minimal.toml with the default observability port 9090).
        let config_content = format!(
            "[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 59158\ntransport = \"udp\"\n\n[observability]\nmetrics_port = 9091\n\n[admin]\nuds_path = {:?}\n",
            socket_path.to_str().unwrap()
        );
        let config_path: PathBuf = {
            let mut p = std::env::temp_dir();
            p.push(format!("heimdall_test_admin_{}.toml", std::process::id()));
            p
        };
        std::fs::write(&config_path, &config_content).expect("failed to write temp config");

        let mut child = spawn_daemon(config_path.to_str().unwrap());

        wait_for_ready();

        // Connect and send `version`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let response = rt.block_on(async {
            let client = heimdall_runtime::AdminRpcClient::new(&socket_path);
            client.version().await
        });

        // Tear down daemon before asserting.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&config_path);

        let resp = response.expect("admin-RPC version call failed");
        assert!(resp.ok, "expected ok=true, got: {resp:?}");

        let version = resp
            .data
            .as_ref()
            .and_then(|d| d.get("version"))
            .and_then(|v| v.as_str())
            .expect("missing version in response data");
        assert_eq!(
            version,
            env!("CARGO_PKG_VERSION"),
            "version mismatch: expected {}, got {version}",
            env!("CARGO_PKG_VERSION")
        );
    }

    /// Verifies that a daemon started without `[admin]` does not create a UDS.
    #[test]
    fn no_admin_config_does_not_create_socket() {
        let socket_path = {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "heimdall_test_no_admin_{}.sock",
                std::process::id()
            ));
            p
        };

        let config = fixture("valid", "minimal.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        let exists = socket_path.exists();

        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();

        assert!(!exists, "unexpected UDS at {socket_path:?}");
    }
}

#[cfg(unix)]
extern crate libc;
