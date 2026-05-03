// SPDX-License-Identifier: MIT

//! Listener binding integration tests (Sprint 46 task #461 AC).
//!
//! Spawns heimdall as a subprocess with each transport configuration and
//! verifies that the listening socket is reachable, then sends SIGTERM and
//! verifies clean exit.
//!
//! Tests use distinct port numbers so they can run in parallel without
//! conflicting with each other.
//!
//! Unix-only (process group isolation requires POSIX APIs).
#![allow(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::net::{TcpStream, UdpSocket};
    use std::os::unix::process::CommandExt as _;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn heimdall_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
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
        // Allow time for the tokio runtime to start and listeners to bind.
        std::thread::sleep(Duration::from_millis(600));
    }

    fn sigterm(child: &std::process::Child) {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    /// Verify a UDP listener is bound by attempting to occupy the same port,
    /// which must fail with "address already in use".
    fn udp_port_is_bound(port: u16) -> bool {
        UdpSocket::bind(("127.0.0.1", port)).is_err()
    }

    /// Verify a TCP listener is bound by connecting to it.
    fn tcp_port_is_bound(port: u16) -> bool {
        TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        )
        .is_ok()
    }

    fn wait_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
        child.wait().expect("wait failed")
    }

    fn write_tls_fixtures(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
        let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let cert = params.self_signed(&key).expect("sign");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
        (cert_path, key_path)
    }

    // ── UDP ──────────────────────────────────────────────────────────────────────

    #[test]
    fn udp_listener_bound_and_sigterm_exits_zero() {
        let config = fixture("listener_udp.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        assert!(
            udp_port_is_bound(59153),
            "expected UDP port 59153 to be in use after daemon start"
        );

        sigterm(&child);

        let start = Instant::now();
        let status = wait_exit(&mut child);

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 s after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }

    // ── TCP ──────────────────────────────────────────────────────────────────────

    #[test]
    fn tcp_listener_bound_and_sigterm_exits_zero() {
        let config = fixture("listener_tcp.toml");
        let mut child = spawn_daemon(&config);

        wait_for_ready();

        assert!(
            tcp_port_is_bound(59154),
            "expected TCP port 59154 to accept connections after daemon start"
        );

        sigterm(&child);

        let start = Instant::now();
        let status = wait_exit(&mut child);

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 s after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }

    // ── DoT ──────────────────────────────────────────────────────────────────────

    #[test]
    fn dot_listener_bound_and_sigterm_exits_zero() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_tls_fixtures(tmpdir.path());

        let config_path = tmpdir.path().join("dot.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[roles]
forwarder = true

[[listeners]]
address = "127.0.0.1"
port = 59155
transport = "dot"
tls_cert = "{}"
tls_key = "{}"
"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .expect("write config");

        let mut child = spawn_daemon(config_path.to_str().unwrap());

        wait_for_ready();

        assert!(
            tcp_port_is_bound(59155),
            "expected DoT port 59155 to accept connections after daemon start"
        );

        sigterm(&child);

        let start = Instant::now();
        let status = wait_exit(&mut child);

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 s after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }

    // ── DoH/H2 ───────────────────────────────────────────────────────────────────

    #[test]
    fn doh2_listener_bound_and_sigterm_exits_zero() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_tls_fixtures(tmpdir.path());

        let config_path = tmpdir.path().join("doh2.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[roles]
forwarder = true

[[listeners]]
address = "127.0.0.1"
port = 59156
transport = "doh"
tls_cert = "{}"
tls_key = "{}"
"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .expect("write config");

        let mut child = spawn_daemon(config_path.to_str().unwrap());

        wait_for_ready();

        assert!(
            tcp_port_is_bound(59156),
            "expected DoH/H2 port 59156 to accept connections after daemon start"
        );

        sigterm(&child);

        let start = Instant::now();
        let status = wait_exit(&mut child);

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 s after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }

    // ── DoQ ──────────────────────────────────────────────────────────────────────

    #[test]
    fn doq_listener_bound_and_sigterm_exits_zero() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_tls_fixtures(tmpdir.path());

        let config_path = tmpdir.path().join("doq.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[roles]
forwarder = true

[[listeners]]
address = "127.0.0.1"
port = 59157
transport = "doq"
tls_cert = "{}"
tls_key = "{}"
"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .expect("write config");

        let mut child = spawn_daemon(config_path.to_str().unwrap());

        wait_for_ready();

        // DoQ is UDP-based; verify the port is bound.
        assert!(
            udp_port_is_bound(59157),
            "expected DoQ port 59157 to be in use after daemon start"
        );

        sigterm(&child);

        let start = Instant::now();
        let status = wait_exit(&mut child);

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "heimdall did not exit within 5 s after SIGTERM"
        );
        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
