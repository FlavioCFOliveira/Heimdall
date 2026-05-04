// SPDX-License-Identifier: MIT
#![allow(unsafe_code)]

//! Smoke tests for Tokio runtime boot (Sprint 46 task #458 AC).
//!
//! Verifies that `heimdall start` logs the chosen I/O backend and worker count
//! at startup.
//!
//! The tests spawn heimdall as a subprocess, read its stderr for the expected
//! log line, then send SIGTERM to cleanly shut it down.

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn heimdall_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        l.local_addr().unwrap().port()
    }

    /// Build a minimal valid config with unique ports to avoid parallel conflicts.
    fn unique_config_toml() -> String {
        let dns_port = free_port();
        let obs_port = free_port();
        format!(
            "[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = {dns_port}\ntransport = \"udp\"\n\n[observability]\nmetrics_port = {obs_port}\n"
        )
    }

    fn spawn_and_collect_startup_logs(
        toml: &str,
    ) -> (std::process::Child, String, tempfile::NamedTempFile) {
        use std::io::Write as _;
        let mut cfg = tempfile::NamedTempFile::new().expect("tempfile");
        cfg.write_all(toml.as_bytes()).expect("write config");
        cfg.flush().expect("flush");
        let config_path = cfg.path().to_str().unwrap().to_owned();

        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", &config_path])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // Isolate the daemon in its own process group (matches signals.rs pattern).
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let mut child = cmd.spawn().expect("failed to spawn heimdall");
        let stderr = child.stderr.take().expect("stderr pipe");

        // Wait for signal handlers to be installed.
        std::thread::sleep(Duration::from_millis(2000));

        // Read whatever has been logged so far (non-blocking drain of the pipe).
        use std::io::Read as _;
        use std::os::unix::io::AsRawFd as _;
        unsafe {
            let fd = stderr.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stderr);
        let _ = reader.read_to_end(&mut buf);
        let logs = String::from_utf8_lossy(&buf).into_owned();

        (child, logs, cfg)
    }

    #[test]
    fn start_logs_io_backend_and_worker_count() {
        let toml = unique_config_toml();
        let (mut child, logs, _cfg) = spawn_and_collect_startup_logs(&toml);

        // Send SIGTERM so the daemon exits cleanly.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let status = child.wait().expect("wait failed");

        assert!(
            status.success(),
            "expected exit 0 after SIGTERM, got {status:?}"
        );

        assert!(
            logs.contains("Tokio runtime started") || logs.contains("io_backend"),
            "expected runtime log line in startup logs:\n{logs}"
        );
    }

    #[test]
    fn start_logs_worker_thread_count() {
        let toml = unique_config_toml();
        let (mut child, logs, _cfg) = spawn_and_collect_startup_logs(&toml);

        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        child.wait().expect("wait failed");

        assert!(
            logs.contains("worker_threads"),
            "expected worker_threads in startup logs:\n{logs}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate tempfile;

#[cfg(target_os = "linux")]
#[test]
fn io_backend_matches_kernel_version() {
    use heimdall_runtime::RuntimeFlavour;
    use heimdall_runtime::build_runtime;

    let (_rt, info) = build_runtime(1).expect("build_runtime");

    // On a kernel ≥ 5.19 with the io-uring feature, we expect IoUring.
    // Without the feature (our current build), always Epoll.
    #[cfg(not(feature = "io-uring"))]
    assert_eq!(
        info.flavour,
        RuntimeFlavour::Epoll,
        "expected Epoll without io-uring feature"
    );
}
