// SPDX-License-Identifier: MIT
#![allow(unsafe_code)]

//! sd_notify integration tests (Sprint 46 task #463 AC).
//!
//! Spawns heimdall with a mock `$NOTIFY_SOCKET` (Unix datagram socket bound
//! by the test process) and `$WATCHDOG_USEC=200000` (200 ms → keepalive every
//! 100 ms).  Verifies the expected notification sequence:
//!   READY=1  →  WATCHDOG=1 (≥ 1)  →  STOPPING=1
//!
//! Unix-only: uses `UnixDatagram` and POSIX signal APIs.

#[cfg(unix)]
mod unix {
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn heimdall_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Read all available datagrams from `sock` until `deadline`, returning
    /// them as a `Vec<String>`.
    fn drain_until(sock: &UnixDatagram, deadline: Instant) -> Vec<String> {
        let mut msgs = Vec::new();
        let mut buf = [0u8; 128];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Shrink the per-read timeout so we don't overshoot the deadline.
            let timeout = remaining.min(Duration::from_millis(50));
            let _ = sock.set_read_timeout(Some(timeout));
            match sock.recv(&mut buf) {
                Ok(n) => {
                    msgs.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // No message within the window — check deadline and loop.
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        msgs
    }

    /// Verify that heimdall emits READY=1, ≥1 WATCHDOG=1, and STOPPING=1 in
    /// the correct order when `$NOTIFY_SOCKET` and `$WATCHDOG_USEC` are set.
    #[test]
    fn sd_notify_sequence_ready_watchdog_stopping() {
        // macOS sun_path limit is 104 bytes; use /tmp with the PID to stay short.
        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/hdl_notify_{}.sock",
            std::process::id()
        ));
        // Clean up any stale socket from a previous test run.
        let _ = std::fs::remove_file(&socket_path);

        // Bind the receiver socket before spawning the daemon so it can connect.
        let receiver = UnixDatagram::bind(&socket_path).expect("bind notify socket");
        // Ensure the socket is removed when the test exits.
        struct SocketGuard(std::path::PathBuf);
        impl Drop for SocketGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _guard = SocketGuard(socket_path.clone());

        let config = fixture("minimal.toml");

        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", &config])
            .env("RUST_LOG", "warn")
            .env("NOTIFY_SOCKET", socket_path.to_str().unwrap())
            // 200 ms watchdog period → keepalive every 100 ms (interval = usec / 2).
            .env("WATCHDOG_USEC", "200000")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let mut child = cmd.spawn().expect("failed to spawn heimdall");

        // Collect notifications for 600 ms — enough for READY=1 and several
        // WATCHDOG=1 keepalives at 100 ms intervals.
        let pre_term_deadline = Instant::now() + Duration::from_millis(600);
        let mut messages = drain_until(&receiver, pre_term_deadline);

        // Send SIGTERM and collect STOPPING=1 within a further 500 ms.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let post_term_deadline = Instant::now() + Duration::from_millis(500);
        messages.extend(drain_until(&receiver, post_term_deadline));

        let _ = child.wait();

        let ready_pos = messages.iter().position(|m| m == "READY=1");
        let stopping_pos = messages.iter().rposition(|m| m == "STOPPING=1");
        let watchdog_count = messages.iter().filter(|m| m.as_str() == "WATCHDOG=1").count();

        assert!(
            ready_pos.is_some(),
            "READY=1 not received; messages: {messages:?}"
        );
        assert!(
            stopping_pos.is_some(),
            "STOPPING=1 not received; messages: {messages:?}"
        );
        assert!(
            ready_pos.unwrap() < stopping_pos.unwrap(),
            "READY=1 must precede STOPPING=1; messages: {messages:?}"
        );
        assert!(
            watchdog_count >= 1,
            "expected at least 1 WATCHDOG=1; messages: {messages:?}"
        );
    }
}

#[cfg(unix)]
extern crate libc;
