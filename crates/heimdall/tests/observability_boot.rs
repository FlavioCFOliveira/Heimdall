// SPDX-License-Identifier: MIT

//! HTTP observability endpoint boot tests (Sprint 46 task #554 AC).
//!
//! Spawns `heimdall start`, waits for the HTTP observability listener to be
//! ready, then exercises each endpoint via blocking HTTP/1.1 requests.
//!
//! Test matrix:
//! - /healthz returns 200 "OK"
//! - /readyz returns 200 when the server is running
//! - /metrics returns 200 with OpenMetrics content type and heimdall_up metric
//! - /version returns 200 JSON with a `version` field
//!
//! Unix-only; uses a free port chosen at bind time (stored in the temp config).
#![allow(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpStream, SocketAddr};
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;
    use std::time::Duration;

    fn heimdall_bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    /// Find a free TCP port on 127.0.0.1 by binding a listener, reading the
    /// assigned port, and closing the listener before returning.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        l.local_addr().unwrap().port()
    }

    fn spawn_daemon(config_path: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config_path])
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

    /// Perform a minimal HTTP/1.1 GET over a raw TCP connection.
    /// Returns `(status_code, body, headers_lowercase)`.
    fn http_get(addr: SocketAddr, path: &str) -> (u16, String, Vec<String>) {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .expect("TCP connect to observability");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).unwrap();

        let mut reader = BufReader::new(stream);
        let mut status_code: u16 = 0;
        let mut headers: Vec<String> = Vec::new();
        let mut body = String::new();

        // Status line.
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        if let Some(code_str) = status_line.split_whitespace().nth(1) {
            status_code = code_str.parse().unwrap_or(0);
        }

        // Headers.
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            if trimmed.is_empty() {
                break;
            }
            headers.push(trimmed.to_lowercase());
        }

        // Body.
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    body.push_str(&l);
                    body.push('\n');
                }
                Err(_) => break,
            }
        }

        (status_code, body, headers)
    }

    /// Poll until the observability port accepts TCP connections or the deadline
    /// expires.  Returns `true` if the port became available within `timeout`.
    fn wait_for_port(addr: SocketAddr, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    #[test]
    fn healthz_returns_200_ok() {
        let port = free_port();
        let config_path = write_temp_config(port);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let mut child = spawn_daemon(&config_path);

        let ready = wait_for_port(addr, Duration::from_secs(5));
        if !ready {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
            let _ = std::fs::remove_file(&config_path);
            panic!("observability port did not open within 5 seconds");
        }

        let (code, body, _) = http_get(addr, "/healthz");

        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();
        let _ = std::fs::remove_file(&config_path);

        assert_eq!(code, 200, "/healthz must return 200");
        assert!(
            body.to_uppercase().contains("OK"),
            "/healthz body must contain 'OK', got: {body:?}"
        );
    }

    #[test]
    fn readyz_returns_200_when_running() {
        let port = free_port();
        let config_path = write_temp_config(port);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let mut child = spawn_daemon(&config_path);

        let ready = wait_for_port(addr, Duration::from_secs(5));
        if !ready {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
            let _ = std::fs::remove_file(&config_path);
            panic!("observability port did not open within 5 seconds");
        }

        let (code, _, _) = http_get(addr, "/readyz");

        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();
        let _ = std::fs::remove_file(&config_path);

        assert_eq!(code, 200, "/readyz must return 200 after startup");
    }

    #[test]
    fn metrics_returns_openmetrics_with_heimdall_up() {
        let port = free_port();
        let config_path = write_temp_config(port);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let mut child = spawn_daemon(&config_path);

        let ready = wait_for_port(addr, Duration::from_secs(5));
        if !ready {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
            let _ = std::fs::remove_file(&config_path);
            panic!("observability port did not open within 5 seconds");
        }

        let (code, body, headers) = http_get(addr, "/metrics");

        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();
        let _ = std::fs::remove_file(&config_path);

        assert_eq!(code, 200, "/metrics must return 200");
        assert!(
            headers.iter().any(|h| h.contains("openmetrics")),
            "/metrics Content-Type must contain 'openmetrics'; headers: {headers:?}"
        );
        assert!(
            body.contains("heimdall_up"),
            "/metrics body must contain heimdall_up metric; body: {body:?}"
        );
    }

    #[test]
    fn version_returns_json_with_version_field() {
        let port = free_port();
        let config_path = write_temp_config(port);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let mut child = spawn_daemon(&config_path);

        let ready = wait_for_port(addr, Duration::from_secs(5));
        if !ready {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
            let _ = std::fs::remove_file(&config_path);
            panic!("observability port did not open within 5 seconds");
        }

        let (code, body, headers) = http_get(addr, "/version");

        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = child.wait();
        let _ = std::fs::remove_file(&config_path);

        assert_eq!(code, 200, "/version must return 200");
        assert!(
            headers.iter().any(|h| h.contains("application/json")),
            "/version Content-Type must be application/json; headers: {headers:?}"
        );
        let json: serde_json::Value =
            serde_json::from_str(body.trim()).expect("/version body must be valid JSON");
        assert!(
            json.get("version").and_then(|v| v.as_str()).is_some(),
            "/version JSON must have a 'version' string field; body: {body:?}"
        );
    }

    /// Write a temp config that points [observability] at the given port.
    fn write_temp_config(port: u16) -> String {
        let path = std::env::temp_dir().join(format!(
            "heimdall_obs_test_{pid}_{port}.toml",
            pid = std::process::id()
        ));
        let content = format!(
            "[observability]\nmetrics_port = {port}\nmetrics_addr = \"127.0.0.1\"\n"
        );
        std::fs::write(&path, content).expect("write temp config");
        path.to_str().unwrap().to_owned()
    }
}

#[cfg(unix)]
extern crate libc;
