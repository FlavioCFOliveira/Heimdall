// SPDX-License-Identifier: MIT

//! Subprocess test harness for Heimdall end-to-end integration tests.
//!
//! Modules:
//! - [`TestServer`] — subprocess spawner with RAII teardown.
//! - [`dns_client`] — minimal synchronous DNS-over-UDP test client.
//! - [`pki`] — TLS test PKI: root CA, server cert, client cert.
//! - [`zones`] — DNSSEC test zone generators (valid + bogus).
//! - [`tsig`] — TSIG key fixtures for HMAC-SHA256 test keys.
//! - [`config`] — TOML template builders.
//!
//! [`TestServer`] spawns the real `heimdall` binary with an ephemeral-port
//! TOML config, waits until `/readyz` returns 200, and tears down the child
//! process (SIGTERM → SIGKILL) when dropped — even if the test panics.
//!
//! Usage:
//! ```no_run
//! use heimdall_e2e_harness::{TestServer, config, free_port};
//! use std::time::Duration;
//!
//! let dns_port = free_port();
//! let obs_port = free_port();
//! let toml = config::minimal_recursive(dns_port, obs_port);
//! let server = TestServer::start_with_ports(env!("CARGO_BIN_EXE_heimdall"), &toml, dns_port, obs_port)
//!     .wait_ready(Duration::from_secs(5))
//!     .expect("server did not become ready");
//! // use server.dns_port, server.obs_port …
//! // Drop shuts down the daemon automatically.
//! ```

#![cfg(unix)]
#![allow(unsafe_code)]

pub mod dns_client;
pub mod pki;
pub mod zones;

use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::Duration;

#[derive(Debug)]
pub struct TestServer {
    child: Child,
    /// Port of the first DNS listener (set by the caller, or 0 if not applicable).
    pub dns_port: u16,
    /// Port of the observability HTTP server.
    pub obs_port: u16,
    // Keeps the tempdir alive for the lifetime of the server.
    _tempdir: tempfile::TempDir,
    stderr: Option<ChildStderr>,
}

impl TestServer {
    /// Like [`start_with_ports`] but does not record specific ports.
    ///
    /// Use when you only care about the observability endpoint or set
    /// `dns_port`/`obs_port` fields manually after construction.
    pub fn start(bin: &str, toml: &str) -> Self {
        Self::start_with_ports(bin, toml, 0, 0)
    }

    /// Spawn `bin` with `toml` as the config file, recording `dns_port` and
    /// `obs_port` for use in helper methods.  Returns immediately without
    /// waiting for readiness — call [`wait_ready`] afterwards.
    ///
    /// # Panics
    ///
    /// Panics if the binary cannot be spawned.
    pub fn start_with_ports(bin: &str, toml: &str, dns_port: u16, obs_port: u16) -> Self {
        let tempdir = tempfile::TempDir::new().expect("tempdir for TestServer config");
        let config_path = tempdir.path().join("heimdall.toml");
        std::fs::write(&config_path, toml).expect("write TestServer config");

        let mut cmd = Command::new(bin);
        cmd.args(["start", "--config", config_path.to_str().unwrap()])
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // Isolate in its own process group so signals target only the daemon.
        unsafe {
            use std::os::unix::process::CommandExt as _;
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let mut child = cmd.spawn().expect("spawn heimdall binary");
        let stderr = child.stderr.take();

        Self {
            child,
            dns_port,
            obs_port,
            _tempdir: tempdir,
            stderr,
        }
    }

    /// Block until `/readyz` returns 200 or `timeout` expires.
    ///
    /// Returns `Ok(self)` on success, `Err(self)` on timeout so the caller
    /// can still inspect or drop the server.
    pub fn wait_ready(self, timeout: Duration) -> Result<Self, Self> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.obs_port)
            .parse()
            .expect("valid obs_port");
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline {
            if let Ok(mut stream) =
                TcpStream::connect_timeout(&addr, Duration::from_millis(50))
            {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                let req =
                    "GET /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                if stream.write_all(req.as_bytes()).is_ok() {
                    let mut line = String::new();
                    let mut reader = BufReader::new(stream);
                    if reader.read_line(&mut line).is_ok() && line.contains("200") {
                        return Ok(self);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(self)
    }

    /// Returns the DNS listener address (`127.0.0.1:<dns_port>`).
    pub fn dns_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.dns_port).parse().unwrap()
    }

    /// Returns the observability HTTP address (`127.0.0.1:<obs_port>`).
    pub fn obs_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.obs_port).parse().unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let panicking = std::thread::panicking();

        // SIGTERM first; allow up to 5 seconds for clean exit.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let exited = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => break false,
            }
        };

        if !exited {
            // Escalate to SIGKILL.
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }

        if panicking {
            if let Some(mut stderr) = self.stderr.take() {
                let mut buf = Vec::new();
                let _ = stderr.read_to_end(&mut buf);
                if !buf.is_empty() {
                    eprintln!(
                        "=== heimdall stderr (TestServer dns_port={}) ===\n{}\n=== end ===",
                        self.dns_port,
                        String::from_utf8_lossy(&buf)
                    );
                }
            }
        }
    }
}

// ── Port allocation ───────────────────────────────────────────────────────────

/// Allocate a free TCP port on `127.0.0.1` by binding port 0 and reading the
/// kernel-assigned port.  The socket is closed before returning, so there is a
/// brief TOCTOU window — acceptable for test use.
pub fn free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

// ── Config templates ──────────────────────────────────────────────────────────

/// TOML config template builders for common server roles.
pub mod config {
    use std::path::Path;

    /// Minimal recursive resolver: one UDP + one TCP listener.
    pub fn minimal_recursive(dns_port: u16, obs_port: u16) -> String {
        format!(
            r#"[roles]
recursive = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}
"#
        )
    }

    /// Authoritative server loading one zone file from `zone_path` under `origin`.
    pub fn minimal_auth(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Authoritative server with TSIG-protected zone transfer.
    ///
    /// Generates the same listeners as [`minimal_auth`] but adds TSIG key fields
    /// so that AXFR/IXFR requests must be signed with `key_name` / `secret_b64`.
    pub fn minimal_auth_with_tsig(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        key_name: &str,
        algorithm: &str,
        secret_b64: &str,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin             = "{origin}"
path               = "{path_str}"
tsig_key_name      = "{key_name}"
tsig_algorithm     = "{algorithm}"
tsig_secret_base64 = "{secret_b64}"
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over UDP.
    pub fn minimal_forwarder(
        dns_port: u16,
        obs_port: u16,
        upstream_addr: &str,
        upstream_port: u16,
    ) -> String {
        format!(
            r#"[roles]
forwarder = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[forward_zones]]
match = "."
upstreams = [{{ address = "{upstream_addr}", port = {upstream_port}, transport = "udp" }}]
"#
        )
    }

    /// All three roles active (authoritative + recursive + forwarder) with one
    /// UDP + TCP listener.  Useful for multi-role coexistence tests.
    pub fn all_roles(dns_port: u16, obs_port: u16) -> String {
        format!(
            r#"[roles]
authoritative = true
recursive = true
forwarder = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}
"#
        )
    }

    /// Authoritative server with a single DoT listener.
    ///
    /// `cert_path` and `key_path` are paths to PEM files for the TLS server
    /// certificate and private key (e.g. from [`crate::pki::TestPki`]).
    pub fn minimal_auth_dot(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let cert_str = cert_path.to_str().expect("cert path must be valid UTF-8");
        let key_str = key_path.to_str().expect("key path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "dot"
tls_cert = "{cert_str}"
tls_key  = "{key_str}"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Authoritative server with a single DoH/2 listener (transport = `"doh"`).
    ///
    /// `cert_path` and `key_path` are paths to PEM files for the TLS server
    /// certificate and private key (e.g. from [`crate::pki::TestPki`]).
    pub fn minimal_auth_doh2(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let cert_str = cert_path.to_str().expect("cert path must be valid UTF-8");
        let key_str = key_path.to_str().expect("key path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "doh"
tls_cert = "{cert_str}"
tls_key  = "{key_str}"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Authoritative server with a single DoH/3 listener (transport = `"doh3"`).
    ///
    /// `cert_path` and `key_path` are paths to PEM files for the TLS server
    /// certificate and private key (e.g. from [`crate::pki::TestPki`]).
    pub fn minimal_auth_doh3(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let cert_str = cert_path.to_str().expect("cert path must be valid UTF-8");
        let key_str = key_path.to_str().expect("key path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "doh3"
tls_cert = "{cert_str}"
tls_key  = "{key_str}"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Authoritative server with a single DoQ listener (transport = `"doq"`).
    ///
    /// `cert_path` and `key_path` are paths to PEM files for the TLS server
    /// certificate and private key (e.g. from [`crate::pki::TestPki`]).
    pub fn minimal_auth_doq(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let cert_str = cert_path.to_str().expect("cert path must be valid UTF-8");
        let key_str = key_path.to_str().expect("key path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "doq"
tls_cert = "{cert_str}"
tls_key  = "{key_str}"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Minimal config with only observability — no DNS listeners, no role.
    /// Useful for harness self-tests.
    pub fn minimal_obs(obs_port: u16) -> String {
        format!(
            r#"[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}
"#
        )
    }
}

// ── Convenience constructors ──────────────────────────────────────────────────

impl TestServer {
    /// Spawn an authoritative server serving `zone_path` as `origin` and wait
    /// up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth(bin: &str, origin: &str, zone_path: &Path) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth(dns_port, obs_port, origin, zone_path);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn an authoritative server with TSIG-protected zone transfer and wait
    /// up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth_with_tsig(
        bin: &str,
        origin: &str,
        zone_path: &Path,
        key_name: &str,
        algorithm: &str,
        secret_b64: &str,
    ) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth_with_tsig(
            dns_port, obs_port, origin, zone_path, key_name, algorithm, secret_b64,
        );
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_with_tsig: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn an authoritative DoT server serving `zone_path` as `origin`,
    /// using TLS material at `cert_path`/`key_path`, and wait up to 2 seconds
    /// for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth_dot(
        bin: &str,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth_dot(
            dns_port, obs_port, origin, zone_path, cert_path, key_path,
        );
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_dot: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn an authoritative DoH/2 server serving `zone_path` as `origin`,
    /// using TLS material at `cert_path`/`key_path`, and wait up to 2 seconds
    /// for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth_doh2(
        bin: &str,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth_doh2(
            dns_port, obs_port, origin, zone_path, cert_path, key_path,
        );
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_doh2: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn an authoritative DoH/3 server serving `zone_path` as `origin`,
    /// using TLS material at `cert_path`/`key_path`, and wait up to 2 seconds
    /// for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth_doh3(
        bin: &str,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth_doh3(
            dns_port, obs_port, origin, zone_path, cert_path, key_path,
        );
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_doh3: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn an authoritative DoQ server serving `zone_path` as `origin`,
    /// using TLS material at `cert_path`/`key_path`, and wait up to 2 seconds
    /// for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth_doq(
        bin: &str,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_auth_doq(
            dns_port, obs_port, origin, zone_path, cert_path, key_path,
        );
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_doq: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn a recursive resolver and wait up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_recursive(bin: &str) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_recursive(dns_port, obs_port);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_recursive: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }
}

// ── TSIG key fixtures ─────────────────────────────────────────────────────────

/// TSIG key constants for HMAC-SHA256 test keys.
pub mod tsig {
    /// Algorithm name as it appears in TSIG records.
    pub const ALGORITHM: &str = "hmac-sha256.";

    /// Name of the primary test TSIG key.
    pub const KEY_NAME: &str = "test-tsig-key.";

    /// Base64-encoded 256-bit HMAC-SHA256 test secret.  NOT a production secret.
    pub const KEY_SECRET_B64: &str =
        "SGVpbWRhbGxUZXN0VFNJR0tleUhNQUNTSEEyNTYyMDI=";

    /// Raw test key bytes (32 bytes, deterministic).
    pub const KEY_BYTES: &[u8; 32] = b"HeimdallTestTSIGKeyHMACSHA256202";
}

extern crate libc;
