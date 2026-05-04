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
pub mod spy_dns;
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
    /// Absolute path of the TOML config file the daemon was started with.
    config_path: std::path::PathBuf,
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
            config_path,
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

    /// Returns the OS process ID of the child daemon.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the path to the TOML config file the daemon was started with.
    ///
    /// Tests can overwrite this file and then call [`send_sighup`] to trigger a
    /// reload cycle (OPS-001 through OPS-006).
    #[must_use]
    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    /// Overwrite the daemon's config file with `toml` and return the path.
    ///
    /// Panics if the write fails.
    pub fn write_config(&self, toml: &str) -> &std::path::Path {
        std::fs::write(&self.config_path, toml).expect("write updated config");
        &self.config_path
    }

    /// Send `SIGHUP` to the daemon process.
    ///
    /// The daemon responds to `SIGHUP` by reloading its TOML configuration
    /// (implemented in `crates/heimdall/src/signals.rs`).
    ///
    /// # Safety
    ///
    /// Uses `libc::kill` to send a POSIX signal.  Safe in the context of
    /// integration tests where the PID is known to be the child we spawned.
    pub fn send_sighup(&self) {
        // SAFETY: the PID belongs to the child process we spawned, and SIGHUP
        // is a well-defined signal.  The child is still alive at this point.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGHUP);
        }
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "{upstream_addr}", port = {upstream_port}, transport = "udp" }}]
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over DoT.
    ///
    /// `tls_verify = false` is set so the forwarder accepts the test CA without needing
    /// the OS trust store.  Use only with test environments.
    pub fn minimal_forwarder_dot(
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "{upstream_addr}", port = {upstream_port}, transport = "dot", tls_verify = false }}]
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over DoH/H2.
    ///
    /// `tls_verify = false` is set so the forwarder accepts the test CA.
    pub fn minimal_forwarder_doh2(
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "localhost", port = {upstream_port}, transport = "doh", tls_verify = false }}]
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over DoH/H3.
    ///
    /// `tls_verify = false` is set so the forwarder accepts the test CA.
    pub fn minimal_forwarder_doh3(
        dns_port: u16,
        obs_port: u16,
        upstream_addr: &str,
        upstream_port: u16,
    ) -> String {
        let _ = upstream_addr; // localhost is used for SNI-based QUIC
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "127.0.0.1", port = {upstream_port}, transport = "doh3", tls_verify = false, sni = "localhost" }}]
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over DoQ (RFC 9250).
    ///
    /// `tls_verify = false` is set so the forwarder accepts the test CA.
    pub fn minimal_forwarder_doq(
        dns_port: u16,
        obs_port: u16,
        upstream_addr: &str,
        upstream_port: u16,
    ) -> String {
        let _ = upstream_addr; // localhost is used for SNI-based QUIC
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "127.0.0.1", port = {upstream_port}, transport = "doq", tls_verify = false, sni = "localhost" }}]
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]
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

    /// Authoritative server loading one zone file from `zone_path` under `origin`,
    /// listening on a specific address (`dns_addr`) instead of the default `127.0.0.1`.
    ///
    /// Used in multi-server iterative-resolution tests where each nameserver
    /// in the delegation hierarchy must be on a distinct loopback IP address.
    pub fn minimal_auth_on_addr(
        dns_addr: &str,
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
address = "{dns_addr}"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "{dns_addr}"
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

    /// Recursive resolver with a custom root-hints file and a custom outbound
    /// query port.
    ///
    /// - `root_hints_path`: path to a zone-file-format hints file listing the
    ///   in-test root nameserver address.
    /// - `query_port`: the UDP/TCP port used for ALL outbound resolution queries
    ///   (root, TLD, leaf).  Must match the port of all in-test nameservers.
    pub fn minimal_recursive_custom(
        dns_port: u16,
        obs_port: u16,
        root_hints_path: &Path,
        query_port: u16,
    ) -> String {
        let hints_str = root_hints_path.to_str().expect("hints path must be valid UTF-8");
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[recursive]
root_hints_path = "{hints_str}"
query_port = {query_port}
"#
        )
    }

    /// Like [`minimal_recursive_custom`] but also sets `qname_min_mode`.
    ///
    /// `qname_min_mode` must be one of `"relaxed"`, `"strict"`, or `"off"`.
    pub fn minimal_recursive_custom_with_qname_min(
        dns_port: u16,
        obs_port: u16,
        root_hints_path: &Path,
        query_port: u16,
        qname_min_mode: &str,
    ) -> String {
        let hints_str = root_hints_path.to_str().expect("hints path must be valid UTF-8");
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[recursive]
root_hints_path = "{hints_str}"
query_port = {query_port}
qname_min_mode = "{qname_min_mode}"
"#
        )
    }

    /// Like [`minimal_recursive_custom_with_qname_min`] but also sets
    /// `cache.min_ttl_secs` for TTL-expiry tests.
    ///
    /// Set `min_ttl_secs = 1` to allow very short-lived cache entries without
    /// the default 60-second floor.  Use only in test environments.
    pub fn minimal_recursive_custom_with_qname_min_and_min_ttl(
        dns_port: u16,
        obs_port: u16,
        root_hints_path: &Path,
        query_port: u16,
        qname_min_mode: &str,
        min_ttl_secs: u32,
    ) -> String {
        let hints_str = root_hints_path.to_str().expect("hints path must be valid UTF-8");
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[recursive]
root_hints_path = "{hints_str}"
query_port = {query_port}
qname_min_mode = "{qname_min_mode}"

[cache]
min_ttl_secs = {min_ttl_secs}
"#
        )
    }

    /// Authoritative server loading TWO zone files on a single instance,
    /// bound to `dns_addr`.
    ///
    /// Used in iterative-resolution tests where root (`.`) and TLD (e.g.
    /// `test.`) zone data can be served by the same process at the same IP.
    pub fn minimal_auth_two_zones(
        dns_addr: &str,
        dns_port: u16,
        obs_port: u16,
        origin1: &str,
        zone_path1: &Path,
        origin2: &str,
        zone_path2: &Path,
    ) -> String {
        let path1 = zone_path1.to_str().expect("zone path must be valid UTF-8");
        let path2 = zone_path2.to_str().expect("zone path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "{dns_addr}"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "{dns_addr}"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin1}"
path   = "{path1}"

[[zones.zone_files]]
origin = "{origin2}"
path   = "{path2}"
"#
        )
    }

    /// Authoritative server loading THREE zone files on a single instance.
    ///
    /// Used in DNSSEC E2E tests where a signed zone, a bogus zone, and an
    /// insecure zone must all be served by the same process (Sprint 47 task #473).
    pub fn minimal_auth_three_zones(
        dns_port: u16,
        obs_port: u16,
        origin1: &str,
        zone_path1: &Path,
        origin2: &str,
        zone_path2: &Path,
        origin3: &str,
        zone_path3: &Path,
    ) -> String {
        let path1 = zone_path1.to_str().expect("zone path must be valid UTF-8");
        let path2 = zone_path2.to_str().expect("zone path must be valid UTF-8");
        let path3 = zone_path3.to_str().expect("zone path must be valid UTF-8");
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
origin = "{origin1}"
path   = "{path1}"

[[zones.zone_files]]
origin = "{origin2}"
path   = "{path2}"

[[zones.zone_files]]
origin = "{origin3}"
path   = "{path3}"
"#
        )
    }

    /// Authoritative server with all six transport listeners on separate ports.
    ///
    /// Listeners: UDP (`udp_port`), TCP (`tcp_port`), DoT (`dot_port`),
    /// DoH/H2 (`doh2_port`), DoH/H3 (`doh3_port`), DoQ (`doq_port`).
    /// Serves `origin` from `zone_path`.  TLS listeners use `cert_path`/`key_path`.
    ///
    /// Used in ROLE-024/025 step-4 byte-identity E2E tests.
    #[allow(clippy::too_many_arguments)]
    pub fn auth_all_transports(
        udp_port: u16,
        tcp_port: u16,
        dot_port: u16,
        doh2_port: u16,
        doh3_port: u16,
        doq_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> String {
        let zone_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let cert_str = cert_path.to_str().expect("cert path must be valid UTF-8");
        let key_str  = key_path.to_str().expect("key path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address   = "127.0.0.1"
port      = {udp_port}
transport = "udp"

[[listeners]]
address   = "127.0.0.1"
port      = {tcp_port}
transport = "tcp"

[[listeners]]
address   = "127.0.0.1"
port      = {dot_port}
transport = "dot"
tls_cert  = "{cert_str}"
tls_key   = "{key_str}"

[[listeners]]
address   = "127.0.0.1"
port      = {doh2_port}
transport = "doh"
tls_cert  = "{cert_str}"
tls_key   = "{key_str}"

[[listeners]]
address   = "127.0.0.1"
port      = {doh3_port}
transport = "doh3"
tls_cert  = "{cert_str}"
tls_key   = "{key_str}"

[[listeners]]
address   = "127.0.0.1"
port      = {doq_port}
transport = "doq"
tls_cert  = "{cert_str}"
tls_key   = "{key_str}"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[[zones.zone_files]]
origin = "{origin}"
path   = "{zone_str}"
"#
        )
    }

    /// Minimal config with only observability — no DNS listeners, no role.
    /// Useful for harness self-tests.
    pub fn minimal_obs(dns_port: u16, obs_port: u16) -> String {
        // ROLE-026 requires an active role; listener validation requires at
        // least one [[listeners]] when any role is active.
        format!(
            r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}
"#
        )
    }

    /// Authoritative server with ACL deny on `deny_cidr`.
    ///
    /// Queries from addresses that match `deny_cidr` are silently dropped
    /// (UDP) or connection-closed (TCP).  All other sources are admitted by
    /// the per-operation defaults (authoritative queries allowed).
    pub fn minimal_auth_with_acl_deny(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &std::path::Path,
        deny_cidr: &str,
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

[acl]
deny_sources = ["{deny_cidr}"]

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Authoritative server with Response Rate Limiting set to `rps` responses
    /// per second per client subnet.
    ///
    /// After `rps` responses in the same window the RRL engine sends TC=1 slip
    /// responses so clients retry over TCP.
    pub fn minimal_auth_with_rrl(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &std::path::Path,
        rps: u32,
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

[rate_limit]
enabled = true
responses_per_second = {rps}

[[zones.zone_files]]
origin = "{origin}"
path   = "{path_str}"
"#
        )
    }

    /// Forwarder with per-client query rate limit set to `qps` queries per second.
    ///
    /// `allow_cidr` is explicitly allowed through the ACL so the forwarder role
    /// (denied by default) can reach the rate-limiting stage.
    /// After `qps` admitted queries the engine returns REFUSED.
    pub fn minimal_forwarder_with_query_rl(
        dns_port: u16,
        obs_port: u16,
        upstream_addr: &str,
        upstream_port: u16,
        allow_cidr: &str,
        qps: u32,
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

[acl]
allow_sources = ["{allow_cidr}"]

[rate_limit]
enabled = true
query_rate_per_second = {qps}

[[forward_zones]]
match = "."
upstreams = [{{ address = "{upstream_addr}", port = {upstream_port}, transport = "udp" }}]
"#
        )
    }

    /// Authoritative primary server loading `zone_path` as `origin`, configured
    /// to NOTIFY a single secondary at `notify_secondary`.
    ///
    /// This sets `notify_secondaries` in the zone entry so that the primary will
    /// send NOTIFY to the secondary on startup (RFC 1996 §3.7).
    ///
    /// TSIG is enabled using the standard test key constants from [`crate::tsig`]
    /// so that the secondary (also configured with the same key) can perform
    /// authenticated zone transfers (PROTO-048).
    pub fn minimal_primary_with_notify(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &std::path::Path,
        notify_secondary: std::net::SocketAddr,
    ) -> String {
        let path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let notify_str = notify_secondary.to_string();
        let key_name = crate::tsig::KEY_NAME;
        let algorithm = crate::tsig::ALGORITHM;
        let secret_b64 = crate::tsig::KEY_SECRET_B64;
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
origin              = "{origin}"
path                = "{path_str}"
zone_role           = "primary"
notify_secondaries  = ["{notify_str}"]
tsig_key_name       = "{key_name}"
tsig_algorithm      = "{algorithm}"
tsig_secret_base64  = "{secret_b64}"
"#
        )
    }

    /// Authoritative secondary server pulling `origin` from `primary_addr`.
    ///
    /// No local zone file is needed — data is obtained via AXFR from the primary.
    /// The secondary accepts inbound NOTIFY messages to trigger immediate refresh.
    ///
    /// TSIG is enabled using the standard test key constants from [`crate::tsig`]
    /// so that outbound AXFR/IXFR queries are signed (PROTO-048).  The primary
    /// must be configured with the same key (e.g. via
    /// [`minimal_primary_with_notify`] or [`minimal_auth_with_tsig`]).
    pub fn minimal_secondary(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        primary_addr: std::net::SocketAddr,
    ) -> String {
        let primary_str = primary_addr.to_string();
        let key_name = crate::tsig::KEY_NAME;
        let algorithm = crate::tsig::ALGORITHM;
        let secret_b64 = crate::tsig::KEY_SECRET_B64;
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
origin              = "{origin}"
zone_role           = "secondary"
upstream_primary    = "{primary_str}"
tsig_key_name       = "{key_name}"
tsig_algorithm      = "{algorithm}"
tsig_secret_base64  = "{secret_b64}"
"#
        )
    }

    /// Authoritative + recursive coexistence server.
    ///
    /// Both `[roles] authoritative = true` and `[roles] recursive = true` are
    /// enabled.  Auth serves `origin` from `zone_path`.  Recursive uses
    /// `root_hints_path` as the root-hints file and `query_port` for all
    /// outbound resolution queries.
    ///
    /// QNAME minimisation is set to `"off"` for deterministic test behaviour:
    /// the recursive resolver sends the full QNAME to every upstream.
    pub fn minimal_auth_recursive_with_hints(
        dns_port: u16,
        obs_port: u16,
        origin: &str,
        zone_path: &Path,
        root_hints_path: &Path,
        query_port: u16,
    ) -> String {
        let zone_path_str = zone_path.to_str().expect("zone path must be valid UTF-8");
        let hints_str = root_hints_path.to_str().expect("hints path must be valid UTF-8");
        format!(
            r#"[roles]
authoritative = true
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[zones.zone_files]]
origin = "{origin}"
path   = "{zone_path_str}"

[recursive]
root_hints_path = "{hints_str}"
query_port = {query_port}
qname_min_mode = "off"
"#
        )
    }

    /// Forwarder role that sends all queries to `upstream_addr:upstream_port` over UDP
    /// with a single RPZ policy zone loaded from `rpz_zone_path`.
    pub fn minimal_forwarder_with_rpz(
        dns_port: u16,
        obs_port: u16,
        upstream_addr: &str,
        upstream_port: u16,
        rpz_zone: &str,
        rpz_zone_path: &str,
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[[forward_zones]]
match = "."
upstreams = [{{ address = "{upstream_addr}", port = {upstream_port}, transport = "udp" }}]

[[rpz]]
zone = "{rpz_zone}"
source = "{rpz_zone_path}"
"#
        )
    }

    /// Recursive server with an RPZ policy zone (RPZ-001).
    ///
    /// `root_hints_path` must point to a file containing the root NS hints.
    /// `query_port` is the port used for outbound resolution queries (typically
    /// the port of a SpyDNS server in test environments).
    pub fn minimal_recursive_with_rpz(
        dns_port: u16,
        obs_port: u16,
        root_hints_path: &std::path::Path,
        query_port: u16,
        rpz_zone: &str,
        rpz_zone_path: &str,
    ) -> String {
        let hints_str = root_hints_path.to_str().expect("hints path must be valid UTF-8");
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

[acl]
allow_sources = ["127.0.0.1/32", "::1/128"]

[recursive]
root_hints_path = "{hints_str}"
query_port = {query_port}

[[rpz]]
zone = "{rpz_zone}"
source = "{rpz_zone_path}"
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

    /// Spawn an authoritative server bound to `dns_addr` (instead of 127.0.0.1),
    /// serving `zone_path` as `origin`, and wait up to 2 seconds for readiness.
    ///
    /// Use in iterative-resolution tests where root, TLD, and leaf nameservers
    /// must each bind to a distinct loopback IP address.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds or if
    /// binding `dns_addr` fails.
    pub fn start_auth_on_addr(
        bin: &str,
        dns_addr: &str,
        dns_port: u16,
        origin: &str,
        zone_path: &Path,
    ) -> Self {
        let obs_port = free_port();
        let toml =
            config::minimal_auth_on_addr(dns_addr, dns_port, obs_port, origin, zone_path);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_on_addr: server on {dns_addr}:{} did not become ready within 2s",
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

    /// Spawn an authoritative secondary server for `origin`, pulling from
    /// `primary_addr`, and wait up to 3 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 3 seconds.
    pub fn start_secondary(bin: &str, origin: &str, primary_addr: std::net::SocketAddr) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_secondary(dns_port, obs_port, origin, primary_addr);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(3))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_secondary: server on dns_port={} did not become ready within 3s",
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

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoT
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_dot(bin: &str, upstream_port: u16) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_forwarder_dot(dns_port, obs_port, "127.0.0.1", upstream_port);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_forwarder_dot: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoH/H2
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doh2(bin: &str, upstream_port: u16) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_forwarder_doh2(dns_port, obs_port, "127.0.0.1", upstream_port);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_forwarder_doh2: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoH/H3
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doh3(bin: &str, upstream_port: u16) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_forwarder_doh3(dns_port, obs_port, "127.0.0.1", upstream_port);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_forwarder_doh3: server on dns_port={} did not become ready within 2s",
                    s.dns_port
                )
            })
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoQ (RFC 9250)
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doq(bin: &str, upstream_port: u16) -> Self {
        let dns_port = free_port();
        let obs_port = free_port();
        let toml = config::minimal_forwarder_doq(dns_port, obs_port, "127.0.0.1", upstream_port);
        Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_forwarder_doq: server on dns_port={} did not become ready within 2s",
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
