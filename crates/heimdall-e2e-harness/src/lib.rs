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
//! Usage (in a `[[test]]` of a crate that has the `heimdall` binary as a
//! dev-dependency, where Cargo populates `CARGO_BIN_EXE_heimdall` at compile
//! time):
//!
//! ```no_run
//! use heimdall_e2e_harness::{TestServer, config, free_port};
//! use std::time::Duration;
//!
//! // In a real test this is `env!("CARGO_BIN_EXE_heimdall")`. Here we read it
//! // at runtime so this doctest compiles in the harness crate itself, which
//! // does not have the binary as a build-time artefact.
//! let bin = std::env::var("CARGO_BIN_EXE_heimdall")
//!     .expect("CARGO_BIN_EXE_heimdall must be set by Cargo");
//! let dns_port = free_port();
//! let obs_port = free_port();
//! let toml = config::minimal_recursive(dns_port, obs_port);
//! let server = TestServer::start_with_ports(&bin, &toml, dns_port, obs_port)
//!     .wait_ready(Duration::from_secs(5))
//!     .expect("server did not become ready");
//! // use server.dns_port, server.obs_port …
//! // Drop shuts down the daemon automatically.
//! ```

#![cfg(unix)]
#![allow(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::undocumented_unsafe_blocks,
    clippy::needless_raw_string_hashes,
    clippy::uninlined_format_args,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_arguments,
    clippy::single_match_else,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::bool_to_int_with_if,
    clippy::doc_markdown,
    clippy::collapsible_if,
    unused_variables
)]

pub mod dns_client;
pub mod pki;
pub mod poll;
pub mod spy_dns;
pub mod zones;

use std::{
    io::{BufRead as _, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    process::{Child, ChildStderr, Command, Stdio},
    time::Duration,
};

pub use poll::{
    poll_until, poll_until_async, poll_until_or_timeout, wait_bounded, wait_bounded_async,
};

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
    /// Like `start_with_ports` but does not record specific ports.
    ///
    /// Use when you only care about the observability endpoint or set
    /// `dns_port`/`obs_port` fields manually after construction.
    pub fn start(bin: &str, toml: &str) -> Self {
        Self::start_with_ports(bin, toml, 0, 0)
    }

    /// Spawn `bin` with `toml` as the config file, recording `dns_port` and
    /// `obs_port` for use in helper methods.  Returns immediately without
    /// waiting for readiness — call `wait_ready` afterwards.
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
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                let req = "GET /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
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
    /// Tests can overwrite this file and then call `send_sighup` to trigger a
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

    /// Send `SIGTERM`, wait for the process to exit, and return all lines
    /// written to the daemon's stderr.
    ///
    /// This is the correct way to capture structured JSON log lines emitted
    /// by the daemon (the daemon writes JSON to stderr when stderr is not a
    /// TTY).  Call this instead of letting the server drop so that the
    /// `Drop` impl's RAII teardown does not race with the read.
    ///
    /// # Panics
    ///
    /// Panics if the process cannot be waited on.
    pub fn stop_and_take_stderr_lines(&mut self) -> Vec<String> {
        use std::io::BufRead as _;

        // SAFETY: same guarantees as send_sighup.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    unsafe {
                        libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL);
                    }
                    let _ = self.child.wait();
                    break;
                }
            }
        }

        let mut lines = Vec::new();
        if let Some(stderr) = self.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(l) => lines.push(l),
                    Err(_) => break,
                }
            }
        }
        lines
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

/// Cross-binary file lock that serialises the daemon-spawn window.
///
/// `SpawnLock` is a refcounted handle on a host-wide `flock(2)` exclusive
/// lock on `/tmp/heimdall-test-spawn.lock`.  The first handle acquired in a
/// process takes the underlying flock; subsequent handles bump the refcount
/// and re-use the same flock.  The flock is released when the **last**
/// handle in the process is dropped.
///
/// Why refcount within a process?  `flock(2)` is per-open-file-description:
/// opening the lock file twice in the same process and then attempting to
/// `LOCK_EX` on both fds deadlocks the second call.  In-process tests that
/// hold two reservations simultaneously (for two daemons that must be
/// configured to point at each other) must therefore share a single flock.
/// Concurrency between tests *inside* the same process is handled by Rust's
/// type system + the in-process `Mutex` that guards the refcount — the
/// flock's purpose is to coordinate across *different* test processes
/// (cargo's per-binary parallelism is the relevant case).
///
/// The lock file is created world-readable+writable so that tests run by any
/// CI user can re-use it.  It is **never** removed: removal would race with
/// other holders.
struct SpawnLock {
    /// Token: when dropped, decrements the process-wide refcount and may
    /// release the underlying flock.
    _token: SpawnLockToken,
}

/// Drop guard that decrements the global refcount.
struct SpawnLockToken;

impl Drop for SpawnLockToken {
    fn drop(&mut self) {
        let state = spawn_lock_state();
        let mut guard = state.lock().expect("spawn lock mutex poisoned");
        debug_assert!(guard.refcount > 0, "spawn lock refcount underflow");
        guard.refcount = guard.refcount.saturating_sub(1);
        if guard.refcount == 0 {
            // Drop the flock (this releases the host-wide kernel lock).
            guard.flock = None;
        }
    }
}

/// Process-wide state guarded by a single `Mutex`.
struct SpawnLockState {
    /// Number of live `SpawnLock` instances in this process.
    refcount: u32,
    /// The underlying flock; `None` when `refcount == 0`.
    flock: Option<nix::fcntl::Flock<std::fs::File>>,
}

fn spawn_lock_state() -> &'static std::sync::Mutex<SpawnLockState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<SpawnLockState>> =
        std::sync::OnceLock::new();
    STATE.get_or_init(|| {
        std::sync::Mutex::new(SpawnLockState {
            refcount: 0,
            flock: None,
        })
    })
}

impl SpawnLock {
    /// Acquire (or share) the host-wide spawn lock.  Blocks until the
    /// underlying `flock(2)` is granted.
    ///
    /// The lock file path is fixed at `/tmp/heimdall-test-spawn.lock`.  Any
    /// process running Heimdall tests on the same host shares it.  The
    /// environment variable `HEIMDALL_TEST_SPAWN_LOCK` overrides the path
    /// for tests that need an isolated lock namespace (rare).
    ///
    /// # Panics
    ///
    /// Panics if the lock file cannot be opened, `flock(LOCK_EX)` fails for
    /// reasons other than EINTR, or the global mutex is poisoned.  All
    /// three are unrecoverable test-environment failures.
    fn acquire() -> Self {
        let state = spawn_lock_state();
        let mut guard = state.lock().expect("spawn lock mutex poisoned");
        // If the kernel flock is not yet held by this process, acquire it
        // while holding the in-process mutex.  Holding the mutex throughout
        // the (blocking) `flock(LOCK_EX)` syscall is essential: it prevents
        // a second thread from issuing a parallel `flock` on a *different*
        // open file description, which would deadlock against the first
        // (flock is per-OFD, not per-process).
        if guard.flock.is_none() {
            guard.flock = Some(acquire_kernel_flock());
        }
        guard.refcount = guard.refcount.saturating_add(1);
        Self {
            _token: SpawnLockToken,
        }
    }
}

/// Open `/tmp/heimdall-test-spawn.lock` and block until `flock(LOCK_EX)`
/// returns it.  Retries on EINTR.
fn acquire_kernel_flock() -> nix::fcntl::Flock<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = std::env::var("HEIMDALL_TEST_SPAWN_LOCK")
        .unwrap_or_else(|_| "/tmp/heimdall-test-spawn.lock".to_owned());
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(&path)
            .unwrap_or_else(|e| panic!("open spawn lock file {path}: {e}"));
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive) {
            Ok(flock) => return flock,
            Err((_, nix::errno::Errno::EINTR)) if attempts < 64 => {}
            Err((_, e)) => panic!("flock {path}: {e}"),
        }
    }
}

/// A reservation of a `(dns_port, obs_port)` pair on `127.0.0.1` plus the
/// host-wide spawn-window lock that lets the daemon bind those ports without
/// racing other test processes.
///
/// # Lifecycle
///
/// 1. [`reserve_loopback_pair`] acquires [`SpawnLock`] (serialising across
///    all test binaries on the host), then probes UDP+TCP on two ephemeral
///    ports and holds them open as sentinels.
/// 2. The caller writes the TOML config with `dns_port` and `obs_port`.
/// 3. The caller invokes [`Self::release_sockets`] which drops the sentinels.
///    At this moment the kernel marks both ports as free, but the spawn lock
///    is **still held**.
/// 4. The caller spawns the daemon and waits for `/readyz`.  Because no other
///    test on the host can be in this window simultaneously, the only races
///    are with unrelated host processes — orders of magnitude less likely
///    than the in-test races the previous design suffered from.
/// 5. The caller drops the `PortReservation` once the daemon is ready, which
///    releases the spawn lock and lets the next reservation proceed.
///
/// Failing to drop the reservation will block every other test on the host
/// until the process exits.  Failing to call `release_sockets` before
/// spawning will cause the daemon to fail with `EADDRINUSE`.
pub struct PortReservation {
    /// Reserved DNS listener port.
    pub dns_port: u16,
    /// Reserved observability HTTP port.
    pub obs_port: u16,
    udp_dns: Option<std::net::UdpSocket>,
    tcp_dns: Option<std::net::TcpListener>,
    udp_obs: Option<std::net::UdpSocket>,
    tcp_obs: Option<std::net::TcpListener>,
    _spawn_lock: SpawnLock,
}

impl PortReservation {
    /// Release the four sentinel sockets so the daemon can bind the reserved
    /// ports.  The spawn lock is still held — the caller **must** keep this
    /// `PortReservation` alive until the daemon's `/readyz` returns 200.
    ///
    /// Calling `release_sockets` twice is a no-op on the second call (the
    /// sentinels are already gone).  This is safe and intentional.
    pub fn release_sockets(&mut self) {
        // Drop the inner sockets via `take()`; the kernel closes the fds and
        // marks the ports free.  TCP listeners enter TIME_WAIT but that is
        // harmless because the daemon binds with SO_REUSEADDR.
        drop(self.udp_dns.take());
        drop(self.tcp_dns.take());
        drop(self.udp_obs.take());
        drop(self.tcp_obs.take());
    }
}

impl std::fmt::Debug for PortReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortReservation")
            .field("dns_port", &self.dns_port)
            .field("obs_port", &self.obs_port)
            .field("sockets_held", &self.udp_dns.is_some())
            .finish_non_exhaustive()
    }
}

/// Reserve a `(dns_port, obs_port)` pair on `127.0.0.1` for an upcoming
/// daemon spawn.  Acquires a host-wide file lock so spawns across all test
/// binaries are serialised; the lock is released only when the returned
/// [`PortReservation`] is dropped.
///
/// See [`PortReservation`] for the required usage pattern.  In short:
///
/// ```no_run
/// # use heimdall_e2e_harness::reserve_loopback_pair;
/// let mut res = reserve_loopback_pair();
/// // ... build TOML using res.dns_port and res.obs_port ...
/// res.release_sockets();
/// // ... spawn daemon; wait for /readyz ...
/// drop(res); // releases the spawn lock for the next test
/// ```
///
/// # Panics
///
/// Panics if a free UDP+TCP port pair cannot be found after 64 attempts on
/// each side, or if the spawn lock file cannot be opened.
pub fn reserve_loopback_pair() -> PortReservation {
    // Lock first so two test processes cannot race on the bind probe at the
    // same time: even though each gets distinct ephemeral ports, two
    // simultaneous release_sockets() windows on the host would each be
    // independently exposed to outside snipers.
    let spawn_lock = SpawnLock::acquire();

    let (dns_port, udp_dns, tcp_dns) = probe_loopback_port_pair();
    // The probe for the second port must not pick the first one again — the
    // first port's sockets are still held, so the kernel will skip it.
    let (obs_port, udp_obs, tcp_obs) = probe_loopback_port_pair();
    debug_assert_ne!(dns_port, obs_port, "kernel handed out duplicate ports");

    PortReservation {
        dns_port,
        obs_port,
        udp_dns: Some(udp_dns),
        tcp_dns: Some(tcp_dns),
        udp_obs: Some(udp_obs),
        tcp_obs: Some(tcp_obs),
        _spawn_lock: spawn_lock,
    }
}

/// Bind one ephemeral UDP + TCP pair on `127.0.0.1`; return the port and the
/// two open sockets.  Both sockets are kept alive by the caller as sentinels.
fn probe_loopback_port_pair() -> (u16, std::net::UdpSocket, std::net::TcpListener) {
    use std::net::{TcpListener, UdpSocket};
    for _ in 0..64 {
        let Ok(tcp) = TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let port = match tcp.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => continue,
        };
        // Try UDP on the same port.  If unavailable, drop and retry — the
        // kernel will hand out a different ephemeral port next round.
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(udp) => return (port, udp, tcp),
            Err(_) => drop(tcp),
        }
    }
    panic!("probe_loopback_port_pair: no UDP+TCP-available port after 64 attempts");
}

/// Allocate a single port on `127.0.0.1` that is simultaneously free for
/// **both** TCP and UDP.
///
/// This is a thin wrapper around [`reserve_loopback_pair`] that returns the
/// `dns_port` and immediately drops the reservation, recreating the legacy
/// `free_port()` API for tests that have not yet migrated to the new
/// reservation pattern.
///
/// **Prefer [`reserve_loopback_pair`]** for new code: the reservation it
/// returns holds the host-wide spawn lock until `/readyz` is 200, closing
/// the TOCTOU window between probe and daemon-bind.  `free_port()` releases
/// the lock immediately, so concurrent tests can still in principle race —
/// it is retained only to minimise the migration footprint.
pub fn free_port() -> u16 {
    let reservation = reserve_loopback_pair();
    reservation.dns_port
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
    pub fn minimal_auth(dns_port: u16, obs_port: u16, origin: &str, zone_path: &Path) -> String {
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
        let hints_str = root_hints_path
            .to_str()
            .expect("hints path must be valid UTF-8");
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
        let hints_str = root_hints_path
            .to_str()
            .expect("hints path must be valid UTF-8");
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
        let hints_str = root_hints_path
            .to_str()
            .expect("hints path must be valid UTF-8");
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
        let key_str = key_path.to_str().expect("key path must be valid UTF-8");
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
        let hints_str = root_hints_path
            .to_str()
            .expect("hints path must be valid UTF-8");
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
        let hints_str = root_hints_path
            .to_str()
            .expect("hints path must be valid UTF-8");
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
    /// Spawn the daemon with a port pair drawn from a [`PortReservation`],
    /// release the sentinel sockets immediately before spawning, wait for
    /// `/readyz` to return 200, then drop the reservation (releasing the
    /// host-wide spawn lock).
    ///
    /// `build_toml` receives `(dns_port, obs_port)` and must produce the TOML
    /// config string.  `which` is a short label included in the panic message
    /// on readiness timeout so the caller can be identified in CI logs.
    ///
    /// # Panics
    ///
    /// Panics if the daemon does not become ready within `timeout`.
    fn spawn_with_reservation<F>(
        bin: &str,
        which: &'static str,
        timeout: Duration,
        build_toml: F,
    ) -> Self
    where
        F: FnOnce(u16, u16) -> String,
    {
        let mut reservation = reserve_loopback_pair();
        let dns_port = reservation.dns_port;
        let obs_port = reservation.obs_port;
        let toml = build_toml(dns_port, obs_port);
        // Release the sentinel sockets just before spawn so the daemon can
        // bind.  The spawn lock is still held — no other test on the host
        // can be in its own release_sockets→bind window simultaneously.
        reservation.release_sockets();
        let server = Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(timeout)
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::{which}: server on dns_port={} did not become ready within {timeout:?}",
                    s.dns_port
                )
            });
        // Drop the reservation now that the daemon owns the ports; this
        // releases the host-wide spawn lock for the next reservation.
        drop(reservation);
        server
    }

    /// Spawn an authoritative server serving `zone_path` as `origin` and wait
    /// up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_auth(bin: &str, origin: &str, zone_path: &Path) -> Self {
        Self::spawn_with_reservation(bin, "start_auth", Duration::from_secs(2), |dns, obs| {
            config::minimal_auth(dns, obs, origin, zone_path)
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
        // dns_port is caller-supplied (not from the reservation) so we keep
        // the legacy obs_port path here.  The reservation primarily exists
        // to serialise the spawn window across processes.
        let mut reservation = reserve_loopback_pair();
        let obs_port = reservation.obs_port;
        let toml = config::minimal_auth_on_addr(dns_addr, dns_port, obs_port, origin, zone_path);
        reservation.release_sockets();
        let server = Self::start_with_ports(bin, &toml, dns_port, obs_port)
            .wait_ready(Duration::from_secs(2))
            .unwrap_or_else(|s| {
                panic!(
                    "TestServer::start_auth_on_addr: server on {dns_addr}:{} did not become ready within 2s",
                    s.dns_port
                )
            });
        drop(reservation);
        server
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
        Self::spawn_with_reservation(
            bin,
            "start_auth_with_tsig",
            Duration::from_secs(2),
            |dns, obs| {
                config::minimal_auth_with_tsig(
                    dns, obs, origin, zone_path, key_name, algorithm, secret_b64,
                )
            },
        )
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
        Self::spawn_with_reservation(bin, "start_auth_dot", Duration::from_secs(2), |dns, obs| {
            config::minimal_auth_dot(dns, obs, origin, zone_path, cert_path, key_path)
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
        Self::spawn_with_reservation(
            bin,
            "start_auth_doh2",
            Duration::from_secs(2),
            |dns, obs| config::minimal_auth_doh2(dns, obs, origin, zone_path, cert_path, key_path),
        )
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
        Self::spawn_with_reservation(
            bin,
            "start_auth_doh3",
            Duration::from_secs(2),
            |dns, obs| config::minimal_auth_doh3(dns, obs, origin, zone_path, cert_path, key_path),
        )
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
        Self::spawn_with_reservation(bin, "start_auth_doq", Duration::from_secs(2), |dns, obs| {
            config::minimal_auth_doq(dns, obs, origin, zone_path, cert_path, key_path)
        })
    }

    /// Spawn an authoritative secondary server for `origin`, pulling from
    /// `primary_addr`, and wait up to 3 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 3 seconds.
    pub fn start_secondary(bin: &str, origin: &str, primary_addr: std::net::SocketAddr) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_secondary",
            Duration::from_secs(3),
            |dns, obs| config::minimal_secondary(dns, obs, origin, primary_addr),
        )
    }

    /// Spawn a recursive resolver and wait up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_recursive(bin: &str) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_recursive",
            Duration::from_secs(2),
            config::minimal_recursive,
        )
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoT
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_dot(bin: &str, upstream_port: u16) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_forwarder_dot",
            Duration::from_secs(2),
            |dns, obs| config::minimal_forwarder_dot(dns, obs, "127.0.0.1", upstream_port),
        )
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoH/H2
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doh2(bin: &str, upstream_port: u16) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_forwarder_doh2",
            Duration::from_secs(2),
            |dns, obs| config::minimal_forwarder_doh2(dns, obs, "127.0.0.1", upstream_port),
        )
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoH/H3
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doh3(bin: &str, upstream_port: u16) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_forwarder_doh3",
            Duration::from_secs(2),
            |dns, obs| config::minimal_forwarder_doh3(dns, obs, "127.0.0.1", upstream_port),
        )
    }

    /// Spawn a forwarder that proxies all queries to `upstream_port` over DoQ (RFC 9250)
    /// with `tls_verify = false`.  Waits up to 2 seconds for readiness.
    ///
    /// # Panics
    ///
    /// Panics if the server does not become ready within 2 seconds.
    pub fn start_forwarder_doq(bin: &str, upstream_port: u16) -> Self {
        Self::spawn_with_reservation(
            bin,
            "start_forwarder_doq",
            Duration::from_secs(2),
            |dns, obs| config::minimal_forwarder_doq(dns, obs, "127.0.0.1", upstream_port),
        )
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
    pub const KEY_SECRET_B64: &str = "SGVpbWRhbGxUZXN0VFNJR0tleUhNQUNTSEEyNTYyMDI=";

    /// Raw test key bytes (32 bytes, deterministic).
    pub const KEY_BYTES: &[u8; 32] = b"HeimdallTestTSIGKeyHMACSHA256202";
}

extern crate libc;
