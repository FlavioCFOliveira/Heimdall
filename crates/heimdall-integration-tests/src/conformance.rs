// SPDX-License-Identifier: MIT

//! Hand-rolled Docker container harness for conformance reference implementations
//! (Sprint 49 task #492, ENG-035).
//!
//! Provides one `start_*` builder per reference implementation:
//!
//! | Builder | Image | Role |
//! |---|---|---|
//! | [`start_nsd`] | nlnetlabs/nsd:4.8.1 | Authoritative |
//! | [`start_knot_auth`] | cznic/knot:3.3.7 | Authoritative |
//! | [`start_knot_resolver`] | cznic/knot-resolver:5.7.4 | Recursive |
//! | [`start_unbound`] | mvance/unbound:1.21.1 | Recursive |
//! | [`start_powerdns_auth`] | powerdns/pdns-auth-49 | Authoritative |
//! | [`start_powerdns_recursor`] | powerdns/pdns-recursor-50 | Recursive |
//! | [`start_coredns`] | coredns/coredns:1.11.3 | Forwarder |
//!
//! Image tags are listed in `tests/conformance/digests.lock`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use heimdall_integration_tests::conformance;
//!
//! if !conformance::docker_available() {
//!     return; // skip in environments without Docker
//! }
//!
//! let zone = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/conformance/example.test.zone");
//! let nsd = conformance::start_nsd(std::path::Path::new(zone));
//! // query nsd.dns_addr ...
//! // container stops when `nsd` is dropped
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    net::{SocketAddr, UdpSocket},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
// ── Public interface ─────────────────────────────────────────────────────────

/// Returns `true` when a Docker daemon socket is present in the current environment.
///
/// Tests that call [`start_nsd`] or similar builders should call this first and
/// return early (not panic) when Docker is absent — running containers is
/// optional in developer workstations and CI environments that do not mount Docker.
///
/// Checks socket files rather than spawning `docker info` to avoid introducing
/// child processes that interfere with the `hardening_nopriv` process-tree tests.
pub fn docker_available() -> bool {
    // Respect the DOCKER_HOST override first.
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if host.starts_with("unix://") {
            let path = host.trim_start_matches("unix://");
            return std::path::Path::new(path).exists();
        }
        return true; // TCP host configured — assume reachable
    }
    // Standard socket locations (Linux + macOS Docker Desktop).
    let candidates = ["/var/run/docker.sock", "/run/docker.sock"];
    if candidates.iter().any(|p| std::path::Path::new(p).exists()) {
        return true;
    }
    // macOS Docker Desktop user-scoped socket.
    if let Some(home) = std::env::var_os("HOME") {
        let user_sock = std::path::Path::new(&home).join(".docker/run/docker.sock");
        if user_sock.exists() {
            return true;
        }
    }
    false
}

/// A running reference-implementation container.
///
/// The container is stopped (with a 5-second grace period) when this value
/// is dropped.  Tests should hold this value for the duration of the test
/// to keep the container alive.
pub struct RefContainer {
    id: String,
    /// Host `SocketAddr` at which the container's DNS/53 UDP port is reachable.
    pub dns_addr: SocketAddr,
}

/// Start an NSD authoritative server pre-loaded with `zone_path`.
///
/// `zone_path` must be an absolute path to a zone file for `example.test.`.
pub fn start_nsd(zone_path: &Path) -> RefContainer {
    let vol = format!(
        "{}:/etc/nsd/zones/example.test.zone:ro",
        zone_path.display()
    );
    RefContainer::start("nlnetlabs/nsd:4.8.1", 53, &["-v", &vol])
}

/// Start a Knot DNS authoritative server pre-loaded with `zone_path`.
pub fn start_knot_auth(zone_path: &Path) -> RefContainer {
    let vol = format!("{}:/storage/example.test.zone:ro", zone_path.display());
    RefContainer::start("cznic/knot:3.3.7", 53, &["-v", &vol])
}

/// Start a Knot Resolver (recursive).
pub fn start_knot_resolver() -> RefContainer {
    RefContainer::start("cznic/knot-resolver:5.7.4", 53, &[])
}

/// Start an Unbound recursive resolver.
pub fn start_unbound() -> RefContainer {
    RefContainer::start("mvance/unbound:1.21.1", 53, &[])
}

/// Start a PowerDNS Authoritative server pre-loaded with `zone_path`.
pub fn start_powerdns_auth(zone_path: &Path) -> RefContainer {
    let vol = format!(
        "{}:/etc/powerdns/zones/example.test.zone:ro",
        zone_path.display()
    );
    RefContainer::start("powerdns/pdns-auth-49:latest", 53, &["-v", &vol])
}

/// Start a PowerDNS Recursor (recursive).
pub fn start_powerdns_recursor() -> RefContainer {
    RefContainer::start("powerdns/pdns-recursor-50:latest", 53, &[])
}

/// Start a CoreDNS forwarder that forwards all queries to `upstream`.
pub fn start_coredns(upstream: SocketAddr) -> RefContainer {
    let corefile = format!(". {{\n  forward . {upstream}\n  log\n}}\n");
    let vol = format!("/dev/stdin:/etc/coredns/Corefile:ro");
    let _ = vol; // CoreDNS requires the Corefile via env or stdin trick
    // Simpler: write Corefile to a temp file, mount it
    let tmp = std::env::temp_dir().join("heimdall-coredns-corefile");
    std::fs::write(&tmp, corefile.as_bytes()).expect("write Corefile");
    let vol = format!("{}:/etc/coredns/Corefile:ro", tmp.display());
    RefContainer::start(
        "coredns/coredns:1.11.3",
        53,
        &["-v", &vol, "-conf", "/etc/coredns/Corefile"],
    )
}

// ── Internal implementation ───────────────────────────────────────────────────

impl RefContainer {
    fn start(image: &str, container_port: u16, extra_args: &[&str]) -> Self {
        let port_spec = format!("0:{container_port}/udp");
        let mut args: Vec<&str> = vec!["run", "-d", "--rm", "-p", &port_spec];
        args.extend_from_slice(extra_args);
        args.push(image);

        let out = Command::new("docker")
            .args(&args)
            .output()
            .expect("docker run");
        assert!(
            out.status.success(),
            "docker run {image} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout)
            .expect("container id")
            .trim()
            .to_owned();

        let host_port = resolve_host_port(&id, container_port);
        let dns_addr: SocketAddr = format!("127.0.0.1:{host_port}").parse().expect("dns_addr");

        wait_until_dns_ready(dns_addr, Duration::from_secs(10));

        RefContainer { id, dns_addr }
    }
}

impl Drop for RefContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["stop", "--time", "5", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }
}

/// Ask Docker for the host port that was mapped to `container_port/udp`.
fn resolve_host_port(container_id: &str, container_port: u16) -> u16 {
    let out = Command::new("docker")
        .args(["port", container_id, &format!("{container_port}/udp")])
        .output()
        .expect("docker port");
    let output = String::from_utf8(out.stdout).expect("docker port output");
    // Output format: "0.0.0.0:49201\n:::49201\n"
    // Extract the port from the first IPv4 line.
    output
        .lines()
        .find(|l| l.starts_with("0.0.0.0:"))
        .and_then(|l| l.split(':').next_back())
        .and_then(|p| p.parse().ok())
        .expect("host udp port")
}

/// Polls the DNS server at `addr` via UDP until it responds or `timeout` elapses.
///
/// Sends a minimal DNS query for `. IN NS` and considers any parseable reply
/// as proof that the server is ready.
fn wait_until_dns_ready(addr: SocketAddr, timeout: Duration) {
    // Minimal wire query: ID=1, RD=1, QDCOUNT=1, root NS IN
    let query: &[u8] = &[
        0x00, 0x01, // ID
        0x01, 0x00, // flags: RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x00, // root label
        0x00, 0x02, // QTYPE=NS
        0x00, 0x01, // QCLASS=IN
    ];

    let deadline = Instant::now() + timeout;
    loop {
        let sock = UdpSocket::bind("0.0.0.0:0").expect("probe socket");
        sock.set_read_timeout(Some(Duration::from_millis(300))).ok();
        if sock.send_to(query, addr).is_ok() {
            let mut buf = [0u8; 512];
            if sock.recv(&mut buf).is_ok() {
                return; // server responded
            }
        }
        if Instant::now() >= deadline {
            panic!("conformance container at {addr} did not become ready within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
