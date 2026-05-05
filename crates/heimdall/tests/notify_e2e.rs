// SPDX-License-Identifier: MIT

//! E2E: NOTIFY inbound triggers secondary refresh; outbound from primary on startup
//! (Sprint 47 task #592, PROTO-038, RFC 1996).
//!
//! Two sub-cases:
//!
//! (a) Outbound NOTIFY: primary emits NOTIFY to each address in
//!     `notify_secondaries` on startup (RFC 1996 §3.7).  A mock UDP listener
//!     captures the packet and ACKs it; the test verifies the opcode and qtype.
//!
//! (b) Inbound NOTIFY: a secondary with a long REFRESH timer (3600 s) receives
//!     a NOTIFY after the primary zone is updated.  The secondary issues an
//!     immediate refresh pull and reaches the new serial well within the REFRESH
//!     window (verified with a 3-second deadline).

#![cfg(unix)]

use std::{
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const ZONE_ORIGIN: &str = "notify-test.test.";

/// Zone at serial 1 with a long REFRESH (3600 s) to force timer-based refresh
/// out of the test window — only a NOTIFY will trigger an early pull.
const ZONE_SERIAL_1: &str = r#"; notify-test.test. — serial 1
$ORIGIN notify-test.test.
$TTL 300

@   IN SOA ns1 hostmaster (
            1      ; serial
            3600   ; refresh (1 h — long, so only NOTIFY triggers fast pull)
            60     ; retry
            604800 ; expire
            300 )  ; minimum

@    IN NS   ns1
ns1  IN A    127.0.0.1
host IN A    192.0.2.1
"#;

/// Zone at serial 2 — used after the primary zone update.
const ZONE_SERIAL_2: &str = r#"; notify-test.test. — serial 2
$ORIGIN notify-test.test.
$TTL 300

@   IN SOA ns1 hostmaster (
            2      ; serial
            3600   ; refresh
            60     ; retry
            604800 ; expire
            300 )  ; minimum

@    IN NS   ns1
ns1  IN A    127.0.0.1
host IN A    192.0.2.2
"#;

// ── Mock NOTIFY listener ──────────────────────────────────────────────────────

/// In-process UDP listener that ACKs incoming NOTIFY packets and records them.
struct NotifyCapture {
    packets: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl NotifyCapture {
    fn start(addr: SocketAddr) -> Self {
        let sock =
            UdpSocket::bind(addr).unwrap_or_else(|e| panic!("NotifyCapture: bind {addr}: {e}"));
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set_read_timeout");
        let bound_addr = sock.local_addr().expect("local_addr");
        let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_packets = Arc::clone(&packets);
        let thread_stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !thread_stop.load(Ordering::Relaxed) {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let pkt = buf[..n].to_vec();
                        // Send ACK: echo with QR=1 set so the primary counts it acknowledged.
                        if n >= 4 {
                            let mut ack = pkt.clone();
                            ack[2] |= 0x80; // QR=1
                            ack[3] &= 0xF0; // RCODE=0 (NOERROR)
                            let _ = sock.send_to(&ack, src);
                        }
                        thread_packets
                            .lock()
                            .expect("NotifyCapture mutex")
                            .push(pkt);
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => return,
                }
            }
        });

        let _ = bound_addr;
        Self { packets, stop }
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.packets.lock().expect("NotifyCapture mutex").clone()
    }
}

impl Drop for NotifyCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Parse opcode from DNS flags bytes (bytes 2-3 of the wire message).
fn opcode_from_wire(pkt: &[u8]) -> u8 {
    if pkt.len() < 3 {
        return 0xFF;
    }
    (pkt[2] >> 3) & 0x0F
}

/// Parse QTYPE from the question section of a DNS message (first question).
fn qtype_from_wire(pkt: &[u8]) -> u16 {
    if pkt.len() < 12 {
        return 0;
    }
    let mut pos = 12;
    loop {
        if pos >= pkt.len() {
            return 0;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > pkt.len() {
            return 0;
        }
        pos += 1 + len;
    }
    if pos + 2 > pkt.len() {
        return 0;
    }
    u16::from_be_bytes([pkt[pos], pkt[pos + 1]])
}

// ── (a) Outbound NOTIFY on primary startup ───────────────────────────────────

/// On startup, the primary sends NOTIFY to every address in `notify_secondaries`.
///
/// Verifies (RFC 1996 §3.7):
/// - At least one packet is received at the mock listener within 2 s.
/// - The packet carries opcode=4 (NOTIFY).
/// - The first question is qtype=SOA (6).
#[test]
fn primary_sends_notify_to_secondaries_on_startup() {
    // Bind the mock listener BEFORE starting the primary so the port is
    // open and ready when the primary tries to connect.
    let capture_port = free_port();
    let capture_addr: SocketAddr = format!("127.0.0.1:{capture_port}").parse().unwrap();
    let capture = NotifyCapture::start(capture_addr);

    let dns_port = free_port();
    let obs_port = free_port();

    // Write zone at serial 1 to a temp file.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let zone_path = dir.path().join("notify-test.test.zone");
    std::fs::write(&zone_path, ZONE_SERIAL_1).expect("write zone");

    let toml = config::minimal_primary_with_notify(
        dns_port,
        obs_port,
        ZONE_ORIGIN,
        &zone_path,
        capture_addr,
    );
    let _primary = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(3))
        .unwrap_or_else(|s| panic!("primary did not become ready on dns_port={}", s.dns_port));

    // Wait up to 2 s for the outbound NOTIFY to arrive at the capture socket.
    let deadline = Instant::now() + Duration::from_secs(2);
    let notify_pkt = loop {
        let pkts = capture.received();
        if let Some(pkt) = pkts.into_iter().find(|p| opcode_from_wire(p) == 4) {
            break Some(pkt);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let pkt = notify_pkt
        .expect("primary did not emit a NOTIFY to notify_secondaries within 2 s of startup");
    assert_eq!(
        opcode_from_wire(&pkt),
        4,
        "NOTIFY packet must have opcode=4 (NOTIFY); got {}",
        opcode_from_wire(&pkt),
    );
    assert_eq!(
        qtype_from_wire(&pkt),
        6,
        "NOTIFY question must be qtype=SOA (6); got {}",
        qtype_from_wire(&pkt),
    );
}

// ── (b) Inbound NOTIFY wakes secondary refresh loop ──────────────────────────

/// An inbound NOTIFY triggers an immediate zone refresh on the secondary,
/// bypassing the long SOA REFRESH timer (3600 s).
///
/// The primary's in-memory zone is immutable after startup (hot-reload of zone
/// data is deferred to the Redis sprint).  To present the secondary with a
/// higher serial, Primary-1 (serial 1) is gracefully stopped and a fresh
/// Primary-2 (serial 2) is bound on the same port before the NOTIFY is sent.
///
/// Procedure:
/// 1. Start Primary-1 at serial 1 on port P.
/// 2. Start secondary → initial AXFR → serial 1 → sleeping for 3600 s.
/// 3. Gracefully stop Primary-1; wait briefly for the port to be released.
/// 4. Start Primary-2 at serial 2 on the same port P; wait for readiness.
/// 5. Send a NOTIFY to the secondary's DNS port.
/// 6. Verify the secondary reaches serial 2 within 4 s (not 3600 s).
#[test]
fn inbound_notify_triggers_immediate_refresh() {
    let dns_port = free_port();
    let dir = tempfile::TempDir::new().expect("tempdir");

    // ── Step 1: start Primary-1 at serial 1 ──────────────────────────────────
    let obs_port_1 = free_port();
    let zone_path_1 = dir.path().join("notify-test.test.v1.zone");
    std::fs::write(&zone_path_1, ZONE_SERIAL_1).expect("write zone serial 1");

    let toml_1 = auth_primary_toml(dns_port, obs_port_1, ZONE_ORIGIN, &zone_path_1);
    let primary_1 = TestServer::start_with_ports(BIN, &toml_1, dns_port, obs_port_1)
        .wait_ready(Duration::from_secs(3))
        .unwrap_or_else(|s| panic!("Primary-1 did not become ready on dns_port={}", s.dns_port));

    let primary_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

    // ── Step 2: start secondary, wait for serial 1 ───────────────────────────
    let secondary = TestServer::start_secondary(BIN, ZONE_ORIGIN, primary_addr);
    let initial_ok = poll_serial(&secondary, ZONE_ORIGIN, 1, Duration::from_secs(5));
    assert!(
        initial_ok,
        "secondary did not reach serial 1 within 5 s after initial AXFR"
    );

    // ── Step 3: stop Primary-1 and let OS release the port ───────────────────
    drop(primary_1);
    // Give the OS a moment to fully release the port (SO_REUSEPORT helps, but
    // a small sleep avoids any EADDRINUSE race during the bind of Primary-2).
    std::thread::sleep(Duration::from_millis(250));

    // ── Step 4: start Primary-2 at serial 2 on the same port ─────────────────
    let obs_port_2 = free_port();
    let zone_path_2 = dir.path().join("notify-test.test.v2.zone");
    std::fs::write(&zone_path_2, ZONE_SERIAL_2).expect("write zone serial 2");

    let toml_2 = auth_primary_toml(dns_port, obs_port_2, ZONE_ORIGIN, &zone_path_2);
    let _primary_2 = TestServer::start_with_ports(BIN, &toml_2, dns_port, obs_port_2)
        .wait_ready(Duration::from_secs(3))
        .unwrap_or_else(|s| panic!("Primary-2 did not become ready on dns_port={}", s.dns_port));

    // ── Step 5: send NOTIFY to secondary ─────────────────────────────────────
    let notify_resp = dns_client::send_notify_udp(secondary.dns_addr(), ZONE_ORIGIN);
    assert_eq!(
        notify_resp.rcode, 0,
        "secondary must ACK NOTIFY with RCODE=NOERROR (0); got {}",
        notify_resp.rcode,
    );
    assert_eq!(
        notify_resp.opcode, 4,
        "NOTIFY ACK must have opcode=4 (NOTIFY); got {}",
        notify_resp.opcode,
    );

    // ── Step 6: secondary must reach serial 2 quickly (not after 3600 s) ─────
    let refreshed = poll_serial(&secondary, ZONE_ORIGIN, 2, Duration::from_secs(4));
    assert!(
        refreshed,
        "secondary did not reach serial 2 within 4 s after NOTIFY — \
         inbound NOTIFY must trigger immediate refresh (PROTO-038)"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Poll `server` for the SOA serial of `qname` until it matches `expected` or
/// timeout expires.
fn poll_serial(server: &TestServer, qname: &str, expected: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(s) = dns_client::query_soa_serial(server.dns_addr(), qname) {
            if s == expected {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Minimal authoritative-primary TOML config (no notify_secondaries, TSIG enabled).
///
/// Used for the inbound-NOTIFY test where we manually send NOTIFY from the test,
/// not from the primary itself.
fn auth_primary_toml(dns_port: u16, obs_port: u16, origin: &str, zone_path: &Path) -> String {
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
origin    = "{origin}"
path      = "{path_str}"
zone_role = "primary"
tsig_key_name      = "{key_name}"
tsig_algorithm     = "{algorithm}"
tsig_secret_base64 = "{secret_b64}"
"#,
        key_name = tsig::KEY_NAME,
        algorithm = tsig::ALGORITHM,
        secret_b64 = tsig::KEY_SECRET_B64,
    )
}
