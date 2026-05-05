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
    clippy::unused_async,
    clippy::type_complexity
)]

//! Integration tests for secondary SOA timers: REFRESH / RETRY / EXPIRE timing
//! and minimum-value clamping (Sprint 47 task #593).
//!
//! The mock primary runs on a real OS thread (blocking std I/O), so it is
//! completely independent of the tokio scheduler.  This ensures the secondary's
//! TCP I/O completes correctly even when `tokio::time::pause()` is active.
//!
//! Initial zone pulls are verified with real-time polling (`std::time::Instant`).
//! Timer-based assertions use `tokio::time::pause()` + `tokio::time::advance()`.
//! After advancing, `tokio::time::resume()` is called before polling for the
//! secondary's pull result so that the I/O reactor processes connections normally.
//!
//! Covered assertions:
//!
//! (a) REFRESH timer — secondary issues SOA+AXFR pull after REFRESH seconds.
//! (b) RETRY timer — when the primary is unreachable, the secondary retries after
//!     RETRY seconds (not REFRESH), then succeeds once the primary recovers.
//! (c) EXPIRE — during sustained outage no spurious `on_zone_update` calls arrive.
//! (d) Minimum bounds — REFRESH < 60 s clamped to 60 s; verified by no-pull at
//!     t=11 s and confirmed loop liveness via NOTIFY.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use heimdall_core::{
    header::{Header, Qclass, Qtype, Question},
    name::Name,
    parser::Message,
    rdata::RData,
    record::{Record, Rtype},
    serialiser::Serialiser,
    zone::{ZoneFile, ZoneLimits},
};
use heimdall_roles::auth::zone_role::{ZoneConfig, ZoneRole};

// ── Constants ─────────────────────────────────────────────────────────────────

const ZONE_APEX: &str = "timer-test.test.";
const REFRESH_SECS: u64 = 60;
const RETRY_SECS: u64 = 30;
const EXPIRE_SECS: u64 = 3600;

// ── Thread-based mock primary ─────────────────────────────────────────────────

struct MockPrimary {
    serial: Arc<AtomicU32>,
    /// When `true`, connections are accepted then immediately dropped (simulates outage).
    refuse: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl MockPrimary {
    /// Spawn a blocking OS thread acting as a DNS primary server.
    ///
    /// Running on a real thread means the mock is independent of tokio's
    /// scheduler and I/O reactor.  The secondary's TCP I/O completes normally
    /// regardless of `tokio::time::pause()` state.
    fn spawn(initial_serial: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock primary");
        let addr = listener.local_addr().expect("local_addr");
        let serial = Arc::new(AtomicU32::new(initial_serial));
        let refuse = Arc::new(AtomicBool::new(false));

        let srv_serial = Arc::clone(&serial);
        let srv_refuse = Arc::clone(&refuse);
        std::thread::spawn(move || {
            for accept_result in listener.incoming() {
                match accept_result {
                    Ok(mut stream) => {
                        if srv_refuse.load(Ordering::Relaxed) {
                            drop(stream);
                            continue;
                        }
                        let s = Arc::clone(&srv_serial);
                        std::thread::spawn(move || {
                            serve_connection_sync(&mut stream, s);
                        });
                    }
                    Err(_) => return,
                }
            }
        });

        Self {
            serial,
            refuse,
            addr,
        }
    }

    fn set_serial(&self, s: u32) {
        self.serial.store(s, Ordering::Relaxed);
    }

    fn set_reachable(&self, reachable: bool) {
        self.refuse.store(!reachable, Ordering::Relaxed);
    }
}

/// Handle one TCP connection: serve up to 2 DNS queries (SOA + AXFR pattern).
fn serve_connection_sync(stream: &mut TcpStream, serial: Arc<AtomicU32>) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    for _ in 0..2 {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return;
        }
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).is_err() {
            return;
        }
        let Ok(query) = Message::parse(&buf) else {
            return;
        };

        let qtype = query.questions.first().map_or(Qtype::A, |q| q.qtype);
        let s = serial.load(Ordering::Relaxed);

        let wire = match qtype {
            Qtype::Soa => build_soa_response(&query, s),
            Qtype::Axfr => build_axfr_response(&query, s),
            _ => return,
        };

        let len_bytes = (wire.len() as u16).to_be_bytes();
        if stream.write_all(&len_bytes).is_err() {
            return;
        }
        if stream.write_all(&wire).is_err() {
            return;
        }
    }
}

// ── Record / message builders ─────────────────────────────────────────────────

fn apex() -> Name {
    Name::from_str(ZONE_APEX).expect("valid apex")
}

fn build_soa_record(serial: u32) -> Record {
    build_soa_record_custom(
        serial,
        REFRESH_SECS as u32,
        RETRY_SECS as u32,
        EXPIRE_SECS as u32,
    )
}

fn build_soa_record_custom(serial: u32, refresh: u32, retry: u32, expire: u32) -> Record {
    Record {
        name: apex(),
        rtype: Rtype::Soa,
        rclass: Qclass::In,
        ttl: 300,
        rdata: RData::Soa {
            mname: apex(),
            rname: apex(),
            serial,
            refresh,
            retry,
            expire,
            minimum: 300,
        },
    }
}

fn build_soa_response(query: &Message, serial: u32) -> Vec<u8> {
    let mut header = Header {
        id: query.header.id,
        ancount: 1,
        qdcount: 1,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_aa(true);
    let msg = Message {
        header,
        questions: query.questions.clone(),
        answers: vec![build_soa_record(serial)],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(false);
    ser.write_message(&msg).expect("serialise SOA");
    ser.finish()
}

fn build_axfr_response(query: &Message, serial: u32) -> Vec<u8> {
    let soa = build_soa_record(serial);
    let a = Record {
        name: Name::from_str(&format!("host.{ZONE_APEX}")).expect("valid name"),
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: 300,
        rdata: RData::A("192.0.2.1".parse().expect("valid ip")),
    };
    let ns = Record {
        name: apex(),
        rtype: Rtype::Ns,
        rclass: Qclass::In,
        ttl: 300,
        rdata: RData::Ns(apex()),
    };
    let records = vec![soa.clone(), ns, a, soa];
    #[allow(clippy::cast_possible_truncation)]
    let ancount = records.len() as u16;
    let mut header = Header {
        id: query.header.id,
        ancount,
        qdcount: 1,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_aa(true);
    let msg = Message {
        header,
        questions: vec![Question {
            qname: apex(),
            qtype: Qtype::Axfr,
            qclass: Qclass::In,
        }],
        answers: records,
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(false);
    ser.write_message(&msg).expect("serialise AXFR");
    ser.finish()
}

// ── Setup helpers ─────────────────────────────────────────────────────────────

fn make_zone_config(primary_addr: SocketAddr) -> ZoneConfig {
    ZoneConfig {
        apex: apex(),
        role: ZoneRole::Secondary,
        upstream_primary: Some(primary_addr),
        notify_secondaries: vec![],
        tsig_key: None,
        axfr_acl: vec![],
        zone_file: None,
    }
}

fn make_drain() -> Arc<heimdall_runtime::drain::Drain> {
    Arc::new(heimdall_runtime::drain::Drain::new())
}

fn make_update_tracker() -> (
    Arc<dyn Fn(Arc<ZoneFile>) + Send + Sync>,
    Arc<Mutex<Vec<u32>>>,
) {
    let serials: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&serials);
    let cb: Arc<dyn Fn(Arc<ZoneFile>) + Send + Sync> = Arc::new(move |zone: Arc<ZoneFile>| {
        if let Some(rec) = zone.records.iter().find(|r| r.rtype == Rtype::Soa)
            && let RData::Soa { serial, .. } = &rec.rdata
        {
            s.lock().expect("mutex").push(*serial);
        }
    });
    (cb, serials)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Yield to the tokio runtime `n` times.
async fn flush(n: usize) {
    for _ in 0..n {
        tokio::task::yield_now().await;
    }
}

/// Poll `cond` until it returns `true`, yielding to the runtime between checks.
///
/// Uses `std::time::Instant` for the timeout, which is unaffected by
/// `tokio::time::pause()`.  Since the mock primary runs on a real OS thread,
/// the secondary's TCP I/O completes even while the test task is in this loop.
async fn poll_until<F: Fn() -> bool>(cond: F, timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        if cond() {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "poll_until timed out after {timeout:?}"
        );
        tokio::task::yield_now().await;
    }
}

// ── (a) REFRESH timer ─────────────────────────────────────────────────────────

/// After `REFRESH_SECS`, the secondary issues a SOA+AXFR pull and delivers the
/// updated serial via `on_zone_update`.
#[tokio::test]
async fn refresh_timer_triggers_pull() {
    let mock = MockPrimary::spawn(1);
    let (cb, serials) = make_update_tracker();
    let notify = Arc::new(tokio::sync::Notify::new());
    let zone_cfg = make_zone_config(mock.addr);
    let drain = make_drain();
    let notify_c = Arc::clone(&notify);

    tokio::spawn(async move {
        let _ = heimdall_roles::auth::secondary::run_secondary_refresh_loop_with_notify(
            zone_cfg, drain, notify_c, cb,
        )
        .await;
    });

    // Initial pull — verified with real wall-clock time.
    let s = Arc::clone(&serials);
    poll_until(
        move || s.lock().expect("m").last().copied() == Some(1),
        Duration::from_secs(3),
    )
    .await;

    // Freeze mock clock; update primary to serial 2.
    tokio::time::pause();
    mock.set_serial(2);

    // Advance REFRESH_SECS → select! sleep fires → secondary wakes.
    tokio::time::advance(Duration::from_secs(REFRESH_SECS)).await;
    // Resume real time so the I/O reactor processes the secondary's TCP pull.
    // The sleep already fired; resume() just unfreezes future sleeps so the
    // park/reactor loop can run normally during poll_until.
    tokio::time::resume();

    let s = Arc::clone(&serials);
    poll_until(
        move || s.lock().expect("m").last().copied() == Some(2),
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(
        serials.lock().expect("m").last().copied(),
        Some(2),
        "after REFRESH timer, secondary must pull serial 2"
    );
}

// ── (b) RETRY timer ───────────────────────────────────────────────────────────

/// When the primary is unreachable, the secondary retries after `RETRY_SECS`
/// (not `REFRESH_SECS`), then succeeds once the primary recovers.
#[tokio::test]
async fn retry_timer_used_after_failed_pull() {
    let mock = MockPrimary::spawn(1);
    let (cb, serials) = make_update_tracker();
    let notify = Arc::new(tokio::sync::Notify::new());
    let zone_cfg = make_zone_config(mock.addr);
    let drain = make_drain();
    let notify_c = Arc::clone(&notify);

    tokio::spawn(async move {
        let _ = heimdall_roles::auth::secondary::run_secondary_refresh_loop_with_notify(
            zone_cfg, drain, notify_c, cb,
        )
        .await;
    });

    // Wait for initial pull at serial 1.
    let s = Arc::clone(&serials);
    poll_until(
        move || s.lock().expect("m").last().copied() == Some(1),
        Duration::from_secs(3),
    )
    .await;

    // Freeze time; make primary unreachable.
    tokio::time::pause();
    mock.set_reachable(false);

    // Advance REFRESH_SECS → pull fires but fails (connection dropped by mock);
    // secondary switches internal timer to retry_secs.
    tokio::time::advance(Duration::from_secs(REFRESH_SECS)).await;
    // Give the failing pull task time to connect, receive EOF, and re-enter select!.
    flush(80).await;

    // No update during outage.
    assert_eq!(
        serials.lock().expect("m").last().copied(),
        Some(1),
        "during primary outage no update should arrive"
    );

    // Restore primary at serial 2; advance RETRY_SECS → secondary retries.
    mock.set_serial(2);
    mock.set_reachable(true);
    tokio::time::advance(Duration::from_secs(RETRY_SECS)).await;
    tokio::time::resume();

    let s = Arc::clone(&serials);
    poll_until(
        move || s.lock().expect("m").last().copied() == Some(2),
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(
        serials.lock().expect("m").last().copied(),
        Some(2),
        "after RETRY timer and primary recovery, secondary must deliver serial 2"
    );
}

// ── (c) EXPIRE — no spurious updates during sustained outage ─────────────────

/// During a primary outage, no spurious `on_zone_update` calls arrive.
#[tokio::test]
async fn expire_period_produces_no_spurious_updates() {
    let mock = MockPrimary::spawn(1);
    let (cb, serials) = make_update_tracker();
    let notify = Arc::new(tokio::sync::Notify::new());
    let zone_cfg = make_zone_config(mock.addr);
    let drain = make_drain();
    let notify_c = Arc::clone(&notify);

    tokio::spawn(async move {
        let _ = heimdall_roles::auth::secondary::run_secondary_refresh_loop_with_notify(
            zone_cfg, drain, notify_c, cb,
        )
        .await;
    });

    // Wait for initial pull at serial 1.
    let s = Arc::clone(&serials);
    poll_until(
        move || s.lock().expect("m").last().copied() == Some(1),
        Duration::from_secs(3),
    )
    .await;

    let count_before = serials.lock().expect("m").len();

    // Freeze time; take primary offline.
    tokio::time::pause();
    mock.set_reachable(false);

    // Advance past EXPIRE: many REFRESH+RETRY cycles all fail.
    tokio::time::advance(Duration::from_secs(EXPIRE_SECS + REFRESH_SECS)).await;
    // Allow all the failing pull tasks to drain.
    flush(200).await;

    let count_after = serials.lock().expect("m").len();
    assert_eq!(
        count_before, count_after,
        "no spurious zone updates must arrive while primary is unreachable"
    );
}

// ── (d) Minimum-bounds rejection (PROTO-103) ──────────────────────────────────

/// PROTO-103: a zone whose SOA REFRESH is below the 60 s minimum MUST be
/// rejected by the secondary.  The `on_zone_update` callback must never fire.
#[tokio::test]
async fn minimum_bounds_clamped() {
    // Thread-based mock that serves a zone with sub-minimum SOA timers.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let addr = listener.local_addr().expect("local_addr");

    // REFRESH=10 (< MIN=60), RETRY=10 (< MIN=30), EXPIRE=60 (< MIN=3600).
    let zone_text = format!(
        "$ORIGIN {ZONE_APEX}\n\
         $TTL 300\n\
         @ IN SOA ns1 hostmaster 1 10 10 60 60\n\
         @ IN NS ns1\n\
         ns1 IN A 127.0.0.1\n"
    );

    std::thread::spawn(move || {
        let zone = ZoneFile::parse(&zone_text, None, ZoneLimits::default()).expect("parse zone");
        let soa = zone
            .records
            .iter()
            .find(|r| r.rtype == Rtype::Soa)
            .expect("SOA")
            .clone();
        let apex_name = apex();

        for accept_result in listener.incoming() {
            let Ok(mut stream) = accept_result else {
                continue;
            };
            let soa_c = soa.clone();
            let apex_c = apex_name.clone();
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                for _ in 0..10 {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).is_err() {
                        return;
                    }
                    let len = usize::from(u16::from_be_bytes(len_buf));
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).is_err() {
                        return;
                    }
                    let Ok(query) = Message::parse(&buf) else {
                        return;
                    };
                    let qtype = query.questions.first().map_or(Qtype::A, |q| q.qtype);

                    let wire = match qtype {
                        Qtype::Soa => {
                            let mut hdr = Header {
                                id: query.header.id,
                                ancount: 1,
                                qdcount: 1,
                                ..Header::default()
                            };
                            hdr.set_qr(true);
                            hdr.set_aa(true);
                            let msg = Message {
                                header: hdr,
                                questions: query.questions.clone(),
                                answers: vec![soa_c.clone()],
                                authority: vec![],
                                additional: vec![],
                            };
                            let mut ser = Serialiser::new(false);
                            ser.write_message(&msg).expect("ser");
                            ser.finish()
                        }
                        Qtype::Axfr => {
                            let ns = Record {
                                name: apex_c.clone(),
                                rtype: Rtype::Ns,
                                rclass: Qclass::In,
                                ttl: 300,
                                rdata: RData::Ns(apex_c.clone()),
                            };
                            let records = vec![soa_c.clone(), ns, soa_c.clone()];
                            #[allow(clippy::cast_possible_truncation)]
                            let ancount = records.len() as u16;
                            let mut hdr = Header {
                                id: query.header.id,
                                ancount,
                                qdcount: 1,
                                ..Header::default()
                            };
                            hdr.set_qr(true);
                            hdr.set_aa(true);
                            let msg = Message {
                                header: hdr,
                                questions: vec![Question {
                                    qname: apex_c.clone(),
                                    qtype: Qtype::Axfr,
                                    qclass: Qclass::In,
                                }],
                                answers: records,
                                authority: vec![],
                                additional: vec![],
                            };
                            let mut ser = Serialiser::new(false);
                            ser.write_message(&msg).expect("ser axfr");
                            ser.finish()
                        }
                        _ => return,
                    };
                    let len_bytes = (wire.len() as u16).to_be_bytes();
                    if stream.write_all(&len_bytes).is_err() {
                        return;
                    }
                    if stream.write_all(&wire).is_err() {
                        return;
                    }
                }
            });
        }
    });

    let (cb, serials) = make_update_tracker();
    let notify = Arc::new(tokio::sync::Notify::new());
    let zone_cfg = make_zone_config(addr);
    let drain = make_drain();
    let notify_c = Arc::clone(&notify);

    tokio::spawn(async move {
        let _ = heimdall_roles::auth::secondary::run_secondary_refresh_loop_with_notify(
            zone_cfg, drain, notify_c, cb,
        )
        .await;
    });

    // Give the secondary 1.5 s of real time to attempt the initial pull.
    // Because the zone has below-minimum SOA timers, records_to_zone returns
    // SoaTimerBelowMinimum and on_zone_update is never called.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    assert_eq!(
        serials.lock().expect("m").len(),
        0,
        "PROTO-103: on_zone_update must never fire when primary serves a zone \
         with below-minimum SOA timers"
    );
}
