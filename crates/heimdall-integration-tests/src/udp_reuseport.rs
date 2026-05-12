// SPDX-License-Identifier: MIT

//! `SO_REUSEPORT` UDP listener fan-out integration test (BIN-058, Sprint 67
//! task #676).
//!
//! Boots a 4-worker UDP listener on `127.0.0.1` via the production
//! [`heimdall_runtime::bind_reuseport_udp`] helper, fires 100 concurrent
//! queries from independent source ports, and asserts:
//!
//! 1. All 100 queries receive a well-formed DNS response (correct ID, QR=1).
//! 2. The kernel's reuseport hash demonstrably fans datagrams across more
//!    than one worker — captured via the per-worker datagram counter
//!    exposed by [`heimdall_runtime::UdpListener::counter`].
//!
//! ## Platform gating
//!
//! `SO_REUSEPORT` semantics on macOS / BSD do not match Linux (those
//! platforms do not load-balance across the reuseport group), so the test
//! gates itself with `#[cfg(target_os = "linux")]` and emits an
//! `eprintln!` skip on other platforms.
//!
//! ## On reliability of the "more than one worker" assertion
//!
//! The Linux reuseport hash is keyed on the connection's 4-tuple
//! `(src_ip, src_port, dst_ip, dst_port)`.  Sending 100 distinct source
//! ports therefore produces 100 different hash inputs.  Under that load
//! and with N = 4 workers, the probability that all 100 packets land on
//! a single worker — i.e. that the test falsely fails to observe fan-out
//! — is `(1/4)^99`, which is astronomically small.  We assert the
//! conservative invariant: **at least two workers handled at least one
//! datagram each**.  Operators of single-CPU CI runners or QEMU lab
//! environments will still see the test pass because the hash is computed
//! purely from the 4-tuple, not from per-CPU steering.

#[cfg(target_os = "linux")]
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(target_os = "linux")]
use heimdall_core::{
    header::{Header, Qclass, Qtype, Question},
    name::Name,
    parser::Message,
    serialiser::Serialiser,
};
#[cfg(target_os = "linux")]
use heimdall_runtime::{
    Drain, ListenerConfig as TransportListenerConfig, UdpListener,
    admission::{
        AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
        QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
    },
    bind_reuseport_udp,
};
#[cfg(target_os = "linux")]
use tokio::net::UdpSocket;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Builds a permissive admission pipeline that allows every request.  The
/// production-path pipeline construction is exercised by `transport_tests.rs`;
/// here we only need a wired pipeline to satisfy [`UdpListener::new`].
#[cfg(target_os = "linux")]
fn permissive_pipeline() -> Arc<AdmissionPipeline> {
    let allow_all = CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Allow,
    }]);
    let acl_handle = heimdall_runtime::admission::new_acl_handle(allow_all);
    Arc::new(AdmissionPipeline {
        acl: acl_handle,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    })
}

/// Serialises a minimal DNS query (header + one question, no OPT RR) into
/// wire form with the given transaction ID.
#[cfg(target_os = "linux")]
fn query_wire(id: u16) -> Vec<u8> {
    use std::str::FromStr as _;
    let mut hdr = Header::default();
    hdr.id = id;
    hdr.qdcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str("example.com.").expect("valid DNS name"),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    ser.finish()
}

// ── The test ──────────────────────────────────────────────────────────────────

/// Spin up a 4-worker UDP listener using `SO_REUSEPORT`, fire 100 concurrent
/// queries from 100 distinct source ports, and verify that:
///
/// - every query received a well-formed response with the matching ID;
/// - at least two workers handled at least one datagram (the kernel did
///   actually fan out, not pin everything on a single worker).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuseport_udp_listener_fans_out_across_workers() {
    const N_WORKERS: usize = 4;
    const N_QUERIES: usize = 100;
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

    // Pick an ephemeral port via a throwaway socket (then drop it, because
    // SO_REUSEPORT requires that every member of the group set the option
    // at creation time — the throwaway helper does not).  Linux's reuseport
    // group binding will then bind cleanly on the freed port.
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe bind");
    let bind_addr = probe.local_addr().expect("probe local_addr");
    drop(probe);

    // Build N reuseport-bound UdpListener instances, each with its own
    // counter, sharing the same admission pipeline.
    let pipeline = permissive_pipeline();
    let resource_counters = Arc::clone(&pipeline.resource_counters);
    let transport_cfg = TransportListenerConfig {
        bind_addr,
        ..TransportListenerConfig::default()
    };
    let mut counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(N_WORKERS);
    let drain = Arc::new(Drain::new());
    for w in 0..N_WORKERS {
        let socket = bind_reuseport_udp(bind_addr, None)
            .unwrap_or_else(|e| panic!("reuseport bind worker {w}: {e}"));
        let counter = Arc::new(AtomicU64::new(0));
        let listener = UdpListener::new(
            Arc::new(socket),
            transport_cfg.clone(),
            Arc::clone(&pipeline),
            Arc::clone(&resource_counters),
        )
        .with_counter(Arc::clone(&counter));
        counters.push(counter);
        let drain_clone = Arc::clone(&drain);
        tokio::spawn(async move {
            let _ = listener.run(drain_clone).await;
        });
    }
    // No explicit sleep: all UDP sockets are already bound (with SO_REUSEPORT)
    // and the kernel buffers datagrams independently per worker. Each query
    // task wraps `recv_from` in a `RESPONSE_TIMEOUT` budget that absorbs any
    // worker-scheduling delay.

    // Fire 100 concurrent queries from distinct source ports.  Each task
    // binds an independent client socket — that is what makes the kernel
    // hash distinct across queries.  Distinct IDs let us correlate
    // responses without race conditions.
    let mut send_tasks = Vec::with_capacity(N_QUERIES);
    for q in 0..N_QUERIES {
        let id = u16::try_from(q + 1).expect("test bounded above u16::MAX");
        send_tasks.push(tokio::spawn(async move {
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("client bind");
            let wire = query_wire(id);
            client.send_to(&wire, bind_addr).await.expect("send_to");
            let mut buf = vec![0u8; 4096];
            let recv = tokio::time::timeout(RESPONSE_TIMEOUT, client.recv_from(&mut buf)).await;
            match recv {
                Ok(Ok((n, _))) => {
                    let resp = Message::parse(&buf[..n]).expect("valid DNS response");
                    assert_eq!(resp.header.id, id, "response ID must match query");
                    assert!(resp.header.qr(), "QR bit must be set on response");
                    Ok::<(), String>(())
                }
                Ok(Err(e)) => Err(format!("recv_from: {e}")),
                Err(_) => Err("response timeout".to_owned()),
            }
        }));
    }

    // Collect every send-task's outcome.  All 100 must succeed.
    let mut received: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for (i, task) in send_tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok(())) => received += 1,
            Ok(Err(reason)) => failures.push(format!("query {i}: {reason}")),
            Err(join_err) => failures.push(format!("query {i}: join error {join_err}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{received}/{N_QUERIES} responses received; failures: {failures:#?}"
    );
    assert_eq!(
        received, N_QUERIES,
        "all 100 queries must receive a response"
    );

    // Distribution invariant: at least two workers each received at least
    // one datagram.  See the module-level docstring for the probability
    // argument behind this conservative bound.  Stop the listeners first so
    // any straggling counter writes are observable before we read.
    let _ = drain.drain_and_wait(Duration::from_secs(2)).await;
    let per_worker: Vec<u64> = counters.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    let total: u64 = per_worker.iter().sum();
    let workers_with_traffic = per_worker.iter().filter(|&&v| v > 0).count();
    eprintln!("reuseport per-worker datagram counts: {per_worker:?} (total: {total})");
    assert!(
        total >= u64::try_from(N_QUERIES).expect("N_QUERIES fits in u64"),
        "total datagrams observed across workers ({total}) is below the {N_QUERIES} sent"
    );
    assert!(
        workers_with_traffic >= 2,
        "expected ≥ 2 workers to receive at least one datagram, observed only \
         {workers_with_traffic} (per-worker: {per_worker:?}).  Either the kernel \
         does not implement SO_REUSEPORT load-balancing on this host, or the 4-tuple \
         hash collided into a single worker — the latter is statistically negligible \
         with 100 distinct source ports across {N_WORKERS} workers."
    );
}

// ── Non-Linux platform skip ───────────────────────────────────────────────────
//
// On macOS / BSD the production helper [`heimdall_runtime::bind_reuseport_udp`]
// returns `Unsupported`, so the integration test cannot meaningfully run.
// We surface this as a visible test that emits an `eprintln!` skip and
// returns success — matching the contract in rmp #676 AC 3 and giving CI
// log readers a clear breadcrumb.

#[cfg(not(target_os = "linux"))]
#[test]
fn reuseport_udp_listener_fans_out_across_workers() {
    eprintln!(
        "Skip: SO_REUSEPORT fan-out integration test is Linux-only.  \
         macOS / BSD have different SO_REUSEPORT semantics (no kernel \
         load-balancing across the reuseport group) — see BIN-058 and \
         heimdall_runtime::bind_reuseport_udp for details."
    );
}
