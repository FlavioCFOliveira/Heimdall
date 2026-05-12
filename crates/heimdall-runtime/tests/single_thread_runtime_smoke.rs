// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

//! Smoke test for rmp #675: drives the UDP listener end-to-end under a
//! **single-thread** Tokio runtime.
//!
//! Before the async migration of [`heimdall_runtime::QueryDispatcher`], the
//! recursive and forwarder role implementations bridged the sync trait to
//! their async handlers via `tokio::task::block_in_place` +
//! `Handle::current().block_on()`.  `block_in_place` panics on a
//! single-threaded runtime ("can call blocking only when running on the
//! multi-threaded runtime"), which made it impossible to use Heimdall's
//! transport stack in a `current_thread` scheduler.
//!
//! This test pins that invariant: the dispatcher trait is now `async`-shaped,
//! and a UDP listener can answer a query under
//! [`tokio::runtime::Builder::new_current_thread`] without panic.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use heimdall_core::{
    header::{Header, Qclass, Qtype, Question, Rcode},
    name::Name,
    parser::Message,
    serialiser::Serialiser,
};
use heimdall_runtime::{
    Drain, ListenerConfig, QueryDispatcher, UdpListener,
    admission::{
        AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
        QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
    },
};
use tokio::net::UdpSocket;

// ── Stub dispatcher ───────────────────────────────────────────────────────────

/// Returns a NOERROR response with no answers — exercises the async dispatch
/// path without requiring any role implementation or network access.
struct NoErrorStub;

impl QueryDispatcher for NoErrorStub {
    fn dispatch<'a>(
        &'a self,
        msg: &'a Message,
        _src: std::net::IpAddr,
        _is_udp: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>> {
        Box::pin(async move {
            // Yield once so the future is genuinely polled cooperatively on the
            // single-thread runtime (rather than completing in a single poll).
            // This proves the runtime can interleave dispatch work with I/O.
            tokio::task::yield_now().await;

            let mut hdr = Header {
                id: msg.header.id,
                qdcount: msg.header.qdcount,
                ..Header::default()
            };
            hdr.set_qr(true);
            hdr.set_rcode(Rcode::NoError);
            let resp = Message {
                header: hdr,
                questions: msg.questions.clone(),
                answers: vec![],
                authority: vec![],
                additional: vec![],
            };
            let mut ser = Serialiser::new(true);
            let _ = ser.write_message(&resp);
            ser.finish()
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

fn query_wire(id: u16, qname: &str, qtype: Qtype) -> Vec<u8> {
    let hdr = Header {
        id,
        qdcount: 1,
        ..Header::default()
    };
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::parse_str(qname).expect("valid DNS name"),
            qtype,
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

// ── Test ──────────────────────────────────────────────────────────────────────

/// Single-thread runtime smoke test (rmp #675 AC #4).
///
/// Builds a `current_thread` Tokio runtime, binds a UDP listener with the
/// async stub dispatcher, sends one query, and asserts a well-formed
/// `NOERROR` response is received.  This run-shape would have panicked under
/// the previous `block_in_place` bridge.
#[test]
fn single_thread_runtime_drives_udp_listener_end_to_end() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(async {
        // Bind on the loopback ephemeral port so the test is hermetic.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind server socket");
        let server_addr = socket.local_addr().expect("server local_addr");

        let config = ListenerConfig {
            bind_addr: server_addr,
            ..ListenerConfig::default()
        };

        let listener = UdpListener::new(
            Arc::new(socket),
            config,
            permissive_pipeline(),
            Arc::new(ResourceCounters::new()),
        )
        .with_dispatcher(Arc::new(NoErrorStub));

        let drain = Arc::new(Drain::new());

        // Spawn the listener on the same single-thread runtime.  Using
        // `block_in_place` here would panic; the async dispatcher trait makes
        // this spawn legal.
        let listener_handle = tokio::spawn(listener.run(Arc::clone(&drain)));

        // No explicit sleep: the UDP socket is already bound; the kernel
        // queues datagrams and the listener picks them up as soon as the
        // recv loop is polled. The 5 s receive timeout below absorbs any
        // scheduler variance.

        // Send a query from a client socket.
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        let query_id = 0xBEEFu16;
        let wire = query_wire(query_id, "example.com.", Qtype::A);
        client
            .send_to(&wire, server_addr)
            .await
            .expect("send query");

        // Receive the response.
        let mut buf = vec![0u8; 4096];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response within timeout")
            .expect("recv_from ok");

        let resp = Message::parse(&buf[..n]).expect("valid DNS response");
        assert_eq!(resp.header.id, query_id, "response ID must echo query ID");
        assert!(resp.header.qr(), "response must have QR=1");
        assert_eq!(
            resp.header.flags & 0x000F,
            u16::from(Rcode::NoError.as_u8()),
            "response RCODE must be NOERROR"
        );
        assert_eq!(
            resp.questions.len(),
            1,
            "response must echo the question section"
        );

        // Drain the listener.
        drain
            .drain_and_wait(Duration::from_millis(500))
            .await
            .expect("drain completes");

        // The listener task is expected to be torn down by the drain; abort
        // it explicitly to keep the test deterministic on slow runners.
        listener_handle.abort();
    });
}
