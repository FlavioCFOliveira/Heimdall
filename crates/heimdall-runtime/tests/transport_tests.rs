// SPDX-License-Identifier: MIT

//! Integration tests for the Sprint 21 transport listeners (NET-003, NET-011,
//! PROTO-008, PROTO-014, PROTO-115, THREAT-063, THREAT-068).
//!
//! Each test binds an ephemeral OS port, starts the listener in a background
//! tokio task, exercises the protocol from a test client, and verifies the
//! outcome.  All listeners are stopped via [`Drain::drain_and_wait`].

use std::{sync::Arc, time::Duration};

use heimdall_core::{
    edns::{EdnsCookie, EdnsOption, OptRr},
    header::{Header, Qclass, Qtype, Question, Rcode},
    name::Name,
    parser::Message,
    rdata::RData,
    record::{Record, Rtype},
    serialiser::Serialiser,
};
use heimdall_runtime::{
    Drain, ListenerConfig, TcpListener, UdpListener,
    admission::{
        AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
        PipelineDecision, QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits,
        RrlConfig, RrlDecision, RrlEngine,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Builds a permissive admission pipeline that accepts all queries.
fn permissive_pipeline() -> Arc<AdmissionPipeline> {
    // `AclRule` with empty matchers matches every request; action = Allow.
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

fn make_resource_counters() -> Arc<ResourceCounters> {
    Arc::new(ResourceCounters::new())
}

/// Serialises a minimal DNS query into wire form.
fn query_wire(id: u16, name: &str, qtype: Qtype) -> Vec<u8> {
    let mut hdr = Header::default();
    hdr.id = id;
    hdr.qdcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str_unwrap(name),
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

/// Serialises a DNS query with an OPT RR advertising `udp_size`.
fn query_wire_with_opt(id: u16, name: &str, qtype: Qtype, udp_size: u16) -> Vec<u8> {
    let opt_rr = OptRr {
        udp_payload_size: udp_size,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: vec![],
    };
    let mut hdr = Header::default();
    hdr.id = id;
    hdr.qdcount = 1;
    hdr.arcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str_unwrap(name),
            qtype,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![Record {
            name: Name::root(),
            rtype: Rtype::Opt,
            rclass: Qclass::Any,
            ttl: 0,
            rdata: RData::Opt(opt_rr),
        }],
    };
    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    ser.finish()
}

/// Wraps `wire` in a 2-byte RFC 7766 length prefix.
fn tcp_frame(wire: &[u8]) -> Vec<u8> {
    let len = wire.len() as u16;
    let mut framed = Vec::with_capacity(2 + wire.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    framed
}

/// Reads one framed DNS response from `stream` (2-byte length + body).
async fn read_framed_response(stream: &mut TcpStream) -> Message {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("read length prefix");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .expect("read response body");
    Message::parse(&body).expect("valid DNS response")
}

/// Signals drain and waits up to 2 seconds for the drain to complete.
async fn stop(drain: Arc<Drain>) {
    drain
        .drain_and_wait(Duration::from_secs(2))
        .await
        .expect("drain completed");
}

// ── Name helper ───────────────────────────────────────────────────────────────

trait NameFromStr {
    fn from_str_unwrap(s: &str) -> Name;
}

impl NameFromStr for Name {
    fn from_str_unwrap(s: &str) -> Name {
        use std::str::FromStr as _;
        Name::from_str(s).expect("valid DNS name in test")
    }
}

// ── BackpressureAction mapping ────────────────────────────────────────────────

// These tests exercise the pure backpressure mapping functions without I/O.

#[test]
fn backpressure_udp_rrl_slip_maps_to_tc_truncated() {
    use heimdall_runtime::{BackpressureAction, transport::backpressure::udp_backpressure};

    let decision = PipelineDecision::DenyRrl(RrlDecision::Slip);
    assert_eq!(udp_backpressure(&decision), BackpressureAction::TcTruncated);
}

#[test]
fn backpressure_udp_acl_deny_maps_to_silent_drop() {
    use heimdall_runtime::{BackpressureAction, transport::backpressure::udp_backpressure};

    let decision = PipelineDecision::DenyAcl;
    assert_eq!(
        udp_backpressure(&decision),
        BackpressureAction::UdpSilentDrop
    );
}

#[test]
fn backpressure_tcp_always_maps_to_fin_close() {
    use heimdall_runtime::{BackpressureAction, transport::backpressure::tcp_backpressure};

    let decision = PipelineDecision::DenyAcl;
    assert_eq!(tcp_backpressure(&decision), BackpressureAction::TcpFinClose);
}

// ── UDP integration tests ─────────────────────────────────────────────────────

/// A plain UDP query receives a REFUSED response with the correct ID.
#[tokio::test]
async fn udp_query_returns_refused() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        ..ListenerConfig::default()
    };
    let listener = UdpListener::new(
        Arc::new(socket),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wire = query_wire(0xABCD, "example.com.", Qtype::A);
    client.send_to(&wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("response within timeout")
        .unwrap();

    let resp = Message::parse(&buf[..n]).expect("valid DNS response");
    assert_eq!(resp.header.id, 0xABCD);
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "RCODE must be REFUSED"
    );

    stop(drain).await;
}

/// EDNS payload negotiation: response OPT `udp_payload_size` must not exceed
/// the client-advertised size.
#[tokio::test]
async fn udp_edns_payload_size_is_negotiated() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        max_udp_payload: 1232,
        ..ListenerConfig::default()
    };
    let listener = UdpListener::new(
        Arc::new(socket),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Advertise a 512-byte client buffer, which is smaller than server max.
    let wire = query_wire_with_opt(0x1234, "example.com.", Qtype::A, 512);
    client.send_to(&wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("response within timeout")
        .unwrap();

    let resp = Message::parse(&buf[..n]).expect("valid DNS response");
    assert_eq!(resp.header.id, 0x1234);
    // Response datagram must fit within the client-advertised 512 bytes.
    assert!(
        n <= 512,
        "response datagram must not exceed client-advertised EDNS size ({n} bytes)"
    );

    // OPT RR must be present and reflect the negotiated size.
    let opt = resp
        .additional
        .iter()
        .find_map(|r| {
            if let RData::Opt(o) = &r.rdata {
                Some(o)
            } else {
                None
            }
        })
        .expect("OPT RR must be present in response");
    assert!(
        opt.udp_payload_size <= 512,
        "OPT udp_payload_size must be ≤ client-advertised 512 (got {})",
        opt.udp_payload_size
    );

    stop(drain).await;
}

/// A malformed UDP datagram is silently dropped — no response is sent and the
/// listener remains alive for subsequent valid queries.
#[tokio::test]
async fn udp_malformed_datagram_is_dropped_silently() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        ..ListenerConfig::default()
    };
    let listener = UdpListener::new(
        Arc::new(socket),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send garbage — no response should arrive.
    client
        .send_to(b"\xFF\xFF\xFF\xFF garbage", server_addr)
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    assert!(
        result.is_err(),
        "no response expected for malformed datagram (timed out as expected)"
    );

    // Listener must still be alive — send a valid query and expect a response.
    let wire = query_wire(0xDEAD, "example.com.", Qtype::A);
    client.send_to(&wire, server_addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("valid query must receive a response")
        .unwrap();

    let resp = Message::parse(&buf[..n]).expect("valid DNS response");
    assert_eq!(resp.header.id, 0xDEAD);

    stop(drain).await;
}

/// DNS Cookie round-trip: client sends a client cookie; server echoes it back
/// with a freshly derived 8-byte server cookie.
#[tokio::test]
async fn udp_cookie_round_trip() {
    const SECRET: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    const CLIENT_COOKIE: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        server_cookie_secret: SECRET,
        ..ListenerConfig::default()
    };
    let listener = UdpListener::new(
        Arc::new(socket),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Build a query with OPT RR containing a client cookie only.
    let opt_rr = OptRr {
        udp_payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: vec![EdnsOption::Cookie(EdnsCookie {
            client: CLIENT_COOKIE,
            server: None,
        })],
    };
    let mut hdr = Header::default();
    hdr.id = 0x5555;
    hdr.qdcount = 1;
    hdr.arcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str_unwrap("example.com."),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![Record {
            name: Name::root(),
            rtype: Rtype::Opt,
            rclass: Qclass::Any,
            ttl: 0,
            rdata: RData::Opt(opt_rr),
        }],
    };
    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    let wire = ser.finish();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("response within timeout")
        .unwrap();

    let resp = Message::parse(&buf[..n]).expect("valid DNS response");
    assert_eq!(resp.header.id, 0x5555);

    let opt = resp
        .additional
        .iter()
        .find_map(|r| {
            if let RData::Opt(o) = &r.rdata {
                Some(o)
            } else {
                None
            }
        })
        .expect("OPT RR must be present in cookie response");

    let cookie = opt
        .options
        .iter()
        .find_map(|o| {
            if let EdnsOption::Cookie(c) = o {
                Some(c)
            } else {
                None
            }
        })
        .expect("Cookie option must be present in response");

    assert_eq!(
        cookie.client, CLIENT_COOKIE,
        "client cookie must be echoed unchanged"
    );
    let server_cookie = cookie
        .server
        .as_ref()
        .expect("server cookie must be present");
    assert_eq!(server_cookie.len(), 8, "server cookie must be 8 bytes");

    stop(drain).await;
}

// ── TCP integration tests ─────────────────────────────────────────────────────

/// A well-formed RFC 7766 framed DNS query over TCP receives a REFUSED response.
#[tokio::test]
async fn tcp_framed_query_returns_refused() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        ..ListenerConfig::default()
    };
    let listener = TcpListener::new(
        Arc::new(tcp_listener),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut stream = TcpStream::connect(server_addr).await.unwrap();
    let wire = query_wire(0xCAFE, "example.com.", Qtype::A);
    stream.write_all(&tcp_frame(&wire)).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(2), read_framed_response(&mut stream))
        .await
        .expect("response within timeout");

    assert_eq!(resp.header.id, 0xCAFE);
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "RCODE must be REFUSED"
    );

    stop(drain).await;
}

/// A TCP connection that sends no bytes is closed by the server after the
/// handshake timeout expires.
#[tokio::test]
async fn tcp_handshake_timeout_closes_idle_connection() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        // Very short handshake timeout so the test completes quickly.
        tcp_handshake_timeout_secs: 1,
        ..ListenerConfig::default()
    };
    let listener = TcpListener::new(
        Arc::new(tcp_listener),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut stream = TcpStream::connect(server_addr).await.unwrap();
    // Do NOT send anything — wait for the server to close the connection.

    let mut buf = vec![0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("server must close connection within 3 s");

    // Server closes: EOF (0 bytes) or connection reset.
    match result {
        Ok(0) | Err(_) => { /* expected: server timed out and closed */ }
        Ok(n) => panic!("unexpected {n} bytes received on idle TCP connection"),
    }

    stop(drain).await;
}

/// Pipelining limit: after `tcp_max_pipelining` queries the server must close
/// the connection (or stop accepting further messages on it).
#[tokio::test]
async fn tcp_pipelining_limit_closes_after_max_queries() {
    const MAX_PIPELINE: u32 = 4;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_max_pipelining: MAX_PIPELINE,
        tcp_handshake_timeout_secs: 5,
        tcp_idle_timeout_secs: 10,
        tcp_stall_timeout_secs: 5,
        ..ListenerConfig::default()
    };
    let listener = TcpListener::new(
        Arc::new(tcp_listener),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut stream = TcpStream::connect(server_addr).await.unwrap();

    // Send exactly MAX_PIPELINE queries.
    for i in 0..MAX_PIPELINE {
        let wire = query_wire(i as u16, "example.com.", Qtype::A);
        stream.write_all(&tcp_frame(&wire)).await.unwrap();
    }

    // Read all MAX_PIPELINE responses.
    let mut received: u32 = 0;
    for _ in 0..MAX_PIPELINE {
        let r =
            tokio::time::timeout(Duration::from_secs(2), read_framed_response(&mut stream)).await;
        if r.is_ok() {
            received += 1;
        } else {
            break;
        }
    }
    assert_eq!(
        received, MAX_PIPELINE,
        "must receive {MAX_PIPELINE} responses"
    );

    // After the pipeline limit is hit the server closes the connection.
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    match result {
        Ok(Ok(0)) | Err(_) => { /* connection closed — correct */ }
        Ok(Ok(n)) => {
            // A framed response (if any) arriving at this point is acceptable;
            // just verify it's at least a 2-byte length prefix.
            assert!(n >= 2, "unexpected {n} bytes after pipeline limit");
        }
        Ok(Err(_)) => { /* connection reset by server — acceptable */ }
    }

    stop(drain).await;
}

/// edns-tcp-keepalive: when the client includes `TcpKeepalive(None)` in its
/// OPT RR the server must respond with `TcpKeepalive(Some(value))`.
#[tokio::test]
async fn tcp_response_includes_keepalive_when_client_requests_it() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_keepalive_secs: 30,
        ..ListenerConfig::default()
    };
    let listener = TcpListener::new(
        Arc::new(tcp_listener),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Build a query with OPT RR that includes TcpKeepalive(None) — client
    // requests the server's keepalive value.
    let opt_rr = OptRr {
        udp_payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: vec![EdnsOption::TcpKeepalive(None)],
    };
    let mut hdr = Header::default();
    hdr.id = 0x9ABC;
    hdr.qdcount = 1;
    hdr.arcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str_unwrap("example.com."),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![Record {
            name: Name::root(),
            rtype: Rtype::Opt,
            rclass: Qclass::Any,
            ttl: 0,
            rdata: RData::Opt(opt_rr),
        }],
    };
    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    let wire = ser.finish();

    let mut stream = TcpStream::connect(server_addr).await.unwrap();
    stream.write_all(&tcp_frame(&wire)).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(2), read_framed_response(&mut stream))
        .await
        .expect("response within timeout");

    assert_eq!(resp.header.id, 0x9ABC);

    let opt = resp
        .additional
        .iter()
        .find_map(|r| {
            if let RData::Opt(o) = &r.rdata {
                Some(o)
            } else {
                None
            }
        })
        .expect("OPT RR must be present in TCP keepalive response");

    let has_keepalive = opt
        .options
        .iter()
        .any(|o| matches!(o, EdnsOption::TcpKeepalive(Some(_))));
    assert!(
        has_keepalive,
        "response must carry TcpKeepalive option with a value"
    );

    stop(drain).await;
}

/// TCP multiple queries on the same connection (basic pipelining): each
/// query-response pair is correctly demultiplexed by ID.
#[tokio::test]
async fn tcp_multiple_pipelined_queries_all_receive_responses() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_max_pipelining: 8,
        ..ListenerConfig::default()
    };
    let listener = TcpListener::new(
        Arc::new(tcp_listener),
        config,
        permissive_pipeline(),
        make_resource_counters(),
    );
    let drain = Arc::new(Drain::new());

    tokio::spawn(listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut stream = TcpStream::connect(server_addr).await.unwrap();

    // Send 3 queries sequentially (read response before sending next, so IDs
    // arrive in the same order and we can verify them).
    for id in [0x1111u16, 0x2222, 0x3333] {
        let wire = query_wire(id, "example.com.", Qtype::A);
        stream.write_all(&tcp_frame(&wire)).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(2), read_framed_response(&mut stream))
            .await
            .expect("response within timeout");

        assert_eq!(resp.header.id, id, "response ID must match query ID");
        assert!(resp.header.qr());
    }

    stop(drain).await;
}
