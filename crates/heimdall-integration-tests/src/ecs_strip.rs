// SPDX-License-Identifier: MIT

//! ECS strip integration tests (PROTO-015, PROTO-017, PROTO-018, PROTO-019).
//!
//! PROTO-015 forbids implementing ECS; PROTO-017 mandates incoming ECS options
//! are not echoed in responses; PROTO-018 mandates outbound recursive queries
//! never carry ECS; PROTO-019 mandates outbound auth responses never carry ECS.
//!
//! # Test matrix
//!
//! | # | Scenario | Assertion |
//! |---|---|---|
//! | i | Query with ECS into auth UDP listener | Response OPT has no ECS |
//! | ii | Recursive resolver sends outbound query | Outbound query has no ECS |
//! | iii | Query with ECS into recursive UDP listener | Response OPT has no ECS |
//! | iv | Query with ECS into auth TCP listener | Response OPT has no ECS |

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{net::IpAddr, pin::Pin, str::FromStr, sync::Arc, time::Duration};

    use heimdall_core::{
        edns::{EdnsOption, OptRr},
        header::{Header, Qclass, Qtype, Question},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
        serialiser::Serialiser,
    };
    use heimdall_roles::{
        dnssec_roles::{NtaStore, TrustAnchorStore},
        recursive::{RecursiveServer, RootHints, UpstreamQuery},
    };
    use heimdall_runtime::{
        Drain, ListenerConfig, TcpListener, UdpListener,
        admission::{
            AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
            QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
        },
        cache::recursive::RecursiveCache,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
    };

    // ── Shared helpers ────────────────────────────────────────────────────────────

    /// A raw ECS option payload for subnet 192.0.2.0/24 (family=1, prefix=24, scope=0).
    ///
    /// Wire encoding per RFC 7871 §6:
    ///   FAMILY (2 bytes) = 0x0001 (IPv4)
    ///   SOURCE PREFIX-LENGTH (1 byte) = 24
    ///   SCOPE PREFIX-LENGTH (1 byte) = 0
    ///   ADDRESS (ceil(24/8) = 3 bytes) = [192, 0, 2]
    const ECS_PAYLOAD: &[u8] = &[0x00, 0x01, 0x18, 0x00, 192, 0, 2];

    /// Serialises a DNS query carrying an OPT RR with a ClientSubnet option.
    fn query_with_ecs(id: u16, name: &str, qtype: Qtype) -> Vec<u8> {
        let ecs = EdnsOption::ClientSubnet(ECS_PAYLOAD.to_vec());
        let opt_rr = OptRr {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![ecs],
        };
        let mut hdr = Header::default();
        hdr.id = id;
        hdr.qdcount = 1;
        hdr.arcount = 1;
        let msg = Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str(name).expect("valid qname"),
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

    /// Wraps `wire` in a 2-byte RFC 7766 length prefix for TCP.
    fn tcp_frame(wire: &[u8]) -> Vec<u8> {
        let len = wire.len() as u16;
        let mut out = Vec::with_capacity(2 + wire.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(wire);
        out
    }

    /// Reads one framed DNS response from a TCP stream.
    async fn read_tcp_response(stream: &mut TcpStream) -> Message {
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .expect("length prefix");
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.expect("body");
        Message::parse(&body).expect("valid DNS message")
    }

    /// Returns `true` if any option in `msg`'s OPT RR is a `ClientSubnet`.
    fn response_has_ecs(msg: &Message) -> bool {
        msg.additional.iter().any(|r| {
            if let RData::Opt(opt) = &r.rdata {
                opt.options
                    .iter()
                    .any(|o| matches!(o, EdnsOption::ClientSubnet(_)))
            } else {
                false
            }
        })
    }

    fn permissive_pipeline() -> Arc<AdmissionPipeline> {
        let allow_all = CompiledAcl::new(vec![AclRule {
            matchers: vec![],
            action: AclAction::Allow,
        }]);
        let acl = heimdall_runtime::admission::new_acl_handle(allow_all);
        Arc::new(AdmissionPipeline {
            acl,
            resource_limits: ResourceLimits::default(),
            resource_counters: Arc::new(ResourceCounters::new()),
            rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
            query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
            load_signal: Arc::new(LoadSignal::new()),
            telemetry: Arc::new(AdmissionTelemetry::new()),
        })
    }

    async fn drain_and_wait(drain: Arc<Drain>) {
        drain
            .drain_and_wait(Duration::from_secs(2))
            .await
            .expect("drain");
    }

    // ── Case (i): ECS not echoed in UDP response (auth/transport layer) ───────────

    /// Sends a query carrying ECS (option-code 8) to a UDP listener and asserts
    /// the response OPT RR contains no ClientSubnet option (PROTO-017, PROTO-019).
    ///
    /// No role dispatcher is attached — the server returns REFUSED.  ECS stripping
    /// occurs in the UDP transport's `build_response_opt` regardless of role.
    #[tokio::test]
    async fn ecs_option_not_echoed_in_udp_auth_response() {
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
            Arc::new(ResourceCounters::new()),
        );
        let drain = Arc::new(Drain::new());
        tokio::spawn(listener.run(Arc::clone(&drain)));
        tokio::time::sleep(Duration::from_millis(20)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire = query_with_ecs(0x0001, "example.com.", Qtype::A);
        client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response within timeout")
            .unwrap();
        let resp = Message::parse(&buf[..n]).expect("valid DNS response");

        assert!(
            !response_has_ecs(&resp),
            "(i) ECS option must not appear in UDP response OPT RR"
        );

        drain_and_wait(drain).await;
    }

    // ── Case (ii): recursive outbound query has no ECS ────────────────────────────

    /// Mock upstream that captures the first query it receives.
    struct CapturingUpstream {
        captured: tokio::sync::Mutex<Option<Message>>,
        response: Message,
    }

    impl CapturingUpstream {
        fn new(response: Message) -> Arc<Self> {
            Arc::new(Self {
                captured: tokio::sync::Mutex::new(None),
                response,
            })
        }

        async fn take(&self) -> Option<Message> {
            self.captured.lock().await.take()
        }
    }

    impl UpstreamQuery for CapturingUpstream {
        fn query<'a>(
            &'a self,
            _server: IpAddr,
            _port: u16,
            msg: &'a Message,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>
        {
            let msg_clone = msg.clone();
            let response = self.response.clone();
            Box::pin(async move {
                // Store first capture (subsequent calls may occur for delegation following).
                let _ = self.captured.lock().await.get_or_insert(msg_clone);
                Ok(response)
            })
        }
    }

    /// Builds a minimal authoritative response for use as the mock upstream reply.
    fn make_aa_response() -> Message {
        use std::net::Ipv4Addr;

        use heimdall_core::{header::Rcode, rdata::RData};

        let owner = Name::from_str("www.example.com.").expect("name");
        let mut hdr = Header::default();
        hdr.id = 1;
        hdr.qdcount = 1;
        hdr.ancount = 1;
        hdr.set_qr(true);
        hdr.set_aa(true);
        hdr.set_rcode(Rcode::NoError);
        Message {
            header: hdr,
            questions: vec![Question {
                qname: owner.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![Record {
                name: owner,
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(203, 0, 113, 1)),
            }],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Drives a recursive resolution through `RecursiveServer::handle()` and
    /// asserts that the query sent to the upstream (via `UpstreamQuery::query()`)
    /// contains no ECS option (PROTO-018).
    #[tokio::test]
    async fn recursive_outbound_query_has_no_ecs_option() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let cache = Arc::new(RecursiveCache::new(512, 512));
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor"));
        let nta_store = Arc::new(NtaStore::new(100));
        let root_hints = Arc::new(RootHints::from_builtin().expect("root hints"));
        let server = RecursiveServer::new(cache, trust_anchor, nta_store, root_hints);

        let upstream = CapturingUpstream::new(make_aa_response());

        // Query for a name that forces upstream resolution (cache miss).
        let qname = Name::from_str("www.example.com.").expect("qname");
        let mut hdr = Header::default();
        hdr.id = 42;
        hdr.set_rd(true);
        hdr.qdcount = 1;
        let query = Message {
            header: hdr,
            questions: vec![Question {
                qname,
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let upstream_arc: Arc<dyn UpstreamQuery> = Arc::clone(&upstream) as Arc<dyn UpstreamQuery>;
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let _ = server.handle(&query, src, false, upstream_arc).await;

        let captured = upstream.take().await;
        let captured = captured.expect("(ii) at least one outbound query must be issued");

        assert!(
            !response_has_ecs(&captured),
            "(ii) outbound recursive query must not carry ECS option"
        );
    }

    // ── Case (iii): ECS not echoed in UDP response (role dispatcher attached) ─────

    /// A synchronous `QueryDispatcher` stub that returns REFUSED immediately,
    /// simulating the recursive role for the purpose of transport-layer ECS testing.
    ///
    /// `RecursiveServer::dispatch()` requires outbound DNS network access (root
    /// nameservers) and cannot run in a unit test.  The ECS stripping invariant is
    /// in the transport layer (`build_response_opt`), not in the role dispatcher,
    /// so any conforming dispatcher exercises the same stripping code path.
    struct RefusedDispatcher;

    impl heimdall_runtime::QueryDispatcher for RefusedDispatcher {
        fn dispatch(&self, msg: &Message, _src: std::net::IpAddr, _is_udp: bool) -> Vec<u8> {
            use heimdall_core::header::Rcode;

            let mut hdr = Header {
                id: msg.header.id,
                qdcount: msg.header.qdcount,
                ..Header::default()
            };
            hdr.set_qr(true);
            hdr.set_rcode(Rcode::Refused);
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
        }
    }

    /// Same assertion as case (i), but a role dispatcher is attached to confirm
    /// ECS stripping occurs regardless of whether a role is active (PROTO-017,
    /// PROTO-019).  A lightweight inline dispatcher is used instead of the real
    /// `RecursiveServer` to avoid requiring live DNS network access in tests.
    #[tokio::test]
    async fn ecs_option_not_echoed_in_udp_response_with_role_dispatcher() {
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
            Arc::new(ResourceCounters::new()),
        )
        .with_dispatcher(Arc::new(RefusedDispatcher));
        let drain = Arc::new(Drain::new());
        tokio::spawn(listener.run(Arc::clone(&drain)));
        tokio::time::sleep(Duration::from_millis(20)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire = query_with_ecs(0x0003, "example.com.", Qtype::A);
        client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response within timeout")
            .unwrap();
        let resp = Message::parse(&buf[..n]).expect("valid DNS response");

        assert!(
            !response_has_ecs(&resp),
            "(iii) ECS option must not appear in UDP response OPT RR when a role dispatcher is attached"
        );

        drain_and_wait(drain).await;
    }

    // ── Case (iv): ECS not echoed in TCP response (auth transport) ───────────────

    /// Sends a query carrying ECS to a TCP listener and asserts the response
    /// OPT RR contains no ClientSubnet option (PROTO-019, PROTO-017).
    ///
    /// TCP and UDP share the same ECS-stripping invariant; this test confirms the
    /// behaviour across both transports (no dispatcher → REFUSED).
    #[tokio::test]
    async fn ecs_option_not_echoed_in_tcp_auth_response() {
        use std::net::TcpListener as StdTcpListener;

        let std_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).expect("non-blocking");
        let tokio_listener =
            Arc::new(tokio::net::TcpListener::from_std(std_listener).expect("tokio listener"));

        let config = ListenerConfig {
            bind_addr: server_addr,
            ..ListenerConfig::default()
        };
        let listener = TcpListener::new(
            tokio_listener,
            config,
            permissive_pipeline(),
            Arc::new(ResourceCounters::new()),
        );
        let drain = Arc::new(Drain::new());
        tokio::spawn(listener.run(Arc::clone(&drain)));
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut stream = TcpStream::connect(server_addr).await.expect("connect");
        let wire = query_with_ecs(0x0004, "example.com.", Qtype::A);
        stream
            .write_all(&tcp_frame(&wire))
            .await
            .expect("send query");

        let resp = read_tcp_response(&mut stream).await;

        assert!(
            !response_has_ecs(&resp),
            "(iv) ECS option must not appear in TCP response OPT RR"
        );

        drain_and_wait(drain).await;
    }
}
