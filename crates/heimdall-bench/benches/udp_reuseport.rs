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
    clippy::unused_async
)]

//! Sustained-QPS bench for the `SO_REUSEPORT` UDP listener fan-out
//! (BIN-058, Sprint 67 task #676).
//!
//! Measures throughput at 1, 2, 4, and 8 workers by:
//!
//! 1. binding N UDP sockets with `SO_REUSEPORT` on `127.0.0.1:<ephemeral>`
//!    *once* per parameter value;
//! 2. spawning N [`heimdall_runtime::UdpListener`] recv loops with a
//!    permissive admission pipeline and no role dispatcher (the listener
//!    answers REFUSED — the smallest possible response, which keeps the
//!    bench focused on the recv + send hot path rather than role logic);
//! 3. driving sustained load in a `criterion::iter_custom` window where
//!    each criterion "iter" is one query + matching response.
//!
//! Per criterion semantics, `Throughput::Elements(1)` is interpreted as one
//! element processed per iter, so the published metric is `queries/sec`.
//!
//! ## Running
//!
//! ```text
//! cargo bench -p heimdall-bench --bench udp_reuseport
//! ```
//!
//! ## Reporting policy
//!
//! Per the project's PERF governance, **do not commit absolute QPS numbers**
//! from this bench.  Reference-hardware measurements belong in
//! `docs/bench/baselines/<arch>/` and are pinned to the rig described in
//! `docs/bench/REPRODUCING.md`.  The bench's value is the *shape* of the
//! scaling curve (the ratio between 1 and N workers) on a given host.

#[cfg(target_os = "linux")]
mod linux {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use criterion::{BenchmarkId, Criterion, Throughput};
    use heimdall_core::{
        header::{Header, Qclass, Qtype, Question},
        name::Name,
        parser::Message,
        serialiser::Serialiser,
    };
    use heimdall_runtime::{
        Drain, ListenerConfig, UdpListener,
        admission::{
            AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
            QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
        },
        bind_reuseport_udp,
    };
    use tokio::{
        net::UdpSocket,
        runtime::{Builder, Runtime},
    };

    fn query_wire(id: u16) -> Vec<u8> {
        use std::str::FromStr as _;
        let mut hdr = Header::default();
        hdr.id = id;
        hdr.qdcount = 1;
        let msg = Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str("example.com.").expect("valid name"),
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

    /// A live N-worker reuseport UDP listener bound to an ephemeral local
    /// port, ready to be hammered.  Dropping the harness drains the
    /// listeners on `tokio::runtime::Runtime::block_on`.
    struct Harness {
        addr: std::net::SocketAddr,
        drain: Arc<Drain>,
    }

    impl Harness {
        fn bind(rt: &Runtime, workers: usize) -> Self {
            rt.block_on(async move {
                let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("probe bind");
                let addr = probe.local_addr().expect("probe local_addr");
                drop(probe);

                let pipeline = permissive_pipeline();
                let resource_counters = Arc::clone(&pipeline.resource_counters);
                let cfg = ListenerConfig {
                    bind_addr: addr,
                    ..ListenerConfig::default()
                };
                let drain = Arc::new(Drain::new());
                for _ in 0..workers {
                    let sock = bind_reuseport_udp(addr, None).expect("reuseport bind");
                    let listener = UdpListener::new(
                        Arc::new(sock),
                        cfg.clone(),
                        Arc::clone(&pipeline),
                        Arc::clone(&resource_counters),
                    );
                    let drain_c = Arc::clone(&drain);
                    tokio::spawn(async move {
                        let _ = listener.run(drain_c).await;
                    });
                }
                // Settle: ensure every worker has reached its recv_from before
                // criterion's clock starts.
                tokio::time::sleep(Duration::from_millis(20)).await;
                Self { addr, drain }
            })
        }

        fn shutdown(self, rt: &Runtime) {
            rt.block_on(async move {
                let _ = self.drain.drain_and_wait(Duration::from_secs(1)).await;
            });
        }
    }

    /// Sends `iters` queries from a single throw-away client socket and
    /// returns the wall-clock time taken to receive all `iters` responses.
    ///
    /// Reusing one client socket across iters keeps the bench tight on the
    /// listener path (the cost of binding a fresh client is excluded from
    /// the steady-state measurement).
    fn run_iters(rt: &Runtime, addr: std::net::SocketAddr, wire: &[u8], iters: u64) -> Duration {
        rt.block_on(async move {
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("client bind");
            let mut buf = vec![0u8; 4096];
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = client.send_to(wire, addr).await;
                let _ =
                    tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                        .await;
            }
            start.elapsed()
        })
    }

    pub fn bench_reuseport_scaling(c: &mut Criterion) {
        let rt = Builder::new_multi_thread()
            .worker_threads(16)
            .enable_all()
            .build()
            .expect("tokio rt build");
        let mut group = c.benchmark_group("udp_reuseport_scaling");
        group.throughput(Throughput::Elements(1));
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(5));

        for &workers in &[1usize, 2, 4, 8] {
            let harness = Harness::bind(&rt, workers);
            let addr = harness.addr;
            let wire = query_wire(0x1234);
            group.bench_with_input(BenchmarkId::from_parameter(workers), &workers, |b, _| {
                b.iter_custom(|iters| run_iters(&rt, addr, &wire, iters));
            });
            harness.shutdown(&rt);
        }
        group.finish();
    }
}

// ── Non-Linux: empty bench, criterion still emits a clean exit. ───────────────

#[cfg(target_os = "linux")]
criterion::criterion_group!(benches, linux::bench_reuseport_scaling);

#[cfg(not(target_os = "linux"))]
fn skip_non_linux(_c: &mut criterion::Criterion) {
    eprintln!(
        "Skip: udp_reuseport bench is Linux-only (SO_REUSEPORT semantics \
         differ on macOS / BSD).  See BIN-058."
    );
}

#[cfg(not(target_os = "linux"))]
criterion::criterion_group!(benches, skip_non_linux);

criterion::criterion_main!(benches);
