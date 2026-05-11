// SPDX-License-Identifier: MIT

//! Transport listener binding (boot phase 12, BIN-022).
//!
//! Reads the configured `[[listeners]]` entries and instantiates each listener
//! with its bound socket and a permissive boot-time admission pipeline. Binding
//! is all-or-nothing: if any socket cannot be bound the function returns an
//! error and all previously bound sockets are dropped (BIN-022).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use arc_swap::ArcSwap;
use heimdall_runtime::{
    Doh2HardeningConfig, Doh2Listener, Doh2Telemetry, Doh3HardeningConfig, Doh3Listener,
    Doh3Telemetry, DoqListener, DotListener, Drain, ListenerConfig as TransportListenerConfig,
    NewTokenTekManager, QueryDispatcher, QuicHardeningConfig, QuicTelemetry, StrikeRegister,
    TcpListener, TlsServerConfig, TlsTelemetry, TransportError, UdpListener, ZoneTransferHandler,
    admission::{
        AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CidrSet, CompiledAcl,
        LoadSignal, Matcher, QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, Role,
        RrlConfig, RrlEngine,
    },
    bind_reuseport_udp, build_quinn_endpoint, build_quinn_endpoint_h3, build_tls_server_config,
    config::{Config, ListenerConfig as CfgListener, TransportKind},
};
use rustls::crypto::ring;
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// A fully-bound listener ready to be run as a supervisor worker.
pub enum BoundListener {
    Udp(UdpListener),
    Tcp(TcpListener),
    Dot(DotListener),
    Doh2(Doh2Listener),
    Doh3(Doh3Listener),
    Doq(DoqListener),
}

impl BoundListener {
    /// Label used for supervisor worker naming and log messages.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Udp(_) => "udp",
            Self::Tcp(_) => "tcp",
            Self::Dot(_) => "dot",
            Self::Doh2(_) => "doh2",
            Self::Doh3(_) => "doh3",
            Self::Doq(_) => "doq",
        }
    }

    /// Run the listener loop until `drain` signals shutdown.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        match self {
            Self::Udp(l) => l.run(drain).await,
            Self::Tcp(l) => l.run(drain).await,
            Self::Dot(l) => l.run(drain).await,
            Self::Doh2(l) => l.run(drain).await,
            Self::Doh3(l) => l.run(drain).await,
            Self::Doq(l) => l.run(drain).await,
        }
    }
}

/// Bind all configured listeners. Fail-closed per BIN-022: any bind failure
/// causes all previously bound sockets to be dropped before returning an error.
///
/// `server_role` is the DNS server role served by all listeners — injected into
/// each `RequestCtx` so the admission pipeline applies the correct defaults.
///
/// `telemetry` is the shared admission counter store.  Pass the same `Arc` to
/// `RunningState` so that `/metrics` reflects live pipeline decisions.
pub async fn bind_all(
    config: &Config,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
    server_role: Role,
    telemetry: Arc<AdmissionTelemetry>,
) -> Result<Vec<BoundListener>, String> {
    // Install the ring crypto provider before any TLS operation. safe to call
    // multiple times; subsequent calls are no-ops.
    let _ = ring::default_provider().install_default();
    let mut listeners = Vec::with_capacity(config.listeners.len());
    // BIN-058: the UDP path may expand a single [[listeners]] entry into N
    // workers when `server.udp_listener_workers > 1`.  Resolve once outside
    // the loop so every UDP entry sees the same value.
    let udp_workers = resolve_udp_worker_count(config.server.udp_listener_workers);

    for (i, cfg) in config.listeners.iter().enumerate() {
        let pipeline = Arc::new(make_pipeline_from_config(config, Arc::clone(&telemetry)));
        let resource_counters = Arc::clone(&pipeline.resource_counters);

        match bind_one(
            i,
            cfg,
            pipeline,
            resource_counters,
            dispatcher.clone(),
            xfr_handler.clone(),
            server_role,
            udp_workers,
        )
        .await
        {
            Ok(bound) => {
                for listener in bound {
                    info!(
                        transport = listener.label(),
                        address = %cfg.address,
                        port = cfg.port,
                        "listener bound"
                    );
                    listeners.push(listener);
                }
            }
            Err(e) => {
                // Drop all previously bound listeners before returning.
                drop(listeners);
                error!(index = i, error = %e, "listener bind failed");
                return Err(e);
            }
        }
    }

    Ok(listeners)
}

/// Resolve the effective UDP worker count for [`bind_all`] (BIN-058).
///
/// Linux honours the configured value as-is.  On macOS and BSD targets, any
/// value > 1 is downgraded to 1 with a `WARN` log because `SO_REUSEPORT`
/// semantics on those platforms differ from Linux (no kernel load-balancing).
fn resolve_udp_worker_count(configured: u32) -> u32 {
    if configured <= 1 {
        return configured.max(1);
    }
    #[cfg(target_os = "linux")]
    {
        configured
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn!(
            configured,
            "server.udp_listener_workers > 1 ignored: SO_REUSEPORT fan-out is only \
             supported on Linux; falling back to a single UDP worker per listener"
        );
        1
    }
}

#[allow(clippy::too_many_arguments)]
async fn bind_one(
    i: usize,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
    server_role: Role,
    udp_workers: u32,
) -> Result<Vec<BoundListener>, String> {
    let bind_addr = SocketAddr::new(cfg.address, cfg.port);

    match cfg.transport {
        TransportKind::Udp => {
            bind_udp(
                i,
                bind_addr,
                cfg,
                pipeline,
                resource_counters,
                dispatcher,
                server_role,
                udp_workers,
            )
            .await
        }
        TransportKind::Tcp => bind_tcp(
            i,
            bind_addr,
            cfg,
            pipeline,
            resource_counters,
            dispatcher,
            xfr_handler,
            server_role,
        )
        .await
        .map(|l| vec![l]),
        TransportKind::Dot => bind_dot(
            i,
            bind_addr,
            cfg,
            pipeline,
            resource_counters,
            dispatcher,
            server_role,
        )
        .await
        .map(|l| vec![l]),
        TransportKind::Doh => bind_doh2(
            i,
            bind_addr,
            cfg,
            pipeline,
            resource_counters,
            dispatcher,
            server_role,
        )
        .await
        .map(|l| vec![l]),
        TransportKind::Doh3 => bind_doh3(
            i,
            bind_addr,
            cfg,
            pipeline,
            resource_counters,
            dispatcher,
            server_role,
        )
        .map(|l| vec![l]),
        TransportKind::Doq => bind_doq(
            i,
            bind_addr,
            cfg,
            pipeline,
            resource_counters,
            dispatcher,
            server_role,
        )
        .map(|l| vec![l]),
    }
}

#[allow(clippy::too_many_arguments)]
async fn bind_udp(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    server_role: Role,
    udp_workers: u32,
) -> Result<Vec<BoundListener>, String> {
    // Single-worker fast path: keep the historical bind via Tokio so that
    // configurations that do not opt into the fan-out behave identically to
    // pre-BIN-058 releases.
    if udp_workers <= 1 {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| format!("listeners[{i}]: UDP bind {addr}: {e}"))?;
        // udp_recv_buffer hint: applied via socket2 in a later task.
        let _ = (cfg, &socket);

        let transport_cfg = transport_cfg_from(addr, server_role);
        let mut listener =
            UdpListener::new(Arc::new(socket), transport_cfg, pipeline, resource_counters);
        if let Some(d) = dispatcher {
            listener = listener.with_dispatcher(d);
        }
        return Ok(vec![BoundListener::Udp(listener)]);
    }

    // Multi-worker fan-out (BIN-058): bind N sockets with SO_REUSEPORT and
    // build one UdpListener per socket.  All workers share the admission
    // pipeline, resource counters, dispatcher, and listener config.  Each
    // gets its own per-worker datagram counter (UdpListener::with_counter).
    //
    // INVARIANT: udp_workers > 1 only on Linux thanks to resolve_udp_worker_count.
    info!(
        index = i,
        address = %addr,
        workers = udp_workers,
        "binding SO_REUSEPORT UDP worker group (BIN-058)"
    );
    let workers_usize = usize::try_from(udp_workers)
        .map_err(|e| format!("listeners[{i}]: invalid udp_workers: {e}"))?;
    let mut bound = Vec::with_capacity(workers_usize);
    let transport_cfg = transport_cfg_from(addr, server_role);
    let recv_buffer = Some(cfg.udp_recv_buffer);
    for w in 0..workers_usize {
        let socket = bind_reuseport_udp(addr, recv_buffer).map_err(|e| {
            format!(
                "listeners[{i}]: SO_REUSEPORT UDP bind {addr} (worker {w}/{workers_usize}): {e}"
            )
        })?;
        let mut listener = UdpListener::new(
            Arc::new(socket),
            transport_cfg.clone(),
            Arc::clone(&pipeline),
            Arc::clone(&resource_counters),
        );
        if let Some(d) = dispatcher.clone() {
            listener = listener.with_dispatcher(d);
        }
        bound.push(BoundListener::Udp(listener));
    }
    Ok(bound)
}

#[allow(clippy::too_many_arguments)]
async fn bind_tcp(
    i: usize,
    addr: SocketAddr,
    _cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
    server_role: Role,
) -> Result<BoundListener, String> {
    let tokio_listener = TokioTcpListener::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: TCP bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr, server_role);
    let mut listener = TcpListener::new(
        Arc::new(tokio_listener),
        transport_cfg,
        pipeline,
        resource_counters,
    );
    if let Some(d) = dispatcher {
        listener = listener.with_dispatcher(d);
    }
    if let Some(xfr) = xfr_handler {
        listener = listener.with_xfr_handler(xfr);
    }
    Ok(BoundListener::Tcp(listener))
}

async fn bind_dot(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    server_role: Role,
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoT TLS config: {e}"))?;
    let tls_acceptor = TlsAcceptor::from(rustls_cfg);

    let tokio_listener = TokioTcpListener::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: DoT bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr, server_role);
    let telemetry = Arc::new(TlsTelemetry::new());
    let mut listener = DotListener::new(
        tokio_listener,
        tls_acceptor,
        transport_cfg,
        tls_cfg,
        pipeline,
        resource_counters,
        telemetry,
    );
    if let Some(d) = dispatcher {
        listener = listener.with_dispatcher(d);
    }
    Ok(BoundListener::Dot(listener))
}

async fn bind_doh2(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    server_role: Role,
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoH/H2 TLS config: {e}"))?;

    // Doh2Listener enforces ALPN "h2" after handshake (NET-006, NET-007).
    // build_tls_server_config produces a generic ServerConfig with no ALPN set;
    // we are the sole owner of this Arc so try_unwrap succeeds.
    let mut server_cfg = std::sync::Arc::try_unwrap(rustls_cfg)
        .map_err(|_| format!("listeners[{i}]: DoH/H2: unexpected extra Arc owners"))?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(server_cfg));

    let tokio_listener = TokioTcpListener::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: DoH/H2 bind {addr}: {e}"))?;

    let mut transport_cfg = transport_cfg_from(addr, server_role);
    transport_cfg.alt_svc.clone_from(&cfg.alt_svc);
    let listener = Doh2Listener {
        listener: tokio_listener,
        tls_acceptor,
        config: transport_cfg,
        hardening: Doh2HardeningConfig::default(),
        pipeline,
        resource_counters,
        telemetry: Arc::new(Doh2Telemetry::new()),
        dispatcher,
    };
    Ok(BoundListener::Doh2(listener))
}

fn bind_doq(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    server_role: Role,
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoQ TLS config: {e}"))?;

    // DoQ requires ALPN "doq" (RFC 9250 §9.1, NET-008). Without it kdig sends
    // TLS Alert 120 (no_application_protocol) because it requires confirmed ALPN.
    let mut server_cfg = std::sync::Arc::try_unwrap(rustls_cfg)
        .map_err(|_| format!("listeners[{i}]: DoQ: unexpected extra Arc owners"))?;
    server_cfg.alpn_protocols = vec![b"doq".to_vec()];
    let rustls_cfg = std::sync::Arc::new(server_cfg);

    let hardening = QuicHardeningConfig::default();
    let endpoint = build_quinn_endpoint(addr, rustls_cfg, &hardening)
        .map_err(|e| format!("listeners[{i}]: DoQ bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr, server_role);
    let telemetry = Arc::new(QuicTelemetry::new());
    let strike = Arc::new(StrikeRegister::new());
    let tek = Arc::new(NewTokenTekManager::new(43_200, 86_400));
    let mut listener = DoqListener::new(
        endpoint,
        transport_cfg,
        hardening,
        strike,
        tek,
        pipeline,
        resource_counters,
        telemetry,
    );
    if let Some(d) = dispatcher {
        listener = listener.with_dispatcher(d);
    }
    Ok(BoundListener::Doq(listener))
}

fn bind_doh3(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    server_role: Role,
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoH/H3 TLS config: {e}"))?;

    // build_quinn_endpoint_h3 requires alpn_protocols = ["h3"] on the ServerConfig
    // (NET-006). We are the sole Arc owner here so try_unwrap succeeds.
    let mut server_cfg = std::sync::Arc::try_unwrap(rustls_cfg)
        .map_err(|_| format!("listeners[{i}]: DoH/H3: unexpected extra Arc owners"))?;
    server_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let rustls_cfg = std::sync::Arc::new(server_cfg);

    let quic_hardening = QuicHardeningConfig::default();
    let doh3_hardening = Doh3HardeningConfig::default();
    let endpoint = build_quinn_endpoint_h3(addr, rustls_cfg, &quic_hardening, &doh3_hardening)
        .map_err(|e| format!("listeners[{i}]: DoH/H3 bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr, server_role);
    let telemetry = std::sync::Arc::new(Doh3Telemetry::new());
    let listener = Doh3Listener {
        endpoint,
        hardening: doh3_hardening,
        pipeline,
        resource_counters,
        telemetry,
        dispatcher,
        max_udp_payload: transport_cfg.max_udp_payload,
    };
    Ok(BoundListener::Doh3(listener))
}

fn load_tls_config(i: usize, cfg: &CfgListener) -> Result<TlsServerConfig, String> {
    let cert_path = cfg
        .tls_cert
        .as_ref()
        .ok_or_else(|| {
            format!(
                "listeners[{i}]: tls_cert is required for {:?}",
                cfg.transport
            )
        })?
        .clone();
    let key_path = cfg
        .tls_key
        .as_ref()
        .ok_or_else(|| {
            format!(
                "listeners[{i}]: tls_key is required for {:?}",
                cfg.transport
            )
        })?
        .clone();
    Ok(TlsServerConfig {
        cert_path,
        key_path,
        ..TlsServerConfig::default()
    })
}

fn transport_cfg_from(bind_addr: SocketAddr, server_role: Role) -> TransportListenerConfig {
    TransportListenerConfig {
        bind_addr,
        server_role,
        ..TransportListenerConfig::default()
    }
}

/// Build an admission pipeline from the TOML config, sharing `telemetry` with
/// the caller so that counter increments are visible via `/metrics`.
///
/// ACL evaluation order (first-match wins):
/// 1. Explicit allow rules from `config.acl.allow_sources` (source CIDR).
/// 2. Explicit deny rules from `config.acl.deny_sources` (source CIDR).
/// 3. Per-operation defaults (AXFR deny, auth allow, recursive/forwarder deny).
fn make_pipeline_from_config(
    config: &heimdall_runtime::config::Config,
    telemetry: Arc<AdmissionTelemetry>,
) -> AdmissionPipeline {
    // ── ACL rules ──────────────────────────────────────────────────────────────
    let mut acl_rules: Vec<AclRule> = Vec::new();

    for cidr_str in &config.acl.allow_sources {
        if let Some(cidr_set) = parse_cidr_set(cidr_str) {
            acl_rules.push(AclRule {
                matchers: vec![Matcher::SourceCidr(cidr_set)],
                action: AclAction::Allow,
            });
        }
    }
    for cidr_str in &config.acl.deny_sources {
        if let Some(cidr_set) = parse_cidr_set(cidr_str) {
            acl_rules.push(AclRule {
                matchers: vec![Matcher::SourceCidr(cidr_set)],
                action: AclAction::Deny,
            });
        }
    }

    let acl: heimdall_runtime::AclHandle =
        Arc::new(ArcSwap::new(Arc::new(CompiledAcl::new(acl_rules))));

    // ── RRL (authoritative role) ───────────────────────────────────────────────
    let rrl_rate = if config.rate_limit.enabled {
        config
            .rate_limit
            .responses_per_second
            .unwrap_or(u32::MAX / 2)
    } else {
        u32::MAX / 2
    };
    let rrl = Arc::new(RrlEngine::new(RrlConfig {
        rate_per_sec: rrl_rate,
        ..RrlConfig::default()
    }));

    // ── Query RL (recursive / forwarder role) ─────────────────────────────────
    let qrl_anon_rate = if config.rate_limit.enabled {
        config
            .rate_limit
            .query_rate_per_second
            .unwrap_or(u32::MAX / 2)
    } else {
        u32::MAX / 2
    };
    let query_rl = Arc::new(QueryRlEngine::new(QueryRlConfig {
        anon_rate: qrl_anon_rate,
        cookie_rate: qrl_anon_rate.saturating_mul(4),
        auth_rate: qrl_anon_rate.saturating_mul(10),
        burst_window_secs: 1,
    }));

    AdmissionPipeline {
        acl,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl,
        query_rl,
        load_signal: Arc::new(LoadSignal::new()),
        telemetry,
    }
}

/// Parse a CIDR string (`"1.2.3.4/24"` or bare `"1.2.3.4"`) into a [`CidrSet`].
///
/// Returns `None` when the string cannot be parsed; a warning is logged.
fn parse_cidr_set(s: &str) -> Option<CidrSet> {
    let (addr_str, prefix_len) = if let Some((addr, plen)) = s.split_once('/') {
        let plen: u8 = plen.parse().ok()?;
        (addr, plen)
    } else {
        // Bare IP — treat as /32 (IPv4) or /128 (IPv6).
        let addr: IpAddr = s.parse().ok()?;
        let plen = if addr.is_ipv4() { 32 } else { 128 };
        (s, plen)
    };
    let addr: IpAddr = addr_str.parse().ok()?;
    let mut set = CidrSet::default();
    set.insert(addr, prefix_len);
    Some(set)
}
