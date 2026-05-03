// SPDX-License-Identifier: MIT

//! Transport listener binding (boot phase 12, BIN-022).
//!
//! Reads the configured `[[listeners]]` entries and instantiates each listener
//! with its bound socket and a permissive boot-time admission pipeline. Binding
//! is all-or-nothing: if any socket cannot be bound the function returns an
//! error and all previously bound sockets are dropped (BIN-022).

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use heimdall_runtime::Drain;
use heimdall_runtime::admission::{
    AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal, QueryRlConfig, QueryRlEngine,
    ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
};
use heimdall_runtime::config::Config;
use heimdall_runtime::config::ListenerConfig as CfgListener;
use heimdall_runtime::config::TransportKind;
use heimdall_runtime::{
    Doh2HardeningConfig, Doh2Listener, Doh2Telemetry, Doh3HardeningConfig, Doh3Listener,
    Doh3Telemetry, DoqListener, DotListener,
    ListenerConfig as TransportListenerConfig, NewTokenTekManager, QueryDispatcher,
    QuicHardeningConfig, QuicTelemetry, StrikeRegister, TcpListener, TlsServerConfig,
    TlsTelemetry, TransportError, UdpListener, ZoneTransferHandler, build_quinn_endpoint,
    build_quinn_endpoint_h3, build_tls_server_config,
};
use rustls::crypto::ring;
use tokio_rustls::TlsAcceptor;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::net::UdpSocket;
use tracing::{error, info};

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
pub async fn bind_all(
    config: &Config,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
) -> Result<Vec<BoundListener>, String> {
    // Install the ring crypto provider before any TLS operation. safe to call
    // multiple times; subsequent calls are no-ops.
    let _ = ring::default_provider().install_default();
    let mut listeners = Vec::with_capacity(config.listeners.len());

    for (i, cfg) in config.listeners.iter().enumerate() {
        let pipeline = Arc::new(make_permissive_pipeline());
        let resource_counters = Arc::clone(&pipeline.resource_counters);

        match bind_one(i, cfg, pipeline, resource_counters, dispatcher.clone(), xfr_handler.clone()).await {
            Ok(listener) => {
                info!(
                    transport = listener.label(),
                    address = %cfg.address,
                    port = cfg.port,
                    "listener bound"
                );
                listeners.push(listener);
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

async fn bind_one(
    i: usize,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
) -> Result<BoundListener, String> {
    let bind_addr = SocketAddr::new(cfg.address, cfg.port);

    match cfg.transport {
        TransportKind::Udp => {
            bind_udp(i, bind_addr, cfg, pipeline, resource_counters, dispatcher).await
        }
        TransportKind::Tcp => {
            bind_tcp(i, bind_addr, cfg, pipeline, resource_counters, dispatcher, xfr_handler).await
        }
        TransportKind::Dot => {
            bind_dot(i, bind_addr, cfg, pipeline, resource_counters, dispatcher).await
        }
        TransportKind::Doh => {
            bind_doh2(i, bind_addr, cfg, pipeline, resource_counters, dispatcher).await
        }
        TransportKind::Doh3 => {
            bind_doh3(i, bind_addr, cfg, pipeline, resource_counters, dispatcher).await
        }
        TransportKind::Doq => {
            bind_doq(i, bind_addr, cfg, pipeline, resource_counters, dispatcher).await
        }
    }
}

async fn bind_udp(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) -> Result<BoundListener, String> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: UDP bind {addr}: {e}"))?;

    // udp_recv_buffer hint: applied via socket2 in a later task.
    let _ = (cfg, &socket);

    let transport_cfg = transport_cfg_from(addr);
    let mut listener = UdpListener::new(
        Arc::new(socket),
        transport_cfg,
        pipeline,
        resource_counters,
    );
    if let Some(d) = dispatcher {
        listener = listener.with_dispatcher(d);
    }
    Ok(BoundListener::Udp(listener))
}

async fn bind_tcp(
    i: usize,
    addr: SocketAddr,
    _cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
    xfr_handler: Option<Arc<dyn ZoneTransferHandler + Send + Sync>>,
) -> Result<BoundListener, String> {
    let tokio_listener = TokioTcpListener::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: TCP bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr);
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
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoT TLS config: {e}"))?;
    let tls_acceptor = TlsAcceptor::from(rustls_cfg);

    let tokio_listener = TokioTcpListener::bind(addr)
        .await
        .map_err(|e| format!("listeners[{i}]: DoT bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr);
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

    let transport_cfg = transport_cfg_from(addr);
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

async fn bind_doq(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) -> Result<BoundListener, String> {
    let tls_cfg = load_tls_config(i, cfg)?;
    let rustls_cfg = build_tls_server_config(&tls_cfg)
        .map_err(|e| format!("listeners[{i}]: DoQ TLS config: {e}"))?;

    let hardening = QuicHardeningConfig::default();
    let endpoint = build_quinn_endpoint(addr, rustls_cfg, &hardening)
        .map_err(|e| format!("listeners[{i}]: DoQ bind {addr}: {e}"))?;

    let transport_cfg = transport_cfg_from(addr);
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

async fn bind_doh3(
    i: usize,
    addr: SocketAddr,
    cfg: &CfgListener,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
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

    let transport_cfg = transport_cfg_from(addr);
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
        .ok_or_else(|| format!("listeners[{i}]: tls_cert is required for {:?}", cfg.transport))?
        .clone();
    let key_path = cfg
        .tls_key
        .as_ref()
        .ok_or_else(|| format!("listeners[{i}]: tls_key is required for {:?}", cfg.transport))?
        .clone();
    Ok(TlsServerConfig {
        cert_path,
        key_path,
        ..TlsServerConfig::default()
    })
}

fn transport_cfg_from(bind_addr: SocketAddr) -> TransportListenerConfig {
    TransportListenerConfig {
        bind_addr,
        ..TransportListenerConfig::default()
    }
}

fn make_permissive_pipeline() -> AdmissionPipeline {
    let acl: heimdall_runtime::AclHandle =
        Arc::new(ArcSwap::new(Arc::new(CompiledAcl::new(vec![]))));
    let resource_limits = ResourceLimits::default();
    let resource_counters = Arc::new(ResourceCounters::new());
    let rrl = Arc::new(RrlEngine::new(RrlConfig::default()));
    let query_rl = Arc::new(QueryRlEngine::new(QueryRlConfig::default()));
    let load_signal = Arc::new(LoadSignal::new());
    let telemetry = Arc::new(AdmissionTelemetry::new());
    AdmissionPipeline {
        acl,
        resource_limits,
        resource_counters,
        rrl,
        query_rl,
        load_signal,
        telemetry,
    }
}
