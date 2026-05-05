// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]
#![deny(missing_docs)]
// See `crates/heimdall-core/src/lib.rs` for the rationale: production code
// keeps the workspace lint posture intact, while test code gets a
// pragmatic relaxation matching `heimdall-e2e-harness`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreadable_literal,
        clippy::items_after_statements,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
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
    )
)]

//! # heimdall-runtime
//!
//! Async runtime skeleton, configuration loader, running-state container, drain
//! primitive, and task supervisor for Heimdall.
//!
//! ## Module overview
//!
//! - [`runtime`] — tokio runtime boot and I/O model detection (epoll / `io_uring`).
//! - [`config`]  — TOML config types, loader, and hot-reload plumbing.
//! - [`state`]   — [`state::RunningState`] + lock-free [`state::StateContainer`].
//! - [`drain`]   — controlled drain: stop accepting work and wait for in-flight
//!   operations to complete.
//! - [`supervisor`] — task spawning, panic isolation, and shutdown orchestration.
//! - [`store`]   — Redis persistence: zone data, cache, IXFR journal.
//! - [`cache`]   — Segregated query-response caches: [`cache::RecursiveCache`]
//!   and [`cache::ForwarderCache`] (CACHE-001..CACHE-016).
//! - [`admission`] — Multi-axis ACL, RRL, per-client query rate limiting,
//!   resource limits, composite load signal, and five-stage admission pipeline
//!   (THREAT-033..078, Sprint 20).
//! - [`transport`] — Classic DNS transports: UDP/53 and TCP/53 listeners with
//!   RFC 7766 framing, EDNS payload negotiation, DNS Cookie wiring, and
//!   backpressure action mapping (Sprint 21); DoT/853 with TLS 1.3, mTLS,
//!   TEK rotation, and `XoT` stub (Sprint 22); DoH/H2 with HTTP/2 hardening
//!   (SEC-036..046) and RFC 8484 GET+POST handling (Sprint 23); DoQ/853 with
//!   QUIC v1+v2, 0-RTT refusal, unconditional Retry, `NEW_TOKEN` anti-replay,
//!   and QUIC hardening (SEC-017..035, SEC-071..075, Sprint 24); DoH/H3 with
//!   h3+h3-quinn, HTTP/3 hardening (SEC-036..046), and RFC 8484 GET+POST over
//!   QUIC (NET-006..007, ADR-0051..0052, Sprint 25).
//! - [`ops`] — Runtime operations: SIGHUP reload, admin-RPC over UDS,
//!   HTTP observability endpoints, and systemd `sd_notify` integration (Sprint 33).
//! - [`security`] — Platform hardening primitives: seccomp-BPF allow-list
//!   (Linux, THREAT-024), privilege drop (Linux, THREAT-022/023), and
//!   pledge/unveil wrappers (OpenBSD, THREAT-029) (Sprint 37).

pub mod admission;
pub mod cache;
pub mod config;
pub mod drain;
pub mod ops;
pub mod runtime;
pub mod security;
pub mod state;
pub mod store;
pub mod supervisor;
pub mod transport;

pub use admission::{
    AclHandle, AdmissionPipeline, CompiledAcl, LoadSignal, QueryRlEngine, RequestCtx,
    ResourceCounters, ResourceLimits, RrlEngine,
};
pub use cache::{CacheEntry, CacheKey, ForwarderCache, RecursiveCache, TtlBounds};
pub use config::{Config, ConfigError, ConfigLoader, TransportKind};
pub use drain::{Drain, DrainError, DrainGuard};
pub use ops::{
    AdminResponse, AdminRpcClient, AdminRpcServer, AuditLogger, BuildInfo, ObservabilityServer,
    ReloadOutcome, SighupReloader, notify_extend_timeout_usec, notify_ready, notify_stopping,
    notify_watchdog, spawn_watchdog,
};
pub use runtime::{RuntimeError, RuntimeFlavour, RuntimeInfo, build_runtime};
pub use state::{RunningState, StateContainer};
pub use store::{
    RedisAuth, RedisConfig, RedisStore, RedisTopology, StoreDrainStats, StoreError, StoreMetrics,
    TrackedConn,
};
pub use supervisor::{Supervisor, WorkerError};
pub use transport::{
    BackpressureAction, CookieState, Doh2HardeningConfig, Doh2Listener, Doh2Telemetry,
    Doh3HardeningConfig, Doh3Listener, Doh3Telemetry, DoqListener, DotListener, ListenerConfig,
    MtlsIdentitySource, NewTokenTekManager, QueryDispatcher, QuicHardeningConfig, QuicTelemetry,
    StrikeRegister, TcpListener, TlsServerConfig, TlsTelemetry, TransportError, UdpListener,
    ZoneTransferHandler, build_quinn_endpoint, build_quinn_endpoint_h3, build_tls_server_config,
    extract_mtls_identity,
};
