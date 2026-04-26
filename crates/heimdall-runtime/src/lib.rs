// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]
#![warn(missing_docs)]

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
//!   backpressure action mapping (Sprint 21).

pub mod admission;
pub mod cache;
pub mod config;
pub mod drain;
pub mod runtime;
pub mod state;
pub mod store;
pub mod supervisor;
pub mod transport;

pub use admission::{
    AdmissionPipeline, AclHandle, CompiledAcl, LoadSignal, QueryRlEngine, RequestCtx,
    ResourceCounters, ResourceLimits, RrlEngine,
};
pub use cache::{CacheEntry, CacheKey, ForwarderCache, RecursiveCache, TtlBounds};
pub use config::{Config, ConfigError, ConfigLoader};
pub use drain::{Drain, DrainError, DrainGuard};
pub use runtime::{RuntimeError, RuntimeFlavour, RuntimeInfo};
pub use state::{RunningState, StateContainer};
pub use store::{RedisAuth, RedisConfig, RedisStore, RedisTopology, StoreError, StoreMetrics};
pub use supervisor::{Supervisor, WorkerError};
pub use transport::{
    BackpressureAction, CookieState, ListenerConfig, TcpListener, TransportError, UdpListener,
};
