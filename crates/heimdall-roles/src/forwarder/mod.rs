// SPDX-License-Identifier: MIT

//! Forwarder role for the Heimdall DNS server (Sprint 32).
//!
//! The forwarder role forwards DNS queries to configured upstream resolvers,
//! applying:
//!
//! - Rule-based dispatch ([`dispatcher`]) with exact, suffix, and wildcard
//!   zone-pattern matching (hot-reloadable without tearing down in-flight
//!   queries).
//! - Multiple transport protocols ([`client`]): UDP/TCP ([`client_classic`]),
//!   `DoT` ([`client_dot`]), and compile-correct stubs for DoH/H2
//!   ([`client_doh_h2`]), DoH/H3 ([`client_doh_h3`]), and `DoQ`
//!   ([`client_doq`]).
//! - Transport fallback chain with structural gating: only declared transports
//!   are instantiated (NET-014).
//! - Independent DNSSEC validation ([`validate`]) — the upstream AD bit is
//!   never trusted (DNSSEC-019).
//! - Response caching ([`cache`]) using the segregated [`ForwarderCache`].
//! - Per-client query rate limiting ([`ratelimit`]) keyed on source IP, mTLS
//!   identity, TSIG identity, or DNS Cookie (THREAT-051).
//!
//! # Entry point
//!
//! [`ForwarderServer`] is the top-level coordinator.  Callers invoke
//! [`ForwarderServer::handle`] for each incoming query.  A return value of
//! `None` means no forward rule matched; the caller should fall through to
//! the next role.
//!
//! [`ForwarderCache`]: heimdall_runtime::cache::ForwarderCache

pub mod cache;
pub mod client;
pub mod client_classic;
pub mod client_doh_h2;
pub mod client_doh_h3;
pub mod client_doq;
pub mod client_dot;
pub mod dispatcher;
pub mod pool;
pub mod ratelimit;
pub mod server;
pub mod upstream;
pub mod validate;

pub use cache::{CachedResponse, ForwarderCacheClient};
pub use client::{ClientRegistry, UpstreamClient};
pub use dispatcher::ForwardDispatcher;
pub use pool::{ForwarderError, ForwarderPool};
pub use ratelimit::{ForwarderRateLimiter, RlKey};
pub use server::ForwarderServer;
pub use upstream::{
    ForwardRule, MatchMode, UpstreamConfig, UpstreamTransport, instantiated_transports,
};
pub use validate::ForwarderValidator;
