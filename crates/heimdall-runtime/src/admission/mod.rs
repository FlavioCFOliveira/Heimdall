// SPDX-License-Identifier: MIT

//! Multi-axis ACL engine, Response Rate Limiting, per-client query rate
//! limiting, resource limits, composite load signal, and the five-stage
//! admission pipeline for Heimdall (Sprint 20).
//!
//! ## Module overview
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`acl`] | [`CompiledAcl`], [`AclHandle`], [`RequestCtx`], matcher axes (THREAT-033..047) |
//! | [`cidr`] | [`CidrSet`] — IPv4/IPv6 bit-trie for O(prefix\_len) longest-prefix match |
//! | [`rrl`] | [`RrlEngine`] — Response Rate Limiting per RFC 8906 (THREAT-048..050) |
//! | [`query_rl`] | [`QueryRlEngine`] — per-client query rate limiting (THREAT-051..053) |
//! | [`resource`] | [`ResourceLimits`], [`ResourceCounters`] (THREAT-062..068) |
//! | [`load_signal`] | [`LoadSignal`] — composite under-load signal with hysteresis (THREAT-069) |
//! | [`pipeline`] | [`AdmissionPipeline`] — five-stage evaluation (THREAT-076) |
//! | [`telemetry`] | [`AdmissionTelemetry`] — per-stage counters (THREAT-057/077) |

pub mod acl;
pub mod cidr;
pub mod load_signal;
pub mod pipeline;
pub mod query_rl;
pub mod resource;
pub mod rrl;
pub mod telemetry;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use acl::{
    AclAction, AclHandle, AclRule, CompiledAcl, EnumSet, Matcher, Operation, QnamePattern,
    RequestCtx, Role, Transport, new_acl_handle,
};
pub use cidr::CidrSet;
pub use load_signal::{LoadFactors, LoadSignal};
pub use pipeline::{AdmissionPipeline, ConnLimitReason, PipelineDecision};
pub use query_rl::{QueryRlConfig, QueryRlEngine, RlBucket, RlKey};
pub use resource::{ResourceCounters, ResourceLimits};
pub use rrl::{RrlConfig, RrlDecision, RrlEngine};
pub use telemetry::AdmissionTelemetry;
