// SPDX-License-Identifier: MIT

//! Runtime operations: SIGHUP reload, admin-RPC, observability server, and
//! systemd `sd_notify` integration.
//!
//! All operations in this module target the running server instance and interact
//! with the [`crate::state::StateContainer`] to read or update live configuration.
//!
//! # Modules
//!
//! - [`reload`]        — SIGHUP handler with at-most-one-queued reload semantics (OPS-001..018).
//! - [`admin_rpc`]     — Length-prefix-framed JSON admin-RPC over Unix Domain Socket (OPS-007..015).
//! - [`observability`] — HTTP observability endpoints: `/healthz`, `/readyz`, `/metrics`,
//!   `/version` (OPS-021..031).
//! - [`sd_notify`]     — Manual systemd `sd_notify` integration via `$NOTIFY_SOCKET` (OPS-032).

pub mod admin_rpc;
pub mod anomaly;
pub mod audit;
pub mod observability;
pub mod reload;
pub mod sd_notify;

pub use admin_rpc::{AdminResponse, AdminRpcClient, AdminRpcServer};
pub use audit::AuditLogger;
pub use observability::{BuildInfo, ObservabilityServer};
pub use reload::{ReloadOutcome, SighupReloader};
pub use sd_notify::{
    notify_extend_timeout_usec, notify_ready, notify_stopping, notify_watchdog, spawn_watchdog,
};
