// SPDX-License-Identifier: MIT

//! Iterative recursive resolver role for the Heimdall DNS server.
//!
//! This module implements Sprint 30: the recursive resolver core.
//!
//! # Modules
//!
//! - [`dispatcher`] — [`RecursiveServer`]: the top-level query handler.
//! - [`follow`] — [`DelegationFollower`]: iterative delegation-following state machine.
//! - [`server_state`] — [`ServerStateCache`]: per-upstream-server health tracking.
//! - [`root_hints`] — [`RootHints`]: IANA root hints with priming stub.
//! - [`validate`] — [`ResponseValidator`]: DNSSEC signature validation wiring.
//! - [`cache`] — [`RecursiveCacheClient`]: typed wrapper around the runtime cache.
//! - [`timing`] — [`QueryBudget`]: timeout and retry budget tracking.
//! - [`error`] — [`RecursiveError`]: error-to-RCODE/EDE mapping.

pub mod cache;
pub mod dispatcher;
pub mod error;
pub mod follow;
pub mod root_hints;
pub mod server_state;
pub mod timing;
pub mod validate;

pub use cache::{CachedResponse, RecursiveCacheClient};
pub use dispatcher::RecursiveServer;
pub use error::RecursiveError;
pub use follow::{DelegationFollower, FollowResult, UpstreamQuery, MAX_CNAME_HOPS, MAX_DELEGATION_DEPTH};
pub use root_hints::{RootHints, RootHintsError, RootNs};
pub use server_state::ServerStateCache;
pub use timing::QueryBudget;
pub use validate::ResponseValidator;
