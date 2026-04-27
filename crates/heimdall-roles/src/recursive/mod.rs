// SPDX-License-Identifier: MIT

//! Iterative recursive resolver role for the Heimdall DNS server.
//!
//! This module implements Sprints 30 and 31: the recursive resolver core and
//! its protocol extensions.
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
//! - [`qname_min`] — [`QnameMinimiser`]: QNAME minimisation per RFC 9156.
//! - [`zero_x_twenty`] — [`CasePatternStore`]: 0x20 case randomisation.
//! - [`aggressive_nsec`] — [`try_aggressive_synthesis`]: RFC 8198 synthesis.
//! - [`glue`] — [`extract_glue`]: bailiwick-enforced glue extraction.

pub mod aggressive_nsec;
pub mod cache;
pub mod dispatcher;
pub mod error;
pub mod follow;
pub mod glue;
pub mod qname_min;
pub mod root_hints;
pub mod server_state;
pub mod timing;
pub mod validate;
pub mod zero_x_twenty;

pub use aggressive_nsec::{AggressiveResult, try_aggressive_synthesis};
pub use cache::{CachedResponse, RecursiveCacheClient};
pub use dispatcher::RecursiveServer;
pub use error::RecursiveError;
pub use follow::{
    DelegationFollower, FollowResult, MAX_CNAME_HOPS, MAX_DELEGATION_DEPTH, UpstreamQuery,
};
pub use glue::{ValidatedNs, extract_glue, is_in_bailiwick};
pub use qname_min::{QnameMinError, QnameMinMode, QnameMinimiser};
pub use root_hints::{RootHints, RootHintsError, RootNs};
pub use server_state::ServerStateCache;
pub use timing::QueryBudget;
pub use validate::ResponseValidator;
pub use zero_x_twenty::{CasePatternStore, apply_ox20, verify_ox20};
