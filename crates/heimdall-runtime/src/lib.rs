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

pub mod config;
pub mod drain;
pub mod runtime;
pub mod state;
pub mod supervisor;

pub use config::{Config, ConfigError, ConfigLoader};
pub use drain::{Drain, DrainError, DrainGuard};
pub use runtime::{RuntimeError, RuntimeFlavour, RuntimeInfo};
pub use state::{RunningState, StateContainer};
pub use supervisor::{Supervisor, WorkerError};
