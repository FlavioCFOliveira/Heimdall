// SPDX-License-Identifier: MIT

//! Platform security hardening primitives.
//!
//! - `seccomp`  (Linux/`x86_64`) — BPF syscall allow-list filter (THREAT-024).
//! - `privdrop` (Linux) — Privilege drop and capability management (THREAT-022/023).
//! - `pledge`   (OpenBSD) — pledge(2) and unveil(2) wrappers (THREAT-029).

#[cfg(target_os = "linux")]
pub mod privdrop;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod seccomp;

#[cfg(target_os = "openbsd")]
pub mod pledge;
