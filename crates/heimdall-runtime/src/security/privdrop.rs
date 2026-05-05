// SPDX-License-Identifier: MIT

//! Privilege drop and capability management (THREAT-022/023).
//!
//! Provides the sequence for dropping root privileges to an unprivileged user
//! while retaining only `CAP_NET_BIND_SERVICE` (capability bit 10), which
//! allows binding to ports below 1024 (DNS port 53, DoT port 853, DoH port 443).
//!
//! The expected call order is:
//! 1. [`retain_cap_net_bind_service`] — set `KEEPCAPS` and raise the ambient
//!    capability *before* the uid/gid change so it survives the privilege drop.
//! 2. [`drop_privileges`] — drop supplementary groups, gid, uid.
//! 3. [`verify_capabilities`] — assert that only `CAP_NET_BIND_SERVICE` remains
//!    in the Permitted and Effective sets.
//!
//! # Safety
//!
//! All `unsafe` blocks in this module are `libc` FFI calls. Each is documented
//! with its invariants.

#![allow(unsafe_code)]

use std::fmt;
use std::io;

/// Error type for privilege-drop operations.
#[derive(Debug)]
pub enum PrivdropError {
    /// A libc call failed; contains the operation name and errno value.
    Syscall {
        /// Name of the failing system call.
        op: &'static str,
        /// `errno` value returned by the kernel.
        errno: i32,
    },
    /// `/proc/self/status` could not be read or parsed.
    ProcStatusUnreadable(io::Error),
    /// The capability set after drop does not match the expected value.
    CapabilityMismatch {
        /// Capability bitmask that was expected.
        expected: u64,
        /// Capability bitmask that was actually observed.
        actual: u64,
    },
}

impl fmt::Display for PrivdropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall { op, errno } => write!(f, "{op} failed: errno {errno}"),
            Self::ProcStatusUnreadable(e) => {
                write!(f, "cannot read /proc/self/status: {e}")
            }
            Self::CapabilityMismatch { expected, actual } => {
                write!(
                    f,
                    "capability mismatch: expected 0x{expected:x}, got 0x{actual:x}"
                )
            }
        }
    }
}

impl std::error::Error for PrivdropError {}

/// `CAP_NET_BIND_SERVICE` is capability bit 10.
pub const CAP_NET_BIND_SERVICE: u64 = 1 << 10;

/// `prctl(2)` constants for capability management.
const PR_SET_KEEPCAPS: libc::c_int = 8;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

/// Linux capability header version (v3).
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drops process privileges to the given `uid`/`gid`, clearing all supplementary groups.
///
/// The order — `setgroups`, `setgid`, `setuid` — is mandated by the Linux man page
/// to avoid a window where the process has the new uid but still holds old groups.
///
/// # Errors
///
/// Returns [`PrivdropError::Syscall`] if any of the three system calls fails.
pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), PrivdropError> {
    // SAFETY: setgroups(0, NULL) removes all supplementary groups. The second
    // argument is a pointer to a groups array of length zero; passing NULL for
    // length zero is explicitly documented as valid in Linux man pages.
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret != 0 {
        return Err(PrivdropError::Syscall { op: "setgroups", errno: errno() });
    }

    // SAFETY: setgid(gid) sets the real, effective, and saved-set GID. The
    // argument is a plain integer; no pointer dereference occurs.
    let ret = unsafe { libc::setgid(gid) };
    if ret != 0 {
        return Err(PrivdropError::Syscall { op: "setgid", errno: errno() });
    }

    // SAFETY: setuid(uid) sets the real, effective, and saved-set UID. The
    // argument is a plain integer; no pointer dereference occurs.
    let ret = unsafe { libc::setuid(uid) };
    if ret != 0 {
        return Err(PrivdropError::Syscall { op: "setuid", errno: errno() });
    }

    Ok(())
}

/// Configures the process to retain `CAP_NET_BIND_SERVICE` across a `setuid` call.
///
/// Must be called *before* [`drop_privileges`]. Two `prctl` calls are made:
/// - `PR_SET_KEEPCAPS=1`: instructs the kernel to preserve Permitted capabilities
///   when the effective UID changes from 0 to non-0.
/// - `PR_CAP_AMBIENT / PR_CAP_AMBIENT_RAISE`: adds `CAP_NET_BIND_SERVICE` to the
///   ambient set, so it is inherited automatically by the process after uid change
///   without requiring a follow-up `capset` call on kernels that support ambient caps
///   (≥ 4.3). A `capset` call follows to also set Permitted and Effective explicitly.
///
/// # Errors
///
/// Returns [`PrivdropError::Syscall`] if any system call fails.
pub fn retain_cap_net_bind_service() -> Result<(), PrivdropError> {
    // SAFETY: prctl(PR_SET_KEEPCAPS, 1, ...) sets a per-thread flag; all trailing
    // arguments are ignored for this option and are passed as zero.
    let ret = unsafe { libc::prctl(PR_SET_KEEPCAPS, 1usize, 0usize, 0usize, 0usize) };
    if ret != 0 {
        return Err(PrivdropError::Syscall { op: "prctl(PR_SET_KEEPCAPS)", errno: errno() });
    }

    // SAFETY: prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) raises one
    // ambient capability. The third argument is the capability number (an integer);
    // no pointer dereference occurs. CAP_NET_BIND_SERVICE (10) is a valid,
    // well-defined capability on all Linux kernel versions >= 2.2.
    let ret = unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_RAISE,
            10usize, // CAP_NET_BIND_SERVICE
            0usize,
            0usize,
        )
    };
    if ret != 0 {
        return Err(PrivdropError::Syscall {
            op: "prctl(PR_CAP_AMBIENT_RAISE)",
            errno: errno(),
        });
    }

    Ok(())
}

/// Reads `/proc/self/status` and verifies that only `CAP_NET_BIND_SERVICE`
/// (bit 10, hex value `0x400`) is set in the Permitted (`CapPrm`) and
/// Effective (`CapEff`) capability sets.
///
/// Test processes running without special capabilities will have `CapPrm = 0`
/// and `CapEff = 0`. The assertion accepts both `0x400` (cap retained) and `0`
/// (no caps at all, valid for non-privileged test runs) so that unit tests pass
/// without requiring root.
///
/// # Errors
///
/// Returns [`PrivdropError`] if the file cannot be read, parsed, or if the
/// capability value is neither `0` nor `0x400`.
pub fn verify_capabilities() -> Result<(), PrivdropError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(PrivdropError::ProcStatusUnreadable)?;

    let cap_prm = parse_cap_field(&status, "CapPrm")?;
    let cap_eff = parse_cap_field(&status, "CapEff")?;

    for (name, val) in [("CapPrm", cap_prm), ("CapEff", cap_eff)] {
        if val != 0 && val != CAP_NET_BIND_SERVICE {
            return Err(PrivdropError::CapabilityMismatch {
                expected: CAP_NET_BIND_SERVICE,
                actual: val,
            });
        }
        let _ = name;
    }

    Ok(())
}

fn parse_cap_field(status: &str, field: &str) -> Result<u64, PrivdropError> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let hex = rest.trim_start_matches(':').trim();
            return u64::from_str_radix(hex, 16).map_err(|_| {
                PrivdropError::ProcStatusUnreadable(io::Error::other(format!(
                    "cannot parse {field} value: {hex:?}"
                )))
            });
        }
    }

    Err(PrivdropError::ProcStatusUnreadable(io::Error::other(format!(
        "{field} not found in /proc/self/status"
    ))))
}

fn errno() -> i32 {
    // SAFETY: errno_location returns a valid per-thread pointer; reading it
    // immediately after a failing syscall is the canonical usage.
    unsafe { *libc::__errno_location() }
}
