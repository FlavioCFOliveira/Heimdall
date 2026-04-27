// SPDX-License-Identifier: MIT

//! OpenBSD pledge(2) and unveil(2) wrappers (THREAT-029).
//!
//! pledge(2) restricts the set of permitted system-call classes to those named
//! in the `promises` string. Once pledged, any system call outside the named
//! set causes the kernel to deliver SIGABRT to the process.
//!
//! unveil(2) restricts filesystem access to a set of explicitly revealed paths.
//! After calling `unveil_lock()`, all other paths become inaccessible.
//!
//! # Safety
//!
//! Both syscall wrappers use `unsafe` blocks to call into libc. Invariants are
//! documented at each call site.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fmt;

/// Error returned when pledge(2) or unveil(2) fails.
#[derive(Debug)]
pub struct PledgeError {
    op: &'static str,
    errno: i32,
}

impl fmt::Display for PledgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}() failed: errno {}", self.op, self.errno)
    }
}

impl std::error::Error for PledgeError {}

/// Restricts the calling process to the given `promises` syscall classes.
///
/// `execpromises` is the set applied to future `execve` calls; pass `None` to
/// retain no promises across exec (effectively disabling exec after pledge).
///
/// # Errors
///
/// Returns [`PledgeError`] if the kernel rejects the pledge call (e.g., the
/// process is trying to extend its current promise set, which is not allowed).
pub fn pledge(promises: &str, execpromises: Option<&str>) -> Result<(), PledgeError> {
    let c_promises = CString::new(promises).map_err(|_| PledgeError { op: "pledge", errno: libc::EINVAL })?;

    let ret = match execpromises {
        Some(ep) => {
            let c_ep = CString::new(ep).map_err(|_| PledgeError { op: "pledge", errno: libc::EINVAL })?;
            // SAFETY: both CString values are valid NUL-terminated strings whose
            // lifetimes extend through the syscall. The return value is checked
            // immediately.
            unsafe { libc::pledge(c_promises.as_ptr(), c_ep.as_ptr()) }
        }
        None => {
            // SAFETY: c_promises is a valid NUL-terminated string; NULL is the
            // documented value for "no execpromises" on OpenBSD.
            unsafe { libc::pledge(c_promises.as_ptr(), std::ptr::null()) }
        }
    };

    if ret != 0 {
        let e = unsafe { *libc::__errno() };
        Err(PledgeError { op: "pledge", errno: e })
    } else {
        Ok(())
    }
}

/// Reveals `path` to the calling process with the given `permissions`.
///
/// `permissions` is a string of one or more of: `r` (read), `w` (write),
/// `x` (execute), `c` (create).
///
/// # Errors
///
/// Returns [`PledgeError`] if the unveil call fails.
pub fn unveil(path: &str, permissions: &str) -> Result<(), PledgeError> {
    let c_path = CString::new(path).map_err(|_| PledgeError { op: "unveil", errno: libc::EINVAL })?;
    let c_perms = CString::new(permissions).map_err(|_| PledgeError { op: "unveil", errno: libc::EINVAL })?;

    // SAFETY: both CString values are valid NUL-terminated strings. The kernel
    // copies the strings internally; they need only live through the syscall.
    let ret = unsafe { libc::unveil(c_path.as_ptr(), c_perms.as_ptr()) };

    if ret != 0 {
        let e = unsafe { *libc::__errno() };
        Err(PledgeError { op: "unveil", errno: e })
    } else {
        Ok(())
    }
}

/// Locks the unveil set, making all paths not previously revealed inaccessible.
///
/// Equivalent to `unveil(NULL, NULL)` per the OpenBSD man page.
///
/// # Errors
///
/// Returns [`PledgeError`] if the lock call fails.
pub fn unveil_lock() -> Result<(), PledgeError> {
    // SAFETY: unveil(NULL, NULL) is the documented way to finalise the unveil
    // set. Both arguments are NULL pointers, which is explicitly permitted.
    let ret = unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) };

    if ret != 0 {
        let e = unsafe { *libc::__errno() };
        Err(PledgeError { op: "unveil_lock", errno: e })
    } else {
        Ok(())
    }
}
