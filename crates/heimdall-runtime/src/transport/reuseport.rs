// SPDX-License-Identifier: MIT

//! `SO_REUSEPORT` UDP socket binding helper (BIN-058, Sprint 67 task #676).
//!
//! Tokio's `UdpSocket::bind` path does not expose `SO_REUSEPORT`, so we build
//! the socket via [`socket2`], configure the option, bind it, switch it to
//! non-blocking mode, and hand the resulting [`std::net::UdpSocket`] to
//! [`tokio::net::UdpSocket::from_std`].
//!
//! ## Platform semantics
//!
//! - **Linux ≥ 3.9**: `SO_REUSEPORT` enables a reuseport group on the
//!   `(addr, port)` 4-tuple key.  The kernel hashes inbound datagrams across
//!   members of the group by 4-tuple, providing per-flow load balancing
//!   across N worker sockets.  This is the path used by the multi-worker UDP
//!   listener fan-out.
//!
//! - **macOS / BSD**: `SO_REUSEPORT` exists but does **not** provide
//!   load-balancing.  Every socket in the group receives every datagram, so
//!   the option is useful for graceful restart but **not** for scaling.  The
//!   boot path therefore caps the worker count to `1` on these targets and
//!   logs a `WARN`; this module's helper is only callable on Linux to make
//!   the platform restriction explicit.
//!
//! ## Why this is safe Rust
//!
//! All socket-syscall unsafety is encapsulated inside the [`socket2`] crate,
//! which has been audited for soundness by the wider ecosystem.  This module
//! contains only safe API calls.  The crate-level `#![deny(unsafe_code)]`
//! lint therefore remains in force.

use std::{io, net::SocketAddr};

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(target_os = "linux")]
use tokio::net::UdpSocket;

// ── bind_reuseport_udp ────────────────────────────────────────────────────────

/// Bind a UDP socket with `SO_REUSEPORT` set, ready to be wrapped in a
/// [`tokio::net::UdpSocket`].
///
/// `recv_buffer_bytes`, when `Some`, is requested via `SO_RCVBUF`.  The kernel
/// silently caps the request at `net.core.rmem_max`; the call is best-effort
/// and not surfaced as a hard error if the kernel returns a smaller buffer.
///
/// Returns a `tokio::net::UdpSocket` ready for use in a tokio task.
///
/// # Errors
///
/// Returns [`io::Error`] when:
/// - the socket cannot be created (out of file descriptors, EAFNOSUPPORT, …);
/// - `SO_REUSEPORT` cannot be set (kernel < 3.9 or container that strips
///   `CAP_NET_BIND_SERVICE` on the syscall);
/// - the bind fails (address in use without `SO_REUSEPORT` agreement, ACL
///   denial, port < 1024 without privilege, …);
/// - switching to non-blocking mode fails (extremely rare).
///
/// # Linux-only
///
/// This function is only compiled on Linux because BSD-flavoured platforms
/// (including macOS) implement `SO_REUSEPORT` with different semantics — see
/// the module-level documentation.
#[cfg(target_os = "linux")]
pub fn bind_reuseport_udp(
    addr: SocketAddr,
    recv_buffer_bytes: Option<usize>,
) -> io::Result<UdpSocket> {
    // Domain follows the address family.  Type::DGRAM + Protocol::UDP selects
    // a non-blocking-capable UDP socket; we set non-blocking below.
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // SO_REUSEADDR + SO_REUSEPORT.  REUSEADDR allows the bind to succeed if
    // the previous instance left a socket in TIME_WAIT (rare for UDP but
    // costs nothing); REUSEPORT is the load-balancing knob we want.
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;

    // SO_RCVBUF: best-effort.  We swallow errors and let the operator inspect
    // `ss -uap` / `cat /proc/net/udp` if the buffer is smaller than requested.
    if let Some(want) = recv_buffer_bytes {
        let _ = sock.set_recv_buffer_size(want);
    }

    // Bind on the (addr, port) tuple shared across all reuseport members.
    sock.bind(&addr.into())?;

    // tokio::net::UdpSocket::from_std requires the std socket to be
    // non-blocking.  socket2's flag is platform-specific; calling it here is
    // both correct on Linux and matches Tokio's expectation.
    sock.set_nonblocking(true)?;

    // Hand the file descriptor to std::net::UdpSocket, then to tokio.
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

// ── Non-Linux stub: signal callers to use the single-worker path ──────────────

/// `SO_REUSEPORT` UDP binding is only meaningful on Linux.  On other targets
/// the helper unconditionally returns [`io::ErrorKind::Unsupported`] so callers
/// fall back to the single-worker bind path.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`] on non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub fn bind_reuseport_udp(
    _addr: SocketAddr,
    _recv_buffer_bytes: Option<usize>,
) -> io::Result<tokio::net::UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT fan-out is only supported on Linux; callers must fall back \
         to a single UDP worker per listener on this platform",
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// On Linux, binding two sockets to the same `(127.0.0.1, ephemeral)`
    /// address with `SO_REUSEPORT` set must succeed.  We grab an ephemeral
    /// port from the first bind, then explicitly bind a second socket on
    /// the same address — without `SO_REUSEPORT` this would fail with
    /// `EADDRINUSE`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_sockets_can_share_same_port_on_linux() {
        let first = bind_reuseport_udp("127.0.0.1:0".parse().expect("valid v4 addr"), None)
            .expect("first bind");
        let addr = first.local_addr().expect("local_addr");
        let _second =
            bind_reuseport_udp(addr, None).expect("second bind must succeed under SO_REUSEPORT");
        // Both sockets stay alive until the end of the test — this is the
        // condition `EADDRINUSE` would prevent.
    }

    /// On non-Linux platforms the helper must surface `Unsupported` so
    /// the boot path falls back cleanly.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_returns_unsupported() {
        let err = bind_reuseport_udp("127.0.0.1:0".parse().expect("valid v4 addr"), None)
            .expect_err("must error on non-linux");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
