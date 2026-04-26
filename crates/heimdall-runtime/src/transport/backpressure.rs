// SPDX-License-Identifier: MIT

//! Transport-specific backpressure action mapping (THREAT-071, THREAT-072, THREAT-075).
//!
//! When the admission pipeline denies a request, the transport layer must decide
//! what to do with the underlying socket: silently drop the datagram, close the
//! TCP connection with FIN, or send a truncated response to encourage the client
//! to retry over TCP.
//!
//! The mapping is intentionally simple and per-transport so that it can be
//! evaluated on the hot path without allocation or branching on per-query state.

use crate::admission::{PipelineDecision, RrlDecision};

// ── BackpressureAction ────────────────────────────────────────────────────────

/// The action the transport layer must take when the admission pipeline denies
/// a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureAction {
    /// UDP: silently discard the datagram — send no response (THREAT-071).
    ///
    /// Prevents the server from being used as a reflection or amplification
    /// vehicle: an unanswered datagram gives the attacker no signal to exploit.
    UdpSilentDrop,
    /// TCP: send a FIN to perform a clean half-close after the current message
    /// (THREAT-072).
    ///
    /// Used for expected denial conditions (rate limit, backpressure) where
    /// there is no reason to believe the connection is malicious.
    TcpFinClose,
    /// TCP: send a RST to perform an unclean close.
    ///
    /// Reserved for cases where mid-stream write failures make a clean FIN
    /// impossible — the transport layer selects this action after detecting an
    /// I/O error, not from the pipeline decision alone.
    TcpRstClose,
    /// UDP: send a truncated response with TC=1 to encourage the client to
    /// retry over TCP (THREAT-075, `PROTO-117`).
    ///
    /// Used only for RRL slip events (`DenyRrl(Slip)`): the slip path is
    /// designed to let a fraction of rate-limited queries through in truncated
    /// form so that well-behaved clients can complete the query on TCP, where
    /// the rate limiter does not apply.
    TcTruncated,
}

// ── Public mapping functions ───────────────────────────────────────────────────

/// Maps a [`PipelineDecision`] to the correct [`BackpressureAction`] for a
/// **UDP** listener.
///
/// Rules (THREAT-071, THREAT-075):
/// - `DenyRrl(Slip)` → [`BackpressureAction::TcTruncated`] so the client can
///   retry over TCP and receive a full response.
/// - All other deny decisions → [`BackpressureAction::UdpSilentDrop`].
/// - `Allow` is never passed to this function in normal operation; if it is,
///   `UdpSilentDrop` is returned as a safe fallback.
#[must_use]
pub fn udp_backpressure(reason: &PipelineDecision) -> BackpressureAction {
    match reason {
        // RRL slip: send a TC=1 truncated response so the client retries over TCP.
        PipelineDecision::DenyRrl(RrlDecision::Slip) => BackpressureAction::TcTruncated,
        // Every other denial: silently discard — no amplification, no reflection.
        _ => BackpressureAction::UdpSilentDrop,
    }
}

/// Maps a [`PipelineDecision`] to the correct [`BackpressureAction`] for a
/// **TCP** listener.
///
/// Rules (THREAT-072):
/// - All deny decisions → [`BackpressureAction::TcpFinClose`].
/// - The transport layer independently switches to [`BackpressureAction::TcpRstClose`]
///   when a mid-stream write error is detected; that decision is not made here.
/// - `Allow` is never passed to this function in normal operation; if it is,
///   `TcpFinClose` is returned as a safe fallback.
#[must_use]
pub fn tcp_backpressure(_reason: &PipelineDecision) -> BackpressureAction {
    BackpressureAction::TcpFinClose
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{ConnLimitReason, PipelineDecision, RrlDecision};

    // ── UDP backpressure ──────────────────────────────────────────────────────

    #[test]
    fn udp_deny_acl_is_silent_drop() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyAcl),
            BackpressureAction::UdpSilentDrop,
        );
    }

    #[test]
    fn udp_deny_conn_limit_is_silent_drop() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyConnLimit {
                reason: ConnLimitReason::GlobalPending,
            }),
            BackpressureAction::UdpSilentDrop,
        );
    }

    #[test]
    fn udp_deny_cookie_under_load_is_silent_drop() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyCookieUnderLoad),
            BackpressureAction::UdpSilentDrop,
        );
    }

    #[test]
    fn udp_deny_rrl_drop_is_silent_drop() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyRrl(RrlDecision::Drop)),
            BackpressureAction::UdpSilentDrop,
        );
    }

    #[test]
    fn udp_deny_rrl_slip_is_tc_truncated() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyRrl(RrlDecision::Slip)),
            BackpressureAction::TcTruncated,
        );
    }

    #[test]
    fn udp_deny_query_rl_is_silent_drop() {
        assert_eq!(
            udp_backpressure(&PipelineDecision::DenyQueryRl),
            BackpressureAction::UdpSilentDrop,
        );
    }

    // ── TCP backpressure ──────────────────────────────────────────────────────

    #[test]
    fn tcp_deny_acl_is_fin_close() {
        assert_eq!(
            tcp_backpressure(&PipelineDecision::DenyAcl),
            BackpressureAction::TcpFinClose,
        );
    }

    #[test]
    fn tcp_deny_conn_limit_is_fin_close() {
        assert_eq!(
            tcp_backpressure(&PipelineDecision::DenyConnLimit {
                reason: ConnLimitReason::GlobalPending,
            }),
            BackpressureAction::TcpFinClose,
        );
    }

    #[test]
    fn tcp_deny_rrl_slip_is_fin_close() {
        // Unlike UDP, TCP does not slip to TC=1; it always FINs.
        assert_eq!(
            tcp_backpressure(&PipelineDecision::DenyRrl(RrlDecision::Slip)),
            BackpressureAction::TcpFinClose,
        );
    }

    #[test]
    fn tcp_deny_query_rl_is_fin_close() {
        assert_eq!(
            tcp_backpressure(&PipelineDecision::DenyQueryRl),
            BackpressureAction::TcpFinClose,
        );
    }
}
