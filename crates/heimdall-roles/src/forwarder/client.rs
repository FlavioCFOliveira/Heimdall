// SPDX-License-Identifier: MIT

//! Upstream client trait and transport registry.
//!
//! [`UpstreamClient`] is the abstract interface over a single outbound DNS
//! query to a specific upstream resolver.  [`ClientRegistry`] instantiates
//! and holds only the clients needed for the transports declared in the active
//! `ForwardRule` set (NET-014).

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use heimdall_core::parser::Message;

use crate::forwarder::client_classic::UdpTcpClient;
use crate::forwarder::client_doh_h2::DohH2Client;
use crate::forwarder::client_doh_h3::DohH3Client;
use crate::forwarder::client_doq::DoqClient;
use crate::forwarder::client_dot::DotClient;
use crate::forwarder::upstream::{UpstreamConfig, UpstreamTransport};

// ── UpstreamClient ────────────────────────────────────────────────────────────

/// Abstraction over a single outbound DNS query to a specific upstream resolver.
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// tasks.
pub trait UpstreamClient: Send + Sync {
    /// Sends `msg` to `upstream` and returns the DNS response.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the network operation fails, times out, or
    /// the upstream returns a malformed response.
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>>;
}

// ── ClientRegistry ────────────────────────────────────────────────────────────

/// Registry of instantiated transport clients.
///
/// Only clients for transports referenced in the active `ForwardRule` set
/// are allocated (NET-014).  Absent transport slots hold `None`.
pub struct ClientRegistry {
    udp_tcp: Option<Arc<UdpTcpClient>>,
    dot: Option<Arc<DotClient>>,
    doh_h2: Option<Arc<DohH2Client>>,
    doh_h3: Option<Arc<DohH3Client>>,
    doq: Option<Arc<DoqClient>>,
}

impl ClientRegistry {
    /// Builds the registry, instantiating only the clients for transports in
    /// `transports` (NET-014).
    ///
    /// `transports` is borrowed; ownership is not required.
    /// Transports absent from `transports` are left as `None`; their client
    /// constructors are not called.
    #[must_use]
    pub fn build(transports: &HashSet<UpstreamTransport>) -> Self {
        Self {
            udp_tcp: if transports.contains(&UpstreamTransport::UdpTcp) {
                Some(Arc::new(UdpTcpClient::new()))
            } else {
                None
            },
            dot: if transports.contains(&UpstreamTransport::Dot) {
                Some(Arc::new(DotClient::new()))
            } else {
                None
            },
            doh_h2: if transports.contains(&UpstreamTransport::DohH2) {
                Some(Arc::new(DohH2Client::new()))
            } else {
                None
            },
            doh_h3: if transports.contains(&UpstreamTransport::DohH3) {
                Some(Arc::new(DohH3Client::new()))
            } else {
                None
            },
            doq: if transports.contains(&UpstreamTransport::Doq) {
                Some(Arc::new(DoqClient::new()))
            } else {
                None
            },
        }
    }

    /// Returns the client for `transport`, or `None` if that transport was not
    /// declared in the rule set.
    #[must_use]
    pub fn get_client(&self, transport: &UpstreamTransport) -> Option<Arc<dyn UpstreamClient>> {
        match transport {
            UpstreamTransport::UdpTcp => self
                .udp_tcp
                .as_ref()
                .map(|c| Arc::clone(c) as Arc<dyn UpstreamClient>),
            UpstreamTransport::Dot => self
                .dot
                .as_ref()
                .map(|c| Arc::clone(c) as Arc<dyn UpstreamClient>),
            UpstreamTransport::DohH2 => self
                .doh_h2
                .as_ref()
                .map(|c| Arc::clone(c) as Arc<dyn UpstreamClient>),
            UpstreamTransport::DohH3 => self
                .doh_h3
                .as_ref()
                .map(|c| Arc::clone(c) as Arc<dyn UpstreamClient>),
            UpstreamTransport::Doq => self.doq.as_ref().map(|c| Arc::clone(c) as Arc<dyn UpstreamClient>),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_declared_transports_instantiated() {
        let mut transports = HashSet::new();
        transports.insert(UpstreamTransport::UdpTcp);

        let registry = ClientRegistry::build(&transports);

        // UdpTcp was declared → client present.
        assert!(
            registry.get_client(&UpstreamTransport::UdpTcp).is_some(),
            "UdpTcp client must be present"
        );

        // DoT was NOT declared → client absent.
        assert!(
            registry.get_client(&UpstreamTransport::Dot).is_none(),
            "DoT client must be absent when not declared"
        );

        // DohH2 was NOT declared → client absent.
        assert!(registry.get_client(&UpstreamTransport::DohH2).is_none());
    }

    #[test]
    fn empty_transports_produces_all_none() {
        let registry = ClientRegistry::build(&HashSet::new());
        assert!(registry.get_client(&UpstreamTransport::UdpTcp).is_none());
        assert!(registry.get_client(&UpstreamTransport::Dot).is_none());
        assert!(registry.get_client(&UpstreamTransport::DohH2).is_none());
        assert!(registry.get_client(&UpstreamTransport::DohH3).is_none());
        assert!(registry.get_client(&UpstreamTransport::Doq).is_none());
    }
}
