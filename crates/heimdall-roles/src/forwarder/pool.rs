// SPDX-License-Identifier: MIT

//! Connection pool and transport fallback chain (Task #332).
//!
//! [`ForwarderPool`] tries each transport in a configurable fallback chain
//! until one query succeeds.  On chain exhaustion it returns
//! [`ForwarderError::AllTransportsFailed`].

use std::fmt;
use std::sync::Arc;

use heimdall_core::parser::Message;

use crate::forwarder::client::ClientRegistry;
use crate::forwarder::upstream::{UpstreamConfig, UpstreamTransport};

// ── ForwarderError ────────────────────────────────────────────────────────────

/// Errors produced by the forwarder transport layer.
#[derive(Debug)]
pub enum ForwarderError {
    /// Every transport in the fallback chain failed.
    AllTransportsFailed,
    /// The overall query budget was exhausted before a response arrived.
    Timeout,
    /// The upstream returned RCODE REFUSED.
    UpstreamRefused,
    /// The upstream returned RCODE SERVFAIL.
    UpstreamServFail,
    /// DNSSEC validation rejected the response.
    ValidationFailed(String),
}

impl fmt::Display for ForwarderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllTransportsFailed => write!(f, "all transports in the fallback chain failed"),
            Self::Timeout => write!(f, "forwarder query timed out"),
            Self::UpstreamRefused => write!(f, "upstream returned REFUSED"),
            Self::UpstreamServFail => write!(f, "upstream returned SERVFAIL"),
            Self::ValidationFailed(msg) => write!(f, "DNSSEC validation failed: {msg}"),
        }
    }
}

impl std::error::Error for ForwarderError {}

// ── ForwarderPool ─────────────────────────────────────────────────────────────

/// Manages the transport fallback chain for a forwarder upstream group.
///
/// On each call to [`query`], the pool walks `fallback_chain` in order,
/// attempting the query through each transport's client.  The first successful
/// response is returned; if every transport fails, [`ForwarderError::AllTransportsFailed`]
/// is returned.
///
/// [`query`]: ForwarderPool::query
pub struct ForwarderPool {
    registry: Arc<ClientRegistry>,
    /// Ordered transport fallback chain (e.g. `[DohH2, Dot, UdpTcp]`).
    fallback_chain: Vec<UpstreamTransport>,
}

impl ForwarderPool {
    /// Creates a new [`ForwarderPool`].
    #[must_use]
    pub fn new(registry: Arc<ClientRegistry>, fallback_chain: Vec<UpstreamTransport>) -> Self {
        Self {
            registry,
            fallback_chain,
        }
    }

    /// Tries each transport in the fallback chain until one query succeeds.
    ///
    /// Returns the first successful [`Message`] response.  If all transports
    /// fail, returns [`ForwarderError::AllTransportsFailed`].
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError::AllTransportsFailed`] if every transport in
    /// the chain returns an error or is not registered in the [`ClientRegistry`].
    pub async fn query(
        &self,
        upstream: &UpstreamConfig,
        msg: &Message,
    ) -> Result<Message, ForwarderError> {
        let mut last_error: Option<ForwarderError> = None;

        for transport in &self.fallback_chain {
            let Some(client) = self.registry.get_client(transport) else {
                // This transport was not declared in the rule set (NET-014).
                // Treat as a chain skip, not a hard failure.
                tracing::debug!(
                    ?transport,
                    "forwarder pool: transport not registered, skipping"
                );
                continue;
            };

            // Override the transport on the upstream config for this attempt.
            // The host/port/sni/tls_verify remain unchanged.
            let mut attempt_upstream = upstream.clone();
            attempt_upstream.transport = transport.clone();

            match client.query(&attempt_upstream, msg).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(
                        ?transport,
                        error = %e,
                        "forwarder pool: transport attempt failed"
                    );
                    last_error = Some(ForwarderError::AllTransportsFailed);
                }
            }
        }

        // All transports exhausted.
        let _ = last_error; // acknowledged
        Err(ForwarderError::AllTransportsFailed)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::forwarder::client::ClientRegistry;
    use crate::forwarder::upstream::{UpstreamConfig, UpstreamTransport};

    fn test_upstream() -> UpstreamConfig {
        UpstreamConfig {
            host: "127.0.0.1".to_string(),
            port: 53,
            transport: UpstreamTransport::UdpTcp,
            sni: None,
            tls_verify: true,
        }
    }

    fn minimal_message() -> Message {
        use heimdall_core::header::Header;
        Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[tokio::test]
    async fn chain_exhaustion_returns_error() {
        // Only DohH2 transport registered, which is a stub returning Unsupported.
        let mut transports = HashSet::new();
        transports.insert(UpstreamTransport::DohH2);
        let registry = Arc::new(ClientRegistry::build(&transports));

        // Fallback chain has DohH2 (stub → Unsupported) and UdpTcp (not registered).
        let pool = ForwarderPool::new(
            registry,
            vec![UpstreamTransport::DohH2, UpstreamTransport::UdpTcp],
        );

        let result = pool.query(&test_upstream(), &minimal_message()).await;
        assert!(
            matches!(result, Err(ForwarderError::AllTransportsFailed)),
            "exhausted chain must return AllTransportsFailed; got: {result:?}"
        );
    }

    #[tokio::test]
    async fn empty_chain_returns_error() {
        let registry = Arc::new(ClientRegistry::build(&HashSet::new()));
        let pool = ForwarderPool::new(registry, vec![]);
        let result = pool.query(&test_upstream(), &minimal_message()).await;
        assert!(matches!(result, Err(ForwarderError::AllTransportsFailed)));
    }
}
