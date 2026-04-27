// SPDX-License-Identifier: MIT

//! DNS-over-QUIC outbound client stub (Task #331).
//!
//! A compile-correct stub that satisfies the [`UpstreamClient`] trait.
//! Actual QUIC implementation requires integration sprint wiring (quinn) and
//! is deferred.

use std::future::Future;
use std::io;
use std::pin::Pin;

use heimdall_core::parser::Message;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

// ── DoqClientStub ─────────────────────────────────────────────────────────────

/// Stub for the DNS-over-QUIC outbound client.
///
/// Returns [`io::ErrorKind::Unsupported`] on every query.  The full
/// implementation requires integration sprint wiring.
pub struct DoqClientStub;

impl UpstreamClient for DoqClientStub {
    fn query<'a>(
        &'a self,
        _upstream: &'a UpstreamConfig,
        _msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DoQ outbound client requires integration sprint wiring",
            ))
        })
    }
}
