// SPDX-License-Identifier: MIT

//! DoH/H2 outbound client stub (Task #329).
//!
//! A compile-correct stub that satisfies the [`UpstreamClient`] trait.
//! Actual HTTP/2 implementation requires integration sprint wiring (hyper, h2,
//! rustls) and is deferred.

use std::future::Future;
use std::io;
use std::pin::Pin;

use heimdall_core::parser::Message;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

// ── DohH2ClientStub ───────────────────────────────────────────────────────────

/// Stub for the DoH/HTTP2 outbound client.
///
/// Returns [`io::ErrorKind::Unsupported`] on every query.  The full
/// implementation requires integration sprint wiring.
pub struct DohH2ClientStub;

impl UpstreamClient for DohH2ClientStub {
    fn query<'a>(
        &'a self,
        _upstream: &'a UpstreamConfig,
        _msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DoH/H2 outbound client requires integration sprint wiring",
            ))
        })
    }
}
