// SPDX-License-Identifier: MIT

//! DoH/H3 outbound client stub (Task #330).
//!
//! A compile-correct stub that satisfies the [`UpstreamClient`] trait.
//! Actual HTTP/3 implementation requires integration sprint wiring (h3, h3-quinn,
//! quinn) and is deferred.

use std::future::Future;
use std::io;
use std::pin::Pin;

use heimdall_core::parser::Message;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

// ── DohH3ClientStub ───────────────────────────────────────────────────────────

/// Stub for the DoH/HTTP3 outbound client.
///
/// Returns [`io::ErrorKind::Unsupported`] on every query.  The full
/// implementation requires integration sprint wiring.
pub struct DohH3ClientStub;

impl UpstreamClient for DohH3ClientStub {
    fn query<'a>(
        &'a self,
        _upstream: &'a UpstreamConfig,
        _msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DoH/H3 outbound client requires integration sprint wiring",
            ))
        })
    }
}
