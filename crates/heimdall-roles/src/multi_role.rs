// SPDX-License-Identifier: MIT

//! Multi-role query dispatcher (auth + recursive coexistence).
//!
//! [`MultiRoleDispatcher`] routes each incoming DNS query to the correct role:
//!
//! - Queries whose QNAME is covered by a loaded authoritative zone are handled
//!   by the [`AuthServer`] (AA=1 responses, NXDOMAIN
//!   for non-existent names within the zone).
//! - All other queries are handed to the recursive resolver (AA=0 responses).
//!
//! This allows a single Heimdall instance to serve both local authoritative
//! data and act as a full recursive resolver for external names simultaneously.

use std::{
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

use heimdall_core::parser::Message;
use heimdall_runtime::{QueryDispatcher, admission::AdmissionTelemetry};

use crate::{auth::AuthServer, recursive::RecursiveServer};

/// Composite dispatcher that routes between the authoritative and recursive roles.
///
/// Routing rule: if the query QNAME falls within any loaded authoritative zone
/// (`AuthServer::owns_qname`), auth answers; otherwise the recursive resolver
/// handles the query.
pub struct MultiRoleDispatcher {
    auth: Arc<AuthServer>,
    recursive: RecursiveServer,
    telemetry: Arc<AdmissionTelemetry>,
}

impl MultiRoleDispatcher {
    /// Build a new dispatcher combining `auth` and `recursive` roles.
    ///
    /// `telemetry` is used to increment `queries_recursive_total` for queries
    /// routed to the recursive role.  Auth increments `queries_auth_total`
    /// internally via its own telemetry reference.
    #[must_use]
    pub fn new(
        auth: Arc<AuthServer>,
        recursive: RecursiveServer,
        telemetry: Arc<AdmissionTelemetry>,
    ) -> Self {
        Self {
            auth,
            recursive,
            telemetry,
        }
    }
}

impl QueryDispatcher for MultiRoleDispatcher {
    fn dispatch(&self, msg: &Message, src: IpAddr, is_udp: bool) -> Vec<u8> {
        let use_auth = msg
            .questions
            .first()
            .is_none_or(|q| self.auth.owns_qname(&q.qname)); // no question → let auth produce FORMERR

        if use_auth {
            // auth counter is incremented inside AuthServer::dispatch
            self.auth.dispatch(msg, src, is_udp)
        } else {
            self.telemetry
                .queries_recursive_total
                .fetch_add(1, Ordering::Relaxed);
            self.recursive.dispatch(msg, src, is_udp)
        }
    }
}
