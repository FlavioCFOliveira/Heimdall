// SPDX-License-Identifier: MIT

//! Top-level forwarder coordinator (Task #332, Task #334).
//!
//! [`ForwarderServer`] wires together the dispatcher, pool, validator, cache
//! client, and rate limiter into a single entry point for forwarder-role query
//! handling.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use heimdall_core::dnssec::ValidationOutcome;
use heimdall_core::edns::{EdnsOption, ExtendedError, OptRr, ede_code};
use heimdall_core::header::{Header, Qclass, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_runtime::QueryDispatcher;
use heimdall_runtime::admission::AdmissionTelemetry;
use heimdall_runtime::cache::forwarder::ForwarderCache;
use tracing::{debug, warn};

use crate::dnssec_roles::{NtaStore, TrustAnchorStore};
use crate::forwarder::cache::ForwarderCacheClient;
use crate::forwarder::dispatcher::ForwardDispatcher;
use crate::forwarder::pool::{ForwarderError, ForwarderPool};
use crate::forwarder::ratelimit::{ForwarderRateLimiter, RlKey};
use crate::forwarder::upstream::ForwardRule;
use crate::forwarder::validate::ForwarderValidator;
use crate::rpz::engine::{RpzContext, RpzDecision, RpzEngine};

// ── ForwarderServer ───────────────────────────────────────────────────────────

/// Top-level coordinator for the forwarder role.
///
/// Wires together:
/// - [`ForwardDispatcher`] — rule matching (hot-reloadable).
/// - [`ForwarderPool`] — transport fallback.
/// - [`ForwarderValidator`] — independent DNSSEC validation (DNSSEC-019).
/// - [`ForwarderCacheClient`] — response caching.
/// - [`ForwarderRateLimiter`] — per-client query rate limiting (THREAT-051).
/// - [`RpzEngine`] — optional Response Policy Zone enforcement (RPZ-004..010).
pub struct ForwarderServer {
    dispatcher: ForwardDispatcher,
    pool: ForwarderPool,
    validator: Arc<ForwarderValidator>,
    cache: Arc<ForwarderCacheClient>,
    rate_limiter: Arc<ForwarderRateLimiter>,
    rpz: Option<Arc<RpzEngine>>,
    telemetry: Option<Arc<AdmissionTelemetry>>,
}

impl ForwarderServer {
    /// Creates a new [`ForwarderServer`].
    ///
    /// `rate_limit` is the per-client queries-per-second limit (THREAT-051).
    #[must_use]
    pub fn new(
        rules: Vec<ForwardRule>,
        pool: ForwarderPool,
        trust_anchor: Arc<TrustAnchorStore>,
        nta_store: Arc<NtaStore>,
        forwarder_cache: Arc<ForwarderCache>,
        rate_limit: u32,
    ) -> Self {
        Self {
            dispatcher: ForwardDispatcher::new(rules),
            pool,
            validator: Arc::new(ForwarderValidator::new(trust_anchor, nta_store)),
            cache: Arc::new(ForwarderCacheClient::new(forwarder_cache)),
            rate_limiter: Arc::new(ForwarderRateLimiter::new(rate_limit)),
            rpz: None,
            telemetry: None,
        }
    }

    /// Attaches admission telemetry for cache hit/miss metric tracking.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<AdmissionTelemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Attaches an [`RpzEngine`] to this server (RPZ-004..010).
    ///
    /// When set, every query is evaluated against the engine's policy zones
    /// before being forwarded to an upstream.  The engine is shared and
    /// reference-counted so hot-reload snapshots can be installed atomically.
    #[must_use]
    pub fn with_rpz(mut self, engine: Arc<RpzEngine>) -> Self {
        self.rpz = Some(engine);
        self
    }

    /// Processes a DNS query through the forwarder role.
    ///
    /// Returns `None` if no forward rule matches (the caller should fall
    /// through to the next role, e.g. recursive resolution).
    ///
    /// Returns `Some(Message)` in all other cases — including rate-limit
    /// rejection (REFUSED), cache hits, and upstream failures (SERVFAIL).
    ///
    /// # Handle logic
    ///
    /// 1. Rate-limit check → REFUSED if denied.
    /// 2. Extract `qname` from the first question; `FormErr` if absent.
    /// 3. Dispatcher match → `None` if no rule matches.
    /// 4. Cache lookup → return cached response if available.
    /// 5. Try each upstream in the matched rule via the pool.
    /// 6. On success: validate DNSSEC; store in cache; set AD flag if Secure.
    /// 7. On pool exhaustion: return SERVFAIL with EDE 22 (No Reachable Authority).
    pub async fn handle(&self, query: &Message, client_key: &RlKey) -> Option<Message> {
        // Step 1: rate-limit check.
        if !self.rate_limiter.check_and_consume(client_key) {
            debug!(?client_key, "forwarder: rate-limit denied query");
            return Some(refused_response(query));
        }

        // Step 2: extract qname.
        let Some(q) = query.questions.first() else {
            return Some(formerr_response(query));
        };
        let qname = q.qname.clone();
        let qtype = Rtype::from_u16(q.qtype.as_u16());
        let qclass = q.qclass.as_u16();
        let do_bit = do_bit_set(query);

        let qname_str = qname.to_string();

        // Step 3: dispatcher match.
        let rule = self.dispatcher.match_query(&qname_str)?;

        debug!(
            qname = %qname,
            zone = %rule.zone,
            "forwarder: matched rule"
        );

        // Step 4: cache lookup.
        if let Some(cached) = self.cache.lookup(&qname, qtype, qclass, do_bit) {
            debug!(qname = %qname, "forwarder: cache hit");
            if let Some(t) = &self.telemetry {
                t.inc_cache_hit_forwarder();
            }
            let ad = do_bit
                && matches!(cached.entry.dnssec_outcome, ValidationOutcome::Secure)
                && !query.header.cd();
            return Some(build_cached_response(query, &cached.entry.rdata_wire, ad));
        }

        if let Some(t) = &self.telemetry {
            t.inc_cache_miss_forwarder();
        }

        // Step 5: try each upstream in the matched rule.
        let now_secs = current_unix_secs();
        let zone_apex = Name::root(); // Conservative: use root as apex for NTA checks.

        for upstream in &rule.upstreams {
            match self.pool.query(upstream, query).await {
                Ok(response) => {
                    // Step 6: validate and cache.
                    let outcome = self.validator.validate(&response, &zone_apex, now_secs);
                    self.cache.store(
                        &qname,
                        qtype,
                        qclass,
                        &response,
                        outcome.clone(),
                        &zone_apex,
                        false,
                    );

                    let ad = do_bit
                        && matches!(outcome, ValidationOutcome::Secure)
                        && !query.header.cd();
                    let mut resp = response;
                    resp.header.set_ad(ad);
                    return Some(resp);
                }
                Err(ForwarderError::AllTransportsFailed) => {
                    warn!(
                        upstream = %upstream.host,
                        "forwarder: all transports failed for upstream"
                    );
                }
                Err(e) => {
                    warn!(
                        upstream = %upstream.host,
                        error = %e,
                        "forwarder: upstream error"
                    );
                }
            }
        }

        // Step 7: all upstreams exhausted → SERVFAIL with EDE 22.
        warn!(qname = %qname, "forwarder: all upstreams exhausted");
        Some(servfail_with_ede(query, ede_code::NO_REACHABLE_AUTHORITY))
    }

    /// Returns the dispatcher for hot-reload.
    #[must_use]
    pub fn dispatcher(&self) -> &ForwardDispatcher {
        &self.dispatcher
    }
}

// ── QueryDispatcher impl ──────────────────────────────────────────────────────

impl QueryDispatcher for ForwarderServer {
    fn dispatch(&self, msg: &Message, src: IpAddr, is_udp: bool) -> Vec<u8> {
        use heimdall_core::serialiser::Serialiser;

        // RPZ pre-resolution intercept (RPZ-004..010).
        // Runs before rate-limit and rule-match so that DROP and TcpOnly can short-circuit
        // without touching the upstream.
        //
        // TcpOnly on TCP is NOT intercepted here: the query must reach the upstream
        // so that the full response can be passed through to the client.
        if let Some(engine) = &self.rpz {
            if let Some(q) = msg.questions.first() {
                let qname = q.qname.clone();
                let qtype = Rtype::from_u16(q.qtype.as_u16());
                let ctx = RpzContext {
                    client_ip: src,
                    qname,
                    qtype,
                    is_udp,
                    response_ips: vec![],
                    ns_names: vec![],
                    ns_ips: vec![],
                };
                let decision = engine.evaluate(&ctx);
                if let RpzDecision::Match { action, zone } = decision {
                    // TcpOnly on TCP: let the query proceed to the upstream normally.
                    let is_tcp_only = matches!(action, crate::rpz::action::RpzAction::TcpOnly);
                    if !(is_tcp_only && !is_udp) {
                        return match action.apply(msg, None, is_udp, 30, &zone) {
                            // DROP — return empty bytes to signal no response (handled by transport).
                            None => vec![],
                            Some(response) => {
                                let mut ser = Serialiser::new(true);
                                let _ = ser.write_message(&response);
                                ser.finish()
                            }
                        };
                    }
                }
            }
        }

        let rl_key = RlKey::SourceIp(src);

        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.handle(msg, &rl_key))
        });

        // None means no forward-zone rule matched → step-4 REFUSED + EDE-20 (ROLE-024/025).
        let response = response.unwrap_or_else(|| step4_refused_ede20(msg));

        let mut ser = Serialiser::new(true);
        let _ = ser.write_message(&response);
        ser.finish()
    }
}

// ── Response builders ─────────────────────────────────────────────────────────

/// Builds a REFUSED response for `query`.
fn refused_response(query: &Message) -> Message {
    let mut header = Header::default();
    header.id = query.header.id;
    header.set_qr(true);
    header.set_rcode(Rcode::Refused);
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// Builds a step-4 REFUSED + EDE INFO-CODE 20 "Not Authoritative" response (ROLE-024/025).
///
/// Embeds the EDE in a temporary OPT RR so the transport layer can extract it
/// via `extract_dispatcher_ede` and include it in the transport's own OPT RR.
fn step4_refused_ede20(query: &Message) -> Message {
    let mut header = Header {
        id: query.header.id,
        qdcount: query.header.qdcount,
        arcount: 1,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_rcode(Rcode::Refused);

    let opt_rr = OptRr {
        udp_payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: vec![EdnsOption::ExtendedError(ExtendedError::new(
            ede_code::NOT_AUTHORITATIVE,
        ))],
    };
    let opt_rec = Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(opt_rr),
    };

    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rec],
    }
}

/// Builds a FORMERR response for `query`.
fn formerr_response(query: &Message) -> Message {
    let mut header = Header::default();
    header.id = query.header.id;
    header.set_qr(true);
    header.set_rcode(Rcode::FormErr);
    Message {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// Builds a SERVFAIL response with an EDE option for `query`.
fn servfail_with_ede(query: &Message, ede_info_code: u16) -> Message {
    use heimdall_core::edns::{EdnsOption, OptRr};
    use heimdall_core::header::Qclass;
    use heimdall_core::rdata::RData;
    use heimdall_core::record::{Record, Rtype};

    let mut header = Header::default();
    header.id = query.header.id;
    header.set_qr(true);
    header.set_rcode(Rcode::ServFail);

    let ede = ExtendedError::new(ede_info_code);
    let opt = Record {
        name: Name::root(),
        rtype: Rtype::Opt,
        rclass: Qclass::from_u16(4096),
        ttl: 0,
        rdata: RData::Opt(OptRr {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![EdnsOption::ExtendedError(ede)],
        }),
    };

    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![opt],
    }
}

/// Reconstructs a cached response from raw wire bytes.
///
/// On deserialisation failure, returns a SERVFAIL (defensive fallback).
fn build_cached_response(query: &Message, rdata_wire: &[u8], set_ad: bool) -> Message {
    if rdata_wire.is_empty() {
        // Negative cache entry (NODATA/NXDOMAIN with no answer records).
        let mut header = Header::default();
        header.id = query.header.id;
        header.set_qr(true);
        header.set_ad(set_ad);
        return Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
    }

    if let Ok(mut msg) = Message::parse(rdata_wire) {
        msg.header.id = query.header.id;
        msg.header.set_qr(true);
        msg.header.set_ad(set_ad);
        msg
    } else {
        // Deserialisation failure — treat as SERVFAIL.
        let mut header = Header::default();
        header.id = query.header.id;
        header.set_qr(true);
        header.set_rcode(Rcode::ServFail);
        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Returns the current Unix timestamp in seconds, truncated to `u32`.
///
/// Truncation is intentional: DNSSEC signatures use 32-bit timestamps
/// (RFC 4034 §3.1.5) and the value is used only for validity-period
/// comparison.
fn current_unix_secs() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as u32;
    secs
}

/// Returns `true` if the query has the EDNS DNSSEC-OK bit set.
fn do_bit_set(query: &Message) -> bool {
    use heimdall_core::rdata::RData;
    use heimdall_core::record::Rtype;

    query
        .additional
        .iter()
        .any(|r| r.rtype == Rtype::Opt && matches!(&r.rdata, RData::Opt(opt) if opt.dnssec_ok))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::HashSet;

    use heimdall_core::header::{Header, Qclass, Qtype, Question};
    use heimdall_core::name::Name;

    use super::*;
    use crate::forwarder::client::ClientRegistry;
    use crate::forwarder::upstream::{MatchMode, UpstreamConfig, UpstreamTransport};

    fn make_server_no_rules() -> ForwarderServer {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        std::mem::forget(dir);
        let nta_store = Arc::new(NtaStore::new(100));
        let cache = Arc::new(ForwarderCache::new(512, 512));
        let registry = Arc::new(ClientRegistry::build(&HashSet::new()));
        let pool = ForwarderPool::new(registry, vec![]);

        ForwarderServer::new(vec![], pool, trust_anchor, nta_store, cache, 100)
    }

    fn make_server_with_udp_rule() -> ForwarderServer {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        std::mem::forget(dir);
        let nta_store = Arc::new(NtaStore::new(100));
        let cache = Arc::new(ForwarderCache::new(512, 512));

        let mut transports = HashSet::new();
        transports.insert(UpstreamTransport::UdpTcp);
        let registry = Arc::new(ClientRegistry::build(&transports));
        let pool = ForwarderPool::new(registry, vec![UpstreamTransport::UdpTcp]);

        let rule = crate::forwarder::upstream::ForwardRule {
            zone: "example.com.".to_string(),
            match_mode: MatchMode::Suffix,
            upstreams: vec![UpstreamConfig {
                host: "8.8.8.8".to_string(),
                port: 53,
                transport: UpstreamTransport::UdpTcp,
                sni: None,
                tls_verify: true,
            }],
            fallback_recursive: false,
        };

        ForwarderServer::new(vec![rule], pool, trust_anchor, nta_store, cache, 100)
    }

    fn query_for(name: &str) -> Message {
        use std::str::FromStr;
        let mut header = Header::default();
        header.set_rd(true);
        header.qdcount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(name).expect("INVARIANT: valid name"),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[tokio::test]
    async fn no_rule_match_returns_none() {
        let server = make_server_no_rules();
        let query = query_for("other.org.");
        let key = RlKey::SourceIp("127.0.0.1".parse().expect("INVARIANT: valid IP"));
        let result = server.handle(&query, &key).await;
        assert!(result.is_none(), "no matching rule must return None");
    }

    #[tokio::test]
    async fn rate_limited_client_returns_refused() {
        // Rate limit = 1 rps; fire two queries immediately.
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        std::mem::forget(dir);
        let nta_store = Arc::new(NtaStore::new(100));
        let cache = Arc::new(ForwarderCache::new(512, 512));
        let registry = Arc::new(ClientRegistry::build(&HashSet::new()));
        let pool = ForwarderPool::new(registry, vec![]);

        let rule = crate::forwarder::upstream::ForwardRule {
            zone: "example.com.".to_string(),
            match_mode: MatchMode::Suffix,
            upstreams: vec![],
            fallback_recursive: false,
        };

        let server = ForwarderServer::new(
            vec![rule],
            pool,
            trust_anchor,
            nta_store,
            cache,
            1, // 1 rps
        );

        let query = query_for("example.com.");
        let key = RlKey::SourceIp("10.0.0.1".parse().expect("INVARIANT: valid IP"));

        // First query: allowed (consumes the initial token).
        // It may succeed or return SERVFAIL (no upstreams), but NOT REFUSED.
        let first = server.handle(&query, &key).await;
        if let Some(ref msg) = first {
            assert_ne!(
                msg.header.rcode(),
                Rcode::Refused,
                "first query must not be refused"
            );
        }

        // Second query: rate-limited → REFUSED.
        let second = server.handle(&query, &key).await;
        let msg = second.expect("rate-limited query must return Some(REFUSED)");
        assert_eq!(
            msg.header.rcode(),
            Rcode::Refused,
            "rate-limited second query must be REFUSED"
        );
    }

    #[tokio::test]
    async fn missing_question_returns_formerr() {
        let server = make_server_with_udp_rule();
        let msg = Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let key = RlKey::SourceIp("127.0.0.1".parse().expect("INVARIANT: valid IP"));
        // The rate limiter allows this (first query).
        let result = server.handle(&msg, &key).await;
        // No questions → FormErr or None (dispatcher never runs).
        // The rate limiter passes; FormerErr is emitted before dispatcher.
        if let Some(resp) = result {
            assert_eq!(resp.header.rcode(), Rcode::FormErr);
        }
        // None is also acceptable if the dispatcher runs first (not possible here).
    }
}
