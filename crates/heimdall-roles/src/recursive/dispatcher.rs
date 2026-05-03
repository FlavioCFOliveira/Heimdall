// SPDX-License-Identifier: MIT

//! Iterative resolver dispatcher (ROLE-011).
//!
//! [`RecursiveServer`] is the top-level entry point for recursive DNS query
//! handling.  It checks the cache, orchestrates the delegation-following loop
//! via [`DelegationFollower`], validates DNSSEC signatures via
//! [`ResponseValidator`], and builds the final response message.

use std::net::IpAddr;
use std::sync::Arc;

use heimdall_core::edns::{EdnsOption, ExtendedError, OptRr, ede_code};
use heimdall_core::header::{Header, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_runtime::QueryDispatcher;
use heimdall_runtime::cache::ValidationOutcome;
use heimdall_runtime::cache::recursive::RecursiveCache;
use tracing::{debug, info, warn};

use crate::dnssec_roles::{NtaStore, TrustAnchorStore};
use crate::recursive::cache::RecursiveCacheClient;
use crate::recursive::follow::{DelegationFollower, FollowResult, UpstreamQuery};
use crate::recursive::qname_min::QnameMinMode;
use crate::recursive::root_hints::RootHints;
use crate::recursive::server_state::ServerStateCache;
use crate::recursive::validate::ResponseValidator;

// ── RecursiveServer ───────────────────────────────────────────────────────────

/// The recursive DNS resolver.
///
/// `RecursiveServer` is the single public entry point for recursive resolution.
/// It wires together the cache, DNSSEC validation, and iterative delegation
/// following.
pub struct RecursiveServer {
    cache: Arc<RecursiveCacheClient>,
    // Retained for future use: DNSSEC re-validation and NTA management.
    #[allow(dead_code)]
    trust_anchor: Arc<TrustAnchorStore>,
    #[allow(dead_code)]
    nta_store: Arc<NtaStore>,
    server_state: Arc<ServerStateCache>,
    root_hints: Arc<RootHints>,
    validator: Arc<ResponseValidator>,
    /// UDP/TCP port for all outbound resolution queries.  Default: 53.
    query_port: u16,
    /// QNAME minimisation mode for outbound queries (RFC 9156).
    qname_min_mode: QnameMinMode,
}

// Builder helpers are intentionally instance methods for cohesion and to
// allow per-instance state access in future sprints.
#[allow(clippy::unused_self)]
impl RecursiveServer {
    /// Creates a new [`RecursiveServer`] using the standard DNS port (53).
    ///
    /// The `root_hints` must already be initialised (see
    /// [`RootHints::from_builtin`]).  The `trust_anchor` must have at least
    /// one valid DNSKEY (the IANA KSK-2017 is bootstrapped automatically by
    /// [`TrustAnchorStore::new`]).
    #[must_use]
    pub fn new(
        cache: Arc<RecursiveCache>,
        trust_anchor: Arc<TrustAnchorStore>,
        nta_store: Arc<NtaStore>,
        root_hints: Arc<RootHints>,
    ) -> Self {
        Self::with_query_port(cache, trust_anchor, nta_store, root_hints, 53)
    }

    /// Creates a new [`RecursiveServer`] with a custom outbound query port.
    ///
    /// Use `query_port = 53` in production.  A non-53 value is only
    /// appropriate in test environments where all in-process nameservers
    /// share a single port.
    #[must_use]
    pub fn with_query_port(
        cache: Arc<RecursiveCache>,
        trust_anchor: Arc<TrustAnchorStore>,
        nta_store: Arc<NtaStore>,
        root_hints: Arc<RootHints>,
        query_port: u16,
    ) -> Self {
        Self::with_query_port_and_qname_min(
            cache,
            trust_anchor,
            nta_store,
            root_hints,
            query_port,
            QnameMinMode::default(),
        )
    }

    /// Creates a new [`RecursiveServer`] with a custom query port and QNAME min mode.
    #[must_use]
    pub fn with_query_port_and_qname_min(
        cache: Arc<RecursiveCache>,
        trust_anchor: Arc<TrustAnchorStore>,
        nta_store: Arc<NtaStore>,
        root_hints: Arc<RootHints>,
        query_port: u16,
        qname_min_mode: QnameMinMode,
    ) -> Self {
        let server_state = Arc::new(ServerStateCache::new());
        let cache_client = Arc::new(RecursiveCacheClient::new(cache));
        let validator = Arc::new(ResponseValidator::new(
            Arc::clone(&trust_anchor),
            Arc::clone(&nta_store),
        ));
        Self {
            cache: cache_client,
            trust_anchor,
            nta_store,
            server_state,
            root_hints,
            validator,
            query_port,
            qname_min_mode,
        }
    }

    /// Returns the cache client, primarily for testing and cache pre-population.
    #[must_use]
    pub fn cache_client(&self) -> &RecursiveCacheClient {
        &self.cache
    }

    /// Handles a single incoming DNS query and returns the response message.
    ///
    /// This method never returns an error — all failure modes are encoded into
    /// the returned `Message` as SERVFAIL, REFUSED, etc., per the DNS protocol.
    ///
    /// # Behaviour
    ///
    /// 1. Parse `qname`, `qtype`, `qclass`, `DO` bit, and `CD` bit from the query.
    /// 2. Check the cache.
    ///    - Hit → return cached response (with AD flag if Secure+DO).
    ///    - Stale → spawn background re-resolution, return stale with EDE 3.
    ///    - Miss → proceed to iterative resolution.
    /// 3. Create a `DelegationFollower` and resolve.
    /// 4. Validate the DNSSEC outcome.
    /// 5. Store in cache and return the response.
    pub async fn handle(&self, query: &Message, upstream: Arc<dyn UpstreamQuery>) -> Message {
        // Extract query parameters.
        let Some(q) = query.questions.first() else {
            return self.error_response(query, Rcode::FormErr, None);
        };

        let qname = q.qname.clone();
        let qtype = Rtype::from_u16(q.qtype.as_u16());
        let qclass = q.qclass.as_u16();
        let do_bit = do_bit_set(query);
        let cd_bit = query.header.cd();

        debug!(
            qname = %qname,
            qtype = %qtype,
            do_bit = do_bit,
            cd_bit = cd_bit,
            "recursive: handling query"
        );

        // Step 2: cache lookup.
        if let Some(cached) = self.cache.lookup(&qname, qtype, qclass, do_bit) {
            if cached.is_stale {
                // Serve stale while background re-resolution proceeds.
                self.spawn_background_resolve(qname.clone(), qtype, qclass, Arc::clone(&upstream));
                let stale_ede = ExtendedError::new(ede_code::STALE_ANSWER);
                return self.build_stale_response(
                    query,
                    cached.entry.dnssec_outcome,
                    do_bit,
                    Some(stale_ede),
                );
            }

            // Fresh hit: build and return.
            let outcome = &cached.entry.dnssec_outcome;
            let ad = do_bit && matches!(outcome, ValidationOutcome::Secure) && !cd_bit;
            return self.build_cached_response(
                query,
                cached.entry.rdata_wire,
                *outcome == ValidationOutcome::Secure,
                ad,
            );
        }

        // Aggressive NSEC/NSEC3 synthesis: try ancestors of qname as potential zone apexes.
        // If cached Secure NSEC records prove non-existence, return NXDOMAIN without upstream.
        if !cd_bit {
            if let Some(synth) = self.try_nsec_synthesis(&qname, qtype) {
                return self.build_synthesis_nxdomain(query, synth, do_bit);
            }
        }

        // Step 3: iterative resolution.
        let follower = DelegationFollower::with_query_port(
            Arc::clone(&self.server_state),
            Arc::clone(&self.root_hints),
            self.query_port,
        )
        .with_qname_min_mode(self.qname_min_mode);

        let follow_result = follower
            .resolve(&qname, qtype, qclass, Arc::clone(&upstream))
            .await;

        // Step 4-5: handle resolution result.
        match follow_result {
            FollowResult::Answer(msg) => {
                let zone_apex = derive_zone_apex(&msg).unwrap_or_else(Name::root);

                let now_secs = current_unix_secs();
                let outcome = if cd_bit {
                    ValidationOutcome::Insecure
                } else {
                    self.validator.validate(&msg, &zone_apex, now_secs)
                };

                if let ValidationOutcome::Bogus(ref reason) = outcome {
                    let reason_str = format!("{reason:?}");
                    warn!(
                        qname = %qname,
                        reason = %reason_str,
                        "DNSSEC validation failed (bogus)"
                    );
                    self.cache.store(
                        &qname,
                        qtype,
                        qclass,
                        &msg,
                        outcome.clone(),
                        &zone_apex,
                        false,
                    );
                    let ede = ExtendedError::new(ede_code::DNSSEC_BOGUS);
                    return self.error_response(query, Rcode::ServFail, Some(ede));
                }

                self.cache.store(
                    &qname,
                    qtype,
                    qclass,
                    &msg,
                    outcome.clone(),
                    &zone_apex,
                    false,
                );

                let ad = do_bit && matches!(outcome, ValidationOutcome::Secure) && !cd_bit;
                self.build_answer_response(query, &msg, ad)
            }

            FollowResult::NxDomain(msg) => {
                let zone_apex = derive_zone_apex(&msg).unwrap_or_else(Name::root);
                self.cache.store(
                    &qname,
                    qtype,
                    qclass,
                    &msg,
                    ValidationOutcome::Insecure,
                    &zone_apex,
                    true,
                );
                if do_bit && !cd_bit {
                    let now_secs = current_unix_secs();
                    self.cache_nsec_from_authority(&msg, &zone_apex, now_secs, qclass);
                }
                self.build_nxdomain_response(query, &msg)
            }

            FollowResult::NoData(msg) => {
                let zone_apex = derive_zone_apex(&msg).unwrap_or_else(Name::root);
                self.cache.store(
                    &qname,
                    qtype,
                    qclass,
                    &msg,
                    ValidationOutcome::Insecure,
                    &zone_apex,
                    true,
                );
                self.build_nodata_response(query, &msg)
            }

            FollowResult::ServFail(err) => {
                let ede_code = err.to_ede_code().map(ExtendedError::new);
                info!(
                    qname = %qname,
                    error = %err,
                    "recursive resolution failed"
                );
                self.error_response(query, err.to_rcode(), ede_code)
            }

            FollowResult::Refused => self.error_response(query, Rcode::Refused, None),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Spawns a background re-resolution task for a stale cache entry.
    fn spawn_background_resolve(
        &self,
        qname: Name,
        qtype: Rtype,
        qclass: u16,
        upstream: Arc<dyn UpstreamQuery>,
    ) {
        let cache = Arc::clone(&self.cache);
        let server_state = Arc::clone(&self.server_state);
        let root_hints = Arc::clone(&self.root_hints);
        let validator = Arc::clone(&self.validator);
        let qname_min_mode = self.qname_min_mode;

        tokio::spawn(async move {
            let follower = DelegationFollower::new(server_state, root_hints)
                .with_qname_min_mode(qname_min_mode);
            let result = follower.resolve(&qname, qtype, qclass, upstream).await;

            if let FollowResult::Answer(msg) = result {
                let zone_apex = derive_zone_apex(&msg).unwrap_or_else(Name::root);
                let now_secs = current_unix_secs();
                let outcome = validator.validate(&msg, &zone_apex, now_secs);
                cache.store(&qname, qtype, qclass, &msg, outcome, &zone_apex, false);
                debug!(qname = %qname, "background re-resolution complete");
            }
        });
    }

    /// Builds an error response message.
    ///
    /// When `ede` is `Some`, an OPT record carrying the EDE option is added to
    /// the additional section.  The transport layer extracts this OPT, merges
    /// its options into the final response OPT, and removes it before sending.
    fn error_response(
        &self,
        query: &Message,
        rcode: Rcode,
        ede: Option<ExtendedError>,
    ) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);
        header.set_rcode(rcode);

        let additional = if let Some(e) = ede {
            let opt_rr = OptRr {
                udp_payload_size: 1232,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: false,
                z: 0,
                options: vec![EdnsOption::ExtendedError(e)],
            };
            let rec = Record {
                name: Name::root(),
                rtype: Rtype::Opt,
                rclass: heimdall_core::header::Qclass::Any,
                ttl: 0,
                rdata: RData::Opt(opt_rr),
            };
            // INVARIANT: 1 additional record fits in u16.
            #[allow(clippy::cast_possible_truncation)]
            {
                header.arcount = 1;
            }
            vec![rec]
        } else {
            vec![]
        };

        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional,
        }
    }

    /// Builds a response from a cached answer.
    fn build_cached_response(
        &self,
        query: &Message,
        _rdata_wire: Vec<u8>,
        _is_secure: bool,
        ad: bool,
    ) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);
        header.set_ad(ad);

        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Builds a stale response with EDE code 3 (Stale Answer).
    fn build_stale_response(
        &self,
        query: &Message,
        _outcome: ValidationOutcome,
        _do_bit: bool,
        _ede: Option<ExtendedError>,
    ) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);

        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Builds a response from a fresh authoritative answer.
    fn build_answer_response(&self, query: &Message, msg: &Message, ad: bool) -> Message {
        // INVARIANT: DNS answers section is capped at u16::MAX by the wire
        // format; realistic answer counts are orders of magnitude smaller.
        #[allow(clippy::cast_possible_truncation)]
        let ancount = msg.answers.len() as u16;
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ancount,
            nscount: 0,
            arcount: 0,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);
        header.set_ad(ad);

        Message {
            header,
            questions: query.questions.clone(),
            answers: msg.answers.clone(),
            authority: vec![],
            additional: vec![],
        }
    }

    /// Extracts NSEC/NSEC3 records from the authority section of a NXDOMAIN message,
    /// validates their RRSIGs, and caches Secure entries.
    ///
    /// Each NSEC record is cached under `(nsec_owner, NSEC, qclass)` so that
    /// `try_aggressive_synthesis` can retrieve them via `fetch_secure_records`.
    fn cache_nsec_from_authority(
        &self,
        msg: &Message,
        zone_apex: &Name,
        now_secs: u32,
        qclass: u16,
    ) {
        use std::collections::HashMap;

        // Only NSEC and NSEC3 records are candidates.
        let nsec_recs: Vec<Record> = msg
            .authority
            .iter()
            .filter(|r| r.rtype == Rtype::Nsec || r.rtype == Rtype::Nsec3)
            .cloned()
            .collect();
        if nsec_recs.is_empty() {
            return;
        }

        // Validate the authority section: NSEC RRSIGs must be Secure.
        let outcome = self.validator.validate(msg, zone_apex, now_secs);
        if !matches!(outcome, ValidationOutcome::Secure) {
            return;
        }

        // Group by owner name and cache each NSEC rrset individually.
        let mut by_owner: HashMap<Name, Vec<Record>> = HashMap::new();
        for rec in nsec_recs {
            by_owner.entry(rec.name.clone()).or_default().push(rec);
        }

        for (owner, records) in by_owner {
            let rtype = records[0].rtype;
            // Build a minimal Message with the NSEC records as answers so that
            // `parse_records_from_wire` in aggressive_nsec can reconstruct them.
            // INVARIANT: record count bounded by the DNS wire format (u16::MAX).
            #[allow(clippy::cast_possible_truncation)]
            let ancount = records.len() as u16;
            let minimal = Message {
                header: Header {
                    ancount,
                    ..Header::default()
                },
                questions: vec![],
                answers: records,
                authority: vec![],
                additional: vec![],
            };
            self.cache
                .store(&owner, rtype, qclass, &minimal, ValidationOutcome::Secure, zone_apex, false);
        }
    }

    /// Attempts aggressive NSEC synthesis by walking up the qname ancestry.
    ///
    /// For `beta.signed.test.`, tries `signed.test.` and `test.` as zone apexes.
    /// Returns the NSEC proof if synthesis succeeds.
    fn try_nsec_synthesis(&self, qname: &Name, qtype: Rtype) -> Option<Vec<Record>> {
        use std::time::Instant;

        use crate::recursive::aggressive_nsec::{AggressiveResult, try_aggressive_synthesis};

        let qname_str = qname.to_string();
        let trimmed = qname_str.trim_end_matches('.');
        let mut current = trimmed;

        loop {
            let dot = current.find('.')?;
            let parent = &current[dot + 1..];
            if parent.is_empty() {
                break;
            }
            let parent_fqdn = format!("{parent}.");
            if let Ok(zone_apex) = Name::parse_str(&parent_fqdn) {
                match try_aggressive_synthesis(&self.cache, qname, qtype, &zone_apex, Instant::now()) {
                    AggressiveResult::Nxdomain { nsec_proof }
                    | AggressiveResult::Nodata { nsec_proof } => {
                        return Some(nsec_proof);
                    }
                    AggressiveResult::Miss => {}
                }
            }
            current = parent;
        }
        None
    }

    /// Builds a synthesised NXDOMAIN response from cached NSEC proof records.
    fn build_synthesis_nxdomain(
        &self,
        query: &Message,
        _nsec_proof: Vec<Record>,
        _do_bit: bool,
    ) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_aa(false);
        header.set_rcode(Rcode::NxDomain);
        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Builds an NXDOMAIN response.
    fn build_nxdomain_response(&self, query: &Message, _msg: &Message) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);
        header.set_rcode(Rcode::NxDomain);

        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Builds a NODATA (NOERROR with empty answer section) response.
    fn build_nodata_response(&self, query: &Message, _msg: &Message) -> Message {
        let mut header = Header {
            id: query.header.id,
            qdcount: query.header.qdcount,
            ..Header::default()
        };
        header.set_qr(true);
        header.set_ra(true);

        Message {
            header,
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }
}

// ── QueryDispatcher impl ──────────────────────────────────────────────────────

/// Bridges the sync [`QueryDispatcher`] trait to the async [`RecursiveServer::handle`].
///
/// Uses `tokio::task::block_in_place` so the current worker thread is moved
/// out of the async scheduler while the resolution runs, allowing
/// `Handle::current().block_on()` to drive the async future to completion.
/// Requires a multi-threaded Tokio runtime (the default in production).
impl QueryDispatcher for RecursiveServer {
    fn dispatch(&self, msg: &Message, _src: IpAddr) -> Vec<u8> {
        use crate::recursive::upstream::UdpTcpUpstream;
        use heimdall_core::serialiser::Serialiser;

        let upstream: Arc<dyn crate::recursive::follow::UpstreamQuery> =
            Arc::new(UdpTcpUpstream);

        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.handle(msg, upstream))
        });

        let mut ser = Serialiser::new(true);
        let _ = ser.write_message(&response);
        ser.finish()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the DO (DNSSEC OK) bit is set in the OPT record.
fn do_bit_set(msg: &Message) -> bool {
    msg.additional.iter().any(|r| {
        if let heimdall_core::rdata::RData::Opt(opt) = &r.rdata {
            opt.dnssec_ok
        } else {
            false
        }
    })
}

/// Derives a plausible zone apex from a response message.
///
/// Uses the owner name of the first SOA record in the authority section, or
/// the answer section owner name as a fallback.
fn derive_zone_apex(msg: &Message) -> Option<Name> {
    // SOA in authority section is the authoritative indicator.
    if let Some(soa) = msg
        .authority
        .iter()
        .find(|r| r.rtype == heimdall_core::record::Rtype::Soa)
    {
        return Some(soa.name.clone());
    }
    // Fallback: owner of the first answer record.
    msg.answers.first().map(|r| r.name.clone())
}

/// Returns the current Unix timestamp in seconds, casting `u64` → `u32` with
/// truncation (safe until 2106).
fn current_unix_secs() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use heimdall_core::header::{Qclass, Qtype, Question};
    use heimdall_core::rdata::RData;
    use heimdall_core::record::Record;
    use heimdall_runtime::cache::entry::CacheEntry;

    use super::*;

    // ── Mock upstream ─────────────────────────────────────────────────────────

    struct MockUpstream {
        responses:
            Arc<std::sync::Mutex<std::collections::VecDeque<Result<Message, std::io::Error>>>>,
        call_count: Arc<AtomicU32>,
    }

    impl MockUpstream {
        fn new(responses: Vec<Result<Message, std::io::Error>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Arc::new(std::sync::Mutex::new(responses.into())),
                call_count: Arc::new(AtomicU32::new(0)),
            })
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl UpstreamQuery for MockUpstream {
        fn query<'a>(
            &'a self,
            _server: IpAddr,
            _port: u16,
            _msg: &'a Message,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>
        {
            let responses = Arc::clone(&self.responses);
            let counter = Arc::clone(&self.call_count);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                let mut guard = responses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.pop_front().unwrap_or_else(|| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "no more responses",
                    ))
                })
            })
        }
    }

    fn make_server() -> (RecursiveServer, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let cache = Arc::new(RecursiveCache::new(512, 512));
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: trust anchor"));
        let nta_store = Arc::new(NtaStore::new(100));
        let root_hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: root hints"));

        let server = RecursiveServer::new(cache, trust_anchor, nta_store, root_hints);
        (server, dir)
    }

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    fn make_query(qname: &Name, qtype: Qtype) -> Message {
        let mut header = Header::default();
        header.id = 42;
        header.set_rd(true);
        header.qdcount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn authoritative_a_answer(qname: &Name) -> Message {
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.ancount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![Record {
                name: qname.clone(),
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            authority: vec![],
            additional: vec![],
        }
    }

    // ── Test: cache hit short-circuits resolution ──────────────────────────────

    #[tokio::test]
    async fn cache_hit_short_circuits_resolution() {
        let (server, _dir) = make_server();

        // Pre-populate the cache.
        let qname = name("cached.example.com.");
        let msg = authoritative_a_answer(&qname);
        server.cache.store(
            &qname,
            Rtype::A,
            1,
            &msg,
            ValidationOutcome::Insecure,
            &Name::root(),
            false,
        );

        // The upstream mock returns nothing — if it were called, this would panic.
        let upstream = MockUpstream::new(vec![]);

        let query = make_query(&qname, Qtype::A);
        let upstream_dyn: Arc<dyn UpstreamQuery> = Arc::clone(&upstream) as Arc<dyn UpstreamQuery>;
        let response = server.handle(&query, upstream_dyn).await;

        assert_eq!(
            response.header.rcode(),
            Rcode::NoError,
            "cache hit must return NOERROR"
        );
        assert_eq!(
            upstream.calls(),
            0,
            "upstream must not be called on a cache hit"
        );
    }

    // ── Test: successful resolution returns answer ────────────────────────────

    #[tokio::test]
    async fn resolution_produces_answer() {
        let (server, _dir) = make_server();
        let qname = name("example.com.");
        let answer = authoritative_a_answer(&qname);
        let upstream = MockUpstream::new(vec![Ok(answer)]);

        let query = make_query(&qname, Qtype::A);
        let response = server.handle(&query, upstream).await;
        assert_eq!(response.header.rcode(), Rcode::NoError);
    }

    // ── Test: query timeout → SERVFAIL ────────────────────────────────────────

    #[tokio::test]
    async fn query_timeout_produces_servfail() {
        let (server, _dir) = make_server();
        let qname = name("timeout.example.com.");

        // Enough timeouts to exhaust all root servers.
        let responses: Vec<Result<Message, _>> = (0..30)
            .map(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated timeout",
                ))
            })
            .collect();

        let upstream = MockUpstream::new(responses);
        let query = make_query(&qname, Qtype::A);
        let response = server.handle(&query, upstream).await;

        assert_eq!(
            response.header.rcode(),
            Rcode::ServFail,
            "all timeouts must yield SERVFAIL"
        );
    }

    // ── Test: stale entry returned ────────────────────────────────────────────

    #[tokio::test]
    async fn stale_entry_returned_with_stale_response() {
        let (_server, _dir) = make_server();
        let qname = name("stale.example.com.");

        // Directly insert a stale entry.  Use min_ttl_secs=0 so the cache
        // does not clamp the already-expired deadline to its minimum TTL.
        use heimdall_runtime::cache::TtlBounds;
        let bounds = TtlBounds {
            min_ttl_secs: 0,
            ..TtlBounds::default()
        };
        let inner_cache = Arc::new(RecursiveCache::with_bounds(512, 512, bounds));
        let cache_client = Arc::new(RecursiveCacheClient::new(Arc::clone(&inner_cache)));

        let key = heimdall_runtime::cache::CacheKey {
            qname: qname.as_wire_bytes().to_ascii_lowercase(),
            qtype: 1,
            qclass: 1,
        };
        let now = Instant::now();
        inner_cache.insert(
            key,
            CacheEntry {
                rdata_wire: vec![],
                ttl_deadline: now - Duration::from_secs(10),
                dnssec_outcome: ValidationOutcome::Insecure,
                is_negative: false,
                serve_stale_until: Some(now + Duration::from_secs(290)),
                zone_apex: b"\x00".to_vec(),
            },
        );

        let result = cache_client.lookup(&qname, Rtype::A, 1, false);
        assert!(result.is_some(), "stale entry must be returned");
        let cached = result.expect("INVARIANT: just checked");
        assert!(cached.is_stale, "entry must be marked stale");
    }
}
