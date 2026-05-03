// SPDX-License-Identifier: MIT

//! Delegation-following state machine for iterative resolution (PROTO-006).
//!
//! [`DelegationFollower`] implements the iterative resolver loop: starting from
//! the root nameservers, it follows NS referrals down the DNS tree until it
//! reaches an authoritative answer, exhausts the budget, or hits a depth limit.
//!
//! Outbound DNS queries are abstracted behind the [`UpstreamQuery`] trait so
//! that the state machine can be unit-tested independently of real sockets.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use heimdall_core::header::Rcode;
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use tracing::{debug, info, warn};

use crate::recursive::error::RecursiveError;
use crate::recursive::qname_min::{QnameMinMode, QnameMinimiser};
use crate::recursive::root_hints::RootHints;
use crate::recursive::server_state::ServerStateCache;
use crate::recursive::timing::QueryBudget;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of delegation hops before returning `ServFail`.
pub const MAX_DELEGATION_DEPTH: u8 = 16;

/// Maximum number of CNAME redirections before returning `ServFail`.
pub const MAX_CNAME_HOPS: u8 = 8;

/// Default DNS port for upstream queries.  Only used as fallback; prefer the
/// configured `query_port` on [`DelegationFollower`].
const DEFAULT_DNS_PORT: u16 = 53;

// ── UpstreamQuery trait ───────────────────────────────────────────────────────

/// Abstraction over sending a single DNS query to a specific upstream server.
///
/// Implementations are responsible for encoding, transport, and decoding.
/// The returned future must be `Send` to allow use in `tokio::spawn` contexts.
///
/// # Safety
///
/// Implementations must not panic. I/O errors must be returned as
/// `Err(std::io::Error)`, not propagated via `unwrap` or `expect`.
pub trait UpstreamQuery: Send + Sync {
    /// Sends `msg` to `server:port` and returns the parsed response.
    fn query<'a>(
        &'a self,
        server: IpAddr,
        port: u16,
        msg: &'a Message,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>;
}

// ── FollowResult ──────────────────────────────────────────────────────────────

/// The outcome of a [`DelegationFollower::resolve`] call.
#[derive(Debug)]
pub enum FollowResult {
    /// A positive answer was received from an authoritative server.
    Answer(Message),
    /// The queried name does not exist (NXDOMAIN).
    NxDomain(Message),
    /// The name exists but has no data of the requested type (NODATA).
    NoData(Message),
    /// Resolution failed; the response should be a SERVFAIL or similar.
    ServFail(RecursiveError),
    /// All reachable upstreams refused the query.
    Refused,
}

// ── DelegationFollower ────────────────────────────────────────────────────────

/// Iterative DNS resolver state machine.
///
/// `DelegationFollower` is stateless across calls: each `resolve()` invocation
/// is independent and creates its own [`QueryBudget`].
pub struct DelegationFollower {
    server_state: Arc<ServerStateCache>,
    root_hints: Arc<RootHints>,
    /// UDP/TCP port used for all outbound DNS queries.  Default: 53.
    query_port: u16,
    /// QNAME minimisation mode for outbound queries (RFC 9156).
    qname_min_mode: QnameMinMode,
}

impl DelegationFollower {
    /// Creates a new [`DelegationFollower`] using the standard DNS port (53).
    #[must_use]
    pub fn new(server_state: Arc<ServerStateCache>, root_hints: Arc<RootHints>) -> Self {
        Self::with_query_port(server_state, root_hints, DEFAULT_DNS_PORT)
    }

    /// Creates a new [`DelegationFollower`] with a custom outbound query port.
    ///
    /// Use port 53 in production. A non-53 value is only appropriate in test
    /// environments where all in-process nameservers share a single port.
    #[must_use]
    pub fn with_query_port(
        server_state: Arc<ServerStateCache>,
        root_hints: Arc<RootHints>,
        query_port: u16,
    ) -> Self {
        Self {
            server_state,
            root_hints,
            query_port,
            qname_min_mode: QnameMinMode::default(),
        }
    }

    /// Sets the QNAME minimisation mode, returning the updated follower.
    #[must_use]
    pub fn with_qname_min_mode(mut self, mode: QnameMinMode) -> Self {
        self.qname_min_mode = mode;
        self
    }

    /// Resolves `(qname, qtype, qclass)` iteratively using `upstream`.
    ///
    /// The caller provides an `UpstreamQuery` implementation; for tests this
    /// is a mock; in production it will be the UDP/TCP transport.
    pub async fn resolve(
        &self,
        qname: &Name,
        qtype: Rtype,
        qclass: u16,
        upstream: Arc<dyn UpstreamQuery>,
    ) -> FollowResult {
        let mut budget = QueryBudget::new();

        // Start with root nameserver addresses.
        let root_addrs = self.root_hints.all_addresses().await;
        if root_addrs.is_empty() {
            return FollowResult::ServFail(RecursiveError::QueryTimeout {
                elapsed_ms: budget.elapsed_ms(),
            });
        }

        let mut current_servers: Vec<IpAddr> = root_addrs;
        let mut current_qname = qname.clone();
        let mut delegation_depth: u8 = 0;
        let mut cname_hops: u8 = 0;
        let mut minimiser = QnameMinimiser::new(qname.clone(), self.qname_min_mode);

        // Delegation-following loop.
        loop {
            if budget.is_exhausted() {
                return FollowResult::ServFail(RecursiveError::QueryTimeout {
                    elapsed_ms: budget.elapsed_ms(),
                });
            }

            if delegation_depth >= MAX_DELEGATION_DEPTH {
                return FollowResult::ServFail(RecursiveError::MaxDelegationsExceeded);
            }

            // Select the best server from the current NSset.
            let Some(best_server) = self.server_state.select_best(&current_servers) else {
                return FollowResult::ServFail(RecursiveError::QueryTimeout {
                    elapsed_ms: budget.elapsed_ms(),
                });
            };

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let should_randomise = !self.server_state.should_disable_ox20(best_server)
                || self.server_state.should_reprobe_ox20(best_server, now_secs);

            // Build a query using QNAME minimisation (RFC 9156).
            let (min_qname, min_qtype) = minimiser.minimised_query(qtype);
            // Track whether we sent a minimised probe so we can fall back on
            // uncooperative server responses (RFC 9156 §4, relaxed mode).
            let was_minimised = min_qname != current_qname;
            let query_qname = if should_randomise {
                randomise_case(&min_qname)
            } else {
                min_qname
            };

            let query_msg = build_query(&query_qname, min_qtype, qclass);
            budget.record_attempt();

            // Send the query.
            let response = match tokio::time::timeout(
                budget.per_attempt_timeout,
                upstream.query(best_server, self.query_port, &query_msg),
            )
            .await
            {
                Ok(Ok(resp)) => resp,
                Ok(Err(io_err)) => {
                    warn!(
                        server = %best_server,
                        error = %io_err,
                        "upstream query I/O error"
                    );
                    self.server_state.record_timeout(best_server);
                    // Try next server: remove from current list.
                    current_servers.retain(|&ip| ip != best_server);
                    if current_servers.is_empty() {
                        return FollowResult::ServFail(RecursiveError::QueryTimeout {
                            elapsed_ms: budget.elapsed_ms(),
                        });
                    }
                    continue;
                }
                Err(_timeout) => {
                    debug!(server = %best_server, "upstream query timed out");
                    self.server_state.record_timeout(best_server);
                    current_servers.retain(|&ip| ip != best_server);
                    if current_servers.is_empty() {
                        return FollowResult::ServFail(RecursiveError::QueryTimeout {
                            elapsed_ms: budget.elapsed_ms(),
                        });
                    }
                    continue;
                }
            };

            // Record 0x20 conformance.
            if should_randomise {
                let is_conformant = check_ox20_conformance(&query_qname, &response);
                self.server_state
                    .record_response(best_server, is_conformant, now_secs);
            }

            // Inspect the RCODE.
            let rcode = response.header.rcode();

            if rcode == Rcode::Refused {
                // If this was a minimised NS probe and the server refused, fall
                // back to the full QNAME in relaxed mode (RFC 9156 §4).
                if was_minimised {
                    match minimiser.handle_fallback(best_server, String::new(), qtype) {
                        Ok(_) => continue,
                        Err(_) => {
                            return FollowResult::ServFail(RecursiveError::UpstreamServFail);
                        }
                    }
                }
                return FollowResult::Refused;
            }

            if rcode == Rcode::ServFail {
                self.server_state.record_timeout(best_server);
                current_servers.retain(|&ip| ip != best_server);
                if current_servers.is_empty() {
                    return FollowResult::ServFail(RecursiveError::UpstreamServFail);
                }
                continue;
            }

            // Check for CNAME in the answer section.
            if let Some(cname_target) = find_cname(&response, &current_qname) {
                cname_hops += 1;
                if cname_hops > MAX_CNAME_HOPS {
                    return FollowResult::ServFail(RecursiveError::MaxCnameHopsExceeded);
                }
                debug!(
                    from = %current_qname,
                    to = %cname_target,
                    hop = cname_hops,
                    "following CNAME"
                );
                current_qname = cname_target;
                // Re-resolve from root for the new target; reset minimiser.
                minimiser = QnameMinimiser::new(current_qname.clone(), self.qname_min_mode);
                current_servers = self.root_hints.all_addresses().await;
                delegation_depth = 0;
                continue;
            }

            // Authoritative answer.
            if response.header.aa() {
                // An NXDOMAIN for a minimised NS probe means the server doesn't
                // have this delegation step — fall back in relaxed mode.
                if rcode == Rcode::NxDomain && was_minimised {
                    match minimiser.handle_fallback(best_server, String::new(), qtype) {
                        Ok(_) => continue,
                        Err(_) => {
                            return FollowResult::ServFail(RecursiveError::UpstreamServFail);
                        }
                    }
                }
                return match rcode {
                    Rcode::NxDomain => FollowResult::NxDomain(response),
                    Rcode::NoError if response.answers.is_empty() => FollowResult::NoData(response),
                    Rcode::NoError => FollowResult::Answer(response),
                    _ => FollowResult::ServFail(RecursiveError::UpstreamServFail),
                };
            }

            // Referral: AA=0, NS records in authority section.
            // Extract in-bailiwick glue and new NSset.
            if let Some((ns_addrs, delegation_zone)) = extract_referral(&response, &current_qname) {
                if ns_addrs.is_empty() {
                    // No in-bailiwick glue; per PROTO-051, resolve each NS target's
                    // address via an independent resolution before continuing.
                    let ns_names = extract_ns_names(&response);
                    if ns_names.is_empty() {
                        warn!(zone = %delegation_zone, "referral has no NS names — SERVFAIL");
                        return FollowResult::ServFail(RecursiveError::QueryTimeout {
                            elapsed_ms: budget.elapsed_ms(),
                        });
                    }
                    let mut chased: Vec<IpAddr> = Vec::new();
                    for ns_name in &ns_names {
                        // A-record chase first; fall back to AAAA only when A yields nothing.
                        let a_result = Box::pin(
                            self.resolve(ns_name, Rtype::A, qclass, Arc::clone(&upstream)),
                        )
                        .await;
                        if let FollowResult::Answer(msg) = a_result {
                            for r in &msg.answers {
                                if r.rtype == Rtype::A {
                                    if let RData::A(addr) = &r.rdata {
                                        chased.push(IpAddr::V4(*addr));
                                    }
                                }
                            }
                        }
                        if chased.is_empty() {
                            let aaaa_result = Box::pin(
                                self.resolve(ns_name, Rtype::Aaaa, qclass, Arc::clone(&upstream)),
                            )
                            .await;
                            if let FollowResult::Answer(msg) = aaaa_result {
                                for r in &msg.answers {
                                    if r.rtype == Rtype::Aaaa {
                                        if let RData::Aaaa(addr) = &r.rdata {
                                            chased.push(IpAddr::V6(*addr));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if chased.is_empty() {
                        warn!(
                            zone = %delegation_zone,
                            "NS address chase produced no addresses — SERVFAIL"
                        );
                        return FollowResult::ServFail(RecursiveError::QueryTimeout {
                            elapsed_ms: budget.elapsed_ms(),
                        });
                    }
                    minimiser.advance_to_zone(delegation_zone.clone());
                    current_servers = chased;
                    delegation_depth += 1;
                    info!(
                        depth = delegation_depth,
                        zone = %delegation_zone,
                        servers = current_servers.len(),
                        "following referral via NS address chase"
                    );
                    continue;
                }
                minimiser.advance_to_zone(delegation_zone.clone());
                current_servers = ns_addrs;
                delegation_depth += 1;
                info!(
                    depth = delegation_depth,
                    zone = %delegation_zone,
                    servers = current_servers.len(),
                    "following referral"
                );
                continue;
            }

            // Unexpected response (no referral, no authoritative answer).
            return FollowResult::ServFail(RecursiveError::UpstreamServFail);
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Builds a minimal DNS query message for `(qname, qtype, qclass)`.
///
/// Includes an OPT record with DO=1 so authoritative servers return RRSIG and
/// DNSKEY records needed for DNSSEC validation.
fn build_query(qname: &Name, qtype: Rtype, qclass: u16) -> Message {
    use heimdall_core::edns::OptRr;
    use heimdall_core::header::{Header, Qclass, Qtype, Question};
    use heimdall_core::rdata::RData;
    use heimdall_core::record::Record;

    let mut header = Header {
        id: pseudo_random_id(),
        qdcount: 1,
        arcount: 1,
        ..Header::default()
    };
    header.set_rd(false); // iterative query

    let opt_rr = OptRr {
        udp_payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: true,
        z: 0,
        options: vec![],
    };
    let opt_rec = Record {
        name: Name::root(),
        rtype: heimdall_core::record::Rtype::Opt,
        rclass: Qclass::Any,
        ttl: 0,
        rdata: RData::Opt(opt_rr),
    };

    Message {
        header,
        questions: vec![Question {
            qname: qname.clone(),
            qtype: Qtype::from_u16(qtype.as_u16()),
            qclass: Qclass::from_u16(qclass),
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rec],
    }
}

/// Returns a copy of `name` with each label's ASCII characters randomly cased.
///
/// Uses a simple `XorShift` seeded from the current time — no external RNG crate.
/// This is 0x20 case randomisation per PROTO-025/026.
fn randomise_case(name: &Name) -> Name {
    let wire = name.as_wire_bytes();
    let mut result = wire.to_vec();
    let mut rng = xorshift_seed();

    let mut i = 0;
    while i < result.len() {
        let len_byte = result[i] as usize;
        if len_byte == 0 {
            break;
        }
        i += 1;
        for byte in result.iter_mut().skip(i).take(len_byte) {
            if byte.is_ascii_alphabetic() {
                rng = xorshift(rng);
                if rng & 1 == 1 {
                    *byte = byte.to_ascii_uppercase();
                } else {
                    *byte = byte.to_ascii_lowercase();
                }
            }
        }
        i += len_byte;
    }

    // Re-parse from the modified wire bytes.
    // If this fails (shouldn't for valid names), fall back to the original.
    Name::from_wire(&result, 0).map_or_else(|_| name.clone(), |(n, _)| n)
}

/// Checks whether the response QNAME case matches the query QNAME.
fn check_ox20_conformance(query_qname: &Name, response: &Message) -> bool {
    let Some(q) = response.questions.first() else {
        return true;
    };
    q.qname.as_wire_bytes() == query_qname.as_wire_bytes()
}

/// Generates a pseudo-random DNS message ID.
fn pseudo_random_id() -> u16 {
    let seed = xorshift_seed();
    (xorshift(seed) & 0xFFFF) as u16
}

/// `XorShift64` PRNG seed from system time.
fn xorshift_seed() -> u64 {
    u64::from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(12345, |d| d.subsec_nanos()),
    )
}

/// `XorShift64` step.
fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// Extracts the first CNAME target from the answer section for `qname`.
fn find_cname(msg: &Message, qname: &Name) -> Option<Name> {
    msg.answers.iter().find_map(|r| {
        if r.rtype == Rtype::Cname
            && r.name == *qname
            && let RData::Cname(target) = &r.rdata
        {
            Some(target.clone())
        } else {
            None
        }
    })
}

/// Extracts in-bailiwick glue addresses and the delegation zone name from a
/// referral response.
///
/// Returns `Some((addresses, zone_name))` when the authority section contains
/// NS records; the additional section is searched for A/AAAA glue that is
/// within the bailiwick of the delegation zone (PROTO-051).
///
/// Returns `None` when no NS records are found.
fn extract_referral(msg: &Message, _current_qname: &Name) -> Option<(Vec<IpAddr>, Name)> {
    // Find the NS records in the authority section.
    let ns_records: Vec<&Record> = msg
        .authority
        .iter()
        .filter(|r| r.rtype == Rtype::Ns)
        .collect();

    if ns_records.is_empty() {
        return None;
    }

    // The delegation zone is the owner name of the NS records.
    let delegation_zone = ns_records[0].name.clone();

    // Collect the NS target names.
    let ns_names: Vec<Name> = ns_records
        .iter()
        .filter_map(|r| {
            if let RData::Ns(target) = &r.rdata {
                Some(target.clone())
            } else {
                None
            }
        })
        .collect();

    // Extract in-bailiwick glue from the additional section (PROTO-051).
    // A glue record is in-bailiwick iff its owner name is a subdomain of the
    // delegation zone.
    let glue_addrs: Vec<IpAddr> = msg
        .additional
        .iter()
        .filter(|r| {
            // Must be A or AAAA.
            !matches!(r.rtype, Rtype::A | Rtype::Aaaa)
                .then_some(false)
                .unwrap_or(true)
            // Must be for one of the NS targets.
                && ns_names.iter().any(|ns| ns == &r.name)
            // Bailiwick check: owner must be within the delegation zone.
                && r.name.is_in_bailiwick(&delegation_zone)
        })
        .filter_map(|r| match &r.rdata {
            RData::A(addr) => Some(IpAddr::V4(*addr)),
            RData::Aaaa(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        })
        .collect();

    Some((glue_addrs, delegation_zone))
}

/// Returns the NS target names from the authority section of a referral.
///
/// Used when in-bailiwick glue is absent so each target can be resolved
/// independently (PROTO-051).
fn extract_ns_names(msg: &Message) -> Vec<Name> {
    msg.authority
        .iter()
        .filter(|r| r.rtype == Rtype::Ns)
        .filter_map(|r| {
            if let RData::Ns(target) = &r.rdata {
                Some(target.clone())
            } else {
                None
            }
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};

    use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
    use heimdall_core::rdata::RData;
    use heimdall_core::record::Record;

    use super::*;

    // ── Mock upstream ─────────────────────────────────────────────────────────

    /// A mock upstream that returns a pre-configured sequence of responses.
    struct MockUpstream {
        responses:
            Arc<std::sync::Mutex<std::collections::VecDeque<Result<Message, std::io::Error>>>>,
        call_count: Arc<AtomicU32>,
    }

    impl MockUpstream {
        fn new(responses: Vec<Result<Message, std::io::Error>>) -> Self {
            Self {
                responses: Arc::new(std::sync::Mutex::new(responses.into())),
                call_count: Arc::new(AtomicU32::new(0)),
            }
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

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    fn make_follower() -> (DelegationFollower, Arc<RootHints>) {
        let server_state = Arc::new(ServerStateCache::new());
        let hints = Arc::new(RootHints::from_builtin().expect("INVARIANT: built-in hints"));
        // Unit tests exercise delegation logic with fixed mock responses; QNAME
        // minimisation is covered by the E2E test (recursive_qname_min.rs).
        let follower = DelegationFollower::new(server_state, Arc::clone(&hints))
            .with_qname_min_mode(QnameMinMode::Off);
        (follower, hints)
    }

    fn authoritative_answer(qname: &Name, qtype: Rtype) -> Message {
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.ancount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::from_u16(qtype.as_u16()),
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

    fn nxdomain_response(qname: &Name) -> Message {
        let mut header = Header::default();
        header.set_qr(true);
        header.set_aa(true);
        header.set_rcode(Rcode::NxDomain);
        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn referral(delegation_zone: &Name, ns_name: &Name, ns_ip: Ipv4Addr) -> Message {
        let mut header = Header::default();
        header.set_qr(true);
        // AA=0 for referral
        Message {
            header,
            questions: vec![],
            answers: vec![],
            authority: vec![Record {
                name: delegation_zone.clone(),
                rtype: Rtype::Ns,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::Ns(ns_name.clone()),
            }],
            additional: vec![Record {
                name: ns_name.clone(),
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::A(ns_ip),
            }],
        }
    }

    #[tokio::test]
    async fn direct_answer_returned() {
        let (follower, _) = make_follower();
        let qname = name("example.com.");
        let answer = authoritative_answer(&qname, Rtype::A);
        let upstream = Arc::new(MockUpstream::new(vec![Ok(answer)]));

        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;
        assert!(matches!(result, FollowResult::Answer(_)));
    }

    #[tokio::test]
    async fn nxdomain_returned() {
        let (follower, _) = make_follower();
        let qname = name("nxdomain.example.com.");
        let resp = nxdomain_response(&qname);
        let upstream = Arc::new(MockUpstream::new(vec![Ok(resp)]));

        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;
        assert!(matches!(result, FollowResult::NxDomain(_)));
    }

    #[tokio::test]
    async fn max_delegation_depth_produces_servfail() {
        let (follower, _) = make_follower();
        let qname = name("deep.example.com.");

        // Each response is a referral; after MAX_DELEGATION_DEPTH we should fail.
        let ns_ip = Ipv4Addr::new(10, 0, 0, 1);
        let ns_name = name("ns.deep.example.com.");
        let zone = name("example.com.");

        let responses: Vec<Result<Message, _>> = (0..=MAX_DELEGATION_DEPTH + 5)
            .map(|_| Ok(referral(&zone, &ns_name, ns_ip)))
            .collect();

        let upstream = Arc::new(MockUpstream::new(responses));
        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;
        assert!(
            matches!(
                result,
                FollowResult::ServFail(RecursiveError::MaxDelegationsExceeded)
            ),
            "must fail with MaxDelegationsExceeded"
        );
    }

    #[tokio::test]
    async fn cname_hop_cap_produces_servfail() {
        let (follower, _) = make_follower();
        // Start with "alias0.example.com." — the first response must be a
        // CNAME whose owner name matches this exact qname.
        let start_name = name("alias0.example.com.");

        // Build MAX_CNAME_HOPS+1 authoritative CNAME responses forming a chain:
        // alias0 → alias1 → … → alias(MAX_CNAME_HOPS).
        // Each response has AA=true so the resolution engine treats it as
        // authoritative rather than a referral, and the CNAME owner name
        // exactly matches the current query name at each hop.
        let mut responses = Vec::new();
        for i in 0u8..=MAX_CNAME_HOPS {
            let from =
                Name::from_str(&format!("alias{i}.example.com.")).expect("INVARIANT: valid name");
            let to = Name::from_str(&format!("alias{}.example.com.", i + 1))
                .expect("INVARIANT: valid name");

            let mut header = Header::default();
            header.set_qr(true);
            header.set_aa(true);
            header.ancount = 1;

            let msg = Message {
                header,
                questions: vec![Question {
                    qname: from.clone(),
                    qtype: Qtype::A,
                    qclass: Qclass::In,
                }],
                answers: vec![Record {
                    name: from,
                    rtype: Rtype::Cname,
                    rclass: Qclass::In,
                    ttl: 300,
                    rdata: RData::Cname(to),
                }],
                authority: vec![],
                additional: vec![],
            };
            responses.push(Ok(msg));
        }

        let upstream = Arc::new(MockUpstream::new(responses));
        let result = follower.resolve(&start_name, Rtype::A, 1, upstream).await;
        assert!(
            matches!(
                result,
                FollowResult::ServFail(RecursiveError::MaxCnameHopsExceeded)
            ),
            "must fail with MaxCnameHopsExceeded"
        );
    }

    #[tokio::test]
    async fn out_of_bailiwick_glue_discarded() {
        let (follower, _) = make_follower();
        let qname = name("www.example.com.");

        // Referral with out-of-bailiwick glue (ns.evil.com. is not under example.com.).
        let delegation_zone = name("example.com.");
        let ns_name = name("ns.evil.com.");

        let mut header = Header::default();
        header.set_qr(true);
        let referral_msg = Message {
            header,
            questions: vec![],
            answers: vec![],
            authority: vec![Record {
                name: delegation_zone.clone(),
                rtype: Rtype::Ns,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::Ns(ns_name.clone()),
            }],
            additional: vec![Record {
                // Out-of-bailiwick: ns.evil.com. is not under example.com.
                name: ns_name,
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
        };

        // The referral has no in-bailiwick glue.  The resolver triggers a NS
        // address chase for ns.evil.com., but since the mock upstream provides no
        // further responses the chase times out → ServFail.
        let upstream = Arc::new(MockUpstream::new(vec![Ok(referral_msg)]));
        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;

        // OOB glue discarded; NS address chase fails → ServFail.
        assert!(
            matches!(result, FollowResult::ServFail(_)),
            "out-of-bailiwick glue must be discarded; failed NS chase must produce ServFail"
        );
    }

    #[tokio::test]
    async fn oob_glue_ns_chase_succeeds_when_ns_resolves() {
        let (follower, _) = make_follower();
        let qname = name("www.example.com.");
        let delegation_zone = name("example.com.");
        let ns_name = name("ns.evil.com.");

        let mut hdr = Header::default();
        hdr.set_qr(true);
        let referral_msg = Message {
            header: hdr,
            questions: vec![],
            answers: vec![],
            authority: vec![Record {
                name: delegation_zone.clone(),
                rtype: Rtype::Ns,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::Ns(ns_name.clone()),
            }],
            additional: vec![Record {
                // Out-of-bailiwick: discarded by bailiwick filter.
                name: ns_name.clone(),
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 172800,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
        };

        // Chase response: A record for ns.evil.com. — mock root returns this
        // authoritatively so the sub-resolution terminates immediately.
        let chase_ip = Ipv4Addr::new(127, 0, 0, 53);
        let ns_a_answer = authoritative_answer(&ns_name, Rtype::A);
        // Patch the answer IP to chase_ip.
        let ns_a_answer = {
            let mut m = ns_a_answer;
            m.answers[0].rdata = RData::A(chase_ip);
            m
        };

        // Final answer: www.example.com. A 5.6.7.8 served by chase_ip.
        let final_answer = authoritative_answer(&qname, Rtype::A);

        let upstream = Arc::new(MockUpstream::new(vec![
            Ok(referral_msg),  // main resolution: OOB referral
            Ok(ns_a_answer),   // NS chase: A record for ns.evil.com.
            Ok(final_answer),  // final query to chase_ip: answer
        ]));

        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;
        assert!(
            matches!(result, FollowResult::Answer(_)),
            "when NS address chase succeeds, resolution must complete with an answer; got {result:?}"
        );
    }

    #[tokio::test]
    async fn timeout_from_all_servers_produces_servfail() {
        let (follower, _) = make_follower();
        let qname = name("timeout.example.com.");

        // All responses are timeouts.
        let responses: Vec<Result<Message, _>> = (0..20)
            .map(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated timeout",
                ))
            })
            .collect();

        let upstream = Arc::new(MockUpstream::new(responses));
        let result = follower.resolve(&qname, Rtype::A, 1, upstream).await;
        assert!(
            matches!(result, FollowResult::ServFail(_)),
            "all timeouts must produce ServFail"
        );
    }

    #[test]
    fn randomise_case_produces_valid_name() {
        let original = name("example.com.");
        let randomised = randomise_case(&original);
        // After case-randomisation, the name must still match case-insensitively.
        assert_eq!(
            original.as_wire_bytes().to_ascii_lowercase(),
            randomised.as_wire_bytes().to_ascii_lowercase(),
            "case randomisation must preserve name identity (case-insensitive)"
        );
    }
}
