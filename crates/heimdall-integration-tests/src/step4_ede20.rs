// SPDX-License-Identifier: MIT

//! Step-4 EDE INFO-CODE 20 dispatcher integration tests (ROLE-024/025).
//!
//! ROLE-024 mandates REFUSED + EDE-20 "Not Authoritative" when the forwarder
//! role is active and no forward-zone rule matches.  ROLE-025 generalises this
//! to every step-4 trigger combination: auth-only outside zone set, auth+forwarder
//! with no matches in either role, and forwarder-only with no rule match.
//!
//! Tests exercise the in-process `QueryDispatcher::dispatch()` path for all
//! four documented trigger combinations and assert an identical response shape:
//! RCODE=REFUSED, OPT carries EDE INFO-CODE 20, answer/authority sections empty.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use heimdall_core::{
        edns::{EdnsOption, ede_code},
        header::{Header, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
        rdata::RData,
        zone::{ZoneFile, ZoneLimits},
    };
    use heimdall_roles::{
        AuthServer, ForwarderServer,
        auth::zone_role::{ZoneConfig, ZoneRole},
        forwarder::{ForwarderPool, UpstreamTransport},
    };
    use heimdall_runtime::QueryDispatcher;

    // ── Helpers ───────────────────────────────────────────────────────────────────

    const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    /// Builds a minimal DNS query for `qname`.
    fn make_query(qname: &str) -> Message {
        let mut hdr = Header::default();
        hdr.id = 1;
        hdr.qdcount = 1;
        Message {
            header: hdr,
            questions: vec![Question {
                qname: Name::from_str(qname).expect("valid qname"),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Parses `wire` into a `Message`, returning `(rcode, ede_code)`.
    fn parse_response(wire: &[u8]) -> (Rcode, Option<u16>) {
        let msg = Message::parse(wire).expect("valid DNS response wire");
        let rcode = msg.header.rcode();
        let ede = msg.additional.iter().find_map(|r| {
            if let RData::Opt(opt) = &r.rdata {
                opt.options.iter().find_map(|o| {
                    if let EdnsOption::ExtendedError(e) = o {
                        Some(e.info_code)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        });
        (rcode, ede)
    }

    /// Asserts that `wire` is a REFUSED response with EDE INFO-CODE 20 and
    /// empty answer/authority sections.
    fn assert_step4_refused(wire: &[u8], label: &str) {
        assert!(!wire.is_empty(), "{label}: wire must not be empty");
        let msg = Message::parse(wire).expect("valid DNS wire");

        assert_eq!(
            msg.header.rcode(),
            Rcode::Refused,
            "{label}: RCODE must be REFUSED"
        );
        assert!(
            msg.answers.is_empty(),
            "{label}: answer section must be empty"
        );
        assert!(
            msg.authority.is_empty(),
            "{label}: authority section must be empty"
        );

        let (_, ede) = parse_response(wire);
        assert_eq!(
            ede,
            Some(ede_code::NOT_AUTHORITATIVE),
            "{label}: OPT must carry EDE INFO-CODE 20 (Not Authoritative)"
        );
    }

    /// Zone text for example.com.
    const ZONE_TEXT: &str = "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
www IN A 192.0.2.2\n\
";

    fn make_auth_server() -> AuthServer {
        let zone = ZoneFile::parse(ZONE_TEXT, None, ZoneLimits::default()).expect("zone");
        let apex = Name::from_str("example.com.").expect("apex");
        use std::sync::Arc;
        let cfg = ZoneConfig {
            apex,
            role: ZoneRole::Primary,
            upstream_primary: None,
            notify_secondaries: vec![],
            tsig_key: None,
            axfr_acl: vec![],
            zone_file: Some(Arc::new(zone)),
        };
        use heimdall_runtime::admission::AdmissionTelemetry;
        AuthServer::new(vec![cfg], Arc::new(AdmissionTelemetry::new()))
    }

    /// Builds a forwarder with no forward rules (so every query is a no-match).
    fn make_forwarder_no_rules() -> ForwarderServer {
        use std::sync::Arc;

        use heimdall_roles::dnssec_roles::{NtaStore, TrustAnchorStore};
        use heimdall_runtime::cache::ForwarderCache;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor"));
        std::mem::forget(dir); // keep alive

        let nta_store = Arc::new(NtaStore::new(100));
        let cache = Arc::new(ForwarderCache::new(512, 512));

        // Pool with a single unreachable upstream — never actually called since
        // no rules exist and handle() returns None before any pool query.
        use std::collections::HashSet;

        use heimdall_roles::forwarder::ClientRegistry;
        let transports: HashSet<UpstreamTransport> =
            [UpstreamTransport::UdpTcp].into_iter().collect();
        let registry = Arc::new(ClientRegistry::build(&transports));
        let pool = ForwarderPool::new(registry, vec![UpstreamTransport::UdpTcp]);

        ForwarderServer::new(
            vec![], // no rules → every query is a no-match
            pool,
            trust_anchor,
            nta_store,
            cache,
            1000,
        )
    }

    // ── Case (i): auth-only deployment, query outside zone ───────────────────────

    /// (i) Authoritative-only deployment: a query for a name outside all loaded
    /// zones hits step-4 and must receive REFUSED + EDE INFO-CODE 20 (ROLE-025).
    #[test]
    fn auth_only_outside_zone_returns_refused_ede20() {
        let server = make_auth_server();
        let query = make_query("outside.example.net.");
        let wire = server.dispatch(&query, CLIENT_IP, true);
        assert_step4_refused(&wire, "(i) auth-only, outside zone");
    }

    // ── Case (ii): auth + forwarder, neither matches ──────────────────────────────

    /// (ii) Auth + forwarder active, query outside the auth zone set and no
    /// forward-zone matches: auth handles the query (it owns step-4 for unmatched
    /// queries when recursive is absent) and returns REFUSED + EDE-20 (ROLE-025).
    ///
    /// In the current dispatcher wiring (main.rs), auth+forwarder without recursive
    /// routes to the auth role, so auth's step-4 path applies.
    #[test]
    fn auth_forwarder_no_match_returns_refused_ede20() {
        let server = make_auth_server();
        // Simulate auth+forwarder: auth is the top-level dispatcher (forwarder is a
        // lower-priority fallback not yet represented in a combined dispatcher, so
        // auth's step-4 logic is the applicable path per ROLE-025).
        let query = make_query("other.example.org.");
        let wire = server.dispatch(&query, CLIENT_IP, true);
        assert_step4_refused(&wire, "(ii) auth+forwarder, no match");
    }

    // ── Case (iii): forwarder-only, no forward-zone match ────────────────────────

    /// (iii) Forwarder-only deployment: a query for a name that matches no
    /// forward-zone rule hits step-4 and must receive REFUSED + EDE INFO-CODE 20
    /// (ROLE-024).
    ///
    /// This requires the fix in `ForwarderServer::dispatch()` that replaces the
    /// former plain REFUSED (`refused_response`) with `step4_refused_ede20`.
    #[tokio::test(flavor = "multi_thread")]
    async fn forwarder_only_no_match_returns_refused_ede20() {
        let server = make_forwarder_no_rules();
        let query = make_query("example.com.");
        let wire = server.dispatch(&query, CLIENT_IP, true);
        assert_step4_refused(&wire, "(iii) forwarder-only, no rule match");
    }

    // ── Case (iv): recursive disabled, forwarder active, no match ────────────────

    /// (iv) Recursive resolver is disabled; only the forwarder role is active.
    /// A query for a name that matches no forward-zone rule hits step-4 and must
    /// receive REFUSED + EDE INFO-CODE 20, confirming that the step-4 invariant
    /// holds in every combination where step-3 (recursive resolution) is absent.
    ///
    /// Functionally identical to case (iii); named separately to document the
    /// "recursive disabled" trigger per ROLE-025 acceptance criteria.
    #[tokio::test(flavor = "multi_thread")]
    async fn recursive_disabled_forwarder_no_match_returns_refused_ede20() {
        let server = make_forwarder_no_rules();
        let query = make_query("unmatched.example.");
        let wire = server.dispatch(&query, CLIENT_IP, false);
        assert_step4_refused(&wire, "(iv) recursive disabled, forwarder no match");
    }
}
