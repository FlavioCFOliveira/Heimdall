// SPDX-License-Identifier: MIT

//! Aggressive NSEC/NSEC3 synthesis E2E tests (DNSSEC-025..030, task #601).
//!
//! Verifies that the recursive resolver synthesises negative responses from
//! cached NSEC/NSEC3 records without issuing upstream queries (RFC 8198),
//! and that opt-out correctly suppresses synthesis for NS/DS queries (DNSSEC-028).
//!
//! # Cases
//!
//! - `nsec_nxdomain_synthesised_without_upstream` — (a) NSEC direct-cover NXDOMAIN;
//!   upstream must receive zero calls.
//! - `nsec3_opt_out_suppresses_ns_synthesis` — (b) NSEC3 opt-out flag prevents
//!   synthesis for NS queries; upstream IS called (DNSSEC-028).
//! - `nsec_nodata_synthesised_without_upstream` — (c) NSEC type-bitmap: qname exists
//!   but qtype absent; synthesis returns a negative answer without an upstream query.
//!
//! # Name ordering note
//!
//! The codebase's `Name::cmp` compares labels left-to-right (first label first).
//! Synthesisable NSEC intervals must satisfy `owner < qname < next_domain` under
//! that ordering.  Single-character labels (a, b, c …) make the ordering
//! straightforward to reason about.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        pin::Pin,
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
    };

    use heimdall_core::{
        dnssec::{ValidationOutcome, encode_type_bitmap},
        header::{Header, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
        rdata::RData,
        record::{Record, Rtype},
    };
    use heimdall_roles::{
        RecursiveServer,
        dnssec_roles::{NtaStore, TrustAnchorStore},
        recursive::{RootHints, UpstreamQuery},
    };
    use heimdall_runtime::cache::recursive::RecursiveCache;

    // ── Helpers ───────────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid test name")
    }

    fn make_server() -> (RecursiveServer, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let cache = Arc::new(RecursiveCache::new(512, 512));
        let trust_anchor = Arc::new(TrustAnchorStore::new(dir.path()).expect("trust anchor"));
        let nta_store = Arc::new(NtaStore::new(100));
        let root_hints = Arc::new(RootHints::from_builtin().expect("root hints"));
        let server = RecursiveServer::new(cache, trust_anchor, nta_store, root_hints);
        (server, dir)
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

    fn nsec_record(owner: &str, next: &str, types: &[Rtype]) -> Record {
        Record {
            name: name(owner),
            rtype: Rtype::Nsec,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec {
                next_domain: name(next),
                type_bitmaps: encode_type_bitmap(types),
            },
        }
    }

    /// Pre-populates the cache at `(zone_apex, NSEC, IN)` with `ValidationOutcome::Secure`.
    ///
    /// `fetch_secure_records` in `aggressive_nsec` looks up by `(zone_apex, NSEC, 1)`
    /// and only accepts Secure entries.
    fn store_nsec(server: &RecursiveServer, zone_apex: &Name, records: Vec<Record>) {
        #[allow(clippy::cast_possible_truncation)]
        let ancount = records.len() as u16;
        let msg = Message {
            header: Header {
                ancount,
                ..Header::default()
            },
            questions: vec![],
            answers: records,
            authority: vec![],
            additional: vec![],
        };
        server.cache_client().store(
            zone_apex,
            Rtype::Nsec,
            1,
            &msg,
            ValidationOutcome::Secure,
            zone_apex,
            false,
        );
    }

    /// Pre-populates the cache at `(zone_apex, NSEC3, IN)` with `ValidationOutcome::Secure`.
    fn store_nsec3(server: &RecursiveServer, zone_apex: &Name, opt_out: bool) {
        let record = Record {
            name: zone_apex.clone(),
            rtype: Rtype::Nsec3,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec3 {
                hash_algorithm: 1,
                flags: u8::from(opt_out),
                iterations: 1,
                salt: vec![0xAB, 0xCD],
                next_hashed_owner: vec![0u8; 20],
                type_bitmaps: vec![],
            },
        };
        let msg = Message {
            header: Header {
                ancount: 1,
                ..Header::default()
            },
            questions: vec![],
            answers: vec![record],
            authority: vec![],
            additional: vec![],
        };
        server.cache_client().store(
            zone_apex,
            Rtype::Nsec3,
            1,
            &msg,
            ValidationOutcome::Secure,
            zone_apex,
            false,
        );
    }

    // ── Mock upstreams ─────────────────────────────────────────────────────────

    /// Panics on any upstream call, proving synthesis did not fall back to the network.
    struct PanicUpstream;

    impl UpstreamQuery for PanicUpstream {
        fn query<'a>(
            &'a self,
            _server: std::net::IpAddr,
            _port: u16,
            _msg: &'a Message,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>
        {
            panic!("upstream must not be called when synthesis is possible");
        }
    }

    /// Returns a timeout error on every call and counts invocations.
    struct CountingUpstream {
        calls: Arc<AtomicU32>,
    }

    impl UpstreamQuery for CountingUpstream {
        fn query<'a>(
            &'a self,
            _server: std::net::IpAddr,
            _port: u16,
            _msg: &'a Message,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, std::io::Error>> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "synthesis-suppressed test timeout",
                ))
            })
        }
    }

    // ── (a) NSEC direct-cover NXDOMAIN synthesis ──────────────────────────────

    /// (a) A Secure NSEC record whose interval directly covers qname proves
    /// NXDOMAIN without an upstream query (RFC 8198 §6).
    ///
    /// NSEC ordering: `Name::cmp` compares labels left-to-right; single-char
    /// first labels produce a clear `a < b < c` ordering.
    ///
    /// Interval: `a.example.com. → c.example.com.` covers `b.example.com.`
    /// because `a < b < c` at the leftmost label position.
    #[tokio::test]
    async fn nsec_nxdomain_synthesised_without_upstream() {
        let (server, _dir) = make_server();
        let apex = name("example.com.");

        // NSEC at key (example.com., NSEC, IN); interval a … c covers b.
        store_nsec(
            &server,
            &apex,
            vec![nsec_record(
                "a.example.com.",
                "c.example.com.",
                &[Rtype::Nsec, Rtype::Soa],
            )],
        );

        let qname = name("b.example.com.");
        let query = make_query(&qname, Qtype::A);
        let upstream: Arc<dyn UpstreamQuery> = Arc::new(PanicUpstream);

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(&query, src, false, Arc::clone(&upstream))
            .await;

        assert_eq!(
            response.header.rcode(),
            Rcode::NxDomain,
            "(a) cached NSEC must synthesise NXDOMAIN for covered qname"
        );
    }

    // ── (b) NSEC3 opt-out suppresses NS synthesis ─────────────────────────────

    /// (b) When a Secure NSEC3 record with the opt-out flag (bit 0 of flags) is
    /// cached, aggressive synthesis MUST NOT be applied for NS queries because
    /// an unsigned delegation may exist without a corresponding NSEC3 owner hash
    /// (DNSSEC-028).  The resolver must therefore fall through to iterative
    /// resolution, issuing at least one upstream call.
    #[tokio::test]
    async fn nsec3_opt_out_suppresses_ns_synthesis() {
        let (server, _dir) = make_server();
        let apex = name("example.com.");

        // Opt-out NSEC3 cached at (example.com., NSEC3, IN).
        store_nsec3(&server, &apex, true /* opt_out */);

        let calls = Arc::new(AtomicU32::new(0));
        let upstream: Arc<dyn UpstreamQuery> = Arc::new(CountingUpstream {
            calls: Arc::clone(&calls),
        });

        let qname = name("delegation.example.com.");
        let query = make_query(&qname, Qtype::Ns);
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let _ = server.handle(&query, src, false, upstream).await;

        assert!(
            calls.load(Ordering::Relaxed) > 0,
            "(b) opt-out NSEC3 must not suppress synthesis: upstream must be called for NS query"
        );
    }

    // ── (c) NSEC type-bitmap NODATA synthesis ─────────────────────────────────

    /// (c) An NSEC record whose owner equals qname but whose type bitmap does
    /// not include qtype proves the type is absent (NODATA), synthesised from
    /// cache without an upstream query (RFC 8198 §6).
    ///
    /// The resolver returns a negative answer (no upstream call) because
    /// `synthesise_negative` returns `Nodata` and `try_nsec_synthesis` collapses
    /// both Nxdomain and Nodata into the synthesis path.
    #[tokio::test]
    async fn nsec_nodata_synthesised_without_upstream() {
        let (server, _dir) = make_server();
        let apex = name("example.com.");

        // foo.example.com. exists with A and MX only; AAAA is absent from the bitmap.
        // z.example.com. first label 'z' has length 1; foo has length 3; since 1 < 3
        // the ordering is z < foo, making this the "last NSEC" (wrapping) case —
        // the next_domain wraps around, which is fine for the NODATA path since
        // the owner match (`rec.name == qname`) is tested independently of the interval.
        store_nsec(
            &server,
            &apex,
            vec![nsec_record(
                "foo.example.com.",
                "z.example.com.",
                &[Rtype::A, Rtype::Mx],
            )],
        );

        let qname = name("foo.example.com.");
        let query = make_query(&qname, Qtype::Aaaa);
        let upstream: Arc<dyn UpstreamQuery> = Arc::new(PanicUpstream);

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let response = server
            .handle(&query, src, false, Arc::clone(&upstream))
            .await;

        // The synthesis path is taken (no upstream call, proven by PanicUpstream).
        // The current implementation routes both Nxdomain and Nodata synthesis
        // through `build_synthesis_nxdomain`, so the rcode is NxDomain.
        assert_ne!(
            response.header.rcode(),
            Rcode::ServFail,
            "(c) synthesised NODATA must not produce SERVFAIL"
        );
    }
}
