// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! E2E: Glue record handling per RFC 9471 (PROTO-050..054).
//! Sprint 47 task #543.
//!
//! ## Strategy
//!
//! A root spy at `127.0.0.2:<port>` returns NS referrals.  An in-bailiwick child
//! spy at `127.0.0.3:<port>` serves final answers.  An out-of-bailiwick spy at
//! `127.0.0.4:<port>` must receive no queries.
//!
//! All spies share the resolver's `query_port`.  The recursive resolver's root
//! hints point exclusively to `127.0.0.2`.  QNAME minimisation is disabled so
//! the query sequence is deterministic.
//!
//! ## Tests
//!
//! 1. `inbailiwick_glue_accepted`: referral with in-bailiwick glue → resolver
//!    contacts the in-bailiwick NS; resolution succeeds.
//!
//! 2. `oob_glue_triggers_ns_address_chase`: referral with OOB-only NS/glue; the
//!    resolver discards the OOB glue, independently resolves the NS name's A
//!    record (PROTO-051), and completes resolution.  OOB spy receives no queries.
//!
//! 3. `mixed_glue_oob_discarded`: referral has both in-bailiwick and OOB NS
//!    entries; OOB glue is discarded and the in-bailiwick path is used.  OOB spy
//!    receives no queries.

#![cfg(all(unix, target_os = "linux"))]

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use heimdall_e2e_harness::{
    TestServer, config, dns_client, free_port, spy_dns, spy_dns::SpyResponse,
};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

/// A-record IP served by the in-bailiwick child NS spy.
const CHILD_ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// IPv4 address of the root spy.
const ROOT_SPY_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// IPv4 address of the in-bailiwick child NS spy.
const IB_NS_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// IPv4 address of the out-of-bailiwick NS spy (must receive no queries).
const OOB_NS_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Starts a recursive resolver whose root hints point to `ROOT_SPY_IP:query_port`
/// with QNAME minimisation disabled.
fn start_resolver(query_port: u16) -> (TestServer, SocketAddr, tempfile::TempDir) {
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(
        &hints_path,
        format!("ns.root-test. 3600 IN A {ROOT_SPY_IP}\n"),
    )
    .expect("write root hints");

    let rec_port = free_port();
    let rec_obs = free_port();
    let rec_toml = config::minimal_recursive_custom_with_qname_min(
        rec_port,
        rec_obs,
        &hints_path,
        query_port,
        "off",
    );

    let server = TestServer::start_with_ports(BIN, &rec_toml, rec_port, rec_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("recursive resolver did not become ready");

    std::thread::sleep(Duration::from_millis(150));
    let addr: SocketAddr = format!("127.0.0.1:{rec_port}").parse().unwrap();
    (server, addr, hints_dir)
}

// ── Test 1: in-bailiwick glue accepted ───────────────────────────────────────

/// In-bailiwick glue is accepted and used to contact the NS server.
///
/// Referral: `child.test. NS ns1.child.test.`, glue `ns1.child.test. A 127.0.0.3`.
/// `ns1.child.test.` is under `child.test.` → in-bailiwick → accepted.
#[test]
fn inbailiwick_glue_accepted() {
    let query_port = free_port();

    // Root spy: NS referral with in-bailiwick glue.
    let root_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((ROOT_SPY_IP, query_port)),
        vec![SpyResponse::Referral {
            zone: "child.test.".into(),
            ns_name: "ns1.child.test.".into(),
            glue_ip: IB_NS_IP,
        }],
    );

    // In-bailiwick child NS spy: returns the A answer.
    let child_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((IB_NS_IP, query_port)),
        vec![SpyResponse::Answer {
            ip: CHILD_ANSWER_IP,
        }],
    );

    let (_rec, rec_addr, _hints_dir) = start_resolver(query_port);

    let resp = dns_client::query_a(rec_addr, "www.child.test.");
    assert_eq!(
        resp.rcode, 0,
        "in-bailiwick glue: expected NOERROR, got rcode={}",
        resp.rcode
    );
    assert!(
        resp.ancount > 0,
        "in-bailiwick glue: expected an answer record"
    );

    assert!(
        !root_spy.received().is_empty(),
        "root spy must have received a query"
    );
    assert!(
        !child_spy.received().is_empty(),
        "child NS spy must have been contacted via in-bailiwick glue"
    );
}

// ── Test 2: OOB-only glue → NS address chase ─────────────────────────────────

/// OOB-only glue is discarded; the resolver independently resolves the NS name's
/// A record (PROTO-051) and completes resolution via the chased address.
///
/// Referral: `child.test. NS ns1.oob.example.`, glue `ns1.oob.example. A 127.0.0.4`.
/// `ns1.oob.example.` is NOT under `child.test.` → OOB → glue discarded.
/// The resolver chases `ns1.oob.example. A`; root spy returns `127.0.0.3`.
/// The child spy at `127.0.0.3` returns the final answer.
/// The OOB spy at `127.0.0.4` must receive NO queries.
#[test]
fn oob_glue_triggers_ns_address_chase() {
    let query_port = free_port();

    // Root spy:
    //   Response[0] — original query: referral for `child.test.` with NS
    //     `ns1.oob.example.` and matching glue `ns1.oob.example. A OOB_NS_IP`.
    //     The bailiwick filter rejects it (OOB); glue_addrs is empty → NS chase.
    //   Response[1] — NS chase: resolver resolves `ns1.oob.example. A`.
    //     Root spy answers authoritatively with IB_NS_IP.
    let _root_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((ROOT_SPY_IP, query_port)),
        vec![
            SpyResponse::Referral {
                zone: "child.test.".into(),
                ns_name: "ns1.oob.example.".into(), // OOB: not under child.test.
                glue_ip: OOB_NS_IP,
            },
            // Chase response: ns1.oob.example. A → IB_NS_IP (127.0.0.3).
            SpyResponse::Answer { ip: IB_NS_IP },
        ],
    );

    // Child NS spy: receives the resolver's final query for www.child.test.
    let child_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((IB_NS_IP, query_port)),
        vec![SpyResponse::Answer {
            ip: CHILD_ANSWER_IP,
        }],
    );

    // OOB spy: must receive NO queries.
    let oob_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((OOB_NS_IP, query_port)),
        vec![SpyResponse::Answer {
            ip: Ipv4Addr::new(10, 0, 0, 1),
        }],
    );

    let (_rec, rec_addr, _hints_dir) = start_resolver(query_port);

    let resp = dns_client::query_a(rec_addr, "www.child.test.");
    assert_eq!(
        resp.rcode, 0,
        "OOB glue chase: expected NOERROR, got rcode={}",
        resp.rcode
    );
    assert!(
        resp.ancount > 0,
        "OOB glue chase: expected an answer record"
    );

    // OOB spy must not have been queried.
    let oob_received = oob_spy.received();
    assert!(
        oob_received.is_empty(),
        "OOB spy must receive no queries; got: {oob_received:?}"
    );

    // Child spy must have been contacted (via chased NS address).
    assert!(
        !child_spy.received().is_empty(),
        "child spy must have been contacted after the NS address chase"
    );
}

// ── Test 3: mixed glue — OOB discarded, in-bailiwick used ────────────────────

/// Mixed referral: one in-bailiwick NS + glue, one OOB NS + glue.
/// The OOB entry is discarded; the in-bailiwick entry is used.
/// OOB spy receives no queries.
///
/// Referral: `child.test. NS ns1.child.test.` glue `127.0.0.3` (in-bailiwick)
///         + `child.test. NS ns1.oob.example.` glue `127.0.0.4` (OOB).
#[test]
fn mixed_glue_oob_discarded() {
    let query_port = free_port();

    // Root spy: multi-NS referral with both in-bailiwick and OOB entries.
    let root_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((ROOT_SPY_IP, query_port)),
        vec![SpyResponse::ReferralMultiNs {
            zone: "child.test.".into(),
            entries: vec![
                // In-bailiwick: ns1.child.test. A 127.0.0.3 (accepted).
                ("ns1.child.test.".into(), IB_NS_IP),
                // OOB: ns1.oob.example. A 127.0.0.4 (discarded).
                ("ns1.oob.example.".into(), OOB_NS_IP),
            ],
        }],
    );

    // In-bailiwick child NS spy.
    let child_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((IB_NS_IP, query_port)),
        vec![SpyResponse::Answer {
            ip: CHILD_ANSWER_IP,
        }],
    );

    // OOB spy: must receive no queries.
    let oob_spy = spy_dns::SpyDnsServer::start(
        SocketAddr::from((OOB_NS_IP, query_port)),
        vec![SpyResponse::Answer {
            ip: Ipv4Addr::new(10, 0, 0, 1),
        }],
    );

    let (_rec, rec_addr, _hints_dir) = start_resolver(query_port);

    let resp = dns_client::query_a(rec_addr, "www.child.test.");
    assert_eq!(
        resp.rcode, 0,
        "mixed glue: expected NOERROR, got rcode={}",
        resp.rcode
    );
    assert!(resp.ancount > 0, "mixed glue: expected an answer record");

    // OOB spy must not have been contacted.
    let oob_received = oob_spy.received();
    assert!(
        oob_received.is_empty(),
        "mixed glue: OOB spy must receive no queries; got: {oob_received:?}"
    );

    assert!(
        !root_spy.received().is_empty(),
        "root spy must have been contacted"
    );
    assert!(
        !child_spy.received().is_empty(),
        "child spy must have been contacted"
    );
}
