// SPDX-License-Identifier: MIT

//! Integration tests for the RPZ module (Sprint 34).
//!
//! Covers all 26 required test cases:
//! - Action engine (Task #345): tests 1–9
//! - QNAME trigger (Task #346): tests 10–13
//! - Trigger precedence (Task #347): tests 14–15
//! - Multi-zone evaluation (Task #350): tests 16–18
//! - AD suppression + EDE (Task #351): tests 19–20
//! - CIDR trie (Task #352): tests 21–22
//! - File loader (Task #349): tests 23–24
//! - Dynamic reload (Task #354): tests 25–26

use std::io::Write as IoWrite;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use heimdall_core::edns::{EdnsOption, ede_code};
use heimdall_core::header::{Header, Qclass, Qtype, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};

use heimdall_roles::rpz::{
    CidrRange, CidrTrie, PolicyZone, PolicyZoneConfig, QnameTrie, RpzAction, RpzContext,
    RpzDecision, RpzEngine, RpzEntry, RpzTrigger, ZoneSource, load_from_file,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_query(qname: &str) -> Message {
    let name = Name::from_str(qname).unwrap();
    let mut header = Header::default();
    header.id = 42;
    header.set_rd(true);
    header.qdcount = 1;
    Message {
        header,
        questions: vec![heimdall_core::header::Question {
            qname: name,
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn make_a_response(qname: &str, ad: bool) -> Message {
    let name = Name::from_str(qname).unwrap();
    let mut header = Header::default();
    header.id = 42;
    header.set_qr(true);
    header.set_ad(ad);
    header.set_rd(true);
    header.qdcount = 1;
    header.ancount = 1;
    Message {
        header,
        questions: vec![heimdall_core::header::Question {
            qname: name.clone(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![Record {
            name,
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        }],
        authority: vec![],
        additional: vec![],
    }
}

/// Returns `true` if `msg` contains an EDE option with `info_code` in its Additional section.
fn has_ede(msg: &Message, info_code: u16) -> bool {
    msg.additional.iter().any(|r| {
        if let RData::Opt(opt) = &r.rdata {
            opt.options.iter().any(|o| {
                matches!(o, EdnsOption::ExtendedError(e) if e.info_code == info_code)
            })
        } else {
            false
        }
    })
}

fn zone_with_qname_exact(zone_name: &str, order: u8, qname_str: &str, action: RpzAction) -> PolicyZone {
    let mut z = PolicyZone::new(zone_name.to_string(), order);
    z.insert(RpzEntry {
        trigger: RpzTrigger::QnameExact(Name::from_str(qname_str).unwrap()),
        action,
        position: 0,
    });
    z
}

fn eval_ctx(qname: &str) -> RpzContext {
    RpzContext {
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        qname: Name::from_str(qname).unwrap(),
        qtype: Rtype::A,
        is_udp: true,
        response_ips: vec![],
        ns_names: vec![],
        ns_ips: vec![],
    }
}

// ── Action engine (Task #345) ─────────────────────────────────────────────────

/// Test 1: NXDOMAIN action clears AD and sets EDE code 15.
#[test]
fn action_nxdomain_clears_ad() {
    let q = make_query("blocked.example.com.");
    let msg = RpzAction::Nxdomain.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
    assert_eq!(msg.header.rcode(), Rcode::NxDomain, "RCODE must be NXDOMAIN");
    assert!(!msg.header.ad(), "AD flag must be cleared");
    assert!(has_ede(&msg, ede_code::BLOCKED), "EDE code 15 must be present");
}

/// Test 2: NODATA action returns empty Answer, RCODE NoError, AD=0, EDE 15.
#[test]
fn action_nodata_empty_answer() {
    let q = make_query("blocked.example.com.");
    let msg = RpzAction::Nodata.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
    assert_eq!(msg.header.rcode(), Rcode::NoError, "RCODE must be NoError");
    assert!(msg.answers.is_empty(), "Answer section must be empty");
    assert!(!msg.header.ad(), "AD flag must be cleared");
    assert!(has_ede(&msg, ede_code::BLOCKED), "EDE code 15 must be present");
}

/// Test 3: PASSTHRU returns the original response unmodified.
#[test]
fn action_passthru_preserves_response() {
    let q = make_query("good.example.com.");
    let upstream = make_a_response("good.example.com.", true);
    let result = RpzAction::Passthru
        .apply(&q, Some(&upstream), false, 30, "rpz.example.com.")
        .unwrap();
    assert_eq!(result, upstream, "PASSTHRU must return original response unchanged");
}

/// Test 4: DROP returns None.
#[test]
fn action_drop_returns_none() {
    let q = make_query("drop.example.com.");
    let result = RpzAction::Drop.apply(&q, None, false, 30, "rpz.example.com.");
    assert!(result.is_none(), "DROP must return None");
}

/// Test 5: TcpOnly on UDP sets TC=1, empty Answer.
#[test]
fn action_tcp_only_on_udp_sets_tc() {
    let q = make_query("tcp.example.com.");
    let msg = RpzAction::TcpOnly.apply(&q, None, true, 30, "rpz.example.com.").unwrap();
    assert!(msg.header.tc(), "TC flag must be set on UDP");
    assert!(msg.answers.is_empty(), "Answer must be empty for TC response");
}

/// Test 6: TcpOnly on TCP returns original response unchanged.
#[test]
fn action_tcp_only_on_tcp_is_passthru() {
    let q = make_query("tcp.example.com.");
    let upstream = make_a_response("tcp.example.com.", false);
    let result = RpzAction::TcpOnly
        .apply(&q, Some(&upstream), false, 30, "rpz.example.com.")
        .unwrap();
    assert_eq!(result, upstream, "TcpOnly on TCP must be passthru");
}

/// Test 7: LocalData replaces Answer, clears AD, sets EDE 17.
#[test]
fn action_local_data_replaces_answer() {
    let q = make_query("local.example.com.");
    let synthetic = Record {
        name: Name::from_str("local.example.com.").unwrap(),
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: 30,
        rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
    };
    let action = RpzAction::LocalData { records: vec![synthetic.clone()] };
    let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
    assert!(!msg.header.ad(), "AD must be cleared by LocalData");
    assert_eq!(msg.answers, vec![synthetic], "Answer must be replaced by local records");
    assert!(has_ede(&msg, ede_code::FILTERED), "EDE code 17 must be present");
}

/// Test 8: CnameRedirect to root `.` is treated as NXDOMAIN.
#[test]
fn action_cname_redirect_to_root_is_nxdomain() {
    let q = make_query("evil.example.com.");
    let action = RpzAction::CnameRedirect { target: Box::new(Name::root()) };
    let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
    assert_eq!(msg.header.rcode(), Rcode::NxDomain, "CNAME to root must produce NXDOMAIN");
}

/// Test 9: CnameRedirect to a real name sets CNAME in Answer, clears AD, EDE 16.
#[test]
fn action_cname_redirect_sets_cname() {
    let q = make_query("evil.example.com.");
    let target = Name::from_str("safe.example.com.").unwrap();
    let action = RpzAction::CnameRedirect { target: Box::new(target) };
    let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
    assert!(!msg.header.ad(), "AD must be cleared by CnameRedirect");
    assert!(
        msg.answers.iter().any(|r| r.rtype == Rtype::Cname),
        "Answer must contain a CNAME record"
    );
    assert!(has_ede(&msg, ede_code::CENSORED), "EDE code 16 must be present");
}

// ── QNAME trigger (Task #346) ─────────────────────────────────────────────────

/// Test 10: QnameTrie exact match.
#[test]
fn qname_trie_exact_match() {
    let mut trie = QnameTrie::new();
    let name = Name::from_str("blocked.example.com.").unwrap();
    trie.insert_exact(&name, RpzAction::Nxdomain);
    assert_eq!(trie.lookup(&name), Some(&RpzAction::Nxdomain));
}

/// Test 11: Wildcard matches subdomain but not apex.
#[test]
fn qname_trie_wildcard_match() {
    let mut trie = QnameTrie::new();
    let suffix = Name::from_str("evil.com.").unwrap();
    trie.insert_wildcard(&suffix, RpzAction::Nxdomain);

    let sub = Name::from_str("sub.evil.com.").unwrap();
    assert_eq!(trie.lookup(&sub), Some(&RpzAction::Nxdomain), "subdomain must match wildcard");

    let apex = Name::from_str("evil.com.").unwrap();
    assert!(trie.lookup(&apex).is_none(), "apex must NOT match wildcard");
}

/// Test 12: Longest-matching wildcard wins.
#[test]
fn qname_trie_longest_wildcard_wins() {
    let mut trie = QnameTrie::new();
    let short = Name::from_str("example.com.").unwrap();
    let long = Name::from_str("b.example.com.").unwrap();
    trie.insert_wildcard(&short, RpzAction::Nodata);
    trie.insert_wildcard(&long, RpzAction::Drop);

    let qname = Name::from_str("a.b.example.com.").unwrap();
    assert_eq!(trie.lookup(&qname), Some(&RpzAction::Drop), "longer wildcard must win");
}

/// Test 13: Lookup of unrelated name returns None.
#[test]
fn qname_trie_no_match() {
    let mut trie = QnameTrie::new();
    let name = Name::from_str("blocked.example.com.").unwrap();
    trie.insert_exact(&name, RpzAction::Nxdomain);

    let other = Name::from_str("benign.org.").unwrap();
    assert!(trie.lookup(&other).is_none());
}

// ── Trigger precedence (Task #347) ────────────────────────────────────────────

/// Test 14: Client-IP trigger fires before QNAME when both match.
#[test]
fn client_ip_beats_qname() {
    let mut z = PolicyZone::new("rpz.test.".to_string(), 0);
    // Client-IP: 192.0.2.1 → Drop
    z.insert(RpzEntry {
        trigger: RpzTrigger::ClientIp(CidrRange {
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 32,
        }),
        action: RpzAction::Drop,
        position: 0,
    });
    // QNAME: "example.com." → Nxdomain
    z.insert(RpzEntry {
        trigger: RpzTrigger::QnameExact(Name::from_str("example.com.").unwrap()),
        action: RpzAction::Nxdomain,
        position: 1,
    });

    let engine = RpzEngine::new(vec![z]);
    let ctx = eval_ctx("example.com.");
    // Client-IP must win.
    assert_eq!(
        engine.evaluate(&ctx),
        RpzDecision::Match { zone: "rpz.test.".to_string(), action: RpzAction::Drop }
    );
}

/// Test 15: Exact QNAME trigger fires before wildcard.
#[test]
fn exact_qname_beats_wildcard() {
    let mut z = PolicyZone::new("rpz.test.".to_string(), 0);
    // Wildcard: *.example.com. → Nxdomain
    z.insert(RpzEntry {
        trigger: RpzTrigger::QnameWildcard(Name::from_str("example.com.").unwrap()),
        action: RpzAction::Nxdomain,
        position: 0,
    });
    // Exact: sub.example.com. → Passthru
    z.insert(RpzEntry {
        trigger: RpzTrigger::QnameExact(Name::from_str("sub.example.com.").unwrap()),
        action: RpzAction::Passthru,
        position: 1,
    });

    let engine = RpzEngine::new(vec![z]);
    // sub.example.com. → exact match wins, Passthru → NoMatch
    assert_eq!(engine.evaluate(&eval_ctx("sub.example.com.")), RpzDecision::NoMatch);
    // other.example.com. → only wildcard matches → Nxdomain
    assert_eq!(
        engine.evaluate(&eval_ctx("other.example.com.")),
        RpzDecision::Match { zone: "rpz.test.".to_string(), action: RpzAction::Nxdomain }
    );
}

// ── Multi-zone evaluation (Task #350) ─────────────────────────────────────────

/// Test 16: First zone wins (zone0 DROP vs zone1 NXDOMAIN for same QNAME).
#[test]
fn engine_first_match_wins() {
    let z0 = zone_with_qname_exact("zone0.rpz.", 0, "bad.example.com.", RpzAction::Drop);
    let z1 = zone_with_qname_exact("zone1.rpz.", 1, "bad.example.com.", RpzAction::Nxdomain);
    let engine = RpzEngine::new(vec![z0, z1]);
    assert_eq!(
        engine.evaluate(&eval_ctx("bad.example.com.")),
        RpzDecision::Match { zone: "zone0.rpz.".to_string(), action: RpzAction::Drop }
    );
}

/// Test 17: PASSTHRU in zone0 short-circuits; zone1 DROP is never reached.
#[test]
fn engine_passthru_stops_evaluation() {
    let z0 = zone_with_qname_exact("zone0.rpz.", 0, "allowed.example.com.", RpzAction::Passthru);
    let z1 = zone_with_qname_exact("zone1.rpz.", 1, "allowed.example.com.", RpzAction::Drop);
    let engine = RpzEngine::new(vec![z0, z1]);
    // Passthru converts to NoMatch (allow through).
    assert_eq!(engine.evaluate(&eval_ctx("allowed.example.com.")), RpzDecision::NoMatch);
}

/// Test 18: No rule matches → NoMatch.
#[test]
fn engine_no_match_returns_no_match() {
    let z = zone_with_qname_exact("zone0.rpz.", 0, "blocked.example.com.", RpzAction::Nxdomain);
    let engine = RpzEngine::new(vec![z]);
    assert_eq!(engine.evaluate(&eval_ctx("benign.org.")), RpzDecision::NoMatch);
}

// ── AD suppression + EDE (Task #351) ─────────────────────────────────────────

/// Test 19: AD=0 on NXDOMAIN, NODATA, LocalData, CnameRedirect actions.
#[test]
fn ad_cleared_on_all_non_passthru_actions() {
    let q = make_query("test.example.com.");
    let zone_name = "rpz.example.com.";

    let nxdomain_msg = RpzAction::Nxdomain.apply(&q, None, false, 30, zone_name).unwrap();
    assert!(!nxdomain_msg.header.ad(), "Nxdomain must clear AD");

    let nodata_msg = RpzAction::Nodata.apply(&q, None, false, 30, zone_name).unwrap();
    assert!(!nodata_msg.header.ad(), "Nodata must clear AD");

    let local_action = RpzAction::LocalData {
        records: vec![Record {
            name: Name::from_str("test.example.com.").unwrap(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 30,
            rdata: RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        }],
    };
    let local_msg = local_action.apply(&q, None, false, 30, zone_name).unwrap();
    assert!(!local_msg.header.ad(), "LocalData must clear AD");

    let cname_action = RpzAction::CnameRedirect {
        target: Box::new(Name::from_str("safe.example.com.").unwrap()),
    };
    let cname_msg = cname_action.apply(&q, None, false, 30, zone_name).unwrap();
    assert!(!cname_msg.header.ad(), "CnameRedirect must clear AD");
}

/// Test 20: PASSTHRU preserves AD=1 from the original response.
#[test]
fn passthru_preserves_ad() {
    let q = make_query("good.example.com.");
    let upstream = make_a_response("good.example.com.", true); // AD=1
    assert!(upstream.header.ad(), "upstream must have AD=1 for this test");

    let result = RpzAction::Passthru
        .apply(&q, Some(&upstream), false, 30, "rpz.example.com.")
        .unwrap();
    assert!(result.header.ad(), "PASSTHRU must preserve AD=1");
}

// ── CIDR trie (Task #352) ─────────────────────────────────────────────────────

/// Test 21: IPv4 /16 match and non-match.
#[test]
fn cidr_trie_v4_match() {
    let mut trie = CidrTrie::new();
    trie.insert(
        &CidrRange { addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), prefix_len: 16 },
        RpzAction::Drop,
    );
    assert_eq!(
        trie.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        Some(&RpzAction::Drop)
    );
    assert!(trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
}

/// Test 22: Most-specific CIDR wins (/24 beats /8).
#[test]
fn cidr_trie_most_specific_wins() {
    let mut trie = CidrTrie::new();
    trie.insert(
        &CidrRange { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), prefix_len: 8 },
        RpzAction::Nodata,
    );
    trie.insert(
        &CidrRange { addr: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), prefix_len: 24 },
        RpzAction::Drop,
    );
    // 10.1.0.5 matches both — /24 must win.
    assert_eq!(
        trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))),
        Some(&RpzAction::Drop)
    );
    // 10.2.0.1 matches only /8.
    assert_eq!(
        trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))),
        Some(&RpzAction::Nodata)
    );
}

// ── File loader (Task #349) ───────────────────────────────────────────────────

/// Test 23: Load a zone file with a QNAME→NXDOMAIN entry.
#[test]
fn load_from_file_nxdomain_entry() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmp,
        "$ORIGIN rpz.test.\n\
         $TTL 30\n\
         @ IN SOA ns1 hostmaster 1 3600 900 604800 30\n\
         blocked.example.com IN CNAME .\n"
    )
    .unwrap();
    tmp.flush().unwrap();

    let config = PolicyZoneConfig {
        zone: "rpz.test.".to_string(),
        source: ZoneSource::File { path: tmp.path().to_path_buf() },
        evaluation_order: 0,
        policy_ttl: 30,
    };

    let zone = load_from_file(&config).expect("load_from_file must succeed");
    let qname = Name::from_str("blocked.example.com.").unwrap();
    assert_eq!(
        zone.check_qname(&qname),
        Some(RpzAction::Nxdomain),
        "QNAME exact → NXDOMAIN entry must be present"
    );
}

/// Test 24: Malformed file content produces an RpzLoadError.
#[test]
fn load_from_file_malformed_rejected() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "@@@ THIS IS NOT VALID ZONE FILE SYNTAX @@@\n").unwrap();
    tmp.flush().unwrap();

    let config = PolicyZoneConfig {
        zone: "rpz.test.".to_string(),
        source: ZoneSource::File { path: tmp.path().to_path_buf() },
        evaluation_order: 0,
        policy_ttl: 30,
    };

    assert!(load_from_file(&config).is_err(), "malformed file must produce RpzLoadError");
}

// ── Dynamic reload (Task #354) ────────────────────────────────────────────────

/// Test 25: `upsert_entry` makes an entry visible immediately.
#[test]
fn engine_upsert_entry_visible_immediately() {
    let engine = RpzEngine::new(vec![PolicyZone::new("rpz.test.".to_string(), 0)]);
    assert_eq!(engine.evaluate(&eval_ctx("new.example.com.")), RpzDecision::NoMatch);

    engine.upsert_entry(
        "rpz.test.",
        &RpzEntry {
            trigger: RpzTrigger::QnameExact(Name::from_str("new.example.com.").unwrap()),
            action: RpzAction::Nxdomain,
            position: 0,
        },
    );

    assert_eq!(
        engine.evaluate(&eval_ctx("new.example.com.")),
        RpzDecision::Match { zone: "rpz.test.".to_string(), action: RpzAction::Nxdomain }
    );
}

/// Test 26: `remove_entry` makes an entry invisible immediately.
#[test]
fn engine_remove_entry_invisible_immediately() {
    let trigger = RpzTrigger::QnameExact(Name::from_str("remove.example.com.").unwrap());
    let mut z = PolicyZone::new("rpz.test.".to_string(), 0);
    z.insert(RpzEntry { trigger: trigger.clone(), action: RpzAction::Drop, position: 0 });

    let engine = RpzEngine::new(vec![z]);
    assert!(
        matches!(engine.evaluate(&eval_ctx("remove.example.com.")), RpzDecision::Match { .. }),
        "entry must match before removal"
    );

    engine.remove_entry("rpz.test.", &trigger);
    assert_eq!(
        engine.evaluate(&eval_ctx("remove.example.com.")),
        RpzDecision::NoMatch,
        "entry must be gone after removal"
    );
}
