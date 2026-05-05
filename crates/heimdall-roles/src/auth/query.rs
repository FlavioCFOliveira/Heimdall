// SPDX-License-Identifier: MIT

//! Standard query serving for the authoritative server role (RFC 1034/1035).
//!
//! Entry point: [`serve_query`]. The function handles QTYPE lookup, CNAME/DNAME
//! synthesis, DNSSEC pass-through, glue, truncation, and AA flag.

use std::collections::HashMap;

use heimdall_core::{
    header::{Header, Opcode, Qtype, Question, Rcode},
    name::Name,
    parser::Message,
    rdata::RData,
    record::{Record, Rtype},
    zone::ZoneFile,
};

use crate::auth::AuthError;

/// Maximum number of CNAME hops to follow before declaring a loop (PROTO-007).
const MAX_CNAME_HOPS: usize = 8;

/// Default maximum response size for UDP (bytes); overridden by EDNS.
const DEFAULT_UDP_MAX: usize = 512;

// ── Index helpers ─────────────────────────────────────────────────────────────

/// Lightweight in-memory index built from a [`ZoneFile`]: maps
/// `(owner_lowercase, rtype_u16)` → list of records.
type ZoneIndex = HashMap<(String, u16), Vec<Record>>;

fn build_index(zone: &ZoneFile) -> ZoneIndex {
    let mut map: ZoneIndex = HashMap::new();
    for rec in &zone.records {
        let key = (
            rec.name.to_string().to_ascii_lowercase(),
            rec.rtype.as_u16(),
        );
        map.entry(key).or_default().push(rec.clone());
    }
    map
}

/// Returns all records for `(owner, rtype)` from the index.
fn lookup<'a>(idx: &'a ZoneIndex, owner: &Name, rtype: Rtype) -> &'a [Record] {
    let key = (owner.to_string().to_ascii_lowercase(), rtype.as_u16());
    idx.get(&key).map_or(&[], Vec::as_slice)
}

/// Returns true if `name` is at or below `apex` (i.e. within the zone).
fn is_in_zone(name: &Name, apex: &Name) -> bool {
    let n = name.to_string().to_ascii_lowercase();
    let a = apex.to_string().to_ascii_lowercase();
    n == a || n.ends_with(&format!(".{a}"))
}

/// Extracts the SOA record from the zone index.
fn soa_record(idx: &ZoneIndex, apex: &Name) -> Option<Record> {
    lookup(idx, apex, Rtype::Soa).first().cloned()
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Serve a standard DNS query against an in-memory zone.
///
/// Implements RFC 1034/1035 query processing with CNAME/DNAME synthesis,
/// DNSSEC pass-through (`DO` flag), glue, and truncation.
///
/// # Parameters
///
/// - `zone` — the authoritative zone.
/// - `apex` — the zone apex (must match the zone's `$ORIGIN`).
/// - `msg` — the incoming query (must have exactly one question).
/// - `dnssec_ok` — whether the `DO` bit was set in the incoming EDNS OPT.
/// - `max_udp_payload` — EDNS-negotiated max UDP payload (0 → 512).
///
/// # Errors
///
/// Returns [`AuthError::NoQuestion`] if the message carries no question.
pub fn serve_query(
    zone: &ZoneFile,
    apex: &Name,
    msg: &Message,
    dnssec_ok: bool,
    max_udp_payload: u16,
) -> Result<Message, AuthError> {
    let q = msg.questions.first().ok_or(AuthError::NoQuestion)?;

    // Determine effective UDP limit.
    let udp_limit = if max_udp_payload == 0 {
        DEFAULT_UDP_MAX
    } else {
        usize::from(max_udp_payload)
    };

    // Zone check: qname must be at-or-below apex; otherwise REFUSED.
    if !is_in_zone(&q.qname, apex) {
        return Ok(make_response(
            msg,
            Rcode::Refused,
            false,
            vec![],
            vec![],
            vec![],
        ));
    }

    let idx = build_index(zone);

    // AXFR/IXFR questions are handled by the transfer modules, not here.
    if matches!(q.qtype, Qtype::Axfr | Qtype::Ixfr) {
        return Ok(make_response(
            msg,
            Rcode::Refused,
            true,
            vec![],
            vec![],
            vec![],
        ));
    }

    // Perform the authoritative lookup.
    let (rcode, answers, authority, additional) = authoritative_lookup(&idx, apex, q, dnssec_ok);

    let resp = build_final_response(msg, rcode, answers, authority, additional, udp_limit);
    Ok(resp)
}

// ── Core lookup logic ─────────────────────────────────────────────────────────

fn authoritative_lookup(
    idx: &ZoneIndex,
    apex: &Name,
    q: &Question,
    dnssec_ok: bool,
) -> (Rcode, Vec<Record>, Vec<Record>, Vec<Record>) {
    // DNAME synthesis: if any ancestor of qname (within the zone, not apex) has a
    // DNAME record, synthesize a CNAME and return (RFC 6672 §3.2).
    if let Some((dname_rec, dname_target)) = find_dname_ancestor(idx, apex, &q.qname) {
        return synthesize_dname_response(idx, apex, q, &dname_rec, &dname_target);
    }

    // Check whether the owner name exists in the zone at all.
    let name_exists = idx
        .keys()
        .any(|(owner, _)| *owner == q.qname.to_string().to_ascii_lowercase());

    if !name_exists {
        // Wildcard lookup: check for `*.{parent}` before returning NXDOMAIN (RFC 4592).
        if let Some(wc_str) = wildcard_owner_str(&q.qname, apex)
            && idx.keys().any(|(owner, _)| *owner == wc_str)
        {
            return serve_wildcard(idx, apex, q, &wc_str, dnssec_ok);
        }

        // NXDOMAIN: name does not exist. Include SOA + NSEC covering records in authority.
        let mut auth = soa_record(idx, apex).into_iter().collect::<Vec<_>>();
        let mut additional = vec![];
        if dnssec_ok {
            // Include all NSEC records from the zone (covering the qname proves non-existence).
            let all_nsec: Vec<Record> = collect_zone_records(idx, Rtype::Nsec);
            let nsec_rrsigs: Vec<Record> = collect_rrsig_for_type(idx, Rtype::Nsec);
            auth.extend(all_nsec);
            auth.extend(nsec_rrsigs);
            // DNSKEY in additional so the resolver can validate NSEC RRSIGs.
            additional.extend_from_slice(lookup(idx, apex, Rtype::Dnskey));
        }
        return (Rcode::NxDomain, vec![], auth, additional);
    }

    // Handle QTYPE::ANY — return all RRsets for the owner (RFC 8482 basic).
    if q.qtype == Qtype::Any {
        let ans = collect_all_types(idx, &q.qname, dnssec_ok);
        if ans.is_empty() {
            let auth = soa_record(idx, apex).into_iter().collect();
            return (Rcode::NoError, vec![], auth, vec![]);
        }
        let additional = collect_glue(idx, apex, &ans);
        return (Rcode::NoError, ans, vec![], additional);
    }

    // QTYPE::SOA: return SOA directly.
    if q.qtype == Qtype::Soa {
        let ans: Vec<Record> = lookup(idx, &q.qname, Rtype::Soa).to_vec();
        if ans.is_empty() {
            let auth = soa_record(idx, apex).into_iter().collect();
            return (Rcode::NoError, vec![], auth, vec![]);
        }
        let mut extra: Vec<Record> = vec![];
        if dnssec_ok {
            extra.extend_from_slice(lookup(idx, &q.qname, Rtype::Rrsig));
        }
        return (Rcode::NoError, ans, extra, vec![]);
    }

    // Determine the target rtype from Qtype.
    let target_rtype = qtype_to_rtype(q.qtype);

    // Check for CNAME at the owner (unless querying directly for CNAME).
    if q.qtype != Qtype::Cname {
        let cname_chain = follow_cname(idx, apex, &q.qname, target_rtype, dnssec_ok);
        if let Some((ans, additional)) = cname_chain {
            return (Rcode::NoError, ans, vec![], additional);
        }
    }

    // Direct lookup.
    let mut ans: Vec<Record> = if let Some(rtype) = target_rtype {
        lookup(idx, &q.qname, rtype).to_vec()
    } else {
        vec![]
    };

    if dnssec_ok {
        ans.extend_from_slice(lookup(idx, &q.qname, Rtype::Rrsig));
    }

    if ans.is_empty() {
        // NODATA: name exists but no records of the requested type.
        let auth = soa_record(idx, apex).into_iter().collect();
        return (Rcode::NoError, vec![], auth, vec![]);
    }

    let mut additional = collect_glue(idx, apex, &ans);
    if dnssec_ok {
        // Include the zone apex DNSKEY in additional so resolvers can verify RRSIGs.
        additional.extend_from_slice(lookup(idx, apex, Rtype::Dnskey));
    }
    (Rcode::NoError, ans, vec![], additional)
}

// ── CNAME chain follower ──────────────────────────────────────────────────────

/// Follow a CNAME chain from `start` up to [`MAX_CNAME_HOPS`] hops.
///
/// Returns `None` if there is no CNAME at `start`.
/// Returns `Some((answers, additional))` with the full chain if a CNAME exists.
fn follow_cname(
    idx: &ZoneIndex,
    apex: &Name,
    start: &Name,
    target_rtype: Option<Rtype>,
    dnssec_ok: bool,
) -> Option<(Vec<Record>, Vec<Record>)> {
    let cnames = lookup(idx, start, Rtype::Cname);
    if cnames.is_empty() {
        return None;
    }

    let mut ans: Vec<Record> = vec![];
    let mut current = start.clone();
    let mut seen: Vec<String> = vec![current.to_string().to_ascii_lowercase()];

    for _ in 0..MAX_CNAME_HOPS {
        let chain = lookup(idx, &current, Rtype::Cname);
        if chain.is_empty() {
            break;
        }
        ans.extend_from_slice(chain);
        if dnssec_ok {
            ans.extend_from_slice(lookup(idx, &current, Rtype::Rrsig));
        }

        let next = match chain.first().map(|r| &r.rdata) {
            Some(RData::Cname(n)) => n.clone(),
            _ => break,
        };

        let next_lower = next.to_string().to_ascii_lowercase();
        // Loop detection.
        if seen.contains(&next_lower) {
            break;
        }
        seen.push(next_lower);
        current = next;
    }

    // After following the chain, attempt to resolve the final target rtype.
    if let Some(rtype) = target_rtype {
        let final_recs = lookup(idx, &current, rtype);
        ans.extend_from_slice(final_recs);
        if dnssec_ok {
            ans.extend_from_slice(lookup(idx, &current, Rtype::Rrsig));
        }
    }

    let additional = collect_glue(idx, apex, &ans);
    Some((ans, additional))
}

// ── Wildcard matching (RFC 4592) ──────────────────────────────────────────────

/// Returns the single-level wildcard owner string for `name` under `apex`, or
/// `None` if `name` is at the apex or the parent is outside the zone.
///
/// For `foo.example.com.` with apex `example.com.` returns `"*.example.com."`.
fn wildcard_owner_str(name: &Name, apex: &Name) -> Option<String> {
    let name_s = name.to_string().to_ascii_lowercase();
    let apex_s = apex.to_string().to_ascii_lowercase();

    if name_s == apex_s {
        return None;
    }

    let dot_pos = name_s.find('.')?;
    let parent = &name_s[dot_pos + 1..]; // e.g. "example.com."

    if parent != apex_s && !parent.ends_with(&format!(".{apex_s}")) {
        return None;
    }

    Some(format!("*.{parent}"))
}

/// Serve a response from the wildcard owner `wc_str` for query `q`.
/// Returns NODATA if the wildcard has no records of the requested type.
fn serve_wildcard(
    idx: &ZoneIndex,
    apex: &Name,
    q: &Question,
    wc_str: &str,
    dnssec_ok: bool,
) -> (Rcode, Vec<Record>, Vec<Record>, Vec<Record>) {
    let target_rtype = qtype_to_rtype(q.qtype);

    let ans: Vec<Record> = if let Some(rtype) = target_rtype {
        let key = (wc_str.to_string(), rtype.as_u16());
        idx.get(&key).map_or_else(Vec::new, |recs| {
            recs.iter()
                .map(|r| Record {
                    name: q.qname.clone(),
                    ..r.clone()
                })
                .collect()
        })
    } else {
        vec![]
    };

    if ans.is_empty() {
        if dnssec_ok {
            // Check RRSIG too before concluding NODATA.
        }
        let auth = soa_record(idx, apex).into_iter().collect();
        return (Rcode::NoError, vec![], auth, vec![]);
    }

    (Rcode::NoError, ans, vec![], vec![])
}

// ── DNAME synthesis (RFC 6672) ────────────────────────────────────────────────

/// Walk the ancestors of `name` (exclusive, stopping at apex exclusive) looking
/// for a DNAME record.  Returns `(dname_record, dname_target)` if found.
fn find_dname_ancestor(idx: &ZoneIndex, apex: &Name, name: &Name) -> Option<(Record, Name)> {
    let name_s = name.to_string().to_ascii_lowercase();
    let apex_s = apex.to_string().to_ascii_lowercase();

    let mut current = name_s.as_str();
    loop {
        let dot_pos = current.find('.')?;
        current = &current[dot_pos + 1..];

        // Stop at or above apex.
        if current == apex_s || current.is_empty() {
            break;
        }
        if !current.ends_with(&format!(".{apex_s}")) {
            break;
        }

        let key = (current.to_string(), Rtype::Dname.as_u16());
        if let Some(recs) = idx.get(&key)
            && let Some(rec) = recs.first()
            && let RData::Dname(target) = &rec.rdata
        {
            return Some((rec.clone(), target.clone()));
        }
    }
    None
}

/// Build the DNAME synthesis response: DNAME record + synthesized CNAME.
fn synthesize_dname_response(
    idx: &ZoneIndex,
    apex: &Name,
    q: &Question,
    dname_rec: &Record,
    dname_target: &Name,
) -> (Rcode, Vec<Record>, Vec<Record>, Vec<Record>) {
    use std::str::FromStr;

    let qname_s = q.qname.to_string();
    let dname_owner_s = dname_rec.name.to_string();

    // Compute the prefix: strip ".<dname_owner>" suffix from qname.
    let dot_owner = format!(".{dname_owner_s}");
    let prefix = qname_s
        .strip_suffix(&dot_owner)
        .unwrap_or_else(|| qname_s.strip_suffix(&dname_owner_s).unwrap_or(""));

    let target_str = if prefix.is_empty() {
        dname_target.to_string()
    } else {
        format!("{prefix}.{dname_target}")
    };

    let Ok(cname_target) = Name::from_str(&target_str) else {
        // Name too long or invalid after synthesis → SERVFAIL semantics; use SOA NXDOMAIN path.
        let auth = soa_record(idx, apex).into_iter().collect();
        return (Rcode::NxDomain, vec![], auth, vec![]);
    };

    let synth_cname = Record {
        name: q.qname.clone(),
        rtype: Rtype::Cname,
        rclass: dname_rec.rclass,
        ttl: dname_rec.ttl,
        rdata: RData::Cname(cname_target),
    };

    (
        Rcode::NoError,
        vec![dname_rec.clone(), synth_cname],
        vec![],
        vec![],
    )
}

// ── Glue collection ───────────────────────────────────────────────────────────

/// For NS records pointing to in-zone names, include A/AAAA glue in additional.
fn collect_glue(idx: &ZoneIndex, apex: &Name, records: &[Record]) -> Vec<Record> {
    let mut glue: Vec<Record> = vec![];
    for rec in records {
        let ns_target = match &rec.rdata {
            RData::Ns(n) => n.clone(),
            _ => continue,
        };
        if !is_in_zone(&ns_target, apex) {
            continue;
        }
        glue.extend_from_slice(lookup(idx, &ns_target, Rtype::A));
        glue.extend_from_slice(lookup(idx, &ns_target, Rtype::Aaaa));
    }
    glue
}

// ── Collect all RRsets for ANY ────────────────────────────────────────────────

fn collect_all_types(idx: &ZoneIndex, owner: &Name, dnssec_ok: bool) -> Vec<Record> {
    let owner_lower = owner.to_string().to_ascii_lowercase();
    let dnssec_types = [
        Rtype::Rrsig.as_u16(),
        Rtype::Nsec.as_u16(),
        Rtype::Dnskey.as_u16(),
    ];
    idx.iter()
        .filter(|((o, t), _)| *o == owner_lower && (dnssec_ok || !dnssec_types.contains(t)))
        .flat_map(|(_, recs)| recs.iter().cloned())
        .collect()
}

// ── Response building ─────────────────────────────────────────────────────────

fn build_final_response(
    query: &Message,
    rcode: Rcode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    udp_limit: usize,
) -> Message {
    let aa = rcode != Rcode::Refused;
    let mut resp = make_response(query, rcode, aa, answers, authority, additional);

    // Truncation: if response would exceed UDP limit, set TC=1 and truncate to header+question.
    // (Full truncation logic; TCP callers pass a large udp_limit to skip this.)
    let wire_estimate = estimate_wire_size(&resp);
    if wire_estimate > udp_limit {
        resp.header.set_tc(true);
        resp.answers.clear();
        resp.authority.clear();
        resp.additional.clear();
        resp.header.ancount = 0;
        resp.header.nscount = 0;
        resp.header.arcount = 0;
    }

    resp
}

fn make_response(
    query: &Message,
    rcode: Rcode,
    aa: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
) -> Message {
    #[allow(clippy::cast_possible_truncation)]
    let (ancount, nscount, arcount) = (
        answers.len() as u16,
        authority.len() as u16,
        additional.len() as u16,
    );
    let mut header = Header {
        id: query.header.id,
        qdcount: query.header.qdcount,
        ancount,
        nscount,
        arcount,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_opcode(Opcode::Query);
    header.set_aa(aa);
    header.set_rd(query.header.rd());
    header.set_rcode(rcode);

    Message {
        header,
        questions: query.questions.clone(),
        answers,
        authority,
        additional,
    }
}

/// Rough wire-size estimate (header + 4 bytes per record on average).
/// Good enough for the truncation guard; actual serialisation is precise.
fn estimate_wire_size(msg: &Message) -> usize {
    12 + // header
    msg.questions.iter().map(|q| q.qname.as_wire_bytes().len() + 4).sum::<usize>() +
    (msg.answers.len() + msg.authority.len() + msg.additional.len()) * 50
}

/// Map a [`Qtype`] to the corresponding [`Rtype`].  Returns `None` for
/// meta-types (ANY, AXFR, IXFR) that do not have a direct RDATA rtype.
fn qtype_to_rtype(qt: Qtype) -> Option<Rtype> {
    match qt {
        Qtype::A => Some(Rtype::A),
        Qtype::Ns => Some(Rtype::Ns),
        Qtype::Cname => Some(Rtype::Cname),
        Qtype::Soa => Some(Rtype::Soa),
        Qtype::Mx => Some(Rtype::Mx),
        Qtype::Txt => Some(Rtype::Txt),
        Qtype::Aaaa => Some(Rtype::Aaaa),
        Qtype::Srv => Some(Rtype::Srv),
        Qtype::Ptr => Some(Rtype::Ptr),
        Qtype::Dname => Some(Rtype::Dname),
        Qtype::Ds => Some(Rtype::Ds),
        Qtype::Rrsig => Some(Rtype::Rrsig),
        Qtype::Nsec => Some(Rtype::Nsec),
        Qtype::Dnskey => Some(Rtype::Dnskey),
        _ => None,
    }
}

// ── NSEC zone-wide helpers ────────────────────────────────────────────────────

/// Collects all records of `rtype` from all owners in the zone index.
fn collect_zone_records(idx: &ZoneIndex, rtype: Rtype) -> Vec<Record> {
    idx.iter()
        .filter(|((_, rt), _)| *rt == rtype.as_u16())
        .flat_map(|(_, records)| records.iter().cloned())
        .collect()
}

/// Collects RRSIG records that cover `type_covered` from all owners in the zone index.
fn collect_rrsig_for_type(idx: &ZoneIndex, type_covered: Rtype) -> Vec<Record> {
    idx.iter()
        .filter(|((_, rt), _)| *rt == Rtype::Rrsig.as_u16())
        .flat_map(|(_, records)| records.iter())
        .filter(
            |r| matches!(&r.rdata, RData::Rrsig { type_covered: tc, .. } if *tc == type_covered),
        )
        .cloned()
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use heimdall_core::{
        header::{Qclass, Qtype, Question, Rcode},
        name::Name,
        zone::{ZoneFile, ZoneLimits},
    };

    use super::*;

    const ZONE_TEXT: &str = "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
www IN A 192.0.2.2\n\
alias IN CNAME www\n\
";

    fn parse_zone() -> ZoneFile {
        ZoneFile::parse(ZONE_TEXT, None, ZoneLimits::default())
            .expect("INVARIANT: test zone must parse")
    }

    fn apex() -> Name {
        Name::from_str("example.com.").expect("INVARIANT: valid apex")
    }

    fn make_query(qname: &str, qtype: Qtype) -> Message {
        let header = Header {
            id: 1,
            qdcount: 1,
            ..Header::default()
        };
        Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(qname).expect("INVARIANT: valid test name"),
                qtype,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn nxdomain_includes_soa_in_authority() {
        let zone = parse_zone();
        let msg = make_query("noexist.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NxDomain);
        assert!(resp.answers.is_empty());
        assert!(
            !resp.authority.is_empty(),
            "SOA must be in authority on NXDOMAIN"
        );
        assert_eq!(resp.authority[0].rtype, Rtype::Soa);
        assert!(resp.header.aa(), "AA must be set");
    }

    #[test]
    fn nodata_includes_soa_in_authority() {
        let zone = parse_zone();
        // www exists but has no AAAA record.
        let msg = make_query("www.example.com.", Qtype::Aaaa);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(resp.answers.is_empty());
        assert!(
            !resp.authority.is_empty(),
            "SOA must be in authority on NODATA"
        );
        assert_eq!(resp.authority[0].rtype, Rtype::Soa);
    }

    #[test]
    fn aa_flag_set_on_authoritative_response() {
        let zone = parse_zone();
        let msg = make_query("www.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert!(
            resp.header.aa(),
            "AA must be set for authoritative responses"
        );
        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(!resp.answers.is_empty());
    }

    #[test]
    fn any_query_returns_multiple_types() {
        let zone = parse_zone();
        // The apex has SOA and NS.
        let msg = make_query("example.com.", Qtype::Any);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        // Should have at least SOA + NS.
        assert!(resp.answers.len() >= 2, "ANY should return multiple RRsets");
        let rtypes: Vec<Rtype> = resp.answers.iter().map(|r| r.rtype).collect();
        assert!(rtypes.contains(&Rtype::Soa));
        assert!(rtypes.contains(&Rtype::Ns));
    }

    #[test]
    fn cname_chain_followed() {
        let zone = parse_zone();
        // "alias" CNAMEs to "www", which has an A record.
        let msg = make_query("alias.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        // Answers should contain the CNAME and the final A record.
        let rtypes: Vec<Rtype> = resp.answers.iter().map(|r| r.rtype).collect();
        assert!(
            rtypes.contains(&Rtype::Cname),
            "CNAME record must be in answers"
        );
        assert!(
            rtypes.contains(&Rtype::A),
            "final A record must be in answers"
        );
    }

    #[test]
    fn refused_for_out_of_zone_query() {
        let zone = parse_zone();
        let msg = make_query("other.example.net.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::Refused);
    }

    #[test]
    fn glue_included_for_ns_record() {
        let zone = parse_zone();
        // Querying for NS at apex should produce NS in answers and A glue in additional.
        let msg = make_query("example.com.", Qtype::Ns);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(!resp.answers.is_empty(), "NS records expected in answers");
        // ns1.example.com. has an A record → should appear as glue.
        let additional_has_a = resp.additional.iter().any(|r| r.rtype == Rtype::A);
        assert!(additional_has_a, "glue A record must be in additional");
    }

    #[test]
    fn a_record_for_ns1() {
        let zone = parse_zone();
        let msg = make_query("ns1.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("serve_query must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(!resp.answers.is_empty());
        if let RData::A(addr) = &resp.answers[0].rdata {
            assert_eq!(*addr, Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("expected A record");
        }
    }

    #[test]
    fn no_question_returns_error() {
        let zone = parse_zone();
        let header = Header {
            id: 99,
            ..Header::default()
        };
        let msg = Message {
            header,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let err = serve_query(&zone, &apex(), &msg, false, 0);
        assert!(err.is_err());
    }

    // ── Wildcard tests ────────────────────────────────────────────────────────

    const ZONE_WITH_WILDCARD: &str = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
noaaaa IN A 192.0.2.100\n\
* IN A 192.0.2.254\n\
";

    fn parse_wildcard_zone() -> ZoneFile {
        ZoneFile::parse(ZONE_WITH_WILDCARD, None, ZoneLimits::default())
            .expect("INVARIANT: test zone must parse")
    }

    #[test]
    fn wildcard_matches_undefined_name() {
        let zone = parse_wildcard_zone();
        let msg = make_query("undefined.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(!resp.answers.is_empty(), "wildcard A must be in answers");
        assert!(resp.answers.iter().all(|r| r.rtype == Rtype::A));
    }

    #[test]
    fn wildcard_nodata_when_type_missing() {
        let zone = parse_wildcard_zone();
        let msg = make_query("undefined.example.com.", Qtype::Aaaa);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(
            resp.answers.is_empty(),
            "no AAAA answers (wildcard has only A)"
        );
        assert!(
            !resp.authority.is_empty(),
            "SOA in authority on NODATA wildcard"
        );
    }

    #[test]
    fn wildcard_not_used_when_name_exists() {
        let zone = parse_wildcard_zone();
        // noaaaa.example.com. exists (has A) but has no AAAA — wildcard must NOT apply.
        let msg = make_query("noaaaa.example.com.", Qtype::Aaaa);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(
            resp.answers.is_empty(),
            "AAAA must be empty — NODATA, not wildcard"
        );
        assert!(!resp.authority.is_empty(), "SOA in authority on NODATA");
    }

    // ── DNAME tests ───────────────────────────────────────────────────────────

    const ZONE_WITH_DNAME: &str = "\
$ORIGIN example.com.\n\
$TTL 300\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
sub IN DNAME other.example.\n\
";

    fn parse_dname_zone() -> ZoneFile {
        ZoneFile::parse(ZONE_WITH_DNAME, None, ZoneLimits::default())
            .expect("INVARIANT: test zone must parse")
    }

    #[test]
    fn dname_synthesis_produces_cname() {
        let zone = parse_dname_zone();
        let msg = make_query("foo.sub.example.com.", Qtype::A);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(
            resp.answers.len() >= 2,
            "answer must have DNAME + synthesized CNAME"
        );
        let rtypes: Vec<Rtype> = resp.answers.iter().map(|r| r.rtype).collect();
        assert!(rtypes.contains(&Rtype::Dname), "DNAME must be in answers");
        assert!(
            rtypes.contains(&Rtype::Cname),
            "synthesized CNAME must be in answers"
        );
    }

    #[test]
    fn dname_owner_query_returns_dname_record() {
        let zone = parse_dname_zone();
        let msg = make_query("sub.example.com.", Qtype::Dname);
        let resp = serve_query(&zone, &apex(), &msg, false, 0).expect("must not fail");

        assert_eq!(resp.header.rcode(), Rcode::NoError);
        assert!(
            !resp.answers.is_empty(),
            "DNAME record must be returned for owner query"
        );
        assert_eq!(resp.answers[0].rtype, Rtype::Dname);
    }
}
