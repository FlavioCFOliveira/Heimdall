// SPDX-License-Identifier: MIT

//! RPZ action definitions and application logic (RPZ-004..010, RPZ-021..023, RPZ-026).
//!
//! Each [`RpzAction`] variant encodes one of the seven RPZ response policies
//! defined in the draft-ietf-dnsop-dns-rpz-* series.  The [`RpzAction::apply`]
//! method translates a matched action into a concrete DNS [`Message`].

use heimdall_core::edns::{EdnsOption, ExtendedError, OptRr, ede_code};
use heimdall_core::header::{Header, Opcode, Qclass, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};

// ── RpzAction ─────────────────────────────────────────────────────────────────

/// The seven RPZ response policy actions (RPZ-004..010).
///
/// `Name` is 255 bytes inline, which makes `CnameRedirect` large.  Boxing it
/// here avoids penalising the common small variants at all call sites.
#[allow(clippy::large_enum_variant)] // CnameRedirect boxes Name internally; the allow keeps call-sites clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpzAction {
    /// Return NXDOMAIN (RPZ-004). EDE info-code 15 "Blocked".
    Nxdomain,
    /// Return NODATA with SOA in the Authority section (RPZ-005). EDE info-code 15 "Blocked".
    Nodata,
    /// Allow through without modification; short-circuits further zone evaluation (RPZ-006).
    ///
    /// No EDE option is appended. The AD flag is preserved unchanged (RPZ-022).
    Passthru,
    /// Silently discard the query — the caller MUST NOT send any response (RPZ-007).
    Drop,
    /// Force TCP retry on UDP transport; pass-through on TCP (RPZ-008).
    ///
    /// On UDP: return TC=1, empty Answer. On TCP: return the original response unchanged.
    TcpOnly,
    /// Replace the Answer section with operator-supplied local records (RPZ-009).
    ///
    /// EDE info-code 17 "Filtered". AD flag cleared.
    LocalData {
        /// The operator-specified records to substitute into the Answer section.
        records: Vec<Record>,
    },
    /// Redirect via a CNAME to `target`; if `target` is root (`.`), equivalent to
    /// [`RpzAction::Nxdomain`] (RPZ-010). EDE info-code 16 "Censored". AD flag cleared.
    CnameRedirect {
        /// The CNAME target. A root name (`.`) triggers NXDOMAIN treatment.
        target: Box<Name>,
    },
}

impl RpzAction {
    /// Returns the EDE info-code for this action (RPZ-026), or `None` for actions
    /// that do not append an EDE option (`Passthru`, `Drop`, `TcpOnly`).
    #[must_use]
    pub fn ede_code(&self) -> Option<u16> {
        match self {
            Self::Nxdomain | Self::Nodata => Some(ede_code::BLOCKED),
            Self::LocalData { .. } => Some(ede_code::FILTERED),
            Self::CnameRedirect { .. } => Some(ede_code::CENSORED),
            Self::Passthru | Self::Drop | Self::TcpOnly => None,
        }
    }

    /// Applies this action to produce a response message.
    ///
    /// # Parameters
    ///
    /// - `query`: the original client query (used to mirror `id`, `flags` RD/CD, and
    ///   `questions` into synthetic responses).
    /// - `original_response`: the resolver's would-be response before RPZ interception.
    ///   Some actions (`Passthru`, `TcpOnly`-on-TCP) return this unchanged.
    /// - `is_udp`: `true` when the query arrived over UDP; relevant only for `TcpOnly`.
    /// - `policy_ttl`: TTL to use for synthetic records (RPZ-033 default: 30 seconds).
    /// - `zone_name`: the matched policy zone FQDN, used to derive a synthetic SOA owner.
    ///
    /// # Returns
    ///
    /// `None` for [`RpzAction::Drop`]; the caller MUST NOT transmit any response.
    /// `Some(msg)` for all other actions.
    #[must_use]
    pub fn apply(
        &self,
        query: &Message,
        original_response: Option<&Message>,
        is_udp: bool,
        policy_ttl: u32,
        zone_name: &str,
    ) -> Option<Message> {
        match self {
            Self::Nxdomain => Some(build_nxdomain(query, policy_ttl, zone_name)),
            Self::Nodata => Some(build_nodata(query, policy_ttl, zone_name)),
            Self::Passthru => original_response.cloned().or_else(|| {
                // No upstream response available yet — treat as passthru of an empty success.
                Some(build_passthru_empty(query))
            }),
            Self::Drop => None,
            Self::TcpOnly => {
                if is_udp {
                    Some(build_tc_response(query))
                } else {
                    original_response.cloned().or_else(|| Some(build_passthru_empty(query)))
                }
            }
            Self::LocalData { records } => {
                Some(build_local_data(query, records.clone(), policy_ttl, zone_name))
            }
            Self::CnameRedirect { target } => {
                if target.is_root() {
                    Some(build_nxdomain(query, policy_ttl, zone_name))
                } else {
                    Some(build_cname_redirect(query, target, policy_ttl, zone_name))
                }
            }
        }
    }
}

// ── Helper: build a base response header mirroring the query ─────────────────

/// Creates a response `Header` that mirrors the query's `id`, `RD`, and `CD` bits.
///
/// Sets QR=1, AA=0, AD=0, RA=1, and the supplied `rcode`.
fn base_response_header(query: &Message, rcode: Rcode) -> Header {
    // Build flags step-by-step; individual set_* calls cannot be batched into
    // struct-init form because Header::default() gives a defined zero state and
    // the flag setters manipulate specific bits of the flags word.
    let mut h = Header {
        id: query.header.id,
        qdcount: query.header.qdcount,
        ..Header::default()
    };
    h.set_qr(true);
    h.set_opcode(Opcode::Query);
    h.set_aa(false);
    h.set_tc(false);
    h.set_rd(query.header.rd());
    h.set_ra(true);
    // Z bit: mirror from query (RPZ does not touch reserved bits).
    h.set_z(query.header.z());
    h.set_ad(false); // RPZ-021: AD cleared on all non-Passthru actions.
    h.set_cd(query.header.cd());
    h.set_rcode(rcode);
    h
}

// ── Helper: build a synthetic SOA record for the policy zone ─────────────────

/// Builds a minimal synthetic SOA record for `zone_name` to populate the
/// Authority section of NXDOMAIN and NODATA responses.
///
/// The SOA owner is the zone name; mname and rname are local stand-ins.
/// All timing values are set to `policy_ttl` as a reasonable conservative default.
fn synthetic_soa(zone_name: &str, policy_ttl: u32) -> Record {
    let owner = Name::parse_str(zone_name).unwrap_or_else(|_| Name::root());
    let mname =
        Name::parse_str(&format!("ns.{zone_name}")).unwrap_or_else(|_| Name::root());
    let rname =
        Name::parse_str(&format!("hostmaster.{zone_name}")).unwrap_or_else(|_| Name::root());
    Record {
        name: owner,
        rtype: Rtype::Soa,
        rclass: Qclass::In,
        ttl: policy_ttl,
        rdata: RData::Soa {
            mname,
            rname,
            serial: 1,
            refresh: policy_ttl,
            retry: policy_ttl / 2,
            expire: policy_ttl * 10,
            minimum: policy_ttl,
        },
    }
}

// ── Helper: append an OPT record carrying an EDE option to `additional` ──────

/// Builds and appends an OPT pseudo-RR with the given EDE info-code to
/// the `additional` section.  The OPT record is synthetic (no client OPT
/// negotiation from the original query is honoured here; RPZ responses are
/// always built fresh).
fn append_ede(additional: &mut Vec<Record>, ede_info_code: u16) {
    let ede = EdnsOption::ExtendedError(ExtendedError::new(ede_info_code));
    let opt = OptRr {
        udp_payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: vec![ede],
    };
    let opt_record = Record {
        name: Name::root(), // OPT owner is always root.
        rtype: Rtype::Opt,
        rclass: Qclass::from(opt.udp_payload_size),
        ttl: 0,
        rdata: RData::Opt(opt),
    };
    additional.push(opt_record);
}

// ── Count helpers (bounded: we add at most one OPT record) ───────────────────

/// Converts `len` to `u16`, clamping at `u16::MAX` (DNS section count field).
///
/// In practice the count of RPZ-synthesised records is tiny (≤ 2) so
/// truncation is impossible; the clamp is a safety bound.
fn len_as_u16(len: usize) -> u16 {
    // INVARIANT: RPZ-synthesised sections contain at most a few records; the
    // clamp is a defensive bound only and will never fire in practice.
    #[allow(clippy::cast_possible_truncation)]
    { len.min(usize::from(u16::MAX)) as u16 }
}

// ── Action builders ───────────────────────────────────────────────────────────

/// NXDOMAIN response (RPZ-004): `RCODE=NXDOMAIN`, empty Answer, SOA in Authority,
/// EDE code 15 "Blocked", `AD=0`.
fn build_nxdomain(query: &Message, policy_ttl: u32, zone_name: &str) -> Message {
    let mut header = base_response_header(query, Rcode::NxDomain);
    let authority = vec![synthetic_soa(zone_name, policy_ttl)];
    header.nscount = len_as_u16(authority.len());
    let mut additional = Vec::new();
    append_ede(&mut additional, ede_code::BLOCKED);
    header.arcount = len_as_u16(additional.len());
    Message { header, questions: query.questions.clone(), answers: vec![], authority, additional }
}

/// NODATA response (RPZ-005): `RCODE=NoError`, empty Answer, SOA in Authority,
/// EDE code 15 "Blocked", `AD=0`.
fn build_nodata(query: &Message, policy_ttl: u32, zone_name: &str) -> Message {
    let mut header = base_response_header(query, Rcode::NoError);
    let authority = vec![synthetic_soa(zone_name, policy_ttl)];
    header.nscount = len_as_u16(authority.len());
    let mut additional = Vec::new();
    append_ede(&mut additional, ede_code::BLOCKED);
    header.arcount = len_as_u16(additional.len());
    Message { header, questions: query.questions.clone(), answers: vec![], authority, additional }
}

/// Passthru with no upstream response: return a minimal `NoError` with empty sections.
fn build_passthru_empty(query: &Message) -> Message {
    // Preserve AD from query in the absence of an upstream response — passthru
    // does not modify AD (RPZ-022).
    let mut header = base_response_header(query, Rcode::NoError);
    header.set_ad(query.header.ad()); // Passthru preserves AD (RPZ-022).
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// TC=1 truncation response for `TcpOnly` on UDP (RPZ-008).
fn build_tc_response(query: &Message) -> Message {
    let mut header = base_response_header(query, Rcode::NoError);
    header.set_tc(true);
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// `LocalData` response (RPZ-009): Answer replaced by `records`, `AD=0`, EDE 17.
fn build_local_data(
    query: &Message,
    records: Vec<Record>,
    _policy_ttl: u32,
    _zone_name: &str,
) -> Message {
    let mut header = base_response_header(query, Rcode::NoError);
    header.ancount = len_as_u16(records.len());
    let mut additional = Vec::new();
    append_ede(&mut additional, ede_code::FILTERED);
    header.arcount = len_as_u16(additional.len());
    Message {
        header,
        questions: query.questions.clone(),
        answers: records,
        authority: vec![],
        additional,
    }
}

/// `CnameRedirect` response (RPZ-010): Answer = single CNAME record, `AD=0`, EDE 16.
fn build_cname_redirect(
    query: &Message,
    target: &Name,
    policy_ttl: u32,
    _zone_name: &str,
) -> Message {
    let qname = query.questions.first().map_or_else(Name::root, |q| q.qname.clone());

    let cname_rr = Record {
        name: qname,
        rtype: Rtype::Cname,
        rclass: Qclass::In,
        ttl: policy_ttl,
        rdata: RData::Cname(target.clone()),
    };
    let mut header = base_response_header(query, Rcode::NoError);
    header.ancount = 1;
    let mut additional = Vec::new();
    append_ede(&mut additional, ede_code::CENSORED);
    header.arcount = len_as_u16(additional.len());
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![cname_rr],
        authority: vec![],
        additional,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    use heimdall_core::header::Question;

    fn make_query(qname: &str) -> Message {
        let name = Name::from_str(qname).unwrap();
        let mut header = Header::default();
        header.id = 42;
        header.set_rd(true);
        header.qdcount = 1;
        Message {
            header,
            questions: vec![Question {
                qname: name,
                qtype: heimdall_core::header::Qtype::A,
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
            questions: vec![Question {
                qname: name.clone(),
                qtype: heimdall_core::header::Qtype::A,
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

    fn has_ede(msg: &Message, code: u16) -> bool {
        msg.additional.iter().any(|r| {
            if let RData::Opt(opt) = &r.rdata {
                opt.options
                    .iter()
                    .any(|o| matches!(o, EdnsOption::ExtendedError(e) if e.info_code == code))
            } else {
                false
            }
        })
    }

    #[test]
    fn nxdomain_clears_ad_and_sets_ede15() {
        let q = make_query("blocked.example.com.");
        let msg =
            RpzAction::Nxdomain.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
        assert_eq!(msg.header.rcode(), Rcode::NxDomain);
        assert!(!msg.header.ad());
        assert!(has_ede(&msg, ede_code::BLOCKED));
    }

    #[test]
    fn nodata_clears_ad_and_sets_ede15() {
        let q = make_query("blocked.example.com.");
        let msg =
            RpzAction::Nodata.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
        assert_eq!(msg.header.rcode(), Rcode::NoError);
        assert!(msg.answers.is_empty());
        assert!(!msg.header.ad());
        assert!(has_ede(&msg, ede_code::BLOCKED));
    }

    #[test]
    fn passthru_preserves_response_and_ad() {
        let q = make_query("good.example.com.");
        let upstream = make_a_response("good.example.com.", true);
        let result = RpzAction::Passthru
            .apply(&q, Some(&upstream), false, 30, "rpz.example.com.")
            .unwrap();
        assert_eq!(result, upstream);
        assert!(result.header.ad());
    }

    #[test]
    fn drop_returns_none() {
        let q = make_query("drop.example.com.");
        let result = RpzAction::Drop.apply(&q, None, false, 30, "rpz.example.com.");
        assert!(result.is_none());
    }

    #[test]
    fn tcp_only_on_udp_sets_tc() {
        let q = make_query("tcp.example.com.");
        let msg =
            RpzAction::TcpOnly.apply(&q, None, true, 30, "rpz.example.com.").unwrap();
        assert!(msg.header.tc());
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn tcp_only_on_tcp_is_passthru() {
        let q = make_query("tcp.example.com.");
        let upstream = make_a_response("tcp.example.com.", false);
        let result = RpzAction::TcpOnly
            .apply(&q, Some(&upstream), false, 30, "rpz.example.com.")
            .unwrap();
        assert_eq!(result, upstream);
    }

    #[test]
    fn local_data_replaces_answer_and_sets_ede17() {
        let q = make_query("local.example.com.");
        let record = Record {
            name: Name::from_str("local.example.com.").unwrap(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 30,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let action = RpzAction::LocalData { records: vec![record.clone()] };
        let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
        assert!(!msg.header.ad());
        assert_eq!(msg.answers, vec![record]);
        assert!(has_ede(&msg, ede_code::FILTERED));
    }

    #[test]
    fn cname_redirect_to_root_is_nxdomain() {
        let q = make_query("evil.example.com.");
        let action = RpzAction::CnameRedirect { target: Box::new(Name::root()) };
        let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
        assert_eq!(msg.header.rcode(), Rcode::NxDomain);
    }

    #[test]
    fn cname_redirect_sets_cname_and_ede16() {
        let q = make_query("evil.example.com.");
        let target = Name::from_str("safe.example.com.").unwrap();
        let action = RpzAction::CnameRedirect { target: Box::new(target) };
        let msg = action.apply(&q, None, false, 30, "rpz.example.com.").unwrap();
        assert!(!msg.header.ad());
        assert!(msg.answers.iter().any(|r| r.rtype == Rtype::Cname));
        assert!(has_ede(&msg, ede_code::CENSORED));
    }
}
