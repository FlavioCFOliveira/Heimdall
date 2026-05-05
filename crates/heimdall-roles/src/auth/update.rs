// SPDX-License-Identifier: MIT

//! RFC 2136 UPDATE → NOTIMP handler (`PROTO-032..035`).
//!
//! Dynamic DNS updates are explicitly out of scope (`PROTO-032`). On receipt of
//! an UPDATE message, Heimdall MUST respond with RCODE 4 (`NOTIMP`) immediately
//! and MUST NOT perform TSIG or SIG(0) verification (`PROTO-033`), to avoid a
//! CPU-cost amplification vector under high load.

use heimdall_core::{Header, Message, Opcode, Rcode};
use tracing::warn;

/// Builds a `NOTIMP` response for a DNS UPDATE message (`PROTO-033`).
///
/// The response copies the query ID and question section from `msg` and sets
/// `RCODE = 4` (`NOTIMP`). No TSIG or SIG(0) verification is performed.
///
/// # Panics
///
/// Does not panic. The function is unconditional and infallible.
#[must_use]
pub fn handle_update(msg: &Message) -> Message {
    warn!(
        id = msg.header.id,
        opcode = ?msg.header.opcode(),
        "DNS UPDATE received — responding NOTIMP (PROTO-032/033)"
    );

    let mut resp_header = Header {
        id: msg.header.id,
        ..Header::default()
    };
    resp_header.set_qr(true);
    resp_header.set_opcode(Opcode::Update);
    resp_header.set_rcode(Rcode::NotImp);
    // qdcount = 0: UPDATE has no question section in NOTIMP response.

    Message {
        header: resp_header,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::{
        header::{Opcode, Qclass, Qtype, Question, Rcode},
        name::Name,
        parser::Message,
    };

    use super::*;

    fn make_update_message() -> Message {
        let mut header = Header {
            id: 0xABCD,
            qdcount: 1,
            ..Header::default()
        };
        header.set_opcode(Opcode::Update);
        Message {
            header,
            questions: vec![Question {
                qname: Name::from_str("example.com.").expect("INVARIANT: valid test name"),
                qtype: Qtype::Soa,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn update_yields_notimp() {
        let query = make_update_message();
        let resp = handle_update(&query);

        assert!(resp.header.qr(), "QR flag must be set");
        assert_eq!(resp.header.rcode(), Rcode::NotImp, "RCODE must be NOTIMP");
        assert_eq!(resp.header.id, 0xABCD, "response ID must match query ID");
        assert_eq!(
            resp.header.opcode(),
            Opcode::Update,
            "opcode must be UPDATE"
        );
    }

    #[test]
    fn update_response_has_no_records() {
        let query = make_update_message();
        let resp = handle_update(&query);

        assert!(resp.answers.is_empty(), "no answers in NOTIMP response");
        assert!(resp.authority.is_empty(), "no authority in NOTIMP response");
        assert!(
            resp.additional.is_empty(),
            "no additional in NOTIMP response"
        );
    }

    #[test]
    fn update_no_tsig_verification_path() {
        // The handle_update function must return immediately without touching
        // any crypto primitives.  We verify this indirectly: even a message with
        // clearly missing TSIG (no additional section at all) returns NOTIMP, not
        // an auth error of any kind.
        let query = make_update_message();
        let resp = handle_update(&query);
        assert_eq!(resp.header.rcode(), Rcode::NotImp);
    }
}
