// SPDX-License-Identifier: MIT

//! DNS message parser with RFC 1035 §4.1.4 name decompression.
//!
//! The parser handles the full DNS wire format including name compression
//! pointers, all four message sections, and all RDATA types implemented in
//! [`crate::rdata`].

use crate::header::{Header, ParseError, Question};
use crate::name::{Name, NameError};
use crate::record::Record;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of pointer-follows before declaring a loop (RFC 1035 §4.1.4).
const MAX_POINTER_FOLLOWS: usize = 128;

/// Maximum accepted message size in bytes.  DNS over UDP is limited to 65535
/// bytes; TCP framing is handled separately but uses the same wire format.
const MAX_MESSAGE_SIZE: usize = 65535;

// ── Message ───────────────────────────────────────────────────────────────────

/// A fully parsed DNS message (RFC 1035 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The 12-byte DNS header.
    pub header: Header,
    /// Question section entries.
    pub questions: Vec<Question>,
    /// Answer section resource records.
    pub answers: Vec<Record>,
    /// Authority section resource records.
    pub authority: Vec<Record>,
    /// Additional section resource records.
    pub additional: Vec<Record>,
}

impl Message {
    /// Parses a complete DNS message from `buf`.
    ///
    /// Enforces a maximum buffer size of 65535 bytes.  Name compression
    /// pointers are followed transparently.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on any malformed input, truncation, or pointer loop.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() > MAX_MESSAGE_SIZE {
            return Err(ParseError::InvalidHeader);
        }

        let header = Header::parse(buf)?;
        let mut offset = Header::WIRE_LEN;

        let mut questions = Vec::with_capacity(usize::from(header.qdcount));
        for _ in 0..header.qdcount {
            let q = Question::parse(buf, &mut offset)?;
            questions.push(q);
        }

        let mut answers = Vec::with_capacity(usize::from(header.ancount));
        for _ in 0..header.ancount {
            let r = Record::parse(buf, &mut offset)?;
            answers.push(r);
        }

        let mut authority = Vec::with_capacity(usize::from(header.nscount));
        for _ in 0..header.nscount {
            let r = Record::parse(buf, &mut offset)?;
            authority.push(r);
        }

        let mut additional = Vec::with_capacity(usize::from(header.arcount));
        for _ in 0..header.arcount {
            let r = Record::parse(buf, &mut offset)?;
            additional.push(r);
        }

        Ok(Self { header, questions, answers, authority, additional })
    }
}

// ── Name decompression ────────────────────────────────────────────────────────

/// Parses a (possibly compressed) DNS name from `buf` starting at `*offset`.
///
/// Follows RFC 1035 §4.1.4 compression pointers.  The pointer-follow count is
/// bounded by 128 follows to prevent infinite loops.
///
/// On success `*offset` is advanced past the name bytes in the *original*
/// position (i.e. past the first pointer if a pointer was encountered, or past
/// the trailing zero label otherwise).
///
/// # Errors
///
/// Returns [`ParseError::PointerLoop`] if more than 128 pointers are followed,
/// [`ParseError::InvalidPointer`] if a pointer target is out of range, or
/// [`ParseError::InvalidName`] / [`ParseError::UnexpectedEof`] on malformed data.
pub fn parse_name(buf: &[u8], offset: &mut usize) -> Result<Name, ParseError> {
    // Start with the root name.  `append_label` maintains the trailing zero,
    // overwriting the current root terminator and placing a new one after each
    // appended label — so starting from root() is correct.
    let mut name = Name::root();
    // Track whether we have appended any label yet so we can distinguish the
    // root name (zero labels) from an in-progress build.
    let mut has_labels = false;

    // `read_pos` is where we currently read from; may jump due to pointers.
    let mut read_pos = *offset;
    // `jumped` tracks whether we have already followed a pointer and therefore
    // must not update `*offset` further after the first pointer.
    let mut jumped = false;
    let mut follows = 0usize;

    loop {
        let len_byte = buf.get(read_pos).copied().ok_or(ParseError::UnexpectedEof)?;
        read_pos += 1;

        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer: two-byte field, upper 2 bits are 11.
            let lo = buf.get(read_pos).copied().ok_or(ParseError::UnexpectedEof)?;
            read_pos += 1;

            if !jumped {
                // Advance the caller's offset past the pointer (2 bytes).
                *offset = read_pos;
                jumped = true;
            }

            let ptr = (usize::from(len_byte & 0x3F) << 8) | usize::from(lo);
            if ptr >= buf.len() {
                return Err(ParseError::InvalidPointer);
            }
            follows += 1;
            if follows > MAX_POINTER_FOLLOWS {
                return Err(ParseError::PointerLoop);
            }
            read_pos = ptr;
        } else if len_byte == 0 {
            // Root terminator — name is complete.
            if !jumped {
                *offset = read_pos;
            }
            break;
        } else {
            // Regular label.
            let label_len = usize::from(len_byte);
            if label_len > crate::name::MAX_LABEL_LEN {
                return Err(ParseError::InvalidName(NameError::LabelTooLong));
            }
            let end = read_pos
                .checked_add(label_len)
                .ok_or(ParseError::UnexpectedEof)?;
            if end > buf.len() {
                return Err(ParseError::UnexpectedEof);
            }
            name.append_label(&buf[read_pos..end])
                .map_err(ParseError::InvalidName)?;
            has_labels = true;
            read_pos = end;
        }
    }

    // If no labels were appended, name is the root — which is correct since we
    // started with Name::root().
    let _ = has_labels;
    Ok(name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::header::{Opcode, Qclass, Qtype, Rcode};
    use crate::name::Name;
    use crate::rdata::RData;
    use crate::record::{Record, Rtype};
    use std::net::Ipv4Addr;

    fn minimal_query(id: u16, qname: &Name) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut header = Header::default();
        header.id = id;
        header.set_rd(true);
        header.qdcount = 1;
        header.write_to(&mut buf);
        buf.extend_from_slice(qname.as_wire_bytes());
        buf.extend_from_slice(&Qtype::A.as_u16().to_be_bytes());
        buf.extend_from_slice(&Qclass::In.as_u16().to_be_bytes());
        buf
    }

    #[test]
    fn parse_minimal_query() {
        let qname = Name::from_str("example.com.").unwrap();
        let buf = minimal_query(0xABCD, &qname);
        let msg = Message::parse(&buf).unwrap();
        assert_eq!(msg.header.id, 0xABCD);
        assert!(!msg.header.qr());
        assert!(msg.header.rd());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].qname, qname);
        assert_eq!(msg.questions[0].qtype, Qtype::A);
        assert_eq!(msg.questions[0].qclass, Qclass::In);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn parse_name_no_compression() {
        let wire: &[u8] = &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let mut off = 0;
        let name = parse_name(wire, &mut off).unwrap();
        assert_eq!(off, 13);
        assert_eq!(name, Name::from_str("example.com.").unwrap());
    }

    #[test]
    fn parse_name_with_compression() {
        // "example.com." at offset 0, then a 2-byte pointer back to offset 0.
        let mut buf: Vec<u8> =
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        buf.push(0xC0);
        buf.push(0x00);

        let mut off = 13;
        let name = parse_name(&buf, &mut off).unwrap();
        // offset advances past the 2-byte pointer to 15.
        assert_eq!(off, 15);
        assert_eq!(name, Name::from_str("example.com.").unwrap());
    }

    #[test]
    fn parse_name_pointer_loop() {
        // Two pointers pointing at each other.
        let buf: &[u8] = &[0xC0, 0x02, 0xC0, 0x00];
        let mut off = 0;
        assert!(matches!(parse_name(buf, &mut off), Err(ParseError::PointerLoop)));
    }

    #[test]
    fn parse_name_invalid_pointer() {
        // Pointer to offset 200 in a 4-byte buffer.
        let buf: &[u8] = &[0xC0, 0xC8];
        let mut off = 0;
        assert!(matches!(parse_name(buf, &mut off), Err(ParseError::InvalidPointer)));
    }

    #[test]
    fn reject_oversized_message() {
        let oversized = vec![0u8; 65536];
        assert!(matches!(Message::parse(&oversized), Err(ParseError::InvalidHeader)));
    }

    #[test]
    fn full_response_roundtrip() {
        use crate::serialiser::Serialiser;

        let qname = Name::from_str("example.com.").unwrap();
        let mut header = Header::default();
        header.id = 42;
        header.set_qr(true);
        header.set_opcode(Opcode::Query);
        header.set_aa(true);
        header.set_rcode(Rcode::NoError);
        header.qdcount = 1;
        header.ancount = 1;

        let question = Question {
            qname: qname.clone(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        };
        let answer = Record {
            name: qname.clone(),
            rtype: Rtype::A,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        };
        let msg = Message {
            header,
            questions: vec![question],
            answers: vec![answer],
            authority: vec![],
            additional: vec![],
        };

        let mut ser = Serialiser::new(false);
        ser.write_message(&msg).unwrap();
        let wire = ser.finish();

        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, msg);
    }
}
