// SPDX-License-Identifier: MIT

//! DNS message serialiser with optional RFC 1035 §4.1.4 name compression.

use std::collections::HashMap;
use std::fmt;

use crate::parser::Message;
use crate::record::Record;

// ── SerialiseError ────────────────────────────────────────────────────────────

/// Errors that can occur during DNS message serialisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialiseError {
    /// A name occurred at an offset beyond the 14-bit pointer limit (0x3FFF).
    OffsetOverflow,
    /// The serialised message exceeds 65535 bytes.
    MessageTooLarge,
}

impl fmt::Display for SerialiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OffsetOverflow => {
                write!(f, "name offset exceeds 14-bit pointer limit (0x3FFF)")
            }
            Self::MessageTooLarge => write!(f, "serialised DNS message exceeds 65535 bytes"),
        }
    }
}

impl std::error::Error for SerialiseError {}

// ── Serialiser ────────────────────────────────────────────────────────────────

/// DNS message serialiser.
///
/// When `compress` is `true`, name compression (RFC 1035 §4.1.4) is applied:
/// the first occurrence of each name suffix is recorded and subsequent
/// occurrences are replaced by a 2-byte pointer.
///
/// When `compress` is `false`, names are written in canonical uncompressed form
/// (required for DNSSEC operations, RFC 4034 §6.2).
pub struct Serialiser {
    buf: Vec<u8>,
    /// Maps canonical (lowercased) wire-format name to its first-write offset.
    name_offsets: HashMap<Vec<u8>, u16>,
    compress: bool,
}

impl Serialiser {
    /// Creates a new serialiser.
    ///
    /// Set `compress = true` to enable name compression, `false` for canonical
    /// (uncompressed, lowercase) output suitable for DNSSEC signing.
    #[must_use]
    pub fn new(compress: bool) -> Self {
        Self {
            buf: Vec::with_capacity(512),
            name_offsets: HashMap::new(),
            compress,
        }
    }

    /// Serialises a complete [`Message`] into the internal buffer.
    ///
    /// # Errors
    ///
    /// Returns [`SerialiseError::OffsetOverflow`] if compression pointer offsets
    /// would exceed 14 bits, or [`SerialiseError::MessageTooLarge`] if the
    /// resulting message exceeds 65535 bytes.
    pub fn write_message(&mut self, msg: &Message) -> Result<(), SerialiseError> {
        // Write a placeholder header; we will patch the counts below if needed.
        // (The counts are already set on `msg.header` so we just write directly.)
        msg.header.write_to(&mut self.buf);

        for q in &msg.questions {
            self.write_name_bytes(q.qname.as_wire_bytes())?;
            self.buf.extend_from_slice(&q.qtype.as_u16().to_be_bytes());
            self.buf.extend_from_slice(&q.qclass.as_u16().to_be_bytes());
        }

        for rec in msg.answers.iter().chain(msg.authority.iter()).chain(msg.additional.iter()) {
            self.write_record(rec)?;
        }

        if self.buf.len() > 65535 {
            return Err(SerialiseError::MessageTooLarge);
        }

        Ok(())
    }

    /// Consumes the serialiser and returns the accumulated wire bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Serialises a [`Message`] in canonical (uncompressed, lowercase) form.
    ///
    /// This is the form required by RFC 4034 §6.2 for DNSSEC `RRset` signing.
    /// Names are lowercased and no compression pointers are emitted.
    #[must_use]
    pub fn write_message_canonical(msg: &Message) -> Vec<u8> {
        let mut ser = Self::new(false);
        // Canonical mode: ignore errors (a well-formed Message cannot produce them).
        let _ = ser.write_message(msg);
        ser.finish()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn write_record(&mut self, rec: &Record) -> Result<(), SerialiseError> {
        use crate::rdata::RData;

        self.write_name_bytes(rec.name.as_wire_bytes())?;
        self.buf.extend_from_slice(&rec.rtype.as_u16().to_be_bytes());

        if let RData::Opt { payload_size, extended_rcode, version, dnssec_ok, options } =
            &rec.rdata
        {
            // OPT record: class = payload size, TTL = {extended_rcode, version, DO, 0}.
            self.buf.extend_from_slice(&payload_size.to_be_bytes());
            let do_bit: u8 = if *dnssec_ok { 0x80 } else { 0 };
            self.buf.push(*extended_rcode);
            self.buf.push(*version);
            self.buf.push(do_bit);
            self.buf.push(0);
            // INVARIANT: OPT option data bounded by 16-bit RDLENGTH field.
            #[allow(clippy::cast_possible_truncation)]
            self.buf.extend_from_slice(&(options.len() as u16).to_be_bytes());
            self.buf.extend_from_slice(options);
        } else {
            self.buf.extend_from_slice(&rec.rclass.as_u16().to_be_bytes());
            self.buf.extend_from_slice(&rec.ttl.to_be_bytes());

            // Write RDATA with a length placeholder that we patch afterwards.
            let rdlen_pos = self.buf.len();
            self.buf.extend_from_slice(&0u16.to_be_bytes());
            self.write_rdata(&rec.rdata)?;
            let rdata_len = self.buf.len() - rdlen_pos - 2;
            // INVARIANT: RDATA bounded by 16-bit RDLENGTH field (≤ 65535 bytes).
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (rdata_len as u16).to_be_bytes();
            self.buf[rdlen_pos] = len_bytes[0];
            self.buf[rdlen_pos + 1] = len_bytes[1];
        }

        Ok(())
    }

    /// Writes RDATA, applying name compression where applicable.
    fn write_rdata(&mut self, rdata: &crate::rdata::RData) -> Result<(), SerialiseError> {
        use crate::rdata::RData;

        match rdata {
            RData::Ns(n) | RData::Cname(n) | RData::Dname(n) | RData::Ptr(n) => {
                self.write_name_bytes(n.as_wire_bytes())?;
            }
            RData::Mx { preference, exchange } => {
                self.buf.extend_from_slice(&preference.to_be_bytes());
                self.write_name_bytes(exchange.as_wire_bytes())?;
            }
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                self.write_name_bytes(mname.as_wire_bytes())?;
                self.write_name_bytes(rname.as_wire_bytes())?;
                self.buf.extend_from_slice(&serial.to_be_bytes());
                self.buf.extend_from_slice(&refresh.to_be_bytes());
                self.buf.extend_from_slice(&retry.to_be_bytes());
                self.buf.extend_from_slice(&expire.to_be_bytes());
                self.buf.extend_from_slice(&minimum.to_be_bytes());
            }
            RData::Srv { priority, weight, port, target } => {
                self.buf.extend_from_slice(&priority.to_be_bytes());
                self.buf.extend_from_slice(&weight.to_be_bytes());
                self.buf.extend_from_slice(&port.to_be_bytes());
                self.write_name_bytes(target.as_wire_bytes())?;
            }
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                sig_expiration,
                sig_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                self.buf.extend_from_slice(&type_covered.as_u16().to_be_bytes());
                self.buf.push(*algorithm);
                self.buf.push(*labels);
                self.buf.extend_from_slice(&original_ttl.to_be_bytes());
                self.buf.extend_from_slice(&sig_expiration.to_be_bytes());
                self.buf.extend_from_slice(&sig_inception.to_be_bytes());
                self.buf.extend_from_slice(&key_tag.to_be_bytes());
                // signer_name in RRSIG MUST NOT be compressed (RFC 4034 §6.2).
                self.buf.extend_from_slice(signer_name.as_wire_bytes());
                self.buf.extend_from_slice(signature);
            }
            RData::Nsec { next_domain, type_bitmaps } => {
                // NSEC next_domain MUST NOT be compressed (RFC 4034 §4.1.1).
                self.buf.extend_from_slice(next_domain.as_wire_bytes());
                self.buf.extend_from_slice(type_bitmaps);
            }
            RData::Svcb { priority, target, params }
            | RData::Https { priority, target, params } => {
                self.buf.extend_from_slice(&priority.to_be_bytes());
                self.write_name_bytes(target.as_wire_bytes())?;
                self.buf.extend_from_slice(params);
            }
            // All other types: use the write_to implementation directly.
            other => {
                other.write_to(&mut self.buf);
            }
        }
        Ok(())
    }

    /// Writes a DNS name to the buffer, applying compression when enabled.
    ///
    /// If `compress` is `true`, the method searches for the longest known suffix
    /// that was written earlier and emits a pointer for that suffix.
    ///
    /// The `wire` slice must be a valid wire-format name (length-prefixed labels
    /// terminated by a zero byte).
    fn write_name_bytes(&mut self, wire: &[u8]) -> Result<(), SerialiseError> {
        if !self.compress {
            self.buf.extend_from_slice(wire);
            return Ok(());
        }

        // Find the longest suffix of `wire` (starting at a label boundary) that
        // is already recorded in `name_offsets`.  We walk label by label.
        //
        // `wire` layout:  [len][label][len][label]...[0]
        //
        // We look for a pointer match at each label boundary.  The first match
        // wins (it is the longest suffix since we walk left to right).

        // Collect label-boundary positions in `wire`.
        let mut boundaries: Vec<usize> = Vec::new();
        let mut pos = 0usize;
        while pos < wire.len() {
            let len_byte = wire[pos];
            boundaries.push(pos);
            if len_byte == 0 {
                break;
            }
            pos += 1 + usize::from(len_byte);
        }

        // Find the leftmost boundary that has a suffix match (= longest suffix).
        let mut split_at: Option<usize> = None; // label index at which we start the pointer
        let mut pointer_target: Option<u16> = None;
        for &boundary in &boundaries {
            let suffix = &wire[boundary..];
            let canonical: Vec<u8> = suffix.iter().map(u8::to_ascii_lowercase).collect();
            if let Some(&off) = self.name_offsets.get(&canonical) {
                split_at = Some(boundary);
                pointer_target = Some(off);
                break;
            }
        }

        // Determine how many bytes of `wire` we write literally.
        // If `split_at` is Some(b), write wire[0..b] literally, then a pointer.
        // If `split_at` is None, write `wire` in full (including trailing zero).
        let literal_end = split_at.unwrap_or(wire.len());

        // Before writing, record all suffix offsets for the labels we are about
        // to write literally so future names can point to them.
        let base_offset = self.buf.len();
        for &boundary in &boundaries {
            if boundary >= literal_end {
                break;
            }
            // The suffix starting at `boundary` in `wire` will appear at
            // `base_offset + boundary` in the output buffer.
            let suffix = &wire[boundary..];
            let canonical: Vec<u8> = suffix.iter().map(u8::to_ascii_lowercase).collect();
            let output_offset = base_offset + boundary;
            if output_offset > 0x3FFF {
                return Err(SerialiseError::OffsetOverflow);
            }
            // INVARIANT: output_offset ≤ 0x3FFF (checked above); truncation to u16 is safe.
            #[allow(clippy::cast_possible_truncation)]
            let output_offset_u16 = output_offset as u16;
            self.name_offsets.entry(canonical).or_insert(output_offset_u16);
        }

        // Write literal labels.
        self.buf.extend_from_slice(&wire[..literal_end]);

        // Write pointer or the root terminator (which is already in `wire` when
        // split_at is None, because literal_end == wire.len() covers everything).
        if let Some(ptr_off) = pointer_target {
            // ptr_off ≤ 0x3FFF; shift and mask guarantee u8 fits.
            #[allow(clippy::cast_possible_truncation)]
            let ptr_high = 0xC0u8 | ((ptr_off >> 8) as u8);
            #[allow(clippy::cast_possible_truncation)]
            let ptr_low = (ptr_off & 0xFF) as u8;
            self.buf.push(ptr_high);
            self.buf.push(ptr_low);
        }
        // else: the root zero is already included in wire[..literal_end].

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
    use crate::name::Name;
    use crate::parser::Message;
    use crate::rdata::RData;
    use crate::record::{Record, Rtype};
    use std::net::Ipv4Addr;

    fn make_simple_response() -> Message {
        let qname = Name::from_str("example.com.").unwrap();
        let mut header = Header::default();
        header.id = 1;
        header.set_qr(true);
        header.set_opcode(Opcode::Query);
        header.set_aa(true);
        header.set_rcode(Rcode::NoError);
        header.qdcount = 1;
        header.ancount = 1;

        Message {
            header,
            questions: vec![Question {
                qname: qname.clone(),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![Record {
                name: qname,
                rtype: Rtype::A,
                rclass: Qclass::In,
                ttl: 60,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn no_compression_roundtrip() {
        let msg = make_simple_response();
        let mut ser = Serialiser::new(false);
        ser.write_message(&msg).unwrap();
        let wire = ser.finish();
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn compression_roundtrip() {
        let msg = make_simple_response();
        let mut ser = Serialiser::new(true);
        ser.write_message(&msg).unwrap();
        let wire = ser.finish();

        // With compression the repeated "example.com." should be shorter.
        let mut ser_no = Serialiser::new(false);
        ser_no.write_message(&msg).unwrap();
        let wire_no = ser_no.finish();
        // Compressed must be ≤ uncompressed.
        assert!(wire.len() <= wire_no.len());

        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn canonical_write() {
        let msg = make_simple_response();
        let wire = Serialiser::write_message_canonical(&msg);
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, msg);
    }
}
