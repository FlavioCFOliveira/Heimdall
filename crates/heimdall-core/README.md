# heimdall-core

Wire-format DNS types, parser, and serialiser for the [Heimdall] DNS server.

This crate implements the complete DNS message model as defined in RFC 1034/1035
and extended by numerous subsequent RFCs.  It is the foundation upon which all
Heimdall protocol handling is built.

## Modules

| Module | Contents |
|---|---|
| `name` | [`Name`] — DNS domain name in wire-label format (RFC 1034/1035, case-insensitive per RFC 4343) |
| `header` | [`Header`], [`Opcode`], [`Rcode`], [`Question`], [`Qtype`], [`Qclass`] |
| `record` | [`Record`], [`RRset`], [`Rtype`] — resource record structure and all type codes |
| `rdata` | [`RData`] — RDATA payloads for all supported record types |
| `parser` | [`Message`], [`ParseError`] — full DNS message parser with RFC 1035 §4.1.4 name decompression |
| `serialiser` | [`Serialiser`], [`SerialiseError`] — DNS message serialiser with optional name compression |

## Usage

```rust
use std::str::FromStr;
use heimdall_core::parser::Message;
use heimdall_core::header::{Header, Qclass, Qtype, Question};
use heimdall_core::name::Name;
use heimdall_core::serialiser::Serialiser;

// Build a minimal DNS query for "example.com. A IN".
let mut header = Header::default();
header.id = 0x1234;
header.set_rd(true);
header.qdcount = 1;

let qname = Name::from_str("example.com.").unwrap();
let question = Question {
    qname,
    qtype: Qtype::A,
    qclass: Qclass::In,
};
let msg = Message {
    header,
    questions: vec![question],
    answers: vec![],
    authority: vec![],
    additional: vec![],
};

// Serialise without compression.
let mut ser = Serialiser::new(false);
ser.write_message(&msg).unwrap();
let wire = ser.finish();

// Parse it back.
let parsed = Message::parse(&wire).unwrap();
assert_eq!(parsed.header.id, 0x1234);
assert_eq!(parsed.questions[0].qname.to_string(), "example.com.");
```

## Design notes

- **No heap allocation for names**: [`Name`] stores wire bytes in a `[u8; 255]` fixed array.
- **No compression on write by default**: use `Serialiser::new(true)` for RFC 1035 §4.1.4 compression, or `Serialiser::write_message_canonical` for DNSSEC signing (RFC 4034 §6.2).
- **Security first**: the parser rejects messages larger than 65535 bytes, detects pointer loops (max 128 follows), validates all length fields with checked arithmetic, and never panics on malformed input.
- **Forward compatibility**: unknown RTYPE/RCLASS/OPCODE/RCODE values are preserved as `Unknown(u16)` rather than rejected.

## Testing

```text
# Unit and integration tests
cargo test -p heimdall-core

# Property-based roundtrip tests (requires proptest dev-dependency)
cargo test -p heimdall-core --test proptest_roundtrip

# Fuzzing (requires nightly + cargo-fuzz)
cargo +nightly fuzz run fuzz_parse_message
```

[Heimdall]: https://github.com/FlavioCFOliveira/Heimdall
