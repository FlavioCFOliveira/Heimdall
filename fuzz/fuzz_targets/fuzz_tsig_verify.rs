// SPDX-License-Identifier: MIT

//! Fuzzing target for TSIG MAC verification (RFC 8945).
//!
//! Exercises two attack surfaces:
//!   1. [`TsigRecord::parse_rdata`] — wire-level RDATA decoder that must reject
//!      every malformed input without panic, overflow, or out-of-bounds read.
//!   2. [`TsigSigner::verify`] — the cryptographic verifier that must return a
//!      typed error (never panic) on any (message, TSIG, now) combination,
//!      including BadSig / BadKey / BadTime / UnsupportedAlgorithm.
//!
//! The MAC comparison itself is constant-time via `ring::hmac::verify`; the
//! fuzz target's job is to confirm that no other code path violates the
//! "no panic on adversarial input" invariant.
//!
//! Run with cargo-fuzz (requires nightly):
//! ```text
//! cargo +nightly fuzz run fuzz_tsig_verify
//! ```

#![no_main]

use heimdall_core::{
    name::Name,
    tsig::{TsigAlgorithm, TsigRecord, TsigSigner},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least: 2 bytes for now, 2 bytes for split offset, 1 byte for
    // algorithm selector, the rest split into msg_wire / rdata.
    if data.len() < 8 {
        return;
    }

    // Phase 1: RDATA decoder fuzz. Split arbitrarily, pass the second half
    // to the parser with a fixed root key name. The parser must not panic.
    let now = u64::from(u16::from_be_bytes([data[0], data[1]]));
    let split = usize::from(u16::from_be_bytes([data[2], data[3]])) % data.len();
    let (msg_part, rdata_part) = data.split_at(split);

    let key_name = Name::root();
    let parsed = TsigRecord::parse_rdata(key_name.clone(), rdata_part);

    // Phase 2: when the parser accepted the RDATA, run the verifier against
    // it. The verifier walks every algorithm/key/time/MAC code path and must
    // return a typed error on every adversarial input.
    if let Ok(tsig) = parsed {
        let algorithm = match data[4] % 3 {
            0 => TsigAlgorithm::HmacSha256,
            1 => TsigAlgorithm::HmacSha384,
            _ => TsigAlgorithm::HmacSha512,
        };
        // A fixed key — the secret material is irrelevant; the fuzzer is
        // testing the verifier's robustness against malformed inputs, not
        // its cryptographic strength.
        let key_bytes = b"fuzz-key-fixed-secret-for-tests";
        let signer = TsigSigner::new(key_name, algorithm, key_bytes, 300);

        let _ = signer.verify(msg_part, &tsig, now);
    }
});
