// SPDX-License-Identifier: MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Treat `data` as an EDNS option TLV stream and attempt to parse it.
    // Any outcome other than a panic is acceptable — the parser must never
    // trigger undefined behaviour or panic on arbitrary input.
    let _ = heimdall_core::edns::OptRr::parse_rdata(data, 512, 0, 0, false, 0);
});
