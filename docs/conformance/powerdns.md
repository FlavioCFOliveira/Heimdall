# PowerDNS conformance comparison methodology

Sprint 49 task #564 — Tier 3 nightly.

## Scope

Two comparison modules are exercised:

| Harness | PowerDNS component | Heimdall role |
|---|---|---|
| `golden_auth_corpus_matches_powerdns_auth` | `pdns-auth-49` (authoritative) | Authoritative |
| `golden_recursive_corpus_matches_powerdns_recursor` | `pdns-recursor-50` (recursive) | Recursive |

Both comparisons use the `conformance::start_powerdns_*` builders defined in
`crates/heimdall-integration-tests/src/conformance.rs`.

## Methodology

1. The harness starts the PowerDNS container via Docker (image pinned in
   `tests/conformance/digests.lock`).
2. For each query in the corpus, the test sends the identical wire-format DNS
   query to both Heimdall and PowerDNS.
3. The comparison checks `RCODE`, `AA` flag, and `ANCOUNT`.  Additional-section
   ordering is explicitly excluded (RFC 1034 §3.6 does not mandate order).
4. Any divergence that is not in the allowed-divergence list fails the test.

## Known divergences

None at this time.  Document here when operational differences between PowerDNS
and Heimdall are discovered and accepted.
