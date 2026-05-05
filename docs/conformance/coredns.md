# CoreDNS conformance comparison methodology

Sprint 49 task #565 — Tier 3 nightly.

## Scope

CoreDNS is compared against Heimdall's **forwarder role** only.  CoreDNS is
configured as a pure forwarder (`. { forward . 1.1.1.1 }`) with logging enabled
and all other plugins disabled.

## Methodology

1. The harness starts a CoreDNS container via Docker with a dynamically
   generated `Corefile` that forwards all queries to `1.1.1.1:53`.
2. Heimdall forwarder (port 5355 by default, `HEIMDALL_FORWARDER_ADDR`) is
   pre-started with the same upstream configuration.
3. For each corpus query the test sends the same wire query to both servers
   and compares `RCODE`.
4. Divergences listed in the allowed-divergence table below do not fail the test.

## Known divergences

| Query | Heimdall | CoreDNS | Reason |
|---|---|---|---|
| _(none documented yet)_ | | | |

## Divergence discovery process

1. Identify a divergence in CI output (Heimdall RCODE ≠ CoreDNS RCODE).
2. Reproduce with `dig` against both servers.
3. Trace to RFC section or implementation decision.
4. Add to the allowed-divergence table above and to `is_allowed_divergence()`
   in `golden_coredns.rs` with a comment citing this document.
