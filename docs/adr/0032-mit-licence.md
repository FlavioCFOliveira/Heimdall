---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0032: MIT License for Heimdall

## Context and Problem Statement

Heimdall must be released under an open-source licence. The choice determines how the project interacts with its dependency graph, how contributors can use the code, and what obligations operators distributing Heimdall must fulfil. `ENG-090` through `ENG-097` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md) fix MIT as the licence; this ADR documents the rationale.

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- Must be compatible with the entire dependency whitelist (`ENG-094`): MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-DFS-2016, MPL-2.0.
- Must not impose distribution obligations on operators beyond attribution.
- Must not require relicensing when Heimdall libraries are embedded in commercial products.
- Must keep the Contributor Licence Agreement surface minimal: MIT with DCO (Developer Certificate of Origin) is a proven pattern.

## Considered Options

- **MIT** — permissive; minimal obligations; compatible with all dependency licences in the whitelist; no reciprocity requirement.
- **Apache-2.0** — permissive with patent-grant clause; also compatible with all whitelist licences; slightly more complex than MIT for contributors.
- **MIT AND Apache-2.0 dual-licence** — common Rust ecosystem pattern; allows downstream to choose their preferred permissive licence; added complexity with no material benefit given the target audience.
- **GPL-3.0** — copyleft; would propagate to any derivative work; incompatible with the commercial embedding use case; blocked by `ENG-095`.
- **LGPL-2.1** — weaker copyleft; ambiguous interaction with static linking in musl/Rust builds; blocked by `ENG-095`.
- **MPL-2.0** — file-level copyleft; compatible as a dependency licence but brings file-level reciprocity obligations if Heimdall itself were MPL-2.0; adds complexity for contributors.
- **AGPL-3.0** — copyleft with network-use clause; would impose source disclosure on any SaaS operator running Heimdall; blocked by `ENG-095` and contrary to project goals.

## Decision Outcome

Chosen option: **MIT**, because:

- It is the simplest permissive licence and the most widely understood in the Rust ecosystem.
- It is fully compatible with every licence in the dependency whitelist without any edge cases.
- It places no distribution obligations on operators beyond preserving the copyright notice.
- It allows Heimdall libraries to be embedded in commercial products without licence compatibility analysis, which is desirable for wide adoption.
- Rust's own standard library is MIT / Apache-2.0, and tokio, rustls, quinn, and hyper are all MIT or MIT/Apache-2.0; a single MIT licence avoids dual-licence complexity.

## Consequences

**Positive:**

- Zero friction for operators distributing Heimdall as a binary.
- No reciprocity obligation; commercial adoption unrestricted.
- Contributors do not need to sign a CLA; DCO (`Signed-off-by:` per `ENG-223`) is sufficient.

**Negative:**

- No patent-grant clause (Apache-2.0 provides this). Mitigation: not a material concern for a DNS server; patent risk is low in this domain, and the dependency graph (tokio, rustls, quinn) is already Apache-2.0 / MIT, providing upstream patent grants.

## Cross-References

- `ENG-090..097` — MIT licensing normative requirements.
- `ENG-094` — Dependency licence whitelist.
- `ENG-095` — Dependency licence blocklist.
- `ENG-223` — DCO contribution sign-off.
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
