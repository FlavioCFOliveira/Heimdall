---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# ADoT capability discovery for authoritative servers

## Context and Problem Statement

[`NET-020`](../../specification/002-transports.md) in [`002-transports.md`](../../specification/002-transports.md) requires that Authoritative DNS-over-TLS (ADoT, [RFC 9539](https://www.rfc-editor.org/rfc/rfc9539)) be attempted against a specific authoritative name server only when Heimdall holds **positive, configured, or discovered evidence** that the server supports ADoT. The mechanism that produces such evidence was left as a tracked open question, alongside a closely related item — the downgrade-protection strategy for the capability signal itself, since a discovery channel that is itself spoofable on-path would be useless.

The present decision settles two questions jointly:

1. **The discovery mechanism set** — SVCB-DNS records, operator-static configuration, passive probing, or some combination, with their triggering rules and cache lifecycle.
2. **The downgrade-protection strategy for the capability signal** — how the integrity and authenticity of the discovery channel are preserved against an on-path attacker who could otherwise inject or suppress capability evidence to coerce a transport choice.

The decisions had to compose with [`NET-019`](../../specification/002-transports.md) (DNS classic baseline always available), [`NET-022`](../../specification/002-transports.md) (TLS 1.3 only on outbound), [`NET-023`](../../specification/002-transports.md) (no client 0-RTT), [`NET-024`](../../specification/002-transports.md) (mandatory upstream certificate validation, now fixed by [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md)), the DNSSEC validation policy of [`005-dnssec-policy.md`](../../specification/005-dnssec-policy.md), and the per-role configuration surface of [`ROLE-016`](../../specification/001-server-roles.md) through [`ROLE-023`](../../specification/001-server-roles.md).

## Decision Drivers

- **NET-020 conformance**. ADoT MUST NOT be forced; positive evidence MUST precede every ADoT attempt. The mechanism must produce evidence whose integrity is verifiable.
- **Downgrade resistance**. An on-path attacker MUST NOT be able to influence Heimdall's transport choice by suppressing or forging capability evidence. The discovery channel must therefore carry cryptographic authentication.
- **IETF alignment**. The standardisation track for resolver-to-authoritative encrypted-DNS capability advertisement is [draft-ietf-dnsop-svcb-dns](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-dns/) on top of [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460); committing to this path positions Heimdall to benefit from growing publication adoption without a future migration cost.
- **Operational coverage**. The dominant case in 2026 is an authoritative that has not yet published SVCB records but whose ADoT support is known to the operator (for example, large hosted-DNS providers that have rolled out ADoT before the SVCB-DNS draft is widely adopted). The mechanism set must accommodate this case.
- **No behavioural fingerprint, no DoS pattern**. Speculative ADoT connection attempts against every authoritative ("passive probing") expose a behavioural fingerprint that adversarial network observers can use, expand cold-connection latency for every contact, and create a low-rate DoS pattern against authoritatives that do not support encrypted DNS. The mechanism must avoid these failure modes.
- **No new cache concept**. The cache lifecycle of capability evidence should reuse the existing DNS-cache infrastructure of [`004-cache-policy.md`](../../specification/004-cache-policy.md) and the standard DNS-record TTL discipline, rather than introducing a parallel capability cache with its own eviction rules.

## Considered Options

### A. Discovery mechanism set

- **SVCB-DNS records (`_dns.<NS>.`) + operator-static override; mandatory DNSSEC validation; no passive probing (chosen).** IETF-aligned, downgrade-protected by mandatory DNSSEC, with an operator-static escape hatch for authoritatives whose SVCB records are not yet published.
- **Operator-static-only.** Predictable but does not scale to the public Internet; ADoT adoption stagnates because no automatic discovery exists; misses the IETF-aligned dynamic discovery path.
- **Passive probing.** Speculative ADoT connection on every cold contact; falls back to plain DNS on failure. Vulnerable to downgrade by an on-path attacker that blocks port 853, exposes a behavioural fingerprint, inflates cold-connection latency, fails the "positive evidence" requirement of [`NET-020`](../../specification/002-transports.md).
- **All-of-the-above (SVCB + static + probing).** Inherits the failure modes of probing without compensating gain; complicates the implementation and the test matrix.

### B. Downgrade-protection strategy

- **Mandatory DNSSEC validation of SVCB records (chosen).** SVCB records that are not validated to the `secure` outcome are discarded for the purposes of [`NET-020`](../../specification/002-transports.md). On-path forgery becomes infeasible without the corresponding DNSSEC signing key.
- **TOFU (trust-on-first-use) on SVCB records.** First observation establishes the capability; subsequent observations are checked for consistency. Accepts an attacker-controlled first observation as authoritative; not robust under adversarial-network conditions.
- **Out-of-band channel (HTTPS over a separate trust path).** Adds a parallel discovery channel with its own trust story; complicates the architecture; unclear adoption.

### C. Triggering and caching

- **On-demand triggering during the resolution path; cache TTL inherited from the SVCB record (positive) or from the negative-caching rules of [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308) (negative); per-NS scoping (chosen).** Reuses existing DNS-cache infrastructure; no new cache concept; no eager pre-fetch traffic.
- **Eager pre-fetch on configuration load.** Generates discovery traffic for authoritatives the resolver may never contact; wastes bandwidth and cache; makes startup time depend on the publication state of every authoritative the configuration could potentially exercise.
- **Per-zone scoping.** Repeats discovery for every zone served by the same NS; multiplies discovery traffic without a corresponding gain in correctness; misaligns with the unit at which encrypted-DNS endpoints are configured at authoritative deployments (an NS, not a zone).

## Decision Outcome

**A. Mechanism.** SVCB-DNS records at `_dns.<NS>.`, per [`NET-029`](../../specification/002-transports.md), with operator-static override per [`NET-031`](../../specification/002-transports.md). No passive probing per [`NET-032`](../../specification/002-transports.md).

**B. Downgrade protection.** Mandatory DNSSEC validation of SVCB records to the `secure` outcome before they are treated as evidence, per [`NET-030`](../../specification/002-transports.md). Operator-static evidence under [`NET-031`](../../specification/002-transports.md) substitutes for the DNSSEC-authenticated channel because the configuration boundary is itself an authenticated, operator-controlled input under [`ROLE-016`](../../specification/001-server-roles.md) and [`ROLE-021`](../../specification/001-server-roles.md).

**C. Triggering and caching.** On-demand triggering during the resolution path per [`NET-034`](../../specification/002-transports.md); TTL-driven cache lifecycle per [`NET-033`](../../specification/002-transports.md); per-NS scoping per [`NET-035`](../../specification/002-transports.md).

### Rejection rationale — discovery mechanism

The **operator-static-only** option was rejected on scale and adoption grounds. ADoT adoption depends on a discovery channel that does not require manual operator intervention for every authoritative; without dynamic discovery, the deployment surface of ADoT remains the small set of authoritatives an operator has the time to enumerate, and the IETF-aligned standardisation track remains under-exercised at the deployment layer. Operator-static is preserved as an escape hatch under [`NET-031`](../../specification/002-transports.md), but not as the sole mechanism.

The **passive probing** option was rejected on three reinforcing grounds. First, [`NET-020`](../../specification/002-transports.md) explicitly requires "positive evidence" before an ADoT attempt; speculative connection attempts are tentative, not evidence. Second, an on-path attacker can downgrade ADoT by blocking port 853 connections; the resolver falls back to plain DNS over UDP and TCP per the prevailing fallback policy, and the attacker has effectively demoted the encrypted transport without modifying any cryptographic material. Third, every cold contact pays the latency of a port-853 handshake attempt before falling back, even against authoritatives that do not and never have supported ADoT, which is operationally wasteful and produces a behavioural fingerprint that adversarial network observers can use.

The **all-of-the-above** combination was rejected because it inherits the failure modes of passive probing while adding the SVCB-DNS and operator-static channels' implementation complexity. The combination's only advantage over the chosen design is incremental coverage of authoritatives that publish neither SVCB nor are operator-known; the trade-off is unfavourable.

### Rejection rationale — downgrade protection

The **TOFU (trust-on-first-use)** option was rejected because the first observation of an SVCB record is the most exposed window for an on-path attacker. An attacker who controls the first response from `_dns.<NS>.` (for example, by being on-path during the resolver's first contact attempt, or by being the network providing the resolver's bootstrap connectivity) can poison the cache with attacker-chosen capability evidence; subsequent consistency checks confirm the attacker's choice as legitimate. TOFU is an acceptable trust model in some ecosystems (e.g., SSH host keys for low-stakes interactive use) but not for an authentication primitive whose failure compromises every encrypted-DNS contact.

The **out-of-band HTTPS channel** option was rejected because it introduces a parallel trust story (HTTPS to whom? With what trust anchors? Against what name?) and a parallel discovery channel without a corresponding standardisation path. The IETF-aligned discovery channel is in-band (DNS), and the integrity of the in-band channel is provided by DNSSEC; an out-of-band channel would parallel that without simplifying it.

### Rejection rationale — triggering and caching

The **eager pre-fetch on configuration load** option was rejected because it generates discovery traffic for every authoritative the configuration could potentially exercise — including authoritatives the resolver may never contact during its operational lifetime. The waste of bandwidth and cache space is non-trivial at scale; the dependency of startup time on the publication state of every potentially-relevant authoritative is also operationally undesirable.

The **per-zone scoping** option was rejected because it duplicates discovery for every zone served by the same authoritative name server. Encrypted-DNS endpoint configuration at the authoritative side is associated with the name server (an NS canonical name), not the zone; a per-zone discovery would issue redundant SVCB queries without corresponding gain in correctness.

## Consequences

### Operator-visible configuration shape

```toml
[recursive]
enabled = true

# Operator-static override: declares specific authoritative NSes as ADoT-capable
# regardless of SVCB publication state.

[[recursive.adot_static]]
ns_name = "ns1.example."
port = 853

[[recursive.adot_static]]
ns_name = "ns1.cloudflare.com."
port = 853
server_name = "ns1.cloudflare.com."
spki_pins = ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]

[[recursive.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53
```

The optional `server_name`, `spki_pins`, and `trust_anchor` sub-keys on `[[recursive.adot_static]]` are admitted under [`ROLE-023`](../../specification/001-server-roles.md) and apply the validation policy of [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) on the corresponding outbound ADoT connection.

### Discovery and resolution path

For an authoritative name server `<NS>` that the recursive resolver needs to contact:

1. Check operator-static override: is there an `[[recursive.adot_static]]` entry with `ns_name == <NS>`? If yes, ADoT is supported (treat as evidence under [`NET-031`](../../specification/002-transports.md)); proceed with ADoT contact under [`NET-024`](../../specification/002-transports.md). Skip step 2.
2. Check SVCB cache for `_dns.<NS>.`: is a current entry available? If positive (SVCB record present and `alpn` includes `"dot"`), ADoT is supported (under [`NET-029`](../../specification/002-transports.md) + [`NET-030`](../../specification/002-transports.md)). If negative (no SVCB record at `_dns.<NS>.`), no evidence (under [`NET-032`](../../specification/002-transports.md)).
3. If no current cache entry, perform on-demand discovery: query `_dns.<NS>. SVCB`, validate to DNSSEC `secure` outcome, cache under TTL semantics per [`NET-033`](../../specification/002-transports.md). If `secure` and `alpn` includes `"dot"` → ADoT supported. If `secure` but no `dot` ALPN → no ADoT evidence. If `bogus` / `insecure` / `indeterminate` → no evidence (per [`NET-030`](../../specification/002-transports.md)); also discard the record.
4. If no evidence by either channel → contact `<NS>` via plain DNS over UDP / TCP per [`NET-019`](../../specification/002-transports.md). No ADoT attempt is made under [`NET-032`](../../specification/002-transports.md).

This flow runs once per `<NS>` per cache lifetime; subsequent contacts to the same `<NS>` reuse the cached evidence under [`NET-035`](../../specification/002-transports.md).

### Closure of two open questions

The present decision closes both:

- **"ADoT capability discovery for authoritative servers (recursive resolver)"** in [`002-transports.md §5`](../../specification/002-transports.md), by fixing SVCB-DNS as the discovery mechanism and the operator-static override as the supplement.
- **"Downgrade-protection strategy for ADoT capability signalling (recursive resolver)"** in [`002-transports.md §5`](../../specification/002-transports.md), by binding the discovery channel to mandatory DNSSEC validation under [`NET-030`](../../specification/002-transports.md).

Both bullets are removed from [`002-transports.md §5`](../../specification/002-transports.md). The companion open question "ADoT fallback policy on handshake failure (recursive resolver)" remains open (sprint 1 task #11).

### Non-consequences (deliberate scope limits)

- **HTTPS resource record handling.** The chosen mechanism uses SVCB records; the HTTPS resource record (a SVCB-typed record family for HTTPS-related discovery, [RFC 9460 §9](https://www.rfc-editor.org/rfc/rfc9460#section-9)) is out of scope for ADoT discovery. ADoH discovery is itself out of scope at this stage per [`NET-021`](../../specification/002-transports.md).
- **Authoritative-side SVCB publication.** Whether and how authoritative operators publish their `_dns.<NS>.` SVCB records is the authoritative side of the equation and is governed by `draft-ietf-dnsop-svcb-dns`; Heimdall as a resolver is the consumer of those records, not the publisher.
- **DoQ capability discovery.** [`NET-021`](../../specification/002-transports.md) defers DoQ for authoritative contact; DoQ-capable evidence advertised via SVCB (via the `alpn` SvcParam value `"doq"`) MUST be ignored at this stage, even when DNSSEC-validated, until DoQ-for-authoritative is reconsidered in a future revision of [`002-transports.md`](../../specification/002-transports.md).
- **ADoT session-ticket cache.** The ADoT outbound connection's session-ticket cache, scoping, TTL, and invalidation triggers are tracked separately as an open question in [`002-transports.md §5`](../../specification/002-transports.md) and are not affected by the present decision.
- **Outbound connection pool for ADoT.** The per-authoritative connection-pool policy for ADoT is tracked separately in [`002-transports.md §5`](../../specification/002-transports.md) and is not affected by the present decision.

### Numbering

This ADR takes the sequence number `0008`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
