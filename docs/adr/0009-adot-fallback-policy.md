---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# ADoT fallback policy on handshake failure

## Context and Problem Statement

The ADoT capability-discovery mechanism fixed by [`NET-029`](../../specification/002-transports.md) through [`NET-035`](../../specification/002-transports.md) (recorded in [`0008-adot-capability-discovery.md`](0008-adot-capability-discovery.md)) determines when Heimdall has positive evidence that an authoritative name server supports ADoT, and the outbound certificate validation policy fixed by [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) (recorded in [`0007-outbound-server-certificate-validation-policy.md`](0007-outbound-server-certificate-validation-policy.md)) determines when an outbound TLS handshake is permitted to complete. The remaining open question was: what does Heimdall do when an ADoT attempt — chosen because the resolver held positive evidence of capability — fails at the transport or TLS layer? Three failure-mode categories had to be addressed jointly:

1. **Same-`<NS>` retry policy** — whether to immediately retry plain DNS against the same authoritative whose ADoT contact just failed.
2. **NS-set iteration policy** — whether to attempt the next authoritative name server of the zone before considering transport degradation.
3. **Last-resort plain contact** — whether to fall through to plain DNS over UDP/TCP per [`NET-019`](../../specification/002-transports.md) when every authoritative's ADoT contact has failed, and what operator control should govern that fall-through.

The decisions had to compose with [`NET-019`](../../specification/002-transports.md) (DNS classic baseline), [`NET-020`](../../specification/002-transports.md) (ADoT positive-evidence requirement), the discovery mechanism fixed by [`NET-029`](../../specification/002-transports.md) through [`NET-035`](../../specification/002-transports.md), the outbound validation policy fixed by [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md), the EDE catalogue maintained by [`PROTO-012`](../../specification/006-protocol-conformance.md), and the structured-event obligations of [`THREAT-080`](../../specification/007-threat-model.md).

## Decision Drivers

- **Preserve the ADoT intent** as long as practicable. An operator (or upstream adoption of SVCB-DNS) that has produced positive evidence of ADoT support has implicitly chosen encrypted-DNS contact for the authoritative; transport degradation should not erase that intent on the first transient failure.
- **Bound the downgrade window**. A persistent ADoT-broken state on an authoritative (as opposed to a transient handshake glitch) should not block the zone indefinitely; recovery from a transient failure should be automatic.
- **Preserve availability** for deployments that have not opted into strict-ADoT enforcement. The dominant case in 2026 is a resolver whose operator wants encrypted-DNS contact when available but is not willing to fail the zone when an authoritative's TLS endpoint is broken.
- **Offer strict-ADoT for high-trust deployments**. Deployments that prefer encrypted-DNS-or-failure to encrypted-or-degraded must have an explicit operator opt-in.
- **Refuse silent same-`<NS>` plain-DNS retry on the failed authoritative**. An immediate plain retry on `<NS>` after an ADoT handshake failure converts every transient ADoT failure into an immediate transport downgrade against `<NS>`, which is the silent-downgrade failure mode that the entire ADoT-discovery + capability-evidence + DNSSEC-validation chain was designed to prevent.
- **Distinguish failure causes in the EDE channel**. Operators benefit from a structured signal that distinguishes "no authoritative is reachable on any transport" from "every authoritative was reachable on plain but strict-ADoT mode prevented contact".
- **Fail-loud observability** (cf. [`THREAT-080`](../../specification/007-threat-model.md)). Every transport degradation and every strict-mode denial must surface as a structured event so that operators detect persistent failures and downgrade-attack patterns without relying on client-side complaints.

## Considered Options

### A. Default fallback policy

- **NS-iteration first; bounded ADoT-broken cache; last-resort plain contact under operator-controlled strict-mode (chosen).** On ADoT handshake failure against `<NS>`, attempt the next NS of the zone (using ADoT for NSes with positive evidence, plain DNS for NSes without). When every NS's ADoT contact is broken, fall through to plain DNS as a last resort, unless strict-mode is enabled.
- **Immediate plain fallback on the same NS (silent downgrade).** Simple but defeats the purpose of ADoT: a downgrade attacker who blocks port 853 succeeds silently against the targeted NS.
- **Fail outright on first ADoT handshake failure.** Maximally secure, minimally available; a single broken NS makes the zone unreachable.
- **Operator-configurable per-zone or per-authoritative fallback policy.** Maximum flexibility, maximum complexity, no use case beyond what strict-mode under [`NET-040`](../../specification/002-transports.md) covers.

### B. ADoT-broken cache lifecycle

- **Per-`(<NS>, ADoT)` negative-evidence entry with bounded TTL on the order of minutes (chosen).** Covers transient handshake failures (cert rotation, brief network glitches) without persisting the downgrade indefinitely; auto-recovery on TTL expiry without operator intervention.
- **No cache; every contact retries ADoT.** Wastes handshake attempts on a persistently-broken endpoint; inflates query latency on every cold contact during the broken window.
- **Long-lived cache (hours or days).** Persists the downgrade past reasonable recovery windows; an authoritative that recovers from a brief outage continues to be contacted via plain DNS for the remainder of the cache lifetime.
- **Operator-managed only (no automatic state).** Forces operator intervention for every transient failure; not viable at scale.

### C. Strict-ADoT operator control

- **Boolean `strict_adot` opt-in under `[recursive]`, default `false` (chosen).** Single explicit knob; default preserves availability; opt-in toggles the no-plain-fall-through enforcement.
- **Per-zone strict-mode declaration.** More expressive, more configuration surface, no identified use case where global strict-mode is insufficient.
- **No strict-mode at all.** Excludes the zero-trust deployment shape that has legitimate use; reduces Heimdall's coverage of high-assurance scenarios.

### D. EDE encoding on final failure

- **EDE 22 "No Reachable Authority" on every final-failure SERVFAIL; optional additional EDE 23 "Network Error" on strict-mode denials (chosen).** EDE 22 is the canonical IANA-registered code for the condition; the additional EDE 23 distinguishes the operator-configurable strict-mode-denial scenario from a true unreachability event.
- **EDE 22 only.** Loses the strict-mode-denial signal; harder for operators to diagnose strict-mode misconfigurations.
- **EDE 18 "Prohibited" on strict-mode denials.** EDE 18 is associated with the IANA "active denial" cluster (Blocked, Censored); strict-mode is an operator-configured posture, not an active denial response, so EDE 18 mismatches.
- **No EDE on the final failure.** Loses the structured-diagnostic value [`PROTO-012`](../../specification/006-protocol-conformance.md) was specifically intended to provide.

## Decision Outcome

**A. Default policy.** NS-iteration first under [`NET-037`](../../specification/002-transports.md); bounded ADoT-broken cache under [`NET-038`](../../specification/002-transports.md); last-resort plain contact under [`NET-039`](../../specification/002-transports.md) when strict-mode is not active.

**B. Cache lifecycle.** Per-`(<NS>, ADoT)` negative entry with bounded TTL on the order of a few minutes per [`NET-038`](../../specification/002-transports.md); auto-recovery on TTL expiry; numeric default tracked as an open question.

**C. Strict-ADoT.** Boolean `strict_adot` operator opt-in under `[recursive]`, default `false`, per [`NET-040`](../../specification/002-transports.md). When enabled, strict-mode SERVFAIL replaces last-resort plain contact.

**D. EDE encoding.** EDE 22 ("No Reachable Authority") on every final-failure SERVFAIL; optional additional EDE 23 ("Network Error") on strict-mode denials; no EDE on responses that succeed via last-resort plain contact, per [`NET-041`](../../specification/002-transports.md).

**E. Failure trigger.** Enumerated set of transport, TLS, and certificate-validation conditions per [`NET-036`](../../specification/002-transports.md). DNS-protocol-level failures after a successful TLS handshake are NOT fallback triggers; they follow regular DNS resolution semantics.

**F. Same-`<NS>` retry refusal.** Immediate plain retry on the same `<NS>` after an ADoT handshake failure is explicitly prohibited under [`NET-037`](../../specification/002-transports.md). The next attempt is against the next NS of the zone, not the same NS on a degraded transport.

**G. Observability.** Every fallback event and every strict-mode denial emits a structured event under [`THREAT-080`](../../specification/007-threat-model.md), per [`NET-042`](../../specification/002-transports.md).

### Rejection rationale — default fallback policy

The **immediate plain fallback on the same `<NS>`** option was rejected because it is the failure mode the entire ADoT chain (`NET-020` discovery, `NET-029`–`NET-035` evidence, `SEC-047`–`SEC-059` validation) was designed to prevent. An on-path attacker who can suppress port-853 connections to `<NS>` already controls the network path between Heimdall and `<NS>`; under immediate plain fallback, the attacker silently downgrades every contact to plain DNS for the duration of the suppression. The chosen NS-iteration-first policy under [`NET-037`](../../specification/002-transports.md) prevents this by attempting other NSes of the zone before considering same-NS transport degradation, and the bounded ADoT-broken cache under [`NET-038`](../../specification/002-transports.md) ensures that even when the next-NS attempt happens, the attacker would have to suppress port 853 across every NS of the zone to maintain the silent downgrade.

The **fail-outright** option was rejected on availability grounds. A single misconfigured authoritative — for example, an authoritative whose certificate has expired but whose plain DNS is still operational — would render every zone served by that authoritative unreachable. The chosen design preserves availability by allowing iteration through the NS-set and, in the non-strict default, by falling through to plain DNS as a last resort.

The **per-zone configurable** option was rejected because no use case beyond what `strict_adot` already covers has been identified. A per-zone configuration would require operators to enumerate zones at the recursive-role level, which conflicts with the recursive role's purpose (resolving any zone). Strict-mode at the role level is the right granularity.

### Rejection rationale — cache lifecycle

The **no cache** option was rejected on efficiency grounds: every contact during the broken window pays a handshake-attempt + timeout before falling through, multiplied by every query for every zone served by the broken NS. The chosen short-TTL cache eliminates the redundant handshake attempts during the broken window without persisting the downgrade past reasonable recovery.

The **long-lived cache** option was rejected because it persists the downgrade past the recovery window. An authoritative that recovers from a brief outage continues to be contacted via plain DNS for hours or days, which defeats the purpose of having the recovery happen automatically in the first place. The chosen TTL-on-the-order-of-minutes balances recovery speed against handshake-attempt amplification.

The **operator-managed only** option was rejected because forcing operator intervention for every transient failure does not scale and removes the automatic-recovery property.

### Rejection rationale — strict-ADoT control

The **per-zone strict-mode** option was rejected because no use case has been identified where global strict-mode is insufficient. The dominant strict-mode use case is a high-trust deployment that wants encrypted-DNS-or-failure across the board; per-zone differentiation would add configuration surface without a clear operator scenario.

The **no strict-mode at all** option was rejected because it excludes the zero-trust deployment shape, which has legitimate use cases (high-assurance environments, regulated industries, deployments where unencrypted DNS contact is policy-prohibited at the network layer). The single-Boolean operator opt-in covers that use case at minimal complexity cost.

### Rejection rationale — EDE encoding

The **EDE 22 only** option was rejected on diagnosability grounds. An operator who is debugging a strict-mode SERVFAIL would benefit from a signal that distinguishes "every NS is genuinely unreachable" from "every NS reachable on plain but strict-mode prevented contact"; the additional EDE 23 conveys the latter without revealing strict-mode policy state to adversaries (a strict-mode response already requires the adversary to have suppressed every encrypted endpoint, which presumes transport-layer capability).

The **EDE 18 "Prohibited"** option was rejected because EDE 18 sits in the IANA "active denial" cluster alongside EDE 15 "Blocked" and EDE 16 "Censored", suggesting an active blocking posture that strict-mode does not adopt. Strict-mode denies a specific transport-degradation fall-through, not the query itself.

The **no EDE** option was rejected because [`PROTO-012`](../../specification/006-protocol-conformance.md) requires EDE implementation; not using EDE where applicable codes exist leaves the structured-diagnostic channel unused.

## Consequences

### Operator-visible configuration shape

```toml
[recursive]
enabled = true
strict_adot = false  # default; set to true to opt into strict-ADoT mode

[[recursive.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53
```

Setting `strict_adot = true` on a deployment causes step (5) of the resolution algorithm under [`NET-039`](../../specification/002-transports.md) to be skipped, replacing the last-resort plain-DNS contact with a SERVFAIL response carrying EDE 22 and (optionally) EDE 23 under [`NET-041`](../../specification/002-transports.md).

### Resolution algorithm

For a query against zone `Z` whose NS-set is `{ N1, N2, ..., Nk }`:

1. For each `Ni` in NS-selection order:
   - If `Ni` is in the ADoT-broken cache under [`NET-038`](../../specification/002-transports.md): contact `Ni` via plain DNS per [`NET-019`](../../specification/002-transports.md). On success, return response. On failure, continue to next `Ni`.
   - If `Ni` has positive ADoT capability evidence under [`NET-029`](../../specification/002-transports.md) through [`NET-031`](../../specification/002-transports.md): attempt ADoT to `Ni`. On successful TLS handshake, exchange DNS query/response per `NET-024`. On ADoT handshake failure under [`NET-036`](../../specification/002-transports.md): record `Ni` in ADoT-broken cache; emit structured event under [`NET-042`](../../specification/002-transports.md); continue to next `Ni`.
   - If `Ni` has no positive ADoT capability evidence: contact `Ni` via plain DNS per [`NET-019`](../../specification/002-transports.md). On success, return response. On failure, continue to next `Ni`.
2. If every `Ni` in `Z`'s NS-set has been attempted without producing a response, AND every ADoT-capable `Ni` is in the ADoT-broken cache:
   - If `strict_adot = false`: attempt last-resort plain DNS against any `Ni` per [`NET-039`](../../specification/002-transports.md); emit structured event for the transport degradation.
   - If `strict_adot = true`: return SERVFAIL with EDE 22 (and optionally EDE 23 if the strict-mode-denial branch is the cause) per [`NET-041`](../../specification/002-transports.md); emit structured event under [`NET-042`](../../specification/002-transports.md).
3. If every contact fails on every transport: return SERVFAIL with EDE 22.

### Per-condition outcome matrix

| Condition | `strict_adot = false` | `strict_adot = true` |
|---|---|---|
| ADoT succeeds on `N1` | Response returned (encrypted contact) | Response returned (encrypted contact) |
| ADoT fails on `N1`, succeeds on `N2` | Response returned via `N2` (encrypted contact) | Response returned via `N2` (encrypted contact) |
| ADoT fails on every `Ni`, plain DNS would have worked | Response returned via plain DNS last-resort + structured event | SERVFAIL + EDE 22 + (optional) EDE 23 + structured event |
| ADoT fails on every `Ni`, plain DNS also fails on every `Ni` | SERVFAIL + EDE 22 + structured event | SERVFAIL + EDE 22 + structured event |
| `Ni` has no ADoT evidence; plain DNS works | Response returned via plain DNS (no special handling) | Response returned via plain DNS (no special handling) |
| Every `Ni` has no ADoT evidence; plain DNS fails on every `Ni` | SERVFAIL + EDE 22 + structured event | SERVFAIL + EDE 22 + structured event |

### Closure of the open question

The "ADoT fallback policy on handshake failure (recursive resolver)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). One operational-default open question is added: the numeric default of the ADoT-broken cache TTL.

### Non-consequences (deliberate scope limits)

- **Strict-ADoT exemptions per zone.** A future per-zone exemption from strict-mode (allow plain fallback for specific zones even under strict-mode) is not part of this decision; strict-mode is global. A future revision MAY introduce per-zone exemptions if operational experience identifies the need.
- **Adaptive ADoT-broken cache TTL.** The current design uses a fixed (operationally-defaulted) TTL. An adaptive scheme that lengthens the TTL after repeated failures or shortens it after successful recovery is out of scope; if operator experience identifies the need, a future revision MAY introduce adaptation.
- **Cross-NS coupling.** The current design treats each `Ni` independently in the ADoT-broken cache. An NS that is broken does not influence the perception of other NSes of the same zone; the resolver continues to attempt ADoT against the others. A future revision MAY introduce zone-level signalling if a clear use case emerges.
- **Inter-resolver-instance state sharing.** Multiple Heimdall instances do not share ADoT-broken cache state; each instance maintains its own cache. Inter-instance sharing would require a coordination layer outside the scope of this decision.

### Numbering

This ADR takes the sequence number `0009`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
