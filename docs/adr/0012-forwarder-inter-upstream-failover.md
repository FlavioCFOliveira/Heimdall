---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Forwarder inter-upstream failover policy (within a single rule)

## Context and Problem Statement

A `[[forwarder.forward_zone]]` rule may declare multiple upstreams in its `upstream` array (per [`FWD-002`](../../specification/014-forward-zones.md) and [`FWD-014`](../../specification/014-forward-zones.md)). When one of those upstreams fails for the present query — at the transport layer, at the DNS-protocol layer, or by returning a non-success RCODE per [`FWD-020`](../../specification/014-forward-zones.md) — the resolver needs to decide what to do next. Two layers of fallback are involved:

1. **Inter-upstream failover within the same rule** — try another upstream of the same rule. This decision (the present ADR).
2. **Rule-level fallback** — when every upstream of the rule has been attempted without producing a successful response, invoke `fallback = "error"` (return SERVFAIL or propagate the upstream RCODE) or `fallback = "recursive"` (proceed to step 3 of the four-step precedence). Already fixed by [`FWD-018`](../../specification/014-forward-zones.md) through [`FWD-024`](../../specification/014-forward-zones.md), recorded in [`0004-forward-zone-fallback-on-upstream-failure.md`](0004-forward-zone-fallback-on-upstream-failure.md).

The remaining open question was the inter-upstream failover policy. Five sub-questions had to be settled jointly:

1. **Failover order** — declaration order, round-robin, random, parallel, or operator-tunable.
2. **Health awareness** — whether and how to skip recently-failed upstreams.
3. **Transport-downgrade prohibition** — whether, by default, an encrypted upstream's failure may lead to plain-DNS contact within the same query's failover sequence.
4. **Operator opt-in to downgrade** — the per-rule knob the technical-requirements line of the task explicitly identifies.
5. **Telemetry** — structured-event obligations on every inter-upstream transition, including blocked downgrades.

The decisions had to compose with the rule-level fallback ([`FWD-018`](../../specification/014-forward-zones.md) through [`FWD-024`](../../specification/014-forward-zones.md)), with the per-upstream transport declaration ([`FWD-014`](../../specification/014-forward-zones.md), [`NET-013`](../../specification/002-transports.md)), with the outbound TLS validation pipeline ([`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md)), and with the structured-event taxonomy of [`THREAT-080`](../../specification/007-threat-model.md).

## Decision Drivers

- **Operator intent preservation**. A rule with `upstream = [U1, U2, U3]` expresses an ordered preference; the failover order must respect that.
- **No silent downgrade** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). An operator who declared an encrypted upstream as the first preference must not have queries silently fall through to plain DNS on an encrypted-upstream failure; that is precisely the silent-downgrade failure mode that the encrypted-DNS infrastructure is designed to prevent.
- **Operator opt-in for availability over privacy**. Some deployments prefer "encrypted-when-possible, plain-when-necessary" semantics (a corporate environment with mixed legacy / modern upstreams). A per-rule operator knob captures this without forcing the unsafe default on every deployment.
- **Health-aware skipping**. A persistently-failing upstream within a rule should not be retried on every query; a short-TTL broken cache absorbs the transient-vs-persistent distinction without operator intervention.
- **Structured-event observability** (cf. [`THREAT-080`](../../specification/007-threat-model.md)). Inter-upstream failover, broken-cache events, blocked downgrades, and permitted downgrades are all operationally significant and must surface as structured signals.
- **Composability with rule-level fallback**. The two layers (inter-upstream failover, rule-level fallback) must be ordered (inter-upstream first, rule-level second) and clearly delineated.

## Considered Options

### A. Failover order

- **Declaration order ("sequential", chosen).** Deterministic, respects operator intent, simple to reason about, simple to implement.
- **Round-robin.** Distributes load across upstreams. Operator who declared `[primary, fallback]` would not get the implied semantics.
- **Random.** Same as round-robin in operator-intent mismatch, plus non-deterministic test outputs.
- **Parallel-first-response.** Send the query to multiple upstreams simultaneously, take the first response. Reduces latency but multiplies upstream load and exposes the resolver's traffic to multiple parties for every query.
- **Operator-tunable enum.** Adds configuration surface without an identified use case beyond what the chosen design covers.

### B. Health awareness

- **Per-upstream-entry broken cache with bounded TTL (chosen).** Keyed by the upstream-entry index in the rule. Auto-recovery on TTL expiry without operator intervention.
- **Cross-rule broken cache (keyed by upstream `address`).** A failure observed under one rule influences other rules that happen to declare the same address. Tempting for shared-NS-pool semantics, but couples rules that the operator declared independently and may not want coupled.
- **No health awareness.** Every query retries the broken upstream; wasted handshake attempts during the broken window.
- **Health probes (active probing of upstreams).** Adds discovery traffic outside the resolution path; complicates the implementation; rejected for the same reasons as passive ADoT probing in [`0008-adot-capability-discovery.md`](0008-adot-capability-discovery.md) (behavioural fingerprinting, DoS pattern).

### C. Transport-downgrade default

- **Prohibition by default (chosen).** Once an encrypted upstream has been attempted in the failover sequence, plain upstreams declared later in the array are skipped silently and the skip is reported as a blocked downgrade. The transport-class floor is per-query state, reset for each new query.
- **Permitted by default.** Silent encrypted→plain transition on every encrypted failure; precisely the silent-downgrade failure mode the security-first posture rejects.
- **Per-rule mandatory declaration.** Every rule MUST declare `allow_transport_downgrade`; loader rejects omission. Verbose without information gain (the dominant case is `false`).

### D. Operator opt-in to downgrade

- **Per-rule Boolean `allow_transport_downgrade` (default `false`) (chosen).** A single explicit knob that toggles the transport-class floor for a specific rule. Granularity at the rule level matches the granularity at which operators configure the upstream array.
- **Per-instance global knob.** Affects all rules; loses per-rule expressiveness. An operator who has both legacy and modern zones cannot differentiate.
- **No opt-in (downgrade never).** Excludes the legitimate "availability preferred" deployment shape (corporate mixed legacy / modern upstreams).

### E. Composability with rule-level fallback

- **Sequential layered: inter-upstream first, then rule-level (chosen).** Clear order; one layer fully exhausts before the other applies. Matches operator intuition (try upstreams of the rule, then fall through to the rule's general fallback policy).
- **Interleaved.** Some queries fall through to rule-level after the first inter-upstream failure, others after exhaustion. No clear use case; complicates the failure model.

## Decision Outcome

**A. Order.** Sequential by declaration order, per [`FWD-025`](../../specification/014-forward-zones.md).

**B. Health.** Per-upstream-entry broken cache with bounded TTL, scoped to the rule, automatic recovery on TTL expiry, per [`FWD-026`](../../specification/014-forward-zones.md). Numeric default of TTL tracked as open question.

**C. Transport-downgrade prohibition.** Default `false` for `allow_transport_downgrade`; transport-class floor enforced per [`FWD-027`](../../specification/014-forward-zones.md) and [`FWD-028`](../../specification/014-forward-zones.md).

**D. Operator opt-in.** Per-rule Boolean `allow_transport_downgrade`, default `false`, per [`FWD-027`](../../specification/014-forward-zones.md). When `true`, transport-class floor is not enforced per [`FWD-029`](../../specification/014-forward-zones.md).

**E. Composability.** Inter-upstream failover under [`FWD-025`](../../specification/014-forward-zones.md) runs first; rule-level fallback under [`FWD-021`](../../specification/014-forward-zones.md) / [`FWD-022`](../../specification/014-forward-zones.md) runs after exhaustion, per [`FWD-030`](../../specification/014-forward-zones.md).

**F. Telemetry.** Structured events on every inter-upstream transition, broken-cache event, blocked downgrade, and permitted downgrade, per [`FWD-031`](../../specification/014-forward-zones.md).

### Rejection rationale

The **round-robin / random / parallel** failover orders were rejected because they conflict with the operator-stated preference order in `upstream = [U1, U2, ...]`. The natural reading of an array is "ordered preference"; rejecting that semantics would force operators to express preference some other way (numeric priority field, etc.) without a corresponding gain.

The **cross-rule broken cache** was rejected because rules are independently declared and may target the same address with different intent (different transports, different TLS overrides, different ACL bindings under the open ACL syntax question). Coupling broken-state across rules would propagate a failure in one rule's view to other rules that the operator may have configured to tolerate the same upstream's idiosyncrasies.

The **no health awareness** option was rejected on efficiency grounds: each query retries the broken upstream during the broken window, wasting handshake attempts and inflating per-query latency.

The **active health probing** option was rejected because it generates traffic outside the resolution path and exposes a probe behaviour that adversarial network observers can fingerprint, parallel to the rejection grounds for passive ADoT probing.

The **permit-downgrade-by-default** option was rejected outright on security grounds: it converts every encrypted upstream failure into a silent downgrade, which is precisely the threat the encrypted-DNS infrastructure is designed to prevent.

The **per-rule mandatory declaration** of the downgrade knob was rejected on ergonomics: the dominant case is the safe default; requiring every rule to repeat `allow_transport_downgrade = false` adds verbosity without information.

The **per-instance global** downgrade knob was rejected because it loses the per-rule expressiveness needed for mixed deployments. A corporate environment with both legacy plain-DNS upstreams (for internal zones) and modern encrypted-DNS upstreams (for external zones) needs to differentiate; a global knob does not allow this.

The **interleaved layering** of inter-upstream failover and rule-level fallback was rejected because it lacks a clear semantic model: when does a query fall through to rule-level fallback versus continue inter-upstream? The chosen sequential layering is unambiguous.

## Consequences

### Failover sequence (illustrative)

For a rule with `upstream = [U1 (DoT), U2 (UDP), U3 (DoT), U4 (UDP)]`, `allow_transport_downgrade = false`, and `fallback = "recursive"`:

1. Try U1 (DoT). If success → return response. If failure → record U1 in broken cache; transport-class floor becomes "encrypted".
2. Try U2 (UDP). U2 is plain; transport-class floor is encrypted; **U2 is skipped under `FWD-028`** (blocked-downgrade event emitted under `FWD-031`).
3. Try U3 (DoT). If success → return response. If failure → record U3 in broken cache.
4. Try U4 (UDP). U4 is plain; transport-class floor is encrypted; **U4 is skipped** (blocked-downgrade event emitted).
5. Inter-upstream failover exhausted. Invoke rule-level fallback under `FWD-022`: proceed to step 3 of `ROLE-008`–`ROLE-012` (recursive resolver).

For the same rule with `allow_transport_downgrade = true`:

1. Try U1 (DoT). On failure → record U1 in broken cache; **no transport-class floor**.
2. Try U2 (UDP). On failure → record U2 in broken cache.
3. Try U3 (DoT). On failure → record U3 in broken cache.
4. Try U4 (UDP). On failure → record U4 in broken cache.
5. Inter-upstream failover exhausted. Invoke rule-level fallback under `FWD-022`.

In the second case, the actual downgrade transitions (DoT-to-UDP between U1 and U2; UDP-to-DoT between U2 and U3; DoT-to-UDP between U3 and U4) emit structured events under `FWD-031` for operator visibility.

### Closure

The "Upstream fallback policy on failure (forwarder)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). One operational-default open question is added in its place: the numeric default of the per-upstream-entry broken-cache TTL.

### Non-consequences (deliberate scope limits)

- **Upstream load-balancing across rules.** Distributing query load across multiple upstreams of the same rule is governed by the chosen sequential failover (no load-balancing within a single query). Across-rule load balancing is governed by the separate "Upstream load-balancing, failover, and health-checking (forwarder)" open question in [`002-transports.md §5`](../../specification/002-transports.md), which remains open.
- **Active health probing.** No active probes; broken-cache state derives from observed failures, not active checks. A future revision MAY introduce health probing if operational experience identifies the need.
- **Cross-rule cache sharing.** Broken-cache state is per-rule, not shared across rules.
- **Cross-instance cache sharing.** Multiple Heimdall instances do not share broken-cache state; each instance maintains its own.
- **Adaptive broken-cache TTL.** The current design uses a fixed (operationally-defaulted) TTL. Adaptation to repeated failures or successful recovery is out of scope; future revisions MAY introduce it.

### Numbering

This ADR takes the sequence number `0012`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
