---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Forwarder upstream load-balancing and health-checking

## Context and Problem Statement

[`FWD-025`](../../specification/014-forward-zones.md) (recorded in [`0012-forwarder-inter-upstream-failover.md`](0012-forwarder-inter-upstream-failover.md)) fixed sequential-by-declaration-order failover for the forwarder's upstream array. The remaining open question — "Upstream load-balancing, failover, and health-checking (forwarder)" in [`002-transports.md §5`](../../specification/002-transports.md) — covered three related concerns that `FWD-025` did not address: distribution of query load across multiple upstreams when all are healthy (load-balancing); detection of upstream unavailability (health-checking); and restoration of upstream state after recovery.

The decision had to settle three sub-questions:

1. **Load-balancing strategy** — what distribution patterns to support (sequential, round-robin, weighted, latency-aware, consistent-hash); how to expose the choice to operators.
2. **Health-checking style** — passive (derived from regular query outcomes) versus active (synthetic probe queries).
3. **Restoration** — how an upstream returns from broken to eligible state.

The decisions had to compose with the inter-upstream failover under [`FWD-025`](../../specification/014-forward-zones.md) and [`FWD-026`](../../specification/014-forward-zones.md) (broken cache), with the transport-class floor under [`FWD-028`](../../specification/014-forward-zones.md), with the rule-level fallback under [`FWD-021`](../../specification/014-forward-zones.md) / [`FWD-022`](../../specification/014-forward-zones.md), with the no-active-probing posture established for ADoT discovery under [`NET-032`](../../specification/002-transports.md), and with the structured-event and metrics obligations of [`THREAT-080`](../../specification/007-threat-model.md) and [`THREAT-083`](../../specification/007-threat-model.md).

## Decision Drivers

- **Operator coverage**. Some deployments need uniform distribution across upstreams (round-robin); others need proportional distribution (weighted); the dominant case stays with declaration-order (sequential).
- **Hot-path performance**. Selection runs on every query; the chosen mechanism must be O(1) or near-O(1) per query.
- **Composability with sequential failover**. Load balancing affects the **initial** upstream; failover, once it begins for a query, must remain sequential to preserve `FWD-025`'s deterministic-exhaustion property.
- **Passive health for free**. The broken-cache mechanism of [`FWD-026`](../../specification/014-forward-zones.md) already produces health state from regular query outcomes; reusing it removes the need for a parallel health subsystem.
- **No active probing** (cf. [`../../CLAUDE.md`](../../CLAUDE.md), [`NET-032`](../../specification/002-transports.md)). Active probes generate traffic outside the resolution path, expose behavioural fingerprints, and create low-rate DoS patterns against upstreams.

## Considered Options

### A. Load-balancing strategy

- **Sequential + round-robin + weighted, opt-in via `balance` enum, default sequential (chosen).** Three named strategies; default preserves `FWD-025` semantics.
- **Sequential-only (defer balancing).** Closes the open question with "no balancing this release"; misses the AC that explicitly enumerates round-robin and weighted as candidates.
- **Latency-aware adaptive.** Continuous latency measurement + ranking; complex; without active probing it relies on regular-query timing only, which does not differentiate broken-but-eventually-responding from healthy-and-fast.
- **Consistent-hash.** Useful for distributed caches; not for forwarder upstream selection.

### B. Health-checking style

- **Passive only via the existing `FWD-026` broken cache (chosen).** Reuses an already-fixed mechanism; no new state, no new traffic.
- **Active probing.** Synthetic queries to test upstream health. Rejected for the same reasons as ADoT probing in [`0008-adot-capability-discovery.md`](0008-adot-capability-discovery.md): probing traffic is outside the resolution path, behavioural fingerprint, low-rate DoS pattern.
- **Hybrid (passive default, active opt-in).** Adds an opt-in knob without an identified use case; the operator who needs health information beyond `FWD-026` would more profitably consume the metrics under [`THREAT-083`](../../specification/007-threat-model.md).

### C. Restoration

- **TTL-based via `FWD-026` (chosen).** When the broken-cache entry expires, the upstream re-enters the eligible set and is attempted on the next matching query; success removes the entry permanently. Already fixed.
- **Active recovery probe.** Test the broken upstream periodically; restore on success. Rejected as active probing.
- **Operator-only restoration.** Force operator intervention to restore an upstream; not viable at scale.

## Decision Outcome

**A. Strategy.** Sequential + round-robin + weighted via `balance` enum, default sequential, per [`FWD-032`](../../specification/014-forward-zones.md) through [`FWD-035`](../../specification/014-forward-zones.md). Initial upstream selection only; failover under [`FWD-025`](../../specification/014-forward-zones.md) reverts to sequential per [`FWD-036`](../../specification/014-forward-zones.md).

**B. Health.** Passive only via [`FWD-026`](../../specification/014-forward-zones.md), per [`FWD-037`](../../specification/014-forward-zones.md). No active probing.

**C. Restoration.** TTL-based per [`FWD-026`](../../specification/014-forward-zones.md), per [`FWD-037`](../../specification/014-forward-zones.md).

**D. Telemetry.** Selection events MUST NOT emit per-query structured events ([`THREAT-080`](../../specification/007-threat-model.md) hot-path saturation); selection statistics exposed as metrics under [`THREAT-083`](../../specification/007-threat-model.md), per [`FWD-038`](../../specification/014-forward-zones.md). Existing structured-event obligations under [`FWD-031`](../../specification/014-forward-zones.md) (transitions, broken cache, blocked / permitted downgrades) continue to apply on non-hot-path events.

### Rejection rationale

The **sequential-only deferral** option was rejected on coverage grounds: the task's technical-requirements line explicitly enumerates round-robin and weighted as candidates, indicating the operator expectation that these be available. Deferring would close the task without addressing what the AC asked for.

The **latency-aware adaptive** option was rejected on two grounds. First, without active probing (which is rejected separately), latency information comes only from regular query timing; this conflates "fast and healthy" with "fast but eventually wrong" and adds complexity without a clear operator gain. Second, the load-balancing decision in DNS-forwarder context is for distributing queries across roughly-equivalent upstreams; latency-aware optimisation is a more relevant concept for HTTP-style request routing where latency varies across endpoints by orders of magnitude.

The **consistent-hash** option was rejected because it solves a different problem (preserving cache locality for keyed distribution); the forwarder is not a distributed cache.

The **active probing** option for health was rejected for the same reasons given in [`NET-032`](../../specification/002-transports.md) and [`0008-adot-capability-discovery.md`](0008-adot-capability-discovery.md): probe traffic is outside the resolution path, exposes a behavioural fingerprint, and creates low-rate DoS against upstreams. Passive health via regular query outcomes captures the operationally significant signal without these costs.

The **active recovery probe** option was rejected as a special case of active probing.

The **operator-only restoration** option was rejected because it forces operator intervention for every transient failure; not viable for production deployments.

## Consequences

### Operator-visible configuration shape

```toml
# Sequential (default) — first declared upstream gets all queries when healthy:
[[forwarder.forward_zone]]
zone = "internal.corp."
upstream = [
  { address = "10.0.0.1", port = 53, transport = "udp" },
  { address = "10.0.0.2", port = 53, transport = "udp" },
]

# Round-robin — uniform distribution across healthy upstreams:
[[forwarder.forward_zone]]
zone = "external.example."
balance = "round-robin"
upstream = [
  { address = "10.0.0.1", port = 53, transport = "udp" },
  { address = "10.0.0.2", port = 53, transport = "udp" },
  { address = "10.0.0.3", port = 53, transport = "udp" },
]

# Weighted — proportional distribution; primary upstream takes 4x as many queries:
[[forwarder.forward_zone]]
zone = "weighted-zone.example."
balance = "weighted"
upstream = [
  { address = "10.0.0.1", port = 53, transport = "udp", weight = 4 },
  { address = "10.0.0.2", port = 53, transport = "udp", weight = 1 },
]
```

### Closure

The "Upstream load-balancing, failover, and health-checking (forwarder)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). No new operational-default open question is added here — the cache TTL default already tracked under [`FWD-026`](../../specification/014-forward-zones.md) covers the only remaining numeric default.

### Non-consequences (deliberate scope limits)

- **Active health probing.** Rejected entirely; passive via [`FWD-026`](../../specification/014-forward-zones.md) is the sole health-state source.
- **Latency-aware / consistent-hash strategies.** Rejected; not part of the chosen `balance` enum.
- **Cross-instance balance state sharing.** Each Heimdall instance maintains its own rotation index / weighted-selection state; instances do not coordinate.
- **Per-query structured events for selection.** Rejected on hot-path saturation grounds; metrics under [`THREAT-083`](../../specification/007-threat-model.md) are the operator-visible signal.

### Numbering

This ADR takes the sequence number `0013`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
