---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# QUIC `NEW_TOKEN` operational defaults (key rotation, retention window, strike-register persistence)

## Context and Problem Statement

[`SEC-025`](../../specification/003-crypto-policy.md) through [`SEC-030`](../../specification/003-crypto-policy.md) fix the structural posture of QUIC amplification mitigation on Heimdall's QUIC-based listeners (DoQ, DoH over HTTP/3): mandatory amplification-limit enforcement per [RFC 9000 §8.1](https://www.rfc-editor.org/rfc/rfc9000#section-8.1); Retry on every new flow that does not present a valid server-issued `NEW_TOKEN`; single-use `NEW_TOKEN` enforced through a strike-register or equivalent anti-replay mechanism; rotatable Token-Encryption-Key for the `NEW_TOKEN` payload. The numeric calibration of three operational parameters — TEK rotation cadence, retention window for retired keys, strike-register persistence strategy — was left as an open question in [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). The present decision fixes the defaults, the operator-configurable ranges, the strike-register persistence model, and the strike-register sizing.

The decision had to settle four sub-questions jointly:

1. **TEK rotation cadence and retention window** — parallel to the TLS session-ticket TEK decision in [`0015-tls-session-ticket-operational-defaults.md`](0015-tls-session-ticket-operational-defaults.md).
2. **Strike-register persistence model** — in-memory only, synchronous Redis writes per consumption, or hybrid in-memory primary with periodic Redis snapshots.
3. **Strike-register size cap** — bounded against denial-of-resource via flood of consumed tokens.
4. **Forward-secrecy and observability** — destruction of retired TEKs; structured-event obligations on overflow, snapshot failures, and restore events.

The decisions had to compose with [`SEC-025`](../../specification/003-crypto-policy.md) through [`SEC-030`](../../specification/003-crypto-policy.md) (NEW_TOKEN structural posture), with the TLS TEK calibration of [`SEC-060`](../../specification/003-crypto-policy.md) through [`SEC-062`](../../specification/003-crypto-policy.md) (parallel forward-secrecy story), with the Redis persistence layer fixed by [`013-persistence.md`](../../specification/013-persistence.md), and with the structured-event taxonomy of [`THREAT-080`](../../specification/007-threat-model.md).

## Decision Drivers

- **Connection-setup latency**. NEW_TOKEN validation runs on every QUIC connection's setup path. Synchronous Redis round-trips per setup would add measurable latency to a path that is otherwise designed for performance.
- **Replay-attack resistance**. The single-use guarantee is the core security property of NEW_TOKEN; restart-replay (a token consumed in-memory but not yet snapshotted) must be bounded.
- **Bounded resource use**. The strike-register is an attacker-controlled state (an attacker can attempt many connections); it must be bounded in memory.
- **Alignment with [`SEC-060`](../../specification/003-crypto-policy.md)–[`SEC-062`](../../specification/003-crypto-policy.md)**. The TLS TEK and the QUIC NEW_TOKEN TEK serve analogous purposes (encryption of opaque tokens with rotation for forward secrecy); the calibration should follow parallel rules.
- **Alignment with [`013-persistence.md`](../../specification/013-persistence.md)**. The project's persistence layer is Redis; the strike-register snapshot uses that layer rather than introducing a parallel persistence mechanism.

## Considered Options

### A. TEK rotation and retention

- **12 hours / 24 hours (chosen).** Parallel to [`SEC-060`](../../specification/003-crypto-policy.md). Compromise window 36 hours under defaults.
- **6 hours / 12 hours.** More aggressive; smaller compromise window; rotation overhead negligible at this cadence either way.
- **24 hours / 48 hours.** More relaxed; doubles the compromise window without operational benefit at this cadence.

### B. Strike-register persistence model

- **Hybrid in-memory primary + periodic Redis snapshot, default 60 s interval (chosen).** Hot path stays in-memory; restart replay window bounded by snapshot interval; snapshot interval operator-configurable in `[10, 600]` seconds.
- **Synchronous Redis writes per consumption.** Zero replay window; latency overhead per QUIC connection setup; high Redis load proportional to connection-setup rate.
- **In-memory only, no persistence.** Maximum performance; restart replay window is the full TEK retention window (24 hours under defaults), which is unacceptable under the security-first posture.
- **Operator-tunable persistence mode (`memory` / `snapshot` / `synchronous`).** Adds configuration surface without an identified use case for `synchronous`.

### C. Strike-register size cap

- **Default 1,000,000 entries, configurable in `[10,000, 100,000,000]` (chosen).** ~24 MB at default; bounded against flood; eviction oldest-first.
- **No cap.** DoS vector via memory exhaustion.
- **Smaller fixed cap.** Risks legitimate over-cap eviction; no compelling reason to lower the default.

### D. Forward-secrecy and observability

- **Destroy retired TEKs after retention window; emit structured events on overflow, snapshot failure, restore (chosen).** Parallel to [`SEC-062`](../../specification/003-crypto-policy.md); aligns with [`THREAT-080`](../../specification/007-threat-model.md) catalogue.
- **Persist retired TEKs.** Defeats forward secrecy.
- **No structured events.** Operators cannot detect strike-register saturation or snapshot failures, both of which are operationally significant.

## Decision Outcome

**A. TEK rotation / retention.** 12 hours / 24 hours, configurable in `[1, 168]` and `[tek_rotation, 336]` respectively, per [`SEC-071`](../../specification/003-crypto-policy.md).

**B. Strike-register persistence.** Hybrid in-memory primary + periodic Redis snapshot at 60-second default interval (configurable in `[10, 600]`), per [`SEC-072`](../../specification/003-crypto-policy.md). On instance start, restore from the last snapshot, discard out-of-window entries, per [`SEC-073`](../../specification/003-crypto-policy.md).

**C. Strike-register size cap.** Default 1,000,000 entries (≈24 MB), configurable in `[10,000, 100,000,000]`, eviction oldest-consumption-timestamp-first, per [`SEC-074`](../../specification/003-crypto-policy.md).

**D. Forward secrecy.** Retired TEKs destroyed after retention window; tokens under destroyed TEKs cause silent fallback to QUIC Retry; compromise window 36 hours under defaults, per [`SEC-075`](../../specification/003-crypto-policy.md). Parallel to [`SEC-062`](../../specification/003-crypto-policy.md).

**E. Observability.** Structured events on cap overflow, snapshot failure, restore success, restore degraded, per [`SEC-076`](../../specification/003-crypto-policy.md).

### Rejection rationale

The **synchronous Redis writes** option was rejected on connection-setup latency grounds. Every QUIC connection setup that uses a NEW_TOKEN avoids one Retry round-trip; if the NEW_TOKEN validation itself adds a Redis round-trip, the saving is partly cancelled and the latency profile becomes a function of Redis health rather than the QUIC stack alone. Under the chosen hybrid design, the connection-setup path is unaffected by Redis health; only the snapshot itself can fail, and snapshot failure is degradative (longer effective replay window after restart) rather than blocking.

The **in-memory only** option was rejected on replay-window grounds. A restart of a Heimdall instance would resurrect the strike-register as empty; every NEW_TOKEN issued in the past 24 hours (under default retention) would become validly redeemable once. The chosen 60-second snapshot bounds the replay window to one minute, which is operationally tolerable.

The **operator-tunable persistence mode** option was rejected because no use case has been identified that needs `synchronous` mode beyond the chosen 60-second snapshot. An operator with stricter requirements can lower the snapshot interval to 10 seconds (the lower bound of the configurable range under [`SEC-072`](../../specification/003-crypto-policy.md)), achieving most of the effect at a fraction of the cost.

The **no-cap** option on the strike-register was rejected on standard DoS-resistance grounds, parallel to [`THREAT-066`](../../specification/007-threat-model.md). An attacker that opens many connections without ever completing them could grow the strike-register without bound under a no-cap model; the chosen 1M-entry cap with oldest-eviction prevents this while preserving correctness for in-window tokens (oldest entries are most likely to have aged out anyway).

The **persist retired TEKs** option was rejected on forward-secrecy grounds. A retired TEK that is recoverable later defeats the rotation's purpose. The chosen design destroys retired TEKs at the end of retention; the only persistence is the strike-register itself (which records consumed tokens, not encryption keys).

## Consequences

### Operator-visible configuration shape

```toml
[quic.new_token]
tek_rotation_hours = 12               # default; range [1, 168]
tek_retention_hours = 24              # default; range [tek_rotation_hours, 336]
snapshot_interval_seconds = 60        # default; range [10, 600]
strike_register_max_entries = 1000000 # default; range [10000, 100000000]
```

### Compromise window summary

| Parameter (default) | Value | Effect |
|---|---|---|
| TEK rotation | 12h | New tokens after rotation under fresh TEK |
| TEK retention window | 24h | Retired TEK still in memory (decryption only) |
| **Compromise window (sum)** | **36h** | TEK exposure window before destruction |
| Snapshot interval | 60s | Replay window after restart (max) |
| Strike-register cap | 1M | Memory bound (~24 MB) |

### Closure

The "QUIC `NEW_TOKEN` operational defaults" open question is removed from [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). No new operational-default open question is added; the four numeric parameters are fixed with operator-tunable ranges.

### Non-consequences (deliberate scope limits)

- **Inter-instance strike-register sharing.** Multiple Heimdall instances behind a load balancer would benefit from sharing the strike-register; that is a deployment concern outside the scope of this decision (would require a cross-instance consistency model). Each instance maintains its own strike-register and snapshot key in Redis (keyed by instance ID).
- **Cryptographic algorithm for NEW_TOKEN encryption.** The AEAD used to encrypt the token payload is a library detail; the spec fixes only the rotation, retention, and persistence semantics.
- **Snapshot encryption-at-rest in Redis.** The strike-register snapshot stores token hashes (not the tokens themselves) plus consumption timestamps; encryption-at-rest is a Redis-deployment concern, not a Heimdall concern. Token hashes do not enable replay attacks if disclosed.
- **Operator-triggered TEK rotation via admin RPC.** Rotation is interval-driven; an explicit operator-triggered rotation may be added in a future revision under the admin-RPC capability set fixed by [`012-runtime-operations.md`](../../specification/012-runtime-operations.md), but is not part of this decision.

### Numbering

This ADR takes the sequence number `0017`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1 and 2 thus far have occupied `0002`–`0017`; the grandfather batch (sprint 11 work) will start at `0018` or later; the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md) ("expected to start at `0002`") will be updated during sprint 11.
