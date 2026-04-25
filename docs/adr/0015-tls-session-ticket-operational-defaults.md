---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# TLS 1.3 session-ticket operational defaults (TEK rotation, acceptance window, max ticket lifetime)

## Context and Problem Statement

[`SEC-008`](../../specification/003-crypto-policy.md) through [`SEC-011`](../../specification/003-crypto-policy.md) fix the structural posture of TLS 1.3 session resumption on Heimdall's TLS-protected listeners (DoT and DoH over HTTP/2): stateless tickets only, opaque to the client, encrypted under a server-held Ticket-Encryption-Key (TEK), no stateful server-side session cache, periodic TEK rotation, retired-TEK acceptance window, bounded ticket lifetime, multi-use tickets permitted. The numeric calibration of three operational parameters — TEK rotation interval, acceptance window for retired TEKs, maximum ticket lifetime — was left as an open question in [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). The present decision fixes the numeric defaults and the operator-configurable ranges.

The decision had to settle three sub-questions jointly:

1. **TEK rotation interval default and permitted range** — how often the active TEK is replaced.
2. **Acceptance window for retired TEKs** — how long a retired TEK remains usable for decryption (only) of tickets issued before retirement.
3. **Maximum ticket lifetime** — the upper bound on the lifetime field Heimdall sets in NewSessionTicket messages, regardless of any longer value the protocol permits.

The decisions had to compose with [`SEC-008`](../../specification/003-crypto-policy.md) through [`SEC-011`](../../specification/003-crypto-policy.md) (stateless tickets, TEK-encrypted), with the forward-secrecy posture implicit in periodic TEK rotation, with [RFC 8446 §4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1) (protocol-maximum 7-day ticket lifetime), and with the operator-configurability discipline established by [`ROLE-016`](../../specification/001-server-roles.md) through [`ROLE-021`](../../specification/001-server-roles.md) for the configuration boundary.

## Decision Drivers

- **Forward secrecy posture** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Shorter rotation intervals and shorter acceptance windows reduce the exposure of any compromised TEK to a smaller set of tickets; the upper bound is the sum of the rotation interval and the acceptance window.
- **Resumption availability**. Tickets must remain valid long enough that legitimate clients can use them; an aggressive rotation schedule with a short acceptance window forces full handshakes too often, defeating the purpose of resumption.
- **Operational simplicity**. Rotation overhead is negligible at hourly cadences; nothing forces hyper-aggressive rotation, but excessively long intervals leave a longer compromise window for no operational benefit.
- **Industry alignment**. Major TLS terminators (Cloudflare, Google, Mozilla guidance) rotate TEKs on the order of a few hours to a day; the chosen defaults must sit comfortably within that band.
- **Operator-tunability**. Operators with stricter forward-secrecy requirements (regulated industries, high-trust deployments) must be able to tighten the defaults; operators with simpler operational models must be able to relax them within bounds.
- **Misconfiguration prevention**. The acceptance window must not be allowed to fall below the rotation interval, because that combination produces a deterministic window of every rotation cycle in which fresh tickets are immediately invalid.

## Considered Options

- **12 hours / 24 hours / 24 hours (chosen).** TEK rotation every 12 hours; retired-TEK acceptance window of 24 hours (= 2× rotation); ticket lifetime cap of 24 hours.
- **6 hours / 12 hours / 12 hours.** More aggressive rotation, shorter exposure windows, more frequent full handshakes for intermittent clients. Suitable for high-trust deployments; not the default.
- **24 hours / 48 hours / 24 hours.** More relaxed rotation, longer compromise window, fewer rotations per day. Acceptable for standard deployments; not the default.
- **No defaults; operator must declare all three.** Verbose, prevents deployment without conscious decision. No identified use case.

The relationship `acceptance_window = 2 × rotation_interval` is the conventional ratio: it ensures that any ticket issued in the last moments of an active TEK has an effective remaining lifetime equal to one full rotation interval, matching client-side expectations of "tickets are usable for at least one rotation cycle".

The relationship `ticket_lifetime <= rotation_interval + acceptance_window` is implicit in the `acceptance_window` semantics — a ticket whose `ticket_lifetime` exceeds that sum will be rejected when its TEK has aged out, regardless of the protocol-level lifetime. The chosen `ticket_lifetime = 24` matches the acceptance window precisely under the chosen defaults.

## Decision Outcome

**A. TEK rotation interval.** Default 12 hours, configurable in `[1, 168]` (1 hour to 7 days), per [`SEC-060`](../../specification/003-crypto-policy.md).

**B. Acceptance window for retired TEKs.** Default 24 hours, configurable in `[tek_rotation_hours, 336]` (must be ≥ rotation, up to 14 days), per [`SEC-060`](../../specification/003-crypto-policy.md).

**C. Maximum ticket lifetime.** Default 24 hours, configurable in `[1, 168]` (RFC 8446 protocol-maximum 7 days), per [`SEC-060`](../../specification/003-crypto-policy.md).

**D. Load-time invariants.** `tek_acceptance_window_hours >= tek_rotation_hours`; all three values positive integers; all within their permitted ranges. Violation MUST be rejected at load, per [`SEC-061`](../../specification/003-crypto-policy.md).

**E. Forward-secrecy property.** Retired TEKs aged out of the acceptance window MUST be destroyed (in-memory wipe + memory release); MUST NOT be persisted to disk; tickets under destroyed TEKs MUST trigger silent fallback to full handshake. Compromise window bounded by `rotation + acceptance_window` (36 hours under defaults), per [`SEC-062`](../../specification/003-crypto-policy.md).

**F. Configuration scope.** Per-instance, not per-listener — the TEK is shared across all TLS-protected listeners on the instance. Operator config keys live under `tls.session_ticket.*`.

### Rejection rationale

The **6h / 12h / 12h** option was rejected as the default because the additional forward-secrecy gain over the chosen defaults is incremental (compromise window narrows from 36h to 18h), while the cost in full-handshake rate against intermittent clients is more material. Operators who need that aggressive posture can configure it directly under [`SEC-060`](../../specification/003-crypto-policy.md).

The **24h / 48h / 24h** option was rejected as the default because it doubles the compromise window (to 72h) without a clear operational benefit at this cadence; rotation every 12h is already operationally trivial. Operators who prefer relaxed rotation can configure it directly.

The **mandatory-explicit-declaration** option was rejected on ergonomics: the dominant deployment case is "use sensible defaults"; requiring every operator to enumerate all three values adds verbosity without information.

The candidate `acceptance_window < rotation_interval` ratios were rejected outright (and made a load-time invariant) because they produce a deterministic window in every rotation cycle in which freshly-issued tickets are immediately invalid — a class of misconfiguration that breaks resumption silently.

## Consequences

### Operator-visible configuration shape

```toml
[tls.session_ticket]
tek_rotation_hours = 12              # default; range [1, 168]
tek_acceptance_window_hours = 24     # default; range [tek_rotation_hours, 336]
max_ticket_lifetime_hours = 24       # default; range [1, 168]
```

A configuration that omits the section entirely uses the documented defaults. A configuration that sets only some keys uses the defaults for the omitted keys.

### Forward-secrecy summary

| Parameter (default) | Value | Effect on forward secrecy |
|---|---|---|
| TEK rotation interval | 12h | Newly-issued tickets after rotation are encrypted under a fresh TEK; no relationship to prior keys. |
| Retired-TEK acceptance window | 24h | Window during which a retired TEK is still in memory (decryption only). After 24h, key is destroyed. |
| Max ticket lifetime | 24h | Tickets older than this are rejected even if their TEK is still in the acceptance window. |
| **Compromise window** (sum) | **36h** | Time window during which a compromised TEK could decrypt issued tickets. Beyond this, forward secrecy is restored by key destruction. |

### Closure

The "TLS session-ticket operational defaults" open question is removed from [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). No new operational-default open question is added in its place — the numeric calibration is fixed by [`SEC-060`](../../specification/003-crypto-policy.md), with operator-tunable ranges.

### Non-consequences (deliberate scope limits)

- **Inter-instance TEK sharing.** Multiple Heimdall instances behind a load balancer would benefit from sharing TEKs for cross-instance ticket reuse; that is a deployment concern outside the scope of this decision (would require a TEK-distribution channel, key-management procedure, and consistency model). Each Heimdall instance maintains its own TEK schedule independently.
- **Ticket-key derivation cryptography.** The cryptographic algorithm used to encrypt and authenticate tickets is the rustls default (an AEAD with a per-TEK random nonce); the algorithm choice is a library detail and is not specified here.
- **Persistence of TEKs across restarts.** The current design does not persist TEKs across instance restarts: a restart starts a fresh schedule with a freshly-generated TEK. Persisting TEKs would extend the resumption window across restart events but introduces key-storage concerns; out of scope for this decision.
- **TEK rotation triggered by external signal.** Rotation is interval-driven; an explicit operator-triggered rotation via admin RPC may be added in a future revision (under the admin-RPC capability set fixed by [`012-runtime-operations.md`](../../specification/012-runtime-operations.md)) but is not part of this decision.

### Numbering

This ADR takes the sequence number `0015`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). With Sprint 1 having occupied `0002`–`0014`, the grandfather batch (sprint 11 work) will start at `0016` or later; the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md) ("expected to start at `0002`") is now further out of date and will need updating during sprint 11.
