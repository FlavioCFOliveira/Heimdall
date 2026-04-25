---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# ADoT session-ticket cache policy (client-side, outbound)

## Context and Problem Statement

The recursive resolver role contacts authoritative servers via ADoT under [`NET-020`](../../specification/002-transports.md), [`NET-022`](../../specification/002-transports.md), and [`NET-024`](../../specification/002-transports.md) when capability evidence is available under [`NET-029`](../../specification/002-transports.md) through [`NET-031`](../../specification/002-transports.md) and the outbound certificate validation policy under [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) is satisfied. Each new TLS 1.3 handshake to an authoritative carries the cost of an asymmetric-cryptography exchange (key share + signature verification on the leaf certificate + chain verification) and a round trip beyond what session resumption could save. TLS 1.3 NewSessionTicket ([RFC 8446 §4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1)) provides a stateless mechanism by which the server delivers an opaque ticket to the client; the client may present that ticket on a subsequent handshake as a pre-shared key, skipping the certificate-handling work and reducing the handshake to a 0-RTT or 1-RTT exchange (depending on whether early data is permitted, which it is not for Heimdall outbound under [`NET-017`](../../specification/002-transports.md)).

The remaining open question was the cache policy used by Heimdall as an ADoT client to manage tickets received from authoritatives. Four sub-questions had to be settled jointly:

1. **Cache scope** — per server IP, per name server canonical name, per `(NS, IP)` pair, or none.
2. **Ticket TTL semantics** — server-issued only, capped by an operator parameter, or fixed.
3. **Cache-size bounds and eviction** — per-pair cap, global cap, eviction policy.
4. **Invalidation triggers** — what events cause a cached ticket to be discarded.

The decisions had to compose with the per-NS scoping established by [`NET-035`](../../specification/002-transports.md) for capability discovery, with the outbound certificate validation pipeline of [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md), with the inbound server-side ticket policy of [`SEC-008`](../../specification/003-crypto-policy.md) through [`SEC-011`](../../specification/003-crypto-policy.md) (which is independent and serves the inverse direction), and with the bounded-state and observability discipline of [`THREAT-080`](../../specification/007-threat-model.md).

## Decision Drivers

- **Performance** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Each saved full handshake removes asymmetric crypto and a round trip; for high-frequency contacts to popular authoritatives, the saving is material.
- **Correctness against authoritative deployment shapes**. Different IPs of the same authoritative may be served by independent TLS terminations with independent TEKs. A ticket from one IP may not validate at another IP; the cache scope must accommodate this.
- **Bounded memory** (cf. [`THREAT-061`](../../specification/007-threat-model.md) through [`THREAT-078`](../../specification/007-threat-model.md)). Unbounded ticket caches are a denial-of-service vector via memory exhaustion.
- **Graceful recovery from server-side TEK rotation**. When the authoritative rotates its TEK past the acceptance window, all previously-issued tickets become invalid; Heimdall must detect this without operator intervention.
- **Server-side independence** (cf. [`SEC-008`](../../specification/003-crypto-policy.md) through [`SEC-011`](../../specification/003-crypto-policy.md)). The client-side outbound cache and the server-side inbound TEK store are different surfaces, and conflating them would create a class of cross-direction misconfigurations.

## Considered Options

### A. Cache scope

- **Per `(NS, IP)` pair (chosen).** Conservative against authoritatives whose IPs do not share TLS termination state. Avoids cross-IP ticket-reuse attempts that would silently fail and waste a round trip.
- **Per NS canonical name (cache shared across IPs of the same NS).** Saves marginal memory, risks cross-IP rejection, generates needless `decrypt_error` recovery rounds.
- **Per IP only.** Loses the NS context; misaligns with the per-NS scoping of [`NET-035`](../../specification/002-transports.md).
- **No cache.** Simplest, eliminates the performance benefit; every contact pays a full handshake.

### B. Ticket TTL semantics

- **Smaller of server-issued `ticket_lifetime` and operator-configurable cap (chosen).** Honours the server's intent while bounding the maximum reuse window for operator policy reasons.
- **Server-issued only.** Honours the server's intent without an operator-side bound; an authoritative that issues tickets with the protocol-maximum 7-day lifetime can have its tickets cached for 7 days.
- **Fixed numeric (e.g., 1 hour).** Predictable but ignores server intent; an authoritative that issues short-lived tickets to compel re-handshake would be overridden.

### C. Cache size bounds and eviction

- **Per-pair cap + global cap, both LRU (chosen).** Per-pair cap supports rotation and parallel sessions for a single authoritative; global cap bounds the total memory footprint regardless of the cardinality of contacted authoritatives.
- **Per-pair cap only, no global cap.** Memory grows with the number of distinct authoritatives contacted; unbounded under adversarial conditions.
- **Global cap only, no per-pair cap.** Single authoritative could consume the entire cache by issuing many tickets; starves the cache for other authoritatives.
- **No bounds (unbounded cache).** DoS vector via memory exhaustion; rejected for the same reason as in [`THREAT-066`](../../specification/007-threat-model.md).

### D. Invalidation triggers

- **Cert change (SPKI digest mismatch) + decrypt_error TLS alert + admin-RPC explicit invalidation (chosen).** Three orthogonal triggers that together cover certificate-rotation events, TEK-rotation events, and operator-driven cache flushes.
- **decrypt_error only.** Misses the cert-change case (authoritative has rotated cert; Heimdall would present a stale ticket then receive the new cert; the ticket would be accepted by the server's TEK but signed against a different key the cache does not associate with).
- **Time-based only (TTL expiry; no event-driven invalidation).** Misses both rotation cases until the TTL expires; the window of stale-ticket presentation is unbounded by ticket lifetime alone.

## Decision Outcome

**A. Scope.** Per `(NS, IP)` pair, per [`NET-043`](../../specification/002-transports.md).

**B. TTL.** Smaller of server-issued `ticket_lifetime` and operator-configurable cap, per [`NET-044`](../../specification/002-transports.md). Numeric default of the cap tracked as an open question.

**C. Bounds.** Per-pair cap + global cap, both LRU, per [`NET-045`](../../specification/002-transports.md). Numeric defaults of both caps tracked as open questions.

**D. Invalidation.** SPKI mismatch + decrypt_error + admin-RPC, per [`NET-046`](../../specification/002-transports.md).

**E. Independence from server-side TEK policy.** Client-side outbound cache and server-side inbound TEK store are separate surfaces, per [`NET-047`](../../specification/002-transports.md). They MUST NOT be combined.

**F. Permissive existence (`MAY`).** Heimdall MAY maintain the cache; the implementation default is to enable it for the performance benefit, in line with the performance principle of [`../../CLAUDE.md`](../../CLAUDE.md). An operator who prefers to disable client-side resumption (for example, for forward-secrecy auditing reasons) MAY do so; the operator-side disable knob is an operational detail and is not separately tracked here.

### Rejection rationale — scope

The **per-NS** option was rejected on correctness grounds. Authoritative deployments routinely place different IPs behind independent TLS terminations: anycast deployments where each PoP runs its own TLS stack with its own TEK; load-balanced deployments where each backend instance has its own TEK; provider-of-providers shapes where the same NS canonical name is served by multiple operators with no shared state. A per-NS cache would attempt to present a ticket issued by IP_x at IP_y, the IP_y server would reject it via `decrypt_error`, and Heimdall would fall back to a full handshake — a wasted round trip that the per-`(NS, IP)` scope avoids by construction.

The **per-IP only** option was rejected because it discards the NS context that [`NET-035`](../../specification/002-transports.md) preserves for capability evidence. Operationally, the resolver's primary unit of identity is the NS canonical name; pairing the cache scope with that unit (and adding the IP as a sub-key) keeps the cache aligned with the rest of the resolver's state model.

The **no-cache** option was rejected on performance grounds. For high-frequency authoritatives (large public TLDs, popular zones), the saving is material; eliminating the cache to simplify the implementation has no compensating benefit.

### Rejection rationale — TTL

The **server-issued-only** option was rejected because it leaves the maximum ticket-reuse window solely in the authoritative's control. An authoritative that issues 7-day tickets (the protocol maximum) effectively asks Heimdall to retain its session state for 7 days; an operator-side cap allows the resolver to enforce its own bounded-state policy without depending on every authoritative to issue conservative lifetimes.

The **fixed numeric** option was rejected because it overrides the server's intent. An authoritative that issues short-lived tickets has typically chosen to do so deliberately; honouring the smaller of the two values respects both sides.

### Rejection rationale — bounds

The **per-pair cap only** option was rejected because it does not bound the cache's total memory footprint as the number of contacted authoritatives grows. An adversarial pattern that compels Heimdall to contact many distinct authoritatives (a query for a name in a long delegation chain, for example) could grow the cache without limit.

The **global cap only** option was rejected because a single authoritative that issues many tickets (rotation, parallel connections, error-recovery scenarios) could fill the cache and starve other authoritatives. Both caps acting together produce a fair and bounded design.

The **no bounds** option was rejected on standard DoS-resistance grounds, consistent with [`THREAT-066`](../../specification/007-threat-model.md).

### Rejection rationale — invalidation

The **decrypt_error only** option was rejected because it misses the certificate-rotation case. An authoritative that has rotated its certificate but not its TEK would still accept the cached ticket (the ticket is encrypted with the TEK, not the cert); Heimdall would resume the session against the new certificate without realising that the leaf SPKI no longer matches what was current when the ticket was cached, missing an opportunity to re-validate the cert chain freshly. The chosen design forces a full handshake (and therefore a fresh cert validation) when the SPKI digest changes, even if the ticket itself would still decrypt.

The **time-based only** option was rejected because it leaves stale tickets in the cache until the TTL expires. In the cert-rotation case, that is up to 7 days under the protocol maximum (or up to the operator-configurable cap); the chosen event-driven triggers reduce the stale-ticket window to the next handshake against the cached pair.

## Consequences

### Cache lifecycle

The cache state per `(NS, IP)` pair consists of: a list of cached tickets (each with its server-issued `ticket_lifetime`, the time it was received, and the SHA-256 digest of the leaf certificate's SubjectPublicKeyInfo at the time of caching); LRU metadata (last-used timestamp); a per-pair size counter against the per-pair cap.

On outbound TLS handshake to `(NS, IP)`:

1. Look up `(NS, IP)` in the cache. If no entry, full handshake; on success, store any NewSessionTicket received.
2. If an entry exists with at least one ticket whose effective TTL has not expired, present the most recently issued (or LRU-elected) such ticket as a pre-shared key per [RFC 8446 §4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11).
3. After the handshake completes:
   - If the ticket was accepted and the leaf certificate's SPKI digest matches the recorded digest: resumption succeeded. Store any NewSessionTicket received in the same handshake (subject to the per-pair cap and global cap, with LRU eviction).
   - If the ticket was accepted but the leaf certificate's SPKI digest differs from the recorded digest: the resumption itself succeeded, but [`NET-046`](../../specification/002-transports.md) (a) applies. The full validation pipeline of [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) MUST have run on the new certificate (it ran during the handshake regardless of resumption), so security properties are intact; the cached ticket and the SPKI-mismatched record are discarded post-handshake to prevent stale-state reuse. Subsequent connections to the same pair start fresh.
   - If the ticket was rejected (decrypt_error, [`NET-046`](../../specification/002-transports.md) (b)): discard the ticket. Heimdall MUST proceed with a full handshake; on success, store any NewSessionTicket received.

### Memory budget (illustrative)

Assuming representative numeric defaults (to be specified in the open question): per-pair cap of 4 tickets, global cap of 8192 pairs, average ticket size of 200 bytes, average per-pair overhead of 64 bytes (LRU metadata + SPKI digest + counters). The cache footprint upper bound is approximately:

```
8192 pairs × (4 tickets × 200 bytes + 64 bytes) = 8192 × (800 + 64) ≈ 7 MB
```

This is an order-of-magnitude bound at the assumed defaults; actual memory use depends on per-implementation overhead and on the cap values fixed by the open question.

### Closure

The "ADoT session-ticket cache policy for authoritative servers (recursive resolver)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). One operational-default open question is added in its place: the numeric defaults of the per-pair cap, the global cap, and the operator-configurable maximum ticket-reuse window cap.

### Non-consequences (deliberate scope limits)

- **Server-side TEK rotation impact.** Whether the authoritative's TEK rotation is communicated through any in-band signal beyond `decrypt_error` is the authoritative's policy and is not visible to Heimdall as a client. Heimdall recovers via the [`NET-046`](../../specification/002-transports.md) (b) trigger.
- **Pre-shared-key (PSK) modes other than ticket-based resumption.** TLS 1.3 supports out-of-band PSKs; the present decision concerns only ticket-based resumption ([RFC 8446 §2.2](https://www.rfc-editor.org/rfc/rfc8446#section-2.2)). Out-of-band PSKs are out of scope.
- **0-RTT (early data).** Outbound 0-RTT is prohibited by [`NET-017`](../../specification/002-transports.md) and [`NET-023`](../../specification/002-transports.md); the cache stores tickets to enable 1-RTT resumption only.
- **Cache persistence across restarts.** Whether the cache is purely in-memory or persists across instance restarts is an implementation detail; persistence would require additional design (encryption-at-rest for opaque tickets, cross-restart trust assumptions) and is out of scope for the present decision.
- **Inter-instance cache sharing.** Multiple Heimdall instances do not share the cache; each instance maintains its own. Inter-instance sharing would require a coordination layer outside the scope of this decision.

### Numbering

This ADR takes the sequence number `0010`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
