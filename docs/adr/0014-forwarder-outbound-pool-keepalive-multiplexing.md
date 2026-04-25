---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Forwarder outbound connection pool, keepalive, and multiplexing

## Context and Problem Statement

The forwarder role's outbound side spans every transport defined by [`NET-001`](../../specification/002-transports.md): plain DNS over UDP / TCP on port 53, DoT on port 853, DoH over HTTP/2 and HTTP/3, and DoQ on port 853 (per [`NET-012`](../../specification/002-transports.md)). Each transport has different connection semantics: UDP is connectionless; TCP and DoT support pipelining over a single connection; HTTP/2, HTTP/3, and DoQ support stream multiplexing over a single underlying connection.

The recursive resolver's outbound TCP / DoT pool was fixed by [`NET-048`](../../specification/002-transports.md) through [`NET-053`](../../specification/002-transports.md) (recorded in [`0011-outbound-connection-pool.md`](0011-outbound-connection-pool.md)) and the recursive ADoT session-ticket cache by [`NET-043`](../../specification/002-transports.md) through [`NET-047`](../../specification/002-transports.md) (recorded in [`0010-adot-session-ticket-cache.md`](0010-adot-session-ticket-cache.md)). Both are scoped per-`(NS, IP)` (and per-transport for the connection pool), reflecting the recursive resolver's iteration model.

The forwarder's model differs: the operator declares discrete `[[forwarder.forward_zone.upstream]]` entries, each potentially carrying distinct trust anchor (per [`SEC-047`](../../specification/003-crypto-policy.md)), mTLS material, SPKI pinning (per [`SEC-053`](../../specification/003-crypto-policy.md)), `server_name` override (per [`SEC-052`](../../specification/003-crypto-policy.md)), `weight` (per [`FWD-035`](../../specification/014-forward-zones.md)), or other sub-keys. Two upstream entries declaring the same `address`, `port`, and `transport` may be operationally distinct (different ACL bindings, different mTLS clients, different weights). The pool scope must therefore align with the operator-declared upstream entry, not with the network-level `(address, port, transport)` triple.

The remaining open question — "Outbound connection pooling, keepalive, and multiplexing (forwarder)" in [`002-transports.md §5`](../../specification/002-transports.md) — required settling six related sub-questions:

1. **Pool scope** — per-`(NS, IP, transport)` (recursive's choice) or per-upstream-entry (the forwarder's natural unit).
2. **Per-transport pool model** — UDP (no pool), TCP / DoT (pipelining), HTTP/2 (stream multiplexing), HTTP/3 (QUIC stream multiplexing), DoQ (QUIC stream multiplexing).
3. **Pool size bounds and queue** — per-pool cap, per-connection cap (in-flight queries or streams), global cap, queue depth.
4. **Idle keepalive per transport** — TCP-level keepalive (edns-tcp-keepalive); HTTP/2, HTTP/3 PING; QUIC PING.
5. **Multiplexing caps** — server-advertised vs. client-side; how to combine.
6. **TLS / QUIC ticket cache** — same per-`(upstream-entry, IP)` adaptation of [`NET-043`](../../specification/002-transports.md) through [`NET-047`](../../specification/002-transports.md).
7. **Invalidation triggers per transport** — RST/FIN, GOAWAY, CONNECTION_CLOSE, TLS errors, idle expiry, admin drain.

The decisions had to compose with the recursive-side pool ([`NET-048`](../../specification/002-transports.md) through [`NET-053`](../../specification/002-transports.md)) so that shared semantics (TCP pipelining under [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766), edns-tcp-keepalive under [RFC 7828](https://www.rfc-editor.org/rfc/rfc7828)) are not duplicated; with the recursive-side ticket cache ([`NET-043`](../../specification/002-transports.md) through [`NET-047`](../../specification/002-transports.md)) for the encrypted transports; and with the forwarder upstream balancing under [`FWD-032`](../../specification/014-forward-zones.md) through [`FWD-038`](../../specification/014-forward-zones.md), so that pool and balance interact cleanly.

## Decision Drivers

- **Per-upstream-entry granularity**. The forwarder's operator model is per-entry; the pool scope must match it.
- **Hot-path performance** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). For HTTP/2, HTTP/3, and DoQ, stream multiplexing is the dominant performance lever; the design must use it.
- **Bounded resource use**. Connections, streams, and queue depth must all be bounded against unbounded growth under adversarial conditions.
- **Cooperative idle keepalive**. RFC 7828 on TCP-based transports; HTTP/2 / HTTP/3 / QUIC PING on stream-based transports — each transport's native cooperative mechanism MUST be used.
- **DRY across recursive and forwarder pools**. The shared semantics (TCP pipelining, edns-tcp-keepalive, ticket cache) are referenced from the recursive policy rather than restated, reducing the surface for divergence between the two policies.

## Considered Options

### A. Pool scope

- **Per-upstream-entry (chosen).** Aligns with the forwarder's operator model. Two upstream entries with same `address`, `port`, `transport` but different operator-declared sub-keys (TLS overrides, mTLS, weights) get independent pools. Avoids cross-entry cross-pollination of state.
- **Per-`(address, port, transport)` triple (recursive's scope).** Saves marginal memory by sharing connections across operator-declared entries; risks state confusion when entries differ in TLS / mTLS / weight.
- **Per-rule.** Even more shared; loses the per-entry granularity that the operator explicitly chose.

### B. Per-transport pool model

- **UDP no-pool; TCP / DoT pipelining (referencing `NET-048`–`NET-053`); HTTP/2 / HTTP/3 / DoQ stream multiplexing (chosen).** Each transport uses its native concurrency primitive; UDP is correctly identified as connectionless.
- **Treat all transports uniformly as connection pools without multiplexing.** Fails to use HTTP/2 / HTTP/3 / DoQ's stream-multiplexing primitive; one query per connection on those transports is a serious performance regression.
- **Treat HTTP/2 / HTTP/3 / DoQ as connection pools without limits on streams.** Unbounded streams on a single connection is a DoS vector against the upstream and against Heimdall's own resource budget.

### C. Pool size bounds

- **Per-pool cap + per-connection cap (in-flight queries or streams) + global cap + bounded FIFO queue (chosen).** Three orthogonal bounds; matches the recursive pool's structure under [`NET-048`](../../specification/002-transports.md) extended for stream multiplexing.
- **Per-pool cap only.** Cannot bound stream multiplexing; a single connection could carry thousands of streams.
- **Connection-level only (no per-stream cap).** Same defect: stream multiplexing unbounded.
- **No queue (drop on cap).** Wastes the "wait briefly for capacity" hot-path optimisation; converts brief contention into immediate failures.

### D. Idle keepalive

- **TCP / DoT: edns-tcp-keepalive per `NET-049` / `NET-050`. HTTP/2 / HTTP/3 / DoQ: native PING + operational TTL (chosen).** Each transport's native keepalive primitive is used; default operational TTL covers the no-PING case.
- **edns-tcp-keepalive only.** Not applicable to HTTP/2 / HTTP/3 / DoQ; would leave those transports with no keepalive policy.
- **Native PING only (no TTL fallback).** Connections without recent activity could be silently broken; the periodic PING discipline must be triggered by an idle timer.

### E. Multiplexing caps

- **Server-advertised cap AND client-side cap, smaller-wins (chosen).** Honours the server's stated limit (RFC 9113 `SETTINGS_MAX_CONCURRENT_STREAMS`, RFC 9000 `initial_max_streams_bidi`); applies the client-side operator-configurable cap as an additional bound.
- **Client-side only.** Ignores the server's signal; the server may stop accepting new streams when the cap is exceeded, leading to errors.
- **Server-advertised only.** Some servers advertise generous caps; the resolver's own resource budget must constrain the multiplexing.

### F. TLS / QUIC ticket cache

- **Per-`(upstream-entry, IP)` adaptation of `NET-043`–`NET-047` (chosen).** Reuses the recursive-side ticket-cache policy with the appropriate scope substitution. DRY.
- **Independent forwarder ticket cache.** Duplicates the recursive policy without reason.
- **Shared with recursive cache.** Mixes the two operator models; the per-upstream-entry vs per-NS scoping divergence makes this awkward and error-prone.

### G. Invalidation triggers per transport

- **TCP / DoT: per `NET-052`. HTTP/2: + GOAWAY. HTTP/3 / DoQ: + CONNECTION_CLOSE. All transports: idle expiry, admin drain (chosen).** Each transport's native close signals are honoured; pending queries reissued.
- **Idle / admin only.** Misses GOAWAY / CONNECTION_CLOSE; resolver continues writing to a closed connection.
- **TCP-level only.** Misses HTTP/2 / HTTP/3 / DoQ-level signals.

## Decision Outcome

**A. Scope.** Per-upstream-entry, per [`NET-054`](../../specification/002-transports.md).

**B. Per-transport pool model.** UDP no-pool; TCP / DoT pipelining (semantics of [`NET-048`](../../specification/002-transports.md)–[`NET-053`](../../specification/002-transports.md)); HTTP/2, HTTP/3, DoQ stream multiplexing, per [`NET-055`](../../specification/002-transports.md).

**C. Bounds.** Per-pool cap + per-connection cap + global cap + bounded FIFO queue, per [`NET-056`](../../specification/002-transports.md). Numeric defaults tracked as open questions.

**D. Keepalive.** TCP / DoT via edns-tcp-keepalive (`NET-049` / `NET-050`); HTTP/2 / HTTP/3 / DoQ via native PING with operational TTL fallback, per [`NET-057`](../../specification/002-transports.md).

**E. Multiplexing.** Server-advertised cap AND client-side cap, smaller wins, per [`NET-058`](../../specification/002-transports.md).

**F. Ticket cache.** Per-`(upstream-entry, IP)` adaptation of [`NET-043`](../../specification/002-transports.md)–[`NET-047`](../../specification/002-transports.md), per [`NET-059`](../../specification/002-transports.md).

**G. Invalidation triggers.** Per-transport: TCP / DoT per [`NET-052`](../../specification/002-transports.md); HTTP/2 + GOAWAY; HTTP/3 / DoQ + CONNECTION_CLOSE; common idle expiry + admin drain, per [`NET-060`](../../specification/002-transports.md).

**H. Telemetry.** Structured events under [`THREAT-080`](../../specification/007-threat-model.md) extended for stream-based events (GOAWAY, CONNECTION_CLOSE, multiplexing cap reached), per [`NET-061`](../../specification/002-transports.md).

### Rejection rationale

The per-`(address, port, transport)` scope was rejected because the forwarder's operator-declared upstream entries can differ in dimensions that the network triple does not capture. Two entries with the same `(address, port, transport)` may have different `trust_anchor` sub-keys (one against a public CA bundle, another against a private PKI), different `spki_pins`, different `server_name` overrides, or different `weight` values; sharing connection state across them would mix incompatible TLS configurations.

The "treat all transports uniformly as connection pools without multiplexing" option was rejected because it discards the dominant performance primitive of HTTP/2, HTTP/3, and DoQ. A DoH/H2 forwarder upstream that limits itself to one query per connection would consume an order of magnitude more sockets than necessary and lose the latency benefit of stream multiplexing.

The "no per-stream cap" option was rejected because unbounded streams on a single connection is a denial-of-resource vector; the server's `SETTINGS_MAX_CONCURRENT_STREAMS` and `initial_max_streams_bidi` are caps the server expects clients to respect, and the client-side cap is the resolver's own budget.

The "no queue" option was rejected because brief contention (for example, during traffic bursts) is normal and queue depth absorbs it without converting bursts into failures. Bounded queue depth keeps the worst-case memory bounded.

The "edns-tcp-keepalive only" option was rejected because HTTP/2, HTTP/3, and DoQ have their own native idle-detection primitives (PING frames); using edns-tcp-keepalive on those transports would conflict with the protocol layering.

The "native PING only" option was rejected because PING traffic must itself be triggered by an idle timer; without a TTL, the resolver has no signal to start sending PING.

The "client-side cap only" option was rejected because servers expect clients to honour `SETTINGS_MAX_CONCURRENT_STREAMS` and similar; ignoring the server's signal causes stream-creation errors that the cap is designed to prevent.

The "shared ticket cache with recursive" option was rejected because the recursive cache is per-`(NS, IP)` and the forwarder cache is per-`(upstream-entry, IP)`; a unified cache would have to choose one scoping or carry both, neither of which is cleaner than two independent caches.

The "idle / admin only" invalidation set was rejected because GOAWAY (HTTP/2) and CONNECTION_CLOSE (QUIC) are server-initiated close signals that arrive immediately; ignoring them and waiting for the idle timer wastes a query attempt that will fail synchronously.

## Consequences

### Closure

The "Outbound connection pooling, keepalive, and multiplexing (forwarder)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). One operational-default open question is added: the numeric defaults of the per-pool cap, the per-connection in-flight or stream cap, the global cap, the queue depth, the idle-keepalive timeout for HTTP/2 / HTTP/3 / QUIC outbound connections, and the per-transport client-side stream caps.

### Resource budget (illustrative)

Assuming representative numeric defaults (to be specified): per-pool cap of 4 connections, per-connection stream cap of 100 (for stream-based transports), global cap of 4096 connections, average per-connection memory ≈ 24 KiB (TCP + TLS state for `"dot"`; QUIC state for `"doq"` / `"doh"` over H3):

```
4096 connections × 24 KiB ≈ 96 MiB
4096 file descriptors
4096 × 100 streams ≈ 410k concurrent streams (for stream-based transports)
```

Numeric defaults will be calibrated against measurement; the structure is the normative invariant.

### Non-consequences (deliberate scope limits)

- **Forwarder UDP retransmission and cookie state.** UDP is connectionless; retries follow the standard DNS retry semantics; no pool state.
- **Forwarder UDP-to-TCP fallback on truncation.** Governed separately by the existing PROTO-* truncation policy; not part of pool design.
- **DoH / H2 vs H3 selection per upstream.** Tracked as a separate open question in [`014-forward-zones.md §5`](../../specification/014-forward-zones.md).
- **Cross-instance pool sharing.** Each Heimdall instance maintains its own forwarder pools; no inter-instance coordination.
- **Adaptive caps based on observed server behaviour.** The current design uses operator-configured static caps. Adaptation is out of scope.

### Numbering

This ADR takes the sequence number `0014`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
