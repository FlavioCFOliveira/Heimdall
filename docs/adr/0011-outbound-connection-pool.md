---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Outbound connection pool policy (ADoT and plain TCP on port 53, recursive resolver outbound)

## Context and Problem Statement

The recursive resolver role contacts authoritative servers via plain DNS over TCP on port 53 (under [`NET-019`](../../specification/002-transports.md)) and via ADoT on port 853 (under [`NET-020`](../../specification/002-transports.md), [`NET-024`](../../specification/002-transports.md)). Each TCP-based contact carries a TCP-handshake cost, and each ADoT contact carries the additional cost of a TLS 1.3 handshake. For high-frequency authoritative contacts (large public TLDs, popular zones), opening a fresh connection per query would multiply per-query latency and CPU cost without operational benefit; connection reuse via pipelining ([RFC 7766](https://www.rfc-editor.org/rfc/rfc7766)) and idle-keepalive ([RFC 7828](https://www.rfc-editor.org/rfc/rfc7828)) is the standard amortisation pattern in DNS resolvers.

The remaining open question was the connection-pool policy used by Heimdall as an outbound TCP / DoT client. Five sub-questions had to be settled jointly:

1. **Pool scope** — per server IP, per name server canonical name, per `(NS, IP)` pair, or per `(NS, IP, transport)` triple.
2. **Pool size bounds and eviction** — per-pool cap, global cap, eviction policy, queue behaviour on cap.
3. **Idle keepalive lifetime** — fixed default, server-controlled, or hybrid.
4. **edns-tcp-keepalive interaction** — mandatory advertisement, response handling.
5. **Connection invalidation triggers** — what events cause a pooled connection to be closed.

The decisions had to compose with [`PROTO-014`](../../specification/006-protocol-conformance.md) (edns-tcp-keepalive baseline), with [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) (TCP for DNS, pipelining), with [RFC 7828](https://www.rfc-editor.org/rfc/rfc7828) (edns-tcp-keepalive option semantics), with the inbound resource-limit family ([`THREAT-061`](../../specification/007-threat-model.md) through [`THREAT-078`](../../specification/007-threat-model.md)), with the structured-event taxonomy of [`THREAT-080`](../../specification/007-threat-model.md), and with the per-`(NS, IP)` scoping established for ADoT capability discovery and ticket caching ([`NET-035`](../../specification/002-transports.md), [`NET-043`](../../specification/002-transports.md)).

## Decision Drivers

- **Performance** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Connection reuse + pipelining is the dominant optimisation for high-frequency authoritative contact; without pooling, each query pays a TCP handshake + (for ADoT) a TLS handshake.
- **Bounded resource use** (cf. [`THREAT-061`](../../specification/007-threat-model.md) through [`THREAT-078`](../../specification/007-threat-model.md)). Outbound connections consume sockets, file descriptors, memory; an unbounded pool is a denial-of-resources vector.
- **Symmetry with inbound caps**. The inbound resource-limit family bounds per-connection and per-listener concurrency; the outbound family should mirror this discipline to produce a coherent system-wide bound on Heimdall's network footprint.
- **Server-controlled idle lifetime**. RFC 7828 edns-tcp-keepalive lets the server signal its preferred idle-timeout; honouring this signal is the IETF-aligned cooperative pattern.
- **Robust recovery**. Authoritatives close connections (RST, FIN, TLS error, server restart, key rotation); the pool must recover transparently without losing in-flight queries.
- **Operator observability**. Pool overflow, idle-timeout closure, slow-server disconnect, and admin-RPC drain are all operationally significant events that should surface as structured signals under [`THREAT-080`](../../specification/007-threat-model.md).

## Considered Options

### A. Pool scope

- **Per `(NS, IP, transport)` triple (chosen).** Conservative and correct. Plain TCP and DoT are different sockets with different state (TLS); even for the same `(NS, IP)`, the two are independent connections. Aligns with the per-`(NS, IP)` scoping of [`NET-035`](../../specification/002-transports.md) and [`NET-043`](../../specification/002-transports.md).
- **Per `(NS, IP)` pair (transport collapsed).** Mixes plain-TCP and DoT connections in the same pool, which makes per-pool caps less precise; an operator who wants to bound DoT connections separately from plain-TCP cannot do so.
- **Per NS canonical name.** Loses IP-level granularity; a single broken IP can saturate the pool against the NS.
- **Per IP only.** Loses NS context.
- **No pooling.** Catastrophic for performance; rejected outright.

### B. Pool size bounds

- **Per-pool cap + global cap + bounded FIFO queue (chosen).** Per-pool cap supports parallel queries to a popular authoritative; global cap bounds total outbound footprint; bounded queue prevents backpressure from accumulating unbounded waiting queries.
- **Per-pool cap only.** Total outbound footprint grows with the cardinality of contacted authoritatives; under adversarial conditions this is unbounded.
- **Global cap only.** A single popular authoritative could starve all other pools.
- **Unbounded.** Standard DoS vector; rejected on the same grounds as [`THREAT-066`](../../specification/007-threat-model.md).

### C. Idle keepalive lifetime

- **Default operational timeout, overridden by edns-tcp-keepalive in server response (chosen).** Honours the server's signal where one is given; falls back to a reasonable default otherwise. RFC 7828 cooperation with bounded fallback.
- **Fixed numeric (no server override).** Ignores the server's preference; an authoritative that wants short idle (because it is resource-constrained) cannot signal that to Heimdall.
- **Server-controlled only (no default).** Servers that do not include edns-tcp-keepalive leave Heimdall with no idle policy; either no idle (close immediately) or unbounded idle (resource leak).
- **Operator-tunable per-NS.** No clear use case; the fallback default + server override covers the operational range.

### D. edns-tcp-keepalive interaction

- **Mandatory outbound advertisement; mandatory honour of server response value (chosen).** Heimdall always sends the option in TCP-based outbound queries; when the response carries it, the `TIMEOUT` field replaces the default. `TIMEOUT = 0` is honoured as a request to close after the in-flight query.
- **Outbound advertisement only (ignore server response).** Misses the server's signal; defeats the cooperative purpose of the option.
- **No outbound advertisement.** Conflicts with `PROTO-014` already in force.

### E. Invalidation triggers

- **TCP RST/FIN + TLS error + idle expiry + admin-RPC (chosen).** Four orthogonal triggers covering server-initiated close, TLS-layer failure, time-based expiry, and operator-initiated drain.
- **Idle expiry only.** Misses server-initiated close; the resolver continues to write to a closed socket until the next query, wasting a query attempt.
- **TCP RST/FIN only.** Misses time-based expiry; idle connections accumulate forever.
- **Coupled with ticket invalidation under [`NET-046`](../../specification/002-transports.md).** Tempting (TLS errors invalidate both ticket and connection), but the two operate at different layers and should remain conceptually separable; the chosen triggers under [`NET-052`](../../specification/002-transports.md) reference [`NET-046`](../../specification/002-transports.md) for the TLS-error trigger class without coupling the two surfaces.

## Decision Outcome

**A. Scope.** Per `(NS, IP, transport)` triple, per [`NET-048`](../../specification/002-transports.md).

**B. Bounds.** Per-pool cap + global cap + bounded FIFO queue, oldest-idle-first eviction, per [`NET-048`](../../specification/002-transports.md). Numeric defaults tracked as open questions.

**C. Idle keepalive.** Default operational timeout (numeric default tracked as open question) with edns-tcp-keepalive override per [`NET-049`](../../specification/002-transports.md) and [`NET-050`](../../specification/002-transports.md).

**D. edns-tcp-keepalive.** Mandatory outbound advertisement; server's `TIMEOUT` honoured (including `TIMEOUT = 0` as immediate-close-after-query), per [`NET-050`](../../specification/002-transports.md).

**E. Pipelining and per-connection cap.** Pipelining permitted with a bounded per-connection in-flight cap, per [`NET-051`](../../specification/002-transports.md). Numeric default tracked as open question.

**F. Invalidation triggers.** TCP RST/FIN + TLS error + idle expiry + admin-RPC, per [`NET-052`](../../specification/002-transports.md). In-flight queries on closed connections are re-issued on a fresh connection subject to the standard retry budget.

**G. Symmetry with inbound resource limits.** Outbound caps mirror [`THREAT-062`](../../specification/007-threat-model.md), [`THREAT-063`](../../specification/007-threat-model.md), and [`THREAT-068`](../../specification/007-threat-model.md); structured events emitted under [`THREAT-080`](../../specification/007-threat-model.md), per [`NET-053`](../../specification/002-transports.md).

### Rejection rationale

The **per-`(NS, IP)` (transport collapsed)** option was rejected because plain-TCP and DoT connections are different objects (different ports, different kernel-level sockets, different TLS state); collapsing them into a single pool obscures the resource accounting and prevents independent caps. The chosen per-`(NS, IP, transport)` triple keeps the two transports in separate pools that can be sized independently.

The **per-pool-only** and **global-only** size bounds were rejected for the same reasons in the [`0010-adot-session-ticket-cache.md`](0010-adot-session-ticket-cache.md) cache-bounds section: per-pool-only does not bound total memory/FD footprint; global-only allows a single popular authoritative to starve other pools.

The **no-pooling** option was rejected on performance grounds. Each query would pay a TCP handshake; ADoT queries would additionally pay a TLS handshake. For an iterative resolver doing thousands of queries per second to popular authoritatives, the cost is prohibitive.

The **fixed-numeric idle timeout** was rejected because it ignores the server's signal. RFC 7828 was designed precisely to let servers tell clients how long they want connections kept alive; a client that ignores the signal is non-cooperative.

The **outbound-advertisement-only** option was rejected because it defeats the cooperative purpose of edns-tcp-keepalive. A client that advertises the option but ignores the server's response value is sending a half-faithful signal; the spec compels Heimdall to honour the response value.

The **idle-expiry-only** invalidation was rejected because TCP RST and FIN are server-initiated close signals that arrive immediately; ignoring them and waiting for the idle timer to expire wastes a query attempt that will fail synchronously when Heimdall tries to write to the closed socket. The chosen design treats RST/FIN as immediate eviction triggers.

## Consequences

### Pool lifecycle (illustrative)

For an outbound query against zone `Z` to be sent to authoritative `(NS, IP)`:

1. Determine `transport` — `"dot"` if `(NS, IP)` has positive ADoT capability evidence under [`NET-029`](../../specification/002-transports.md) through [`NET-031`](../../specification/002-transports.md) and is not in the ADoT-broken cache under [`NET-038`](../../specification/002-transports.md); else `"tcp"` (over the plain-DNS baseline of [`NET-019`](../../specification/002-transports.md)).
2. Lookup `(NS, IP, transport)` pool. If an idle connection is available with in-flight count < per-connection cap: use it.
3. If pool is below the per-pool cap: open a new connection (TCP handshake; TLS handshake for `"dot"`, with [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) validation; potential [`NET-043`](../../specification/002-transports.md) ticket reuse).
4. If pool is at the per-pool cap: enqueue the query in the per-pool FIFO queue; when an in-flight slot becomes available on an existing connection or the pool drops below cap, dequeue and serve.
5. If the per-pool queue is at its bound: emit a structured event under [`THREAT-080`](../../specification/007-threat-model.md); the resolver's standard retry / SERVFAIL pipeline applies.
6. Send query with edns-tcp-keepalive option per [`NET-050`](../../specification/002-transports.md).
7. On response: parse, deliver to resolver pipeline; if response carried edns-tcp-keepalive option, update connection's idle-timeout to the signalled `TIMEOUT` value (or close after delivery if `TIMEOUT = 0`).
8. After in-flight count reaches zero on a connection, start the idle timer. On expiry: close and remove from pool.
9. Concurrent triggers (RST/FIN, TLS error, admin drain) close the connection at any time per [`NET-052`](../../specification/002-transports.md); in-flight queries reissued.

### Memory / FD budget (illustrative, at to-be-specified defaults)

Per-pool cap = 8, global cap = 2048, average per-connection memory ≈ 16 KiB (TCP buffers + TLS state where applicable):

```
2048 connections × 16 KiB ≈ 32 MiB
2048 file descriptors
```

Actual budgets depend on the numeric defaults fixed by the open question.

### Closure

The "Outbound connection pool policy for ADoT and for plain TCP on port 53 (recursive resolver)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md). One operational-default open question is added in its place: the numeric defaults of the per-pool cap, the global cap, the queue depth, the idle-keepalive timeout, and the per-connection in-flight cap.

### Non-consequences (deliberate scope limits)

- **Outbound connection pool for the forwarder upstream side.** The forwarder's outbound connection pooling is tracked separately under "Outbound connection pooling, keepalive, and multiplexing (forwarder)" in [`002-transports.md §5`](../../specification/002-transports.md). The two scopes are deliberately separated because the forwarder's outbound side spans more transports (DoH/H2, DoH/H3, DoQ in addition to TCP and DoT) and because the forwarder operates on per-upstream operator declarations rather than on per-NS recursive iteration.
- **UDP retry pooling.** UDP is connectionless; this decision concerns only TCP-based connections (TCP/53 and DoT/853).
- **DoH/H2 and DoH/H3 multiplexing on the recursive outbound side.** Recursive ADoH is out of scope per [`NET-021`](../../specification/002-transports.md); when DoH/H2 or DoH/H3 are reconsidered for the recursive outbound side, multiplexing semantics will need a separate decision (HTTP/2 stream multiplexing differs from TCP pipelining).
- **DoQ for the recursive outbound side.** DoQ for authoritative contact is out of scope per [`NET-021`](../../specification/002-transports.md); when reconsidered, QUIC-stream-based pooling will need a separate decision.
- **Cross-instance pool sharing.** Multiple Heimdall instances do not share pools; each instance maintains its own. Inter-instance sharing would require a coordination layer outside the scope of this decision.

### Numbering

This ADR takes the sequence number `0011`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
