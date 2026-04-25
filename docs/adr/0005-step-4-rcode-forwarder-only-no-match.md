---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Step-4 RCODE for the forwarder-only-no-match sub-case

## Context and Problem Statement

[`ROLE-012`](../../specification/001-server-roles.md) in [`001-server-roles.md`](../../specification/001-server-roles.md) requires that, when the four-step query-resolution precedence ([`ROLE-008`](../../specification/001-server-roles.md) through [`ROLE-012`](../../specification/001-server-roles.md)) is exhausted with no active role having served the query, Heimdall MUST return an error response to the client. The specific error code returned in step 4 was however left as an open question: `SERVFAIL`, `REFUSED`, or another response code, and whether the choice is transport-dependent. The general step-4 question was paired with a more specific sub-case open question — "Forwarder-only mode behaviour on no match" — covering the deployment shape where only the forwarder role is active for resolution-fallback (`[forwarder].enabled = true`, `[recursive].enabled = false`) and the query matches no forward-zone rule.

The present decision closes the **specific** sub-case (forwarder-only-no-match) and leaves the **general** step-4 question open for a separate decision (sprint 1 task #7), so that the general decision is made coherently across all step-4 trigger combinations rather than incrementally.

The decision had to settle four sub-questions jointly:

1. **The DNS RCODE returned to the client** in the forwarder-only-no-match sub-case — `REFUSED`, `SERVFAIL`, `NOTIMP`, or another value.
2. **Whether to attach an EDNS(0) Extended DNS Errors (EDE) option** under [`PROTO-012`](../../specification/006-protocol-conformance.md), and if so, which EDE INFO-CODE.
3. **Per-transport consistency** — whether the response is identical on every transport defined in [`002-transports.md`](../../specification/002-transports.md), or transport-dependent.
4. **Scope of the decision** — narrow (forwarder-only-no-match only) or broad (all step-4 cases).

## Decision Drivers

- **Semantic accuracy**. The chosen RCODE must match the actual condition the server is in. Inaccurate RCODEs (e.g., `SERVFAIL` when nothing has failed) mislead clients and complicate diagnosis.
- **Operator policy expressiveness**. The forwarder-only deployment is an explicit operator choice to limit Heimdall's resolution scope to the configured forward-zone rules. The error response should communicate that policy choice, not a malfunction.
- **Client diagnostic clarity** (cf. [`PROTO-012`](../../specification/006-protocol-conformance.md)). [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) provides a standardised structured-diagnostic channel through Extended DNS Errors; using it where a clearly-applicable INFO-CODE exists is the operator-friendly choice.
- **Per-transport uniformity** (cf. [`NET-001`](../../specification/002-transports.md) through [`NET-008`](../../specification/002-transports.md)). The DNS message format is identical across UDP, TCP, DoT, DoH, and DoQ; the response should not introduce semantic divergence at the transport layer.
- **No unintended preemption** of the broader step-4 question. The decision must close the specific forwarder-only sub-case without forcing the same answer onto every other step-4 trigger combination, so that the general question can be deliberated against its own merits.

## Considered Options

### A. RCODE for the forwarder-only-no-match sub-case

- **`REFUSED` (RCODE 5) (chosen).** [RFC 1035 §4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1) defines this as "the name server refuses to perform the specified operation for policy reasons". The forwarder-only-no-match condition is exactly such a policy refusal: the operator's exhaustive enumeration of forward-zone rules did not include the queried name.
- **`SERVFAIL` (RCODE 2).** Defined by RFC 1035 as a server-internal-failure indicator. The condition here is not a failure: nothing has malfunctioned, the configuration simply does not authorise the query.
- **`NOTIMP` (RCODE 4).** Defined by RFC 1035 as "the name server does not support the requested kind of query". Heimdall fully implements DNS query; the issue is name-specific authorisation, not operation-class support.
- **`NXDOMAIN` (RCODE 3).** Implies that the server has authoritatively determined the name does not exist. Heimdall is not authoritative for the name and has not consulted any zone that could answer existence; producing `NXDOMAIN` would be a false statement of authoritative knowledge.
- **`FORMERR` (RCODE 1) or any reserved RCODE.** Each of these has its own specific semantics distinct from the forwarder-only-no-match condition; selection of one would mislead clients on the nature of the response.

### B. EDE INFO-CODE attached to the response

- **EDE 20 "Not Authoritative" (chosen).** Defined by IANA per [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) for the case where the server is not authoritative for the queried name. The forwarder-only-no-match condition is exactly that: Heimdall is not authoritative for the name and is not configured to forward queries for it. The INFO-CODE is applicable to authoritative-style "I'm not the authority" semantics and to forwarder-style "I don't have a path to authority" semantics alike.
- **EDE 18 "Prohibited".** Defined for "the requested operation or query has been administratively prohibited". Carries connotations of active blocking (alongside EDE 15 "Blocked" and EDE 16 "Censored" in the IANA registry). The forwarder-only-no-match condition is closer to "I have no configured path" than "I have explicitly blocked this query"; using EDE 18 would risk triggering client-side anti-censorship heuristics.
- **EDE 28 "Unable To Conform To Policy".** Vague and non-specific; the operator's diagnosis from a packet capture would be improved by a more specific code.
- **EDE 0 "Other Error".** Effectively no diagnostic information; using EDE 0 where a more specific code applies negates the value of the EDE channel.
- **No EDE option on the response.** [`PROTO-012`](../../specification/006-protocol-conformance.md) requires Heimdall to implement EDE; refusing to include an EDE option where a clearly-applicable INFO-CODE exists is leaving operator-visible diagnostic value unused.

### C. Per-transport consistency

- **Identical DNS message bytes on every transport (chosen).** The response RCODE and EDE INFO-CODE are fixed in the DNS message; the message is the same on UDP, TCP, DoT, DoH (HTTP/2 and HTTP/3), and DoQ. Transport-level differences are limited to framing (DoH carries the message in an HTTP body with `application/dns-message` per [`NET-026`](../../specification/002-transports.md); DoQ carries the message on a QUIC stream per [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250); etc.) and do not alter the DNS-level semantics.
- **Transport-dependent variation.** No technical reason supports varying the response by transport, and divergence would multiply the test matrix and the operator-facing surprise budget without a corresponding benefit.

### D. Scope of the present decision

- **Narrow: forwarder-only-no-match only (chosen).** Closes the specific sub-case without preempting the general step-4 decision. The general decision (task #7 in the same sprint) will then either generalise the same answer uniformly to every step-4 trigger combination or differentiate by trigger.
- **Broad: all step-4 cases.** Would preempt task #7's deliberation against its own context (e.g., authoritative-only deployments where the queried name does not match any local zone may have different operator expectations). The "Assume Nothing" principle of [`../../CLAUDE.md`](../../CLAUDE.md) argues against folding two separately-tracked open questions into a single decision without explicit authorisation.

## Decision Outcome

**A. RCODE.** `REFUSED` (RCODE 5), per [`ROLE-024`](../../specification/001-server-roles.md).

**B. EDE.** Extended DNS Errors INFO-CODE `20` ("Not Authoritative"), per [`ROLE-024`](../../specification/001-server-roles.md).

**C. Per-transport consistency.** Identical DNS message bytes across UDP, TCP, DoT, DoH (HTTP/2 and HTTP/3), and DoQ, per [`ROLE-024`](../../specification/001-server-roles.md).

**D. Scope.** Narrow — the forwarder-only-no-match sub-case only. The general step-4 question (covering authoritative-only-no-match and the degenerate all-roles-inactive case) remains tracked in [`001-server-roles.md §4`](../../specification/001-server-roles.md) under "Error code for step 4 of the precedence" and will be resolved separately.

### Rejection rationale — RCODE

`SERVFAIL` was rejected because it carries the semantics of an internal failure. In the forwarder-only-no-match condition, no internal failure has occurred: the server is functioning correctly, has read its configuration, has applied the configured forward-zone rules, and has determined that none matches. Communicating "internal failure" to the client would prompt client-side retries (clients typically retry on `SERVFAIL` per RFC 8484 and the broader resolver discipline) that have no chance of producing a different result, wasting client resources and failing to communicate the actual condition. The operator's diagnostic process would also be misled, since `SERVFAIL` typically leads operators to look for malfunctions rather than for missing configuration.

`NOTIMP` was rejected because it carries the semantics of "the operation is not implemented by this server". Heimdall fully implements DNS query (the operation in question); the issue is that no rule matches the name, which is a configuration-scope condition rather than an operation-class condition. Returning `NOTIMP` would suggest to clients that querying Heimdall in any other way might succeed, which is incorrect — the issue is the specific name, not the query operation.

`NXDOMAIN` was rejected because it asserts that the queried name does not exist. The server's posture in the forwarder-only-no-match condition is the inverse: Heimdall has no information about whether the name exists, because no role was authorised by configuration to determine it. Emitting `NXDOMAIN` here would manufacture an authoritative-style claim that the server is not entitled to make.

### Rejection rationale — EDE

EDE 18 "Prohibited" was rejected because the IANA registry groups it with EDE 15 "Blocked" and EDE 16 "Censored" as the "active denial" cluster. Client implementations and end-users that observe EDE 18 may reasonably infer an active anti-censorship or filtering posture, which is not what the forwarder-only-no-match condition expresses; the condition is "no configured path", not "active block".

EDE 28 "Unable To Conform To Policy" was rejected because it does not distinguish a "no path" condition from any of the other operator-policy-driven response codes (rate limits, ACL denies, RPZ actions). Reusing EDE 28 across all of those would dilute the diagnostic value of the channel.

EDE 0 "Other Error" was rejected because it is the catch-all for cases where no more specific code applies; here, EDE 20 is more specific and applicable.

The "no EDE" option was rejected because [`PROTO-012`](../../specification/006-protocol-conformance.md) requires EDE implementation across all roles; not using EDE where a clearly-applicable INFO-CODE exists is leaving the standardised diagnostic channel unused for no operational benefit.

### Rejection rationale — per-transport variation

A transport-dependent response was rejected because the DNS message format (header, RCODE, OPT pseudo-RR with EDE) is independent of the transport. There is no technical reason to vary RCODE or EDE by transport, and no operator use case demands it. Variation would expand the test matrix from one cell to six (one per transport-listener mode under [`ROLE-020`](../../specification/001-server-roles.md), accounting separately for DoH/H2 and DoH/H3 since they share the `"doh"` listener but differ at the HTTP layer), with the only consequence being additional opportunities for divergence bugs.

### Rejection rationale — broad scope

A broad decision applying to every step-4 trigger combination was rejected because the open-questions tracking explicitly distinguishes the two questions (forwarder-only-no-match versus general step-4 RCODE). The two are related but not identical: the forwarder-only-no-match condition has a specific operator semantics (an exhaustive forward-zone rule list that excludes the queried name) that may or may not generalise to authoritative-only-no-match (where the operator's authoritative zone list does not include the queried name) and to the degenerate case (no role active for resolution at all). The "Assume Nothing" principle of [`../../CLAUDE.md`](../../CLAUDE.md) argues for closing each tracked open question on its own merits and on the user's deliberate authorisation.

## Consequences

### Operator-visible behaviour

A forwarder-only deployment (`[forwarder].enabled = true`, `[recursive].enabled = false`) responding to a query whose name does not match any forward-zone rule produces:

```
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: <id>
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: <buf>
; EDE: 20 (Not Authoritative)
;; QUESTION SECTION:
;<qname>.    IN  <qtype>
```

The same response bytes appear on UDP/53, TCP/53, DoT, DoH (HTTP/2 and HTTP/3, wrapped in `application/dns-message` per [`NET-026`](../../specification/002-transports.md)), and DoQ.

### Test vectors

Six test vectors per transport are recorded as F9–F14 in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md). They exercise the joint path `FWD-016` (no rule matches → step 4) → `ROLE-024` (REFUSED + EDE 20) on each transport, and assert byte-identical DNS messages across them.

### Cross-references updated

- [`ROLE-012`](../../specification/001-server-roles.md) updated to identify [`ROLE-024`](../../specification/001-server-roles.md) as the partial closure of step 4 for the forwarder-only-no-match sub-case, while preserving the open question for the general step-4 RCODE.
- The "Forwarder-only mode behaviour on no match" open question is removed from [`001-server-roles.md §4`](../../specification/001-server-roles.md).
- The "Error code for step 4 of the precedence" open question remains in [`001-server-roles.md §4`](../../specification/001-server-roles.md), now narrowed to the trigger combinations not covered by [`ROLE-024`](../../specification/001-server-roles.md).
- [`006-protocol-conformance.md §7`](../../specification/006-protocol-conformance.md) updated: the "Extended DNS Errors code set per situation" open question now records that EDE INFO-CODE `20` is fixed for the forwarder-only-no-match sub-case by [`ROLE-024`](../../specification/001-server-roles.md), narrowing the open question's scope to the remaining situations.

### Non-consequences (deliberate scope limits)

- **General step-4 RCODE.** The case where step 4 is reached and the precondition of [`ROLE-024`](../../specification/001-server-roles.md) (forwarder active, recursive inactive) is not satisfied — for instance, an authoritative-only deployment where the queried name falls outside all configured zones — is not addressed by this ADR. It remains tracked in [`001-server-roles.md §4`](../../specification/001-server-roles.md) under "Error code for step 4 of the precedence" and will be resolved separately. A future ADR may align the answer with the present decision (uniform `REFUSED` + EDE 20) or differentiate.
- **EDE catalogue beyond the present sub-case.** The broader question of which EDE INFO-CODEs accompany other Heimdall response situations (DNSSEC `bogus`, NXDOMAIN sub-cases, rate-limited responses, network errors, RPZ actions) remains tracked in [`006-protocol-conformance.md §7`](../../specification/006-protocol-conformance.md). The present decision narrows that question by one situation only.
- **Client retry semantics.** How Heimdall's clients (stub resolvers, recursive resolvers querying Heimdall, library users) interpret `REFUSED` + EDE 20 is governed by [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914); the present decision does not modify those semantics.

### Numbering

This ADR takes the sequence number `0005`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11), to reflect the actual starting number of that batch given the sprint ordering already established.
