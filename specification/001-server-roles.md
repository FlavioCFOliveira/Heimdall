# Server roles and role activation

**Purpose.** This document defines the set of DNS server roles that Heimdall supports and the invariant that governs how those roles are activated in a running instance.

**Status.** Stable.

**Requirement category.** `ROLE`.

For the project-wide principles that frame these requirements (security non-negotiable, performance as the primary guide, "Assume Nothing"), see [`../CLAUDE.md`](../CLAUDE.md). For specification-wide conventions, see [`README.md`](README.md).

## 1. Supported server roles

Heimdall supports exactly the following three DNS server roles.

### 1.1 Authoritative server

Serves authoritative answers for zones configured locally on the instance. For a given zone, Heimdall may additionally act as primary, as secondary, or as both, and participates in the zone-transfer ecosystem (AXFR, IXFR, NOTIFY) accordingly, as fixed by `PROTO-036` through `PROTO-049` in [`006-protocol-conformance.md`](006-protocol-conformance.md).

### 1.2 Recursive resolver

Resolves arbitrary DNS queries by walking the DNS hierarchy, starting from the root servers, descending through the TLD servers, and down to the authoritative servers for the queried name. The recursive resolver maintains an internal cache.

### 1.3 Forwarder (caching proxy)

Forwards DNS queries to one or more configured upstream resolvers and returns their answers to the client. The forwarder maintains a local cache.

## 2. Normative requirements

- **ROLE-001.** Heimdall MUST support the three server roles defined in section 1: authoritative server, recursive resolver, and forwarder.
- **ROLE-002.** Heimdall MUST be distributed as a single binary that contains all three roles.
- **ROLE-003.** Each running instance MUST activate only the roles that are explicitly enabled in its configuration.
- **ROLE-004.** A role that is not enabled in configuration MUST NOT instantiate any listening socket.
- **ROLE-005.** A role that is not enabled in configuration MUST NOT allocate any state, cache, or worker thread associated with that role.
- **ROLE-006.** A role that is not enabled in configuration MUST NOT expose any code path reachable from the network.
- **ROLE-007.** The set of active roles in an instance is determined exclusively by its configuration. There is no implicit default role and no role that is always on.
- **ROLE-008.** When two or more roles are active on the same running instance, every incoming name-resolution query MUST be resolved by applying the four-step precedence defined in `ROLE-009`, `ROLE-010`, `ROLE-011`, and `ROLE-012`, in that order. The first step that matches the query name under the active configuration MUST produce the response, and no subsequent step MUST be evaluated for that query. Zone-transfer operations (AXFR, IXFR, NOTIFY) on the authoritative server role are not name-resolution queries within the meaning of this requirement; they are governed exclusively by `PROTO-036` through `PROTO-049` in [`006-protocol-conformance.md`](006-protocol-conformance.md).
- **ROLE-009.** Step 1 of the precedence: the query name MUST first be checked against the set of zones configured as locally authoritative on the instance. If the query name falls within such a zone, the response MUST be produced by the authoritative role, including an `NXDOMAIN` response for a name that does not exist within the zone.
- **ROLE-010.** Step 2 of the precedence: if step 1 does not match, the query name MUST be checked against the set of configured forward-zone rules. If a forward-zone rule matches, the query MUST be forwarded to the upstream or upstreams declared by that rule.
- **ROLE-011.** Step 3 of the precedence: if step 2 does not match and the recursive resolver role is active on the instance, the query MUST be resolved by the recursive resolver role.
- **ROLE-012.** Step 4 of the precedence: if no active role can serve the query under steps 1 to 3, the server MUST return an error response to the client. The specific error code returned in this step (`SERVFAIL` versus `REFUSED`) is tracked as an open question in section 4 and MUST NOT be assumed before it is specified.
- **ROLE-013.** The order of the four steps defined in `ROLE-009` through `ROLE-012` MUST be fixed in the implementation and MUST NOT be configurable by operators. Operators configure which zones are locally authoritative, which zones are forwarded and to which upstreams, and whether the recursive resolver role is enabled; the order in which these three checks are evaluated is not an operator decision.
- **ROLE-014.** The precedence defined in `ROLE-008` through `ROLE-013` MUST apply to every incoming query processed by the instance, regardless of the transport on which the query arrived. This requirement is orthogonal to `NET-011` in [`002-transports.md`](002-transports.md): `NET-011` determines which (role, transport) combinations are supported at the software level for incoming traffic, while `ROLE-008` through `ROLE-013` determine which active role produces the response to a given query once it has been accepted on any such combination.
- **ROLE-015.** Nothing in `ROLE-008` through `ROLE-014` precludes a deployment in which multiple Heimdall instances, or multiple listeners on a single instance, are configured with distinct role sets. Such deployment-level choices operate on top of, and do not replace, the per-instance precedence defined by `ROLE-008` through `ROLE-013`.

## 3. Rationale

The single-binary, per-instance role activation model is dictated by the **minimum-attack-surface** principle. At runtime, an instance exposes only the subsystems strictly required for the roles it is operating. Code, sockets, state, and threads belonging to disabled roles are absent from the process, not merely guarded by flags. This places role activation on the structural side of the system rather than on the conditional-logic side, which reduces the probability of a disabled role being reached through an unintended path.

The fixed four-step query-resolution precedence defined by `ROLE-008` through `ROLE-015` follows from four properties that are deliberately preserved together. First, the order matches operator intuition and the structure of the configuration itself: authoritative zones are explicit configuration, forward-zone rules are explicit configuration, and recursion is the fallback path for every query for which no explicit rule applies. Second, the order covers the common deployment patterns without ambiguity: a pure authoritative server exercises only step 1 and step 4; a pure recursive resolver exercises only step 3; a pure forwarder exercises only step 2 and step 4; a hybrid corporate DNS that serves internal zones authoritatively, forwards a defined set of external zones to a dedicated upstream, and recurses for everything else exercises steps 1, 2, and 3 in the natural order. Third, the order is consistent with the behaviour of widely-deployed DNS servers (BIND, Unbound, PowerDNS Recursor, Knot Resolver, dnsmasq), so operators moving to Heimdall encounter no surprise in the resolution semantics. Fourth, a fixed order yields a finite and exercisable test matrix, whereas a configurable order would not. Making the order part of the implementation rather than of the configuration surface is the same structural-gating approach already applied to role activation by `ROLE-003` through `ROLE-007` and to transport listener instantiation by `NET-009` in [`002-transports.md`](002-transports.md): the safe behaviour is built in rather than selected.

## 4. Open questions

The following items are **not yet decided** and MUST NOT be assumed. They are listed here because they are directly downstream of the decisions in this file and will need to be specified before the implementation of these roles can begin.

- **Per-role configuration surface.** The exact configuration keys, structure, and validation rules that enable each role and bind it to interfaces, ports, and zones are **to be specified**.
- **Forward-zone rule syntax and matching semantics.** The syntax of forward-zone rules referenced by `ROLE-010`, and the matching semantics applied to the query name (exact match, suffix match, wildcard patterns), are **to be specified**. Client-attribute-based selection among forward-zone rules (the "views" use case) is governed by the ACL-driven response-selection model fixed by `THREAT-033` through `THREAT-047` in [`007-threat-model.md`](007-threat-model.md).
- **Forward-zone fallback behaviour on upstream failure.** The behaviour of step 2 of the precedence defined by `ROLE-010` when the forward-zone rule matches but the declared upstream is unavailable, times out, or returns an error — specifically whether the query falls through to step 3 (the recursive resolver, if active) or whether the error is propagated to the client — is **to be specified**.
- **Forwarder-only mode behaviour on no match.** The response produced by a forwarder-only deployment (recursive resolver inactive) for a query that matches no forward-zone rule — whether `REFUSED`, `SERVFAIL`, or another response code, and the conditions under which each applies — is **to be specified**. This item interacts with `ROLE-011` and `ROLE-012`.
- **Error code for step 4 of the precedence.** The specific error code returned under `ROLE-012` when no active role can serve the query — `SERVFAIL` versus `REFUSED` — and whether the chosen code is transport-dependent, is **to be specified**.

No implementation activity may proceed on the basis of assumptions about any of the items above.
