# Cache policy

**Purpose.** This document defines Heimdall's query-response cache policy. It fixes the decisions that govern how query-response caches are instantiated, segregated across roles, and operated, independently of which roles or transports are active in a given deployment. It does not restate which roles Heimdall supports or when their state is allocated; those questions are settled in [`001-server-roles.md`](001-server-roles.md).

**Status.** Stable.

**Requirement category.** `CACHE`.

For the project-wide principles that frame these requirements (security non-negotiable, performance as the primary guide, "Assume Nothing"), see [`../CLAUDE.md`](../CLAUDE.md). For specification-wide conventions, see [`README.md`](README.md). For the role model this document depends on, see [`001-server-roles.md`](001-server-roles.md).

## 1. Scope

This document governs the query-response cache maintained by Heimdall on the roles that cache answers:

- The recursive resolver role, as defined in [`001-server-roles.md`](001-server-roles.md), section 1.2.
- The forwarder role, as defined in [`001-server-roles.md`](001-server-roles.md), section 1.3.

The authoritative server role is explicitly outside the scope of this document. Authoritative responses are derived from configured zone data, not from a query-response cache, and this document does not constrain how zone data is loaded, stored, or served by the authoritative role.

## 2. Cache segregation between recursive resolver and forwarder

### 2.1 Normative requirements

- **CACHE-001.** When the recursive resolver role is active on an instance, Heimdall MUST maintain a dedicated query-response cache for that role. When the forwarder role is active on an instance, Heimdall MUST maintain a dedicated query-response cache for that role. The two caches MUST be independent instances and MUST NOT share backing storage, index structures, entries, or administrative state.
- **CACHE-002.** An entry populated by the forwarder cache MUST NOT be consumed, served, or otherwise observed by the recursive resolver role. An entry populated by the recursive resolver cache MUST NOT be consumed, served, or otherwise observed by the forwarder role. No cross-lookup between the two caches is permitted under any configuration.
- **CACHE-003.** Heimdall MUST NOT expose any configuration option that enables, partially enables, or otherwise permits sharing of entries between the recursive resolver cache and the forwarder cache. Cache sharing between these two roles is not an operator-configurable property.
- **CACHE-004.** Each cache instance required by `CACHE-001` MUST be keyed by the tuple `(qname, qtype, qclass)` within its own role. The key space of one cache MUST NOT overlap with the key space of the other cache; keys are local to the cache instance that holds them.
- **CACHE-005.** Each cache instance required by `CACHE-001` MUST maintain its own TTL bounds, eviction policy, size limits, admission policy, metrics, and poisoning-attribution signals. These per-cache properties MUST NOT be aggregated across the two caches and MUST remain attributable to the role that owns the cache.
- **CACHE-006.** A cache instance required by `CACHE-001` MUST be instantiated only when its corresponding role is active on the instance, consistent with `ROLE-003`, `ROLE-004`, `ROLE-005`, `ROLE-006`, and `ROLE-007` in [`001-server-roles.md`](001-server-roles.md). When the corresponding role is not enabled in configuration, the cache instance, its backing storage, and the code paths that operate on it MUST NOT be allocated or reachable.
- **CACHE-007.** The authoritative server role MUST NOT maintain a query-response cache under this document. The requirements of this document MUST NOT be applied to authoritative zone data.

## 3. Rationale

The trust boundaries of the two caching roles are not the same, even though both roles validate DNSSEC. The recursive resolver walks the DNS hierarchy itself and validates the resulting data against the configured trust anchor before caching it, in accordance with `DNSSEC-008` through `DNSSEC-018` in [`005-dnssec-policy.md`](005-dnssec-policy.md). The forwarder delegates resolution to a configured upstream and then independently re-validates every response locally, against the same trust anchor, in accordance with `DNSSEC-019` through `DNSSEC-024` in [`005-dnssec-policy.md`](005-dnssec-policy.md). The two roles therefore produce cache entries through different resolution paths: the recursive role derives entries from data it has fetched and validated along a trust chain it walked itself, while the forwarder role derives entries from data fetched by an upstream and subsequently re-validated locally. If the two roles shared a single cache, entries produced through one resolution path would be consumed through the other, collapsing two operationally distinct trust boundaries into one and erasing the attribution of each entry to the role that produced it. Segregation preserves that attribution and keeps each role's trust boundary intact.

Keeping the caches independent also keeps per-role invariants coherent. TTL derivation, eviction behaviour, admission rules, metrics, and attribution of suspicious entries are each defined relative to a single role's resolution path and operational envelope. A shared cache would force those properties to be reconciled across two roles with different semantics, which would either erase the distinctions or re-introduce them through conditional logic that is harder to reason about and harder to test.

Segregation also preserves poisoning-attribution signals. A suspicious or anomalous entry in the recursive resolver cache is attributable to the authoritative servers traversed during the recursive walk, whereas a suspicious or anomalous entry in the forwarder cache is attributable to the configured upstream that produced the pre-validation response. A shared cache would conflate those two signals, which would weaken the operator's ability to localise the source of an anomaly even when both entries have been locally validated under the same trust anchor. The cross-contamination argument for segregation therefore rests on operational invariants and trust-boundary clarity, and is independent of the fact that both roles validate.

The memory cost of segregation is acceptable. In realistic deployments the intersection of names cached by a recursive resolver and by a forwarder on the same instance is small: the forwarder primarily caches names served by the upstreams declared for its forward-zone rules, while the recursive resolver caches names it walks itself, which are largely disjoint in practice. The gain on the trust-boundary side outweighs the marginal duplication on the storage side.

Finally, disallowing an operator-facing configuration switch for cache sharing (`CACHE-003`) is consistent with the structural-gating approach already adopted for role activation in [`001-server-roles.md`](001-server-roles.md) and for transport listener instantiation in [`002-transports.md`](002-transports.md). A property that belongs to the trust model of the system is made part of the implementation rather than part of the operator's configuration surface.

## 4. Open questions

The following items are **not yet decided** and MUST NOT be assumed. They are listed here because they are directly downstream of the decision in this file and will be specified incrementally in subsequent revisions of this document.

- **Cache data structure per role.** The concrete cache data structure used by each role — candidates include LRU, ARC, SIEVE, segmented LRU, per-thread sharded variants, or alternative designs — and the per-role selection and parameters are **to be specified**.
- **Negative caching (NXDOMAIN and NODATA).** The negative caching policy required by [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308) for `NXDOMAIN` and `NODATA` responses, and whether the negative-caching policy is uniform across the recursive resolver and the forwarder or diverges between them, is **to be specified**.
- **TTL bounds and overrides.** The TTL bounds and overrides applicable to each cache — including `max-cache-TTL`, `min-cache-TTL`, the negative-cache TTL cap, and the serve-stale policy under [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767) — are **to be specified**.
- **Cache admission rate-limiting and poisoning mitigation.** The cache admission rate-limiting strategy and the set of poisoning-mitigation mechanisms, including Cache Poisoning Mitigation (CaMP) and cookie-based mitigations, are **to be specified**.
- **Cache interaction with DNSSEC.** The interaction between each cache and DNSSEC — covering the representation of the four validation outcomes defined in `DNSSEC-010` of [`005-dnssec-policy.md`](005-dnssec-policy.md) at the cache-entry level, the caching of `RRSIG` records alongside the data they cover, and the caching of `NSEC` and `NSEC3` proofs of non-existence — is **to be specified**. Admission and eviction policy for cached `NSEC` and `NSEC3` entries is materially impacted by `DNSSEC-025` through `DNSSEC-030` in [`005-dnssec-policy.md`](005-dnssec-policy.md): such entries are actively consumed to synthesise `NXDOMAIN` and `NODATA` responses locally, so their admission, retention, and eviction directly determine the hit rate of aggressive synthesis on both validating roles. This item cross-references the DNSSEC requirements consolidated in [`005-dnssec-policy.md`](005-dnssec-policy.md), in particular `DNSSEC-008` through `DNSSEC-018` for the recursive resolver role, `DNSSEC-019` through `DNSSEC-024` for the forwarder role, and `DNSSEC-025` through `DNSSEC-030` for aggressive use, and will be resolved jointly with the open questions tracked there.

No implementation activity may proceed on the basis of assumptions about any of the items above.
