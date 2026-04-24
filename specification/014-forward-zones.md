# Forward-zone rules for the forwarder role

**Purpose.** This document defines the syntax, matching semantics, and precedence of forward-zone rules, which are the operator-declared input to step 2 of the four-step query-resolution precedence defined in [`001-server-roles.md`](001-server-roles.md).

**Status.** Stable.

**Requirement category.** `FWD`.

For the project-wide principles that frame these requirements (security non-negotiable, performance as the primary guide, "Assume Nothing"), see [`../CLAUDE.md`](../CLAUDE.md). For specification-wide conventions, see [`README.md`](README.md). For the role model and the four-step precedence this document depends on, see [`001-server-roles.md`](001-server-roles.md). For the ACL matrix that composes with forward-zone rules and for the views mechanism that emerges from that composition, see [`007-threat-model.md`](007-threat-model.md).

## 1. Scope

A forward-zone rule declares that queries matching a zone pattern MUST be forwarded to the upstream resolver or resolvers declared by that rule, in accordance with `ROLE-010` in [`001-server-roles.md`](001-server-roles.md). The present document fixes:

- The TOML shape of forward-zone rules under the `[[forwarder.forward_zone]]` array introduced by `ROLE-022` in [`001-server-roles.md`](001-server-roles.md).
- The three matching modes (`"exact"`, `"suffix"`, `"wildcard"`) applied to the query name against the rule's `zone` pattern.
- The deterministic rule-precedence algorithm applied when more than one rule matches a query.
- The interaction with the multi-axis ACL matrix fixed by `THREAT-033` through `THREAT-047` in [`007-threat-model.md`](007-threat-model.md), and in particular with the views mechanism fixed by `THREAT-046`.

The present document does NOT fix:

- The fallback behaviour of step 2 of the precedence when an upstream declared by a matching rule is unavailable, times out, or returns an error. This is tracked as an open question in [`001-server-roles.md §4`](001-server-roles.md).
- The upstream-side cryptographic and transport validation policy (certificate validation, mTLS client authentication, SPKI pinning, session-ticket cache, connection pooling, health-checking, load-balancing, EDNS Client Subnet). These items are tracked as open questions in [`002-transports.md §5`](002-transports.md) and in [`003-crypto-policy.md`](003-crypto-policy.md).
- The syntax of the optional ACL binding on a forward-zone rule. The ACL configuration syntax is tracked as an open question in [`007-threat-model.md §5`](007-threat-model.md); the ACL binding on a forward-zone rule reuses that syntax once fixed.
- The HTTP version (HTTP/2 versus HTTP/3) selection policy on outbound DoH connections to upstreams. This is tracked as an open question in section 5 of this document.

## 2. Normative requirements

- **FWD-001.** Forward-zone rules MUST be declared as an array of tables at the TOML path `[[forwarder.forward_zone]]`, nested under the `[forwarder]` role-activation table in accordance with `ROLE-022` in [`001-server-roles.md`](001-server-roles.md).
- **FWD-002.** Each `[[forwarder.forward_zone]]` entry MUST carry, at minimum, the string key `zone` and the array-of-tables key `upstream`. The `upstream` array MUST contain at least one entry. A `[[forwarder.forward_zone]]` entry lacking `zone`, lacking `upstream`, or declaring an empty `upstream` array MUST be rejected at configuration load and MUST cause the instance to refuse to start.
- **FWD-003.** The value of the `zone` key MUST be a syntactically valid DNS name in canonical form with a trailing dot, as defined by [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034), [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343), and [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499). The root zone MUST be representable as the single-character value `"."`. A `zone` value that is not a syntactically valid DNS name MUST be rejected at configuration load.
- **FWD-004.** Each `[[forwarder.forward_zone]]` entry MAY carry the string key `match` whose value is exactly one of the three enumerated strings `"exact"`, `"suffix"`, or `"wildcard"`. When the `match` key is absent, the implicit value MUST be `"suffix"`. Any other value for `match` MUST be rejected at configuration load and MUST cause the instance to refuse to start.
- **FWD-005.** When `match = "wildcard"`, the `zone` value MUST begin with the label `*` (i.e., the `zone` value MUST start with the three-character prefix `*.`), and the portion of `zone` following the leading `*.` MUST itself be a syntactically valid DNS name in canonical form with a trailing dot. When `match = "exact"` or `match = "suffix"`, the `zone` value MUST NOT contain the label `*` at any position.
- **FWD-006.** In `"exact"` mode, a rule matches a query QNAME if and only if QNAME is equal to `zone` label-for-label. Name comparison MUST be ASCII-case-insensitive as defined by [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343).
- **FWD-007.** In `"suffix"` mode, a rule matches a query QNAME if and only if QNAME is equal to `zone` OR QNAME is a proper descendant of `zone` (i.e., QNAME ends with `zone` as a label-aligned suffix and has at least one additional label to the left of `zone`). Name comparison MUST be ASCII-case-insensitive as defined by [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343).
- **FWD-008.** In `"wildcard"` mode, let `zone_suffix` denote the value of `zone` with the leading `*.` removed. A rule matches a query QNAME if and only if QNAME consists of exactly one label immediately followed by `zone_suffix` (label-for-label), regardless of the content of that leftmost label. The leftmost label MAY be any syntactically valid DNS label, including the literal label `*`. Name comparison MUST be ASCII-case-insensitive as defined by [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343). A QNAME equal to `zone_suffix` (no additional leftmost label) MUST NOT be considered to match in `"wildcard"` mode, and a QNAME with two or more additional labels to the left of `zone_suffix` MUST NOT be considered to match in `"wildcard"` mode.
- **FWD-009.** Multiple forward-zone rules MAY match the same query QNAME. When the set of matching rules for a given query is non-empty, after ACL filtering under `FWD-015` has been applied, the rule of highest rank MUST be selected to determine the upstreams. The rank of a rule against a given query MUST be computed as the ordered tuple `(mode_priority, zone_label_count, negative_declaration_order)`, and rules MUST be compared by lexicographic ordering on that tuple, greater-wins. When every component of the tuple is equal between two rules, the rules are identical in effect and the declaration_order tiebreak in `FWD-012` selects the earliest-declared.
- **FWD-010.** The mode_priority component of the rank tuple MUST take the following values, and no other: `"exact"` → `3`; `"wildcard"` → `2`; `"suffix"` → `1`.
- **FWD-011.** The zone_label_count component of the rank tuple MUST be the number of dot-separated labels in the `zone` value of the rule, counting the leading `*` label in `"wildcard"` mode as one label and counting the trailing root as zero labels. Under this definition: the root zone `"."` has zone_label_count 0; `"example.com."` has zone_label_count 2; `"*.example.com."` has zone_label_count 3.
- **FWD-012.** The declaration_order component of the rank tuple MUST be the zero-indexed position of the rule in the configuration file, with earlier-declared rules having smaller declaration_order values. In the rank tuple, declaration_order MUST be negated so that the greater-wins lexicographic comparison selects the earliest-declared rule when all other components are equal.
- **FWD-013.** Two or more `[[forwarder.forward_zone]]` entries that share the same `zone` value and the same `match` mode MUST be permitted by the configuration loader, in order to support the views mechanism fixed by `THREAT-046` in [`007-threat-model.md`](007-threat-model.md). When such rules coexist and all pass ACL filtering under `FWD-015`, the declaration_order tiebreak in `FWD-009` selects the earliest-declared among them.
- **FWD-014.** Each entry in the `upstream` array of a forward-zone rule MUST carry, at minimum, the three keys `address`, `port`, and `transport`. The `transport` value MUST be exactly one of the five enumerated strings `"udp"`, `"tcp"`, `"dot"`, `"doh"`, `"doq"`, matching the listener-transport enum of `ROLE-020` in [`001-server-roles.md`](001-server-roles.md). The declaration of `transport` on every upstream is mandatory in accordance with `NET-013` in [`002-transports.md`](002-transports.md); there is no implicit default outbound transport. Additional per-upstream sub-keys — including, but not limited to, TLS client certificate and private-key material paths, the optional outbound mTLS sub-table, SPKI pinning material, TSIG key binding, connection-pool parameters, and DoH HTTP version selection — are admitted under each upstream entry and are governed by the specification documents applicable to each. Any upstream sub-key not defined by this specification or by the specifications it cross-references MUST be rejected at configuration load per `ROLE-021` in [`001-server-roles.md`](001-server-roles.md).
- **FWD-015.** The multi-axis ACL matrix fixed by `THREAT-033` through `THREAT-047` in [`007-threat-model.md`](007-threat-model.md) MUST be evaluated against the client of a query before forward-zone rule ranking under `FWD-009`. A forward-zone rule whose optional ACL binding is present and whose ACL does not match the client under evaluation MUST be excluded from the set of matching rules considered by `FWD-009`. A forward-zone rule with no ACL binding MUST be treated as matching the ACL filter for every client. The exact syntax of the ACL binding on a forward-zone rule entry is governed by the "ACL configuration syntax" open question in [`007-threat-model.md §5`](007-threat-model.md) and is NOT fixed by this document; the composition rule stated in the present requirement is however fixed.
- **FWD-016.** When no forward-zone rule matches a given query after `FWD-015` and `FWD-009` have been applied, step 2 of the four-step query-resolution precedence fixed by `ROLE-008` through `ROLE-012` in [`001-server-roles.md`](001-server-roles.md) MUST NOT match, and evaluation of the query MUST proceed to step 3 (recursive resolver, if active under `ROLE-011`) or to step 4 (error response under `ROLE-012`), as applicable. The forward-zone rule evaluation itself MUST NOT produce an error response to the client; the error-response decision under `ROLE-012` is the sole authority on the absence-of-matching-role outcome.
- **FWD-017.** The configuration loader MUST reject any `[[forwarder.forward_zone]]` entry that carries a key not defined by this specification or by the specifications it cross-references. This rule inherits from `ROLE-021` in [`001-server-roles.md`](001-server-roles.md) and enforces the "Assume Nothing" principle of [`../CLAUDE.md`](../CLAUDE.md) at the forward-zone rule boundary.

## 3. Rationale

The separation of forward-zone rules into a dedicated specification document under the `FWD-*` category keeps [`001-server-roles.md`](001-server-roles.md) focused on the role-activation model and the four-step precedence. Forward-zone rules are a substantial sub-surface with their own syntax, matching semantics, precedence algorithm, and ACL-composition rules; collapsing them into [`001-server-roles.md`](001-server-roles.md) would conflate two concerns that evolve independently and would increase the size of the role-model document beyond what is useful for the reader whose question is solely about role activation.

The three matching modes fixed by `FWD-004` cover the operator use cases on a specificity-to-breadth continuum. Exact mode is the most specific and matches only the zone apex; it is the right choice when an operator wants to forward a single name (for example, a delegation-only test domain). Wildcard mode follows the [RFC 1034 §4.3.3](https://www.rfc-editor.org/rfc/rfc1034#section-4.3.3) wildcard semantics of "exactly one label below the anchor" and is narrower than suffix but wider than exact. Suffix mode is the most common choice, matches the zone apex and all its descendants, and is therefore the default under `FWD-004` because it aligns with the operator expectation of "forward this whole zone". Making `"suffix"` the implicit default allows the simplest and most common rule to be expressed with the minimum number of keys.

The matching semantics in `FWD-006` through `FWD-008` are ASCII-case-insensitive per [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343), consistent with DNS name-comparison semantics across the rest of the specification. The strict restriction on wildcard mode in `FWD-008` — exactly one additional label to the left, never zero and never two or more — preserves the bounded nature of the wildcard and distinguishes it from suffix mode in a way that makes the rank algorithm in `FWD-009` through `FWD-012` well-defined.

The rank-based precedence algorithm fixed by `FWD-009` through `FWD-012` produces a total ordering on the set of matching rules and therefore a deterministic selection. Mode priority as the lexicographically most-significant component of the rank tuple ensures that mode-based specificity dominates label-count-based specificity when the two conflict: an exact-mode rule for `example.com.` is the most specific possible rule for queries equal to that name, regardless of how many labels any concurrent suffix-mode rule might carry. Within a mode, zone_label_count expresses the longest-match-wins principle that is the operator experience on widely-deployed DNS software (Unbound's `forward-zone`, BIND's `forward`, dnsmasq's `--server=/domain/`). Declaration order as the tiebreak of last resort gives the operator a deterministic handle over residual ambiguity without introducing a priority field that would have to be manually maintained and whose divergence from declaration order would be a silent source of misconfiguration.

The uniform TOML shape fixed by `FWD-002` and `FWD-004` — three core keys (`zone`, `match`, `upstream`) on every entry, with a single enum `match` rather than sigil prefixes in the `zone` string, mutually exclusive `exact` / `suffix` / `wildcard` top-level keys, or tagged-union constructions — yields a homogeneous configuration surface across all rules. The loader validates the same keys on every entry, the unknown-key rejection of [`ROLE-021`](001-server-roles.md) applies uniformly, and the rule shape remains extensible in the future (for example, by the addition of an ACL-binding sub-key) without reshaping the existing rules.

The composition with the ACL matrix fixed by `FWD-015` makes views (`THREAT-046` in [`007-threat-model.md`](007-threat-model.md)) an emergent property rather than a separate subsystem. When multiple forward-zone rules share the same `zone` and `match` mode but bind to different ACLs, the ACL filter selects the subset of rules whose client-attribute constraints are satisfied by the query's client; the rank algorithm under `FWD-009` then selects among the remaining rules, with declaration order as the final tiebreak. This composition preserves the invariant established by `THREAT-046` that ACLs are the sole mechanism by which client attributes influence routing.

The detailed rationale for the location, syntax, and precedence decisions, including the alternatives considered and the rejection grounds for each, is recorded in [`../docs/adr/0003-forward-zone-rule-syntax-and-precedence.md`](../docs/adr/0003-forward-zone-rule-syntax-and-precedence.md).

## 4. Matching and precedence test vectors

The following test vectors are **normative**: any implementation MUST produce the documented winning rule for each enumerated query against the documented rule set. The test vectors are intended as directly exercisable inputs to the forward-zone rule matcher and to its unit-test suite, complementing the normative requirements of section 2.

**Rule set A** (all rules declared in this order, no ACL binding):

| ID | `zone`                | `match`    |
|----|-----------------------|------------|
| R1 | `"example.com."`      | `"suffix"` |
| R2 | `"internal.corp."`    | `"suffix"` |
| R3 | `"corp."`             | `"suffix"` |
| R4 | `"test.example.com."` | `"exact"`  |
| R5 | `"*.example.com."`    | `"wildcard"` |
| R6 | `"example.com."`      | `"exact"`  |
| R7 | `"."`                 | `"suffix"` |

**Vectors against rule set A:**

| # | Query QNAME                | Matching rules      | Winning rule | Deciding factor                                      |
|---|----------------------------|---------------------|--------------|------------------------------------------------------|
| 1 | `example.com.`             | R1, R6, R7          | **R6**       | `mode_priority(exact) > mode_priority(suffix)`       |
| 2 | `www.example.com.`         | R1, R5, R7          | **R5**       | `mode_priority(wildcard) > mode_priority(suffix)`    |
| 3 | `a.b.example.com.`         | R1, R7              | **R1**       | R5 excluded (query is two labels below `example.com.`); `zone_label_count(R1)=2 > zone_label_count(R7)=0` |
| 4 | `test.example.com.`        | R1, R4, R5, R7      | **R4**       | `mode_priority(exact) > mode_priority(wildcard) > mode_priority(suffix)` |
| 5 | `host.internal.corp.`      | R2, R3, R7          | **R2**       | `zone_label_count(R2)=2 > zone_label_count(R3)=1 > zone_label_count(R7)=0` within `"suffix"` mode |
| 6 | `internal.corp.`           | R2, R3, R7          | **R2**       | Suffix mode includes the apex; same ranking as vector 5 |
| 7 | `corp.`                    | R3, R7              | **R3**       | `zone_label_count(R3)=1 > zone_label_count(R7)=0` within `"suffix"` mode |
| 8 | `unrelated.org.`           | R7                  | **R7**       | Only the root catch-all matches                      |
| 9 | `*.example.com.` (literal leftmost `*` label) | R1, R5, R7 | **R5** | Wildcard mode does not discriminate on the content of the leftmost label; `mode_priority(wildcard) > mode_priority(suffix)` |
| 10 | `foo.test.example.com.`   | R1, R7              | **R1**       | R5 excluded (query is two labels below `example.com.`); R4 excluded (exact mode requires equality) |

**Rule set B** (duplicate zone under different declaration order, no ACL binding):

| ID  | `zone`            | `match`    |
|-----|-------------------|------------|
| R1b | `"example.com."`  | `"suffix"` |
| R2b | `"example.com."`  | `"suffix"` |

**Vectors against rule set B:**

| # | Query QNAME            | Matching rules | Winning rule | Deciding factor                                    |
|---|------------------------|----------------|--------------|----------------------------------------------------|
| 11 | `www.example.com.`    | R1b, R2b       | **R1b**      | All rank components equal; declaration_order tiebreak selects earliest-declared |

**Views composition (informative).** When rule set B is extended by distinct ACL bindings on `R1b` and `R2b` — for example, `R1b` binding to ACL `clientA` and `R2b` binding to ACL `clientB` — a query from `clientA` passes only `R1b` through `FWD-015` and selects `R1b`; a query from `clientB` passes only `R2b` and selects `R2b`; a query from a client matching neither ACL passes neither rule, and evaluation proceeds under `FWD-016`. The exact syntax of the ACL bindings in this example is governed by the "ACL configuration syntax" open question in [`007-threat-model.md §5`](007-threat-model.md) and is not fixed by the present document; the composition behaviour itself is normative per `FWD-013` and `FWD-015`.

## 5. Open questions

The following items are **not yet decided** and MUST NOT be assumed. They are listed here to make the gap visible; several are tracked authoritatively in other specification files and are cross-referenced only for convenience.

- **Forward-zone fallback behaviour on upstream failure.** The behaviour of step 2 of the precedence when a matching forward-zone rule declares an upstream that is unavailable, times out, or returns an error is tracked in [`001-server-roles.md §4`](001-server-roles.md).
- **Upstream certificate validation policy.** The validation policy applied to upstream server certificates on TLS-based and QUIC-based outbound transports is tracked in [`002-transports.md §5`](002-transports.md).
- **Upstream fallback policy between configured upstreams.** The fallback behaviour across multiple upstreams declared in the same `upstream` array of a single forward-zone rule is tracked in [`002-transports.md §5`](002-transports.md).
- **Upstream load-balancing, failover, and health-checking.** The strategy for distributing queries across multiple upstreams, for detecting unavailability, and for restoring traffic on recovery is tracked in [`002-transports.md §5`](002-transports.md).
- **Outbound connection pooling, keepalive, and multiplexing.** The per-transport strategy for reusing outbound connections to upstreams is tracked in [`002-transports.md §5`](002-transports.md).
- **EDNS(0) Client Subnet on the upstream path.** Whether ECS options received from downstream clients are propagated verbatim, stripped, rewritten, or controlled by operator configuration on outbound queries to upstreams is tracked in [`002-transports.md §5`](002-transports.md).
- **ACL binding syntax on forward-zone rules.** The exact TOML shape of the ACL binding on a `[[forwarder.forward_zone]]` entry is bound to the "ACL configuration syntax" open question in [`007-threat-model.md §5`](007-threat-model.md) and will be fixed jointly with it.
- **DoH outbound HTTP version selection (HTTP/2 versus HTTP/3).** When `transport = "doh"` is declared on an upstream, the mechanism by which Heimdall selects HTTP/2 or HTTP/3 for the outbound connection — operator-declared per-upstream preference, ALPN-driven negotiation on a per-connection basis, or a fallback policy — is **to be specified**. `NET-012` in [`002-transports.md`](002-transports.md) requires that both HTTP versions be supported on the outbound DoH path, but the selection policy among them is not fixed.

No implementation activity may proceed on the basis of assumptions about any of the items above.
