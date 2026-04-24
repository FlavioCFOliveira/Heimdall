---
status: accepted
date: 2026-04-24
deciders: [FlavioCFOliveira]
---

# Forward-zone rule syntax, matching semantics, and precedence

## Context and Problem Statement

[`ROLE-010`](../../specification/001-server-roles.md) in [`001-server-roles.md`](../../specification/001-server-roles.md) defines step 2 of the four-step query-resolution precedence: if the query name falls outside the set of locally authoritative zones, Heimdall checks the query name against the set of configured forward-zone rules and forwards matching queries to the declared upstreams. The specification until now identified the syntax, matching semantics, and precedence of these rules as an open question in [`001-server-roles.md §4`](../../specification/001-server-roles.md) ("Forward-zone rule syntax and matching semantics"). Three orthogonal questions had to be settled jointly:

1. **Location** of the normative material (inline extension of [`001-server-roles.md`](../../specification/001-server-roles.md) versus a dedicated companion file).
2. **Matching syntax** for the three modes required by the task's technical requirements (`exact`, `suffix`, `bounded wildcard`).
3. **Precedence algorithm** when more than one rule matches a query, so that rule selection is deterministic in every case.

The decisions had to compose with the multi-axis ACL matrix fixed by [`THREAT-033`](../../specification/007-threat-model.md) through [`THREAT-047`](../../specification/007-threat-model.md) in [`007-threat-model.md`](../../specification/007-threat-model.md), and in particular with the views mechanism fixed by [`THREAT-046`](../../specification/007-threat-model.md), which requires that client-attribute-based selection among rules be implemented as ACL-driven response selection rather than as a separate subsystem.

## Decision Drivers

- **Determinism.** Every query that reaches step 2 of the precedence must select at most one forward-zone rule; the selection must be a total function of the query and the rule set.
- **Operator intuition.** "Longest-match-wins" is the established behaviour of widely-deployed DNS software (Unbound `forward-zone`, BIND `forward`, dnsmasq `--server=/domain/`). Operators moving to Heimdall should encounter no surprise in rule selection.
- **Hot-path performance** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). The precedence algorithm must be evaluable at query-processing cost consistent with [`THREAT-047`](../../specification/007-threat-model.md) ("MUST NOT materially degrade the query hot path").
- **"Assume Nothing"** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Every rule-level concept — match mode, upstream transport, ACL binding — must be explicit in configuration; no implicit coercions, no silent defaults except the explicitly documented `match = "suffix"` default.
- **Composability with the ACL matrix.** Rule selection must compose with [`THREAT-033`](../../specification/007-threat-model.md) through [`THREAT-047`](../../specification/007-threat-model.md) so that views under [`THREAT-046`](../../specification/007-threat-model.md) emerge from the same ACL engine rather than re-implementing client-attribute matching at the forward-zone layer.
- **Document separation of concerns.** [`001-server-roles.md`](../../specification/001-server-roles.md) is already large and carries the role model and the four-step precedence; piling a substantial sub-surface into it would harm readability without corresponding benefit.

## Considered Options

### A. Location of the normative material

- **Dedicated companion file `014-forward-zones.md` with category `FWD-*` (chosen).** Follows the specification-wide convention of one file per substantive concern (cf. [`003-crypto-policy.md`](../../specification/003-crypto-policy.md), [`004-cache-policy.md`](../../specification/004-cache-policy.md), [`011-rpz.md`](../../specification/011-rpz.md), [`012-runtime-operations.md`](../../specification/012-runtime-operations.md), [`013-persistence.md`](../../specification/013-persistence.md)). Keeps [`001-server-roles.md`](../../specification/001-server-roles.md) focused on the role-activation model and the four-step precedence.
- **Extension of [`001-server-roles.md`](../../specification/001-server-roles.md) §2 with `ROLE-0NN` requirements covering forward-zone rules.** Would grow [`001-server-roles.md`](../../specification/001-server-roles.md) by roughly one-quarter in size for a sub-surface that is conceptually downstream of the role model and that evolves independently (rule precedence, upstream-facing transport defaults, ACL composition).

### B. Matching syntax for the three modes

- **Enum `match` field with values `"exact"`, `"suffix"`, `"wildcard"` and default `"suffix"` (chosen).** Homogeneous TOML shape on every rule; uniform validation; uniform unknown-key rejection under [`ROLE-021`](../../specification/001-server-roles.md); straightforward extensibility.
- **Sigil prefix embedded in the `zone` string** (`zone = "=example.com."` for exact, `zone = "*.example.com."` for wildcard, bare `zone = "example.com."` for suffix). Compact and familiar to BIND and dnsmasq operators. Mixes matching semantics into a string whose primary role is to carry a DNS name, which complicates parser staging and conflicts with the zone-file wildcard syntax used by [`005-dnssec-policy.md`](../../specification/005-dnssec-policy.md) and [`006-protocol-conformance.md`](../../specification/006-protocol-conformance.md) in other contexts.
- **Mutually exclusive top-level keys per mode** (`exact = "..."` xor `suffix = "..."` xor `wildcard = "..."`). Requires bespoke mutual-exclusivity validation and produces inhomogeneous rules that are harder to inspect and to diff.
- **Tagged union** (`zone = { type = "suffix", name = "example.com." }`). Explicit but atypical in TOML; verbose for the common case.

### C. Precedence algorithm when multiple rules match

- **Longest-match with mode priority (chosen).** Rank tuple `(mode_priority, zone_label_count, negative_declaration_order)` with `mode_priority(exact) = 3`, `mode_priority(wildcard) = 2`, `mode_priority(suffix) = 1`. Lexicographic greater-wins comparison produces a total ordering on matching rules. Declaration order is the tiebreak of last resort.
- **Pure longest-match ignoring mode.** Rank tuple `(zone_label_count, negative_declaration_order)`. Simpler, but ambiguous when an exact-mode rule and a suffix-mode rule share the same `zone` value (a legitimate configuration pattern for "forward the apex of the zone exactly, and don't forward subdomains"): both rules tie on label count and the tiebreak of last resort has to adjudicate what is arguably a mode-specificity difference.
- **Pure declaration order.** First matching rule wins, regardless of specificity. Trivial to implement but contrary to established DNS operator intuition; forces operators to manually order rules from most specific to least specific and fails silently when that ordering drifts.
- **Explicit `priority` field per rule.** Operator declares an integer priority; higher wins. Requires manual maintenance of a numeric space and couples rule selection to a magic-number discipline that is prone to drift when rules are added or removed.

## Decision Outcome

**Chosen location.** Dedicated companion file [`014-forward-zones.md`](../../specification/014-forward-zones.md) with requirement category `FWD-*`. Forward-zone rules are added to the index in [`specification/README.md`](../../specification/README.md); [`ROLE-010`](../../specification/001-server-roles.md) and [`ROLE-022`](../../specification/001-server-roles.md) in [`001-server-roles.md`](../../specification/001-server-roles.md) are updated to cross-reference the new file; the open question "Forward-zone rule syntax and matching semantics" is removed from [`001-server-roles.md §4`](../../specification/001-server-roles.md).

**Chosen syntax.** Enum `match` field with the three values `"exact"`, `"suffix"`, `"wildcard"` and default `"suffix"`, per [`FWD-004`](../../specification/014-forward-zones.md). Wildcard mode follows [RFC 1034 §4.3.3](https://www.rfc-editor.org/rfc/rfc1034#section-4.3.3) semantics as fixed by [`FWD-008`](../../specification/014-forward-zones.md): exactly one label to the left of the wildcard anchor, no less, no more.

**Chosen precedence.** Rank tuple `(mode_priority, zone_label_count, negative_declaration_order)` with lexicographic greater-wins comparison, per [`FWD-009`](../../specification/014-forward-zones.md) through [`FWD-012`](../../specification/014-forward-zones.md). The ACL matrix is evaluated before ranking (per [`FWD-015`](../../specification/014-forward-zones.md)), so that views ([`THREAT-046`](../../specification/007-threat-model.md)) emerge as an ACL-filter-plus-rank composition rather than a separate subsystem.

### Rejection rationale — location

Extending [`001-server-roles.md`](../../specification/001-server-roles.md) in place was rejected on document-economy and evolution grounds. The role model, the four-step precedence, and the configuration-surface rules fixed by `ROLE-001..023` form a coherent and self-contained subject. Forward-zone rule matching and precedence form a second coherent subject that will acquire its own open questions (DoH HTTP version selection on outbound upstreams, interaction with upstream-failure fallback, future extensions such as conditional upstream selection) and its own rationale. Co-locating both subjects in a single file would force every future clarification on either to land in the same document, increasing review friction and harming navigability.

### Rejection rationale — syntax

The **sigil prefix** alternative was rejected on two grounds. First, it conflates the matching-semantics decision with the DNS-name payload in a single string, so the loader must parse the string before it can validate the semantics; the parser-staging discipline applied elsewhere in the loader (TOML parse → typed model → semantic validation) is broken. Second, the `*.` prefix is already the RFC 1035 zone-file wildcard-owner syntax; using the same prefix in forward-zone rule configuration is a source of confusion with authoritative zone-file content, where `*.example.com.` has a very different meaning (synthesising records).

The **mutually exclusive keys** alternative was rejected on homogeneity grounds. Under it, different rules in the same configuration file carry structurally different shapes: some have `suffix`, some have `exact`, some have `wildcard`. The loader must validate mutual exclusivity on every rule, and diffing two rules that happen to use different modes is harder because the structure differs, not just the content.

The **tagged union** alternative was rejected on ergonomic grounds. The common case (`match = "suffix"`) requires no shape at all under the chosen enum approach (the field is absent), whereas under the tagged-union approach every rule must carry a `zone = { type = "...", name = "..." }` two-key substructure. The verbosity tax on the common case outweighs the theoretical tidiness of explicit discrimination.

### Rejection rationale — precedence

**Pure longest-match** was rejected because it conflates mode specificity with label-count specificity. A concrete failure case: an operator declares two rules, one `{ zone = "example.com.", match = "exact" }` to forward the apex exactly to an internal resolver, and one `{ zone = "example.com.", match = "suffix" }` to forward subdomains to a different external resolver. Under pure longest-match, the two rules tie on label count and the declaration-order tiebreak adjudicates a difference that is semantically a mode difference. Under the chosen algorithm, the exact rule wins for queries equal to the apex (correct by operator intent) and the suffix rule wins for queries to subdomains (also correct).

**Pure declaration order** was rejected on three grounds. First, it diverges from the operator experience on Unbound, BIND, and dnsmasq, all of which implement longest-match semantics at least for plain-suffix rules. Second, it requires operators to maintain a manual sort order in the configuration file from most-specific to least-specific; the cost of that maintenance grows quadratically with rule count and is a silent-failure mode when the sort order drifts. Third, it inverts the usual declaration-order convention where earlier declarations are more general and later declarations are more specific (the "base, then exceptions" idiom).

**Explicit `priority` field** was rejected because it introduces a global integer namespace that operators must maintain by hand. The advantages of a priority field (operator override of natural precedence in edge cases) are in practice achievable by reorganising `zone` / `match` under the chosen algorithm, and the residual edge cases are handled by declaration order as the tiebreak of last resort. A priority field would also be a second source of truth for rule precedence, competing with and occasionally contradicting the natural mode-and-label-count rank.

## Consequences

### Operator-visible shape of a forward-zone rule

```toml
[[forwarder.forward_zone]]
zone = "internal.corp."
match = "suffix"              # default if omitted
upstream = [
  { address = "10.0.0.1", port = 53,  transport = "udp" },
  { address = "10.0.0.2", port = 853, transport = "dot" },
]
```

A minimal rule (suffix mode, one upstream) requires four lines and three keys. The loader rejects any rule missing `zone` or `upstream`, any rule with an empty `upstream` array, any rule with an unknown `match` value, any rule with an unknown top-level key, and any upstream entry missing `address`, `port`, or `transport`.

### Precedence under the chosen algorithm — worked examples

For the ruleset:

```
R1: zone = "example.com.",       match = "suffix"
R2: zone = "internal.corp.",     match = "suffix"
R3: zone = "corp.",              match = "suffix"
R4: zone = "test.example.com.",  match = "exact"
R5: zone = "*.example.com.",     match = "wildcard"
R6: zone = "example.com.",       match = "exact"
R7: zone = ".",                  match = "suffix"
```

the selections are:

| Query                     | Winning rule | Reason                                                 |
|---------------------------|--------------|--------------------------------------------------------|
| `example.com.`            | R6           | `mode_priority(exact) > mode_priority(suffix)`         |
| `www.example.com.`        | R5           | `mode_priority(wildcard) > mode_priority(suffix)`      |
| `a.b.example.com.`        | R1           | R5 excluded (two labels below anchor); longest suffix  |
| `test.example.com.`       | R4           | exact > wildcard > suffix (mode priority cascade)      |
| `host.internal.corp.`     | R2           | longest suffix in suffix mode                          |
| `unrelated.org.`          | R7           | only the root catch-all matches                        |

The full normative vector set is in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md).

### Views — ACL filtering composes with rank

Under [`FWD-015`](../../specification/014-forward-zones.md), the ACL matrix of [`THREAT-033`](../../specification/007-threat-model.md) through [`THREAT-047`](../../specification/007-threat-model.md) is evaluated against the client of the query before the rank algorithm runs. A rule whose ACL binding does not match the client is excluded from the candidate set. This makes views ([`THREAT-046`](../../specification/007-threat-model.md)) an emergent property: two rules with the same `zone` and the same `match` mode but bound to different ACLs are both permitted by [`FWD-013`](../../specification/014-forward-zones.md), and the client's ACL profile selects which one remains after filtering. No separate client-attribute-matching subsystem is introduced at the forward-zone layer; the ACL engine is the sole authority on client-attribute-based routing.

The exact syntax of the ACL binding on a forward-zone rule entry is governed by the "ACL configuration syntax" open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md) and will be fixed jointly with it. The composition semantics (filter-first-then-rank) are fixed now.

### Deferred items

The following items were deliberately left out of scope of the present decision and are tracked in the open questions of the relevant specification files:

- Upstream certificate validation, mTLS, SPKI pinning, session-ticket cache, connection pooling, health-checking, load-balancing, and ECS propagation — tracked in [`002-transports.md §5`](../../specification/002-transports.md).
- Upstream-failure fallback (drop-through to step 3 versus error propagation) — tracked in [`001-server-roles.md §4`](../../specification/001-server-roles.md).
- ACL binding syntax on a forward-zone rule — bound to the ACL configuration syntax open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md).
- DoH outbound HTTP version selection (HTTP/2 versus HTTP/3 per upstream) — new open question tracked in [`014-forward-zones.md §5`](../../specification/014-forward-zones.md).

### Numbering

This ADR takes the sequence number `0003`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive "grandfather batch is expected to occupy the low sequence numbers starting at `0002`" guidance in [`ENG-123`](../../specification/010-engineering-policies.md) SHOULD be updated when the grandfather batch is authored (roadmap sprint 11), to reflect the actual starting number of that batch given the sprint ordering.
