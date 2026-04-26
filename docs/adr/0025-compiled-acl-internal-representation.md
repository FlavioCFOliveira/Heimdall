---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# Compiled ACL internal representation

## Context and Problem Statement

[`THREAT-047`](../../specification/007-threat-model.md) requires the ACL evaluation to be hot-path-evaluable without materially degrading the query path. The concrete internal representation was tracked as an open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md). The decision had to choose data structures for each ACL axis (CIDR, mTLS identity, TSIG identity, transport, role, operation, qname pattern), the cross-axis evaluation strategy, and the performance target.

## Decision Outcome

**Per-axis indexes** ([`THREAT-123`](../../specification/007-threat-model.md)):
- Radix / PATRICIA trie for `source_cidr` (separate IPv4, IPv6).
- `HashMap<String, RuleSet>` (FxHash) for `mtls_identity`, `tsig_key_name`, exact-mode `qname_pattern`.
- Suffix trie (reversed-label) for suffix-mode `qname_pattern`.
- Labelled trie with single-label wildcard slot for wildcard-mode `qname_pattern`.
- Per-axis bitsets for `transport`, `role`, `operation` enums.

**Cross-axis evaluation** ([`THREAT-124`](../../specification/007-threat-model.md)): per-axis lookup → candidate-rule-ID bitset per axis → AND across bitsets → first set bit (declaration order) is the matched rule. AND-of-bitsets is a tight `u64` loop, sub-µs at 10k rules.

**Small-rule-set fast path** ([`THREAT-125`](../../specification/007-threat-model.md)): rules ≤ 64 → bitsets collapse to single `u64`; cross-axis AND is a single 64-bit AND.

**Build / lifecycle** ([`THREAT-126`](../../specification/007-threat-model.md)): synchronous compilation at config load + every reload (`THREAT-120`); stored behind ArcSwap; build time ≤ 100 ms at 10k rules; `acl-compile-slow` structured event when exceeded.

**Performance target** ([`THREAT-127`](../../specification/007-threat-model.md)): P99 ACL evaluation < 1 µs at 10000 rules on reference hardware. CI: criterion benchmarks at small (≤ 64), medium (1000), large (10000) sizes; > 10% regression fails Tier 2.

## Considered Options

- **Per-axis indexes + bitset AND (chosen).** Sub-µs at 10k rules; cache-friendly; trivial parallel processing across axes.
- **Linear scan over rules.** O(N) per query; would fail the < 1 µs target at 10k rules.
- **Compiled decision tree across axes.** Tighter than linear scan but worse cache profile than bitset AND; harder to update incrementally on admin-RPC reload.
- **Trie everywhere (no bitsets).** Suitable for hierarchical axes (CIDR, qname suffix) but wasteful for enum axes (transport, role, operation).

## Consequences

- 10k-rule ACL bitset width: ~156 `u64` words (~1.2 kB).
- Memory footprint of the compiled ACL: order of single-digit megabytes at 10k rules (acceptable per `THREAT-066`).
- Negated matchers via complement bitsets before AND.
- Admin-RPC fine-grained reloads MUST recompile the affected listener's ACL but MAY share unchanged per-axis indexes between old and new compiled sets via Arc cloning of the trie nodes.

## Closure

The "Internal representation of compiled ACL rules" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). All five ACL-track open questions of Sprint 4 (configuration syntax, action on deny, deny logging, dynamic reload, compiled representation) are now closed.

## Numbering

This ADR takes the sequence number `0025`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md).
