---
status: accepted
date: 2026-04-24
deciders: [FlavioCFOliveira]
---

# Record architecture decisions using MADR

## Context and Problem Statement

Architectural and engineering decisions must be recorded with their rationale so that the reasoning behind choices is preserved, traceable from specification requirements, and available to future contributors. Without a structured record, the "why" behind decisions is lost and the same ground gets re-covered repeatedly.

## Decision Drivers

- Rationale must be preserved and distinguishable from normative requirements ([`ENG-112`](../../specification/010-engineering-policies.md)).
- Specification files hold normative content; ADRs hold rationale — neither form may duplicate the other ([`ENG-125`](../../specification/010-engineering-policies.md)).
- Every architectural and engineering decision, including every new dependency and every new `unsafe` pattern, must pass through a human gate backed by an ADR ([`ENG-126`](../../specification/010-engineering-policies.md)).

## Considered Options

- **MADR (Markdown Any Decision Records)** — lightweight, Markdown-native, version-controlled alongside the code, minimal tooling dependency.
- **RFC-style documents** — more formal, higher overhead, better suited to standards bodies than to a single-repository project.
- **Inline prose in specification files** — conflates normative and rationale content, explicitly prohibited by [`ENG-125`](../../specification/010-engineering-policies.md).
- **No formal process** — fails to satisfy [`ENG-112`](../../specification/010-engineering-policies.md) through [`ENG-126`](../../specification/010-engineering-policies.md).

## Decision Outcome

Chosen option: **MADR version 3.0.0 or later** ([`ENG-113`](../../specification/010-engineering-policies.md)).

## Consequences

**ADR location and naming**

- ADR files live under `docs/adr/` at the repository root, separate from `/specification/` ([`ENG-116`](../../specification/010-engineering-policies.md)).
- Each file is named `NNNN-kebab-case-slug.md` where `NNNN` is a zero-padded four-digit monotonically increasing sequence number ([`ENG-117`](../../specification/010-engineering-policies.md), [`ENG-118`](../../specification/010-engineering-policies.md)).
- Sequence numbers are never reused, even after supersession or deprecation ([`ENG-118`](../../specification/010-engineering-policies.md)).

**Required content**

Every ADR must contain, at minimum ([`ENG-114`](../../specification/010-engineering-policies.md)):

1. Title
2. Context and Problem Statement
3. Decision Drivers
4. Considered Options
5. Decision Outcome
6. Consequences

A Validation section may be added when the decision is verifiable through testing or benchmarking.

**Required frontmatter**

Every ADR must carry a YAML frontmatter block with at least `status`, `date`, and `deciders` ([`ENG-115`](../../specification/010-engineering-policies.md)).

**Lifecycle**

The `status` field takes exactly one of ([`ENG-120`](../../specification/010-engineering-policies.md)):

- `proposed` — draft under review.
- `accepted` — agreed and merged.
- `deprecated` — no longer applicable; no replacement.
- `superseded-by ADR-NNNN` — replaced by a specific later ADR.

Status transitions are append-only: an `accepted` ADR is never silently edited ([`ENG-121`](../../specification/010-engineering-policies.md)). A change of decision requires a new ADR and an update to the superseded ADR's `status` field. Deprecated and superseded ADRs are retained as historical record and must never be deleted ([`ENG-122`](../../specification/010-engineering-policies.md)).

**Grandfather batch**

The decisions already implicit in prior specification requirements must receive retrospective ADRs in a coordinated batch starting at `0002` ([`ENG-123`](../../specification/010-engineering-policies.md)). The batch must cover, at minimum: Tokio, `rustls`, `quinn`, `hyper`, `rustix`, the Cargo workspace layout, the MIT licence, and the MSRV policy.

**Cross-references**

ADRs may reference specification requirement identifiers (for example, `ENG-112`) via relative Markdown links, and specification requirements may reference ADRs by relative link. Hard-coded absolute URLs must not be used ([`ENG-124`](../../specification/010-engineering-policies.md)).
