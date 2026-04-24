---
status: accepted
date: 2026-04-24
deciders: [FlavioCFOliveira]
---

# Configuration file format and per-role topology

## Context and Problem Statement

Heimdall requires an unambiguous configuration surface through which operators enable each of the three roles (authoritative server, recursive resolver, forwarder) and bind each to interfaces, ports, and zones, in line with the structural-gating requirement fixed by [`ROLE-003`](../../specification/001-server-roles.md) through [`ROLE-007`](../../specification/001-server-roles.md). The specification until now identified this as an open question in [`001-server-roles.md §4`](../../specification/001-server-roles.md). Two orthogonal questions had to be settled jointly:

1. The serialisation format of the configuration file.
2. The topology with which role activation, listener bindings, and per-zone settings are laid out within that format.

Both questions feed into later sub-surface decisions (forward-zone rule syntax, ACL configuration syntax, the Redis connection surface, and more) that are tracked separately as open questions in their respective specification files. The decision recorded here fixes only the top-level format and role-activation topology; it does not pre-empt any of those downstream surfaces.

## Decision Drivers

- **Security is non-negotiable** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)): the configuration loader is an external-input boundary, so the parser's code and behavioural surface must be minimised.
- **Structural gating** is the chosen pattern for role activation ([`ROLE-003`](../../specification/001-server-roles.md) through [`ROLE-007`](../../specification/001-server-roles.md)): disabled roles MUST NOT instantiate any state. The configuration topology must express this explicitly, not by inference.
- **"Assume Nothing"** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)): unknown keys and implicit coercions must be rejected at load time, not silently accepted.
- **Ecosystem consistency**: the project already uses TOML for `Cargo.toml`, `deny.toml`, and `rustfmt.toml`. A second serialisation format would add parsers, dependencies, and cognitive load without benefit.
- **Operator mental model**: enabling a role and binding its listeners is a single intent; the topology must not force operators to split that intent across unrelated top-level sections.

## Considered Options

### A. Serialisation format

- **TOML (TOML v1.0.0).** Stable specification with a small, typed grammar. Mature Rust crate (`toml`). Consistent with existing project files. Comments supported. No type-coercion surprises. No anchor or alias semantics.
- **YAML.** Familiar to DevOps operators. Richer features (anchors, aliases, merge keys). Larger parser attack surface. Implicit type coercions (`yes`/`no` as Booleans, `00:12` as sexagesimal, unquoted numerics ambiguous as float or string). Known parser-level vulnerability classes (billion-laughs / YAML-bomb expansions). Incompatible with the security-first posture of [`../../CLAUDE.md`](../../CLAUDE.md).
- **JSON.** Universal and trivially validatable. No comment support, making it unsuitable for human-edited configuration. Verbose nesting. No native type for dates or heterogeneous tables.
- **Custom BIND-style syntax.** Familiar to traditional DNS operators. Requires authoring and maintaining a bespoke parser, expanding attack surface and maintenance burden. Diverges from the Rust-ecosystem conventions already adopted in the repository.

### B. Per-role topology (conditional on TOML)

- **Top-level per-role tables.** Each role is represented by a dedicated top-level table (`[authoritative]`, `[recursive]`, `[forwarder]`) carrying a Boolean `enabled` key; listeners, zones, and forward-zone rules are declared as arrays of tables nested under the role's table.
- **Unified flat listener table.** A single `[[listener]]` array where each entry carries a `role` key. Role activation is derived implicitly from the presence of listeners for that role, contrary to the explicit activation fixed by [`ROLE-007`](../../specification/001-server-roles.md).
- **Hybrid (`[roles]` activation flags + flat listener table).** Boolean flags in a dedicated `[roles]` table plus flat `[[listener]]` entries referencing a `role` key. Two sources of truth for "role is active" — the flag and the presence of listeners — introduce reconcilability problems at load time.

## Decision Outcome

**Chosen format:** TOML v1.0.0, fixed by [`ROLE-016`](../../specification/001-server-roles.md).

**Chosen topology:** top-level per-role tables with explicit `enabled` flags and nested listener arrays, fixed by [`ROLE-017`](../../specification/001-server-roles.md) through [`ROLE-023`](../../specification/001-server-roles.md).

### Rejection rationale — serialisation format

YAML was rejected primarily on the **parser attack surface** and the **type-coercion ambiguity** axes. The YAML 1.2 core schema carries coercion rules that have caused real production incidents in comparable projects (unquoted `off` / `yes` / `no` silently re-typed as Booleans, unquoted version strings like `1.10` silently re-typed as numbers, unquoted `NO` as the Norway country code). The anchor-and-alias mechanism has been the root cause of denial-of-service vectors in multiple parsers (billion-laughs, YAML-bombs). The [`../../CLAUDE.md`](../../CLAUDE.md) principle of security as non-negotiable rules out a format whose complexity has caused repeated security incidents across ecosystems when a simpler, typed alternative is available.

JSON was rejected primarily on **the absence of comments** and on **verbosity in nested configuration**. A configuration file that must carry operator-authored guidance, rationale comments, and temporary annotations cannot be expressed in a format that has no syntactic place for them.

A custom BIND-style syntax was rejected primarily on **attack surface** and **maintenance cost**. Writing a correct parser for a domain-specific configuration grammar is a non-trivial undertaking; the resulting parser would sit on the external-input boundary in the same role as the TOML parser, without the benefit of an existing mature implementation or of a stable public specification.

### Rejection rationale — topology

The unified flat listener table was rejected because it makes role activation **implicit**. [`ROLE-007`](../../specification/001-server-roles.md) requires that "the set of active roles in an instance is determined **exclusively** by its configuration" with no implicit default. A topology in which `authoritative` is active because an entry with `role = "authoritative"` happens to exist derives activation from sub-structure, which is a weaker guarantee than an explicit Boolean flag.

The hybrid topology was rejected because it introduces **two sources of truth** for the same property. If `[roles].recursive = false` but a listener with `role = "recursive"` exists, the loader must either fail hard (in which case the `[roles]` flag is redundant) or reconcile the conflict (in which case one of the two statements is silently ignored, which contradicts the "Assume Nothing" principle).

## Consequences

### Operator-visible shape

Each active role has its own top-level table:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[authoritative.zone]]
# Per-zone keys — shape governed by the open questions of
# 001-server-roles.md §4 and 006-protocol-conformance.md.
```

A role is disabled either by omitting its table entirely or by setting `enabled = false`. Per [`ROLE-021`](../../specification/001-server-roles.md), the loader rejects unknown top-level tables and unknown sub-keys; a typo in a key name produces a hard load failure rather than a silently-ignored setting.

### Listener transport values

The five permitted listener `transport` strings fixed by [`ROLE-020`](../../specification/001-server-roles.md) map to the four transports of [`NET-001`](../../specification/002-transports.md) as follows:

| Listener `transport` | Corresponding transport ([`NET-001`](../../specification/002-transports.md)) |
|----------------------|---------------------------------------------------------------|
| `"udp"`              | DNS classic (section 1.1), UDP socket                          |
| `"tcp"`              | DNS classic (section 1.1), TCP socket                          |
| `"dot"`              | DNS-over-TLS (section 1.2)                                     |
| `"doh"`              | DNS-over-HTTPS (section 1.3), serves both HTTP/2 and HTTP/3    |
| `"doq"`              | DNS-over-QUIC (section 1.4)                                    |

DNS classic is declared at the listener level as two separate sockets (`"udp"` + `"tcp"`) because the two carry different socket semantics in the kernel and because [`NET-009`](../../specification/002-transports.md) gates listener instantiation per socket, not per transport family. A single DoH listener serves both HTTP/2 and HTTP/3 because [`NET-006`](../../specification/002-transports.md) requires both version negotiations from a single DoH endpoint via ALPN and Alt-Svc.

### Example configuration snippets per `NET-011` cell

The snippets below cover every legal `(role, transport)` cell of [`NET-011`](../../specification/002-transports.md). Per-zone keys under `[[authoritative.zone]]`, forward-zone rule keys under `[[forwarder.forward_zone]]`, TLS certificate and key paths on TLS-based listeners, and mTLS sub-tables are shown as placeholder comments; their concrete shape is governed by the open questions tracked in [`001-server-roles.md §4`](../../specification/001-server-roles.md), [`002-transports.md §5`](../../specification/002-transports.md), [`003-crypto-policy.md`](../../specification/003-crypto-policy.md), [`005-dnssec-policy.md`](../../specification/005-dnssec-policy.md), and [`006-protocol-conformance.md`](../../specification/006-protocol-conformance.md).

#### Authoritative-only deployments (NET-011 row 1)

Authoritative × DNS classic on port 53:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[authoritative.listener]]
transport = "tcp"
address = "0.0.0.0"
port = 53

[[authoritative.zone]]
# Zone-level keys — open question.

[recursive]
enabled = false

[forwarder]
enabled = false
```

Authoritative × DoT on port 853:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[[authoritative.zone]]
# Zone-level keys — open question.

[recursive]
enabled = false

[forwarder]
enabled = false
```

Authoritative × DoH on port 443:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "doh"
address = "0.0.0.0"
port = 443
# tls.* keys — open question in 003-crypto-policy.md.
# DoH URI path — governed by NET-027 (default "/dns-query").

[[authoritative.zone]]
# Zone-level keys — open question.

[recursive]
enabled = false

[forwarder]
enabled = false
```

Authoritative × DoQ on port 853:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "doq"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[[authoritative.zone]]
# Zone-level keys — open question.

[recursive]
enabled = false

[forwarder]
enabled = false
```

#### Recursive-only deployments (NET-011 row 2)

Recursive × DNS classic on port 53:

```toml
[authoritative]
enabled = false

[recursive]
enabled = true
# Trust anchor path and NTA store path — open questions in
# 005-dnssec-policy.md.

[[recursive.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[recursive.listener]]
transport = "tcp"
address = "0.0.0.0"
port = 53

[forwarder]
enabled = false
```

Recursive × DoT on port 853:

```toml
[authoritative]
enabled = false

[recursive]
enabled = true

[[recursive.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[forwarder]
enabled = false
```

Recursive × DoH on port 443:

```toml
[authoritative]
enabled = false

[recursive]
enabled = true

[[recursive.listener]]
transport = "doh"
address = "0.0.0.0"
port = 443
# tls.* keys — open question in 003-crypto-policy.md.

[forwarder]
enabled = false
```

Recursive × DoQ on port 853:

```toml
[authoritative]
enabled = false

[recursive]
enabled = true

[[recursive.listener]]
transport = "doq"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[forwarder]
enabled = false
```

#### Forwarder-only deployments (NET-011 row 3)

Forwarder × DNS classic on port 53:

```toml
[authoritative]
enabled = false

[recursive]
enabled = false

[forwarder]
enabled = true

[[forwarder.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[forwarder.listener]]
transport = "tcp"
address = "0.0.0.0"
port = 53

[[forwarder.forward_zone]]
# Forward-zone rule keys — open question in 001-server-roles.md §4.
# Outbound upstream declaration — open questions in 002-transports.md §5.
```

Forwarder × DoT on port 853:

```toml
[authoritative]
enabled = false

[recursive]
enabled = false

[forwarder]
enabled = true

[[forwarder.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[[forwarder.forward_zone]]
# Forward-zone rule keys — open question in 001-server-roles.md §4.
```

Forwarder × DoH on port 443:

```toml
[authoritative]
enabled = false

[recursive]
enabled = false

[forwarder]
enabled = true

[[forwarder.listener]]
transport = "doh"
address = "0.0.0.0"
port = 443
# tls.* keys — open question in 003-crypto-policy.md.

[[forwarder.forward_zone]]
# Forward-zone rule keys — open question in 001-server-roles.md §4.
```

Forwarder × DoQ on port 853:

```toml
[authoritative]
enabled = false

[recursive]
enabled = false

[forwarder]
enabled = true

[[forwarder.listener]]
transport = "doq"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[[forwarder.forward_zone]]
# Forward-zone rule keys — open question in 001-server-roles.md §4.
```

#### Multi-role hybrid (demonstrating ROLE-008 precedence)

A single instance may activate more than one role. The four-step query-resolution precedence fixed by [`ROLE-008`](../../specification/001-server-roles.md) through [`ROLE-015`](../../specification/001-server-roles.md) is invariant and is not expressed in configuration:

```toml
[authoritative]
enabled = true

[[authoritative.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[authoritative.listener]]
transport = "tcp"
address = "0.0.0.0"
port = 53

[[authoritative.zone]]
# Zone-level keys — open question.

[recursive]
enabled = true

[[recursive.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853
# tls.* keys — open question in 003-crypto-policy.md.

[forwarder]
enabled = true

[[forwarder.listener]]
transport = "doh"
address = "0.0.0.0"
port = 443
# tls.* keys — open question in 003-crypto-policy.md.

[[forwarder.forward_zone]]
# Forward-zone rule keys — open question in 001-server-roles.md §4.
```

### Loader behaviour (summary, non-normative)

The normative statements live in [`ROLE-016`](../../specification/001-server-roles.md) through [`ROLE-023`](../../specification/001-server-roles.md). For orientation only:

- Unknown top-level tables: hard load failure.
- Unknown sub-keys under any role-activation table: hard load failure.
- Unknown `transport` value in a listener entry: hard load failure.
- Active role with no listener entries: hard load failure.
- `enabled = false` or absent role-activation table: role fully absent from the runtime, consistent with [`ROLE-003`](../../specification/001-server-roles.md) through [`ROLE-007`](../../specification/001-server-roles.md).

### Non-consequences (intentional scope limits)

The present decision does NOT fix:

- The per-zone key set under `[[authoritative.zone]]` (governed by the open questions in [`001-server-roles.md §4`](../../specification/001-server-roles.md) and [`006-protocol-conformance.md`](../../specification/006-protocol-conformance.md)).
- The forward-zone rule syntax under `[[forwarder.forward_zone]]` (governed by the "Forward-zone rule syntax and matching semantics" open question in [`001-server-roles.md §4`](../../specification/001-server-roles.md)).
- The TLS certificate and key material paths on `"dot"`, `"doh"`, and `"doq"` listeners (to be tracked in [`003-crypto-policy.md`](../../specification/003-crypto-policy.md)).
- The mTLS sub-table sub-keys (governed by the cross-transport mTLS validation policy open question in [`003-crypto-policy.md`](../../specification/003-crypto-policy.md)).
- The ACL configuration syntax (governed by the open question in [`007-threat-model.md`](../../specification/007-threat-model.md)).
- The Redis connection-block shape (governed by the open questions in [`013-persistence.md`](../../specification/013-persistence.md)).
- Any other sub-tree beyond the role-activation structure itself.

Each of those surfaces is governed by its own open-questions track and is explicitly out of scope here.

### Numbering note (operational)

This ADR takes the sequence number `0002`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The grandfather-batch guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") is descriptive (`expected to`), not mandatory (MUST). Because this ADR is authored before the grandfather batch is written (roadmap sprint ordering), the batch will occupy the next available sequence numbers at the time it is produced; the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md) SHOULD be updated at that time to reflect the actual starting number. The monotonic non-reuse rule of [`ENG-118`](../../specification/010-engineering-policies.md) is MUST and takes precedence over the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md).
