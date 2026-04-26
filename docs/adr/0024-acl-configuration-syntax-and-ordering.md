---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ACL configuration syntax and ordering semantics

## Context and Problem Statement

[`THREAT-033`](../../specification/007-threat-model.md) through [`THREAT-047`](../../specification/007-threat-model.md) fix the ACL matrix structure (multi-axis, default-deny on AXFR/IXFR/recursive/forwarder, default-allow on authoritative-on-auth-listener, views as ACL-driven response selection). The ACL configuration syntax was tracked as an open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md). The decision had to settle: format (TOML vs YAML); evaluation model (declaration order vs explicit priority); combination rules for deny-then-allow and negated matchers; per-listener-vs-global scoping.

## Decision Outcome

**Format**: TOML, aligned with [`ROLE-016`](../../specification/001-server-roles.md).

**Scope**: per-listener `[[<role>.listener.acl]]` arrays with global default fallback via `[acl] default_action`, per [`THREAT-108`](../../specification/007-threat-model.md).

**Rule shape**: mandatory `action` (`"allow"` | `"deny"`) + optional matcher fields per [`THREAT-109`](../../specification/007-threat-model.md), [`THREAT-110`](../../specification/007-threat-model.md).

**Matcher fields** (seven, one per ACL axis): `source_cidr`, `mtls_identity`, `tsig_key_name`, `transport`, `role`, `operation`, `qname_pattern`, per [`THREAT-110`](../../specification/007-threat-model.md).

**Negation**: `!` prefix on matcher value, per [`THREAT-111`](../../specification/007-threat-model.md).

**Evaluation**: AND within rule, first-match-wins across rules in declaration order, listener default → global default → per-class default fallback chain, per [`THREAT-112`](../../specification/007-threat-model.md). No explicit numeric priority field.

**Validation**: at configuration load, per [`THREAT-113`](../../specification/007-threat-model.md). Unknown matcher fields rejected per [`ROLE-021`](../../specification/001-server-roles.md).

## Considered Options

- **TOML + declaration order + per-listener with global default + 7 matcher fields + `!` negation (chosen).**
- **Explicit numeric `priority` field per rule + global rule pool.** Rejected: priority numbers are magic-number-prone; global pool loses per-listener context.
- **YAML.** Rejected: contradicts [`ROLE-016`](../../specification/001-server-roles.md).
- **Custom DSL.** Rejected: parser surface; no benefit over TOML.

## Example configurations

### Public resolver (default-deny everything except defined client networks)

```toml
[[recursive.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[recursive.listener.acl]]
action = "allow"
source_cidr = "192.0.2.0/24"        # ISP customer network
operation = "query"

[[recursive.listener.acl]]
action = "allow"
source_cidr = "2001:db8::/32"       # IPv6 customer network
operation = "query"

# Implicit fallback: THREAT-044 default-deny for recursive-role queries.
```

### Corporate DNS with views (mTLS-tenant isolation)

```toml
[[recursive.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853

[recursive.listener.mtls]
trust_anchor = "/etc/heimdall/corporate-ca.pem"
identity_source = "subject_dn"

# Tenant A → only allowed to forward via the tenant-A forward-zone rule:
[[recursive.listener.acl]]
action = "allow"
mtls_identity = "CN=tenant-a-svc,O=Acme,C=US"
qname_pattern = "*.tenant-a.acme.corp."

# Tenant B → only allowed to forward via the tenant-B forward-zone rule:
[[recursive.listener.acl]]
action = "allow"
mtls_identity = "CN=tenant-b-svc,O=Acme,C=US"
qname_pattern = "*.tenant-b.acme.corp."

# Catch-all deny for any other identity / qname combination.
[[recursive.listener.acl]]
action = "deny"
```

### Authoritative server (default-allow with negative deny for known abusive prefixes)

```toml
[[authoritative.listener]]
transport = "udp"
address = "0.0.0.0"
port = 53

[[authoritative.listener.acl]]
action = "deny"
source_cidr = "203.0.113.0/24"     # known-abusive prefix (operator-curated)

# THREAT-043 implicit default-allow for authoritative-role queries on auth listeners.

[[authoritative.listener.acl]]
action = "allow"
source_cidr = "10.0.0.0/8"
operation = "axfr"
tsig_key_name = "secondary-key-1"  # explicit allow for authorised secondary
```

### AXFR/IXFR explicit allow on a separate listener (default-deny per `THREAT-042`)

```toml
[[authoritative.listener]]
transport = "tcp"
address = "0.0.0.0"
port = 53

[[authoritative.listener.acl]]
action = "allow"
operation = "axfr"
tsig_key_name = "secondary-key-1"
source_cidr = "10.0.0.5/32"

[[authoritative.listener.acl]]
action = "allow"
operation = "ixfr"
tsig_key_name = "secondary-key-1"
source_cidr = "10.0.0.5/32"

# All other AXFR/IXFR remain default-denied per THREAT-042.
```

## Closure

The "ACL configuration syntax" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). The remaining ACL-track open questions (action on deny, deny logging format, dynamic reload, compiled internal representation) remain for sprint 4 tasks #29–#32.

## Numbering

This ADR takes the sequence number `0024`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md).
