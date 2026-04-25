---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Forward-zone rule fallback behaviour on upstream failure

## Context and Problem Statement

[`ROLE-010`](../../specification/001-server-roles.md) in [`001-server-roles.md`](../../specification/001-server-roles.md) defines step 2 of the four-step query-resolution precedence: a query whose name does not fall within any locally authoritative zone is matched against the configured forward-zone rules and, if a rule matches, forwarded to the upstreams declared by the rule. The syntax, matching semantics, and rule-precedence algorithm of forward-zone rules were fixed by [`FWD-001`](../../specification/014-forward-zones.md) through [`FWD-017`](../../specification/014-forward-zones.md) in [`014-forward-zones.md`](../../specification/014-forward-zones.md), recorded in [`0003-forward-zone-rule-syntax-and-precedence.md`](0003-forward-zone-rule-syntax-and-precedence.md). The behaviour of step 2 when **all upstreams of a matching rule have been exhausted** with every contact attempt resulting in failure was however left open: the question was whether the query falls through to step 3 (the recursive resolver, if active under [`ROLE-011`](../../specification/001-server-roles.md)) or whether the upstream failure is propagated to the client. The present decision closes that question.

The decision had to settle three sub-questions jointly:

1. **The default fallback model and its operator-facing controls.** Per-rule, global, hybrid, or mandatory-explicit; fail-closed default versus fail-open default; the enum of permitted values.
2. **The set of upstream outcomes that constitute "failure" for the purposes of fallback handling.** Whether transport failures and DNS-protocol RCODEs other than NOERROR / NXDOMAIN are uniformly treated as failures, or whether some subset (for example, only transport failures, or transport failures plus SERVFAIL) qualifies.
3. **The handling of structural inconsistencies in configuration.** What happens when a rule declares `fallback = "recursive"` but the recursive resolver role is not active in the same instance.

The decisions had to compose with the existing fail-safe / fail-closed posture of [`../../CLAUDE.md`](../../CLAUDE.md), with the structured-event observability obligation of [`THREAT-080`](../../specification/007-threat-model.md) in [`007-threat-model.md`](../../specification/007-threat-model.md), and with the operator semantics established by widely-deployed DNS forwarders (Unbound `forward-first`, BIND `forward first / forward only`, dnsmasq `--server` with strict-order semantics).

## Decision Drivers

- **Fail-closed default** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). The forwarder boundary must default to the safer of two interpretations of an ambiguous outcome.
- **No silent data exfiltration**. A forward-zone rule directs queries for a specific zone to specific upstreams; if those upstreams fail, the natural and unsafe failure mode is silent re-routing through public recursion. The default behaviour must not enable that mode.
- **Operator intent preservation**. A rule expresses operator routing intent; the default must respect that intent rather than overriding it on failure.
- **Operator opt-in for resilience**. Operators who want the inverse (fail-open with recursion as a backup) must have an explicit, per-rule mechanism to declare that intent.
- **Operator parity**. Operators migrating from Unbound, BIND, or dnsmasq must encounter behaviour consistent with the equivalent configuration in those products.
- **"Assume Nothing" at configuration boundary** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Inconsistent configurations must be detected at load, not at first failing query.
- **Observability**. Every fallback event must produce a structured signal so that operators can detect failing upstreams without relying on client-side complaints.

## Considered Options

### A. Default fallback model

- **Per-rule `fallback` enum field with default `"error"` (chosen).** Each `[[forwarder.forward_zone]]` entry MAY carry `fallback = "error" | "recursive"`, defaulting to `"error"` (fail-closed). Two-value enum, simple validation, simple semantics.
- **Per-rule `fallback` enum field with default `"recursive"` (fail-open default).** Same surface, opposite default. Operator must opt into fail-closed for sensitive zones.
- **Global `default_fallback` in `[forwarder]` plus per-rule override.** Operator declares a global default at the role level and overrides per rule. Two sources of truth for any given rule's effective fallback value.
- **Mandatory per-rule explicit declaration (no implicit default).** Every rule MUST carry the `fallback` field; loader rejects omission. Maximum verbosity.

### B. Upstream-outcome set that triggers fallback

- **All non-success outcomes are failures (chosen).** Successful response set fixed at NOERROR with answer records, NODATA, and NXDOMAIN; everything else (SERVFAIL, REFUSED, FORMERR, NOTIMP, other RCODEs, transport failures, malformed empty responses) is failure. Single, total, simple model.
- **Transport failures plus SERVFAIL only.** REFUSED and other RCODEs treated as legitimate upstream policy signals and propagated unconditionally. More conservative on RCODE handling but introduces classification ambiguity for other RCODEs.
- **Transport failures only.** Any DNS-level RCODE returned by the upstream is propagated to the client, regardless of `fallback`. Most conservative; can mask persistent upstream malfunction (an upstream that always returns SERVFAIL silently produces SERVFAIL to the client without ever invoking fallback handling).
- **Operator-configurable per rule.** Per-rule list of RCODEs and failure conditions that trigger fallback. Maximum flexibility, maximum complexity, maximum room for misconfiguration.

### C. Handling of `fallback = "recursive"` when the recursive role is inactive

- **Reject at configuration load (chosen).** Loader cross-checks every `[[forwarder.forward_zone]]` entry's `fallback` value against the activation state of `[recursive]`; configuration is rejected and the instance refuses to start when the cross-check fails.
- **Silently downgrade to `fallback = "error"`.** Loader accepts the configuration; the rule behaves as if it were declared with the default fail-closed value. Configuration error becomes invisible.
- **Fall through to step 4 of the four-step precedence at runtime.** The mismatch is detected at query time; the resulting error response is governed by [`ROLE-012`](../../specification/001-server-roles.md), which itself is open.
- **Accept with warning at load.** Loader emits a warning and continues. Warnings tend to be filtered out of CI / CD pipelines and operational dashboards; the failure mode regresses to silent acceptance in practice.

### D. Client-visible response in fail-closed mode

- **Synthesise SERVFAIL on transport failures, propagate the upstream's RCODE on RCODE-level failures (chosen).** Transparent-forwarder semantics for the RCODE portion of the failure space; well-defined synthesis where no upstream RCODE exists.
- **Always synthesise SERVFAIL.** Heimdall returns SERVFAIL regardless of what (if anything) the upstream said. Loses the upstream's policy signal (a REFUSED from the upstream is laundered into SERVFAIL).
- **Always propagate the upstream's RCODE, synthesising one only when the upstream did not respond.** Equivalent to the chosen option in practice.

## Decision Outcome

**A. Default fallback model.** Per-rule `fallback` enum with values `"error"` and `"recursive"` and default `"error"`, per [`FWD-018`](../../specification/014-forward-zones.md).

**B. Upstream-outcome set.** All outcomes that are not a successful response under [`FWD-019`](../../specification/014-forward-zones.md) are failures under [`FWD-020`](../../specification/014-forward-zones.md). The successful set is exactly NOERROR with answer records, NODATA, and NXDOMAIN.

**C. Inconsistent configuration handling.** A configuration with at least one `fallback = "recursive"` rule and an inactive `[recursive]` role is rejected at load, per [`FWD-023`](../../specification/014-forward-zones.md).

**D. Fail-closed mode response.** Transport failures synthesise SERVFAIL; RCODE-level failures propagate the upstream's RCODE unchanged, per [`FWD-021`](../../specification/014-forward-zones.md).

**E. Observability.** Every fallback invocation under [`FWD-021`](../../specification/014-forward-zones.md) or [`FWD-022`](../../specification/014-forward-zones.md) emits a structured event under [`THREAT-080`](../../specification/007-threat-model.md), per [`FWD-024`](../../specification/014-forward-zones.md).

### Rejection rationale — default fallback model

The **fail-open default** (default `"recursive"`) was rejected on safety grounds. A forward-zone rule for `internal.corp.` directed to an internal upstream resolver carries an implicit operator intent of "queries for this zone go to that upstream and only to that upstream". Under a fail-open default, the loss of the internal upstream causes those queries to be served by the public recursive resolver, including any internal hostname leakage that the rule was implicitly preventing. The cost of remembering to opt every internal zone into `fallback = "error"` is a configuration tax paid on every deployment; the cost of forgetting once is a data-exfiltration incident. The asymmetry favours the fail-closed default.

The **global default with per-rule override** model was rejected on configuration-clarity grounds. A rule's effective fallback value would depend on both the local field and the global setting, with the local field unset meaning "inherit the global", which is a third state on top of the two enum values. Diffing two configurations that differ only in their global default would change the effective behaviour of every rule that did not explicitly set `fallback`, which is a non-local effect. The chosen per-rule-with-implicit-default model has a single rule for resolving the value of `fallback` (set or default to `"error"`) and no non-local effects.

The **mandatory explicit declaration** model was rejected on ergonomic grounds. The default `"error"` is correct for the dominant case (an internal-routing forward-zone rule); requiring every rule to repeat that value adds verbosity without information. The chosen model gets the same safety property by default and requires extra syntax only for the minority case (resilient public-mirror or public-zone forwarding where recursive fallback is preferred).

### Rejection rationale — upstream-outcome set

The **transport-failures-plus-SERVFAIL-only** model was rejected on simplicity grounds. The argument that REFUSED is a legitimate operator-policy signal from the upstream is correct, but the chosen model already preserves that signal through the transparent-forwarder propagation rule of [`FWD-021`](../../specification/014-forward-zones.md): under `fallback = "error"`, a REFUSED from the upstream is propagated to the client unchanged. The trade-off in the smaller failure set is therefore not visible to clients in fail-closed mode; it only differs in fail-open mode, where the question is whether REFUSED triggers recursion or stops at the upstream. Operators who opted into `fallback = "recursive"` did so to obtain resilience; treating REFUSED as terminal in that mode would partially defeat the opt-in.

The **transport-failures-only** model was rejected on visibility grounds. An upstream that persistently returns SERVFAIL — for example, a misconfigured authoritative behind the rule's upstream — would, under this model, never invoke fallback. Heimdall would dutifully forward the SERVFAIL to clients indefinitely, and there would be no observable signal at the resolver level that the upstream was malfunctioning (SERVFAIL responses are normal traffic). The chosen model invokes fallback handling on SERVFAIL, which in `fallback = "error"` mode produces the same client-visible result (propagated SERVFAIL) but fires a structured event under [`FWD-024`](../../specification/014-forward-zones.md), giving operators visibility into the underlying upstream malfunction.

The **operator-configurable per-rule** model was rejected on complexity grounds. A configuration knob for "which RCODEs trigger fallback" multiplies the rule-shape complexity by the size of the RCODE alphabet, and most operators have no use for the granularity; the dominant use case is binary (resilient zone versus strict zone), and the chosen enum captures that binary directly.

### Rejection rationale — inconsistent configuration handling

**Silent downgrade to `fallback = "error"`** was rejected because it transforms a structural configuration error into a behavioural runtime degradation that no operator inspects. A rule declared as `fallback = "recursive"` carries an operator-stated expectation of recursive failover; if that expectation cannot be satisfied (because recursive is inactive), the operator must be told before the configuration is accepted, not when an upstream first fails.

**Fall through to step 4 of the precedence** was rejected because it couples this decision to another open question ([`ROLE-012`](../../specification/001-server-roles.md)'s SERVFAIL-vs-REFUSED choice) and pushes the symptom deeper into the resolution path, where it is harder to diagnose. The error is in configuration, not in resolution; the loader is the right place to surface it.

**Warning at load** was rejected because operational warnings are routinely filtered, batched, or dropped in CI / CD pipelines and in container-startup logs. A configuration accepted with a warning is, in practice, a configuration accepted silently. The chosen reject-at-load model removes that failure mode entirely.

### Rejection rationale — fail-closed mode response

**Always synthesise SERVFAIL** was rejected because it discards the upstream's policy signal where one exists. An upstream that returns REFUSED is communicating a deliberate decision (typically "I do not serve queries from your network"); turning that into SERVFAIL conflates a policy denial with a server error and leaves the client to discover the policy denial through other means. The chosen transparent-forwarder propagation rule preserves the upstream's signal where it exists and synthesises a default only where no signal exists (transport failures).

## Consequences

### Operator-visible shape with `fallback`

```toml
# Default fail-closed behaviour (no fallback to recursion):
[[forwarder.forward_zone]]
zone = "internal.corp."
match = "suffix"
upstream = [{ address = "10.0.0.1", port = 53, transport = "udp" }]

# Explicit opt-in to recursive fallback (requires [recursive].enabled = true):
[[forwarder.forward_zone]]
zone = "public-mirror.example."
match = "suffix"
fallback = "recursive"
upstream = [{ address = "192.0.2.1", port = 853, transport = "dot" }]
```

### Upstream-outcome to client-outcome matrix

The behaviour fixed by [`FWD-019`](../../specification/014-forward-zones.md) through [`FWD-022`](../../specification/014-forward-zones.md) is the cross-product of upstream outcomes against `fallback` modes. The normative version of the matrix is in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md); the version below is repeated here for the convenience of ADR readers.

| Upstream outcome (after all upstreams of the rule exhausted) | `fallback = "error"` | `fallback = "recursive"` |
|---|---|---|
| NOERROR with answer records | Propagated unchanged | Propagated unchanged |
| NODATA | Propagated unchanged | Propagated unchanged |
| NXDOMAIN | Propagated unchanged | Propagated unchanged |
| SERVFAIL | Propagated unchanged | → step 3 (recursive) |
| REFUSED | Propagated unchanged | → step 3 (recursive) |
| Other RCODEs (FORMERR, NOTIMP, reserved/extended) | Propagated unchanged | → step 3 (recursive) |
| Transport-level failure | SERVFAIL synthesised | → step 3 (recursive) |
| Malformed empty NOERROR | SERVFAIL synthesised | → step 3 (recursive) |

### Loader-time configuration rejection

The chosen model adds one new structural cross-check at configuration load:

- If any `[[forwarder.forward_zone]]` entry has `fallback = "recursive"` and `[recursive].enabled = false` or `[recursive]` is absent, the configuration is rejected and the instance refuses to start.

This composes with the existing structural cross-checks of [`ROLE-019`](../../specification/001-server-roles.md) (active role with no listeners), [`ROLE-021`](../../specification/001-server-roles.md) (unknown keys), and [`FWD-002`](../../specification/014-forward-zones.md) (missing `zone` or `upstream`). The instance starts only if all such cross-checks pass.

### Observability

Every fallback invocation under [`FWD-021`](../../specification/014-forward-zones.md) (fail-closed handling) and [`FWD-022`](../../specification/014-forward-zones.md) (recursive handover) emits a structured event under [`THREAT-080`](../../specification/007-threat-model.md), with the rule identity, the upstream attempt sequence, the per-attempt outcome classification, the rule's `fallback` value, and the client-visible outcome. This obligation extends the existing event catalogue maintained by [`THREAT-080`](../../specification/007-threat-model.md) and is consistent with the non-exhaustive-list discipline that document establishes.

### Non-consequences (deliberate scope limits)

- **Inter-upstream fallback within a single rule.** The order in which the upstreams of a single rule are tried, the per-upstream timeouts, and whether an encrypted-to-plain downgrade is permitted between upstreams of the same rule remain governed by the open question "Upstream fallback policy on failure (forwarder)" in [`002-transports.md §5`](../../specification/002-transports.md). The text of that open question is updated to make this boundary explicit, but the question itself remains open.
- **Recursion failure handling.** When [`FWD-022`](../../specification/014-forward-zones.md) hands the query to step 3 and the recursive resolver itself fails to resolve, the resulting SERVFAIL is the recursive resolver's responsibility to produce; no further forward-zone rule is consulted, and there is no "second fallback" path.
- **Cache interaction.** Whether and how recursive results obtained under [`FWD-022`](../../specification/014-forward-zones.md) are cached by the segregated recursive cache (cf. [`004-cache-policy.md`](../../specification/004-cache-policy.md)) is governed by the cache policy and is not affected by the present decision; from the cache's perspective, the recursive result obtained after fallback is indistinguishable from a recursive result obtained directly under [`ROLE-011`](../../specification/001-server-roles.md).

### Numbering

This ADR takes the sequence number `0004`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11), to reflect the actual starting number of that batch given the sprint ordering already established.
