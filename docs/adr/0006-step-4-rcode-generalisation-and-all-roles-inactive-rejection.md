---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Step-4 RCODE generalisation and rejection of all-roles-inactive configurations

## Context and Problem Statement

[`ROLE-024`](../../specification/001-server-roles.md) closed the forwarder-only sub-case of step 4 of the four-step query-resolution precedence: when the forwarder role is active and the recursive resolver role is inactive, the response to a query that no rule serves is `REFUSED` with EDE INFO-CODE `20` ("Not Authoritative"), byte-identical across every transport. The decision rationale for that sub-case is recorded in [`0005-step-4-rcode-forwarder-only-no-match.md`](0005-step-4-rcode-forwarder-only-no-match.md).

[`ROLE-012`](../../specification/001-server-roles.md) however still left open the response code returned under any other step-4 trigger combination — in particular: an authoritative-only deployment whose configured zones do not match the queried name; a hybrid deployment with the authoritative role and the forwarder role both active and the recursive resolver role inactive, where the query matches neither a locally authoritative zone nor any forward-zone rule; and the degenerate case of an instance with all three role-activation tables resolving to `enabled = false` (so that every query unconditionally produces a step-4 outcome).

The present decision settles two questions jointly:

1. **The response code for every step-4 trigger combination not addressed by [`ROLE-024`](../../specification/001-server-roles.md)** — whether to generalise the `REFUSED` + EDE `20` response uniformly to all step-4 triggers, or to differentiate by trigger.
2. **The handling of the all-roles-inactive configuration** — whether to accept it (every query becomes step 4, every response is `REFUSED` + EDE `20`) or to reject it at configuration load (the instance has no operational purpose).

The decisions had to compose with [`ROLE-024`](../../specification/001-server-roles.md), with the structural-gating discipline of [`ROLE-003`](../../specification/001-server-roles.md) through [`ROLE-007`](../../specification/001-server-roles.md), with the load-time rejection patterns established by [`ROLE-019`](../../specification/001-server-roles.md), [`ROLE-021`](../../specification/001-server-roles.md), and [`FWD-023`](../../specification/014-forward-zones.md), and with the operator-experience expectations of "Assume Nothing" and fail-loud-at-load fixed by [`../../CLAUDE.md`](../../CLAUDE.md).

## Decision Drivers

- **Semantic uniformity at step 4**. Every trigger combination that produces a step-4 outcome shares the same operator semantics: Heimdall has no configured path to serve the query. The response should reflect that uniform semantics, not impose distinctions where none exist.
- **Operator-experience simplicity**. A single response shape across all step-4 triggers is easier for operators to document, test, observe, and explain to clients.
- **Test-matrix economy**. A uniform response replaces a per-trigger differentiation matrix with a single cell exercised against every trigger, reducing both the breadth of the test suite and the surface for divergence bugs.
- **Operator fail-loud at load** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). A configuration that describes an instance with no operational purpose is a configuration error, not an exotic deployment shape that needs runtime tolerance.
- **Consistency with existing structural-rejection precedents**. [`ROLE-019`](../../specification/001-server-roles.md) (active role with no listeners), [`ROLE-021`](../../specification/001-server-roles.md) (unknown configuration keys), and [`FWD-023`](../../specification/014-forward-zones.md) (`fallback = "recursive"` against inactive recursive) all reject structural inconsistencies at load. An instance with no role active is the same class of structural inconsistency.

## Considered Options

### A. Step-4 RCODE generalisation

- **Uniform `REFUSED` + EDE `20` for every step-4 trigger (chosen).** Single response shape; [`ROLE-024`](../../specification/001-server-roles.md) becomes one instance of a general rule. Existing per-transport test vectors `F9–F14` in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md) cover the response shape; the additional triggers exercise the same response.
- **Differentiate per trigger combination.** Each of the trigger combinations (auth-only-no-match, hybrid both miss, all-roles-inactive) gets its own RCODE / EDE pair. Maximum diagnostic specificity, maximum complexity. No use case for the differentiation has been identified — the operator semantics is identical across triggers.
- **Same RCODE (`REFUSED`), differentiated EDE per trigger.** Compromise between A.1 and A.2. The differentiation would have to map onto IANA-registered EDE codes; the only candidate codes are EDE `18` ("Prohibited"), `20` ("Not Authoritative"), and `28` ("Unable To Conform To Policy"), and none expresses a meaningful distinction across the trigger combinations beyond what EDE `20` already captures.

### B. Handling of the all-roles-inactive configuration

- **Reject at configuration load (chosen).** The configuration loader cross-checks every role-activation table; if all three resolve to `enabled = false` (or are absent), the configuration is rejected and the instance refuses to start. Composes with [`ROLE-019`](../../specification/001-server-roles.md), [`ROLE-021`](../../specification/001-server-roles.md), and [`FWD-023`](../../specification/014-forward-zones.md).
- **Accept silently.** The instance starts, every query produces a step-4 outcome under the chosen [`ROLE-025`](../../specification/001-server-roles.md), every response is `REFUSED` + EDE `20`. The instance has no operational purpose but is reachable on the listener it does not bind (which under [`ROLE-019`](../../specification/001-server-roles.md) means there are no listeners; the instance is therefore a process running that nothing can talk to). The configuration error becomes a runtime non-state.
- **Accept with warning at load.** As above, but the loader emits a structured warning. Warnings tend to be filtered out of CI / CD pipelines and operational dashboards; the configuration error regresses to silent acceptance in practice. Same failure mode as in [`FWD-023`](../../specification/014-forward-zones.md)'s rejection rationale.

## Decision Outcome

**A. Step-4 RCODE generalisation.** Uniform `REFUSED` + EDE INFO-CODE `20` ("Not Authoritative") for every step-4 trigger combination not already addressed by [`ROLE-024`](../../specification/001-server-roles.md). The composition of [`ROLE-024`](../../specification/001-server-roles.md) and [`ROLE-025`](../../specification/001-server-roles.md) constitutes the full closure of the step-4 response. The response is byte-identical across every transport defined in [`002-transports.md`](../../specification/002-transports.md), and the per-transport test vectors `F9–F14` in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md) demonstrate the per-transport invariance for the response shape, which extends unchanged to the additional trigger combinations covered by [`ROLE-025`](../../specification/001-server-roles.md).

**B. All-roles-inactive configuration.** Rejected at load by [`ROLE-026`](../../specification/001-server-roles.md). The instance refuses to start.

### Rejection rationale — RCODE differentiation

The **per-trigger differentiation** option was rejected on the absence of a use case for the distinction. The operator semantics across the trigger combinations is identical:

| Trigger combination | Operator semantics |
|---|---|
| Forwarder-only-no-match (covered by [`ROLE-024`](../../specification/001-server-roles.md)) | Operator declared an exhaustive forward-zone rule list; query is outside it. |
| Auth-only-no-match | Operator declared an exhaustive authoritative-zone list; query is outside it. |
| Hybrid auth + forwarder, both miss, recursive inactive | Operator declared exhaustive lists at every active role; query is outside all of them. |
| All-roles-inactive (rejected at load by [`ROLE-026`](../../specification/001-server-roles.md)) | Configuration error; not a runtime state. |

In every case the operator's posture is "Heimdall is not the right server for this name". `REFUSED` per [RFC 1035 §4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1) is the canonical RCODE for that posture, and the EDE INFO-CODE `20` ("Not Authoritative") per [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) is the canonical structured-diagnostic supplement. Differentiation would impose a vocabulary on clients that the underlying conditions do not justify.

The **same-RCODE-different-EDE** compromise was rejected because the alternative EDE codes that could serve as differentiators (`18` "Prohibited", `28` "Unable To Conform To Policy") either carry connotations that mismatch the actual operator semantics (`18` aligns with the IANA "active denial" cluster alongside "Blocked" and "Censored", suggesting a posture Heimdall is not adopting in any of the trigger combinations) or are too generic to add diagnostic value (`28` does not distinguish a "no path" condition from any other operator-policy-driven response).

### Rejection rationale — silent acceptance of all-roles-inactive

**Silent acceptance** was rejected on three grounds. First, an instance with no role active has no operational purpose: it has no listeners (under [`ROLE-019`](../../specification/001-server-roles.md), an active role MUST have at least one listener; an inactive role MUST NOT instantiate a listener under [`ROLE-004`](../../specification/001-server-roles.md), so a configuration with no active role binds no socket and accepts no traffic). Tolerating this state at runtime would silently transform a configuration error into a "running process that does nothing" condition, which is harder to diagnose than a load-time rejection. Second, the discipline of fail-loud-at-load already established by [`ROLE-019`](../../specification/001-server-roles.md), [`ROLE-021`](../../specification/001-server-roles.md), and [`FWD-023`](../../specification/014-forward-zones.md) sets the expectation that the loader is the authoritative point at which configuration errors surface; admitting an exception for the all-roles-inactive case would inconsistently handle the same failure class. Third, no legitimate use case for an instance with no active role has been identified — even configuration-validation tooling would normally validate and exit, not start a long-running process.

The **warning-only** middle ground was rejected for the same reason it was rejected in [`FWD-023`](../../specification/014-forward-zones.md): operational warnings are routinely filtered, batched, or dropped in CI / CD pipelines and in container-startup logs. A configuration accepted with a warning is, in practice, a configuration accepted silently; the chosen reject-at-load model removes that failure mode entirely.

## Consequences

### Closure of the step-4 response

The combination of [`ROLE-024`](../../specification/001-server-roles.md) and [`ROLE-025`](../../specification/001-server-roles.md) constitutes the complete normative closure of the response code returned under [`ROLE-012`](../../specification/001-server-roles.md). [`ROLE-012`](../../specification/001-server-roles.md) is updated to identify both requirements as the closure of step 4. The "Error code for step 4 of the precedence" open question is removed from [`001-server-roles.md §4`](../../specification/001-server-roles.md). With the present decision and with the prior closures of tasks #3 through #6 in the same sprint, [`001-server-roles.md §4`](../../specification/001-server-roles.md) carries no remaining open questions.

### New configuration-load cross-check

[`ROLE-026`](../../specification/001-server-roles.md) introduces one new structural cross-check at configuration load:

- If `[authoritative]`, `[recursive]`, and `[forwarder]` all resolve to `enabled = false` (each table absent or each table with `enabled = false`), the configuration is rejected and the instance refuses to start.

This composes with the existing structural cross-checks of [`ROLE-019`](../../specification/001-server-roles.md), [`ROLE-021`](../../specification/001-server-roles.md), [`FWD-002`](../../specification/014-forward-zones.md), and [`FWD-023`](../../specification/014-forward-zones.md).

### Test-vector reuse

The per-transport test vectors `F9–F14` in [`014-forward-zones.md §4`](../../specification/014-forward-zones.md) cover the response shape (byte-identical RCODE `REFUSED` + EDE `20` across UDP, TCP, DoT, DoH/H2, DoH/H3, DoQ). Under [`ROLE-025`](../../specification/001-server-roles.md), the same response shape applies to every other step-4 trigger combination; per-trigger test cases (auth-only-no-match, hybrid both miss) need only verify the trigger path and assert that the response shape matches the F9–F14 reference, not enumerate per-transport variations.

The all-roles-inactive case under [`ROLE-026`](../../specification/001-server-roles.md) does not produce a query-time test vector at all; the test is "the configuration is rejected at load and the instance refuses to start", which exercises the loader and not the resolution path.

### Non-consequences (deliberate scope limits)

- **Other step-4-adjacent decisions.** The present decision does not address response code variations that operators might want for ACL denies, RPZ actions, RRL drops, or other policy-driven responses; those are governed by [`007-threat-model.md`](../../specification/007-threat-model.md) and are out of scope here.
- **Caching of step-4 responses.** Whether and how clients cache `REFUSED` + EDE `20` responses is governed by client-side conventions and by [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308) ("Negative Caching of DNS Queries"), which permits but does not require caching of `REFUSED`. The present decision does not mandate any cache-side behaviour.
- **The complete catalogue of EDE codes per situation.** The broader open question of which EDE INFO-CODEs accompany other Heimdall response situations remains tracked in [`006-protocol-conformance.md §7`](../../specification/006-protocol-conformance.md), now further narrowed by `EDE 20` being fixed for the entire step-4 response under [`ROLE-024`](../../specification/001-server-roles.md) and [`ROLE-025`](../../specification/001-server-roles.md).

### Numbering

This ADR takes the sequence number `0006`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11), to reflect the actual starting number of that batch given the sprint ordering already established.
