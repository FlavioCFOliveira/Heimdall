---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# HTTP/2 and HTTP/3 hardening numeric defaults (DoH over HTTP/2, DoH over HTTP/3)

## Context and Problem Statement

[`SEC-036`](../../specification/003-crypto-policy.md) through [`SEC-045`](../../specification/003-crypto-policy.md) fix the structural HTTP/2 and HTTP/3 hardening posture for DoH over HTTP/2 and DoH over HTTP/3: explicit server-layer enforcement (not library defaults) of header-block size, per-connection stream-concurrency cap, HPACK and QPACK dynamic-table caps, rapid-reset detection (CVE-2023-44487), CONTINUATION-frame cap (CVE-2024-27983), control-frame rate limits, header-block completion timeout, and flow-control window bounds. [`SEC-046`](../../specification/003-crypto-policy.md) deferred the numeric calibration of these mitigations as an open question.

The present decision fixes the numeric defaults, the operator-configurable ranges, the load-time validation invariants, and the per-mitigation conformance test obligations.

## Decision Drivers

- **DoH workload profile**. DoH queries are small (a few hundred bytes); responses rarely exceed 4 KiB even with DNSSEC; concurrent-stream usage is modest in browser-driven DoH and substantial in iterative-resolver-driven DoH. The defaults should comfortably accommodate both without leaving the documented attack vectors reachable.
- **Published attack thresholds**. CVE-2023-44487 (rapid-reset) and CVE-2024-27983 (CONTINUATION flood) have well-understood thresholds at which the attack becomes effective; the defaults must be below those thresholds.
- **Industry alignment**. Major HTTP/2 stacks (nginx, Cloudflare, h2load) converge on similar conservative defaults: 100 max concurrent streams, 4 KiB HPACK table, 16 KiB header-block budgets, 5–10 second header-block timeouts.
- **Operator tunability**. Specific deployments may need higher or lower thresholds (browser-heavy DoH may need more streams; constrained edge deployments may need lower limits); the configuration must accept overrides within bounded ranges.
- **Misconfiguration prevention**. Some combinations of values are nonsensical (max-window below initial-window; header-block-size above flow-control window; cap of zero on per-block CONTINUATION); load-time invariants prevent these.

## Considered Options

- **Conservative defaults aligned with industry baselines, operator-configurable in bounded ranges (chosen).** 16 KiB header block, 100 streams, 4 KiB HPACK / QPACK, 100 RST_STREAM / 30 s rapid-reset, 32 CONTINUATION cap, 200 control frames / 60 s, 5 s header-block timeout, 64 KiB initial / 16 MiB max flow-control.
- **Aggressive defaults (16 streams, 8 KiB headers, 16 CONTINUATION cap).** Smaller attack surface; risks false positives against legitimate browser clients that open many streams.
- **Relaxed defaults (1000 streams, 64 KiB headers, 256 CONTINUATION cap).** More operational headroom; higher attack surface, in particular for header-block-size where a 64 KiB block is a known DoH-irrelevant size.
- **Adaptive runtime baselining.** Heimdall measures peer behaviour and adapts thresholds. Requires baseline traffic data and a feedback mechanism; complexity not justified by use case.

## Decision Outcome

**A. Numeric defaults table.** Per [`SEC-077`](../../specification/003-crypto-policy.md). Twelve operator-configurable parameters, each with an enforced inclusive range.

**B. Load-time invariants.** Per [`SEC-078`](../../specification/003-crypto-policy.md). Five invariants verified at instance start; violation rejected at load.

**C. Conformance test matrix.** Per [`SEC-079`](../../specification/003-crypto-policy.md). At minimum 18 normative cells (9 mitigations × 2 transports), each exercised at threshold-plus-one and threshold-minus-one, with cross-check against [`THREAT-080`](../../specification/007-threat-model.md) structured events.

### Numeric defaults summary

| Mitigation | Default | Industry reference |
|---|---|---|
| `max_header_block_bytes` | 16 KiB | nginx `large_client_header_buffers`-equivalent |
| `max_concurrent_streams` | 100 | nginx / Apache HTTPD / Cloudflare default |
| `hpack_dyn_table_max` | 4 KiB | RFC 9113 default |
| `qpack_dyn_table_max` | 4 KiB | RFC 9204 default |
| `rapid_reset_threshold_count` / `window_seconds` | 100 / 30 s | Below CVE-2023-44487 effective rate |
| `continuation_frame_cap` | 32 | Far below CVE-2024-27983 effective floods |
| `control_frame_threshold_count` / `window_seconds` | 200 / 60 s | Aggregate cap on SETTINGS+PING+RST_STREAM+PRIORITY |
| `header_block_timeout_seconds` | 5 s | nginx `client_header_timeout`-equivalent |
| `flow_control_initial_bytes` | 64 KiB | RFC 9113 default; sufficient for DoH responses |
| `flow_control_max_bytes` | 16 MiB | Bound against peer-induced inflation |

### Load-time invariants

- `flow_control_max_bytes >= flow_control_initial_bytes`.
- `max_header_block_bytes <= flow_control_initial_bytes`.
- `continuation_frame_cap >= 1`.
- `control_frame_threshold_count >= 1`.
- All values non-negative integers within their permitted ranges.

### Rejection rationale

The **aggressive defaults** option was rejected because they risk false positives against legitimate browser clients. A browser opens multiple concurrent streams during DoH operation; tightening `max_concurrent_streams` to 16 would cause stream-creation failures for normal usage. The chosen defaults match the industry baseline closely enough that operators familiar with nginx- or Cloudflare-style HTTP/2 hardening get the expected behaviour out of the box.

The **relaxed defaults** option was rejected because they leave the published CVE attack surfaces partially open. A 64 KiB header-block size is far above any DoH need (DoH headers are well under 1 KiB) and creates space for HPACK / QPACK decompression-bomb attempts. A 1000-stream cap is high enough that a single attacker connection can saturate the resolver's memory budget per `THREAT-066`.

The **adaptive runtime baselining** option was rejected on complexity grounds: it requires a baseline-collection phase (problematic for a fresh deployment), a feedback loop (which itself becomes an attack target), and a divergence-detection mechanism (false positives at scale). Static defaults with operator override under bounded ranges cover the operational range without those costs.

## Consequences

### Operator-visible configuration shape

```toml
[doh.hardening]
max_header_block_bytes = 16384
max_concurrent_streams = 100
hpack_dyn_table_max = 4096
qpack_dyn_table_max = 4096
rapid_reset_threshold_count = 100
rapid_reset_window_seconds = 30
continuation_frame_cap = 32
control_frame_threshold_count = 200
control_frame_window_seconds = 60
header_block_timeout_seconds = 5
flow_control_initial_bytes = 65536
flow_control_max_bytes = 16777216
```

A configuration that omits the section entirely uses the documented defaults. A configuration that sets only some keys uses the defaults for the omitted keys.

### Conformance test matrix

The 18 mandated cells cover every `SEC-037`–`SEC-045` mitigation × {DoH/H2, DoH/H3}, each exercised with a threshold-plus-one payload (assert termination) and a threshold-minus-one payload (assert no termination). Termination events MUST emit structured events under [`THREAT-080`](../../specification/007-threat-model.md). The matrix is the minimum surface; implementations MAY exercise additional payloads (e.g., randomised stress around the threshold).

### Closure

The "HTTP/2 and HTTP/3 hardening numeric defaults" open question is removed from [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). With this closure and the closures of tasks #19, #20, and #21 in Sprint 2, the only remaining open question in [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md) is the per-upstream `ocsp_required` opt-in (added during Sprint 1's task #8 work).

### Non-consequences (deliberate scope limits)

- **Adaptive thresholds at runtime.** Out of scope; defaults are static with operator override.
- **Per-listener overrides.** The hardening configuration is per-instance; per-listener divergence has no identified use case and would multiply the test matrix.
- **HTTP/2 SETTINGS negotiation strategy.** Heimdall enforces the chosen caps regardless of any value the peer announces for itself; the negotiation strategy (whether to advertise the configured caps in the SETTINGS frame, whether to accept SETTINGS that exceed the caps with a GOAWAY, etc.) is an implementation detail constrained by [`SEC-038`](../../specification/003-crypto-policy.md) but not specified at the numeric-default level here.
- **Per-stream allocation caps.** [`THREAT-067`](../../specification/007-threat-model.md) covers per-query allocation caps at a higher level; the present numeric defaults reinforce them at the HTTP layer but do not duplicate the spec.

### Numbering

This ADR takes the sequence number `0018`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). With Sprints 1 and 2 having occupied `0002`–`0018`, the grandfather batch (sprint 11 work) will start at `0019` or later; the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md) ("expected to start at `0002`") will be updated during sprint 11.
