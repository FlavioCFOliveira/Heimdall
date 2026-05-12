# Specification ↔ code mapping

## Binary contract (`BIN-*`)

Requirements from [`specification/015-binary-contract.md`](../specification/015-binary-contract.md).

| Spec ID | Description | Implementation |
|---------|-------------|----------------|
| BIN-001 | clap-based CLI surface with subcommands start/check-config/version/help | `heimdall::cli` |
| BIN-002 | `start` subcommand options (`--config`, `--log-level`, `--log-format`, `--color`) | `heimdall::cli::StartArgs` |
| BIN-003 | `check-config` deep validation (parse + Redis + zone dry-run + bind dry-run) | `heimdall::check_config` |
| BIN-004 | `version` subcommand with embedded build metadata | `heimdall::version` |
| BIN-006 | Exit-code table (0/1/2/64/70) | `heimdall::exit_codes` |
| BIN-012 | `HEIMDALL_CONFIG` environment variable | `heimdall::env` |
| BIN-013 | `RUST_LOG` environment variable → `tracing-subscriber` | `heimdall::logging` |
| BIN-014 | `HEIMDALL_WORKER_THREADS` environment variable | `heimdall::env` |
| BIN-015 | 18-phase boot sequence | `crates/heimdall/src/main.rs`, `crates/heimdall/src/signals.rs` |
| BIN-016..BIN-019 | Tokio multi-thread runtime + `io_uring`/`epoll`/`kqueue` detection | `crates/heimdall/src/runtime.rs`, `heimdall_runtime::runtime` |
| BIN-022 | All-or-nothing listener binding | `crates/heimdall/src/listeners.rs` |
| BIN-023-SIG..BIN-027-SIG | Signal handling (SIGTERM, SIGINT, SIGHUP, SIGPIPE) | `crates/heimdall/src/signals.rs` |
| BIN-028-SD..BIN-030-SD | `sd_notify` state machine (`READY=1`, `STOPPING=1`, `WATCHDOG=1`, `EXTEND_TIMEOUT_USEC`) | `heimdall_runtime::ops::sd_notify`, `crates/heimdall/src/signals.rs` |
| BIN-036..BIN-038 | Resource limits (`RLIMIT_NOFILE`, `RLIMIT_NPROC`, `RLIMIT_CORE`) | `crates/heimdall/src/rlimit.rs` |
| BIN-039..BIN-040 | Memory allocator selection (compile-time feature flag) | `crates/heimdall/src/alloc.rs` (mimalloc default; ADR-0062) |
| BIN-041..BIN-043 | Privilege drop to `heimdall` user, retain `CAP_NET_BIND_SERVICE` | `crates/heimdall/src/privdrop.rs`, `heimdall_runtime::security::privdrop` |
| BIN-044..BIN-046 | Panic-abort policy, custom panic hook, exit code 70 | Pending |
| BIN-047..BIN-049 | Drain coordinator (configurable grace, `Drain::drain_and_wait`) | `heimdall_runtime::drain`, `crates/heimdall/src/signals.rs` |
| BIN-050 | Redis pool bootstrap (fail-closed) at boot phase 9 | `crates/heimdall/src/redis_boot.rs` |
| BIN-051 | Redis pool graceful drain on shutdown | Pending (task #569) |
| BIN-056..BIN-057 | Version embedding via `vergen` `build.rs` | Pending (task #555) |

---

# Specification ↔ code mapping (DNSSEC)

This table maps DNSSEC specification requirements to their implementation locations
in `heimdall-core`.  Every public item in `heimdall_core::dnssec` carries a
`Implements DNSSEC-NNN` marker in its rustdoc comment that cross-references this table.

| Spec ID | RFC Reference | Description | Implementation |
|---------|---------------|-------------|----------------|
| DNSSEC-001 | RFC 4035 §5.3 | RRSIG verification pipeline | `heimdall_core::dnssec::verify::verify_rrsig` |
| DNSSEC-001 | RFC 4035 §5.3 | RRSIG verification with budget | `heimdall_core::dnssec::verify::verify_rrsig_with_budget` |
| DNSSEC-002 | IANA DNSSEC Algorithm Numbers | Algorithm enumeration | `heimdall_core::dnssec::algorithms::DnsAlgorithm` |
| DNSSEC-003 | RFC 8624 §3.1 | Algorithm policy (MUST/SHOULD validate, MUST NOT sign) | `DnsAlgorithm::must_validate`, `should_validate`, `must_not_sign`, `recommended_for_signing` |
| DNSSEC-004 | RFC 4034 §5.2 | DS record matching against DNSKEY | `heimdall_core::dnssec::algorithms::dnskey_matches_ds` |
| DNSSEC-005 | RFC 4034 §6.1, §6.3 | Canonical DNS name order; canonical `RRset` RDATA order | `heimdall_core::dnssec::canonical::canonical_rdata_order`, `Name::cmp` (via `Ord`) |
| DNSSEC-006 | RFC 4034 §6.2 | Canonical `RRset` wire form for signing | `heimdall_core::dnssec::canonical::rrset_signing_input` |
| DNSSEC-006 | RFC 4034 §6.2 | Canonical name wire bytes (lowercase, uncompressed) | `heimdall_core::dnssec::canonical::canonical_name_wire` |
| DNSSEC-006 | RFC 4034 §6.2 | Canonical RDATA wire bytes (names lowercased) | `heimdall_core::dnssec::canonical::canonical_rdata_wire` |
| DNSSEC-007 | RFC 4034 §4.1.2 | NSEC type-bitmap encoding | `heimdall_core::dnssec::nsec::encode_type_bitmap` |
| DNSSEC-007 | RFC 4034 §4.1.2 | NSEC type-bitmap lookup | `heimdall_core::dnssec::nsec::type_in_bitmap` |
| DNSSEC-008 | RFC 4034 §5.4 | NSEC existence proof (NXDOMAIN) | `heimdall_core::dnssec::nsec::nsec_proves_nxdomain` |
| DNSSEC-009 | RFC 5155 §5 | NSEC3 SHA-1 hash computation | `heimdall_core::dnssec::nsec::nsec3_hash` |
| DNSSEC-009 | RFC 5155 §5 | NSEC3 hash with CPU budget | `heimdall_core::dnssec::nsec::nsec3_hash_with_budget` |
| DNSSEC-010 | RFC 5155 §8.3 | NSEC3 existence proof (closest-encloser) | `heimdall_core::dnssec::nsec::nsec3_proves_nxdomain` |
| DNSSEC-011 | RFC 8198 | Aggressive NSEC/NSEC3 synthesis | `heimdall_core::dnssec::synthesis::synthesise_negative` |
| DNSSEC-040 | RFC 9276 `KeyTrap` | Maximum DNSKEY candidates per RRSIG | `verify_rrsig` `max_attempts` parameter; `BogusReason::KeyTrapLimit` |
| DNSSEC-044 | RFC 9276 §3.1 | NSEC3 150-iteration cap | `heimdall_core::dnssec::nsec::MAX_NSEC3_ITERATIONS` |
| DNSSEC-045 | — | Per-query wall-clock CPU budget | `heimdall_core::dnssec::budget::ValidationBudget` |

## Algorithm support matrix (RFC 8624 §3.1)

| Algorithm | Number | Validate | Sign | ring support |
|-----------|--------|----------|------|--------------|
| RSA/SHA-1 | 5 | MAY (legacy) | MUST NOT | Yes (SHA-256 verifier used; SHA-1 only for DS digest) |
| RSA/SHA-1-NSEC3 | 7 | MAY (legacy) | MUST NOT | Yes |
| RSA/SHA-256 | 8 | MUST | — | Yes |
| RSA/SHA-512 | 10 | SHOULD | — | Yes |
| ECDSA P-256/SHA-256 | 13 | MUST | RECOMMENDED | Yes |
| ECDSA P-384/SHA-384 | 14 | SHOULD | — | Yes |
| Ed25519 | 15 | MUST | RECOMMENDED | Yes |
| Ed448 | 16 | SHOULD | — | **Deferred** — not supported by ring 0.17 |

## DS digest type support matrix (RFC 8624 §3.3)

| Digest Type | Number | Policy | ring support |
|-------------|--------|--------|--------------|
| SHA-1 | 1 | NOT RECOMMENDED | Yes (`SHA1_FOR_LEGACY_USE_ONLY`) |
| SHA-256 | 2 | MUST | Yes |
| SHA-384 | 4 | MAY | Yes |

## Notes

- `DNSSEC-040` maps to the `KeyTrap` vulnerability class (CVE-2023-50387 / RFC 9276).
  The default cap of 16 attempts per `verify_rrsig` call matches RFC 9276's guidance.
- `DNSSEC-044` maps to the NSEC3 iteration-count denial-of-service class (RFC 9276 §3).
  Values above 150 are silently rejected (`None` return or `Err(KeyTrapLimit)`).
- `DNSSEC-045` is an implementation-defined requirement providing defence-in-depth
  against both `KeyTrap` (DNSSEC-040) and NSEC3-flood (DNSSEC-044) attacks by bounding
  total wall-clock CPU time per query to 500 ms by default.
- Ed448 (algorithm 16) is deferred because ring 0.17 does not support it.  The
  validator returns `BogusReason::AlgorithmNotImplemented(16)` when encountered.

---

# Specification ↔ code mapping (SLI / SLO)

Requirements from [`specification/016-slo-sli.md`](../specification/016-slo-sli.md).
Every SLI is a consumption-layer view over metrics already exposed by
`THREAT-081` / `THREAT-083`; no SLI introduces a new emission surface. SLO
commitments are evaluated by the operator's monitoring pipeline (Prometheus +
Alertmanager + the dashboard tier), not by Heimdall itself.

## SLI range (`SLI-001` .. `SLI-012`)

| Spec ID range | Description | Implementation |
|---------------|-------------|----------------|
| SLI-001..003 | End-to-end query-latency SLIs at p50 / p99 / p99.9 over 5-minute sliding windows, computed from the metric histograms exposed by `THREAT-083`. Measurement boundary inherited from `PERF-007`. | Consumed via Prometheus recording rules; emitted by `heimdall_runtime::observability::metrics` (latency histograms). |
| SLI-004 | Query error-rate SLI (`SERVFAIL` + transport errors), 5-minute window, with ACL and rate-limit denies excluded from numerator and denominator. | Consumed via Prometheus recording rules; emitted by `heimdall_runtime::observability::metrics` (response-code counters). |
| SLI-005 | Availability SLI over 5-minute windows, defined as the fraction of qualifying windows in which ≥ 99% of admitted queries were answered within the cell's p99 target. Low-traffic windows excluded. | Consumed via Prometheus recording rules using SLI-002 + SLI-004 inputs. |
| SLI-006..007 | Cache hit-rate SLIs on the recursive resolver and forwarder roles, computed independently per the segregated-cache model in [`004-cache-policy.md`](../specification/004-cache-policy.md). | Consumed via Prometheus recording rules; emitted by `heimdall_runtime::cache::metrics` (per-role hit / miss counters). |
| SLI-008..009 | DNSSEC validation rate SLI across the four-state outcome vocabulary of `DNSSEC-010`, with `bogus`-driven `SERVFAIL` distinguished as a sub-counter. | Consumed via Prometheus recording rules; emitted by `heimdall_core::dnssec::validation_outcome` counters. |
| SLI-010 | Readiness SLI derived from the `GET /readyz` predicate fixed by `OPS-024` and `OPS-042`. | Consumed externally via blackbox-probe scrape of `/readyz`. |
| SLI-011..012 | SLI-emission obligations: derivability from `THREAT-081`/`THREAT-083` metrics with no new emission surface; hot-path discipline inherited from `THREAT-085` and `THREAT-086`. | Architectural constraint; enforced by review at `heimdall_runtime::observability::*`. |

## SLO range (`SLO-001` .. `SLO-018`)

| Spec ID range | Description | Implementation |
|---------------|-------------|----------------|
| SLO-001..002 | p99 ≤ 1.10 × baseline and p99.9 ≤ 1.15 × baseline, derived directly from the regression thresholds fixed by `PERF-037`. Absolute baselines come from the Sprint 35 calibration under `PERF-034`. | Alertmanager rules in `contrib/prometheus/heimdall.alerts.yml`. |
| SLO-003 | Error rate ≤ 0.1% over the compliance window, excluding `bogus`-driven `SERVFAIL`. | Alertmanager rule. |
| SLO-004 | Availability ≥ 99.99% over 30 days (~4.32 min error budget). | Alertmanager multi-window multi-burn-rate rule. |
| SLO-005..006 | Recursive cache hit rate ≥ 80%; forwarder cache hit rate ≥ 70%. | Alertmanager rules. |
| SLO-007 | DNSSEC `bogus` rate ≤ 0.5%; `secure`+`insecure`+`indeterminate` ≥ 99.5%. | Alertmanager rule. |
| SLO-008 | Readiness ≥ 99.95% over 30 days (one nine below availability to account for external dependencies). | Alertmanager rule on the blackbox-probe scrape. |
| SLO-009 | Strict no-aggregation: per cell, per SLO, independent. | Enforced by alert-rule structure. |
| SLO-010 | Operator overrides under `PERF-038` propagate to SLO baselines in lock-step; drift emits `slo-baseline-drift`. | Pending: drift-detection rule. |
| SLO-011..013 | Error-budget computation, burn-rate alerting (`slo-burn-fast` at burn rate ≥ 14.4 over 1h, `slo-burn-slow` at burn rate ≥ 6 over 6h), and `slo-budget-exhausted` / `slo-budget-restored` structured events under `THREAT-080`. | Alertmanager + `heimdall_runtime::observability::events`. |
| SLO-014..016 | Release-freeze gate engaged by budget exhaustion (security releases exempt per [`010-engineering-policies.md`](../specification/010-engineering-policies.md)); 7-day post-mortem under `slo:postmortem`; no retroactive widening of SLO commitments. | Project governance; enforced in release-cut workflow. |
| SLO-017..018 | Rolling 30-day compliance report; annual revisit coupled to `PERF-026` / `PERF-067`. | Operational dashboard; documented in `docs/process/`. |

---

# Specification ↔ code mapping (Upgrade / Rollback)

Requirements from [`specification/017-upgrade-rollback.md`](../specification/017-upgrade-rollback.md).
The framework is the deployment-side counterpart of the SemVer release process
fixed by [`010-engineering-policies.md`](../specification/010-engineering-policies.md).
Every UPG-* and ROLLBACK-* compatibility predicate MUST be verifiably true on
the tagged commit before artefacts are published; predicates are encoded as
automated tests under `ENG-203` and integrated into the Tier 4 release gate
framework extended under Sprint 64 task #666.

## UPG range (`UPG-001` .. `UPG-014`)

| Spec ID range | Description | Implementation |
|---------------|-------------|----------------|
| UPG-001 | Explicit one-byte schema-version field at the head of every persisted payload (consistent with `STORE-043`). | Pending: shared header invariant on `heimdall_runtime::storage::*`. |
| UPG-002..003 | Two-version backward- and forward-compatibility on consecutive `MINOR` releases on the same `MAJOR` line; structural ignore-unknown-fields rule on parsers; write-side rejection on the third `MINOR` release with explicit deprecation-event reference. | Pending: parser-side ignore-unknown contracts; rejection error path. |
| UPG-004 | `MAJOR` bump may break payload schemas if and only if the `ENG-169` deprecation-warning obligation has been discharged on the previous `MINOR`. | Project governance; enforced in release-cut workflow. |
| UPG-005..008 | Per-payload compatibility rules: authoritative-zone schema (`STORE-018..023`), cache schema (`STORE-026..030`), RPZ schema (`STORE-031..036`), admin-RPC audit-log envelope (`OPS-040`). RPZ unknown-action falls back to `PASSTHRU` per `RPZ-006` with `upg-unknown-rpz-action` event. Cross-version cache pollution handled as per-entry ignore-and-re-resolve. | Pending: per-domain compatibility shims under `heimdall_runtime::storage::*`. |
| UPG-009 | Tagged-commit predicate tests against a sample-payload corpus checked in under `tests/compat/`. | Pending: corpus + test runners (Sprint 66). |
| UPG-010..012 | Two-version deprecation window on operator-facing surfaces (TOML keys, env vars, CLI flags, ADRs); UUIDv7 deprecation-event identifier persisted under `docs/process/deprecations.md`; `upg-deprecation-announced` / `upg-deprecation-removed` structured events under `THREAT-080`; ADR-status lifecycle (`ENG-120`, `ENG-122`) reconciled with the operator-surface deprecation window. | Pending: deprecation register + structured-event emission. |
| UPG-013..014 | Acceptance gate: release MUST NOT publish artefacts unless every UPG-* / ROLLBACK-* predicate is verifiably true on the tagged commit. Encoded as automated tests under `ENG-203`; integrated into the Tier 4 gate framework extended under Sprint 64 task #666; blocking status check; `upg-acceptance-gate-failed` structured event under `THREAT-080`. | Pending: Tier 4 wiring. |

## ROLLBACK range (`ROLLBACK-001` .. `ROLLBACK-008`)

| Spec ID range | Description | Implementation |
|---------------|-------------|----------------|
| ROLLBACK-001 | Three-phase rolling-upgrade procedure: canary, bake window, expansion phase. | Project governance; encoded in deployment-side orchestration. |
| ROLLBACK-002 | Single-instance canary regardless of cluster size; per-cell SLO error-budget attribution under `SLO-011`/`SLO-012`. | Project governance; encoded in deployment-side orchestration. |
| ROLLBACK-003 | 30-minute bake-window floor (six SLI samples at the 5-minute window of `SLI-001..005`). | Project governance; encoded in deployment-side orchestration. |
| ROLLBACK-004 | Blast-radius limits: ≤ 25% per step on clusters of 8+; ≤ 50% per step on smaller clusters; per-step bake window ≥ 5 min; trigger-fired step reverts the entire fleet. | Project governance; encoded in deployment-side orchestration. |
| ROLLBACK-005 | Automatic rollback triggers: `slo-burn-fast` (`SLO-013`), sustained `/readyz` failure (`OPS-024`/`OPS-042`), panic-abort exit (`BIN-046`), `bogus` rate excursion above `SLO-007`. | Pending: deployment-side orchestration hooks; structured events already covered by SLO/Threat surfaces. |
| ROLLBACK-006 | Rollback procedure sequenced behind the controlled drain (`BIN-047..049`) and Redis pool drain (`BIN-051`); operator-side detail in [`../docs/runbooks/rollback.md`](runbooks/rollback.md). | `heimdall_runtime::drain` + `crates/heimdall/src/signals.rs`; runbook authoritative for procedure. |
| ROLLBACK-007 | Cross-version Redis schema-mismatch handling: per-entry parse failure for cache (`UPG-006`), role-assembly fail-closed for zone data (`BIN-021`); recovery in [`../docs/runbooks/rollback.md`](runbooks/rollback.md) §4 and [`../docs/runbooks/redis-recovery.md`](runbooks/redis-recovery.md). | Pending: structured-event emission on parse failure. |
| ROLLBACK-008 | Operator pre-flight checklist (artefact present, Redis reachable, prior `/version`/`/readyz` recorded, change-management approver notified per `OPS-040`); checklist content lives in the runbook. | Documented in [`../docs/runbooks/rollback.md`](runbooks/rollback.md). |
