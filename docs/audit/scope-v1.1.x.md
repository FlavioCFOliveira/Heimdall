# Heimdall Security Audit — Scope Document (v1.0.0 → v1.1.x Delta)

**Version:** 1.0
**Date:** 2026-05-12
**Status:** Pre-engagement review
**Classification:** Confidential (share under NDA)
**Tracking:** rmp #696
**Companion document:** [`docs/audit/scope.md`](scope.md) — Sprint 41 scope for v1.0.0

---

## 1. Purpose

This document defines the scope, objectives, and constraints for an external
security audit (or diff-audit) of the Heimdall DNS server covering the change
surface between tag `v1.0.0` (audited and signed off in Sprint 41) and the
v1.1.x line ending at tag `v1.1.1`. The Sprint 41 sign-off covered v1.0.0,
which the v1.1.0 CHANGELOG documents as a non-functional placeholder release
(`fn main() {}`). v1.1.0 was the first fully functional General Availability
build; v1.1.1 is a hardening patch on the v1.1 line.

For deployment in hostile, Internet-facing, multi-tenant, or regulated
environments, the v1.0.0 sign-off alone is not load-bearing. This audit
re-validates (or, at the engagement's discretion, audits as a delta) the
surface introduced or modified between v1.0.0 and v1.1.1.

The document is intended to be shared with candidate audit firms during the
RFP process and ratified by the selected firm before the engagement begins.
Engagement starts when the operator contracts the Sprint 41 auditor (or an
equivalent firm) under the same RFP framework recorded in
[`docs/audit/rfp.md`](rfp.md).

---

## 2. Audit Objectives

The Sprint 41 audit objectives (`docs/audit/scope.md` §2) remain in force for
all components carried unchanged from v1.0.0. This delta audit adds the
following objectives, narrowly scoped to the v1.0.0 → v1.1.1 change surface:

1. Validate the **functional admission pipeline** end-to-end: ACL → connection
   limits → cookie / load gate → RRL → per-client rate limiter. v1.0.0
   exercised only the library layer; v1.1.0 wired the pipeline into `main()`
   for the first time.
2. Validate the **DNSSEC end-to-end validation surface** (BOGUS / SECURE /
   INSECURE classification, structural zone checks at load time), including
   the **DNSSEC signing path** introduced under ADR-0066.
3. Validate **TSIG** end-to-end (SHA-256 / SHA-1 / SHA-384 / SHA-512), BADSIG /
   BADKEY error paths and per-key telemetry.
4. Validate the **runtime-hardening posture** as wired in `main()`: seccomp-bpf
   activation, privilege drop, W^X, OS resource limits (`BIN-036..038`,
   `THREAT-068`).
5. Validate the **admin-RPC trust boundary**: UDS with `SO_PEERCRED`-attested
   identity is the only currently-shipping carrier; the gRPC + mTLS TCP
   carrier (ADR-0053 / ADR-0054, rmp #690) is not yet in scope.
6. Validate the **observability surface** (`/healthz`, `/readyz`, `/metrics`,
   `/version`) for information leakage, timing side channels, and bypass of
   the `/readyz` 503-during-drain semantics.
7. Validate the **HMAC-chained admin audit log** for replay, truncation, and
   privileged-rebase risk; confirm `AuditLogger::verify_chain` correctly
   detects every documented tamper class.
8. Validate the **SO_REUSEPORT UDP worker fan-out** for connection-affinity
   leakage, kernel-level work-stealing edge cases, and per-worker counter
   integrity (ADR pending; see specification/015-binary-contract.md `BIN-058`).
9. Validate the **async `QueryDispatcher` contract** does not introduce
   cancellation-safety regressions across `tokio::select!` branches in any
   transport listener.
10. Validate the **drain coordinator** does not exhibit shutdown races (FD
    leaks, dangling tasks, lost in-flight responses) under the 30 s grace
    timeout.
11. Validate the **`rustls` `ring` crypto-provider switch** (ADR-0067) does
    not regress the algorithm posture documented in `THREAT-150`.

---

## 3. In-Scope Components — v1.0.0 → v1.1.1 Delta

### 3.1 Binary entry-point and admission pipeline (NEW in v1.1.0)

| Component | File(s) | Reference |
|---|---|---|
| `heimdall start` | `crates/heimdall/src/main.rs`, `crates/heimdall/src/start.rs` | Sprints 43–45 |
| `heimdall check-config` | `crates/heimdall/src/check_config.rs` | Sprint 46 task #556 |
| `heimdall version` | `crates/heimdall/src/version.rs` | Sprint 46 task #555 |
| `heimdall probe` | `crates/heimdall-probe/src/main.rs` | Sprint 45 task #576, Sprint 63 task #659 |
| Admission pipeline (5 stages) | `crates/heimdall-runtime/src/admission/` | Sprints 43–46, THREAT-033..076 |
| OS resource limits at boot | `crates/heimdall/src/limits.rs` | Sprint 46 task #539, BIN-036..038, THREAT-068 |
| Allocator selection (mimalloc default) | `crates/heimdall/src/alloc.rs` | Sprint 46 task #540, ADR-0062 |
| Build-info embedding | `crates/heimdall/build.rs` | Sprint 46 task #555, ADR-0063 |

**Key questions for the auditor:**
- Are the five admission-pipeline stages correctly ordered, and do per-stage
  failures fail safely (closed)?
- Does the `BIN-036..038` resource-limit set fall back safely if the kernel
  rejects a `setrlimit` value?
- Is `heimdall-probe` resistant to spoofed UDP responses crafted to satisfy
  the probe's truncated-validation logic?

### 3.2 DNSSEC validation and signing (NEW + EXTENDED in v1.1.x)

| Component | File(s) | Reference |
|---|---|---|
| Full BOGUS / SECURE / INSECURE classification | `crates/heimdall-roles/src/recursive/validate.rs` | Sprint 47, PROTO-101 |
| Structural zone checks at load time | `crates/heimdall-roles/src/auth/zone_load.rs` | Sprint 47 |
| DNSSEC signing path (RSA + SIG(0)) | `crates/heimdall-roles/src/dnssec_roles/sign.rs` | Sprint 62 tasks #654, #655, #656; ADR-0066 |
| `ring` vs `aws-lc-rs` posture | workspace `Cargo.toml`, `crates/heimdall*/Cargo.toml` | ADR-0067, Sprint 65 task #669, THREAT-150 amend |

**Key questions for the auditor:**
- Does the signing path preserve constant-time discipline across all
  algorithm branches?
- Is the Ed448 deferral documented in ADR-0066 (ring upstream gap)
  cryptographically acceptable for the v1.1.x deployment posture?

### 3.3 TSIG (NEW in v1.1.0)

| Component | File(s) | Reference |
|---|---|---|
| TSIG core (sign + verify) | `crates/heimdall-core/src/tsig.rs` | Sprint 47 task #589, RFC 8945 |
| TSIG MAC verification | (above) | Sprint 67 task — fuzz target `fuzz_tsig_verify` |
| Per-key telemetry | `crates/heimdall-runtime/src/observability/tsig.rs` | Sprint 47 |

**Key questions for the auditor:**
- Are BADSIG / BADKEY paths constant-time with respect to key existence and
  MAC mismatch?
- Does the per-key telemetry leak any information that would let an attacker
  enumerate configured keys?

### 3.4 Transports — drain and async dispatcher (CHANGED in v1.1.x)

| Component | File(s) | Reference |
|---|---|---|
| Async `QueryDispatcher` trait | `crates/heimdall-runtime/src/transport/dispatcher.rs` | Sprint 67 (commit ee2f16b) |
| SO_REUSEPORT UDP fan-out | `crates/heimdall-runtime/src/transport/reuseport.rs` | Sprint 67 (commit ee2f16b), BIN-058 |
| Drain coordinator wiring | `crates/heimdall-runtime/src/drain.rs` | Sprint 62 task #653, Sprint 67 |
| Synthetic-zone owner check | `crates/heimdall-runtime/src/transport/mod.rs::build_synthetic_health_response` | Sprint 69 task #662, ENV-065 |
| Drain E2E test | `crates/heimdall-integration-tests/src/drain_e2e.rs` | Sprint 67 |

**Key questions for the auditor:**
- Are `tokio::select!` branches in every transport listener
  cancellation-safe under the new async-dispatch contract?
- Does the SO_REUSEPORT fan-out preserve per-worker isolation under
  adversarial datagram patterns?
- Can the drain coordinator be tricked into completing before all in-flight
  responses have been written?

### 3.5 Admin-RPC and audit log (NEW in v1.1.0)

| Component | File(s) | Reference |
|---|---|---|
| Admin-RPC carrier (JSON / UDS) | `crates/heimdall-runtime/src/admin/uds.rs` | Sprint 33, task #670 |
| SO_PEERCRED identity attestation | `crates/heimdall-runtime/src/admin/identity.rs` | task #670, SEC-012..016 |
| HMAC-chained audit log | `crates/heimdall-runtime/src/audit/logger.rs` | Sprint 52 task #524 |
| Chain integrity check | `crates/heimdall-runtime/src/audit/logger.rs::verify_chain` | Sprint 52 task #524 |

**Out of scope** for this audit cycle: the gRPC + mTLS TCP carrier
(ADR-0053 / ADR-0054, rmp #690). To be added once #690 lands.

**Key questions for the auditor:**
- Is the SO_PEERCRED identity attestation correctly bound to every
  admin-RPC operation that records `caller_uid`?
- Can the HMAC chain be rebased, truncated, or replayed without
  `verify_chain` detecting it?
- Are admin-RPC error messages free of internal-state leakage?

### 3.6 Observability surface (NEW in v1.1.0)

| Component | File(s) | Reference |
|---|---|---|
| `/healthz`, `/readyz` | `crates/heimdall-runtime/src/observability/http.rs` | Sprint 52 tasks #520–#521 |
| `/metrics` (OpenMetrics) | `crates/heimdall-runtime/src/observability/metrics.rs` | Sprint 52 task #522 |
| `/version` | `crates/heimdall-runtime/src/observability/http.rs` | Sprint 52 task #523, ADR-0063 |
| `sd_notify(WATCHDOG=1)` | `crates/heimdall-runtime/src/observability/watchdog.rs` | Sprint 52 task #523 |

**Key questions for the auditor:**
- Does the `/version` endpoint leak any information that should remain
  internal (e.g., build host, build path)?
- Is the 503-during-drain `/readyz` semantics atomic with respect to listener
  drain?

### 3.7 Persistence (EXTENDED in v1.1.x)

| Component | File(s) | Reference |
|---|---|---|
| Redis pool bootstrap at boot | `crates/heimdall/src/store.rs` | Sprint 46 task #552, BIN-050, STORE-005..016 |
| Graceful Redis pool drain on shutdown | (above) | Sprint 46 task #569 |
| STORE-051..069 durability postures | `specification/013-persistence.md` | Sprint 66 (commit 68fdcf1) |

**Key questions for the auditor:**
- Are Redis credentials handled in a way that prevents disclosure via
  process listing, logs, or core dumps?
- Is the RTO / RPO documented in STORE-051..069 achievable under the
  documented restore procedure?

### 3.8 Supply chain (REFRESHED in v1.1.x)

| Component | File(s) | Reference |
|---|---|---|
| `cargo-vet` audits | `supply-chain/audits.toml` | Sprint 67 (commit 8a009df) |
| `cargo-deny` configuration | `deny.toml`, `supply-chain/config.toml` | Sprint 67 (commit 8a009df) |
| RUSTSEC-2025-0134 waiver | `deny.toml` `[advisories].ignore` | Sprint 67 — waiver retired |
| `mimalloc` and `tikv-jemallocator` | `crates/heimdall/Cargo.toml` | ADR-0062 |

**Key questions for the auditor:**
- Are the cargo-vet certifications for the eight crypto-bearing crates
  (`aws-lc-rs`, `aws-lc-sys`, `quinn-proto`, `rcgen`, `rustls-pemfile`,
  `rustls-pki-types`, `rustls-webpki`, plus one more) substantiated by an
  independent review path or only by self-certification?

### 3.9 Hardening profile (EXTENDED in v1.1.x)

| Component | File(s) | Reference |
|---|---|---|
| seccomp-bpf allow-list | `crates/heimdall-runtime/src/hardening_seccomp.rs` | Sprint 37, ADR-0019 / 0020 |
| Privilege drop + CAP_NET_BIND_SERVICE | `crates/heimdall-runtime/src/hardening_privdrop.rs` | THREAT-022 / 023 |
| `pledge` / `unveil` (OpenBSD) | `crates/heimdall-runtime/src/hardening_pledge.rs` | ADR-0022 |
| macOS sandbox profile | `crates/heimdall-runtime/src/hardening_macos.rs` | ADR-0023 |
| W^X (linker flags) | `Cargo.toml` `[profile.release]` | THREAT-027, ADR-0057 |
| `clippy::unwrap_used` / `expect_used` = `deny` | workspace `Cargo.toml` | Sprint 67 (commit 5e878dc) |

**Key questions for the auditor:**
- Has the seccomp allow-list been audited against the new async-dispatch
  call graph (which may add `epoll_*` / `io_uring_*` system-call usage
  paths)?

### 3.10 Fuzz targets (NEW in v1.1.x)

The fuzz surface grew from four targets (v1.0.0) to eight (v1.1.1):
`fuzz_config_toml`, `fuzz_dnssec_verify`, `fuzz_doh2_framing`,
`fuzz_tsig_verify` (Sprint 67 commit 264abce). Corpora committed under
`fuzz/corpus/<target>/`. OSS-Fuzz integration tracked under ENG-052.

---

## 4. Out of Scope — v1.1.x Delta

- The gRPC + mTLS admin-RPC TCP carrier (ADR-0053 / 0054, rmp #690) — not
  yet shipped at v1.1.1; to be added to a future audit cycle once it lands.
- The `io_uring` fast-path (ADR-0065) — design only, no code yet.
- The Ed448 DNSSEC signing path — deferred per ADR-0066 (ring upstream gap).
- The `aws-lc-rs` cryptographic provider — deferred per ADR-0067 until a
  build matrix is justified by a concrete operator request.
- The PERF-011 / PERF-012 reference-hardware baseline capture (rmp #665) —
  not security-relevant; tracked separately.

---

## 5. Reference Materials

- [`docs/audit/scope.md`](scope.md) — Sprint 41 v1.0.0 scope, still in force
  for all unchanged components.
- [`docs/audit/rfp.md`](rfp.md) — RFP framework to be reused with the
  selected auditor.
- [`docs/audit/findings-triage-template.md`](findings-triage-template.md) —
  finding intake and severity rubric.
- [`docs/audit/sign-off-template.md`](sign-off-template.md) — sign-off
  artefact template (`docs/audit/v1.1.x-signoff.md` to be published once the
  engagement completes).
- [`docs/release-notes/v1.1.0.md`](../release-notes/v1.1.0.md) — first
  functional General Availability release notes.
- [`docs/release-notes/v1.1.1.md`](../release-notes/v1.1.1.md) — v1.1.1
  hardening-patch release notes.
- ADRs landed between v1.0.0 and v1.1.1: 0059 (LTS model), 0060 (clap),
  0061 (tracing-subscriber), 0062 (allocator), 0063 (build-info), 0064
  (perf governance), 0065 (io_uring fast-path), 0066 (DNSSEC signing),
  0067 (`rustls` `ring` crypto provider).
- New specification files since v1.0.0: `015-binary-contract.md`,
  `016-slo-sli.md`, `017-upgrade-rollback.md`,
  `018-capacity-planning.md`.

---

## 6. Engagement Procedure

1. Operator contracts the Sprint 41 auditor (or an equivalent firm) under
   the same RFP framework (`docs/audit/rfp.md`).
2. Auditor and project team agree the version (v1.1.1 confirmed; v1.2.0
   admissible if v1.2.0 ships before the audit window closes).
3. Auditor performs the work against the change surface enumerated in §3.
4. Findings are triaged using [`findings-triage-template.md`](findings-triage-template.md).
5. All Critical and High findings are resolved before publication.
6. Sign-off is published at `docs/audit/v1.1.x-signoff.md` with auditor
   identity and date.
7. SECURITY.md, README.md, and the v1.2.0 release notes cross-reference the
   sign-off.
8. Medium-tier CVEs that warrant CVE assignment are published as GHSA
   advisories per the coordinated-disclosure policy in SECURITY.md.

---

**Authoring note.** This document is preparatory: it identifies and bounds
the audit surface so engagement can begin without further discovery. It is
not itself an audit and carries no security claim.
