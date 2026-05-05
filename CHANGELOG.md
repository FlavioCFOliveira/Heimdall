# Changelog

All notable changes to Heimdall will be documented in this file.

The format is based on [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- Entries are generated from the commit history by a Conventional-Commits-aware tool.
     Manual curation must be recorded in the pull request that applies it (ENG-151). -->

## [1.1.0] — 2026-05-05

### Notice

**v1.0.0 was a non-functional placeholder release** (`fn main() {}`).  The
v1.1.0 release is the first fully functional General Availability build.
All prior CHANGELOG entries for v1.0.0 describe library-layer completions that
were real, but the binary entry-point was not wired until this release.

### MSRV

Rust 1.94.0 (workspace pinned to nightly channel via `rust-toolchain.toml`
until 1.94 stable ships).

### Added

- **Binary entry-point** — `heimdall start`, `heimdall check-config`,
  `heimdall version`, `heimdall probe` subcommands fully wired (Sprints 43–45).
- **Admission pipeline** — five-stage request admission (ACL → connection limits
  → cookie/load gate → RRL → per-client rate limiter) with per-stage telemetry
  (Sprints 43–46, THREAT-033..076).
- **DNSSEC validation** — full BOGUS/SECURE/INSECURE classification with
  structural zone checks at load time (Sprint 47, PROTO-101).
- **TSIG** — algorithm negotiation E2E (SHA-256/SHA-1/SHA-384/SHA-512),
  BADSIG/BADKEY error paths, per-key telemetry (Sprint 47, task #589).
- **Role enforcement** — ROLE-005/006 disabled-role rejection E2E; ROLE-019/020
  listener-role validation; ROLE-021 unknown-key rejection (Sprint 47,
  tasks #587–#588).
- **Observability** — `/healthz`, `/readyz` (503 during drain), `/metrics`
  (OpenMetrics format with `# EOF`), `/version` (10 fields including `tier`,
  `msrv`, `runtime.uid/gid`) (Sprint 52, tasks #520–#523).
- **Admin audit log** — HMAC-SHA256 chained entries with strict monotonic
  sequence; `AuditLogger::verify_chain` for offline integrity checks (Sprint 52,
  task #524).
- **Watchdog integration** — `sd_notify(WATCHDOG=1)` via `WATCHDOG_USEC`
  (Sprint 52, task #523).
- **Soak and stability tests** — 8 new integration-test modules: sustained-load
  QPS stability, memory-leak (VmRSS), FD-leak across 1 000 reload cycles,
  cache-eviction hit-rate arithmetic, TEK rotation monotonicity, crash-recovery
  via Redis persistence, DDoS simulation (RRL + NXNSAttack cap), and
  144-reload correctness under concurrent queries (Sprint 53, tasks #525–#530,
  #550–#551).
- **heimdall-probe** — diagnostic CLI: DNS query, DNSSEC chain check, server
  health, latency benchmark (Sprint 45, task #576).
- **HTTP/2 + QUIC hardening** — SETTINGS frame limits, header-field-count cap,
  QUIC stream-count and CRYPTO-frame limits (Sprint 42, tasks #572–#573).

### Changed

- Workspace version bumped to 1.1.0.
- `/metrics` content type changed to `application/openmetrics-text` with
  mandatory `# EOF` terminator per OpenMetrics specification.
- `BuildInfo` extended with `tier` and `msrv` fields; emitted in `/version`.

### Fixed

- `AuditLogger` sequence counter moved inside the inner mutex — concurrent
  HMAC-chain entries are now guaranteed to be in monotonic order.

---

## [1.0.0] — 2026-04-27

### MSRV

Rust 1.94.0 (nightly channel pinned via rust-toolchain.toml until 1.94 stable is available).

### Changed

- Workspace version bumped to 1.0.0 GA.
- SECURITY.md updated with supported-versions table and LTS end-of-life date.
- API and configuration surfaces stable per SemVer 2.0.0 commitment (ENG-162..164).

### Added

- `docs/release-notes/v1.0.0.md`: GA release notes with SemVer stability commitment,
  LTS policy, upgrade path, audit sign-off reference, and artefact verification.
- `docs/adr/<N>-lts-model.md`: LTS model ADR — v1.0 branch, 12-month support window.
- Incident-response playbook: triage → fix → GHSA → CVE → release → announcement.
- v1.1.0 GitHub milestone opened; post-GA cadence established (ENG-174).

### Fixed

- All Critical and High audit findings resolved before v1.0.0 tag.

## [1.0.0-rc.1] — 2026-04-27

### MSRV

Rust 1.94.0 (nightly channel pinned via rust-toolchain.toml until 1.94 stable is available).

### Changed

- Workspace version bumped to 1.0.0-rc.1.
- API and configuration surfaces frozen (see release notes for the frozen surface list).
- Docs-freeze gate active from this point: docs/spec PRs require `rc-blocker: <ID>` tag.

### Known Issues

- External security audit (Sprint 41) is in progress; GA blocked until sign-off published.
- SLSA provenance hash binding is a stub (ENG-080).
- cargo install --check-config not yet implemented.

## [0.9.0-beta.1] — 2026-04-27

### MSRV

Rust 1.94.0 (nightly channel pinned via rust-toolchain.toml until 1.94 stable is available).

### Added

- `publish-crates.yml`: automated crates.io publishing for library crates (ENG-183).
- Alpha feedback intake: GH issue templates (bug, feedback), label set, triage process (ENG-130).
- `docs/process/alpha-triage.md`: weekly triage cadence, severity SLAs, beta-blocker burndown gate.

### Changed

- Workspace version bumped to 0.9.0-beta.1.

## [0.9.0-alpha.1] — 2026-04-27

### MSRV

Rust 1.94.0 (nightly channel pinned via rust-toolchain.toml until 1.94 stable is available).

### Added

- Authoritative server role: query serving, AXFR/IXFR, NOTIFY, secondary refresh (Sprint 26).
- Recursive resolver: delegation-following, trust anchors, DNSSEC validation, cache (Sprint 30).
- QNAME minimisation (strict/relaxed), 0x20 case randomisation, aggressive NSEC/NSEC3 (Sprint 31).
- Forwarder role: forward-rule dispatcher, UDP/TCP/DoT clients, pool+fallback, DNSSEC validator (Sprint 32).
- Admin RPC: JSON/UDS, zone/NTA/TEK/RPZ/stats/drain/diag commands (Sprint 33).
- Response Policy Zones (RPZ): QNAME/CIDR/NSDNAME, multi-zone first-match-wins (Sprint 34).
- Criterion benchmarks, regression CLI, kernel-tuning docs (Sprint 35).
- Protocol conformance suite: golden comparisons vs Unbound/NSD/Knot, DoT/DoH/DoQ interop, RFC 4034 vectors (Sprint 36).
- Runtime hardening: seccomp-bpf, privilege drop, pledge/unveil, macOS sandbox, W^X, drift gate (Sprint 37).
- Supply chain: signing key runbook, CycloneDX SBOM, reproducible builds, cargo-vet/deny, OSS-Fuzz, SLSA Level 3 target (Sprint 38).
- Packaging: static musl .tar.gz, .deb, .rpm, distroless OCI image, cargo install validation (Sprint 39).
- Documentation: operator manual, configuration reference, troubleshooting, admin guide, deployment runbooks, security posture, rustdoc coverage, docs-vs-spec CI sync (Sprint 40).
- Security audit infrastructure: scope document, RFP, findings triage template, sign-off template (Sprint 41).

### Security

- TLS 1.3 only (rustls); TLS 1.2 explicitly disabled (SEC-003).
- QUIC 0-RTT refused (SEC-022).
- seccomp-bpf allow-list with SECCOMP_RET_KILL_PROCESS (THREAT-024).
- Privilege drop to unprivileged user + CAP_NET_BIND_SERVICE only (THREAT-022/023).
- W^X enforced via linker flags (-z relro -z now -z noexecstack) (THREAT-027).

### Known Issues

- External security audit (Sprint 41) is in progress; not yet suitable for hostile environments.
- SLSA provenance hash binding is a stub (ENG-080).
- cargo install --check-config not yet implemented.
