# Changelog

All notable changes to Heimdall will be documented in this file.

The format is based on [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- Entries are generated from the commit history by a Conventional-Commits-aware tool.
     Manual curation must be recorded in the pull request that applies it (ENG-151). -->

## [1.1.1] — 2026-05-11

### Notice

v1.1.1 is a hardening patch on the v1.1.0 General Availability build.
One functional addition (`heimdall-probe` rewritten as a UDP DNS probe
per ENV-065) and one engineering addition (`SO_REUSEPORT` UDP worker
fan-out) ship in the server binary; every other change lands in the
test harness, build pipeline, specification surface, and operational
documentation.  This release also lands the engineering hygiene items
that closed out the 2026-05-11 production-readiness audit on the v1.1
line: the workspace-wide promotion of `clippy::unwrap_used` and
`clippy::expect_used` to `deny`, the async `QueryDispatcher` contract
across every role, four additional fuzz targets, and the
formally-reviewed cargo-vet audits replacing the prior exemption stubs.

### Added

- **`SO_REUSEPORT` UDP worker fan-out** (`feat(transport)`, ee2f16b).
  New `crates/heimdall-runtime/src/transport/reuseport.rs` wraps the
  `socket2` bind with per-worker `AtomicU64` datagram counters for
  verifiable kernel-level load balancing.  Linux only; macOS is capped
  at one worker with a startup warning.  New benchmark
  (`crates/heimdall-bench/benches/udp_reuseport.rs`) and integration
  test (`crates/heimdall-integration-tests/src/udp_reuseport.rs`)
  prove the fan-out arithmetically.
- **Async `QueryDispatcher` contract** across every role
  (`feat(transport)`, ee2f16b).  `dispatch` returns
  `Pin<Box<dyn Future + Send>>` so authoritative, recursive, and
  forwarder roles can await Redis / upstream / signing operations
  without blocking the listener loop.  New `owns_zone_apex` method
  resolves the synthetic-zone precedence rule for the Docker
  HEALTHCHECK probe (ENV-065).
- **Drain coordinator wired end-to-end** across every transport
  (`feat(transport)`, ee2f16b).  30-second grace timeout,
  `CancellationToken` shared across UDP / TCP / DoT / DoH H2+H3 / DoQ
  listeners and the admission pipeline.  New integration test
  (`crates/heimdall-integration-tests/src/drain_e2e.rs`) covers the
  TCP path end-to-end.
- **Four new fuzz targets** (`test(fuzz)`, 264abce) bringing the total
  to eight: `fuzz_config_toml`, `fuzz_dnssec_verify`, `fuzz_doh2_framing`,
  `fuzz_tsig_verify`.  Seed corpora committed under
  `fuzz/corpus/<target>/`.
- **Poll-until-condition test harness** (`refactor(e2e-harness)`,
  ba02f1c).  New `poll.rs` module replaces ad-hoc `sleep + assert`
  patterns with `poll_until` / `poll_until_async` / `wait_bounded`
  helpers (5 ms cadence default).  `SpawnLock` serialises daemon spawn
  across parallel test binaries via `flock(2)`, allowing Tier 2 to drop
  `--test-threads=1`.
- **Three new specification documents** (`docs(spec)`):
  - `specification/016-slo-sli.md` — twelve SLIs and ten SLOs per
    `(role, transport)` cell with multi-window multi-burn-rate alerting
    and the `slo-budget-exhausted` release-freeze gate.
  - `specification/017-upgrade-rollback.md` — two-version data
    compatibility, deprecation-window framework with UUIDv7 events,
    rolling-upgrade semantics, automatic rollback triggers.
  - `specification/018-capacity-planning.md` — empirical sizing
    framework per `(role, transport, architecture)` cell with the
    placeholder figures pending the real PERF-011 baseline capture
    (rmp #665).
- **One new ADR**: `docs/adr/0067-tls-crypto-provider.md` accepting
  `ring` as the rustls default crypto provider for v1.1.x, retiring
  the RUSTSEC-2025-0134 waiver path.  ADR-0066 (DNSSEC signing) also
  added under `docs(adr)` covering Sprint 62 tasks #654/#655/#656.
- **Operational documentation**: four new runbooks
  (`incident-response`, `redis-recovery`, `rollback`, `upgrade-failure`)
  and five new process documents (`package-signing`,
  `release-protection`, `sanitizer-suppressions`, `soak-runner`,
  `test-conventions`).
- **`heimdall-probe` UDP DNS probe** (`feat(probe)`, Sprint 63 task
  #659): sends an `A` query for `health.heimdall.internal.` to
  `127.0.0.1` on the configured DNS port and exits 0 on a valid DNS
  response within 2 seconds, or 1 on timeout / network error /
  malformed response.  Zero external crate dependencies (stdlib only).
  Host and port overridable via positional arguments or
  `HEIMDALL_PROBE_HOST` / `HEIMDALL_PROBE_PORT`.
- **Drain supervisor wiring** in `run_to_completion`
  (`feat(supervisor)`, Sprint 62 task #653): the previously-unwired
  `drain.drain_and_wait` call is now invoked on shutdown, honouring
  the 30 s grace timeout across every transport.

### Changed

- **`clippy::unwrap_used` and `clippy::expect_used` promoted from
  `warn` to `deny`** (`chore(lints)`, 5e878dc).  Every prior commit on
  this release branch removed the call sites the new policy would
  flag (~50 `.unwrap()` removals across `heimdall-roles`).  The
  `fuzz/` directory is now `exclude`-d from the workspace `members`
  set so cargo-fuzz instrumentation does not pollute the normal build
  path; it remains exercised by Tier 2 (smoke) and Tier 3 (extended).
- **Docker `HEALTHCHECK` timings** aligned with ENV-065 (Sprint 63
  task #660): `--interval=30s --timeout=5s --start-period=10s`
  (previously 10s / 2s / 5s).  The `--retries` flag is dropped (spec
  is silent; Docker default of 3 applies).
- **`contrib/docker-compose.yml`** sample services updated to invoke
  the probe against the configured DNS listener port (5353 / 5354 /
  5355) with the new HEALTHCHECK timings (Sprint 63 task #660).
- **`.github/workflows/release-container.yml`** refactored to native
  multi-arch builds (Sprint 63 task #658, ENV-045 / ENV-047):
  per-architecture jobs on dedicated runners (`linux/amd64` →
  `ubuntu-latest`, `linux/arm64` → `ubuntu-24.04-arm`, `linux/riscv64`
  → self-hosted), each pushing by digest only; a dedicated `manifest`
  job assembles the multi-arch manifest list with `docker buildx
  imagetools create` and applies the official tags (`vM.m.p` always;
  `vM.m`, `vM`, `latest` on stable releases per ENV-053).  `cosign`
  signing and SBOM (CycloneDX) attestation operate against the
  multi-arch manifest digest; QEMU emulation removed entirely.
- **CI pipeline restructured** (`ci`): `ci.yml` stub removed;
  `ci-tier2.yml` drops `--test-threads=1` from integration-test runs
  (the new harness `SpawnLock` makes intra-binary parallelism safe);
  `ci-tier3.yml` adds the LLVM sanitizer triad (AddressSanitizer,
  ThreadSanitizer, LeakSanitizer) under an advisory window 2026-05-10
  → 2026-05-24, after which the jobs are scheduled to become blocking
  (rmp #692).
- **`.github/workflows/bench.yml` fail-closed** when the baseline JSON
  is a placeholder or has an empty `micro_benchmarks` object (was
  warn + exit 0; now error + exit 1).  Effective once rmp #665 lands
  the real baseline.
- **`.github/workflows/release-deb.yml` and `release-rpm.yml`** wire
  debsigs / rpmsign signing steps that read the
  `PACKAGE_SIGNING_KEY{,_ID,_PASSPHRASE}` GitHub Secrets.  Fail-soft
  when secrets are unset (operator action pending per rmp #681).
- **`supply-chain/audits.toml`** — eight crypto-bearing crates
  (`aws-lc-rs`, `aws-lc-sys`, `quinn-proto`, `rcgen`, `rustls-pemfile`,
  `rustls-pki-types`, `rustls-webpki`, plus one more) migrated from
  `config.toml` exemptions to formally-reviewed safe-to-deploy entries
  (8a009df).
- **Dependabot removed and ENG-189 amended** (`MUST` → `MAY`).
  Dependency updates are now optional via bot or maintainer PRs;
  `ENG-191` (no vendoring of `rustls`/`quinn`/`tokio`/`hyper`) is
  unchanged.
- **Routine dependency bumps**: `rustls 0.23.39 → 0.23.40`,
  `tokio 1.52.1 → 1.52.3`, `sigstore/cosign-installer 4.1.1 → 4.1.2`,
  `github/codeql-action 3 → 4`.

### Spec

- **ENV-046** (`009-target-environment.md` §2.12) and **ENV-050**
  (§2.14) amended to authorise four pre-release tag patterns:
  `vM.m.p`, `vM.m.p-alpha.N`, `vM.m.p-beta.N`, `vM.m.p-rc.N`.
  ENV-050 additionally codifies a monotone progression rule
  (`alpha → beta → rc`) for the same target stable version
  (Sprint 63 task #661).
- **STORE-051..069** added to `013-persistence.md` covering
  operator-side durability postures per data domain, restore RTO/RPO
  targets, split-brain detection and resolution under Sentinel and
  Cluster, the Cluster-versus-Sentinel selection criteria, and the
  eager-warm-up cap and `/readyz` semantics.
- **BIN-058** added to `015-binary-contract.md` reflecting the
  SO_REUSEPORT worker fan-out into the binary boot sequence.
- **THREAT** entries added to `007-threat-model.md` reflecting the
  `ring` vs `aws-lc-rs` default decision (ADR-0067) and the residual
  risks alignment.
- **ENG-189** amended: the automated dependency-update bot is
  optional (`MAY`), with explicit fallback for manual maintainer
  updates.

### Fixed

- **`heimdall-probe`** rewritten as a UDP DNS probe (was HTTP
  `/healthz`) per ENV-065.  Backwards compatible at the Docker
  HEALTHCHECK layer but materially different at the protocol level
  (Sprint 63 task #659).
- **Async dispatcher contract** (ee2f16b) removes the implicit
  blocking-await that masked latency tail-spikes under load in
  v1.1.0; p99 / p99.9 histograms now reflect the actual server time
  on every transport.

### Known limitations

- **Performance baseline still placeholder** (rmp #665).  `bench.yml`
  is fail-closed on a missing or empty baseline JSON, but the actual
  PERF-011 / PERF-012 reference-hardware capture has not yet happened.
- **24-hour soak never executed on a dedicated runner** (rmp #687).
  The workflow, the test harness, and the runner runbook are in place;
  the self-hosted runner is not yet provisioned.
- **Package signing fail-soft** (rmp #681).  `.deb` and `.rpm`
  artefacts are produced but not signed until the GPG key lands.
- **Admin-RPC over TCP not yet covered by gRPC + mTLS** (rmp #690 /
  ADR-0053 / ADR-0054).  Operators that need remote admin access must
  forward the UDS over `ssh -L` until the gRPC carrier ships.
- **External security re-audit on the v1.0.0 → v1.1.x delta is
  outstanding** (rmp #696).  The Sprint 41 sign-off covered v1.0.0,
  which was the non-functional placeholder release.
- **CI Tier 3 sanitizers (asan/tsan/leaksan) remain advisory until
  2026-05-24** (rmp #692).
- **CI Tier 2 `bench-regression` and `fuzz-smoke` are still
  `continue-on-error`** (rmp #693 / #694).
- **`linux/riscv64` release artefacts remain `continue-on-error`**
  pending the ENV-047 tier-promotion decision (rmp #695).

---

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
