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
| BIN-039..BIN-040 | Memory allocator selection (compile-time feature flag) | Pending (task #540) |
| BIN-041..BIN-043 | Privilege drop to `heimdall` user, retain `CAP_NET_BIND_SERVICE` | `crates/heimdall/src/privdrop.rs`, `heimdall_runtime::security::privdrop` |
| BIN-044..BIN-046 | Panic-abort policy, custom panic hook, exit code 70 | Pending |
| BIN-047..BIN-049 | Drain coordinator (configurable grace, `Drain::drain_and_wait`) | `heimdall_runtime::drain`, `crates/heimdall/src/signals.rs` |
| BIN-050..BIN-051 | Redis pool bootstrap (fail-closed) and graceful drain | Pending (task #552) |
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
