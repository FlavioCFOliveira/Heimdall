# Binary contract

**Purpose.** This document defines the binary entry-point contract for the `heimdall(8)` daemon: the CLI surface exposed to operators, the boot sequence that wires configuration, runtime, and roles together, the signal model, the exit-code table, the environment-variable contract, the file and socket descriptor obligations, the working-directory and umask assumptions, the `sd_notify` state machine, and the panic-abort policy. It is the source of truth against which `main.rs` and the operator manual are written and tested. It does not redefine how transports, roles, caches, or runtime-operations work; those questions are settled in [`001-server-roles.md`](001-server-roles.md), [`002-transports.md`](002-transports.md), [`012-runtime-operations.md`](012-runtime-operations.md), and the crate-level specifications for `heimdall-runtime` and `heimdall-roles`.

**Status.** Stable. All open questions resolved (Sprint 46, 2026-05-03).

**Requirement category.** `BIN`.

For the project-wide principles that frame these requirements (security non-negotiable, performance as the primary guide, "Assume Nothing"), see [`../CLAUDE.md`](../CLAUDE.md). For specification-wide conventions, see [`README.md`](README.md). For the role model, see [`001-server-roles.md`](001-server-roles.md). For the transport model, see [`002-transports.md`](002-transports.md). For the runtime operations model (SIGHUP reload, admin-RPC, observability endpoint), see [`012-runtime-operations.md`](012-runtime-operations.md). For the target-environment model (OS tiers, privilege drop), see [`009-target-environment.md`](009-target-environment.md). For the crypto policy (TLS, QUIC), see [`003-crypto-policy.md`](003-crypto-policy.md). For the threat model (ACL, rate limiting, audit events), see [`007-threat-model.md`](007-threat-model.md).

## 1. Scope

This document applies to the `heimdall` binary crate — the thin entry-point that loads configuration, instantiates the Tokio runtime, assembles roles, binds listeners, and supervises the running daemon. It does not govern the library crates (`heimdall-core`, `heimdall-runtime`, `heimdall-roles`) beyond their public surface as seen from `main.rs`. Every normative statement in this document is binding on the `heimdall` binary crate and on the operator documentation that describes its operation.

## 2. CLI surface

### 2.1 Subcommand structure

- **BIN-001.** The `heimdall` binary MUST expose its CLI through `clap` using the builder or derive API. The top-level binary MUST support the following subcommands exactly: `start`, `check-config`, `version`, and `help`. No other top-level subcommands MUST be introduced without a corresponding normative requirement in this document.

- **BIN-002.** The `start` subcommand MUST accept the following options:
  - `--config <PATH>` (short: `-c`): path to the TOML configuration file. Defaults to `/etc/heimdall/heimdall.toml`. Overridden by `HEIMDALL_CONFIG` environment variable per `BIN-012`.
  - `--log-level <LEVEL>` (short: `-l`): structured log level. Accepted values (case-insensitive): `error`, `warn`, `info`, `debug`, `trace`. Defaults to `info`. Overridden by `RUST_LOG` per `BIN-013`.
  - `--log-format <FORMAT>`: log output format. Accepted values: `json`, `pretty`. Defaults to `json`. The `pretty` format MUST only be used in interactive terminal sessions; production deployments MUST use `json`.
  - `--color <WHEN>`: colour in terminal output. Accepted values: `auto`, `always`, `never`. Defaults to `auto`.

- **BIN-003.** The `check-config` subcommand MUST accept the same `--config` option as `start`. It MUST perform a deep validation of the configuration file: parse, semantic validation, Redis reachability probe, zone-load dry run (parsing and DNSSEC validation of all zone files referenced by the configuration), and listener bind dry run (attempt to bind all configured sockets and immediately release them). It MUST exit with code `0` if and only if all checks pass. On any failure it MUST exit with code `2` and MUST emit a human-readable description of every failure to stderr.

- **BIN-004.** The `version` subcommand MUST print version and build metadata to stdout and exit with code `0`. The output MUST include at minimum: the project semantic version, the git commit SHA of the build, the build timestamp in RFC 3339 format, the Minimum Supported Rust Version in effect for the build, the set of transports compiled in, and the set of roles compiled in. The exact output format (plain text or JSON) is an implementation detail, but MUST be stable across patch releases.

- **BIN-005.** Every subcommand and every option MUST have a short description that appears in `--help` output. The top-level `heimdall --help` MUST list all subcommands. Every subcommand `--help` MUST list all options for that subcommand. `help` as a positional argument MUST be equivalent to `--help`.

### 2.2 Exit-code table

- **BIN-006.** The `heimdall` binary MUST use the following exit-code table without exception. No exit code outside this table MUST be emitted by `heimdall` itself (exit codes from child processes or from the OS signal mechanism are not governed by this document):

  | Code | Symbolic name      | Meaning                                                                                |
  |-----:|--------------------|----------------------------------------------------------------------------------------|
  |    0 | `EX_OK`            | Successful completion (`version`, `check-config` pass, clean `start` after drain).    |
  |    1 | `EX_STARTUP`       | Startup error: a recoverable or transient error prevented the daemon from starting.    |
  |    2 | `EX_CONFIG`        | Configuration invalid: parse or semantic-validation failure, or `check-config` failed.|
  |   64 | `EX_USAGE`         | Usage error: unknown subcommand, missing required option, unrecognised flag.           |
  |   70 | `EX_SOFTWARE`      | Internal software error: an unexpected panic reached `main()`, or an invariant was violated. |

  All codes are aligned with `sysexits.h` conventions where standard codes exist.

- **BIN-007.** A clean shutdown triggered by `SIGTERM`, `SIGINT`, or the admin-RPC `Drain` RPC MUST exit with code `0` after the drain grace period.

- **BIN-008.** A startup failure caused by a missing or unreadable configuration file, a Redis connection failure, a listener bind failure, or a zone-load failure MUST exit with code `1`. A configuration parse or semantic-validation failure MUST exit with code `2`.

## 3. Environment-variable contract

- **BIN-009.** Environment variables MUST be evaluated at process start, before option parsing, so that they can be overridden by explicit command-line options.

- **BIN-010.** The environment-variable precedence rule is: explicit CLI option > environment variable > compiled-in default. An environment variable MUST never silently shadow a CLI option; the CLI option always wins.

- **BIN-011.** Unrecognised environment variables with the `HEIMDALL_` prefix MUST be silently ignored. This document does not define a warning for unknown environment variables in order to avoid breaking deployments that set additional environment variables for operator tooling.

- **BIN-012.** `HEIMDALL_CONFIG`: if set and non-empty, treated as the configuration file path. Overridden by `--config`. On a Unix system the path MUST be validated for existence and readability before the Tokio runtime is started.

- **BIN-013.** `RUST_LOG`: if set and non-empty, treated as the `tracing-subscriber` directive string. Overrides `--log-level`. The full `tracing-subscriber` directive syntax applies; per-crate filtering is permitted. If `RUST_LOG` is invalid (fails directive parsing), `heimdall` MUST log a `WARN`-level message and fall back to the `--log-level` value.

- **BIN-014.** `HEIMDALL_WORKER_THREADS`: if set and non-empty, treated as the number of Tokio worker threads. MUST be a positive integer. MUST NOT exceed the number of logical CPUs reported by the OS. Invalid or out-of-range values MUST cause exit with code `2`. If unset, defaults to the Tokio default (number of logical CPUs).

## 4. Boot sequence

### 4.1 Phase ordering

- **BIN-015.** The `start` subcommand MUST execute the following phases in the exact order listed. No phase MAY begin before the preceding phase has completed successfully. Any failure in a phase MUST abort the boot sequence and exit with the code specified for that phase.

  1. **Parse CLI.** Parse arguments via `clap`. On error: exit `64`.
  2. **Resolve config path.** Apply environment-variable and CLI-option precedence per section 3. On missing or unreadable file: exit `1`.
  3. **Parse and validate configuration.** Load and parse the TOML configuration file. Perform semantic validation. On any error: exit `2`.
  4. **Initialise logging.** Initialise `tracing-subscriber` with the resolved log level and format. This phase MUST complete before any subsequent diagnostic logging.
  5. **Set resource limits.** Apply `RLIMIT_NOFILE`, `RLIMIT_NPROC`, and `RLIMIT_CORE` per `BIN-025` through `BIN-027`.
  6. **Select allocator.** The allocator is selected at compile time per `BIN-028`; no runtime selection occurs in this phase.
  7. **Start Tokio runtime.** Start the Tokio multi-thread runtime per `BIN-019`. On failure: exit `1`.
  8. **Bootstrap Redis pool.** Establish the Redis connection pool per `BIN-029`. On failure: exit `1`.
  9. **Load configuration state.** Load zone files, DNSSEC trust anchors, RPZ data, and all other inputs required by the active roles. On any parse or validation failure: exit `2`.
  10. **Install signal handlers.** Install handlers for `SIGTERM`, `SIGINT`, and `SIGHUP` per section 5.
  11. **Assemble roles.** Instantiate the active roles (authoritative, recursive, forwarder) per `BIN-021`.
  12. **Bind listeners.** Bind all configured transport listeners per `BIN-022`. On bind failure: exit `1`.
  13. **Bind admin-RPC listener.** Bind the admin-RPC socket per `BIN-030`. On failure: exit `1`.
  14. **Bind observability endpoint.** Bind the HTTP observability endpoint per `BIN-031`. On failure: exit `1`.
  15. **Drop privileges.** Drop to the `heimdall` user, retaining `CAP_NET_BIND_SERVICE` only, per `BIN-023`.
  16. **Emit `sd_notify(READY=1)`.** Notify `systemd` (or equivalent) that the daemon is ready per section 6.
  17. **Enter main loop.** Begin serving queries. Block until the drain coordinator signals completion per `BIN-024`.
  18. **Clean exit.** After drain completes, emit `sd_notify(STOPPING=1)` per `BIN-034` and exit `0`.

### 4.2 Tokio runtime

- **BIN-016.** The Tokio runtime MUST be started with `tokio::runtime::Builder::new_multi_thread()`. Single-threaded and current-thread runtimes MUST NOT be used in production builds.

- **BIN-017.** On Linux, `heimdall` MUST attempt to probe for `io_uring` availability at runtime. If `io_uring` is available and not disabled by configuration, Tokio MUST be started with the `tokio-uring` backend or equivalent `io_uring` integration. If `io_uring` is unavailable or disabled, `heimdall` MUST fall back to the `epoll`-based Tokio backend. This detection MUST be logged at `INFO` level before the Tokio runtime is started.

- **BIN-018.** On macOS (development-only) and BSD targets, `heimdall` MUST use the `kqueue`-based Tokio backend. No `io_uring` probe is performed on these platforms.

- **BIN-019.** If the Tokio runtime fails to start for any reason, `heimdall` MUST log the error to stderr (logging may not yet be initialised) and exit with code `1`.

### 4.3 Role assembly

- **BIN-020.** Role assembly MUST be driven exclusively by the `roles` section of the parsed configuration. The set of active roles is fixed at boot and MUST NOT change at runtime without a full reload triggered by `SIGHUP`.

- **BIN-021.** `heimdall` MUST assemble only the roles listed as active in the configuration. Inactive roles MUST NOT consume memory, open file descriptors, or start background tasks. The role assembly MUST fail closed: if a required dependency of an active role (zone files for authoritative, root hints for recursive, upstream upstreams for forwarder) is absent or invalid, boot MUST fail with exit code `1` or `2` as appropriate.

### 4.4 Listener binding

- **BIN-022.** `heimdall` MUST bind all configured transport listeners in a single sequential pass during phase 12 of the boot sequence. If any listener bind fails, the entire boot MUST fail with exit code `1`. Partially bound state (some listeners bound, others not) MUST NOT be permitted to persist; any already-bound sockets MUST be closed before the process exits.

## 5. Signal model

- **BIN-023-SIG.** Signal handlers MUST be installed using an async-safe mechanism compatible with Tokio (e.g. `tokio::signal`). POSIX signal handlers that call non-async-safe functions MUST NOT be used.

- **BIN-024.** On receipt of `SIGTERM` or `SIGINT`, `heimdall` MUST initiate a controlled drain. The drain MUST: stop accepting new connections on all listeners; allow in-flight queries to complete up to the configured grace timeout (default 30 seconds per `BIN-032`); after the grace timeout, forcibly close any remaining connections; emit `sd_notify(STOPPING=1)`; then exit with code `0`.

- **BIN-025-SIG.** On receipt of `SIGHUP`, `heimdall` MUST trigger the full configuration reload defined by `OPS-001` through `OPS-006` in [`012-runtime-operations.md`](012-runtime-operations.md). The `SIGHUP` handler MUST NOT block the main async runtime; it MUST enqueue the reload request to the serialisation queue defined by `OPS-039`.

- **BIN-026-SIG.** `SIGPIPE` MUST be ignored at process start. Broken pipe conditions MUST be handled via Rust `io::Error` return values in the async I/O layer.

- **BIN-027-SIG.** `SIGUSR1` and `SIGUSR2` are reserved for future use. Receipt of these signals MUST be logged at `DEBUG` level and otherwise ignored.

## 6. `sd_notify` state machine

- **BIN-028-SD.** When `heimdall` is started under `systemd` (detected by the presence of the `NOTIFY_SOCKET` environment variable), it MUST send the following notifications via `sd_notify` at the indicated transitions:

  | Notification          | When                                                                                   |
  |-----------------------|----------------------------------------------------------------------------------------|
  | `READY=1`             | After phase 15 (privilege drop) completes and the daemon is ready to serve queries.    |
  | `STATUS=<message>`    | At each phase transition during boot (informational, for `systemctl status`).          |
  | `STOPPING=1`          | When the drain coordinator signals completion, immediately before process exit.         |
  | `WATCHDOG=1`          | At the interval configured by `WatchdogSec` in the service unit, if `WATCHDOG_USEC` is set. |
  | `WATCHDOG_USEC=<n>`   | Sent once at `READY=1` to override the watchdog interval to half the configured value. |

- **BIN-029-SD.** The watchdog keepalive MUST be driven by a periodic Tokio task that reads `WATCHDOG_USEC` at startup and sends `WATCHDOG=1` at half the watchdog interval. If the task fails to run (e.g. due to a completely blocked runtime), the watchdog will expire and `systemd` will restart the process, which is the intended fail-safe behaviour.

- **BIN-030-SD.** If `NOTIFY_SOCKET` is not set, all `sd_notify` calls MUST be silently skipped. The binary MUST NOT fail or warn if `NOTIFY_SOCKET` is absent.

## 7. File and socket descriptor contract

- **BIN-031-FD.** At process start, `heimdall` MUST close or mark as close-on-exec (`FD_CLOEXEC`) all file descriptors inherited from the parent process except stdin (fd 0), stdout (fd 1), and stderr (fd 2). This MUST be done before any threads are started.

- **BIN-032-FD.** All sockets opened by `heimdall` MUST have `SO_CLOEXEC` set at creation time, so that they are not inherited by child processes (e.g. `check-config` subprocesses or OS-level health scripts).

- **BIN-033-FD.** `heimdall` MUST NOT daemonise itself (i.e. MUST NOT call `fork()` + `setsid()`). Process supervision is delegated to `systemd`, `runit`, `supervisord`, or equivalent. The binary MUST run in the foreground.

## 8. Working directory and umask

- **BIN-034-CWD.** `heimdall` MUST NOT assume a particular working directory. All file paths in the configuration file MUST be absolute. A relative path in the configuration MUST cause a validation error at phase 3 of the boot sequence with exit code `2`.

- **BIN-035-UMASK.** `heimdall` MUST set `umask(0o027)` at process start (before any file descriptors are created), so that newly created files are not world-readable. The Unix domain socket for the admin-RPC listener and for Redis connections MUST have permissions `0o600` or stricter.

## 9. Resource limits

- **BIN-036.** At boot phase 5, `heimdall` MUST raise `RLIMIT_NOFILE` to the configured value (default: 65536). If the configured value exceeds the hard limit reported by the OS, `heimdall` MUST use the hard limit and emit a `WARN`-level log entry.

- **BIN-037.** At boot phase 5, `heimdall` MUST set `RLIMIT_NPROC` to `0` to prevent forking. The only exception is if an explicit configuration option re-enables forking (which MUST require a separate normative requirement).

- **BIN-038.** At boot phase 5, `heimdall` MUST set `RLIMIT_CORE` to `0` to prevent core dumps in production. The default compiled-in value MUST be `0`. A configuration option MAY re-enable core dumps for debugging builds, but MUST NOT be present in any production build.

## 10. Memory allocator

- **BIN-039.** The global memory allocator MUST be selected at compile time via a feature flag. The supported options are `jemalloc` (via `tikv-jemallocator`), `mimalloc` (via `mimalloc`), and the default system allocator (no flag). The benchmark results from task ENG-226 (Sprint 46) MUST be used to select the production default. The feature flag MUST be documented in `Cargo.toml` and in the operator manual.

- **BIN-040.** The allocator selection MUST NOT affect any public API or observable behaviour of the daemon other than memory usage and throughput performance.

## 11. Privilege model

- **BIN-041.** `heimdall` MUST be started as root (or with `CAP_NET_BIND_SERVICE`) when binding to ports below 1024. After all listeners are bound (phase 12) and before the main loop begins (phase 17), `heimdall` MUST drop to the unprivileged `heimdall` user account and retain only `CAP_NET_BIND_SERVICE`.

- **BIN-042.** On Linux, privilege drop MUST use `setuid(2)` / `setgid(2)` / `setgroups(2)` and the `capng` or `caps` crate to set the final capability bounding set. On BSD and macOS, `seteuid(2)` and `setegid(2)` MUST be used. The privilege drop MUST be logged at `INFO` level.

- **BIN-043.** After privilege drop, `heimdall` MUST NOT be able to re-acquire root or additional capabilities. A failed privilege drop MUST cause exit with code `1`.

## 12. Panic-abort policy

- **BIN-044.** The `heimdall` binary crate MUST set `panic = "abort"` in its `Cargo.toml` `[profile.release]` section. Stack unwinding on panic MUST NOT be permitted in release builds, to prevent information leakage through partial stack unwinds.

- **BIN-045.** In debug builds, `panic = "unwind"` is permitted to allow test infrastructure to catch panics.

- **BIN-046.** A panic that reaches `main()` (i.e. is not caught by any test harness) MUST result in exit code `70` (`EX_SOFTWARE`). A custom panic hook MUST be installed before the Tokio runtime starts to log the panic message and backtrace at `ERROR` level before aborting.

## 13. Drain coordinator

- **BIN-047.** The drain coordinator is a single component, owned by `main()`, that holds a `CancellationToken` (or equivalent) shared with all subsystems. On receiving a drain signal (from `SIGTERM`, `SIGINT`, or admin-RPC `Drain`), `main()` MUST cancel the token and wait for all subsystems to acknowledge completion.

- **BIN-048.** The drain grace timeout MUST default to 30 seconds. It MUST be operator-configurable in the configuration file. After the grace timeout, `main()` MUST log a `WARN`-level message listing the subsystems that have not yet completed, forcibly drop them, and proceed to exit.

- **BIN-049.** The Redis connection pool MUST be drained as part of the shutdown sequence per `BIN-050`. The drain coordinator MUST wait for the Redis pool drain to complete within the grace timeout before exiting.

## 14. Redis pool bootstrap and drain

- **BIN-050.** At boot phase 8, `heimdall` MUST establish the Redis connection pool as configured in [`013-persistence.md`](013-persistence.md). A failure to reach Redis at boot MUST cause exit with code `1`. The error MUST be logged at `ERROR` level with the connection address, the error code, and a human-readable description.

- **BIN-051.** On shutdown (drain phase), `heimdall` MUST drain the Redis connection pool: all pending operations MUST be allowed to complete or time out, and all connections MUST be closed cleanly. No torn writes (partial pipeline flushes) and no leaked connections MUST be permitted.

## 15. Admin-RPC listener

- **BIN-052.** At boot phase 13, `heimdall` MUST bind the admin-RPC listener as configured in `OPS-008` and `OPS-009` in [`012-runtime-operations.md`](012-runtime-operations.md). The default binding MUST be a Unix domain socket at the path configured in the `[admin]` section of the configuration file (default: `/run/heimdall/admin.sock`).

- **BIN-053.** The admin-RPC socket MUST be created with permissions `0o600` and owned by the `heimdall` user, to restrict access to the operator account.

## 16. HTTP observability endpoint

- **BIN-054.** At boot phase 14, `heimdall` MUST bind the HTTP observability endpoint as configured in `OPS-021` through `OPS-031` in [`012-runtime-operations.md`](012-runtime-operations.md). The default binding MUST be `127.0.0.1:9053`.

- **BIN-055.** The observability endpoint MUST be bound before the `sd_notify(READY=1)` signal is sent, so that health checks executed by `systemd` immediately after `READY=1` can succeed.

## 17. Version embedding

- **BIN-056.** The project version, git commit SHA, and build timestamp MUST be embedded at compile time via `build.rs` using the `vergen` crate (or equivalent). The embedded values MUST be exposed through the `version` subcommand output and the `GET /version` HTTP endpoint.

- **BIN-057.** In reproducible-build environments where `git` metadata is unavailable, `heimdall` MUST fall back to the string `"unknown"` for the git commit SHA and the string `"1970-01-01T00:00:00Z"` for the build timestamp. The build MUST NOT fail if git metadata is unavailable.

## 18. Open questions

There are no open questions in this document at the time of its initial writing. All decisions listed here were fixed during Sprint 46 (2026-05-03) as part of the v1.0.0 GA binary-integration work.
