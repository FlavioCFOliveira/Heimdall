# Heimdall Boot Sequence

This document describes the phases that `heimdall start` executes from process
creation until the first DNS query is served.  Each phase is numbered to match
the `BIN-015` specification requirement in
[`specification/015-binary-contract.md`](../../specification/015-binary-contract.md).

---

## Phase overview

```
Phase  1  CLI parse (clap)
Phase  2  Log level / format resolution (RUST_LOG, --log-level, --log-format)
Phase  3  Logging subscriber initialisation (tracing-subscriber)
Phase  4  Configuration file load and validation (TOML → Config)
Phase  5  Runtime sizing (worker_threads from config or CPU count)
Phase  6  Tokio multi-thread runtime construction (epoll / io_uring / kqueue)
Phase  7  Initial RunningState construction (ArcSwap)
Phase  8  Redis pool bootstrap — fail-closed (future: task 552)
Phase  9  Role assembly — forwarder / recursive / authoritative (future: task 537)
Phase 10  Resource limits — RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_CORE (future: task 539)
Phase 11  Memory allocator selection — mimalloc / jemalloc / default (future: task 540)
Phase 12  Listener binding — UDP / TCP / DoT / DoH / DoQ (all-or-nothing, BIN-022)
Phase 13  Admin-RPC listener binding (future: task 553)
Phase 14  HTTP observability listener binding (future: task 554)
Phase 15  Privilege drop — KEEPCAPS → setuid/setgid heimdall → CAP_NET_BIND_SERVICE (Linux only; BIN-041..043)
Phase 16  SIGHUP reload handler installation
Phase 17  Listener worker spawn (tokio::spawn per bound listener)
Phase 18  Watchdog keepalive spawn (WATCHDOG_USEC / 2 interval; OPS-045)
          sd_notify READY=1 → process is ready to serve
          →  supervision loop awaits SIGTERM / SIGINT
```

---

## Detailed phase notes

### Phase 1 — CLI parse

The CLI is parsed by [clap](../../docs/adr/0060-clap.md) in derive mode.
The `start` subcommand accepts:

| Flag / env | Default | Description |
|---|---|---|
| `--config` / `HEIMDALL_CONFIG` | `/etc/heimdall/heimdall.toml` | Path to the TOML configuration file |
| `--log-level` / `RUST_LOG` | `info` | Tracing filter (`error`, `warn`, `info`, `debug`, `trace`) |
| `--log-format` | `json` (prod), `pretty` (TTY) | Log format: `json` or `pretty` |

### Phase 4 — Configuration load and validation

Configuration is loaded synchronously from the path supplied via `--config`.
Validation is all-or-nothing: any error causes an exit with code **2** and a
human-readable message on `stderr`.  The file is watched at runtime for SIGHUP
reloads.

Key validated constraints:

- At least one `[[listeners]]` entry is required when any role is active.
- TLS transports (`dot`, `doh`, `doq`) require both `tls_cert` and `tls_key`.

### Phase 6 — Tokio runtime

The runtime selects the most efficient I/O backend available on the host:

| Platform | Backend |
|---|---|
| Linux ≥ 5.19 with `io-uring` feature | `io_uring` |
| Linux (default) | `epoll` |
| macOS / BSD | `kqueue` |

Worker thread count defaults to the logical CPU count and is tunable via
`[server] worker_threads = N`.

### Phase 12 — Listener binding

Listener binding is **all-or-nothing** (BIN-022).  If any socket cannot be
bound, all previously bound sockets are dropped and the process exits with
code **1**.

Supported transports and their protocols:

| `transport` | Protocol | Default port |
|---|---|---|
| `udp` | DNS-over-UDP (RFC 1035) | 53 |
| `tcp` | DNS-over-TCP (RFC 7766) | 53 |
| `dot` | DNS-over-TLS (RFC 7858) | 853 |
| `doh` | DNS-over-HTTPS/2 (RFC 8484) | 443 |
| `doq` | DNS-over-QUIC (RFC 9250) | 853 |

### Phase 15 — Privilege drop (Linux only)

When running as root on Linux, Heimdall:

1. Looks up the `heimdall` system user via `getpwnam`.
2. Sets `PR_SET_KEEPCAPS` so capabilities survive the `setuid` call.
3. Raises `CAP_NET_BIND_SERVICE` in the ambient set.
4. Calls `setgid` and `setuid` to drop to the `heimdall` user.
5. Verifies that only `CAP_NET_BIND_SERVICE` is present and effective is not empty.

On macOS and other non-Linux platforms, this phase is a no-op.  If a listener
is configured on a port below 1024 on a non-Linux platform, a warning is
logged at startup.

### Phase 18 — sd_notify and supervision

At the end of Phase 17, after all listener workers are spawned:

- `spawn_watchdog()` starts a background task that sends `WATCHDOG=1` to
  `$NOTIFY_SOCKET` every `$WATCHDOG_USEC / 2` microseconds (when systemd sets
  the variable).
- `notify_ready()` sends `READY=1` to systemd, transitioning the unit from
  `activating` to `active (running)`.

---

## Shutdown sequence

When Heimdall receives SIGTERM (or SIGINT):

1. `notify_stopping()` sends `STOPPING=1` to systemd.
2. `notify_extend_timeout_usec(grace * 1_000_000)` requests that systemd
   extend its stop timeout to match the configured `drain_grace_secs`.
3. `drain_and_wait(grace)` stops all listeners from accepting new connections
   and waits up to `drain_grace_secs` seconds for in-flight queries to complete.
4. On clean drain: logs `"Drain complete"` and exits with code **0**.
5. On grace timeout: logs `"Drain grace period elapsed"` with the number of
   remaining in-flight queries and exits with code **0**.
6. A second SIGTERM during drain forces immediate exit with code **0**.

| Exit code | Meaning |
|---|---|
| 0 | Clean shutdown |
| 1 | Runtime error (listener bind failure, privilege drop failure, etc.) |
| 2 | Configuration error |

---

## Signal model

| Signal | Effect |
|---|---|
| `SIGTERM` | Graceful shutdown with drain |
| `SIGINT` | Graceful shutdown with drain (identical to SIGTERM) |
| `SIGHUP` | Hot-reload configuration file (zero downtime) |
| `SIGPIPE` | Ignored (broken pipe surfaces as `io::Error` in handlers) |
| `SIGUSR1` | Reserved (debug-logged, no action) |
| `SIGUSR2` | Reserved (debug-logged, no action) |

---

## Environment variables

| Variable | Description |
|---|---|
| `HEIMDALL_CONFIG` | Override the default config path (`/etc/heimdall/heimdall.toml`) |
| `RUST_LOG` | Tracing filter directive (e.g. `info`, `heimdall=debug`) |
| `HEIMDALL_WORKER_THREADS` | Override the `worker_threads` config value |
| `NOTIFY_SOCKET` | Set by systemd; Heimdall sends sd_notify datagrams here |
| `WATCHDOG_USEC` | Set by systemd when `WatchdogSec=` is configured; enables keepalive |

---

## See also

- [Operator Manual](../operator-manual.md) — full operational reference
- [Configuration Reference](../configuration-reference.md) — all TOML options
- [Deployment: Linux systemd](../deployment/linux-systemd.md)
- [systemd unit file](../../contrib/systemd/heimdall.service)
