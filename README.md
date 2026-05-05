# Heimdall

A high-performance, security-first DNS server written in Rust, designed for
environments of extremely high load and concurrency.

## Quickstart

### Build from source

```text
cargo build --release -p heimdall
```

The binary is at `target/release/heimdall`.

### Minimal configuration

Create `/etc/heimdall/heimdall.toml`:

```toml
# Recursive resolver listening on UDP and TCP port 53.
[roles]
recursive = true

[[listeners]]
address   = "127.0.0.1"
port      = 5353
transport = "udp"

[[listeners]]
address   = "127.0.0.1"
port      = 5353
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = 9082
```

### Validate the configuration

```text
heimdall check-config --config /etc/heimdall/heimdall.toml
```

Exit 0 means the configuration is valid.  Exit 2 means validation failed;
the error is written to stderr.

### Start the server

```text
heimdall start --config /etc/heimdall/heimdall.toml
```

The server binds its listeners, performs privilege drop, and emits
`sd_notify(READY=1)` when it is ready to serve queries.

### Verify it is running

```text
# Send a test query (requires dig).
dig @127.0.0.1 -p 5353 example.com A

# Or use heimdall-probe.
heimdall probe query example.com A @127.0.0.1:5353
```

### Print build metadata

```text
heimdall version
```

### Reload configuration without downtime

```text
kill -HUP $(pidof heimdall)
```

### Graceful drain and stop

```text
# Via admin-RPC (requires the admin socket to be configured).
heimdall probe admin drain

# Or send SIGTERM.
kill -TERM $(pidof heimdall)
```

---

## Example configurations

The `contrib/` directory contains ready-to-use configurations for common
deployment shapes:

| File | Role |
|------|------|
| `contrib/heimdall-recursive.toml` | Recursive resolver |
| `contrib/heimdall-auth.toml` | Authoritative server |
| `contrib/heimdall-forwarder.toml` | Forwarder |

---

## Specification

The [`specification/`](specification/) directory is the single source of truth
for all functional requirements, architectural decisions, and invariants.
Key documents:

- [`001-server-roles.md`](specification/001-server-roles.md) — Authoritative, recursive, and forwarder roles
- [`002-transports.md`](specification/002-transports.md) — UDP/TCP/DoT/DoH/DoQ transport model
- [`003-crypto-policy.md`](specification/003-crypto-policy.md) — TLS 1.3 and QUIC cryptographic policy
- [`007-threat-model.md`](specification/007-threat-model.md) — Threat model and security requirements
- [`012-runtime-operations.md`](specification/012-runtime-operations.md) — SIGHUP reload, admin-RPC, observability
- [`015-binary-contract.md`](specification/015-binary-contract.md) — CLI surface, boot sequence, signal model, exit codes

See [`specification/README.md`](specification/README.md) for the full index.

---

## Release notes

- [v1.1.0](docs/release-notes/v1.1.0.md) — First functional GA release (2026-05-05)
- [v1.0.0](docs/release-notes/v1.0.0.md) — Non-functional placeholder (2026-04-27)
