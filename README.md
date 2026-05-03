# Heimdall

A high-performance, security-first DNS server written in Rust, designed for environments of extremely high load and concurrency.

## Specification

The [`specification/`](specification/) directory is the single source of truth for all functional requirements, architectural decisions, and invariants. Key documents:

- [`001-server-roles.md`](specification/001-server-roles.md) — Authoritative, recursive, and forwarder roles
- [`002-transports.md`](specification/002-transports.md) — UDP/TCP/DoT/DoH/DoQ transport model
- [`003-crypto-policy.md`](specification/003-crypto-policy.md) — TLS 1.3 and QUIC cryptographic policy
- [`007-threat-model.md`](specification/007-threat-model.md) — Threat model and security requirements
- [`012-runtime-operations.md`](specification/012-runtime-operations.md) — SIGHUP reload, admin-RPC, observability endpoint
- [`015-binary-contract.md`](specification/015-binary-contract.md) — `heimdall(8)` binary entry-point: CLI surface, boot sequence, signal model, exit codes

See [`specification/README.md`](specification/README.md) for the full index.

## Operator manual

The `heimdall` daemon is started via:

```
heimdall start --config /etc/heimdall/heimdall.toml
```

Validate configuration without starting:

```
heimdall check-config --config /etc/heimdall/heimdall.toml
```

Print version and build metadata:

```
heimdall version
```

For the complete binary contract (CLI options, environment variables, exit codes, signal model), see [`specification/015-binary-contract.md`](specification/015-binary-contract.md).
