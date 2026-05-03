# Heimdall Operator Manual

This document is the primary operational reference for system administrators
deploying and managing Heimdall in production environments.

**See also**

- [Configuration Reference](configuration-reference.md) — every TOML option
  documented exhaustively.
- [Troubleshooting Guide](troubleshooting.md) — symptom-driven diagnosis.
- [Admin-RPC Guide](admin-guide.md) — JSON-over-UDS runtime control.
- [Security Posture](security-posture.md) — threat model coverage and
  cryptographic policy.
- [Deployment Runbooks](deployment/) — per-platform installation procedures.

---

## 1. Overview and roles

Heimdall is a high-performance, security-focused DNS server written in Rust.
It targets environments of extremely high load and concurrency. A single
Heimdall process may operate in one or more of three roles simultaneously.
The active set of roles is governed by the `[role]` section of the
configuration file and by which zones are loaded.

### 1.1 Recursive resolver

The recursive resolver iteratively follows DNS delegation chains from the root
to authoritative servers. It validates DNSSEC signatures by default (per
`DNSSEC-009`), applies aggressive NSEC/NSEC3 negative caching, enforces the
KeyTrap cap, caps NSEC3 iterations at 150, and maintains a segregated cache
to prevent cache-poisoning interactions with the forwarder role (CACHE-001).

QNAME minimisation (RFC 7816) is enabled by default to limit the data exposed
to upstream authoritative servers.

### 1.2 Authoritative server

The authoritative server serves zones loaded from disk (RFC 1035 master-file
format). It supports:

- Inbound AXFR/IXFR requests from secondaries, ACL-guarded (default deny).
- Acting as secondary via AXFR/IXFR from a configured primary.
- NOTIFY inbound (RFC 1996) to trigger incremental zone refresh.
- Response Rate Limiting (RRL) per RFC 8906, active by default.

Dynamic update (RFC 2136) is not supported.

### 1.3 Forwarder

The forwarder role dispatches queries to configured upstream resolvers. It
supports per-rule upstream selection, DoT/DoH/DoQ/UDP transport, independent
DNSSEC validation on every upstream response, a segregated forwarder cache,
pool-based connection keepalive, and per-client rate limiting.

---

## 2. Installation

### 2.1 Linux (systemd)

See the [Linux systemd runbook](deployment/linux-systemd.md) for complete
step-by-step installation from `.deb`, `.rpm`, or `.tar.gz`.

**Quick summary**:

```sh
# Debian / Ubuntu
sudo dpkg -i heimdall_<version>_amd64.deb

# RHEL / Fedora
sudo rpm -i heimdall-<version>.x86_64.rpm

# Generic tar.gz
sudo install -m 755 heimdall /usr/bin/heimdall

# Create dedicated user
sudo useradd -r -d /var/lib/heimdall -s /sbin/nologin heimdall

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now heimdall
```

The reference systemd unit file ships at `contrib/systemd/heimdall.service`
and applies all mandatory hardening directives (THREAT-025, THREAT-031).
Per-role drop-ins live in `contrib/systemd/heimdall.service.d/`.

### 2.2 OpenBSD (rc.d)

See the [OpenBSD runbook](deployment/openbsd.md).

```sh
# Create dedicated user (package install does this automatically)
useradd -d /var/empty -s /sbin/nologin _heimdall

# Install the rc.d script
install -m 755 contrib/openbsd/heimdall.rc /etc/rc.d/heimdall

# Enable
rcctl enable heimdall
rcctl start heimdall
```

`pledge(2)` and `unveil(2)` are applied by the Heimdall binary itself at
process start (THREAT-029, THREAT-100 through THREAT-102). They cannot be
applied externally by the rc.d script.

**Important**: after a SIGHUP reload the unveil set is not extended. To grant
access to a new path (for example a new TLS certificate directory), stop and
restart the Heimdall process.

### 2.3 macOS (developer quickstart)

macOS is a development-only target (ENV-009). It is not supported for
production use.

```sh
# Build from source
cargo build --release

# Run under the macOS sandbox profile
sandbox-exec -f contrib/macos/heimdall.sb \
    ./target/release/heimdall --config /usr/local/etc/heimdall/heimdall.toml
```

The macOS sandbox profile (`contrib/macos/heimdall.sb`) provides
`sandbox-exec`-level confinement on a best-effort basis (THREAT-030).

### 2.4 OCI / Docker

See the [OCI runbook](deployment/oci.md).

The official image is a distroless static image built with musl; it contains
only the Heimdall binary and CA certificates (ENV-026, ENV-033).

```sh
# Build locally
docker buildx build --platform linux/amd64,linux/arm64 -t heimdall:local .

# Run with a bind-mounted configuration
docker run --rm \
    -p 53:53/udp -p 53:53/tcp \
    -v /etc/heimdall:/etc/heimdall:ro \
    heimdall:local
```

---

## 3. Configuration quickstart

Configuration is a single TOML file, by default at
`/etc/heimdall/heimdall.toml`. Pass an alternative path with `--config`.

A minimal recursive-resolver configuration:

```toml
[network]
listen = ["0.0.0.0:53", "[::]:53"]

[role]
mode = "recursive"

[log]
level = "info"
format = "json"
```

A complete annotated example lives at `contrib/heimdall.toml.example`.
Every option is documented exhaustively in the
[Configuration Reference](configuration-reference.md).

---

## 4. Transport configuration

Heimdall supports four transports. All are configured in the `[network]`
section, and TLS-bearing transports additionally require the `[tls]` section.

### 4.1 Classic DNS (UDP/TCP port 53)

```toml
[network]
listen = ["0.0.0.0:53", "[::]:53"]
```

Binding to port 53 requires `CAP_NET_BIND_SERVICE` on Linux (provided by the
reference systemd unit) or root on other platforms.

### 4.2 DNS over TLS (DoT, port 853)

```toml
[network]
listen_dot = ["0.0.0.0:853"]

[tls]
certificate = "/etc/heimdall/tls/cert.pem"
private_key = "/etc/heimdall/tls/key.pem"
```

Only TLS 1.3 is accepted (SEC-001 through SEC-004, ADR-0027). TLS 1.2 is
disabled at compile time. Session tickets use stateless TEK rotation (SEC-008
through SEC-011). Early data (0-RTT) is disabled (SEC-005 through SEC-007).

### 4.3 DNS over HTTPS (DoH, port 443)

```toml
[network]
listen_doh = ["0.0.0.0:443"]

[tls]
certificate = "/etc/heimdall/tls/cert.pem"
private_key = "/etc/heimdall/tls/key.pem"
```

Both HTTP/2 (RFC 8484) and HTTP/3 over QUIC are served on the same listener
address. HTTP/2 and HTTP/3 hardening (SEC-036 through SEC-046) is applied:
header-block size limits, concurrent-stream caps, rapid-reset detection,
CONTINUATION-flood caps, and flow-control bounds.

### 4.4 DNS over QUIC (DoQ, port 853)

```toml
[network]
listen_doq = ["0.0.0.0:853"]

[tls]
certificate = "/etc/heimdall/tls/cert.pem"
private_key = "/etc/heimdall/tls/key.pem"
```

QUIC v1 and v2 are accepted (SEC-017 through SEC-021). 0-RTT application
data is rejected unconditionally (SEC-022 through SEC-024). Unconditional
Retry is applied for address validation.

---

## 5. Security hardening overview

Heimdall's hardening profile is non-optional and applies to every deployment.

### 5.1 Privilege drop (Linux, THREAT-022/023)

The Heimdall binary binds its listening sockets and then drops privileges to
the dedicated `heimdall` user. Only `CAP_NET_BIND_SERVICE` is retained
(required for re-binding to privileged ports across SIGHUP reloads). All
other capabilities are dropped.

### 5.2 seccomp-bpf (Linux, THREAT-024)

A seccomp-bpf allow-list filter restricts the process to the syscalls it
actually uses. Any syscall not on the allow-list is rejected with `ENOSYS`
(THREAT-094, ADR-0020). The filter is applied after socket binding and
privilege drop.

### 5.3 pledge + unveil (OpenBSD, THREAT-029)

On OpenBSD, `pledge(2)` restricts the system-call surface and `unveil(2)`
restricts filesystem visibility to the minimum required by the active role set
(THREAT-100 through THREAT-102). These are applied by the Heimdall binary at
startup. The unveil set is fixed at startup and cannot be extended via SIGHUP.

### 5.4 macOS sandbox (THREAT-030)

On macOS, the `sandbox-exec` profile at `contrib/macos/heimdall.sb` confines
the process. This is a SHOULD-level control; macOS is development-only.

### 5.5 W^X (THREAT-027)

No memory region is simultaneously writable and executable. The systemd unit
enforces `MemoryDenyWriteExecute=yes`.

### 5.6 Filesystem isolation (THREAT-026)

The systemd unit applies `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`, and `PrivateDevices=yes`. Read-only and read-write paths are
declared explicitly via drop-ins.

---

## 6. Lifecycle management

For the complete 18-phase boot sequence, see [docs/operator/boot.md](operator/boot.md).

### 6.1 Start

```sh
# systemd
systemctl start heimdall

# OpenBSD
rcctl start heimdall

# Direct
heimdall start --config /etc/heimdall/heimdall.toml
```

Heimdall notifies systemd via `sd_notify(3)` when it is ready to serve
traffic.  The unit type is `notify` with `NotifyAccess=main`.  A watchdog
keepalive (`WATCHDOG=1`) is sent every `WatchdogSec / 2` seconds while the
process is healthy.

### 6.2 Stop and drain

```sh
# systemd
systemctl stop heimdall
```

On `SIGTERM` (sent by systemd `stop`), Heimdall:

1. Sends `STOPPING=1` to systemd and `EXTEND_TIMEOUT_USEC` to extend the
   stop timeout to match `[server] drain_grace_secs` (default 30 s).
2. Stops all listeners from accepting new connections.
3. Waits up to `drain_grace_secs` for in-flight queries to complete.
4. Exits with code 0 (clean) or 0 with a warning log (timeout).

A second `SIGTERM` during drain forces immediate exit.

### 6.3 Configuration reload (SIGHUP)

```sh
# systemd
systemctl reload heimdall

# Direct
kill -HUP <pid>

# Admin-RPC
echo '{"cmd":"reload"}' | nc -U /run/heimdall/admin.sock
```

SIGHUP reloads the configuration file, re-reads TLS certificates, and applies
updated ACL rules without restarting the process or closing existing
connections. On OpenBSD, the unveil set is not extended by a reload; paths
not in the original unveil set require a full restart.

### 6.4 Health checks

```sh
# Liveness probe (returns 200 if the process is alive)
curl http://127.0.0.1:8080/healthz

# Readiness probe (returns 200 when ready to serve DNS traffic)
curl http://127.0.0.1:8080/readyz
```

The `[admin]` section configures the observability HTTP server port and the
admin UDS socket path. See the [Admin-RPC Guide](admin-guide.md) for details.

---

## 7. Observability

### 7.1 Prometheus metrics

```sh
curl http://127.0.0.1:8080/metrics
```

Metrics are exposed in Prometheus text format. Key metric families include:

| Family | Description |
|--------|-------------|
| `heimdall_queries_total` | Total queries received, by transport and role |
| `heimdall_query_duration_seconds` | Query latency histogram |
| `heimdall_cache_hits_total` | Cache hits and misses, by cache type |
| `heimdall_rrl_slipped_total` | Responses truncated by RRL (slip behaviour) |
| `heimdall_rrl_dropped_total` | Responses dropped by RRL |
| `heimdall_bogus_total` | DNSSEC validation failures |
| `heimdall_upstream_errors_total` | Upstream errors, by upstream and error type |
| `heimdall_tls_handshakes_total` | TLS handshake outcomes, by transport |

### 7.2 Structured logging

Heimdall emits structured logs in JSON (`format = "json"`) or plain text
(`format = "text"`) at the configured `level`. JSON format is recommended for
log aggregation pipelines (Elasticsearch, Loki, Splunk).

### 7.3 Version

```sh
curl http://127.0.0.1:8080/version
```

Returns the Heimdall version, build commit, and feature flags.

---

## 8. Upgrade procedure

1. **Download** the new binary or package.
2. **Review** the `CHANGELOG.md` for breaking configuration changes.
3. **Test** in a staging environment against the production configuration.
4. **Install** the new binary. On Linux with systemd:

```sh
# Stop the running instance
systemctl stop heimdall

# Install the new binary
install -m 755 heimdall-new /usr/bin/heimdall

# Start the new instance
systemctl start heimdall

# Verify readiness
curl http://127.0.0.1:8080/readyz
```

For zero-downtime upgrades in load-balanced deployments:
1. Remove the instance from the load balancer.
2. Drain via `echo '{"cmd":"drain"}' | nc -U /run/heimdall/admin.sock`.
3. Stop, upgrade, and restart.
4. Verify `/readyz` returns 200.
5. Re-add to the load balancer.

**Rolling back**: stop the new process, restore the previous binary from the
package manager or the previous archive, and restart. Configuration files are
forward-compatible within a minor version; consult `CHANGELOG.md` for minor
and major version boundaries.
