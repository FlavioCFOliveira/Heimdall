# Heimdall Configuration Reference

Heimdall is configured via a single TOML file (TOML v1.0.0). The default path
is `/etc/heimdall/heimdall.toml`; override it with `--config <path>`.

The configuration loader rejects any key not defined by this reference (ROLE-021).
Unknown keys cause the process to refuse to start — there are no silently ignored
options.

**See also**

- [Operator Manual](operator-manual.md) — deployment and lifecycle overview.
- `contrib/heimdall.toml.example` — annotated example configuration.

---

## `[network]`

Configures the listening addresses for all transports.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | array of strings | `[]` | UDP and TCP listener addresses in `addr:port` format. Each entry binds both a UDP and a TCP socket. Port 53 requires `CAP_NET_BIND_SERVICE` on Linux. Example: `["0.0.0.0:53", "[::]:53"]`. |
| `listen_dot` | array of strings | `[]` | DNS-over-TLS listener addresses (`addr:port`). Port 853 requires `CAP_NET_BIND_SERVICE`. Requires `[tls]` to be configured. See THREAT-016, SEC-001. |
| `listen_doh` | array of strings | `[]` | DNS-over-HTTPS listener addresses. Both HTTP/2 (RFC 8484) and HTTP/3 are served on the same address (NET-006). Requires `[tls]`. |
| `listen_doq` | array of strings | `[]` | DNS-over-QUIC listener addresses (RFC 9250). QUIC v1 and v2 accepted; 0-RTT refused. Requires `[tls]`. See SEC-017 through SEC-024. |

**Example**:

```toml
[network]
listen     = ["0.0.0.0:53", "[::]:53"]
listen_dot = ["0.0.0.0:853"]
listen_doh = ["0.0.0.0:443"]
listen_doq = ["0.0.0.0:853"]
```

---

## `[tls]`

Configures the TLS certificate used by DoT, DoH, and DoQ listeners. Required
when any of `listen_dot`, `listen_doh`, or `listen_doq` is non-empty.

Only TLS 1.3 is accepted (SEC-001 through SEC-004). TLS 1.2 is disabled at
compile time (ADR-0027). Session tickets use stateless TEK rotation (SEC-008
through SEC-011). Early data (0-RTT) is disabled (SEC-005 through SEC-007).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `certificate` | string (path) | — | Path to the PEM-encoded X.509 certificate chain. The file must be readable by the Heimdall process user at startup and on every SIGHUP reload. |
| `private_key` | string (path) | — | Path to the PEM-encoded PKCS#8 private key. The file must be readable by the Heimdall process user at startup and on every SIGHUP reload. |

**Example**:

```toml
[tls]
certificate = "/etc/heimdall/tls/cert.pem"
private_key = "/etc/heimdall/tls/key.pem"
```

---

## `[role]`

Selects the top-level operating mode. This is a simplified shorthand that
enables the corresponding role-activation table. For fine-grained control,
use the `[recursive]`, `[authoritative]`, or `[forwarder]` tables directly.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | — | Operating mode. One of `"recursive"`, `"authoritative"`, or `"forwarder"`. Sets `enabled = true` in the corresponding role table. A configuration with no active role is rejected at load (ROLE-026). See ROLE-001 through ROLE-007. |

**Example**:

```toml
[role]
mode = "recursive"
```

---

## `[recursive]`

Configures the recursive resolver role. Enabled when `[role] mode =
"recursive"` or when `[recursive] enabled = true`.

The recursive resolver iteratively follows DNS delegation chains from root
servers. It validates DNSSEC by default (DNSSEC-009), applies aggressive
NSEC/NSEC3 negative caching, enforces the KeyTrap cap (DNSSEC-028), and caps
NSEC3 iterations at 150 per RFC 9276 (DNSSEC-030).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `root_hints` | string (path) | built-in | Path to a root hints file in IANA format. When absent, Heimdall uses its compiled-in root hints (updated at build time). Update when the root server addresses change. |
| `dnssec_validation` | boolean | `true` | Enable DNSSEC signature validation. When `true`, responses with bogus signatures are returned with `SERVFAIL`. Setting to `false` is strongly discouraged in production (DNSSEC-009). See THREAT-017. |
| `qname_minimisation` | boolean | `true` | Enable QNAME minimisation per RFC 7816. Reduces the information disclosed to upstream authoritative servers. |
| `cache_size` | integer (bytes) | `134217728` | Maximum memory budget for the recursive cache in bytes (128 MiB default). Applies to the segregated recursive cache (CACHE-001). Adjust based on available RAM and expected working set. See THREAT-074. |

**Example**:

```toml
[recursive]
root_hints        = "/etc/heimdall/root.hints"
dnssec_validation = true
qname_minimisation = true
cache_size        = 536870912  # 512 MiB
```

---

## `[authoritative]`

Configures the authoritative server role. Enabled when `[role] mode =
"authoritative"` or when `[authoritative] enabled = true`.

The authoritative server serves zones loaded from disk. RRL is active by
default on every authoritative listener (THREAT-048).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `zone_dir` | string (path) | — | Directory from which zone files are loaded. Heimdall reads all `*.zone` files in this directory at startup and on each SIGHUP reload. Files must be in RFC 1035 master-file format. |
| `notify` | boolean | `true` | Send DNS NOTIFY (RFC 1996) to secondaries when a zone is updated via AXFR or IXFR. |
| `axfr_allowed` | array of strings | `[]` | CIDR prefixes permitted to request AXFR or IXFR. AXFR and IXFR are default-deny (THREAT-042); this list is the explicit allow. Example: `["10.0.0.0/8", "2001:db8::/32"]`. |

**Example**:

```toml
[authoritative]
zone_dir     = "/var/lib/heimdall/zones"
notify       = true
axfr_allowed = ["10.0.0.0/8"]
```

---

## `[forwarder]`

Configures the forwarder role. Enabled when `[role] mode = "forwarder"` or
when `[forwarder] enabled = true`.

The forwarder dispatches queries to upstream resolvers. It independently
validates DNSSEC on every upstream response (THREAT-017), maintains a
segregated forwarder cache (CACHE-001), and applies per-client rate limiting
by default (THREAT-051).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | array of strings | — | Ordered list of upstream resolver addresses. Each entry is an `addr:port` string. Queries are sent to upstreams in order; the first available upstream is used. |
| `transport` | string | `"udp"` | Transport used for upstream connections. One of `"udp"`, `"dot"`, `"doh"`, or `"doq"`. `"dot"`, `"doh"`, and `"doq"` require `verify_cert = true` to be set (ADR-0007). See SEC-001 through SEC-004, THREAT-017. |
| `verify_cert` | boolean | `true` | Verify the upstream server's TLS certificate. Setting to `false` disables certificate verification for encrypted transports and is strongly discouraged in production (ADR-0007). |

**Example**:

```toml
[forwarder]
upstream    = ["9.9.9.9:853", "149.112.112.112:853"]
transport   = "dot"
verify_cert = true
```

---

## `[acl]`

Configures the access control lists applied to every listener. ACL rules are
evaluated before any role-specific processing (THREAT-033). The ACL subsystem
supports source-IP/CIDR matching (THREAT-035), transport matching (THREAT-038),
and operation-type matching (THREAT-040).

Recursive and forwarder queries require explicit allow rules (THREAT-044).
AXFR/IXFR is always default-deny regardless of ACL configuration (THREAT-042).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow` | array of strings | `[]` | CIDR prefixes from which queries are accepted. Each entry is an IPv4 or IPv6 CIDR. `"0.0.0.0/0"` and `"::/0"` allow all clients. Evaluated before `deny`. See THREAT-035, ADR-0024. |
| `deny` | array of strings | `[]` | CIDR prefixes from which queries are rejected. Takes precedence over `allow` when both match. A matching deny rule returns `REFUSED`. |

**Example**:

```toml
[acl]
allow = ["192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"]
deny  = ["10.0.0.128/25"]
```

---

## `[rrl]`

Configures Response Rate Limiting (RRL) per RFC 8906. RRL is active by
default on the authoritative server role (THREAT-048). It limits the response
rate to clients exhibiting amplification patterns.

When a client's budget is exhausted, Heimdall applies slip behaviour
(THREAT-049): it periodically returns a truncated response with the `TC` bit
set, so that legitimate clients can fall back to TCP.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `window` | integer (seconds) | `15` | Sliding window duration over which the response budget is measured. See THREAT-050. |
| `limit` | integer | `100` | Maximum responses per window per `(client-prefix, qname, qtype)` bucket. Responses beyond this limit are subject to slip or drop. |
| `slip` | integer | `2` | Slip ratio: one in every `slip` responses beyond the limit is returned as a truncated TCP-fallback prompt; the rest are dropped. Set to `0` to drop all excess responses. See THREAT-049. |

**Example**:

```toml
[rrl]
window = 15
limit  = 100
slip   = 2
```

---

## `[log]`

Configures structured logging output.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `"info"` | Log verbosity. One of `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"`. `"debug"` and `"trace"` are high volume and are not recommended in production. |
| `format` | string | `"json"` | Log output format. `"json"` emits structured JSON lines suitable for log aggregators (Elasticsearch, Loki, Splunk). `"text"` emits human-readable lines suitable for direct terminal use. |

**Example**:

```toml
[log]
level  = "info"
format = "json"
```

---

## `[admin]`

Configures the admin-RPC Unix domain socket and the HTTP observability
endpoint (OPS-007 through OPS-032).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket_path` | string (path) | `"/run/heimdall/admin.sock"` | Filesystem path of the admin-RPC Unix domain socket. The socket is created at startup with mode `0600` owned by the Heimdall process user. Authentication is provided by filesystem permissions (OPS-008). See the [Admin-RPC Guide](admin-guide.md). |

**Example**:

```toml
[admin]
socket_path = "/run/heimdall/admin.sock"
```

---

## Spec cross-reference index

| Spec ID | Relevant options |
|---------|-----------------|
| ROLE-001 through ROLE-026 | `[role]`, `[recursive]`, `[authoritative]`, `[forwarder]` |
| SEC-001 through SEC-007 | `[tls]`, TLS 1.3-only policy, no early data |
| SEC-008 through SEC-011 | `[tls]`, TEK rotation |
| SEC-017 through SEC-024 | `listen_doq`, QUIC v1/v2, no 0-RTT |
| CACHE-001 | `cache_size` |
| DNSSEC-009 | `dnssec_validation` |
| DNSSEC-028 | `dnssec_validation` (KeyTrap cap, always enforced) |
| THREAT-033 through THREAT-047 | `[acl]` |
| THREAT-042 | `axfr_allowed` |
| THREAT-048 through THREAT-053 | `[rrl]` |
| THREAT-051 | `[forwarder]` per-client rate limiting |
| OPS-007 through OPS-008 | `[admin] socket_path` |
| OPS-021 through OPS-032 | `[admin]`, observability endpoints |
| RFC 7816 | `qname_minimisation` |
| RFC 8906 | `[rrl]` |
| RFC 9250 | `listen_doq` |
| ADR-0007 | `[forwarder] verify_cert` |
| ADR-0024 | `[acl]` compiled representation |
| ADR-0027 | `[tls]` rustls, TLS 1.3 only |
