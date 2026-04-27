# Heimdall Admin-RPC Guide

The admin-RPC surface exposes granular runtime control of a running Heimdall
instance. It is distinct from the SIGHUP full-reload mechanism and is usable
independently of it (OPS-007).

**See also**

- [Operator Manual](operator-manual.md) — lifecycle overview.
- [Configuration Reference](configuration-reference.md) — `[admin]` options.
- [Troubleshooting Guide](troubleshooting.md) — diagnostic workflows.

---

## Protocol

The admin-RPC protocol is JSON over a Unix Domain Socket (UDS).

- **Default socket path**: `/run/heimdall/admin.sock`
- **Socket mode**: `0600`, owned by the Heimdall process user
- **Authentication**: filesystem permissions on the UDS (OPS-008)
- **Transport**: connection-oriented byte stream; each JSON object is
  delimited by a newline character (`\n`)
- **Request format**: `{"cmd":"<command>"[, <parameters>]}\n`
- **Response format**: `{"ok":true[, <result>]}\n` or
  `{"ok":false,"error":"<message>"}\n`

Every admin-RPC operation emits a structured audit event consistent with
THREAT-080 in `specification/007-threat-model.md`.

### Example interaction pattern

```sh
# One-shot command via netcat
echo '{"cmd":"version"}' | nc -U /run/heimdall/admin.sock

# Interactive session
nc -U /run/heimdall/admin.sock
{"cmd":"cache_stats"}
{"cmd":"nta_list"}
^C
```

---

## Commands

### `version`

Returns build and runtime metadata.

**Synopsis**:

```sh
echo '{"cmd":"version"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "version"}
```

**Response schema**:

```json
{
  "ok": true,
  "version": "<semver>",
  "commit": "<git-sha>",
  "build_timestamp": "<ISO-8601>",
  "msrv": "<rust-version>",
  "transports": ["udp", "tcp", "dot", "doh", "doq"],
  "roles": ["recursive", "authoritative", "forwarder"]
}
```

**Example**:

```sh
$ echo '{"cmd":"version"}' | nc -U /run/heimdall/admin.sock
{"ok":true,"version":"0.1.0","commit":"abc1234","build_timestamp":"2026-04-27T00:00:00Z","msrv":"1.87.0","transports":["udp","tcp","dot"],"roles":["recursive"]}
```

**Audit event**: `admin.version` (read-only, no state change).

**Idempotency**: always safe to repeat.

---

### `stats`

Returns runtime statistics covering queries, cache, and connections.

**Synopsis**:

```sh
echo '{"cmd":"stats"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "stats"}
```

**Response schema**:

```json
{
  "ok": true,
  "queries_total": <integer>,
  "queries_per_second": <float>,
  "cache_hits": <integer>,
  "cache_misses": <integer>,
  "cache_size_bytes": <integer>,
  "bogus_total": <integer>,
  "rrl_slipped": <integer>,
  "rrl_dropped": <integer>,
  "active_connections": <integer>
}
```

**Audit event**: `admin.stats` (read-only).

**Idempotency**: always safe to repeat.

---

### `cache_stats`

Returns detailed cache statistics, equivalent to `OPS-015` `CacheStats`.

**Synopsis**:

```sh
echo '{"cmd":"cache_stats"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "cache_stats"}
```

**Response schema**:

```json
{
  "ok": true,
  "recursive": {
    "size_bytes": <integer>,
    "capacity_bytes": <integer>,
    "hits": <integer>,
    "misses": <integer>,
    "evictions": <integer>
  },
  "forwarder": {
    "size_bytes": <integer>,
    "capacity_bytes": <integer>,
    "hits": <integer>,
    "misses": <integer>,
    "evictions": <integer>
  }
}
```

**Audit event**: `admin.cache_stats` (read-only).

**Idempotency**: always safe to repeat.

---

### `connection_stats`

Returns per-transport active connection counts, equivalent to `OPS-015`
`ConnectionStats`.

**Synopsis**:

```sh
echo '{"cmd":"connection_stats"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "connection_stats"}
```

**Response schema**:

```json
{
  "ok": true,
  "connections": {
    "udp": <integer>,
    "tcp": <integer>,
    "dot": <integer>,
    "doh2": <integer>,
    "doh3": <integer>,
    "doq": <integer>
  }
}
```

**Audit event**: `admin.connection_stats` (read-only).

**Idempotency**: always safe to repeat.

---

### `trace_query`

Traces a single query through the resolution pipeline and returns a
step-by-step diagnostic log. Equivalent to `OPS-015` `TraceQuery`.

**Synopsis**:

```sh
echo '{"cmd":"trace_query","qname":"example.com.","qtype":"A"}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "trace_query",
  "qname": "<fully-qualified domain name>",
  "qtype": "<record type string, e.g. A, AAAA, MX>"
}
```

**Response schema**:

```json
{
  "ok": true,
  "steps": [
    {"step": "acl", "outcome": "allow", "client": "127.0.0.1"},
    {"step": "cache", "outcome": "miss"},
    {"step": "recursive", "delegation": "com.", "ns": "a.gtld-servers.net."},
    {"step": "answer", "rcode": "NOERROR", "rdata": ["93.184.216.34"]}
  ],
  "duration_us": <integer>
}
```

**Audit event**: `admin.trace_query`.

**Idempotency**: always safe to repeat; does not affect cache state.

---

### `zone_add`

Adds a zone to the running authoritative server, equivalent to `OPS-010`
`ZoneAdd`.

**Synopsis**:

```sh
echo '{"cmd":"zone_add","origin":"example.com.","file":"/var/lib/heimdall/zones/example.com.zone"}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "zone_add",
  "origin": "<zone apex FQDN>",
  "file": "<absolute path to zone file>"
}
```

**Response schema**:

```json
{"ok": true, "serial": <SOA serial integer>}
```

If the zone already exists, the command returns an error. Use `zone_reload` to
update an existing zone.

**Audit event**: `admin.zone_add` with `origin` and `file`.

**Idempotency**: not idempotent if the zone already exists.

---

### `zone_reload`

Reloads a single zone from disk without touching other zones or the
configuration, equivalent to `OPS-010` `ZoneReload`.

**Synopsis**:

```sh
echo '{"cmd":"zone_reload","origin":"example.com."}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "zone_reload",
  "origin": "<zone apex FQDN>"
}
```

**Response schema**:

```json
{"ok": true, "serial": <new SOA serial integer>}
```

**Audit event**: `admin.zone_reload` with `origin` and `old_serial`/`new_serial`.

**Idempotency**: safe to repeat; multiple reloads of the same file produce the
same state (assuming the file on disk has not changed between calls).

---

### `zone_remove`

Removes a zone from the running authoritative server, equivalent to `OPS-010`
`ZoneRemove`.

**Synopsis**:

```sh
echo '{"cmd":"zone_remove","origin":"example.com."}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "zone_remove",
  "origin": "<zone apex FQDN>"
}
```

**Response schema**:

```json
{"ok": true}
```

If the zone does not exist, the command returns an error.

**Audit event**: `admin.zone_remove` with `origin`.

**Idempotency**: not idempotent if the zone has already been removed.

---

### `nta_add`

Registers a Negative Trust Anchor (NTA) for a zone, suspending DNSSEC
validation for it. Equivalent to `OPS-011` `NtaAdd` and DNSSEC-017.

Use NTAs as a temporary measure when a zone has broken DNSSEC and the operator
cannot immediately fix it.

**Synopsis**:

```sh
echo '{"cmd":"nta_add","zone":"broken.example.com.","ttl":86400}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "nta_add",
  "zone": "<zone FQDN>",
  "ttl": <integer, seconds>
}
```

**Response schema**:

```json
{"ok": true, "expires_at": "<ISO-8601 timestamp>"}
```

The NTA expires automatically after `ttl` seconds. Revoke it explicitly if the
zone is fixed sooner.

**Audit event**: `admin.nta_add` with `zone`, `ttl`, and `expires_at`.

**Idempotency**: replacing an existing NTA with a new TTL is idempotent in
effect (the NTA is active either way), but the TTL is updated.

---

### `nta_revoke`

Revokes a Negative Trust Anchor, restoring DNSSEC validation for the zone.
Equivalent to `OPS-011` `NtaRevoke`.

**Synopsis**:

```sh
echo '{"cmd":"nta_revoke","zone":"broken.example.com."}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "nta_revoke",
  "zone": "<zone FQDN>"
}
```

**Response schema**:

```json
{"ok": true}
```

**Audit event**: `admin.nta_revoke` with `zone`.

**Idempotency**: revoking a non-existent NTA returns an error.

---

### `nta_list`

Lists all currently registered Negative Trust Anchors. Equivalent to
`OPS-011` `NtaList`.

**Synopsis**:

```sh
echo '{"cmd":"nta_list"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "nta_list"}
```

**Response schema**:

```json
{
  "ok": true,
  "ntas": [
    {"zone": "broken.example.com.", "expires_at": "<ISO-8601>"},
    {"zone": "other.example.", "expires_at": "<ISO-8601>"}
  ]
}
```

**Audit event**: `admin.nta_list` (read-only).

**Idempotency**: always safe to repeat.

---

### `tek_rotate`

Rotates the TLS ticket-encryption key (TEK) immediately. Existing TLS sessions
are not affected; future session-ticket issuance uses the new key. Equivalent
to `OPS-012` `TekRotate` and SEC-008 through SEC-011.

**Synopsis**:

```sh
echo '{"cmd":"tek_rotate"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "tek_rotate"}
```

**Response schema**:

```json
{"ok": true, "rotated_at": "<ISO-8601>"}
```

**Audit event**: `admin.tek_rotate`.

**Idempotency**: safe to repeat; each call rotates to a new key.

---

### `new_token_key_rotate`

Rotates the QUIC `NEW_TOKEN` anti-replay key. Existing QUIC connections are
not affected; future `NEW_TOKEN` issuance uses the new key. Equivalent to
`OPS-012` `NewTokenKeyRotate` and SEC-028 through SEC-030.

**Synopsis**:

```sh
echo '{"cmd":"new_token_key_rotate"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "new_token_key_rotate"}
```

**Response schema**:

```json
{"ok": true, "rotated_at": "<ISO-8601>"}
```

**Audit event**: `admin.new_token_key_rotate`.

**Idempotency**: safe to repeat; each call rotates to a new key.

---

### `rate_limit_tune`

Adjusts rate-limit parameters at runtime within the bounds configured in
`[rrl]`. Equivalent to `OPS-013` `RateLimitTune`.

**Synopsis**:

```sh
echo '{"cmd":"rate_limit_tune","limit":50,"window":15,"slip":2}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "rate_limit_tune",
  "limit": <integer, optional>,
  "window": <integer seconds, optional>,
  "slip": <integer, optional>
}
```

All parameters are optional; omitted parameters retain their current value.

**Response schema**:

```json
{
  "ok": true,
  "limit": <new limit>,
  "window": <new window>,
  "slip": <new slip>
}
```

**Audit event**: `admin.rate_limit_tune` with old and new values.

**Idempotency**: applying the same values twice produces the same state.

---

### `drain`

Initiates a controlled drain: stops accepting new connections and waits for
in-flight work to complete before exiting cleanly. Equivalent to `OPS-014`
`Drain`.

**Synopsis**:

```sh
echo '{"cmd":"drain","timeout_secs":30}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "drain",
  "timeout_secs": <integer, optional, default 30>
}
```

**Response schema**:

```json
{"ok": true, "drained_at": "<ISO-8601>"}
```

The response is returned immediately. The process exits after draining or after
`timeout_secs`, whichever comes first.

**Audit event**: `admin.drain` with `timeout_secs`.

**Idempotency**: calling drain on an already-draining instance is a no-op.

---

### `diag`

Returns free-form diagnostic state about the running instance.

**Synopsis**:

```sh
echo '{"cmd":"diag"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "diag"}
```

**Response schema**:

```json
{
  "ok": true,
  "uptime_secs": <integer>,
  "config_path": "<string>",
  "last_reload": "<ISO-8601 or null>",
  "roles_active": ["<role>", ...],
  "listeners": [
    {"transport": "<string>", "address": "<addr:port>", "connections": <integer>}
  ]
}
```

**Audit event**: `admin.diag` (read-only).

**Idempotency**: always safe to repeat.

---

### `rpz_upsert`

Adds or updates a single Response Policy Zone (RPZ) entry at runtime.
Equivalent to `OPS-015` `RpzEntryAdd` and RPZ-016 through RPZ-020.

**Synopsis**:

```sh
echo '{"cmd":"rpz_upsert","zone":"rpz.example.","trigger":"QNAME","name":"malware.example.com.","action":"NXDOMAIN"}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "rpz_upsert",
  "zone": "<RPZ zone FQDN>",
  "trigger": "<QNAME | CLIENTIP | NSDNAME>",
  "name": "<trigger value>",
  "action": "<NXDOMAIN | NODATA | DROP | PASSTHRU | LOCAL>"
}
```

**Response schema**:

```json
{"ok": true}
```

**Audit event**: `admin.rpz_upsert` with `zone`, `trigger`, `name`, and `action`.

**Idempotency**: upserting the same entry with the same action is a no-op.

---

### `rpz_remove`

Removes a single RPZ entry. Equivalent to `OPS-015` `RpzEntryRemove`.

**Synopsis**:

```sh
echo '{"cmd":"rpz_remove","zone":"rpz.example.","trigger":"QNAME","name":"malware.example.com."}' \
    | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{
  "cmd": "rpz_remove",
  "zone": "<RPZ zone FQDN>",
  "trigger": "<QNAME | CLIENTIP | NSDNAME>",
  "name": "<trigger value>"
}
```

**Response schema**:

```json
{"ok": true}
```

**Audit event**: `admin.rpz_remove` with `zone`, `trigger`, and `name`.

**Idempotency**: removing a non-existent entry returns an error.

---

### `reload`

Triggers the same atomic configuration reload as SIGHUP. Provided for
environments where sending a signal is inconvenient.

**Synopsis**:

```sh
echo '{"cmd":"reload"}' | nc -U /run/heimdall/admin.sock
```

**Request schema**:

```json
{"cmd": "reload"}
```

**Response schema**:

```json
{"ok": true, "outcome": "applied"} // or "rejected" with "error"
```

**Audit event**: `admin.reload` with `outcome`.

**Idempotency**: safe to repeat; an already-applied configuration is a no-op.

---

## Error responses

All commands return a JSON error response on failure:

```json
{
  "ok": false,
  "error": "<human-readable error message>",
  "code": "<machine-readable error code>"
}
```

Common error codes:

| Code | Meaning |
|------|---------|
| `not_found` | The requested resource (zone, NTA, RPZ entry) does not exist |
| `already_exists` | The resource already exists (for non-idempotent creates) |
| `invalid_argument` | A required parameter is missing or has an invalid value |
| `parse_error` | The configuration or zone file failed to parse |
| `internal` | An unexpected internal error; check the structured log for details |
