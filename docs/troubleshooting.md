# Heimdall Troubleshooting Guide

This guide is organised by symptom. Each section describes the diagnosis
commands to run, the likely root causes, and the steps to remediate.

**See also**

- [Operator Manual](operator-manual.md) — lifecycle and reload procedures.
- [Configuration Reference](configuration-reference.md) — every TOML option.
- [Admin-RPC Guide](admin-guide.md) — runtime diagnostic commands.

---

## 1. High SERVFAIL rate

### Symptoms

`heimdall_queries_total{rcode="SERVFAIL"}` is elevated. Clients report
resolution failures for names that should be resolvable.

### Diagnosis

```sh
# Check the SERVFAIL counter in Prometheus metrics
curl -s http://127.0.0.1:8080/metrics | grep heimdall_queries_total

# Check for upstream errors
curl -s http://127.0.0.1:8080/metrics | grep heimdall_upstream_errors_total

# Check for DNSSEC validation failures (bogus outcomes)
curl -s http://127.0.0.1:8080/metrics | grep heimdall_bogus_total

# Inspect structured logs for SERVFAIL details
journalctl -u heimdall -n 200 --output cat | grep '"rcode":"SERVFAIL"'

# Run a trace query via admin-RPC
echo '{"cmd":"trace_query","qname":"failing.example.com.","qtype":"A"}' \
    | nc -U /run/heimdall/admin.sock
```

### Root causes and remediation

**Upstream connectivity failure (forwarder role)**

Verify that configured upstreams are reachable:

```sh
# Test DoT connectivity
openssl s_client -connect 9.9.9.9:853 -servername dns.quad9.net </dev/null

# Test UDP/TCP
dig @9.9.9.9 example.com A +timeout=5
```

Check `[forwarder] upstream` addresses in the configuration. Verify firewall
rules permit outbound connections on the relevant port.

**DNSSEC validation failure**

If `heimdall_bogus_total` is non-zero for names that are legitimately signed,
check the trust anchors:

```sh
echo '{"cmd":"nta_list"}' | nc -U /run/heimdall/admin.sock
```

A stale or missing root trust anchor causes all signed zones to return
`SERVFAIL`. Verify the trust anchor file (`/var/lib/heimdall/trust-anchors.xml`
by default). If the trust anchor is corrupt, remove it and restart Heimdall to
re-bootstrap from the compiled-in anchor.

**RPZ policy action**

If an RPZ zone policy is set to `NXDOMAIN` or `DROP`, affected names will not
resolve. List active RPZ entries:

```sh
echo '{"cmd":"rpz_list"}' | nc -U /run/heimdall/admin.sock
```

Remove or modify the relevant policy entry if it is blocking legitimate names.

**Recursive resolver delegation loop**

A misconfigured zone can cause infinite delegation. The trace command shows
the delegation chain:

```sh
echo '{"cmd":"trace_query","qname":"loop.example.","qtype":"A"}' \
    | nc -U /run/heimdall/admin.sock
```

Heimdall caps the delegation depth and returns `SERVFAIL` when the cap is
exceeded. Report the affected zone to its operator.

---

## 2. High BOGUS DNSSEC rate

### Symptoms

`heimdall_bogus_total` is elevated. `dig` returns `SERVFAIL` with extended
error code 6 (`DNSSEC Bogus`).

### Diagnosis

```sh
# Check bogus counter by zone
curl -s http://127.0.0.1:8080/metrics | grep heimdall_bogus_total

# Inspect logs for specific bogus reasons
journalctl -u heimdall -n 500 --output cat | grep '"dnssec":"bogus"'

# Trace a specific failing name
echo '{"cmd":"trace_query","qname":"bogus.example.com.","qtype":"A"}' \
    | nc -U /run/heimdall/admin.sock

# Check NTA list
echo '{"cmd":"nta_list"}' | nc -U /run/heimdall/admin.sock
```

### Root causes and remediation

**Stale trust anchor**

If the KSK roll-over for the root zone is in progress and the local trust
anchor has not been updated via RFC 5011 automated key roll-over, valid
signatures will appear bogus. Check the trust anchor age:

```sh
ls -la /var/lib/heimdall/trust-anchors.xml
```

If the file has not been updated in more than 30 days, Heimdall's RFC 5011
implementation may be failing to reach the root zone. Check upstream
connectivity for the recursive resolver.

**Negative Trust Anchor (NTA) required**

If a zone has broken DNSSEC (expired signatures, missing records) but the zone
operator has not repaired it, temporarily register an NTA to allow resolution
to continue:

```sh
echo '{"cmd":"nta_add","zone":"broken.example.com.","ttl":86400}' \
    | nc -U /run/heimdall/admin.sock
```

Revoke the NTA once the zone operator fixes the issue (DNSSEC-017).

**Clock skew**

DNSSEC signatures have validity windows. If the system clock is skewed by more
than the signature's validity window, valid signatures appear expired:

```sh
timedatectl status
ntpq -p
```

Ensure the system clock is synchronised via NTP or PTP. The recommended
tolerance is less than 5 minutes of skew for robust DNSSEC validation.

---

## 3. 0x20 case randomisation mismatches

### Symptoms

Logs show `"0x20_mismatch"` entries. Upstream queries fail to match responses.
The recursive resolver returns `SERVFAIL` for certain names.

### Diagnosis

```sh
# Find 0x20 mismatch log entries
journalctl -u heimdall -n 500 --output cat | grep '0x20'

# Trace the problematic query
echo '{"cmd":"trace_query","qname":"problem.example.com.","qtype":"A"}' \
    | nc -U /run/heimdall/admin.sock
```

### Root causes and remediation

**Non-compliant upstream authoritative server**

Some older or non-compliant authoritative servers do not preserve the case
randomisation applied by Heimdall (PROTO-025 through PROTO-031). When the
upstream returns a response with a different case, Heimdall discards it as a
potential cache-poisoning attempt and retries.

If mismatches occur consistently for a specific zone, check the authoritative
server software version. If the authoritative server cannot be upgraded, the
zone's 0x20 enforcement can be observed via logs. Heimdall retries with a new
random case on mismatch; repeated failures escalate to `SERVFAIL`.

**Resolver sitting behind a non-case-preserving middle box**

If Heimdall's upstream path passes through a load balancer or DNS proxy that
normalises case, 0x20 mismatches will be systematic. Diagnose by querying the
upstream directly:

```sh
dig @<upstream-ip> ExAmPlE.CoM A
```

If the response normalises case, the middle box is the problem. Remove it from
the path or configure Heimdall to forward directly to the authoritative server.

---

## 4. TLS handshake failures

### Symptoms

DoT/DoH/DoQ clients report TLS errors. `heimdall_tls_handshakes_total{outcome="error"}`
is elevated. Connections are refused or time out at the TLS layer.

### Diagnosis

```sh
# Check TLS handshake metrics
curl -s http://127.0.0.1:8080/metrics | grep heimdall_tls_handshakes_total

# Test TLS from the client side
openssl s_client -connect <server>:853 -servername <hostname> </dev/null

# Check certificate expiry
openssl x509 -enddate -noout -in /etc/heimdall/tls/cert.pem

# Check logs for TLS error details
journalctl -u heimdall -n 200 --output cat | grep '"transport":"dot"' | grep '"error"'
```

### Root causes and remediation

**Certificate expiry**

If the certificate is expired, clients will refuse the connection. Renew the
certificate and reload:

```sh
systemctl reload heimdall
```

Heimdall re-reads the certificate and private key on SIGHUP without
restarting or dropping existing connections (OPS-001 through OPS-004).

**SPKI pin mismatch**

If clients pin the server's SPKI (Subject Public Key Info) and the certificate
has been renewed with a new key, pinned clients will reject the new certificate.
Coordinate SPKI pin rotation with client operators before certificate renewal.
Maintain a pre-published backup SPKI pin to enable zero-downtime rotation.

**TLS 1.2 rejected by client**

Heimdall enforces TLS 1.3 only (SEC-001 through SEC-004). Clients that do not
support TLS 1.3 cannot connect. The correct remediation is to upgrade the
client. Downgrading to TLS 1.2 is not supported and would violate the
cryptographic policy.

Check client TLS version support:

```sh
openssl s_client -connect <server>:853 -tls1_2 2>&1 | grep "Protocol"
```

If the client is negotiating TLS 1.2, upgrade it to a version that supports
TLS 1.3.

---

## 5. Cache memory pressure

### Symptoms

RSS memory is growing. `heimdall_cache_size_bytes` exceeds `cache_size`. Cache
hit rate is falling (`heimdall_cache_hits_total` ratio decreasing).

### Diagnosis

```sh
# Check cache size metrics
curl -s http://127.0.0.1:8080/metrics | grep heimdall_cache

# Check cache stats via admin-RPC
echo '{"cmd":"cache_stats"}' | nc -U /run/heimdall/admin.sock

# Check memory usage of the Heimdall process
ps -p $(pgrep heimdall) -o rss,vsz
```

### Root causes and remediation

**Cache size too small for the working set**

Increase `cache_size` in `[recursive]` or `[forwarder]` and reload:

```toml
[recursive]
cache_size = 536870912  # 512 MiB
```

```sh
systemctl reload heimdall
```

The cache respects the configured budget; entries are evicted when the budget
is reached. If the working set exceeds available RAM, consider deploying
multiple Heimdall instances with distinct zone sets.

**Random-subdomain (NXDOMAIN flood) attack**

A flood of queries for non-existent sub-domains can fill the cache with
negative responses. Check the NXDOMAIN rate:

```sh
curl -s http://127.0.0.1:8080/metrics | grep 'rcode="NXDOMAIN"'
```

If the rate is abnormally high, tighten the ACL (`[acl] allow`) to restrict
the source prefixes, or reduce the RRL limit to shed load:

```sh
echo '{"cmd":"rate_limit_tune","limit":50}' | nc -U /run/heimdall/admin.sock
```

---

## 6. Upstream timeouts

### Symptoms

`heimdall_upstream_errors_total{error="timeout"}` is elevated. Queries take
abnormally long before returning `SERVFAIL`.

### Diagnosis

```sh
# Check upstream error metrics
curl -s http://127.0.0.1:8080/metrics | grep heimdall_upstream_errors_total

# Check connection stats
echo '{"cmd":"connection_stats"}' | nc -U /run/heimdall/admin.sock

# Test connectivity to each upstream
for upstream in 9.9.9.9 149.112.112.112; do
    echo -n "$upstream: "
    timeout 5 dig @$upstream example.com A +time=3 +tries=1 | grep "Query time"
done
```

### Root causes and remediation

**Upstream is unreachable**

Verify network connectivity from the Heimdall host to each configured upstream:

```sh
traceroute 9.9.9.9
```

If the upstream is genuinely unreachable, remove it from `[forwarder] upstream`
and reload, or wait for the network path to recover.

**Fallback not configured**

If only one upstream is configured and it times out, all queries fail. Add a
secondary upstream:

```toml
[forwarder]
upstream = ["9.9.9.9:853", "149.112.112.112:853"]
```

Heimdall's circuit breaker tracks upstream health and avoids sending queries
to an upstream that is consistently failing (ADR-0012, ADR-0013).

**Firewall blocking outbound connections**

If the transport is `"dot"`, `"doh"`, or `"doq"`, verify that outbound
connections on port 853 (DoT/DoQ) or 443 (DoH) are not blocked by a host
firewall or network ACL.

---

## 7. Port 853 not listening (DoT or DoQ)

### Symptoms

`listen_dot` or `listen_doq` is configured but no socket appears on port 853.
Clients cannot connect.

### Diagnosis

```sh
# Check if the port is bound
ss -tlnp | grep 853
ss -ulnp | grep 853

# Check Heimdall startup logs
journalctl -u heimdall -n 50

# Check readiness
curl http://127.0.0.1:8080/readyz
```

### Root causes and remediation

**`CAP_NET_BIND_SERVICE` missing**

Port 853 is a privileged port. On Linux, `CAP_NET_BIND_SERVICE` is required.
Check the effective capabilities of the running process:

```sh
cat /proc/$(pgrep heimdall)/status | grep Cap
capsh --decode=$(cat /proc/$(pgrep heimdall)/status | grep CapEff | awk '{print $2}')
```

If `CAP_NET_BIND_SERVICE` is absent, verify that the systemd unit includes:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Reload the systemd unit and restart Heimdall.

**Host firewall blocking the port**

```sh
# Check iptables / nftables rules
iptables -L INPUT -n | grep 853
nft list ruleset | grep 853
```

Add an allow rule for inbound TCP/UDP 853.

**TLS configuration missing**

`listen_dot` and `listen_doq` require `[tls] certificate` and
`[tls] private_key`. If they are absent, Heimdall will refuse to start with
a configuration error. Check the startup log for the specific error.

---

## 8. Admin-RPC not responding

### Symptoms

`nc -U /run/heimdall/admin.sock` fails with "No such file or directory" or
"Connection refused".

### Diagnosis

```sh
# Check if the socket file exists
ls -la /run/heimdall/

# Check socket file permissions
stat /run/heimdall/admin.sock

# Check if Heimdall is running
systemctl status heimdall

# Check Heimdall startup logs
journalctl -u heimdall -n 30
```

### Root causes and remediation

**Wrong socket path**

The default path is `/run/heimdall/admin.sock`. If `[admin] socket_path` is
set to a different value, use that path:

```sh
echo '{"cmd":"version"}' | nc -U /run/heimdall/admin.sock
```

**Permission denied**

The socket is created with mode `0600` owned by the Heimdall process user
(`heimdall` on Linux, `_heimdall` on OpenBSD). Connecting as a different user
without sufficient privilege will be refused:

```sh
sudo -u heimdall nc -U /run/heimdall/admin.sock <<< '{"cmd":"version"}'
```

Alternatively, run the admin command as root.

**Socket directory missing**

If `/run/heimdall/` does not exist, Heimdall cannot create the socket. On
systemd deployments, `RuntimeDirectory=heimdall` in the unit creates this
directory automatically. On other deployments:

```sh
mkdir -p /run/heimdall
chown heimdall:heimdall /run/heimdall
chmod 0750 /run/heimdall
systemctl start heimdall
```

---

## 9. High CPU usage

### Symptoms

`top` or `htop` shows Heimdall consuming unexpectedly high CPU. Response
latency degrades.

### Diagnosis

```sh
# Check query rate
curl -s http://127.0.0.1:8080/metrics | grep heimdall_queries_total | tail -5

# Check RRL drop/slip counters
curl -s http://127.0.0.1:8080/metrics | grep heimdall_rrl

# Check for excessive DNSSEC validation work
curl -s http://127.0.0.1:8080/metrics | grep heimdall_bogus_total

# Profile using perf (Linux) or instruments (macOS)
perf top -p $(pgrep heimdall)
```

### Root causes and remediation

**Query amplification attack**

A reflection/amplification attack directs a large volume of spoofed queries
at Heimdall. Check the source-IP distribution in the ACL:

```sh
# Review ACL statistics (if available via admin-RPC)
echo '{"cmd":"diag"}' | nc -U /run/heimdall/admin.sock
```

Narrow the ACL `allow` list to known client prefixes, or increase the RRL
aggressiveness:

```sh
echo '{"cmd":"rate_limit_tune","limit":20,"window":15}' \
    | nc -U /run/heimdall/admin.sock
```

**RRL thresholds too permissive**

If RRL is configured but `limit` is too high, a flood of responses is still
served before RRL kicks in. Lower the `limit` and `window` values in `[rrl]`:

```toml
[rrl]
window = 10
limit  = 50
slip   = 2
```

Reload the configuration:

```sh
systemctl reload heimdall
```

**KeyTrap-style DNSSEC DoS**

A zone with a pathologically large number of DNSKEY or RRSIG records can cause
high CPU in the DNSSEC validation path. Heimdall enforces the KeyTrap cap
(DNSSEC-028) to bound this work. If CPU is high and `heimdall_bogus_total` is
also elevated for a specific zone, the zone operator may be testing limits.
Register an NTA for the offending zone as a temporary measure:

```sh
echo '{"cmd":"nta_add","zone":"attacker.example.","ttl":3600}' \
    | nc -U /run/heimdall/admin.sock
```

**Cache thrashing**

If `cache_size` is too small for the working set, every query incurs an
upstream lookup. Increase `cache_size` and reload (see section 5).
