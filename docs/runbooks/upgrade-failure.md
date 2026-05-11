# Runbook — Upgrade failure

**When to use.** A planned upgrade of Heimdall failed: `/readyz` returns
503 persistently after the new binary started, listener-bind failed, the
process is in a systemd restart loop, or Redis-schema mismatch is logged.

**Goal.** Diagnose the failure mode, get the service back to the prior
working version, and identify the root cause for a forward fix.

Cross-references: BIN-051..056, OPS-* (`012-runtime-operations.md`),
STORE-* (`013-persistence.md`), `docs/runbooks/rollback.md`,
`docs/runbooks/redis-recovery.md`.

---

## Symptoms

| Symptom | Likely cause | Section |
|---------|--------------|---------|
| `/readyz` returns 503, never reaches 200 | Listener bind failed or atomic-swap rejected | §1 |
| Process exits within seconds; systemd restart loop | Config rejected at boot, or panic at startup | §2 |
| `/readyz` is 200 but DNS responses are SERVFAIL on every query | Role dispatcher misconfigured | §3 |
| Redis returns "WRONGTYPE Operation against a key" / parse errors in logs | Redis schema mismatch (newer field encoding) | §4 |
| Bind succeeds but no traffic arrives | Firewall / port conflict | §5 |

---

## Decision tree

```
       ┌────────────────────────────────────┐
       │  systemctl status heimdall          │
       │  → check `Active:` and exit code    │
       └─────────┬──────────────────────────┘
                 │
       ┌─────────▼─────────────────────────┐
       │ Active=failed, exit code != 0?     │
       └──────┬──────────────────┬────────┘
              │ yes              │ no
              │                  │
       ┌──────▼─────┐    ┌───────▼──────────────────┐
       │  §2 boot   │    │ /readyz status?           │
       │  failure   │    └──┬──────────────────┬────┘
       └────────────┘       │ 503              │ 200
                            │                  │
                  ┌─────────▼────┐    ┌────────▼─────────┐
                  │  §1 listener  │    │ Queries succeed? │
                  │  bind failure │    └──┬──────────────┘
                  └───────────────┘       │ no
                                          │
                                  ┌───────▼──────────┐
                                  │  §3 dispatcher    │
                                  │  misconfigured    │
                                  └──────────────────┘
```

---

## §1 Listener bind failure

`/readyz` is 503 because `OPS-024` predicates require every configured
listener to be bound. Check the listener report:

```bash
journalctl -u heimdall --since "10 min ago" | grep -E "bind|listener"
```

Common causes:

- **Port already in use.** Another process (often the previous Heimdall
  binary that did not exit cleanly, or a debug `socat`) holds the port.
  Verify with `ss -tulnp | grep ':53\|:853'`.
- **Permission denied.** Linux <1024 ports require `CAP_NET_BIND_SERVICE`.
  Confirm: `getcap $(which heimdall)`.
- **TLS material missing.** DoT/DoH/DoQ listeners refuse to start without
  cert+key. Confirm the secret was mounted and is readable.
- **Bind address invalid.** `bind_addr` typo in config — atomic-swap
  rejects the new config and the binary exits.

**Mitigation:** fix the cause and restart. If the cause is unclear,
roll back to the previous version (`docs/runbooks/rollback.md`) so the
service is restored while you investigate.

---

## §2 Boot failure / systemd restart loop

The new binary fails before the listeners even open. systemd's restart
backoff escalates; if you see >3 restarts in 5 minutes, **stop the
unit** and investigate so the journal does not fill:

```bash
sudo systemctl stop heimdall
journalctl -u heimdall --since "10 min ago" --no-pager
```

Common causes:

- **Config file syntax error.** Heimdall does not start when the TOML
  parser rejects the config (OPS-001).
- **Missing required env / TOML field.** New version added a new field;
  the upgrade did not bump the config.
- **Panic at startup.** A panic on the boot path is a release-blocker
  bug. Capture the backtrace and roll back.

**Mitigation:** apply rollback. File an upgrade-failure issue against
the new release.

---

## §3 Dispatcher misconfigured / SERVFAIL on every query

`/readyz` is 200 (transports up) but every query gets SERVFAIL. The role
dispatcher is up but rejecting work. Likely causes:

- **Recursive role: trust anchor expired or DNSSEC-NTA misconfigured.**
  Check `/metrics` for `heimdall_dnssec_anchor_age_seconds`.
- **Forwarder role: upstream TLS verify failed.** Check
  `heimdall_forwarder_upstream_tls_failures_total`.
- **Auth role: zone data not loaded.** Check
  `heimdall_zone_loaded_total{zone="..."}` — should be 1 per loaded zone.

`docs/runbooks/redis-recovery.md` may apply if the data loss is upstream
of Heimdall.

---

## §4 Redis schema mismatch

The new binary wrote a Redis field that the rolled-back binary cannot
parse, or vice versa. STORE-* requires forward+backward compatibility
across one minor version, but a regression here can manifest as the
older binary refusing to start.

```bash
# Inspect the cache namespace for evidence of new fields.
redis-cli --scan --pattern "heimdall:cache:*" | head -5
redis-cli HGETALL <one-key>

# If a field is unknown to the rolled-back binary, drop the key:
redis-cli DEL <one-key>
```

For zone data, recovering by drop is unsafe. Restore from RDB/AOF per
`docs/runbooks/redis-recovery.md`.

---

## §5 Bind succeeds but no traffic

The listeners report bound and `/readyz` is 200, but no queries arrive.
Common causes:

- **Firewall**: a host-level (`nft`/`iptables`) rule blocks UDP/53 or
  TCP/853. Verify: `nft list ruleset` or `iptables -L INPUT -n -v`.
- **Service mesh**: a sidecar proxy is intercepting traffic and the new
  binary's listener address differs from the proxy's expectation.
- **Source NAT**: client retries are hitting a different instance with
  a stale ARP cache. Restart the load balancer health check.

---

## "Bisect-by-replay" diagnostic

If the cause is genuinely unclear and the failure is reproducible,
capture a packet trace from before the upgrade and replay it against
the new binary in a staging environment:

```bash
# On the failing host, capture a representative slice (PII concerns
# apply — confirm before storing).
tcpdump -i eth0 -w /tmp/inc-pcap.pcap -c 100000 udp port 53 or tcp port 53

# In staging, replay against the new binary.
sudo tcpreplay --intf1=eth0 /tmp/inc-pcap.pcap
```

Compare the new binary's output to the reference (previous version in a
parallel staging instance) using the existing golden-comparison
infrastructure (`crates/heimdall-integration-tests/src/golden_*`).

---

## Mitigation summary

| Symptom | First action | Fallback |
|---------|--------------|----------|
| Bind failure | Free the port; restart | Roll back |
| Boot loop | Stop unit; capture journal | Roll back |
| SERVFAIL on every query | Inspect role-specific health | Roll back; file bug |
| Redis schema mismatch | Drop affected cache keys | `redis-recovery.md` |
| No traffic | Inspect firewall / mesh | Roll back if unrelated |

---

## After resolution

1. If a rollback was performed, follow `rollback.md` "After the rollback".
2. Open a release-blocker bug in the issue tracker for the regression.
3. Add a regression test to `heimdall-integration-tests` covering the
   failure path so the next forward release cannot reintroduce it.
4. Update this runbook if a new symptom or root cause was discovered.
