# Runbook — Redis backend recovery

**When to use.** Heimdall's Redis backend (the sole runtime persistence
layer per STORE-001 in `013-persistence.md`) is impaired: connection
loss, leader failover that did not converge, partial data loss after a
crash, or corruption suspected. Heimdall continues serving from
in-process state per STORE-017, but new writes (zone reloads, dynamic
RPZ, cache replacement) cannot land.

**Goal.** Restore Redis availability, recover any lost data from RDB/AOF,
and reconnect Heimdall without restarting the process.

Cross-references: STORE-001..050, OPS-001..018,
`docs/runbooks/incident-response.md`,
`docs/runbooks/upgrade-failure.md`.

---

## RTO / RPO targets

| Class | RTO | RPO |
|-------|-----|-----|
| Standalone Redis with AOF (default) | 5 minutes | < 1 second |
| Redis Sentinel (HA) | 1 minute (STORE-041) | < 1 second |
| Redis Cluster | 30 seconds | < 1 second |

If the operator runs Redis with `appendonly no` and no RDB snapshot
schedule, the RPO is unbounded. STORE-003 explicitly accepts that
operator choice; this runbook documents the recovery cost.

---

## Decision tree

```
                   ┌────────────────────────────┐
                   │  Heimdall logs structured   │
                   │  Redis errors (STORE-017)   │
                   └─────────────┬──────────────┘
                                 │
                  ┌──────────────▼─────────────────┐
                  │  Can `redis-cli PING` reach    │
                  │  the leader?                    │
                  └──┬───────────────┬─────────────┘
                     │ no            │ yes
                     │               │
            ┌────────▼────────┐  ┌───▼───────────────────┐
            │  §1 Reachability │  │  Is the leader read-  │
            │  failure         │  │  only / split-brain?  │
            └─────────────────┘  └─────┬───────────┬─────┘
                                       │ yes       │ no
                                       │           │
                              ┌────────▼────┐ ┌────▼────────┐
                              │  §2 Split-   │ │  §3 Data     │
                              │  brain       │ │  loss after  │
                              │              │ │  failover    │
                              └─────────────┘ └─────────────┘
```

---

## §1 Reachability failure

`redis-cli PING` returns "Could not connect" or times out.

```bash
# Standalone
redis-cli -s /var/run/redis/heimdall.sock PING
redis-cli -h 127.0.0.1 -p 6379 PING

# Sentinel — discover the current leader
redis-cli -h <sentinel-host> -p 26379 \
  SENTINEL get-master-addr-by-name heimdall
```

**Mitigation:**

1. Verify the unit is running: `systemctl status redis-server`.
2. Inspect the journal for OOM or I/O errors:
   `journalctl -u redis-server --since "10 min ago"`.
3. If the disk is full (Redis writes RDB+AOF), free disk space; AOF
   replay on next start may need 2× the working set in disk space.
4. If the unit is wedged, restart with `systemctl restart redis-server`.
   Heimdall's auto-reconnect (STORE-016) picks up the link without a
   Heimdall restart.

If Redis is irrecoverable, fail over to Sentinel/Cluster (§3) or restore
from a snapshot (§4).

---

## §2 Split-brain detection

A split-brain in a Sentinel/Cluster deployment exists when more than
one node believes itself to be leader. Heimdall connects to one of them
and writes diverge.

```bash
# Sentinel: count distinct leaders advertised
for s in $SENTINELS; do
  redis-cli -h "$s" -p 26379 \
    SENTINEL get-master-addr-by-name heimdall
done | sort -u
```

If more than one address is returned, you have a split-brain.

```bash
# Cluster: each node should see the same `cluster known-nodes`.
for n in $CLUSTER_NODES; do
  redis-cli -h "$n" CLUSTER INFO | grep cluster_known_nodes
done
```

Mitigation:

1. **Identify the authoritative half** — the half with quorum (most
   nodes alive). The other half MUST be drained.
2. **Stop the minority writers**: bring those Heimdall instances out of
   the load balancer first, then stop their backing Redis nodes.
3. **Snapshot every minority leader's data** before destroying it; you
   may need to merge the divergent keys later.
4. **Force the majority half to take over**:

   ```bash
   redis-cli -h <majority-leader> CLUSTER FAILOVER FORCE
   # or with Sentinel:
   redis-cli -h <sentinel> -p 26379 SENTINEL failover heimdall
   ```

5. **Reconcile divergent keys** by hand. Authoritative-zone Hashes
   (`heimdall:zone:auth:*`, STORE-018..023) are the highest priority —
   the latest serial in each zone wins; tie-break by RDB last-modified
   timestamp.
6. **Drop divergent cache keys** (`heimdall:cache:*`); they will refill.

---

## §3 Data loss after failover

A Sentinel failover ran but the new leader is missing recent writes
(possible when AOF fsync was `everysec` and the prior leader lost the
last second of writes on crash).

Detect by comparing the SOA serial of an authoritative zone in Redis
against the on-disk zone file:

```bash
# Read the SOA from Redis (encoding per STORE-021).
redis-cli HGET heimdall:zone:auth:example.com. "@:SOA:IN"

# Read the SOA from the zone file source of truth.
grep -E '\bSOA\b' /etc/heimdall/zones/example.com.zone | head -1
```

If Redis is behind the file, trigger a SIGHUP — STORE-004 specifies
that a SIGHUP re-parses the zone files and writes the result to Redis
atomically, so the missing serial is recovered:

```bash
sudo systemctl kill -s HUP heimdall
```

Verify the OPS-018 atomic-swap report in `/metrics`:

```
heimdall_reload_zones_swapped_total ↑
heimdall_reload_last_status="success"
```

For cache and RPZ, the recovery story is simpler: cache will refill
naturally; RPZ will be re-loaded on SIGHUP from the zone-file source
(STORE-036).

---

## §4 Restore from RDB / AOF

When the live Redis is destroyed (datacentre loss, deletion accident),
restore from the most recent backup:

```bash
sudo systemctl stop redis-server

# RDB restore
sudo cp /var/lib/redis/snapshots/dump-2026-05-09.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb

# AOF restore (if AOF was enabled)
sudo cp /var/lib/redis/snapshots/appendonly-2026-05-09.aof \
        /var/lib/redis/appendonly.aof

sudo systemctl start redis-server

# Wait for Redis to finish loading.
redis-cli INFO persistence | grep loading
# loading:0 means done

# Verify Heimdall reconnected (STORE-016) and queries flow.
curl -s http://127.0.0.1:8080/readyz
dig @127.0.0.1 example.com. A +short
```

After the data has loaded, **reload all zones** with SIGHUP. The zone
files on disk are the canonical source (STORE-004); SIGHUP forces Redis
to reflect them, which closes the gap between snapshot time and now.

---

## §5 Drain-and-rebuild from authoritative-zone files

If recovery from a snapshot is impossible (no usable backup), Heimdall
can reconstruct authoritative zone data from the on-disk zone files.
The authoritative role only — recursive/forwarder caches and dynamic
RPZ updates ARE LOST.

```bash
# 1. Empty Redis except the heimdall ACL user metadata.
redis-cli --scan --pattern "heimdall:*" | xargs -r redis-cli DEL

# 2. SIGHUP — Heimdall re-parses every zone file and re-writes Redis.
sudo systemctl kill -s HUP heimdall

# 3. Verify each zone is loaded.
for z in $(ls /etc/heimdall/zones/*.zone); do
  fqdn=$(basename "$z" .zone)
  redis-cli EXISTS "heimdall:zone:auth:${fqdn}." || \
    echo "MISSING: ${fqdn}"
done
```

Cache will refill naturally over the next minutes; expect a transient
QPS spike on the recursive/forwarder upstreams.

---

## After recovery

1. Confirm Heimdall metrics show `heimdall_redis_connection_state="up"`
   for at least 15 minutes.
2. Trigger a one-off SIGHUP at a low-traffic time to assert end-to-end
   round-trip integrity (zone-file → Redis → query).
3. Run the relevant `heimdall-integration-tests::soak_crash_recovery`
   suite in staging against the restored Redis topology to validate the
   recovery procedure itself works at scale.
4. Open a prevention ticket per identified gap: backup cadence,
   monitoring, ACL scope, RPO/RTO mismatch with the deployment SLO.
