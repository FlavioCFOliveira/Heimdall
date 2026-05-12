# Runbook — Operational incident response

**When to use.** A production Heimdall deployment exhibits an operational
fault — service unavailability, severe latency regression, crash loop,
mass SERVFAIL, certificate expiry, listener-bind failure, or a Redis
backend outage. This is **not** the runbook for security-CVE response;
that lives in `docs/process/incident-response.md`.

**Goal.** Classify the incident's severity, page the right people, drive
mitigation, and produce a post-mortem.

Cross-references: BIN-051..056, OPS-* (`012-runtime-operations.md`),
STORE-* (`013-persistence.md`), `docs/runbooks/rollback.md`,
`docs/runbooks/redis-recovery.md`, `docs/runbooks/upgrade-failure.md`.

---

## Severity classification

| Severity | Criteria | Page | Comms cadence | Target restore |
|----------|----------|------|---------------|----------------|
| **SEV1** | Total service outage, OR `/readyz` 503 across all instances >5 min, OR Redis unreachable from all instances, OR crash loop on the entire fleet, OR data loss suspected on persisted zones | Page primary on-call IMMEDIATELY; escalate to secondary if unreached in 10 min | Initial within 10 min, every 30 min thereafter | 1 hour |
| **SEV2** | Partial degradation: a transport (e.g. DoH/H3) down, a single role (e.g. recursive) failing, latency p99 >2× SLO for >10 min | Page primary on-call within 30 min | Initial within 30 min, every 60 min | 4 hours |
| **SEV3** | Single-instance issue, single-zone fault, telemetry anomaly with no user-visible impact | File ticket; on-call addresses next business day | Daily standup mention | 5 business days |

The severity is set at incident open and may be downgraded; **upgrades**
require commander approval.

---

## Roles

- **Incident commander (IC)**: takes ownership, coordinates communications,
  decides on escalations. Can be the primary on-call or a delegate.
- **Operator**: executes runbook steps. May be the IC for SEV2/SEV3.
- **Communicator**: drafts external messages; usually a delegate.
- **Scribe**: timestamps every action in the incident channel; this is
  the source of truth for the post-mortem.

For SEV3 a single person may hold all four roles. For SEV1, IC and
Operator MUST be different people.

---

## Decision tree

```
                    ┌──────────────────────────────┐
                    │      Anomaly detected         │
                    └──────────────┬───────────────┘
                                   │
                ┌──────────────────▼──────────────────┐
                │ Is /readyz 503 on >50 % of fleet?    │
                └────────────┬─────────────┬─────────┘
                             │ yes         │ no
                             │             │
                ┌────────────▼─┐  ┌────────▼────────────────┐
                │   SEV1        │  │ Is one transport / role  │
                └──────┬───────┘  │ degraded?                │
                       │          └────┬─────────────┬───────┘
                       │               │ yes         │ no
                       │               │             │
                       │       ┌───────▼────┐  ┌────▼──────────┐
                       │       │   SEV2      │  │  SEV3 / log    │
                       │       └────────────┘  └───────────────┘
                       │
        ┌──────────────▼──────────────┐
        │ Is the cause Redis?          │
        └────┬──────────────────┬─────┘
             │ yes              │ no
             │                  │
   ┌─────────▼────────┐   ┌─────▼─────────────┐
   │ redis-recovery.md │   │ Was a release just │
   └──────────────────┘   │ deployed (<24 h)?  │
                          └────┬────────────┬─┘
                               │ yes        │ no
                               │            │
                       ┌───────▼─────┐ ┌────▼─────────────┐
                       │ rollback.md │ │ Examine logs,     │
                       └─────────────┘ │ /metrics; if      │
                                       │ unclear escalate  │
                                       └───────────────────┘
```

---

## Initial actions (first 10 minutes)

1. **Acknowledge the page**. The on-call rotation tooling expects a
   timestamped ack — silence delays escalation.
2. **Open the incident channel**. Naming: `inc-<YYYYMMDD>-<short-name>`.
3. **Snapshot evidence** before you change anything:

   ```bash
   # Grab the last 5 minutes of logs from every instance.
   journalctl -u heimdall --since "5 min ago" --no-pager > /tmp/inc-logs.txt

   # Snapshot /metrics across the fleet.
   for host in $FLEET; do
     curl -s "http://${host}:8080/metrics" > "/tmp/inc-metrics-${host}.txt"
   done

   # Capture Redis connection state.
   redis-cli CLIENT LIST > /tmp/inc-redis-clients.txt
   redis-cli INFO replication > /tmp/inc-redis-replication.txt
   ```

4. **Set severity** (commander) using the table above.
5. **Send first comms** if SEV1/SEV2 — internal status board + customer
   status page (if applicable).

---

## Mitigation paths

| Symptom | Path |
|---------|------|
| Crash loop after recent deploy | [`rollback.md`](./rollback.md) |
| `/readyz` 503 persistent + listener bind failure | [`upgrade-failure.md`](./upgrade-failure.md) |
| Redis unreachable / read-only / split-brain | [`redis-recovery.md`](./redis-recovery.md) |
| Cache poisoning suspected | `docs/process/incident-response.md` (CVE flow) |
| TLS certificate expired (DoT/DoH/DoQ) | Reissue cert, push to secret store, SIGHUP — OPS-001..010 |
| Single zone serving stale data | `redis-cli` inspect zone hash, compare to authoritative source, `dig +norec @<heimdall> SOA <zone>` to verify serial |

If none match — escalate. The on-call is authorised to declare an unknown
SEV1 and bring in additional engineers.

---

## Communication template

```
Status: [INVESTIGATING|MITIGATING|MONITORING|RESOLVED]
Impact: <one sentence: who is affected, what is broken>
Started: <YYYY-MM-DD HH:MM UTC>
Severity: SEV<n>
Update:  <what we just learned or did>
Next:    <what we are about to do>
ETA:     <best estimate or "unknown">
```

Push at the cadence in the severity table.

---

## Resolution

1. Confirm restoration: `/readyz` 200 across the fleet, latency back to
   SLO, no `::error::` in logs for 15 minutes.
2. Move incident state to **MONITORING** for at least 30 minutes.
3. After 30 minutes of clean signal, **RESOLVED**.
4. The IC schedules the post-mortem within 5 business days
   (`docs/process/post-ga-cadence.md`).
5. The scribe finalises the incident timeline and pastes it into the
   incident folder.

---

## After-action

- File a **prevention** issue per identified cause: monitoring gap,
  runbook gap, code defect, configuration defect.
- Update this runbook if a new symptom or path was discovered. Runbooks
  decay; treat updates as production code.
- If a rollback was performed, follow the rollback "After the rollback"
  section as well.
