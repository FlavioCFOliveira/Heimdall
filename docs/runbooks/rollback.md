# Runbook — Release rollback

**When to use.** A Heimdall release went out and is misbehaving in
production: elevated SERVFAILs, latency regression past PERF-037 thresholds,
crash loops, or an `/readyz` 503 that does not clear within the configured
grace window. The decision is to revert to the previous version.

**Goal.** Restore service to the prior working version with zero data loss
on Redis-backed state, in under 15 minutes.

Cross-references: BIN-051..056 (drain coordination), OPS-* (atomic reload),
STORE-* (`013-persistence.md`), `012-runtime-operations.md`.

---

## Preconditions

Before running any rollback step, confirm:

1. The previous version's container image / `.deb` / `.rpm` / `.tar.gz` is
   still available in the artefact store (GHCR / package mirror). Releases
   are immutable; if it was deleted, **stop and recover from the artefact
   archive** instead.
2. Redis is reachable and healthy — the rollback assumes the persistence
   layer survives the binary swap. If Redis is down, run
   [`redis-recovery.md`](./redis-recovery.md) first.
3. The previous version's `/version` and `/readyz` health responses are
   known (compare via `gh release view <previous-tag>`).
4. The change-management approver is reachable. Rolling back is a deploy
   action and must be logged (OPS-074).

---

## Decision tree

```
                  ┌──────────────────────────┐
                  │  Anomaly detected         │
                  │ (latency / 5xx / crash)   │
                  └─────────────┬────────────┘
                                │
                  ┌─────────────▼─────────────┐
                  │  Has the issue persisted   │
                  │  >5 min after last reload? │
                  └────┬────────────────┬─────┘
                       │ no             │ yes
                       │                │
                  ┌────▼─────┐    ┌─────▼──────────────────┐
                  │  Wait,    │    │  Is the cause a single  │
                  │  observe  │    │  config flag introduced │
                  │           │    │  this release?          │
                  └───────────┘    └────┬───────────┬────────┘
                                        │ yes       │ no
                                        │           │
                                  ┌─────▼─────┐ ┌───▼────────────┐
                                  │ Revert     │ │ Full version    │
                                  │ config     │ │ rollback (this  │
                                  │ via SIGHUP │ │ runbook)        │
                                  └───────────┘ └─────────────────┘
```

If the cause is a single config flag introduced in the release, prefer
**revert config + SIGHUP** over a full version rollback — it is cheaper and
faster (OPS-001..010, atomic reload). Use this runbook only for **code**
regressions.

---

## 1. Container deployments (recommended path)

The rollback is a `docker pull` + restart of the previous tag. Heimdall's
binary contract (BIN-051..056) guarantees a clean drain on SIGTERM and a
fresh process boot on a new image — there is no protocol-level upgrade or
migration step.

```bash
PREV_TAG="v1.1.0"  # the version known good
NEW_TAG="v1.1.1"   # the version being rolled back

# Pull the previous image so we don't depend on the registry being
# reachable during the swap.
docker pull "ghcr.io/<owner>/heimdall:${PREV_TAG}"

# Stop the current container with SIGTERM (NOT SIGKILL — drain matters).
# The binary will refuse new connections and finish in-flight ones before
# the configured grace period (default 30 s, BIN-051).
docker stop --time 60 heimdall

# Start the previous version with the same config volume.
docker run --name heimdall-rollback \
  -d \
  -v /etc/heimdall:/etc/heimdall:ro \
  --network host \
  "ghcr.io/<owner>/heimdall:${PREV_TAG}"
```

Wait for `/readyz` to return 200 (max 30 s, OPS-024). If not:

- Fetch logs: `docker logs heimdall-rollback`.
- Check for Redis schema mismatch (the rolled-back binary is older and may
  not understand fields written by the new binary). See section 4 below.

---

## 2. `.deb` / `.rpm` deployments

The same logic applies, with the package manager handling the binary swap.

### Debian / Ubuntu

```bash
# Confirm the previous version is in the cache or downloadable.
apt-cache madison heimdall

# Downgrade. apt will not allow this without --force unless the version
# is in the package list; on a private apt repo this requires the rollback
# version to remain published.
sudo apt-get install heimdall=1.1.0-1

# systemd will call heimdall.service stop (SIGTERM, drain) then start.
sudo systemctl restart heimdall
```

### RHEL / CentOS / Fedora

```bash
sudo dnf downgrade heimdall-1.1.0-1
sudo systemctl restart heimdall
```

### `.tar.gz`

Replace the binary in `$PATH` and restart the unit; the old binary tarball
must already be on the host (immutable archive policy).

---

## 3. Verify the rollback

1. **Service health**: `/readyz` returns 200 within 30 s.
2. **Version**: `curl http://127.0.0.1:8080/version` returns the rolled-back
   version string.
3. **DNS conformance**: send a known query and assert the response matches
   the previous behaviour.

```bash
dig @127.0.0.1 example.com. A +short
```

4. **Drain count**: `curl http://127.0.0.1:8080/metrics | grep heimdall_drain_inflight`
   should show 0 (no leaked guards from the previous binary).

5. **Latency / QPS**: monitor for 10 minutes; if the regression that
   triggered the rollback is gone, the rollback is confirmed.

---

## 4. Redis schema-mismatch recovery

If the rolled-back (older) binary does not understand a Redis field
written by the new (forward) binary, the older binary will log a parse
error and refuse to start. STORE-* requires field encoding compatibility
across one minor version, but a regression here is possible.

Mitigation:

1. Stop heimdall (it will be in a crash loop already).
2. Drop the affected Redis hash field. Example for cache:

   ```bash
   redis-cli DEL heimdall:cache:*
   ```

   This clears the cache; the recursive role will refill from
   authoritative servers (slower, but safe). For zone data, restore from
   AOF/RDB per `redis-recovery.md`.

3. Start the rolled-back binary; verify `/readyz` recovers.
4. File a release-blocker bug against the new version's Redis field
   encoding; the next forward release must include a downgrade-safe
   field-format guard.

---

## 5. After the rollback

1. **Open an incident**: `docs/process/incident-response.md` covers
   communication, severity, and post-mortem cadence.
2. **Tag the bad release** in the release notes as
   `> withdrawn: rolled back YYYY-MM-DD; do not use`.
3. **Block the bad version** in the package mirror so accidental
   re-installs cannot pick it up (apt: pinning, dnf: exclude).
4. **Schedule the post-mortem**: 5 working days after restoration
   (post-GA cadence in `docs/process/post-ga-cadence.md`).

---

## When NOT to roll back

- The issue is a configuration regression — fix the config and SIGHUP.
- The issue is a Redis-backend issue (use `redis-recovery.md`).
- The issue is a downstream client bug — file an issue against that
  client; do not roll Heimdall back unless the client cannot be patched.
