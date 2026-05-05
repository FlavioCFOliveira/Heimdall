# Annual performance revisit playbook

Sprint 50 task #509 — PERF-026.

## Overview

PERF-026 requires Heimdall's external performance comparison (PERF-019..025) to
be revisited at least once per calendar year.  This document is the operational
playbook for that revisit.  See `ADR-0064` for the governance decision.

The revisit produces:
1. Updated `tests/conformance/digests.lock` with the latest reference image
   versions.
2. Updated `docs/bench/comparisons/YYYY/` with full comparison tables.
3. Updated `docs/bench/baselines/<arch>/latest` if new micro-benchmarks were
   captured on reference hardware.
4. A PR with the above, reviewed by at least one core maintainer.

## Schedule

The annual revisit is scheduled for the first sprint of each calendar year.
The next scheduled date is **2027-01-01** (first sprint of 2027).

Set a calendar reminder in the maintainer calendar 4 weeks before the date to
allow time for hardware scheduling.

## Checklist

### 1. Identify best-in-class reference implementations (PERF-020)

For each cell in the `(role, transport)` matrix, verify that the reference
implementation set is still current:

- [ ] Authoritative: NSD (latest stable), Knot Auth (latest stable), PowerDNS Auth (latest)
- [ ] Recursive: Unbound (latest stable), Knot Resolver (latest stable), PowerDNS Recursor (latest)
- [ ] Forwarder: dnsdist (latest stable), CoreDNS (latest stable), Unbound (forward mode)
- [ ] Encrypted: dnsdist, cloudflared, Flamethrower (where applicable)

Pin the new versions in `tests/conformance/digests.lock`.

### 2. Update reference images

```bash
# Pull and pin new reference images
docker pull nsdock/nsd:latest
docker pull cznic/knot:latest
docker pull mvance/unbound:latest
docker pull powerdns/pdns-auth-49:latest
docker pull powerdns/pdns-recursor-50:latest
docker pull coredns/coredns:latest

# Record new digests
docker inspect --format='{{.RepoDigests}}' nsdock/nsd:latest
# Update tests/conformance/digests.lock
```

### 3. Run per-cell comparison

For each role and transport, run the comparison script on reference hardware:

```bash
# Authoritative, plain DNS
HEIMDALL_AUTH_ADDR=... NSD_ADDR=... KNOT_AUTH_ADDR=... \
scripts/bench/compare-reference.sh --role authoritative --transport udp53

# Authoritative, TCP
HEIMDALL_AUTH_ADDR=... NSD_ADDR=... \
scripts/bench/compare-reference.sh --role authoritative --transport tcp53

# Authoritative, DoT (Heimdall must be in "exceed" territory)
HEIMDALL_AUTH_ADDR=... \
scripts/bench/compare-reference.sh --role authoritative --transport dot

# ... repeat for recursive and forwarder × all transports
```

### 4. Record results

For each comparison, save the output to
`docs/bench/comparisons/YYYY/ROLE-TRANSPORT.txt`:

```bash
mkdir -p docs/bench/comparisons/$(date +%Y)
scripts/bench/compare-reference.sh --role authoritative --transport udp53 \
  > docs/bench/comparisons/$(date +%Y)/authoritative-udp53.txt 2>&1
```

### 5. Update baselines if improved

If Heimdall's performance improved on a cell, capture a new micro-benchmark
baseline and update `latest`:

```bash
HEIMDALL_REFERENCE_HARDWARE=1 scripts/bench/capture-baselines.sh
echo "$(git rev-parse HEAD)" > docs/bench/baselines/$(uname -m)/latest
```

### 6. Review and PR

- [ ] Commit all updated files under `docs/bench/comparisons/YYYY/`
- [ ] Commit updated `tests/conformance/digests.lock`
- [ ] Commit updated baselines if applicable
- [ ] Open a PR titled `perf: annual revisit YYYY` targeting `main`
- [ ] Require at least one core maintainer approval
- [ ] Merge before the end of the first sprint of the year

### 7. Document failures

If Heimdall fails to meet a parity or exceed target on any cell:
- Open a task in the roadmap with priority = high
- Add it to the next sprint if critical
- If intentional or blocked by hardware availability, document as an ADR

## Governance

See `docs/adr/0064-perf-governance.md` for the decision that mandates this
revisit schedule and defines the threshold-update authority.
