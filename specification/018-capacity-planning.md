# Capacity planning

**Purpose.** This document defines the framework within which Heimdall's empirical capacity-planning guidance is expressed and pinned, so that an operator sizing a deployment can derive defensible figures for sustainable queries-per-second per CPU core, memory footprint per cache population, connection budgets per listener, Redis backend sizing, and the threshold at which a single instance must be scaled out into a fleet. It does not redefine the per-cell `(role, transport)` matrix, the calibration procedure, the regression thresholds, the segregated-cache model, the persistence layer, or the runtime-operations surface; those questions are settled in [`008-performance-targets.md`](008-performance-targets.md), [`004-cache-policy.md`](004-cache-policy.md), [`013-persistence.md`](013-persistence.md), and [`012-runtime-operations.md`](012-runtime-operations.md) respectively.

**Status.** Draft (numbers PENDING reference-baseline capture per #665). The framework, the dimensional shape of every capacity rule, and the cross-references are fixed; every absolute numerical value in sections 4 through 8 is a `PENDING — bound to baseline commit <sha>` placeholder, deliberately authored as a placeholder until the operator-blocked capture in rmp task #665 lands the B3 reference-baseline JSON under `docs/bench/baselines/`. Numbers MUST NOT be invented before the capture is complete.

**Requirement category.** `CAP`.

For the project-wide principles that frame these requirements (security non-negotiable, performance as the primary guide, "Assume Nothing"), see [`../CLAUDE.md`](../CLAUDE.md). For specification-wide conventions, see [`README.md`](README.md). For the role model on which the matrix is defined, see [`001-server-roles.md`](001-server-roles.md). For the transport profiles enumerated by the matrix, see [`002-transports.md`](002-transports.md). For the per-cell matrix, the reference hardware baselines, the calibration procedure, the regression thresholds, and the annual revisit cadence to which this document is anchored, see [`008-performance-targets.md`](008-performance-targets.md), in particular `PERF-001` through `PERF-005`, `PERF-010` through `PERF-013`, `PERF-029` through `PERF-038`, and `PERF-050` onwards. For the segregated-cache model on which the per-million-entries footprint is computed, see [`004-cache-policy.md`](004-cache-policy.md). For the resource-limits and admission-control family that bounds connection budgets per listener, see `THREAT-061` through `THREAT-078` in [`007-threat-model.md`](007-threat-model.md). For the Redis-backed persistence layer on which the Redis-sizing guidance is computed, see [`013-persistence.md`](013-persistence.md), in particular `STORE-018` through `STORE-025` and `STORE-040` and `STORE-041`. For the runtime-operations surface that consumes the per-instance capacity figures during deployment, see [`012-runtime-operations.md`](012-runtime-operations.md).

## 1. Scope

This document is **empirical**. Every absolute numerical value it expresses is a measured property of a specific Heimdall build running on a specific reference-hardware revision under a specific kernel and tuning profile. The values are pinned to the commit SHA of the baseline-capture artefact under `docs/bench/baselines/<arch>/<commit-sha>/micro-benchmarks.json` — fixed by `PERF-033` and `PERF-034` in [`008-performance-targets.md`](008-performance-targets.md) and produced by the operator-driven capture procedure in `scripts/bench/capture-baselines.sh` — and are NOT to be treated as portable constants across hardware generations, kernel revisions, or Heimdall versions. The capacity figures travel with the baseline; the framework around them is what this specification fixes.

This document applies uniformly to every Heimdall deployment whose operator is sizing one or more instances, regardless of which combination of roles is active. Capacity rules are expressed per `(role, transport, architecture)` cell consistent with the matrix fixed by `PERF-001` through `PERF-003` and `PERF-010` through `PERF-013` in [`008-performance-targets.md`](008-performance-targets.md). Capacity figures MUST NOT be aggregated across cells.

The scope of this document is operator-facing **capacity guidance**. The acceptance gate that prevents shipping a regressed binary is out of scope here and is covered by the regression-threshold framework in [`008-performance-targets.md`](008-performance-targets.md). The deployment-side service-level commitments computed against a running fleet are out of scope here and are covered by [`016-slo-sli.md`](016-slo-sli.md). The reproducibility of the bench, the corpora, the warm-up and stability criteria, and the kernel-tuning profile are out of scope here and are covered by `PERF-014` through `PERF-052` in [`008-performance-targets.md`](008-performance-targets.md).

## 2. Relationship to the performance-targets framework

The capacity-planning framework defined in this document is the operator-facing projection of the performance-targets framework fixed by [`008-performance-targets.md`](008-performance-targets.md). The performance-targets framework expresses targets and regression thresholds as bounds against a reference-hardware baseline, evaluated under controlled bench conditions. This document re-expresses the same baseline, in the same `(role, transport, architecture)` cell layout, in terms an operator can apply at deployment-planning time: how many cores to provision per instance, how many instances to plan for, how much memory to size each cache against, how to size the Redis backend, and at what query rate to add a second instance.

Concretely: every numerical capacity statement in sections 4 through 8 MUST be derivable from the calibration artefact recorded under `PERF-033` and `PERF-034` in [`008-performance-targets.md`](008-performance-targets.md). A capacity statement that has no corresponding entry in the baseline JSON MUST NOT be introduced. The reverse does not hold: not every dimension in the baseline JSON gives rise to an operator-facing capacity statement, because some dimensions (CPU efficiency, p50 latency) are calibration inputs to the regression framework rather than sizing levers.

## 3. Definitions

For the purposes of this document, the following definitions apply.

- **Cell.** The triple `(role, transport, architecture)` as defined by `PERF-001`, `PERF-002`, and `PERF-010` in [`008-performance-targets.md`](008-performance-targets.md). The matrix spans the three roles defined by [`001-server-roles.md`](001-server-roles.md), the six transport profiles defined by `PERF-002`, and the three architecture columns defined by `PERF-010`, `PERF-011`, `PERF-012`, and `PERF-029`.
- **Baseline JSON.** The machine-readable artefact stored under `docs/bench/baselines/<arch>/<commit-sha>/micro-benchmarks.json` and produced by the capture procedure under `PERF-033`. Each baseline JSON file is keyed by the commit SHA against which it was captured and is the authoritative source of every capacity number expressed in this document.
- **Reference-hardware revision.** The pinned hardware specification on which a baseline JSON was captured, identified by the architecture column (`PERF-011`, `PERF-012`, `PERF-029`) plus the kernel, sysctl, and NIC offload profile fixed by `PERF-050` through `PERF-052`.
- **Sustainable QPS per core.** The sustainable QPS measured under `PERF-006` for a given cell, divided by the physical core count of the reference-hardware revision against which it was measured. This per-core figure is the unit in which sizing guidance is expressed; it is NOT a portable constant and MUST NOT be extrapolated across hardware generations.
- **Cache-population unit.** One million RRset cache entries, used as the unit in which memory-footprint guidance is expressed. The unit applies independently to the recursive cache, the forwarder cache, and the authoritative zone footprint per `STORE-018` through `STORE-025`.

## 4. Per-(role × transport × architecture) sustainable QPS per CPU core

### 4.1 Normative requirements

- **CAP-001.** For every cell of the matrix fixed by `PERF-001` through `PERF-003` and `PERF-010` in [`008-performance-targets.md`](008-performance-targets.md), this document MUST express the sustainable QPS that the cell achieves per physical CPU core on its applicable reference-hardware revision. The per-core figure MUST be derived from the sustainable QPS recorded by the baseline JSON for that cell under `PERF-034`, divided by the physical core count of the reference-hardware revision under `PERF-011`, `PERF-012`, or `PERF-029` as applicable. A capacity number for a cell MUST NOT be expressed before its baseline JSON entry is committed.

- **CAP-002.** The per-core QPS figure per cell MUST be cited together with the commit SHA of the baseline JSON from which it was derived, the architecture column, and the date of capture (`captured_at` in the baseline JSON schema). The citation format MUST be `derived from docs/bench/baselines/<arch>/<commit-sha>/micro-benchmarks.json (captured <YYYY-MM-DD>)`. A per-core figure that does not carry this citation MUST NOT be treated as authoritative.

- **CAP-003.** The per-cell per-core QPS table MUST be reproduced in this document as a placeholder until the baseline JSON capture under #665 is complete. Each row of the table corresponds to a cell of the `(role, transport, architecture)` matrix; each cell of the row carries the value `PENDING — bound to baseline commit <sha>` until the baseline JSON is committed and the table is updated. Inventing or interpolating a value is forbidden under the "Assume Nothing" rule fixed by [`../CLAUDE.md`](../CLAUDE.md).

### 4.2 Per-cell per-core QPS table (placeholder)

| Role          | Transport     | x86_64 (cores per `PERF-011`) | aarch64 (cores per `PERF-012`) | riscv64 (cores per `PERF-029`) |
|---------------|---------------|-------------------------------|--------------------------------|--------------------------------|
| Authoritative | UDP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Authoritative | TCP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Authoritative | DoT           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Authoritative | DoH/H2        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Authoritative | DoH/H3        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Authoritative | DoQ           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | UDP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | TCP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | DoT           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | DoH/H2        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | DoH/H3        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Recursive     | DoQ           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | UDP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | TCP/53        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | DoT           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | DoH/H2        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | DoH/H3        | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |
| Forwarder     | DoQ           | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> | PENDING — bound to baseline commit <sha> |

The 54 cells of the table MUST be filled in by a coordinated update to this document immediately after the baseline JSON capture under #665 lands, in lock-step with the baseline JSON commit SHA citation under `CAP-002`. Until that update happens, every value remains `PENDING — bound to baseline commit <sha>`.

## 5. Memory footprint per cache population

### 5.1 Normative requirements

- **CAP-004.** This document MUST express, for every Heimdall cache exposed by the segregated-cache model in [`004-cache-policy.md`](004-cache-policy.md), the in-process resident memory footprint per cache-population unit (one million RRset entries) measured on the applicable reference-hardware revision. The figure MUST be derived from the per-cache memory dimension recorded by the baseline JSON under `PERF-034`. The framework dimensions are: per-million entries on the recursive cache; per-million entries on the forwarder cache; per-RRset overhead in the authoritative zone footprint as derived from `STORE-018` through `STORE-025` in [`013-persistence.md`](013-persistence.md). All three figures MUST be expressed as `PENDING — bound to baseline commit <sha>` until the baseline JSON capture under #665 is complete.

- **CAP-005.** The recursive-cache and forwarder-cache memory-footprint figures under `CAP-004` MUST be expressed independently per `CACHE-001` through `CACHE-007` in [`004-cache-policy.md`](004-cache-policy.md): the segregation between the recursive and forwarder caches is a structural property of the cache subsystem, and a single combined figure MUST NOT be substituted for the two independent figures. Aggressive NSEC/NSEC3 synthesis state under `DNSSEC-011` is part of the recursive-cache footprint and MUST be included in the recursive-cache per-million-entries figure rather than reported separately.

- **CAP-006.** The authoritative zone-footprint figure under `CAP-004` MUST be expressed per RRset rather than per zone, because the per-zone footprint depends linearly on the RRset count of the zone and a per-zone figure would be misleading. The figure MUST account for the in-process zone representation maintained by the authoritative role, NOT the Redis-side footprint of `STORE-018` through `STORE-021` (which is covered separately by section 7). When the operator wishes to estimate the in-process footprint of a specific zone, the procedure is: count the RRsets in the zone, multiply by the per-RRset figure under this requirement.

- **CAP-007.** Where memory-footprint figures depart from linear extrapolation — for example, when small caches incur fixed-overhead costs that do not scale with entry count, or when very large caches encounter hash-table resizing thresholds that produce step changes in footprint — those non-linearities MUST be documented alongside the per-million-entries figure, with the entry-count ranges over which linear extrapolation is valid recorded explicitly. Operators sizing deployments outside the documented linear range MUST capture their own measurement under their own workload rather than extrapolating.

### 5.2 Per-cache memory-footprint placeholders

- **Recursive cache, per million RRset entries**: `PENDING — bound to baseline commit <sha>`.
- **Forwarder cache, per million RRset entries**: `PENDING — bound to baseline commit <sha>`.
- **Authoritative role, per RRset (in-process)**: `PENDING — bound to baseline commit <sha>`.

## 6. Connection budget per listener

### 6.1 Normative requirements

- **CAP-008.** This document MUST express, for every transport profile enumerated by `PERF-002` in [`008-performance-targets.md`](008-performance-targets.md), the maximum concurrent-connection count the listener sustains at sustainable QPS on the applicable reference-hardware revision. The framework dimensions are: UDP/53 (concurrent in-flight transactions, since UDP is connectionless); TCP/53 (concurrent TCP connections); DoT (concurrent TLS-over-TCP sessions); DoH over HTTP/2 (concurrent TLS-over-TCP sessions, with a separate sub-dimension for concurrent HTTP/2 streams across those sessions); DoH over HTTP/3 (concurrent QUIC connections, with a separate sub-dimension for concurrent HTTP/3 streams across those connections); DoQ (concurrent QUIC connections, with a separate sub-dimension for concurrent QUIC streams across those connections). Every figure MUST be expressed as `PENDING — bound to baseline commit <sha>` until the baseline JSON capture under #665 is complete.

- **CAP-009.** The connection-budget figures under `CAP-008` MUST be reconciled with the per-listener and per-source admission caps fixed by `THREAT-061` through `THREAT-078` in [`007-threat-model.md`](007-threat-model.md). When the empirical connection budget conflicts with an enforced admission cap, the admission cap prevails (consistent with the precedence rule fixed by `PERF-009`). The capacity figure under this section MUST be expressed with the admission caps as a hard upper bound, not as an aspirational target above the cap.

- **CAP-010.** The session-versus-stream distinction on the multiplexed encrypted transports (DoH/H2, DoH/H3, DoQ) MUST be preserved in the connection-budget figures: a single TLS-over-TCP session can multiplex many HTTP/2 streams, and a single QUIC connection can multiplex many HTTP/3 or QUIC streams. The connection-budget figure for those transports MUST express both dimensions independently, because the resource cost of a session and the resource cost of a stream differ by orders of magnitude and operators sizing capacity need both.

### 6.2 Per-listener connection-budget placeholders

| Transport     | Connection-budget dimension            | Value |
|---------------|----------------------------------------|-------|
| UDP/53        | Concurrent in-flight transactions      | PENDING — bound to baseline commit <sha> |
| TCP/53        | Concurrent TCP connections             | PENDING — bound to baseline commit <sha> |
| DoT           | Concurrent TLS-over-TCP sessions       | PENDING — bound to baseline commit <sha> |
| DoH over HTTP/2 | Concurrent TLS-over-TCP sessions     | PENDING — bound to baseline commit <sha> |
| DoH over HTTP/2 | Concurrent HTTP/2 streams across all sessions | PENDING — bound to baseline commit <sha> |
| DoH over HTTP/3 | Concurrent QUIC connections          | PENDING — bound to baseline commit <sha> |
| DoH over HTTP/3 | Concurrent HTTP/3 streams across all connections | PENDING — bound to baseline commit <sha> |
| DoQ           | Concurrent QUIC connections            | PENDING — bound to baseline commit <sha> |
| DoQ           | Concurrent QUIC streams across all connections | PENDING — bound to baseline commit <sha> |

## 7. Redis backend sizing

### 7.1 Normative requirements

- **CAP-011.** This document MUST express, for the Redis backend fixed by [`013-persistence.md`](013-persistence.md), the operator-sizing figures derived from the baseline JSON under `PERF-034` along three dimensions: keys per zone; Redis-side memory per zone; network bandwidth between Heimdall and Redis under sustained-QPS load. The keys-per-zone dimension is structurally derivable from `STORE-018` through `STORE-025`: each authoritative zone is one Redis Hash, with one field per RRset; the keys-per-zone figure is therefore equal to the RRset count of the zone plus the constant per-zone Hash overhead. The memory-per-zone and bandwidth dimensions are empirical and MUST be expressed as `PENDING — bound to baseline commit <sha>` until the baseline JSON capture under #665 is complete.

- **CAP-012.** The keys-per-zone formula under `CAP-011` MUST be expressed as: `keys(zone) = 1 + RRsetCount(zone)` where the leading `1` accounts for the single Hash key per zone under `STORE-018` and `RRsetCount(zone)` is the number of distinct `(owner_name, qtype, qclass)` triples in the zone under `STORE-020`. Operators planning Redis Cluster slot distribution MUST compute keys per zone using this formula and apply the slot-allocation procedure fixed by `STORE-039` and `STORE-040` accordingly. Staging keys created during the atomic-replacement procedure under `STORE-023` MUST be counted as transient and MUST NOT be added to the steady-state keys-per-zone figure.

- **CAP-013.** The Redis-side memory-per-zone figure MUST be expressed as a per-RRset Redis-side overhead derived from the baseline JSON, multiplied by the zone's RRset count, plus a per-zone constant for the Hash-key overhead. The per-RRset Redis-side overhead is distinct from the in-process per-RRset overhead under `CAP-006`: Redis stores the wire-encoded RDATA per the serialisation format fixed by `STORE-043`, plus Redis Hash-field metadata, plus per-key Redis overhead, none of which corresponds 1-to-1 with the in-process zone representation.

- **CAP-014.** The Heimdall-to-Redis network-bandwidth dimension under `CAP-011` MUST be expressed as bytes per second under the sustainable-QPS load of the cell that drives the highest Redis access rate, which is structurally the recursive-resolver cell (cache reads and writes scale with QPS) followed by the forwarder cell (cache reads and writes also scale with QPS but with a narrower upstream-driven population) followed by the authoritative cell (zone reads scale with QPS, zone writes are episodic on reload). The bandwidth figure MUST account for the connection-mode default fixed by `STORE-007` (Unix domain socket) AND for the TCP-with-TLS opt-in fixed by `STORE-008` and `STORE-010`, because the per-byte cost of TLS framing materially affects the bandwidth budget and a single figure for both modes would be misleading.

- **CAP-015.** The Redis sizing guidance under `CAP-011` through `CAP-014` MUST be reconciled with the Redis Cluster and Sentinel topology fixed by `STORE-040` and `STORE-041` in [`013-persistence.md`](013-persistence.md). For Redis Cluster deployments, the per-instance Redis memory budget MUST be derived from the keys-per-zone and memory-per-zone figures distributed across the cluster's slot range with the hash-tag placement fixed by `STORE-040`. For Redis Sentinel deployments, the failover-detection latency upper bound fixed by `STORE-041` (at most 1 second) MUST be carried into the operator's availability planning, because a 1-second blackout per failover is a structural property of the sizing posture, not a defect.

### 7.2 Per-zone Redis sizing placeholders

- **Redis keys per zone (formula)**: `keys(zone) = 1 + RRsetCount(zone)`. Stable; not pending.
- **Redis-side memory per RRset**: `PENDING — bound to baseline commit <sha>`.
- **Redis-side per-zone Hash-key overhead constant**: `PENDING — bound to baseline commit <sha>`.
- **Heimdall-to-Redis bandwidth at sustainable QPS, Unix domain socket**: `PENDING — bound to baseline commit <sha>`.
- **Heimdall-to-Redis bandwidth at sustainable QPS, TCP with TLS**: `PENDING — bound to baseline commit <sha>`.

## 8. Multi-instance scale-out

### 8.1 Normative requirements

- **CAP-016.** This document MUST express, per cell, the QPS threshold at which an operator MUST add a second Heimdall instance to maintain headroom against the per-instance sustainable-QPS figure fixed by section 4. The threshold MUST be expressed as a fraction of the per-instance sustainable QPS, NOT as an absolute QPS number, because the absolute number is a function of the cell's per-core figure and the core count of the deployed instance. The fraction is the operator-sizing safety margin: it MUST be set high enough that a single instance does not run at sustained saturation (where p99 latency degrades non-linearly per `PERF-024`) and low enough that operators do not over-provision capacity that goes unused.

- **CAP-017.** The fractional threshold under `CAP-016` MUST be derived empirically from the latency-versus-load curve in the baseline JSON: the threshold is the load fraction at which the cell's p99 latency begins to deviate from the linear regime under `PERF-007` and starts the convex degradation that is the structural signature of saturation. Until the baseline JSON capture under #665 records that curve, the fractional threshold MUST be expressed as `PENDING — bound to baseline commit <sha>`. Inventing a placeholder fraction (such as "70%" or "80%") is forbidden under the "Assume Nothing" rule.

- **CAP-018.** When scaling out from one instance to N instances, the Redis backend MUST be sized for the aggregate load of the N instances rather than for the per-instance load. The aggregate Redis memory budget MUST be: `Redis_memory_total = Sum_over_N_instances(per_instance_zone_set memory_under_CAP-013)`. The aggregate Heimdall-to-Redis bandwidth MUST be: `Redis_bandwidth_total = N × per_instance_bandwidth_under_CAP-014`, with the caveat that a Redis Cluster deployment under `STORE-040` distributes the bandwidth across cluster nodes per the slot-allocation procedure rather than concentrating it on a single Redis node. For Redis Sentinel deployments under `STORE-041`, the bandwidth concentrates on the current leader, and the leader's network-interface budget MUST be sized for the aggregate.

- **CAP-019.** The cache-populated state of an instance MUST NOT be assumed to be transferable to a newly-added instance: each instance maintains its segregated caches independently per `CACHE-001` through `CACHE-007` in [`004-cache-policy.md`](004-cache-policy.md). When an N-th instance is added to an existing fleet, the new instance MUST be expected to operate at cold-cache or partially-warm-cache latency until its caches reach the population state of the rest of the fleet under representative workload. The duration of this warm-up phase is workload-dependent and MUST NOT be expressed as a fixed figure in this document.

- **CAP-020.** Multi-instance load distribution upstream of the Heimdall fleet (DNS load balancers, anycast, ECMP) is out of scope for this document. The operator is responsible for distributing query load across instances such that no single instance exceeds the `CAP-016` threshold; the mechanism by which that distribution is achieved is a deployment-architecture decision that this document does not constrain.

### 8.2 Multi-instance scale-out placeholders

- **Per-cell QPS threshold for adding a second instance, expressed as fraction of per-instance sustainable QPS**: `PENDING — bound to baseline commit <sha>`.
- **Redis aggregate memory budget for N instances**: derived by `CAP-018` from the per-zone figures under section 7. Pending those figures.
- **Redis aggregate bandwidth budget for N instances (Sentinel topology)**: `N × per_instance_bandwidth_under_CAP-014`. Pending the per-instance figure.
- **Redis aggregate bandwidth budget for N instances (Cluster topology)**: distributed per the slot-allocation procedure under `STORE-040`. Pending the per-instance figure and the operator's slot layout.

## 9. Revisit cadence

### 9.1 Normative requirements

- **CAP-021.** The capacity figures expressed by this document MUST be revisited at least once per calendar year, in lock-step with the annual revisit fixed by `PERF-026` and the calibration-cycle revisit fixed by `PERF-067` in [`008-performance-targets.md`](008-performance-targets.md). Each revisit MUST: (1) re-execute the capture procedure of `scripts/bench/capture-baselines.sh` against a fresh Heimdall build on the current reference-hardware revision; (2) commit the new baseline JSON under `docs/bench/baselines/<arch>/<commit-sha>/micro-benchmarks.json` and update the `latest` pointer; (3) update every `PENDING — bound to baseline commit <sha>` placeholder and every previously-resolved figure in this document to cite the new commit SHA; (4) document, in a dated changelog entry attached to this document, every cell whose per-core QPS, per-million-entries memory, connection budget, Redis sizing, or scale-out threshold changed by more than the regression threshold fixed by `PERF-037`.

- **CAP-022.** When the reference-hardware revision itself changes — for example, when `PERF-011`, `PERF-012`, or `PERF-029` is updated to a new CPU class — the capacity figures from the prior reference-hardware revision MUST NOT be carried forward. The new reference-hardware revision MUST trigger a full re-capture under `CAP-021`. The prior baseline JSON files MUST be retained under `docs/bench/baselines/` indefinitely for historical comparison; they MUST NOT be deleted to "tidy up", because they are evidence for the capacity figures that applied during the prior reference-hardware revision's lifetime.

- **CAP-023.** Operator-driven overrides of the regression baseline under `PERF-038` MUST propagate to the capacity figures in this document in the same lock-step fashion that `SLO-010` in [`016-slo-sli.md`](016-slo-sli.md) requires for the SLO baselines. An override that lowers the per-core sustainable QPS of a cell MUST be reflected in section 4; an override that raises the per-million-entries memory footprint of a cache MUST be reflected in section 5; an override that lowers the connection budget of a listener MUST be reflected in section 6. A `cap-baseline-drift` structured event under `THREAT-080` in [`007-threat-model.md`](007-threat-model.md) MUST be emitted when a `PERF-038` override is applied without a corresponding update to this document; the drift MUST be resolved before the next compliance-window evaluation under [`016-slo-sli.md`](016-slo-sli.md).

## 10. Cross-references

This section enumerates the cross-references on which this document depends. It does not duplicate text from the referenced sections; the authoritative statement of each cross-referenced requirement lives in the file where it is defined.

- The per-cell `(role, transport, architecture)` matrix on which every capacity figure is expressed is defined by `PERF-001` through `PERF-003` and `PERF-010` in [`008-performance-targets.md`](008-performance-targets.md).
- The reference-hardware baselines from which the per-core figures derive are defined by `PERF-011`, `PERF-012`, and `PERF-029` in [`008-performance-targets.md`](008-performance-targets.md).
- The calibration procedure that produces the baseline JSON cited by every capacity figure is defined by `PERF-033` and `PERF-034` in [`008-performance-targets.md`](008-performance-targets.md).
- The regression-threshold framework with which the revisit cadence is reconciled is defined by `PERF-036` and `PERF-037` in [`008-performance-targets.md`](008-performance-targets.md). The operator-override mechanism cross-referenced by `CAP-023` is defined by `PERF-038`.
- The annual revisit governance to which `CAP-021` is anchored is defined by `PERF-026` and `PERF-067` in [`008-performance-targets.md`](008-performance-targets.md).
- The kernel and tuning profile that pins the reference-hardware revision is defined by `PERF-050` through `PERF-052` in [`008-performance-targets.md`](008-performance-targets.md).
- The segregated-cache model on which the per-million-entries memory footprint is computed is defined by `CACHE-001` through `CACHE-007` in [`004-cache-policy.md`](004-cache-policy.md).
- The aggressive NSEC/NSEC3 synthesis state that is included in the recursive-cache footprint under `CAP-005` is defined by `DNSSEC-011` in [`005-dnssec-policy.md`](005-dnssec-policy.md).
- The resource-limits and admission-control family with which the connection-budget figures are reconciled is defined by `THREAT-061` through `THREAT-078` in [`007-threat-model.md`](007-threat-model.md).
- The Redis-backed authoritative-zone storage layout from which the keys-per-zone formula derives is defined by `STORE-018` through `STORE-025` in [`013-persistence.md`](013-persistence.md). The wire serialisation format from which the Redis-side per-RRset overhead derives is defined by `STORE-043`.
- The Redis Cluster slot-allocation and Redis Sentinel failover topology referenced by `CAP-015` and `CAP-018` are defined by `STORE-039`, `STORE-040`, and `STORE-041` in [`013-persistence.md`](013-persistence.md).
- The structured-event taxonomy referenced by the `cap-baseline-drift` event in `CAP-023` is defined by `THREAT-080` in [`007-threat-model.md`](007-threat-model.md).
- The deployment-side SLO framework whose baselines are propagated in lock-step under `CAP-023` is defined in [`016-slo-sli.md`](016-slo-sli.md), in particular `SLO-010`.

## 11. Rationale

The capacity-planning framework is empirical by construction. The "Assume Nothing" rule fixed by [`../CLAUDE.md`](../CLAUDE.md) makes capacity numbers the only category of project artefact whose value MUST come from measurement rather than from specification: a number such as "Heimdall sustains 1.5 million QPS per core on UDP/53" cannot be authored at the specification level, because it is not a decision but a measured property of a specific build on specific hardware under specific tuning. Authoring such a number without a measurement would be folklore at best and misleading at worst. This document therefore fixes the framework — what shape the numbers take, what cells they cover, what they cite, when they are revisited, how they propagate when overrides are applied — and defers every absolute number to the baseline JSON capture under `PERF-033`.

Pinning every capacity figure to a baseline JSON commit SHA under `CAP-002` is the structural mechanism that prevents the framework from drifting silently between Heimdall versions or between hardware revisions. A capacity number without a citation is worse than no number at all: an operator who applies a stale figure to a deployment whose hardware or whose Heimdall build differs from the figure's reference revision risks under-provisioning to the point of saturation or over-provisioning to the point of waste. The citation makes the figure auditable and makes the staleness detectable; the annual revisit under `CAP-021` is the lock-step mechanism that keeps the citations current.

Expressing the per-core sustainable-QPS figure under `CAP-001` rather than the absolute sustainable-QPS figure is the unit of operator-facing sizing. An operator does not size a deployment in absolute QPS at the specification's reference hardware; an operator sizes a deployment in cores against the deployed hardware. The per-core figure makes the sizing arithmetic correct under the (large) assumption that performance scales linearly with core count, which is true within bounded ranges and false outside them; the documentation obligation under `CAP-007` records where the linear range ends and prevents naive extrapolation. This is the same structural choice that the SLO framework in [`016-slo-sli.md`](016-slo-sli.md) makes for latency targets: a multiplier over a baseline rather than an absolute number, because the multiplier is portable and the baseline carries the empirical content.

Treating the recursive cache, the forwarder cache, and the authoritative zone footprint independently under `CAP-004` and `CAP-005` is the same structural choice already made in [`004-cache-policy.md`](004-cache-policy.md): the segregation between caches is a property of the cache subsystem, not a reporting convenience that this document is free to collapse. Reporting a single combined memory figure would give operators the wrong unit of sizing — they would be sized against an aggregate that does not correspond to any single cache's growth rate, and the per-cache regression signal that `PERF-037` enforces would have nothing to project onto. Carrying the segregation through to the capacity-planning surface preserves the diagnostic value of the cache-population unit.

The session-versus-stream split for the multiplexed encrypted transports under `CAP-010` is the equivalent observation for the connection-budget dimension. A DoH/H2 listener that sustains 10 000 concurrent TLS-over-TCP sessions and a DoH/H2 listener that sustains 10 000 concurrent HTTP/2 streams are two qualitatively different deployments: the first is bounded by TLS session memory and TCP socket count; the second is bounded by HTTP/2 stream state and request-handling concurrency. Operators sizing capacity must know which dimension they are bounded by, and a single combined figure would erase that information. The same observation applies to DoH/H3 and DoQ on the QUIC-stream axis.

Expressing the keys-per-zone Redis-sizing dimension under `CAP-012` as a closed-form formula rather than as a measured figure is justified because the formula is structurally derivable from the persistence-layer requirements in [`013-persistence.md`](013-persistence.md): each zone is one Hash, with one field per RRset, plus the Hash-key overhead. There is no empirical content in the keys-per-zone formula — only in the memory-per-RRset figure that the Hash field values consume, which is correctly expressed as PENDING under `CAP-013`. Distinguishing the keys-per-zone closed form from the memory-per-RRset empirical figure under `CAP-013` keeps the framework honest about which figures are derivable from the specification and which require measurement.

Distinguishing the Unix-domain-socket bandwidth from the TCP-with-TLS bandwidth under `CAP-014` is required because the two connection modes have materially different per-byte costs. Treating them as the same figure would either over-state the bandwidth available on the Unix-socket path (the default, per `STORE-007`) or under-state it on the TCP-with-TLS path (the opt-in, per `STORE-008` and `STORE-010`). Operators choosing between the two modes need both figures to make the comparison.

Reconciling the connection-budget figures with the threat-model admission caps under `CAP-009` is the same structural-precedence choice already made by `PERF-009` in [`008-performance-targets.md`](008-performance-targets.md): admission caps are security-driven invariants that the performance and capacity figures must respect, never override. A capacity number that exceeds an admission cap would be unreachable in any deployment that honours the cap, and reporting such a number would mislead the operator into over-provisioning. The precedence rule keeps the security and capacity surfaces coherent.

Expressing the multi-instance scale-out threshold under `CAP-016` and `CAP-017` as a fraction of per-instance sustainable QPS rather than as an absolute QPS is the same per-core-style portability choice. The fraction travels with the cell across deployments; the absolute number does not. Refusing to invent a placeholder fraction under `CAP-017` is the same "Assume Nothing" discipline applied throughout this document: a number such as "scale out at 70% of saturation" sounds operationally sensible but has no empirical basis, and authoring it would create a precedent that the framework is willing to substitute folklore for measurement.

The Redis sizing-aggregation rule under `CAP-018` is a structural derivation rather than an empirical one: the aggregate is the sum of the per-instance figures, modulated by the topology choice between Cluster and Sentinel. Recording the topology distinction is required because the bandwidth distribution differs qualitatively: Cluster spreads bandwidth across slot-owning nodes; Sentinel concentrates it on the leader. Operators choosing between the two topologies under `STORE-040` and `STORE-041` need both rules to size their Redis fleet correctly.

The cold-cache caveat under `CAP-019` is the operator-facing complement of the cache-segregation property under [`004-cache-policy.md`](004-cache-policy.md). Adding a new instance does not transfer the cache state of the existing fleet to the new instance: each instance walks its own warm-up. An operator who assumes that the N-th instance starts at the steady-state hit rate of the existing fleet risks pulling the new instance into latency-degraded service before its caches reach representative population, and `SLO-005` and `SLO-006` in [`016-slo-sli.md`](016-slo-sli.md) will surface the degradation as a hit-rate excursion. Refusing to fix the warm-up duration is the same "Assume Nothing" choice: warm-up time is workload-dependent and varies across deployments.

The annual revisit cadence under `CAP-021` is anchored to `PERF-026` and `PERF-067` for the same reason that `SLO-018` in [`016-slo-sli.md`](016-slo-sli.md) anchors its revisit to the same governance: the capacity-planning framework, the performance-targets framework, the comparative-benchmark framework, and the SLO framework all depend on the same underlying calibration baseline, and decoupling their revisits would produce a drift surface. Coupling them keeps the four frameworks coherent across cycles. Retaining prior baseline JSON files indefinitely under `CAP-022` is the same structural choice already made for ADRs in [`010-engineering-policies.md`](010-engineering-policies.md): historical evidence is not deleted to tidy up, because the evidence is what makes the current figures auditable.

The `cap-baseline-drift` structured event under `CAP-023` is the lock-step propagation mechanism that prevents an operator override under `PERF-038` from creating a silent inconsistency between the source-tree-side regression baseline and the operator-facing capacity figures. A `PERF-038` override that lowers the per-core sustainable QPS of a cell without updating section 4 of this document would leave operators sizing against a stale figure and potentially under-provisioning their deployment; the structured event surfaces the drift before the next compliance-window evaluation under [`016-slo-sli.md`](016-slo-sli.md), at which point the drift becomes observable in the SLO compliance report. The same propagation pattern is already adopted by `SLO-010` for the SLO baselines; carrying it across to capacity figures is consistent.

## 12. Open questions

The framework fixed by sections 4 through 9 is complete; every absolute numerical figure in sections 4 through 8 is **PENDING** the operator-driven baseline-capture procedure tracked as rmp task #665, which is blocked on operator access to PERF-011 and PERF-012 reference hardware. The items below remain open and MUST NOT be assumed before the baseline JSON capture is committed under `docs/bench/baselines/<arch>/<commit-sha>/micro-benchmarks.json`. Each placeholder cited below is bound to the same baseline-capture event; when the capture lands, every placeholder is resolved in lock-step by a coordinated update to this document.

- **Per-cell per-core sustainable QPS, all 54 cells of the matrix.** Under `CAP-001` and `CAP-003`. Blocked on baseline JSON commit per #665.
- **Recursive cache memory footprint per million RRset entries.** Under `CAP-004` and `CAP-005`. Blocked on baseline JSON commit per #665.
- **Forwarder cache memory footprint per million RRset entries.** Under `CAP-004` and `CAP-005`. Blocked on baseline JSON commit per #665.
- **Authoritative role in-process memory footprint per RRset.** Under `CAP-004` and `CAP-006`. Blocked on baseline JSON commit per #665.
- **Documented linear range and non-linearities of the per-million-entries figures.** Under `CAP-007`. Blocked on baseline JSON commit per #665.
- **Connection-budget figures per transport profile, including the session-versus-stream split for DoH/H2, DoH/H3, and DoQ.** Under `CAP-008` and `CAP-010`. Blocked on baseline JSON commit per #665.
- **Redis-side per-RRset memory overhead.** Under `CAP-013`. Blocked on baseline JSON commit per #665.
- **Redis-side per-zone Hash-key overhead constant.** Under `CAP-013`. Blocked on baseline JSON commit per #665.
- **Heimdall-to-Redis bandwidth at sustainable QPS, Unix domain socket connection mode.** Under `CAP-014`. Blocked on baseline JSON commit per #665.
- **Heimdall-to-Redis bandwidth at sustainable QPS, TCP-with-TLS connection mode.** Under `CAP-014`. Blocked on baseline JSON commit per #665.
- **Per-cell scale-out threshold expressed as fraction of per-instance sustainable QPS.** Under `CAP-016` and `CAP-017`. Blocked on baseline JSON commit per #665, specifically on the latency-versus-load curve recorded as part of the baseline JSON.
- **Citation commit SHA in every `PENDING — bound to baseline commit <sha>` placeholder above.** Under `CAP-002`. Blocked on baseline JSON commit per #665.
