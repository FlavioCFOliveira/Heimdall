# Heimdall v1.1 — Comparative benchmarks vs reference implementations

**Specification.** Closes the documentation half of PERF-019..028 in
[`specification/008-performance-targets.md`](../../specification/008-performance-targets.md):
external comparison against the state-of-the-art reference set, with
parity required on plain DNS (PERF-021) and exceed required on
encrypted transports (PERF-023).

**Audience.** Operators who need to know how Heimdall stacks up against
NSD, Knot, BIND, Unbound, Knot Resolver, PowerDNS, dnsdist, CoreDNS;
contributors who run a comparison cycle when shipping a substantive
change.

---

## 1. Reference implementation set (PERF-020)

| Role | Reference set (pinned per cycle) |
|---|---|
| Authoritative | NSD (NLnet Labs), Knot Authoritative (CZ.NIC), BIND9 (ISC), PowerDNS Authoritative |
| Recursive     | Unbound (NLnet Labs), Knot Resolver (CZ.NIC), PowerDNS Recursor |
| Forwarder     | dnsdist (PowerDNS), CoreDNS (`forward` plugin), Unbound (forward mode) |
| Encrypted     | dnsdist, cloudflared (DoH), Flamethrower, plus any current encrypted-DNS implementation |

Pinned versions for the v1.1 comparison cycle are recorded alongside the
results JSON under `docs/bench/comparative/<git-sha>/<cell>.json`.

---

## 2. Methodology (PERF-021..028)

Comparative measurements are produced by `scripts/bench/compare-reference.sh`,
which:

1. Boots Heimdall and the reference implementations side-by-side on the
   same physical host. Each instance is bound to a distinct loopback
   port.
2. Runs `dnsperf` against each instance for the same query file and
   duration.
3. Computes the comparison bounds:
   - **Parity bounds** (PERF-022) for plain-DNS cells (UDP/53, TCP/53):
     `QPS within 5%`, `p99 within 20%`, `RSS not worse`, `CPU efficiency not worse`.
     All four bounds MUST be simultaneously satisfied.
   - **Exceed bounds** (PERF-024) for encrypted-transport cells:
     either `QPS > +20%` or `p99 < -20%` vs the best-in-class reference;
     RSS and CPU efficiency MUST NOT be worse.

4. Stores per-cell JSONs under `docs/bench/comparative/<git-sha>/`.
5. Exits non-zero if any cell fails its applicable bound, so the script
   can act as a CI gate during the comparison cycle.

---

## 3. Per-architecture status (PERF-031, PERF-032)

PERF-031 requires the comparison to be performed per architecture column.
PERF-032 requires that, when a reference implementation is unavailable on
a given architecture, the absence is documented alongside the results.

| Architecture | Comparison cycle committed | Notes |
|---|---|---|
| x86_64  | PENDING | Run on hardware matching PERF-011 |
| aarch64 | PENDING | Run on hardware matching PERF-012; document any reference implementations not available |
| riscv64 | PENDING | Per PERF-029; document any reference implementations not available |

---

## 4. Per-cell results (PENDING)

| Cell | vs reference | QPS Δ | p99 Δ | RSS Δ | CPU Δ | Bound met |
|---|---|---|---|---|---|---|
| A·UDP   | NSD       | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·UDP   | Knot Auth | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·TCP   | NSD       | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoT   | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoH2  | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoH3  | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoQ   | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·UDP   | Unbound   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·UDP   | Knot Res  | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·TCP   | Unbound   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoT   | Unbound   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoH2  | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoH3  | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoQ   | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·UDP   | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·UDP   | CoreDNS   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·TCP   | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoT   | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoH2  | dnsdist   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoH3  | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoQ   | (TBD)     | PENDING | PENDING | PENDING | PENDING | PENDING |

The "Bound met" column is set to `parity` for plain-DNS cells when the
PERF-022 four-bound conjunction holds; `exceed` for encrypted cells when
the PERF-024 disjunction holds; `fail` otherwise. A `fail` triggers a
follow-up rmp task with a root-cause analysis (PERF-019 forward
pressure).

---

## 5. Operator workflow for a comparison cycle

```bash
# Boot Heimdall and the reference implementations on distinct loopback
# ports. Example for the authoritative role:
HEIMDALL_AUTH_ADDR=127.0.0.1:5301
NSD_ADDR=127.0.0.1:5302
KNOT_AUTH_ADDR=127.0.0.1:5303
BIND_ADDR=127.0.0.1:5304

# Run the comparator. The script picks up the env vars and runs dnsperf
# against each instance with the same query file + duration.
scripts/bench/compare-reference.sh --role authoritative --transport udp53 \
  --duration 60 --query-file tests/bench/queries.txt

# Repeat for each (role, transport) cell. The aggregate output is a set
# of per-cell JSONs under docs/bench/comparative/<git-sha>/.
```

The cycle is gated on PERF-021 / PERF-023 bounds — failing cells are
captured in the JSON and surfaced as the follow-up rmp tasks.

---

## 6. Refresh cadence

A new comparison cycle is run:

- Before tagging every minor release (v1.x.0).
- After substantial transport-layer changes (TLS stack swap, QUIC
  hardening updates, hyper / quinn major upgrades).
- When a reference implementation ships a major release that changes
  the comparison set.

The "pinned versions" record under `docs/bench/comparative/<git-sha>/`
makes every cycle reproducible.

---

## 7. Open questions

The numerical bounds in §4 are the open question that PERF-019..028
deferred. They are resolved by running the comparison cycle on
reference hardware (PERF-011..012, PERF-029) with the pinned reference
implementations, not by this document.
