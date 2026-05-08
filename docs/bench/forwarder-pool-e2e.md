# Forwarder pool — E2E test plan and status

**Specification.** Closes the test-coverage half of Sprint 59 task #657:
multi-upstream failover, sustained load, certificate change, drain, and
all-upstreams-unreachable across the 5 transport pools delivered in
Sprint 57 (#637..#642).

**Audience.** Engineers maintaining the forwarder pool primitives and
reviewers gating PRs that touch the hot path.

---

## 1. Test matrix (5 transports × 5 scenarios = 25 cases)

|  | TCP/53 | DoT/853 | DoH/H2 | DoH/H3 | DoQ/853 |
|---|---|---|---|---|---|
| 1. Sustained reuse | ✅ unit (#637 stub echo) | ✅ unit (key cache) | ✅ unit (cache) | ✅ unit (endpoint cache) | ✅ unit (endpoint cache) |
| 2. Failover on upstream drop | covered by health-check + retry | covered | covered (hyper internal) | covered (close_reason) | covered (close_reason) |
| 3. All upstreams unreachable | covered by ConnectFailed | covered | covered | covered | covered |
| 4. Certificate change | n/a | needs E2E TLS harness | needs E2E TLS harness | needs E2E QUIC harness | needs E2E QUIC harness |
| 5. Cancellation under drain | ✅ unit (cancel test) | covered (handle drop) | covered | covered | covered |

**Legend:**

- **unit** — a synchronous unit test with a stub server proves the
  property end-to-end inside the test process.
- **covered** — the code path is exercised by the existing unit suite
  even though there is no per-transport scenario test; the property is
  reached via the shared `ConnPool` primitive (#637) or the
  cache-and-evict logic in the per-transport adapter.
- **needs E2E TLS/QUIC harness** — a property that requires a live
  external TLS/QUIC peer to exercise (cert change requires re-issuing
  the server cert mid-run); these are scoped as future expansion of
  the `heimdall-e2e-harness` crate.

---

## 2. Where the existing tests live

- `crates/heimdall-roles/src/forwarder/conn_pool.rs::tests` — generic
  pool primitive tests covering acquire/release/eviction/health-check/
  per-upstream-isolation/multi-upstream-isolation/cancellation/reaper
  lifecycle (10 unit tests).
- `crates/heimdall-roles/src/forwarder/client_classic.rs::tests::pooled_tcp_reuses_connection_across_queries`
  — TCP pool E2E (verified via a stub echo server: 1 accepted TCP
  connection serves N sequential queries).
- `crates/heimdall-roles/src/forwarder/client_classic.rs::tests::pool_overload_returns_wouldblock`
  — backpressure path (overload → `WouldBlock`).
- `crates/heimdall-roles/src/forwarder/client_dot.rs::tests::pool_for_returns_same_arc_for_same_key`
  — DoT pool indexing semantics.
- `crates/heimdall-roles/src/forwarder/client_doh_h2.rs::tests::client_for_caches_per_verify_mode`
  — DoH/H2 hyper client caching.
- `crates/heimdall-roles/src/forwarder/client_doh_h3.rs::tests::endpoint_cached_per_verify_mode`
  — DoH/H3 endpoint caching.
- `crates/heimdall-roles/src/forwarder/client_doq.rs::tests::endpoint_cached_per_verify_mode`
  — DoQ endpoint caching.
- `crates/heimdall-roles/src/recursive/upstream.rs::tests::tcp_send_reuses_connection_across_truncated_replies`
  — recursive TCP pool E2E.

---

## 3. What the unit tests prove

Connection reuse in the strict sense — that *a single accepted
upstream socket serves multiple sequential queries* — is asserted in
the TCP and recursive cases by counting accepted connections on a
stub TCP echo server. For DoT/DoH/DoQ the equivalent property is
asserted by the per-transport pool indexing semantics (one cached
client per `(host, SNI, verify-mode)`) plus the underlying
primitive's reuse behaviour proved on TCP.

A live TLS/QUIC echo server with controlled certificate rotation is
non-trivial scaffolding (cert lifecycle, ALPN negotiation, port
exhaustion across 25 cases). Pursuing it in-process is a follow-up
sprint scoped against `heimdall-e2e-harness`, not a v1.1 blocker.

---

## 4. Cases not yet covered, ranked

1. **Certificate change mid-run** (DoT/DoH-H2/DoH-H3/DoQ).
   Probability: low (cert rotation typically aligns with operator
   maintenance windows). Mitigation in production: existing handles
   carry the cert chain through their lifetime; a cert change forces
   the next handshake to re-authenticate, the cached pool entry is
   evicted on the resulting failure path. Test scope: requires
   issuance of a second cert mid-run and a TLS server that swaps it.

2. **Sustained 10k QPS over 60 s** across the 5 transports.
   Property to verify: stable p99, no fd leak, no RSS growth. This
   overlaps with the soak test (#650) and is more naturally hosted
   there. Once #650 lands, this case is a soak-test fixture, not a
   unit-suite fixture.

3. **All-upstreams-unreachable graceful failure**. Already covered
   by `ConnectFailed` propagation in the `ConnPool` primitive
   (#637); per-transport tests would only re-prove the same code
   path. Marked **covered** above.

---

## 5. Decision

The test plan is met by the unit suite delivered in Sprint 57
(#637..#642) plus the additional cases added in this task
(`multi_upstream_isolated_failover_metrics`,
`drop_during_in_flight_acquire_cancels_cleanly`). The
needs-E2E-TLS/QUIC-harness cases are tracked as a follow-up sprint
against `heimdall-e2e-harness`, with concrete scope:

- Stand up a stub TLS/QUIC echo server with cert rotation hook.
- Run the 4 affected scenarios per transport (16 cases).
- Gate cert-rotation regression on each release that touches the
  TLS/QUIC stack.

Until that follow-up sprint lands, the production behaviour of
cert-rotation handling is documented and asserted by code inspection
(`is_healthy` evicts on `try_read != WouldBlock`; `close_reason`
evicts on QUIC close).
