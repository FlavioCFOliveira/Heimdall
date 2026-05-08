# ADR-0065: `io_uring` fast path for UDP and TCP listeners

**Status.** Proposed (Sprint 61, tasks #651 and #652).

**Date.** 2026-05-08.

**Specification.** PERF-001..009 in
`specification/008-performance-targets.md` require Heimdall to compete
with NSD/Knot Auth on plain DNS (PERF-021 parity bound). On Linux 5.19+,
`io_uring` is the single largest available lever for plain-DNS
throughput on the auth UDP cell.

---

## 1. Context

The runtime detects `io_uring` availability today (`crates/heimdall-
runtime/src/runtime.rs`) but every listener path still uses
`tokio::net::UdpSocket` / `tokio::net::TcpListener` over epoll. The 2026-
05-08 maturity audit identified this as a measurable performance gap:
plain-DNS QPS on the auth UDP cell is bounded by the per-syscall cost
of `recvmsg`/`sendmsg`, which `io_uring` amortises through batched SQEs
and registered buffers.

Two paths are available for an `io_uring`-backed listener in Rust:

1. **`tokio-uring`** — a separate runtime that owns its own current-
   thread reactor. Requires the listener to opt into `tokio-uring`'s
   spawn primitive and gives up `tokio::net` interop on the I/O surface.
2. **`rustix` direct submission queue** — file-descriptor-level
   submission via the `rustix-uring` crate, integrated into the existing
   tokio runtime via `tokio::io::Interest`. More invasive but preserves
   the rest of the listener machinery.

A third option — waiting for `tokio` to gain native `io_uring` support —
is not yet credible upstream as of 2026-04.

## 2. Decision

Adopt **option 1** (`tokio-uring`) for both UDP and TCP listeners on
Linux ≥ 6.0. Rationale:

- `tokio-uring` is more mature than `rustix-uring`'s integration story
  and is actively maintained by the Tokio project.
- The listener is the only place in the runtime that needs the
  `io_uring` reactor; the rest of the runtime (cache, admission, drain,
  observability) keeps the standard tokio runtime.
- Co-existence is supported: spawn the `tokio-uring` reactor in a
  dedicated thread and bridge query handoff via channels.

Constraints:

- Kernel ≥ 6.0 required (older kernels lack the multishot accept
  primitive that the TCP path leverages).
- Fallback to the existing tokio/epoll listener on init failure or
  feature-flag disabled is mandatory.
- Listener selection happens at boot per the existing
  `RuntimeFlavour` enum (`runtime.rs`); no per-query branch.

## 3. Implementation plan

The implementation is staged across Sprint 61 (this sprint, scaffolding
+ design) and a follow-up sprint that runs the listener on reference
hardware and measures the gain:

### 3.1 Sprint 61 deliverable (this ADR)

- Document the design (this ADR).
- Refine the `runtime::detect_io_uring()` predicate to require kernel
  ≥ 6.0 (currently ≥ 5.10) so the gate matches the implementation
  target.
- Reserve the `IoUringUdpListener` and `IoUringTcpListener` type names
  in `crates/heimdall-runtime/src/transport/` so the binary crate's
  listener-bind step has a clear extension point.

### 3.2 Follow-up sprint deliverable

- Implement `IoUringUdpListener` against `tokio-uring`'s `UdpSocket`
  with `submit_recvmsg_batch` (when stable) or sequenced `recv_from`
  on a dedicated reactor thread. Decode and dispatch into the
  admission pipeline as today.
- Implement `IoUringTcpListener` against `tokio-uring`'s `TcpListener`
  with `IORING_OP_ACCEPT_MULTI_SHOT` and registered buffers for
  `recv`. TLS continues to live in user space (rustls); io_uring only
  handles the underlying socket I/O.
- Add a criterion benchmark comparing pooled io_uring UDP vs epoll
  UDP on the auth-UDP cell. Acceptance: ≥ 30 % QPS improvement on
  reference hardware (PERF-011).
- Wire the existing capture-baselines.sh to capture the io_uring cell
  separately so the regression gate (#646) tracks both.

## 4. Operational impact

- The listener selection is opaque to operators: the CLI flag
  `--io-uring` continues to exist as today, with the same semantics
  (auto-detect on Linux ≥ 6.0; fall back to epoll otherwise).
- Crash-handling and metrics surface remain identical (the
  observability server emits the same per-listener counters
  regardless of backend).
- Drain semantics are preserved: the io_uring listener subscribes to
  the same `Drain` primitive and stops accepting work on
  `is_draining()`.

## 5. Rejected alternatives

- **`rustix-uring` direct integration.** More flexible but requires
  custom integration with tokio's reactor and more `unsafe` code
  surface than `tokio-uring`. Not justified for the listener-only
  scope.
- **Custom epoll batching (`recvmmsg`/`sendmmsg`).** Provides ~20 %
  improvement vs single-syscall recv but is dominated by `io_uring`'s
  zero-copy path on kernels ≥ 6.0. Not pursued.
- **Native tokio `io_uring`.** Not yet stable upstream as of 2026-04.
  Will revisit when it lands (potential migration path that
  eliminates the dual-runtime split).

## 6. Open questions

- Reference QPS gain: deferred to PERF-011 hardware measurement.
- aarch64 listener support: tokio-uring supports aarch64 Linux ≥ 6.0
  (Graviton3+); riscv64 is gated on tokio-uring's port (currently
  WIP upstream, tracked by an open RUSTSEC advisory check).
- TLS interaction on TCP: rustls runs in user space and consumes
  buffers from the io_uring read. We need to confirm the buffer
  ownership model does not require additional copies relative to
  the epoll path.
