# Test conventions

> Status: required reading for anyone writing E2E tests.
> Anchors: Sprint 68 task #685 (port-reservation TOCTOU close).

This document describes the conventions that integration tests must follow
when they spawn a `heimdall` subprocess. The most important rule is the
port-reservation pattern: tests **must** use
[`reserve_loopback_pair`](../../crates/heimdall-e2e-harness/src/lib.rs) (or
one of the `TestServer::start_*` convenience constructors, which use it
internally) instead of allocating ports ad hoc.

## Why port reservation matters

The previous helper, `free_port()`, bound port `0` on a TCP socket, read the
kernel-assigned port, dropped the socket and returned the port. The daemon
would then `bind(2)` on the same port a few milliseconds (sometimes a few
hundred milliseconds) later. Between drop and bind, any other process —
including another concurrent test on the same host — could grab the port,
causing the daemon to fail with `EADDRINUSE` or, worse, causing a flaky
intermittent test where the daemon binds but on a port a different process
is also using.

The CI mitigation was `cargo test -- --test-threads=1`, which serialises
test threads inside a single binary. This is correct but slow: on an
8-core runner the suite runs ~3-4× longer than it has to, and the
constraint is process-local — two concurrent `cargo test` invocations on
the same host still race.

## The reservation pattern

[`reserve_loopback_pair`](../../crates/heimdall-e2e-harness/src/lib.rs)
returns a [`PortReservation`](../../crates/heimdall-e2e-harness/src/lib.rs)
that:

1. Holds **four** sentinel sockets — UDP + TCP for the DNS port and UDP +
   TCP for the observability port — on `127.0.0.1`. The kernel will not
   hand out those ports to any other process while the sentinels are alive.
2. Holds the **host-wide spawn lock** (`flock(2)` on
   `/tmp/heimdall-test-spawn.lock`). The lock is shared across every test
   binary running on the host: only one reservation across the whole host
   can be in the "release-sentinels → daemon-bind → `/readyz` is 200"
   window at any time. The lock is acquired with cross-process semantics
   via `flock(2)` and with cross-thread semantics inside a single process
   via a refcounted `Mutex`, so two reservations in the same test (e.g.
   primary + secondary in a replication test) share the kernel flock
   correctly.

The recommended call sequence is:

```rust
use heimdall_e2e_harness::{TestServer, config, reserve_loopback_pair};

// 1. Reserve ports and acquire the host-wide spawn lock.
let mut reservation = reserve_loopback_pair();
let dns_port = reservation.dns_port;
let obs_port = reservation.obs_port;

// 2. Build the TOML config using the reserved ports.
let toml = config::minimal_recursive(dns_port, obs_port);

// 3. Release the sentinel sockets immediately before spawning the daemon.
//    The spawn lock is STILL HELD at this point.
reservation.release_sockets();

// 4. Spawn the daemon and wait for /readyz.
let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
    .wait_ready(Duration::from_secs(5))
    .expect("server did not become ready");

// 5. Drop the reservation: this releases the spawn lock and lets the next
//    test on the host proceed.
drop(reservation);

// 6. Use the server normally.
```

### Drop order

- `release_sockets` must be called **immediately before** `start_with_ports`.
  Any work done between the two extends the bind window for no benefit.
- The full `PortReservation` must be dropped **after** `/readyz` has
  returned 200. Dropping it earlier exposes the new TOCTOU window again.
- A reservation that is never dropped will deadlock every other Heimdall
  test on the host until the test process exits. This is loud and
  obvious: tests will hang at `reserve_loopback_pair` waiting for the
  lock.

### Two reservations in the same test

Some tests need two daemons that must be configured to point at each other
(e.g. AXFR primary + secondary). The pattern is to call
`reserve_loopback_pair` twice **before either daemon spawns**, build both
TOMLs naming the cross-references, then `release_sockets` on both and
spawn both servers:

```rust
let mut primary_res = reserve_loopback_pair();
let mut secondary_res = reserve_loopback_pair();
// ... build both TOMLs ...
secondary_res.release_sockets();
primary_res.release_sockets();
let secondary = TestServer::start_with_ports(..)
    .wait_ready(..).expect("...");
let primary = TestServer::start_with_ports(..)
    .wait_ready(..).expect("...");
drop(secondary_res);
drop(primary_res);
```

The two reservations share the same underlying `flock(2)` via the
in-process refcount, so this does **not** deadlock.

## When to use `free_port()` instead

The legacy `free_port()` function is preserved as a thin shim around
`reserve_loopback_pair()` that returns a single port and immediately
drops the reservation. It is appropriate **only** when:

- You need a single port for a non-daemon use (e.g. an in-test
  `SlowDnsServer` UDP listener that you bind yourself), and
- You bind that port **immediately** after the call.

For anything that spawns the `heimdall` binary, use
`reserve_loopback_pair()` directly or one of the `TestServer::start_*`
convenience constructors. The convenience constructors (e.g.
`start_auth`, `start_recursive`, `start_forwarder_dot`) already use
`reserve_loopback_pair` internally — no migration is required at those
call sites.

## CI parallelism

With the reservation pattern in place, `cargo test` may run with the
default `--test-threads=N` for `N > 1`. The Tier 2 CI workflow
(`.github/workflows/ci-tier2.yml`) no longer passes `--test-threads=1`.
Tier 1 still passes `--test-threads=1` while the remaining tests are
migrated, but the constraint will be relaxed once the migration is
complete.

## Environment overrides

The lock file path defaults to `/tmp/heimdall-test-spawn.lock`. Set
`HEIMDALL_TEST_SPAWN_LOCK` to override it — useful for sandboxed CI
environments where `/tmp` is read-only or shared with adversarial
workloads.

## Pitfalls and FAQ

**Q: My test calls `reserve_loopback_pair` but the second test in the
same binary hangs.** A: You did not drop the first `PortReservation`.
Drop is required before the next reservation can complete.

**Q: My test calls `release_sockets` but the daemon still fails with
`EADDRINUSE`.** A: Something else on the host is using the port — most
likely an unrelated background process. The reservation pattern closes
the in-test TOCTOU window but cannot prevent an external process from
sniping the port between `release_sockets` and `bind(2)`. Retrying the
test should usually succeed; if it does not, the host is contaminated.

**Q: Can I hold the reservation across `wait_ready` for safety?** A:
Yes — this is the recommended pattern. The reservation holds the spawn
lock, blocking other tests, only until you drop it.

## Waiting for things to happen: `poll_until` vs `wait_bounded`

> Anchor: Sprint 68 task #684 (replace coordination sleeps with poll-until).

The harness exposes four wait primitives that supersede every ad-hoc
`std::thread::sleep` / `tokio::time::sleep` between an action and an
assertion. Pick the right one per the **observability** of the thing
being awaited.

### `poll_until` / `poll_until_async` — eventual consistency

Use when the assertion checks **a positive state change** (counter
incremented, socket bound, log line appeared) and the change can be
re-sampled cheaply. The helper re-evaluates a closure every `interval`
(5 ms by default) until it returns `Some(T)` or a per-test deadline
elapses; on timeout it panics with the descriptive string supplied by
the caller.

```rust
let body = heimdall_e2e_harness::poll_until(
    "cache_hits=1 and cache_misses=1 for role=recursive",
    std::time::Duration::from_secs(5),
    std::time::Duration::from_millis(10),
    || {
        let body = fetch_metrics(server.obs_addr());
        let hits = parse_labeled_counter(&body, "heimdall_cache_hits_total", "recursive");
        let misses = parse_labeled_counter(&body, "heimdall_cache_misses_total", "recursive");
        (hits == 1 && misses == 1).then_some(body)
    },
);
```

Fast path converges in microseconds; the per-test deadline is the only
upper bound. This pattern simultaneously **shortens fast runs** and
**closes the flake window on loaded CI runners**.

### `poll_until_or_timeout` — `Option<T>` flavour

Same algorithm, but returns `None` on timeout instead of panicking. Use
it for helpers whose callers need to express "did it succeed?" as a
boolean (typical for legacy `wait_for_<port>` / `poll_serial`
predicates).

### `wait_bounded` / `wait_bounded_async` — deliberate fixed waits

Use when **none of the above apply** because either:

1. **No observable signal exists** (e.g. the daemon was spawned without
   an observability port, so `/readyz` cannot be polled; or the test
   awaits a stderr flush that is not visible while the daemon runs).
2. **The assertion is negative** ("counter must NOT have incremented",
   "drain must NOT return") — a poll-until-condition helper would
   terminate at the first probe and miss a delayed change.

Every call passes a `reason: &'static str` documenting **why** the wait
is necessary (typically a spec id such as `ROLE-005`, `OPS-004`,
`PROTO-038`). The reason is discarded at runtime; the compiler enforces
that it is supplied, so the rationale lives next to the wait.

```rust
heimdall_e2e_harness::wait_bounded(
    "ROLE-005 negative: recursive queries_total MUST NOT increment within 100 ms \
     when the recursive role is disabled",
    std::time::Duration::from_millis(100),
);
```

### Anti-pattern: raw `sleep` between action and assertion

Banned. The CI policy enforces `rg -n 'thread::sleep|tokio::time::sleep'
crates/heimdall*/tests/ crates/heimdall-integration-tests/src/` returns
zero matches outside of `wait_bounded` / `poll_until` / synthetic
load-generator pacing. A raw `sleep` is either too short (CI flake) or
too long (suite slowdown); both failure modes are fixed by selecting
the appropriate helper.
