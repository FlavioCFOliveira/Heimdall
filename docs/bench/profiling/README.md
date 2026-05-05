# Heimdall CPU profiling methodology

Sprint 50 task #506.

## Overview

CPU profiling runs are captured using
[cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph), which uses
`perf` on Linux and `dtrace` on macOS.  Profiles are taken under steady-state
dnsperf load so that the flamegraph reflects the actual hot path rather than
startup or idle code.

## Running a profile

```bash
# Prerequisites
cargo install flamegraph
# Linux: ensure perf is available and perf_event_paranoid ≤ 1
# sudo sysctl -w kernel.perf_event_paranoid=1

# Start Heimdall (authoritative role)
cargo run --release -p heimdall -- --config contrib/heimdall-auth.toml &

# Capture flamegraph (30-second window, authoritative role)
scripts/bench/profile-flamegraph.sh --role authoritative --duration 30
```

Output SVG is written to `docs/bench/profiling/<role>/<role>-<transport>-<sha>.svg`.

## Interpreting flamegraphs

Open the SVG in a browser.  The x-axis is time (wider = more CPU); the y-axis
is call depth.  Click on a frame to zoom; use the search box to highlight a
function across the entire graph.

Top-10 self-time functions are documented in the `top-functions/` subdirectory,
one file per role per profiling run.

## Stored profiles

| Role | Transport | SHA | Notes |
|---|---|---|---|
| _(none captured yet — requires native Linux perf or macOS dtrace)_ | | | |

Profiles are not committed to the repository (binary SVGs are large).  Only the
`top-functions/` text summaries and the methodology document are committed.

## Anti-patterns to watch for

| Pattern | Signal | Action |
|---|---|---|
| `clone` / `to_owned` in hot path | Wide clone/string frames | Replace with `Cow<'_, str>` or `Arc` |
| `Arc::drop` / reference counting | Wide `drop` frames | Switch to slab or arena allocator |
| `Mutex::lock` / `RwLock::read` | Lock contention visible | Profile with lockstat; consider lock-free |
| `memcpy` from response serialisation | Wide memcpy | Switch to scatter/gather I/O |
| `BTreeMap` in hot lookup | Wide B-tree frames | Replace with `FxHashMap` or trie |
| Excessive system calls | Wide `syscall` frames | Batch I/O; check io_uring path |

Any anti-pattern discovered during a profiling run that is not immediately fixed
MUST be logged as a tracked task in the next sprint backlog.
