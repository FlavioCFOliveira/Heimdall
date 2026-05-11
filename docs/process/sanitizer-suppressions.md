# LLVM sanitizer suppressions policy

> Status: active.
> Anchors: ENG-067/068; Sprint 68 task #682.

The Tier-3 CI pipeline runs the project against three LLVM sanitizers on
every nightly build:

| Sanitizer | What it finds | Scope |
|-----------|---------------|-------|
| AddressSanitizer (ASan) | Out-of-bounds reads/writes, use-after-free, double-free, stack-buffer overflow | All Rust + C code, including ring, aws-lc-sys (when introduced), and any other transitive C dependency |
| ThreadSanitizer (TSan) | Data races on memory accessed without synchronisation | All Rust + C code; complements `loom` which is exhaustive but slow |
| LeakSanitizer (LSan) | Heap allocations that outlive `main()` | All Rust + C code |

These sanitisers cover the FFI surface that `miri` cannot — `miri`'s scope
is `heimdall-core` only, because the runtime/transport crates exercise
network syscalls that miri does not implement. The sanitizers + miri
together form the static-and-dynamic UB defence-in-depth.

## Advisory window

The three sanitizer jobs were introduced on **2026-05-10** as part of
Sprint 68. They are marked `continue-on-error: true` for a 14-day advisory
window so the team can shake out toolchain-level false positives without
blocking PRs:

- Advisory window: **2026-05-10 → 2026-05-24** (inclusive).
- On **2026-05-24** the `continue-on-error` flag MUST be removed from each
  of the three jobs in `.github/workflows/ci-tier3.yml`. Any sanitizer
  detection from that date onward blocks the PR.

A reminder issue is tracked in the issue board with the
`sprint-68-sanitizer-promote` tag. The promotion is a 3-line workflow
edit; it does not require a new PR review cycle if the advisory window
showed zero failures.

## Suppression policy

The project's preferred posture is **no suppressions**: fix the root cause
rather than mask the detection. The only sanctioned suppression categories
are:

1. **Known dependency UB without a usable upstream fix.** When a third-party
   crate has an open issue and a tracked upstream PR, but the fix has not
   yet landed in a released version, a narrowly-scoped suppression MAY be
   added. The suppression entry MUST cite the upstream issue URL.
2. **Toolchain-level false positives.** Some `-Zsanitizer=thread` reports
   on `Atomic*` orderings are false positives caused by the sanitizer
   instrumentation. A suppression here MUST cite the relevant
   `rust-lang/rust` issue.

Every other class of detection — and especially anything in the
`heimdall-*` crates themselves — MUST be fixed.

## Suppression files

When a suppression is sanctioned, add the entry to the corresponding file:

- ASan: `ci/sanitizer-suppressions/asan.txt`
- TSan: `ci/sanitizer-suppressions/tsan.txt`
- LSan: `ci/sanitizer-suppressions/lsan.txt`

The CI step exposes these via the standard `*SAN_OPTIONS` env var:

```sh
ASAN_OPTIONS="$ASAN_OPTIONS:suppressions=ci/sanitizer-suppressions/asan.txt"
TSAN_OPTIONS="$TSAN_OPTIONS:suppressions=ci/sanitizer-suppressions/tsan.txt"
LSAN_OPTIONS="$LSAN_OPTIONS:suppressions=ci/sanitizer-suppressions/lsan.txt"
```

(The suppression files do not exist as of the initial Sprint-68 wiring;
they will be created on demand when the first sanctioned suppression
lands. The CI step references them with the standard syntax above.)

Each entry MUST carry a comment block:

```
# Why: <one-paragraph explanation>
# Tracking: <upstream issue URL or internal ticket>
# Added: <YYYY-MM-DD>
# Review: <YYYY-MM-DD — review date, ≤ 90 days from Added>
race:<symbol-name>
```

The `Review` date is mandatory: a suppression expires after 90 days unless
explicitly re-justified. The expiry is enforced by the
`advisory-waiver-expiry` job in `ci-tier3.yml`.

## Triage path

When a sanitizer detection lands:

1. The CI annotation includes the stack trace; copy it into the issue.
2. Classify per the table above (heimdall code → fix; dependency UB →
   suppression candidate; toolchain false positive → suppression candidate
   with rust-lang issue link).
3. If a fix lands in `heimdall-*`, no further action — the next CI run
   passes.
4. If a suppression is proposed, the PR adding it MUST include a
   sanctioned-category citation and a Review date.

## Why ASan + TSan + LSan (and not just one)

The three sanitizers detect overlapping but distinct classes:

- ASan catches *memory-safety* bugs. Even safe Rust can produce these in
  `unsafe` blocks or via FFI; ASan finds them before they reach prod.
- TSan catches *concurrency* bugs that escape `loom`'s exhaustive search.
  loom proves a small model is race-free; TSan provides empirical
  validation on the real concurrent execution.
- LSan catches *resource leaks*. Heimdall's drain primitive (#664) and
  per-connection JoinSet patterns (#675) are easy to misuse;
  LSan validates that no connection task outlives the supervisor.

Running all three gives empirical UB coverage of the entire workspace
under realistic concurrency, while `miri` provides exhaustive proof for
the core data structures.
