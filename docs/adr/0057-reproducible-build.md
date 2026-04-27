# ADR-0057: Reproducible Builds

**Status:** Accepted  
**Date:** 2026-04-27  
**References:** THREAT-012, ENG-070  
**Deciders:** Lead maintainer

---

## Context

THREAT-012 mandates reproducible builds so that any third party can independently verify
that a published binary was produced from the declared source at the declared commit.
ENG-070 adds a Tier 3 nightly job that rebuilds Heimdall on a fresh runner and compares
the output byte-for-byte against the reference artefact.

Without reproducibility, a signed artefact provides integrity only for that exact signing
run — not assurance that the binary corresponds to the source code.  Reproducibility closes
this gap and is a prerequisite for SLSA Build Level 2+.

---

## Decision

Heimdall releases are built in a reproducible manner by enforcing the following constraints.

### Pinned Rust Toolchain

A `rust-toolchain.toml` file at the repository root pins the exact Rust toolchain version:

```toml
[toolchain]
channel = "1.87.0"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"]
```

The toolchain version is updated only via an ADR or a deliberate upgrade PR, never by
floating to `stable`.

### Deterministic Compiler Flags

The release profile in `Cargo.toml` is locked to deterministic flags:

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "none"          # strip done explicitly post-build for reproducibility
panic = "abort"
overflow-checks = false
```

`codegen-units = 1` eliminates non-determinism from parallel codegen.  `strip = "none"`
keeps the `.debug_info` section intact for the reproducibility comparison; a separate
stripped binary is produced for distribution.

### Source Date Epoch

The `SOURCE_DATE_EPOCH` environment variable is set to the Unix timestamp of the HEAD
commit:

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
```

This propagates into any build tool that respects SOURCE_DATE_EPOCH (cargo, linkers,
container image layers), eliminating timestamp-derived non-determinism.

### Locked Dependencies

`Cargo.lock` is committed and the build always runs with `--locked`:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

### Fixed Build Environment

The release build runs inside a container image pinned by digest:

```
ghcr.io/flaviocfoliveira/heimdall-build:sha256-<digest>
```

The image contains the pinned Rust toolchain, the musl cross-compilation target, and the
exact versions of build-time tools (linker, assembler).  The image digest is committed to
`.github/workflows/release.yml` and updated only deliberately.

### Linker Flags

The linker is invoked with `-Wl,--build-id=none` to suppress non-deterministic build IDs:

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-musl]
rustflags = ["-C", "link-arg=-Wl,--build-id=none"]
```

---

## Verification Procedure (Tier 3)

The nightly reproducible-build job:

1. Checks out the HEAD commit.
2. Sets `SOURCE_DATE_EPOCH` from the commit timestamp.
3. Runs the build inside the pinned container image.
4. Computes `sha256sum` of the output binary.
5. Downloads the reference binary from the most recent Tier 3 artefact store.
6. Asserts byte-for-byte equality:

```sh
sha256sum heimdall-linux-amd64 > current.sha256
sha256sum reference-linux-amd64 > reference.sha256
diff current.sha256 reference.sha256 || { echo "REPRODUCIBILITY FAILURE"; exit 1; }
```

7. On divergence, the job attaches a `diffoscope` report to the run summary for diagnosis.

A third party can reproduce the build by following this procedure with the published
toolchain version, container image digest, and `SOURCE_DATE_EPOCH` value from the release
metadata.

---

## Consequences

### Positive

- A third party can verify that a published binary corresponds to the declared source.
- Reproducibility is a prerequisite for SLSA Build Level 2 and Level 3.
- Nightly divergence detection catches non-determinism introduced by dependency upgrades
  or toolchain changes before they reach a release.

### Negative

- `codegen-units = 1` increases compile time (mitigated by caching in CI).
- The pinned container image digest must be updated whenever the build environment changes.
- Some dependencies (proc macros, build scripts) may introduce non-determinism that is
  difficult to eliminate; these must be diagnosed with `diffoscope` and mitigated
  case by case.

### Neutral

- `strip = "none"` in the release profile means the reference artefact retains debug
  information; the published distribution binary is a separate stripped copy.

---

## Alternatives Rejected

| Alternative | Reason for rejection |
|---|---|
| Floating `stable` toolchain | Non-deterministic across runners; SLSA incompatible |
| `codegen-units` > 1 | Parallel codegen ordering is not guaranteed deterministic |
| No SOURCE_DATE_EPOCH | Timestamps in binaries/archives break byte-for-byte equality |
| Vendored dependencies | Adds significant repository bloat; `--locked` with Cargo.lock is sufficient |
