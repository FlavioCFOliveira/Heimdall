# Contributing to Heimdall

Thank you for your interest in contributing. This document explains how to set up,
work with, and submit changes to the Heimdall codebase.

## Before you start

Read [`CLAUDE.md`](CLAUDE.md) for the project's core principles (security is
non-negotiable; performance is the primary guide; "Assume Nothing"). Every contribution
is expected to uphold those principles without exception.

Read [`specification/`](specification/) to understand what has been decided and why.
The specification is the source of truth for requirements. If something is not in the
specification, it is not a requirement — ask before building it.

## Setting up the development environment

You need the current stable Rust toolchain (the MSRV is always the latest stable `rustc`):

```
rustup update stable
```

Clone and build:

```
git clone https://github.com/FlavioCFOliveira/Heimdall.git
cd Heimdall
cargo build
cargo test
```

For Tier 2 checks that require nightly:

```
rustup toolchain install nightly
rustup component add miri --toolchain nightly
```

## Workflow

All work follows this order without exception (per [`CLAUDE.md`](CLAUDE.md)):

1. **Specify** — ensure the change is grounded in the specification. If you are adding
   behaviour not covered by an existing requirement, open an issue first.
2. **Implement** — write the code strictly according to the specification.
3. **Test** — unit, integration, and property tests as appropriate. No step is optional.
4. **Document** — update any documentation that reflects the changed behaviour.

## Branch and commit conventions

Work on a short-lived branch off `main`:

```
git checkout -b feat/your-feature-name
```

Commits on the branch and the final squashed commit on `main` must follow
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>): <subject>
```

Permitted types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`.

Recommended scopes align with the Cargo workspace layout:
`core`, `runtime`, `roles`, `bin`, `ci`, `spec`, `adr`, `deps`.

Breaking changes must use the `!` suffix or a `BREAKING CHANGE:` footer.

CI enforces commit conventions on every pull request.

## Adding a dependency

Every new external crate requires an Architecture Decision Record (ADR) reviewed and
approved before the dependency is committed (ENG-008..016). The ADR must document:

- The problem the dependency solves and alternatives considered.
- Its audit trail (`cargo-vet`, CVE history, RustSec advisories, maintenance activity).
- Licence compatibility with MIT.
- `unsafe` footprint.
- Supply-chain trust chain.

No pull request introducing a dependency without an accompanying ADR will be merged.

## Unsafe code

Every crate defaults to `#![deny(unsafe_code)]`. Introducing `unsafe` in a crate requires:

- `#[allow(unsafe_code)]` at the narrowest possible scope (per-module or per-item, never
  at the crate root).
- A `// SAFETY:` comment immediately before every `unsafe` block.
- A `# Safety` section in the doc comment of every `unsafe fn`.
- A dedicated ADR if the unsafe pattern is not already covered by an existing ADR.

See ENG-017..022 in the specification for full requirements.

## CI gates

Your pull request must pass all Tier 1 and Tier 2 CI gates before it can be merged:

- `cargo build` — debug and release, Linux and macOS.
- `cargo test` — full test suite.
- `cargo fmt -- --check` — formatting against `rustfmt.toml`.
- `cargo clippy -- -D warnings` — with workspace lint configuration.
- `cargo deny check` — dependency licence, advisory, and ban policy.
- `cargo audit` — RustSec advisory database.
- `cargo vet` — supply-chain audit trail.
- `cargo doc --no-deps` — documentation build.
- Conventional Commit lint — commit message format.
- proptest smoke, fuzz smoke, loom, bench regression (Tier 2).

Run Tier 1 locally before pushing:

```
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test --locked
cargo doc --no-deps --locked
```

## Code review

All pull requests require at minimum two maintainer approvals for source code changes,
or one maintainer approval for documentation and specification changes. Critical paths
(unsafe, cryptographic, DNSSEC, parsers, CI/build infrastructure) require two code-owner
approvals. See [`GOVERNANCE.md`](GOVERNANCE.md) and the specification (ENG-076..089).

Reviewers are assigned automatically by GitHub from [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Security issues

Do not open a public issue for security-sensitive reports. See [`SECURITY.md`](SECURITY.md)
for the coordinated-disclosure process.

## Licence

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE) that covers the project.
