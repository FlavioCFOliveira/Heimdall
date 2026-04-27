# Heimdall — macOS Developer Quickstart

**Target**: macOS on Apple Silicon (aarch64), developer / testing use only.

macOS is a **development-only** platform (ENV-009). It is **not supported for
production use**. Production deployments must use Linux (with systemd and
seccomp-bpf) or OpenBSD (with pledge and unveil).

**See also**: [Operator Manual](../operator-manual.md),
[Configuration Reference](../configuration-reference.md).

---

## 1. Prerequisites

- macOS 14 (Sonoma) or later on Apple Silicon (aarch64).
- Rust toolchain: `rustup` and stable Rust (see `rust-toolchain.toml` for
  the exact version).
- Xcode command-line tools: `xcode-select --install`.

---

## 2. Build from source

```sh
# Clone the repository
git clone https://github.com/FlavioCFOliveira/Heimdall.git
cd Heimdall

# Build a release binary
cargo build --release

# The binary is at:
ls -la target/release/heimdall
```

To run clippy and tests as a sanity check before deployment:

```sh
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

---

## 3. Configure

Copy the example configuration and edit as needed:

```sh
mkdir -p /usr/local/etc/heimdall
cp contrib/heimdall.toml.example /usr/local/etc/heimdall/heimdall.toml
```

Minimum developer configuration (listens on a non-privileged port to avoid
requiring root):

```toml
[network]
listen = ["127.0.0.1:1053"]

[role]
mode = "recursive"

[log]
level = "debug"
format = "text"
```

On macOS, binding to ports 53 or 853 requires root. For development, use
ports above 1024 (`127.0.0.1:1053`, `127.0.0.1:8853`).

---

## 4. Run under the macOS sandbox

The project ships a `sandbox-exec` profile for development-level confinement
(THREAT-030, THREAT-031, ADR-0023). This is a SHOULD-level control; it is
not a substitute for the production-grade hardening on Linux or OpenBSD.

```sh
sandbox-exec -f contrib/macos/heimdall.sb \
    ./target/release/heimdall \
    --config /usr/local/etc/heimdall/heimdall.toml
```

**Note**: Apple has soft-deprecated `sandbox-exec` in recent macOS releases.
The mechanism continues to function. Review the sandbox profile annually or
whenever a new macOS major release is published (THREAT-106).

---

## 5. Verify

```sh
# Test DNS resolution
dig @127.0.0.1 -p 1053 example.com A +short

# Check observability endpoint (default port 8080)
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/version
```

---

## 6. Reload

SIGHUP reloads the configuration (OPS-001 through OPS-006):

```sh
kill -HUP $(pgrep heimdall)
```

Or via admin-RPC:

```sh
echo '{"cmd":"reload"}' | nc -U /var/run/heimdall/admin.sock
```

---

## 7. macOS System Integrity Protection (SIP)

SIP does not affect running Heimdall directly. However, if you need to bind to
protected ports (below 1024) without root, you can use `launchd` or the
`pf` packet filter to redirect port 53 to 1053. For development, using
unprivileged ports is simpler.

---

## 8. Developer tools

Useful commands during development:

```sh
# Run the full CI check locally
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo doc --no-deps --all-features

# Run the hardening drift check
cargo run --locked -p heimdall-ci-tools

# Run benchmarks
cargo bench --locked -p heimdall-bench
```
