# Heimdall — multi-stage hardened OCI container image.
# Implements ENV-026, ENV-033, and ENV-063 through ENV-070 from
# specification/009-target-environment.md §2.20.
#
# Stage 1 (builder): compiles heimdall and heimdall-probe as statically linked
#   musl binaries and strips the debug symbols.
# Stage 2 (final): gcr.io/distroless/static-debian12 (nonroot variant),
#   pinned by SHA-256 digest per ENV-044 / ENV-070.
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64,linux/riscv64 -t heimdall:local .
#
# Run:
#   docker run --rm -p 1053:53/udp -p 1053:53/tcp heimdall:local

# ── Stage 1: builder ──────────────────────────────────────────────────────────
# rust:slim gives us rustup + cargo; the nightly toolchain declared in
# rust-toolchain.toml is downloaded automatically by cargo on first use.
FROM rust:slim-bookworm AS builder

WORKDIR /src

# Install the musl cross-compilation linker for static builds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy rust-toolchain.toml first so rustup installs the correct nightly channel
# before we add the musl targets for that toolchain.
COPY rust-toolchain.toml ./
RUN rustup show \
    && rustup target add \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-musl \
        riscv64gc-unknown-linux-musl

# Copy remaining manifest files to leverage Docker layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# SOURCE_DATE_EPOCH is set from `git log -1 --format=%ct HEAD` by the CI
# workflow (ENV-067) to ensure the embedded build timestamp is deterministic.
# A value of 0 is acceptable for local developer builds but MUST NOT be
# published as an official release artefact (ENV-067).
ARG SOURCE_DATE_EPOCH=0

# TARGETARCH is injected by docker buildx for multi-arch builds.
ARG TARGETARCH

RUN set -ex; \
    case "$TARGETARCH" in \
        amd64|"")  TARGET=x86_64-unknown-linux-musl ;; \
        arm64)     TARGET=aarch64-unknown-linux-musl ;; \
        riscv64)   TARGET=riscv64gc-unknown-linux-musl ;; \
        *)  echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        cargo build --locked --release --target "$TARGET" \
            -p heimdall -p heimdall-probe; \
    strip "target/${TARGET}/release/heimdall"; \
    strip "target/${TARGET}/release/heimdall-probe"; \
    cp "target/${TARGET}/release/heimdall"       /heimdall; \
    cp "target/${TARGET}/release/heimdall-probe" /heimdall-probe

# ── Stage 2: final (distroless static — nonroot) ──────────────────────────────
# Base image is pinned by SHA-256 digest (ENV-044, ENV-070).
# To update: pull the image, verify the diff with the supply-chain audit
# described in ENV-044, then replace the digest below.
#
# gcr.io/distroless/static-debian12:nonroot — multi-arch manifest digest
# (amd64 + arm64); update on each distroless release after a supply-chain audit.
FROM gcr.io/distroless/static-debian12@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1 AS final

# Copy only the stripped static binaries — no shell, no extras (ENV-026).
COPY --from=builder /heimdall       /usr/sbin/heimdall
# heimdall-probe: DNS health-check binary (ENV-065).
COPY --from=builder /heimdall-probe /usr/local/bin/heimdall-probe

# Operator-provided configuration; mount a volume or ConfigMap in production.
COPY contrib/heimdall.toml.example /etc/heimdall/heimdall.toml

# Non-root user: UID/GID 65532 (nonroot in distroless) — ENV-064.
USER nonroot:nonroot

# DNS and encrypted-transport ports.
# Ports < 1024 require CAP_NET_BIND_SERVICE; use --cap-add in production.
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp

# OCI image labels — static subset (ENV-066).
# Build-time labels (revision, created, version) are injected by the CI
# workflow (.github/workflows/release-container.yml) via --label.
LABEL org.opencontainers.image.title="Heimdall"
LABEL org.opencontainers.image.description="High-performance, security-focused DNS server"
LABEL org.opencontainers.image.source="https://github.com/FlavioCFOliveira/Heimdall"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="FlavioCFOliveira"

# Health check: heimdall-probe issues GET /healthz to the observability endpoint
# (127.0.0.1:9090 by default) and exits 0 on HTTP 200 (ENV-065).
HEALTHCHECK --interval=10s --timeout=2s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/heimdall-probe"]

# Single entry point; operator overrides CMD to change subcommand or config
# path (ENV-063).
ENTRYPOINT ["/usr/sbin/heimdall"]
CMD ["start", "--config", "/etc/heimdall/heimdall.toml"]
