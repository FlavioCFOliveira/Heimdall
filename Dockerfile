# Heimdall — minimal hardened OCI container image.
# ENV-026, ENV-033: distroless/static base, non-root user, no shell.
#
# Multi-stage build: compile in a Rust toolchain image, copy only the stripped
# binary into the final distroless image.
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t heimdall:local .
#
# Run:
#   docker run --rm -p 1053:53/udp -p 1053:53/tcp heimdall:local

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1.87.0-slim-bookworm AS builder

WORKDIR /src

# Install musl cross-compilation tools.
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*

# Add the musl target for static linking.
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Copy only the files required for dependency resolution first, to leverage
# Docker layer caching.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Build the release binary (statically linked via musl).
# SOURCE_DATE_EPOCH is set from git history at build time for reproducibility;
# the ARG allows the CI to pass the value in.
ARG SOURCE_DATE_EPOCH=0
ARG TARGETARCH

RUN set -ex; \
    case "$TARGETARCH" in \
        amd64)  TARGET=x86_64-unknown-linux-musl ;; \
        arm64)  TARGET=aarch64-unknown-linux-musl ;; \
        *)      echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    cargo build --locked --release --target "$TARGET"; \
    strip "target/${TARGET}/release/heimdall"; \
    cp "target/${TARGET}/release/heimdall" /heimdall

# ── Stage 2: final (distroless static) ───────────────────────────────────────
# gcr.io/distroless/static-debian12 contains:
#   - CA certificates (for DoT/DoH upstream connections)
#   - /etc/passwd and /etc/group with the nonroot user (uid/gid 65532)
#   - No shell, no package manager, no libc
FROM gcr.io/distroless/static-debian12:nonroot AS final

# Copy only the stripped static binary.
COPY --from=builder /heimdall /usr/local/bin/heimdall

# Copy the example configuration.  Operators should mount a real config via
# a volume or ConfigMap.
COPY contrib/heimdall.toml.example /etc/heimdall/heimdall.toml

# Non-root user (uid/gid 65532 = nonroot in distroless).
USER nonroot:nonroot

# DNS ports.  Note: ports < 1024 require CAP_NET_BIND_SERVICE or a host
# network namespace; expose 53 for documentation and use --cap-add in prod.
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp

# OCI image labels.
LABEL org.opencontainers.image.title="Heimdall"
LABEL org.opencontainers.image.description="High-performance, security-focused DNS server"
LABEL org.opencontainers.image.source="https://github.com/FlavioCFOliveira/Heimdall"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="FlavioCFOliveira"

ENTRYPOINT ["/usr/local/bin/heimdall"]
CMD ["--config", "/etc/heimdall/heimdall.toml"]
