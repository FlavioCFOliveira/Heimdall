# OSS-Fuzz Dockerfile for the Heimdall project.
#
# Follows https://google.github.io/oss-fuzz/getting-started/new-project-guide/
# for Rust projects.
#
# The base image provides:
#   - Clang + LLD for sanitiser instrumentation
#   - cargo-fuzz (installed by the base image or by build.sh)
#   - RUSTFLAGS set by the OSS-Fuzz harness for coverage / sanitiser builds

FROM gcr.io/oss-fuzz-base/base-builder-rust:latest

# Clone the project source into the expected location.
RUN git clone --depth=1 https://github.com/FlavioCFOliveira/Heimdall.git /src/heimdall

# Install a recent stable Rust toolchain that supports the workspace edition.
# The exact version is pinned in rust-toolchain.toml inside the repository.
RUN rustup toolchain install stable

WORKDIR /src/heimdall

COPY build.sh $SRC/
