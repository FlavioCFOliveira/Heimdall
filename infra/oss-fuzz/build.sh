#!/bin/bash -eu
#
# OSS-Fuzz build script for the Heimdall DNS server.
#
# Invoked by the OSS-Fuzz infrastructure inside the Dockerfile environment.
# CFLAGS, CXXFLAGS, and RUSTFLAGS are set by the harness to enable the
# requested sanitiser (ASan, MSan, UBSan) and fuzzing engine (libFuzzer,
# AFL++, Honggfuzz).
#
# References:
#   https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#   https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

cd /src/heimdall

# Build all fuzz targets with the OSS-Fuzz harness.
# cargo-fuzz is pre-installed in the base image; it translates the RUSTFLAGS
# environment variable set by the harness into the correct instrumentation flags.
cargo fuzz build --fuzz-dir fuzz \
    fuzz_parse_message \
    fuzz_parse_edns \
    fuzz_zone_parser \
    fuzz_nsec3_hash

# Copy compiled fuzz binaries to $OUT (the OSS-Fuzz output directory).
for target in fuzz_parse_message fuzz_parse_edns fuzz_zone_parser fuzz_nsec3_hash; do
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/${target}" "${OUT}/${target}"
done

# Copy seed corpora to $OUT as <target>_seed_corpus.zip.
for target in fuzz_parse_message fuzz_parse_edns fuzz_zone_parser fuzz_nsec3_hash; do
    corpus_dir="fuzz/corpus/${target}"
    if [ -d "${corpus_dir}" ] && [ "$(ls -A "${corpus_dir}")" ]; then
        zip -j "${OUT}/${target}_seed_corpus.zip" "${corpus_dir}/"*
    fi
done
