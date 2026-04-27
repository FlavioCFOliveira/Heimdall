#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# run_forwarder_ref.sh — Reference benchmark runner stub for forwarder and
# encrypted-DNS servers (PERF-025..028).
#
# Compares Heimdall (forwarder role, DoT/DoH) against dnsdist, cloudflared,
# and Unbound using flamethrower for load generation.
#
# Requirements:
#   - dnsdist, cloudflared, unbound binaries in PATH
#   - flamethrower binary in PATH
#   - TLS certificates in $CERT_DIR (default: ./testdata/certs/)
#
# This is a stub.  Fill in the actual load-generation and result-collection
# logic when a dedicated benchmarking host is provisioned.
set -euo pipefail

echo "Reference benchmark runner: requires dnsdist, cloudflared, and unbound binaries in PATH"
echo "Load generator: flamethrower (https://github.com/DNS-OARC/flamethrower)"
echo "PERF-025: dnsdist reference — not yet implemented"
echo "PERF-026: cloudflared reference — not yet implemented"
echo "PERF-027..028: Unbound DoT/DoH reference — not yet implemented"
exit 0
