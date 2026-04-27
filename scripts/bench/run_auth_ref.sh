#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# run_auth_ref.sh — Reference benchmark runner stub for authoritative DNS
# servers (PERF-020..022).
#
# Compares Heimdall (authoritative role) against NSD, Knot DNS, and BIND 9
# using flamethrower for load generation.
#
# Requirements:
#   - nsd, knot, named binaries in PATH
#   - flamethrower binary in PATH
#   - Appropriate zone files in $ZONE_DIR (default: ./testdata/zones/)
#
# This is a stub.  Fill in the actual load-generation and result-collection
# logic when a dedicated benchmarking host is provisioned.
set -euo pipefail

echo "Reference benchmark runner: requires nsd, knot, and bind binaries in PATH"
echo "Load generator: flamethrower (https://github.com/DNS-OARC/flamethrower)"
echo "PERF-020: NSD reference — not yet implemented"
echo "PERF-021: Knot DNS reference — not yet implemented"
echo "PERF-022: BIND 9 reference — not yet implemented"
exit 0
