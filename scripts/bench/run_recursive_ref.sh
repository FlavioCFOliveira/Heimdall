#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# run_recursive_ref.sh — Reference benchmark runner stub for recursive DNS
# resolvers (PERF-023..024).
#
# Compares Heimdall (recursive role) against Unbound, PowerDNS Recursor,
# and Knot Resolver using flamethrower for load generation.
#
# Requirements:
#   - unbound, pdns_recursor, kresd binaries in PATH
#   - flamethrower binary in PATH
#
# This is a stub.  Fill in the actual load-generation and result-collection
# logic when a dedicated benchmarking host is provisioned.
set -euo pipefail

echo "Reference benchmark runner: requires unbound, powerdns-recursor, and knot-resolver binaries in PATH"
echo "Load generator: flamethrower (https://github.com/DNS-OARC/flamethrower)"
echo "PERF-023: Unbound reference — not yet implemented"
echo "PERF-024: PowerDNS Recursor / Knot Resolver reference — not yet implemented"
exit 0
